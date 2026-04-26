import asyncio
import os
import random
import re
import typing
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import discord
from discord.ext import tasks

from AAA3A_utils import Cog, Settings
from redbot.core import Config, commands, modlog
from redbot.core.bot import Red
from redbot.core.i18n import Translator, cog_i18n
from redbot.core.utils.chat_formatting import box

_ = Translator("Honeypot", __file__)

DEFAULT_FAKE_MESSAGES = [
    "Hey, is this the right place?",
    "Anyone here?",
    "Check DMs",
    "Who wants free stuff?",
    "DM me for a surprise!",
    "Free Nitro here: check my bio",
    "I'm new here, what's this server?",
    "Anyone trading?",
    "Join my server! Link in bio",
    "Who's online?",
]

SCAM_KEYWORDS = [
    "free nitro", "giveaway", "steam gift", "free discord",
    "discord.gift", "claim your", "you won", "free vbucks",
    "free robux", "free coins", "boost your server",
    "limited time", "exclusive offer", "free membership",
    "hack", "crack", "generator",
]


class ReviewView(discord.ui.View):
    def __init__(
        self,
        cog: "Honeypot",
        target_id: int,
        guild_id: int,
        content: str,
        attachment_urls: list[str],
        pending_mute_role_id: int | None = None,
    ) -> None:
        super().__init__(timeout=86400)
        self.cog = cog
        self.target_id = target_id
        self.guild_id = guild_id
        self.content = content
        self.attachment_urls = attachment_urls
        self.pending_mute_role_id = pending_mute_role_id
        self.review_message: discord.Message | None = None
        self.claimed_by: int | None = None

    def _check_perms(self, interaction: discord.Interaction) -> bool:
        guild_permissions = getattr(interaction.user, "guild_permissions", None)
        if guild_permissions is None or not guild_permissions.moderate_members:
            return False
        return True

    def _disable_all(self) -> None:
        for child in self.children:
            if isinstance(child, discord.ui.Button):
                child.disabled = True

    async def _create_modlog_case(
        self,
        guild: discord.Guild,
        member: discord.Member,
        action: str,
        reason: str,
    ) -> None:
        try:
            await modlog.create_case(
                self.cog.bot,
                guild,
                datetime.now(timezone.utc),
                action_type=action,
                user=member,
                moderator=guild.me,
                reason=reason,
            )
        except Exception:
            pass

    async def _update_done(self, interaction: discord.Interaction, action_taken: str) -> None:
        self._disable_all()
        embed = self.review_message.embeds[0] if self.review_message else None
        if embed:
            embed.color = discord.Color.green()
            embed.add_field(
                name=_("Reviewed by:"),
                value=f"{interaction.user.mention} ({interaction.user.id})",
                inline=False,
            )
            embed.add_field(
                name=_("Action taken:"),
                value=action_taken,
                inline=False,
            )
        await self.review_message.edit(content=_("✅ **Review completed**"), embed=embed, view=self)
        self.stop()

    async def _action_perform(self, interaction: discord.Interaction, action: str) -> tuple[str | None, str | None]:
        """Returns (result_message, action_label) or (None, None) to abort."""
        if not self._check_perms(interaction):
            return (_("You need `Moderate Members` permission."), None)
        guild = self.cog.bot.get_guild(self.guild_id)
        if guild is None:
            return (_("Guild not found."), None)
        member = guild.get_member(self.target_id)
        if member is None:
            return (_("User is no longer in the server."), None)
        if action == "ignore":
            if self.pending_mute_role_id is not None:
                mute_role = guild.get_role(self.pending_mute_role_id)
                if mute_role is not None and mute_role in member.roles:
                    try:
                        await member.remove_roles(mute_role, reason=_("Honeypot review ignored; removing pending mute."))
                    except discord.HTTPException:
                        return (_("Failed to remove the pending mute role. Check bot permissions."), None)
            return (None, _("Ignored (no action)"))
        reason = _("Honeypot review: {action} by {mod}").format(action=action, mod=interaction.user)
        try:
            if action == "kick":
                await member.kick(reason=reason)
                await self._create_modlog_case(guild, member, action, reason)
                return (None, _("Kicked"))
            elif action == "ban":
                config = await self.cog.config.guild(guild).all()
                await member.ban(reason=reason, delete_message_days=config.get("ban_delete_message_days", 0))
                await self._create_modlog_case(guild, member, action, reason)
                return (None, _("Banned"))
        except discord.HTTPException:
            return (_("Failed to perform the action. Check bot permissions."), None)
        return (None, None)

    @discord.ui.button(label="Ban", style=discord.ButtonStyle.danger, emoji="🔨")
    async def ban_action(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        msg, label = await self._action_perform(interaction, "ban")
        if label:
            await self._update_done(interaction, label)
        if msg:
            await interaction.followup.send(msg, ephemeral=True)

    @discord.ui.button(label="Kick", style=discord.ButtonStyle.secondary, emoji="👢")
    async def kick_action(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        msg, label = await self._action_perform(interaction, "kick")
        if label:
            await self._update_done(interaction, label)
        if msg:
            await interaction.followup.send(msg, ephemeral=True)

    @discord.ui.button(label="Ignore", style=discord.ButtonStyle.success, emoji="✅")
    async def ignore_action(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        msg, label = await self._action_perform(interaction, "ignore")
        if label:
            await self._update_done(interaction, label)
        if msg:
            await interaction.followup.send(msg, ephemeral=True)


@cog_i18n(_)
class Honeypot(Cog):
    """Create a channel at the top of the server to attract self bots/scammers and automatically handle them."""

    def __init__(self, bot: Red) -> None:
        super().__init__(bot=bot)

        self.config: Config = Config.get_conf(
            self,
            identifier=205192943327321000143939875896557571750,
            force_registration=True,
        )
        self.config.register_guild(
            enabled=False,
            action=None,
            logs_channel=None,
            ping_role=None,
            honeypot_channel=None,
            mute_role=None,
            ban_delete_message_days=3,
            whitelisted_roles=[],
            purge_enabled=True,
            purge_minutes=5,
            fake_activity_enabled=False,
            fake_activity_interval=10,
            fake_activity_messages=[],
            review_enabled=False,
            review_channel=None,
        )

        _settings: dict[str, dict[str, typing.Any]] = {
            "enabled": {
                "converter": bool,
                "description": "Toggle the cog.",
            },
            "action": {
                "converter": typing.Literal["kick", "ban"],
                "description": "The action to take when a self bot/scammer is detected.",
            },
            "honeypot_channel": {
                "converter": typing.Union[
                    discord.TextChannel,
                    discord.Thread,
                ],
                "description": "The honeypot channel where messages trigger detection.",
            },
            "logs_channel": {
                "converter": typing.Union[
                    discord.TextChannel,
                    discord.Thread,
                ],
                "description": "The channel to send the logs to.",
            },
            "ping_role": {
                "converter": discord.Role,
                "description": "The role to ping when a self bot/scammer is detected.",
            },
            "mute_role": {
                "converter": discord.Role,
                "description": "The temporary containment role to assign while a user is waiting for review.",
            },
            "ban_delete_message_days": {
                "converter": commands.Range[int, 0, 7],
                "description": "Number of days of messages to delete when banning.",
            },
            "purge_enabled": {
                "converter": bool,
                "description": "Toggle purging recent messages from the user in the honeypot channel.",
            },
            "purge_minutes": {
                "converter": commands.Range[int, 1, 60],
                "description": "Minutes of message history to purge from the user.",
            },
            "fake_activity_enabled": {
                "converter": bool,
                "description": "Toggle fake activity in the honeypot channel to attract scammers.",
            },
            "fake_activity_interval": {
                "converter": commands.Range[int, 1, 120],
                "description": "Minutes between fake activity messages.",
            },
            "review_enabled": {
                "converter": bool,
                "description": "Toggle moderator review instead of instant action for suspicious messages.",
            },
            "review_channel": {
                "converter": typing.Union[
                    discord.TextChannel,
                    discord.Thread,
                ],
                "description": "The channel to send moderator review requests to.",
            },
        }
        self.settings: Settings = Settings(
            bot=self.bot,
            cog=self,
            config=self.config,
            group=self.config.GUILD,
            settings=_settings,
            global_path=[],
            use_profiles_system=False,
            can_edit=True,
            commands_group=self.sethoneypot,
        )

        self._last_fake_message: dict[int, datetime] = defaultdict(lambda: datetime.min.replace(tzinfo=timezone.utc))
        self._active_views: dict[int, ReviewView] = {}

    def _get_text_channel_or_thread(
        self, guild: discord.Guild, channel_id: int | None
    ) -> discord.TextChannel | discord.Thread | None:
        if channel_id is None:
            return None
        channel = guild.get_channel(channel_id)
        if channel is None and hasattr(guild, "get_thread"):
            channel = guild.get_thread(channel_id)
        if channel is None:
            channel = self.bot.get_channel(channel_id)
        if isinstance(channel, (discord.TextChannel, discord.Thread)):
            return channel
        return None

    async def cog_load(self) -> None:
        await super().cog_load()
        await self.settings.add_commands()
        self.fake_activity_loop.start()

    async def cog_unload(self) -> None:
        self.fake_activity_loop.cancel()
        await super().cog_unload()

    # ─── Fake Activity Loop ───────────────────────────────────────────────

    @tasks.loop(minutes=1)
    async def fake_activity_loop(self) -> None:
        for guild in self.bot.guilds:
            try:
                config = await self.config.guild(guild).all()
                if not config["enabled"] or not config["fake_activity_enabled"]:
                    continue
                honeypot_channel_id = config["honeypot_channel"]
                if honeypot_channel_id is None:
                    continue
                honeypot_channel = self._get_text_channel_or_thread(guild, honeypot_channel_id)
                if honeypot_channel is None:
                    continue
                interval = config["fake_activity_interval"]
                now = datetime.now(timezone.utc)
                last = self._last_fake_message[guild.id]
                if (now - last).total_seconds() < interval * 60:
                    continue
                custom_msgs: list[str] = config.get("fake_activity_messages", [])
                pool = custom_msgs if custom_msgs else DEFAULT_FAKE_MESSAGES
                msg = random.choice(pool)
                await honeypot_channel.send(msg)
                self._last_fake_message[guild.id] = now
            except Exception:
                pass

    @fake_activity_loop.before_loop
    async def before_fake_activity(self) -> None:
        await self.bot.wait_until_red_ready()

    # ─── Detection ────────────────────────────────────────────────────────

    async def _is_suspicious(self, message: discord.Message) -> bool:
        content = message.content.lower()
        if re.search(r"https?://[^\s]+", content):
            return True
        if message.author.created_at > datetime.now(timezone.utc) - timedelta(days=7):
            return True
        if any(kw in content for kw in SCAM_KEYWORDS):
            return True
        if message.attachments and message.author.created_at > datetime.now(timezone.utc) - timedelta(days=30):
            return True
        return False

    async def _purge_user_messages(
        self, channel: discord.TextChannel | discord.Thread, author_id: int, minutes: int
    ) -> int:
        after = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        deleted = 0
        try:
            async for msg in channel.history(limit=200, after=after):
                if msg.author.id == author_id:
                    try:
                        await msg.delete()
                        deleted += 1
                        await asyncio.sleep(0.5)
                    except (discord.HTTPException, discord.Forbidden):
                        pass
        except (discord.HTTPException, discord.Forbidden):
            pass
        return deleted

    async def _execute_action(
        self, message: discord.Message, config: dict, reason: str
    ) -> tuple[str | None, str | None]:
        """Execute the configured action (kick/ban) against the message author.
        Returns (action_label, failed_message) where failed_message is None on success.
        """
        action = config["action"]
        if action is None:
            return (_("No action configured."), None)
        try:
            if action == "kick":
                await message.author.kick(reason=reason)
            elif action == "ban":
                await message.author.ban(
                    reason=reason,
                    delete_message_days=config["ban_delete_message_days"],
                )
        except discord.HTTPException as e:
            return (None, _("**Failed:** An error occurred while trying to take action:\n") + box(str(e), lang="py"))
        try:
            await modlog.create_case(
                self.bot,
                message.guild,
                message.created_at,
                action_type=action,
                user=message.author,
                moderator=message.guild.me,
                reason=reason,
            )
        except Exception:
            pass
        label = _("The member has been kicked.") if action == "kick" else _("The member has been banned.")
        return (label, None)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None:
            return
        if await self.bot.cog_disabled_in_guild(self, message.guild):
            return
        if message.author.bot:
            return
        config = await self.config.guild(message.guild).all()
        if (
            not config["enabled"]
            or (honeypot_channel_id := config["honeypot_channel"]) is None
            or (logs_channel_id := config["logs_channel"]) is None
            or (logs_channel := self._get_text_channel_or_thread(message.guild, logs_channel_id)) is None
        ):
            return
        if message.channel.id != honeypot_channel_id:
            return
        if (
            message.author.id in self.bot.owner_ids
            or await self.bot.is_mod(message.author)
            or await self.bot.is_admin(message.author)
            or message.author.guild_permissions.manage_guild
            or message.author.top_role >= message.guild.me.top_role
        ):
            return

        try:
            await message.delete()
        except discord.HTTPException:
            pass

        whitelisted_role_ids: list[int] = config.get("whitelisted_roles", [])
        has_whitelist_role = any(
            role.id in whitelisted_role_ids for role in message.author.roles
        )

        embed: discord.Embed = discord.Embed(
            title=_("Honeypot — Self Bot/Scammer Detected!"),
            description=f">>> {message.content}" if message.content else _("*(message with attachments only)*"),
            color=discord.Color.red(),
            timestamp=message.created_at,
        )
        embed.set_author(
            name=f"{message.author.display_name} ({message.author.id})",
            icon_url=message.author.display_avatar,
        )
        embed.set_thumbnail(url=message.author.display_avatar)
        if message.attachments:
            embed.add_field(
                name=_("Attachments:"),
                value="\n".join(a.url for a in message.attachments[:5]),
                inline=False,
            )

        # Purge — always runs before any action/review
        purged = 0
        if config["purge_enabled"]:
            purged = await self._purge_user_messages(
                message.channel, message.author.id, config["purge_minutes"]
            )
        if purged:
            embed.add_field(
                name=_("Purged messages:"),
                value=str(purged),
                inline=True,
            )

        # Whitelisted role — delete + log only, no punishment
        if has_whitelist_role:
            embed.add_field(
                name=_("Whitelisted role:"),
                value=_("User has a whitelisted role — no punishment applied."),
                inline=False,
            )
            embed.color = discord.Color.orange()
            await logs_channel.send(embed=embed)
            return

        # Determine path: suspicious → instant action, otherwise → possible review
        suspicious = await self._is_suspicious(message)

        if suspicious:
            # Instant action — scammer detected
            action_label, failed = await self._execute_action(message, config, reason="Self bot/scammer detected (message in the HoneyPot channel).")
            embed.add_field(name=_("Action:"), value=failed if failed else action_label, inline=False)
        else:
            # Not obviously a scammer — maybe accidental poster
            if config["review_enabled"] and (review_channel_id := config["review_channel"]) is not None:
                review_channel = self._get_text_channel_or_thread(message.guild, review_channel_id)
                if review_channel is not None:
                    embed.color = discord.Color.gold()
                    embed.title = _("Honeypot — Review Required")
                    embed.add_field(
                        name=_("Status:"),
                        value=_("⏳ Pending moderator review"),
                        inline=False,
                    )
                    pending_mute_role_id = None
                    if mute_role_id := config.get("mute_role"):
                        mute_role = message.guild.get_role(mute_role_id)
                        if mute_role is not None and mute_role not in message.author.roles:
                            try:
                                await message.author.add_roles(
                                    mute_role,
                                    reason="Honeypot review pending; temporary containment mute.",
                                )
                                pending_mute_role_id = mute_role.id
                                embed.add_field(
                                    name=_("Pending review mute:"),
                                    value=_("Mute role applied until moderators complete review."),
                                    inline=False,
                                )
                            except discord.HTTPException:
                                embed.add_field(
                                    name=_("Pending review mute:"),
                                    value=_("Failed to apply mute role. Check bot permissions."),
                                    inline=False,
                                )
                    attachment_urls = [a.url for a in message.attachments]
                    view = ReviewView(
                        self,
                        message.author.id,
                        message.guild.id,
                        message.content,
                        attachment_urls,
                        pending_mute_role_id=pending_mute_role_id,
                    )
                    review_files = []
                    for attachment in message.attachments[:10]:
                        try:
                            f = await attachment.to_file()
                            review_files.append(f)
                        except Exception:
                            pass
                    ping_content = None
                    if ping_role_id := config.get("ping_role"):
                        if ping_role := message.guild.get_role(ping_role_id):
                            ping_content = ping_role.mention
                    review_send_kwargs = {
                        "content": ping_content,
                        "embed": embed,
                        "view": view,
                    }
                    if review_files:
                        review_send_kwargs["files"] = review_files
                    sent = await review_channel.send(**review_send_kwargs)
                    view.review_message = sent
                    self._active_views[message.author.id] = view
                    await logs_channel.send(
                        _("🟡 **Review required** for {user} ({user_id}) — sent to {channel}.").format(
                            user=message.author.mention,
                            user_id=message.author.id,
                            channel=review_channel.mention,
                        ),
                        allowed_mentions=discord.AllowedMentions.none(),
                    )
                    return

            # Review disabled or channel not set — fallback to auto-action
            action_label, failed = await self._execute_action(message, config, reason="User posted in honeypot channel (no scam pattern detected).")
            embed.add_field(name=_("Action:"), value=failed if failed else action_label, inline=False)

        embed.set_footer(text=message.guild.name, icon_url=message.guild.icon)
        await logs_channel.send(
            content=(
                ping_role.mention
                if (ping_role_id := config["ping_role"]) is not None
                and (ping_role := message.guild.get_role(ping_role_id)) is not None
                else None
            ),
            embed=embed,
            allowed_mentions=discord.AllowedMentions(roles=True),
        )

    # ─── Commands ─────────────────────────────────────────────────────────

    @commands.guild_only()
    @commands.guildowner()
    @commands.hybrid_group()
    async def sethoneypot(self, ctx: commands.Context) -> None:
        """Set the honeypot settings. Only the server owner can use this command."""

    @commands.bot_has_guild_permissions(manage_channels=True)
    @sethoneypot.command(aliases=["makechannel"])
    async def createchannel(self, ctx: commands.Context) -> None:
        """Create the honeypot channel."""
        if (
            honeypot_channel_id := await self.config.guild(ctx.guild).honeypot_channel()
        ) is not None and (
            honeypot_channel := ctx.guild.get_channel(honeypot_channel_id)
        ) is not None:
            raise commands.UserFeedbackCheckFailure(
                _("The honeypot channel already exists: {channel.mention} ({channel.id}).").format(
                    channel=honeypot_channel,
                ),
            )
        honeypot_channel = await ctx.guild.create_text_channel(
            name="honeypot",
            position=0,
            overwrites={
                ctx.guild.me: discord.PermissionOverwrite(
                    view_channel=True,
                    read_messages=True,
                    send_messages=True,
                    manage_messages=True,
                    manage_channels=True,
                ),
                ctx.guild.default_role: discord.PermissionOverwrite(
                    view_channel=True,
                    read_messages=True,
                    send_messages=True,
                ),
            },
            reason=_("Honeypot channel creation requested by {author} ({author_id}).").format(
                author=ctx.author.display_name, author_id=ctx.author.id,
            ),
        )
        await self.config.guild(ctx.guild).honeypot_channel.set(honeypot_channel.id)
        await ctx.send(
            _(
                "The honeypot channel has been set to {channel.mention} ({channel.id}).\n"
                "Please configure the remaining settings (action, logs channel, etc.) before enabling."
            ).format(channel=honeypot_channel),
        )

    # ─── Whitelisted Roles ────────────────────────────────────────────────

    @sethoneypot.group(name="whitelistedroles", aliases=["wlroles"])
    async def whitelisted_roles_group(self, ctx: commands.Context) -> None:
        """Manage whitelisted roles that bypass punishment."""

    @whitelisted_roles_group.command(name="add")
    async def whitelisted_roles_add(self, ctx: commands.Context, role: discord.Role) -> None:
        """Add a role to the whitelist. Users with this role won't be punished."""
        async with self.config.guild(ctx.guild).whitelisted_roles() as roles:
            if role.id in roles:
                raise commands.UserFeedbackCheckFailure(_("That role is already whitelisted."))
            roles.append(role.id)
        await ctx.send(_("✅ {role} ({role_id}) added to the whitelist.").format(role=role.mention, role_id=role.id))

    @whitelisted_roles_group.command(name="remove")
    async def whitelisted_roles_remove(self, ctx: commands.Context, role: discord.Role) -> None:
        """Remove a role from the whitelist."""
        async with self.config.guild(ctx.guild).whitelisted_roles() as roles:
            if role.id not in roles:
                raise commands.UserFeedbackCheckFailure(_("That role is not in the whitelist."))
            roles.remove(role.id)
        await ctx.send(_("✅ {role} removed from the whitelist.").format(role=role.mention))

    @whitelisted_roles_group.command(name="list")
    async def whitelisted_roles_list(self, ctx: commands.Context) -> None:
        """List all whitelisted roles."""
        role_ids = await self.config.guild(ctx.guild).whitelisted_roles()
        if not role_ids:
            await ctx.send(_("No roles are whitelisted."))
            return
        roles = [ctx.guild.get_role(rid) for rid in role_ids if ctx.guild.get_role(rid) is not None]
        if not roles:
            await ctx.send(_("No valid whitelisted roles found (they may have been deleted)."))
            return
        lines = "\n".join(f"- {r.mention} ({r.id})" for r in roles)
        await ctx.send(_("**Whitelisted roles:**\n{lines}").format(lines=lines))

    # ─── Fake Activity Messages ───────────────────────────────────────────

    @sethoneypot.group(name="fakeactivity", aliases=["fakemsg"])
    async def fake_activity_group(self, ctx: commands.Context) -> None:
        """Manage fake activity messages for the honeypot channel."""

    @fake_activity_group.command(name="add")
    async def fake_activity_add(self, ctx: commands.Context, *, message: str) -> None:
        """Add a custom fake activity message."""
        async with self.config.guild(ctx.guild).fake_activity_messages() as msgs:
            msgs.append(message)
        await ctx.send(_("✅ Fake activity message added. ({num} total)").format(num=len(msgs)))

    @fake_activity_group.command(name="remove")
    async def fake_activity_remove(self, ctx: commands.Context, index: int) -> None:
        """Remove a fake activity message by its number (see list)."""
        async with self.config.guild(ctx.guild).fake_activity_messages() as msgs:
            if index < 1 or index > len(msgs):
                raise commands.UserFeedbackCheckFailure(
                    _("Invalid index. Use `{prefix}sethoneypot fakeactivity list` to see valid indices.").format(
                        prefix=ctx.clean_prefix,
                    ),
                )
            removed = msgs.pop(index - 1)
        await ctx.send(_("✅ Removed message #{index}: {msg}").format(index=index, msg=removed))

    @fake_activity_group.command(name="list")
    async def fake_activity_list(self, ctx: commands.Context) -> None:
        """List all custom fake activity messages."""
        msgs = await self.config.guild(ctx.guild).fake_activity_messages()
        if not msgs:
            await ctx.send(_("No custom fake activity messages set. Defaults will be used."))
            return
        lines = "\n".join(f"`{i}.` {m}" for i, m in enumerate(msgs, 1))
        await ctx.send(_("**Custom fake activity messages:**\n{lines}").format(lines=lines))

    @fake_activity_group.command(name="reset")
    async def fake_activity_reset(self, ctx: commands.Context) -> None:
        """Reset to default fake activity messages."""
        await self.config.guild(ctx.guild).fake_activity_messages.set([])
        await ctx.send(_("✅ Custom messages cleared. Defaults will be used."))
