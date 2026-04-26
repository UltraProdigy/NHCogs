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
    "BAN CHANNEL - DO NOT WRITE HERE.",
    "Security trap channel. Do not post here.",
    "Writing in this channel may trigger moderation review.",
    "Do not use this channel. Staff monitoring is active.",
    "Warning: messages here are treated as honeypot activity.",
]

DEFAULT_STATS = {
    "detections": 0,
    "suspicious": 0,
    "reviewed": 0,
    "review_expired": 0,
    "ignored": 0,
    "kicked": 0,
    "banned": 0,
    "failed_actions": 0,
    "dry_run_actions": 0,
    "whitelisted": 0,
    "pending_mutes": 0,
    "pending_mute_failures": 0,
    "purged_messages": 0,
}

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
        review_timeout_minutes: int = 1440,
        expires_at: datetime | None = None,
    ) -> None:
        super().__init__(timeout=None)
        self.cog = cog
        self.target_id = target_id
        self.guild_id = guild_id
        self.content = content
        self.attachment_urls = attachment_urls
        self.pending_mute_role_id = pending_mute_role_id
        self.created_at = datetime.now(timezone.utc)
        self.expires_at = expires_at or self.created_at + timedelta(minutes=review_timeout_minutes)
        self.review_message: discord.Message | None = None
        self.claimed_by: int | None = None
        self.active_key: int | None = None

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
        self.cog._active_views.pop(self.active_key or self.target_id, None)
        if interaction.guild is not None:
            await self.cog._delete_pending_review(interaction.guild, self.active_key)
        self.stop()

    async def on_timeout(self) -> None:
        await self.cog._expire_review(self)

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
            await self.cog._increment_stat(guild, "ignored")
            return (None, _("Ignored (no action)"))
        reason = _("Honeypot review: {action} by {mod}").format(action=action, mod=interaction.user)
        config = await self.cog.config.guild(guild).all()
        if config.get("dry_run"):
            if self.pending_mute_role_id is not None:
                mute_role = guild.get_role(self.pending_mute_role_id)
                if mute_role is not None and mute_role in member.roles:
                    try:
                        await member.remove_roles(mute_role, reason=_("Honeypot dry-run review completed; removing pending mute."))
                    except discord.HTTPException:
                        return (_("Failed to remove the pending mute role. Check bot permissions."), None)
            await self.cog._increment_stat(guild, "dry_run_actions")
            return (None, _("Dry run: would have {action}ed the member.").format(action=action))
        try:
            if action == "kick":
                await member.kick(reason=reason)
                await self._create_modlog_case(guild, member, action, reason)
                await self.cog._increment_stat(guild, "kicked")
                return (None, _("Kicked"))
            elif action == "ban":
                await member.ban(reason=reason, delete_message_days=config.get("ban_delete_message_days", 0))
                await self._create_modlog_case(guild, member, action, reason)
                await self.cog._increment_stat(guild, "banned")
                return (None, _("Banned"))
        except discord.HTTPException:
            await self.cog._increment_stat(guild, "failed_actions")
            return (_("Failed to perform the action. Check bot permissions."), None)
        return (None, None)

    @discord.ui.button(label="Ban", style=discord.ButtonStyle.danger, emoji="🔨", custom_id="honeypot:review:ban")
    async def ban_action(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        msg, label = await self._action_perform(interaction, "ban")
        if label:
            await self._update_done(interaction, label)
        if msg:
            await interaction.followup.send(msg, ephemeral=True)

    @discord.ui.button(label="Kick", style=discord.ButtonStyle.secondary, emoji="👢", custom_id="honeypot:review:kick")
    async def kick_action(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        msg, label = await self._action_perform(interaction, "kick")
        if label:
            await self._update_done(interaction, label)
        if msg:
            await interaction.followup.send(msg, ephemeral=True)

    @discord.ui.button(label="Ignore", style=discord.ButtonStyle.success, emoji="✅", custom_id="honeypot:review:ignore")
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
            fallback_action="review",
            dry_run=False,
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
            review_timeout_minutes=1440,
            whitelist_mode="bypass",
            stats=DEFAULT_STATS.copy(),
            pending_reviews={},
        )

        _settings: dict[str, dict[str, typing.Any]] = {
            "enabled": {
                "converter": bool,
                "description": "Toggle the cog.",
            },
            "action": {
                "converter": typing.Literal["kick", "ban"],
                "description": "The action to take when a clearly suspicious user is detected.",
            },
            "fallback_action": {
                "converter": typing.Literal["review", "kick", "ban", "none"],
                "description": "What to do when a honeypot post is not clearly suspicious.",
            },
            "dry_run": {
                "converter": bool,
                "description": "Log what would happen without kicking or banning users.",
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
            "review_timeout_minutes": {
                "converter": commands.Range[int, 1, 10080],
                "description": "Minutes before pending review expires and temporary mute is removed.",
            },
            "whitelist_mode": {
                "converter": typing.Literal["bypass", "review", "none"],
                "description": "How whitelisted roles behave: bypass, review, or none.",
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
        self._restore_task: asyncio.Task | None = None

    async def _increment_stat(self, guild: discord.Guild, key: str, amount: int = 1) -> None:
        async with self.config.guild(guild).stats() as stats:
            stats.setdefault(key, 0)
            stats[key] += amount

    async def _store_pending_review(
        self,
        guild: discord.Guild,
        view: ReviewView,
        review_channel_id: int,
        review_message_id: int,
    ) -> None:
        async with self.config.guild(guild).pending_reviews() as pending_reviews:
            pending_reviews[str(review_message_id)] = {
                "target_id": view.target_id,
                "review_channel_id": review_channel_id,
                "review_message_id": review_message_id,
                "content": view.content,
                "attachment_urls": view.attachment_urls,
                "pending_mute_role_id": view.pending_mute_role_id,
                "expires_at": view.expires_at.isoformat(),
            }

    async def _delete_pending_review(self, guild: discord.Guild, review_message_id: int | None) -> None:
        if review_message_id is None:
            return
        async with self.config.guild(guild).pending_reviews() as pending_reviews:
            pending_reviews.pop(str(review_message_id), None)

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
        self.review_timeout_loop.start()
        self._restore_task = asyncio.create_task(self._restore_pending_reviews())

    async def cog_unload(self) -> None:
        self.fake_activity_loop.cancel()
        self.review_timeout_loop.cancel()
        if self._restore_task is not None:
            self._restore_task.cancel()
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

    @tasks.loop(minutes=5)
    async def review_timeout_loop(self) -> None:
        now = datetime.now(timezone.utc)
        for view in list(self._active_views.values()):
            if view.expires_at <= now:
                await self._expire_review(view)

    @review_timeout_loop.before_loop
    async def before_review_timeout(self) -> None:
        await self.bot.wait_until_red_ready()

    async def _restore_pending_reviews(self) -> None:
        await self.bot.wait_until_red_ready()
        all_guilds = await self.config.all_guilds()
        now = datetime.now(timezone.utc)
        for guild_id, guild_config in all_guilds.items():
            guild = self.bot.get_guild(int(guild_id))
            if guild is None:
                continue
            pending_reviews = guild_config.get("pending_reviews", {})
            for review_message_id, data in list(pending_reviews.items()):
                try:
                    expires_at = datetime.fromisoformat(data["expires_at"])
                except (KeyError, ValueError, TypeError):
                    await self._delete_pending_review(guild, int(review_message_id))
                    continue
                view = ReviewView(
                    self,
                    int(data["target_id"]),
                    guild.id,
                    data.get("content", ""),
                    data.get("attachment_urls", []),
                    pending_mute_role_id=data.get("pending_mute_role_id"),
                    expires_at=expires_at,
                )
                view.active_key = int(review_message_id)
                review_channel = self._get_text_channel_or_thread(guild, data.get("review_channel_id"))
                if review_channel is not None:
                    try:
                        view.review_message = await review_channel.fetch_message(int(review_message_id))
                    except (discord.HTTPException, discord.NotFound, discord.Forbidden):
                        view.review_message = None
                if expires_at <= now:
                    await self._expire_review(view)
                    continue
                self.bot.add_view(view, message_id=int(review_message_id))
                self._active_views[int(review_message_id)] = view

    async def _expire_review(self, view: ReviewView) -> None:
        guild = self.bot.get_guild(view.guild_id)
        if guild is None:
            self._active_views.pop(view.active_key or view.target_id, None)
            await self._delete_pending_review(guild, view.active_key)
            view.stop()
            return
        member = guild.get_member(view.target_id)
        if member is not None and view.pending_mute_role_id is not None:
            mute_role = guild.get_role(view.pending_mute_role_id)
            if mute_role is not None and mute_role in member.roles:
                try:
                    await member.remove_roles(mute_role, reason="Honeypot review expired; removing pending mute.")
                except discord.HTTPException:
                    pass
        view._disable_all()
        embed = view.review_message.embeds[0] if view.review_message and view.review_message.embeds else None
        if embed:
            embed.color = discord.Color.green()
            embed.add_field(
                name=_("Reviewed by:"),
                value=_("Automatic timeout"),
                inline=False,
            )
            embed.add_field(
                name=_("Action taken:"),
                value=_("Ignored (review timed out)"),
                inline=False,
            )
        if view.review_message is not None:
            try:
                await view.review_message.edit(content=_("✅ **Review completed**"), embed=embed, view=view)
            except discord.HTTPException:
                pass
        await self._increment_stat(guild, "review_expired")
        await self._increment_stat(guild, "ignored")
        self._active_views.pop(view.active_key or view.target_id, None)
        await self._delete_pending_review(guild, view.active_key)
        view.stop()

    # ─── Detection ────────────────────────────────────────────────────────

    async def _suspicion_reasons(self, message: discord.Message) -> list[str]:
        reasons: list[str] = []
        content = message.content.lower()
        if re.search(r"https?://[^\s]+", content):
            reasons.append(_("Contains a link."))
        if message.author.created_at > datetime.now(timezone.utc) - timedelta(days=7):
            reasons.append(_("Account is less than 7 days old."))
        matched_keywords = [kw for kw in SCAM_KEYWORDS if kw in content]
        if matched_keywords:
            reasons.append(_("Matched scam keyword(s): {keywords}").format(keywords=", ".join(matched_keywords[:5])))
        if message.attachments and message.author.created_at > datetime.now(timezone.utc) - timedelta(days=30):
            reasons.append(_("Has attachments from an account less than 30 days old."))
        return reasons

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
        self, message: discord.Message, config: dict, reason: str, action: str | None = None
    ) -> tuple[str | None, str | None]:
        """Execute the configured action (kick/ban) against the message author.
        Returns (action_label, failed_message) where failed_message is None on success.
        """
        action = action or config["action"]
        if action not in ("kick", "ban"):
            return (_("No action configured."), None)
        if config.get("dry_run"):
            await self._increment_stat(message.guild, "dry_run_actions")
            return (_("Dry run: would have {action}ed the member.").format(action=action), None)
        try:
            if action == "kick":
                await message.author.kick(reason=reason)
                await self._increment_stat(message.guild, "kicked")
            elif action == "ban":
                await message.author.ban(
                    reason=reason,
                    delete_message_days=config["ban_delete_message_days"],
                )
                await self._increment_stat(message.guild, "banned")
        except discord.HTTPException as e:
            await self._increment_stat(message.guild, "failed_actions")
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

    async def _send_review(
        self,
        message: discord.Message,
        config: dict,
        embed: discord.Embed,
        review_channel: discord.TextChannel | discord.Thread,
        logs_channel: discord.TextChannel | discord.Thread,
    ) -> None:
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
                    await self._increment_stat(message.guild, "pending_mutes")
                    embed.add_field(
                        name=_("Pending review mute:"),
                        value=_("Mute role applied until moderators complete review."),
                        inline=False,
                    )
                except discord.HTTPException:
                    await self._increment_stat(message.guild, "pending_mute_failures")
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
            review_timeout_minutes=config.get("review_timeout_minutes", 1440),
        )
        embed.add_field(
            name=_("Review expires:"),
            value=discord.utils.format_dt(view.expires_at, style="R"),
            inline=False,
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
        view.active_key = sent.id
        self._active_views[sent.id] = view
        await self._store_pending_review(message.guild, view, review_channel.id, sent.id)
        await self._increment_stat(message.guild, "reviewed")
        await logs_channel.send(
            _("🟡 **Review required** for {user} ({user_id}) — sent to {channel}.").format(
                user=message.author.mention,
                user_id=message.author.id,
                channel=review_channel.mention,
            ),
            allowed_mentions=discord.AllowedMentions.none(),
        )

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
        await self._increment_stat(message.guild, "detections")

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
        account_age = datetime.now(timezone.utc) - message.author.created_at
        embed.add_field(
            name=_("Account age:"),
            value=_("{days} days").format(days=account_age.days),
            inline=True,
        )
        if message.author.joined_at is not None:
            joined_age = datetime.now(timezone.utc) - message.author.joined_at
            embed.add_field(
                name=_("Server age:"),
                value=_("{days} days").format(days=joined_age.days),
                inline=True,
            )

        # Purge — always runs before any action/review
        purged = 0
        if config["purge_enabled"]:
            purged = await self._purge_user_messages(
                message.channel, message.author.id, config["purge_minutes"]
            )
        if purged:
            await self._increment_stat(message.guild, "purged_messages", purged)
            embed.add_field(
                name=_("Purged messages:"),
                value=str(purged),
                inline=True,
            )

        force_review = False
        if has_whitelist_role:
            whitelist_mode = config.get("whitelist_mode", "bypass")
            await self._increment_stat(message.guild, "whitelisted")
            embed.add_field(
                name=_("Whitelisted role:"),
                value=_("User has a whitelisted role. Mode: `{mode}`.").format(mode=whitelist_mode),
                inline=False,
            )
            if whitelist_mode == "bypass":
                embed.color = discord.Color.orange()
                embed.add_field(name=_("Action:"), value=_("No punishment applied."), inline=False)
                await logs_channel.send(embed=embed)
                return
            if whitelist_mode == "review":
                force_review = True

        suspicion_reasons = await self._suspicion_reasons(message)
        suspicious = bool(suspicion_reasons)
        if suspicion_reasons:
            await self._increment_stat(message.guild, "suspicious")
            embed.add_field(
                name=_("Trigger reason(s):"),
                value="\n".join(f"- {reason}" for reason in suspicion_reasons),
                inline=False,
            )

        review_channel = None
        if config.get("review_channel") is not None:
            review_channel = self._get_text_channel_or_thread(message.guild, config["review_channel"])
        fallback_action = config.get("fallback_action", "review")
        should_review = force_review or (
            not suspicious
            and fallback_action == "review"
            and config["review_enabled"]
            and review_channel is not None
        )

        if should_review and review_channel is not None:
            await self._send_review(message, config, embed, review_channel, logs_channel)
            return

        if force_review and review_channel is None:
            embed.color = discord.Color.orange()
            embed.add_field(
                name=_("Action:"),
                value=_("No punishment applied because whitelist mode requires review, but no review channel is available."),
                inline=False,
            )
            await logs_channel.send(embed=embed)
            return

        if suspicious:
            action_label, failed = await self._execute_action(
                message,
                config,
                reason="Self bot/scammer detected (message in the HoneyPot channel).",
            )
            embed.add_field(name=_("Action:"), value=failed if failed else action_label, inline=False)
            if failed:
                embed.color = discord.Color.dark_red()
                embed.add_field(name=_("Staff attention:"), value=_("Automatic action failed."), inline=False)
        else:
            if fallback_action == "none":
                embed.color = discord.Color.orange()
                embed.add_field(name=_("Action:"), value=_("No fallback action configured."), inline=False)
            elif fallback_action == "review":
                embed.color = discord.Color.orange()
                embed.add_field(
                    name=_("Action:"),
                    value=_("No fallback action applied because review is unavailable."),
                    inline=False,
                )
            else:
                action_label, failed = await self._execute_action(
                    message,
                    config,
                    reason="User posted in honeypot channel (no scam pattern detected).",
                    action=fallback_action,
                )
                embed.add_field(name=_("Action:"), value=failed if failed else action_label, inline=False)
                if failed:
                    embed.color = discord.Color.dark_red()
                    embed.add_field(name=_("Staff attention:"), value=_("Fallback action failed."), inline=False)

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

    @sethoneypot.command(name="stats")
    async def honeypot_stats(self, ctx: commands.Context) -> None:
        """Show honeypot moderation statistics for this server."""
        stats = DEFAULT_STATS.copy()
        stats.update(await self.config.guild(ctx.guild).stats())
        lines = [f"{key}: {value}" for key, value in stats.items()]
        await ctx.send(_("**Honeypot stats:**\n") + box("\n".join(lines)))

    @sethoneypot.command(name="resetstats")
    async def honeypot_reset_stats(self, ctx: commands.Context) -> None:
        """Reset honeypot moderation statistics for this server."""
        await self.config.guild(ctx.guild).stats.set(DEFAULT_STATS.copy())
        await ctx.send(_("✅ Honeypot stats reset."))

    @sethoneypot.command(name="doctor")
    async def honeypot_doctor(self, ctx: commands.Context) -> None:
        """Check common honeypot configuration and permission problems."""
        config = await self.config.guild(ctx.guild).all()
        checks: list[tuple[str, bool, str]] = []
        me = ctx.guild.me
        honeypot_channel = self._get_text_channel_or_thread(ctx.guild, config.get("honeypot_channel"))
        logs_channel = self._get_text_channel_or_thread(ctx.guild, config.get("logs_channel"))
        review_channel = self._get_text_channel_or_thread(ctx.guild, config.get("review_channel"))
        checks.append(("Cog enabled", bool(config.get("enabled")), "Run `sethoneypot enabled true`."))
        checks.append(("Suspicious action set", config.get("action") in ("kick", "ban"), "Set `action` to `kick` or `ban`."))
        checks.append(("Honeypot channel exists", honeypot_channel is not None, "Set `honeypotchannel`."))
        checks.append(("Logs channel exists", logs_channel is not None, "Set `logschannel`."))
        if config.get("fallback_action") == "review" or config.get("review_enabled") or config.get("whitelist_mode") == "review":
            checks.append(("Review channel exists", review_channel is not None, "Set `reviewchannel` or change `fallbackaction`."))
        if config.get("mute_role"):
            mute_role = ctx.guild.get_role(config["mute_role"])
            checks.append(("Mute role exists", mute_role is not None, "Set `muterole` again."))
            if mute_role is not None:
                checks.append(("Bot is above mute role", me.top_role > mute_role, "Move the bot role above the mute role."))
        if honeypot_channel is not None:
            perms = honeypot_channel.permissions_for(me)
            checks.append(("Can view honeypot", perms.view_channel, "Grant View Channel."))
            checks.append(("Can read history", perms.read_message_history, "Grant Read Message History."))
            checks.append(("Can manage messages", perms.manage_messages, "Grant Manage Messages."))
        if logs_channel is not None:
            perms = logs_channel.permissions_for(me)
            checks.append(("Can send logs", perms.send_messages, "Grant Send Messages in logs channel."))
        if review_channel is not None:
            perms = review_channel.permissions_for(me)
            checks.append(("Can send review", perms.send_messages, "Grant Send Messages in review channel."))
        guild_perms = me.guild_permissions
        checks.append(("Can kick members", guild_perms.kick_members, "Grant Kick Members if using kick."))
        checks.append(("Can ban members", guild_perms.ban_members, "Grant Ban Members if using ban."))
        checks.append(("Can manage roles", guild_perms.manage_roles, "Grant Manage Roles for review mute."))
        failed = [f"❌ {name} - {hint}" for name, ok, hint in checks if not ok]
        passed = [f"✅ {name}" for name, ok, _hint in checks if ok]
        body = "\n".join(passed + failed)
        await ctx.send(_("**Honeypot doctor:**\n{body}").format(body=body))

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
