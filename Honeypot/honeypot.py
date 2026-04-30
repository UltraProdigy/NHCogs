import asyncio
import io
import logging
import random
import re
import typing
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import discord
from discord.ext import tasks

from AAA3A_utils import Cog
from redbot.core import Config, commands, modlog
from redbot.core.bot import Red
from redbot.core.i18n import Translator, cog_i18n
from redbot.core.utils.chat_formatting import box

_ = Translator("Honeypot", __file__)
log = logging.getLogger("red.Honeypot")

DEFAULT_FAKE_MESSAGES = [
    "BAN CHANNEL - DO NOT WRITE HERE.",
    "Do not type in this channel.",
    "Messages here are logged and reviewed by staff.",
    "Wrong channel. Do not post here.",
    "Stop. This channel is monitored.",
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

DEFAULT_ATTACHMENT_PATTERNS = [
    r"^image ?\(\d+\)$",
    r"^[1-4]$",
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
            log.exception("Failed to create modlog case in ReviewView")

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
        review_message = self.review_message or interaction.message
        if review_message is not None:
            await review_message.edit(content=_("\u2705 **Review completed**"), embed=embed, view=self)
        async with self.cog._views_lock:
            self.cog._active_views.pop(self.active_key or self.target_id, None)
        if interaction.guild is not None:
            await self.cog._delete_pending_review(interaction.guild, self.active_key)
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
                        return (_("I couldn't remove the temporary mute role. Check my role permissions."), None)
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
                        return (_("I couldn't remove the temporary mute role. Check my role permissions."), None)
            await self.cog._increment_stat(guild, "dry_run_actions")
            return (None, self.cog._dry_run_label(action))
        missing_permission = self.cog._missing_action_permission(guild, action)
        if missing_permission is not None:
            await self.cog._increment_stat(guild, "failed_actions")
            return (missing_permission, None)
        try:
            if self.pending_mute_role_id is not None:
                mute_role = guild.get_role(self.pending_mute_role_id)
                if mute_role is not None and mute_role in member.roles:
                    try:
                        await member.remove_roles(mute_role, reason=_("Removing pending mute before {action}.").format(action=action))
                    except discord.HTTPException:
                        pass
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
            return (_("Action failed. Check my permissions and role position."), None)
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
    """Create a trap channel and handle users who post in it."""

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
            scam_keywords=SCAM_KEYWORDS.copy(),
            attachment_patterns=DEFAULT_ATTACHMENT_PATTERNS.copy(),
            joinwatch_enabled=False,
            joinwatch_channel=None,
            joinwatch_min_age_hours=24,
        )

        self._last_fake_message: dict[int, datetime] = defaultdict(lambda: datetime.min.replace(tzinfo=timezone.utc))
        self._fake_config_cache: dict[int, tuple[datetime, dict]] = {}
        self._active_views: dict[int, ReviewView] = {}
        self._views_lock: asyncio.Lock = asyncio.Lock()
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

    def _dry_run_label(self, action: str) -> str:
        if action == "ban":
            return _("Dry run: I would ban this member.")
        if action == "kick":
            return _("Dry run: I would kick this member.")
        return _("Dry run: I would not take action.")

    def _missing_action_permission(self, guild: discord.Guild, action: str) -> str | None:
        permissions = guild.me.guild_permissions
        if action == "kick" and not permissions.kick_members:
            return _("**Failed:** I do not have the `Kick Members` permission.")
        if action == "ban" and not permissions.ban_members:
            return _("**Failed:** I do not have the `Ban Members` permission.")
        return None

    def _format_bytes(self, size: int) -> str:
        if size >= 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        if size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"

    async def _snapshot_attachments(self, message: discord.Message) -> list[dict[str, typing.Any]]:
        snapshots: list[dict[str, typing.Any]] = []
        upload_limit = getattr(message.guild, "filesize_limit", 25 * 1024 * 1024)
        for attachment in message.attachments[:10]:
            snapshot: dict[str, typing.Any] = {
                "filename": attachment.filename,
                "url": attachment.url,
                "size": attachment.size,
                "content_type": attachment.content_type,
                "description": attachment.description,
                "spoiler": attachment.is_spoiler(),
                "data": None,
                "error": None,
            }
            if attachment.size > upload_limit:
                snapshot["error"] = _("too large to re-upload ({size})").format(size=self._format_bytes(attachment.size))
            else:
                try:
                    snapshot["data"] = await attachment.read()
                except (discord.HTTPException, discord.Forbidden, discord.NotFound):
                    try:
                        snapshot["data"] = await attachment.read(use_cached=True)
                    except TypeError:
                        snapshot["error"] = _("could not download")
                    except (discord.HTTPException, discord.Forbidden, discord.NotFound) as exc:
                        log.warning("Failed to snapshot attachment %s (%s): %s", attachment.filename, attachment.url, exc)
                        snapshot["error"] = _("could not download")
                except TypeError:
                    snapshot["error"] = _("could not download")
            snapshots.append(snapshot)
        if len(message.attachments) > 10:
            snapshots.append(
                {
                    "filename": _("Additional attachments"),
                    "url": None,
                    "size": 0,
                    "content_type": None,
                    "description": None,
                    "spoiler": False,
                    "data": None,
                    "error": _("{count} more attachment(s) not copied; Discord allows 10 files per message.").format(
                        count=len(message.attachments) - 10
                    ),
                }
            )
        return snapshots

    def _attachment_files(self, attachment_snapshots: list[dict[str, typing.Any]]) -> list[discord.File]:
        files: list[discord.File] = []
        for snapshot in attachment_snapshots:
            data = snapshot.get("data")
            if data is None:
                continue
            files.append(
                discord.File(
                    io.BytesIO(data),
                    filename=snapshot["filename"],
                    spoiler=snapshot.get("spoiler", False),
                    description=snapshot.get("description"),
                )
            )
        return files

    def _attachment_summary(self, attachment_snapshots: list[dict[str, typing.Any]]) -> str | None:
        if not attachment_snapshots:
            return None
        lines: list[str] = []
        for snapshot in attachment_snapshots:
            filename = snapshot["filename"]
            if snapshot.get("url"):
                line = f"[{filename}]({snapshot['url']})"
            else:
                line = str(filename)
            if snapshot.get("size"):
                line += f" ({self._format_bytes(snapshot['size'])})"
            if snapshot.get("data") is not None:
                line += " - copied"
            elif snapshot.get("error"):
                line += f" - {snapshot['error']}"
            lines.append(line)
        summary = "\n".join(lines)
        return summary if len(summary) <= 1024 else summary[:1000] + "\n..."

    async def cog_load(self) -> None:
        await super().cog_load()
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
        now = datetime.now(timezone.utc)
        for guild in self.bot.guilds:
            try:
                cached = self._fake_config_cache.get(guild.id)
                if cached and (now - cached[0]).total_seconds() < 120:
                    config = cached[1]
                else:
                    config = await self.config.guild(guild).all()
                    self._fake_config_cache[guild.id] = (now, config)
                if not config["enabled"] or not config["fake_activity_enabled"]:
                    continue
                honeypot_channel_id = config["honeypot_channel"]
                if honeypot_channel_id is None:
                    continue
                honeypot_channel = self._get_text_channel_or_thread(guild, honeypot_channel_id)
                if honeypot_channel is None:
                    continue
                interval = config["fake_activity_interval"]
                last = self._last_fake_message[guild.id]
                if (now - last).total_seconds() < interval * 60:
                    continue
                custom_msgs: list[str] = config.get("fake_activity_messages", [])
                pool = custom_msgs if custom_msgs else DEFAULT_FAKE_MESSAGES
                msg = random.choice(pool)
                await honeypot_channel.send(msg)
                self._last_fake_message[guild.id] = now
            except Exception:
                log.exception("Error in fake_activity_loop for guild %s", guild.id)

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
                async with self._views_lock:
                    self._active_views[int(review_message_id)] = view

    async def _expire_review(self, view: ReviewView) -> None:
        guild = self.bot.get_guild(view.guild_id)
        if guild is None:
            async with self.cog._views_lock:
                self.cog._active_views.pop(view.active_key or view.target_id, None)
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
                value=_("Timed out"),
                inline=False,
            )
            embed.add_field(
                name=_("Action taken:"),
                value=_("Ignored after no staff response"),
                inline=False,
            )
        if view.review_message is not None:
            try:
                await view.review_message.edit(content=_("✅ **Review completed**"), embed=embed, view=view)
            except discord.HTTPException:
                pass
        await self._increment_stat(guild, "review_expired")
        await self._increment_stat(guild, "ignored")
        async with self._views_lock:
            self._active_views.pop(view.active_key or view.target_id, None)
        await self._delete_pending_review(guild, view.active_key)
        view.stop()

    # ─── Detection ────────────────────────────────────────────────────────

    async def _suspicion_reasons(self, message: discord.Message, config: dict) -> list[str]:
        reasons: list[str] = []
        content = message.content.lower()
        if message.author.created_at > datetime.now(timezone.utc) - timedelta(days=7):
            reasons.append(_("Account is under 7 days old"))
        scam_keywords = config.get("scam_keywords") or SCAM_KEYWORDS
        matched_keywords = [kw for kw in scam_keywords if kw.lower() in content]
        if matched_keywords:
            reasons.append(_("Matched keyword: {keywords}").format(keywords=", ".join(matched_keywords[:5])))
        if message.attachments and message.author.created_at > datetime.now(timezone.utc) - timedelta(days=14):
            reasons.append(_("Attachment from an account under 14 days old"))
        attachment_patterns = config.get("attachment_patterns") or DEFAULT_ATTACHMENT_PATTERNS
        filenames = [attachment.filename.lower() for attachment in message.attachments]
        image_name_count = sum(1 for filename in filenames if filename.rsplit(".", 1)[0] == "image")
        if image_name_count >= 4:
            reasons.append(_("Repeated attachment basename: image x{count}").format(count=image_name_count))
        filename_bases = [filename.rsplit(".", 1)[0] for filename in filenames]
        matched_patterns = []
        for pattern in attachment_patterns:
            try:
                matches = sum(1 for filename_base in filename_bases if re.fullmatch(pattern, filename_base, flags=re.IGNORECASE))
            except re.error:
                continue
            if matches >= 4:
                matched_patterns.append(pattern)
        if matched_patterns:
            reasons.append(_("Matched attachment pattern: {patterns}").format(patterns=", ".join(matched_patterns[:3])))
        return reasons

    async def _purge_user_messages(
        self, channel: discord.TextChannel | discord.Thread, author_id: int, minutes: int
    ) -> int:
        after = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        try:
            deleted = await channel.purge(
                limit=200,
                after=after,
                check=lambda m: m.author.id == author_id,
                bulk=True,
            )
            return len(deleted)
        except (discord.HTTPException, discord.Forbidden):
            return 0

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
            return (self._dry_run_label(action), None)
        missing_permission = self._missing_action_permission(message.guild, action)
        if missing_permission is not None:
            await self._increment_stat(message.guild, "failed_actions")
            return (None, missing_permission)
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
            return (None, _("**Action failed:**\n") + box(str(e), lang="py"))
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
            log.exception("Failed to create modlog case in _execute_action")
        label = _("The member has been kicked.") if action == "kick" else _("The member has been banned.")
        return (label, None)

    async def _send_review(
        self,
        message: discord.Message,
        config: dict,
        embed: discord.Embed,
        review_channel: discord.TextChannel | discord.Thread,
        logs_channel: discord.TextChannel | discord.Thread,
        attachment_snapshots: list[dict[str, typing.Any]],
    ) -> None:
        embed.color = discord.Color.gold()
        embed.title = _("Review needed")
        embed.add_field(
            name=_("Status:"),
            value=_("Pending moderator review"),
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
                        value=_("Temporary mute applied while staff reviews this."),
                        inline=False,
                    )
                except discord.HTTPException:
                    await self._increment_stat(message.guild, "pending_mute_failures")
                    embed.add_field(
                        name=_("Pending review mute:"),
                        value=_("I couldn't apply the temporary mute role."),
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
            name=_("Auto-ignore:"),
            value=discord.utils.format_dt(view.expires_at, style="R"),
            inline=False,
        )
        review_files = self._attachment_files(attachment_snapshots)
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
        async with self._views_lock:
            self._active_views[sent.id] = view
        await self._store_pending_review(message.guild, view, review_channel.id, sent.id)
        await self._increment_stat(message.guild, "reviewed")
        await logs_channel.send(
            _("🟡 Review queued for {user} ({user_id}) in {channel}.").format(
                user=message.author.mention,
                user_id=message.author.id,
                channel=review_channel.mention,
            ),
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _send_log(
        self,
        channel: discord.TextChannel | discord.Thread,
        embed: discord.Embed,
        attachment_snapshots: list[dict[str, typing.Any]],
        content: str | None = None,
        allowed_mentions: discord.AllowedMentions | None = None,
    ) -> None:
        send_kwargs: dict[str, typing.Any] = {"content": content, "embed": embed}
        if allowed_mentions is not None:
            send_kwargs["allowed_mentions"] = allowed_mentions
        files = self._attachment_files(attachment_snapshots)
        if files:
            send_kwargs["files"] = files
        await channel.send(**send_kwargs)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None:
            return
        if await self.bot.cog_disabled_in_guild(self, message.guild):
            return
        if message.author.bot:
            return
        honeypot_channel_id = await self.config.guild(message.guild).honeypot_channel()
        if honeypot_channel_id is None or message.channel.id != honeypot_channel_id:
            return
        config = await self.config.guild(message.guild).all()
        if not config["enabled"] or (logs_channel_id := config["logs_channel"]) is None or (logs_channel := self._get_text_channel_or_thread(message.guild, logs_channel_id)) is None:
            return
        if (
            message.author.id in self.bot.owner_ids
            or await self.bot.is_mod(message.author)
            or await self.bot.is_admin(message.author)
            or message.author.guild_permissions.manage_guild
            or message.author.top_role >= message.guild.me.top_role
        ):
            return

        attachment_snapshots = await self._snapshot_attachments(message)

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
            title=_("Honeypot hit"),
            description=f">>> {message.content}" if message.content else _("*(message with attachments only)*"),
            color=discord.Color.red(),
            timestamp=message.created_at,
        )
        embed.set_author(
            name=f"{message.author.display_name} ({message.author.id})",
            icon_url=message.author.display_avatar,
        )
        embed.set_thumbnail(url=message.author.display_avatar)
        attachment_summary = self._attachment_summary(attachment_snapshots)
        if attachment_summary:
            embed.add_field(
                name=_("Attachments:"),
                value=attachment_summary,
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
        force_fallback = False
        if has_whitelist_role:
            whitelist_mode = config.get("whitelist_mode", "bypass")
            await self._increment_stat(message.guild, "whitelisted")
            embed.add_field(
                name=_("Whitelisted role:"),
                value=_("Whitelist mode: `{mode}`").format(mode=whitelist_mode),
                inline=False,
            )
            if whitelist_mode == "bypass":
                embed.color = discord.Color.orange()
                embed.add_field(name=_("Action:"), value=_("No action taken."), inline=False)
                await self._send_log(logs_channel, embed, attachment_snapshots)
                return
            if whitelist_mode == "review":
                force_review = True
            elif whitelist_mode == "fallback":
                force_fallback = True

        suspicion_reasons = await self._suspicion_reasons(message, config)
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
        action = config.get("action")
        fallback_action = config.get("fallback_action", "review")
        should_review = force_review or (
            action == "review"
            and config["review_enabled"]
            and review_channel is not None
        ) or (
            (not suspicious or force_fallback)
            and fallback_action == "review"
            and config["review_enabled"]
            and review_channel is not None
        )

        if should_review and review_channel is not None:
            await self._send_review(message, config, embed, review_channel, logs_channel, attachment_snapshots)
            return

        if force_review and review_channel is None:
            embed.color = discord.Color.orange()
            embed.add_field(
                name=_("Action:"),
                value=_("No action taken. This whitelist mode needs a review channel, but none is available."),
                inline=False,
            )
            await self._send_log(logs_channel, embed, attachment_snapshots)
            return

        if suspicious and not force_fallback:
            if action in ("review", "none"):
                pass
            else:
                action_label, failed = await self._execute_action(
                    message,
                    config,
                    reason="Suspicious post in the honeypot channel.",
                )
                embed.add_field(name=_("Action:"), value=failed if failed else action_label, inline=False)
                if failed:
                    embed.color = discord.Color.dark_red()
                    embed.add_field(name=_("Staff check needed:"), value=_("Automatic action failed."), inline=False)

        if not suspicious or force_fallback or suspicious and action in ("review", "none"):
            if fallback_action == "none":
                embed.color = discord.Color.orange()
                embed.add_field(name=_("Action:"), value=_("No fallback action set."), inline=False)
            elif fallback_action == "review":
                embed.color = discord.Color.orange()
                embed.add_field(
                    name=_("Action:"),
                    value=_("No fallback action taken. Review is unavailable."),
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
                    embed.add_field(name=_("Staff check needed:"), value=_("Fallback action failed."), inline=False)

        embed.set_footer(text=message.guild.name, icon_url=message.guild.icon)
        await self._send_log(
            logs_channel,
            embed,
            attachment_snapshots,
            content=(
                ping_role.mention
                if (ping_role_id := config["ping_role"]) is not None
                and (ping_role := message.guild.get_role(ping_role_id)) is not None
                else None
            ),
            allowed_mentions=discord.AllowedMentions(roles=True),
        )

    # ─── New account join alert ────────────────────────────────────────

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        if await self.bot.cog_disabled_in_guild(self, member.guild):
            return
        if member.bot:
            return
        config = await self.config.guild(member.guild).all()
        if not config["joinwatch_enabled"] or config["joinwatch_channel"] is None:
            return
        channel = self._get_text_channel_or_thread(member.guild, config["joinwatch_channel"])
        if channel is None:
            return
        min_age = timedelta(hours=config["joinwatch_min_age_hours"])
        if member.created_at > datetime.now(timezone.utc) - min_age:
            hours = max(1, round((datetime.now(timezone.utc) - member.created_at).total_seconds() / 3600))
            embed = discord.Embed(
                title=_("New account joined"),
                description=_("{mention} ({id}) joined. Account is ~{hours} hours old.").format(
                    mention=member.mention, id=member.id, hours=hours,
                ),
                color=discord.Color.orange(),
                timestamp=member.joined_at or datetime.now(timezone.utc),
            )
            embed.set_thumbnail(url=member.display_avatar)
            try:
                await channel.send(embed=embed)
            except discord.HTTPException:
                pass

    # ─── Commands ─────────────────────────────────────────────────────────

    @commands.guild_only()
    @commands.check(lambda ctx: ctx.author.id == ctx.guild.owner_id or ctx.author.id in ctx.bot.owner_ids)
    @commands.group()
    async def honeypot(self, ctx: commands.Context) -> None:
        """Configure the honeypot system."""

    # ─── core sub-group ───────────────────────────────────────────────

    @honeypot.group()
    async def core(self, ctx: commands.Context) -> None:
        """Core settings: enabled, action, fallback, dry run."""

    @core.command()
    async def enabled(self, ctx: commands.Context, value: bool = None) -> None:
        """Toggle the cog on/off."""
        if value is None:
            v = await self.config.guild(ctx.guild).enabled()
            await ctx.send(_("Enabled: {value}").format(value=v))
        else:
            await self.config.guild(ctx.guild).enabled.set(value)
            await ctx.send(_("✅ Enabled set to {value}").format(value=value))

    @core.command()
    async def action(self, ctx: commands.Context, value: str = None) -> None:
        """Main action for suspicious users: kick, ban, review, or none."""
        if value is None:
            v = await self.config.guild(ctx.guild).action()
            await ctx.send(_("Action: {value}").format(value=v or _("not set")))
        elif value not in ("kick", "ban", "review", "none"):
            await ctx.send(_("Action must be `kick`, `ban`, `review`, or `none`."))
        else:
            await self.config.guild(ctx.guild).action.set(value)
            await ctx.send(_("✅ Action set to {value}").format(value=value))

    @core.command(name="fallback_action")
    async def fallback_action(self, ctx: commands.Context, value: str = None) -> None:
        """Fallback: review, kick, ban, or none."""
        if value is None:
            v = await self.config.guild(ctx.guild).fallback_action()
            await ctx.send(_("Fallback action: {value}").format(value=v))
        elif value not in ("review", "kick", "ban", "none"):
            await ctx.send(_("Must be `review`, `kick`, `ban`, or `none`."))
        else:
            await self.config.guild(ctx.guild).fallback_action.set(value)
            await ctx.send(_("✅ Fallback action set to {value}").format(value=value))

    @core.command(name="dry_run")
    async def dry_run(self, ctx: commands.Context, value: bool = None) -> None:
        """Log actions without actually punishing users."""
        if value is None:
            v = await self.config.guild(ctx.guild).dry_run()
            await ctx.send(_("Dry run: {value}").format(value=v))
        else:
            await self.config.guild(ctx.guild).dry_run.set(value)
            await ctx.send(_("✅ Dry run set to {value}").format(value=value))

    @core.command(name="whitelist_mode")
    async def whitelist_mode(self, ctx: commands.Context, value: str = None) -> None:
        """How whitelisted roles behave: bypass, review, fallback, or none."""
        if value is None:
            v = await self.config.guild(ctx.guild).whitelist_mode()
            await ctx.send(_("Whitelist mode: {value}").format(value=v))
        elif value not in ("bypass", "review", "fallback", "none"):
            await ctx.send(_("Must be `bypass`, `review`, `fallback`, or `none`."))
        else:
            await self.config.guild(ctx.guild).whitelist_mode.set(value)
            await ctx.send(_("✅ Whitelist mode set to {value}").format(value=value))

    # ─── channel sub-group ────────────────────────────────────────────

    @honeypot.group()
    async def channel(self, ctx: commands.Context) -> None:
        """Honeypot channel, logs channel, ping role."""

    @commands.bot_has_guild_permissions(manage_channels=True)
    @channel.command()
    async def create(self, ctx: commands.Context) -> None:
        """Create the honeypot channel."""
        if (
            honeypot_channel_id := await self.config.guild(ctx.guild).honeypot_channel()
        ) is not None and (
            honeypot_channel := ctx.guild.get_channel(honeypot_channel_id)
        ) is not None:
            raise commands.UserFeedbackCheckFailure(
                _("Already exists: {channel.mention} ({channel.id}).").format(channel=honeypot_channel),
            )
        honeypot_channel = await ctx.guild.create_text_channel(
            name="honeypot",
            position=0,
            overwrites={
                ctx.guild.me: discord.PermissionOverwrite(
                    view_channel=True, read_messages=True, send_messages=True,
                    manage_messages=True, manage_channels=True,
                ),
                ctx.guild.default_role: discord.PermissionOverwrite(
                    view_channel=True, read_messages=True, send_messages=True,
                ),
            },
            reason=_("Honeypot channel requested by {author}.").format(author=ctx.author),
        )
        await self.config.guild(ctx.guild).honeypot_channel.set(honeypot_channel.id)
        await ctx.send(_("✅ Honeypot channel: {channel.mention}").format(channel=honeypot_channel))

    @channel.command(name="set")
    async def channel_set(self, ctx: commands.Context, target: discord.TextChannel | discord.Thread) -> None:
        """Set an existing channel as the honeypot."""
        await self.config.guild(ctx.guild).honeypot_channel.set(target.id)
        await ctx.send(_("✅ Honeypot channel set to {channel.mention}").format(channel=target))

    @channel.command()
    async def logs(self, ctx: commands.Context, target: discord.TextChannel | discord.Thread = None) -> None:
        """Set the logs channel."""
        if target is None:
            v = await self.config.guild(ctx.guild).logs_channel()
            await ctx.send(_("Logs channel: {channel}").format(channel=ctx.guild.get_channel(v) if v else _("not set")))
        else:
            await self.config.guild(ctx.guild).logs_channel.set(target.id)
            await ctx.send(_("✅ Logs channel set to {channel.mention}").format(channel=target))

    @channel.command(name="ping_role")
    async def channel_ping_role(self, ctx: commands.Context, role: discord.Role = None) -> None:
        """Role to ping on detection."""
        if role is None:
            v = await self.config.guild(ctx.guild).ping_role()
            role = ctx.guild.get_role(v) if v else None
            await ctx.send(_("Ping role: {role}").format(role=role.mention if role else _("not set")))
        else:
            await self.config.guild(ctx.guild).ping_role.set(role.id)
            await ctx.send(_("✅ Ping role set to {role.mention}").format(role=role))

    # ─── punishment sub-group ─────────────────────────────────────────

    @honeypot.group()
    async def punishment(self, ctx: commands.Context) -> None:
        """Mute role, delete days on ban."""

    @punishment.command(name="mute_role")
    async def punishment_mute_role(self, ctx: commands.Context, role: discord.Role = None) -> None:
        """Temporary mute role for users awaiting review."""
        if role is None:
            v = await self.config.guild(ctx.guild).mute_role()
            r = ctx.guild.get_role(v) if v else None
            await ctx.send(_("Mute role: {role}").format(role=r.mention if r else _("not set")))
        else:
            await self.config.guild(ctx.guild).mute_role.set(role.id)
            await ctx.send(_("✅ Mute role set to {role.mention}").format(role=role))

    @punishment.command(name="delete_days")
    async def punishment_delete_days(self, ctx: commands.Context, days: int = None) -> None:
        """Days of messages to delete on ban (0-7)."""
        if days is None:
            v = await self.config.guild(ctx.guild).ban_delete_message_days()
            await ctx.send(_("Delete days: {value}").format(value=v))
        elif days < 0 or days > 7:
            await ctx.send(_("Days must be between 0 and 7."))
        else:
            await self.config.guild(ctx.guild).ban_delete_message_days.set(days)
            await ctx.send(_("✅ Delete days set to {value}").format(value=days))

    # ─── purge sub-group ──────────────────────────────────────────────

    @honeypot.group()
    async def purge(self, ctx: commands.Context) -> None:
        """Auto-purge recent messages from caught users."""

    @purge.command()
    async def enabled(self, ctx: commands.Context, value: bool = None) -> None:
        """Toggle purging on detection."""
        if value is None:
            v = await self.config.guild(ctx.guild).purge_enabled()
            await ctx.send(_("Purge enabled: {value}").format(value=v))
        else:
            await self.config.guild(ctx.guild).purge_enabled.set(value)
            await ctx.send(_("✅ Purge enabled set to {value}").format(value=value))

    @purge.command()
    async def minutes(self, ctx: commands.Context, value: int = None) -> None:
        """Minutes of history to purge (1-60)."""
        if value is None:
            v = await self.config.guild(ctx.guild).purge_minutes()
            await ctx.send(_("Purge minutes: {value}").format(value=v))
        elif value < 1 or value > 60:
            await ctx.send(_("Minutes must be between 1 and 60."))
        else:
            await self.config.guild(ctx.guild).purge_minutes.set(value)
            await ctx.send(_("✅ Purge minutes set to {value}").format(value=value))

    # ─── fakeactivity sub-group ───────────────────────────────────────

    @honeypot.group()
    async def fakeactivity(self, ctx: commands.Context) -> None:
        """Fake activity to lure scammers."""

    @fakeactivity.command()
    async def enabled(self, ctx: commands.Context, value: bool = None) -> None:
        """Toggle fake activity messages."""
        if value is None:
            v = await self.config.guild(ctx.guild).fake_activity_enabled()
            await ctx.send(_("Fake activity enabled: {value}").format(value=v))
        else:
            await self.config.guild(ctx.guild).fake_activity_enabled.set(value)
            await ctx.send(_("✅ Fake activity enabled set to {value}").format(value=value))

    @fakeactivity.command()
    async def interval(self, ctx: commands.Context, value: int = None) -> None:
        """Minutes between fake messages (1-120)."""
        if value is None:
            v = await self.config.guild(ctx.guild).fake_activity_interval()
            await ctx.send(_("Fake activity interval: {value} min").format(value=v))
        elif value < 1 or value > 120:
            await ctx.send(_("Interval must be between 1 and 120."))
        else:
            await self.config.guild(ctx.guild).fake_activity_interval.set(value)
            await ctx.send(_("✅ Interval set to {value} minutes").format(value=value))

    @fakeactivity.command(name="add")
    async def fakeactivity_add(self, ctx: commands.Context, *, message: str) -> None:
        """Add a custom fake activity message."""
        async with self.config.guild(ctx.guild).fake_activity_messages() as msgs:
            msgs.append(message)
        await ctx.send(_("✅ Message added. ({num} total)").format(num=len(msgs)))

    @fakeactivity.command(name="remove")
    async def fakeactivity_remove(self, ctx: commands.Context, index: int) -> None:
        """Remove a fake message by index (see list)."""
        async with self.config.guild(ctx.guild).fake_activity_messages() as msgs:
            if index < 1 or index > len(msgs):
                raise commands.UserFeedbackCheckFailure(
                    _("Invalid index. Use `{prefix}honeypot fakeactivity list` to see indices.").format(prefix=ctx.clean_prefix),
                )
            removed = msgs.pop(index - 1)
        await ctx.send(_("✅ Removed #{index}: {msg}").format(index=index, msg=removed))

    @fakeactivity.command(name="list")
    async def fakeactivity_list(self, ctx: commands.Context) -> None:
        """List custom fake activity messages."""
        msgs = await self.config.guild(ctx.guild).fake_activity_messages()
        if not msgs:
            await ctx.send(_("No custom messages. Defaults will be used."))
            return
        lines = "\n".join(f"`{i}.` {m}" for i, m in enumerate(msgs, 1))
        await ctx.send(_("**Fake activity messages:**\n{lines}").format(lines=lines))

    @fakeactivity.command(name="reset")
    async def fakeactivity_reset(self, ctx: commands.Context) -> None:
        """Reset to defaults."""
        await self.config.guild(ctx.guild).fake_activity_messages.set([])
        await ctx.send(_("✅ Reset to defaults."))

    # ─── review sub-group ─────────────────────────────────────────────

    @honeypot.group()
    async def review(self, ctx: commands.Context) -> None:
        """Moderator review for non-obvious cases."""

    @review.command()
    async def enabled(self, ctx: commands.Context, value: bool = None) -> None:
        """Toggle moderator review."""
        if value is None:
            v = await self.config.guild(ctx.guild).review_enabled()
            await ctx.send(_("Review enabled: {value}").format(value=v))
        else:
            await self.config.guild(ctx.guild).review_enabled.set(value)
            await ctx.send(_("✅ Review enabled set to {value}").format(value=value))

    @review.command(name="channel")
    async def review_channel(self, ctx: commands.Context, target: discord.TextChannel | discord.Thread = None) -> None:
        """Channel for review requests."""
        if target is None:
            v = await self.config.guild(ctx.guild).review_channel()
            await ctx.send(_("Review channel: {channel}").format(channel=ctx.guild.get_channel(v) if v else _("not set")))
        else:
            await self.config.guild(ctx.guild).review_channel.set(target.id)
            await ctx.send(_("✅ Review channel set to {channel.mention}").format(channel=target))

    @review.command()
    async def timeout(self, ctx: commands.Context, minutes: int = None) -> None:
        """Minutes before review expires and mute is removed (1-10080)."""
        if minutes is None:
            v = await self.config.guild(ctx.guild).review_timeout_minutes()
            await ctx.send(_("Review timeout: {value} minutes").format(value=v))
        elif minutes < 1 or minutes > 10080:
            await ctx.send(_("Timeout must be between 1 and 10080 minutes."))
        else:
            await self.config.guild(ctx.guild).review_timeout_minutes.set(minutes)
            await ctx.send(_("✅ Review timeout set to {value} minutes").format(value=minutes))

    # ─── roles sub-group (was whitelistedroles) ───────────────────────

    @honeypot.group()
    async def roles(self, ctx: commands.Context) -> None:
        """Manage whitelisted roles that bypass punishment."""

    @roles.command(name="add")
    async def roles_add(self, ctx: commands.Context, role: discord.Role) -> None:
        """Add a role to the whitelist."""
        async with self.config.guild(ctx.guild).whitelisted_roles() as roles:
            if role.id in roles:
                raise commands.UserFeedbackCheckFailure(_("That role is already whitelisted."))
            roles.append(role.id)
        await ctx.send(_("✅ {role} added to the whitelist.").format(role=role.mention))

    @roles.command(name="remove")
    async def roles_remove(self, ctx: commands.Context, role: discord.Role) -> None:
        """Remove a role from the whitelist."""
        async with self.config.guild(ctx.guild).whitelisted_roles() as roles:
            if role.id not in roles:
                raise commands.UserFeedbackCheckFailure(_("That role is not in the whitelist."))
            roles.remove(role.id)
        await ctx.send(_("✅ {role} removed from the whitelist.").format(role=role.mention))

    @roles.command(name="list")
    async def roles_list(self, ctx: commands.Context) -> None:
        """List whitelisted roles."""
        role_ids = await self.config.guild(ctx.guild).whitelisted_roles()
        if not role_ids:
            await ctx.send(_("No whitelisted roles."))
            return
        roles = [ctx.guild.get_role(rid) for rid in role_ids if ctx.guild.get_role(rid) is not None]
        if not roles:
            await ctx.send(_("No valid roles found (deleted?)."))
            return
        await ctx.send(_("**Whitelisted roles:**\n{lines}").format(lines="\n".join(f"- {r.mention}" for r in roles)))

    # ─── keywords sub-group (was scamkeywords) ────────────────────────

    @honeypot.group()
    async def keywords(self, ctx: commands.Context) -> None:
        """Manage scam keywords for suspicious-message detection."""

    @keywords.command(name="add")
    async def keywords_add(self, ctx: commands.Context, *, keyword: str) -> None:
        """Add a scam keyword."""
        keyword = keyword.strip().lower()
        if not keyword:
            raise commands.UserFeedbackCheckFailure(_("Keyword cannot be empty."))
        async with self.config.guild(ctx.guild).scam_keywords() as keywords:
            if keyword in [kw.lower() for kw in keywords]:
                raise commands.UserFeedbackCheckFailure(_("Keyword already exists."))
            keywords.append(keyword)
        await ctx.send(_("✅ Keyword added: `{keyword}`").format(keyword=keyword))

    @keywords.command(name="remove")
    async def keywords_remove(self, ctx: commands.Context, *, keyword: str) -> None:
        """Remove a scam keyword."""
        keyword = keyword.strip().lower()
        async with self.config.guild(ctx.guild).scam_keywords() as keywords:
            for existing in list(keywords):
                if existing.lower() == keyword:
                    keywords.remove(existing)
                    await ctx.send(_("✅ Keyword removed: `{keyword}`").format(keyword=existing))
                    return
        raise commands.UserFeedbackCheckFailure(_("Keyword not found."))

    @keywords.command(name="list")
    async def keywords_list(self, ctx: commands.Context) -> None:
        """List scam keywords."""
        keywords = await self.config.guild(ctx.guild).scam_keywords()
        if not keywords:
            await ctx.send(_("No keywords configured."))
            return
        await ctx.send(_("**Scam keywords:**\n{lines}").format(lines="\n".join(f"`{i}.` {kw}" for i, kw in enumerate(keywords, 1))))

    @keywords.command(name="reset")
    async def keywords_reset(self, ctx: commands.Context) -> None:
        """Reset keywords to defaults."""
        await self.config.guild(ctx.guild).scam_keywords.set(SCAM_KEYWORDS.copy())
        await ctx.send(_("✅ Keywords reset to defaults."))

    @keywords.group(name="attachments")
    async def keyword_attachments(self, ctx: commands.Context) -> None:
        """Manage suspicious attachment filename regexes."""

    @keyword_attachments.command(name="add")
    async def keyword_attachments_add(self, ctx: commands.Context, *, pattern: str) -> None:
        """Add an attachment filename-base regex. It triggers when 4+ files match."""
        try:
            re.compile(pattern)
        except re.error as exc:
            raise commands.UserFeedbackCheckFailure(_("Invalid regex: {error}").format(error=exc))
        async with self.config.guild(ctx.guild).attachment_patterns() as patterns:
            if pattern in patterns:
                raise commands.UserFeedbackCheckFailure(_("Pattern already exists."))
            patterns.append(pattern)
        await ctx.send(_("✅ Attachment pattern added: `{pattern}`").format(pattern=pattern))

    @keyword_attachments.command(name="remove")
    async def keyword_attachments_remove(self, ctx: commands.Context, *, pattern: str) -> None:
        """Remove an attachment filename-base regex."""
        async with self.config.guild(ctx.guild).attachment_patterns() as patterns:
            if pattern not in patterns:
                raise commands.UserFeedbackCheckFailure(_("Pattern not found."))
            patterns.remove(pattern)
        await ctx.send(_("✅ Attachment pattern removed: `{pattern}`").format(pattern=pattern))

    @keyword_attachments.command(name="list")
    async def keyword_attachments_list(self, ctx: commands.Context) -> None:
        """List attachment filename-base regexes."""
        patterns = await self.config.guild(ctx.guild).attachment_patterns()
        if not patterns:
            await ctx.send(_("No attachment patterns configured."))
            return
        await ctx.send(_("**Attachment patterns:**\n{lines}").format(lines="\n".join(f"`{i}.` {pattern}" for i, pattern in enumerate(patterns, 1))))

    @keyword_attachments.command(name="reset")
    async def keyword_attachments_reset(self, ctx: commands.Context) -> None:
        """Reset attachment filename-base regexes to defaults."""
        await self.config.guild(ctx.guild).attachment_patterns.set(DEFAULT_ATTACHMENT_PATTERNS.copy())
        await ctx.send(_("✅ Attachment patterns reset to defaults."))

    # ─── joinwatch sub-group ──────────────────────────────────────────

    @honeypot.group()
    async def joinwatch(self, ctx: commands.Context) -> None:
        """Alert when accounts younger than N hours join."""

    @joinwatch.command()
    async def enabled(self, ctx: commands.Context, value: bool = None) -> None:
        """Toggle new account join alerts."""
        if value is None:
            v = await self.config.guild(ctx.guild).joinwatch_enabled()
            await ctx.send(_("Joinwatch enabled: {value}").format(value=v))
        else:
            await self.config.guild(ctx.guild).joinwatch_enabled.set(value)
            await ctx.send(_("✅ Joinwatch enabled set to {value}").format(value=value))

    @joinwatch.command()
    async def channel(self, ctx: commands.Context, target: discord.TextChannel | discord.Thread = None) -> None:
        """Channel for new account join alerts."""
        if target is None:
            v = await self.config.guild(ctx.guild).joinwatch_channel()
            await ctx.send(_("Joinwatch channel: {channel}").format(channel=ctx.guild.get_channel(v) if v else _("not set")))
        else:
            await self.config.guild(ctx.guild).joinwatch_channel.set(target.id)
            await ctx.send(_("✅ Joinwatch channel set to {channel.mention}").format(channel=target))

    @joinwatch.command()
    async def min_age(self, ctx: commands.Context, hours: int = None) -> None:
        """Max account age in hours to trigger alert (default 24)."""
        if hours is None:
            v = await self.config.guild(ctx.guild).joinwatch_min_age_hours()
            await ctx.send(_("Joinwatch min age: {value} hours").format(value=v))
        elif hours < 1 or hours > 168:
            await ctx.send(_("Hours must be between 1 and 168 (1 week)."))
        else:
            await self.config.guild(ctx.guild).joinwatch_min_age_hours.set(hours)
            await ctx.send(_("✅ Joinwatch min age set to {value} hours").format(value=hours))

    # ─── stats ────────────────────────────────────────────────────────

    @honeypot.command(name="stats")
    async def honeypot_stats(self, ctx: commands.Context) -> None:
        """Show honeypot statistics."""
        stats = DEFAULT_STATS.copy()
        stats.update(await self.config.guild(ctx.guild).stats())
        lines = [f"{key}: {value}" for key, value in stats.items()]
        await ctx.send(_("**Honeypot stats:**\n") + box("\n".join(lines)))

    @honeypot.command(name="resetstats")
    async def honeypot_reset_stats(self, ctx: commands.Context) -> None:
        """Reset statistics."""
        await self.config.guild(ctx.guild).stats.set(DEFAULT_STATS.copy())
        await ctx.send(_("✅ Stats reset."))

    @honeypot.command(name="doctor")
    async def honeypot_doctor(self, ctx: commands.Context) -> None:
        """Check configuration and permissions."""
        config = await self.config.guild(ctx.guild).all()
        checks: list[tuple[str, bool, str]] = []
        me = ctx.guild.me
        honeypot_channel = self._get_text_channel_or_thread(ctx.guild, config.get("honeypot_channel"))
        logs_channel = self._get_text_channel_or_thread(ctx.guild, config.get("logs_channel"))
        review_channel = self._get_text_channel_or_thread(ctx.guild, config.get("review_channel"))
        checks.append(("Cog enabled", bool(config.get("enabled")), "Run `honeypot core enabled true`."))
        checks.append(("Suspicious action set", config.get("action") in ("kick", "ban"), "Run `honeypot core action`."))
        checks.append(("Honeypot channel exists", honeypot_channel is not None, "Run `honeypot channel set`."))
        checks.append(("Logs channel exists", logs_channel is not None, "Run `honeypot channel logs`."))
        if config.get("fallback_action") == "review" or config.get("review_enabled") or config.get("whitelist_mode") == "review":
            checks.append(("Review channel exists", review_channel is not None, "Run `honeypot review channel`."))
        if config.get("mute_role"):
            mute_role = ctx.guild.get_role(config["mute_role"])
            checks.append(("Mute role exists", mute_role is not None, "Set `muterole` again."))
            if mute_role is not None:
                checks.append(("Bot above mute role", me.top_role > mute_role, "Move bot role above mute role."))
        if honeypot_channel is not None:
            perms = honeypot_channel.permissions_for(me)
            checks.append(("Can view", perms.view_channel, "Grant View Channel."))
            checks.append(("Can read history", perms.read_message_history, "Grant Read Message History."))
            checks.append(("Can manage messages", perms.manage_messages, "Grant Manage Messages."))
        if logs_channel is not None:
            perms = logs_channel.permissions_for(me)
            checks.append(("Can send logs", perms.send_messages, "Grant Send Messages."))
        if review_channel is not None:
            perms = review_channel.permissions_for(me)
            checks.append(("Can send review", perms.send_messages, "Grant Send Messages."))
        guild_perms = me.guild_permissions
        checks.append(("Can kick members", guild_perms.kick_members, "Grant Kick Members."))
        checks.append(("Can ban members", guild_perms.ban_members, "Grant Ban Members."))
        checks.append(("Can manage roles", guild_perms.manage_roles, "Grant Manage Roles for mute."))
        failed = [f"❌ {name} - {hint}" for name, ok, hint in checks if not ok]
        passed = [f"✅ {name}" for name, ok, _hint in checks if ok]
        await ctx.send(_("**Honeypot doctor:**\n{body}").format(body="\n".join(passed + failed)))
