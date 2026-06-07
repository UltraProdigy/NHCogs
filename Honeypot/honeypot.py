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
from redbot.core.utils.chat_formatting import box, pagify

_ = Translator("Honeypot", __file__)
log = logging.getLogger("red.Honeypot")

MAX_BAN_DELETE_MESSAGE_DAYS = 7
SECONDS_PER_DAY = 24 * 60 * 60
PURGE_PERMISSION_REQUIREMENTS = (
    ("View Channel", "view_channel"),
    ("Read Message History", "read_message_history"),
    ("Manage Messages", "manage_messages"),
)

DEFAULT_FAKE_MESSAGES = [
    "BAN CHANNEL - DO NOT WRITE HERE.",
    "Do not type in this channel.",
    "This channel is restricted.",
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
    "joinwatch_total_joins": 0,
    "joinwatch_young_joins": 0,
    "joinwatch_auto_roles_scheduled": 0,
    "joinwatch_auto_roles": 0,
    "joinwatch_auto_role_failures": 0,
    "joinwatch_auto_roles_cleared": 0,
    "joinwatch_auto_role_punishments": 0,
}

JOINWATCH_RETRY_DELAY_MINUTES = 5
JOINWATCH_MAX_RETRIES = 5
POST_BAN_SWEEP_DELAY_SECONDS = 5
POST_BAN_SWEEP_LOOKBACK_MINUTES = 5
POST_BAN_SWEEP_PER_CHANNEL_LIMIT = 10
# This flat sweep does not replace ban delete-message-days; it only catches
# messages that race Discord's on-ban deletion path.
# Guild-wide bulk delete is ~1 request/s; pause after a channel actually deletes messages.
POST_BAN_SWEEP_CHANNEL_COOLDOWN_SECONDS = 1.0
REVIEW_KICK_FAIL_WARNING_MODES = ("false", "true", "manual")
KICK_FAIL_WARNING_REASON = "Suspicious activity: target left before the kick could be applied."
CORE_ACTION_OPTIONS = ("kick", "ban", "review", "none")
FALLBACK_ACTION_OPTIONS = ("review", "kick", "ban", "none")
WHITELIST_MODE_OPTIONS = ("bypass", "review", "fallback", "none")
JOINWATCH_AUTO_ROLE_ACTION_OPTIONS = ("none", "kick", "ban")
BAIT_ACTION_OPTIONS = ("kick", "ban")
BOOL_OPTIONS = ("false", "true")


def ban_delete_message_days(config: dict) -> int:
    days = int(config.get("ban_delete_message_days", 0) or 0)
    if days <= 0:
        return 0
    return min(days, MAX_BAN_DELETE_MESSAGE_DAYS)


def ban_delete_message_seconds(config: dict) -> int:
    return ban_delete_message_days(config) * SECONDS_PER_DAY


def missing_purge_permissions(permissions: object) -> list[str]:
    return [
        name
        for name, attribute in PURGE_PERMISSION_REQUIREMENTS
        if not bool(getattr(permissions, attribute, False))
    ]


def is_purgeable_message_channel(channel: object) -> bool:
    return callable(getattr(channel, "purge", None))


def requires_connect_for_message_history(channel: object) -> bool:
    return callable(getattr(channel, "connect", None))


def missing_channel_purge_permissions(channel: object, permissions: object) -> list[str]:
    missing = missing_purge_permissions(permissions)
    if requires_connect_for_message_history(channel) and not bool(
        getattr(permissions, "connect", False)
    ):
        missing.append("Connect")
    return missing


SCAM_KEYWORDS = [
    "free nitro", "giveaway", "steam gift", "free discord",
    "discord.gift", "claim your", "you won", "free vbucks",
    "free robux", "free coins", "boost your server",
    "limited time", "exclusive offer", "free membership",
    "hack", "crack", "generator",
]

DEFAULT_ATTACHMENT_PATTERNS = [
    r"^image$",
    r"^image ?\(\d+\)$",
    r"^\d+$",
]

GENERIC_ATTACHMENT_NAME_RE = re.compile(r"^(?:image(?: ?\(\d+\))?|\d+)$", re.IGNORECASE)


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
        self._resolution_lock: asyncio.Lock = asyncio.Lock()
        self._resolution_started = False

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
        user: discord.Member | discord.User | discord.Object,
        action: str,
        reason: str,
        moderator: typing.Any = None,
    ) -> None:
        try:
            await modlog.create_case(
                self.cog.bot,
                guild,
                datetime.now(timezone.utc),
                action_type=action,
                user=user,
                moderator=moderator or guild.me,
                reason=reason,
            )
        except Exception:
            log.exception("Failed to create modlog case in ReviewView")

    async def _claim_resolution(self) -> bool:
        async with self._resolution_lock:
            if self._resolution_started:
                return False
            self._resolution_started = True
            return True

    async def _release_resolution(self) -> None:
        async with self._resolution_lock:
            self._resolution_started = False

    async def _update_done(self, interaction: discord.Interaction, action_taken: str) -> None:
        self._disable_all()
        embed = self.review_message.embeds[0] if self.review_message and self.review_message.embeds else None
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
            try:
                await review_message.edit(content=_("\u2705 **Review resolved**"), embed=embed, view=self)
            except discord.HTTPException:
                log.debug("Failed to edit completed review message %s", getattr(review_message, "id", None))
        async with self.cog._views_lock:
            self.cog._active_views.pop(self.active_key or self.target_id, None)
        if interaction.guild is not None:
            await self.cog._delete_pending_review(interaction.guild, self.active_key)
        self.stop()

    async def _send_kick_fail_warning_prompt(self, interaction: discord.Interaction) -> None:
        embed = discord.Embed(
            title=_("Target left the server"),
            description=_("The user left before the kick could be applied. Apply a warning instead?"),
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.add_field(name=_("User ID:"), value=f"`{self.target_id}`", inline=False)
        await interaction.followup.send(
            embed=embed,
            view=KickFailWarnView(self),
            ephemeral=True,
        )

    async def _action_perform(self, interaction: discord.Interaction, action: str) -> tuple[str | None, str | None]:
        """Returns (result_message, action_label) or (None, None) to abort."""
        if not self._check_perms(interaction):
            return (_("You need `Moderate Members` permission."), None)
        guild = self.cog.bot.get_guild(self.guild_id)
        if guild is None:
            return (_("Guild not found."), None)
        config = await self.cog.config.guild(guild).all()
        member = guild.get_member(self.target_id)
        if member is None and action == "kick":
            if config.get("dry_run"):
                await self.cog._increment_stat(guild, "dry_run_actions")
                return (None, self.cog._dry_run_label(action))
            warning_mode = self.cog._review_kick_fail_warning_mode(config)
            if warning_mode == "manual":
                await self._send_kick_fail_warning_prompt(interaction)
                return (None, None)
            if warning_mode == "true":
                label, failed = await self.cog._create_kick_fail_warning(
                    guild,
                    self.target_id,
                    moderator=interaction.user,
                )
                return (failed, label)
        if member is None and action not in ("ban", "ignore"):
            return (_("User is no longer in the server."), None)
        if action == "ignore":
            if member is not None and self.pending_mute_role_id is not None:
                mute_role = guild.get_role(self.pending_mute_role_id)
                if mute_role is not None and mute_role in member.roles:
                    removed = await self.cog._remove_review_mute_role(
                        member,
                        mute_role,
                        _("Honeypot review ignored; removing pending mute."),
                    )
                    if not removed:
                        return (_("I couldn't remove the temporary mute role. Check my role permissions."), None)
            await self.cog._increment_stat(guild, "ignored")
            return (None, _("Ignored (no action)"))
        reason = _("Honeypot review: {action}").format(action=action.title())
        if config.get("dry_run"):
            if member is not None and self.pending_mute_role_id is not None:
                mute_role = guild.get_role(self.pending_mute_role_id)
                if mute_role is not None and mute_role in member.roles:
                    removed = await self.cog._remove_review_mute_role(
                        member,
                        mute_role,
                        _("Honeypot dry-run review completed; removing pending mute."),
                    )
                    if not removed:
                        return (_("I couldn't remove the temporary mute role. Check my role permissions."), None)
            await self.cog._increment_stat(guild, "dry_run_actions")
            return (None, self.cog._dry_run_label(action))
        missing_permission = self.cog._missing_action_permission(guild, action)
        if missing_permission is not None:
            await self.cog._increment_stat(guild, "failed_actions")
            return (missing_permission, None)
        try:
            if member is not None and self.pending_mute_role_id is not None:
                mute_role = guild.get_role(self.pending_mute_role_id)
                if mute_role is not None and mute_role in member.roles:
                    removed = await self.cog._remove_review_mute_role(
                        member,
                        mute_role,
                        _("Removing pending mute before {action}.").format(action=action),
                    )
                    if not removed:
                        log.debug("Failed to remove pending mute role before %s for user %s", action, self.target_id)
            if action == "kick":
                if member is None:
                    return (_("User is no longer in the server."), None)
                await member.kick(reason=reason)
                await self._create_modlog_case(guild, member, action, reason, interaction.user)
                await self.cog._increment_stat(guild, "kicked")
                return (None, _("Kicked"))
            elif action == "ban":
                target = member if member is not None else await self.cog._get_user_or_object(self.target_id)
                await guild.ban(
                    target,
                    reason=reason,
                    delete_message_seconds=self.cog._ban_delete_message_seconds(config),
                )
                self.cog._schedule_post_ban_sweep_if_enabled(guild, target.id, config)
                await self._create_modlog_case(guild, target, action, reason, interaction.user)
                await self.cog._increment_stat(guild, "banned")
                return (None, _("Banned"))
        except discord.HTTPException:
            await self.cog._increment_stat(guild, "failed_actions")
            return (_("Action failed. Check my permissions and role position."), None)
        return (None, None)

    @discord.ui.button(label="Ban", style=discord.ButtonStyle.danger, emoji="🔨", custom_id="honeypot:review:ban")
    async def ban_action(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        if not await self._claim_resolution():
            await interaction.followup.send(_("Someone is already handling this review."), ephemeral=True)
            return
        msg, label = await self._action_perform(interaction, "ban")
        if label:
            await self._update_done(interaction, label)
        else:
            await self._release_resolution()
        if msg:
            await interaction.followup.send(msg, ephemeral=True)

    @discord.ui.button(label="Kick", style=discord.ButtonStyle.secondary, emoji="👢", custom_id="honeypot:review:kick")
    async def kick_action(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        if not await self._claim_resolution():
            await interaction.followup.send(_("Someone is already handling this review."), ephemeral=True)
            return
        msg, label = await self._action_perform(interaction, "kick")
        if label:
            await self._update_done(interaction, label)
        else:
            await self._release_resolution()
        if msg:
            await interaction.followup.send(msg, ephemeral=True)

    @discord.ui.button(label="Ignore", style=discord.ButtonStyle.success, emoji="✅", custom_id="honeypot:review:ignore")
    async def ignore_action(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        if not await self._claim_resolution():
            await interaction.followup.send(_("Someone is already handling this review."), ephemeral=True)
            return
        msg, label = await self._action_perform(interaction, "ignore")
        if label:
            await self._update_done(interaction, label)
        else:
            await self._release_resolution()
        if msg:
            await interaction.followup.send(msg, ephemeral=True)


class KickFailWarnView(discord.ui.View):
    def __init__(self, review_view: ReviewView) -> None:
        super().__init__(timeout=300)
        self.review_view = review_view

    @discord.ui.button(label="Yes", style=discord.ButtonStyle.danger, custom_id="honeypot:kickfailwarn:yes")
    async def warn_yes(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        if not self.review_view._check_perms(interaction):
            await interaction.followup.send(_("You need `Moderate Members` permission."), ephemeral=True)
            return
        if not await self.review_view._claim_resolution():
            await interaction.followup.send(_("Someone is already handling this review."), ephemeral=True)
            return
        guild = self.review_view.cog.bot.get_guild(self.review_view.guild_id)
        if guild is None:
            await self.review_view._release_resolution()
            await interaction.followup.send(_("Guild not found."), ephemeral=True)
            return
        label, failed = await self.review_view.cog._create_kick_fail_warning(
            guild,
            self.review_view.target_id,
            moderator=interaction.user,
        )
        if failed:
            await self.review_view._release_resolution()
            await interaction.followup.send(failed, ephemeral=True)
            return
        await self.review_view._update_done(interaction, label or _("Warning applied"))
        await interaction.followup.send(_("Warning applied."), ephemeral=True)
        self.stop()

    @discord.ui.button(label="No", style=discord.ButtonStyle.secondary, custom_id="honeypot:kickfailwarn:no")
    async def warn_no(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        if not self.review_view._check_perms(interaction):
            await interaction.followup.send(_("You need `Moderate Members` permission."), ephemeral=True)
            return
        if not await self.review_view._claim_resolution():
            await interaction.followup.send(_("Someone is already handling this review."), ephemeral=True)
            return
        await self.review_view._update_done(interaction, _("Kick skipped; target left the server."))
        await interaction.followup.send(_("No warning applied."), ephemeral=True)
        self.stop()


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
            honeypot_channels=[],
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
            review_kick_fail_warning="false",
            automated_kick_fail_warning=False,
            whitelist_mode="bypass",
            stats=DEFAULT_STATS.copy(),
            pending_reviews={},
            scam_keywords=SCAM_KEYWORDS.copy(),
            attachment_patterns=DEFAULT_ATTACHMENT_PATTERNS.copy(),
            joinwatch_enabled=False,
            joinwatch_alert_enabled=True,
            joinwatch_channel=None,
            joinwatch_min_age_hours=24,
            joinwatch_auto_role_enabled=False,
            joinwatch_auto_role_id=None,
            joinwatch_auto_role_timer_minutes=1440,
            joinwatch_auto_role_action="none",
            joinwatch_auto_role_random_delay_enabled=False,
            joinwatch_auto_role_random_delay_min_minutes=1,
            joinwatch_auto_role_random_delay_max_minutes=10,
            joinwatch_pending_role_assignments={},
            joinwatch_pending_roles={},
            baitrole_enabled=False,
            baitrole_id=None,
            baitrole_action="ban",
        )

        self._last_fake_message: dict[int, datetime] = defaultdict(lambda: datetime.min.replace(tzinfo=timezone.utc))
        self._active_views: dict[int, ReviewView] = {}
        self._views_lock: asyncio.Lock = asyncio.Lock()
        self._restore_task: asyncio.Task | None = None
        self._post_ban_sweep_tasks: set[asyncio.Task] = set()

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

    async def _is_joinwatch_active_role(
        self,
        guild: discord.Guild,
        member_id: int,
        role_id: int,
    ) -> bool:
        pending_roles = await self.config.guild(guild).joinwatch_pending_roles()
        pending_role = pending_roles.get(str(member_id))
        if pending_role is None:
            return False
        try:
            return int(pending_role["role_id"]) == role_id
        except (KeyError, TypeError, ValueError):
            return False

    async def _remove_review_mute_role(
        self,
        member: discord.Member,
        role: discord.Role,
        reason: str,
    ) -> bool:
        if await self._is_joinwatch_active_role(member.guild, member.id, role.id):
            return True
        try:
            await member.remove_roles(role, reason=reason)
        except discord.HTTPException:
            return False
        return True

    async def _store_joinwatch_pending_role(
        self,
        member: discord.Member,
        role_id: int,
        expires_at: datetime,
        applied_at: datetime | None = None,
        alert_channel_id: int | None = None,
        alert_message_id: int | None = None,
    ) -> None:
        pending_role = {
            "role_id": role_id,
            "applied_at": (applied_at or datetime.now(timezone.utc)).isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        if alert_channel_id is not None and alert_message_id is not None:
            pending_role["alert_channel_id"] = alert_channel_id
            pending_role["alert_message_id"] = alert_message_id
        async with self.config.guild(member.guild).joinwatch_pending_roles() as pending_roles:
            pending_roles[str(member.id)] = pending_role

    async def _delete_joinwatch_pending_role(self, guild: discord.Guild, member_id: int) -> None:
        async with self.config.guild(guild).joinwatch_pending_roles() as pending_roles:
            pending_roles.pop(str(member_id), None)

    async def _store_joinwatch_pending_role_alert(
        self,
        guild: discord.Guild,
        member_id: int,
        channel_id: int,
        message_id: int,
    ) -> None:
        async with self.config.guild(guild).joinwatch_pending_roles() as pending_roles:
            pending_role = pending_roles.get(str(member_id))
            if pending_role is None:
                return
            pending_role["alert_channel_id"] = channel_id
            pending_role["alert_message_id"] = message_id

    async def _store_joinwatch_pending_assignment(
        self,
        member: discord.Member,
        role_id: int,
        apply_at: datetime,
    ) -> None:
        async with self.config.guild(member.guild).joinwatch_pending_role_assignments() as pending_assignments:
            pending_assignments[str(member.id)] = {
                "role_id": role_id,
                "apply_at": apply_at.isoformat(),
            }

    async def _delete_joinwatch_pending_assignment(self, guild: discord.Guild, member_id: int) -> None:
        async with self.config.guild(guild).joinwatch_pending_role_assignments() as pending_assignments:
            pending_assignments.pop(str(member_id), None)

    async def _store_joinwatch_pending_assignment_alert(
        self,
        guild: discord.Guild,
        member_id: int,
        channel_id: int,
        message_id: int,
    ) -> None:
        async with self.config.guild(guild).joinwatch_pending_role_assignments() as pending_assignments:
            pending_assignment = pending_assignments.get(str(member_id))
            if pending_assignment is None:
                return
            pending_assignment["alert_channel_id"] = channel_id
            pending_assignment["alert_message_id"] = message_id

    async def _edit_joinwatch_alert_auto_role(
        self,
        guild: discord.Guild,
        pending_assignment: dict,
        value: str,
    ) -> None:
        channel_id = pending_assignment.get("alert_channel_id")
        message_id = pending_assignment.get("alert_message_id")
        if channel_id is None or message_id is None:
            return
        channel = self._get_text_channel_or_thread(guild, channel_id)
        if channel is None:
            return
        try:
            message = await channel.fetch_message(int(message_id))
        except (discord.HTTPException, discord.NotFound, discord.Forbidden, TypeError, ValueError):
            return
        if not message.embeds:
            return
        embed = discord.Embed.from_dict(message.embeds[0].to_dict())
        field_name = _("Auto-role:")
        legacy_field_name = _("Auto role:")
        for index, field in enumerate(embed.fields):
            if field.name in (field_name, legacy_field_name):
                embed.set_field_at(index, name=field_name, value=value, inline=field.inline)
                break
        else:
            embed.add_field(name=field_name, value=value, inline=False)
        try:
            await message.edit(embed=embed)
        except discord.HTTPException:
            log.debug("Failed to edit joinwatch alert message %s in guild %s", message_id, guild.id)

    def _joinwatch_next_retry(self, data: dict) -> int | None:
        try:
            retry_count = int(data.get("retry_count", 0)) + 1
        except (TypeError, ValueError):
            retry_count = 1
        return retry_count if retry_count <= JOINWATCH_MAX_RETRIES else None

    async def _reschedule_joinwatch_assignment_retry(
        self,
        guild: discord.Guild,
        member_id_str: str,
        data: dict,
        now: datetime,
        failure: str,
    ) -> bool:
        retry_count = self._joinwatch_next_retry(data)
        if retry_count is None:
            await self._edit_joinwatch_alert_auto_role(
                guild,
                data,
                _("Failed: {reason}\nNo more automatic retries.").format(reason=failure),
            )
            async with self.config.guild(guild).joinwatch_pending_role_assignments() as pending_assignments:
                pending_assignments.pop(member_id_str, None)
            return False
        retry_at = now + timedelta(minutes=JOINWATCH_RETRY_DELAY_MINUTES)
        async with self.config.guild(guild).joinwatch_pending_role_assignments() as pending_assignments:
            if member_id_str in pending_assignments:
                pending_assignments[member_id_str]["apply_at"] = retry_at.isoformat()
                pending_assignments[member_id_str]["retry_count"] = retry_count
        data["apply_at"] = retry_at.isoformat()
        data["retry_count"] = retry_count
        await self._edit_joinwatch_alert_auto_role(
            guild,
            data,
            _("Failed: {reason}\nRetrying {time} ({count}/{max}).").format(
                reason=failure,
                time=discord.utils.format_dt(retry_at, style="R"),
                count=retry_count,
                max=JOINWATCH_MAX_RETRIES,
            ),
        )
        return True

    async def _reschedule_joinwatch_role_retry(
        self,
        guild: discord.Guild,
        member_id_str: str,
        data: dict,
        now: datetime,
        failure: str,
    ) -> bool:
        retry_count = self._joinwatch_next_retry(data)
        if retry_count is None:
            await self._edit_joinwatch_alert_auto_role(
                guild,
                data,
                _("Failed: {reason}\nNo more automatic retries.").format(reason=failure),
            )
            async with self.config.guild(guild).joinwatch_pending_roles() as pending_roles:
                pending_roles.pop(member_id_str, None)
            return False
        retry_at = now + timedelta(minutes=JOINWATCH_RETRY_DELAY_MINUTES)
        async with self.config.guild(guild).joinwatch_pending_roles() as pending_roles:
            if member_id_str in pending_roles:
                pending_roles[member_id_str]["expires_at"] = retry_at.isoformat()
                pending_roles[member_id_str]["retry_count"] = retry_count
        data["expires_at"] = retry_at.isoformat()
        data["retry_count"] = retry_count
        await self._edit_joinwatch_alert_auto_role(
            guild,
            data,
            _("Failed: {reason}\nRetrying {time} ({count}/{max}).").format(
                reason=failure,
                time=discord.utils.format_dt(retry_at, style="R"),
                count=retry_count,
                max=JOINWATCH_MAX_RETRIES,
            ),
        )
        return True

    async def _reschedule_joinwatch_pending_roles(
        self,
        guild: discord.Guild,
        old_timer_minutes: int,
        new_timer_minutes: int,
    ) -> int:
        alert_updates: list[tuple[dict, int, datetime]] = []
        updated = 0
        async with self.config.guild(guild).joinwatch_pending_roles() as pending_roles:
            for data in pending_roles.values():
                try:
                    role_id = int(data["role_id"])
                    if data.get("applied_at") is not None:
                        applied_at = datetime.fromisoformat(data["applied_at"])
                    else:
                        old_expires_at = datetime.fromisoformat(data["expires_at"])
                        applied_at = old_expires_at - timedelta(minutes=old_timer_minutes)
                except (KeyError, TypeError, ValueError):
                    continue
                expires_at = applied_at + timedelta(minutes=new_timer_minutes)
                data["applied_at"] = applied_at.isoformat()
                data["expires_at"] = expires_at.isoformat()
                alert_updates.append((dict(data), role_id, expires_at))
                updated += 1
        for data, role_id, expires_at in alert_updates:
            role = guild.get_role(role_id)
            if role is None:
                continue
            await self._edit_joinwatch_alert_auto_role(
                guild,
                data,
                _("{role} applied until {time}.").format(
                    role=role.mention,
                    time=discord.utils.format_dt(expires_at, style="R"),
                ),
            )
        return updated

    async def _refresh_joinwatch_pending_role_alerts(
        self,
        guild: discord.Guild,
        timer_minutes: int,
    ) -> None:
        pending_roles = await self.config.guild(guild).joinwatch_pending_roles()
        for data in list(pending_roles.values()):
            try:
                role_id = int(data["role_id"])
                if data.get("applied_at") is not None:
                    applied_at = datetime.fromisoformat(data["applied_at"])
                    expires_at = applied_at + timedelta(minutes=timer_minutes)
                else:
                    expires_at = datetime.fromisoformat(data["expires_at"])
            except (KeyError, TypeError, ValueError):
                continue
            role = guild.get_role(role_id)
            if role is None:
                continue
            await self._edit_joinwatch_alert_auto_role(
                guild,
                data,
                _("{role} applied until {time}.").format(
                    role=role.mention,
                    time=discord.utils.format_dt(expires_at, style="R"),
                ),
            )

    async def _get_member_or_fetch(self, guild: discord.Guild, member_id: int) -> discord.Member | None:
        member = guild.get_member(member_id)
        if member is not None:
            return member
        try:
            return await guild.fetch_member(member_id)
        except (discord.HTTPException, discord.NotFound, discord.Forbidden):
            return None

    async def _get_user_or_object(self, user_id: int) -> discord.User | discord.Object:
        try:
            return await self.bot.fetch_user(user_id)
        except (discord.HTTPException, discord.NotFound, discord.Forbidden):
            return discord.Object(id=user_id)

    def _review_kick_fail_warning_mode(self, config: dict) -> str:
        value = str(config.get("review_kick_fail_warning", "false")).lower()
        return value if value in REVIEW_KICK_FAIL_WARNING_MODES else "false"

    def _automated_kick_fail_warning_enabled(self, config: dict) -> bool:
        return bool(config.get("automated_kick_fail_warning", False))

    async def _create_kick_fail_warning(
        self,
        guild: discord.Guild,
        user_id: int,
        *,
        moderator: typing.Any = None,
    ) -> tuple[str | None, str | None]:
        user = await self._get_user_or_object(user_id)
        try:
            await modlog.create_case(
                self.bot,
                guild,
                datetime.now(timezone.utc),
                action_type="warning",
                user=user,
                moderator=moderator or guild.me,
                reason=KICK_FAIL_WARNING_REASON,
            )
        except Exception:
            log.exception("Failed to create kick-fail warning case for user %s in guild %s", user_id, guild.id)
            return (None, _("I couldn't create a warning case."))
        return (_("Warning applied: suspicious kick avoidance."), None)

    def _joinwatch_kick_status_value(self, action_label: str | None, default: str) -> str:
        if action_label and action_label != _("The member has been kicked."):
            return action_label
        return default

    def _format_options(self, options: tuple[str, ...]) -> str:
        return ", ".join(f"`{option}`" for option in options)

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

    def _missing_channel_permissions(
        self,
        guild: discord.Guild,
        channel: discord.TextChannel | discord.Thread,
        *,
        read_history: bool = False,
        manage_messages: bool = False,
    ) -> str | None:
        me = guild.me
        if me is None:
            return _("I couldn't find my server member.")
        perms = channel.permissions_for(me)
        if not perms.view_channel:
            return _("I need `View Channel` in {channel}.").format(channel=channel.mention)
        if not perms.send_messages:
            return _("I need `Send Messages` in {channel}.").format(channel=channel.mention)
        if read_history and not perms.read_message_history:
            return _("I need `Read Message History` in {channel}.").format(channel=channel.mention)
        if manage_messages and not perms.manage_messages:
            return _("I need `Manage Messages` in {channel}.").format(channel=channel.mention)
        return None

    def _format_channel_setting(self, guild: discord.Guild, channel_id: int | None) -> str:
        channel = self._get_text_channel_or_thread(guild, channel_id)
        if channel is not None:
            return f"{channel.mention} ({channel.id})"
        return _("not set") if channel_id is None else _("missing ({id})").format(id=channel_id)

    def _honeypot_channel_ids_from_config(self, config: dict) -> list[int]:
        channel_ids: list[int] = []
        for channel_id in config.get("honeypot_channels") or []:
            if isinstance(channel_id, int) and channel_id not in channel_ids:
                channel_ids.append(channel_id)
        legacy_channel_id = config.get("honeypot_channel")
        if isinstance(legacy_channel_id, int) and legacy_channel_id not in channel_ids:
            channel_ids.append(legacy_channel_id)
        return channel_ids

    def _format_honeypot_channel_list(self, guild: discord.Guild, channel_ids: list[int]) -> str:
        if not channel_ids:
            return _("not set")
        return "\n".join(
            f"{index}. {self._format_channel_setting(guild, channel_id)}"
            for index, channel_id in enumerate(channel_ids, 1)
        )

    def _format_role_setting(self, guild: discord.Guild, role_id: int | None) -> str:
        role = guild.get_role(role_id) if role_id else None
        if role is not None:
            return f"{role.mention} ({role.id})"
        return _("not set") if role_id is None else _("missing ({id})").format(id=role_id)

    def _format_bool_setting(self, value: bool) -> str:
        return _("enabled") if value else _("disabled")

    async def _send_config_dump(
        self,
        ctx: commands.Context,
        title: str,
        entries: list[tuple[str, typing.Any]],
    ) -> None:
        lines = [f"{label}: {value}" for label, value in entries]
        await ctx.send(_("{title}:\n").format(title=title) + box("\n".join(lines)))

    def _dry_run_label(self, action: str) -> str:
        if action == "ban":
            return _("Dry run: I would ban this member.")
        if action == "kick":
            return _("Dry run: I would kick this member.")
        return _("Dry run: I would not take action.")

    @staticmethod
    def _ban_delete_message_seconds(config: dict) -> int:
        return ban_delete_message_seconds(config)

    def _missing_action_permission(self, guild: discord.Guild, action: str) -> str | None:
        me = guild.me
        if me is None:
            return _("**Failed:** I couldn't find my server member.")
        permissions = me.guild_permissions
        if action == "kick" and not permissions.kick_members:
            return _("**Failed:** I do not have the `Kick Members` permission.")
        if action == "ban" and not permissions.ban_members:
            return _("**Failed:** I do not have the `Ban Members` permission.")
        return None

    def _missing_role_assignment_permission(self, guild: discord.Guild, role: discord.Role) -> str | None:
        me = guild.me
        if me is None:
            return _("I couldn't find my server member.")
        if not me.guild_permissions.manage_roles:
            return _("I need `Manage Roles` permission to apply the joinwatch auto-role.")
        if me.top_role <= role:
            return _("My top role must be above the joinwatch auto-role.")
        return None

    async def _is_protected_member(self, member: discord.Member) -> bool:
        me = member.guild.me
        if me is None:
            return True
        return (
            member.id in self.bot.owner_ids
            or await self.bot.is_mod(member)
            or await self.bot.is_admin(member)
            or member.guild_permissions.manage_guild
            or member.top_role >= me.top_role
        )

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
                    "filename": _("More attachments"),
                    "url": None,
                    "size": 0,
                    "content_type": None,
                    "description": None,
                    "spoiler": False,
                    "data": None,
                    "error": _("{count} more attachments were not included; Discord only allows 10 files per message.").format(
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
        self.joinwatch_auto_role_loop.start()
        self._restore_task = asyncio.create_task(self._restore_pending_reviews())

    async def cog_unload(self) -> None:
        self.fake_activity_loop.cancel()
        self.review_timeout_loop.cancel()
        self.joinwatch_auto_role_loop.cancel()
        if self._restore_task is not None:
            self._restore_task.cancel()
        pending_sweeps = tuple(self._post_ban_sweep_tasks)
        for task in pending_sweeps:
            task.cancel()
        if pending_sweeps:
            await asyncio.gather(*pending_sweeps, return_exceptions=True)
        self._post_ban_sweep_tasks.clear()
        await super().cog_unload()

    # ─── Fake Activity Loop ───────────────────────────────────────────────

    @tasks.loop(minutes=1)
    async def fake_activity_loop(self) -> None:
        now = datetime.now(timezone.utc)
        for guild in self.bot.guilds:
            try:
                config = await self.config.guild(guild).all()
                if not config["enabled"] or not config["fake_activity_enabled"]:
                    continue
                honeypot_channels = [
                    channel
                    for channel_id in self._honeypot_channel_ids_from_config(config)
                    if (channel := self._get_text_channel_or_thread(guild, channel_id)) is not None
                ]
                if not honeypot_channels:
                    continue
                interval = config["fake_activity_interval"]
                last = self._last_fake_message[guild.id]
                if (now - last).total_seconds() < interval * 60:
                    continue
                custom_msgs: list[str] = config.get("fake_activity_messages", [])
                pool = custom_msgs if custom_msgs else DEFAULT_FAKE_MESSAGES
                msg = random.choice(pool)
                honeypot_channel = random.choice(honeypot_channels)
                await honeypot_channel.send(msg)
                self._last_fake_message[guild.id] = now
            except asyncio.CancelledError:
                raise
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
        try:
            all_guilds = await self.config.all_guilds()
        except Exception:
            log.exception("Failed to load guild configs during review restoration")
            return
        now = datetime.now(timezone.utc)
        for guild_id, guild_config in all_guilds.items():
            try:
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
                    if expires_at <= now and await self._expire_review(view):
                        continue
                    self.bot.add_view(view, message_id=int(review_message_id))
                    async with self._views_lock:
                        self._active_views[int(review_message_id)] = view
            except Exception:
                log.exception("Failed to restore pending reviews for guild %s", guild_id)

    async def _expire_review(self, view: ReviewView) -> bool:
        if not await view._claim_resolution():
            return True
        guild = self.bot.get_guild(view.guild_id)
        if guild is None:
            async with self._views_lock:
                self._active_views.pop(view.active_key or view.target_id, None)
            view.stop()
            return True
        member = guild.get_member(view.target_id)
        if member is not None and view.pending_mute_role_id is not None:
            mute_role = guild.get_role(view.pending_mute_role_id)
            if mute_role is not None and mute_role in member.roles:
                removed = await self._remove_review_mute_role(
                    member,
                    mute_role,
                    "Honeypot review expired; removing pending mute.",
                )
                if not removed:
                    log.debug("Failed to remove mute role on expired review for user %s in guild %s", view.target_id, guild.id)
                    view.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
                    async with self.config.guild(guild).pending_reviews() as pending_reviews:
                        pending_review = pending_reviews.get(str(view.active_key))
                        if pending_review is not None:
                            pending_review["expires_at"] = view.expires_at.isoformat()
                    await view._release_resolution()
                    return False
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
                await view.review_message.edit(content=_("✅ **Review expired**"), embed=embed, view=view)
            except discord.HTTPException:
                log.debug("Failed to edit expired review message %s", view.active_key)
        await self._increment_stat(guild, "review_expired")
        await self._increment_stat(guild, "ignored")
        async with self._views_lock:
            self._active_views.pop(view.active_key or view.target_id, None)
        await self._delete_pending_review(guild, view.active_key)
        view.stop()
        return True

    # ─── Detection ────────────────────────────────────────────────────────

    async def _suspicion_reasons(self, message: discord.Message, config: dict) -> list[str]:
        reasons: list[str] = []
        content = message.content.lower()
        if message.author.created_at > datetime.now(timezone.utc) - timedelta(days=7):
            reasons.append(_("Account is under 7 days old"))
        scam_keywords = config.get("scam_keywords") or SCAM_KEYWORDS
        matched_keywords = [kw for kw in scam_keywords if kw.lower() in content]
        if matched_keywords:
            reasons.append(_("Matched keywords: {keywords}").format(keywords=", ".join(matched_keywords[:5])))
        if message.attachments and message.author.created_at > datetime.now(timezone.utc) - timedelta(days=14):
            reasons.append(_("Attachment from an account under 14 days old"))
        attachment_patterns = config.get("attachment_patterns") or DEFAULT_ATTACHMENT_PATTERNS
        filename_bases = [attachment.filename.rsplit(".", 1)[0].lower() for attachment in message.attachments]
        generic_attachment_count = sum(1 for filename_base in filename_bases if GENERIC_ATTACHMENT_NAME_RE.fullmatch(filename_base))
        if generic_attachment_count >= 2:
            reasons.append(_("Multiple generic attachment names: {count}").format(count=generic_attachment_count))
        matched_patterns: list[str] = []
        matched_attachment_indexes: set[int] = set()
        for pattern in attachment_patterns:
            try:
                matches = [
                    index
                    for index, filename_base in enumerate(filename_bases)
                    if re.fullmatch(pattern, filename_base, flags=re.IGNORECASE)
                ]
            except re.error:
                continue
            if matches:
                matched_attachment_indexes.update(matches)
                matched_patterns.append(pattern)
        if len(matched_attachment_indexes) >= 2 and matched_patterns:
            reasons.append(_("Matched attachment rules: {patterns}").format(patterns=", ".join(matched_patterns[:3])))
        return reasons

    def _iter_message_channels(
        self, guild: discord.Guild
    ) -> typing.Iterator[typing.Any]:
        me = guild.me
        if me is None:
            return
        for channel in guild.channels:
            if not is_purgeable_message_channel(channel):
                continue
            perms = channel.permissions_for(me)
            if not missing_channel_purge_permissions(channel, perms):
                yield channel
        for thread in guild.threads:
            perms = thread.permissions_for(me)
            if not missing_channel_purge_permissions(thread, perms):
                yield thread

    async def _purge_user_messages(
        self,
        channel: typing.Any,
        author_id: int,
        minutes: int,
        *,
        limit: int = 200,
    ) -> int:
        after = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        try:
            deleted = await channel.purge(
                limit=limit,
                after=after,
                check=lambda m: m.author.id == author_id,
                bulk=True,
            )
            return len(deleted)
        except (discord.HTTPException, discord.Forbidden) as exc:
            log.debug(
                "Failed to purge messages for user %s in channel %s (%s): %r",
                author_id,
                getattr(channel, "id", "unknown"),
                getattr(channel, "name", "unknown"),
                exc,
            )
            return 0

    async def _sweep_user_messages_guild(
        self, guild: discord.Guild, user_id: int, minutes: int
    ) -> int:
        total = 0
        for channel in self._iter_message_channels(guild):
            deleted = await self._purge_user_messages(
                channel,
                user_id,
                minutes,
                limit=POST_BAN_SWEEP_PER_CHANNEL_LIMIT,
            )
            total += deleted
            if deleted > 0:
                await asyncio.sleep(POST_BAN_SWEEP_CHANNEL_COOLDOWN_SECONDS)
        return total

    def _schedule_post_ban_sweep_if_enabled(
        self, guild: discord.Guild, user_id: int, config: dict
    ) -> None:
        """After ban: wait, then purge this user's recent messages on accessible channels."""
        if ban_delete_message_days(config) <= 0:
            return
        task = self.bot.loop.create_task(
            self._post_ban_message_sweep(
                guild.id, user_id, POST_BAN_SWEEP_LOOKBACK_MINUTES
            ),
            name=f"honeypot-post-ban-sweep-{guild.id}-{user_id}",
        )
        self._post_ban_sweep_tasks.add(task)
        task.add_done_callback(self._post_ban_sweep_tasks.discard)

    async def _post_ban_message_sweep(
        self, guild_id: int, user_id: int, lookback_minutes: int
    ) -> None:
        try:
            await asyncio.sleep(POST_BAN_SWEEP_DELAY_SECONDS)
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                return
            deleted = await self._sweep_user_messages_guild(
                guild, user_id, lookback_minutes
            )
            if deleted:
                await self._increment_stat(guild, "purged_messages", deleted)
        except Exception:
            log.exception(
                "Post-ban message sweep failed for user %s in guild %s",
                user_id,
                guild_id,
            )

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
                try:
                    await message.author.kick(reason=reason)
                except discord.NotFound:
                    if self._automated_kick_fail_warning_enabled(config):
                        return await self._create_kick_fail_warning(message.guild, message.author.id)
                    raise
                await self._increment_stat(message.guild, "kicked")
            elif action == "ban":
                await message.author.ban(
                    reason=reason,
                    delete_message_seconds=self._ban_delete_message_seconds(config),
                )
                self._schedule_post_ban_sweep_if_enabled(
                    message.guild, message.author.id, config
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
        logs_channel: discord.TextChannel | discord.Thread | None,
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
                        reason="Automated account status update.",
                    )
                    pending_mute_role_id = mute_role.id
                    await self._increment_stat(message.guild, "pending_mutes")
                    embed.add_field(
                        name=_("Pending review mute:"),
                        value=_("Temporary mute applied while the review is pending."),
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
            name=_("Review expires in:"),
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
        if logs_channel is not None:
            try:
                await logs_channel.send(
                    _("Queued for review: {user} ({user_id}) in {channel}.").format(
                        user=message.author.mention,
                        user_id=message.author.id,
                        channel=review_channel.mention,
                    ),
                    allowed_mentions=discord.AllowedMentions.none(),
                )
            except discord.HTTPException:
                log.debug("Failed to send queued review log in guild %s", message.guild.id)

    async def _send_log(
        self,
        channel: discord.TextChannel | discord.Thread | None,
        embed: discord.Embed,
        attachment_snapshots: list[dict[str, typing.Any]],
        content: str | None = None,
        allowed_mentions: discord.AllowedMentions | None = None,
    ) -> None:
        if channel is None:
            return
        send_kwargs: dict[str, typing.Any] = {"content": content, "embed": embed}
        if allowed_mentions is not None:
            send_kwargs["allowed_mentions"] = allowed_mentions
        files = self._attachment_files(attachment_snapshots)
        if files:
            send_kwargs["files"] = files
        try:
            await channel.send(**send_kwargs)
        except discord.HTTPException:
            guild_id = channel.guild.id if isinstance(channel, discord.TextChannel) else channel.guild.id
            log.debug("Failed to send honeypot log in guild %s", guild_id)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None:
            return
        if await self.bot.cog_disabled_in_guild(self, message.guild):
            return
        if message.author.bot:
            return
        config = await self.config.guild(message.guild).all()
        configured_honeypot_channel_ids = self._honeypot_channel_ids_from_config(config)
        if message.channel.id not in configured_honeypot_channel_ids:
            return
        if not config["enabled"]:
            return
        logs_channel = self._get_text_channel_or_thread(message.guild, config.get("logs_channel"))
        if await self._is_protected_member(message.author):
            return

        attachment_snapshots = await self._snapshot_attachments(message)

        try:
            await message.delete()
        except discord.HTTPException:
            log.debug("Failed to delete honeypot message from user %s", message.author.id)
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

        # Purge - always runs before any action/review
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
        second_strike_role_ids = {
            role_id
            for role_id in (
                config.get("mute_role"),
                config.get("joinwatch_auto_role_id"),
            )
            if role_id
        }
        second_strike = bool(second_strike_role_ids) and any(
            role.id in second_strike_role_ids for role in message.author.roles
        )
        if second_strike:
            suspicion_reasons.append(_("Repeat honeypot activity"))
        suspicious = bool(suspicion_reasons)
        if suspicion_reasons:
            await self._increment_stat(message.guild, "suspicious")
            embed.add_field(
                name=_("Trigger reasons:"),
                value="\n".join(f"- {reason}" for reason in suspicion_reasons),
                inline=False,
            )

        review_channel = None
        if config.get("review_channel") is not None:
            review_channel = self._get_text_channel_or_thread(message.guild, config["review_channel"])
        action = config.get("action")
        fallback_action = config.get("fallback_action", "review")
        if second_strike and not force_review and not force_fallback:
            action_label, failed = await self._execute_action(
                message,
                config,
                reason="Suspicious Activity",
                action="ban",
            )
            embed.add_field(name=_("Action:"), value=failed if failed else action_label, inline=False)
            if failed:
                embed.color = discord.Color.dark_red()
                embed.add_field(name=_("Staff check needed:"), value=_("Second strike action failed."), inline=False)
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
            return
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
                    reason="Suspicious message in the honeypot channel.",
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
                    reason="Message in the honeypot channel without a matching scam pattern.",
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

    async def _execute_joinwatch_action(
        self,
        guild: discord.Guild,
        member: discord.Member | None,
        member_id: int,
        config: dict,
        reason: str,
    ) -> tuple[str | None, str | None]:
        action = config.get("joinwatch_auto_role_action", "none")
        if action not in ("kick", "ban"):
            return (_("No joinwatch punishment configured."), None)
        if config.get("dry_run"):
            await self._increment_stat(guild, "dry_run_actions")
            return (self._dry_run_label(action), None)
        missing_permission = self._missing_action_permission(guild, action)
        if missing_permission is not None:
            await self._increment_stat(guild, "failed_actions")
            return (None, missing_permission)
        try:
            if action == "kick":
                if member is None:
                    if self._automated_kick_fail_warning_enabled(config):
                        return await self._create_kick_fail_warning(guild, member_id)
                    return (_("The member is no longer in the server."), None)
                try:
                    await member.kick(reason=reason)
                except discord.NotFound:
                    if self._automated_kick_fail_warning_enabled(config):
                        return await self._create_kick_fail_warning(guild, member_id)
                    raise
            elif action == "ban":
                target = member if member is not None else await self._get_user_or_object(member_id)
                await guild.ban(
                    target,
                    reason=reason,
                    delete_message_seconds=self._ban_delete_message_seconds(config),
                )
                self._schedule_post_ban_sweep_if_enabled(guild, target.id, config)
            await self._increment_stat(guild, "joinwatch_auto_role_punishments")
        except discord.HTTPException as exc:
            await self._increment_stat(guild, "failed_actions")
            return (None, _("**Action failed:**\n") + box(str(exc), lang="py"))
        user = member if member is not None else await self._get_user_or_object(member_id)
        try:
            await modlog.create_case(
                self.bot,
                guild,
                datetime.now(timezone.utc),
                action_type=action,
                user=user,
                moderator=guild.me,
                reason=reason,
            )
        except Exception:
            log.exception("Failed to create modlog case in _execute_joinwatch_action")
        label = _("The member has been kicked.") if action == "kick" else _("The member has been banned.")
        return (label, None)

    @tasks.loop(minutes=1)
    async def joinwatch_auto_role_loop(self) -> None:
        now = datetime.now(timezone.utc)
        for guild in self.bot.guilds:
            try:
                config = await self.config.guild(guild).all()
                pending_assignments = config.get("joinwatch_pending_role_assignments", {})
                pending_roles = config.get("joinwatch_pending_roles", {})
                if pending_assignments and not config.get("joinwatch_auto_role_enabled", False):
                    async with self.config.guild(guild).joinwatch_pending_role_assignments() as stored_assignments:
                        stored_assignments.clear()
                    pending_assignments = {}
                if not pending_assignments and not pending_roles:
                    continue
                logs_channel = self._get_text_channel_or_thread(guild, config.get("logs_channel"))
                for member_id_str, data in list(pending_assignments.items()):
                    try:
                        member_id = int(member_id_str)
                        role_id = int(data["role_id"])
                        apply_at = datetime.fromisoformat(data["apply_at"])
                    except (KeyError, TypeError, ValueError):
                        async with self.config.guild(guild).joinwatch_pending_role_assignments() as stored_assignments:
                            stored_assignments.pop(str(member_id_str), None)
                        continue
                    if apply_at > now:
                        continue
                    member = await self._get_member_or_fetch(guild, member_id)
                    role = guild.get_role(role_id)
                    if member is None:
                        action_label, failed = await self._execute_joinwatch_action(
                            guild,
                            None,
                            member_id,
                            config,
                            reason="Suspicious Account",
                        )
                        if failed:
                            await self._reschedule_joinwatch_assignment_retry(
                                guild,
                                member_id_str,
                                data,
                                now,
                                failed,
                            )
                            continue
                        if config.get("joinwatch_auto_role_action") == "ban":
                            await self._edit_joinwatch_alert_auto_role(guild, data, _("Banned."))
                        elif config.get("joinwatch_auto_role_action") == "kick":
                            await self._edit_joinwatch_alert_auto_role(
                                guild,
                                data,
                                self._joinwatch_kick_status_value(action_label, _("Left server.")),
                            )
                        else:
                            await self._edit_joinwatch_alert_auto_role(guild, data, _("Auto-role timer expired."))
                        await self._delete_joinwatch_pending_assignment(guild, member_id)
                        if logs_channel is not None:
                            embed = discord.Embed(
                                title=_("Joinwatch auto-role timer expired"),
                                description=_("{mention} ({id}) left before the scheduled role could be applied.").format(
                                    mention=f"<@{member_id}>",
                                    id=member_id,
                                ),
                                color=discord.Color.dark_red() if failed else discord.Color.orange(),
                                timestamp=now,
                            )
                            embed.add_field(
                                name=_("Action:"),
                                value=failed if failed else action_label,
                                inline=False,
                            )
                            try:
                                await logs_channel.send(embed=embed)
                            except discord.HTTPException:
                                log.debug(
                                    "Failed to send joinwatch missing-member log for user %s in guild %s",
                                    member_id,
                                    guild.id,
                                )
                        continue
                    if role is None:
                        await self._delete_joinwatch_pending_assignment(guild, member_id)
                        continue
                    if await self._is_protected_member(member):
                        await self._delete_joinwatch_pending_assignment(guild, member_id)
                        continue
                    role_permission_error = self._missing_role_assignment_permission(guild, role)
                    if role_permission_error is not None:
                        await self._increment_stat(guild, "joinwatch_auto_role_failures")
                        await self._reschedule_joinwatch_assignment_retry(
                            guild,
                            member_id_str,
                            data,
                            now,
                            role_permission_error,
                        )
                        continue
                    if role not in member.roles:
                        try:
                            await member.add_roles(role, reason="Automated account status update.")
                            await self._increment_stat(guild, "joinwatch_auto_roles")
                        except discord.HTTPException:
                            await self._increment_stat(guild, "joinwatch_auto_role_failures")
                            await self._reschedule_joinwatch_assignment_retry(
                                guild,
                                member_id_str,
                                data,
                                now,
                                _("I couldn't apply the configured joinwatch auto-role."),
                            )
                            continue
                    expires_at = now + timedelta(
                        minutes=config.get("joinwatch_auto_role_timer_minutes", 1440)
                    )
                    await self._store_joinwatch_pending_role(
                        member,
                        role.id,
                        expires_at,
                        applied_at=now,
                        alert_channel_id=data.get("alert_channel_id"),
                        alert_message_id=data.get("alert_message_id"),
                    )
                    await self._edit_joinwatch_alert_auto_role(
                        guild,
                        data,
                        _("{role} applied until {time}.").format(
                            role=role.mention,
                            time=discord.utils.format_dt(expires_at, style="R"),
                        ),
                    )
                    await self._delete_joinwatch_pending_assignment(guild, member_id)
                for member_id_str, data in list(pending_roles.items()):
                    try:
                        member_id = int(member_id_str)
                        role_id = int(data["role_id"])
                    except (KeyError, TypeError, ValueError):
                        async with self.config.guild(guild).joinwatch_pending_roles() as stored_pending_roles:
                            stored_pending_roles.pop(str(member_id_str), None)
                        continue
                    try:
                        expires_at = datetime.fromisoformat(data["expires_at"])
                    except (KeyError, TypeError, ValueError):
                        async with self.config.guild(guild).joinwatch_pending_roles() as stored_pending_roles:
                            stored_pending_roles.pop(str(member_id_str), None)
                        continue
                    if expires_at > now:
                        continue
                    member = await self._get_member_or_fetch(guild, member_id)
                    role = guild.get_role(role_id)
                    if member is None:
                        action_label, failed = await self._execute_joinwatch_action(
                            guild,
                            None,
                            member_id,
                            config,
                            reason="Suspicious Account",
                        )
                        if failed:
                            await self._reschedule_joinwatch_role_retry(
                                guild,
                                member_id_str,
                                data,
                                now,
                                failed,
                            )
                        else:
                            if config.get("joinwatch_auto_role_action") == "ban":
                                await self._edit_joinwatch_alert_auto_role(guild, data, _("Banned."))
                            elif config.get("joinwatch_auto_role_action") == "kick":
                                await self._edit_joinwatch_alert_auto_role(
                                    guild,
                                    data,
                                    self._joinwatch_kick_status_value(action_label, _("Left server.")),
                                )
                            else:
                                await self._edit_joinwatch_alert_auto_role(guild, data, _("Auto-role timer expired."))
                            await self._delete_joinwatch_pending_role(guild, member_id)
                        if logs_channel is not None:
                            embed = discord.Embed(
                                title=_("Joinwatch auto-role timer expired"),
                                description=_("{mention} ({id}) left before the auto-role timer expired.").format(
                                    mention=f"<@{member_id}>",
                                    id=member_id,
                                ),
                                color=discord.Color.dark_red() if failed else discord.Color.orange(),
                                timestamp=now,
                            )
                            embed.add_field(
                                name=_("Action:"),
                                value=failed if failed else action_label,
                                inline=False,
                            )
                            try:
                                await logs_channel.send(embed=embed)
                            except discord.HTTPException:
                                log.debug(
                                    "Failed to send joinwatch missing-member log for user %s in guild %s",
                                    member_id,
                                    guild.id,
                                )
                        continue
                    if role is None:
                        await self._delete_joinwatch_pending_role(guild, member_id)
                        continue
                    if role not in member.roles:
                        await self._edit_joinwatch_alert_auto_role(
                            guild,
                            data,
                            _("Role manually removed."),
                        )
                        await self._delete_joinwatch_pending_role(guild, member_id)
                        await self._increment_stat(guild, "joinwatch_auto_roles_cleared")
                        continue
                    if await self._is_protected_member(member):
                        await self._delete_joinwatch_pending_role(guild, member_id)
                        continue
                    action_label, failed = await self._execute_joinwatch_action(
                        guild,
                        member,
                        member_id,
                        config,
                        reason="Suspicious Account",
                    )
                    if failed:
                        await self._reschedule_joinwatch_role_retry(
                            guild,
                            member_id_str,
                            data,
                            now,
                            failed,
                        )
                    else:
                        if config.get("joinwatch_auto_role_action") == "ban":
                            await self._edit_joinwatch_alert_auto_role(guild, data, _("Banned."))
                        elif config.get("joinwatch_auto_role_action") == "kick":
                            await self._edit_joinwatch_alert_auto_role(
                                guild,
                                data,
                                self._joinwatch_kick_status_value(action_label, _("Kicked.")),
                            )
                        else:
                            await self._edit_joinwatch_alert_auto_role(guild, data, _("Auto-role timer expired."))
                        await self._delete_joinwatch_pending_role(guild, member_id)
                    if logs_channel is not None:
                        embed = discord.Embed(
                            title=_("Joinwatch auto-role timer expired"),
                            description=_("{mention} ({id}) still had {role} when the timer expired.").format(
                                mention=member.mention,
                                id=member.id,
                                role=role.mention if role is not None else _("the auto-role"),
                            ),
                            color=discord.Color.dark_red() if failed else discord.Color.orange(),
                            timestamp=now,
                        )
                        embed.add_field(
                            name=_("Action:"),
                            value=failed if failed else action_label,
                            inline=False,
                        )
                        try:
                            await logs_channel.send(embed=embed)
                        except discord.HTTPException:
                            log.debug("Failed to send joinwatch auto-role log for user %s in guild %s", member.id, guild.id)
            except Exception:
                log.exception("Failed to process joinwatch auto-role timers for guild %s", guild.id)

    @joinwatch_auto_role_loop.before_loop
    async def before_joinwatch_auto_role(self) -> None:
        await self.bot.wait_until_red_ready()

    # ─── New account join alert ────────────────────────────────────────

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        if await self.bot.cog_disabled_in_guild(self, member.guild):
            return
        if member.bot:
            return
        config = await self.config.guild(member.guild).all()
        if not config["joinwatch_enabled"]:
            return
        await self._increment_stat(member.guild, "joinwatch_total_joins")
        channel = self._get_text_channel_or_thread(member.guild, config["joinwatch_channel"])
        now = datetime.now(timezone.utc)
        min_age = timedelta(hours=config["joinwatch_min_age_hours"])
        if member.created_at > now - min_age:
            await self._increment_stat(member.guild, "joinwatch_young_joins")
            hours = max(1, round((now - member.created_at).total_seconds() / 3600))
            member_label = f"{member.display_name} ({member})"
            embed = discord.Embed(
                title=_("New account joined"),
                description=_("**{member}**\nMention: {mention}\nID: `{id}`\nAccount is ~{hours} hours old.").format(
                    member=member_label, mention=member.mention, id=member.id, hours=hours,
                ),
                color=discord.Color.orange(),
                timestamp=member.joined_at or now,
            )
            embed.set_author(name=f"{member.display_name} ({member.id})", icon_url=member.display_avatar)
            embed.set_thumbnail(url=member.display_avatar)
            if config.get("joinwatch_auto_role_enabled") and config.get("joinwatch_auto_role_id") is not None:
                role = member.guild.get_role(config["joinwatch_auto_role_id"])
                if role is not None and role not in member.roles and not await self._is_protected_member(member):
                    role_permission_error = self._missing_role_assignment_permission(member.guild, role)
                    if role_permission_error is not None:
                        await self._increment_stat(member.guild, "joinwatch_auto_role_failures")
                        embed.add_field(
                            name=_("Auto-role:"),
                            value=role_permission_error,
                            inline=False,
                        )
                    else:
                        if config.get("joinwatch_auto_role_random_delay_enabled", False):
                            min_delay = max(1, int(config.get("joinwatch_auto_role_random_delay_min_minutes", 1)))
                            max_delay = max(
                                min_delay,
                                int(config.get("joinwatch_auto_role_random_delay_max_minutes", 10)),
                            )
                            delay_minutes = random.randint(min_delay, max_delay)
                            apply_at = now + timedelta(minutes=delay_minutes)
                            await self._store_joinwatch_pending_assignment(member, role.id, apply_at)
                            await self._increment_stat(member.guild, "joinwatch_auto_roles_scheduled")
                            embed.add_field(
                                name=_("Auto-role:"),
                                value=_("{role} scheduled for {time}.").format(
                                    role=role.mention,
                                    time=discord.utils.format_dt(apply_at, style="R"),
                                ),
                                inline=False,
                            )
                        else:
                            try:
                                await member.add_roles(role, reason="Automated account status update.")
                                await self._increment_stat(member.guild, "joinwatch_auto_roles")
                                expires_at = now + timedelta(
                                    minutes=config.get("joinwatch_auto_role_timer_minutes", 1440)
                                )
                                await self._store_joinwatch_pending_role(
                                    member,
                                    role.id,
                                    expires_at,
                                    applied_at=now,
                                )
                                embed.add_field(
                                    name=_("Auto-role:"),
                                    value=_("{role} applied until {time}.").format(
                                        role=role.mention,
                                        time=discord.utils.format_dt(expires_at, style="R"),
                                    ),
                                    inline=False,
                                )
                            except discord.HTTPException:
                                await self._increment_stat(member.guild, "joinwatch_auto_role_failures")
                                embed.add_field(
                                    name=_("Auto-role:"),
                                    value=_("I couldn't apply the configured joinwatch auto-role."),
                                    inline=False,
                                )
            if config.get("joinwatch_alert_enabled", True) and channel is not None:
                try:
                    alert_message = await channel.send(embed=embed)
                    if config.get("joinwatch_auto_role_random_delay_enabled", False):
                        await self._store_joinwatch_pending_assignment_alert(
                            member.guild,
                            member.id,
                            alert_message.channel.id,
                            alert_message.id,
                        )
                    else:
                        await self._store_joinwatch_pending_role_alert(
                            member.guild,
                            member.id,
                            alert_message.channel.id,
                            alert_message.id,
                        )
                except discord.HTTPException:
                    log.debug("Failed to send joinwatch alert for user %s in guild %s", member.id, member.guild.id)

    # ─── Baited role trap ─────────────────────────────────────────────

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member) -> None:
        if await self.bot.cog_disabled_in_guild(self, after.guild):
            return
        if after.bot:
            return
        config = await self.config.guild(after.guild).all()
        pending_roles = config.get("joinwatch_pending_roles", {})
        pending_role = pending_roles.get(str(after.id))
        if pending_role is not None:
            try:
                pending_role_id = int(pending_role["role_id"])
            except (KeyError, TypeError, ValueError):
                await self._delete_joinwatch_pending_role(after.guild, after.id)
            else:
                role_removed = any(role.id == pending_role_id for role in before.roles) and not any(
                    role.id == pending_role_id for role in after.roles
                )
                if role_removed:
                    await self._edit_joinwatch_alert_auto_role(
                        after.guild,
                        pending_role,
                        _("Role manually removed."),
                    )
                    await self._delete_joinwatch_pending_role(after.guild, after.id)
                    await self._increment_stat(after.guild, "joinwatch_auto_roles_cleared")
        if not config["baitrole_enabled"] or config["baitrole_id"] is None:
            return
        bait_role = after.guild.get_role(config["baitrole_id"])
        if bait_role is None:
            return
        if bait_role not in before.roles and bait_role in after.roles:
            if await self._is_protected_member(after):
                return
            action = config["baitrole_action"]
            reason = "Took the bait role - potential DM bot/scammer."
            try:
                if action == "ban":
                    await after.ban(
                        reason=reason,
                        delete_message_seconds=self._ban_delete_message_seconds(config),
                    )
                    self._schedule_post_ban_sweep_if_enabled(
                        after.guild, after.id, config
                    )
                    await self._increment_stat(after.guild, "banned")
                elif action == "kick":
                    await after.kick(reason=reason)
                    await self._increment_stat(after.guild, "kicked")
            except discord.HTTPException:
                log.warning("Failed to %s bait-role target %s in guild %s", action, after.id, after.guild.id)
            logs_channel_id = config.get("logs_channel")
            logs_channel = self._get_text_channel_or_thread(after.guild, logs_channel_id)
            if logs_channel is not None:
                embed = discord.Embed(
                    title=_("Bait role triggered"),
                    description=_("{mention} ({id}) took the bait role and was {action}.").format(
                        mention=after.mention, id=after.id, action=action,
                    ),
                    color=discord.Color.dark_red(),
                    timestamp=datetime.now(timezone.utc),
                )
                embed.set_thumbnail(url=after.display_avatar)
                try:
                    await logs_channel.send(embed=embed)
                except discord.HTTPException:
                    log.debug("Failed to send bait role log for user %s in guild %s", after.id, after.guild.id)

    # ─── Commands ─────────────────────────────────────────────────────────

    @commands.guild_only()
    @commands.permissions_check(lambda ctx: ctx.author.id == ctx.guild.owner_id or ctx.author.id in ctx.bot.owner_ids)
    @commands.group()
    async def honeypot(self, ctx: commands.Context) -> None:
        """Configure the honeypot system."""

    # ─── core sub-group ───────────────────────────────────────────────

    @honeypot.group()
    async def core(self, ctx: commands.Context) -> None:
        """Core settings: enabled, action, fallback, dry run."""

    @core.command(name="toggle")
    async def core_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable the cog."""
        if value is None:
            v = await self.config.guild(ctx.guild).enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).enabled.set(value)
            await ctx.send(_("✅ Enabled set to {value}").format(value=value))

    @core.command()
    async def action(self, ctx: commands.Context, value: str = None) -> None:
        """Main action for suspicious users: kick, ban, review, or none."""
        if value is None:
            v = await self.config.guild(ctx.guild).action()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=v or _("not set"),
                    options=self._format_options(CORE_ACTION_OPTIONS),
                )
            )
        elif value not in CORE_ACTION_OPTIONS:
            await ctx.send(_("Choose one of: {options}").format(options=self._format_options(CORE_ACTION_OPTIONS)))
        else:
            await self.config.guild(ctx.guild).action.set(value)
            await ctx.send(_("✅ Action set to {value}").format(value=value))

    @core.command(name="fallback_action")
    async def fallback_action(self, ctx: commands.Context, value: str = None) -> None:
        """Fallback: review, kick, ban, or none."""
        if value is None:
            v = await self.config.guild(ctx.guild).fallback_action()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=v,
                    options=self._format_options(FALLBACK_ACTION_OPTIONS),
                )
            )
        elif value not in FALLBACK_ACTION_OPTIONS:
            await ctx.send(_("Choose one of: {options}").format(options=self._format_options(FALLBACK_ACTION_OPTIONS)))
        else:
            await self.config.guild(ctx.guild).fallback_action.set(value)
            await ctx.send(_("✅ Fallback action set to {value}").format(value=value))

    @core.command(name="dry_run")
    async def dry_run(self, ctx: commands.Context, value: bool = None) -> None:
        """Log actions without actually punishing users."""
        if value is None:
            v = await self.config.guild(ctx.guild).dry_run()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).dry_run.set(value)
            await ctx.send(_("✅ Dry run set to {value}").format(value=value))

    @core.command(name="whitelist_mode")
    async def whitelist_mode(self, ctx: commands.Context, value: str = None) -> None:
        """How whitelisted roles behave: bypass, review, fallback, or none."""
        if value is None:
            v = await self.config.guild(ctx.guild).whitelist_mode()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=v,
                    options=self._format_options(WHITELIST_MODE_OPTIONS),
                )
            )
        elif value not in WHITELIST_MODE_OPTIONS:
            await ctx.send(_("Choose one of: {options}").format(options=self._format_options(WHITELIST_MODE_OPTIONS)))
        else:
            await self.config.guild(ctx.guild).whitelist_mode.set(value)
            await ctx.send(_("✅ Whitelist mode set to {value}").format(value=value))

    @core.command(name="automated_kick_fail_warn")
    async def automated_kick_fail_warn(self, ctx: commands.Context, value: bool = None) -> None:
        """Warn when the target has already left before the kick is applied."""
        if value is None:
            v = await self.config.guild(ctx.guild).automated_kick_fail_warning()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).automated_kick_fail_warning.set(value)
            await ctx.send(_("✅ Warn on automated kick fail set to {value}").format(value=value))

    # ─── channel sub-group ────────────────────────────────────────────

    @honeypot.group(name="channel")
    async def channels(self, ctx: commands.Context) -> None:
        """Honeypot channel, logs channel, ping role."""

    @commands.bot_has_guild_permissions(manage_channels=True)
    @channels.command()
    async def create(self, ctx: commands.Context) -> None:
        """Create the honeypot channel."""
        me = ctx.guild.me
        if me is None:
            raise commands.UserFeedbackCheckFailure(_("I couldn't find my server member."))
        honeypot_channel = await ctx.guild.create_text_channel(
            name="honeypot",
            position=0,
            overwrites={
                me: discord.PermissionOverwrite(
                    view_channel=True, read_messages=True, send_messages=True,
                    manage_messages=True, manage_channels=True,
                ),
                ctx.guild.default_role: discord.PermissionOverwrite(
                    view_channel=True, read_messages=True, send_messages=True,
                ),
            },
            reason=_("Honeypot channel requested by {author}.").format(author=ctx.author),
        )
        async with self.config.guild(ctx.guild).honeypot_channels() as channel_ids:
            if honeypot_channel.id not in channel_ids:
                channel_ids.append(honeypot_channel.id)
        await ctx.send(_("✅ Honeypot channel added: {channel.mention}").format(channel=honeypot_channel))

    @channels.command(name="add")
    async def channel_add(self, ctx: commands.Context, target: discord.TextChannel | discord.Thread) -> None:
        """Add an existing honeypot channel."""
        missing = self._missing_channel_permissions(
            ctx.guild,
            target,
            read_history=True,
            manage_messages=True,
        )
        if missing is not None:
            raise commands.UserFeedbackCheckFailure(missing)
        config = await self.config.guild(ctx.guild).all()
        if target.id in self._honeypot_channel_ids_from_config(config):
            raise commands.UserFeedbackCheckFailure(_("That channel is already a honeypot channel."))
        async with self.config.guild(ctx.guild).honeypot_channels() as channel_ids:
            channel_ids.append(target.id)
        await ctx.send(_("✅ Honeypot channel added: {channel.mention}").format(channel=target))

    @channels.command(name="remove")
    async def channel_remove(self, ctx: commands.Context, target: discord.TextChannel | discord.Thread) -> None:
        """Remove a honeypot channel."""
        removed = False
        async with self.config.guild(ctx.guild).honeypot_channels() as channel_ids:
            while target.id in channel_ids:
                channel_ids.remove(target.id)
                removed = True
        if await self.config.guild(ctx.guild).honeypot_channel() == target.id:
            await self.config.guild(ctx.guild).honeypot_channel.set(None)
            removed = True
        if not removed:
            raise commands.UserFeedbackCheckFailure(_("That channel is not a honeypot channel."))
        await ctx.send(_("✅ Honeypot channel removed: {channel.mention}").format(channel=target))

    @channels.command(name="list")
    async def channel_list(self, ctx: commands.Context) -> None:
        """List honeypot channels."""
        config = await self.config.guild(ctx.guild).all()
        channel_ids = self._honeypot_channel_ids_from_config(config)
        await ctx.send(
            _("Honeypot channels:\n{channels}").format(
                channels=self._format_honeypot_channel_list(ctx.guild, channel_ids),
            )
        )

    @channels.command()
    async def logs(self, ctx: commands.Context, target: discord.TextChannel | discord.Thread = None) -> None:
        """Set the logs channel."""
        if target is None:
            v = await self.config.guild(ctx.guild).logs_channel()
            await ctx.send(_("Logs channel: {channel}").format(channel=ctx.guild.get_channel(v) if v else _("not set")))
        else:
            missing = self._missing_channel_permissions(ctx.guild, target)
            if missing is not None:
                raise commands.UserFeedbackCheckFailure(missing)
            await self.config.guild(ctx.guild).logs_channel.set(target.id)
            await ctx.send(_("✅ Logs channel set to {channel.mention}").format(channel=target))

    @channels.command(name="ping_role")
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

    @purge.command(name="toggle")
    async def purge_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Delete recent messages from the user in the honeypot channel."""
        if value is None:
            v = await self.config.guild(ctx.guild).purge_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
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

    @fakeactivity.command(name="toggle")
    async def fakeactivity_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Simulate activity in the honeypot channel to attract scammers."""
        if value is None:
            v = await self.config.guild(ctx.guild).fake_activity_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
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
        message = message.strip()
        if not message:
            raise commands.UserFeedbackCheckFailure(_("Fake activity message cannot be empty."))
        if len(message) > 2000:
            raise commands.UserFeedbackCheckFailure(_("Fake activity message must be 2000 characters or fewer."))
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

    @review.command(name="toggle")
    async def review_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Send suspicious messages to moderator review instead of acting immediately."""
        if value is None:
            v = await self.config.guild(ctx.guild).review_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
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
            missing = self._missing_channel_permissions(ctx.guild, target)
            if missing is not None:
                raise commands.UserFeedbackCheckFailure(missing)
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

    @review.command(name="kick_fail_warn")
    async def review_kick_fail_warn(self, ctx: commands.Context, value: str = None) -> None:
        """How to handle a review kick when the target has already left: false, true, or manual."""
        if value is None:
            v = await self.config.guild(ctx.guild).review_kick_fail_warning()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=v,
                    options=self._format_options(REVIEW_KICK_FAIL_WARNING_MODES),
                )
            )
            return
        value = value.lower()
        if value not in REVIEW_KICK_FAIL_WARNING_MODES:
            await ctx.send(_("Choose one of: {options}").format(options=self._format_options(REVIEW_KICK_FAIL_WARNING_MODES)))
            return
        await self.config.guild(ctx.guild).review_kick_fail_warning.set(value)
        await ctx.send(_("✅ Kick-fail warning set to {value}").format(value=value))

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
        """Add an attachment filename-base regex. It triggers when 2+ files match."""
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

    @joinwatch.command(name="toggle")
    async def joinwatch_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable new account join alerts."""
        if value is None:
            v = await self.config.guild(ctx.guild).joinwatch_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
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
            missing = self._missing_channel_permissions(ctx.guild, target)
            if missing is not None:
                raise commands.UserFeedbackCheckFailure(missing)
            await self.config.guild(ctx.guild).joinwatch_channel.set(target.id)
            await ctx.send(_("✅ Joinwatch channel set to {channel.mention}").format(channel=target))

    @joinwatch.group(name="alert")
    async def joinwatch_alert(self, ctx: commands.Context) -> None:
        """Configure joinwatch alert messages."""

    @joinwatch_alert.command(name="toggle")
    async def joinwatch_alert_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable joinwatch alert messages."""
        if value is None:
            v = await self.config.guild(ctx.guild).joinwatch_alert_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).joinwatch_alert_enabled.set(value)
            await ctx.send(_("✅ Joinwatch alerts set to {value}").format(value=value))

    @joinwatch.command(name="max_age")
    async def max_age(self, ctx: commands.Context, hours: int = None) -> None:
        """Max account age in hours to trigger alert (default 24)."""
        if hours is None:
            v = await self.config.guild(ctx.guild).joinwatch_min_age_hours()
            await ctx.send(_("Joinwatch max age: {value} hours").format(value=v))
        elif hours < 1 or hours > 168:
            await ctx.send(_("Hours must be between 1 and 168 (1 week)."))
        else:
            await self.config.guild(ctx.guild).joinwatch_min_age_hours.set(hours)
            await ctx.send(_("✅ Joinwatch max age set to {value} hours").format(value=hours))

    @joinwatch.group(name="autorole")
    async def joinwatch_autorole(self, ctx: commands.Context) -> None:
        """Automatically role young accounts and punish if the role remains."""

    @joinwatch_autorole.command(name="toggle")
    async def joinwatch_autorole_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable joinwatch auto-role."""
        if value is None:
            v = await self.config.guild(ctx.guild).joinwatch_auto_role_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).joinwatch_auto_role_enabled.set(value)
            await ctx.send(_("✅ Joinwatch auto-role set to {value}").format(value=value))

    @joinwatch_autorole.command(name="role")
    async def joinwatch_autorole_role(self, ctx: commands.Context, role: discord.Role = None) -> None:
        """Role to apply to young accounts."""
        if role is None:
            role_id = await self.config.guild(ctx.guild).joinwatch_auto_role_id()
            configured_role = ctx.guild.get_role(role_id) if role_id else None
            await ctx.send(
                _("Joinwatch auto-role: {role}").format(
                    role=configured_role.mention if configured_role else _("not set"),
                )
            )
        else:
            role_permission_error = self._missing_role_assignment_permission(ctx.guild, role)
            if role_permission_error is not None:
                raise commands.UserFeedbackCheckFailure(role_permission_error)
            await self.config.guild(ctx.guild).joinwatch_auto_role_id.set(role.id)
            await ctx.send(_("✅ Joinwatch auto-role set to {role.mention}").format(role=role))

    @joinwatch_autorole.command(name="timer")
    async def joinwatch_autorole_timer(self, ctx: commands.Context, minutes: int = None) -> None:
        """Minutes before punishment if the auto-role is still present."""
        if minutes is None:
            v = await self.config.guild(ctx.guild).joinwatch_auto_role_timer_minutes()
            await ctx.send(_("Joinwatch auto-role timer: {value} minutes").format(value=v))
        elif minutes < 1 or minutes > 10080:
            await ctx.send(_("Timer must be between 1 and 10080 minutes."))
        else:
            old_minutes = await self.config.guild(ctx.guild).joinwatch_auto_role_timer_minutes()
            await self.config.guild(ctx.guild).joinwatch_auto_role_timer_minutes.set(minutes)
            updated = await self._reschedule_joinwatch_pending_roles(ctx.guild, old_minutes, minutes)
            await ctx.send(
                _("✅ Joinwatch auto-role timer set to {value} minutes. Updated {count} active timer(s).").format(
                    value=minutes,
                    count=updated,
                )
            )

    @joinwatch_autorole.command(name="action")
    async def joinwatch_autorole_action(self, ctx: commands.Context, value: str = None) -> None:
        """Action when the auto-role is not removed before the timer: none, kick, or ban."""
        if value is None:
            v = await self.config.guild(ctx.guild).joinwatch_auto_role_action()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=v,
                    options=self._format_options(JOINWATCH_AUTO_ROLE_ACTION_OPTIONS),
                )
            )
        elif value not in JOINWATCH_AUTO_ROLE_ACTION_OPTIONS:
            await ctx.send(_("Choose one of: {options}").format(options=self._format_options(JOINWATCH_AUTO_ROLE_ACTION_OPTIONS)))
        else:
            await self.config.guild(ctx.guild).joinwatch_auto_role_action.set(value)
            await ctx.send(_("✅ Joinwatch auto-role action set to {value}").format(value=value))

    @joinwatch_autorole.command(name="bantimers")
    async def joinwatch_autorole_bantimers(self, ctx: commands.Context) -> None:
        """List active joinwatch auto-role punishment timers."""
        config = await self.config.guild(ctx.guild).all()
        pending_roles = config.get("joinwatch_pending_roles", {})
        if not pending_roles:
            await ctx.send(_("No active joinwatch punishment timers."))
            return

        now = datetime.now(timezone.utc)
        invalid = 0
        entries: list[tuple[datetime, str]] = []
        for member_id_str, data in pending_roles.items():
            try:
                member_id = int(member_id_str)
                expires_at = datetime.fromisoformat(data["expires_at"])
            except (KeyError, TypeError, ValueError):
                invalid += 1
                continue

            member = await self._get_member_or_fetch(ctx.guild, member_id)
            member_label = (
                f"{member.display_name} ({member.id})"
                if member is not None
                else _("Unknown member ({id})").format(id=member_id)
            )
            applied_at = None
            if data.get("applied_at") is not None:
                try:
                    applied_at = datetime.fromisoformat(data["applied_at"])
                except (TypeError, ValueError):
                    applied_at = None
            deadline = (
                _("due now")
                if expires_at <= now
                else discord.utils.format_dt(expires_at, style="R")
            )
            applied = (
                discord.utils.format_dt(applied_at, style="R")
                if applied_at is not None
                else _("unknown")
            )
            entries.append(
                (
                    expires_at,
                    _(
                        "{member} | deadline: {deadline} | applied: {applied}"
                    ).format(
                        member=member_label,
                        deadline=deadline,
                        applied=applied,
                    ),
                )
            )

        if not entries:
            await ctx.send(_("No readable joinwatch punishment timers."))
            return

        entries.sort(key=lambda item: item[0])
        header = _("Joinwatch active punishment timers: {count}").format(
            count=len(entries),
        )
        if invalid:
            header += _("\nSkipped invalid entries: {count}").format(count=invalid)
        lines = [header, ""]
        lines.extend(f"{index}. {entry}" for index, (_, entry) in enumerate(entries, 1))
        for page in pagify("\n".join(lines), page_length=1900):
            await ctx.send(page, allowed_mentions=discord.AllowedMentions.none())

    @joinwatch_autorole.group(name="randomize")
    async def joinwatch_autorole_randomize(self, ctx: commands.Context) -> None:
        """Randomize when the joinwatch auto-role is applied."""

    @joinwatch_autorole_randomize.command(name="toggle")
    async def joinwatch_autorole_randomize_toggle(
        self, ctx: commands.Context, value: bool = None
    ) -> None:
        """Enable or disable randomized delay before applying the auto-role."""
        if value is None:
            v = await self.config.guild(ctx.guild).joinwatch_auto_role_random_delay_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).joinwatch_auto_role_random_delay_enabled.set(value)
            await ctx.send(_("✅ Joinwatch auto-role randomized delay set to {value}").format(value=value))

    @joinwatch_autorole_randomize.command(name="min_time")
    async def joinwatch_autorole_randomize_min_time(
        self, ctx: commands.Context, minutes: int = None
    ) -> None:
        """Minimum minutes before applying the auto-role."""
        if minutes is None:
            v = await self.config.guild(ctx.guild).joinwatch_auto_role_random_delay_min_minutes()
            await ctx.send(_("Joinwatch auto-role randomized minimum: {value} minutes").format(value=v))
        elif minutes < 1 or minutes > 10080:
            await ctx.send(_("Minimum delay must be between 1 and 10080 minutes."))
        else:
            current_max = await self.config.guild(ctx.guild).joinwatch_auto_role_random_delay_max_minutes()
            await self.config.guild(ctx.guild).joinwatch_auto_role_random_delay_min_minutes.set(minutes)
            if minutes > current_max:
                await self.config.guild(ctx.guild).joinwatch_auto_role_random_delay_max_minutes.set(minutes)
                await ctx.send(
                    _("✅ Joinwatch randomized delay minimum and maximum set to {value} minutes").format(
                        value=minutes,
                    )
                )
            else:
                await ctx.send(
                    _("✅ Joinwatch randomized delay minimum set to {value} minutes").format(
                        value=minutes,
                    )
                )

    @joinwatch_autorole_randomize.command(name="max_time")
    async def joinwatch_autorole_randomize_max_time(
        self, ctx: commands.Context, minutes: int = None
    ) -> None:
        """Maximum minutes before applying the auto-role."""
        if minutes is None:
            v = await self.config.guild(ctx.guild).joinwatch_auto_role_random_delay_max_minutes()
            await ctx.send(_("Joinwatch auto-role randomized maximum: {value} minutes").format(value=v))
        elif minutes < 1 or minutes > 10080:
            await ctx.send(_("Maximum delay must be between 1 and 10080 minutes."))
        else:
            current_min = await self.config.guild(ctx.guild).joinwatch_auto_role_random_delay_min_minutes()
            if minutes < current_min:
                await ctx.send(
                    _("Maximum delay must be greater than or equal to the current minimum ({value} minutes).").format(
                        value=current_min,
                    )
                )
                return
            await self.config.guild(ctx.guild).joinwatch_auto_role_random_delay_max_minutes.set(minutes)
            await ctx.send(_("✅ Joinwatch randomized delay maximum set to {value} minutes").format(value=minutes))

    # ─── bait sub-group ───────────────────────────────────────────────

    @honeypot.group()
    async def bait(self, ctx: commands.Context) -> None:
        """Trap role: automatically punish users who take a specific role."""

    @bait.command(name="toggle")
    async def bait_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable the bait role trap."""
        if value is None:
            v = await self.config.guild(ctx.guild).baitrole_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).baitrole_enabled.set(value)
            await ctx.send(_("✅ Bait role trap set to {value}").format(value=value))

    @bait.command()
    async def role(self, ctx: commands.Context, role: discord.Role = None) -> None:
        """Set the bait role - users who take it get punished."""
        if role is None:
            v = await self.config.guild(ctx.guild).baitrole_id()
            r = ctx.guild.get_role(v) if v else None
            await ctx.send(_("Bait role: {role}").format(role=r.mention if r else _("not set")))
        else:
            await self.config.guild(ctx.guild).baitrole_id.set(role.id)
            await ctx.send(_("✅ Bait role set to {role.mention}").format(role=role))

    @bait.command(name="action")
    async def bait_action(self, ctx: commands.Context, value: str = None) -> None:
        """Action to take: kick or ban."""
        if value is None:
            v = await self.config.guild(ctx.guild).baitrole_action()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=v,
                    options=self._format_options(BAIT_ACTION_OPTIONS),
                )
            )
        elif value not in BAIT_ACTION_OPTIONS:
            await ctx.send(_("Choose one of: {options}").format(options=self._format_options(BAIT_ACTION_OPTIONS)))
        else:
            await self.config.guild(ctx.guild).baitrole_action.set(value)
            await ctx.send(_("✅ Bait action set to {value}").format(value=value))

    # ─── config dump ───────────────────────────────────────────────────

    @honeypot.group(name="config")
    async def config_dump(self, ctx: commands.Context) -> None:
        """Show current Honeypot configuration by section."""

    @config_dump.command(name="core")
    async def config_core(self, ctx: commands.Context) -> None:
        """Show core configuration."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Core config"),
            [
                (_("Enabled"), self._format_bool_setting(config.get("enabled", False))),
                (_("Action"), config.get("action") or _("not set")),
                (_("Fallback action"), config.get("fallback_action")),
                (_("Dry run"), self._format_bool_setting(config.get("dry_run", False))),
                (_("Whitelist mode"), config.get("whitelist_mode")),
                (_("Warn on automated kick fail"), self._format_bool_setting(config.get("automated_kick_fail_warning", False))),
            ],
        )

    @config_dump.command(name="channel")
    async def config_channel(self, ctx: commands.Context) -> None:
        """Show channel configuration."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Channel config"),
            [
                (_("Honeypot channels"), self._format_honeypot_channel_list(ctx.guild, self._honeypot_channel_ids_from_config(config))),
                (_("Logs channel"), self._format_channel_setting(ctx.guild, config.get("logs_channel"))),
                (_("Ping role"), self._format_role_setting(ctx.guild, config.get("ping_role"))),
            ],
        )

    @config_dump.command(name="punishment")
    async def config_punishment(self, ctx: commands.Context) -> None:
        """Show punishment configuration."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Punishment config"),
            [
                (_("Mute role"), self._format_role_setting(ctx.guild, config.get("mute_role"))),
                (_("Ban delete message days"), config.get("ban_delete_message_days")),
            ],
        )

    @config_dump.command(name="purge")
    async def config_purge(self, ctx: commands.Context) -> None:
        """Show purge configuration."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Purge config"),
            [
                (_("Enabled"), self._format_bool_setting(config.get("purge_enabled", False))),
                (_("Minutes"), config.get("purge_minutes")),
            ],
        )

    @config_dump.command(name="fakeactivity")
    async def config_fakeactivity(self, ctx: commands.Context) -> None:
        """Show fake activity configuration."""
        config = await self.config.guild(ctx.guild).all()
        messages = config.get("fake_activity_messages") or []
        await self._send_config_dump(
            ctx,
            _("Fake activity config"),
            [
                (_("Enabled"), self._format_bool_setting(config.get("fake_activity_enabled", False))),
                (_("Interval"), _("{minutes} minutes").format(minutes=config.get("fake_activity_interval"))),
                (_("Custom messages"), len(messages)),
            ],
        )

    @config_dump.command(name="review")
    async def config_review(self, ctx: commands.Context) -> None:
        """Show review configuration."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Review config"),
            [
                (_("Enabled"), self._format_bool_setting(config.get("review_enabled", False))),
                (_("Channel"), self._format_channel_setting(ctx.guild, config.get("review_channel"))),
                (_("Timeout"), _("{minutes} minutes").format(minutes=config.get("review_timeout_minutes"))),
                (_("Kick fail warning"), config.get("review_kick_fail_warning", "false")),
                (_("Pending reviews"), len(config.get("pending_reviews", {}))),
            ],
        )

    @config_dump.command(name="roles")
    async def config_roles(self, ctx: commands.Context) -> None:
        """Show whitelisted role configuration."""
        config = await self.config.guild(ctx.guild).all()
        role_ids = config.get("whitelisted_roles", [])
        roles = [self._format_role_setting(ctx.guild, role_id) for role_id in role_ids]
        await self._send_config_dump(
            ctx,
            _("Roles config"),
            [
                (_("Whitelist mode"), config.get("whitelist_mode")),
                (_("Whitelisted roles"), ", ".join(roles) if roles else _("none")),
            ],
        )

    @config_dump.command(name="keywords")
    async def config_keywords(self, ctx: commands.Context) -> None:
        """Show keyword configuration counts."""
        config = await self.config.guild(ctx.guild).all()
        keywords = config.get("scam_keywords") or []
        attachment_patterns = config.get("attachment_patterns") or []
        await self._send_config_dump(
            ctx,
            _("Keywords config"),
            [
                (_("Scam keywords"), len(keywords)),
                (_("Attachment patterns"), len(attachment_patterns)),
            ],
        )

    @config_dump.command(name="joinwatch")
    async def config_joinwatch(self, ctx: commands.Context) -> None:
        """Show joinwatch configuration."""
        config = await self.config.guild(ctx.guild).all()
        lines = [
            _("Joinwatch:"),
            f"  {_('Enabled')}: {self._format_bool_setting(config.get('joinwatch_enabled', False))}",
            f"  {_('Alerts')}: {self._format_bool_setting(config.get('joinwatch_alert_enabled', True))}",
            f"  {_('Channel')}: {self._format_channel_setting(ctx.guild, config.get('joinwatch_channel'))}",
            f"  {_('Maximum account age')}: {_('{hours} hours').format(hours=config.get('joinwatch_min_age_hours'))}",
            "",
            _("Auto-role:"),
            f"  {_('Enabled')}: {self._format_bool_setting(config.get('joinwatch_auto_role_enabled', False))}",
            f"  {_('Role')}: {self._format_role_setting(ctx.guild, config.get('joinwatch_auto_role_id'))}",
            f"  {_('Timer')}: {_('{minutes} minutes').format(minutes=config.get('joinwatch_auto_role_timer_minutes'))}",
            f"  {_('Action')}: {config.get('joinwatch_auto_role_action')}",
            f"  {_('Randomized delay')}: {self._format_bool_setting(config.get('joinwatch_auto_role_random_delay_enabled', False))}",
            f"  {_('Delay range')}: {_('{min} to {max} minutes').format(min=config.get('joinwatch_auto_role_random_delay_min_minutes', 1), max=config.get('joinwatch_auto_role_random_delay_max_minutes', 10))}",
            f"  {_('Pending role applications')}: {len(config.get('joinwatch_pending_role_assignments', {}))}",
            f"  {_('Active joinwatch timers')}: {len(config.get('joinwatch_pending_roles', {}))}",
        ]
        await ctx.send(_("Joinwatch config:\n") + box("\n".join(lines)))

    @config_dump.command(name="bait")
    async def config_bait(self, ctx: commands.Context) -> None:
        """Show bait role configuration."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Bait config"),
            [
                (_("Enabled"), self._format_bool_setting(config.get("baitrole_enabled", False))),
                (_("Role"), self._format_role_setting(ctx.guild, config.get("baitrole_id"))),
                (_("Action"), config.get("baitrole_action")),
            ],
        )

    @config_dump.command(name="stats")
    async def config_stats(self, ctx: commands.Context) -> None:
        """Show stored stats and pending review/timer counts."""
        config = await self.config.guild(ctx.guild).all()
        stats = DEFAULT_STATS.copy()
        stats.update(config.get("stats", {}))
        await self._send_config_dump(
            ctx,
            _("Stats config"),
            [
                (_("Stored stats"), len(stats)),
                (_("Pending reviews"), len(config.get("pending_reviews", {}))),
                (_("Pending joinwatch role applications"), len(config.get("joinwatch_pending_role_assignments", {}))),
                (_("Active joinwatch auto-role timers"), len(config.get("joinwatch_pending_roles", {}))),
            ],
        )

    @config_dump.command(name="all")
    async def config_all(self, ctx: commands.Context) -> None:
        """Show a compact summary of all configuration sections."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Honeypot config summary"),
            [
                (_("Core"), self._format_bool_setting(config.get("enabled", False))),
                (_("Honeypot channels"), self._format_honeypot_channel_list(ctx.guild, self._honeypot_channel_ids_from_config(config))),
                (_("Logs channel"), self._format_channel_setting(ctx.guild, config.get("logs_channel"))),
                (_("Review"), self._format_bool_setting(config.get("review_enabled", False))),
                (_("Joinwatch"), self._format_bool_setting(config.get("joinwatch_enabled", False))),
                (_("Joinwatch auto-role"), self._format_bool_setting(config.get("joinwatch_auto_role_enabled", False))),
                (_("Bait role"), self._format_bool_setting(config.get("baitrole_enabled", False))),
                (_("Pending reviews"), len(config.get("pending_reviews", {}))),
                (_("Pending joinwatch role applications"), len(config.get("joinwatch_pending_role_assignments", {}))),
                (_("Active joinwatch auto-role timers"), len(config.get("joinwatch_pending_roles", {}))),
            ],
        )

    # ─── stats ────────────────────────────────────────────────────────

    @honeypot.command(name="modstats")
    async def honeypot_mod_stats(self, ctx: commands.Context) -> None:
        """Show detailed honeypot statistics for moderators."""
        stats = DEFAULT_STATS.copy()
        stats.update(await self.config.guild(ctx.guild).stats())
        pending_reviews = await self.config.guild(ctx.guild).pending_reviews()
        pending_joinwatch_assignments = await self.config.guild(ctx.guild).joinwatch_pending_role_assignments()
        pending_joinwatch_roles = await self.config.guild(ctx.guild).joinwatch_pending_roles()
        total_joins = stats["joinwatch_total_joins"]
        young_joins = stats["joinwatch_young_joins"]
        young_join_rate = (young_joins / total_joins * 100) if total_joins else 0
        sections = {
            "Detection": {
                "Total detections": stats["detections"],
                "Suspicious detections": stats["suspicious"],
                "Whitelisted users": stats["whitelisted"],
                "Purged messages": stats["purged_messages"],
            },
            "Review": {
                "Reviews sent": stats["reviewed"],
                "Active pending reviews": len(pending_reviews),
                "Expired reviews": stats["review_expired"],
                "Ignored reviews": stats["ignored"],
                "Applied temporary mutes": stats["pending_mutes"],
                "Failed temporary mutes": stats["pending_mute_failures"],
            },
            "Joinwatch": {
                "Total joins": total_joins,
                "Young joins": young_joins,
                "Young join rate": f"{young_join_rate:.1f}%",
                "Auto-role applications scheduled": stats["joinwatch_auto_roles_scheduled"],
                "Pending role applications": len(pending_joinwatch_assignments),
                "Auto-roles applied": stats["joinwatch_auto_roles"],
                "Auto-role failures": stats["joinwatch_auto_role_failures"],
                "Auto-roles cleared": stats["joinwatch_auto_roles_cleared"],
                "Active auto-role timers": len(pending_joinwatch_roles),
                "Auto-role punishments": stats["joinwatch_auto_role_punishments"],
            },
            "Actions": {
                "Kicked users": stats["kicked"],
                "Banned users": stats["banned"],
                "Failed actions": stats["failed_actions"],
                "Dry-run actions": stats["dry_run_actions"],
            },
        }
        lines = []
        for section, values in sections.items():
            if lines:
                lines.append("")
            lines.append(f"{section}:")
            lines.extend(f"  {label}: {value}" for label, value in values.items())
        await ctx.send(_("**Honeypot stats:**\n") + box("\n".join(lines)))

    @honeypot.command(name="stats")
    async def honeypot_stats(self, ctx: commands.Context) -> None:
        """Show public-facing honeypot statistics."""
        stats = DEFAULT_STATS.copy()
        stats.update(await self.config.guild(ctx.guild).stats())
        lines = [
            f"  {_('Messages')}: {stats['detections']}",
            f"  {_('Bans')}: {stats['banned']}",
            f"  {_('Sent for Review')}: {stats['reviewed']}",
            f"  {_('Auto roles applied')}: {stats['joinwatch_auto_roles']}",
            f"  {_('Auto role punishments')}: {stats['joinwatch_auto_role_punishments']}",
        ]
        await ctx.send(_("**Server safety stats:**\n") + box("\n".join(lines)))

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
        if me is None:
            await ctx.send(_("**Honeypot doctor:**\n❌ I couldn't find my server member."))
            return
        honeypot_channels = [
            channel
            for channel_id in self._honeypot_channel_ids_from_config(config)
            if (channel := self._get_text_channel_or_thread(ctx.guild, channel_id)) is not None
        ]
        logs_channel = self._get_text_channel_or_thread(ctx.guild, config.get("logs_channel"))
        review_channel = self._get_text_channel_or_thread(ctx.guild, config.get("review_channel"))
        checks.append(("Honeypot enabled", bool(config.get("enabled")), "Run `honeypot core toggle true`."))
        checks.append(("Action configured", config.get("action") in ("kick", "ban", "review", "none"), "Run `honeypot core action`."))
        checks.append(("Honeypot channel exists", bool(honeypot_channels), "Run `honeypot channel add`."))
        checks.append(("Logs channel exists", logs_channel is not None, "Run `honeypot channel logs`."))
        if config.get("fallback_action") == "review" or config.get("review_enabled") or config.get("whitelist_mode") == "review":
            checks.append(("Review channel exists", review_channel is not None, "Run `honeypot review channel`."))
        if config.get("mute_role"):
            mute_role = ctx.guild.get_role(config["mute_role"])
            checks.append(("Mute role exists", mute_role is not None, "Run `honeypot punishment mute_role`."))
            if mute_role is not None:
                checks.append(("Bot above mute role", me.top_role > mute_role, "Move bot role above mute role."))
        if config.get("joinwatch_auto_role_enabled"):
            auto_role_id = config.get("joinwatch_auto_role_id")
            auto_role = ctx.guild.get_role(auto_role_id) if auto_role_id else None
            checks.append(("Joinwatch auto-role exists", auto_role is not None, "Run `honeypot joinwatch autorole role`."))
            if auto_role is not None:
                checks.append(("Bot above joinwatch auto-role", me.top_role > auto_role, "Move bot role above the joinwatch auto-role."))
        if config.get("joinwatch_enabled") and config.get("joinwatch_alert_enabled", True):
            joinwatch_channel = self._get_text_channel_or_thread(ctx.guild, config.get("joinwatch_channel"))
            checks.append(("Joinwatch alert channel exists", joinwatch_channel is not None, "Run `honeypot joinwatch channel`."))
            if joinwatch_channel is not None:
                perms = joinwatch_channel.permissions_for(me)
                checks.append(("Can send joinwatch alerts", perms.send_messages, "Grant Send Messages."))
        for honeypot_channel in honeypot_channels:
            perms = honeypot_channel.permissions_for(me)
            missing_permissions = missing_purge_permissions(perms)
            checks.append(
                (
                    f"Honeypot permissions in {honeypot_channel}",
                    not missing_permissions,
                    "Missing: {permissions}".format(
                        permissions=", ".join(missing_permissions) if missing_permissions else "None",
                    ),
                )
            )
        if ban_delete_message_days(config) > 0:
            skipped_channels = []
            purgeable_channels = [
                channel
                for channel in list(ctx.guild.channels) + list(ctx.guild.threads)
                if is_purgeable_message_channel(channel)
            ]
            for channel in purgeable_channels:
                perms = channel.permissions_for(me)
                missing_permissions = missing_channel_purge_permissions(channel, perms)
                if missing_permissions:
                    skipped_channels.append(
                        "{channel} ({permissions})".format(
                            channel=channel.mention,
                            permissions=", ".join(missing_permissions),
                        )
                    )
            if skipped_channels:
                checks.append(
                    (
                        "Post-ban sweep can purge all visible message channels",
                        False,
                        "Missing purge permissions: "
                        + ", ".join(skipped_channels[:5])
                        + (" ..." if len(skipped_channels) > 5 else ""),
                    )
                )
            else:
                checks.append(
                    (
                        "Post-ban sweep can purge all visible message channels",
                        True,
                        "Grant View Channel, Read Message History, Manage Messages, and Connect for voice/stage channels.",
                    )
                )
        if logs_channel is not None:
            perms = logs_channel.permissions_for(me)
            checks.append(("Can send logs", perms.send_messages, "Grant Send Messages."))
        if review_channel is not None:
            perms = review_channel.permissions_for(me)
            checks.append(("Can send review messages", perms.send_messages, "Grant Send Messages."))
        guild_perms = me.guild_permissions
        checks.append(("Can kick members", guild_perms.kick_members, "Grant Kick Members."))
        checks.append(("Can ban members", guild_perms.ban_members, "Grant Ban Members."))
        checks.append(("Can manage roles", guild_perms.manage_roles, "Grant Manage Roles for mute or joinwatch auto-role."))
        failed = [f"❌ {name} - {hint}" for name, ok, hint in checks if not ok]
        passed = [f"✅ {name}" for name, ok, _hint in checks if ok]
        await ctx.send(_("**Honeypot doctor:**\n{body}").format(body="\n".join(passed + failed)))
