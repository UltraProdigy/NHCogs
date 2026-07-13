import asyncio
import hashlib
import io
import json
import logging
import math
import shutil
import random
import re
import sqlite3
import tempfile
import typing
import zipfile
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import discord
from discord.ext import tasks

from AAA3A_utils import Cog
from redbot.core import Config, commands, modlog
from redbot.core.bot import Red
from redbot.core.data_manager import cog_data_path
from redbot.core.i18n import Translator, cog_i18n
from redbot.core.utils.chat_formatting import box, pagify

from .image_detector import (
    ImageSample,
    image_hashes_from_bytes,
    match_image,
    rebuild_model_state,
)

_ = Translator("Honeypot", __file__)
log = logging.getLogger("red.Honeypot")

try:
    from PIL import Image
except ImportError:  # pragma: no cover - optional metadata enrichment.
    Image = None

PURGE_PERMISSION_REQUIREMENTS = (
    ("View Channel", "view_channel"),
    ("Read Message History", "read_message_history"),
    ("Manage Messages", "manage_messages"),
)
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
    "cached_purge_deletes": 0,
    "forward_purge_deletes": 0,
    "firstpost_seen": 0,
    "firstpost_hits": 0,
    "firstpost_reviews": 0,
    "firstpost_kicks": 0,
    "firstpost_bans": 0,
    "early_catches": 0,
    "spam_hits": 0,
    "spam_reviews": 0,
    "spam_kicks": 0,
    "spam_bans": 0,
    "spam_catches": 0,
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
PURGE_MIN_RETENTION_SECONDS = 60
PURGE_BACKWARD_DEFAULT_SECONDS = 60
PURGE_BACKWARD_MAX_SECONDS = 3600
PURGE_FORWARD_DEFAULT_SECONDS = 10
PURGE_FORWARD_MAX_SECONDS = 300
SPAM_WINDOW_MIN_SECONDS = 3
SPAM_WINDOW_MAX_SECONDS = 60
SPAM_CHANNEL_MIN = 2
SPAM_CHANNEL_MAX = 10
REVIEW_DUMP_START = datetime(2026, 5, 1, tzinfo=timezone.utc)
REVIEW_DUMP_MAX_ZIP_BYTES = 95 * 1024 * 1024
REVIEW_DUMP_ATTACHMENT_DELAY_SECONDS = 1
IMAGE_SCAN_EXTENSIONS = (".jpg", ".jpeg", ".png", ".webp", ".gif")
IMAGE_SCAN_COUNTS = (2, 4)
IMAGE_SCAN_MAX_ATTACHMENTS = 4
IMAGE_SCAN_FEEDBACK_TIMEOUT_SECONDS = 24 * 60 * 60
IMAGE_SCAN_FEEDBACK_BULK_LABELS = ("All TP", "All FP", "Ignore all", "Individual")
IMAGE_SCAN_DECISIONS = ("true_positive", "false_positive")
IMAGE_SCAN_DETECTOR_ACTION_OPTIONS = ("none", "review", "kick", "ban")
IMAGE_SCAN_PROFILE_COLUMNS = (
    "messages_scanned",
    "messages_with_images",
    "images_considered",
    "images_ignored_over_limit",
    "exact_tp_hits",
    "flagged_tp_hits",
    "download_ms_total",
    "download_ms_count",
    "hash_ms_total",
    "hash_ms_count",
    "compare_ms_total",
    "compare_ms_count",
    "decision_ms_total",
    "decision_ms_count",
)
REVIEW_KICK_FAIL_WARNING_MODES = ("false", "true", "manual")
KICK_FAIL_WARNING_REASON = "Suspicious activity: target left before the kick could be applied."
CORE_ACTION_OPTIONS = ("kick", "ban", "review", "none")
FALLBACK_ACTION_OPTIONS = ("review", "kick", "ban", "none")
WHITELIST_MODE_OPTIONS = ("bypass", "review", "fallback", "none")
JOINWATCH_AUTO_ROLE_ACTION_OPTIONS = ("none", "kick", "ban")
BAIT_ACTION_OPTIONS = ("kick", "ban")
BOOL_OPTIONS = ("false", "true")


def missing_purge_permissions(permissions: object) -> list[str]:
    if not bool(getattr(permissions, "view_channel", False)):
        return ["View Channel"]
    return [
        name
        for name, attribute in PURGE_PERMISSION_REQUIREMENTS
        if not bool(getattr(permissions, attribute, False))
    ]


def is_purgeable_message_channel(channel: object) -> bool:
    return callable(getattr(channel, "purge", None))


def joinwatch_channel_id(config: dict) -> int | None:
    channel_id = config.get("joinwatch_channel")
    return channel_id if isinstance(channel_id, int) else None


def imagescan_feedback_items(
    considered: list[discord.Attachment],
    matches: list[tuple[discord.Attachment, dict[str, typing.Any], dict[str, str]]],
    attachment_snapshots: list[dict[str, typing.Any]],
) -> list[tuple[discord.Attachment, int, bytes]]:
    items = []
    for attachment, result, _hashes in matches:
        if result.get("exact_decision") is not None:
            continue
        index = considered.index(attachment)
        if index >= len(attachment_snapshots):
            continue
        data = attachment_snapshots[index].get("data")
        if data is not None:
            items.append((attachment, index + 1, data))
    return items


def is_image_attachment(attachment: discord.Attachment) -> bool:
    content_type = (attachment.content_type or "").lower()
    if content_type.startswith("image/"):
        return True
    filename = attachment.filename.lower()
    return any(filename.endswith(extension) for extension in IMAGE_ATTACHMENT_EXTENSIONS)


def plan_imagescan_event_cache_cleanup(
    files_root: Path,
    guild_id: int,
    *,
    delete: bool = False,
) -> dict[str, int]:
    guild_root = files_root / str(guild_id)
    plan = {
        "event_dirs": 0,
        "deleted_event_dirs": 0,
        "files": 0,
        "bytes": 0,
    }
    if not guild_root.exists():
        return plan
    for child in guild_root.iterdir():
        if child.name == "samples" or not child.is_dir():
            continue
        files = [path for path in child.rglob("*") if path.is_file()]
        plan["event_dirs"] += 1
        plan["files"] += len(files)
        plan["bytes"] += sum(path.stat().st_size for path in files)
        if delete:
            shutil.rmtree(child, ignore_errors=True)
            if not child.exists():
                plan["deleted_event_dirs"] += 1
    return plan


def format_image_hash_diff(score: int, threshold: int) -> str:
    return f"{score}/{threshold}"


def format_imagescan_matched_attachments(
    matches: list[tuple[discord.Attachment, dict[str, typing.Any], dict[str, str]]],
) -> str:
    names = [
        getattr(attachment, "filename", None) or "unknown"
        for attachment, _match, _hashes in matches
    ]
    return "\n".join(names)


def match_imagescan_sample_identifier(
    rows: list[dict[str, typing.Any]],
    identifier: str,
) -> dict[str, typing.Any] | None:
    identifier = identifier.strip()
    if not identifier:
        return None
    exact = [
        row
        for row in rows
        if str(row.get("sample_id")) == identifier or str(row.get("sha256")) == identifier
    ]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None
    prefix = [row for row in rows if str(row.get("sha256", "")).startswith(identifier)]
    return prefix[0] if len(prefix) == 1 else None


def format_image_detection_status(status: str) -> str:
    labels = {
        "no_images": "No image attachments",
        "detected": "Detected, already known",
        "queued": "Not detected, feedback queued",
        "not_checked": "Not checked",
    }
    return labels.get(status, "Not checked")


def is_imagescan_sample_path_safe(files_root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(files_root.resolve())
        return True
    except (OSError, ValueError):
        return False


def summarize_imagescan_sample_storage(rows: list[dict[str, typing.Any]]) -> dict[str, int]:
    stats = {
        "active_with_file": 0,
        "active_without_file": 0,
        "file_bytes": 0,
    }
    for row in rows:
        if not int(row.get("active", 0)):
            continue
        file_path = row.get("file_path")
        if file_path:
            stats["active_with_file"] += 1
            stats["file_bytes"] += int(row.get("file_size_bytes") or 0)
        else:
            stats["active_without_file"] += 1
    return stats


def image_learning_status(*, has_images: bool, has_known_match: bool, can_queue: bool) -> str:
    if not has_images:
        return "no_images"
    if has_known_match:
        return "detected"
    if can_queue:
        return "queued"
    return "not_checked"


class MessageRef(typing.NamedTuple):
    channel_id: int
    message_id: int
    created_at: datetime
    fingerprint: str


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
ATTACHMENT_ONLY_SCAM_KEYWORDS = {"bro"}
WORD_KEYWORD_RE = re.compile(r"^[\w ]+$")
IMAGE_ATTACHMENT_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".gif",
    ".jpeg",
    ".jpg",
    ".png",
    ".tif",
    ".tiff",
    ".webp",
}


def keyword_matches_content(keyword: str, content: str) -> bool:
    keyword = keyword.strip().lower()
    if not keyword:
        return False
    if WORD_KEYWORD_RE.fullmatch(keyword):
        return re.search(rf"(?<!\w){re.escape(keyword)}(?!\w)", content) is not None
    return keyword in content


def matched_scam_keywords(
    keywords: typing.Iterable[str],
    content: str,
    *,
    include_attachment_only: bool = False,
) -> list[str]:
    return [
        keyword
        for keyword in keywords
        if (
            include_attachment_only
            or keyword.strip().lower() not in ATTACHMENT_ONLY_SCAM_KEYWORDS
        )
        and keyword_matches_content(keyword, content)
    ]


def message_spam_fingerprint(message: discord.Message) -> str:
    content = re.sub(r"\s+", " ", message.content.strip().lower())
    attachments = tuple(
        (
            attachment.filename.lower(),
            attachment.size,
            (attachment.content_type or "").lower(),
        )
        for attachment in message.attachments
    )
    raw = repr((content, attachments))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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
        message_fingerprint: str | None = None,
        channel_ids: list[int] | None = None,
    ) -> None:
        super().__init__(timeout=None)
        self.cog = cog
        self.target_id = target_id
        self.guild_id = guild_id
        self.content = content
        self.attachment_urls = attachment_urls
        self.pending_mute_role_id = pending_mute_role_id
        self.message_fingerprint = message_fingerprint
        normalized_channel_ids = []
        for channel_id in channel_ids or []:
            try:
                normalized_channel_ids.append(int(channel_id))
            except (TypeError, ValueError):
                continue
        self.channel_ids = list(dict.fromkeys(normalized_channel_ids))
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

    @staticmethod
    def _remove_review_expiry_field(embed: discord.Embed) -> None:
        for index in reversed(
            [
                index
                for index, field in enumerate(embed.fields)
                if field.name == _("Review expires in:")
            ]
        ):
            embed.remove_field(index)

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
            self._remove_review_expiry_field(embed)
            reviewed_value = (
                f"{interaction.user.mention} ({interaction.user.id})\n"
                f"{discord.utils.format_dt(datetime.now(timezone.utc), style='F')}"
            )
            status_field_index = next(
                (
                    index
                    for index, field in enumerate(embed.fields)
                    if field.name == _("Status:") or field.value == _("Pending moderator review")
                ),
                None,
            )
            if status_field_index is None:
                embed.add_field(name=_("Reviewed by:"), value=reviewed_value, inline=False)
            else:
                embed.set_field_at(
                    status_field_index,
                    name=_("Reviewed by:"),
                    value=reviewed_value,
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
            return (_("User left the server before the kick could be applied. Review is still pending; use Ban or Ignore."), None)
        if member is None and action not in ("ban", "ignore"):
            return (_("User is no longer in the server."), None)
        if action == "ignore":
            self.cog._deactivate_forward_purge(guild.id, self.target_id)
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
            self.cog._deactivate_forward_purge(guild.id, self.target_id)
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
            self.cog._deactivate_forward_purge(guild.id, self.target_id)
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
                self.cog._activate_forward_purge(guild.id, self.target_id, config)
                await member.kick(reason=reason)
                await self._create_modlog_case(guild, member, action, reason, interaction.user)
                await self.cog._increment_stat(guild, "kicked")
                await self.cog._purge_after_review_action(guild, self.target_id, config)
                return (None, _("Kicked"))
            elif action == "ban":
                target = member if member is not None else await self.cog._get_user_or_object(self.target_id)
                self.cog._activate_forward_purge(guild.id, target.id, config)
                await guild.ban(
                    target,
                    reason=reason,
                    delete_message_seconds=self.cog._ban_delete_message_seconds(config),
                )
                self.cog._schedule_post_ban_sweep(guild, target.id)
                await self._create_modlog_case(guild, target, action, reason, interaction.user)
                await self.cog._increment_stat(guild, "banned")
                await self.cog._purge_after_review_action(guild, target.id, config)
                return (None, _("Banned"))
        except discord.HTTPException:
            self.cog._deactivate_forward_purge(guild.id, self.target_id)
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


class ImageScanReviewView(discord.ui.View):
    def __init__(self, cog: "Honeypot", event_id: str, guild_id: int) -> None:
        super().__init__(timeout=None)
        self.cog = cog
        self.event_id = event_id
        self.guild_id = guild_id
        self.review_message: discord.Message | None = None

    @staticmethod
    def _check_perms(interaction: discord.Interaction) -> bool:
        permissions = getattr(interaction.user, "guild_permissions", None)
        return bool(permissions and permissions.moderate_members)

    def _disable_all(self) -> None:
        for item in self.children:
            item.disabled = True

    async def _set_decision(
        self,
        interaction: discord.Interaction,
        decision: str,
        label: str,
    ) -> None:
        if not self._check_perms(interaction):
            await interaction.followup.send(_("You need `Moderate Members` permission."), ephemeral=True)
            return
        await self.cog._imagescan_set_decision(self.guild_id, self.event_id, decision, interaction.user.id)
        self._disable_all()
        message = self.review_message or interaction.message
        embed = message.embeds[0] if message and message.embeds else None
        if embed:
            embed.color = discord.Color.green()
            reviewed_value = (
                f"{interaction.user.mention} ({interaction.user.id})\n"
                f"{discord.utils.format_dt(datetime.now(timezone.utc), style='F')}"
            )
            status_index = self.cog._embed_field_index(embed, _("Status:"))
            if status_index is None:
                embed.add_field(name=_("Classification:"), value=label, inline=False)
            else:
                embed.set_field_at(status_index, name=_("Classification:"), value=label, inline=False)
            embed.add_field(name=_("Reviewed by:"), value=reviewed_value, inline=False)
        if message is not None:
            try:
                await message.edit(content=_("✅ **Image scan classified**"), embed=embed, view=self)
            except discord.HTTPException:
                log.debug("Failed to edit imagescan review message %s", getattr(message, "id", None))
        await interaction.followup.send(_("Classification saved: {label}").format(label=label), ephemeral=True)

    @discord.ui.button(label="Confirm scam", style=discord.ButtonStyle.danger, custom_id="honeypot:imagescan:true_positive")
    async def confirm_scam(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        await self._set_decision(interaction, "true_positive", _("True positive"))

    @discord.ui.button(label="False positive", style=discord.ButtonStyle.secondary, custom_id="honeypot:imagescan:false_positive")
    async def false_positive(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        await self._set_decision(interaction, "false_positive", _("False positive"))

    @discord.ui.button(label="Ignore", style=discord.ButtonStyle.success, custom_id="honeypot:imagescan:ignored")
    async def ignore(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        await self._set_decision(interaction, "ignored", _("Ignored"))


class ImageScanFeedbackSelect(discord.ui.Select):
    def __init__(self, panel: "ImageScanFeedbackView") -> None:
        self.panel = panel
        options = [
            discord.SelectOption(
                label=panel.item_label(index),
                value=str(index),
                default=index == panel.selected_index,
            )
            for index, item in enumerate(panel.items)
            if item["decision"] is None
        ]
        super().__init__(placeholder=_("Select an image"), options=options, min_values=1, max_values=1)

    async def callback(self, interaction: discord.Interaction) -> None:
        self.panel.selected_index = int(self.values[0])
        self.panel._show_individual_controls()
        await interaction.response.edit_message(
            content=self.panel.status_content(),
            view=self.panel,
        )


class ImageScanFeedbackView(discord.ui.View):
    def __init__(
        self,
        cog: "Honeypot",
        source_message: discord.Message,
        items: list[tuple[discord.Attachment, int, bytes]],
    ) -> None:
        super().__init__(timeout=IMAGE_SCAN_FEEDBACK_TIMEOUT_SECONDS)
        self.cog = cog
        self.source_message = source_message
        self.items = [
            {"attachment": attachment, "index": index, "data": data, "decision": None}
            for attachment, index, data in items
        ]
        self.selected_index = 0
        self.clear_items()
        self.add_item(self.all_tp)
        self.add_item(self.all_fp)
        self.add_item(self.ignore_all)
        self.add_item(self.individual)

    def item_label(self, index: int) -> str:
        item = self.items[index]
        filename = item["attachment"].filename or f"attachment-{item['index']}"
        return f"{item['index']}. {filename}"[:100]

    def status_content(self) -> str:
        labels = {"true_positive": "✅ TP", "false_positive": "✅ FP", "ignored": "➖ Ignored", None: "⏳ Pending"}
        lines = [_("**Image detector feedback**")]
        for index, item in enumerate(self.items):
            marker = "➡️ " if item["decision"] is None and index == self.selected_index else ""
            lines.append(f"{marker}{self.item_label(index)} — {labels[item['decision']]}")
        return "\n".join(lines)

    @staticmethod
    def _check_perms(interaction: discord.Interaction) -> bool:
        permissions = getattr(interaction.user, "guild_permissions", None)
        return bool(permissions and permissions.moderate_members)

    def _disable_all(self) -> None:
        for item in self.children:
            item.disabled = True

    async def _confirm_text(self, interaction: discord.Interaction, token: str) -> bool:
        await interaction.followup.send(
            _("Type `{token}` to confirm.").format(token=token),
            ephemeral=True,
        )

        def check(message: discord.Message) -> bool:
            return (
                message.author.id == interaction.user.id
                and message.channel.id == interaction.channel_id
                and message.content.strip().upper() == token
            )

        try:
            await self.cog.bot.wait_for("message", check=check, timeout=60)
        except asyncio.TimeoutError:
            await interaction.followup.send(_("Cancelled."), ephemeral=True)
            return False
        return True

    async def _save_item_decision(
        self,
        interaction: discord.Interaction,
        item_index: int,
        decision: str,
    ) -> tuple[str, dict[str, typing.Any] | None]:
        item = self.items[item_index]
        status, sample = await self.cog._imagescan_add_bytes_sample(
            self.source_message.guild.id,
            item["data"],
            item["attachment"].filename or f"attachment-{item['index']}",
            self.source_message.jump_url,
            decision,
            interaction.user.id,
        )
        config = await self.cog.config.guild(self.source_message.guild).all()
        state = await self.cog._imagescan_model_state(
            self.source_message.guild.id,
            int(config.get("imagescan_detector_threshold", 20)),
        )
        if status == "inserted" and state["valid"]:
            item["decision"] = decision
            return status, sample
        if status == "duplicate":
            item["decision"] = decision
            return status, sample
        if status == "inserted" and sample is not None:
            await self.cog._imagescan_deactivate_sample(
                self.source_message.guild.id,
                sample["sample_id"],
            )
            await self.cog._imagescan_model_state(
                self.source_message.guild.id,
                int(config.get("imagescan_detector_threshold", 20)),
            )
        return "conflict", sample

    def _next_pending_index(self) -> int | None:
        return next((index for index, item in enumerate(self.items) if item["decision"] is None), None)

    def _show_individual_controls(self) -> None:
        self.clear_items()
        pending = self._next_pending_index()
        if pending is None:
            return
        if self.items[self.selected_index]["decision"] is not None:
            self.selected_index = pending
        self.add_item(ImageScanFeedbackSelect(self))
        self.add_item(self.confirm_tp)
        self.add_item(self.confirm_fp)
        self.add_item(self.ignore_image)

    async def _finish_interaction(self, interaction: discord.Interaction, note: str) -> None:
        pending = self._next_pending_index()
        if pending is None:
            self.clear_items()
        else:
            self.selected_index = pending
            self._show_individual_controls()
        if interaction.message is not None:
            await interaction.message.edit(content=self.status_content(), view=self)
        await interaction.followup.send(note, ephemeral=True)

    async def _apply_bulk(self, interaction: discord.Interaction, decision: str, token: str) -> None:
        await interaction.response.defer(ephemeral=True)
        if not self._check_perms(interaction):
            await interaction.followup.send(_("You need `Moderate Members` permission."), ephemeral=True)
            return
        if not await self._confirm_text(interaction, token):
            return
        saved = conflicts = 0
        for index, item in enumerate(self.items):
            if item["decision"] is not None:
                continue
            status, _sample = await self._save_item_decision(interaction, index, decision)
            if status in ("inserted", "duplicate"):
                saved += 1
            else:
                conflicts += 1
        self._disable_all()
        if interaction.message is not None:
            await interaction.message.edit(content=self.status_content(), view=self)
        await interaction.followup.send(
            _("Saved: {saved}. Conflicts: {conflicts}.").format(saved=saved, conflicts=conflicts),
            ephemeral=True,
        )

    @discord.ui.button(label="All TP", style=discord.ButtonStyle.danger)
    async def all_tp(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._apply_bulk(interaction, "true_positive", "ALL TP")

    @discord.ui.button(label="All FP", style=discord.ButtonStyle.secondary)
    async def all_fp(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await self._apply_bulk(interaction, "false_positive", "ALL FP")

    @discord.ui.button(label="Ignore all", style=discord.ButtonStyle.success)
    async def ignore_all(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        if not self._check_perms(interaction):
            await interaction.followup.send(_("You need `Moderate Members` permission."), ephemeral=True)
            return
        for item in self.items:
            if item["decision"] is None:
                item["decision"] = "ignored"
        self._disable_all()
        if interaction.message is not None:
            await interaction.message.edit(content=self.status_content(), view=self)
        await interaction.followup.send(_("All images ignored."), ephemeral=True)

    @discord.ui.button(label="Individual", style=discord.ButtonStyle.primary)
    async def individual(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        if not self._check_perms(interaction):
            await interaction.response.send_message(_("You need `Moderate Members` permission."), ephemeral=True)
            return
        self._show_individual_controls()
        await interaction.response.edit_message(content=self.status_content(), view=self)

    @discord.ui.button(label="Confirm TP", style=discord.ButtonStyle.danger)
    async def confirm_tp(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        if not self._check_perms(interaction):
            await interaction.followup.send(_("You need `Moderate Members` permission."), ephemeral=True)
            return
        status, _sample = await self._save_item_decision(interaction, self.selected_index, "true_positive")
        await self._finish_interaction(interaction, _("TP saved.") if status != "conflict" else _("Rejected: TP/FP overlap."))

    @discord.ui.button(label="Confirm FP", style=discord.ButtonStyle.secondary)
    async def confirm_fp(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        if not self._check_perms(interaction):
            await interaction.followup.send(_("You need `Moderate Members` permission."), ephemeral=True)
            return
        status, _sample = await self._save_item_decision(interaction, self.selected_index, "false_positive")
        await self._finish_interaction(interaction, _("FP saved.") if status != "conflict" else _("Rejected: TP/FP overlap."))

    @discord.ui.button(label="Ignore image", style=discord.ButtonStyle.success)
    async def ignore_image(self, interaction: discord.Interaction, button: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        if not self._check_perms(interaction):
            await interaction.followup.send(_("You need `Moderate Members` permission."), ephemeral=True)
            return
        self.items[self.selected_index]["decision"] = "ignored"
        await self._finish_interaction(interaction, _("Image ignored."))


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
            honeypot_channel=None,
            honeypot_channels=[],
            mute_role=None,
            purge_backward_seconds=PURGE_BACKWARD_DEFAULT_SECONDS,
            purge_forward_seconds=PURGE_FORWARD_DEFAULT_SECONDS,
            whitelisted_roles=[],
            firstpost_collect_enabled=False,
            firstpost_enabled=False,
            firstpost_action="review",
            spam_enabled=False,
            spam_action="review",
            spam_window_seconds=10,
            spam_min_channels=2,
            imagescan_enabled=False,
            imagescan_channel=None,
            imagescan_detector_enabled=False,
            imagescan_detector_action="review",
            imagescan_detector_threshold=20,
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

        self._active_views: dict[int, ReviewView] = {}
        self._views_lock: asyncio.Lock = asyncio.Lock()
        self._review_creation_locks: dict[tuple[int, int], asyncio.Lock] = {}
        self._restore_task: asyncio.Task | None = None
        self._post_ban_sweep_tasks: set[asyncio.Task] = set()
        self._recent_user_messages: dict[int, dict[int, deque[MessageRef]]] = defaultdict(
            lambda: defaultdict(deque)
        )
        self._hot_purge_users: dict[int, dict[int, datetime]] = defaultdict(dict)
        self._firstpost_db_path = cog_data_path(self) / "firstpost_seen.sqlite"
        self._firstpost_db_lock: asyncio.Lock = asyncio.Lock()
        self._firstpost_seen_authors: dict[int, set[int]] = defaultdict(set)
        self._firstpost_dirty_seen_authors: dict[int, set[int]] = defaultdict(set)
        self._firstpost_loaded_guilds: set[int] = set()
        self._review_dump_lock: asyncio.Lock = asyncio.Lock()
        self._imagescan_db_path = cog_data_path(self) / "imagescan.sqlite"
        self._imagescan_files_path = cog_data_path(self) / "imagescan_files"
        self._imagescan_db_lock: asyncio.Lock = asyncio.Lock()

    async def _increment_stat(self, guild: discord.Guild, key: str, amount: int = 1) -> None:
        async with self.config.guild(guild).stats() as stats:
            stats.setdefault(key, 0)
            stats[key] += amount

    def _init_firstpost_seen_store_sync(self) -> None:
        self._firstpost_db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._firstpost_db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS firstpost_seen_authors (
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    first_seen_at INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, user_id)
                )
                """
            )

    async def _init_firstpost_seen_store(self) -> None:
        await asyncio.to_thread(self._init_firstpost_seen_store_sync)

    def _init_imagescan_store_sync(self) -> None:
        self._imagescan_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._imagescan_files_path.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS imagescan_events (
                    event_id TEXT PRIMARY KEY,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    message_jump_url TEXT NOT NULL,
                    review_channel_id TEXT,
                    review_message_id TEXT,
                    created_at INTEGER NOT NULL,
                    image_count INTEGER NOT NULL,
                    content TEXT,
                    decision TEXT NOT NULL DEFAULT 'pending',
                    moderator_id TEXT,
                    decided_at INTEGER
                )
                """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS imagescan_events_message_idx
                ON imagescan_events (guild_id, message_id)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS imagescan_files (
                    event_id TEXT NOT NULL,
                    file_index INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content_type TEXT,
                    sha256 TEXT NOT NULL,
                    width INTEGER,
                    height INTEGER,
                    PRIMARY KEY (event_id, file_index)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS imagescan_samples (
                    sample_id TEXT PRIMARY KEY,
                    guild_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    phash TEXT NOT NULL,
                    dhash TEXT NOT NULL,
                    ahash TEXT NOT NULL,
                    source_message_id TEXT,
                    source_channel_id TEXT,
                    source_jump_url TEXT,
                    file_path TEXT,
                    file_size_bytes INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    moderator_id TEXT,
                    active INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.execute("DROP INDEX IF EXISTS imagescan_samples_sha_idx")
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS imagescan_samples_sha_idx
                ON imagescan_samples (guild_id, sha256)
                WHERE active = 1
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS imagescan_model_state (
                    guild_id TEXT PRIMARY KEY,
                    configured_threshold INTEGER NOT NULL DEFAULT 20,
                    effective_threshold INTEGER NOT NULL DEFAULT 20,
                    max_tp_nearest_score INTEGER,
                    min_fp_to_tp_score INTEGER,
                    gap INTEGER,
                    sample_count_tp INTEGER NOT NULL DEFAULT 0,
                    sample_count_fp INTEGER NOT NULL DEFAULT 0,
                    stored_size_bytes INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS imagescan_profile (
                    guild_id TEXT PRIMARY KEY,
                    messages_scanned INTEGER NOT NULL DEFAULT 0,
                    messages_with_images INTEGER NOT NULL DEFAULT 0,
                    images_considered INTEGER NOT NULL DEFAULT 0,
                    images_ignored_over_limit INTEGER NOT NULL DEFAULT 0,
                    exact_tp_hits INTEGER NOT NULL DEFAULT 0,
                    flagged_tp_hits INTEGER NOT NULL DEFAULT 0,
                    download_ms_total INTEGER NOT NULL DEFAULT 0,
                    download_ms_count INTEGER NOT NULL DEFAULT 0,
                    hash_ms_total INTEGER NOT NULL DEFAULT 0,
                    hash_ms_count INTEGER NOT NULL DEFAULT 0,
                    compare_ms_total INTEGER NOT NULL DEFAULT 0,
                    compare_ms_count INTEGER NOT NULL DEFAULT 0,
                    decision_ms_total INTEGER NOT NULL DEFAULT 0,
                    decision_ms_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    async def _init_imagescan_store(self) -> None:
        await asyncio.to_thread(self._init_imagescan_store_sync)

    @staticmethod
    def _imagescan_sample_from_row(row: sqlite3.Row) -> ImageSample:
        return ImageSample(
            sample_id=str(row["sample_id"]),
            decision=str(row["decision"]),
            sha256=str(row["sha256"]),
            phash=str(row["phash"]),
            dhash=str(row["dhash"]),
            ahash=str(row["ahash"]),
        )

    def _imagescan_load_samples_sync(self, guild_id: int) -> list[ImageSample]:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT sample_id, decision, sha256, phash, dhash, ahash
                FROM imagescan_samples
                WHERE guild_id = ? AND active = 1
                """,
                (str(guild_id),),
            ).fetchall()
        return [self._imagescan_sample_from_row(row) for row in rows]

    async def _imagescan_load_samples(self, guild_id: int) -> list[ImageSample]:
        async with self._imagescan_db_lock:
            return await asyncio.to_thread(self._imagescan_load_samples_sync, guild_id)

    def _imagescan_model_state_sync(self, guild_id: int, configured_threshold: int) -> dict[str, typing.Any]:
        samples = self._imagescan_load_samples_sync(guild_id)
        state = rebuild_model_state(samples, configured_threshold)
        state["stored_size_bytes"] = self._imagescan_stored_size_sync(guild_id)
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.execute(
                """
                INSERT INTO imagescan_model_state (
                    guild_id, configured_threshold, effective_threshold,
                    max_tp_nearest_score, min_fp_to_tp_score, gap,
                    sample_count_tp, sample_count_fp, stored_size_bytes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    configured_threshold = excluded.configured_threshold,
                    effective_threshold = excluded.effective_threshold,
                    max_tp_nearest_score = excluded.max_tp_nearest_score,
                    min_fp_to_tp_score = excluded.min_fp_to_tp_score,
                    gap = excluded.gap,
                    sample_count_tp = excluded.sample_count_tp,
                    sample_count_fp = excluded.sample_count_fp,
                    stored_size_bytes = excluded.stored_size_bytes
                """,
                (
                    str(guild_id),
                    int(state["configured_threshold"]),
                    int(state["effective_threshold"]),
                    state.get("max_tp_nearest_score"),
                    state.get("min_fp_to_tp_score"),
                    state.get("gap"),
                    int(state["sample_count_tp"]),
                    int(state["sample_count_fp"]),
                    int(state["stored_size_bytes"]),
                ),
            )
        return state

    async def _imagescan_model_state(self, guild_id: int, configured_threshold: int) -> dict[str, typing.Any]:
        async with self._imagescan_db_lock:
            return await asyncio.to_thread(self._imagescan_model_state_sync, guild_id, configured_threshold)

    def _imagescan_stored_size_sync(self, guild_id: int) -> int:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(file_size_bytes), 0)
                FROM imagescan_samples
                WHERE guild_id = ? AND active = 1
                """,
                (str(guild_id),),
            ).fetchone()
        return int(row[0] or 0)

    def _imagescan_profile_sync(self, guild_id: int) -> dict[str, int]:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                f"SELECT {', '.join(IMAGE_SCAN_PROFILE_COLUMNS)} FROM imagescan_profile WHERE guild_id = ?",
                (str(guild_id),),
            ).fetchone()
        if row is None:
            return {column: 0 for column in IMAGE_SCAN_PROFILE_COLUMNS}
        return {column: int(row[column] or 0) for column in IMAGE_SCAN_PROFILE_COLUMNS}

    async def _imagescan_profile(self, guild_id: int) -> dict[str, int]:
        async with self._imagescan_db_lock:
            return await asyncio.to_thread(self._imagescan_profile_sync, guild_id)

    def _imagescan_increment_profile_sync(self, guild_id: int, increments: dict[str, int]) -> None:
        if not increments:
            return
        filtered = {
            key: int(value)
            for key, value in increments.items()
            if key in IMAGE_SCAN_PROFILE_COLUMNS and value
        }
        if not filtered:
            return
        columns = ["guild_id", *filtered.keys()]
        placeholders = ", ".join("?" for _ in columns)
        updates = ", ".join(f"{key} = {key} + excluded.{key}" for key in filtered)
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.execute(
                f"""
                INSERT INTO imagescan_profile ({", ".join(columns)})
                VALUES ({placeholders})
                ON CONFLICT(guild_id) DO UPDATE SET {updates}
                """,
                (str(guild_id), *filtered.values()),
            )

    async def _imagescan_increment_profile(self, guild_id: int, increments: dict[str, int]) -> None:
        async with self._imagescan_db_lock:
            await asyncio.to_thread(self._imagescan_increment_profile_sync, guild_id, increments)

    def _imagescan_insert_sample_sync(self, sample: dict[str, typing.Any]) -> str:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.row_factory = sqlite3.Row
            existing = conn.execute(
                """
                SELECT decision
                FROM imagescan_samples
                WHERE guild_id = ? AND sha256 = ? AND active = 1
                """,
                (sample["guild_id"], sample["sha256"]),
            ).fetchone()
            if existing is not None:
                return "duplicate" if existing["decision"] == sample["decision"] else "conflict"
            conn.execute(
                """
                INSERT INTO imagescan_samples (
                    sample_id, guild_id, decision, sha256, phash, dhash, ahash,
                    source_message_id, source_channel_id, source_jump_url,
                    file_path, file_size_bytes, created_at, moderator_id, active
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    sample["sample_id"],
                    sample["guild_id"],
                    sample["decision"],
                    sample["sha256"],
                    sample["phash"],
                    sample["dhash"],
                    sample["ahash"],
                    sample.get("source_message_id"),
                    sample.get("source_channel_id"),
                    sample.get("source_jump_url"),
                    sample.get("file_path"),
                    int(sample.get("file_size_bytes") or 0),
                    int(sample["created_at"]),
                    sample.get("moderator_id"),
                ),
            )
        return "inserted"

    async def _imagescan_insert_sample(self, sample: dict[str, typing.Any]) -> str:
        async with self._imagescan_db_lock:
            return await asyncio.to_thread(self._imagescan_insert_sample_sync, sample)

    def _imagescan_sample_rows_sync(self, guild_id: int, include_inactive: bool = False) -> list[dict[str, typing.Any]]:
        where = "guild_id = ?" if include_inactive else "guild_id = ? AND active = 1"
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT sample_id, guild_id, decision, sha256, phash, dhash, ahash,
                       source_message_id, source_channel_id, source_jump_url,
                       file_path, file_size_bytes, created_at, moderator_id, active
                FROM imagescan_samples
                WHERE {where}
                ORDER BY created_at DESC
                """,
                (str(guild_id),),
            ).fetchall()
        return [dict(row) for row in rows]

    async def _imagescan_sample_rows(self, guild_id: int, include_inactive: bool = False) -> list[dict[str, typing.Any]]:
        async with self._imagescan_db_lock:
            return await asyncio.to_thread(self._imagescan_sample_rows_sync, guild_id, include_inactive)

    def _imagescan_update_sample_file_sync(
        self,
        guild_id: int,
        sample_id: str,
        file_path: str | None,
        file_size: int,
    ) -> None:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.execute(
                """
                UPDATE imagescan_samples
                SET file_path = ?, file_size_bytes = ?
                WHERE guild_id = ? AND sample_id = ?
                """,
                (file_path, file_size, str(guild_id), sample_id),
            )

    async def _imagescan_update_sample_file(
        self,
        guild_id: int,
        sample_id: str,
        file_path: str | None,
        file_size: int,
    ) -> None:
        async with self._imagescan_db_lock:
            await asyncio.to_thread(
                self._imagescan_update_sample_file_sync,
                guild_id,
                sample_id,
                file_path,
                file_size,
            )

    def _imagescan_delete_sample_sync(self, guild_id: int, sample_id: str) -> None:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.execute(
                "DELETE FROM imagescan_samples WHERE guild_id = ? AND sample_id = ?",
                (str(guild_id), sample_id),
            )

    async def _imagescan_delete_sample(self, guild_id: int, sample_id: str) -> None:
        async with self._imagescan_db_lock:
            await asyncio.to_thread(self._imagescan_delete_sample_sync, guild_id, sample_id)

    def _imagescan_deactivate_sample_sync(self, guild_id: int, sample_id: str) -> None:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.execute(
                """
                UPDATE imagescan_samples
                SET active = 0
                WHERE guild_id = ? AND sample_id = ?
                """,
                (str(guild_id), sample_id),
            )

    async def _imagescan_deactivate_sample(self, guild_id: int, sample_id: str) -> None:
        async with self._imagescan_db_lock:
            await asyncio.to_thread(self._imagescan_deactivate_sample_sync, guild_id, sample_id)

    async def _imagescan_add_attachment_sample(
        self,
        guild_id: int,
        message: discord.Message,
        attachment: discord.Attachment,
        index: int,
        decision: str,
        moderator_id: int | None,
    ) -> tuple[str, dict[str, typing.Any] | None]:
        try:
            data = await attachment.read(use_cached=True)
        except (discord.HTTPException, discord.Forbidden, discord.NotFound, TypeError) as exc:
            log.debug("Failed to read imagescan sample attachment %s: %r", attachment.filename, exc)
            return "error", None
        hashes = await asyncio.to_thread(image_hashes_from_bytes, data)
        sample_id = f"{message.id}-{index}-{hashes['sha256'][:12]}"
        sample_dir = self._imagescan_files_path / str(guild_id) / "samples" / str(message.id)
        sample_dir.mkdir(parents=True, exist_ok=True)
        filename = self._imagescan_safe_filename(attachment.filename, index)
        path = sample_dir / f"{index:03d}-{hashes['sha256'][:12]}-{filename}"
        try:
            path.write_bytes(data)
        except OSError as exc:
            log.debug("Failed to write imagescan sample %s: %r", path, exc)
            return "error", None
        sample = {
            "sample_id": sample_id,
            "guild_id": str(guild_id),
            "decision": decision,
            "sha256": hashes["sha256"],
            "phash": hashes["phash"],
            "dhash": hashes["dhash"],
            "ahash": hashes["ahash"],
            "source_message_id": str(message.id),
            "source_channel_id": str(message.channel.id),
            "source_jump_url": message.jump_url,
            "file_path": str(path),
            "file_size_bytes": len(data),
            "created_at": int(datetime.now(timezone.utc).timestamp()),
            "moderator_id": str(moderator_id) if moderator_id is not None else None,
        }
        status = await self._imagescan_insert_sample(sample)
        if status != "inserted":
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        return status, sample

    async def _imagescan_add_file_sample(
        self,
        guild_id: int,
        source_path: Path,
        decision: str,
        moderator_id: int | None,
    ) -> tuple[str, dict[str, typing.Any] | None]:
        try:
            data = await asyncio.to_thread(source_path.read_bytes)
        except OSError as exc:
            log.debug("Failed to read imagescan import file %s: %r", source_path, exc)
            return "error", None
        try:
            hashes = await asyncio.to_thread(image_hashes_from_bytes, data)
        except Exception:
            log.debug("Failed to hash imagescan import file %s", source_path, exc_info=True)
            return "error", None
        sample_id = f"import-{hashes['sha256'][:24]}"
        sample_dir = self._imagescan_files_path / str(guild_id) / "samples" / "imports"
        sample_dir.mkdir(parents=True, exist_ok=True)
        filename = self._imagescan_safe_filename(source_path.name, 1)
        path = sample_dir / f"{hashes['sha256'][:12]}-{filename}"
        try:
            await asyncio.to_thread(path.write_bytes, data)
        except OSError as exc:
            log.debug("Failed to write imagescan import sample %s: %r", path, exc)
            return "error", None
        sample = {
            "sample_id": sample_id,
            "guild_id": str(guild_id),
            "decision": decision,
            "sha256": hashes["sha256"],
            "phash": hashes["phash"],
            "dhash": hashes["dhash"],
            "ahash": hashes["ahash"],
            "source_message_id": None,
            "source_channel_id": None,
            "source_jump_url": source_path.as_posix(),
            "file_path": str(path),
            "file_size_bytes": len(data),
            "created_at": int(datetime.now(timezone.utc).timestamp()),
            "moderator_id": str(moderator_id) if moderator_id is not None else None,
        }
        status = await self._imagescan_insert_sample(sample)
        if status != "inserted":
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        return status, sample

    async def _imagescan_add_bytes_sample(
        self,
        guild_id: int,
        data: bytes,
        filename: str,
        source: str,
        decision: str,
        moderator_id: int | None,
    ) -> tuple[str, dict[str, typing.Any] | None]:
        try:
            hashes = await asyncio.to_thread(image_hashes_from_bytes, data)
        except Exception:
            log.debug("Failed to hash imagescan import item %s", filename, exc_info=True)
            return "error", None
        sample_id = f"upload-{hashes['sha256'][:24]}"
        sample_dir = self._imagescan_files_path / str(guild_id) / "samples" / "uploads"
        sample_dir.mkdir(parents=True, exist_ok=True)
        safe_filename = self._imagescan_safe_filename(filename, 1)
        path = sample_dir / f"{hashes['sha256'][:12]}-{safe_filename}"
        try:
            await asyncio.to_thread(path.write_bytes, data)
        except OSError as exc:
            log.debug("Failed to write imagescan upload sample %s: %r", path, exc)
            return "error", None
        sample = {
            "sample_id": sample_id,
            "guild_id": str(guild_id),
            "decision": decision,
            "sha256": hashes["sha256"],
            "phash": hashes["phash"],
            "dhash": hashes["dhash"],
            "ahash": hashes["ahash"],
            "source_message_id": None,
            "source_channel_id": None,
            "source_jump_url": source,
            "file_path": str(path),
            "file_size_bytes": len(data),
            "created_at": int(datetime.now(timezone.utc).timestamp()),
            "moderator_id": str(moderator_id) if moderator_id is not None else None,
        }
        status = await self._imagescan_insert_sample(sample)
        if status != "inserted":
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        return status, sample

    def _load_firstpost_seen_authors_sync(self, guild_id: int) -> set[int]:
        with sqlite3.connect(self._firstpost_db_path) as conn:
            rows = conn.execute(
                "SELECT user_id FROM firstpost_seen_authors WHERE guild_id = ?",
                (str(guild_id),),
            ).fetchall()
        return {int(row[0]) for row in rows}

    def _count_firstpost_seen_authors_sync(self, guild_id: int) -> int:
        with sqlite3.connect(self._firstpost_db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM firstpost_seen_authors WHERE guild_id = ?",
                (str(guild_id),),
            ).fetchone()
        return int(row[0]) if row else 0

    async def _count_firstpost_seen_authors(self, guild_id: int) -> int:
        return await asyncio.to_thread(self._count_firstpost_seen_authors_sync, guild_id)

    async def _ensure_firstpost_seen_loaded(self, guild_id: int) -> None:
        if guild_id in self._firstpost_loaded_guilds:
            return
        async with self._firstpost_db_lock:
            if guild_id in self._firstpost_loaded_guilds:
                return
            seen = await asyncio.to_thread(self._load_firstpost_seen_authors_sync, guild_id)
            self._firstpost_seen_authors[guild_id].update(seen)
            self._firstpost_loaded_guilds.add(guild_id)

    def _flush_firstpost_seen_authors_sync(
        self, dirty: dict[int, set[int]], first_seen_at: int
    ) -> None:
        rows = [
            (str(guild_id), str(user_id), first_seen_at)
            for guild_id, user_ids in dirty.items()
            for user_id in user_ids
        ]
        if not rows:
            return
        with sqlite3.connect(self._firstpost_db_path) as conn:
            conn.executemany(
                """
                INSERT OR IGNORE INTO firstpost_seen_authors
                (guild_id, user_id, first_seen_at)
                VALUES (?, ?, ?)
                """,
                rows,
            )

    async def _flush_firstpost_seen_authors(self) -> None:
        async with self._firstpost_db_lock:
            dirty = {
                guild_id: set(user_ids)
                for guild_id, user_ids in self._firstpost_dirty_seen_authors.items()
                if user_ids
            }
        if not dirty:
            return
        await asyncio.to_thread(
            self._flush_firstpost_seen_authors_sync,
            dirty,
            int(datetime.now(timezone.utc).timestamp()),
        )
        async with self._firstpost_db_lock:
            for guild_id, user_ids in dirty.items():
                remaining = self._firstpost_dirty_seen_authors.get(guild_id)
                if remaining is None:
                    continue
                remaining.difference_update(user_ids)
                if not remaining:
                    self._firstpost_dirty_seen_authors.pop(guild_id, None)

    async def _mark_firstpost_seen(self, guild: discord.Guild, user_id: int) -> bool:
        await self._ensure_firstpost_seen_loaded(guild.id)
        async with self._firstpost_db_lock:
            if user_id in self._firstpost_seen_authors[guild.id]:
                return False
            self._firstpost_seen_authors[guild.id].add(user_id)
            self._firstpost_dirty_seen_authors[guild.id].add(user_id)
        await self._increment_stat(guild, "firstpost_seen")
        return True

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
                "message_fingerprint": view.message_fingerprint,
                "channel_ids": view.channel_ids,
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
        return 0

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
        await self._init_firstpost_seen_store()
        await self._init_imagescan_store()
        self.review_timeout_loop.start()
        self.joinwatch_auto_role_loop.start()
        self.purge_cache_cleanup_loop.start()
        self.firstpost_seen_flush_loop.start()
        self._restore_task = asyncio.create_task(self._restore_pending_reviews())

    async def cog_unload(self) -> None:
        self.review_timeout_loop.cancel()
        self.joinwatch_auto_role_loop.cancel()
        self.purge_cache_cleanup_loop.cancel()
        self.firstpost_seen_flush_loop.cancel()
        if self._restore_task is not None:
            self._restore_task.cancel()
        pending_sweeps = tuple(self._post_ban_sweep_tasks)
        for task in pending_sweeps:
            task.cancel()
        if pending_sweeps:
            await asyncio.gather(*pending_sweeps, return_exceptions=True)
        self._post_ban_sweep_tasks.clear()
        await self._flush_firstpost_seen_authors()
        await super().cog_unload()

    @tasks.loop(seconds=60)
    async def firstpost_seen_flush_loop(self) -> None:
        await self._flush_firstpost_seen_authors()

    @tasks.loop(minutes=1)
    async def purge_cache_cleanup_loop(self) -> None:
        configs = {int(guild_id): config for guild_id, config in (await self.config.all_guilds()).items()}
        self._prune_purge_cache(configs)

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
                        message_fingerprint=data.get("message_fingerprint"),
                        channel_ids=data.get("channel_ids", []),
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
        await self._restore_imagescan_views()

    def _pending_imagescan_views_sync(self) -> list[tuple[int, str, int]]:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            rows = conn.execute(
                """
                SELECT guild_id, event_id, review_message_id
                FROM imagescan_events
                WHERE decision = 'pending'
                AND review_message_id IS NOT NULL
                """
            ).fetchall()
        return [(int(row[0]), str(row[1]), int(row[2])) for row in rows]

    async def _restore_imagescan_views(self) -> None:
        try:
            rows = await asyncio.to_thread(self._pending_imagescan_views_sync)
        except Exception:
            log.exception("Failed to load pending image scan views")
            return
        for guild_id, event_id, review_message_id in rows:
            try:
                view = ImageScanReviewView(self, event_id, guild_id)
                self.bot.add_view(view, message_id=review_message_id)
            except Exception:
                log.exception("Failed to restore image scan view %s", review_message_id)

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
            ReviewView._remove_review_expiry_field(embed)
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
        matched_keywords = matched_scam_keywords(scam_keywords, content)
        if matched_keywords:
            reasons.append(_("Matched keywords: {keywords}").format(keywords=", ".join(matched_keywords[:5])))
        if message.attachments and message.author.created_at > datetime.now(timezone.utc) - timedelta(days=14):
            reasons.append(_("Attachment from an account under 14 days old"))
        image_attachment_count = sum(1 for attachment in message.attachments if is_image_attachment(attachment))
        if image_attachment_count >= 4:
            reasons.append(_("Multiple image attachments: {count}").format(count=image_attachment_count))
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

    def _record_recent_user_message(self, message: discord.Message, config: dict) -> None:
        if message.guild is None:
            return
        refs = self._recent_user_messages[message.guild.id][message.author.id]
        refs.append(
            MessageRef(
                message.channel.id,
                message.id,
                message.created_at,
                message_spam_fingerprint(message),
            )
        )
        self._prune_recent_user_messages(
            message.guild.id,
            message.author.id,
            retention_seconds=self._purge_retention_seconds(config),
        )

    @staticmethod
    def _purge_backward_seconds(config: dict) -> int:
        value = int(config.get("purge_backward_seconds", PURGE_BACKWARD_DEFAULT_SECONDS) or 0)
        return max(PURGE_MIN_RETENTION_SECONDS, min(value, PURGE_BACKWARD_MAX_SECONDS))

    @staticmethod
    def _purge_forward_seconds(config: dict) -> int:
        value = int(config.get("purge_forward_seconds", PURGE_FORWARD_DEFAULT_SECONDS) or 0)
        return max(0, min(value, PURGE_FORWARD_MAX_SECONDS))

    @staticmethod
    def _purge_retention_seconds(config: dict | None = None) -> int:
        if config is None:
            return PURGE_MIN_RETENTION_SECONDS
        return max(PURGE_MIN_RETENTION_SECONDS, Honeypot._purge_backward_seconds(config))

    def _prune_recent_user_messages(
        self, guild_id: int, user_id: int, *, retention_seconds: int = PURGE_MIN_RETENTION_SECONDS
    ) -> None:
        refs = self._recent_user_messages.get(guild_id, {}).get(user_id)
        if not refs:
            return
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=retention_seconds)
        while refs and refs[0].created_at < cutoff:
            refs.popleft()
        if not refs:
            self._recent_user_messages[guild_id].pop(user_id, None)

    def _prune_purge_cache(self, configs_by_guild_id: dict[int, dict] | None = None) -> None:
        now = datetime.now(timezone.utc)
        for guild_id, users in list(self._recent_user_messages.items()):
            retention_seconds = self._purge_retention_seconds(
                (configs_by_guild_id or {}).get(guild_id)
            )
            for user_id in list(users):
                self._prune_recent_user_messages(
                    guild_id, user_id, retention_seconds=retention_seconds
                )
            if not users:
                self._recent_user_messages.pop(guild_id, None)
        for guild_id, users in list(self._hot_purge_users.items()):
            for user_id, expires_at in list(users.items()):
                if expires_at <= now:
                    users.pop(user_id, None)
            if not users:
                self._hot_purge_users.pop(guild_id, None)

    def _activate_forward_purge(
        self, guild_id: int, user_id: int, config: dict
    ) -> None:
        forward_seconds = self._purge_forward_seconds(config)
        if forward_seconds <= 0:
            self._deactivate_forward_purge(guild_id, user_id)
            return
        self._hot_purge_users[guild_id][user_id] = datetime.now(timezone.utc) + timedelta(
            seconds=forward_seconds
        )

    def _deactivate_forward_purge(self, guild_id: int, user_id: int) -> None:
        users = self._hot_purge_users.get(guild_id)
        if users is not None:
            users.pop(user_id, None)

    def _is_forward_purge_active(self, guild_id: int, user_id: int) -> bool:
        expires_at = self._hot_purge_users.get(guild_id, {}).get(user_id)
        if expires_at is None:
            return False
        if expires_at <= datetime.now(timezone.utc):
            self._hot_purge_users[guild_id].pop(user_id, None)
            return False
        return True

    def _get_cached_message_channel(
        self, guild: discord.Guild, channel_id: int
    ) -> typing.Any | None:
        return guild.get_channel(channel_id) or guild.get_thread(channel_id)

    async def _delete_cached_message_ref(
        self, guild: discord.Guild, user_id: int, ref: MessageRef
    ) -> bool:
        channel = self._get_cached_message_channel(guild, ref.channel_id)
        if channel is None:
            return False
        get_partial_message = getattr(channel, "get_partial_message", None)
        if not callable(get_partial_message):
            return False
        try:
            await get_partial_message(ref.message_id).delete()
            return True
        except discord.NotFound:
            return False
        except (discord.Forbidden, discord.HTTPException) as exc:
            log.debug(
                "Failed to delete cached message %s for user %s in channel %s: %r",
                ref.message_id,
                user_id,
                ref.channel_id,
                exc,
            )
            return False

    async def _delete_recent_cached_user_messages(
        self,
        guild: discord.Guild,
        user_id: int,
        *,
        exclude_message_id: int | None = None,
        retention_seconds: int = PURGE_MIN_RETENTION_SECONDS,
    ) -> int:
        self._prune_recent_user_messages(
            guild.id, user_id, retention_seconds=retention_seconds
        )
        refs = list(self._recent_user_messages.get(guild.id, {}).get(user_id, ()))
        total = 0
        for ref in refs:
            if exclude_message_id is not None and ref.message_id == exclude_message_id:
                continue
            if await self._delete_cached_message_ref(guild, user_id, ref):
                total += 1
        return total

    def _count_recent_cached_user_messages(
        self,
        guild: discord.Guild,
        user_id: int,
        config: dict,
        *,
        exclude_message_id: int | None = None,
    ) -> int:
        retention_seconds = self._purge_retention_seconds(config)
        self._prune_recent_user_messages(
            guild.id, user_id, retention_seconds=retention_seconds
        )
        refs = self._recent_user_messages.get(guild.id, {}).get(user_id, ())
        return sum(
            1
            for ref in refs
            if exclude_message_id is None or ref.message_id != exclude_message_id
        )

    def _dry_run_purge_label(
        self,
        guild: discord.Guild,
        user_id: int,
        config: dict,
        *,
        include_current_message: bool = False,
        current_message_id: int | None = None,
    ) -> str:
        backward_seconds = self._purge_retention_seconds(config)
        forward_seconds = self._purge_forward_seconds(config)
        cached_count = self._count_recent_cached_user_messages(
            guild,
            user_id,
            config,
            exclude_message_id=current_message_id if include_current_message else None,
        )
        if include_current_message:
            cached_count += 1
        return _(
            "Dry run: I would purge {count} cached message(s) from the last {backward}s and forward-purge new messages for {forward}s."
        ).format(
            count=cached_count,
            backward=backward_seconds,
            forward=forward_seconds,
        )

    async def _cached_purge_user_messages(
        self,
        guild: discord.Guild,
        user_id: int,
        config: dict,
        *,
        exclude_message_id: int | None = None,
    ) -> int:
        retention_seconds = self._purge_retention_seconds(config)
        deleted = await self._delete_recent_cached_user_messages(
            guild,
            user_id,
            exclude_message_id=exclude_message_id,
            retention_seconds=retention_seconds,
        )
        self._activate_forward_purge(guild.id, user_id, config)
        return deleted

    async def _purge_after_review_action(self, guild: discord.Guild, user_id: int, config: dict) -> None:
        deleted = await self._cached_purge_user_messages(guild, user_id, config)
        if deleted:
            await self._increment_stat(guild, "purged_messages", deleted)
            await self._increment_stat(guild, "cached_purge_deletes", deleted)

    async def _delete_forward_purge_message(self, message: discord.Message) -> bool:
        try:
            await message.delete()
            return True
        except discord.NotFound:
            return False
        except (discord.Forbidden, discord.HTTPException) as exc:
            log.debug(
                "Failed to forward-purge message %s from user %s in guild %s: %r",
                message.id,
                message.author.id,
                message.guild.id if message.guild else "unknown",
                exc,
            )
            return False

    def _firstpost_suspicion_reasons(
        self, message: discord.Message, config: dict
    ) -> list[str]:
        attachment_count = len(message.attachments)
        reasons: list[str] = []
        content = message.content.strip().lower()
        if attachment_count == 4:
            reasons.append(_("First post with four attachments"))
        elif attachment_count == 2:
            scam_keywords = config.get("scam_keywords") or SCAM_KEYWORDS
            matched_keywords = matched_scam_keywords(
                scam_keywords,
                content,
                include_attachment_only=True,
            )
            if matched_keywords:
                reasons.append(
                    _("First post with two attachments and keywords: {keywords}").format(
                        keywords=", ".join(matched_keywords[:5])
                    )
                )
        return reasons

    async def _delete_firstpost_current_message(self, message: discord.Message) -> bool:
        try:
            await message.delete()
            return True
        except discord.NotFound:
            return True
        except discord.HTTPException:
            log.debug("Failed to delete firstpost message from user %s", message.author.id)
            return False

    async def _finish_firstpost_response(
        self, message: discord.Message, config: dict, *, message_deleted: bool
    ) -> None:
        if config.get("dry_run"):
            return
        purged = await self._cached_purge_user_messages(
            message.guild,
            message.author.id,
            config,
            exclude_message_id=message.id if message_deleted else None,
        )
        if purged:
            await self._increment_stat(message.guild, "purged_messages", purged)
            await self._increment_stat(message.guild, "cached_purge_deletes", purged)

    def _spam_suspicion_reasons(self, message: discord.Message, config: dict) -> list[str]:
        window_seconds = int(config.get("spam_window_seconds", 10) or 10)
        window_seconds = max(SPAM_WINDOW_MIN_SECONDS, min(window_seconds, SPAM_WINDOW_MAX_SECONDS))
        min_channels = int(config.get("spam_min_channels", 2) or 2)
        min_channels = max(SPAM_CHANNEL_MIN, min(min_channels, SPAM_CHANNEL_MAX))
        content = message.content.strip().lower()
        scam_keywords = config.get("scam_keywords") or SCAM_KEYWORDS
        has_signal = bool(message.attachments) or bool(matched_scam_keywords(scam_keywords, content))
        if not has_signal:
            return []
        current_fingerprint = message_spam_fingerprint(message)
        cutoff = message.created_at - timedelta(seconds=window_seconds)
        channel_ids = {
            ref.channel_id
            for ref in self._recent_user_messages.get(message.guild.id, {}).get(message.author.id, ())
            if ref.fingerprint == current_fingerprint and ref.created_at >= cutoff
        }
        if len(channel_ids) < min_channels:
            return []
        return [
            _("Same message in {count} channels within {seconds}s").format(
                count=len(channel_ids),
                seconds=window_seconds,
            )
        ]

    async def _delete_spam_current_message(self, message: discord.Message) -> bool:
        try:
            await message.delete()
            return True
        except discord.NotFound:
            return True
        except discord.HTTPException:
            log.debug("Failed to delete spam message from user %s", message.author.id)
            return False

    async def _finish_spam_response(
        self, message: discord.Message, config: dict, *, message_deleted: bool
    ) -> None:
        if config.get("dry_run"):
            return
        purged = await self._cached_purge_user_messages(
            message.guild,
            message.author.id,
            config,
            exclude_message_id=message.id if message_deleted else None,
        )
        if purged:
                await self._increment_stat(message.guild, "purged_messages", purged)
                await self._increment_stat(message.guild, "cached_purge_deletes", purged)

    async def _prepare_imagescan_learning_feedback(
        self,
        message: discord.Message,
        config: dict,
        embed: discord.Embed,
        attachment_snapshots: list[dict[str, typing.Any]],
    ) -> ImageScanFeedbackView | None:
        image_items = [
            (index, attachment, attachment_snapshots[index])
            for index, attachment in enumerate(message.attachments[: len(attachment_snapshots)])
            if self._imagescan_is_image_attachment(attachment)
        ]
        if not image_items:
            embed.add_field(
                name=_("Image Detection:"),
                value=_(format_image_detection_status("no_images")),
                inline=False,
            )
            return None

        considered = image_items[:IMAGE_SCAN_MAX_ATTACHMENTS]
        samples = await self._imagescan_load_samples(message.guild.id)
        if not any(sample.decision == "true_positive" for sample in samples):
            embed.add_field(
                name=_("Image Detection:"),
                value=_(format_image_detection_status("not_checked")),
                inline=False,
            )
            return None

        state = await self._imagescan_model_state(
            message.guild.id,
            int(config.get("imagescan_detector_threshold", 20)),
        )
        if not state["valid"]:
            embed.add_field(
                name=_("Image Detection:"),
                value=_(format_image_detection_status("not_checked")),
                inline=False,
            )
            return None

        unknown_feedback: list[tuple[discord.Attachment, int, bytes]] = []
        has_known_match = False
        for message_index, attachment, snapshot in considered:
            data = snapshot.get("data")
            if data is None:
                continue
            try:
                hashes = await asyncio.to_thread(image_hashes_from_bytes, data)
            except Exception:
                log.debug("Failed to hash imagescan learning attachment %s", attachment.filename, exc_info=True)
                continue
            result = match_image(hashes, samples, int(state["effective_threshold"]))
            if result["matched"] or result.get("exact_decision") is not None:
                has_known_match = True
                continue
            if result.get("exact_decision") is None:
                unknown_feedback.append((attachment, message_index + 1, data))

        status = "queued" if unknown_feedback else image_learning_status(
            has_images=True,
            has_known_match=has_known_match,
            can_queue=False,
        )
        embed.add_field(
            name=_("Image Detection:"),
            value=_(format_image_detection_status(status)),
            inline=False,
        )
        if status != "queued":
            return None
        return ImageScanFeedbackView(self, message, unknown_feedback)

    async def _send_imagescan_feedback_messages(
        self,
        channel: discord.TextChannel | discord.Thread | None,
        message: discord.Message,
        view: ImageScanFeedbackView | None,
    ) -> None:
        if channel is None or view is None:
            return
        try:
            await channel.send(
                view.status_content(),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            log.debug("Failed to send imagescan feedback message for %s", message.id)

    async def _handle_imagescan_detector_message(
        self,
        message: discord.Message,
        config: dict,
        logs_channel: discord.TextChannel | discord.Thread | None,
    ) -> bool:
        if not config.get("imagescan_detector_enabled", False):
            return False
        image_attachments = [
            attachment
            for attachment in message.attachments
            if self._imagescan_is_image_attachment(attachment)
        ]
        if not image_attachments:
            return False

        started_at = datetime.now(timezone.utc)
        considered = image_attachments[:IMAGE_SCAN_MAX_ATTACHMENTS]
        ignored_over_limit = max(0, len(image_attachments) - len(considered))
        profile: dict[str, int] = {
            "messages_scanned": 1,
            "messages_with_images": 1,
            "images_considered": len(considered),
            "images_ignored_over_limit": ignored_over_limit,
        }
        samples = await self._imagescan_load_samples(message.guild.id)
        if not any(sample.decision == "true_positive" for sample in samples):
            await self._imagescan_increment_profile(message.guild.id, profile)
            return False
        state = await self._imagescan_model_state(
            message.guild.id,
            int(config.get("imagescan_detector_threshold", 20)),
        )
        if not state["valid"]:
            await self._imagescan_increment_profile(message.guild.id, profile)
            return False

        matches: list[tuple[discord.Attachment, dict[str, typing.Any], dict[str, str]]] = []
        for attachment in considered:
            download_started = datetime.now(timezone.utc)
            try:
                data = await attachment.read(use_cached=True)
            except (discord.HTTPException, discord.Forbidden, discord.NotFound, TypeError):
                continue
            profile["download_ms_total"] = profile.get("download_ms_total", 0) + int(
                (datetime.now(timezone.utc) - download_started).total_seconds() * 1000
            )
            profile["download_ms_count"] = profile.get("download_ms_count", 0) + 1

            hash_started = datetime.now(timezone.utc)
            try:
                hashes = await asyncio.to_thread(image_hashes_from_bytes, data)
            except Exception:
                log.debug("Failed to hash imagescan attachment %s", attachment.filename, exc_info=True)
                continue
            profile["hash_ms_total"] = profile.get("hash_ms_total", 0) + int(
                (datetime.now(timezone.utc) - hash_started).total_seconds() * 1000
            )
            profile["hash_ms_count"] = profile.get("hash_ms_count", 0) + 1

            compare_started = datetime.now(timezone.utc)
            result = match_image(hashes, samples, int(state["effective_threshold"]))
            profile["compare_ms_total"] = profile.get("compare_ms_total", 0) + int(
                (datetime.now(timezone.utc) - compare_started).total_seconds() * 1000
            )
            profile["compare_ms_count"] = profile.get("compare_ms_count", 0) + 1
            if result["matched"]:
                matches.append((attachment, result, hashes))
                if result["exact_decision"] == "true_positive":
                    profile["exact_tp_hits"] = profile.get("exact_tp_hits", 0) + 1
                else:
                    profile["flagged_tp_hits"] = profile.get("flagged_tp_hits", 0) + 1

        profile["decision_ms_total"] = int((datetime.now(timezone.utc) - started_at).total_seconds() * 1000)
        profile["decision_ms_count"] = 1
        await self._imagescan_increment_profile(message.guild.id, profile)
        if not matches:
            return False

        attachment_snapshots = await self._snapshot_attachments(message)
        best_attachment, best_match, _hashes = matches[0]
        feedback_items = imagescan_feedback_items(considered, matches, attachment_snapshots)
        feedback_view = ImageScanFeedbackView(self, message, feedback_items) if feedback_items else None
        embed = discord.Embed(
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
        embed.add_field(name=_("Reason:"), value=_("Honeypot"), inline=False)
        embed.add_field(name=_("Channel:"), value=getattr(message.channel, "mention", f"<#{message.channel.id}>"), inline=True)
        embed.add_field(
            name=_("Hash Diff:"),
            value=format_image_hash_diff(best_match["score"], best_match["threshold"]),
            inline=True,
        )
        attachment_field = _("Attachments:") if len(matches) != 1 else _("Attachment:")
        embed.add_field(
            name=attachment_field,
            value=format_imagescan_matched_attachments(matches),
            inline=True,
        )
        embed.set_footer(text=message.guild.name, icon_url=message.guild.icon)

        action = config.get("imagescan_detector_action", "review")
        if action not in IMAGE_SCAN_DETECTOR_ACTION_OPTIONS:
            action = "review"
        review_channel = self._get_text_channel_or_thread(message.guild, config.get("review_channel"))
        message_deleted = False
        if action == "review":
            if review_channel is not None:
                merged = await self._send_review(
                    message,
                    config,
                    embed,
                    review_channel,
                    logs_channel,
                    attachment_snapshots,
                )
                if not merged and feedback_view is not None:
                    try:
                        await review_channel.send(
                            feedback_view.status_content(),
                            view=feedback_view,
                            allowed_mentions=discord.AllowedMentions.none(),
                        )
                    except discord.HTTPException:
                        log.debug("Failed to send imagescan feedback message for %s", message.id)
            else:
                embed.color = discord.Color.orange()
                embed.add_field(name=_("Action:"), value=_("Review channel is not configured."), inline=False)
                await self._send_log(logs_channel, embed, attachment_snapshots, view=feedback_view)
            if not config.get("dry_run"):
                message_deleted = await self._delete_spam_current_message(message)
            await self._finish_spam_response(message, config, message_deleted=message_deleted)
            return True
        if action in ("kick", "ban"):
            action_label, failed = await self._execute_action(
                message,
                config,
                reason="Honeypot",
                action=action,
            )
            embed.add_field(name=_("Action:"), value=failed if failed else action_label, inline=False)
            if failed:
                embed.color = discord.Color.dark_red()
            if not config.get("dry_run"):
                message_deleted = await self._delete_spam_current_message(message)
            await self._send_log(logs_channel, embed, attachment_snapshots, view=feedback_view)
            await self._finish_spam_response(message, config, message_deleted=message_deleted)
            return True

        embed.add_field(name=_("Action:"), value=_("Detector matched; no punishment configured."), inline=False)
        await self._send_log(logs_channel, embed, attachment_snapshots, view=feedback_view)
        return True

    async def _handle_spam_message(
        self,
        message: discord.Message,
        config: dict,
        logs_channel: discord.TextChannel | discord.Thread | None,
    ) -> bool:
        if not config.get("spam_enabled", False):
            return False
        suspicion_reasons = self._spam_suspicion_reasons(message, config)
        if not suspicion_reasons:
            return False
        await self._increment_stat(message.guild, "spam_hits")
        action = config.get("spam_action", "review")
        if action not in CORE_ACTION_OPTIONS:
            action = "review"
        if action == "none":
            return False

        attachment_snapshots = await self._snapshot_attachments(message)
        embed: discord.Embed = discord.Embed(
            title=_("Spam hit"),
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
        embed.add_field(
            name=_("Trigger reasons:"),
            value="\n".join(f"- {reason}" for reason in suspicion_reasons),
            inline=False,
        )
        embed.set_footer(text=message.guild.name, icon_url=message.guild.icon)
        feedback_views = await self._prepare_imagescan_learning_feedback(message, config, embed, attachment_snapshots)

        review_channel = None
        if config.get("review_channel") is not None:
            review_channel = self._get_text_channel_or_thread(message.guild, config["review_channel"])

        message_deleted = False
        if action == "review":
            if config.get("dry_run"):
                embed.add_field(
                    name=_("Purge:"),
                    value=self._dry_run_purge_label(
                        message.guild,
                        message.author.id,
                        config,
                        include_current_message=True,
                        current_message_id=message.id,
                    ),
                    inline=False,
                )
            if review_channel is not None:
                merged = await self._send_review(
                    message,
                    config,
                    embed,
                    review_channel,
                    logs_channel,
                    attachment_snapshots,
                )
                if not merged:
                    await self._send_imagescan_feedback_messages(review_channel, message, feedback_views)
                await self._increment_stat(message.guild, "spam_reviews")
                await self._increment_stat(message.guild, "spam_catches")
            else:
                embed.color = discord.Color.orange()
                embed.add_field(
                    name=_("Action:"),
                    value=_("No action taken. Spam review needs a review channel."),
                    inline=False,
                )
                await self._send_log(logs_channel, embed, attachment_snapshots)
                await self._send_imagescan_feedback_messages(logs_channel, message, feedback_views)
            if not config.get("dry_run"):
                message_deleted = await self._delete_spam_current_message(message)
            await self._finish_spam_response(message, config, message_deleted=message_deleted)
            return True

        action_label, failed = await self._execute_action(
            message,
            config,
            reason="Same message in multiple channels",
            action=action,
        )
        embed.add_field(name=_("Action:"), value=failed if failed else action_label, inline=False)
        if failed:
            embed.color = discord.Color.dark_red()
            embed.add_field(name=_("Staff check needed:"), value=_("Spam action failed."), inline=False)
        else:
            await self._increment_stat(message.guild, "spam_catches")
            if action == "kick":
                await self._increment_stat(message.guild, "spam_kicks")
            elif action == "ban":
                await self._increment_stat(message.guild, "spam_bans")
        if config.get("dry_run"):
            embed.add_field(
                name=_("Purge:"),
                value=self._dry_run_purge_label(
                    message.guild,
                    message.author.id,
                    config,
                    include_current_message=True,
                    current_message_id=message.id,
                ),
                inline=False,
            )
        else:
            message_deleted = await self._delete_spam_current_message(message)
        await self._send_log(logs_channel, embed, attachment_snapshots)
        await self._send_imagescan_feedback_messages(logs_channel, message, feedback_views)
        await self._finish_spam_response(message, config, message_deleted=message_deleted)
        return True

    async def _handle_firstpost_message(
        self,
        message: discord.Message,
        config: dict,
        logs_channel: discord.TextChannel | discord.Thread | None,
    ) -> bool:
        firstpost_enabled = config.get("firstpost_enabled", False)
        collect_enabled = config.get("firstpost_collect_enabled", False)
        if not firstpost_enabled and not collect_enabled:
            return False
        if not await self._mark_firstpost_seen(message.guild, message.author.id):
            return False
        if not firstpost_enabled:
            return False
        suspicion_reasons = self._firstpost_suspicion_reasons(message, config)
        if not suspicion_reasons:
            return False
        await self._increment_stat(message.guild, "firstpost_hits")
        action = config.get("firstpost_action", "review")
        if action not in CORE_ACTION_OPTIONS:
            action = "review"
        if action == "none":
            return False

        attachment_snapshots = await self._snapshot_attachments(message)
        embed: discord.Embed = discord.Embed(
            title=_("Firstpost hit"),
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
        embed.add_field(
            name=_("Trigger reasons:"),
            value="\n".join(f"- {reason}" for reason in suspicion_reasons),
            inline=False,
        )
        embed.set_footer(text=message.guild.name, icon_url=message.guild.icon)
        feedback_views = await self._prepare_imagescan_learning_feedback(message, config, embed, attachment_snapshots)

        review_channel = None
        if config.get("review_channel") is not None:
            review_channel = self._get_text_channel_or_thread(message.guild, config["review_channel"])

        message_deleted = False
        if action == "review":
            if config.get("dry_run"):
                embed.add_field(
                    name=_("Purge:"),
                    value=self._dry_run_purge_label(
                        message.guild,
                        message.author.id,
                        config,
                        include_current_message=True,
                        current_message_id=message.id,
                    ),
                    inline=False,
                )
            if review_channel is not None:
                merged = await self._send_review(
                    message,
                    config,
                    embed,
                    review_channel,
                    logs_channel,
                    attachment_snapshots,
                )
                if not merged:
                    await self._send_imagescan_feedback_messages(review_channel, message, feedback_views)
                await self._increment_stat(message.guild, "firstpost_reviews")
                await self._increment_stat(message.guild, "early_catches")
            else:
                embed.color = discord.Color.orange()
                embed.add_field(
                    name=_("Action:"),
                    value=_("No action taken. Firstpost review needs a review channel."),
                    inline=False,
                )
                await self._send_log(logs_channel, embed, attachment_snapshots)
                await self._send_imagescan_feedback_messages(logs_channel, message, feedback_views)
            if not config.get("dry_run"):
                message_deleted = await self._delete_firstpost_current_message(message)
            await self._finish_firstpost_response(message, config, message_deleted=message_deleted)
            return True

        action_label, failed = await self._execute_action(
            message,
            config,
            reason="Suspicious first observed message.",
            action=action,
        )
        embed.add_field(name=_("Action:"), value=failed if failed else action_label, inline=False)
        if failed:
            embed.color = discord.Color.dark_red()
            embed.add_field(name=_("Staff check needed:"), value=_("Firstpost action failed."), inline=False)
        else:
            await self._increment_stat(message.guild, "early_catches")
            if action == "kick":
                await self._increment_stat(message.guild, "firstpost_kicks")
            elif action == "ban":
                await self._increment_stat(message.guild, "firstpost_bans")
        if config.get("dry_run"):
            embed.add_field(
                name=_("Purge:"),
                value=self._dry_run_purge_label(
                    message.guild,
                    message.author.id,
                    config,
                    include_current_message=True,
                    current_message_id=message.id,
                ),
                inline=False,
            )
        else:
            message_deleted = await self._delete_firstpost_current_message(message)
        await self._send_log(logs_channel, embed, attachment_snapshots)
        await self._send_imagescan_feedback_messages(logs_channel, message, feedback_views)
        await self._finish_firstpost_response(message, config, message_deleted=message_deleted)
        return True

    def _schedule_post_ban_sweep(self, guild: discord.Guild, user_id: int) -> None:
        """After ban: wait, then delete this user's recent cached messages."""
        task = self.bot.loop.create_task(
            self._post_ban_message_sweep(
                guild.id, user_id
            ),
            name=f"honeypot-post-ban-sweep-{guild.id}-{user_id}",
        )
        self._post_ban_sweep_tasks.add(task)
        task.add_done_callback(self._post_ban_sweep_tasks.discard)

    async def _post_ban_message_sweep(self, guild_id: int, user_id: int) -> None:
        try:
            await asyncio.sleep(POST_BAN_SWEEP_DELAY_SECONDS)
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                return
            config = await self.config.guild(guild).all()
            deleted = await self._cached_purge_user_messages(guild, user_id, config)
            if deleted:
                await self._increment_stat(guild, "purged_messages", deleted)
                await self._increment_stat(guild, "cached_purge_deletes", deleted)
        except Exception:
            log.exception(
                "Post-ban cached message purge failed for user %s in guild %s",
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
                self._activate_forward_purge(message.guild.id, message.author.id, config)
                try:
                    await message.author.kick(reason=reason)
                except discord.NotFound:
                    if self._automated_kick_fail_warning_enabled(config):
                        self._deactivate_forward_purge(message.guild.id, message.author.id)
                        return await self._create_kick_fail_warning(message.guild, message.author.id)
                    raise
                await self._increment_stat(message.guild, "kicked")
            elif action == "ban":
                self._activate_forward_purge(message.guild.id, message.author.id, config)
                await message.author.ban(
                    reason=reason,
                    delete_message_seconds=self._ban_delete_message_seconds(config),
                )
                self._schedule_post_ban_sweep(message.guild, message.author.id)
                await self._increment_stat(message.guild, "banned")
        except discord.HTTPException as e:
            self._deactivate_forward_purge(message.guild.id, message.author.id)
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

    def _format_review_channels(self, guild: discord.Guild, channel_ids: list[int]) -> str:
        values = []
        for channel_id in dict.fromkeys(channel_ids):
            channel = self._get_text_channel_or_thread(guild, channel_id)
            values.append(getattr(channel, "mention", f"<#{channel_id}>"))
        return "\n".join(values) or _("Unknown channel")

    @staticmethod
    def _embed_field_index(embed: discord.Embed, *names: str) -> int | None:
        for index, field in enumerate(embed.fields):
            if field.name in names:
                return index
        return None

    def _upsert_embed_field(
        self,
        embed: discord.Embed,
        name: str,
        value: str,
        *,
        inline: bool = False,
        aliases: tuple[str, ...] = (),
    ) -> None:
        index = self._embed_field_index(embed, name, *aliases)
        if index is None:
            embed.add_field(name=name, value=value, inline=inline)
        else:
            embed.set_field_at(index, name=name, value=value, inline=inline)

    @staticmethod
    def _embed_trigger_reasons(embed: discord.Embed) -> list[str]:
        index = Honeypot._embed_field_index(embed, _("Trigger reasons:"))
        if index is None:
            return []
        reasons = []
        for line in embed.fields[index].value.splitlines():
            reason = line.strip()
            if reason.startswith("- "):
                reason = reason[2:].strip()
            if reason:
                reasons.append(reason)
        return reasons

    def _merge_embed_trigger_reasons(self, target: discord.Embed, source: discord.Embed) -> None:
        reasons = list(dict.fromkeys(self._embed_trigger_reasons(target) + self._embed_trigger_reasons(source)))
        if not reasons:
            return
        self._upsert_embed_field(
            target,
            _("Trigger reasons:"),
            "\n".join(f"- {reason}" for reason in reasons),
            inline=False,
        )

    async def _find_active_review_for_user(self, guild_id: int, user_id: int) -> ReviewView | None:
        async with self._views_lock:
            for view in self._active_views.values():
                if (
                    view.guild_id == guild_id
                    and view.target_id == user_id
                    and view.review_message is not None
                    and not view._resolution_started
                ):
                    return view
        return None

    async def _update_pending_review_merge_data(self, guild: discord.Guild, view: ReviewView) -> None:
        if view.active_key is None:
            return
        async with self.config.guild(guild).pending_reviews() as pending_reviews:
            pending_review = pending_reviews.get(str(view.active_key))
            if pending_review is not None:
                pending_review["message_fingerprint"] = view.message_fingerprint
                pending_review["channel_ids"] = view.channel_ids

    async def _merge_into_active_review(
        self,
        view: ReviewView,
        message: discord.Message,
        embed: discord.Embed,
        attachment_snapshots: list[dict[str, typing.Any]],
    ) -> bool:
        if view.review_message is None:
            return False
        active_embed = view.review_message.embeds[0] if view.review_message.embeds else None
        if active_embed is None:
            return False
        merged_embed = discord.Embed.from_dict(active_embed.to_dict())
        if message.channel.id not in view.channel_ids:
            view.channel_ids.append(message.channel.id)
        current_fingerprint = message_spam_fingerprint(message)
        if view.message_fingerprint is None:
            view.message_fingerprint = current_fingerprint
        self._upsert_embed_field(
            merged_embed,
            _("Channels:"),
            self._format_review_channels(message.guild, view.channel_ids),
            inline=False,
            aliases=(_("Channel:"),),
        )
        self._merge_embed_trigger_reasons(merged_embed, embed)
        try:
            await view.review_message.edit(embed=merged_embed, view=view)
        except discord.HTTPException:
            log.debug("Failed to merge review message %s", view.review_message.id)
            return False
        await self._update_pending_review_merge_data(message.guild, view)
        return True

    async def _send_review(
        self,
        message: discord.Message,
        config: dict,
        embed: discord.Embed,
        review_channel: discord.TextChannel | discord.Thread,
        logs_channel: discord.TextChannel | discord.Thread | None,
        attachment_snapshots: list[dict[str, typing.Any]],
    ) -> bool:
        embed.color = discord.Color.gold()
        embed.title = _("Review needed")
        lock_key = (message.guild.id, message.author.id)
        review_lock = self._review_creation_locks.setdefault(lock_key, asyncio.Lock())
        await review_lock.acquire()
        active_review = await self._find_active_review_for_user(*lock_key)
        if active_review is not None and await self._merge_into_active_review(
            active_review,
            message,
            embed,
            attachment_snapshots,
        ):
            review_lock.release()
            return True
        self._upsert_embed_field(
            embed,
            _("Channels:"),
            self._format_review_channels(message.guild, [message.channel.id]),
            inline=False,
            aliases=(_("Channel:"),),
        )
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
                        value=_("Mute successful :white_check_mark:"),
                        inline=False,
                    )
                except discord.HTTPException:
                    await self._increment_stat(message.guild, "pending_mute_failures")
                    embed.add_field(
                        name=_("Pending review mute:"),
                        value=_("Mute failed :x:"),
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
            message_fingerprint=message_spam_fingerprint(message),
            channel_ids=[message.channel.id],
        )
        embed.add_field(
            name=_("Review expires in:"),
            value=discord.utils.format_dt(view.expires_at, style="R"),
            inline=False,
        )
        review_files = self._attachment_files(attachment_snapshots)
        review_send_kwargs = {
            "embed": embed,
            "view": view,
        }
        if review_files:
            review_send_kwargs["files"] = review_files
        try:
            sent = await review_channel.send(**review_send_kwargs)
            view.review_message = sent
            view.active_key = sent.id
            async with self._views_lock:
                self._active_views[sent.id] = view
            await self._store_pending_review(message.guild, view, review_channel.id, sent.id)
            await self._increment_stat(message.guild, "reviewed")
            return False
        finally:
            review_lock.release()

    async def _send_log(
        self,
        channel: discord.TextChannel | discord.Thread | None,
        embed: discord.Embed,
        attachment_snapshots: list[dict[str, typing.Any]],
        content: str | None = None,
        allowed_mentions: discord.AllowedMentions | None = None,
        view: discord.ui.View | None = None,
    ) -> None:
        if channel is None:
            return
        send_kwargs: dict[str, typing.Any] = {"content": content, "embed": embed}
        if allowed_mentions is not None:
            send_kwargs["allowed_mentions"] = allowed_mentions
        if view is not None:
            send_kwargs["view"] = view
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
        if message.webhook_id is not None:
            return
        config = await self.config.guild(message.guild).all()
        if not config["enabled"]:
            return
        logs_channel = self._get_text_channel_or_thread(message.guild, config.get("logs_channel"))
        if await self._is_protected_member(message.author):
            return
        self._record_recent_user_message(message, config)
        if self._is_forward_purge_active(message.guild.id, message.author.id):
            if await self._delete_forward_purge_message(message):
                await self._increment_stat(message.guild, "purged_messages")
                await self._increment_stat(message.guild, "forward_purge_deletes")
            return
        configured_honeypot_channel_ids = self._honeypot_channel_ids_from_config(config)
        if message.channel.id not in configured_honeypot_channel_ids:
            if await self._handle_spam_message(message, config, logs_channel):
                return
            if await self._handle_firstpost_message(message, config, logs_channel):
                return
            if await self._handle_imagescan_detector_message(message, config, logs_channel):
                return
            return

        attachment_snapshots = await self._snapshot_attachments(message)

        if config.get("dry_run"):
            message_deleted = False
        else:
            try:
                await message.delete()
                message_deleted = True
            except discord.HTTPException:
                message_deleted = False
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
        embed.add_field(
            name=_("Channel:"),
            value=getattr(message.channel, "mention", f"<#{message.channel.id}>"),
            inline=True,
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

        if config.get("dry_run"):
            embed.add_field(
                name=_("Purge:"),
                value=self._dry_run_purge_label(
                    message.guild,
                    message.author.id,
                    config,
                    include_current_message=True,
                    current_message_id=message.id,
                ),
                inline=False,
            )
        else:
            # Cached purge uses the configured event-retention window.
            purged = await self._cached_purge_user_messages(
                message.guild,
                message.author.id,
                config,
                exclude_message_id=message.id if message_deleted else None,
            )
            if purged:
                await self._increment_stat(message.guild, "purged_messages", purged)
                await self._increment_stat(message.guild, "cached_purge_deletes", purged)
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
                feedback_views = await self._prepare_imagescan_learning_feedback(message, config, embed, attachment_snapshots)
                embed.color = discord.Color.orange()
                embed.add_field(name=_("Action:"), value=_("No action taken."), inline=False)
                await self._send_log(logs_channel, embed, attachment_snapshots)
                await self._send_imagescan_feedback_messages(logs_channel, message, feedback_views)
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
        feedback_views = await self._prepare_imagescan_learning_feedback(message, config, embed, attachment_snapshots)

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
            )
            await self._send_imagescan_feedback_messages(logs_channel, message, feedback_views)
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
            if not suspicious or force_fallback:
                embed.add_field(
                    name=_("Review reason:"),
                    value=_("Message posted in a honeypot channel without matching suspicious rules"),
                    inline=False,
                )
            merged = await self._send_review(
                message, config, embed, review_channel, logs_channel, attachment_snapshots
            )
            if not merged:
                await self._send_imagescan_feedback_messages(review_channel, message, feedback_views)
            return

        if force_review and review_channel is None:
            embed.color = discord.Color.orange()
            embed.add_field(
                name=_("Action:"),
                value=_("No action taken. This whitelist mode needs a review channel, but none is available."),
                inline=False,
            )
            await self._send_log(logs_channel, embed, attachment_snapshots)
            await self._send_imagescan_feedback_messages(logs_channel, message, feedback_views)
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
        )
        await self._send_imagescan_feedback_messages(logs_channel, message, feedback_views)

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
                self._schedule_post_ban_sweep(guild, target.id)
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
                joinwatch_channel = self._get_text_channel_or_thread(
                    guild, joinwatch_channel_id(config)
                )
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
                        if joinwatch_channel is not None:
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
                                await joinwatch_channel.send(embed=embed)
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
                        if joinwatch_channel is not None:
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
                                await joinwatch_channel.send(embed=embed)
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
                    if joinwatch_channel is not None:
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
                            await joinwatch_channel.send(embed=embed)
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
                    self._schedule_post_ban_sweep(after.guild, after.id)
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

    @staticmethod
    def _review_dump_field_map(embed: discord.Embed) -> dict[str, str]:
        return {str(field.name).strip().rstrip(":").lower(): str(field.value) for field in embed.fields}

    @staticmethod
    def _review_dump_clean_mentions(value: str | None) -> list[str]:
        if not value:
            return []
        return re.findall(r"<#(\d+)>", value)

    @staticmethod
    def _review_dump_extract_user_id(embed: discord.Embed, fields: dict[str, str]) -> int | None:
        candidates = [
            fields.get("user"),
            fields.get("user id"),
            embed.description,
            embed.title,
        ]
        for candidate in candidates:
            if not candidate:
                continue
            match = re.search(r"\b(\d{15,25})\b", str(candidate))
            if match:
                return int(match.group(1))
        return None

    @staticmethod
    def _review_dump_is_banned_review(message: discord.Message) -> bool:
        if not message.embeds:
            return False
        fields = Honeypot._review_dump_field_map(message.embeds[0])
        action = (fields.get("action taken") or fields.get("action") or "").lower()
        if "ban" not in action or "dry-run" in action or "failed" in action:
            return False
        return True

    @staticmethod
    def _review_dump_message_record(message: discord.Message, parent_review_id: int | None = None) -> dict[str, typing.Any]:
        embed = message.embeds[0] if message.embeds else None
        fields = Honeypot._review_dump_field_map(embed) if embed else {}
        record: dict[str, typing.Any] = {
            "message_id": str(message.id),
            "parent_review_message_id": str(parent_review_id) if parent_review_id is not None else None,
            "jump_url": message.jump_url,
            "created_at": message.created_at.isoformat(),
            "content": message.content or None,
            "embed": None,
            "attachment_count": len(message.attachments),
        }
        if embed:
            record["embed"] = {
                "title": embed.title,
                "description": embed.description,
                "timestamp": embed.timestamp.isoformat() if embed.timestamp else None,
                "fields": fields,
            }
        return record

    async def _review_dump_download_attachment(
        self,
        attachment: discord.Attachment,
        case_dir: Path,
        prefix: str,
        index: int,
    ) -> dict[str, typing.Any]:
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", attachment.filename or f"attachment-{index}")
        archive_name = f"{prefix}-{index:03d}-{safe_name}"
        target = case_dir / archive_name
        result: dict[str, typing.Any] = {
            "filename": attachment.filename,
            "archive_path": target.as_posix(),
            "size": attachment.size,
            "content_type": attachment.content_type,
            "url": attachment.url,
            "sha256": None,
            "error": None,
        }
        try:
            data = await attachment.read(use_cached=True)
            target.write_bytes(data)
            result["size"] = len(data)
            result["sha256"] = hashlib.sha256(data).hexdigest()
            await asyncio.sleep(REVIEW_DUMP_ATTACHMENT_DELAY_SECONDS)
        except (discord.HTTPException, OSError) as exc:
            result["archive_path"] = None
            result["error"] = str(exc)
        return result

    async def _review_dump_collect_case(
        self,
        review_message: discord.Message,
        replies_by_reference: dict[int, list[discord.Message]],
        root_dir: Path,
    ) -> dict[str, typing.Any]:
        embed = review_message.embeds[0]
        fields = self._review_dump_field_map(embed)
        attachment_dir = root_dir / "cases" / str(review_message.id) / "attachments"
        attachment_dir.mkdir(parents=True, exist_ok=True)
        attachments: list[dict[str, typing.Any]] = []
        for index, attachment in enumerate(review_message.attachments, 1):
            attachments.append(
                await self._review_dump_download_attachment(attachment, attachment_dir, "review", index)
            )
        addendums: list[dict[str, typing.Any]] = []
        for addendum in sorted(replies_by_reference.get(review_message.id, []), key=lambda item: item.created_at):
            addendum_record = self._review_dump_message_record(addendum, review_message.id)
            addendum_attachments: list[dict[str, typing.Any]] = []
            for index, attachment in enumerate(addendum.attachments, 1):
                addendum_attachments.append(
                    await self._review_dump_download_attachment(
                        attachment,
                        attachment_dir,
                        f"addendum-{addendum.id}",
                        index,
                    )
                )
            addendum_record["attachments"] = addendum_attachments
            addendums.append(addendum_record)
            attachments.extend(addendum_attachments)
        return {
            "review_message_id": str(review_message.id),
            "review_jump_url": review_message.jump_url,
            "review_created_at": review_message.created_at.isoformat(),
            "target_user_id": self._review_dump_extract_user_id(embed, fields),
            "case_type": "manual_review" if fields.get("action taken") else "honeypot_hit",
            "completed_action": fields.get("action taken") or fields.get("action"),
            "reviewed_by": fields.get("reviewed by"),
            "channels": fields.get("channels") or fields.get("channel"),
            "channel_ids": self._review_dump_clean_mentions(fields.get("channels") or fields.get("channel")),
            "trigger_reasons": fields.get("trigger reasons") or fields.get("reason"),
            "message_content": embed.description,
            "embed_fields": fields,
            "review_message": self._review_dump_message_record(review_message),
            "attachments": attachments,
            "addendums": addendums,
        }

    @staticmethod
    def _review_dump_zip_chunks(root_dir: Path, zip_dir: Path, max_bytes: int) -> list[Path]:
        files = [path for path in root_dir.rglob("*") if path.is_file()]
        chunks: list[list[Path]] = [[]]
        chunk_sizes = [0]
        for path in sorted(files):
            size = path.stat().st_size
            if chunks[-1] and chunk_sizes[-1] + size > max_bytes:
                chunks.append([])
                chunk_sizes.append(0)
            chunks[-1].append(path)
            chunk_sizes[-1] += size
        width = max(3, int(math.log10(max(len(chunks), 1))) + 1)
        archives: list[Path] = []
        for index, chunk in enumerate(chunks, 1):
            archive = zip_dir / f"honeypot-review-dump-{index:0{width}d}.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
                for path in chunk:
                    zip_file.write(path, path.relative_to(root_dir))
            archives.append(archive)
        return archives

    async def _review_dump_update_progress(
        self,
        progress_message: discord.Message,
        *,
        scanned: int,
        dumped: int,
        current_date: datetime | None,
        started_at: datetime,
        finished: bool = False,
    ) -> None:
        elapsed = datetime.now(timezone.utc) - started_at
        current = current_date.strftime("%Y-%m-%d %H:%M UTC") if current_date else "unknown"
        status = "Finished" if finished else "Running"
        content = (
            f"**Honeypot review dump:** {status}\n"
            f"Current date: `{current}`\n"
            f"Messages scanned: `{scanned}`\n"
            f"Banned reviews dumped: `{dumped}`\n"
            f"Elapsed: `{str(elapsed).split('.')[0]}`"
        )
        try:
            await progress_message.edit(content=content)
        except discord.HTTPException:
            log.debug("Failed to update review dump progress message %s", progress_message.id)

    @staticmethod
    def _imagescan_is_image_attachment(attachment: discord.Attachment) -> bool:
        content_type = (attachment.content_type or "").lower()
        if content_type.startswith("image/"):
            return True
        filename = (attachment.filename or "").lower()
        return filename.endswith(IMAGE_SCAN_EXTENSIONS)

    def _imagescan_trigger_attachments(self, message: discord.Message) -> list[discord.Attachment]:
        image_attachments = [
            attachment
            for attachment in message.attachments
            if self._imagescan_is_image_attachment(attachment)
        ]
        if len(image_attachments) not in IMAGE_SCAN_COUNTS:
            return []
        return image_attachments

    @staticmethod
    def _imagescan_safe_filename(filename: str | None, index: int) -> str:
        fallback = f"image-{index}.jpg"
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", filename or fallback).strip("._")
        return safe or fallback

    @staticmethod
    def _imagescan_image_dimensions(data: bytes) -> tuple[int | None, int | None]:
        if Image is None:
            return None, None
        try:
            with Image.open(io.BytesIO(data)) as image:
                return image.width, image.height
        except Exception:
            return None, None

    async def _imagescan_copy_attachments(
        self,
        guild_id: int,
        event_id: str,
        attachments: list[discord.Attachment],
    ) -> list[dict[str, typing.Any]] | None:
        event_dir = self._imagescan_files_path / str(guild_id) / event_id
        event_dir.mkdir(parents=True, exist_ok=True)
        records: list[dict[str, typing.Any]] = []
        for index, attachment in enumerate(attachments, 1):
            filename = self._imagescan_safe_filename(attachment.filename, index)
            path = event_dir / f"{index:03d}-{filename}"
            try:
                data = await attachment.read(use_cached=True)
            except (discord.HTTPException, discord.Forbidden, discord.NotFound, TypeError) as exc:
                log.debug("Failed to copy imagescan attachment %s for event %s: %s", attachment.filename, event_id, exc)
                shutil.rmtree(event_dir, ignore_errors=True)
                return None
            width, height = self._imagescan_image_dimensions(data)
            path.write_bytes(data)
            records.append(
                {
                    "event_id": event_id,
                    "file_index": index,
                    "filename": attachment.filename or filename,
                    "path": str(path),
                    "size": len(data),
                    "content_type": attachment.content_type,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "width": width,
                    "height": height,
                }
            )
        return records

    def _imagescan_event_exists_sync(self, guild_id: int, message_id: int) -> bool:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM imagescan_events WHERE guild_id = ? AND message_id = ?",
                (str(guild_id), str(message_id)),
            ).fetchone()
        return row is not None

    async def _imagescan_event_exists(self, guild_id: int, message_id: int) -> bool:
        async with self._imagescan_db_lock:
            return await asyncio.to_thread(self._imagescan_event_exists_sync, guild_id, message_id)

    def _imagescan_insert_event_sync(
        self,
        event: dict[str, typing.Any],
        files: list[dict[str, typing.Any]],
    ) -> None:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO imagescan_events
                (
                    event_id, guild_id, user_id, channel_id, message_id, message_jump_url,
                    review_channel_id, review_message_id, created_at, image_count, content,
                    decision, moderator_id, decided_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"],
                    event["guild_id"],
                    event["user_id"],
                    event["channel_id"],
                    event["message_id"],
                    event["message_jump_url"],
                    event.get("review_channel_id"),
                    event.get("review_message_id"),
                    event["created_at"],
                    event["image_count"],
                    event.get("content"),
                    event.get("decision", "pending"),
                    event.get("moderator_id"),
                    event.get("decided_at"),
                ),
            )
            conn.executemany(
                """
                INSERT OR REPLACE INTO imagescan_files
                (event_id, file_index, filename, path, size, content_type, sha256, width, height)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        file_record["event_id"],
                        file_record["file_index"],
                        file_record["filename"],
                        file_record["path"],
                        file_record["size"],
                        file_record.get("content_type"),
                        file_record["sha256"],
                        file_record.get("width"),
                        file_record.get("height"),
                    )
                    for file_record in files
                ],
            )

    async def _imagescan_insert_event(
        self,
        event: dict[str, typing.Any],
        files: list[dict[str, typing.Any]],
    ) -> None:
        async with self._imagescan_db_lock:
            await asyncio.to_thread(self._imagescan_insert_event_sync, event, files)

    def _imagescan_update_review_message_sync(
        self,
        guild_id: int,
        event_id: str,
        review_channel_id: int,
        review_message_id: int,
    ) -> None:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.execute(
                """
                UPDATE imagescan_events
                SET review_channel_id = ?, review_message_id = ?
                WHERE guild_id = ? AND event_id = ?
                """,
                (str(review_channel_id), str(review_message_id), str(guild_id), event_id),
            )

    async def _imagescan_update_review_message(
        self,
        guild_id: int,
        event_id: str,
        review_channel_id: int,
        review_message_id: int,
    ) -> None:
        async with self._imagescan_db_lock:
            await asyncio.to_thread(
                self._imagescan_update_review_message_sync,
                guild_id,
                event_id,
                review_channel_id,
                review_message_id,
            )

    def _imagescan_set_decision_sync(
        self,
        guild_id: int,
        event_id: str,
        decision: str,
        moderator_id: int,
    ) -> None:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.execute(
                """
                UPDATE imagescan_events
                SET decision = ?, moderator_id = ?, decided_at = ?
                WHERE guild_id = ? AND event_id = ?
                """,
                (
                    decision,
                    str(moderator_id),
                    int(datetime.now(timezone.utc).timestamp()),
                    str(guild_id),
                    event_id,
                ),
            )

    async def _imagescan_set_decision(
        self,
        guild_id: int,
        event_id: str,
        decision: str,
        moderator_id: int,
    ) -> None:
        async with self._imagescan_db_lock:
            await asyncio.to_thread(
                self._imagescan_set_decision_sync,
                guild_id,
                event_id,
                decision,
                moderator_id,
            )

    def _imagescan_counts_sync(self, guild_id: int) -> dict[str, int]:
        counts = {"pending": 0, "true_positive": 0, "false_positive": 0, "ignored": 0}
        with sqlite3.connect(self._imagescan_db_path) as conn:
            rows = conn.execute(
                """
                SELECT decision, COUNT(*)
                FROM imagescan_events
                WHERE guild_id = ?
                GROUP BY decision
                """,
                (str(guild_id),),
            ).fetchall()
        for decision, count in rows:
            counts[str(decision)] = int(count)
        return counts

    async def _imagescan_counts(self, guild_id: int) -> dict[str, int]:
        async with self._imagescan_db_lock:
            return await asyncio.to_thread(self._imagescan_counts_sync, guild_id)

    def _imagescan_export_rows_sync(self, guild_id: int) -> list[dict[str, typing.Any]]:
        with sqlite3.connect(self._imagescan_db_path) as conn:
            conn.row_factory = sqlite3.Row
            events = conn.execute(
                """
                SELECT *
                FROM imagescan_events
                WHERE guild_id = ?
                ORDER BY created_at ASC
                """,
                (str(guild_id),),
            ).fetchall()
            files = conn.execute(
                """
                SELECT *
                FROM imagescan_files
                WHERE event_id IN (
                    SELECT event_id FROM imagescan_events WHERE guild_id = ?
                )
                ORDER BY event_id ASC, file_index ASC
                """,
                (str(guild_id),),
            ).fetchall()
        files_by_event: dict[str, list[dict[str, typing.Any]]] = defaultdict(list)
        for row in files:
            files_by_event[str(row["event_id"])].append(dict(row))
        rows: list[dict[str, typing.Any]] = []
        for row in events:
            item = dict(row)
            item["files"] = files_by_event.get(str(row["event_id"]), [])
            rows.append(item)
        return rows

    async def _imagescan_export_rows(self, guild_id: int) -> list[dict[str, typing.Any]]:
        async with self._imagescan_db_lock:
            return await asyncio.to_thread(self._imagescan_export_rows_sync, guild_id)

    def _imagescan_review_files(self, file_records: list[dict[str, typing.Any]]) -> list[discord.File]:
        files: list[discord.File] = []
        for record in file_records[:10]:
            path = Path(record["path"])
            if not path.exists():
                continue
            files.append(discord.File(path, filename=path.name))
        return files

    async def _imagescan_send_review(
        self,
        message: discord.Message,
        event_id: str,
        review_channel: discord.TextChannel | discord.Thread,
        file_records: list[dict[str, typing.Any]],
    ) -> discord.Message | None:
        embed = discord.Embed(
            title=_("Image scan shadow review"),
            description=f">>> {message.content}" if message.content else _("*(message with images only)*"),
            color=discord.Color.blurple(),
            timestamp=message.created_at,
        )
        embed.set_author(
            name=f"{message.author.display_name} ({message.author.id})",
            icon_url=message.author.display_avatar,
        )
        embed.add_field(
            name=_("User:"),
            value=f"{message.author.mention} (`{message.author.id}`)",
            inline=False,
        )
        embed.add_field(
            name=_("Channel:"),
            value=getattr(message.channel, "mention", f"<#{message.channel.id}>"),
            inline=True,
        )
        embed.add_field(name=_("Message:"), value=message.jump_url, inline=False)
        embed.add_field(name=_("Image count:"), value=str(len(file_records)), inline=True)
        embed.add_field(
            name=_("Scan reason:"),
            value=_("Exactly {count} image attachments").format(count=len(file_records)),
            inline=False,
        )
        embed.add_field(name=_("Status:"), value=_("Pending classification"), inline=False)
        embed.set_footer(text=message.guild.name, icon_url=message.guild.icon)
        view = ImageScanReviewView(self, event_id, message.guild.id)
        kwargs: dict[str, typing.Any] = {
            "embed": embed,
            "view": view,
            "allowed_mentions": discord.AllowedMentions.none(),
        }
        files = self._imagescan_review_files(file_records)
        if files:
            kwargs["files"] = files
        try:
            sent = await review_channel.send(**kwargs)
        except discord.HTTPException as exc:
            log.warning("Failed to send imagescan review for message %s: %s", message.id, exc)
            return None
        view.review_message = sent
        return sent

    async def _handle_imagescan_message(self, message: discord.Message, config: dict) -> None:
        if not config.get("imagescan_enabled", False):
            return
        review_channel_id = config.get("imagescan_channel")
        if review_channel_id is None:
            return
        review_channel = self._get_text_channel_or_thread(message.guild, review_channel_id)
        if review_channel is None:
            return
        attachments = self._imagescan_trigger_attachments(message)
        if not attachments:
            return
        if await self._imagescan_event_exists(message.guild.id, message.id):
            return
        event_id = str(message.id)
        file_records = await self._imagescan_copy_attachments(message.guild.id, event_id, attachments)
        if file_records is None:
            return
        event = {
            "event_id": event_id,
            "guild_id": str(message.guild.id),
            "user_id": str(message.author.id),
            "channel_id": str(message.channel.id),
            "message_id": str(message.id),
            "message_jump_url": message.jump_url,
            "review_channel_id": None,
            "review_message_id": None,
            "created_at": int(message.created_at.timestamp()),
            "image_count": len(file_records),
            "content": message.content or None,
            "decision": "pending",
            "moderator_id": None,
            "decided_at": None,
        }
        await self._imagescan_insert_event(event, file_records)
        sent = await self._imagescan_send_review(message, event_id, review_channel, file_records)
        if sent is not None:
            await self._imagescan_update_review_message(message.guild.id, event_id, review_channel.id, sent.id)

    async def _imagescan_create_dump_archives(self, guild_id: int) -> tuple[Path, list[Path]]:
        temp_root = Path(tempfile.mkdtemp(prefix="honeypot-imagescan-dump-"))
        data_root = temp_root / "data"
        zip_root = temp_root / "zips"
        files_root = data_root / "files"
        data_root.mkdir(parents=True, exist_ok=True)
        zip_root.mkdir(parents=True, exist_ok=True)
        rows = await self._imagescan_export_rows(guild_id)
        with (data_root / "imagescan.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        if self._imagescan_db_path.exists():
            shutil.copy2(self._imagescan_db_path, data_root / "imagescan.sqlite")
        source_files_root = self._imagescan_files_path / str(guild_id)
        if source_files_root.exists():
            for source in source_files_root.rglob("*"):
                if not source.is_file():
                    continue
                target = files_root / str(guild_id) / source.relative_to(source_files_root)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        archives = self._review_dump_zip_chunks(data_root, zip_root, REVIEW_DUMP_MAX_ZIP_BYTES)
        return temp_root, archives

    # ─── Commands ─────────────────────────────────────────────────────────

    @commands.guild_only()
    @commands.permissions_check(lambda ctx: ctx.author.id == ctx.guild.owner_id or ctx.author.id in ctx.bot.owner_ids)
    @commands.group()
    async def honeypot(self, ctx: commands.Context) -> None:
        """Configure server safety and honeypot protections."""

    @honeypot.group(name="debug")
    async def debug(self, ctx: commands.Context) -> None:
        """Maintenance, debug, and export tools."""

    @debug.group(name="imagescan")
    async def debug_imagescan(self, ctx: commands.Context) -> None:
        """Maintenance tools for image scan training data."""

    @debug_imagescan.command(name="cleanup_events")
    async def imagescan_cleanup_events(self, ctx: commands.Context, confirm: str = None) -> None:
        """Clean old image scan event files after dumping them."""
        should_delete = (confirm or "").lower() == "confirm"
        if confirm is not None and not should_delete:
            await ctx.send(_("Use `confirm` to delete event files, or omit it for a dry run."))
            return
        plan = await asyncio.to_thread(
            plan_imagescan_event_cache_cleanup,
            self._imagescan_files_path,
            ctx.guild.id,
            delete=should_delete,
        )
        size_mb = plan["bytes"] / 1024 / 1024
        if should_delete:
            await ctx.send(
                _(
                    "Image scan event cleanup finished: deleted {deleted}/{event_dirs} event folder(s), "
                    "{files} file(s), {size:.2f} MB. Samples were not touched."
                ).format(
                    deleted=plan["deleted_event_dirs"],
                    event_dirs=plan["event_dirs"],
                    files=plan["files"],
                    size=size_mb,
                )
            )
        else:
            await ctx.send(
                _(
                    "Image scan event cleanup dry run: {event_dirs} event folder(s), "
                    "{files} file(s), {size:.2f} MB. Run with `confirm` to delete. "
                    "Samples will not be touched."
                ).format(
                    event_dirs=plan["event_dirs"],
                    files=plan["files"],
                    size=size_mb,
                )
            )

    @debug.command(name="reviewdump")
    async def review_dump(self, ctx: commands.Context) -> None:
        """Export banned review cases from the current channel."""
        if self._review_dump_lock.locked():
            await ctx.send(_("A review dump is already running."))
            return

        async with self._review_dump_lock:
            started_at = datetime.now(timezone.utc)
            after = REVIEW_DUMP_START
            progress_message = await ctx.send(
                _(
                    "**Honeypot review dump:** Running\n"
                    "Current date: `starting`\n"
                    "Messages scanned: `0`\n"
                    "Banned reviews dumped: `0`\n"
                    "Elapsed: `0:00:00`"
                )
            )
            temp_root = Path(tempfile.mkdtemp(prefix="honeypot-review-dump-"))
            data_root = temp_root / "data"
            zip_root = temp_root / "zips"
            data_root.mkdir(parents=True, exist_ok=True)
            zip_root.mkdir(parents=True, exist_ok=True)
            scanned = 0
            dumped = 0
            current_date: datetime | None = None
            last_progress = datetime.now(timezone.utc)
            replies_by_reference: dict[int, list[discord.Message]] = defaultdict(list)
            banned_reviews: list[discord.Message] = []
            cases: list[dict[str, typing.Any]] = []

            try:
                async for message in ctx.channel.history(limit=None, after=after, oldest_first=False):
                    scanned += 1
                    current_date = message.created_at
                    reference = getattr(message, "reference", None)
                    if reference is not None and reference.message_id is not None:
                        replies_by_reference[reference.message_id].append(message)
                    if self._review_dump_is_banned_review(message):
                        banned_reviews.append(message)
                    now = datetime.now(timezone.utc)
                    if scanned == 1 or scanned % 250 == 0 or (now - last_progress).total_seconds() >= 30:
                        await self._review_dump_update_progress(
                            progress_message,
                            scanned=scanned,
                            dumped=dumped,
                            current_date=current_date,
                            started_at=started_at,
                        )
                        last_progress = now
                        await asyncio.sleep(0.25)

                for review_message in sorted(banned_reviews, key=lambda item: item.created_at):
                    cases.append(await self._review_dump_collect_case(review_message, replies_by_reference, data_root))
                    dumped += 1
                    now = datetime.now(timezone.utc)
                    if dumped == 1 or dumped % 10 == 0 or (now - last_progress).total_seconds() >= 30:
                        await self._review_dump_update_progress(
                            progress_message,
                            scanned=scanned,
                            dumped=dumped,
                            current_date=review_message.created_at,
                            started_at=started_at,
                        )
                        last_progress = now

                manifest = {
                    "guild_id": str(ctx.guild.id),
                    "channel_id": str(ctx.channel.id),
                    "channel_name": getattr(ctx.channel, "name", None),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "scan_after": after.isoformat(),
                    "messages_scanned": scanned,
                    "banned_reviews_dumped": dumped,
                    "cases": cases,
                }
                (data_root / "manifest.json").write_text(
                    json.dumps(manifest, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                with (data_root / "reviews.jsonl").open("w", encoding="utf-8") as handle:
                    for case in cases:
                        handle.write(json.dumps(case, ensure_ascii=False) + "\n")

                archives = self._review_dump_zip_chunks(data_root, zip_root, REVIEW_DUMP_MAX_ZIP_BYTES)
                await self._review_dump_update_progress(
                    progress_message,
                    scanned=scanned,
                    dumped=dumped,
                    current_date=current_date,
                    started_at=started_at,
                    finished=True,
                )

                if not archives:
                    await ctx.send(_("No dump files were created."))
                    return
                for archive in archives:
                    await ctx.send(file=discord.File(archive))
            finally:
                shutil.rmtree(temp_root, ignore_errors=True)

    # ─── honeypot sub-group ───────────────────────────────────────────

    @honeypot.group(name="honeypot")
    async def honeypot_settings(self, ctx: commands.Context) -> None:
        """Configure the main honeypot detection layer."""

    @honeypot_settings.command(name="toggle")
    async def honeypot_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable the main honeypot layer."""
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

    @honeypot_settings.command()
    async def action(self, ctx: commands.Context, value: str = None) -> None:
        """Set the default action for honeypot detections."""
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

    @honeypot_settings.command(name="fallback_action")
    async def fallback_action(self, ctx: commands.Context, value: str = None) -> None:
        """Set the action used when a detector falls back to honeypot handling."""
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

    @honeypot_settings.command(name="dry_run")
    async def dry_run(self, ctx: commands.Context, value: bool = None) -> None:
        """Log what would happen without applying punishments."""
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

    @honeypot_settings.command(name="whitelist_mode")
    async def whitelist_mode(self, ctx: commands.Context, value: str = None) -> None:
        """Set how whitelisted roles are handled by honeypot detections."""
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

    @honeypot_settings.command(name="automated_kick_fail_warn")
    async def automated_kick_fail_warn(self, ctx: commands.Context, value: bool = None) -> None:
        """Warn when an automated kick cannot run because the user already left."""
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
        """Configure honeypot and log channels."""

    @commands.bot_has_guild_permissions(manage_channels=True)
    @channels.command()
    async def create(self, ctx: commands.Context) -> None:
        """Create and register a new honeypot channel."""
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
        """Register an existing channel as a honeypot channel."""
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
        """Unregister a honeypot channel."""
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
        """List registered honeypot channels."""
        config = await self.config.guild(ctx.guild).all()
        channel_ids = self._honeypot_channel_ids_from_config(config)
        await ctx.send(
            _("Honeypot channels:\n{channels}").format(
                channels=self._format_honeypot_channel_list(ctx.guild, channel_ids),
            )
        )

    @channels.command()
    async def logs(self, ctx: commands.Context, target: discord.TextChannel | discord.Thread = None) -> None:
        """Set the channel used for honeypot logs."""
        if target is None:
            v = await self.config.guild(ctx.guild).logs_channel()
            await ctx.send(_("Logs channel: {channel}").format(channel=ctx.guild.get_channel(v) if v else _("not set")))
        else:
            missing = self._missing_channel_permissions(ctx.guild, target)
            if missing is not None:
                raise commands.UserFeedbackCheckFailure(missing)
            await self.config.guild(ctx.guild).logs_channel.set(target.id)
            await ctx.send(_("✅ Logs channel set to {channel.mention}").format(channel=target))

    # ─── punishment sub-group ─────────────────────────────────────────

    @honeypot.group()
    async def punishment(self, ctx: commands.Context) -> None:
        """Configure roles used while a case is awaiting review."""

    @punishment.command(name="mute_role")
    async def punishment_mute_role(self, ctx: commands.Context, role: discord.Role = None) -> None:
        """Set the temporary mute role for pending reviews."""
        if role is None:
            v = await self.config.guild(ctx.guild).mute_role()
            r = ctx.guild.get_role(v) if v else None
            await ctx.send(_("Mute role: {role}").format(role=r.mention if r else _("not set")))
        else:
            await self.config.guild(ctx.guild).mute_role.set(role.id)
            await ctx.send(_("✅ Mute role set to {role.mention}").format(role=role))

    # ─── purge sub-group ───────────────────────────────────────────────

    @honeypot.group(name="purge")
    async def purge(self, ctx: commands.Context) -> None:
        """Configure event-registry message purge windows."""

    @purge.command(name="backward")
    async def purge_backward(self, ctx: commands.Context, seconds: int = None) -> None:
        """Set how far back cached message purge can delete."""
        if seconds is None:
            config = await self.config.guild(ctx.guild).all()
            await ctx.send(
                _("Backward purge window: {seconds}s").format(
                    seconds=self._purge_backward_seconds(config),
                )
            )
        elif seconds < PURGE_MIN_RETENTION_SECONDS or seconds > PURGE_BACKWARD_MAX_SECONDS:
            await ctx.send(
                _("Backward purge must be between {minimum} and {maximum} seconds.").format(
                    minimum=PURGE_MIN_RETENTION_SECONDS,
                    maximum=PURGE_BACKWARD_MAX_SECONDS,
                )
            )
        else:
            await self.config.guild(ctx.guild).purge_backward_seconds.set(seconds)
            await ctx.send(_("✅ Backward purge window set to {seconds}s").format(seconds=seconds))

    @purge.command(name="forward")
    async def purge_forward(self, ctx: commands.Context, seconds: int = None) -> None:
        """Set how long future messages are purged after a trigger."""
        if seconds is None:
            config = await self.config.guild(ctx.guild).all()
            await ctx.send(
                _("Forward purge window: {seconds}s").format(
                    seconds=self._purge_forward_seconds(config),
                )
            )
        elif seconds < 0 or seconds > PURGE_FORWARD_MAX_SECONDS:
            await ctx.send(
                _("Forward purge must be between 0 and {maximum} seconds.").format(
                    maximum=PURGE_FORWARD_MAX_SECONDS,
                )
            )
        else:
            await self.config.guild(ctx.guild).purge_forward_seconds.set(seconds)
            await ctx.send(_("✅ Forward purge window set to {seconds}s").format(seconds=seconds))

    # ─── spam sub-group ────────────────────────────────────────────────

    @honeypot.group()
    async def spam(self, ctx: commands.Context) -> None:
        """Configure duplicate-message spam detection."""

    @spam.command(name="toggle")
    async def spam_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable duplicate-message spam detection."""
        if value is None:
            v = await self.config.guild(ctx.guild).spam_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).spam_enabled.set(value)
            await ctx.send(_("✅ Spam detection set to {value}").format(value=value))

    @spam.command(name="action")
    async def spam_action(self, ctx: commands.Context, value: str = None) -> None:
        """Set the action for duplicate-message spam detections."""
        if value is None:
            v = await self.config.guild(ctx.guild).spam_action()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=v,
                    options=self._format_options(CORE_ACTION_OPTIONS),
                )
            )
        elif value not in CORE_ACTION_OPTIONS:
            await ctx.send(_("Choose one of: {options}").format(options=self._format_options(CORE_ACTION_OPTIONS)))
        else:
            await self.config.guild(ctx.guild).spam_action.set(value)
            await ctx.send(_("✅ Spam action set to {value}").format(value=value))

    @spam.command(name="window")
    async def spam_window(self, ctx: commands.Context, seconds: int = None) -> None:
        """Set the time window for duplicate-message detection."""
        if seconds is None:
            v = await self.config.guild(ctx.guild).spam_window_seconds()
            await ctx.send(_("Spam window: {seconds}s").format(seconds=v))
        elif seconds < SPAM_WINDOW_MIN_SECONDS or seconds > SPAM_WINDOW_MAX_SECONDS:
            await ctx.send(
                _("Seconds must be between {minimum} and {maximum}.").format(
                    minimum=SPAM_WINDOW_MIN_SECONDS,
                    maximum=SPAM_WINDOW_MAX_SECONDS,
                )
            )
        else:
            await self.config.guild(ctx.guild).spam_window_seconds.set(seconds)
            await ctx.send(_("✅ Spam window set to {seconds}s").format(seconds=seconds))

    @spam.command(name="channels")
    async def spam_channels(self, ctx: commands.Context, count: int = None) -> None:
        """Set how many channels must contain the same message."""
        if count is None:
            v = await self.config.guild(ctx.guild).spam_min_channels()
            await ctx.send(_("Spam channel threshold: {count}").format(count=v))
        elif count < SPAM_CHANNEL_MIN or count > SPAM_CHANNEL_MAX:
            await ctx.send(
                _("Channel count must be between {minimum} and {maximum}.").format(
                    minimum=SPAM_CHANNEL_MIN,
                    maximum=SPAM_CHANNEL_MAX,
                )
            )
        else:
            await self.config.guild(ctx.guild).spam_min_channels.set(count)
            await ctx.send(_("✅ Spam channel threshold set to {count}").format(count=count))

    # ─── imagescan sub-group ───────────────────────────────────────────

    @honeypot.group(name="imagescan")
    async def imagescan(self, ctx: commands.Context) -> None:
        """Configure adaptive scam-image detection."""

    @imagescan.command(name="add")
    async def imagescan_add(self, ctx: commands.Context) -> None:
        """Add scam images from the message this command replies to."""
        reference = getattr(ctx.message, "reference", None)
        if reference is None or reference.message_id is None:
            await ctx.send(_("Please reply to an offending message."))
            return
        target = reference.resolved
        if not isinstance(target, discord.Message):
            try:
                target = await ctx.channel.fetch_message(reference.message_id)
            except (discord.HTTPException, discord.NotFound, discord.Forbidden):
                await ctx.send(_("I couldn't fetch the replied message."))
                return
        attachments = [
            attachment
            for attachment in target.attachments
            if self._imagescan_is_image_attachment(attachment)
        ][:IMAGE_SCAN_MAX_ATTACHMENTS]
        if not attachments:
            await ctx.send(_("No images found."))
            return
        inserted = duplicates = conflicts = errors = 0
        inserted_sample_ids: list[str] = []
        for index, attachment in enumerate(attachments, 1):
            status, sample = await self._imagescan_add_attachment_sample(
                ctx.guild.id,
                target,
                attachment,
                index,
                "true_positive",
                ctx.author.id,
            )
            if status == "inserted":
                inserted += 1
                if sample is not None:
                    inserted_sample_ids.append(sample["sample_id"])
            elif status == "duplicate":
                duplicates += 1
            elif status == "conflict":
                conflicts += 1
            else:
                errors += 1
        config = await self.config.guild(ctx.guild).all()
        state = await self._imagescan_model_state(
            ctx.guild.id,
            int(config.get("imagescan_detector_threshold", 20)),
        )
        if not state["valid"]:
            for sample_id in inserted_sample_ids:
                await self._imagescan_deactivate_sample(ctx.guild.id, sample_id)
            await self._imagescan_model_state(
                ctx.guild.id,
                int(config.get("imagescan_detector_threshold", 20)),
            )
            await ctx.send(_("Rejected: TP/FP overlap.\nModel unchanged."))
            return
        parts = []
        if inserted:
            parts.append(_("{count} added").format(count=inserted))
        if duplicates:
            parts.append(_("{count} already known").format(count=duplicates))
        if conflicts:
            parts.append(_("{count} conflict").format(count=conflicts))
        if errors:
            parts.append(_("{count} failed").format(count=errors))
        await ctx.send(_("Imagescan add: {result}.").format(result=", ".join(parts) or _("no changes")))

    @imagescan.command(name="dropfile")
    async def imagescan_dropfile(self, ctx: commands.Context, identifier: str) -> None:
        """Remove a stored image file while keeping its hashes active."""
        rows = await self._imagescan_sample_rows(ctx.guild.id)
        sample = match_imagescan_sample_identifier(rows, identifier)
        if sample is None:
            await ctx.send(_("No unique active image sample matched `{identifier}`.").format(identifier=identifier))
            return
        file_path = sample.get("file_path")
        deleted = False
        if file_path:
            path = Path(str(file_path))
            if not is_imagescan_sample_path_safe(self._imagescan_files_path, path):
                await ctx.send(_("Refused to touch a file outside image scan storage."))
                return
            if path.exists():
                try:
                    path.unlink()
                    deleted = True
                except OSError:
                    await ctx.send(_("Failed to delete sample file."))
                    return
        await self._imagescan_update_sample_file(ctx.guild.id, str(sample["sample_id"]), None, 0)
        await ctx.send(
            _("Sample file dropped: `{sample_id}` (`{sha}`). File deleted: {deleted}. Hash retained.").format(
                sample_id=sample["sample_id"],
                sha=str(sample["sha256"])[:12],
                deleted=str(deleted).lower(),
            )
        )

    @imagescan.command(name="remove")
    async def imagescan_remove(self, ctx: commands.Context, identifier: str) -> None:
        """Remove an image sample and its stored file from the active dataset."""
        rows = await self._imagescan_sample_rows(ctx.guild.id)
        sample = match_imagescan_sample_identifier(rows, identifier)
        if sample is None:
            await ctx.send(_("No unique active image sample matched `{identifier}`.").format(identifier=identifier))
            return
        file_path = sample.get("file_path")
        deleted_file = False
        if file_path:
            path = Path(str(file_path))
            if not is_imagescan_sample_path_safe(self._imagescan_files_path, path):
                await ctx.send(_("Refused to touch a file outside image scan storage."))
                return
            if path.exists():
                try:
                    path.unlink()
                    deleted_file = True
                except OSError:
                    await ctx.send(_("Failed to delete sample file."))
                    return
        await self._imagescan_delete_sample(ctx.guild.id, str(sample["sample_id"]))
        config = await self.config.guild(ctx.guild).all()
        state = await self._imagescan_model_state(
            ctx.guild.id,
            int(config.get("imagescan_detector_threshold", 20)),
        )
        await ctx.send(
            _(
                "Sample removed: `{sample_id}` (`{sha}`). File deleted: {deleted}. "
                "Effective threshold: {threshold}"
            ).format(
                sample_id=sample["sample_id"],
                sha=str(sample["sha256"])[:12],
                deleted=str(deleted_file).lower(),
                threshold=state["effective_threshold"],
            )
        )

    @debug_imagescan.command(name="legacy_toggle")
    async def imagescan_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable image shadow reviews."""
        if value is None:
            v = await self.config.guild(ctx.guild).imagescan_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            if value and await self.config.guild(ctx.guild).imagescan_channel() is None:
                raise commands.UserFeedbackCheckFailure(
                    _("Set an image scan channel first with `honeypot imagescan channel`.")
                )
            await self.config.guild(ctx.guild).imagescan_enabled.set(value)
            await ctx.send(_("✅ Image scan enabled set to {value}").format(value=value))

    @debug_imagescan.command(name="legacy_channel")
    async def imagescan_channel(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel | discord.Thread = None,
    ) -> None:
        """Set the channel for image shadow reviews."""
        if channel is None:
            channel_id = await self.config.guild(ctx.guild).imagescan_channel()
            current = self._get_text_channel_or_thread(ctx.guild, channel_id)
            await ctx.send(_("Current image scan channel: {channel}").format(channel=current.mention if current else "None"))
            return
        await self.config.guild(ctx.guild).imagescan_channel.set(channel.id)
        await ctx.send(_("✅ Image scan channel set to {channel}").format(channel=channel.mention))

    @imagescan.group(name="detector")
    async def imagescan_detector(self, ctx: commands.Context) -> None:
        """Configure production image detector behavior."""

    @imagescan_detector.command(name="toggle")
    async def imagescan_detector_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable production image detection."""
        if value is None:
            v = await self.config.guild(ctx.guild).imagescan_detector_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
            return
        await self.config.guild(ctx.guild).imagescan_detector_enabled.set(value)
        await ctx.send(_("Image detector enabled set to {value}").format(value=value))

    @imagescan_detector.command(name="action")
    async def imagescan_detector_action(self, ctx: commands.Context, value: str = None) -> None:
        """Set image detector action."""
        if value is None:
            v = await self.config.guild(ctx.guild).imagescan_detector_action()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=v,
                    options=self._format_options(IMAGE_SCAN_DETECTOR_ACTION_OPTIONS),
                )
            )
            return
        if value not in IMAGE_SCAN_DETECTOR_ACTION_OPTIONS:
            await ctx.send(
                _("Choose one of: {options}").format(
                    options=self._format_options(IMAGE_SCAN_DETECTOR_ACTION_OPTIONS),
                )
            )
            return
        await self.config.guild(ctx.guild).imagescan_detector_action.set(value)
        await ctx.send(_("Image detector action set to {value}").format(value=value))

    @imagescan_detector.command(name="threshold")
    async def imagescan_detector_threshold(self, ctx: commands.Context, value: int = None) -> None:
        """Set maximum image hash distance."""
        if value is None:
            config = await self.config.guild(ctx.guild).all()
            state = await self._imagescan_model_state(
                ctx.guild.id,
                int(config.get("imagescan_detector_threshold", 20)),
            )
            await ctx.send(
                _("Threshold: {configured} effective {effective}").format(
                    configured=state["configured_threshold"],
                    effective=state["effective_threshold"],
                )
            )
            return
        if value < 0 or value > 100:
            await ctx.send(_("Threshold must be between 0 and 100."))
            return
        await self.config.guild(ctx.guild).imagescan_detector_threshold.set(value)
        await self._imagescan_model_state(ctx.guild.id, value)
        await ctx.send(_("Image detector threshold set to {value}").format(value=value))

    @imagescan.command(name="rebuild")
    async def imagescan_model_rebuild(self, ctx: commands.Context) -> None:
        """Recompute image detector threshold state."""
        config = await self.config.guild(ctx.guild).all()
        state = await self._imagescan_model_state(
            ctx.guild.id,
            int(config.get("imagescan_detector_threshold", 20)),
        )
        if not state["valid"]:
            await ctx.send(_("Rejected: TP/FP overlap.\nModel unchanged."))
            return
        await ctx.send(
            _("Model rebuilt. Effective threshold: {threshold}").format(
                threshold=state["effective_threshold"],
            )
        )

    @imagescan.command(name="status")
    async def imagescan_status(self, ctx: commands.Context) -> None:
        """Show image detector settings, samples, and timing."""
        config = await self.config.guild(ctx.guild).all()
        state = await self._imagescan_model_state(
            ctx.guild.id,
            int(config.get("imagescan_detector_threshold", 20)),
        )
        profile = await self._imagescan_profile(ctx.guild.id)
        total_samples = int(state["sample_count_tp"]) + int(state["sample_count_fp"])
        sample_rows = await self._imagescan_sample_rows(ctx.guild.id)
        storage = summarize_imagescan_sample_storage(sample_rows)

        def avg(total_key: str, count_key: str) -> int:
            count = profile.get(count_key, 0)
            return int(profile.get(total_key, 0) / count) if count else 0

        lines = [
            f"Enabled: {self._format_bool_setting(config.get('imagescan_detector_enabled', False))}",
            f"Action: {config.get('imagescan_detector_action', 'review')}",
            f"Threshold: {state['configured_threshold']} effective {state['effective_threshold']}",
            f"Samples: {state['sample_count_tp']} TP, {state['sample_count_fp']} FP, {total_samples} total",
            (
                "Sample files: "
                f"{storage['active_with_file']} stored, "
                f"{storage['active_without_file']} hash-only"
            ),
            f"Sample storage: {self._format_bytes(storage['file_bytes'])}",
            (
                "Scanned: "
                f"{profile.get('messages_scanned', 0)} messages, "
                f"{profile.get('images_considered', 0)} images considered, "
                f"{profile.get('images_ignored_over_limit', 0)} images ignored over limit"
            ),
            f"Hits: {profile.get('exact_tp_hits', 0)} exact TP, {profile.get('flagged_tp_hits', 0)} flagged TP",
            f"Decision latency: avg {avg('decision_ms_total', 'decision_ms_count')} ms",
            (
                "Download/hash/compare: avg "
                f"{avg('download_ms_total', 'download_ms_count')} / "
                f"{avg('hash_ms_total', 'hash_ms_count')} / "
                f"{avg('compare_ms_total', 'compare_ms_count')} ms"
            ),
        ]
        await ctx.send(_("**Image scan status:**\n") + box("\n".join(lines)))

    @debug_imagescan.command(name="dump")
    async def imagescan_dump(self, ctx: commands.Context) -> None:
        """Export image shadow-review events and copied files."""
        temp_root: Path | None = None
        try:
            temp_root, archives = await self._imagescan_create_dump_archives(ctx.guild.id)
            if not archives:
                await ctx.send(_("No image scan dump files were created."))
                return
            await ctx.send(_("Image scan dump created. Sending {count} file(s).").format(count=len(archives)))
            for archive in archives:
                await ctx.send(file=discord.File(archive))
        finally:
            if temp_root is not None:
                shutil.rmtree(temp_root, ignore_errors=True)

    # ─── firstpost sub-group ────────────────────────────────────────────

    @debug_imagescan.command(name="importtpzip")
    async def imagescan_import_tp_zip(self, ctx: commands.Context) -> None:
        """Import true-positive scam images from attached zip files."""
        attachments = list(ctx.message.attachments)
        reference = getattr(ctx.message, "reference", None)
        if not attachments and reference is not None and reference.message_id is not None:
            target = reference.resolved
            if not isinstance(target, discord.Message):
                try:
                    target = await ctx.channel.fetch_message(reference.message_id)
                except (discord.HTTPException, discord.NotFound, discord.Forbidden):
                    target = None
            if isinstance(target, discord.Message):
                attachments = list(target.attachments)
        zip_attachments = [
            attachment
            for attachment in attachments
            if (attachment.filename or "").lower().endswith(".zip")
        ]
        if not zip_attachments:
            await ctx.send(_("Attach a .zip file or reply to a message with a .zip file."))
            return
        progress = await ctx.send(_("Importing zip file(s)..."))
        inserted = duplicates = conflicts = errors = skipped = 0
        error_notes: list[str] = []
        inserted_sample_ids: list[str] = []
        processed = 0
        for attachment in zip_attachments:
            attachment_name = attachment.filename or "attachment.zip"
            try:
                archive_data = await attachment.read()
            except (discord.HTTPException, discord.Forbidden, discord.NotFound, TypeError) as primary_exc:
                try:
                    archive_data = await attachment.read(use_cached=True)
                except (discord.HTTPException, discord.Forbidden, discord.NotFound, TypeError) as cached_exc:
                    errors += 1
                    error_notes.append(
                        _("{filename}: download failed ({error})").format(
                            filename=attachment_name,
                            error=type(cached_exc if cached_exc is not None else primary_exc).__name__,
                        )
                    )
                    continue
            try:
                archive = zipfile.ZipFile(io.BytesIO(archive_data))
            except zipfile.BadZipFile:
                errors += 1
                error_notes.append(
                    _("{filename}: invalid zip file").format(filename=attachment_name)
                )
                continue
            with archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    filename = Path(info.filename).name
                    if Path(filename).suffix.lower() not in IMAGE_ATTACHMENT_EXTENSIONS:
                        skipped += 1
                        continue
                    try:
                        data = archive.read(info)
                    except (RuntimeError, OSError, zipfile.BadZipFile):
                        errors += 1
                        continue
                    status, sample = await self._imagescan_add_bytes_sample(
                        ctx.guild.id,
                        data,
                        filename,
                        f"{attachment.url}#{info.filename}",
                        "true_positive",
                        ctx.author.id,
                    )
                    if status == "inserted":
                        inserted += 1
                        if sample is not None:
                            inserted_sample_ids.append(sample["sample_id"])
                    elif status == "duplicate":
                        duplicates += 1
                    elif status == "conflict":
                        conflicts += 1
                    else:
                        errors += 1
                    processed += 1
                    if processed == 1 or processed % 25 == 0:
                        try:
                            await progress.edit(
                                content=_("Imported {count} image(s)...").format(count=processed)
                            )
                        except discord.HTTPException:
                            pass
                        await asyncio.sleep(0)
        config = await self.config.guild(ctx.guild).all()
        state = await self._imagescan_model_state(
            ctx.guild.id,
            int(config.get("imagescan_detector_threshold", 20)),
        )
        if not state["valid"]:
            for sample_id in inserted_sample_ids:
                await self._imagescan_deactivate_sample(ctx.guild.id, sample_id)
            await self._imagescan_model_state(
                ctx.guild.id,
                int(config.get("imagescan_detector_threshold", 20)),
            )
            await progress.edit(content=_("Rejected: TP/FP overlap.\nModel unchanged."))
            return
        final_message = _(
            "Import finished: {inserted} added, {duplicates} already known, "
            "{conflicts} conflicts, {errors} failed, {skipped} skipped. "
            "Effective threshold: {threshold}"
        ).format(
            inserted=inserted,
            duplicates=duplicates,
            conflicts=conflicts,
            errors=errors,
            skipped=skipped,
            threshold=state["effective_threshold"],
        )
        if error_notes:
            shown_errors = "\n".join(f"- {note}" for note in error_notes[:5])
            if len(error_notes) > 5:
                shown_errors += _("\n- and {count} more").format(count=len(error_notes) - 5)
            final_message = f"{final_message}\n{_('Failed:')}\n{shown_errors}"
        await progress.edit(content=final_message)

    @honeypot.group()
    async def firstpost(self, ctx: commands.Context) -> None:
        """Configure first-message detection."""

    @firstpost.command(name="toggle")
    async def firstpost_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable first-message enforcement."""
        if value is None:
            v = await self.config.guild(ctx.guild).firstpost_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).firstpost_enabled.set(value)
            if value:
                await self.config.guild(ctx.guild).firstpost_collect_enabled.set(False)
            await ctx.send(_("✅ Firstpost enabled set to {value}").format(value=value))

    @firstpost.command(name="warmup")
    async def firstpost_collect(self, ctx: commands.Context, value: bool = None) -> None:
        """Record first-message senders without taking action."""
        if value is None:
            v = await self.config.guild(ctx.guild).firstpost_collect_enabled()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=str(v).lower(),
                    options=self._format_options(BOOL_OPTIONS),
                )
            )
        else:
            await self.config.guild(ctx.guild).firstpost_collect_enabled.set(value)
            if value:
                await self.config.guild(ctx.guild).firstpost_enabled.set(False)
            await ctx.send(_("✅ Firstpost warmup set to {value}").format(value=value))

    @firstpost.command(name="action")
    async def firstpost_action(self, ctx: commands.Context, value: str = None) -> None:
        """Set the action for suspicious first messages."""
        if value is None:
            v = await self.config.guild(ctx.guild).firstpost_action()
            await ctx.send(
                _("Current: {value}. Choices: {options}").format(
                    value=v,
                    options=self._format_options(CORE_ACTION_OPTIONS),
                )
            )
        elif value not in CORE_ACTION_OPTIONS:
            await ctx.send(_("Choose one of: {options}").format(options=self._format_options(CORE_ACTION_OPTIONS)))
        else:
            await self.config.guild(ctx.guild).firstpost_action.set(value)
            await ctx.send(_("✅ Firstpost action set to {value}").format(value=value))

    # ─── review sub-group ─────────────────────────────────────────────

    @honeypot.group()
    async def review(self, ctx: commands.Context) -> None:
        """Configure moderator review for suspicious cases."""

    @review.command(name="toggle")
    async def review_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable moderator review routing."""
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
        """Set the channel for moderator review requests."""
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
        """Set how long pending reviews stay active."""
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
        """Set how review kicks report users who already left."""
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

    @honeypot_settings.group()
    async def roles(self, ctx: commands.Context) -> None:
        """Manage roles trusted by the main honeypot layer."""

    @roles.command(name="add")
    async def roles_add(self, ctx: commands.Context, role: discord.Role) -> None:
        """Add a role to the honeypot whitelist."""
        async with self.config.guild(ctx.guild).whitelisted_roles() as roles:
            if role.id in roles:
                raise commands.UserFeedbackCheckFailure(_("That role is already whitelisted."))
            roles.append(role.id)
        await ctx.send(_("✅ {role} added to the whitelist.").format(role=role.mention))

    @roles.command(name="remove")
    async def roles_remove(self, ctx: commands.Context, role: discord.Role) -> None:
        """Remove a role from the honeypot whitelist."""
        async with self.config.guild(ctx.guild).whitelisted_roles() as roles:
            if role.id not in roles:
                raise commands.UserFeedbackCheckFailure(_("That role is not in the whitelist."))
            roles.remove(role.id)
        await ctx.send(_("✅ {role} removed from the whitelist.").format(role=role.mention))

    @roles.command(name="list")
    async def roles_list(self, ctx: commands.Context) -> None:
        """List roles on the honeypot whitelist."""
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

    @honeypot_settings.group()
    async def keywords(self, ctx: commands.Context) -> None:
        """Manage text and attachment patterns used by honeypot detection."""

    @keywords.command(name="add")
    async def keywords_add(self, ctx: commands.Context, *, keyword: str) -> None:
        """Add a honeypot keyword."""
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
        """Remove a honeypot keyword."""
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
        """List configured honeypot keywords."""
        keywords = await self.config.guild(ctx.guild).scam_keywords()
        if not keywords:
            await ctx.send(_("No keywords configured."))
            return
        await ctx.send(_("**Scam keywords:**\n{lines}").format(lines="\n".join(f"`{i}.` {kw}" for i, kw in enumerate(keywords, 1))))

    @keywords.command(name="reset")
    async def keywords_reset(self, ctx: commands.Context) -> None:
        """Reset honeypot keywords to defaults."""
        await self.config.guild(ctx.guild).scam_keywords.set(SCAM_KEYWORDS.copy())
        await ctx.send(_("✅ Keywords reset to defaults."))

    @keywords.group(name="attachments")
    async def keyword_attachments(self, ctx: commands.Context) -> None:
        """Manage attachment filename patterns used by honeypot detection."""

    @keyword_attachments.command(name="add")
    async def keyword_attachments_add(self, ctx: commands.Context, *, pattern: str) -> None:
        """Add an attachment filename pattern."""
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
        """Remove an attachment filename pattern."""
        async with self.config.guild(ctx.guild).attachment_patterns() as patterns:
            if pattern not in patterns:
                raise commands.UserFeedbackCheckFailure(_("Pattern not found."))
            patterns.remove(pattern)
        await ctx.send(_("✅ Attachment pattern removed: `{pattern}`").format(pattern=pattern))

    @keyword_attachments.command(name="list")
    async def keyword_attachments_list(self, ctx: commands.Context) -> None:
        """List configured attachment filename patterns."""
        patterns = await self.config.guild(ctx.guild).attachment_patterns()
        if not patterns:
            await ctx.send(_("No attachment patterns configured."))
            return
        await ctx.send(_("**Attachment patterns:**\n{lines}").format(lines="\n".join(f"`{i}.` {pattern}" for i, pattern in enumerate(patterns, 1))))

    @keyword_attachments.command(name="reset")
    async def keyword_attachments_reset(self, ctx: commands.Context) -> None:
        """Reset attachment filename patterns to defaults."""
        await self.config.guild(ctx.guild).attachment_patterns.set(DEFAULT_ATTACHMENT_PATTERNS.copy())
        await ctx.send(_("✅ Attachment patterns reset to defaults."))

    # ─── joinwatch sub-group ──────────────────────────────────────────

    @honeypot.group()
    async def joinwatch(self, ctx: commands.Context) -> None:
        """Configure young-account join monitoring."""

    @joinwatch.command(name="toggle")
    async def joinwatch_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable young-account join monitoring."""
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
        """Set the channel for young-account join alerts."""
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
        """Configure joinwatch alert delivery."""

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
        """Set the maximum account age for joinwatch alerts."""
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
        """Configure temporary roles for young accounts."""

    @joinwatch_autorole.command(name="toggle")
    async def joinwatch_autorole_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable joinwatch auto-role handling."""
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
        """Set the temporary role for young accounts."""
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
        """Set how long the temporary role may remain."""
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
        """Set the action when the temporary role is not removed in time."""
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
        """List active joinwatch auto-role timers."""
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
        """Configure randomized auto-role delay."""

    @joinwatch_autorole_randomize.command(name="toggle")
    async def joinwatch_autorole_randomize_toggle(
        self, ctx: commands.Context, value: bool = None
    ) -> None:
        """Enable or disable randomized auto-role delay."""
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
        """Set the minimum randomized auto-role delay."""
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
        """Set the maximum randomized auto-role delay."""
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

    # ─── bait role sub-group ──────────────────────────────────────────

    @honeypot.group(name="bait_role")
    async def bait_role(self, ctx: commands.Context) -> None:
        """Configure the bait role trap."""

    @bait_role.command(name="toggle")
    async def bait_toggle(self, ctx: commands.Context, value: bool = None) -> None:
        """Enable or disable bait role enforcement."""
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

    @bait_role.command()
    async def role(self, ctx: commands.Context, role: discord.Role = None) -> None:
        """Set the role that triggers bait role enforcement."""
        if role is None:
            v = await self.config.guild(ctx.guild).baitrole_id()
            r = ctx.guild.get_role(v) if v else None
            await ctx.send(_("Bait role: {role}").format(role=r.mention if r else _("not set")))
        else:
            await self.config.guild(ctx.guild).baitrole_id.set(role.id)
            await ctx.send(_("✅ Bait role set to {role.mention}").format(role=role))

    @bait_role.command(name="action")
    async def bait_action(self, ctx: commands.Context, value: str = None) -> None:
        """Set the action for bait role enforcement."""
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
        """Show current honeypot configuration by section."""

    @config_dump.command(name="honeypot")
    async def config_honeypot(self, ctx: commands.Context) -> None:
        """Show main honeypot detection settings."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Honeypot config"),
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
        """Show honeypot and log channel settings."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Channel config"),
            [
                (_("Honeypot channels"), self._format_honeypot_channel_list(ctx.guild, self._honeypot_channel_ids_from_config(config))),
                (_("Logs channel"), self._format_channel_setting(ctx.guild, config.get("logs_channel"))),
            ],
        )

    @config_dump.command(name="punishment")
    async def config_punishment(self, ctx: commands.Context) -> None:
        """Show review punishment settings."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Punishment config"),
            [
                (_("Mute role"), self._format_role_setting(ctx.guild, config.get("mute_role"))),
            ],
        )

    @config_dump.command(name="purge")
    async def config_purge(self, ctx: commands.Context) -> None:
        """Show message purge behavior."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Purge config"),
            [
                (_("Mode"), _("Event registry purge")),
                (_("Backward window"), _("{seconds}s").format(seconds=self._purge_backward_seconds(config))),
                (_("Forward window"), _("{seconds}s").format(seconds=self._purge_forward_seconds(config))),
                (_("Minimum retention"), _("{seconds}s").format(seconds=PURGE_MIN_RETENTION_SECONDS)),
            ],
        )

    @config_dump.command(name="firstpost")
    async def config_firstpost(self, ctx: commands.Context) -> None:
        """Show first-message detection settings."""
        config = await self.config.guild(ctx.guild).all()
        seen_count = await self._count_firstpost_seen_authors(ctx.guild.id)
        await self._send_config_dump(
            ctx,
            _("Firstpost config"),
            [
                (_("Enabled"), self._format_bool_setting(config.get("firstpost_enabled", False))),
                (_("Warmup"), self._format_bool_setting(config.get("firstpost_collect_enabled", False))),
                (_("Action"), config.get("firstpost_action", "review")),
                (_("Seen authors"), seen_count),
            ],
        )

    @config_dump.command(name="imagescan")
    async def config_imagescan(self, ctx: commands.Context) -> None:
        """Show image detector settings."""
        config = await self.config.guild(ctx.guild).all()
        state = await self._imagescan_model_state(
            ctx.guild.id,
            int(config.get("imagescan_detector_threshold", 20)),
        )
        await self._send_config_dump(
            ctx,
            _("Image scan config"),
            [
                (_("Enabled"), self._format_bool_setting(config.get("imagescan_detector_enabled", False))),
                (_("Action"), config.get("imagescan_detector_action", "review")),
                (_("Threshold"), f"{state['configured_threshold']} effective {state['effective_threshold']}"),
            ],
        )

    @config_dump.command(name="spam")
    async def config_spam(self, ctx: commands.Context) -> None:
        """Show duplicate-message spam settings."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Spam config"),
            [
                (_("Enabled"), self._format_bool_setting(config.get("spam_enabled", False))),
                (_("Action"), config.get("spam_action", "review")),
                (_("Window"), _("{seconds}s").format(seconds=config.get("spam_window_seconds", 10))),
                (_("Channels"), config.get("spam_min_channels", 2)),
            ],
        )

    @config_dump.command(name="review")
    async def config_review(self, ctx: commands.Context) -> None:
        """Show moderator review settings."""
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
        """Show honeypot whitelist role settings."""
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
        """Show honeypot keyword and attachment pattern counts."""
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
        """Show joinwatch settings."""
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

    @config_dump.command(name="bait_role")
    async def config_bait(self, ctx: commands.Context) -> None:
        """Show bait role trap settings."""
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
        """Show stored stat and pending timer counts."""
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
        """Show a compact summary of all honeypot settings."""
        config = await self.config.guild(ctx.guild).all()
        await self._send_config_dump(
            ctx,
            _("Honeypot config summary"),
            [
                (_("Honeypot"), self._format_bool_setting(config.get("enabled", False))),
                (_("Honeypot channels"), self._format_honeypot_channel_list(ctx.guild, self._honeypot_channel_ids_from_config(config))),
                (_("Logs channel"), self._format_channel_setting(ctx.guild, config.get("logs_channel"))),
                (_("Review"), self._format_bool_setting(config.get("review_enabled", False))),
                (_("Spam"), self._format_bool_setting(config.get("spam_enabled", False))),
                (_("Image scan"), self._format_bool_setting(config.get("imagescan_detector_enabled", False))),
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
        """Show detailed moderation statistics."""
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
                "Cached purge deletes": stats["cached_purge_deletes"],
                "Forward purge deletes": stats["forward_purge_deletes"],
            },
            "Firstpost": {
                "Firstpost seen": stats["firstpost_seen"],
                "Firstpost hits": stats["firstpost_hits"],
                "Firstpost reviews": stats["firstpost_reviews"],
                "Firstpost kicks": stats["firstpost_kicks"],
                "Firstpost bans": stats["firstpost_bans"],
                "Early catches": stats["early_catches"],
            },
            "Spam": {
                "Spam hits": stats["spam_hits"],
                "Spam reviews": stats["spam_reviews"],
                "Spam kicks": stats["spam_kicks"],
                "Spam bans": stats["spam_bans"],
                "Spam catches": stats["spam_catches"],
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
        """Show public server safety statistics."""
        stats = DEFAULT_STATS.copy()
        stats.update(await self.config.guild(ctx.guild).stats())
        lines = [
            f"  {_('Messages')}: {stats['detections']}",
            f"  {_('Bans')}: {stats['banned']}",
            f"  {_('Sent for Review')}: {stats['reviewed']}",
            f"  {_('Early catches')}: {stats['early_catches']}",
            f"  {_('Spam catches')}: {stats['spam_catches']}",
            f"  {_('Auto roles applied')}: {stats['joinwatch_auto_roles']}",
            f"  {_('Auto role punishments')}: {stats['joinwatch_auto_role_punishments']}",
        ]
        await ctx.send(_("**Server safety stats:**\n") + box("\n".join(lines)))

    @debug.command(name="resetstats")
    @commands.permissions_check(lambda ctx: ctx.author.id == ctx.guild.owner_id or ctx.author.id in ctx.bot.owner_ids)
    async def honeypot_reset_stats(self, ctx: commands.Context) -> None:
        """Reset stored honeypot statistics."""
        await self.config.guild(ctx.guild).stats.set(DEFAULT_STATS.copy())
        await ctx.send(_("✅ Stats reset."))

    @honeypot.command(name="doctor")
    async def honeypot_doctor(self, ctx: commands.Context) -> None:
        """Check honeypot configuration and required permissions."""
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
        checks.append(("Honeypot enabled", bool(config.get("enabled")), "Run `honeypot honeypot toggle true`."))
        checks.append(("Action configured", config.get("action") in ("kick", "ban", "review", "none"), "Run `honeypot honeypot action`."))
        checks.append(("Firstpost action configured", config.get("firstpost_action", "review") in CORE_ACTION_OPTIONS, "Run `honeypot firstpost action`."))
        checks.append(("Spam action configured", config.get("spam_action", "review") in CORE_ACTION_OPTIONS, "Run `honeypot spam action`."))
        checks.append(("Honeypot channel exists", bool(honeypot_channels), "Run `honeypot channel add`."))
        checks.append(("Logs channel exists", logs_channel is not None, "Run `honeypot channel logs`."))
        if (
            config.get("fallback_action") == "review"
            or config.get("review_enabled")
            or config.get("whitelist_mode") == "review"
            or (
                config.get("firstpost_enabled", False)
                and config.get("firstpost_action", "review") == "review"
            )
            or (
                config.get("spam_enabled", False)
                and config.get("spam_action", "review") == "review"
            )
        ):
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
        skipped_channels = []
        purgeable_channels = [
            channel
            for channel in list(ctx.guild.channels) + list(ctx.guild.threads)
            if is_purgeable_message_channel(channel)
        ]
        for channel in purgeable_channels:
            perms = channel.permissions_for(me)
            if not perms.view_channel:
                continue
            if not perms.manage_messages:
                skipped_channels.append(channel.mention)
        if skipped_channels:
            shown_channels = ", ".join(skipped_channels[:8])
            if len(skipped_channels) > 8:
                shown_channels += " ..."
            checks.append(
                (
                    "Cached purge can delete visible message channels",
                    False,
                    "\nManage - " + shown_channels,
                )
            )
        else:
            checks.append(
                (
                    "Cached purge can delete visible message channels",
                    True,
                    "Grant Manage Messages in visible channels where cached purge should delete messages.",
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
        failed = [
            f"❌ {name}{hint}" if hint.startswith("\n") else f"❌ {name} - {hint}"
            for name, ok, hint in checks
            if not ok
        ]
        passed = [f"✅ {name}" for name, ok, _hint in checks if ok]
        await ctx.send(_("**Honeypot doctor:**\n{body}").format(body="\n".join(passed + failed)))
