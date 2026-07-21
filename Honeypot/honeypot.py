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
from time import perf_counter
import typing
import zipfile
from collections import defaultdict, deque
from contextlib import asynccontextmanager, closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import discord
from discord.ext import tasks

from AAA3A_utils import Cog
from redbot.core import Config, commands, modlog
from redbot.core.bot import Red
from redbot.core.data_manager import cog_data_path
from redbot.core.i18n import Translator, cog_i18n
from redbot.core.utils.chat_formatting import box, pagify

from .detection_cases import (
    ActionIntent,
    AttachmentKey,
    CaseStatus,
    DeleteStatus,
    DetectionCaseStore,
    DetectionSignal,
    NewAttachment,
    NewMessage,
    effective_action,
)
from .case_review import (
    CaseFeedbackItem,
    CaseReviewService,
    available_image_review_actions,
    bulk_image_confirmation_label,
    case_custom_id,
    case_feedback_items,
    is_persisted_image_attachment,
    render_case,
    render_timeline,
    validate_image_review_action,
)
from .console_dump import ReadOnlyLogBuffer, build_log_dump
from . import detection_runtime
from .image_detector import (
    ImageSample,
    image_hashes_from_bytes,
    match_image,
    rebuild_model_state,
)

_ = Translator("Honeypot", __file__)
log = logging.getLogger("red.Honeypot")
_TIMELINE_VIEW_UNSET = object()
DETECTION_FAST_RETRY_SECONDS = 10
DETECTION_FAST_RETRY_LIMIT = 5
DETECTION_SLOW_RETRY_MINUTES = 5
CONSOLE_DUMP_USAGE = (
    "Usage: `consoledump <bot|honeypot> <hours 1-24> "
    "[debug|info|warning|error|critical]`\n"
    "Scope: `bot` includes all captured Python logs. `honeypot` includes Honeypot "
    "logs and related tracebacks.\n"
    "Hours: a whole number from 1 to 24.\n"
    "Level (optional): the minimum log level to include. Omit it to include all "
    "levels.\n"
    "Examples: `consoledump bot 2`, `consoledump honeypot 1`, "
    "`consoledump bot 6 error`"
)

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
    "forward_purge_delete_failures": 0,
    "evidence_capture_failures": 0,
    "delete_forbidden": 0,
    "delete_transient_failures": 0,
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
    "honeypot_hits": 0,
    "honeypot_reviews": 0,
    "honeypot_kicks": 0,
    "honeypot_bans": 0,
    "honeypot_catches": 0,
    "image_hits": 0,
    "image_reviews": 0,
    "image_kicks": 0,
    "image_bans": 0,
    "image_catches": 0,
    "joinwatch_total_joins": 0,
    "joinwatch_young_joins": 0,
    "joinwatch_auto_roles_scheduled": 0,
    "joinwatch_auto_roles": 0,
    "joinwatch_auto_role_failures": 0,
    "joinwatch_auto_roles_cleared": 0,
    "joinwatch_auto_role_punishments": 0,
}

JOINWATCH_RETRY_DELAY_MINUTES = 1
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
DETECTION_CAPTURE_DEADLINE_SECONDS = 20.0
DETECTION_ATTACHMENT_TIMEOUT_SECONDS = 15.0
DETECTION_CAPTURE_START_TIMEOUT_SECONDS = 1.0
DETECTION_IMAGE_READ_MAX_BYTES = 25 * 1024 * 1024
DETECTION_EVIDENCE_RESERVATION_STALE_SECONDS = 5 * 60
DETECTION_CAPTURE_CONCURRENCY = 4
DETECTION_HEARTBEAT_INTERVAL_SECONDS = 60.0
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




def is_imagescan_sample_path_safe(files_root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(files_root.resolve())
        return True
    except (OSError, ValueError):
        return False


def case_evidence_root(evidence_root: Path, guild_id: int, case_id: str) -> Path:
    """Return the canonical storage root for one guild-scoped detection case."""
    return evidence_root / str(guild_id) / case_id


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


# Interaction response policy: use ephemeral messages only for useful information
# that is not already visible in the public message, such as permission denials,
# errors, conflicts, or confirmation prompts. Do not repeat successful actions
# when the updated embed, content, or disabled controls already show the result.
class DetectionCaseView(discord.ui.View):
    """Persistent controls whose callbacks always resolve state through SQLite."""

    def __init__(
        self,
        cog: "Honeypot",
        case_id: str,
        *,
        has_image_feedback: bool,
        feedback_items: tuple[CaseFeedbackItem, ...] = (),
        message_sequence: int | None = None,
        resolved: bool = False,
        allow_individual: bool = True,
        moderation_actions: tuple[str, ...] = ("ban", "kick", "ignore"),
    ) -> None:
        super().__init__()
        self.timeout = None
        self.cog = cog
        self.case_id = case_id
        self.message_sequence = message_sequence
        scope = f"message-{message_sequence}" if message_sequence is not None else None
        add_item = getattr(self, "add_item", None)
        if not callable(add_item):
            return
        if self.message_sequence is None and not resolved:
            for label, action, style, emoji in (
                ("Ban", "ban", discord.ButtonStyle.danger, "🔨"),
                ("Kick", "kick", discord.ButtonStyle.secondary, "👢"),
                ("Ignore", "ignore", discord.ButtonStyle.success, "✅"),
            ):
                if action not in moderation_actions:
                    continue
                button = discord.ui.Button(
                    label=label,
                    style=style,
                    emoji=emoji,
                    custom_id=case_custom_id(case_id, "moderate", action),
                    disabled=resolved,
                    row=0,
                )

                async def moderation_callback(interaction, selected=action):
                    await self.cog._case_review_moderation_interaction(
                        interaction, self.case_id, selected
                    )

                button.callback = moderation_callback
                add_item(button)
        if resolved or not has_image_feedback:
            return
        available_actions = available_image_review_actions(feedback_items)
        labels = {
            "tp": "All TP" if "fp" in available_actions else "Add all",
            "fp": "All FP",
            "ignore": "Ignore",
        }
        styles = {
            "tp": discord.ButtonStyle.success,
            "fp": discord.ButtonStyle.danger,
            "ignore": discord.ButtonStyle.secondary,
        }
        for action in available_actions:
            label = labels[action]
            style = styles[action]
            button = discord.ui.Button(
                label=label,
                style=style,
                custom_id=case_custom_id(
                    case_id,
                    f"{scope}-resolve" if scope is not None else "resolve",
                    action,
                ),
                disabled=resolved,
                row=1,
            )

            async def callback(interaction, selected=action):
                if self.message_sequence is None:
                    await self.cog._case_review_bulk_interaction(
                        interaction, self.case_id, selected
                    )
                else:
                    await self.cog._case_review_message_bulk_interaction(
                        interaction,
                        self.case_id,
                        self.message_sequence,
                        selected,
                    )

            button.callback = callback
            add_item(button)
        if not allow_individual:
            return
        individual = discord.ui.Button(
            label="Individual",
            style=discord.ButtonStyle.primary,
            custom_id=case_custom_id(
                case_id,
                f"{scope}-images" if scope is not None else "images",
                "individual",
            ),
            disabled=resolved,
            row=1,
        )

        async def individual_callback(interaction):
            if self.message_sequence is None:
                await self.cog._case_review_individual_prompt(
                    interaction, self.case_id
                )
            else:
                await self.cog._case_review_individual_prompt(
                    interaction,
                    self.case_id,
                    message_sequence=self.message_sequence,
                )

        individual.callback = individual_callback
        add_item(individual)


class DetectionBulkConfirmationView(discord.ui.View):
    def __init__(
        self,
        cog: "Honeypot",
        case_id: str,
        action: str,
        *,
        message_sequence: int | None = None,
        confirm_label: str | None = None,
        expected_keys: tuple[AttachmentKey, ...] = (),
    ) -> None:
        super().__init__()
        self.timeout = 60
        self.cog = cog
        self.case_id = case_id
        self.action = action
        self.message_sequence = message_sequence
        self.expected_keys = expected_keys
        add_item = getattr(self, "add_item", None)
        if not callable(add_item):
            return
        label = confirm_label or (
            "Confirm All TP" if action == "tp" else "Confirm All FP"
        )
        style = (
            discord.ButtonStyle.success
            if action == "tp"
            else discord.ButtonStyle.danger
        )
        button = discord.ui.Button(label=label, style=style)

        async def callback(interaction):
            if self.message_sequence is None:
                completed = await self.cog._case_review_bulk_interaction(
                    interaction,
                    self.case_id,
                    self.action,
                    confirmed=True,
                    expected_keys=self.expected_keys,
                )
            else:
                completed = await self.cog._case_review_message_bulk_interaction(
                    interaction,
                    self.case_id,
                    self.message_sequence,
                    self.action,
                    confirmed=True,
                    expected_keys=self.expected_keys,
                )
            if completed:
                try:
                    await interaction.delete_original_response()
                except discord.NotFound:
                    pass

        button.callback = callback
        add_item(button)


class DetectionModerationConfirmationView(discord.ui.View):
    def __init__(self, cog: "Honeypot", case_id: str, action: str) -> None:
        super().__init__()
        self.timeout = 60
        self.cog = cog
        self.case_id = case_id
        self.action = action
        add_item = getattr(self, "add_item", None)
        if not callable(add_item):
            return
        button = discord.ui.Button(
            label=f"Confirm {action.title()}",
            style=(
                discord.ButtonStyle.danger
                if action == "ban"
                else discord.ButtonStyle.secondary
            ),
        )

        async def callback(interaction):
            completed = await self.cog._case_review_moderation_interaction(
                interaction, self.case_id, self.action, confirmed=True
            )
            if completed:
                try:
                    await interaction.delete_original_response()
                except discord.NotFound:
                    pass

        button.callback = callback
        add_item(button)


class DetectionIndividualView(discord.ui.View):
    def __init__(
        self, cog: "Honeypot", feedback_items: tuple[CaseFeedbackItem, ...]
    ) -> None:
        super().__init__()
        self.timeout = 300
        self.cog = cog
        self.selected_key: AttachmentKey | None = None
        add_item = getattr(self, "add_item", None)
        if not callable(add_item):
            return
        choices = feedback_items[:25]
        items = {str(index): item for index, item in enumerate(choices)}
        selector = discord.ui.Select(
            placeholder="Choose an image",
            min_values=1,
            max_values=1,
            options=[
                discord.SelectOption(
                    label=(
                        f"{item.key.message_sequence}.{item.key.position + 1} "
                        f"{item.filename}"
                    )[:100],
                    value=str(index),
                )
                for index, item in enumerate(choices)
            ],
            row=0,
        )
        action_buttons = []

        def replace_action_buttons(item: CaseFeedbackItem) -> None:
            remove_item = getattr(self, "remove_item", None)
            for button in action_buttons:
                if callable(remove_item):
                    remove_item(button)
                elif hasattr(self, "children") and button in self.children:
                    self.children.remove(button)
            action_buttons.clear()
            available_actions = available_image_review_actions((item,))
            labels = {
                "tp": "TP" if "fp" in available_actions else "Add",
                "fp": "FP",
                "ignore": "Ignore",
            }
            styles = {
                "tp": discord.ButtonStyle.success,
                "fp": discord.ButtonStyle.danger,
                "ignore": discord.ButtonStyle.secondary,
            }
            for action in available_actions:
                label = labels[action]
                style = styles[action]
                button = discord.ui.Button(
                    label=label,
                    style=style,
                    disabled=False,
                    row=1,
                )

                async def callback(interaction, selected=action):
                    if self.selected_key is None:
                        return
                    await self.cog._case_review_attachment_interaction(
                        interaction, self.selected_key, selected
                    )

                button.callback = callback
                action_buttons.append(button)
                add_item(button)

        async def select_callback(interaction):
            selected_value = selector.values[0]
            selected_item = items[selected_value]
            self.selected_key = selected_item.key
            for option in selector.options:
                option.default = option.value == selected_value
            replace_action_buttons(selected_item)
            await interaction.response.edit_message(
                content=_("Choose the result for the selected image."), view=self
            )

        selector.callback = select_callback
        add_item(selector)












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
            review_kick_fail_warning="false",
            automated_kick_fail_warning=False,
            whitelist_mode="bypass",
            stats=DEFAULT_STATS.copy(),
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

        self._console_log_buffer = ReadOnlyLogBuffer()
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
        self._detection_case_db_path = cog_data_path(self) / "detection_cases.sqlite"
        self._detection_case_files_path = cog_data_path(self) / "detection_case_files"
        self._case_store = DetectionCaseStore(self._detection_case_db_path)
        self._case_review_service = CaseReviewService(self._case_store)
        self._case_views: dict[str, object] = {}
        self._case_restore_task: asyncio.Task | None = None
        self._initial_image_scan_tasks: set[asyncio.Task] = set()
        self._initial_image_scan_batches: dict[
            tuple[int, int], dict[int, asyncio.Task]
        ] = {}
        self._detection_case_evidence_lock: asyncio.Lock = asyncio.Lock()
        self._detection_case_capture_slots = asyncio.Semaphore(
            DETECTION_CAPTURE_CONCURRENCY
        )
        self._detection_admission_locks = tuple(asyncio.Lock() for _ in range(64))
        self._detection_publication_locks = tuple(asyncio.Lock() for _ in range(64))
        self._detection_heartbeat_interval_seconds = DETECTION_HEARTBEAT_INTERVAL_SECONDS

    def _delete_detection_case_evidence(
        self, cases: tuple[tuple[int, str], ...]
    ) -> None:
        evidence_root = self._detection_case_files_path.resolve()
        for guild_id, case_id in cases:
            case_root = case_evidence_root(
                self._detection_case_files_path, guild_id, case_id
            )
            if not case_root.exists():
                continue
            if not case_root.resolve().is_relative_to(evidence_root):
                raise RuntimeError("detection case evidence path escapes storage root")
            shutil.rmtree(case_root)

    def _discard_rejected_detection_case_capture(
        self, guild_id: int, case_id: str, capture_path: Path
    ) -> None:
        evidence_root = self._detection_case_files_path.resolve()
        case_root = case_evidence_root(
            self._detection_case_files_path, guild_id, case_id
        ).resolve()
        resolved_capture = capture_path.resolve()
        if not case_root.is_relative_to(evidence_root):
            raise RuntimeError("detection case evidence path escapes storage root")
        if not resolved_capture.is_relative_to(case_root):
            raise RuntimeError("detection case evidence path escapes case root")
        capture_path.unlink(missing_ok=True)
        parent = resolved_capture.parent
        while parent != case_root:
            try:
                parent.rmdir()
            except OSError:
                return
            parent = parent.parent
        try:
            case_root.rmdir()
        except OSError:
            pass

    @asynccontextmanager
    async def _detection_case_deletion_barrier(self):
        async with self._detection_case_evidence_lock:
            acquired_slots = 0
            try:
                for _ in range(DETECTION_CAPTURE_CONCURRENCY):
                    await self._detection_case_capture_slots.acquire()
                    acquired_slots += 1
                yield
            finally:
                for _ in range(acquired_slots):
                    self._detection_case_capture_slots.release()

    async def _delete_detection_case_scope(
        self,
        delete_cases: typing.Callable[[int], tuple[tuple[int, str], ...]],
        scope_id: int,
    ) -> None:
        async with self._detection_case_deletion_barrier():
            await asyncio.to_thread(delete_cases, scope_id)
            cases = await asyncio.to_thread(
                self._case_store.list_planned_case_deletions
            )
            await self._finish_detection_case_deletions(cases)

    async def _finish_detection_case_deletions(
        self, cases: tuple[tuple[int, str], ...]
    ) -> None:
        errors: list[Exception] = []
        for guild_id, case_id in cases:
            job = await asyncio.to_thread(
                self._case_store.get_case_deletion_job, case_id
            )
            if job is None:
                continue
            if not job.remote_deleted:
                try:
                    await self._delete_detection_case_publications(guild_id, case_id)
                    await asyncio.to_thread(
                        self._case_store.mark_case_deletion_remote, case_id
                    )
                except Exception as error:
                    await asyncio.to_thread(
                        self._case_store.mark_case_deletion_remote,
                        case_id,
                        error=str(error),
                    )
                    await self._record_operational_failure(
                        guild_id,
                        "case_publication_deletion",
                        f"{type(error).__name__}: {error}",
                        case_id=case_id,
                    )
                    errors.append(error)
            local_deleted = job.local_deleted
            if not local_deleted:
                try:
                    await asyncio.to_thread(
                        self._delete_detection_case_evidence,
                        ((guild_id, case_id),),
                    )
                    await asyncio.to_thread(
                        self._case_store.mark_case_deletion_local, case_id
                    )
                    local_deleted = True
                except Exception as error:
                    await self._record_operational_failure(
                        guild_id,
                        "case_evidence_deletion",
                        f"{type(error).__name__}: {error}",
                        case_id=case_id,
                    )
                    errors.append(error)
            if not job.rows_deleted and local_deleted:
                inflight = await asyncio.to_thread(
                    self._case_store.case_deletion_has_inflight_publications,
                    case_id,
                )
                if inflight:
                    errors.append(
                        RuntimeError(
                            f"detection case publications are still in flight: {case_id}"
                        )
                    )
                else:
                    finalized = await asyncio.to_thread(
                        self._case_store.finalize_case_deletion,
                        guild_id,
                        case_id,
                    )
                    if not finalized:
                        errors.append(
                            RuntimeError(
                                f"detection case deletion job disappeared: {case_id}"
                            )
                        )
                    else:
                        self._case_views.pop(case_id, None)
            await asyncio.to_thread(
                self._case_store.complete_case_deletion_job, case_id
            )
        if errors:
            raise errors[0]

    async def _delete_detection_case_publications(
        self, guild_id: int, case_id: str
    ) -> None:
        job = await asyncio.to_thread(
            self._case_store.get_case_deletion_job, case_id
        )
        if job is None:
            raise RuntimeError(f"detection case deletion job disappeared: {case_id}")
        if (
            job.parent_channel_id is None
            and job.summary_message_id is None
            and job.thread_id is None
            and not job.legacy_publications
        ):
            return
        guild = self.bot.get_guild(guild_id)
        if guild is None:
            raise RuntimeError(
                f"guild {guild_id} is unavailable for detection case deletion"
            )
        parent = await self._fetch_text_channel_or_thread(
            guild, job.parent_channel_id
        )
        summary = None
        if parent is not None and job.summary_message_id is not None:
            try:
                summary = await parent.fetch_message(job.summary_message_id)
            except discord.NotFound:
                summary = None

        thread = None
        if summary is not None:
            fetch_thread = getattr(summary, "fetch_thread", None)
            if callable(fetch_thread):
                try:
                    thread = await fetch_thread()
                except discord.NotFound:
                    thread = None
        if thread is None and job.thread_id is not None:
            thread = await self._fetch_text_channel_or_thread(guild, job.thread_id)

        if thread is not None:
            try:
                await thread.delete(reason="Honeypot user data deletion")
            except discord.NotFound:
                pass
        for channel_id, message_id in job.legacy_publications:
            legacy_channel = await self._fetch_text_channel_or_thread(
                guild, channel_id
            )
            if legacy_channel is None:
                continue
            try:
                legacy_message = await legacy_channel.fetch_message(message_id)
                await legacy_message.delete()
            except discord.NotFound:
                pass
        if summary is not None:
            try:
                await summary.delete()
            except discord.NotFound:
                pass

    async def _retry_detection_case_deletions(self) -> None:
        async with self._detection_case_deletion_barrier():
            cases = await asyncio.to_thread(
                self._case_store.list_planned_case_deletions
            )
            await self._finish_detection_case_deletions(cases)

    async def red_delete_data_for_user(
        self, *, requester: typing.Any, user_id: int
    ) -> None:
        """Delete detection-case metadata and evidence associated with a Red user."""
        await self._delete_detection_case_scope(
            self._case_store.plan_user_case_deletion, user_id
        )

    @commands.Cog.listener()
    async def on_guild_remove(self, guild: discord.Guild) -> None:
        """Delete detection-case metadata and evidence when Red leaves a guild."""
        await self._delete_detection_case_scope(
            self._case_store.plan_guild_case_deletion, guild.id
        )

    async def cog_after_invoke(self, ctx: commands.Context) -> commands.Context | None:
        """Finish command cleanup without AAA3A_utils' redundant success reaction."""
        if isinstance(ctx.command, commands.Group) and (
            ctx.invoked_subcommand is not None or not ctx.command.invoke_without_command
        ):
            return None
        if ctx.command_failed:
            return await super().cog_after_invoke(ctx)
        typing = getattr(ctx, "_typing", None)
        task = getattr(typing, "task", None)
        if callable(getattr(task, "cancel", None)):
            task.cancel()
        return ctx

    async def _increment_stat(self, guild: discord.Guild, key: str, amount: int = 1) -> None:
        guild_config = getattr(self.config, "guild", None)
        if not callable(guild_config):
            return
        async with guild_config(guild).stats() as stats:
            stats.setdefault(key, 0)
            stats[key] += amount

    async def _record_detection_stats(
        self, guild: discord.Guild, signals: tuple[DetectionSignal, ...]
    ) -> None:
        signals = tuple(
            signal
            for signal in signals
            if not signal.metadata.get("whitelist_bypass")
        )
        if not signals:
            return
        await self._increment_stat(guild, "detections")
        if any(signal.decisive for signal in signals):
            await self._increment_stat(guild, "suspicious")
        for detector, prefix, catch_key in (
            ("honeypot", "honeypot", "honeypot_catches"),
            ("firstpost", "firstpost", "early_catches"),
            ("spam", "spam", "spam_catches"),
            ("image", "image", "image_catches"),
        ):
            detector_signals = tuple(
                signal for signal in signals if signal.detector == detector
            )
            if not detector_signals:
                continue
            await self._increment_stat(guild, f"{prefix}_hits")
            if any(signal.decisive for signal in detector_signals):
                await self._increment_stat(guild, catch_key)
            intents = {signal.action for signal in detector_signals}
            for intent, suffix in (
                (ActionIntent.REVIEW, "reviews"),
                (ActionIntent.KICK, "kicks"),
                (ActionIntent.BAN, "bans"),
            ):
                if intent in intents:
                    await self._increment_stat(guild, f"{prefix}_{suffix}")

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
        with closing(sqlite3.connect(self._imagescan_db_path)) as conn, conn:
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
        with closing(sqlite3.connect(self._imagescan_db_path)) as conn, conn:
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
        with closing(sqlite3.connect(self._imagescan_db_path)) as conn, conn:
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
        with closing(sqlite3.connect(self._imagescan_db_path)) as conn:
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
        with closing(sqlite3.connect(self._imagescan_db_path)) as conn, conn:
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

    def _imagescan_publish_file_sample_sync(
        self,
        sample: dict[str, typing.Any],
        data: bytes,
        path: Path,
    ) -> str:
        temp_path = path.with_name(f".sample-{uuid4().hex}.tmp")
        published = False
        with closing(sqlite3.connect(self._imagescan_db_path)) as conn:
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    """SELECT decision FROM imagescan_samples
                       WHERE guild_id = ? AND sha256 = ? AND active = 1""",
                    (sample["guild_id"], sample["sha256"]),
                ).fetchone()
                if existing is not None:
                    conn.rollback()
                    return (
                        "duplicate"
                        if existing["decision"] == sample["decision"]
                        else "conflict"
                    )
                if path.exists():
                    conn.rollback()
                    return "conflict"
                temp_path.write_bytes(data)
                conn.execute(
                    """INSERT INTO imagescan_samples (
                           sample_id, guild_id, decision, sha256, phash, dhash, ahash,
                           source_message_id, source_channel_id, source_jump_url,
                           file_path, file_size_bytes, created_at, moderator_id, active
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
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
                temp_path.replace(path)
                published = True
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                finally:
                    if published:
                        path.unlink(missing_ok=True)
                raise
            finally:
                temp_path.unlink(missing_ok=True)
        return "inserted"

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
        try:
            async with self._imagescan_db_lock:
                status = await asyncio.to_thread(
                    self._imagescan_publish_file_sample_sync,
                    sample,
                    data,
                    path,
                )
        except (OSError, sqlite3.Error) as exc:
            log.debug("Failed to write imagescan import sample %s: %r", path, exc)
            return "error", None
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
        except discord.NotFound:
            return True
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
        except (discord.NotFound, TypeError, ValueError):
            return
        except (discord.Forbidden, discord.HTTPException) as exc:
            await self._record_operational_failure(
                guild.id,
                "joinwatch_alert_update",
                f"Could not fetch joinwatch alert {message_id}: {exc}",
            )
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
        except discord.HTTPException as exc:
            log.debug("Failed to edit joinwatch alert message %s in guild %s", message_id, guild.id)
            await self._record_operational_failure(
                guild.id,
                "joinwatch_alert_update",
                f"Could not update joinwatch alert {message_id}: {exc}",
            )

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
        await self._record_operational_failure(
            guild.id,
            "joinwatch_role_assignment",
            failure,
            attempts=JOINWATCH_MAX_RETRIES + 1 if retry_count is None else retry_count,
            terminal=retry_count is None,
        )
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
        await self._record_operational_failure(
            guild.id,
            "joinwatch_role_action",
            failure,
            attempts=JOINWATCH_MAX_RETRIES + 1 if retry_count is None else retry_count,
            terminal=retry_count is None,
        )
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

    async def _fetch_text_channel_or_thread(
        self, guild: discord.Guild, channel_id: int | None
    ) -> discord.TextChannel | discord.Thread | None:
        channel = self._get_text_channel_or_thread(guild, channel_id)
        if channel is not None or channel_id is None:
            return channel
        fetch_channel = getattr(guild, "fetch_channel", None)
        if not callable(fetch_channel):
            return None
        try:
            channel = await fetch_channel(channel_id)
        except discord.NotFound:
            return None
        if isinstance(channel, (discord.TextChannel, discord.Thread)):
            return channel
        return None

    async def _fetch_message_channel(
        self, guild: discord.Guild, channel_id: int | None
    ) -> typing.Any | None:
        if channel_id is None:
            return None
        channel = guild.get_channel(channel_id)
        if channel is None and hasattr(guild, "get_thread"):
            channel = guild.get_thread(channel_id)
        if channel is None:
            channel = self.bot.get_channel(channel_id)
        if channel is None:
            fetch_channel = getattr(guild, "fetch_channel", None)
            if not callable(fetch_channel):
                raise RuntimeError("detection source channel cannot be fetched")
            try:
                channel = await fetch_channel(channel_id)
            except discord.NotFound:
                return None
        if not callable(getattr(channel, "fetch_message", None)):
            raise RuntimeError("detection source channel cannot resolve messages")
        return channel

    def _missing_channel_permissions(
        self,
        guild: discord.Guild,
        channel: discord.TextChannel | discord.Thread,
        *,
        send_messages: bool = True,
        read_history: bool = False,
        manage_messages: bool = False,
        create_public_threads: bool = False,
        send_in_threads: bool = False,
        embed_links: bool = False,
        attach_files: bool = False,
        manage_threads: bool = False,
    ) -> str | None:
        me = guild.me
        if me is None:
            return _("I couldn't find my server member.")
        perms = channel.permissions_for(me)
        if not perms.view_channel:
            return _("I need `View Channel` in {channel}.").format(channel=channel.mention)
        if send_messages and not perms.send_messages:
            return _("I need `Send Messages` in {channel}.").format(channel=channel.mention)
        if read_history and not perms.read_message_history:
            return _("I need `Read Message History` in {channel}.").format(channel=channel.mention)
        if manage_messages and not perms.manage_messages:
            return _("I need `Manage Messages` in {channel}.").format(channel=channel.mention)
        if create_public_threads and not perms.create_public_threads:
            return _("I need `Create Public Threads` in {channel}.").format(
                channel=channel.mention
            )
        if send_in_threads and not perms.send_messages_in_threads:
            return _("I need `Send Messages in Threads` in {channel}.").format(
                channel=channel.mention
            )
        if embed_links and not perms.embed_links:
            return _("I need `Embed Links` in {channel}.").format(
                channel=channel.mention
            )
        if attach_files and not perms.attach_files:
            return _("I need `Attach Files` in {channel}.").format(
                channel=channel.mention
            )
        if manage_threads and not perms.manage_threads:
            return _("I need `Manage Threads` in {channel}.").format(
                channel=channel.mention
            )
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

    async def _is_protected_member(
        self,
        member: discord.Member | discord.User,
        guild: discord.Guild | None = None,
    ) -> bool:
        if member.id in getattr(self.bot, "owner_ids", ()):
            return True
        member_guild = getattr(member, "guild", None)
        guild = member_guild or guild
        if guild is None:
            return True
        if member_guild is None or not hasattr(member, "guild_permissions"):
            resolved_member = guild.get_member(member.id)
            if resolved_member is None:
                fetch_member = getattr(guild, "fetch_member", None)
                if not callable(fetch_member):
                    await self._record_operational_failure(
                        guild.id,
                        "member_resolution",
                        f"Could not resolve guild member {member.id}: lookup unavailable",
                    )
                    return True
                try:
                    resolved_member = await fetch_member(member.id)
                except discord.NotFound:
                    return False
                except discord.HTTPException as error:
                    await self._record_operational_failure(
                        guild.id,
                        "member_resolution",
                        f"Could not resolve guild member {member.id}: {error}",
                    )
                    return True
            member = resolved_member
        me = guild.me
        if me is None:
            return True
        return (
            await self.bot.is_mod(member)
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

    def _install_console_log_buffer(self) -> None:
        root_logger = logging.getLogger()
        if self._console_log_buffer not in root_logger.handlers:
            root_logger.addHandler(self._console_log_buffer)

    def _remove_console_log_buffer(self) -> None:
        root_logger = logging.getLogger()
        if self._console_log_buffer in root_logger.handlers:
            root_logger.removeHandler(self._console_log_buffer)


    async def cog_load(self) -> None:
        await super().cog_load()
        await self._init_firstpost_seen_store()
        await self._init_imagescan_store()
        self._detection_case_files_path.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(self._case_store.initialize)
        await self._run_detection_reconciliation()
        self.joinwatch_auto_role_loop.start()
        self.purge_cache_cleanup_loop.start()
        self.firstpost_seen_flush_loop.start()
        self.detection_case_loop.start()
        self.detection_reconciliation_loop.start()
        self._case_restore_task = asyncio.create_task(self._restore_detection_case_views())
        self._case_restore_task.add_done_callback(
            lambda task: self._observe_background_task(task, "detection case view restoration")
        )
        self._install_console_log_buffer()

    @staticmethod
    def _observe_background_task(task: asyncio.Task, label: str) -> None:
        if task.cancelled():
            return
        try:
            error = task.exception()
        except asyncio.CancelledError:
            return
        if error is not None:
            log.error(
                "%s failed",
                label,
                exc_info=(type(error), error, error.__traceback__),
            )

    async def _cancel_owned_task(self, task: asyncio.Task | None) -> None:
        if task is None:
            return
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            # The done callback observes and logs task failures.
            pass

    async def cog_unload(self) -> None:
        self._remove_console_log_buffer()
        self.joinwatch_auto_role_loop.cancel()
        self.purge_cache_cleanup_loop.cancel()
        self.firstpost_seen_flush_loop.cancel()
        self.detection_case_loop.cancel()
        self.detection_reconciliation_loop.cancel()
        try:
            await self._cancel_owned_task(self._case_restore_task)
        finally:
            self._case_restore_task = None
        pending_sweeps = tuple(self._post_ban_sweep_tasks)
        for task in pending_sweeps:
            task.cancel()
        if pending_sweeps:
            await asyncio.gather(*pending_sweeps, return_exceptions=True)
        self._post_ban_sweep_tasks.clear()
        pending_scans = tuple(self._initial_image_scan_tasks)
        for task in pending_scans:
            task.cancel()
        if pending_scans:
            await asyncio.gather(*pending_scans, return_exceptions=True)
        self._initial_image_scan_tasks.clear()
        self._initial_image_scan_batches.clear()
        await self._flush_firstpost_seen_authors()
        await super().cog_unload()

    @tasks.loop(seconds=60)
    async def firstpost_seen_flush_loop(self) -> None:
        await self._flush_firstpost_seen_authors()

    @tasks.loop(minutes=1)
    async def purge_cache_cleanup_loop(self) -> None:
        configs = {int(guild_id): config for guild_id, config in (await self.config.all_guilds()).items()}
        self._prune_purge_cache(configs)

    @tasks.loop(minutes=1)
    async def detection_case_loop(self) -> None:
        await self._run_detection_case_expiry()

    @detection_case_loop.before_loop
    async def before_detection_case_loop(self) -> None:
        await self.bot.wait_until_red_ready()

    @tasks.loop(seconds=DETECTION_FAST_RETRY_SECONDS)
    async def detection_reconciliation_loop(self) -> None:
        await self._run_detection_reconciliation()

    @detection_reconciliation_loop.before_loop
    async def before_detection_reconciliation_loop(self) -> None:
        await self.bot.wait_until_red_ready()

    async def _run_detection_case_expiry(self) -> None:
        now = datetime.now(timezone.utc)
        due_cases = await asyncio.to_thread(self._case_store.list_due_cases, now)
        for case in due_cases:
            await self.resolve_detection_case(case.case_id, "expired", now=now)

    async def _send_operational_alert(self, guild_id: int, content: str) -> None:
        try:
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                return
            config = await self.config.guild_from_id(guild_id).all()
            channel = self._get_text_channel_or_thread(guild, config.get("logs_channel"))
            if channel is None:
                return
            await channel.send(content, allowed_mentions=discord.AllowedMentions.none())
        except Exception:
            log.warning("Could not publish Honeypot operational alert", exc_info=True)

    async def _record_operational_failure(
        self,
        guild_id: int,
        source: str,
        summary: str,
        *,
        case_id: str | None = None,
        operation_id: str | None = None,
        attempts: int = 1,
        terminal: bool = False,
    ) -> None:
        try:
            failure = await asyncio.to_thread(
                self._case_store.record_operational_failure,
                guild_id=guild_id,
                source=source,
                summary=summary,
                occurred_at=datetime.now(timezone.utc),
                case_id=case_id,
                operation_id=operation_id,
            )
        except Exception:
            log.exception("Could not persist Honeypot operational failure")
            return
        exhausted_fast_retries = (
            terminal and attempts == DETECTION_FAST_RETRY_LIMIT + 1
        )
        if failure.occurrences == 1 or exhausted_fast_retries:
            state = "fast retries exhausted" if exhausted_fast_retries else "will retry"
            await self._send_operational_alert(
                guild_id,
                f"⚠️ Honeypot operation failed ({source}, attempt {attempts}, {state}): "
                f"{summary[:500]}",
            )

    async def _run_detection_reconciliation(
        self, *, now: datetime | None = None
    ) -> None:
        try:
            await self._retry_detection_orphan_publications()
        except Exception:
            log.warning("Detection orphan publication retry failed", exc_info=True)
        try:
            await self._retry_detection_case_deletions()
        except Exception:
            log.warning("Detection case deletion retry failed", exc_info=True)
        current_time = now or datetime.now(timezone.utc)
        stale_before = current_time - timedelta(minutes=5)
        await asyncio.to_thread(
            self._case_store.reconcile_moderator_actions, current_time
        )
        operations = await asyncio.to_thread(
            self._case_store.claim_due_operations,
            current_time,
            50,
            stale_before,
        )
        for operation in operations:
            await self._execute_detection_case_operation(operation, current_time)
        cases = await asyncio.to_thread(
            self._case_store.list_reconcilable_cases, current_time, stale_before
        )
        for case in cases:
            await self.resolve_detection_case(
                case.case_id, "expired", now=current_time
            )

    async def resolve_detection_case(
        self,
        case_id: str,
        resolution: str,
        moderator_id: int | None = None,
        *,
        now: datetime | None = None,
    ) -> bool:
        resolved_at = now or datetime.now(timezone.utc)
        lease = await asyncio.to_thread(
            self._case_store.claim_resolution,
            case_id,
            resolved_at,
            resolved_at - timedelta(minutes=5),
            require_terminal_captures=resolution == "ignore",
        )
        if lease is None:
            return False
        try:
            status = CaseStatus.EXPIRED if resolution == "expired" else CaseStatus.RESOLVED
            decision = {
                "tp": "true_positive",
                "fp": "false_positive",
                "ignore": "ignored",
            }.get(resolution.removeprefix("images:"))
            snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
            decisions = (
                {item.key: decision for item in case_feedback_items(snapshot)}
                if snapshot is not None and decision is not None
                else None
            )
            owned_role_ids = await asyncio.to_thread(
                self._case_store.owned_role_ids, case_id
            )
            final_operations = [
                ("review_update", f"review-update:{case_id}"),
                ("evidence_cleanup", f"evidence-cleanup:{case_id}"),
            ]
            for role_id in owned_role_ids:
                final_operations.append(
                    ("role_release", f"role-release:{case_id}:{int(role_id)}")
                )
            finished = await asyncio.to_thread(
                self._case_store.finish_resolution,
                lease,
                status,
                resolution,
                moderator_id,
                resolved_at,
                decisions,
                tuple(final_operations),
            )
        except BaseException:
            await asyncio.to_thread(self._case_store.release_resolution, lease)
            raise
        if not finished:
            return False
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        guild = self.bot.get_guild(snapshot.case.guild_id)
        if guild is not None and resolution == "expired":
            await self._increment_stat(guild, "review_expired")
        elif guild is not None and resolution == "ignore":
            await self._increment_stat(guild, "ignored")
        final_operation_priority = {
            "review_update": 0,
            "role_release": 1,
            "evidence_cleanup": 2,
        }
        for operation in sorted(
            snapshot.operations,
            key=lambda item: (
                final_operation_priority.get(item.operation_type, 99),
                item.operation_id,
            ),
        ):
            if operation.operation_type not in {
                "review_update", "role_release", "evidence_cleanup"
            }:
                continue
            claimed = await asyncio.to_thread(
                self._case_store.claim_operation, operation.operation_id, resolved_at
            )
            if claimed is not None:
                await self._execute_detection_case_operation(claimed, resolved_at)
        return True

    async def _execute_detection_message_child(
        self,
        snapshot,
        operation_type: str,
        sequence: int,
        now: datetime,
        *,
        publication_channel=None,
    ) -> bool:
        operation = next(
            (
                item
                for item in snapshot.operations
                if item.operation_type == operation_type
                and item.message_sequence == sequence
            ),
            None,
        )
        if operation is None:
            return False
        claim_time = now
        if operation.status.value == "failed" and operation.retry_at is not None:
            claim_time = max(claim_time, operation.retry_at)
        claimed = await asyncio.to_thread(
            self._case_store.claim_operation, operation.operation_id, claim_time
        )
        if claimed is not None:
            await self._execute_detection_case_operation(
                claimed,
                claim_time,
                publication_channel=publication_channel,
            )
            return True
        return False

    async def _release_detection_case_roles(
        self, case_id: str, now: datetime
    ) -> None:
        role_ids = await asyncio.to_thread(self._case_store.owned_role_ids, case_id)
        for role_id in role_ids:
            operation = await asyncio.to_thread(
                self._case_store.ensure_operation,
                case_id,
                "role_release",
                f"role-release:{case_id}:{int(role_id)}",
            )
            claimed = await asyncio.to_thread(
                self._case_store.claim_operation, operation.operation_id, now
            )
            if claimed is not None:
                await self._execute_detection_case_operation(claimed, now)

    @staticmethod
    def _persisted_capture_results(snapshot, sequence: int):
        terminal_statuses = {
            status.value for status in detection_runtime.CaptureStatus
        }
        return tuple(
            detection_runtime.CaptureResult(
                attachment.position,
                detection_runtime.CaptureStatus(attachment.capture_status),
                Path(attachment.evidence_path)
                if attachment.evidence_path is not None
                else None,
                attachment.error,
            )
            for attachment in snapshot.attachments
            if attachment.message_sequence == sequence
            and attachment.capture_status in terminal_statuses
        )

    async def _execute_detection_message_process(
        self,
        operation,
        snapshot,
        now: datetime,
        *,
        live_message=None,
        publication_channel=None,
        timings: dict[str, float] | None = None,
    ) -> str:
        timings = timings if timings is not None else {}
        source = next(
            (
                message
                for message in snapshot.messages
                if message.sequence == operation.message_sequence
            ),
            None,
        )
        if source is None:
            raise RuntimeError("detection case source message is unavailable")
        signals = tuple(
            item.signal
            for item in snapshot.signals
            if item.message_sequence == source.sequence
        )
        containment_required = any(
            signal.action != ActionIntent.NONE
            or (
                signal.detector == "honeypot"
                and not signal.metadata.get("whitelist_bypass")
            )
            or signal.metadata.get("containment_required")
            for signal in signals
        )
        has_forward_purge_signal = any(
            signal.detector == "forward_purge" for signal in signals
        )
        action = effective_action(signals)
        config = await self.config.guild_from_id(snapshot.case.guild_id).all()
        guild = (
            live_message.guild
            if live_message is not None
            else self.bot.get_guild(snapshot.case.guild_id)
        )
        if guild is None:
            raise RuntimeError("detection case guild is unavailable")
        direct_message = live_message is not None
        channel = None
        if live_message is None:
            channel = await self._fetch_message_channel(guild, source.channel_id)
        if channel is not None:
            fetch_message = getattr(channel, "fetch_message", None)
            if callable(fetch_message):
                try:
                    live_message = await fetch_message(source.message_id)
                except discord.NotFound:
                    live_message = None

        persisted = self._persisted_capture_results(snapshot, source.sequence)
        message_attachments = tuple(
            attachment
            for attachment in snapshot.attachments
            if attachment.message_sequence == source.sequence
        )
        evidence_started = perf_counter()
        capture_started = asyncio.Event()
        if live_message is not None and len(persisted) < len(message_attachments):
            capture_task = asyncio.create_task(
                self._capture_case_attachments(
                    live_message,
                    operation.case_id,
                    source.sequence,
                    started_event=capture_started,
                )
            )
        else:
            capture_started.set()
            capture_task = asyncio.create_task(asyncio.sleep(0, result=persisted))

        try:
            containment_started = perf_counter()
            if message_attachments and not persisted:
                try:
                    await asyncio.wait_for(
                        capture_started.wait(),
                        timeout=DETECTION_CAPTURE_START_TIMEOUT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    await asyncio.to_thread(
                        self._case_store.fail_pending_attachment_captures,
                        operation.case_id,
                        source.sequence,
                        "attachment capture could not start before containment",
                    )
                    capture_task.cancel()
                    await asyncio.gather(capture_task, return_exceptions=True)
                    refreshed = await asyncio.to_thread(
                        self._case_store.get_case, operation.case_id
                    )
                    persisted = self._persisted_capture_results(
                        refreshed, source.sequence
                    )
                    capture_task = asyncio.create_task(
                        asyncio.sleep(0, result=persisted)
                    )
            delete_result = detection_runtime.DeleteResult(
                source.delete_status, 0, source.error
            )
            if source.delete_status is DeleteStatus.PENDING and containment_required:
                if config.get("dry_run"):
                    delete_result = detection_runtime.DeleteResult(
                        DeleteStatus.PLANNED, 0, None
                    )
                elif live_message is None:
                    delete_result = detection_runtime.DeleteResult(
                        DeleteStatus.ALREADY_GONE, 1, None
                    )
                else:
                    delete_result = await detection_runtime.delete_message(live_message)
                needs_attention = delete_result.status in {
                    DeleteStatus.FORBIDDEN,
                    DeleteStatus.TRANSIENT_FAILURE,
                }
                await asyncio.to_thread(
                    self._case_store.update_message_delete,
                    operation.case_id,
                    source.sequence,
                    delete_result.status,
                    delete_result.error,
                    needs_attention,
                )
                if needs_attention:
                    retry = await asyncio.to_thread(
                        self._case_store.ensure_operation,
                        operation.case_id,
                        "source_delete",
                        (
                            f"source-delete:{operation.case_id}:"
                            f"{source.channel_id}:{source.message_id}"
                        ),
                        source.sequence,
                    )
                    claimed_retry = await asyncio.to_thread(
                        self._case_store.claim_operation,
                        retry.operation_id,
                        now,
                    )
                    if claimed_retry is not None:
                        failed_retry = await asyncio.to_thread(
                            self._case_store.fail_operation,
                            claimed_retry.operation_id,
                            claimed_retry.claim_token,
                            delete_result.error or delete_result.status.value,
                            now,
                            now + timedelta(seconds=DETECTION_FAST_RETRY_SECONDS),
                            delete_result.status.value,
                        )
                        if failed_retry:
                            await self._record_operational_failure(
                                snapshot.case.guild_id,
                                "source_delete",
                                delete_result.error or delete_result.status.value,
                                case_id=operation.case_id,
                                operation_id=claimed_retry.operation_id,
                                attempts=claimed_retry.attempts,
                            )
                if direct_message:
                    if delete_result.status is DeleteStatus.DELETED:
                        await self._increment_stat(guild, "purged_messages")
                        if has_forward_purge_signal:
                            await self._increment_stat(guild, "forward_purge_deletes")
                    elif delete_result.status is DeleteStatus.FORBIDDEN:
                        await self._increment_stat(guild, "delete_forbidden")
                        if has_forward_purge_signal:
                            await self._increment_stat(
                                guild, "forward_purge_delete_failures"
                            )
                    elif delete_result.status is DeleteStatus.TRANSIENT_FAILURE:
                        await self._increment_stat(guild, "delete_transient_failures")
                        if has_forward_purge_signal:
                            await self._increment_stat(
                                guild, "forward_purge_delete_failures"
                            )
            if containment_required and live_message is not None:
                deleted = await self._purge_detection_case_cached_messages(
                    guild,
                    snapshot.case.user_id,
                    config,
                    operation.case_id,
                    source.sequence,
                    exclude_message_id=source.message_id,
                )
                if deleted:
                    await self._increment_stat(guild, "purged_messages", deleted)
                    await self._increment_stat(guild, "cached_purge_deletes", deleted)

            refreshed = await asyncio.to_thread(
                self._case_store.get_case, operation.case_id
            )
            if refreshed is None:
                return "case_deleted"
            if action in {ActionIntent.KICK, ActionIntent.BAN}:
                await self._execute_detection_message_child(
                    refreshed, "moderation_action", source.sequence, now
                )
            elif action is ActionIntent.REVIEW:
                await self._execute_detection_message_child(
                    refreshed, "role_apply", source.sequence, now
                )
            timings["containment_ms"] = (
                perf_counter() - containment_started
            ) * 1000

            first_publish_started = perf_counter()
            logs_channel = publication_channel or self._get_text_channel_or_thread(
                guild, config.get("logs_channel")
            )
            review_publication = next(
                (
                    item
                    for item in refreshed.operations
                    if item.operation_type == "review_publish"
                    and item.message_sequence == source.sequence
                ),
                None,
            )
            has_review_publication = review_publication is not None
            preview_published = False
            if has_review_publication:
                try:
                    preview_published = await self._publish_detection_case(
                        operation.case_id,
                        config,
                        logs_channel,
                        message_sequence=source.sequence,
                        skip_if_done=capture_task,
                    )
                except Exception as error:
                    await self._record_operational_failure(
                        snapshot.case.guild_id,
                        "review_publish",
                        f"{type(error).__name__}: {error}",
                        case_id=operation.case_id,
                        operation_id=review_publication.operation_id,
                    )
                    log.warning(
                        "Detection case preview publication failed case=%s "
                        "message=%s error=%s",
                        operation.case_id,
                        source.sequence,
                        error,
                    )
            timings["first_publish_ms"] = (
                perf_counter() - first_publish_started
            ) * 1000

            evidence_wait_started = perf_counter()
            await capture_task
            timings["evidence_wait_ms"] = (
                perf_counter() - evidence_wait_started
            ) * 1000
            timings["evidence_ms"] = (perf_counter() - evidence_started) * 1000
            refreshed = await asyncio.to_thread(
                self._case_store.get_case, operation.case_id
            )
            if refreshed is None:
                return "case_deleted"
            captures = self._persisted_capture_results(refreshed, source.sequence)
            if len(captures) < len(message_attachments):
                raise RuntimeError(
                    "attachment evidence is not terminal; retry after reservation expiry"
                )
            capture_failures = sum(
                capture.status
                in {
                    detection_runtime.CaptureStatus.FAILED,
                    detection_runtime.CaptureStatus.TIMEOUT,
                    detection_runtime.CaptureStatus.TOO_LARGE,
                }
                for capture in captures
            )
            if capture_failures:
                await self._increment_stat(
                    guild, "evidence_capture_failures", capture_failures
                )

            scan_started = perf_counter()
            if live_message is not None:
                await self._scan_all_case_message_images(
                    live_message,
                    config,
                    operation.case_id,
                    source.sequence,
                    captures,
                )
            else:
                attachments = tuple(
                    attachment
                    for attachment in refreshed.attachments
                    if attachment.message_sequence == source.sequence
                )
                await self._scan_case_message_images(
                    snapshot.case.guild_id,
                    attachments,
                    config,
                    operation.case_id,
                    source.sequence,
                    captures,
                )
            timings["scan_ms"] = (perf_counter() - scan_started) * 1000
            refreshed = await asyncio.to_thread(
                self._case_store.get_case, operation.case_id
            )
            refresh_started = perf_counter()
            review_executed = await self._execute_detection_message_child(
                refreshed,
                "review_publish",
                source.sequence,
                now,
                publication_channel=publication_channel,
            )
            if has_review_publication and not review_executed:
                await self._publish_detection_case(
                    operation.case_id,
                    config,
                    logs_channel,
                    message_sequence=source.sequence,
                )
            timings["refresh_ms"] = (perf_counter() - refresh_started) * 1000
            await asyncio.to_thread(
                self._case_store.reconcile_moderator_actions,
                datetime.now(timezone.utc),
            )
            return "processed"
        finally:
            if not capture_task.done():
                capture_task.cancel()
            await asyncio.gather(capture_task, return_exceptions=True)

    async def _execute_detection_case_operation(
        self,
        operation,
        now: datetime,
        *,
        publication_channel=None,
        live_message=None,
        timings: dict[str, float] | None = None,
    ) -> None:
        heartbeat = asyncio.create_task(self._renew_detection_operation(operation))
        operation_result = None
        role_was_added = False
        snapshot = None
        try:
            snapshot = await asyncio.to_thread(self._case_store.get_case, operation.case_id)
            if snapshot is None:
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)
                return
            if operation.operation_type == "message_process":
                if snapshot.case.status not in {
                    CaseStatus.PENDING,
                    CaseStatus.RESOLVING,
                }:
                    if operation.message_sequence is not None:
                        await asyncio.to_thread(
                            self._case_store.fail_pending_attachment_captures,
                            operation.case_id,
                            operation.message_sequence,
                            "case closed before attachment capture completed",
                        )
                    operation_result = "case_terminal"
                else:
                    operation_result = await self._execute_detection_message_process(
                        operation,
                        snapshot,
                        now,
                        live_message=live_message,
                        publication_channel=publication_channel,
                        timings=timings,
                    )
            elif (
                operation.operation_type == "role_apply"
                and snapshot.case.status is not CaseStatus.PENDING
            ):
                operation_result = "case_terminal"
            elif operation.operation_type == "review_update":
                await self._case_review_rerender(operation.case_id)
            elif operation.operation_type == "role_apply":
                guild = self.bot.get_guild(snapshot.case.guild_id)
                if guild is None:
                    raise RuntimeError("detection case guild is unavailable")
                role_id = int(operation.idempotency_key.rsplit(":", 1)[1])
                member = guild.get_member(snapshot.case.user_id)
                role = guild.get_role(role_id)
                if member is None:
                    raise RuntimeError("detection case member is unavailable")
                if role is None:
                    raise RuntimeError("detection case role is unavailable")
                effect_started = await asyncio.to_thread(
                    self._case_store.operation_effect_started, operation.operation_id
                )
                if role not in member.roles:
                    started = await asyncio.to_thread(
                        self._case_store.start_role_apply_effect,
                        operation.operation_id,
                        operation.claim_token,
                        datetime.now(timezone.utc),
                    )
                    if not started:
                        raise RuntimeError("detection operation lease was lost")
                    await member.add_roles(
                        role, reason="Detection case pending moderator review."
                    )
                    role_was_added = True
                    ownership_result = await asyncio.to_thread(
                        self._case_store.record_operation_role_ownership,
                        operation.operation_id,
                        operation.claim_token,
                        operation.case_id,
                        snapshot.case.guild_id,
                        snapshot.case.user_id,
                        role_id,
                        datetime.now(timezone.utc),
                    )
                    if ownership_result is None:
                        operation_result = "ambiguous_role_ownership"
                        await asyncio.to_thread(
                            self._case_store.mark_case_needs_attention,
                            operation.case_id,
                        )
                    elif ownership_result == "release_required":
                        terminal_snapshot = await asyncio.to_thread(
                            self._case_store.get_case, operation.case_id
                        )
                        release = next(
                            (
                                item
                                for item in terminal_snapshot.operations
                                if item.operation_type == "role_release"
                                and item.idempotency_key
                                == f"role-release:{operation.case_id}:{role_id}"
                            ),
                            None,
                        )
                        if release is not None:
                            claimed_release = await asyncio.to_thread(
                                self._case_store.claim_operation,
                                release.operation_id,
                                datetime.now(timezone.utc),
                            )
                            if claimed_release is not None:
                                await self._execute_detection_case_operation(
                                    claimed_release, datetime.now(timezone.utc)
                                )
                elif effect_started:
                    operation_result = "ambiguous_role_ownership"
                    await asyncio.to_thread(
                        self._case_store.mark_case_needs_attention,
                        operation.case_id,
                    )
                else:
                    owner_case_id = await asyncio.to_thread(
                        self._case_store.role_owner_case,
                        snapshot.case.guild_id,
                        snapshot.case.user_id,
                        role_id,
                    )
                    transferred = await asyncio.to_thread(
                        self._case_store.transfer_terminal_role_ownership,
                        operation.operation_id,
                        operation.claim_token,
                        operation.case_id,
                        snapshot.case.guild_id,
                        snapshot.case.user_id,
                        role_id,
                        datetime.now(timezone.utc),
                    )
                    if transferred:
                        operation_result = "transferred_role_ownership"
                    elif owner_case_id is not None and owner_case_id != operation.case_id:
                        raise RuntimeError(
                            "previous detection case role release is still in progress"
                        )
                    elif owner_case_id == operation.case_id:
                        operation_result = "role_already_owned"
                    else:
                        operation_result = "preexisting_role"
            elif operation.operation_type == "review_publish":
                config = await self.config.guild_from_id(snapshot.case.guild_id).all()
                guild = self.bot.get_guild(snapshot.case.guild_id)
                logs_channel = publication_channel or (
                    self._get_text_channel_or_thread(
                        guild, config.get("logs_channel")
                    )
                    if guild is not None
                    else None
                )
                await self._publish_detection_case(
                    operation.case_id,
                    config,
                    logs_channel,
                    message_sequence=operation.message_sequence,
                )
            elif operation.operation_type == "moderation_action":
                source = next(
                    (
                        message
                        for message in snapshot.messages
                        if message.sequence == operation.message_sequence
                    ),
                    None,
                )
                if source is None:
                    raise RuntimeError("detection case source message is unavailable")
                signals = tuple(
                    item.signal
                    for item in snapshot.signals
                    if item.message_sequence == source.sequence
                )
                action = effective_action(signals)
                if action not in (ActionIntent.KICK, ActionIntent.BAN):
                    raise RuntimeError(
                        "detection case moderation action is no longer applicable"
                    )
                config = await self.config.guild_from_id(snapshot.case.guild_id).all()
                if config.get("dry_run"):
                    operation_result = f"planned_{action.value}"
                else:
                    guild = self.bot.get_guild(snapshot.case.guild_id)
                    if guild is None:
                        raise RuntimeError("detection case guild is unavailable")
                    effect_started = await asyncio.to_thread(
                        self._case_store.operation_effect_started, operation.operation_id
                    )
                    effect_confirmed = False
                    if effect_started and action is ActionIntent.BAN:
                        target = guild.get_member(snapshot.case.user_id)
                        if target is None:
                            target = await self._get_user_or_object(snapshot.case.user_id)
                        try:
                            await guild.fetch_ban(target)
                        except discord.NotFound:
                            pass
                        else:
                            effect_confirmed = True
                    member = guild.get_member(snapshot.case.user_id)
                    if member is None and action is ActionIntent.BAN:
                        member = await self._get_user_or_object(snapshot.case.user_id)
                    if member is None and action is ActionIntent.KICK:
                        try:
                            member = await guild.fetch_member(snapshot.case.user_id)
                        except discord.NotFound:
                            operation_result = "kick_missing"
                            effect_confirmed = True
                    if not effect_confirmed:
                        if member is None:
                            raise RuntimeError("detection case member is unavailable")
                        public_reason = self._public_moderation_reason(signals, action)
                        started = await asyncio.to_thread(
                            self._case_store.start_operation_effect,
                            operation.operation_id,
                            operation.claim_token,
                            datetime.now(timezone.utc),
                        )
                        if not started:
                            raise RuntimeError("moderation action operation lease was lost")
                        _, failed = await self._execute_action(
                            guild,
                            member,
                            source.created_at,
                            config,
                            reason=public_reason,
                            action=action.value,
                        )
                        if failed is not None:
                            raise RuntimeError(failed)
                        operation_result = action.value
                    elif operation_result is None:
                        operation_result = action.value
            elif operation.operation_type == "cached_purge":
                guild = self.bot.get_guild(snapshot.case.guild_id)
                if guild is None:
                    raise RuntimeError("detection case guild is unavailable")
                _, case_id, channel_id, message_id = operation.idempotency_key.split(":")
                if case_id != operation.case_id:
                    raise RuntimeError("cached purge operation case identity does not match")
                channel = self._get_cached_message_channel(guild, int(channel_id))
                if channel is None:
                    operation_result = "channel_unavailable"
                    raise RuntimeError("cached purge channel is unavailable")
                get_partial_message = getattr(channel, "get_partial_message", None)
                if not callable(get_partial_message):
                    operation_result = "unsupported_channel"
                    raise RuntimeError("cached purge channel cannot resolve messages")
                result = await detection_runtime.delete_message(
                    get_partial_message(int(message_id))
                )
                operation_result = result.status.value
                if result.status not in (
                    DeleteStatus.DELETED,
                    DeleteStatus.ALREADY_GONE,
                ):
                    raise RuntimeError(result.error or result.status.value)
            elif operation.operation_type == "source_delete":
                guild = self.bot.get_guild(snapshot.case.guild_id)
                if guild is None:
                    raise RuntimeError("detection case guild is unavailable")
                _, case_id, channel_id, message_id = operation.idempotency_key.split(":")
                if case_id != operation.case_id:
                    raise RuntimeError("source delete operation case identity does not match")
                if operation.message_sequence is None:
                    raise RuntimeError("source delete operation has no message identity")
                channel = await self._fetch_message_channel(guild, int(channel_id))
                if channel is None:
                    result = detection_runtime.DeleteResult(
                        DeleteStatus.ALREADY_GONE, 1, None
                    )
                else:
                    try:
                        message = await channel.fetch_message(int(message_id))
                    except discord.NotFound:
                        result = detection_runtime.DeleteResult(
                            DeleteStatus.ALREADY_GONE, 1, None
                        )
                    else:
                        result = await detection_runtime.delete_message(message)
                operation_result = result.status.value
                if result.status not in {
                    DeleteStatus.DELETED,
                    DeleteStatus.ALREADY_GONE,
                }:
                    raise RuntimeError(result.error or result.status.value)
                completed_delete = await asyncio.to_thread(
                    self._case_store.complete_message_delete_retry,
                    operation.case_id,
                    operation.message_sequence,
                    result.status,
                )
                if completed_delete and result.status is DeleteStatus.DELETED:
                    await self._increment_stat(guild, "purged_messages")
                    source_signals = tuple(
                        item.signal
                        for item in snapshot.signals
                        if item.message_sequence == operation.message_sequence
                    )
                    if any(
                        signal.detector == "forward_purge"
                        for signal in source_signals
                    ):
                        await self._increment_stat(guild, "forward_purge_deletes")
            elif operation.operation_type in {"moderator_ban", "moderator_kick"}:
                action = operation.operation_type.removeprefix("moderator_")
                config = await self.config.guild_from_id(snapshot.case.guild_id).all()
                if config.get("dry_run"):
                    operation_result = f"planned_{action}"
                else:
                    guild = self.bot.get_guild(snapshot.case.guild_id)
                    if guild is None:
                        raise RuntimeError("detection case guild is unavailable")
                    effect_started = await asyncio.to_thread(
                        self._case_store.operation_effect_started, operation.operation_id
                    )
                    effect_confirmed = False
                    if effect_started and action == "ban":
                        target = guild.get_member(snapshot.case.user_id)
                        if target is None:
                            target = await self._get_user_or_object(snapshot.case.user_id)
                        try:
                            await guild.fetch_ban(target)
                        except discord.NotFound:
                            pass
                        else:
                            effect_confirmed = True
                    if not effect_confirmed:
                        member = guild.get_member(snapshot.case.user_id)
                        if member is None and action == "ban":
                            member = await self._get_user_or_object(snapshot.case.user_id)
                        if member is None and action == "kick":
                            try:
                                member = await guild.fetch_member(snapshot.case.user_id)
                            except discord.NotFound:
                                operation_result = "kick_missing"
                                effect_confirmed = True
                    if not effect_confirmed:
                        if member is None:
                            raise RuntimeError("detection case member is unavailable")
                        moderator = guild.get_member(operation.actor_id)
                        if moderator is None:
                            moderator = await self._get_user_or_object(operation.actor_id)
                        effect_started_at = datetime.now(timezone.utc)
                        started = await asyncio.to_thread(
                            self._case_store.start_operation_effect,
                            operation.operation_id,
                            operation.claim_token,
                            effect_started_at,
                        )
                        if not started:
                            raise RuntimeError("moderator action operation lease was lost")
                        _, failed = await self._execute_action(
                            guild,
                            member,
                            effect_started_at,
                            config,
                            reason=f"Honeypot review: {action.title()}",
                            action=action,
                            moderator=moderator,
                        )
                        if failed is not None:
                            raise RuntimeError(failed)
                    if operation_result is None:
                        operation_result = action
            elif operation.operation_type == "role_release":
                guild = self.bot.get_guild(snapshot.case.guild_id)
                if guild is None:
                    raise RuntimeError("detection case guild is unavailable")
                role_id = int(operation.idempotency_key.rsplit(":", 1)[1])
                owned_role_ids = await asyncio.to_thread(
                    self._case_store.owned_role_ids, operation.case_id
                )
                if role_id not in owned_role_ids:
                    operation_result = "ownership_transferred"
                else:
                    started = await asyncio.to_thread(
                        self._case_store.start_role_release_effect,
                        operation.operation_id,
                        operation.claim_token,
                        operation.case_id,
                        role_id,
                        datetime.now(timezone.utc),
                    )
                    if not started:
                        owner_case_id = await asyncio.to_thread(
                            self._case_store.role_owner_case,
                            snapshot.case.guild_id,
                            snapshot.case.user_id,
                            role_id,
                        )
                        if owner_case_id != operation.case_id:
                            operation_result = "ownership_transferred"
                        else:
                            raise RuntimeError("detection operation lease was lost")
                    if operation_result != "ownership_transferred":
                        role = guild.get_role(role_id)
                        member = None
                        if role is not None:
                            member = guild.get_member(snapshot.case.user_id)
                            if member is None:
                                fetch_member = getattr(guild, "fetch_member", None)
                                if not callable(fetch_member):
                                    raise RuntimeError(
                                        "detection case member lookup is unavailable"
                                    )
                                try:
                                    member = await fetch_member(snapshot.case.user_id)
                                except discord.NotFound:
                                    member = None
                                except discord.HTTPException as error:
                                    raise RuntimeError(
                                        "detection case member lookup failed"
                                    ) from error
                        if member is not None and role in member.roles:
                            removed = await self._remove_review_mute_role(
                                member,
                                role,
                                "Detection case resolved; removing pending mute.",
                            )
                            if not removed:
                                raise RuntimeError("failed to release detection case role")
                        await asyncio.to_thread(
                            self._case_store.release_role_ownership,
                            operation.case_id,
                            role_id,
                        )
            elif operation.operation_type == "evidence_cleanup":
                review_update = next(
                    (
                        item
                        for item in snapshot.operations
                        if item.operation_type == "review_update"
                    ),
                    None,
                )
                if (
                    snapshot.case.review_message_id is not None
                    and review_update is not None
                    and review_update.status.value != "succeeded"
                ):
                    raise RuntimeError(
                        "terminal review projection is not complete"
                    )
                case_root = case_evidence_root(
                    self._detection_case_files_path,
                    snapshot.case.guild_id,
                    operation.case_id,
                ).resolve()
                evidence_root = self._detection_case_files_path.resolve()
                if not case_root.is_relative_to(evidence_root):
                    raise RuntimeError("detection case evidence path escapes storage root")
                for attachment in snapshot.attachments:
                    if attachment.evidence_path is None:
                        continue
                    path = Path(attachment.evidence_path).resolve()
                    if not path.is_relative_to(case_root):
                        raise RuntimeError("detection case evidence path escapes case root")
                for attachment in snapshot.attachments:
                    if (
                        attachment.evidence_path is None
                        or not is_persisted_image_attachment(attachment)
                        or attachment.learning_decision
                        not in {"true_positive", "false_positive"}
                    ):
                        continue
                    evidence_path = Path(attachment.evidence_path)
                    if not evidence_path.exists():
                        continue
                    result, _sample = await self._imagescan_add_file_sample(
                        snapshot.case.guild_id,
                        evidence_path,
                        attachment.learning_decision,
                        snapshot.case.moderator_id,
                    )
                    if result not in {"inserted", "duplicate"}:
                        raise RuntimeError(
                            f"failed to copy detection evidence into learning samples: {result}"
                        )
                if case_root.exists():
                    for path in sorted(case_root.rglob("*"), reverse=True):
                        resolved = path.resolve()
                        if not resolved.is_relative_to(case_root):
                            raise RuntimeError(
                                "detection case evidence path escapes case root"
                            )
                        if path.is_dir():
                            path.rmdir()
                        else:
                            path.unlink(missing_ok=True)
                if case_root.exists():
                    case_root.rmdir()
            else:
                raise RuntimeError(
                    f"unsupported detection case operation: {operation.operation_type}"
                )
        except asyncio.CancelledError:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)
            raise
        except Exception as error:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)
            retry_at = now + (
                timedelta(seconds=DETECTION_FAST_RETRY_SECONDS)
                if operation.attempts <= DETECTION_FAST_RETRY_LIMIT
                else timedelta(minutes=DETECTION_SLOW_RETRY_MINUTES)
            )
            if operation.operation_type == "source_delete":
                retry_at = now + timedelta(seconds=DETECTION_FAST_RETRY_SECONDS)
            cached_purge_exhausted = (
                operation.operation_type == "cached_purge"
                and operation_result == DeleteStatus.TRANSIENT_FAILURE.value
                and operation.attempts >= 3
            )
            if operation.operation_type == "cached_purge" and (
                operation_result == DeleteStatus.FORBIDDEN.value
                or operation_result == "channel_unavailable"
                or operation_result == "unsupported_channel"
                or cached_purge_exhausted
            ):
                retry_at = None
                await asyncio.to_thread(
                    self._case_store.mark_case_needs_attention, operation.case_id
                )
            failure = await asyncio.to_thread(
                self._case_store.fail_operation,
                operation.operation_id,
                operation.claim_token,
                f"{type(error).__name__}: {error}",
                now,
                retry_at,
                operation_result,
            )
            if failure and snapshot is not None:
                await self._record_operational_failure(
                    snapshot.case.guild_id,
                    operation.operation_type,
                    f"{type(error).__name__}: {error}",
                    case_id=operation.case_id,
                    operation_id=operation.operation_id,
                    attempts=operation.attempts,
                    terminal=(
                        retry_at is None
                        or operation.attempts > DETECTION_FAST_RETRY_LIMIT
                    ),
                )
            if operation.operation_type == "role_apply" and snapshot is not None:
                failed_guild = self.bot.get_guild(snapshot.case.guild_id)
                if failed_guild is not None:
                    await self._increment_stat(
                        failed_guild, "pending_mute_failures"
                    )
            log.warning(
                "Detection case operation failed case=%s operation=%s kind=%s error=%s",
                operation.case_id,
                operation.operation_id,
                operation.operation_type,
                error,
            )
            return
        heartbeat.cancel()
        await asyncio.gather(heartbeat, return_exceptions=True)
        if operation.operation_type in {"moderator_ban", "moderator_kick"}:
            completed = await asyncio.to_thread(
                self._case_store.complete_moderator_action,
                operation.operation_id,
                operation.claim_token,
                now,
                operation_result,
            )
        else:
            completed = await asyncio.to_thread(
                self._case_store.complete_operation,
                operation.operation_id,
                operation.claim_token,
                now,
                operation_result,
            )
        if not completed:
            current_case = await asyncio.to_thread(
                self._case_store.get_case, operation.case_id
            )
            if current_case is not None:
                raise RuntimeError(
                    "detection case operation lease was lost before completion"
                )
        elif snapshot is not None and (
            operation.attempts > 1
            or operation.operation_type == "review_publish"
        ):
            recovered = await asyncio.to_thread(
                self._case_store.resolve_operational_failure,
                operation.operation_id,
                now,
            )
            if recovered and operation.attempts > 1:
                await self._send_operational_alert(
                    snapshot.case.guild_id,
                    f"✅ Recovered: {operation.operation_type} succeeded after "
                    f"{operation.attempts} attempts.",
                )
        elif role_was_added and snapshot is not None:
            guild = self.bot.get_guild(snapshot.case.guild_id)
            if guild is not None:
                await self._increment_stat(guild, "pending_mutes")
        if operation.operation_type in {
            "review_update",
            "role_release",
            "evidence_cleanup",
        }:
            await asyncio.to_thread(
                self._case_store.compact_terminal_case, operation.case_id
            )
        elif completed and operation.operation_type in {
            "moderation_action",
            "moderator_ban",
            "moderator_kick",
        }:
            await self._finish_case_review_if_ready(
                operation.case_id,
                operation.actor_id,
            )
            await self._case_review_rerender_safely(operation.case_id)
        elif completed and operation.operation_type == "message_process":
            await self._finish_case_review_if_ready(operation.case_id, None)

    async def _renew_detection_operation(self, operation) -> None:
        while True:
            await asyncio.sleep(self._detection_heartbeat_interval_seconds)
            renewed = await asyncio.to_thread(
                self._case_store.renew_operation_claim,
                operation.operation_id,
                operation.claim_token,
                datetime.now(timezone.utc),
            )
            if not renewed:
                return

    async def _restore_detection_case_views(self) -> None:
        await self.bot.wait_until_red_ready()
        snapshots = await asyncio.to_thread(self._case_store.list_open_cases)
        for snapshot in snapshots:
            message_id = snapshot.case.review_message_id
            if message_id is None:
                continue
            projection = render_case(snapshot)
            pending_feedback = self._pending_feedback_items(
                projection.feedback_items
            )
            view = DetectionCaseView(
                self,
                snapshot.case.case_id,
                has_image_feedback=bool(pending_feedback),
                feedback_items=pending_feedback,
                moderation_actions=projection.moderation_actions,
            )
            self._case_views[snapshot.case.case_id] = view
            self.bot.add_view(view, message_id=message_id)
            await self._case_review_rerender(snapshot.case.case_id)





    # ─── Detection ────────────────────────────────────────────────────────

    def _forward_purge_signal(self, message: discord.Message) -> DetectionSignal | None:
        if not self._is_forward_purge_active(message.guild.id, message.author.id):
            return None
        return DetectionSignal(
            detector="forward_purge",
            reason="Active forward-purge containment window",
            action=ActionIntent.REVIEW,
            decisive=True,
            metadata={"containment_required": True},
        )

    @staticmethod
    def _signal_action(value: object, valid_actions: tuple[str, ...]) -> ActionIntent:
        action = value if value in valid_actions else "review"
        return ActionIntent(typing.cast(str, action))

    def _spam_signal(self, message: discord.Message, config: dict) -> DetectionSignal | None:
        if not config.get("spam_enabled", False):
            return None
        reasons = self._spam_suspicion_reasons(message, config)
        if not reasons:
            return None
        return DetectionSignal(
            detector="spam",
            reason="\n".join(reasons),
            action=self._signal_action(config.get("spam_action", "review"), CORE_ACTION_OPTIONS),
            decisive=True,
            metadata={"reasons": tuple(reasons)},
        )

    async def _firstpost_signal(
        self, message: discord.Message, config: dict
    ) -> DetectionSignal | None:
        firstpost_enabled = config.get("firstpost_enabled", False)
        collect_enabled = config.get("firstpost_collect_enabled", False)
        if not firstpost_enabled and not collect_enabled:
            return None
        await self._ensure_firstpost_seen_loaded(message.guild.id)
        if message.author.id in self._firstpost_seen_authors[message.guild.id]:
            return None
        if not firstpost_enabled:
            return None
        reasons = self._firstpost_suspicion_reasons(message, config)
        if not reasons:
            return None
        return DetectionSignal(
            detector="firstpost",
            reason="\n".join(reasons),
            action=self._signal_action(config.get("firstpost_action", "review"), CORE_ACTION_OPTIONS),
            decisive=True,
            metadata={"reasons": tuple(reasons)},
        )

    def _firstpost_candidate(
        self, message: discord.Message, config: dict
    ) -> DetectionSignal | None:
        if not config.get("firstpost_enabled", False):
            return None
        reasons = self._firstpost_suspicion_reasons(message, config)
        if not reasons:
            return None
        return DetectionSignal(
            detector="firstpost",
            reason="\n".join(reasons),
            action=self._signal_action(
                config.get("firstpost_action", "review"), CORE_ACTION_OPTIONS
            ),
            decisive=True,
            metadata={"reasons": tuple(reasons)},
        )


    async def _honeypot_signals(
        self,
        message: discord.Message,
        config: dict,
        *,
        image_evidence: DetectionSignal | None = None,
    ) -> tuple[DetectionSignal, ...]:
        if message.channel.id not in self._honeypot_channel_ids_from_config(config):
            return ()
        whitelisted_role_ids = set(config.get("whitelisted_roles", ()))
        has_whitelist_role = any(
            role.id in whitelisted_role_ids for role in message.author.roles
        )
        whitelist_mode = config.get("whitelist_mode", "bypass") if has_whitelist_role else None
        if whitelist_mode == "bypass":
            return (
                DetectionSignal(
                    detector="honeypot",
                    reason="Message posted in a configured honeypot channel",
                    action=ActionIntent.NONE,
                    decisive=True,
                    metadata={"whitelist_bypass": True},
                ),
            )
        reasons = await self._suspicion_reasons(message, config)
        if image_evidence is not None:
            reasons.append(_("Known suspicious image match"))
        second_strike_role_ids = {
            role_id
            for role_id in (config.get("mute_role"), config.get("joinwatch_auto_role_id"))
            if role_id
        }
        second_strike = bool(second_strike_role_ids) and any(
            role.id in second_strike_role_ids for role in message.author.roles
        )
        if second_strike:
            reasons.append(_("Repeat honeypot activity"))
        force_review = whitelist_mode == "review"
        force_fallback = whitelist_mode == "fallback"
        if second_strike and not force_review and not force_fallback:
            action = ActionIntent.BAN
        elif force_review:
            action = ActionIntent.REVIEW
        elif force_fallback or not reasons:
            action = self._signal_action(
                config.get("fallback_action", "review"), FALLBACK_ACTION_OPTIONS
            )
        else:
            action = self._signal_action(config.get("action", "review"), CORE_ACTION_OPTIONS)
        return (
            DetectionSignal(
                detector="honeypot",
                reason="\n".join(reasons) if reasons else "Message posted in a configured honeypot channel",
                action=action,
                decisive=True,
                metadata={
                    "reasons": tuple(reasons),
                    "second_strike": second_strike,
                    "force_review": force_review,
                    "force_fallback": force_fallback,
                },
            ),
        )

    async def _initial_image_signal(
        self,
        message: discord.Message,
        config: dict,
        *,
        action_override: ActionIntent | None = None,
    ) -> DetectionSignal | None:
        if not config.get("imagescan_detector_enabled", False):
            return None
        image_count = sum(
            1 for attachment in message.attachments if is_image_attachment(attachment)
        )
        if not image_count:
            return None
        decision_started = perf_counter()
        profile = {
            "messages_scanned": 1,
            "messages_with_images": 1,
            "images_considered": min(image_count, IMAGE_SCAN_MAX_ATTACHMENTS),
            "images_ignored_over_limit": max(
                0, image_count - IMAGE_SCAN_MAX_ATTACHMENTS
            ),
        }
        samples = await self._imagescan_load_samples(message.guild.id)
        if not any(sample.decision == "true_positive" for sample in samples):
            await self._imagescan_increment_profile(message.guild.id, profile)
            return None
        state = await self._imagescan_model_state(
            message.guild.id, int(config.get("imagescan_detector_threshold", 20))
        )
        if not state["valid"]:
            await self._imagescan_increment_profile(message.guild.id, profile)
            return None
        matches: list[dict[str, object]] = []
        scans = await self._scan_image_attachments(
            message,
            samples,
            int(state["effective_threshold"]),
            limit=IMAGE_SCAN_MAX_ATTACHMENTS,
            stop_after_match=True,
            batch_key=(message.guild.id, message.id),
        )
        successful_scans = [scan for scan in scans if scan["error"] is None]
        for stage in ("download", "hash", "compare"):
            profile[f"{stage}_ms_total"] = sum(
                int(scan[f"{stage}_ms"]) for scan in successful_scans
            )
            profile[f"{stage}_ms_count"] = len(successful_scans)
        profile["decision_ms_total"] = int(
            (perf_counter() - decision_started) * 1000
        )
        profile["decision_ms_count"] = 1
        for scan in scans:
            if scan["error"] is not None:
                log.debug(
                    "Failed to scan initial imagescan attachment %s",
                    scan["attachment"].filename,
                )
                continue
            result = scan["result"]
            if not result["matched"]:
                continue
            matches.append(
                {
                    "position": scan["image_position"],
                    "filename": scan["attachment"].filename,
                    "hash_diff": result.get("score"),
                    "threshold": result.get("threshold"),
                    "exact_decision": result.get("exact_decision"),
                }
            )
            if result.get("exact_decision") == "true_positive":
                profile["exact_tp_hits"] = profile.get("exact_tp_hits", 0) + 1
            else:
                profile["flagged_tp_hits"] = profile.get("flagged_tp_hits", 0) + 1
        await self._imagescan_increment_profile(message.guild.id, profile)
        if not matches:
            self._initial_image_scan_batches.pop((message.guild.id, message.id), None)
            return None
        return DetectionSignal(
            detector="image",
            reason="Initial image scan matched known suspicious content",
            action=(
                action_override
                if action_override is not None
                else self._signal_action(
                    config.get("imagescan_detector_action", "review"),
                    IMAGE_SCAN_DETECTOR_ACTION_OPTIONS,
                )
            ),
            decisive=True,
            metadata={"matches": tuple(matches)},
        )

    async def _collect_detection_signals(
        self, message: discord.Message, config: dict
    ) -> tuple[DetectionSignal, ...]:
        forward = self._forward_purge_signal(message)
        signals: list[DetectionSignal] = []
        if forward is not None:
            signals.append(forward)
        in_honeypot = (
            message.channel.id in self._honeypot_channel_ids_from_config(config)
        )
        if in_honeypot:
            image = None
            if not any(signal.decisive for signal in signals):
                image = await self._initial_image_signal(
                    message,
                    config,
                    action_override=ActionIntent.NONE,
                )
            signals.extend(
                await self._honeypot_signals(
                    message,
                    config,
                    image_evidence=image,
                )
            )
            if image is not None:
                signals.append(image)
        else:
            spam = self._spam_signal(message, config)
            if spam is not None:
                signals.append(spam)
            firstpost = await self._firstpost_signal(message, config)
            if firstpost is not None:
                signals.append(firstpost)
            if not any(signal.decisive for signal in signals):
                image = await self._initial_image_signal(message, config)
                if image is not None:
                    signals.append(image)
        return tuple(signals)

    @staticmethod
    def _public_moderation_reason(
        signals: tuple[DetectionSignal, ...], action: ActionIntent
    ) -> str:
        owning_signal = next(
            (signal for signal in signals if signal.action is action),
            next((signal for signal in signals if signal.decisive), None),
        )
        if owning_signal is None:
            return "Honeypot"
        if owning_signal.detector == "spam":
            return "Same message in multiple channels"
        if owning_signal.detector == "firstpost":
            return "Suspicious first observed message."
        if owning_signal.detector == "image":
            return "Honeypot"
        if owning_signal.detector == "honeypot":
            if owning_signal.metadata.get("review_fallback"):
                return "Message in the honeypot channel without a matching scam pattern."
            if owning_signal.metadata.get("second_strike"):
                return "Suspicious Activity"
            if owning_signal.metadata.get("reasons") and not owning_signal.metadata.get(
                "force_fallback"
            ):
                return "Suspicious message in the honeypot channel."
            return "Message in the honeypot channel without a matching scam pattern."
        return "Honeypot"

    @classmethod
    def _resolve_unavailable_review_signals(
        cls, config: dict, signals: tuple[DetectionSignal, ...]
    ) -> tuple[DetectionSignal, ...]:
        review_available = bool(
            config.get("review_enabled", True)
            and (
                config.get("review_channel") is not None
                or config.get("logs_channel") is not None
            )
        )
        if review_available:
            return signals
        fallback = cls._signal_action(
            config.get("fallback_action", "review"), FALLBACK_ACTION_OPTIONS
        )
        if fallback is ActionIntent.REVIEW:
            fallback = ActionIntent.NONE
        return tuple(
            DetectionSignal(
                signal.detector,
                signal.reason,
                (
                    fallback
                    if signal.detector == "honeypot"
                    and signal.action is ActionIntent.REVIEW
                    and not signal.metadata.get("containment_required")
                    else signal.action
                ),
                signal.decisive,
                (
                    {**signal.metadata, "review_fallback": True}
                    if signal.detector == "honeypot"
                    and signal.action is ActionIntent.REVIEW
                    else signal.metadata
                ),
            )
            for signal in signals
        )

    @staticmethod
    def _new_case_message(message: discord.Message) -> NewMessage:
        return NewMessage(
            guild_id=message.guild.id,
            user_id=message.author.id,
            channel_id=message.channel.id,
            message_id=message.id,
            content=message.content,
            created_at=message.created_at,
            jump_url=getattr(message, "jump_url", None),
            attachments=tuple(
                NewAttachment(
                    position=position,
                    filename=attachment.filename,
                    size=attachment.size,
                    content_type=attachment.content_type,
                    width=getattr(attachment, "width", None),
                    height=getattr(attachment, "height", None),
                    url=attachment.url,
                    description=getattr(attachment, "description", None),
                    spoiler=attachment.is_spoiler(),
                )
                for position, attachment in enumerate(message.attachments)
            ),
            display_name=getattr(message.author, "display_name", None),
            avatar_url=(
                str(getattr(getattr(message.author, "display_avatar", None), "url"))
                if getattr(getattr(message.author, "display_avatar", None), "url", None)
                else None
            ),
            account_created_at=getattr(message.author, "created_at", None),
            guild_joined_at=getattr(message.author, "joined_at", None),
        )

    async def _capture_case_attachments(
        self,
        message: discord.Message,
        case_id: str,
        sequence: int,
        *,
        started_event: asyncio.Event | None = None,
    ) -> tuple[detection_runtime.CaptureResult, ...]:
        async with self._detection_case_evidence_lock:
            await self._detection_case_capture_slots.acquire()
        try:
            accepts_evidence = await asyncio.to_thread(
                self._case_store.case_accepts_evidence,
                message.guild.id,
                case_id,
            )
            if not accepts_evidence:
                return tuple(
                    detection_runtime.CaptureResult(
                        position,
                        detection_runtime.CaptureStatus.FAILED,
                        None,
                        "detection case deletion is in progress",
                    )
                    for position, _attachment in enumerate(message.attachments)
                )
            return await self._capture_case_attachments_unlocked(
                message,
                case_id,
                sequence,
                started_event=started_event,
                prefetched_scans=self._initial_image_scan_batches.get(
                    (message.guild.id, message.id), {}
                ),
            )
        finally:
            self._detection_case_capture_slots.release()

    async def _capture_case_attachments_unlocked(
        self,
        message: discord.Message,
        case_id: str,
        sequence: int,
        *,
        started_event: asyncio.Event | None = None,
        prefetched_scans: dict[int, asyncio.Task] | None = None,
    ) -> tuple[detection_runtime.CaptureResult, ...]:
        target = case_evidence_root(
            self._detection_case_files_path, message.guild.id, case_id
        ) / str(sequence) / f".attempt-{uuid4().hex}"
        if not message.attachments:
            if started_event is not None:
                started_event.set()
            return ()
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        if snapshot is None:
            return ()
        case_declared_bytes = sum(
            max(0, int(attachment.size)) for attachment in snapshot.attachments
        )
        tasks: dict[int, asyncio.Task] = {}
        claim_tokens: dict[int, str] = {}
        attachment_sizes: dict[int, int] = {}
        captures_by_position = {}
        for position, attachment in enumerate(message.attachments):
            size = max(0, int(getattr(attachment, "size", 0) or 0))
            attachment_sizes[position] = size
            claimed_at = datetime.now(timezone.utc)
            reservation = await asyncio.to_thread(
                self._case_store.reserve_attachment_capture,
                case_id,
                sequence,
                position,
                size,
                claimed_at,
                stale_before=claimed_at
                - timedelta(seconds=DETECTION_EVIDENCE_RESERVATION_STALE_SECONDS),
                max_attachment_bytes=size,
                max_case_bytes=case_declared_bytes,
            )
            if reservation.status == "too_large":
                captures_by_position[position] = detection_runtime.CaptureResult(
                    position,
                    detection_runtime.CaptureStatus.TOO_LARGE,
                    None,
                    reservation.error,
                )
                continue
            if reservation.status != "claimed" or reservation.claim_token is None:
                captures_by_position[position] = detection_runtime.CaptureResult(
                    position,
                    detection_runtime.CaptureStatus.FAILED,
                    None,
                    reservation.error or "evidence capture reservation unavailable",
                )
                continue
            claim_tokens[position] = reservation.claim_token
            prefetched_task = (prefetched_scans or {}).get(position)

            async def capture_reader(
                candidate, max_bytes, *, prefetched=prefetched_task
            ):
                if prefetched is None:
                    return await detection_runtime.read_attachment_bounded(
                        candidate, max_bytes
                    )
                scan = await asyncio.shield(prefetched)
                if scan["error"] is not None:
                    return await detection_runtime.read_attachment_bounded(
                        candidate, max_bytes
                    )
                data = scan["data"]
                if len(data) > max_bytes:
                    raise detection_runtime.AttachmentTooLargeError(
                        f"attachment exceeds the {max_bytes} byte evidence limit"
                    )
                return data

            tasks[position] = asyncio.create_task(
                detection_runtime.capture_attachment(
                    attachment,
                    target,
                    position,
                    DETECTION_ATTACHMENT_TIMEOUT_SECONDS,
                    max_bytes=size,
                    reader=capture_reader,
                )
            )
        if started_event is not None:
            started_event.set()
        try:
            done, pending = await asyncio.wait(
                tuple(tasks.values()), timeout=DETECTION_CAPTURE_DEADLINE_SECONDS
            ) if tasks else (set(), set())
        except BaseException:
            for task in tasks.values():
                task.cancel()
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for result in results:
                if (
                    isinstance(result, detection_runtime.CaptureResult)
                    and result.path is not None
                ):
                    await asyncio.to_thread(
                        self._discard_rejected_detection_case_capture,
                        message.guild.id,
                        case_id,
                        result.path,
                    )
            for position, claim_token in claim_tokens.items():
                await asyncio.to_thread(
                    self._case_store.release_attachment_capture,
                    case_id,
                    sequence,
                    position,
                    claim_token,
                    detection_runtime.CaptureStatus.FAILED.value,
                    "attachment capture cancelled",
                )
            raise
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for position, task in tasks.items():
            if task in done:
                captures_by_position[position] = task.result()
            else:
                captures_by_position[position] = detection_runtime.CaptureResult(
                    position,
                    detection_runtime.CaptureStatus.TIMEOUT,
                    None,
                    "overall attachment capture deadline exceeded",
                )
        captures = tuple(
            captures_by_position[position]
            for position in range(len(message.attachments))
        )
        persisted_captures = []
        for capture in captures:
            claim_token = claim_tokens.get(capture.position)
            if claim_token is None:
                persisted_captures.append(capture)
                continue
            if capture.status is detection_runtime.CaptureStatus.CAPTURED and capture.path is not None:
                actual_bytes = await asyncio.to_thread(lambda path=capture.path: path.stat().st_size)
                completion = await asyncio.to_thread(
                    self._case_store.complete_attachment_capture,
                    case_id,
                    sequence,
                    capture.position,
                    claim_token,
                    actual_bytes,
                    str(capture.path),
                    datetime.now(timezone.utc),
                    max_attachment_bytes=attachment_sizes[capture.position],
                    max_case_bytes=case_declared_bytes,
                )
                if completion == "captured":
                    persisted_captures.append(capture)
                    continue
                if completion == "too_large":
                    await asyncio.to_thread(
                        self._discard_rejected_detection_case_capture,
                        message.guild.id,
                        case_id,
                        capture.path,
                    )
                    persisted_captures.append(
                        detection_runtime.CaptureResult(
                            capture.position,
                            detection_runtime.CaptureStatus.TOO_LARGE,
                            None,
                            "captured attachment exceeds its reserved evidence bytes",
                        )
                    )
                else:
                    await asyncio.to_thread(
                        self._discard_rejected_detection_case_capture,
                        message.guild.id,
                        case_id,
                        capture.path,
                    )
                    persisted_captures.append(
                        detection_runtime.CaptureResult(
                            capture.position,
                            detection_runtime.CaptureStatus.FAILED,
                            None,
                            "evidence capture claim is no longer owned",
                        )
                    )
                continue
            released = await asyncio.to_thread(
                self._case_store.release_attachment_capture,
                case_id,
                sequence,
                capture.position,
                claim_token,
                capture.status.value,
                capture.error,
            )
            persisted_captures.append(
                capture
                if released
                else detection_runtime.CaptureResult(
                    capture.position,
                    detection_runtime.CaptureStatus.FAILED,
                    None,
                    "evidence capture claim is no longer owned",
                )
            )
        failed_captures = tuple(
            capture
            for capture in persisted_captures
            if capture.status in {
                detection_runtime.CaptureStatus.FAILED,
                detection_runtime.CaptureStatus.TIMEOUT,
            }
            and capture.error not in {
                "detection case deletion is in progress",
                "evidence capture claim is no longer owned",
            }
        )
        if failed_captures:
            details = "; ".join(
                f"attachment {capture.position + 1}: "
                f"{capture.error or capture.status.value}"
                for capture in failed_captures[:3]
            )
            await self._record_operational_failure(
                message.guild.id,
                "evidence_capture",
                f"Failed to capture {len(failed_captures)} attachment(s): {details}"[:512],
                case_id=case_id,
            )
        return tuple(persisted_captures)

    async def _scan_image_attachments(
        self,
        message: discord.Message,
        samples,
        threshold: int,
        *,
        capture_results: tuple[detection_runtime.CaptureResult, ...] = (),
        limit: int | None = None,
        stop_after_match: bool = False,
        batch_key: tuple[int, int] | None = None,
        skip_positions: frozenset[int] = frozenset(),
    ) -> tuple[dict[str, object], ...]:
        captures = {capture.position: capture for capture in capture_results}
        candidates = []
        image_position = 0
        for position, attachment in enumerate(message.attachments):
            if position in skip_positions:
                continue
            if not is_image_attachment(attachment):
                continue
            image_position += 1
            if limit is not None and image_position > limit:
                break
            candidates.append((position, image_position, attachment))

        async def scan_one(position, image_position, attachment):
            try:
                download_started = perf_counter()
                capture = captures.get(position)
                if capture is not None and capture.path is not None:
                    data = await asyncio.wait_for(
                        asyncio.to_thread(
                            detection_runtime.read_file_bounded,
                            capture.path,
                            DETECTION_IMAGE_READ_MAX_BYTES,
                        ),
                        timeout=DETECTION_ATTACHMENT_TIMEOUT_SECONDS,
                    )
                elif capture is not None:
                    raise RuntimeError(capture.error or "attachment capture is unavailable")
                else:
                    data = await asyncio.wait_for(
                        detection_runtime.read_attachment_bounded(
                            attachment, DETECTION_IMAGE_READ_MAX_BYTES
                        ),
                        timeout=DETECTION_ATTACHMENT_TIMEOUT_SECONDS,
                    )
                download_ms = (perf_counter() - download_started) * 1000
                hash_started = perf_counter()
                hashes = await asyncio.to_thread(image_hashes_from_bytes, data)
                hash_ms = (perf_counter() - hash_started) * 1000
                compare_started = perf_counter()
                result = await asyncio.to_thread(match_image, hashes, samples, threshold)
                compare_ms = (perf_counter() - compare_started) * 1000
                error = None
            except Exception as exception:
                hashes = {}
                result = {}
                error = f"{type(exception).__name__}: {exception}"[:512]
                download_ms = 0.0
                hash_ms = 0.0
                compare_ms = 0.0
            return {
                "position": position,
                "image_position": image_position,
                "attachment": attachment,
                "hashes": hashes,
                "result": result,
                "error": error,
                "data": data if error is None else None,
                "download_ms": download_ms,
                "hash_ms": hash_ms,
                "compare_ms": compare_ms,
            }

        if stop_after_match:
            tasks = {
                position: asyncio.create_task(
                    scan_one(position, image_position, attachment)
                )
                for position, image_position, attachment in candidates
            }
            self._initial_image_scan_tasks.update(tasks.values())
            if batch_key is not None:
                self._initial_image_scan_batches[batch_key] = tasks
            for task in tasks.values():
                task.add_done_callback(self._initial_image_scan_tasks.discard)
            scans = []
            try:
                for completed in asyncio.as_completed(tasks.values()):
                    scan = await completed
                    scans.append(scan)
                    if scan["error"] is None and scan["result"].get("matched"):
                        return tuple(scans)
            except BaseException:
                for task in tasks.values():
                    task.cancel()
                await asyncio.gather(*tasks.values(), return_exceptions=True)
                raise
            return tuple(scans)

        return tuple(
            [
                await scan_one(position, image_position, attachment)
                for position, image_position, attachment in candidates
            ]
        )

    async def _scan_all_case_message_images(
        self,
        message: discord.Message,
        config: dict,
        case_id: str,
        sequence: int,
        capture_results: tuple[detection_runtime.CaptureResult, ...],
    ) -> None:
        await self._scan_case_message_images(
            message.guild.id,
            tuple(message.attachments),
            config,
            case_id,
            sequence,
            capture_results,
            initial_scan_key=(message.guild.id, message.id),
        )

    async def _scan_case_message_images(
        self,
        guild_id: int,
        attachments: tuple,
        config: dict,
        case_id: str,
        sequence: int,
        capture_results: tuple[detection_runtime.CaptureResult, ...],
        initial_scan_key: tuple[int, int] | None = None,
    ) -> None:
        if not attachments:
            return
        try:
            samples = await self._imagescan_load_samples(guild_id)
            model = await self._imagescan_model_state(
                guild_id,
                config.get("imagescan_detector_threshold", 20),
            )
        except Exception as error:
            bounded = f"{type(error).__name__}: {error}"[:512]
            for position, attachment in enumerate(attachments):
                if is_image_attachment(attachment):
                    await asyncio.to_thread(
                        self._case_store.update_attachment_scan,
                        case_id, sequence, position, None, None, {}, bounded,
                    )
            await self._record_operational_failure(
                guild_id,
                "image_scan_setup",
                bounded,
                case_id=case_id,
            )
            return
        reused_scans = ()
        if initial_scan_key is not None:
            initial_tasks = self._initial_image_scan_batches.pop(initial_scan_key, ())
            if initial_tasks:
                reused_scans = tuple(
                    scan
                    for scan in await asyncio.gather(*initial_tasks.values())
                    if scan["error"] is None
                )
        reused_positions = frozenset(scan["position"] for scan in reused_scans)
        new_scans = await self._scan_image_attachments(
            type("PersistedDetectionMessage", (), {"attachments": attachments})(),
            samples,
            model["effective_threshold"],
            capture_results=capture_results,
            skip_positions=reused_positions,
        )
        scans = tuple(sorted(reused_scans + new_scans, key=lambda item: item["position"]))
        unavailable_capture_positions = {
            capture.position
            for capture in capture_results
            if capture.status is not detection_runtime.CaptureStatus.CAPTURED
        }
        failed_scans = tuple(
            scan
            for scan in scans
            if scan["error"] is not None
            and scan["position"] not in unavailable_capture_positions
        )
        for scan in scans:
            position = scan["position"]
            if scan["error"] is None:
                hashes = scan["hashes"]
                await asyncio.to_thread(
                    self._case_store.update_attachment_scan,
                    case_id,
                    sequence,
                    position,
                    hashes.get("sha256"),
                    hashes.get("phash"),
                    scan["result"],
                    None,
                )
            else:
                await asyncio.to_thread(
                    self._case_store.update_attachment_scan,
                    case_id,
                    sequence,
                    position,
                    None,
                    None,
                    {},
                    scan["error"],
                )
        if failed_scans:
            details = "; ".join(
                f"attachment {scan['position'] + 1}: {scan['error']}"
                for scan in failed_scans[:3]
            )
            await self._record_operational_failure(
                guild_id,
                "image_scan",
                f"Failed to scan {len(failed_scans)} attachment(s): {details}"[:512],
                case_id=case_id,
            )

    @staticmethod
    def _case_timeline_attachment_line(attachment) -> str:
        details = [attachment.capture_status]
        metadata = attachment.match_metadata
        matched_filename = metadata.get("matched_filename")
        hash_diff = metadata.get(
            "hash_diff", metadata.get("distance", metadata.get("score"))
        )
        threshold = metadata.get("threshold")
        if matched_filename:
            match = f"matched {matched_filename}"
            if hash_diff is not None:
                difference = str(hash_diff)
                if threshold is not None:
                    difference += f"/{threshold}"
                match += f" (hash difference {difference})"
            details.append(match)
        elif metadata.get("matched"):
            match = "matched known suspicious content"
            if hash_diff is not None:
                difference = str(hash_diff)
                if threshold is not None:
                    difference += f"/{threshold}"
                match += f" (hash difference {difference})"
            details.append(match)
        matches = metadata.get("matches")
        if isinstance(matches, (list, tuple)):
            for match in matches[:3]:
                if not isinstance(match, typing.Mapping):
                    continue
                filename = match.get("matched_filename", match.get("filename", "known sample"))
                distance = match.get("hash_diff", match.get("distance", match.get("score")))
                detail = f"matched {filename}"
                if distance is not None:
                    difference = str(distance)
                    match_threshold = match.get("threshold")
                    if match_threshold is not None:
                        difference += f"/{match_threshold}"
                    detail += f" (hash difference {difference})"
                details.append(detail)
        if attachment.learning_decision:
            decisions = {
                "true_positive": "True positive",
                "false_positive": "False positive",
                "ignored": "Ignored",
            }
            details.append(
                decisions.get(attachment.learning_decision, attachment.learning_decision)
            )
        if attachment.publication_error:
            details.append(f"upload warning: {attachment.publication_error}")
        filename = attachment.filename.replace("`", "ˋ")
        return (
            f"- {attachment.key.position + 1}. `{filename}`\n"
            f"  {'; '.join(details)}"
        )

    @staticmethod
    def _case_timeline_message_content(message) -> str:
        reasons = (
            "\n".join(f"- {reason}" for reason in message.signal_reasons)
            if message.signal_reasons
            else "- Detection signal recorded"
        )
        content = (message.content or "(message with attachments only)").replace(
            "```", "``\u200b`"
        )
        source = message.jump_url or "Source unavailable"
        attachments = (
            "\n\nAttachments:\n"
            + "\n".join(
                Honeypot._case_timeline_attachment_line(attachment)
                for attachment in message.attachments
            )
            if message.attachments
            else ""
        )
        return (
            f"**Message {message.sequence}** • {source} • "
            f"<t:{int(message.created_at.timestamp())}:F>\n"
            f"Status: {message.delete_status}\n"
            f"Signals:\n{reasons}\n```\n{content}\n```{attachments}"
        )

    @staticmethod
    def _case_timeline_message_chunks(message) -> tuple[str, ...]:
        rendered = Honeypot._case_timeline_message_content(message)
        metadata, opening, fenced = rendered.partition("```\n")
        content, closing, trailing = fenced.partition("\n```")
        if not opening or not closing:
            raise RuntimeError("timeline message content is missing its code fence")

        chunks: list[str] = []
        remaining = content
        while remaining:
            prefix = (
                metadata + opening
                if not chunks
                else f"**Message {message.sequence} (continued)**\n```\n"
            )
            suffix = "\n```"
            available = 2000 - len(prefix) - len(suffix)
            if available <= 0:
                raise RuntimeError("timeline message metadata exceeds Discord's limit")
            split_at = min(len(remaining), available)
            if split_at < len(remaining):
                newline = remaining.rfind("\n", 0, split_at + 1)
                if newline > 0:
                    split_at = newline + 1
            payload = prefix + remaining[:split_at] + suffix
            remaining = remaining[split_at:]
            if not remaining and trailing and len(payload) + len(trailing) <= 2000:
                payload += trailing
                trailing = ""
            chunks.append(payload)

        while trailing:
            prefix = f"**Message {message.sequence} (continued)**\n"
            available = 2000 - len(prefix)
            split_at = min(len(trailing), available)
            if split_at < len(trailing):
                newline = trailing.rfind("\n", 0, split_at + 1)
                if newline > 0:
                    split_at = newline + 1
            chunks.append(prefix + trailing[:split_at].lstrip("\n"))
            trailing = trailing[split_at:]

        return tuple(chunks)

    @staticmethod
    def _case_publication_nonce(logical_key: str) -> int:
        digest = hashlib.blake2b(logical_key.encode("utf-8"), digest_size=8).digest()
        return int.from_bytes(digest, "big") & ((1 << 63) - 1)

    async def _complete_case_timeline_publication(
        self, publication, sent_message, thread_id: int
    ) -> None:
        if publication.claim_token is None:
            raise RuntimeError("timeline publication is not claimed")
        try:
            await asyncio.to_thread(
                self._case_store.complete_timeline_publication,
                publication.logical_key,
                publication.claim_token,
                channel_id=thread_id,
                message_id=sent_message.id,
                revision=1,
            )
        except KeyError:
            current = next(
                (
                    item
                    for item in await asyncio.to_thread(
                        self._case_store.list_timeline_publications,
                        publication.case_id,
                    )
                    if item.logical_key == publication.logical_key
                ),
                None,
            )
            if (
                current is not None
                and current.state == "published"
                and current.channel_id == thread_id
                and current.message_id == sent_message.id
            ):
                return
            await self._compensate_case_publication(
                publication.case_id, thread_id, sent_message
            )
            raise

    async def _compensate_case_publication(
        self, case_id: str, channel_id: int, message
    ) -> None:
        delete = getattr(message, "delete", None)
        if callable(delete):
            try:
                await delete()
                return
            except discord.NotFound:
                return
            except discord.HTTPException:
                pass
        recorded = await asyncio.to_thread(
            self._case_store.add_case_deletion_publication,
            case_id,
            channel_id,
            message.id,
        )
        if not recorded:
            recorded = await asyncio.to_thread(
                self._case_store.record_orphan_publication,
                case_id,
                channel_id,
                message.id,
            )
        if not recorded:
            raise RuntimeError("failed to retain a late case publication for cleanup")

    async def _retry_detection_orphan_publications(self) -> None:
        publications = await asyncio.to_thread(
            self._case_store.list_orphan_publications
        )
        for case_id, guild_id, channel_id, message_id in publications:
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                continue
            channel = await self._fetch_text_channel_or_thread(guild, channel_id)
            if channel is None:
                continue
            try:
                message = await channel.fetch_message(message_id)
                await message.delete()
            except discord.NotFound:
                pass
            except discord.HTTPException as error:
                await self._record_operational_failure(
                    guild_id,
                    "orphan_publication_deletion",
                    f"{type(error).__name__}: {error}",
                    case_id=case_id,
                )
                continue
            await asyncio.to_thread(
                self._case_store.complete_orphan_publication,
                case_id,
                channel_id,
                message_id,
            )

    async def _acquire_case_timeline_publication(
        self, publication, *, replace_message_id: int | None = None
    ):
        for _attempt in range(20):
            claimed = await asyncio.to_thread(
                self._case_store.claim_timeline_publication,
                publication.logical_key,
                datetime.now(timezone.utc),
                replace_message_id=replace_message_id,
            )
            if claimed is not None:
                return claimed, True
            current = next(
                (
                    item
                    for item in await asyncio.to_thread(
                        self._case_store.list_timeline_publications,
                        publication.case_id,
                    )
                    if item.logical_key == publication.logical_key
                ),
                None,
            )
            if current is None:
                raise KeyError(publication.logical_key)
            if current.state == "published":
                return current, False
            await asyncio.sleep(0)
        raise RuntimeError("timeline publication claim is unavailable")

    async def _release_case_timeline_publication(self, publication) -> None:
        if publication.claim_token is not None:
            await asyncio.to_thread(
                self._case_store.release_timeline_publication_claim,
                publication.logical_key,
                publication.claim_token,
            )

    async def _upsert_case_timeline_text(
        self,
        publication,
        thread,
        content: str,
        *,
        view: object = _TIMELINE_VIEW_UNSET,
    ) -> None:
        edit_kwargs = {"content": content}
        send_kwargs = {}
        if view is not _TIMELINE_VIEW_UNSET:
            edit_kwargs["view"] = view
            send_kwargs["view"] = view
        replace_message_id = None
        if publication.state == "published" and publication.message_id is not None:
            try:
                message = await thread.fetch_message(publication.message_id)
                await message.edit(**edit_kwargs)
                return
            except discord.NotFound:
                replace_message_id = publication.message_id
        publication, owned = await self._acquire_case_timeline_publication(
            publication, replace_message_id=replace_message_id
        )
        if not owned:
            message = await thread.fetch_message(publication.message_id)
            await message.edit(**edit_kwargs)
            return
        try:
            message = await thread.send(
                content,
                **send_kwargs,
                allowed_mentions=discord.AllowedMentions.none(),
                nonce=self._case_publication_nonce(publication.logical_key),
            )
            await self._complete_case_timeline_publication(
                publication, message, thread.id
            )
        except BaseException:
            await self._release_case_timeline_publication(publication)
            raise

    @staticmethod
    def _case_note_chunks(notes: tuple[str, ...]) -> tuple[str, ...]:
        chunks: list[str] = []
        current = "**Case operation notes**"
        for note in notes:
            line = f"\n- {note}"
            if len(current) + len(line) > 2000:
                chunks.append(current)
                current = "**Case operation notes (continued)**" + line
            else:
                current += line
        if notes:
            chunks.append(current)
        else:
            chunks.append("**Case operation notes**\nNo current operation warnings.")
        return tuple(chunks)

    async def _ensure_detection_case_thread(self, snapshot, summary_message):
        fetch_thread = getattr(summary_message, "fetch_thread", None)
        thread = None
        if callable(fetch_thread):
            try:
                thread = await fetch_thread()
            except discord.NotFound:
                thread = None
        if thread is None:
            create_thread = getattr(summary_message, "create_thread", None)
            if not callable(create_thread):
                raise RuntimeError("detection case summary cannot create a thread")
            try:
                thread = await create_thread(
                    name=f"case-{snapshot.case.user_id}",
                    auto_archive_duration=1440,
                    reason="Honeypot detection case",
                )
            except discord.HTTPException as create_error:
                if not callable(fetch_thread):
                    raise
                try:
                    thread = await fetch_thread()
                except discord.NotFound:
                    raise create_error
        parent = getattr(summary_message, "channel", None)
        parent_channel_id = getattr(parent, "id", snapshot.case.review_channel_id)
        try:
            await asyncio.to_thread(
                self._case_store.activate_projection_endpoint,
                snapshot.case.case_id,
                parent_channel_id=parent_channel_id,
                summary_message_id=summary_message.id,
                thread_id=thread.id,
                projected_revision=len(snapshot.messages),
                verified_at=datetime.now(timezone.utc),
            )
        except KeyError:
            delete = getattr(thread, "delete", None)
            if callable(delete):
                try:
                    await delete(reason="Honeypot user data deletion")
                except discord.NotFound:
                    pass
            raise
        return thread

    async def _activate_detection_case_thread(self, thread):
        if not getattr(thread, "archived", False) and not getattr(
            thread, "locked", False
        ):
            return thread
        return await thread.edit(
            archived=False,
            locked=False,
            reason="Honeypot detection case update",
        )

    async def _finalize_detection_case_thread(self, thread) -> None:
        await thread.edit(
            archived=True,
            locked=True,
            reason="Honeypot detection case resolved",
        )

    async def _publish_case_timeline(
        self,
        snapshot,
        thread,
        *,
        resolved: bool,
        message_sequence: int | None = None,
    ) -> None:
        timeline = render_timeline(snapshot)
        feedback_items = case_feedback_items(snapshot)
        note_chunks = self._case_note_chunks(timeline.case_notes)
        timeline_publications = await asyncio.to_thread(
            self._case_store.list_timeline_publications,
            snapshot.case.case_id,
        )
        existing_note_count = sum(
            1
            for publication in timeline_publications
            if publication.kind == "case_note"
        )
        for chunk_index in range(max(len(note_chunks), existing_note_count)):
            publication = await asyncio.to_thread(
                self._case_store.ensure_timeline_publication,
                snapshot.case.case_id,
                kind="case_note",
                chunk_index=chunk_index,
            )
            content = (
                note_chunks[chunk_index]
                if chunk_index < len(note_chunks)
                else "**Case operation notes**\nNo current operation warnings."
            )
            await self._upsert_case_timeline_text(publication, thread, content)
        if resolved or message_sequence is None:
            messages = timeline.messages
        else:
            published_message_sequences = {
                publication.message_sequence
                for publication in timeline_publications
                if publication.kind == "message"
                and publication.chunk_index == 0
                and publication.state == "published"
            }
            messages = tuple(
                message
                for message in timeline.messages
                if message.sequence == message_sequence
                or (
                    message.sequence < message_sequence
                    and message.sequence not in published_message_sequences
                )
            )
        for message in messages:
            batches, oversized, upload_limit = self._case_timeline_evidence_batches(
                message, thread
            )
            pending_message_feedback = self._pending_feedback_items(
                feedback_items, message.sequence
            )
            has_pending_image_feedback = bool(pending_message_feedback)
            message_chunks = self._case_timeline_message_chunks(message)
            existing_message_chunks = sum(
                1
                for publication in timeline_publications
                if publication.kind == "message"
                and publication.message_sequence == message.sequence
            )
            for chunk_index in range(
                max(len(message_chunks), existing_message_chunks)
            ):
                publication = await asyncio.to_thread(
                    self._case_store.ensure_timeline_publication,
                    snapshot.case.case_id,
                    kind="message",
                    message_sequence=message.sequence,
                    chunk_index=chunk_index,
                )
                content = (
                    message_chunks[chunk_index]
                    if chunk_index < len(message_chunks)
                    else f"**Message {message.sequence} (continued)**\nNo additional content."
                )
                view = (
                    DetectionCaseView(
                        self,
                        snapshot.case.case_id,
                        has_image_feedback=has_pending_image_feedback,
                        feedback_items=pending_message_feedback,
                        message_sequence=message.sequence,
                        resolved=resolved,
                        moderation_actions=(),
                    )
                    if chunk_index == 0 and not batches
                    else None
                )
                await self._upsert_case_timeline_text(
                    publication, thread, content, view=view
                )
            limit_label = f"{upload_limit / (1024 * 1024):g} MiB"
            for attachment in oversized:
                await asyncio.to_thread(
                    self._case_store.update_attachment_publication_error,
                    snapshot.case.case_id,
                    attachment.key.message_sequence,
                    attachment.key.position,
                    f"attachment exceeds the {limit_label} review destination upload limit",
                )
            for chunk_index, batch in enumerate(batches):
                evidence = await asyncio.to_thread(
                    self._case_store.ensure_timeline_publication,
                    snapshot.case.case_id,
                    kind="evidence",
                    message_sequence=message.sequence,
                    chunk_index=chunk_index,
                )
                content = f"Message {message.sequence} attachments"
                view = (
                    DetectionCaseView(
                        self,
                        snapshot.case.case_id,
                        has_image_feedback=has_pending_image_feedback,
                        feedback_items=pending_message_feedback,
                        message_sequence=message.sequence,
                        resolved=resolved,
                        moderation_actions=(),
                    )
                    if chunk_index == 0
                    else None
                )
                replace_message_id = None
                if evidence.state == "published" and evidence.message_id is not None:
                    try:
                        published = await thread.fetch_message(evidence.message_id)
                        existing_attachments = getattr(
                            published, "attachments", None
                        )
                        same_batch = (
                            getattr(published, "content", None) == content
                            and existing_attachments is not None
                            and len(existing_attachments) == len(batch)
                        )
                        if same_batch:
                            await published.edit(view=view)
                        else:
                            files = [
                                discord.File(
                                    Path(attachment.evidence_path),
                                    filename=attachment.filename,
                                    spoiler=attachment.spoiler,
                                    description=attachment.description,
                                )
                                for attachment in batch
                            ]
                            await published.edit(
                                content=content,
                                attachments=files,
                                view=view,
                            )
                        continue
                    except discord.NotFound:
                        replace_message_id = evidence.message_id
                evidence, owned = await self._acquire_case_timeline_publication(
                    evidence, replace_message_id=replace_message_id
                )
                if not owned:
                    published = await thread.fetch_message(evidence.message_id)
                    await published.edit(view=view)
                    continue
                files = [
                    discord.File(
                        Path(attachment.evidence_path),
                        filename=attachment.filename,
                        spoiler=attachment.spoiler,
                        description=attachment.description,
                    )
                    for attachment in batch
                ]
                try:
                    published = await thread.send(
                        content,
                        files=files,
                        view=view,
                        allowed_mentions=discord.AllowedMentions.none(),
                        nonce=self._case_publication_nonce(evidence.logical_key),
                    )
                    await self._complete_case_timeline_publication(
                        evidence, published, thread.id
                    )
                except BaseException:
                    await self._release_case_timeline_publication(evidence)
                    raise
            existing_evidence = tuple(
                publication
                for publication in await asyncio.to_thread(
                    self._case_store.list_timeline_publications,
                    snapshot.case.case_id,
                )
                if publication.kind == "evidence"
                and publication.message_sequence == message.sequence
                and publication.chunk_index >= len(batches)
            )
            for obsolete in existing_evidence:
                if obsolete.state != "published" or obsolete.message_id is None:
                    continue
                try:
                    published = await thread.fetch_message(obsolete.message_id)
                except discord.NotFound:
                    continue
                await published.edit(
                    content=(
                        f"Message {message.sequence} attachments: "
                        "No additional attachments."
                    ),
                    attachments=[],
                    view=None,
                )
    @staticmethod
    def _case_timeline_evidence_batches(message, thread):
        upload_limit = getattr(thread, "filesize_limit", None)
        if not isinstance(upload_limit, int) or upload_limit <= 0:
            upload_limit = getattr(getattr(thread, "guild", None), "filesize_limit", None)
        if not isinstance(upload_limit, int) or upload_limit <= 0:
            upload_limit = math.inf
        terminal_statuses = {
            status.value for status in detection_runtime.CaptureStatus
        }
        if any(
            attachment.capture_status not in terminal_statuses
            for attachment in message.attachments
        ):
            return (), (), upload_limit
        batches = []
        batch = []
        oversized = []
        max_batch_files = 10
        for attachment in message.attachments:
            if attachment.capture_status != "captured" or not attachment.evidence_path:
                continue
            path = Path(attachment.evidence_path)
            if not path.is_file():
                continue
            actual_size = path.stat().st_size
            if actual_size > upload_limit:
                oversized.append(attachment)
                continue
            if len(batch) == max_batch_files:
                batches.append(tuple(batch))
                batch = []
            batch.append(attachment)
        if batch:
            batches.append(tuple(batch))
        return tuple(batches), tuple(oversized), upload_limit

    async def _publish_detection_case(
        self,
        case_id: str,
        config: dict,
        logs_channel: discord.TextChannel | discord.Thread | None,
        *,
        message_sequence: int | None = None,
        skip_if_done: asyncio.Task | None = None,
    ) -> bool:
        digest = hashlib.blake2b(case_id.encode("utf-8"), digest_size=8).digest()
        lock = self._detection_publication_locks[
            int.from_bytes(digest, "big") % len(self._detection_publication_locks)
        ]
        async with lock:
            if skip_if_done is not None and skip_if_done.done():
                return False
            await self._publish_detection_case_serial(
                case_id,
                config,
                logs_channel,
                message_sequence=message_sequence,
            )
            return True

    @staticmethod
    def _pending_feedback_items(
        feedback_items: tuple[CaseFeedbackItem, ...],
        message_sequence: int | None = None,
    ) -> tuple[CaseFeedbackItem, ...]:
        return tuple(
            item
            for item in feedback_items
            if item.decision is None
            and (
                message_sequence is None
                or item.message_sequence == message_sequence
            )
        )

    async def _publish_detection_case_serial(
        self,
        case_id: str,
        config: dict,
        logs_channel: discord.TextChannel | discord.Thread | None,
        *,
        message_sequence: int | None = None,
    ) -> None:
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        if snapshot is None:
            return
        guild = None
        if config.get("review_channel") is not None or snapshot.case.review_channel_id is not None:
            guild = self.bot.get_guild(snapshot.case.guild_id)
        review_channel = (
            await self._fetch_text_channel_or_thread(
                guild, config.get("review_channel")
            )
            if guild is not None and config.get("review_channel") is not None
            else None
        )
        if review_channel is not None and not isinstance(
            review_channel, discord.TextChannel
        ):
            raise RuntimeError(
                "The configured review destination must be a text channel."
            )
        channel = review_channel or logs_channel
        has_persisted_primary = bool(
            snapshot.case.review_channel_id and snapshot.case.review_message_id
        )
        if channel is None and not has_persisted_primary:
            raise RuntimeError(
                "No configured detection case publication destination is available."
            )
        projection = render_case(snapshot)
        def projection_embed():
            page_embed = discord.Embed(
                title=_(projection.title),
                description=projection.description,
                color=(
                    discord.Color.dark_red()
                    if projection.needs_attention
                    else discord.Color.gold()
                ),
            )
            set_thumbnail = getattr(page_embed, "set_thumbnail", None)
            if projection.thumbnail_url and callable(set_thumbnail):
                set_thumbnail(url=projection.thumbnail_url)
            for field in projection.pages[0]:
                page_embed.add_field(
                    name=_(field.name), value=_(field.value), inline=False
                )
            return page_embed

        embed = projection_embed()
        resolved = snapshot.case.status.value in {"resolved", "expired"}
        moderation_actions = projection.moderation_actions
        pending_feedback = self._pending_feedback_items(
            projection.feedback_items
        )
        view = DetectionCaseView(
            self,
            case_id,
            has_image_feedback=bool(pending_feedback),
            feedback_items=pending_feedback,
            resolved=resolved,
            allow_individual=len(pending_feedback) <= 25,
            moderation_actions=moderation_actions,
        )
        self._case_views[case_id] = view
        existing = None
        if snapshot.case.review_channel_id and snapshot.case.review_message_id and guild is not None:
            old_channel = await self._fetch_text_channel_or_thread(
                guild, snapshot.case.review_channel_id
            )
            if old_channel is not None:
                try:
                    existing = await old_channel.fetch_message(snapshot.case.review_message_id)
                except discord.NotFound:
                    cleared = await asyncio.to_thread(
                        self._case_store.clear_review_message,
                        case_id,
                        snapshot.case.review_channel_id,
                        snapshot.case.review_message_id,
                    )
                    if not cleared:
                        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        if existing is not None:
            await existing.edit(embed=embed, view=view)
            thread = await self._ensure_detection_case_thread(snapshot, existing)
            thread = await self._activate_detection_case_thread(thread)
            await self._publish_case_timeline(
                snapshot,
                thread,
                resolved=resolved,
                message_sequence=message_sequence,
            )
            if resolved:
                await self._finalize_detection_case_thread(thread)
            return
        if channel is None:
            raise RuntimeError(
                "No configured detection case publication destination is available."
            )
        summary_message = None
        token = await asyncio.to_thread(
            self._case_store.claim_publication, case_id, "primary", datetime.now(timezone.utc)
        )
        if token is not None:
            heartbeat = asyncio.create_task(
                self._renew_case_publication_claim(case_id, "primary", token)
            )
            try:
                sent = await channel.send(
                    embed=embed,
                    view=view,
                    nonce=UUID(case_id).int & ((1 << 63) - 1),
                )
                summary_message = sent
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)
                completed = await asyncio.to_thread(
                    self._case_store.complete_primary_publication,
                    case_id, token, channel.id, sent.id,
                )
                if not completed:
                    await self._compensate_case_publication(
                        case_id, channel.id, sent
                    )
                    raise RuntimeError("detection case primary publication lease was lost")
                if guild is not None:
                    await self._increment_stat(guild, "reviewed")
            except BaseException:
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)
                await asyncio.to_thread(
                    self._case_store.release_publication_claim, case_id, "primary", token
                )
                raise
        else:
            for _attempt in range(20):
                await asyncio.sleep(0)
                snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
                if snapshot is not None and snapshot.case.review_message_id is not None:
                    winner_channel = await self._fetch_text_channel_or_thread(
                        guild, snapshot.case.review_channel_id
                    )
                    if winner_channel is not None:
                        winner_message = await winner_channel.fetch_message(
                            snapshot.case.review_message_id
                        )
                        await winner_message.edit(embed=embed, view=view)
                        summary_message = winner_message
                    break
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        if summary_message is None and snapshot.case.review_message_id is not None:
            destination = await self._fetch_text_channel_or_thread(
                guild, snapshot.case.review_channel_id
            )
            if destination is not None:
                summary_message = await destination.fetch_message(
                    snapshot.case.review_message_id
                )
        if summary_message is None:
            raise RuntimeError("detection case summary publication is unavailable")
        thread = await self._ensure_detection_case_thread(snapshot, summary_message)
        thread = await self._activate_detection_case_thread(thread)
        await self._publish_case_timeline(
            snapshot,
            thread,
            resolved=resolved,
            message_sequence=message_sequence,
        )
        if resolved:
            await self._finalize_detection_case_thread(thread)




    async def _renew_case_publication_claim(
        self, case_id: str, slot: str, token: str
    ) -> None:
        while True:
            await asyncio.sleep(self._detection_heartbeat_interval_seconds)
            renewed = await asyncio.to_thread(
                self._case_store.renew_publication_claim,
                case_id,
                slot,
                token,
                datetime.now(timezone.utc),
            )
            if not renewed:
                return


    @staticmethod
    def _case_review_has_permission(interaction: discord.Interaction) -> bool:
        permissions = getattr(getattr(interaction, "user", None), "guild_permissions", None)
        return bool(
            permissions
            and (
                getattr(permissions, "moderate_members", False)
                or getattr(permissions, "manage_messages", False)
                or getattr(permissions, "ban_members", False)
                or getattr(permissions, "kick_members", False)
            )
        )

    @staticmethod
    def _case_review_has_action_permission(
        interaction: discord.Interaction, action: str
    ) -> bool:
        return action in {"ban", "kick", "ignore"} and Honeypot._case_review_has_permission(
            interaction
        )

    async def _case_review_error(self, interaction: discord.Interaction, message: str) -> None:
        response = interaction.response
        if not response.is_done():
            await response.send_message(message, ephemeral=True)
        else:
            await interaction.followup.send(message, ephemeral=True)

    async def _case_review_rerender(self, case_id: str) -> None:
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        if snapshot is None:
            return
        config = await self.config.guild_from_id(snapshot.case.guild_id).all()
        await self._publish_detection_case(case_id, config, None)

    async def _case_review_rerender_if_open(self, case_id: str) -> None:
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        if (
            snapshot is None
            or snapshot.case.status.value in {"resolved", "expired"}
            or snapshot.case.review_message_id is None
        ):
            return
        await self._case_review_rerender(case_id)

    async def _case_review_rerender_safely(self, case_id: str) -> None:
        try:
            await self._case_review_rerender_if_open(case_id)
        except Exception as error:
            log.warning(
                "Detection case moderation state could not be published "
                "case=%s error=%s",
                case_id,
                error,
            )

    async def _finish_case_review_if_ready(
        self, case_id: str, moderator_id: int | None
    ) -> bool:
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        if (
            snapshot is None
            or any(
                attachment.capture_status == "pending"
                for attachment in snapshot.attachments
            )
            or any(item.decision is None for item in case_feedback_items(snapshot))
        ):
            return False
        completed = next(
            (
                operation
                for operation in reversed(snapshot.operations)
                if operation.operation_type
                in {
                    "moderation_action",
                    "moderator_ban",
                    "moderator_kick",
                    "moderator_ignore",
                }
                and operation.status.value == "succeeded"
                and operation.result
                in {
                    "ban",
                    "kick",
                    "kick_missing",
                    "ignore",
                    "planned_ban",
                    "planned_kick",
                }
            ),
            None,
        )
        if completed is None:
            return False
        if snapshot.case.status.value in {"resolving", "resolved"}:
            await self._run_detection_reconciliation()
            refreshed = await asyncio.to_thread(self._case_store.get_case, case_id)
            return bool(
                refreshed is not None
                and refreshed.case.status.value in {"resolved", "expired"}
            )
        resolution = "kick" if completed.result == "kick_missing" else completed.result
        return await self.resolve_detection_case(
            case_id,
            resolution,
            completed.actor_id or moderator_id,
        )

    async def _case_review_bulk_interaction(
        self,
        interaction: discord.Interaction,
        case_id: str,
        action: str,
        *,
        confirmed: bool = False,
        expected_keys: tuple[AttachmentKey, ...] = (),
    ) -> bool:
        if not self._case_review_has_permission(interaction):
            await self._case_review_error(interaction, _("You do not have permission to review this case."))
            return False
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        pending_feedback = self._pending_feedback_items(
            case_feedback_items(snapshot) if snapshot is not None else ()
        )
        review_items = (
            tuple(item for item in pending_feedback if item.key in set(expected_keys))
            if confirmed and expected_keys
            else pending_feedback
        )
        try:
            validate_image_review_action(review_items, action)
        except ValueError as error:
            await self._case_review_error(
                interaction,
                _(str(error)),
            )
            return False
        if action in {"tp", "fp"} and not confirmed:
            await interaction.response.send_message(
                _("Confirm this bulk image decision."),
                view=DetectionBulkConfirmationView(
                    self,
                    case_id,
                    action,
                    confirm_label=bulk_image_confirmation_label(
                        pending_feedback, action
                    ),
                    expected_keys=tuple(item.key for item in pending_feedback),
                ),
                ephemeral=True,
            )
            return False
        await interaction.response.defer()
        try:
            await self._case_review_service.apply_bulk(
                case_id,
                action,
                interaction.user.id,
                expected_keys=expected_keys or None,
            )
            await self._finish_case_review_if_ready(case_id, interaction.user.id)
            await self._case_review_rerender_if_open(case_id)
            return True
        except (KeyError, ValueError) as error:
            await self._case_review_error(interaction, str(error))
            return False

    async def _case_review_message_bulk_interaction(
        self,
        interaction: discord.Interaction,
        case_id: str,
        message_sequence: int,
        action: str,
        *,
        confirmed: bool = False,
        expected_keys: tuple[AttachmentKey, ...] = (),
    ) -> bool:
        if not self._case_review_has_permission(interaction):
            await self._case_review_error(
                interaction, _("You do not have permission to review this case.")
            )
            return False
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        pending_feedback = self._pending_feedback_items(
            case_feedback_items(snapshot) if snapshot is not None else (),
            message_sequence,
        )
        review_items = (
            tuple(item for item in pending_feedback if item.key in set(expected_keys))
            if confirmed and expected_keys
            else pending_feedback
        )
        try:
            validate_image_review_action(review_items, action)
        except ValueError as error:
            await self._case_review_error(
                interaction,
                _(str(error)),
            )
            return False
        if action in {"tp", "fp"} and not confirmed:
            await interaction.response.send_message(
                _("Confirm this message's image decision."),
                view=DetectionBulkConfirmationView(
                    self,
                    case_id,
                    action,
                    message_sequence=message_sequence,
                    confirm_label=bulk_image_confirmation_label(
                        pending_feedback, action
                    ),
                    expected_keys=tuple(item.key for item in pending_feedback),
                ),
                ephemeral=True,
            )
            return False
        await interaction.response.defer()
        try:
            await self._case_review_service.apply_message(
                case_id,
                message_sequence,
                action,
                interaction.user.id,
                expected_keys=expected_keys or None,
            )
            await self._finish_case_review_if_ready(case_id, interaction.user.id)
            await self._case_review_rerender_if_open(case_id)
            return True
        except (KeyError, ValueError) as error:
            await self._case_review_error(interaction, str(error))
            return False

    async def _case_review_moderation_interaction(
        self,
        interaction: discord.Interaction,
        case_id: str,
        action: str,
        *,
        confirmed: bool = False,
    ) -> bool:
        if not self._case_review_has_action_permission(interaction, action):
            await self._case_review_error(
                interaction, _("You do not have permission to review this case.")
            )
            return False
        if action in {"ban", "kick"} and not confirmed:
            snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
            has_unreviewed_images = snapshot is not None and any(
                is_persisted_image_attachment(attachment)
                and (
                    attachment.capture_status == "pending"
                    or (
                        attachment.capture_status == "captured"
                        and attachment.evidence_path is not None
                        and attachment.learning_decision is None
                    )
                )
                for attachment in snapshot.attachments
            )
            if has_unreviewed_images:
                await interaction.response.send_message(
                    _(
                        "Some images are still processing or have not been reviewed. "
                        "Continue with moderation now?"
                    ),
                    view=DetectionModerationConfirmationView(self, case_id, action),
                    ephemeral=True,
                )
                return False
        await interaction.response.defer()
        try:
            if action == "ignore":
                snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
                moderated_at = datetime.now(timezone.utc)
                operation = await asyncio.to_thread(
                    self._case_store.record_moderator_ignore,
                    case_id,
                    interaction.user.id,
                    moderated_at,
                )
                if operation is None:
                    raise ValueError("detection case is already resolving or resolved")
                if snapshot is not None:
                    self._deactivate_forward_purge(
                        snapshot.case.guild_id, snapshot.case.user_id
                    )
                    guild = self.bot.get_guild(snapshot.case.guild_id)
                    if guild is not None:
                        await self._increment_stat(guild, "ignored")
                await self._release_detection_case_roles(case_id, moderated_at)
                await self._finish_case_review_if_ready(case_id, interaction.user.id)
                await self._case_review_rerender_if_open(case_id)
                return True
            if action not in {"ban", "kick"}:
                raise ValueError("unsupported detection case moderation action")
            operation = await asyncio.to_thread(
                self._case_store.claim_moderator_action,
                case_id,
                action,
                interaction.user.id,
                datetime.now(timezone.utc),
            )
            if operation is None:
                raise ValueError("detection case is already resolving or resolved")
            if operation.operation_type != f"moderator_{action}":
                raise ValueError("another moderator action already owns this case")
            await self._case_review_rerender_safely(case_id)
            now = datetime.now(timezone.utc)
            if operation.status.value == "failed" and operation.retry_at is not None:
                now = max(now, operation.retry_at)
            claimed = await asyncio.to_thread(
                self._case_store.claim_operation, operation.operation_id, now
            )
            if claimed is not None:
                await self._execute_detection_case_operation(claimed, now)
            snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
            persisted = next(
                (
                    item
                    for item in snapshot.operations
                    if item.operation_id == operation.operation_id
                ),
                None,
            )
            if persisted is None:
                if snapshot.case.status.value in {"resolved", "expired"}:
                    return True
                raise ValueError("moderator action result is unavailable")
            if persisted.status.value != "succeeded":
                await self._case_review_rerender_safely(case_id)
                raise ValueError(persisted.last_error or "moderator action failed")
            return True
        except (KeyError, ValueError) as error:
            await self._case_review_error(interaction, str(error))
            return False

    async def _case_review_attachment_interaction(
        self, interaction: discord.Interaction, key: AttachmentKey, action: str
    ) -> None:
        if not self._case_review_has_permission(interaction):
            await self._case_review_error(interaction, _("You do not have permission to review this case."))
            return
        await interaction.response.defer()
        try:
            await self._case_review_service.apply_individual(key, action, interaction.user.id)
            await self._finish_case_review_if_ready(key.case_id, interaction.user.id)
            await self._case_review_rerender_if_open(key.case_id)
        except (KeyError, ValueError) as error:
            await self._case_review_error(interaction, str(error))

    async def _case_review_individual_prompt(
        self,
        interaction: discord.Interaction,
        case_id: str,
        *,
        message_sequence: int | None = None,
    ) -> None:
        if not self._case_review_has_permission(interaction):
            await self._case_review_error(interaction, _("You do not have permission to review this case."))
            return
        snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
        feedback_items = tuple(
            item
            for item in case_feedback_items(snapshot)
            if item.decision is None
            and (
                message_sequence is None
                or item.message_sequence == message_sequence
            )
        )
        if not feedback_items:
            await self._case_review_error(
                interaction, _("No unresolved image evidence remains.")
            )
            return
        await interaction.response.send_message(
            _("Choose an image to review."),
            view=DetectionIndividualView(self, feedback_items),
            ephemeral=True,
        )


    async def _process_detected_message(
        self,
        message: discord.Message,
        config: dict,
        logs_channel: discord.TextChannel | discord.Thread | None,
        signals: tuple[DetectionSignal, ...],
        *,
        timings: dict[str, float] | None = None,
        admission_lock: asyncio.Lock | None = None,
    ) -> None:
        timings = timings if timings is not None else {}
        signals = self._resolve_unavailable_review_signals(config, signals)
        role_id = config.get("mute_role")

        def initial_operations(owned_signals):
            action = effective_action(owned_signals)
            whitelist_bypass = bool(owned_signals) and all(
                signal.metadata.get("whitelist_bypass") for signal in owned_signals
            )
            publish_review = config.get("review_enabled", True) and not whitelist_bypass
            containment = any(
                signal.action != ActionIntent.NONE
                or (
                    signal.detector == "honeypot"
                    and not signal.metadata.get("whitelist_bypass")
                )
                or signal.metadata.get("containment_required")
                for signal in owned_signals
            )
            operations = []
            if publish_review:
                operations.append(
                    ("review_publish", "review_publish:{case_id}:{sequence}")
                )
            if containment or message.attachments:
                operations.append(
                    ("message_process", "message-process:{case_id}:{sequence}")
                )
            if action in {ActionIntent.KICK, ActionIntent.BAN}:
                operations.append(
                    (
                        "moderation_action",
                        f"moderation_action:{{case_id}}:{{sequence}}:{action.value}",
                    )
                )
            if (
                role_id is not None
                and action is ActionIntent.REVIEW
                and not config.get("dry_run")
            ):
                operations.append(
                    ("role_apply", f"role-apply:{{case_id}}:{int(role_id)}")
                )
            return tuple(operations)

        tracking_firstpost = config.get("firstpost_enabled", False) or config.get(
            "firstpost_collect_enabled", False
        )
        admission_started = perf_counter()
        try:
            append = await asyncio.to_thread(
                self._case_store.append_message,
                self._new_case_message(message),
                signals,
                initial_operations,
                claim_firstpost=tracking_firstpost,
            )
        finally:
            if admission_lock is not None:
                admission_lock.release()
        timings["admission_ms"] = (perf_counter() - admission_started) * 1000
        if append is None:
            self._firstpost_seen_authors[message.guild.id].add(message.author.id)
            return
        if tracking_firstpost:
            self._firstpost_seen_authors[message.guild.id].add(message.author.id)
            if append.firstpost_claimed:
                self._firstpost_dirty_seen_authors[message.guild.id].add(
                    message.author.id
                )
                await self._increment_stat(message.guild, "firstpost_seen")
        admitted_snapshot = await asyncio.to_thread(
            self._case_store.get_case, append.case.case_id
        )
        persisted_signals = tuple(
            item.signal
            for item in admitted_snapshot.signals
            if item.message_sequence == append.message.sequence
        )
        if append.message_created:
            await self._record_detection_stats(message.guild, persisted_signals)
        if append.message_created and any(
            signal.metadata.get("whitelist_bypass") for signal in persisted_signals
        ):
            await self._increment_stat(message.guild, "whitelisted")
        durable_operations = initial_operations(persisted_signals)
        if not append.message_created:
            for operation_type, idempotency_key in durable_operations:
                await asyncio.to_thread(
                    self._case_store.ensure_operation,
                    append.case.case_id,
                    operation_type,
                    idempotency_key.format(
                        case_id=append.case.case_id,
                        sequence=append.message.sequence,
                    ),
                    append.message.sequence,
                )
            admitted_snapshot = await asyncio.to_thread(
                self._case_store.get_case, append.case.case_id
            )
        pipeline_operation = next(
            (
                operation
                for operation in admitted_snapshot.operations
                if operation.operation_type == "message_process"
                and operation.message_sequence == append.message.sequence
            ),
            None,
        )
        pipeline_claim = (
            await asyncio.to_thread(
                self._case_store.claim_operation,
                pipeline_operation.operation_id,
                datetime.now(timezone.utc),
            )
            if pipeline_operation is not None
            else None
        )
        if pipeline_operation is not None:
            if pipeline_claim is None:
                if (
                    not append.message_created
                    and pipeline_operation.status.value == "succeeded"
                ):
                    for child_type in (
                        "moderation_action",
                        "role_apply",
                        "review_publish",
                    ):
                        await self._execute_detection_message_child(
                            admitted_snapshot,
                            child_type,
                            append.message.sequence,
                            datetime.now(timezone.utc),
                            publication_channel=logs_channel,
                        )
                    if any(
                        operation.operation_type == "review_publish"
                        and operation.message_sequence == append.message.sequence
                        for operation in admitted_snapshot.operations
                    ):
                        await self._publish_detection_case(
                            append.case.case_id, config, logs_channel
                        )
                return
            await self._execute_detection_case_operation(
                pipeline_claim,
                datetime.now(timezone.utc),
                publication_channel=logs_channel,
                live_message=message,
                timings=timings,
            )
            return

        review_operation = next(
            (
                operation
                for operation in admitted_snapshot.operations
                if operation.operation_type == "review_publish"
                and operation.message_sequence == append.message.sequence
            ),
            None,
        )
        if review_operation is not None:
            review_claim = await asyncio.to_thread(
                self._case_store.claim_operation,
                review_operation.operation_id,
                datetime.now(timezone.utc),
            )
            if review_claim is not None:
                await self._execute_detection_case_operation(
                    review_claim,
                    datetime.now(timezone.utc),
                    publication_channel=logs_channel,
                )
            elif (
                not append.message_created
                and review_operation.status.value == "succeeded"
            ):
                await self._publish_detection_case(
                    append.case.case_id, config, logs_channel
                )
        return
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
            await self._record_operational_failure(
                guild.id,
                "cached_message_deletion",
                f"{type(exc).__name__}: {exc}",
            )
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
        deleted = 0
        for ref in refs:
            if exclude_message_id is not None and ref.message_id == exclude_message_id:
                continue
            if await self._delete_cached_message_ref(guild, user_id, ref):
                deleted += 1
        return deleted

    async def _cached_purge_user_messages(
        self,
        guild: discord.Guild,
        user_id: int,
        config: dict,
        *,
        exclude_message_id: int | None = None,
    ) -> int:
        deleted = await self._delete_recent_cached_user_messages(
            guild,
            user_id,
            exclude_message_id=exclude_message_id,
            retention_seconds=self._purge_retention_seconds(config),
        )
        self._activate_forward_purge(guild.id, user_id, config)
        return deleted

    def _schedule_post_ban_sweep(self, guild: discord.Guild, user_id: int) -> None:
        """After a ban, delete recent cached messages that Discord may have missed."""
        task = self.bot.loop.create_task(
            self._post_ban_message_sweep(guild.id, user_id),
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
        except Exception as error:
            await self._record_operational_failure(
                guild_id,
                "post_ban_cached_purge",
                f"{type(error).__name__}: {error}",
            )
            log.exception(
                "Post-ban cached message purge failed for user %s in guild %s",
                user_id,
                guild_id,
            )


    async def _purge_detection_case_cached_messages(
        self,
        guild: discord.Guild,
        user_id: int,
        config: dict,
        case_id: str,
        message_sequence: int,
        *,
        exclude_message_id: int | None = None,
    ) -> int:
        retention_seconds = self._purge_retention_seconds(config)
        self._prune_recent_user_messages(
            guild.id, user_id, retention_seconds=retention_seconds
        )
        refs = tuple(self._recent_user_messages.get(guild.id, {}).get(user_id, ()))
        deleted = 0
        for ref in refs:
            if exclude_message_id is not None and ref.message_id == exclude_message_id:
                continue
            operation = await asyncio.to_thread(
                self._case_store.ensure_operation,
                case_id,
                "cached_purge",
                f"cached_purge:{case_id}:{ref.channel_id}:{ref.message_id}",
                message_sequence,
            )
            was_deleted = (
                operation.status.value == "succeeded"
                and operation.result == DeleteStatus.DELETED.value
            )
            now = datetime.now(timezone.utc)
            if operation.status.value == "failed" and operation.retry_at is not None:
                now = max(now, operation.retry_at)
            claimed = await asyncio.to_thread(
                self._case_store.claim_operation, operation.operation_id, now
            )
            if claimed is not None:
                if config.get("dry_run"):
                    await asyncio.to_thread(
                        self._case_store.complete_operation,
                        claimed.operation_id,
                        claimed.claim_token,
                        now,
                        "planned",
                    )
                else:
                    await self._execute_detection_case_operation(claimed, now)
            snapshot = await asyncio.to_thread(self._case_store.get_case, case_id)
            persisted = next(
                item
                for item in snapshot.operations
                if item.operation_id == operation.operation_id
            )
            if persisted.result == DeleteStatus.DELETED.value and not was_deleted:
                deleted += 1
        if not config.get("dry_run"):
            self._activate_forward_purge(guild.id, user_id, config)
        return deleted

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



    async def _execute_action(
        self,
        guild: discord.Guild,
        member: discord.Member | discord.User | discord.Object,
        created_at: datetime,
        config: dict,
        reason: str,
        action: str | None = None,
        moderator: discord.Member | discord.User | discord.Object | None = None,
    ) -> tuple[str | None, str | None]:
        """Execute the configured action (kick/ban) against a guild member.
        Returns (action_label, failed_message) where failed_message is None on success.
        """
        action = action or config["action"]
        if action not in ("kick", "ban"):
            return (_("No action configured."), None)
        if config.get("dry_run"):
            await self._increment_stat(guild, "dry_run_actions")
            return (self._dry_run_label(action), None)
        missing_permission = self._missing_action_permission(guild, action)
        if missing_permission is not None:
            await self._increment_stat(guild, "failed_actions")
            return (None, missing_permission)
        try:
            if action == "kick":
                self._activate_forward_purge(guild.id, member.id, config)
                try:
                    await member.kick(reason=reason)
                except discord.NotFound:
                    if self._automated_kick_fail_warning_enabled(config):
                        self._deactivate_forward_purge(guild.id, member.id)
                        return await self._create_kick_fail_warning(guild, member.id)
                    raise
                await self._increment_stat(guild, "kicked")
            elif action == "ban":
                self._activate_forward_purge(guild.id, member.id, config)
                delete_message_seconds = self._ban_delete_message_seconds(config)
                member_ban = getattr(member, "ban", None)
                if callable(member_ban):
                    await member_ban(
                        reason=reason,
                        delete_message_seconds=delete_message_seconds,
                    )
                else:
                    await guild.ban(
                        member,
                        reason=reason,
                        delete_message_seconds=delete_message_seconds,
                    )
                self._schedule_post_ban_sweep(guild, member.id)
                await self._increment_stat(guild, "banned")
        except discord.HTTPException as e:
            self._deactivate_forward_purge(guild.id, member.id)
            await self._increment_stat(guild, "failed_actions")
            return (None, _("**Action failed:**\n") + box(str(e), lang="py"))
        try:
            await modlog.create_case(
                self.bot,
                guild,
                created_at,
                action_type=action,
                user=member,
                moderator=moderator or guild.me,
                reason=reason,
            )
        except Exception:
            log.exception("Failed to create modlog case in _execute_action")
        label = _("The member has been kicked.") if action == "kick" else _("The member has been banned.")
        return (label, None)











    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None:
            return
        if message.author.bot:
            return
        if message.webhook_id is not None:
            return
        lock_index = (
            message.guild.id * 31 + message.author.id
        ) % len(self._detection_admission_locks)
        batch_key = (message.guild.id, message.id)
        pipeline_started = perf_counter()
        admission_lock = self._detection_admission_locks[lock_index]
        admission_lock_owned = False
        try:
            await admission_lock.acquire()
            admission_lock_owned = True
            try:
                queue_wait_ms = (perf_counter() - pipeline_started) * 1000
                if await self.bot.cog_disabled_in_guild(self, message.guild):
                    return
                config = await self.config.guild(message.guild).all()
                if not config["enabled"]:
                    return
                logs_channel = self._get_text_channel_or_thread(
                    message.guild, config.get("logs_channel")
                )
                if await self._is_protected_member(message.author, message.guild):
                    return
                self._record_recent_user_message(message, config)
                signals_started = perf_counter()
                signals = await self._collect_detection_signals(message, config)
                timings = {
                    "queue_wait_ms": queue_wait_ms,
                    "signals_ms": (perf_counter() - signals_started) * 1000,
                }
                if not signals:
                    return
                admission_lock_owned = False
                await self._process_detected_message(
                    message,
                    config,
                    logs_channel,
                    signals,
                    timings=timings,
                    admission_lock=admission_lock,
                )
            finally:
                if admission_lock_owned:
                    admission_lock.release()
        finally:
            self._initial_image_scan_batches.pop(batch_key, None)
        return


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
                            except discord.HTTPException as exc:
                                log.debug(
                                    "Failed to send joinwatch missing-member log for user %s in guild %s",
                                    member_id,
                                    guild.id,
                                )
                                await self._record_operational_failure(
                                    guild.id,
                                    "joinwatch_timer_alert",
                                    f"Could not publish timer result for user {member_id}: {exc}",
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
                            except discord.HTTPException as exc:
                                log.debug(
                                    "Failed to send joinwatch missing-member log for user %s in guild %s",
                                    member_id,
                                    guild.id,
                                )
                                await self._record_operational_failure(
                                    guild.id,
                                    "joinwatch_timer_alert",
                                    f"Could not publish timer result for user {member_id}: {exc}",
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
                        except discord.HTTPException as exc:
                            log.debug("Failed to send joinwatch auto-role log for user %s in guild %s", member.id, guild.id)
                            await self._record_operational_failure(
                                guild.id,
                                "joinwatch_timer_alert",
                                f"Could not publish timer result for user {member.id}: {exc}",
                            )
            except Exception as exc:
                log.exception("Failed to process joinwatch auto-role timers for guild %s", guild.id)
                await self._record_operational_failure(
                    guild.id,
                    "joinwatch_timer_processing",
                    f"Could not process joinwatch timers: {exc}",
                )

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
                        await self._record_operational_failure(
                            member.guild.id,
                            "joinwatch_role_assignment",
                            role_permission_error,
                            terminal=True,
                        )
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
                            except discord.HTTPException as exc:
                                await self._increment_stat(member.guild, "joinwatch_auto_role_failures")
                                await self._record_operational_failure(
                                    member.guild.id,
                                    "joinwatch_role_assignment",
                                    f"Could not apply auto-role to user {member.id}: {exc}",
                                    terminal=True,
                                )
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
                except discord.HTTPException as exc:
                    log.debug("Failed to send joinwatch alert for user %s in guild %s", member.id, member.guild.id)
                    await self._record_operational_failure(
                        member.guild.id,
                        "joinwatch_alert_publish",
                        f"Could not publish joinwatch alert for user {member.id}: {exc}",
                        terminal=True,
                    )

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
            except discord.HTTPException as exc:
                log.warning("Failed to %s bait-role target %s in guild %s", action, after.id, after.guild.id)
                await self._record_operational_failure(
                    after.guild.id,
                    "bait_role_action",
                    f"Could not {action} bait-role target {after.id}: {exc}",
                    terminal=True,
                )
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
                except discord.HTTPException as exc:
                    log.debug("Failed to send bait role log for user %s in guild %s", after.id, after.guild.id)
                    await self._record_operational_failure(
                        after.guild.id,
                        "bait_role_alert",
                        f"Could not publish bait-role alert for user {after.id}: {exc}",
                        terminal=True,
                    )

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


    @staticmethod
    def _imagescan_safe_filename(filename: str | None, index: int) -> str:
        fallback = f"image-{index}.jpg"
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", filename or fallback).strip("._")
        return safe or fallback












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

    @commands.command(name="consoledump")
    @commands.guild_only()
    async def console_dump(
        self,
        ctx: commands.Context,
        scope: str | None = None,
        hours: str | None = None,
        level: str | None = None,
    ) -> None:
        """Export recent sanitized Python logs to a private text channel."""
        channel = ctx.channel
        if not isinstance(channel, discord.TextChannel):
            await ctx.send(_("Console dumps require a private text channel."))
            return
        if not channel.permissions_for(ctx.author).manage_messages:
            await ctx.send(_("You need Manage Messages to use this command."))
            return
        if channel.permissions_for(ctx.guild.default_role).view_channel:
            await ctx.send(
                _("Console dumps cannot be sent to a channel visible to @everyone.")
            )
            return
        missing_permissions = self._missing_channel_permissions(
            ctx.guild,
            channel,
            attach_files=True,
        )
        if missing_permissions is not None:
            await ctx.send(missing_permissions)
            return

        normalized_scope = scope.casefold() if scope is not None else None
        normalized_level = level.casefold() if level is not None else None
        try:
            parsed_hours = int(hours) if hours is not None else None
        except ValueError:
            parsed_hours = None
        levels = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        if (
            normalized_scope not in {"bot", "honeypot"}
            or parsed_hours is None
            or not 1 <= parsed_hours <= 24
            or (normalized_level is not None and normalized_level not in levels)
        ):
            await ctx.send(CONSOLE_DUMP_USAGE)
            return

        dump = build_log_dump(
            self._console_log_buffer.snapshot(),
            scope=normalized_scope,
            hours=parsed_hours,
            minimum_level=levels.get(normalized_level),
            upload_limit=int(ctx.guild.filesize_limit),
            now=datetime.now(timezone.utc),
        )
        await ctx.send(
            file=discord.File(io.BytesIO(dump.content), filename=dump.filename),
            allowed_mentions=discord.AllowedMentions.none(),
        )

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
            send_messages=False,
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
    async def logs(self, ctx: commands.Context, target: discord.TextChannel = None) -> None:
        """Set the channel used for honeypot logs."""
        if target is None:
            v = await self.config.guild(ctx.guild).logs_channel()
            await ctx.send(_("Logs channel: {channel}").format(channel=ctx.guild.get_channel(v) if v else _("not set")))
        else:
            if not isinstance(target, discord.TextChannel):
                raise commands.UserFeedbackCheckFailure(
                    _("The logs channel must be a normal text channel.")
                )
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
    async def review_channel(
        self, ctx: commands.Context, target: discord.TextChannel = None
    ) -> None:
        """Set the channel for moderator review requests."""
        if target is None:
            v = await self.config.guild(ctx.guild).review_channel()
            await ctx.send(_("Review channel: {channel}").format(channel=ctx.guild.get_channel(v) if v else _("not set")))
        else:
            if not isinstance(target, discord.TextChannel):
                raise commands.UserFeedbackCheckFailure(
                    _("The review destination must be a normal text channel.")
                )
            missing = self._missing_channel_permissions(
                ctx.guild,
                target,
                read_history=True,
                create_public_threads=True,
                send_in_threads=True,
                embed_links=True,
                attach_files=True,
                manage_threads=True,
            )
            if missing is not None:
                raise commands.UserFeedbackCheckFailure(missing)
            await self.config.guild(ctx.guild).review_channel.set(target.id)
            await ctx.send(_("✅ Review channel set to {channel.mention}").format(channel=target))

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
            is_thread = isinstance(target, discord.Thread)
            missing = self._missing_channel_permissions(
                ctx.guild,
                target,
                send_messages=not is_thread,
                send_in_threads=is_thread,
            )
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
                (_("Case lifetime"), _("24 hours (fixed)")),
                (_("Kick fail warning"), config.get("review_kick_fail_warning", "false")),
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
        now = datetime.now(timezone.utc)
        case_counts = await asyncio.to_thread(
            self._case_store.operational_counts,
            ctx.guild.id,
            now,
            now - timedelta(minutes=5),
        )
        await self._send_config_dump(
            ctx,
            _("Stats config"),
            [
                (_("Stored stats"), len(stats)),
                (_("Pending joinwatch role applications"), len(config.get("joinwatch_pending_role_assignments", {}))),
                (_("Active joinwatch auto-role timers"), len(config.get("joinwatch_pending_roles", {}))),
                (_("Active detection cases"), case_counts["active_cases"]),
                (_("Due detection cases"), case_counts["due_cases"]),
                (_("Stale resolving cases"), case_counts["stale_resolving_cases"]),
                (_("Failed containment cases"), case_counts["failed_containment"]),
                (_("Forbidden message deletes"), case_counts["forbidden_deletes"]),
                (_("Outstanding durable operations"), case_counts["outstanding_operations"]),
                (_("Queued privacy deletions"), case_counts["privacy_deletion_jobs"]),
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
                (_("Pending joinwatch role applications"), len(config.get("joinwatch_pending_role_assignments", {}))),
                (_("Active joinwatch auto-role timers"), len(config.get("joinwatch_pending_roles", {}))),
            ],
        )

    @honeypot.group(name="errors", invoke_without_command=True)
    async def honeypot_errors(self, ctx: commands.Context) -> None:
        """Show unacknowledged Honeypot operational failures."""
        failures = await asyncio.to_thread(
            self._case_store.list_operational_failures,
            ctx.guild.id,
            include_resolved=True,
        )
        if not failures:
            await ctx.send(_("No unacknowledged Honeypot errors."))
            return
        lines = []
        for failure in failures:
            state = "recovered" if failure.resolved_at is not None else "active"
            lines.append(
                f"- <t:{int(failure.last_seen_at.timestamp())}:R> "
                f"`{failure.source}` ({state}, x{failure.occurrences}): "
                f"{failure.summary[:500]}"
            )
        body = "\n".join(lines)
        header = _("**Honeypot operational errors:**\n")
        for page in pagify(body, page_length=2000 - len(header)):
            await ctx.send(header + page)

    @honeypot_errors.command(name="clear")
    async def honeypot_errors_clear(self, ctx: commands.Context) -> None:
        """Acknowledge all currently visible Honeypot operational failures."""
        count = await asyncio.to_thread(
            self._case_store.clear_operational_failures,
            ctx.guild.id,
            datetime.now(timezone.utc),
        )
        await ctx.send(_("Acknowledged {count} Honeypot errors.").format(count=count))

    # ─── stats ────────────────────────────────────────────────────────

    @honeypot.command(name="modstats")
    async def honeypot_mod_stats(self, ctx: commands.Context) -> None:
        """Show detailed moderation statistics."""
        stats = DEFAULT_STATS.copy()
        stats.update(await self.config.guild(ctx.guild).stats())
        pending_joinwatch_assignments = await self.config.guild(ctx.guild).joinwatch_pending_role_assignments()
        pending_joinwatch_roles = await self.config.guild(ctx.guild).joinwatch_pending_roles()
        now = datetime.now(timezone.utc)
        case_counts = await asyncio.to_thread(
            self._case_store.operational_counts,
            ctx.guild.id,
            now,
            now - timedelta(minutes=5),
        )
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
                "Forward purge delete failures": stats["forward_purge_delete_failures"],
                "Evidence capture failures": stats["evidence_capture_failures"],
                "Active detection cases": case_counts["active_cases"],
                "Due detection cases": case_counts["due_cases"],
                "Stale resolving cases": case_counts["stale_resolving_cases"],
                "Failed containment cases": case_counts["failed_containment"],
                "Forbidden message deletes": case_counts["forbidden_deletes"],
                "Outstanding durable operations": case_counts["outstanding_operations"],
                "Queued privacy deletions": case_counts["privacy_deletion_jobs"],
            },
            "Firstpost": {
                "Firstpost seen": stats["firstpost_seen"],
                "Firstpost hits": stats["firstpost_hits"],
                "Firstpost reviews": stats["firstpost_reviews"],
                "Firstpost kicks": stats["firstpost_kicks"],
                "Firstpost bans": stats["firstpost_bans"],
                "Early catches": stats["early_catches"],
            },
            "Honeypot": {
                "Honeypot hits": stats["honeypot_hits"],
                "Honeypot reviews": stats["honeypot_reviews"],
                "Honeypot kicks": stats["honeypot_kicks"],
                "Honeypot bans": stats["honeypot_bans"],
                "Honeypot catches": stats["honeypot_catches"],
            },
            "Spam": {
                "Spam hits": stats["spam_hits"],
                "Spam reviews": stats["spam_reviews"],
                "Spam kicks": stats["spam_kicks"],
                "Spam bans": stats["spam_bans"],
                "Spam catches": stats["spam_catches"],
            },
            "Image detection": {
                "Image hits": stats["image_hits"],
                "Image reviews": stats["image_reviews"],
                "Image kicks": stats["image_kicks"],
                "Image bans": stats["image_bans"],
                "Image catches": stats["image_catches"],
            },
            "Review": {
                "Reviews sent": stats["reviewed"],
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
        detected_activity = stats["detections"]
        moderation_actions = stats["kicked"] + stats["banned"]
        automated_protections = (
            stats["joinwatch_auto_roles"]
            + stats["joinwatch_auto_role_punishments"]
        )
        lines = [
            f"  {_('Detected activity')}: {detected_activity}",
            f"  {_('Moderation actions')}: {moderation_actions}",
            f"  {_('Sent for review')}: {stats['reviewed']}",
            f"  {_('Automated protections')}: {automated_protections}",
        ]
        await ctx.send(_("**Server safety stats:**\n") + box("\n".join(lines)))

    @debug.command(name="resetstats")
    @commands.permissions_check(lambda ctx: ctx.author.id == ctx.guild.owner_id or ctx.author.id in ctx.bot.owner_ids)
    async def honeypot_reset_stats(self, ctx: commands.Context) -> None:
        """Reset stored honeypot statistics."""
        await self.config.guild(ctx.guild).stats.set(DEFAULT_STATS.copy())
        await ctx.send(_("✅ Stats reset."))

    def _verify_detection_case_evidence_directory(self) -> None:
        probe_path: Path | None = None
        probe_error: OSError | None = None
        try:
            self._detection_case_files_path.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                dir=self._detection_case_files_path,
                prefix=".doctor-",
                delete=False,
            ) as probe:
                probe_path = Path(probe.name)
                probe.write(b"ok")
            if probe_path.read_bytes() != b"ok":
                raise OSError("evidence directory read/write check failed")
        except OSError as error:
            probe_error = error
        finally:
            if probe_path is not None:
                try:
                    probe_path.unlink(missing_ok=True)
                except OSError as cleanup_error:
                    if probe_error is None:
                        probe_error = cleanup_error
        if probe_error is not None:
            raise probe_error

    @honeypot.command(name="doctor")
    async def honeypot_doctor(self, ctx: commands.Context) -> None:
        """Check honeypot configuration and required permissions."""
        config = await self.config.guild(ctx.guild).all()
        checks: list[tuple[str, bool, str]] = []
        warnings: list[str] = []
        case_database_ok = True
        try:
            await asyncio.to_thread(self._case_store.verify_read_write)
        except (OSError, sqlite3.Error) as error:
            case_database_ok = False
            checks.append(
                ("Detection case database", False, f"Read/write check failed: {error}")
            )
        try:
            await asyncio.to_thread(self._verify_detection_case_evidence_directory)
        except OSError as error:
            checks.append(
                (
                    "Detection case evidence directory",
                    False,
                    f"Read/write check failed: {error}",
                )
            )
        if case_database_ok:
            now = datetime.now(timezone.utc)
            operational_failures = await asyncio.to_thread(
                self._case_store.list_operational_failures,
                ctx.guild.id,
            )
            if operational_failures:
                oldest = min(item.first_seen_at for item in operational_failures)
                checks.append(
                    (
                        f"Active operational failures: {len(operational_failures)}",
                        False,
                        f"Oldest: <t:{int(oldest.timestamp())}:R>. "
                        "Run `honeypot errors`.",
                    )
                )
            case_counts = await asyncio.to_thread(
                self._case_store.operational_counts,
                ctx.guild.id,
                now,
                now - timedelta(minutes=5),
            )
            checks.extend(
                check
                for check in (
                    (
                        f"Due detection cases: {case_counts['due_cases']}",
                        case_counts["due_cases"] == 0,
                        "Run detection case reconciliation.",
                    ),
                    (
                        f"Stale resolving cases: {case_counts['stale_resolving_cases']}",
                        case_counts["stale_resolving_cases"] == 0,
                        "Run detection case reconciliation.",
                    ),
                    (
                        f"Failed containment cases: {case_counts['failed_containment']}",
                        case_counts["failed_containment"] == 0,
                        "Inspect moderation case delete failures.",
                    ),
                )
                if not check[1]
            )
        me = ctx.guild.me
        if me is None:
            await ctx.send(_("**Honeypot doctor:**\n❌ I couldn't find my server member."))
            return
        honeypot_channels = [
            channel
            for channel_id in self._honeypot_channel_ids_from_config(config)
            if (channel := self._get_text_channel_or_thread(ctx.guild, channel_id)) is not None
        ]
        logs_channel_id = config.get("logs_channel")
        configured_logs_channel = (
            self._get_cached_message_channel(ctx.guild, logs_channel_id)
            if isinstance(logs_channel_id, int)
            else None
        )
        logs_channel = (
            configured_logs_channel
            if isinstance(configured_logs_channel, discord.TextChannel)
            else None
        )
        logs_channel_invalid = (
            configured_logs_channel is not None and logs_channel is None
        )
        review_channel = self._get_text_channel_or_thread(ctx.guild, config.get("review_channel"))
        if not config.get("enabled"):
            warnings.append("⚠️ Honeypot is disabled.")
        if config.get("action") not in CORE_ACTION_OPTIONS:
            checks.append(("Honeypot action is invalid", False, "Run `honeypot honeypot action`."))
        if config.get("firstpost_action", "review") not in CORE_ACTION_OPTIONS:
            checks.append(("Firstpost action is invalid", False, "Run `honeypot firstpost action`."))
        if config.get("spam_action", "review") not in CORE_ACTION_OPTIONS:
            checks.append(("Spam action is invalid", False, "Run `honeypot spam action`."))
        if config.get("enabled") and not honeypot_channels:
            checks.append(("No honeypot channel exists", False, "Run `honeypot channel add`."))
        if logs_channel_invalid:
            checks.append(
                (
                    "Logs channel must be a normal text channel",
                    False,
                    "Run `honeypot channel logs` with a normal text channel.",
                )
            )
        if config.get("enabled") and logs_channel is None and not logs_channel_invalid:
            checks.append(("Logs channel is missing", False, "Run `honeypot channel logs`."))
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
            if review_channel is None:
                checks.append(("Review channel is missing", False, "Run `honeypot review channel`."))
        if config.get("mute_role"):
            mute_role = ctx.guild.get_role(config["mute_role"])
            if mute_role is None:
                checks.append(("Mute role is missing", False, "Run `honeypot punishment mute_role`."))
            if mute_role is not None:
                if not me.top_role > mute_role:
                    checks.append(("Bot is not above mute role", False, "Move bot role above mute role."))
        if config.get("joinwatch_auto_role_enabled"):
            auto_role_id = config.get("joinwatch_auto_role_id")
            auto_role = ctx.guild.get_role(auto_role_id) if auto_role_id else None
            if auto_role is None:
                checks.append(("Joinwatch auto-role is missing", False, "Run `honeypot joinwatch autorole role`."))
            if auto_role is not None:
                if not me.top_role > auto_role:
                    checks.append(("Bot is not above joinwatch auto-role", False, "Move bot role above the joinwatch auto-role."))
        if config.get("joinwatch_enabled") and config.get("joinwatch_alert_enabled", True):
            joinwatch_channel = self._get_text_channel_or_thread(ctx.guild, config.get("joinwatch_channel"))
            if joinwatch_channel is None:
                checks.append(("Joinwatch alert channel is missing", False, "Run `honeypot joinwatch channel`."))
            if joinwatch_channel is not None:
                perms = joinwatch_channel.permissions_for(me)
                send_permission = (
                    "send_messages_in_threads"
                    if isinstance(joinwatch_channel, discord.Thread)
                    else "send_messages"
                )
                if not getattr(perms, send_permission, False):
                    permission_label = (
                        "Send Messages in Threads"
                        if send_permission == "send_messages_in_threads"
                        else "Send Messages"
                    )
                    checks.append(
                        (
                            "Cannot send joinwatch alerts",
                            False,
                            f"Grant {permission_label}.",
                        )
                    )
        for honeypot_channel in honeypot_channels:
            perms = honeypot_channel.permissions_for(me)
            missing_permissions = missing_purge_permissions(perms)
            if missing_permissions:
                checks.append(
                    (
                        f"{honeypot_channel} permissions",
                        False,
                        "Missing: " + ", ".join(missing_permissions),
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
            checks.append(
                (
                    "Cached purge can delete visible message channels",
                    False,
                    "\nManage - " + ", ".join(skipped_channels),
                )
            )
        if logs_channel is not None:
            perms = logs_channel.permissions_for(me)
            if not perms.send_messages:
                checks.append(("Cannot send logs", False, "Grant Send Messages."))
        case_destination = review_channel or logs_channel
        if case_destination is not None:
            perms = case_destination.permissions_for(me)
            destination_label = (
                "Review channel" if review_channel is not None else "Logs channel"
            )
            required = (
                ("view_channel", "View Channel"),
                ("send_messages", "Send Messages"),
                ("create_public_threads", "Create Public Threads"),
                ("send_messages_in_threads", "Send Messages in Threads"),
                ("read_message_history", "Read Message History"),
                ("embed_links", "Embed Links"),
                ("attach_files", "Attach Files"),
                ("manage_threads", "Manage Threads"),
            )
            missing = [
                label for attribute, label in required if not getattr(perms, attribute, False)
            ]
            if not isinstance(case_destination, discord.TextChannel) or missing:
                checks.append(
                    (
                        f"{destination_label} cannot host case threads",
                        False,
                        (
                            "Use a normal text channel."
                            if not isinstance(case_destination, discord.TextChannel)
                            else "Grant: " + ", ".join(missing)
                        ),
                    )
                )
        guild_perms = me.guild_permissions
        configured_actions = {
            config.get("action"),
            config.get("fallback_action"),
            config.get("firstpost_action"),
            config.get("spam_action"),
            config.get("imagescan_detector_action"),
        }
        if "kick" in configured_actions and not guild_perms.kick_members:
            checks.append(("Cannot kick members", False, "Grant Kick Members."))
        if "ban" in configured_actions and not guild_perms.ban_members:
            checks.append(("Cannot ban members", False, "Grant Ban Members."))
        if (config.get("mute_role") or config.get("joinwatch_auto_role_enabled")) and not guild_perms.manage_roles:
            checks.append(("Cannot manage configured roles", False, "Grant Manage Roles."))
        failed = [
            f"❌ {name}{hint}" if hint.startswith("\n") else f"❌ {name} - {hint}"
            for name, ok, hint in checks
            if not ok
        ]
        header = _("**Honeypot doctor:**\n")
        findings = failed + warnings
        body = "\n".join(findings) if findings else "✅ No configuration or runtime problems found."
        for page in pagify(body, page_length=2000 - len(header)):
            await ctx.send(header + page)
