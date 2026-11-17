from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import re
import time
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from datetime import time as datetime_time
from typing import TypeVar
from uuid import uuid4

import aiohttp
import discord
from redbot.core import commands
from redbot.core.data_manager import cog_data_path

from NHCogs.gateway_capabilities import GatewayCapabilityUnavailable, require

from ..command_overview import send_group_overview
from ..operational_errors import OperationalFailure
from ..operational_support import NHMISC_CONFIG_IDENTIFIER, OperationalSupport
from ..ranked_donut_chart import OTHER_COLOR, SERIES_COLORS, render_ranked_donut_chart
from .achievement_definitions import (
    SOLO_GATER_DEFINITION,
    SOLO_GATER_KEY,
    STARGATE_COMPLETED_KEY,
)
from .achievement_store import (
    AchievementDefinition,
    AchievementProfile,
    AchievementStore,
    GateProofConflict,
    StargateProof,
    StargateProofAssignment,
)
from .achievement_sync import (
    DiscordRoleSnapshot,
    build_discord_priority_plan,
    build_discord_role_backup,
    build_discord_role_snapshot,
)
from .activity_storage import (
    ActivityConsistencyReport,
    ActivityDatabaseStats,
    ActivityLocation,
    ActivityStore,
    ChannelTimelineDay,
    ChannelUserCount,
    DailyDominantLocation,
    DailySummary,
    EmojiCount,
    EmojiInfo,
    TimelineDay,
    TopChannel,
    UserChannelDistribution,
    UserStats,
)
from .bot_proxy_store import BotProxyStore
from .discord_links import MESSAGE_LINK_PATTERN
from .forum_autopin import ForumAutopinService, ForumChannelConverter, is_forum_channel
from .gate_increment_store import (
    AchievementDefinitionConflict,
    GateIncrementAchievementPlan,
    GateIncrementBusy,
    GateIncrementMemberPlan,
    GateIncrementSnapshot,
    GateIncrementStore,
    GateProgressConflict,
    MemberState,
    OperationState,
    RecoveryAction,
    SourceMessageKey,
    classify_member_recovery,
)
from .gate_roles import (
    GATE_TIER_ROLE_IDS,
    SINGLEPLAYER_GATE_COMPLETED_ROLE_ID,
    build_role_ids_for_target,
    plan_gate_transition,
)
from .role_analytics_service import (
    FullMemberRequestCooldownError,
    MemberIntentRequiredError,
    RoleAnalyticsService,
    SyncAlreadyRunningError,
)
from .role_analytics_store import (
    AnalyticsUnavailableError,
    RoleAnalyticsStore,
    SyncStatus,
)
from .role_export import (
    ExportMember,
    ExportTooLarge,
    build_csv_export,
    build_role_export,
)
from .role_expression import (
    RoleExpressionSyntaxError,
    compile_role_expression,
    parse_role_expression,
    render_role_expression,
    role_ids,
)
from .runtime_health import task_health_issue
from .sticky_roles import StickyRoleStore
from .voice_activity import VoiceChannelVisitTracker

log = logging.getLogger("red.NHMisc")

_InteractionResult = TypeVar("_InteractionResult")

DEFAULT_VCJUMPING_VISIT_COUNT = 3
DEFAULT_VCJUMPING_WINDOW_SECONDS = 30
ACHIEVEMENT_INTERACTION_DB_TIMEOUT_SECONDS = 15
DEFAULT_ACTIVITY_DETAIL_RETENTION_DAYS = 31
DEFAULT_ACTIVITY_HISTORY_RETENTION_DAYS = -1
RETENTION_CONFIRMATION = "I understand"


def _parse_sticky_db_decision(content: str) -> tuple[str, int | None, str]:
    command, separator, remainder = content.strip().partition(" ")
    if not separator:
        return command.lower(), None, ""

    role_id_text, _, argument = remainder.strip().partition(" ")
    try:
        role_id = int(role_id_text)
    except ValueError:
        role_id = None
    return command.lower(), role_id, argument.strip()

DEFAULT_CHATCHART_USER_COUNT = 10
CUSTOM_EMOJI_PATTERN = re.compile(r"<a?:[^:>]+:(\d+)>")
MAX_EMOJI_ICON_BYTES = 128 * 1024
DISCORD_MESSAGE_CONTENT_LIMIT = 2_000
MAX_CHATCHART_USER_COUNT = 20
CHATCHART_SERIES_COLORS = SERIES_COLORS
CHATCHART_OTHER_COLOR = OTHER_COLOR
DISCORD_SNOWFLAKE_MIN_DIGITS = 15
STARGATE_EMOJI_NAME = "stargate"
STARGATE_EMOJI_ID = 769315278953381928
MAX_GATE_INCREMENT_CANDIDATES = 25
MAX_ACHIEVEMENT_RECIPIENTS = 25
TIER_DISTRIBUTION_ROLES = (
    ("Stone", "stoneTier", 757571320945967205, 757645112267243541),
    ("Steam", "steamTier", 757571510880829540, 757643319265460224),
    ("LV", "lvTier", 757571726790885378, 630848584539045926),
    ("MV", "mvTier", 757571761159012383, 631180331839389738),
    ("HV", "hvTier", 757571801961201714, 631180321727184896),
    ("EV", "evTier", 757571842209873991, 631180312906563594),
    ("IV", "ivTier", 757571883268046908, 631180295252738099),
    ("LuV", "luvTier", 757571961114066994, 631180266982866986),
    ("ZPM", "zpmTier", 757571992500305962, 631180246837624852),
    ("UV", "uvTier", 757572023269720078, 631180223928336414),
    ("UHV", "uhvTier", 757572062058643467, 631180193960296478),
    ("UEV", "uevTier", 888133083931476009, 631180158262575174),
    ("UIV", "uivTier", 888133292547772467, 631180143385247754),
    ("UMV", "umvTier", 888133377620852776, 631180120782012426),
    ("UXV", "uxvTier", 888133463461494864, 631180089782042625),
)


def _require_guild_role(
    guild,
    role_id: int,
    *,
    report_name: str,
    role_label: str,
):
    role = guild.get_role(role_id)
    if role is None:
        raise commands.UserFeedbackCheckFailure(
            f"{report_name} is misconfigured: {role_label} role "
            f"({role_id}) was not found in this server"
        )
    return role


@dataclass(frozen=True, slots=True)
class GateIncrementCandidate:
    user_id: int
    display_name: str
    current_gate_role_ids: tuple[int, ...]
    current_tier: int | None
    target_role_id: int | None
    target_ordinal: int | None = None
    highest_ordinal: int = 0
    has_solo_gater: bool = False
    previous_state: MemberState | None = None


ACHIEVEMENT_RETRY_SECONDS = 60 * 60


@dataclass
class _AchievementReconciliation:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    retry_at: int = 0
    task: asyncio.Task | None = None
    message: discord.Message | None = None


@dataclass(frozen=True, slots=True)
class ReconciliationSkip:
    user_id: int
    subject: str
    error: str


def _exception_label(error: BaseException) -> str:
    name = type(error).__name__
    detail = str(error).strip()
    if not detail or detail == name:
        return name
    return f"{name}: {detail}"


def _format_reconciliation_report(
    *,
    aborted: bool,
    corrected: int | None,
    skips: tuple[ReconciliationSkip, ...] | None,
    status_line: str,
) -> str:
    """Build a reconciliation notice, keeping skip lines inside Discord's limit."""
    skipped = "unknown" if skips is None else str(len(skips))
    corrected_text = "unknown" if corrected is None else str(corrected)
    lines = [
        f"Achievement role reconciliation {'failed' if aborted else 'complete'}",
        f"Members corrected: {corrected_text}",
        f"Members skipped: {skipped}",
    ]
    if skips:
        lines.append("Skipped:")
        for shown, skip in enumerate(skips):
            line = f"{skip.user_id} {skip.subject}: {skip.error}"
            used = sum(len(item) + 1 for item in lines)
            if shown >= 20 or used + len(line) > 1700:
                lines.append(f"and {len(skips) - shown} more")
                break
            lines.append(line)
    if status_line:
        lines.append(status_line)
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class GateProofCandidate:
    member: discord.Member
    missing_ordinals: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class GateProofBatchEntry:
    user_id: int | None
    ordinal: int
    source_guild_id: int
    source_channel_id: int
    source_message_id: int

    @property
    def jump_url(self) -> str:
        return (
            "https://discord.com/channels/"
            f"{self.source_guild_id}/{self.source_channel_id}/"
            f"{self.source_message_id}"
        )


_GATE_PROOF_BATCH_LINE = re.compile(
    r"([1-9]\d*) (https://discord\.com/channels/(\d+)/(\d+)/(\d+))"
    r"(?:[ \t]+(.*))?"
)
_GATE_PROOF_BATCH_TARGET = re.compile(r"(?:<@!?([1-9]\d*)>|([1-9]\d*))")


def _parse_gate_proof_targets(targets: str, *, line_number: int) -> tuple[int, ...]:
    user_ids = []
    position = 0
    while position < len(targets):
        while position < len(targets) and targets[position] in " \t":
            position += 1
        if position == len(targets):
            break
        match = _GATE_PROOF_BATCH_TARGET.match(targets, position)
        if match is None:
            raise ValueError(
                f"Gate proof batch line {line_number} must use: "
                "number space link optional user mentions or IDs"
            )
        user_ids.append(int(match.group(1) or match.group(2)))
        position = match.end()
    if not user_ids:
        raise ValueError(
            f"Gate proof batch line {line_number} must use: "
            "number space link optional user mentions or IDs"
        )
    return tuple(user_ids)


def _parse_gate_proof_batch(
    content: str,
    *,
    expected_guild_id: int,
) -> tuple[GateProofBatchEntry, ...] | None:
    lines = content.splitlines()
    if not lines or re.match(r"\d+ ", lines[0]) is None:
        return None

    entries = []
    assignments: set[tuple[int | None, int]] = set()
    for line_number, line in enumerate(lines, start=1):
        match = _GATE_PROOF_BATCH_LINE.fullmatch(line)
        if match is None:
            raise ValueError(
                f"Gate proof batch line {line_number} must use: "
                "number space link optional user mentions or IDs"
            )
        ordinal = int(match.group(1))
        source_guild_id = int(match.group(3))
        if source_guild_id != expected_guild_id:
            raise ValueError("Gate proof links must point to the current server")
        target_text = match.group(6)
        user_ids: tuple[int | None, ...] = (
            _parse_gate_proof_targets(target_text, line_number=line_number)
            if target_text is not None
            else (None,)
        )
        for user_id in user_ids:
            assignment = (user_id, ordinal)
            if assignment in assignments:
                target = f"<@{user_id}>" if user_id is not None else "the author"
                raise ValueError(
                    f"Gate {ordinal} appears more than once for {target}"
                )
            assignments.add(assignment)
            entries.append(
                GateProofBatchEntry(
                    user_id=user_id,
                    ordinal=ordinal,
                    source_guild_id=source_guild_id,
                    source_channel_id=int(match.group(4)),
                    source_message_id=int(match.group(5)),
                )
            )
    return tuple(entries)


def _gate_increment_candidate_ids(source_message) -> tuple[int, ...]:
    ordered_user_ids = []
    if source_message.webhook_id is None:
        ordered_user_ids.append(source_message.author.id)
    ordered_user_ids.extend(source_message.raw_mentions)
    return tuple(dict.fromkeys(ordered_user_ids))


def _build_gate_increment_candidates(
    source_message,
) -> tuple[GateIncrementCandidate, ...]:
    guild = source_message.guild

    candidates = []
    for user_id in _gate_increment_candidate_ids(source_message):
        member = guild.get_member(user_id)
        if member is None or member.bot:
            continue
        candidates.append(_build_gate_increment_candidate(member))
    return tuple(candidates)


def _build_achievement_candidates(source_message) -> tuple:
    guild = source_message.guild
    candidates = []
    for user_id in _gate_increment_candidate_ids(source_message):
        member = guild.get_member(user_id)
        if member is None or member.bot:
            continue
        candidates.append(member)
    return tuple(candidates)


def _build_gate_proof_candidates(
    source_message,
    missing_by_user: dict[int, tuple[int, ...]],
) -> tuple[GateProofCandidate, ...]:
    return tuple(
        GateProofCandidate(member, missing_by_user.get(member.id, ()))
        for member in _build_achievement_candidates(source_message)
    )


def _build_gate_increment_candidate(member) -> GateIncrementCandidate:
    member_role_ids = tuple(role.id for role in member.roles)
    transition = plan_gate_transition(member_role_ids)
    target_role_id = (
        GATE_TIER_ROLE_IDS[transition.target_tier - 1]
        if transition.target_tier is not None
        else None
    )
    return GateIncrementCandidate(
        user_id=member.id,
        display_name=member.display_name,
        current_gate_role_ids=transition.current_role_ids,
        current_tier=transition.current_tier,
        target_role_id=target_role_id,
        target_ordinal=(transition.current_tier or 0) + 1,
        highest_ordinal=transition.current_tier or 0,
        has_solo_gater=SINGLEPLAYER_GATE_COMPLETED_ROLE_ID in member_role_ids,
    )


def _build_gate_increment_member_plans(
    candidates: tuple[GateIncrementCandidate, ...],
    *,
    grant_solo: bool,
) -> tuple[GateIncrementMemberPlan, ...]:
    plans = []
    for candidate in candidates:
        target_role_id = candidate.target_role_id
        if target_role_id is None:
            raise RuntimeError("Selected Gate increment candidate has no target role")
        plans.append(
            GateIncrementMemberPlan(
                candidate.user_id,
                candidate.current_gate_role_ids,
                target_role_id,
                target_ordinal=candidate.target_ordinal,
                grant_solo=grant_solo,
            )
        )
    return tuple(plans)


def _gate_increment_custom_achievement_definitions(
    definitions,
) -> tuple[AchievementDefinition, ...]:
    eligible = tuple(
        definition
        for definition in definitions
        if definition.grantable
        and definition.key not in {STARGATE_COMPLETED_KEY, SOLO_GATER_KEY}
    )
    if len(eligible) > 25:
        raise commands.UserFeedbackCheckFailure(
            "Gate increment supports at most 25 custom achievements"
        )
    return eligible


def _gate_increment_custom_award_labels(
    snapshot: GateIncrementSnapshot,
    member,
) -> tuple[str, ...]:
    definitions_by_key = {
        achievement.key: achievement
        for achievement in snapshot.custom_achievements
    }
    labels = []
    for key in member.custom_achievement_keys:
        achievement = definitions_by_key.get(key)
        if achievement is None:
            continue
        labels.append(
            f"<@&{achievement.role_id}>"
            if achievement.role_id is not None
            else achievement.display_name
        )
    return tuple(labels)


def _validate_gate_increment_output_limits(
    source_message,
    moderator_id: int,
    plans: tuple[GateIncrementMemberPlan, ...],
    achievements: tuple[GateIncrementAchievementPlan, ...],
    owned_keys_by_user: dict[int, set[str]] | None = None,
    *,
    snapshot: GateIncrementSnapshot | None = None,
) -> None:
    owned_keys_by_user = owned_keys_by_user or {}
    public_lines = []
    log_lines = []
    if snapshot is not None:
        for member in snapshot.members:
            if member.state is not MemberState.COMPLETED or member.user_id is None:
                continue
            awards = [f"<@&{member.target_role_id}>"]
            log_awards = []
            if member.solo_awarded:
                awards.append(f"<@&{SINGLEPLAYER_GATE_COMPLETED_ROLE_ID}>")
                log_awards.append("Solo Gater")
            labels = _gate_increment_custom_award_labels(snapshot, member)
            awards.extend(labels)
            log_awards.extend(labels)
            public_lines.append(f"<@{member.user_id}> " + " ".join(awards))
            if not member.moderation_logged:
                gate_number = GATE_TIER_ROLE_IDS.index(member.target_role_id) + 1
                log_line = f"<@{member.user_id}> Gate {gate_number}"
                if log_awards:
                    log_line += " + " + " + ".join(log_awards)
                log_lines.append(log_line)
    for plan in plans:
        achievement_labels = tuple(
            f"<@&{achievement.role_id}>"
            if achievement.role_id is not None
            else achievement.display_name
            for achievement in achievements
            if achievement.key not in owned_keys_by_user.get(plan.user_id, set())
        )
        awards = [f"<@&{plan.target_role_id}>"]
        log_awards = []
        if plan.grant_solo:
            awards.append(f"<@&{SINGLEPLAYER_GATE_COMPLETED_ROLE_ID}>")
            log_awards.append("Solo Gater")
        awards.extend(achievement_labels)
        log_awards.extend(achievement_labels)
        public_lines.append(f"<@{plan.user_id}> " + " ".join(awards))
        gate_number = GATE_TIER_ROLE_IDS.index(plan.target_role_id) + 1
        log_line = f"<@{plan.user_id}> Gate {gate_number}"
        if log_awards:
            log_line += " + " + " + ".join(log_awards)
        log_lines.append(log_line)
    public_content = "🎉 **Congratulations!**\n" + "\n".join(public_lines)
    source_url = (
        "https://discord.com/channels/"
        f"{source_message.guild.id}/{source_message.channel.id}/{source_message.id}"
    )
    log_content = (
        "Gate incremented\n"
        f"Moderator: <@{moderator_id}>\n"
        f"Members: {', '.join(log_lines)}\n"
        f"Source: {source_url}"
    )
    if max(len(public_content), len(log_content)) > DISCORD_MESSAGE_CONTENT_LIMIT:
        raise commands.UserFeedbackCheckFailure(
            "The combined Gate increment is too large for one Discord message. "
            "Select fewer users or achievements, or use a new source message"
        )


def _validate_gate_increment_configuration(guild) -> tuple:
    bot_member = guild.me
    permissions = getattr(bot_member, "guild_permissions", None)
    if bot_member is None or not permissions or not permissions.manage_roles:
        raise commands.UserFeedbackCheckFailure("I need Manage Roles permission")

    roles = []
    for role_id in GATE_TIER_ROLE_IDS:
        role = guild.get_role(role_id)
        if (
            role is None
            or role.managed
            or role.position >= bot_member.top_role.position
        ):
            raise commands.UserFeedbackCheckFailure(
                "Gate roles are configured incorrectly"
            )
        roles.append(role)
    return tuple(roles)


def _plan_gate_revoke_roles(guild, member, current_count: int) -> tuple:
    if not 1 <= current_count <= len(GATE_TIER_ROLE_IDS):
        raise commands.UserFeedbackCheckFailure("Stored Gate progress is invalid")
    _validate_gate_increment_configuration(guild)
    current_role_ids = tuple(role.id for role in member.roles)
    current_gate_role_ids = {
        role_id for role_id in current_role_ids if role_id in GATE_TIER_ROLE_IDS
    }
    if current_gate_role_ids != {GATE_TIER_ROLE_IDS[current_count - 1]}:
        raise commands.UserFeedbackCheckFailure(
            "This user's Gate role is out of sync"
        )
    original_roles = tuple(
        role for role in member.roles if role.id != guild.default_role.id
    )
    target_count = current_count - 1
    desired_role_ids = [
        role_id
        for role_id in current_role_ids
        if role_id not in GATE_TIER_ROLE_IDS
        and role_id != guild.default_role.id
    ]
    if target_count:
        desired_role_ids.append(GATE_TIER_ROLE_IDS[target_count - 1])
    desired_roles = tuple(guild.get_role(role_id) for role_id in desired_role_ids)
    if any(role is None for role in desired_roles):
        raise commands.UserFeedbackCheckFailure(
            "Gate roles are configured incorrectly"
        )
    return target_count, original_roles, desired_roles


class NHMisc(commands.Cog):
    """Miscellaneous small utilities for Red-DiscordBot."""

    CONFIG_IDENTIFIER = NHMISC_CONFIG_IDENTIFIER
    QUIESCENT_UNLOAD_VERSION = 1
    RUNTIME_HEALTH_VERSION = 1

    def __init__(self, bot, support):
        super().__init__()
        self.bot = bot
        self._support: OperationalSupport = support
        self.config = support.log_config
        self.config.register_guild(
            bot_proxy_channel=None,
            bot_proxy_delete_closed_sessions=False,
            bot_proxy_enabled=True,
            vcjumping_visit_count=DEFAULT_VCJUMPING_VISIT_COUNT,
            vcjumping_window_seconds=DEFAULT_VCJUMPING_WINDOW_SECONDS,
            activity_channel=None,
            activity_detail_retention_days=DEFAULT_ACTIVITY_DETAIL_RETENTION_DAYS,
            activity_history_retention_days=DEFAULT_ACTIVITY_HISTORY_RETENTION_DAYS,
            sticky_debug_logging_enabled=False,
            forum_autopin_channel_ids=[],
        )
        self._operational_errors = support.operational_errors
        self._bot_proxy_store = BotProxyStore(cog_data_path(self) / "bot_proxy.sqlite")
        self._bot_proxy = None
        self._voice_visits = VoiceChannelVisitTracker()
        self._audit_log_tasks: set[asyncio.Task] = set()
        self._forum_autopin = ForumAutopinService(
            self.config, alert_sender=self._send_forum_autopin_alert, logger=log
        )
        self._activity_store = ActivityStore(cog_data_path(self) / "activity.sqlite")
        self._sticky_roles = StickyRoleStore(cog_data_path(self) / "sticky_roles.sqlite")
        self._role_analytics_store = RoleAnalyticsStore(
            cog_data_path(self) / "role_analytics.sqlite"
        )
        self._role_analytics = RoleAnalyticsService(
            self.bot, self._role_analytics_store, logger=log
        )
        achievements_path = cog_data_path(self) / "achievements.sqlite"
        self._achievement_store = AchievementStore(achievements_path)
        self._achievement_syncing_guilds: set[int] = set()
        self._activity_task: asyncio.Task | None = None
        self._role_analytics_startup_task: asyncio.Task | None = None
        self._role_analytics_daily_task: asyncio.Task | None = None
        self._achievement_reconciliations: dict[int, _AchievementReconciliation] = {}
        self._achievement_reconciliation_runs: set[asyncio.Task] = set()
        self._achievement_reconciliation_closing = False
        self._gate_increment_store = GateIncrementStore(
            achievements_path
        )
        self._gate_increment_recovery_task: asyncio.Task | None = None
        self._gate_increment_context_menu = discord.app_commands.ContextMenu(
            name="Increment Gate roles",
            callback=self._gate_increment_context_action,
        )
        self._gate_increment_context_menu.default_permissions = discord.Permissions(
            manage_messages=True
        )
        self._gate_increment_context_menu.guild_only = True
        self._gate_increment_context_registered = False
        self._gate_revoke_locks: dict[tuple[int, int], asyncio.Lock] = {}
        self._authorized_gate_role_edits: dict[
            tuple[int, int], frozenset[int]
        ] = {}
        self._gate_revoke_slash_command = discord.app_commands.Command(
            name="gaterevoke",
            description="Revoke one of a member's Gates",
            callback=self._gate_revoke_slash,
        )
        self._gate_revoke_slash_command.default_permissions = discord.Permissions(
            manage_messages=True
        )
        self._gate_revoke_slash_command.guild_only = True
        self._gate_revoke_user_context_menu = discord.app_commands.ContextMenu(
            name="Revoke Gate",
            callback=self._gate_revoke_user_context_action,
        )
        self._gate_revoke_user_context_menu.default_permissions = (
            discord.Permissions(manage_messages=True)
        )
        self._gate_revoke_user_context_menu.guild_only = True
        self._achievements_slash_command = discord.app_commands.Command(
            name="achievements",
            description="Show a member's achievements",
            callback=self._achievements_slash,
        )
        self._achievements_slash_command.guild_only = True
        self._achievements_user_context_menu = discord.app_commands.ContextMenu(
            name="View achievements",
            callback=self._achievements_user_context_action,
        )
        self._achievements_user_context_menu.guild_only = True
        self._grant_achievements_context_menu = discord.app_commands.ContextMenu(
            name="Grant achievements",
            callback=self._grant_achievements_context_action,
        )
        self._grant_achievements_context_menu.default_permissions = (
            discord.Permissions(manage_messages=True)
        )
        self._grant_achievements_context_menu.guild_only = True
        self._add_gate_proof_context_menu = discord.app_commands.ContextMenu(
            name="Add Gate Proof",
            callback=self._add_gate_proof_context_action,
        )
        self._add_gate_proof_context_menu.default_permissions = (
            discord.Permissions(manage_messages=True)
        )
        self._add_gate_proof_context_menu.guild_only = True
        self._achievement_commands_registered = False

    async def cog_load(self) -> None:
        await self._activity_store.initialize()
        await self._sticky_roles.initialize()
        await self._role_analytics_store.initialize()
        await self._achievement_store.initialize()
        await self._gate_increment_store.initialize()
        await self._bot_proxy_store.initialize()
        await self._recover_bot_proxy_sessions()
        self._register_gate_increment_context_menu()
        self._register_achievement_commands()
        self._activity_task = asyncio.create_task(self._activity_midnight_loop())
        self._role_analytics_startup_task = asyncio.create_task(
            self._role_analytics_startup_reconcile()
        )
        self._role_analytics_daily_task = asyncio.create_task(
            self._role_analytics_daily_loop()
        )
        self._gate_increment_recovery_task = asyncio.create_task(
            self._recover_interrupted_gate_increments()
        )

    async def report_operational_error(
        self,
        *,
        guild_id: int,
        source: str,
        action: str,
        error: BaseException,
        channel_id: int | None = None,
        thread_id: int | None = None,
        message_id: int | None = None,
    ) -> OperationalFailure | None:
        return await self._support.report_operational_error(
            guild_id=guild_id,
            source=source,
            action=action,
            error=error,
            channel_id=channel_id,
            thread_id=thread_id,
            message_id=message_id,
        )

    async def cog_command_error(
        self,
        ctx: commands.Context,
        error: commands.CommandError,
    ) -> None:
        await self._support.handle_command_error(ctx, error, source="NHMisc")

    async def _report_operational_error_for_guilds(
        self,
        action: str,
        error: BaseException,
    ) -> None:
        for guild in tuple(self.bot.guilds):
            await self.report_operational_error(
                guild_id=guild.id,
                source="NHMisc",
                action=action,
                error=error,
            )

    def _ensure_bot_proxy(self):
        if self._bot_proxy is None:
            from .bot_proxy_avatar import AvatarLoader
            from .bot_proxy_manager import BotProxyWorkflowManager

            self._bot_proxy = BotProxyWorkflowManager(
                config=self.config,
                store=self._bot_proxy_store,
                moderation_log=self._support.send_moderation_log,
                error_reporter=self.report_operational_error,
                avatar_loader=AvatarLoader(),
            )
        return self._bot_proxy

    async def _recover_bot_proxy_sessions(self) -> None:
        for record in await self._bot_proxy_store.list_active_sessions():
            try:
                thread = self.bot.get_channel(record.thread_id)
                if thread is None:
                    thread = await self.bot.fetch_channel(record.thread_id)
                delete_closed = await self.config.guild_from_id(
                    record.guild_id
                ).bot_proxy_delete_closed_sessions()
                if delete_closed:
                    await self._delete_recovered_bot_proxy_session(record, thread)
                else:
                    await self._archive_recovered_bot_proxy_session(record, thread)
            except Exception as error:
                await self.report_operational_error(
                    guild_id=record.guild_id,
                    source="NHMisc",
                    action="recover Bot Proxy session",
                    error=error,
                    channel_id=record.launcher_channel_id,
                    thread_id=record.thread_id,
                    message_id=record.dashboard_message_id,
                )
            else:
                await self._bot_proxy_store.remove_active_session(record.session_id)

    async def _archive_recovered_bot_proxy_session(self, record, thread) -> None:
        try:
            dashboard = await thread.fetch_message(record.dashboard_message_id)
            await dashboard.edit(
                content="Bot Proxy session: Interrupted",
                view=None,
            )
        finally:
            await thread.edit(archived=True, locked=True)

    async def _delete_recovered_bot_proxy_session(self, record, thread) -> None:
        failure: Exception | None = None
        try:
            await thread.delete()
        except discord.NotFound:
            pass
        except Exception as error:  # noqa: BLE001
            failure = error

        try:
            channel = self.bot.get_channel(record.launcher_channel_id)
            if channel is None:
                channel = await self.bot.fetch_channel(record.launcher_channel_id)
            launcher = await channel.fetch_message(record.launcher_message_id)
            await launcher.delete()
        except discord.NotFound:
            pass
        except Exception as error:  # noqa: BLE001
            if failure is None:
                failure = error
        if failure is not None:
            raise failure

    def runtime_health_issues(self) -> tuple[str, ...]:
        required_tasks = (
            (self._activity_task, "activity midnight task"),
            (self._role_analytics_daily_task, "role analytics daily task"),
        )
        return tuple(
            issue
            for task, label in required_tasks
            if (issue := task_health_issue(task, label)) is not None
        )

    async def cog_unload(self) -> None:
        self._achievement_reconciliation_closing = True
        tasks = {
            task
            for task in (
                *self._audit_log_tasks,
                *self._achievement_reconciliation_runs,
                self._activity_task,
                self._role_analytics_startup_task,
                self._role_analytics_daily_task,
                self._gate_increment_recovery_task,
                *(state.task for state in self._achievement_reconciliations.values()),
            )
            if task is not None
        }
        self._unregister_gate_increment_context_menu()
        self._unregister_achievement_commands()
        for task in tasks:
            task.cancel()
        analytics_shutdown = asyncio.create_task(self._role_analytics.shutdown())
        bot_proxy = getattr(self, "_bot_proxy", None)
        bot_proxy_shutdown = (
            asyncio.create_task(bot_proxy.shutdown()) if bot_proxy is not None else None
        )
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for state in self._achievement_reconciliations.values():
            if state.task is not None and state.message is not None:
                content = state.message.content.rsplit("\n", 1)[0] + "\nRetry cancelled"
                await self._publish_achievement_reconciliation(state.message.guild, state, content)
        self._achievement_reconciliations.clear()
        await analytics_shutdown
        if bot_proxy_shutdown is not None:
            await bot_proxy_shutdown
        self._audit_log_tasks.clear()
        self._activity_task = None
        self._role_analytics_startup_task = None
        self._role_analytics_daily_task = None
        self._gate_increment_recovery_task = None

    def _register_gate_increment_context_menu(self) -> None:
        command_type = discord.AppCommandType.message
        existing = self.bot.tree.get_command(
            self._gate_increment_context_menu.name,
            type=command_type,
        )
        if existing is self._gate_increment_context_menu:
            self._gate_increment_context_registered = True
            return
        self.bot.tree.add_command(
            self._gate_increment_context_menu,
            override=True,
        )
        self._gate_increment_context_registered = True

    def _unregister_gate_increment_context_menu(self) -> None:
        if not self._gate_increment_context_registered:
            return
        command_type = discord.AppCommandType.message
        existing = self.bot.tree.get_command(
            self._gate_increment_context_menu.name,
            type=command_type,
        )
        if existing is self._gate_increment_context_menu:
            self.bot.tree.remove_command(
                self._gate_increment_context_menu.name,
                type=command_type,
            )
        self._gate_increment_context_registered = False

    def _register_achievement_commands(self) -> None:
        for command in (
            self._gate_revoke_slash_command,
            self._gate_revoke_user_context_menu,
            self._achievements_slash_command,
            self._achievements_user_context_menu,
            self._grant_achievements_context_menu,
            self._add_gate_proof_context_menu,
        ):
            self.bot.tree.add_command(command, override=True)
        self._achievement_commands_registered = True

    def _unregister_achievement_commands(self) -> None:
        if not self._achievement_commands_registered:
            return
        self.bot.tree.remove_command(
            self._gate_revoke_slash_command.name,
            type=discord.AppCommandType.chat_input,
        )
        self.bot.tree.remove_command(
            self._gate_revoke_user_context_menu.name,
            type=discord.AppCommandType.user,
        )
        self.bot.tree.remove_command(
            self._achievements_slash_command.name,
            type=discord.AppCommandType.chat_input,
        )
        self.bot.tree.remove_command(
            self._achievements_user_context_menu.name,
            type=discord.AppCommandType.user,
        )
        self.bot.tree.remove_command(
            self._grant_achievements_context_menu.name,
            type=discord.AppCommandType.message,
        )
        self.bot.tree.remove_command(
            self._add_gate_proof_context_menu.name,
            type=discord.AppCommandType.message,
        )
        self._achievement_commands_registered = False

    async def configured_sticky_role_ids(self, guild_id: int) -> frozenset[int]:
        return frozenset(await self._sticky_roles.get_sticky_roles(guild_id))

    async def _achievement_discord_snapshot(
        self, guild: discord.Guild
    ) -> DiscordRoleSnapshot | None:
        require(self.bot, "members")
        cached_member_count = len(guild.members)
        reported_member_count = guild.member_count
        if (
            not guild.chunked
            or reported_member_count is None
            or cached_member_count != reported_member_count
        ):
            raise commands.UserFeedbackCheckFailure(
                "Discord member cache is incomplete. Run `!rolesync` first"
            )

        guild_id = guild.id
        state = await self._role_analytics_store.get_state(guild_id)
        if state.status is not SyncStatus.READY or state.last_completed_at is None:
            return None
        cached_non_bot_members = tuple(member for member in guild.members if not member.bot)
        try:
            analytics_member_count = await self._role_analytics_store.count_matching(
                guild_id,
                "1 = 1",
                (),
            )
        except AnalyticsUnavailableError:
            return None
        if analytics_member_count != len(cached_non_bot_members):
            raise commands.UserFeedbackCheckFailure(
                "Role analytics member count does not match Discord. Run `!rolesync` first"
            )
        if await self._achievement_store.is_bootstrapped(guild_id):
            definitions = await self._achievement_store.list_definitions(guild_id)
        else:
            definitions = (SOLO_GATER_DEFINITION,)
        bound_definitions = tuple(
            definition for definition in definitions if definition.role_id is not None
        )
        role_ids = (
            *GATE_TIER_ROLE_IDS,
            *(definition.role_id for definition in bound_definitions),
        )
        if any(guild.get_role(role_id) is None for role_id in role_ids):
            raise commands.UserFeedbackCheckFailure("Achievement roles are configured incorrectly")
        users_by_role = await self._role_analytics_users_with_roles(
            guild_id,
            role_ids,
        )
        if users_by_role is None:
            return None
        cached_role_ids_by_user = {
            member.id: {role.id for role in member.roles} for member in cached_non_bot_members
        }
        cached_users_by_role = tuple(
            tuple(
                sorted(
                    user_id
                    for user_id, member_role_ids in cached_role_ids_by_user.items()
                    if role_id in member_role_ids
                )
            )
            for role_id in role_ids
        )
        if users_by_role != cached_users_by_role:
            raise commands.UserFeedbackCheckFailure(
                "Role analytics role holders do not match Discord. Run `!rolesync` first"
            )
        gate_role_count = len(GATE_TIER_ROLE_IDS)
        return build_discord_role_snapshot(
            snapshot_at=state.last_completed_at,
            users_by_gate_role=users_by_role[:gate_role_count],
            boolean_users={
                definition.key: holders
                for definition, holders in zip(
                    bound_definitions,
                    users_by_role[gate_role_count:],
                    strict=True,
                )
            },
            role_holders=dict(zip(role_ids, cached_users_by_role, strict=True)),
            cached_member_count=cached_member_count,
            reported_member_count=reported_member_count,
        )

    async def _role_analytics_users_with_roles(
        self,
        guild_id: int,
        role_ids_to_query: tuple[int, ...],
    ) -> tuple[tuple[int, ...], ...] | None:
        predicate_sql = """
            EXISTS (
                SELECT 1
                FROM role_analytics_memberships AS membership
                WHERE membership.guild_id = member.guild_id
                    AND membership.generation = member.generation
                    AND membership.user_id = member.user_id
                    AND membership.role_id = ?
            )
        """
        try:
            users_by_role = []
            for role_id in role_ids_to_query:
                users_by_role.append(
                    await self._role_analytics_store.matching_user_ids(
                        guild_id,
                        predicate_sql,
                        (role_id,),
                    )
                )
        except AnalyticsUnavailableError:
            return None
        return tuple(users_by_role)

    async def _reconcile_achievement_roles_for_guild(
        self, guild: discord.Guild, *, retry: bool = False,
    ) -> None:
        if self._achievement_reconciliation_closing:
            return
        task = asyncio.current_task()
        self._achievement_reconciliation_runs.add(task)
        try:
            await self._run_achievement_reconciliation(guild, retry=retry)
        finally:
            self._achievement_reconciliation_runs.discard(task)

    async def _run_achievement_reconciliation(self, guild, *, retry: bool) -> None:
        state = self._achievement_reconciliations.setdefault(guild.id, _AchievementReconciliation())
        async with state.lock:
            aborted = False
            capability_wait = False
            try:
                corrected, skips = await self._reconcile_achievement_roles_once(guild)
            except (GatewayCapabilityUnavailable, AnalyticsUnavailableError):
                corrected = None
                skips = None
                aborted = True
                capability_wait = True
            except Exception as error:
                corrected = None
                skips = None
                aborted = True
                log.exception("Achievement role reconciliation failed for guild %s", guild.id)
                await self._support.report_operational_error(
                    guild_id=guild.id, source="NHMisc",
                    action="reconcile achievement roles", error=error,
                )
            unsuccessful = aborted or bool(skips)
            pending = state.task is not None
            if unsuccessful and not retry and not pending:
                state.retry_at = int(time.time()) + (30 if capability_wait else ACHIEVEMENT_RETRY_SECONDS)
                state.task = asyncio.create_task(self._retry_achievement_roles(guild, state))
            if retry or (pending and not unsuccessful):
                status_line = "Retry failed" if unsuccessful else "Retry completed"
            elif unsuccessful:
                status_line = f"Retrying <t:{state.retry_at}:R>"
            else:
                status_line = ""
            content = _format_reconciliation_report(
                aborted=aborted,
                corrected=corrected,
                skips=skips,
                status_line=status_line,
            )
            if capability_wait:
                content = (
                    "Achievement role reconciliation paused: member data is unavailable\n\n"
                    "Pending work is preserved and will be retried"
                )
            # A crash already pings through the operational error report.
            # Skip-only retries ping with a new message; edits never ping.
            ping = bool(retry and unsuccessful and not aborted)
            if corrected or unsuccessful or pending or retry:
                await self._publish_achievement_reconciliation(
                    guild, state, content, ping=ping
                )
            if retry and capability_wait:
                state.retry_at = int(time.time()) + 30
            elif retry or not unsuccessful:
                if state.task is not None and state.task is not asyncio.current_task():
                    state.task.cancel()
                state.task = None
                state.message = None
                state.retry_at = 0

    async def _retry_achievement_roles(self, guild, state) -> None:
        while not self._achievement_reconciliation_closing:
            await asyncio.sleep(max(0, state.retry_at - time.time()))
            await self._reconcile_achievement_roles_for_guild(guild, retry=True)
            if state.task is not asyncio.current_task():
                return

    async def _publish_achievement_reconciliation(
        self, guild, state, content, *, ping: bool = False
    ) -> None:
        try:
            if ping or state.message is None:
                previous = state.message
                message = await self._send_error_notice(
                    guild,
                    content,
                    ping=ping,
                    failure_action="publish achievement reconciliation retry",
                )
                if ping and previous is not None:
                    await self._quietly_finalize_reconciliation_message(
                        previous, guild, content
                    )
                if not ping:
                    state.message = message
                return
            if state.message.channel.permissions_for(guild.default_role).view_channel:
                raise commands.UserFeedbackCheckFailure("The error channel is now public")
            state.message = await state.message.edit(
                content=content, allowed_mentions=discord.AllowedMentions.none(),
            )
        except Exception as error:
            await self._support.report_operational_error(
                guild_id=guild.id, source="NHMisc",
                action="update achievement reconciliation log", error=error,
            )

    async def _quietly_finalize_reconciliation_message(self, message, guild, content) -> None:
        """Leave the earlier retry notice in its final state without a ping."""
        try:
            if message.channel.permissions_for(guild.default_role).view_channel:
                return
            await message.edit(
                content=content, allowed_mentions=discord.AllowedMentions.none(),
            )
        except Exception:
            log.exception(
                "Could not update the earlier achievement reconciliation notice for guild %s",
                guild.id,
            )

    async def _reconcile_achievement_roles_once(  # noqa: PLR0912
        self, guild: discord.Guild
    ) -> tuple[int, tuple[ReconciliationSkip, ...]]:
        require(self.bot, "members")
        definitions = tuple(
            definition
            for definition in await self._achievement_store.list_definitions(guild.id)
            if definition.role_id is not None
        )
        users_by_role = await self._role_analytics_users_with_roles(
            guild.id,
            (
                *GATE_TIER_ROLE_IDS,
                *(definition.role_id for definition in definitions),
            ),
        )
        if users_by_role is None:
            raise AnalyticsUnavailableError("Role analytics are unavailable")
        gate_role_count = len(GATE_TIER_ROLE_IDS)
        actual_gate_roles: dict[int, set[int]] = {}
        for role_id, user_ids in zip(
            GATE_TIER_ROLE_IDS,
            users_by_role[:gate_role_count],
            strict=True,
        ):
            for user_id in user_ids:
                actual_gate_roles.setdefault(user_id, set()).add(role_id)
        projections = await self._achievement_store.list_gate_projections(guild.id)
        corrected = 0
        skips: list[ReconciliationSkip] = []
        for user_id in set(actual_gate_roles) | set(projections):
            completed_count = projections.get(user_id, 0)
            expected = (
                {GATE_TIER_ROLE_IDS[completed_count - 1]}
                if 0 < completed_count <= len(GATE_TIER_ROLE_IDS)
                else set()
            )
            if actual_gate_roles.get(user_id, set()) == expected:
                continue
            try:
                member = await guild.fetch_member(user_id)
                if await self._restore_gate_projection(
                    guild,
                    member,
                    completed_count,
                    reason="Achievement database reconciliation",
                ):
                    corrected += 1
            except discord.NotFound:
                continue
            except (
                commands.UserFeedbackCheckFailure,
                discord.Forbidden,
                discord.HTTPException,
            ) as error:
                log.exception(
                    "Failed to reconcile Gate projection for guild %s member %s",
                    guild.id,
                    user_id,
                )
                skips.append(
                    ReconciliationSkip(
                        user_id=user_id,
                        subject="Gate",
                        error=_exception_label(error),
                    )
                )

        for definition, actual_user_ids in zip(
            definitions,
            users_by_role[gate_role_count:],
            strict=True,
        ):
            actual_users = set(actual_user_ids)
            stored_users = set(
                await self._achievement_store.projected_users_for_boolean(
                    guild.id,
                    definition.key,
                )
            )
            for user_id in actual_users ^ stored_users:
                should_have_role = user_id in stored_users
                try:
                    member = await guild.fetch_member(user_id)
                    await self._edit_achievement_roles(
                        guild,
                        member,
                        add_role_ids=(definition.role_id,) if should_have_role else (),
                        remove_role_ids=() if should_have_role else (definition.role_id,),
                        reason="Achievement database reconciliation",
                    )
                    corrected += 1
                except discord.NotFound:
                    continue
                except (
                    commands.UserFeedbackCheckFailure,
                    discord.Forbidden,
                    discord.HTTPException,
                ) as error:
                    log.exception(
                        "Failed to reconcile achievement %s for guild %s member %s",
                        definition.key,
                        guild.id,
                        user_id,
                    )
                    subject = (
                        "Solo Gater"
                        if definition.key == SOLO_GATER_KEY
                        else definition.display_name
                    )
                    skips.append(
                        ReconciliationSkip(
                            user_id=user_id,
                            subject=subject,
                            error=_exception_label(error),
                        )
                    )
        return corrected, tuple(skips)

    @staticmethod
    async def _restore_gate_projection(
        guild: discord.Guild,
        member: discord.Member,
        completed_count: int,
        *,
        reason: str,
    ) -> bool:
        if not 0 <= completed_count <= len(GATE_TIER_ROLE_IDS):
            raise commands.UserFeedbackCheckFailure("Gate projection exceeds configured tiers")
        _validate_gate_increment_configuration(guild)
        current_role_ids = tuple(role.id for role in member.roles)
        non_gate_role_ids = tuple(
            role_id
            for role_id in current_role_ids
            if role_id not in GATE_TIER_ROLE_IDS
            and role_id != guild.default_role.id
        )
        desired_role_ids = non_gate_role_ids
        if completed_count:
            desired_role_ids = (
                *desired_role_ids,
                GATE_TIER_ROLE_IDS[completed_count - 1],
            )
        current_assignable = {
            role_id
            for role_id in current_role_ids
            if role_id != guild.default_role.id
        }
        if set(desired_role_ids) == current_assignable:
            return False
        desired_roles = [guild.get_role(role_id) for role_id in desired_role_ids]
        if any(role is None for role in desired_roles):
            raise commands.UserFeedbackCheckFailure(
                "Gate roles are configured incorrectly"
            )
        await member.edit(roles=desired_roles, reason=reason)
        return True

    async def _role_analytics_startup_reconcile(self) -> None:
        await self.bot.wait_until_ready()
        try:
            await self._role_analytics.reconcile_enabled_guilds(tuple(self.bot.guilds))
            for guild in self.bot.guilds:
                if not await self._achievement_store.is_bootstrapped(guild.id):
                    await self._send_error_notice(
                        guild,
                        "Achievement initialization is required\n\n"
                        "The achievement database has not been initialized from the "
                        "current Discord roles.\n"
                        "Run `!rolesync discord`.",
                        ping=False,
                    )
                    continue
                await self._reconcile_achievement_roles_for_guild(guild)
        except Exception as error:
            log.exception("Failed to reconcile role analytics on startup")
            await self._report_operational_error_for_guilds(
                "startup role reconciliation",
                error,
            )

    async def _role_analytics_daily_loop(self) -> None:
        await self.bot.wait_until_ready()
        while True:
            await asyncio.sleep(24 * 60 * 60)
            try:
                await self._role_analytics.run_daily_reconciliation(
                    tuple(self.bot.guilds)
                )
                for guild in self.bot.guilds:
                    if await self._achievement_store.is_bootstrapped(guild.id):
                        await self._reconcile_achievement_roles_for_guild(guild)
            except Exception as error:
                log.exception("Failed to run daily role analytics reconciliation")
                await self._report_operational_error_for_guilds(
                    "daily role reconciliation",
                    error,
                )

    @commands.Cog.listener()
    async def on_resumed(self) -> None:
        try:
            await self._role_analytics.reconcile_enabled_guilds(tuple(self.bot.guilds))
            for guild in self.bot.guilds:
                if await self._achievement_store.is_bootstrapped(guild.id):
                    await self._reconcile_achievement_roles_for_guild(guild)
        except Exception as error:
            log.exception("Failed to reconcile achievement roles after resume")
            await self._report_operational_error_for_guilds(
                "resume role reconciliation",
                error,
            )

    async def red_delete_data_for_user(self, *, requester, user_id: int) -> None:
        if self._bot_proxy is None:
            await self._bot_proxy_store.delete_user_data(user_id)
        else:
            await self._bot_proxy.delete_user_data(user_id)
        await self._activity_store.delete_user_everywhere(user_id)
        await self._sticky_roles.delete_user_everywhere(user_id)
        await self._role_analytics_store.delete_user_everywhere(user_id)
        await self._achievement_store.delete_user_everywhere(user_id)
        await self._gate_increment_store.redact_user_data(user_id)

    @staticmethod
    async def _defer_achievement_interaction(
        interaction: discord.Interaction,
        *,
        ephemeral: bool,
    ) -> bool:
        try:
            await interaction.response.defer(
                ephemeral=ephemeral,
                thinking=True,
            )
        except discord.NotFound as error:
            if error.code != 10062:
                raise
            return False
        return True

    @staticmethod
    async def _await_achievement_interaction_data(
        awaitable: Awaitable[_InteractionResult],
    ) -> _InteractionResult:
        return await asyncio.wait_for(
            awaitable,
            timeout=ACHIEVEMENT_INTERACTION_DB_TIMEOUT_SECONDS,
        )

    @staticmethod
    async def _send_achievement_interaction_error(
        interaction: discord.Interaction,
        message: str,
        *,
        public_defer: bool,
    ) -> None:
        if public_defer:
            await interaction.delete_original_response()
            await interaction.followup.send(message, ephemeral=True)
            return
        await interaction.edit_original_response(content=message)

    async def _handle_achievement_interaction_failure(
        self,
        interaction: discord.Interaction,
        action: str,
        error: Exception,
        *,
        public_defer: bool,
    ) -> None:
        if isinstance(error, asyncio.TimeoutError):
            message = "Achievement data is busy. Try again in a moment"
        else:
            message = "Achievement data could not be loaded. Try again later"
        try:
            await self._send_achievement_interaction_error(
                interaction,
                message,
                public_defer=public_defer,
            )
        except Exception as feedback_error:
            log.exception(
                "Achievement interaction failed and its Discord error could not be "
                "sent: action=%s guild=%s user=%s original_error=%r",
                action,
                getattr(interaction.guild, "id", None),
                getattr(interaction.user, "id", None),
                error,
            )
            guild_id = getattr(interaction.guild, "id", None)
            if guild_id is not None:
                await self.report_operational_error(
                    guild_id=guild_id,
                    source="NHMisc",
                    action=f"send failure feedback for {action}",
                    error=feedback_error,
                    channel_id=getattr(interaction, "channel_id", None),
                )
        guild_id = getattr(interaction.guild, "id", None)
        if guild_id is not None:
            await self.report_operational_error(
                guild_id=guild_id,
                source="NHMisc",
                action=action,
                error=error,
                channel_id=getattr(interaction, "channel_id", None),
            )

    @staticmethod
    async def _finish_action_interaction(interaction, view, *failures: str) -> None:
        view.stop()
        visible_failures = tuple(failure for failure in failures if failure)
        if not visible_failures:
            await interaction.delete_original_response()
            return
        await interaction.edit_original_response(
            content="; ".join(visible_failures),
            embed=None,
            view=None,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _achievements_slash(
        self,
        interaction: discord.Interaction,
        user: discord.Member | None = None,
    ) -> None:
        action = "achievements slash"
        if interaction.guild is None:
            await interaction.response.send_message(
                "This command can only be used in a server",
                ephemeral=True,
            )
            return
        if not await self._defer_achievement_interaction(
            interaction,
            ephemeral=True,
        ):
            return
        try:
            target = user or interaction.user
            interaction_data = getattr(interaction, "data", None) or {}
            command_id = interaction_data.get("id")
            command_mention = (
                f"</achievements:{command_id}>"
                if command_id is not None
                else "`/achievements`"
            )
            await self._respond_with_achievement_profile(
                interaction,
                target,
                command_mention=command_mention,
            )
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                action,
                error,
                public_defer=False,
            )

    async def _achievements_user_context_action(
        self,
        interaction: discord.Interaction,
        user: discord.Member,
    ) -> None:
        action = "view achievements context action"
        if interaction.guild is None:
            await interaction.response.send_message(
                "This action can only be used in a server",
                ephemeral=True,
            )
            return
        if not await self._defer_achievement_interaction(
            interaction,
            ephemeral=True,
        ):
            return
        try:
            await self._respond_with_achievement_profile(
                interaction,
                user,
                command_mention="`/achievements`",
            )
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                action,
                error,
                public_defer=False,
            )

    async def _respond_with_achievement_profile(
        self,
        interaction: discord.Interaction,
        target: discord.User | discord.Member,
        *,
        command_mention: str,
    ) -> None:
        is_bootstrapped = await self._await_achievement_interaction_data(
            self._achievement_store.is_bootstrapped(interaction.guild.id)
        )
        if not is_bootstrapped:
            await self._send_achievement_interaction_error(
                interaction,
                "Achievement data is still initializing",
                public_defer=False,
            )
            return
        profile = await self._await_achievement_interaction_data(
            self._achievement_store.get_profile(
                interaction.guild.id,
                target.id,
            )
        )
        definitions = await self._await_achievement_interaction_data(
            self._achievement_store.list_definitions(interaction.guild.id)
        )
        embed = self._build_achievements_embed(
            interaction.guild.id,
            target,
            profile,
            definitions,
        )
        from .achievement_views import AchievementProfileView

        await interaction.edit_original_response(
            embed=embed,
            view=AchievementProfileView(
                embed,
                requester_id=interaction.user.id,
                command_mention=command_mention,
            ),
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @staticmethod
    def _build_achievements_embed(
        guild_id: int,
        user: discord.User | discord.Member,
        profile: AchievementProfile,
        definitions,
    ) -> discord.Embed:
        embed = discord.Embed(title=f"Achievements — {user.display_name}")
        stargate_lines = [f"Stargates: {profile.stargate_count}"]
        if profile.stargate_proofs:
            proof_links = [
                (
                    f"[Stargate {proof.ordinal}](https://discord.com/channels/"
                    f"{guild_id}/"
                    f"{proof.source_channel_id}/{proof.source_message_id})"
                )
                for proof in profile.stargate_proofs
            ]
            stargate_lines.append(" · ".join(proof_links))
        embed.description = "\n".join(stargate_lines)
        active_boolean_keys = set(profile.boolean_keys)
        boolean_lines = [
            definition.display_name
            for definition in definitions
            if definition.key in active_boolean_keys
            and definition.key != "stargate_completed"
        ]
        if boolean_lines:
            embed.add_field(
                name="Achievements",
                value="\n".join(boolean_lines),
                inline=False,
            )
        if profile.stargate_count == 0 and not boolean_lines:
            embed.description = "No achievements recorded"
        return embed

    @staticmethod
    def _build_gate_revoke_embed(
        guild_id: int,
        member: discord.Member,
        awards,
        selected_award,
        *,
        notice: str | None = None,
    ) -> discord.Embed:
        lines = [
            f"Target: <@{member.id}>",
            f"Gate role: {len(awards)} → {len(awards) - 1}",
            "",
        ]
        for award in awards:
            proof = "No proof stored"
            if (
                award.source_channel_id is not None
                and award.source_message_id is not None
            ):
                proof = (
                    "[Open proof](https://discord.com/channels/"
                    f"{guild_id}/{award.source_channel_id}/{award.source_message_id})"
                )
            marker = "▶ " if award is selected_award else ""
            lines.append(f"{marker}Stargate {award.ordinal}: {proof}")
        if selected_award is None:
            lines.extend(("", "Choose a Stargate to revoke"))
        elif selected_award is awards[-1]:
            lines.extend(("", f"Stargate {selected_award.ordinal} will be removed"))
        else:
            lines.extend(
                (
                    "",
                    f"Selected: Stargate {selected_award.ordinal}",
                    "Choose whether to compact the remaining Stargate numbers "
                    "or leave the gap",
                )
            )
        if notice:
            lines.extend(("", notice))
        return discord.Embed(
            title="Revoke Gate",
            description="\n".join(lines),
            color=discord.Color.blue(),
        )

    async def _gate_revoke_slash(
        self,
        interaction: discord.Interaction,
        user: discord.Member,
    ) -> None:
        await self._start_gate_revoke(interaction, user)

    async def _gate_revoke_user_context_action(
        self,
        interaction: discord.Interaction,
        user: discord.Member,
    ) -> None:
        await self._start_gate_revoke(interaction, user)

    async def _start_gate_revoke(
        self,
        interaction: discord.Interaction,
        member: discord.Member,
    ) -> None:
        action = "revoke Gate"
        permissions = interaction.permissions
        if (
            interaction.guild is None
            or permissions is None
            or not permissions.manage_messages
        ):
            await interaction.response.send_message(
                "You need Manage Messages permission",
                ephemeral=True,
            )
            return
        if not await self._defer_achievement_interaction(
            interaction,
            ephemeral=True,
        ):
            return
        try:
            guild = interaction.guild
            is_bootstrapped = await self._await_achievement_interaction_data(
                self._achievement_store.is_bootstrapped(guild.id)
            )
            if not is_bootstrapped:
                await interaction.edit_original_response(
                    content="Achievement data is still initializing. Run rolesync first"
                )
                return
            awards = await self._await_achievement_interaction_data(
                self._achievement_store.get_active_stargates(guild.id, member.id)
            )
            if not awards:
                await interaction.edit_original_response(
                    content="This user has no Gate to revoke"
                )
                return
            _plan_gate_revoke_roles(guild, member, len(awards))
            await self._require_private_moderation_log_channel(guild)

            from .achievement_views import GateRevokeView

            view = GateRevokeView(
                self,
                interaction.user.id,
                member,
                awards,
            )
            await interaction.edit_original_response(
                embed=view.render_embed(),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            view.message = await interaction.original_response()
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(content=str(error))
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                action,
                error,
                public_defer=False,
            )

    async def _confirm_gate_revoke(self, interaction, view, *, compact: bool) -> None:
        await interaction.response.defer()
        guild = interaction.guild
        member = view.member
        reviewed_awards = view.awards
        reviewed_award = view.selected_award
        if reviewed_award is None:
            await interaction.edit_original_response(
                embed=view.render_embed(notice="Choose a Stargate to revoke"),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        key = (guild.id, member.id)
        lock = self._gate_revoke_locks.setdefault(key, asyncio.Lock())
        async with lock:
            live_awards = await self._achievement_store.get_active_stargates(
                guild.id,
                member.id,
            )
            if live_awards != reviewed_awards:
                await interaction.edit_original_response(
                    embed=view.render_embed(
                        notice="Gate progress changed. Start the action again"
                    ),
                    view=view,
                    allowed_mentions=discord.AllowedMentions.none(),
                )
                return

            try:
                await self._require_private_moderation_log_channel(guild)
                target_count, original_roles, desired_roles = (
                    _plan_gate_revoke_roles(
                        guild,
                        member,
                        len(live_awards),
                    )
                )
            except commands.UserFeedbackCheckFailure as error:
                await interaction.edit_original_response(
                    embed=view.render_embed(notice=str(error)),
                    view=view,
                    allowed_mentions=discord.AllowedMentions.none(),
                )
                return

            self._authorized_gate_role_edits[key] = frozenset(
                {GATE_TIER_ROLE_IDS[target_count - 1]} if target_count else set()
            )
            try:
                try:
                    await member.edit(
                        roles=desired_roles,
                        reason=(
                            f"Revoke Stargate {reviewed_award.ordinal} through NHMisc "
                            f"by moderator {interaction.user.id}"
                        ),
                    )
                except Exception:
                    await interaction.edit_original_response(
                        embed=view.render_embed(
                            notice="The Gate role could not be changed"
                        ),
                        view=view,
                        allowed_mentions=discord.AllowedMentions.none(),
                    )
                    return

                result = await self._achievement_store.revoke_stargate(
                    guild.id,
                    member.id,
                    expected_awards=reviewed_awards,
                    selected_award_id=reviewed_award.award_id,
                    compact=compact,
                )
                if result is None:
                    role_restored = True
                    try:
                        await member.edit(
                            roles=original_roles,
                            reason="Restore Gate role after stale revoke",
                        )
                    except Exception:
                        role_restored = False
                    await interaction.edit_original_response(
                        embed=view.render_embed(
                            notice=(
                                "Gate progress changed. The revoke was cancelled"
                                if role_restored
                                else (
                                    "Gate progress changed and the original Gate role "
                                    "could not be restored"
                                )
                            )
                        ),
                        view=view,
                        allowed_mentions=discord.AllowedMentions.none(),
                    )
                    return
            finally:
                self._authorized_gate_role_edits.pop(key, None)

            await self._finish_gate_revoke(
                interaction,
                view,
                member,
                reviewed_awards,
                reviewed_award,
                result,
                compact=compact,
            )

    async def _finish_gate_revoke(
        self,
        interaction,
        view,
        member,
        reviewed_awards,
        reviewed_award,
        result,
        *,
        compact: bool,
    ) -> None:
        view.stop()
        guild = interaction.guild
        proof = "No proof stored"
        if (
            reviewed_award.source_channel_id is not None
            and reviewed_award.source_message_id is not None
        ):
            proof = (
                "https://discord.com/channels/"
                f"{guild.id}/{reviewed_award.source_channel_id}/"
                f"{reviewed_award.source_message_id}"
            )
        mode = "shift to fill gap" if compact else "leave gap"
        ordinal_changes = ", ".join(
            f"Stargate {old} → Stargate {new}"
            for _award_id, old, new in result.ordinal_changes
        ) or "none"
        try:
            delivered = await self._send_moderation_log(
                guild,
                "Gate revoked\n"
                f"Moderator: <@{interaction.user.id}>\n"
                f"Member: <@{member.id}>\n"
                f"Gate role: {len(reviewed_awards)} → {len(result.remaining)}\n"
                f"Removed: Stargate {reviewed_award.ordinal}\n"
                f"Proof: {proof}\n"
                f"Mode: {mode}\n"
                f"Ordinal changes: {ordinal_changes}",
                log_failure=False,
            )
        except Exception:
            delivered = False
        if not delivered:
            try:
                await interaction.edit_original_response(
                    content="The Gate was revoked, but the moderation log could not be sent",
                    embed=None,
                    view=None,
                    allowed_mentions=discord.AllowedMentions.none(),
                )
            except discord.HTTPException:
                log.exception(
                    "Gate revoke audit and Discord error could not be delivered "
                    "for guild %s member %s",
                    guild.id,
                    member.id,
                )
            return
        try:
            await interaction.delete_original_response()
        except discord.HTTPException:
            log.exception(
                "Gate revoke review could not be removed for guild %s member %s",
                guild.id,
                member.id,
            )

    async def _grant_achievements_context_action(
        self,
        interaction: discord.Interaction,
        source_message: discord.Message,
    ) -> None:
        action = "grant achievements context action"
        permissions = interaction.permissions
        if (
            interaction.guild is None
            or permissions is None
            or not permissions.manage_messages
        ):
            await interaction.response.send_message(
                "You need Manage Messages permission",
                ephemeral=True,
            )
            return
        if not await self._defer_achievement_interaction(
            interaction,
            ephemeral=True,
        ):
            return
        try:
            is_bootstrapped = await self._await_achievement_interaction_data(
                self._achievement_store.is_bootstrapped(interaction.guild.id)
            )
            if not is_bootstrapped:
                await interaction.edit_original_response(
                    content=(
                        "Achievement data is still initializing. Run rolesync first"
                    )
                )
                return
            candidates = _build_achievement_candidates(source_message)
            if not candidates:
                await interaction.edit_original_response(
                    content="This message has no eligible recipients"
                )
                return
            if len(candidates) > MAX_ACHIEVEMENT_RECIPIENTS:
                await interaction.edit_original_response(
                    content=(
                        "This action supports at most "
                        f"{MAX_ACHIEVEMENT_RECIPIENTS} users"
                    )
                )
                return
            all_definitions = await self._await_achievement_interaction_data(
                self._achievement_store.list_definitions(interaction.guild.id)
            )
            definitions = tuple(
                definition
                for definition in all_definitions
                if definition.grantable
            )
            if not definitions:
                await interaction.edit_original_response(
                    content="No achievements are available for manual grants"
                )
                return
            from .achievement_views import AchievementGrantView

            view = AchievementGrantView(
                self,
                source_message,
                interaction.user.id,
                candidates,
                definitions,
            )
            await interaction.edit_original_response(
                embed=view.render_embed(),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            view.message = await interaction.original_response()
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                action,
                error,
                public_defer=False,
            )

    async def _add_gate_proof_context_action(
        self,
        interaction: discord.Interaction,
        source_message: discord.Message,
    ) -> None:
        action = "add gate proof context action"
        permissions = interaction.permissions
        if (
            interaction.guild is None
            or permissions is None
            or not permissions.manage_messages
        ):
            await interaction.response.send_message(
                "You need Manage Messages permission",
                ephemeral=True,
            )
            return
        if not await self._defer_achievement_interaction(
            interaction,
            ephemeral=True,
        ):
            return
        try:
            is_bootstrapped = await self._await_achievement_interaction_data(
                self._achievement_store.is_bootstrapped(interaction.guild.id)
            )
            if not is_bootstrapped:
                await interaction.edit_original_response(
                    content=(
                        "Achievement data is still initializing. Run rolesync first"
                    )
                )
                return
            if await self._maybe_open_gate_proof_batch(
                interaction,
                source_message,
            ):
                return
            try:
                view = await self._build_normal_gate_proof_view(
                    interaction.guild,
                    source_message,
                    interaction.user.id,
                )
            except ValueError as error:
                await interaction.edit_original_response(content=str(error))
                return
            await interaction.edit_original_response(
                embed=view.render_embed(),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            view.message = await interaction.original_response()
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                action,
                error,
                public_defer=False,
            )

    async def _build_normal_gate_proof_view(
        self,
        guild: discord.Guild,
        source_message: discord.Message,
        opener_id: int,
    ):
        members = _build_achievement_candidates(source_message)
        if not members:
            raise ValueError("This message has no eligible recipients")
        missing_by_user = await self._await_achievement_interaction_data(
            self._achievement_store.missing_stargate_proofs(
                guild.id,
                tuple(member.id for member in members),
            )
        )
        candidates = _build_gate_proof_candidates(
            source_message,
            missing_by_user,
        )
        from .achievement_views import GateProofView

        return GateProofView(
            self,
            source_message,
            opener_id,
            candidates,
        )

    async def _open_normal_gate_proof_fallback(
        self,
        interaction: discord.Interaction,
        fallback_view,
    ) -> None:
        await interaction.response.defer()
        try:
            view = await self._build_normal_gate_proof_view(
                interaction.guild,
                fallback_view.source_message,
                fallback_view.opener_id,
            )
        except ValueError as error:
            await interaction.edit_original_response(
                content=str(error),
                embed=None,
                view=fallback_view,
            )
            return
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                "open normal gate proof fallback",
                error,
                public_defer=False,
            )
            return
        fallback_view.stop()
        await interaction.edit_original_response(
            content=None,
            embed=view.render_embed(),
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )
        view.message = interaction.message

    async def _show_gate_proof_batch_fallback(
        self,
        interaction: discord.Interaction,
        source_message: discord.Message,
        error_message: str,
    ) -> None:
        from .achievement_views import GateProofBatchFallbackView

        view = GateProofBatchFallbackView(
            self,
            source_message,
            interaction.user.id,
            error_message,
        )
        await interaction.edit_original_response(
            content=f"Gate proof batch failed\n{error_message}",
            embed=None,
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )
        view.message = await interaction.original_response()

    async def _maybe_open_gate_proof_batch(
        self,
        interaction: discord.Interaction,
        source_message: discord.Message,
    ) -> bool:
        try:
            view = await self._build_gate_proof_batch_view(
                interaction.guild,
                source_message,
                interaction.user.id,
            )
        except ValueError as error:
            await self._show_gate_proof_batch_fallback(
                interaction,
                source_message,
                str(error),
            )
            return True
        if view is None:
            return False

        await interaction.edit_original_response(
            embed=view.render_embed(),
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )
        view.message = await interaction.original_response()
        return True

    async def _build_gate_proof_batch_view(
        self,
        guild: discord.Guild,
        source_message: discord.Message,
        opener_id: int,
    ):
        entries = _parse_gate_proof_batch(
            source_message.content,
            expected_guild_id=guild.id,
        )
        if entries is None:
            return None
        entries, members = await self._resolve_gate_proof_batch_members(
            guild,
            source_message,
            entries,
        )
        profiles = {}
        for member in members.values():
            profile = await self._await_achievement_interaction_data(
                self._achievement_store.get_profile(
                    guild.id,
                    member.id,
                )
            )
            profiles[member.id] = profile
        for entry in entries:
            profile = profiles[entry.user_id]
            if entry.ordinal > profile.stargate_count:
                raise ValueError(
                    f"Gate {entry.ordinal} does not exist for <@{entry.user_id}>"
                )

        from .achievement_views import GateProofBatchView

        requested_keys = {(entry.user_id, entry.ordinal) for entry in entries}
        return GateProofBatchView(
            self,
            source_message,
            opener_id,
            members,
            entries,
            existing_proofs={
                (user_id, proof.ordinal): proof
                for user_id, profile in profiles.items()
                for proof in profile.stargate_proofs
                if (user_id, proof.ordinal) in requested_keys
            },
        )

    async def _resolve_gate_proof_batch_members(
        self,
        guild: discord.Guild,
        source_message: discord.Message,
        entries: tuple[GateProofBatchEntry, ...],
    ) -> tuple[tuple[GateProofBatchEntry, ...], dict[int, discord.Member]]:
        normalized_entries = []
        for entry in entries:
            user_id = (
                entry.user_id
                if entry.user_id is not None
                else source_message.author.id
            )
            normalized_entries.append(
                GateProofBatchEntry(
                    user_id,
                    entry.ordinal,
                    entry.source_guild_id,
                    entry.source_channel_id,
                    entry.source_message_id,
                )
            )
        normalized = tuple(normalized_entries)
        if source_message.webhook_id is not None and any(
            entry.user_id is None for entry in entries
        ):
            raise ValueError(
                "A Gate proof batch without user targets must be posted by a server member"
            )

        members = {}
        for entry in normalized:
            user_id = entry.user_id
            assert user_id is not None
            if user_id in members:
                continue
            member = guild.get_member(user_id)
            if member is None:
                try:
                    member = await guild.fetch_member(user_id)
                except discord.NotFound:
                    member = None
            if member is None or member.bot:
                raise ValueError(
                    f"<@{user_id}> is not an eligible current server member"
                )
            members[user_id] = member
        return normalized, members

    async def _confirm_gate_proofs(self, interaction, view) -> None:
        await interaction.response.defer()
        assignments = dict(view.selected_assignments)
        if not assignments:
            await interaction.edit_original_response(
                embed=view.render_embed(notice="Select at least one Gate proof"),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        try:
            source_message = await self._fetch_gate_increment_source(
                self._gate_increment_key(view.source_message)
            )
            await self._require_private_moderation_log_channel(
                source_message.guild
            )
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(
                embed=view.render_embed(notice=str(error)),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                "confirm gate proofs",
                error,
                public_defer=False,
            )
            return
        current_candidate_ids = tuple(
            member.id for member in _build_achievement_candidates(source_message)
        )
        if current_candidate_ids != view.candidate_ids:
            view.stop()
            await interaction.edit_original_response(
                content="The source message changed. Start again",
                embed=None,
                view=None,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        try:
            await self._achievement_store.attach_stargate_proofs(
                source_message.guild.id,
                assignments,
                source_channel_id=source_message.channel.id,
                source_message_id=source_message.id,
            )
        except GateProofConflict:
            view.stop()
            await interaction.edit_original_response(
                content="Gate proof data changed. Start again",
                embed=None,
                view=None,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        assignment_lines = "\n".join(
            f"<@{user_id}>: Gate {ordinal}"
            for user_id, ordinal in assignments.items()
        )
        source_url = (
            "https://discord.com/channels/"
            f"{source_message.guild.id}/{source_message.channel.id}/"
            f"{source_message.id}"
        )
        log_delivered = await self._send_moderation_log(
            source_message.guild,
            "Gate proofs attached\n"
            f"Moderator: <@{interaction.user.id}>\n"
            f"{assignment_lines}\n"
            f"Source: {source_url}",
            log_failure=False,
        )
        await self._finish_action_interaction(
            interaction,
            view,
            "Gate proofs were attached, but the moderation log could not be sent"
            if not log_delivered
            else "",
        )

    async def _confirm_gate_proof_batch(
        self,
        interaction,
        view,
        *,
        replace_existing: bool,
    ) -> None:
        await interaction.response.defer()
        try:
            source_message = await self._fetch_gate_increment_source(
                self._gate_increment_key(view.source_message)
            )
            await self._require_private_moderation_log_channel(
                source_message.guild
            )
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(
                embed=view.render_embed(notice=str(error)),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                "confirm gate proof batch",
                error,
                public_defer=False,
            )
            return
        current_members: dict[int, discord.Member] = {}
        try:
            current_entries = _parse_gate_proof_batch(
                source_message.content,
                expected_guild_id=source_message.guild.id,
            )
            if current_entries is not None:
                current_entries, current_members = (
                    await self._resolve_gate_proof_batch_members(
                        source_message.guild,
                        source_message,
                        current_entries,
                    )
                )
        except ValueError:
            current_entries = None
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                "confirm gate proof batch",
                error,
                public_defer=False,
            )
            return
        if (
            current_entries != view.entries
            or set(current_members) != set(view.members)
        ):
            view.stop()
            await interaction.edit_original_response(
                content="The source message changed. Start again",
                embed=None,
                view=None,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        selected_entries = tuple(
            entry
            for entry in view.entries
            if replace_existing
            or (entry.user_id, entry.ordinal) not in view.existing_proofs
        )
        assignments = tuple(
            StargateProofAssignment(
                entry.user_id,
                StargateProof(
                    entry.ordinal,
                    entry.source_channel_id,
                    entry.source_message_id,
                ),
            )
            for entry in view.entries
        )
        try:
            await self._achievement_store.apply_stargate_proof_batch(
                source_message.guild.id,
                assignments,
                expected_proofs={
                    (assignment.user_id, assignment.proof.ordinal): (
                        view.existing_proofs.get(
                            (assignment.user_id, assignment.proof.ordinal)
                        )
                    )
                    for assignment in assignments
                },
                replace_existing=replace_existing,
            )
        except GateProofConflict:
            view.stop()
            await interaction.edit_original_response(
                content="Gate proof data changed. Start again",
                embed=None,
                view=None,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        proof_lines = "\n".join(
            f"<@{entry.user_id}>: Gate {entry.ordinal}: {entry.jump_url}"
            for entry in selected_entries
        )
        log_action = (
            "Batch Gate proofs updated"
            if replace_existing
            else "Batch Gate proofs attached"
        )
        log_delivered = await self._send_moderation_log(
            source_message.guild,
            f"{log_action}\n"
            f"Moderator: <@{interaction.user.id}>\n"
            f"{proof_lines}\n"
            f"Request: {source_message.jump_url}",
            log_failure=False,
        )
        await self._finish_action_interaction(
            interaction,
            view,
            "Gate proofs were updated, but the moderation log could not be sent"
            if not log_delivered
            else "",
        )

    async def _confirm_achievement_grant(self, interaction, view) -> None:
        await interaction.response.defer()
        if not view.selected_user_ids or not view.selected_keys:
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="Select at least one recipient and achievement"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        try:
            source_message = await self._fetch_gate_increment_source(
                self._gate_increment_key(view.source_message)
            )
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(
                embed=view.render_embed(notice=str(error)),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                "confirm achievement grant",
                error,
                public_defer=False,
            )
            return
        candidates = _build_achievement_candidates(source_message)
        if tuple(member.id for member in candidates) != view.candidate_ids:
            view.source_message = source_message
            view.replace_candidates(candidates)
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="The source message changed. Review the recipients again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        selected_members = tuple(
            member for member in candidates if member.id in view.selected_user_ids
        )
        selected_definitions = tuple(
            definition
            for definition in view.definitions
            if definition.key in view.selected_keys
        )
        current_definitions = {
            definition.key: definition
            for definition in await self._achievement_store.list_definitions(
                source_message.guild.id
            )
        }
        if any(
            current_definitions.get(definition.key) != definition
            for definition in selected_definitions
        ):
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="Achievement configuration changed. Start again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        try:
            projected_roles = self._validate_achievement_role_projection(
                source_message.guild,
                selected_definitions,
            )
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(
                embed=view.render_embed(notice=str(error)),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return

        created_grants: list[tuple[int, tuple[str, ...]]] = []
        already_count = 0
        failed_members = 0
        for member in selected_members:
            created_keys, already, failed = await self._grant_achievements_to_member(
                source_message,
                member,
                selected_definitions,
                projected_roles,
            )
            if created_keys:
                created_grants.append((member.id, created_keys))
            already_count += already
            failed_members += int(failed)
        created_count = sum(len(keys) for _, keys in created_grants)
        moderation_log_delivered = True
        if created_count:
            achievements = ", ".join(
                f"{definition.display_name} (`{definition.key}`)"
                for definition in selected_definitions
            )
            recipients = ", ".join(
                f"<@{member.id}>" for member in selected_members
            )
            source_url = (
                "https://discord.com/channels/"
                f"{source_message.guild.id}/{source_message.channel.id}/"
                f"{source_message.id}"
            )
            moderation_log_delivered = await self._send_moderation_log(
                source_message.guild,
                "Achievements granted\n"
                f"Moderator: <@{interaction.user.id}>\n"
                f"Recipients: {recipients}\n"
                f"Achievements: {achievements}\n"
                f"Awards created: {created_count}\n"
                f"Source: {source_url}",
                log_failure=False,
            )
        congratulations_published = await self._publish_achievement_grant_result(
            source_message,
            tuple(created_grants),
            current_definitions,
        )
        if failed_members:
            await self._send_error_notice(
                source_message.guild,
                "Achievement grant partially failed\n"
                f"Moderator: <@{interaction.user.id}>\n"
                f"Members skipped: {failed_members}",
                ping=False,
            )
        await self._finish_action_interaction(
            interaction,
            view,
            f"{failed_members} users could not be updated" if failed_members else "",
            "the moderation log could not be sent"
            if not moderation_log_delivered
            else "",
            "the congratulations message could not be sent"
            if not congratulations_published
            else "",
        )

    @commands.group(name="achievement", invoke_without_command=True)
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement(self, ctx: commands.Context) -> None:
        """Manage member achievements"""
        embed = discord.Embed(
            title="Achievements",
            description=(
                "View profiles with `/achievements` or Apps → View achievements\n"
                "Grant achievements with Apps → Grant achievements\n"
                "Increment Gates with Apps → Increment Gate roles\n"
                "Revoke Gates with `/gaterevoke` or Apps → Revoke Gate\n"
                "Attach proofs with Apps → Add Gate Proof or "
                f"`{ctx.clean_prefix}achievement proof <message_link>`"
            ),
        )
        embed.add_field(
            name="Commands",
            value=self._format_direct_commands(ctx),
            inline=False,
        )
        await ctx.send(
            embed=embed,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @achievement.command(name="proof")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_proof(
        self,
        ctx: commands.Context,
        message_link: str,
    ) -> None:
        """Open a review for attaching the linked message as a Gate proof"""
        self._require_private_achievement_channel(ctx)
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run "
                f"`{ctx.clean_prefix}rolesync discord` first"
            )
        source_message = await self._resolve_gate_proof_message_link(
            ctx,
            message_link,
        )

        try:
            view = await self._build_gate_proof_batch_view(
                ctx.guild,
                source_message,
                ctx.author.id,
            )
        except ValueError as error:
            from .achievement_views import GateProofBatchFallbackView

            view = GateProofBatchFallbackView(
                self,
                source_message,
                ctx.author.id,
                str(error),
            )
            view.message = await ctx.send(
                content=f"Gate proof batch failed\n{error}",
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return

        if view is None:
            try:
                view = await self._build_normal_gate_proof_view(
                    ctx.guild,
                    source_message,
                    ctx.author.id,
                )
            except ValueError as error:
                raise commands.UserFeedbackCheckFailure(str(error)) from error
        view.message = await ctx.send(
            embed=view.render_embed(),
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _resolve_gate_proof_message_link(
        self,
        ctx: commands.Context,
        value: str,
    ) -> discord.Message:
        match = MESSAGE_LINK_PATTERN.fullmatch(value)
        if match is None or int(match.group(1)) != ctx.guild.id:
            raise commands.UserFeedbackCheckFailure(
                "The proof message link must be from the current server"
            )
        channel_id = int(match.group(2))
        message_id = int(match.group(3))
        channel = ctx.guild.get_channel_or_thread(channel_id)
        if channel is None:
            try:
                channel = await ctx.guild.fetch_channel(channel_id)
            except (discord.NotFound, discord.Forbidden) as error:
                raise commands.UserFeedbackCheckFailure(
                    "The proof message channel is unavailable"
                ) from error
        fetch_message = getattr(channel, "fetch_message", None)
        if not callable(fetch_message):
            raise commands.UserFeedbackCheckFailure(
                "The proof message channel is unavailable"
            )
        try:
            return await fetch_message(message_id)
        except (discord.NotFound, discord.Forbidden) as error:
            raise commands.UserFeedbackCheckFailure(
                "The proof message is unavailable"
            ) from error

    @achievement.command(name="create")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_create(
        self, ctx: commands.Context, *, display_name: str
    ) -> None:
        """Create a boolean achievement without a Discord role"""
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run `!rolesync discord` first"
            )
        try:
            definition = await self._achievement_store.create_boolean_definition(
                ctx.guild.id,
                display_name,
            )
        except ValueError as error:
            raise commands.UserFeedbackCheckFailure(str(error)) from error
        await ctx.send(f"Created achievement: {definition.display_name}")
        await self._send_moderation_log(
            ctx.guild,
            "Achievement created\n"
            f"Moderator: <@{ctx.author.id}>\n"
            f"Achievement: {definition.display_name}\n"
            f"Key: `{definition.key}`",
        )

    def _require_private_achievement_channel(self, ctx: commands.Context) -> None:
        if self._channel_is_public(ctx):
            raise commands.UserFeedbackCheckFailure(
                "Achievement administration is unavailable in this channel"
            )

    @achievement.command(name="list")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_list(self, ctx: commands.Context) -> None:
        """List achievement names, stable keys, and optional role bindings"""
        self._require_private_achievement_channel(ctx)
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run `!rolesync discord` first"
            )
        definitions = await self._achievement_store.list_definitions(ctx.guild.id)
        if not definitions:
            await ctx.send("No achievements are configured")
            return
        embed = discord.Embed(title="Achievements")
        for definition in definitions:
            role = (
                f"<@&{definition.role_id}>"
                if definition.role_id is not None
                else "No Discord role"
            )
            embed.add_field(
                name=definition.display_name,
                value=f"Key: `{definition.key}`\nRole: {role}",
                inline=False,
            )
        await ctx.send(
            embed=embed,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @achievement.command(name="missingproofs")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_missingproofs(self, ctx: commands.Context) -> None:
        """Export current Gate holders whose recorded Gates lack proof links"""
        self._require_private_achievement_export_channel(ctx)
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run `!rolesync discord` first"
            )
        if (
            not bool(ctx.guild.chunked)
            or ctx.guild.member_count is None
            or len(ctx.guild.members) != ctx.guild.member_count
        ):
            raise commands.UserFeedbackCheckFailure(
                "The member cache is incomplete. Run `!rolesync` first"
            )

        missing_by_user = (
            await self._achievement_store.list_missing_stargate_proofs(ctx.guild.id)
        )
        affected = [
            (member, missing_by_user[member.id])
            for member in ctx.guild.members
            if not member.bot and member.id in missing_by_user
        ]
        affected.sort(
            key=lambda item: (
                -len(item[1]),
                item[0].display_name.casefold(),
                item[0].id,
            )
        )
        if not affected:
            await ctx.send("All current Gate holders have proofs for every Gate")
            return

        try:
            payload = build_csv_export(
                ("user_id", "username", "display_name", "missing_gates"),
                (
                    (
                        member.id,
                        member.name,
                        member.display_name,
                        ", ".join(map(str, missing_gates)),
                    )
                    for member, missing_gates in affected
                ),
                ctx.guild.filesize_limit,
                "missing-stargate-proofs",
            )
        except ExportTooLarge:
            await ctx.send("Export is too large to upload")
            return

        preview = affected[:20]
        embed = discord.Embed(
            title="Missing Stargate proofs",
            description="\n".join(
                f"<@{member.id}> — Gates {', '.join(map(str, missing_gates))}"
                for member, missing_gates in preview
            ),
        )
        embed.add_field(
            name="Summary",
            value=(
                f"Affected members: {len(affected)}\n"
                f"Missing proofs: {sum(len(gates) for _, gates in affected)}"
            ),
            inline=False,
        )
        embed.set_footer(text="Complete report attached")
        await ctx.send(
            embed=embed,
            file=discord.File(io.BytesIO(payload.data), filename=payload.filename),
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @achievement.command(name="rename")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_rename(
        self,
        ctx: commands.Context,
        achievement_key: str,
        *,
        display_name: str,
    ) -> None:
        """Change an achievement's display name without changing its key"""
        self._require_private_achievement_channel(ctx)
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run `!rolesync discord` first"
            )
        try:
            definition = await self._achievement_store.rename_definition(
                ctx.guild.id,
                achievement_key,
                display_name,
            )
        except (LookupError, ValueError) as error:
            raise commands.UserFeedbackCheckFailure(str(error)) from error
        await ctx.send(
            f"Renamed achievement `{definition.key}` to {definition.display_name}"
        )
        await self._send_moderation_log(
            ctx.guild,
            "Achievement renamed\n"
            f"Moderator: <@{ctx.author.id}>\n"
            f"Key: `{definition.key}`\n"
            f"New name: {definition.display_name}",
        )

    @achievement.command(name="delete", aliases=("del",))
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_delete(
        self,
        ctx: commands.Context,
        achievement_key: str,
    ) -> None:
        """Permanently delete an unbound achievement and all of its awards"""
        self._require_private_achievement_channel(ctx)
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run `!rolesync discord` first"
            )
        try:
            preview = await self._achievement_store.prepare_definition_deletion(
                ctx.guild.id,
                achievement_key,
            )
        except (LookupError, ValueError) as error:
            raise commands.UserFeedbackCheckFailure(str(error)) from error
        from .achievement_views import AchievementDeleteView

        view = AchievementDeleteView(self, ctx.author.id, preview)
        view.message = await ctx.send(
            embed=view.render_embed(),
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _confirm_achievement_delete(
        self,
        interaction: discord.Interaction,
        view,
    ) -> None:
        await interaction.response.defer()
        try:
            deleted = await self._achievement_store.delete_definition(
                interaction.guild.id,
                view.preview.definition.key,
                expected_award_count=view.preview.award_count,
            )
        except (LookupError, RuntimeError, ValueError) as error:
            await interaction.edit_original_response(
                embed=view.render_embed(notice=str(error)),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        log_delivered = await self._send_moderation_log(
            interaction.guild,
            "Achievement deleted\n"
            f"Moderator: <@{interaction.user.id}>\n"
            f"Achievement: {deleted.definition.display_name}\n"
            f"Key: `{deleted.definition.key}`\n"
            f"Awards deleted: {deleted.award_count}",
            log_failure=False,
        )
        await self._finish_action_interaction(
            interaction,
            view,
            "The achievement was deleted, but the moderation log could not be sent"
            if not log_delivered
            else "",
        )

    @achievement.group(name="role", invoke_without_command=True)
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_role(self, ctx: commands.Context) -> None:
        """Manage optional Discord role bindings for achievements"""
        embed = discord.Embed(
            title="Achievement roles",
            description="Manage optional Discord role bindings for achievements",
        )
        embed.add_field(
            name="Commands",
            value=self._format_direct_commands(
                ctx,
                preferred_order=("bind", "unbind", "replace", "list"),
            ),
            inline=False,
        )
        await ctx.send(
            embed=embed,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @achievement_role.command(name="bind")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_role_bind(
        self, ctx: commands.Context, role: discord.Role
    ) -> None:
        """Choose an achievement and bind it to an existing Discord role"""
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run `!rolesync discord` first"
            )
        if role.id in GATE_TIER_ROLE_IDS:
            raise commands.UserFeedbackCheckFailure(
                "Gate progression roles cannot be bound as boolean achievements"
            )
        definitions = await self._achievement_store.list_definitions(ctx.guild.id)
        if any(definition.role_id == role.id for definition in definitions):
            raise commands.UserFeedbackCheckFailure(
                "This role is already bound to an achievement"
            )
        unbound = tuple(
            definition for definition in definitions if definition.role_id is None
        )
        if not unbound:
            raise commands.UserFeedbackCheckFailure(
                "There are no unbound achievements"
            )
        if len(unbound) > 25:
            raise commands.UserFeedbackCheckFailure(
                "There are too many unbound achievements for one selection menu"
            )
        users_by_role = await self._role_analytics_users_with_roles(
            ctx.guild.id,
            (role.id,),
        )
        if users_by_role is None:
            raise commands.UserFeedbackCheckFailure(
                "Role analytics is not ready. Run `!rolesync` first"
            )
        from .achievement_views import AchievementRoleBindView

        view = AchievementRoleBindView(
            self,
            ctx.author.id,
            role,
            users_by_role[0],
            unbound,
        )
        view.message = await ctx.send(
            embed=view.render_embed(),
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _grant_achievements_to_member(
        self,
        source_message: discord.Message,
        member: discord.Member,
        definitions: tuple,
        projected_roles: tuple,
    ) -> tuple[tuple[str, ...], int, bool]:
        created_keys = []
        already_count = 0
        for definition in definitions:
            result = await self._achievement_store.grant_boolean(
                source_message.guild.id,
                member.id,
                definition.key,
                source_channel_id=source_message.channel.id,
                source_message_id=source_message.id,
            )
            if result.created:
                created_keys.append(definition.key)
            else:
                already_count += 1
        if not projected_roles:
            return tuple(created_keys), already_count, False
        try:
            await self._edit_achievement_roles(
                source_message.guild,
                member,
                add_role_ids=tuple(role.id for role in projected_roles),
                reason=f"Achievement grant from message {source_message.id}",
            )
        except (discord.Forbidden, discord.HTTPException):
            await self._achievement_store.revoke_booleans(
                source_message.guild.id,
                (member.id,),
                tuple(created_keys),
            )
            return (), already_count, True
        return tuple(created_keys), already_count, False

    @staticmethod
    async def _publish_achievement_grant_result(
        source_message: discord.Message,
        created_grants: tuple[tuple[int, tuple[str, ...]], ...],
        definitions: dict[str, AchievementDefinition],
    ) -> bool:
        lines = []
        for user_id, keys in created_grants:
            labels = []
            for key in keys:
                definition = definitions[key]
                labels.append(
                    f"<@&{definition.role_id}>"
                    if definition.role_id is not None
                    else definition.display_name
                )
            lines.append(f"<@{user_id}> {', '.join(labels)}")
        if not lines:
            return True
        try:
            await source_message.reply(
                "🎉 **Congratulations!**\n" + "\n".join(lines),
                allowed_mentions=discord.AllowedMentions(
                    users=True,
                    roles=False,
                    everyone=False,
                    replied_user=False,
                ),
            )
        except discord.HTTPException:
            log.exception(
                "Failed to publish achievement grant result for message %s",
                source_message.id,
            )
            return False
        return True

    async def _confirm_achievement_role_bind(self, interaction, view) -> None:
        await interaction.response.defer()
        definitions = await self._achievement_store.list_definitions(
            interaction.guild.id
        )
        selected = next(
            (
                definition
                for definition in definitions
                if definition.key == view.selected_key
                and definition.role_id is None
            ),
            None,
        )
        role_is_bound = any(
            definition.role_id == view.role.id for definition in definitions
        )
        if selected is None or role_is_bound:
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="Achievement configuration changed. Start again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        users_by_role = await self._role_analytics_users_with_roles(
            interaction.guild.id,
            (view.role.id,),
        )
        if users_by_role is None:
            await interaction.edit_original_response(
                embed=view.render_embed(notice="Role analytics is not ready"),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        if users_by_role[0] != view.holder_ids:
            view.holder_ids = users_by_role[0]
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="Role holders changed. Review the plan again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        result = await self._achievement_store.bind_role(
            interaction.guild.id,
            selected.key,
            role_id=view.role.id,
            user_ids=view.holder_ids,
        )
        log_delivered = await self._send_moderation_log(
            interaction.guild,
            "Achievement role bound\n"
            f"Moderator: <@{interaction.user.id}>\n"
            f"Achievement: {result.definition.display_name} "
            f"(`{result.definition.key}`)\n"
            f"Role: {view.role.mention}\n"
            f"Imported awards: {result.imported_count}",
            log_failure=False,
        )
        await self._finish_action_interaction(
            interaction,
            view,
            "The role was bound, but the moderation log could not be sent"
            if not log_delivered
            else "",
        )
        await self._reconcile_achievement_roles_for_guild(interaction.guild)

    @achievement_role.command(name="unbind")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_role_unbind(
        self, ctx: commands.Context, role: discord.Role
    ) -> None:
        """Stop tracking a Discord role without deleting achievement history"""
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run `!rolesync discord` first"
            )
        try:
            definition = await self._achievement_store.unbind_role(
                ctx.guild.id,
                role.id,
            )
        except LookupError as error:
            raise commands.UserFeedbackCheckFailure(
                "This role is not bound to an achievement"
            ) from error
        await ctx.send(
            f"Stopped tracking {role.mention} for {definition.display_name}",
            allowed_mentions=discord.AllowedMentions.none(),
        )
        await self._send_moderation_log(
            ctx.guild,
            "Achievement role unbound\n"
            f"Moderator: <@{ctx.author.id}>\n"
            f"Achievement: {definition.display_name} (`{definition.key}`)\n"
            f"Role: {role.mention}",
        )

    @achievement_role.command(name="replace")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_role_replace(
        self,
        ctx: commands.Context,
        old_role: discord.Role,
        new_role: discord.Role,
    ) -> None:
        """Move an achievement binding to another Discord role"""
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run `!rolesync discord` first"
            )
        if old_role.id == new_role.id:
            raise commands.UserFeedbackCheckFailure("Choose two different roles")
        if new_role.id in GATE_TIER_ROLE_IDS:
            raise commands.UserFeedbackCheckFailure(
                "Gate progression roles cannot be bound as boolean achievements"
            )
        definitions = await self._achievement_store.list_definitions(ctx.guild.id)
        definition = next(
            (
                item for item in definitions if item.role_id == old_role.id
            ),
            None,
        )
        if definition is None:
            raise commands.UserFeedbackCheckFailure(
                "The old role is not bound to an achievement"
            )
        if any(item.role_id == new_role.id for item in definitions):
            raise commands.UserFeedbackCheckFailure(
                "The new role is already bound to an achievement"
            )
        users_by_role = await self._role_analytics_users_with_roles(
            ctx.guild.id,
            (old_role.id, new_role.id),
        )
        if users_by_role is None:
            raise commands.UserFeedbackCheckFailure(
                "Role analytics is not ready. Run `!rolesync` first"
            )
        stored_holder_ids = tuple(
            await self._achievement_store.projected_users_for_boolean(
                ctx.guild.id,
                definition.key,
            )
        )
        from .achievement_views import AchievementRoleReplaceView

        view = AchievementRoleReplaceView(
            self,
            ctx.author.id,
            definition,
            old_role,
            new_role,
            stored_holder_ids=stored_holder_ids,
            old_holder_ids=users_by_role[0],
            new_holder_ids=users_by_role[1],
        )
        view.message = await ctx.send(
            embed=view.render_embed(),
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _confirm_achievement_role_replace(
        self,
        interaction: discord.Interaction,
        view,
        *,
        remove_old: bool,
    ) -> None:
        await interaction.response.defer()
        definitions = await self._achievement_store.list_definitions(
            interaction.guild.id
        )
        current_definition = next(
            (
                definition
                for definition in definitions
                if definition.key == view.definition.key
            ),
            None,
        )
        new_role_is_bound = any(
            definition.role_id == view.new_role.id for definition in definitions
        )
        if current_definition != view.definition or new_role_is_bound:
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="Achievement configuration changed. Start again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return

        users_by_role = await self._role_analytics_users_with_roles(
            interaction.guild.id,
            (view.old_role.id, view.new_role.id),
        )
        if users_by_role is None:
            await interaction.edit_original_response(
                embed=view.render_embed(notice="Role analytics is not ready"),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        if users_by_role != (view.old_holder_ids, view.new_holder_ids):
            view.old_holder_ids, view.new_holder_ids = users_by_role
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="Role holders changed. Review the plan again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return

        if (
            interaction.guild.get_role(view.old_role.id) is None
            or interaction.guild.get_role(view.new_role.id) is None
        ):
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="A reviewed role no longer exists. Start again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return

        replacement_holder_ids = tuple(
            sorted(set(view.old_holder_ids) | set(view.new_holder_ids))
        )
        try:
            result = await self._achievement_store.replace_role(
                interaction.guild.id,
                achievement_key=view.definition.key,
                old_role_id=view.old_role.id,
                new_role_id=view.new_role.id,
                user_ids=replacement_holder_ids,
            )
        except (LookupError, ValueError):
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="Achievement configuration changed. Start again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        projected_user_ids = set(
            await self._achievement_store.projected_users_for_boolean(
                interaction.guild.id,
                result.definition.key,
            )
        )
        old_holder_ids = set(view.old_holder_ids)
        new_holder_ids = set(view.new_holder_ids)
        affected_user_ids = projected_user_ids | (
            old_holder_ids if remove_old else set()
        )
        changed_members = 0
        skipped_members = 0
        for user_id in sorted(affected_user_ids):
            add_role_ids = (
                (view.new_role.id,)
                if user_id in projected_user_ids and user_id not in new_holder_ids
                else ()
            )
            remove_role_ids = (
                (view.old_role.id,)
                if remove_old and user_id in old_holder_ids
                else ()
            )
            if not add_role_ids and not remove_role_ids:
                continue
            member = interaction.guild.get_member(user_id)
            try:
                if member is None:
                    member = await interaction.guild.fetch_member(user_id)
                await self._edit_achievement_roles(
                    interaction.guild,
                    member,
                    add_role_ids=add_role_ids,
                    remove_role_ids=remove_role_ids,
                    reason=f"Replace achievement role by {interaction.user.id}",
                )
                changed_members += 1
            except commands.UserFeedbackCheckFailure:
                skipped_members += 1
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                skipped_members += 1

        mode = "move members" if remove_old else "keep old role"
        moderation_log_delivered = await self._send_moderation_log(
            interaction.guild,
            "Achievement role replaced\n"
            f"Moderator: <@{interaction.user.id}>\n"
            f"Achievement: {result.definition.display_name} "
            f"(`{result.definition.key}`)\n"
            f"Old role: {view.old_role.mention}\n"
            f"New role: {view.new_role.mention}\n"
            f"Mode: {mode}\n"
            f"Imported awards: {result.imported_count}\n"
            f"Members changed: {changed_members}\n"
            f"Members skipped: {skipped_members}",
            log_failure=False,
        )
        if skipped_members:
            await self._send_error_notice(
                interaction.guild,
                "Achievement role replacement partially failed\n"
                f"Achievement: `{result.definition.key}`\n"
                f"Members skipped: {skipped_members}",
                ping=False,
            )
        await self._finish_action_interaction(
            interaction,
            view,
            f"{skipped_members} members could not be updated"
            if skipped_members
            else "",
            "the moderation log could not be sent"
            if not moderation_log_delivered
            else "",
        )

    @achievement_role.command(name="list")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_role_list(self, ctx: commands.Context) -> None:
        """List all active achievement role bindings"""
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run `!rolesync discord` first"
            )
        definitions = await self._achievement_store.list_definitions(ctx.guild.id)
        lines = [
            f"<@&{definition.role_id}> {definition.display_name}"
            for definition in definitions
            if definition.role_id is not None
        ]
        await ctx.send(
            "\n".join(lines) if lines else "No achievement roles are configured",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @achievement.command(name="revoke")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def achievement_revoke(
        self,
        ctx: commands.Context,
        *members: discord.Member,
    ) -> None:
        """Review and revoke achievements shared by all selected members"""
        unique_members = tuple({member.id: member for member in members}.values())
        if not unique_members:
            raise commands.UserFeedbackCheckFailure("Mention at least one user")
        if len(unique_members) > MAX_ACHIEVEMENT_RECIPIENTS:
            raise commands.UserFeedbackCheckFailure(
                f"Select at most {MAX_ACHIEVEMENT_RECIPIENTS} users"
            )
        if not await self._achievement_store.is_bootstrapped(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Achievement data is still initializing. Run rolesync first"
            )
        shared_keys = set(
            await self._achievement_store.shared_boolean_keys(
                ctx.guild.id,
                tuple(member.id for member in unique_members),
            )
        )
        catalog = await self._achievement_store.list_definitions(ctx.guild.id)
        definitions = tuple(
            definition
            for definition in catalog
            if definition.revocable and definition.key in shared_keys
        )
        if not definitions:
            raise commands.UserFeedbackCheckFailure(
                "The selected users have no shared revocable achievements"
            )
        from .achievement_views import AchievementRevokeView

        view = AchievementRevokeView(
            self,
            ctx.author.id,
            unique_members,
            definitions,
        )
        view.message = await ctx.send(
            embed=view.render_embed(),
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _confirm_achievement_revoke(self, interaction, view) -> None:
        await interaction.response.defer()
        shared_keys = set(
            await self._achievement_store.shared_boolean_keys(
                interaction.guild.id,
                tuple(member.id for member in view.members),
            )
        )
        if not view.selected_keys or not view.selected_keys <= shared_keys:
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="Achievement ownership changed. Start the command again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        selected_definitions = tuple(
            definition
            for definition in view.definitions
            if definition.key in view.selected_keys
        )
        current_definitions = {
            definition.key: definition
            for definition in await self._achievement_store.list_definitions(
                interaction.guild.id
            )
        }
        if any(
            current_definitions.get(definition.key) != definition
            for definition in selected_definitions
        ):
            await interaction.edit_original_response(
                embed=view.render_embed(
                    notice="Achievement configuration changed. Start again"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        try:
            projected_roles = self._validate_achievement_role_projection(
                interaction.guild,
                selected_definitions,
            )
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(
                embed=view.render_embed(notice=str(error)),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        role_ids = tuple(role.id for role in projected_roles)
        achievement_keys = tuple(
            definition.key for definition in selected_definitions
        )
        revoked_count = 0
        failed_members = 0
        for member in view.members:
            revoked_count += await self._achievement_store.revoke_booleans(
                interaction.guild.id,
                (member.id,),
                achievement_keys,
            )
            try:
                if role_ids:
                    await self._edit_achievement_roles(
                        interaction.guild,
                        member,
                        remove_role_ids=role_ids,
                        reason=f"Achievement revocation by {interaction.user.id}",
                    )
            except (discord.Forbidden, discord.HTTPException):
                failed_members += 1
                continue
        moderation_log_delivered = True
        if revoked_count:
            achievements = ", ".join(
                f"{definition.display_name} (`{definition.key}`)"
                for definition in selected_definitions
            )
            members = ", ".join(f"<@{member.id}>" for member in view.members)
            moderation_log_delivered = await self._send_moderation_log(
                interaction.guild,
                "Achievements revoked\n"
                f"Moderator: <@{interaction.user.id}>\n"
                f"Members: {members}\n"
                f"Achievements: {achievements}\n"
                f"Awards revoked: {revoked_count}",
                log_failure=False,
            )
        if failed_members:
            await self._send_error_notice(
                interaction.guild,
                "Achievement revoke partially failed\n"
                f"Moderator: <@{interaction.user.id}>\n"
                f"Members with roles not updated: {failed_members}",
                ping=False,
            )
        await self._finish_action_interaction(
            interaction,
            view,
            f"{failed_members} users could not be updated" if failed_members else "",
            "the moderation log could not be sent"
            if not moderation_log_delivered
            else "",
        )

    @staticmethod
    def _validate_achievement_role_projection(
        guild: discord.Guild,
        definitions: tuple,
    ) -> tuple:
        role_ids = tuple(
            definition.role_id
            for definition in definitions
            if definition.role_id is not None
        )
        if not role_ids:
            return ()
        bot_member = guild.me
        permissions = getattr(bot_member, "guild_permissions", None)
        if bot_member is None or not permissions or not permissions.manage_roles:
            raise commands.UserFeedbackCheckFailure("I need Manage Roles permission")
        roles = tuple(guild.get_role(role_id) for role_id in role_ids)
        if any(
            role is None
            or role.managed
            or role.position >= bot_member.top_role.position
            for role in roles
        ):
            raise commands.UserFeedbackCheckFailure(
                "Achievement roles are configured incorrectly"
            )
        return roles

    @staticmethod
    async def _edit_achievement_roles(
        guild: discord.Guild,
        member: discord.Member,
        *,
        add_role_ids: tuple[int, ...] = (),
        remove_role_ids: tuple[int, ...] = (),
        reason: str,
    ) -> None:
        add_ids = set(add_role_ids)
        remove_ids = set(remove_role_ids)
        current_ids = {
            role.id
            for role in member.roles
            if role.id != guild.default_role.id
        }
        desired_ids = (current_ids | add_ids) - remove_ids
        desired_roles = [
            guild.get_role(role_id)
            for role_id in desired_ids
        ]
        if any(role is None for role in desired_roles):
            raise commands.UserFeedbackCheckFailure(
                "Achievement roles are configured incorrectly"
            )
        if desired_ids == current_ids:
            return
        await member.edit(roles=desired_roles, reason=reason)

    @commands.group(name="rolesync", invoke_without_command=True)
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def rolesync(self, ctx: commands.Context) -> None:
        """Initialize or reconcile the role analytics database"""
        if self._role_analytics.is_syncing(ctx.guild.id):
            raise commands.UserFeedbackCheckFailure(
                "Role synchronization is already running"
            )
        await ctx.send("Role synchronization started")
        try:
            result = await self._role_analytics.sync_guild(ctx.guild, manual=True)
        except SyncAlreadyRunningError as error:
            raise commands.UserFeedbackCheckFailure(
                "Role synchronization is already running"
            ) from error
        except (MemberIntentRequiredError, FullMemberRequestCooldownError) as error:
            log.warning("Role synchronization unavailable for guild %s: %s", ctx.guild.id, error)
            raise commands.UserFeedbackCheckFailure(
                "Role synchronization is unavailable right now"
            ) from error
        except Exception as error:
            log.exception("Role synchronization failed for guild %s", ctx.guild.id)
            await self.report_operational_error(
                guild_id=ctx.guild.id,
                source="NHMisc",
                action="synchronize role analytics",
                error=error,
                channel_id=ctx.channel.id,
                message_id=ctx.message.id,
            )
            raise commands.UserFeedbackCheckFailure(
                "Role synchronization failed"
            ) from error

        if await self._achievement_store.is_bootstrapped(ctx.guild.id):
            await self._reconcile_achievement_roles_for_guild(ctx.guild)

        await ctx.send(
            f"Role synchronization complete: {result.member_count} members, "
            f"{result.membership_count} role memberships in {result.elapsed_seconds:.1f}s"
        )

    async def _upload_achievement_sync_backup(
        self,
        guild: discord.Guild,
        alert_channel: discord.TextChannel,
        snapshot: DiscordRoleSnapshot,
    ) -> None:
        database_bytes = await self._achievement_store.backup_database()
        holder_ids = {
            user_id for user_ids in snapshot.role_holders.values() for user_id in user_ids
        }
        members_by_id = {member.id: member for member in guild.members}
        if not holder_ids.issubset(members_by_id):
            raise commands.UserFeedbackCheckFailure(
                "Discord member cache changed. Run `!rolesync discord` again"
            )
        discord_roles_bytes = build_discord_role_backup(
            guild_id=guild.id,
            snapshot_at=snapshot.snapshot_at,
            cached_member_count=snapshot.cached_member_count,
            reported_member_count=snapshot.reported_member_count,
            role_holders=snapshot.role_holders,
            user_names={
                user_id: (
                    members_by_id[user_id].name,
                    members_by_id[user_id].display_name,
                )
                for user_id in holder_ids
            },
        )
        artifacts = (
            ("database.sqlite3", database_bytes),
            ("discord-roles.jsonl.gz", discord_roles_bytes),
        )
        if any(len(data) > guild.filesize_limit for _name, data in artifacts):
            raise commands.UserFeedbackCheckFailure(
                "Achievement synchronization backup is too large to upload"
            )

        backup_id = uuid4().hex
        database_hash = hashlib.sha256(database_bytes).hexdigest()
        discord_roles_hash = hashlib.sha256(discord_roles_bytes).hexdigest()
        files = [
            discord.File(
                io.BytesIO(data),
                filename=f"achievement-sync-{backup_id}-{name}",
            )
            for name, data in artifacts
        ]
        try:
            await alert_channel.send(
                "Achievement synchronization backup\n"
                f"Database SHA-256: {database_hash}\n"
                f"Discord roles SHA-256: {discord_roles_hash}",
                files=files,
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except (discord.Forbidden, discord.HTTPException) as error:
            log.exception(
                "Failed to upload achievement synchronization backup for guild %s",
                guild.id,
            )
            raise commands.UserFeedbackCheckFailure(
                "Could not upload the achievement synchronization backup"
            ) from error

    async def _achievement_discord_sync_summary(
        self,
        guild_id: int,
        snapshot: DiscordRoleSnapshot,
        *,
        bootstrapped: bool,
    ) -> str:
        if not bootstrapped:
            return snapshot.render_initialization_summary()
        stored_gate_tiers = await self._achievement_store.list_gate_projections(
            guild_id
        )
        stored_boolean_users = {
            key: await self._achievement_store.active_users_for_boolean(
                guild_id, key
            )
            for key in snapshot.boolean_users
        }
        plan = build_discord_priority_plan(
            snapshot,
            stored_gate_tiers=stored_gate_tiers,
            stored_boolean_users=stored_boolean_users,
        )
        return plan.render_summary()

    async def _wait_for_achievement_sync_confirmation(
        self,
        *,
        guild_id: int,
        channel: discord.TextChannel,
        moderator_id: int,
    ) -> bool:
        def confirmation_check(message: discord.Message) -> bool:
            return (
                message.guild is not None
                and message.guild.id == guild_id
                and message.channel.id == channel.id
                and message.author.id == moderator_id
                and message.content.strip().lower() == "confirm"
            )

        try:
            await self.bot.wait_for(
                "message",
                check=confirmation_check,
                timeout=300,
            )
        except TimeoutError:
            await self._support.send_log_message(
                channel,
                "Achievement synchronization confirmation expired",
            )
            return False
        return True

    async def _apply_achievement_discord_snapshot(
        self,
        guild_id: int,
        snapshot: DiscordRoleSnapshot,
        *,
        bootstrapped: bool,
    ) -> str | None:
        if bootstrapped:
            result = await self._achievement_store.apply_discord_snapshot(
                guild_id,
                gate_tiers=snapshot.gate_tiers,
                boolean_users=snapshot.boolean_users,
            )
            return (
                "Achievement synchronization complete\n"
                f"Users changed: {result.changed_users}\n"
                f"Gate users changed: {result.gate_users_changed}\n"
                f"Achievements created: {result.boolean_grants}\n"
                f"Achievements revoked: {result.boolean_revocations}"
            )

        created = await self._achievement_store.bootstrap_guild(
            guild_id,
            gate_tiers=snapshot.gate_tiers,
            boolean_definitions=(SOLO_GATER_DEFINITION,),
            boolean_users=snapshot.boolean_users,
        )
        if not created:
            return None
        return (
            "Achievement initialization complete\n"
            f"Gate holders: {len(snapshot.gate_tiers)}\n"
            "Solo Gater holders: "
            f"{len(snapshot.boolean_users.get(SOLO_GATER_KEY, ()))}"
        )

    @rolesync.command(name="discord")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def rolesync_discord(self, ctx: commands.Context) -> None:
        """Replace achievement state from Discord roles in the operational error channel"""
        guild_id = ctx.guild.id
        if guild_id in self._achievement_syncing_guilds:
            raise commands.UserFeedbackCheckFailure(
                "Achievement synchronization is already awaiting confirmation"
            )
        error_channel = await self._require_rolesync_error_channel(ctx)
        self._achievement_syncing_guilds.add(guild_id)
        try:
            snapshot = await self._achievement_discord_snapshot(ctx.guild)
            if snapshot is None:
                await ctx.send(
                    "Role analytics is not ready. Run `!rolesync` first, then run "
                    "`!rolesync discord` again."
                )
                return

            bootstrapped = await self._achievement_store.is_bootstrapped(guild_id)
            summary = await self._achievement_discord_sync_summary(
                guild_id,
                snapshot,
                bootstrapped=bootstrapped,
            )
            await self._upload_achievement_sync_backup(
                ctx.guild,
                error_channel,
                snapshot,
            )

            plan_message = await self._support.send_log_message(error_channel, summary)
            if plan_message is None:
                raise commands.UserFeedbackCheckFailure(
                    "Could not publish the synchronization plan"
                )

            confirmed = await self._wait_for_achievement_sync_confirmation(
                guild_id=guild_id,
                channel=error_channel,
                moderator_id=ctx.author.id,
            )
            if not confirmed:
                return

            fresh_snapshot = await self._achievement_discord_snapshot(ctx.guild)
            if fresh_snapshot != snapshot:
                await self._support.send_log_message(
                    error_channel,
                    "Role analytics changed. Run `!rolesync discord` again.",
                )
                return

            fresh_bootstrapped = await self._achievement_store.is_bootstrapped(guild_id)
            fresh_summary = await self._achievement_discord_sync_summary(
                guild_id,
                fresh_snapshot,
                bootstrapped=fresh_bootstrapped,
            )
            if fresh_bootstrapped != bootstrapped or fresh_summary != summary:
                await self._support.send_log_message(
                    error_channel,
                    "Achievement data changed. Run `!rolesync discord` again.",
                )
                return

            completion = await self._apply_achievement_discord_snapshot(
                guild_id,
                snapshot,
                bootstrapped=bootstrapped,
            )
            if completion is None:
                await self._support.send_log_message(
                    error_channel,
                    "Achievement initialization was already completed",
                )
                return
            await self._support.send_log_message(error_channel, completion)
        finally:
            self._achievement_syncing_guilds.discard(guild_id)

    def _error_channel_label(self, guild: discord.Guild, channel_id: int) -> str:
        channel = self._support.get_log_channel(guild, channel_id)
        if channel is None:
            return f"the configured error channel (`{channel_id}`)"
        mention = getattr(channel, "mention", None)
        if mention:
            return str(mention)
        name = getattr(channel, "name", None)
        if name:
            return f"#{name}"
        return f"the configured error channel (`{channel_id}`)"

    async def _require_rolesync_error_channel(self, ctx: commands.Context) -> discord.TextChannel:
        """Accept rolesync discord only in the shared operational error channel."""
        channel_id = await self._support.config.guild(ctx.guild).error_channel()
        channel = ctx.channel
        if channel_id is None:
            raise commands.UserFeedbackCheckFailure(
                "Configure the shared error channel before running this command"
            )
        if getattr(channel, "id", None) != channel_id:
            raise commands.UserFeedbackCheckFailure(
                "Run this command in "
                f"{self._error_channel_label(ctx.guild, channel_id)}"
            )
        if self._channel_allows_everyone(channel, ctx.guild):
            raise commands.UserFeedbackCheckFailure(
                "The operational error channel must be hidden from `@everyone`"
            )
        missing_permissions = self._support.missing_log_permissions(
            ctx.guild,
            channel,
            require_attach_files=True,
        )
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)
        return channel

    @commands.command(name="rolestats")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    @commands.cooldown(1, 5, commands.BucketType.user)
    async def rolestats(self, ctx: commands.Context, *, expression: str) -> None:
        """Count members matching a boolean role expression"""
        parsed, predicate_sql, parameters = self._prepare_role_expression(
            ctx.guild, expression
        )
        try:
            count = await self._role_analytics_store.count_matching(
                ctx.guild.id, predicate_sql, parameters
            )
        except AnalyticsUnavailableError as error:
            raise commands.UserFeedbackCheckFailure(
                "Role analytics are unavailable right now"
            ) from error

        await ctx.send(
            f"{count} users match: {render_role_expression(parsed)}",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @commands.command(name="roleusers")
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    @commands.cooldown(1, 10, commands.BucketType.guild)
    async def roleusers(self, ctx: commands.Context, *, expression: str) -> None:
        """Export members matching a boolean role expression"""
        self._require_private_role_export_channel(ctx)
        parsed, predicate_sql, parameters = self._prepare_role_expression(
            ctx.guild, expression
        )
        if not bool(ctx.guild.chunked):
            await self._repair_role_analytics_cache(ctx.guild)
            raise commands.UserFeedbackCheckFailure(
                "Role analytics are unavailable right now"
            )

        try:
            user_ids = await self._role_analytics_store.matching_user_ids(
                ctx.guild.id, predicate_sql, parameters
            )
        except AnalyticsUnavailableError as error:
            raise commands.UserFeedbackCheckFailure(
                "Role analytics are unavailable right now"
            ) from error
        if not user_ids:
            await ctx.send("No users match this expression")
            return

        members = [ctx.guild.get_member(user_id) for user_id in user_ids]
        if any(member is None for member in members):
            await self._repair_role_analytics_cache(ctx.guild)
            raise commands.UserFeedbackCheckFailure(
                "Role analytics are unavailable right now"
            )

        export_members = tuple(
            ExportMember(member.id, member.name, member.display_name)
            for member in members
        )
        try:
            payload = build_role_export(export_members, ctx.guild.filesize_limit)
        except ExportTooLarge:
            await ctx.send("Export is too large to upload")
            return

        await ctx.send(
            f"{len(user_ids)} users match: {render_role_expression(parsed)}",
            file=discord.File(io.BytesIO(payload.data), filename=payload.filename),
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _send_nhmisc_overview(
        self,
        ctx: commands.Context,
        *,
        title: str,
        current: tuple[str, ...] | None = None,
        include_descendants: bool = True,
    ) -> None:
        async def send_configuration() -> None:
            if not current:
                return
            embed = discord.Embed(title=title)
            embed.add_field(
                name="Current configuration",
                value="\n".join(current),
                inline=False,
            )
            await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())

        await send_group_overview(
            ctx,
            send_configuration if current else None,
            include_descendants=include_descendants,
            title=title,
        )

    @staticmethod
    def _channel_allows_everyone(
        channel: discord.abc.GuildChannel,
        guild: discord.Guild,
    ) -> bool:
        permissions = channel.permissions_for(guild.default_role)
        return bool(permissions.view_channel)

    @staticmethod
    def _channel_is_public(ctx: commands.Context) -> bool:
        return NHMisc._channel_allows_everyone(ctx.channel, ctx.guild)

    @staticmethod
    def _format_direct_commands(
        ctx: commands.Context,
        *,
        preferred_order: tuple[str, ...] = (),
        expand_singletons: bool = False,
    ) -> str:
        order = {name: index for index, name in enumerate(preferred_order)}
        commands_to_render = sorted(
            ctx.command.commands,
            key=lambda command: order.get(
                command.qualified_name.rsplit(" ", 1)[-1],
                len(order),
            ),
        )
        lines = []
        for command in commands_to_render:
            if command.hidden:
                continue
            rendered_command = command
            visible_children = tuple(
                child
                for child in getattr(rendered_command, "commands", ())
                if not child.hidden
            )
            while (
                expand_singletons
                and not rendered_command.signature.strip()
                and len(visible_children) == 1
            ):
                rendered_command = visible_children[0]
                visible_children = tuple(
                    child
                    for child in getattr(rendered_command, "commands", ())
                    if not child.hidden
                )
            signature = rendered_command.signature.strip()
            usage = f"{ctx.clean_prefix}{rendered_command.qualified_name}"
            if signature:
                usage = f"{usage} {signature}"
            description = rendered_command.short_doc.strip()
            line = f"`{usage}`"
            if description:
                line = f"{line} - {description}"
            lines.append(line)
        return "\n".join(lines) or "No subcommands available"

    @staticmethod
    def _configured_channel_label(
        guild: discord.Guild, channel_id: int | None
    ) -> str:
        if channel_id is None:
            return "Not configured"
        channel = guild.get_channel(channel_id)
        if channel is None:
            return "Configured channel is missing"
        return channel.mention

    @commands.group(name="botproxy", invoke_without_command=True)
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def botproxy(self, ctx: commands.Context) -> None:
        """Create and configure private Bot Proxy sessions"""
        from .bot_proxy_workflow import BOT_PROXY_WORKFLOW_BUTTONS

        embed = discord.Embed(
            title="Bot Proxy",
            description="Private moderator workflows for messages sent by the bot",
        )
        embed.add_field(
            name="Commands",
            value=self._format_direct_commands(
                ctx,
                preferred_order=("toggle", "create", "channel", "deleteclosed"),
            ),
            inline=False,
        )
        embed.add_field(
            name="Workflow buttons",
            value=BOT_PROXY_WORKFLOW_BUTTONS,
            inline=False,
        )
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())

    @botproxy.command(
        name="toggle",
        usage="[true|false]",
    )
    async def botproxy_toggle(
        self,
        ctx: commands.Context,
        enabled: bool | None = None,
    ) -> None:
        """Show or set whether Bot Proxy is enabled for this server"""
        if self._channel_allows_everyone(ctx.channel, ctx.guild):
            raise commands.UserFeedbackCheckFailure(
                "Run this command in a private moderator channel"
            )
        manager = self._ensure_bot_proxy()
        if enabled is None:
            current = await manager.enabled(ctx.guild)
            await ctx.send(
                f"Bot Proxy: {'enabled' if current else 'disabled'}",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        await manager.set_enabled(ctx.guild, enabled)

    @botproxy.command(name="create")
    async def botproxy_create(self, ctx: commands.Context) -> None:
        """Create an additional empty Bot Proxy session"""
        if self._channel_allows_everyone(ctx.channel, ctx.guild):
            raise commands.UserFeedbackCheckFailure(
                "Run this command in a private moderator channel"
            )
        manager = self._ensure_bot_proxy()
        try:
            workspace = await manager.workspace_channel(ctx.guild)
        except ValueError as error:
            await ctx.send(
                str(error),
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        if ctx.channel.id != workspace.id:
            await ctx.send(
                "Run this command in the configured private Bot Proxy channel",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        try:
            await manager.require_enabled(ctx.guild)
        except ValueError as error:
            await ctx.send(
                str(error),
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        try:
            await manager.create_session(ctx.guild, ctx.author)
        except ValueError as error:
            await ctx.send(
                str(error),
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        except Exception as error:
            await self.report_operational_error(
                guild_id=ctx.guild.id,
                source="NHMisc",
                action="create Bot Proxy session",
                error=error,
                channel_id=ctx.channel.id,
            )
            await ctx.send(
                "Bot Proxy failed",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        try:
            await ctx.message.delete()
        except discord.HTTPException as error:
            await self.report_operational_error(
                guild_id=ctx.guild.id,
                source="NHMisc",
                action="delete Bot Proxy create command",
                error=error,
                channel_id=ctx.channel.id,
                message_id=ctx.message.id,
            )

    @botproxy.command(
        name="channel",
        usage="[channel|clear]",
    )
    async def botproxy_channel(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel | str | None = None,
    ) -> None:
        """Show, set, or clear the private Bot Proxy session channel"""
        if self._channel_allows_everyone(ctx.channel, ctx.guild):
            raise commands.UserFeedbackCheckFailure(
                "Run this command in a private moderator channel"
            )
        if isinstance(channel, str):
            if channel.casefold() != "clear":
                raise commands.UserFeedbackCheckFailure(
                    "Provide a channel or use clear"
                )
            await self.config.guild(ctx.guild).bot_proxy_channel.clear()
            await ctx.send("Bot Proxy channel cleared")
            return
        if channel is None:
            channel_id = await self.config.guild(ctx.guild).bot_proxy_channel()
            await ctx.send(
                f"Bot Proxy channel: "
                f"{self._configured_channel_label(ctx.guild, channel_id)}",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        if self._channel_allows_everyone(channel, ctx.guild):
            raise commands.UserFeedbackCheckFailure(
                "Configure a channel that is private from `@everyone`"
            )
        permissions = channel.permissions_for(ctx.guild.me)
        required = (
            ("view_channel", "View Channel"),
            ("send_messages", "Send Messages"),
            ("create_public_threads", "Create Public Threads"),
            ("send_messages_in_threads", "Send Messages in Threads"),
            ("manage_threads", "Manage Threads"),
            ("manage_messages", "Manage Messages"),
            ("manage_webhooks", "Manage Webhooks"),
        )
        missing = [label for attr, label in required if not getattr(permissions, attr)]
        if missing:
            raise commands.UserFeedbackCheckFailure(
                f"Bot is missing {', '.join(missing)} in {channel.mention}"
            )
        await self.config.guild(ctx.guild).bot_proxy_channel.set(channel.id)
        await ctx.send(f"Bot Proxy channel set to {channel.mention}")

    @botproxy.command(
        name="deleteclosed",
        usage="[true|false]",
    )
    async def botproxy_deleteclosed(
        self,
        ctx: commands.Context,
        enabled: bool | None = None,
    ) -> None:
        """Show or set whether closing a Bot Proxy session deletes its thread"""
        if self._channel_allows_everyone(ctx.channel, ctx.guild):
            raise commands.UserFeedbackCheckFailure(
                "Run this command in a private moderator channel"
            )
        setting = self.config.guild(ctx.guild).bot_proxy_delete_closed_sessions
        if enabled is None:
            current = await setting()
            await ctx.send(
                f"Delete closed Bot Proxy sessions: {'enabled' if current else 'disabled'}",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        await setting.set(enabled)
        await ctx.send(
            f"Delete closed Bot Proxy sessions {'enabled' if enabled else 'disabled'}",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @commands.group(name="nhmisc", invoke_without_command=True)
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def nhmisc(self, ctx: commands.Context) -> None:
        """Configuration, activity, and moderation tools"""
        await send_group_overview(ctx, title="NHMisc", include_descendants=False)

    @nhmisc.group(name="roleanalytics", invoke_without_command=True)
    @commands.has_permissions(manage_messages=True)
    async def nhmisc_roleanalytics(self, ctx: commands.Context) -> None:
        """Configure role analytics"""
        state = await self._role_analytics_store.get_state(ctx.guild.id)
        member_count = (
            f"{state.source_member_count:,}"
            if state.source_member_count is not None
            else "Not available"
        )
        await self._send_nhmisc_overview(
            ctx,
            title="Role analytics",
            current=(
                f"Enabled: {'Yes' if state.enabled else 'No'}",
                f"Status: {state.status.value.replace('_', ' ').title()}",
                f"Members in snapshot: {member_count}",
            ),
        )

    @nhmisc_roleanalytics.command(name="disable")
    async def nhmisc_roleanalytics_disable(self, ctx: commands.Context) -> None:
        """Disable role analytics and delete this guild's analytics database"""
        await self._role_analytics.disable_guild(ctx.guild.id)
        await ctx.send("Role analytics disabled")

    @nhmisc.group(name="log", invoke_without_command=True)
    @commands.has_permissions(manage_messages=True)
    async def nhmisc_log(self, ctx: commands.Context) -> None:
        """Configure NHMisc logging destinations"""
        config = await self.config.guild(ctx.guild).all()
        await self._send_nhmisc_overview(
            ctx,
            title="Logging",
            current=(
                "Voice: "
                + self._configured_channel_label(ctx.guild, config["voice_log_channel"]),
                "Alert: "
                + self._configured_channel_label(ctx.guild, config["alert_channel"]),
                "Moderation: "
                + self._configured_channel_label(
                    ctx.guild, config["moderation_log_channel"]
                ),
            ),
        )

    async def _show_log_destination(
        self,
        ctx: commands.Context,
        *,
        title: str,
        config_key: str,
    ) -> None:
        channel_id = await getattr(self.config.guild(ctx.guild), config_key)()
        embed = discord.Embed(title=title)
        current = (
            "Run this command in a channel hidden from `@everyone` "
            "to view the current configuration"
            if self._channel_is_public(ctx)
            else f"Channel: {self._configured_channel_label(ctx.guild, channel_id)}"
        )
        embed.add_field(name="Current configuration", value=current, inline=False)
        await ctx.send(embed=embed)

    async def _handle_log_channel_word_or_show(
        self,
        ctx: commands.Context,
        channel: str | None,
        *,
        title: str,
        config_key: str,
        cleared: str,
    ) -> None:
        if isinstance(channel, str):
            if channel.casefold() != "clear":
                raise commands.UserFeedbackCheckFailure("Provide a channel or use clear")
            await getattr(self.config.guild(ctx.guild), config_key).set(None)
            await ctx.send(cleared, allowed_mentions=discord.AllowedMentions.none())
            return
        await self._show_log_destination(ctx, title=title, config_key=config_key)

    @nhmisc_log.command(name="voice", usage="[channel|clear]")
    async def nhmisc_log_voice(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel | str | None = None,
    ) -> None:
        """Show, set, or clear the text channel used for voice event logs"""
        if channel is None or isinstance(channel, str):
            await self._handle_log_channel_word_or_show(
                ctx,
                channel,
                title="Voice logging",
                config_key="voice_log_channel",
                cleared="Voice log channel cleared",
            )
            return
        missing_permissions = self._support.missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)
        await self.config.guild(ctx.guild).voice_log_channel.set(channel.id)
        await ctx.send(f"Voice log channel set to {channel.mention}")

    @nhmisc_log.command(name="alert", usage="[channel|clear]")
    async def nhmisc_log_alert(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel | str | None = None,
    ) -> None:
        """Show, set, or clear the text channel used for alert logs"""
        if channel is None or isinstance(channel, str):
            await self._handle_log_channel_word_or_show(
                ctx,
                channel,
                title="Alert logging",
                config_key="alert_channel",
                cleared="Alert channel cleared",
            )
            return
        missing_permissions = self._support.missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)
        await self.config.guild(ctx.guild).alert_channel.set(channel.id)
        await ctx.send(f"Alert channel set to {channel.mention}")

    @nhmisc_log.command(name="moderation", usage="[channel|clear]")
    async def nhmisc_log_moderation(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel | str | None = None,
    ) -> None:
        """Show, set, or clear the private channel used for moderator action logs"""
        if channel is None or isinstance(channel, str):
            await self._handle_log_channel_word_or_show(
                ctx,
                channel,
                title="Moderator action logging",
                config_key="moderation_log_channel",
                cleared="Moderator action channel cleared",
            )
            return
        missing_permissions = self._support.missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)
        if self._channel_allows_everyone(channel, ctx.guild):
            raise commands.UserFeedbackCheckFailure(
                "Configure a channel that is private from `@everyone`"
            )

        await self.config.guild(ctx.guild).moderation_log_channel.set(channel.id)
        await ctx.send(f"Moderator action channel set to {channel.mention}")

    @nhmisc.group(name="vcjumping", invoke_without_command=True)
    @commands.has_permissions(manage_messages=True)
    async def nhmisc_vcjumping(self, ctx: commands.Context) -> None:
        """Configure voice channel jumping detection"""
        config = await self.config.guild(ctx.guild).all()
        await self._send_nhmisc_overview(
            ctx,
            title="VC jumping detection",
            current=(
                f"Channel entries: {config['vcjumping_visit_count']}",
                f"Time window: {config['vcjumping_window_seconds']} seconds",
            ),
        )

    @nhmisc_vcjumping.command(name="visits")
    async def nhmisc_vcjumping_visits(self, ctx: commands.Context, count: int) -> None:
        """Set how many voice channel entries trigger VC jumping alerts"""
        if count < 2:
            raise commands.UserFeedbackCheckFailure("VC jumping visit count must be at least 2")

        await self.config.guild(ctx.guild).vcjumping_visit_count.set(count)
        await ctx.send(f"VC jumping alerts will trigger after {count} channel entries")

    @nhmisc_vcjumping.command(name="seconds")
    async def nhmisc_vcjumping_seconds(self, ctx: commands.Context, seconds: int) -> None:
        """Set the VC jumping detection time window in seconds"""
        if seconds < 1:
            raise commands.UserFeedbackCheckFailure("VC jumping window must be at least 1 second")

        await self.config.guild(ctx.guild).vcjumping_window_seconds.set(seconds)
        await ctx.send(f"VC jumping window set to {seconds} seconds")

    @nhmisc.group(name="forumautopin", invoke_without_command=True)
    @commands.has_permissions(manage_messages=True)
    async def nhmisc_forumautopin(self, ctx: commands.Context) -> None:
        """Configure automatic pinning for new forum post starter messages"""
        configured = await self._forum_autopin.get_forum_ids(ctx.guild)
        forum_lines = [f"Configured forums: {len(configured)}"]
        for channel_id in configured[:10]:
            channel = ctx.guild.get_channel(channel_id)
            forum_lines.append(
                channel.mention if channel is not None else "Configured forum is missing"
            )
        if len(configured) > 10:
            forum_lines.append(f"...and {len(configured) - 10} more")

        await self._send_nhmisc_overview(
            ctx,
            title="Forum autopin",
            current=tuple(forum_lines),
        )

    @nhmisc_forumautopin.command(name="add")
    async def nhmisc_forumautopin_add(
        self,
        ctx: commands.Context,
        channel: ForumChannelConverter,
    ) -> None:
        """Enable starter-message autopinning in a forum"""
        missing_permission = self._forum_autopin.missing_permissions(ctx.guild, channel)
        if missing_permission is not None:
            raise commands.UserFeedbackCheckFailure(missing_permission)

        enabled = await self._forum_autopin.enable(ctx.guild, channel.id)
        state = "is now enabled" if enabled else "is already enabled"
        await ctx.send(
            f"Forum autopin {state} for {channel.mention}",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @nhmisc_forumautopin.command(name="remove")
    async def nhmisc_forumautopin_remove(
        self,
        ctx: commands.Context,
        channel: ForumChannelConverter,
    ) -> None:
        """Disable starter-message autopinning in a forum"""
        disabled = await self._forum_autopin.disable(ctx.guild, channel.id)
        state = "is disabled" if disabled else "is not enabled"
        await ctx.send(
            f"Forum autopin {state} for {channel.mention}",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @nhmisc_forumautopin.command(name="list")
    async def nhmisc_forumautopin_list(self, ctx: commands.Context) -> None:
        """List forums configured for starter-message autopinning"""
        configured = await self._forum_autopin.get_forum_ids(ctx.guild)
        if not configured:
            await ctx.send(
                "No forums are configured for automatic starter-message pinning"
            )
            return

        lines = ["Forums with starter-message autopinning:"]
        for channel_id in configured:
            channel = ctx.guild.get_channel(channel_id) or self.bot.get_channel(channel_id)
            if is_forum_channel(channel):
                lines.append(f"- {channel.mention} (`{channel_id}`)")
            else:
                lines.append(f"- Missing forum (`{channel_id}`)")
        await self._send_paginated_text(ctx, "\n".join(lines))

    @commands.command(name="gatecount")
    @commands.guild_only()
    async def gatecount(self, ctx: commands.Context) -> None:
        """Show member counts for the current Gate roles"""
        _require_guild_role(
            ctx.guild,
            SINGLEPLAYER_GATE_COMPLETED_ROLE_ID,
            report_name="Gatecount",
            role_label="Singleplayer completed",
        )
        for tier, role_id in enumerate(GATE_TIER_ROLE_IDS, start=1):
            _require_guild_role(
                ctx.guild,
                role_id,
                report_name="Gatecount",
                role_label=f"Tier {tier}",
            )
        singleplayer_count = await self._count_role_expression(
            ctx.guild, str(SINGLEPLAYER_GATE_COMPLETED_ROLE_ID)
        )
        tier_counts = await self._count_highest_role_buckets(
            ctx.guild, GATE_TIER_ROLE_IDS
        )
        total_gates = sum(
            tier * count for tier, count in enumerate(tier_counts, start=1)
        )

        def format_role_count(role_id: int, count: int) -> str:
            player_label = "player" if count == 1 else "players"
            return f"<@&{role_id}> — **{count} {player_label}**"

        lines = [
            format_role_count(
                SINGLEPLAYER_GATE_COMPLETED_ROLE_ID, singleplayer_count
            )
        ]
        lines.extend(
            format_role_count(role_id, count)
            for role_id, count in zip(GATE_TIER_ROLE_IDS, tier_counts, strict=True)
        )
        lines.extend(("", f"**Total Gates: {total_gates}**"))
        embed = discord.Embed(
            title="Current Gatecount:",
            description="\n".join(lines),
            color=discord.Color.blue(),
        )
        await ctx.send(
            embed=embed,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _gate_increment_context_action(
        self,
        interaction: discord.Interaction,
        source_message: discord.Message,
    ) -> None:
        action = "increment gate roles context action"
        permissions = interaction.permissions
        if (
            interaction.guild is None
            or permissions is None
            or not permissions.manage_messages
        ):
            await interaction.response.send_message(
                "You need Manage Messages permission",
                ephemeral=True,
            )
            return
        if not await self._defer_achievement_interaction(
            interaction,
            ephemeral=True,
        ):
            return
        try:
            is_bootstrapped = await self._await_achievement_interaction_data(
                self._achievement_store.is_bootstrapped(interaction.guild.id)
            )
            if not is_bootstrapped:
                await interaction.edit_original_response(
                    content=(
                        "Achievement data is still initializing. Run rolesync first"
                    )
                )
                return
            await self._gate_increment_context_action_after_defer(
                interaction,
                source_message,
            )
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                action,
                error,
                public_defer=False,
            )

    async def _gate_increment_context_action_after_defer(
        self,
        interaction: discord.Interaction,
        source_message: discord.Message,
    ) -> None:
        existing = await self._await_achievement_interaction_data(
            self._gate_increment_store.get_operation(
                self._gate_increment_key(source_message)
            )
        )
        if existing is not None:
            existing = await self._retry_gate_increment_publication(
                source_message, existing
            )

        try:
            view = await self._create_gate_increment_review(
                source_message,
                interaction.user.id,
                snapshot=existing,
                ephemeral=True,
            )
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(content=str(error))
            return
        await interaction.edit_original_response(
            embed=view.render_embed(),
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )
        view.message = await interaction.original_response()

    async def _create_gate_increment_review(
        self,
        source_message: discord.Message,
        opener_id: int,
        *,
        snapshot: GateIncrementSnapshot | None = None,
        ephemeral: bool,
    ):
        _validate_gate_increment_configuration(source_message.guild)
        candidates = await self._fetch_gate_increment_candidates(source_message, snapshot)
        self._validate_gate_increment_candidate_count(candidates)
        definitions = _gate_increment_custom_achievement_definitions(
            await self._achievement_store.list_definitions(source_message.guild.id)
        )
        from .gate_increment_views import GateIncrementReviewView

        return GateIncrementReviewView(
            self,
            source_message,
            opener_id,
            candidates,
            custom_achievements=definitions,
            snapshot=snapshot,
            ephemeral=ephemeral,
        )

    @staticmethod
    def _gate_increment_key(source_message: discord.Message) -> SourceMessageKey:
        return SourceMessageKey(
            source_message.guild.id,
            source_message.channel.id,
            source_message.id,
        )

    @staticmethod
    def _format_gate_increment_operation(snapshot: GateIncrementSnapshot) -> str:
        operation = snapshot.operation
        if operation.state is OperationState.APPLYING:
            return (
                "⏳ **GATE INCREMENT IN PROGRESS**\n"
                "This message is already being processed"
            )
        if operation.state is OperationState.COMPLETED:
            return (
                "**Gate increment recorded**\n"
                f"{operation.completed_count} users already received a Gate from this message"
            )
        return (
            "⚠️ **GATE INCREMENT PARTIALLY COMPLETED**\n"
            f"{operation.completed_count} users were updated and "
            f"{operation.failed_count + operation.conflict_count} changes require "
            "attention\nThis message cannot start another increment"
        )

    async def _retry_gate_increment_publication(
        self,
        source_message: discord.Message,
        snapshot: GateIncrementSnapshot,
    ) -> GateIncrementSnapshot:
        operation = snapshot.operation
        if operation.completed_count:
            await self._publish_gate_increment_moderation_log(
                source_message,
                operation.moderator_id or self.bot.user.id,
                snapshot,
            )
            await self._publish_gate_increment_result(source_message, snapshot)
            refreshed = await self._gate_increment_store.get_operation(operation.key)
            if refreshed is not None:
                return refreshed
        return snapshot

    async def _resume_gate_increment_review(self, interaction, view) -> None:
        await interaction.response.defer()
        try:
            source_message = await self._fetch_gate_increment_source(
                view.snapshot.operation.key
            )
            snapshot = await self._execute_gate_increment_operation(
                source_message,
                interaction.user.id,
            )
            if snapshot.operation.state is OperationState.APPLYING:
                await self._finish_gate_increment_review(
                    interaction,
                    view,
                    self._format_gate_increment_operation(snapshot),
                )
                return
            await self._publish_gate_increment_moderation_log(
                source_message,
                  interaction.user.id,
                snapshot,
            )
            published = await self._publish_gate_increment_result(
                source_message,
                snapshot,
            )
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(
                content=str(error),
                embed=view.render_embed(),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                "resume gate increment review",
                error,
                public_defer=False,
            )
            return
        await self._finish_gate_increment_review(
            interaction,
            view,
            self._format_gate_increment_completion(snapshot, published),
        )

    async def _refresh_gate_increment_review(self, interaction, view) -> None:
        await interaction.response.defer()
        try:
            source_message = await self._fetch_gate_increment_source(
                self._gate_increment_key(view.source_message)
            )
            _validate_gate_increment_configuration(source_message.guild)
            snapshot = await self._gate_increment_store.get_operation(
                self._gate_increment_key(source_message)
            )
            candidates = await self._fetch_gate_increment_candidates(source_message, snapshot)
            self._validate_gate_increment_candidate_count(candidates)
            definitions = _gate_increment_custom_achievement_definitions(
                await self._achievement_store.list_definitions(source_message.guild.id)
            )
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(
                content=None,
                embed=view.render_embed(notice=str(error)),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                "refresh gate increment review",
                error,
                public_defer=False,
            )
            return
        view.source_message = source_message
        view.replace_snapshot(snapshot)
        view.replace_candidates(candidates)
        view.replace_custom_achievements(definitions)
        await interaction.edit_original_response(
            content=None,
            embed=view.render_embed(),
            view=view,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _prepare_gate_increment_confirmation(self, interaction, view):
        try:
            source_message = await self._fetch_gate_increment_source(
                self._gate_increment_key(view.source_message)
            )
            _validate_gate_increment_configuration(source_message.guild)
            snapshot = await self._gate_increment_store.get_operation(
                self._gate_increment_key(source_message)
            )
            view.replace_snapshot(snapshot)
            live_candidates = await self._fetch_gate_increment_candidates(
                source_message, snapshot
            )
            self._validate_gate_increment_candidate_count(live_candidates)
            live_achievements = _gate_increment_custom_achievement_definitions(
                await self._achievement_store.list_definitions(
                    source_message.guild.id
                )
            )
            profiles = await asyncio.gather(
                *(
                    self._achievement_store.get_profile(
                        source_message.guild.id,
                        candidate.user_id,
                    )
                    for candidate in live_candidates
                    if candidate.user_id in view.selected_user_ids
                    and view.selected_custom_achievement_keys
                )
            )
            selected_user_ids = tuple(
                candidate.user_id
                for candidate in live_candidates
                if candidate.user_id in view.selected_user_ids
                and view.selected_custom_achievement_keys
            )
            owned_keys_by_user = {
                user_id: set(profile.boolean_keys)
                for user_id, profile in zip(
                    selected_user_ids,
                    profiles,
                    strict=True,
                )
            }
            await self._require_private_moderation_log_channel(source_message.guild)
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(
                content=None,
                embed=view.render_embed(notice=str(error)),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return None
        except Exception as error:
            await self._handle_achievement_interaction_failure(
                interaction,
                "confirm gate increment review",
                error,
                public_defer=False,
            )
            return None
        return (
            source_message,
            live_candidates,
            live_achievements,
            owned_keys_by_user,
        )

    async def _prepare_gate_increment_claim(self, interaction, view):
        if not await self._achievement_store.is_bootstrapped(
            view.source_message.guild.id
        ):
            await interaction.edit_original_response(
                content=None,
                embed=view.render_embed(
                    notice="Achievement data is still initializing. Run rolesync first"
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return None
        if not view.selected_user_ids:
            await interaction.edit_original_response(
                embed=view.render_embed(notice="Select at least one user"),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return None
        prepared = await self._prepare_gate_increment_confirmation(interaction, view)
        if prepared is None:
            return None
        (
            source_message,
            live_candidates,
            live_achievements,
            owned_keys_by_user,
        ) = prepared

        if self._gate_increment_review_is_stale(
            view, live_candidates
        ) or self._gate_increment_achievement_selection_is_stale(
            view, live_achievements
        ):
            view.source_message = source_message
            view.replace_candidates(live_candidates)
            view.replace_custom_achievements(live_achievements)
            await interaction.edit_original_response(
                content=None,
                embed=view.render_embed(
                    notice=(
                        "The source message or member roles changed. Review the "
                        "updated increment plan before confirming"
                    )
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return None

        selected_candidates = tuple(
            candidate
            for candidate in live_candidates
            if candidate.user_id in view.selected_user_ids
            and candidate.target_role_id is not None
        )
        plans = _build_gate_increment_member_plans(
            selected_candidates,
            grant_solo=(
                view.solo_gater_enabled and len(selected_candidates) == 1
            ),
        )
        selected_achievements = tuple(
            GateIncrementAchievementPlan(
                definition.key,
                definition.display_name,
                definition.role_id,
            )
            for definition in live_achievements
            if definition.key in view.selected_custom_achievement_keys
        )
        try:
            _validate_gate_increment_output_limits(
                source_message,
                interaction.user.id,
                plans,
                selected_achievements,
                owned_keys_by_user,
                snapshot=view.snapshot,
            )
        except commands.UserFeedbackCheckFailure as error:
            await interaction.edit_original_response(
                content=None,
                embed=view.render_embed(notice=str(error)),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return None
        return source_message, plans, selected_achievements

    async def _confirm_gate_increment_review(self, interaction, view) -> None:
        await interaction.response.defer()
        prepared = await self._prepare_gate_increment_claim(interaction, view)
        if prepared is None:
            return
        source_message, plans, selected_achievements = prepared
        key = self._gate_increment_key(source_message)
        try:
            claim = await self._gate_increment_store.claim(
                key,
                interaction.user.id,
                plans,
                selected_achievements,
            )
        except GateProgressConflict:
            await interaction.edit_original_response(
                content=None,
                embed=view.render_embed(
                    notice=(
                        "A selected user's Gate progress changed. Refresh and "
                        "review the plan again"
                    )
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        except AchievementDefinitionConflict:
            await interaction.edit_original_response(
                content=None,
                embed=view.render_embed(
                    notice=(
                        "A selected achievement changed. Refresh and review "
                        "the plan again"
                    )
                ),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        except GateIncrementBusy:
            await interaction.edit_original_response(
                content=None,
                embed=view.render_embed(notice="This message is being processed. Try again when it finishes"),
                view=view,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        if not claim.created:
            existing = await self._gate_increment_store.get_operation(key)
            await self._finish_gate_increment_review(
                interaction,
                view,
                self._format_gate_increment_operation(existing),
            )
            return

        snapshot = await self._execute_gate_increment_operation(
            source_message,
            interaction.user.id,
            selected_user_ids={plan.user_id for plan in plans},
        )
        selected_members = tuple(
            member for member in snapshot.members if member.user_id in view.selected_user_ids
        )
        completed_members = tuple(
            member_plan
            for member_plan in selected_members
            if member_plan.state is MemberState.COMPLETED
        )
        moderation_log_delivered = await self._publish_gate_increment_moderation_log(
            source_message,
            interaction.user.id,
            snapshot,
        )
        skipped_members = len(selected_members) - len(completed_members)
        if skipped_members:
            await self._send_error_notice(
                source_message.guild,
                "Gate increment partially failed\n"
                f"Moderator: <@{interaction.user.id}>\n"
                f"Members skipped: {skipped_members}",
                ping=False,
            )
        published = await self._publish_gate_increment_result(
            source_message,
            snapshot,
        )
        status = self._format_gate_increment_completion(snapshot, published)
        if not moderation_log_delivered:
            status += "\nRoles changed, but the moderation log could not be sent"
        await self._finish_gate_increment_review(
            interaction,
            view,
            status,
            success=(
                skipped_members == 0
                and published
                and moderation_log_delivered
            ),
        )

    async def _publish_gate_increment_moderation_log(
        self,
        source_message,
        moderator_id: int,
        snapshot: GateIncrementSnapshot,
    ) -> bool:
        completed_members = tuple(
            member
            for member in snapshot.members
            if member.state is MemberState.COMPLETED
            and not member.moderation_logged
        )
        if not completed_members:
            return True
        increment_lines = []
        for member_plan in completed_members:
            if member_plan.target_role_id not in GATE_TIER_ROLE_IDS:
                continue
            awards = []
            if member_plan.solo_awarded:
                awards.append("Solo Gater")
            awards.extend(_gate_increment_custom_award_labels(snapshot, member_plan))
            increment = (
                f"<@{member_plan.user_id}> Gate "
                f"{GATE_TIER_ROLE_IDS.index(member_plan.target_role_id) + 1}"
            )
            if awards:
                increment += " + " + " + ".join(awards)
            increment_lines.append(increment)
        source_url = (
            "https://discord.com/channels/"
            f"{source_message.guild.id}/{source_message.channel.id}/"
            f"{source_message.id}"
        )
        try:
            delivered = await self._send_moderation_log(
                source_message.guild,
                "Gate incremented\n"
                f"Moderator: <@{moderator_id}>\n"
                f"Members: {', '.join(increment_lines)}\n"
                f"Source: {source_url}",
                log_failure=False,
            )
        except Exception:
            return False
        if not delivered:
            return False
        await self._gate_increment_store.mark_moderation_logged(
            snapshot.operation.key,
            tuple(member.position for member in completed_members),
        )
        return True

    async def _fetch_gate_increment_candidates(
        self, source_message: discord.Message, snapshot: GateIncrementSnapshot | None = None,
    ) -> tuple[GateIncrementCandidate, ...]:
        candidates = []
        previous_members = {
            member.user_id: member for member in snapshot.members
        } if snapshot is not None else {}
        for user_id in _gate_increment_candidate_ids(source_message):
            previous = previous_members.get(user_id)
            if previous is not None:
                candidates.append(GateIncrementCandidate(
                    user_id=user_id,
                    display_name="",
                    current_gate_role_ids=(),
                    current_tier=None,
                    target_role_id=None,
                    previous_state=previous.state,
                ))
                continue
            try:
                member = await source_message.guild.fetch_member(user_id)
            except discord.NotFound:
                continue
            except discord.HTTPException as error:
                raise commands.UserFeedbackCheckFailure(
                    "Could not refresh the users in this message"
                ) from error
            if member.bot:
                continue
            member_role_ids = tuple(role.id for role in member.roles)
            transition = plan_gate_transition(member_role_ids)
            awards = await self._achievement_store.get_active_stargates(
                source_message.guild.id,
                member.id,
            )
            completed_count = len(awards)
            expected_gate_role_ids = (
                (GATE_TIER_ROLE_IDS[completed_count - 1],)
                if completed_count
                else ()
            )
            if transition.current_role_ids != expected_gate_role_ids:
                raise commands.UserFeedbackCheckFailure(
                    f"<@{member.id}>'s Gate role is out of sync with achievement data"
                )
            used_ordinals = {
                award.ordinal for award in awards if award.ordinal is not None
            }
            target_ordinal = 1
            while target_ordinal in used_ordinals:
                target_ordinal += 1
            target_role_id = (
                GATE_TIER_ROLE_IDS[completed_count]
                if completed_count < len(GATE_TIER_ROLE_IDS)
                else None
            )
            candidates.append(
                GateIncrementCandidate(
                    user_id=member.id,
                    display_name=member.display_name,
                    current_gate_role_ids=transition.current_role_ids,
                    current_tier=completed_count or None,
                    target_role_id=target_role_id,
                    target_ordinal=(target_ordinal if target_role_id else None),
                    highest_ordinal=max(used_ordinals, default=0),
                    has_solo_gater=(
                        SINGLEPLAYER_GATE_COMPLETED_ROLE_ID in member_role_ids
                    ),
                )
            )
            if sum(candidate.target_role_id is not None for candidate in candidates) > MAX_GATE_INCREMENT_CANDIDATES:
                break
        return tuple(candidates)

    @staticmethod
    def _validate_gate_increment_candidate_count(
        candidates: tuple[GateIncrementCandidate, ...],
    ) -> None:
        if not candidates:
            raise commands.UserFeedbackCheckFailure(
                "This message has no eligible users to increment"
            )
        if sum(candidate.target_role_id is not None for candidate in candidates) > MAX_GATE_INCREMENT_CANDIDATES:
            raise commands.UserFeedbackCheckFailure(
                f"This message contains more than {MAX_GATE_INCREMENT_CANDIDATES} "
                "users. Gate increment supports at most "
                f"{MAX_GATE_INCREMENT_CANDIDATES} at a time"
            )

    @staticmethod
    def _gate_increment_review_is_stale(view, live_candidates) -> bool:
        if tuple(candidate.user_id for candidate in live_candidates) != view.candidate_ids:
            return True
        preview_by_user_id = {
            candidate.user_id: candidate for candidate in view.candidates
        }
        return any(
            (
                candidate.current_gate_role_ids
                != preview_by_user_id[candidate.user_id].current_gate_role_ids
                or candidate.target_role_id
                != preview_by_user_id[candidate.user_id].target_role_id
                or candidate.target_ordinal
                != preview_by_user_id[candidate.user_id].target_ordinal
                or candidate.highest_ordinal
                != preview_by_user_id[candidate.user_id].highest_ordinal
            )
            for candidate in live_candidates
            if candidate.user_id in view.selected_user_ids
        )

    @staticmethod
    def _gate_increment_achievement_selection_is_stale(
        view, live_achievements
    ) -> bool:
        selected_keys = view.selected_custom_achievement_keys
        preview_by_key = {
            achievement.key: achievement
            for achievement in view.custom_achievements
            if achievement.key in selected_keys
        }
        live_by_key = {
            achievement.key: achievement
            for achievement in live_achievements
            if achievement.key in selected_keys
        }
        if preview_by_key.keys() != live_by_key.keys():
            return True
        return any(
            (
                preview_by_key[key].display_name != live_by_key[key].display_name
                or preview_by_key[key].role_id != live_by_key[key].role_id
            )
            for key in selected_keys
        )

    async def _execute_gate_increment_operation(
        self,
        source_message: discord.Message,
        moderator_id: int,
        *,
        selected_user_ids: set[int] | None = None,
    ) -> GateIncrementSnapshot:
        key = self._gate_increment_key(source_message)
        token = uuid4().hex
        if not await self._gate_increment_store.acquire_execution_lease(key, token):
            snapshot = await self._gate_increment_store.get_operation(key)
            if snapshot is None:
                raise RuntimeError("Gate increment operation disappeared")
            return snapshot

        try:
            _validate_gate_increment_configuration(source_message.guild)
            snapshot = await self._gate_increment_store.get_operation(key)
            if snapshot is None:
                raise RuntimeError("Gate increment operation disappeared")
            for member_plan in snapshot.members:
                if member_plan.state is MemberState.COMPLETED:
                    continue
                if selected_user_ids is not None and member_plan.user_id not in selected_user_ids:
                    continue
                await self._recover_gate_increment_member(
                    source_message.guild,
                    key,
                    member_plan,
                    moderator_id,
                    snapshot.custom_achievements,
                )
            return await self._gate_increment_store.finalize_operation(key)
        except Exception:
            await self._gate_increment_store.release_execution_lease(key, token)
            raise

    async def _recover_gate_increment_member(
        self,
        guild: discord.Guild,
        key: SourceMessageKey,
        member_plan,
        moderator_id: int,
        custom_achievements: tuple[GateIncrementAchievementPlan, ...] = (),
    ) -> None:
        await self._gate_increment_store.mark_member_in_progress(
            key, member_plan.position
        )
        if member_plan.user_id is None or member_plan.target_role_id is None:
            await self._gate_increment_store.mark_member_conflict(
                key, member_plan.position, "redacted"
            )
            return
        completed = False
        conflict_code = None
        failure_code = None
        try:
            member = await guild.fetch_member(member_plan.user_id)
            transition = plan_gate_transition(role.id for role in member.roles)
            recovery = classify_member_recovery(
                member_plan,
                transition.current_role_ids,
            )
            custom_keys = set(member_plan.custom_achievement_keys)
            extra_role_ids = tuple(
                achievement.role_id
                for achievement in custom_achievements
                if achievement.key in custom_keys and achievement.role_id is not None
            )
            required_role_ids = set(extra_role_ids)
            if member_plan.solo_awarded:
                required_role_ids.add(SINGLEPLAYER_GATE_COMPLETED_ROLE_ID)
            current_role_ids = {role.id for role in member.roles}
            if recovery is RecoveryAction.COMPLETE and required_role_ids.issubset(
                current_role_ids
            ):
                completed = True
            elif recovery is RecoveryAction.CONFLICT:
                conflict_code = "roles_changed"
            else:
                failure_code = await self._apply_fixed_gate_target(
                    guild,
                    member,
                    member_plan.target_role_id,
                    key,
                    moderator_id,
                    grant_solo=member_plan.solo_awarded,
                    extra_role_ids=extra_role_ids,
                )
                completed = failure_code is None
        except discord.NotFound:
            failure_code = "member_missing"
        except discord.Forbidden:
            failure_code = "forbidden"
        except discord.HTTPException:
            failure_code = "discord_error"

        if completed:
            await self._gate_increment_store.mark_member_completed(
                key, member_plan.position
            )
        elif conflict_code is not None:
            await self._gate_increment_store.mark_member_conflict(
                key, member_plan.position, conflict_code
            )
        else:
            await self._gate_increment_store.mark_member_failed(
                key, member_plan.position, failure_code or "unknown"
            )

    @staticmethod
    async def _apply_fixed_gate_target(
        guild: discord.Guild,
        member: discord.Member,
        target_role_id: int,
        key: SourceMessageKey,
        moderator_id: int,
        *,
        grant_solo: bool = False,
        extra_role_ids: tuple[int, ...] = (),
    ) -> str | None:
        desired_role_ids = build_role_ids_for_target(
            (role.id for role in member.roles),
            target_role_id,
        )
        if grant_solo and SINGLEPLAYER_GATE_COMPLETED_ROLE_ID not in desired_role_ids:
            desired_role_ids = (*desired_role_ids, SINGLEPLAYER_GATE_COMPLETED_ROLE_ID)
        for role_id in extra_role_ids:
            if role_id not in desired_role_ids:
                desired_role_ids = (*desired_role_ids, role_id)
        desired_roles = [
            guild.get_role(role_id)
            for role_id in desired_role_ids
            if role_id != guild.default_role.id
        ]
        if any(role is None for role in desired_roles):
            return "role_missing"
        await member.edit(
            roles=desired_roles,
            reason=(
                f"Gate increment for message {key.message_id}; "
                f"moderator {moderator_id}"
            ),
        )
        return None

    async def _publish_gate_increment_result(
        self,
        source_message: discord.Message,
        snapshot: GateIncrementSnapshot,
    ) -> bool:
        if (
            snapshot.operation.published_completed_count
            >= snapshot.operation.completed_count
        ):
            return True
        publication_token = uuid4().hex
        if not await self._gate_increment_store.acquire_publication_lease(
            snapshot.operation.key,
            publication_token,
        ):
            return True
        refreshed = await self._gate_increment_store.get_operation(
            snapshot.operation.key
        )
        if refreshed is None:
            await self._gate_increment_store.release_publication_lease(
                snapshot.operation.key,
                publication_token,
            )
            raise RuntimeError("Gate increment operation disappeared")
        snapshot = refreshed
        lines = []
        recipient_ids = []
        for member in snapshot.members:
            if (
                member.state is not MemberState.COMPLETED
                or member.user_id is None
                or member.target_role_id is None
            ):
                continue
            awards = [f"<@&{member.target_role_id}>"]
            if member.solo_awarded:
                awards.append(f"<@&{SINGLEPLAYER_GATE_COMPLETED_ROLE_ID}>")
            awards.extend(_gate_increment_custom_award_labels(snapshot, member))
            lines.append(f"<@{member.user_id}> " + " ".join(awards))
            recipient_ids.append(member.user_id)
        if not lines:
            await self._gate_increment_store.release_publication_lease(
                snapshot.operation.key,
                publication_token,
            )
            return True
        content = "🎉 **Congratulations!**\n" + "\n".join(lines)
        if len(content) > DISCORD_MESSAGE_CONTENT_LIMIT:
            await self._gate_increment_store.release_publication_lease(
                snapshot.operation.key,
                publication_token,
            )
            log.error(
                "Gate increment result exceeds Discord limit for message %s",
                source_message.id,
            )
            return False
        allowed_mentions = discord.AllowedMentions(
            users=[discord.Object(id=user_id) for user_id in recipient_ids],
            roles=False,
            everyone=False,
            replied_user=False,
        )
        return await self._deliver_gate_increment_result(
            source_message,
            snapshot,
            publication_token,
            content,
            allowed_mentions,
        )

    async def _deliver_gate_increment_result(
        self,
        source_message,
        snapshot: GateIncrementSnapshot,
        publication_token: str,
        content: str,
        allowed_mentions,
    ) -> bool:
        if snapshot.operation.result_message_id is not None:
            try:
                result_message = source_message.channel.get_partial_message(
                    snapshot.operation.result_message_id
                )
                await result_message.edit(
                    content=content,
                    allowed_mentions=allowed_mentions,
                )
            except discord.HTTPException:
                await self._gate_increment_store.release_publication_lease(
                    snapshot.operation.key,
                    publication_token,
                )
                log.exception(
                    "Failed to update Gate increment result for message %s",
                    source_message.id,
                )
                return False
            await self._gate_increment_store.record_result_message(
                snapshot.operation.key,
                publication_token,
                snapshot.operation.result_channel_id or source_message.channel.id,
                snapshot.operation.result_message_id,
                snapshot.operation.completed_count,
            )
            return True
        try:
            result_message = await source_message.reply(
                content,
                allowed_mentions=allowed_mentions,
                nonce=f"gate-{snapshot.operation.operation_id}",
            )
        except discord.HTTPException:
            await self._gate_increment_store.release_publication_lease(
                snapshot.operation.key,
                publication_token,
            )
            log.exception(
                "Failed to publish Gate increment result for message %s",
                source_message.id,
            )
            return False
        await self._gate_increment_store.record_result_message(
            snapshot.operation.key,
            publication_token,
            result_message.channel.id,
            result_message.id,
            snapshot.operation.completed_count,
        )
        return True

    @staticmethod
    def _format_gate_increment_completion(
        snapshot: GateIncrementSnapshot,
        published: bool,
    ) -> str:
        operation = snapshot.operation
        if operation.state is OperationState.COMPLETED:
            status = f"Updated {operation.completed_count} users"
        else:
            status = (
                f"Updated {operation.completed_count} users; "
                f"{operation.failed_count + operation.conflict_count} changes "
                "require attention"
            )
        if operation.completed_count and not published:
            status += "\nRoles changed, but congratulations could not be sent"
        return status

    async def _finish_gate_increment_review(
        self,
        interaction,
        view,
        status: str,
        *,
        success: bool = False,
    ) -> None:
        view.stop()
        if success:
            await interaction.delete_original_response()
            return
        if view.ephemeral:
            await interaction.edit_original_response(
                content=status,
                embed=None,
                view=None,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        if view.message is not None:
            try:
                await view.message.delete()
            except discord.HTTPException:
                pass
        await interaction.followup.send(
            status,
            ephemeral=True,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _fetch_gate_increment_source(
        self, key: SourceMessageKey
    ) -> discord.Message:
        guild = self.bot.get_guild(key.guild_id)
        if guild is None:
            raise commands.UserFeedbackCheckFailure(
                "The source server is unavailable"
            )
        channel = guild.get_channel(key.channel_id) or self.bot.get_channel(
            key.channel_id
        )
        if channel is None:
            raise commands.UserFeedbackCheckFailure(
                "The source channel is unavailable"
            )
        try:
            return await channel.fetch_message(key.message_id)
        except (discord.NotFound, discord.Forbidden) as error:
            raise commands.UserFeedbackCheckFailure(
                "The source message is unavailable"
            ) from error

    async def _recover_interrupted_gate_increments(self) -> None:
        try:
            interrupted = await self._gate_increment_store.list_interrupted_operations()
        except Exception as error:
            log.exception("Failed to read interrupted Gate increments")
            guilds = tuple(getattr(self.bot, "guilds", ()))
            if guilds:
                await self.report_operational_error(
                    guild_id=guilds[0].id,
                    source="NHMisc",
                    action="read interrupted Gate increments",
                    error=error,
                )
            return
        for snapshot in interrupted:
            try:
                source_message = await self._fetch_gate_increment_source(
                    snapshot.operation.key
                )
                recovered = await self._execute_gate_increment_operation(
                    source_message,
                    snapshot.operation.moderator_id or self.bot.user.id,
                )
                await self._publish_gate_increment_moderation_log(
                    source_message,
                    recovered.operation.moderator_id or self.bot.user.id,
                    recovered,
                )
                await self._publish_gate_increment_result(
                    source_message,
                    recovered,
                )
            except Exception as error:
                log.exception(
                    "Failed to recover Gate increment for message %s",
                    snapshot.operation.key.message_id,
                )
                await self.report_operational_error(
                    guild_id=snapshot.operation.key.guild_id,
                    source="NHMisc",
                    action="recover interrupted Gate increment",
                    error=error,
                    channel_id=snapshot.operation.key.channel_id,
                    message_id=snapshot.operation.key.message_id,
                )

    @commands.command(name="tierdistribution")
    @commands.guild_only()
    async def tierdistribution(self, ctx: commands.Context) -> None:
        """Show the current distribution of progression and Gate player roles"""
        resolved_tiers = []
        for label, emoji_name, emoji_id, role_id in TIER_DISTRIBUTION_ROLES:
            role = _require_guild_role(
                ctx.guild,
                role_id,
                report_name="Tier distribution",
                role_label=label,
            )
            resolved_tiers.append((emoji_name, emoji_id, role))

        resolved_gate_roles = [
            _require_guild_role(
                ctx.guild,
                role_id,
                report_name="Tier distribution",
                role_label=f"Gate Tier {tier}",
            )
            for tier, role_id in enumerate(GATE_TIER_ROLE_IDS, start=1)
        ]

        tier_bucket_counts = await self._count_highest_role_buckets(
            ctx.guild,
            tuple(role.id for _, _, role in resolved_tiers),
        )
        tier_counts = [
            (emoji_name, emoji_id, count)
            for (emoji_name, emoji_id, _), count in zip(
                resolved_tiers, tier_bucket_counts, strict=True
            )
        ]
        gate_count = await self._count_role_expression(
            ctx.guild,
            " OR ".join(str(role.id) for role in resolved_gate_roles),
        )
        total_count = sum(count for _, _, count in tier_counts) + gate_count

        def format_count(count: int) -> str:
            player_label = "Player" if count == 1 else "Players"
            percentage = count / total_count * 100 if total_count else 0.0
            return f"**{count} {player_label}** ({percentage:.1f}%)"

        lines = [
            f"<:{emoji_name}:{emoji_id}> — {format_count(count)}"
            for emoji_name, emoji_id, count in tier_counts
        ]
        lines.append(
            f"<:{STARGATE_EMOJI_NAME}:{STARGATE_EMOJI_ID}> — "
            f"{format_count(gate_count)}"
        )

        embed = discord.Embed(
            title="Current Tier Distribution:",
            description="\n".join(lines),
            color=discord.Color.blue(),
        )
        await ctx.send(embed=embed)

    @nhmisc.group(name="stickyroles", invoke_without_command=True)
    async def nhmisc_stickyroles(self, ctx: commands.Context) -> None:
        """Configure sticky role persistence"""
        await self._require_manage_guild(ctx)
        role_ids = sorted(await self._sticky_roles.get_sticky_roles(ctx.guild.id))
        role_lines = [f"Configured roles: {len(role_ids)}"]
        for role_id in role_ids[:10]:
            role = ctx.guild.get_role(role_id)
            role_lines.append(
                role.mention if role is not None else "Configured role is missing"
            )
        if len(role_ids) > 10:
            role_lines.append(f"...and {len(role_ids) - 10} more")

        await self._send_nhmisc_overview(
            ctx,
            title="Sticky roles",
            current=tuple(role_lines),
        )

    @nhmisc_stickyroles.command(name="add")
    async def nhmisc_stickyroles_add(self, ctx: commands.Context, role: str) -> None:
        """Mark a role as sticky by role mention or raw role ID"""
        await self._require_manage_guild(ctx)
        role_id = self._parse_role_id(role)
        discord_role = ctx.guild.get_role(role_id)
        if discord_role is None:
            raise commands.UserFeedbackCheckFailure("That role does not exist on this server")
        if not self._can_restore_role(ctx.guild, discord_role):
            raise commands.UserFeedbackCheckFailure(
                "I cannot restore that role. Check Manage Roles and role hierarchy."
            )

        added = await self._sticky_roles.add_sticky_role(ctx.guild.id, role_id)
        if added:
            await ctx.send(
                f"{discord_role.mention} is now sticky",
                allowed_mentions=discord.AllowedMentions.none(),
            )
        else:
            await ctx.send(
                f"{discord_role.mention} is already sticky",
                allowed_mentions=discord.AllowedMentions.none(),
            )

    @nhmisc_stickyroles.command(name="remove")
    async def nhmisc_stickyroles_remove(self, ctx: commands.Context, role: str) -> None:
        """Remove a sticky role by role mention or raw role ID"""
        await self._require_manage_guild(ctx)
        role_id = self._parse_role_id(role)
        config_exists, saved_rows = await self._sticky_roles.get_role_state(
            ctx.guild.id, role_id
        )
        if not config_exists and saved_rows == 0:
            await ctx.send(
                f"{self._format_role_reference(ctx.guild, role_id)} is not present in the sticky role DB",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return

        await self._prompt_sticky_role_db_action(
            guild=ctx.guild,
            channel=ctx.channel,
            role_id=role_id,
            role_name=self._role_name_for_prompt(ctx.guild, role_id),
            config_exists=config_exists,
            saved_rows=saved_rows,
            reason="manual remove command",
            requester=ctx.author,
        )

    @nhmisc_stickyroles.command(name="list")
    async def nhmisc_stickyroles_list(self, ctx: commands.Context) -> None:
        """List sticky roles configured for this server"""
        await self._require_manage_guild(ctx)
        role_ids = await self._sticky_roles.get_sticky_roles(ctx.guild.id)
        if not role_ids:
            await ctx.send("No sticky roles are configured on this server")
            return

        lines = ["Sticky roles:"]
        for role_id in sorted(role_ids):
            lines.append(f"- {self._format_role_reference(ctx.guild, role_id)}")
        await self._send_paginated_text(ctx, "\n".join(lines))

    @nhmisc_stickyroles.command(name="scan")
    async def nhmisc_stickyroles_scan(self, ctx: commands.Context) -> None:
        """Scan sticky role DB for role IDs missing from Discord"""
        await self._require_manage_guild(ctx)
        existing_role_ids = {role.id for role in ctx.guild.roles}
        orphaned_roles = await self._sticky_roles.get_orphaned_roles(
            ctx.guild.id, existing_role_ids
        )
        if not orphaned_roles:
            await ctx.send("No sticky role DB entries need review")
            return

        await ctx.send(
            f"Found {len(orphaned_roles)} sticky role DB entries that need review. "
            "I will ask about them one by one."
        )
        for role_id, config_exists, saved_rows in orphaned_roles:
            await self._prompt_sticky_role_db_action(
                guild=ctx.guild,
                channel=ctx.channel,
                role_id=role_id,
                role_name=None,
                config_exists=config_exists,
                saved_rows=saved_rows,
                reason="manual orphan scan",
                requester=ctx.author,
            )

    @nhmisc_stickyroles.group(name="debuglogging", invoke_without_command=True)
    async def nhmisc_stickyroles_debuglogging(self, ctx: commands.Context) -> None:
        """Configure sticky role debug logging"""
        await self._require_manage_guild(ctx)
        config = await self.config.guild(ctx.guild).all()
        await self._send_nhmisc_overview(
            ctx,
            title="Sticky role debug logging",
            current=(
                "Enabled: "
                + ("Yes" if config["sticky_debug_logging_enabled"] else "No"),
                "Destination: Process log",
            ),
        )

    @nhmisc_stickyroles_debuglogging.command(name="toggle")
    async def nhmisc_stickyroles_debuglogging_toggle(
        self, ctx: commands.Context, enabled: bool
    ) -> None:
        """Enable or disable sticky role debug logging"""
        await self._require_manage_guild(ctx)
        await self.config.guild(ctx.guild).sticky_debug_logging_enabled.set(enabled)
        state = "enabled" if enabled else "disabled"
        await ctx.send(f"Sticky role debug logging {state}")

    @nhmisc.group(name="activity", invoke_without_command=True)
    async def nhmisc_activity(self, ctx: commands.Context) -> None:
        """Configure and inspect passive message activity summaries"""
        await self._require_activity_staff(ctx)
        config = await self.config.guild(ctx.guild).all()
        history_days = config["activity_history_retention_days"]
        if history_days < 0:
            history_label = "Unlimited"
        elif history_days == 0:
            history_label = "Disabled"
        else:
            history_label = f"{history_days} days"

        await self._send_nhmisc_overview(
            ctx,
            title="Activity tracking",
            current=(
                "Summary channel: "
                f"{self._configured_channel_label(ctx.guild, config['activity_channel'])}",
                f"Detail retention: {config['activity_detail_retention_days']} days",
                f"History retention: {history_label}",
            ),
        )

    @nhmisc_activity.command(name="channel", usage="[channel|clear]")
    async def nhmisc_activity_channel(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel | str | None = None,
    ) -> None:
        """Show, set, or clear the channel used for automatic daily activity summaries"""
        if isinstance(channel, str):
            await self._require_manage_guild(ctx)
            if channel.casefold() != "clear":
                raise commands.UserFeedbackCheckFailure("Provide a channel or use clear")
            await self.config.guild(ctx.guild).activity_channel.set(None)
            await ctx.send("Activity summary channel cleared")
            return
        if channel is None:
            await self._require_activity_staff(ctx)
            await self._show_log_destination(
                ctx, title="Activity summary", config_key="activity_channel"
            )
            return
        await self._require_manage_guild(ctx)
        missing_permissions = self._support.missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)

        await self.config.guild(ctx.guild).activity_channel.set(channel.id)
        await ctx.send(f"Activity summary channel set to {channel.mention}")

    @nhmisc_activity.command(name="current")
    async def nhmisc_activity_current(self, ctx: commands.Context) -> None:
        """Preview the current UTC day's activity without closing it"""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        today = self._utc_today()
        summary = await self._activity_store.build_current_summary(
            ctx.guild.id, today, ctx.guild.member_count or 0
        )
        if summary is None:
            await ctx.send("No activity data has been collected for the current UTC day")
            return

        await ctx.send(embed=self._build_daily_summary_embed(summary, title_prefix="Current day"))

    @nhmisc_activity.command(name="latest")
    async def nhmisc_activity_latest(self, ctx: commands.Context) -> None:
        """Repost the latest retained closed daily activity summary"""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        summary = await self._activity_store.get_latest_summary(ctx.guild.id)
        if summary is None:
            await ctx.send("No retained daily activity summary is available")
            return

        await ctx.send(embed=self._build_daily_summary_embed(summary, title_prefix="Latest day"))

    @nhmisc_activity.command(name="timeline")
    async def nhmisc_activity_timeline(self, ctx: commands.Context, days: int) -> None:
        """Show a compact timeline for retained closed daily summaries"""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Days must be at least 1")

        config = await self.config.guild(ctx.guild).all()
        history_retention = int(config["activity_history_retention_days"])
        if history_retention == 0:
            await ctx.send("Historical activity summaries are not retained on this server")
            return
        if history_retention > 0 and days > history_retention:
            days = history_retention

        end_date = self._utc_today() - timedelta(days=1)
        timeline = await self._activity_store.get_timeline(ctx.guild.id, end_date, days)
        top_channels = await self._activity_store.get_timeline_top_channels(
            ctx.guild.id, end_date, days
        )
        await ctx.send(embed=self._build_timeline_embed(timeline, top_channels, days))

    @nhmisc_activity.command(name="channelstats")
    async def nhmisc_activity_channelstats(
        self, ctx: commands.Context, channel: discord.TextChannel, days: int
    ) -> None:
        """Show message activity for a channel day by day"""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Days must be at least 1")

        config = await self.config.guild(ctx.guild).all()
        history_retention = int(config["activity_history_retention_days"])
        detail_retention = max(1, int(config["activity_detail_retention_days"]))
        if history_retention == 0:
            days = min(days, detail_retention)
        elif history_retention > 0:
            days = min(days, max(history_retention, detail_retention))

        timeline = await self._activity_store.get_channel_timeline(
            ctx.guild.id,
            channel.id,
            None,
            self._utc_today(),
            days,
        )
        await ctx.send(embed=self._build_channel_timeline_embed(channel, timeline, days))

    @nhmisc_activity.command(name="verify")
    async def nhmisc_activity_verify(self, ctx: commands.Context) -> None:
        """Verify today's aggregate activity cache consistency"""
        await self._require_activity_staff(ctx)
        today = self._utc_today()
        report = await self._activity_store.verify_open_day_consistency(ctx.guild.id, today)
        await ctx.send(embed=self._build_activity_consistency_embed(report, today))

    @nhmisc_activity.command(name="dbsize")
    async def nhmisc_activity_dbsize(self, ctx: commands.Context) -> None:
        """Show activity SQLite database size and row counts"""
        await self._require_activity_staff(ctx)
        stats = await self._activity_store.get_database_stats()
        await ctx.send(embed=self._build_activity_database_stats_embed(stats))

    @nhmisc_activity.command(name="retention")
    async def nhmisc_activity_retention(self, ctx: commands.Context, days: int) -> None:
        """Set how many days of per-user/channel detail rows are retained"""
        await self._require_manage_guild(ctx)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Detail retention must be at least 1 day")

        cutoff = self._utc_today() - timedelta(days=days - 1)
        rows_to_delete = await self._activity_store.count_detail_rows_older_than(
            ctx.guild.id, cutoff
        )
        if rows_to_delete:
            confirmed = await self._confirm_retention_delete(
                ctx,
                (
                    f"Changing detail retention to {days} days will permanently delete "
                    f"{rows_to_delete} user/channel detail rows older than {cutoff.isoformat()}.\n"
                    f"Reply with `{RETENTION_CONFIRMATION}` to continue."
                ),
            )
            if not confirmed:
                return
            deleted = await self._activity_store.prune_detail_rows_older_than(ctx.guild.id, cutoff)
            await ctx.send(f"Deleted {deleted} detail rows")

        await self.config.guild(ctx.guild).activity_detail_retention_days.set(days)
        await ctx.send(f"Activity detail retention set to {days} days")

    @nhmisc_activity.command(name="historyretention")
    async def nhmisc_activity_history_retention(self, ctx: commands.Context, days: int) -> None:
        """Set how many closed daily aggregate summaries are retained"""
        await self._require_manage_guild(ctx)
        if days < -1:
            raise commands.UserFeedbackCheckFailure(
                "History retention must be -1, 0, or a positive number of days"
            )

        cutoff = self._history_retention_cutoff(days)
        summary_rows = top_rows = channel_rows = 0
        if cutoff is not None:
            (
                summary_rows,
                top_rows,
                channel_rows,
            ) = await self._activity_store.count_history_rows_older_than(ctx.guild.id, cutoff)
        if summary_rows or top_rows or channel_rows:
            confirmed = await self._confirm_retention_delete(
                ctx,
                (
                    f"Changing history retention to {days} will permanently delete "
                    f"{summary_rows} daily summary rows, {top_rows} top-channel rows, "
                    f"and {channel_rows} channel summary rows "
                    f"older than {cutoff.isoformat()}.\n"
                    f"Reply with `{RETENTION_CONFIRMATION}` to continue."
                ),
            )
            if not confirmed:
                return
            (
                deleted_summary,
                deleted_top,
                deleted_channel,
            ) = await self._activity_store.prune_history_rows_older_than(ctx.guild.id, cutoff)
            await ctx.send(
                f"Deleted {deleted_summary} daily summary rows, {deleted_top} top-channel rows, "
                f"and {deleted_channel} channel summary rows"
            )

        await self.config.guild(ctx.guild).activity_history_retention_days.set(days)
        await ctx.send(f"Activity history retention set to {days}")

    @nhmisc.group(
        name="usermodstats",
        invoke_without_command=True,
        usage="[target] [range]",
    )
    async def nhmisc_usermodstats(
        self,
        ctx: commands.Context,
        target: str | None = None,
        range_text: str | None = None,
    ) -> None:
        """Show user activity reports, or run one when a user and range are given"""
        await self._require_activity_staff(ctx)
        if target is None and range_text is None:
            await self._send_nhmisc_overview(ctx, title="User activity reports")
            return
        if target is None or range_text is None:
            raise commands.UserFeedbackCheckFailure("Pass a user and a range")
        await self._report_user_modstats(ctx, target, range_text)

    @nhmisc_usermodstats.command(name="user", usage="<target> <range>")
    async def nhmisc_usermodstats_user(
        self, ctx: commands.Context, target: str, range_text: str
    ) -> None:
        """Show moderator-only message activity stats for a user"""
        await self._report_user_modstats(ctx, target, range_text)

    async def _report_user_modstats(
        self, ctx: commands.Context, target: str, range_text: str
    ) -> None:
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        user_id = self._parse_user_id(target)
        days = self._parse_range_days(range_text)
        days = await self._cap_detail_days(ctx.guild, days)
        end_date = self._utc_today()
        stats = await self._activity_store.get_user_stats(ctx.guild.id, user_id, end_date, days)

        title = f"User activity: {self._format_user_reference(ctx.guild, user_id)}"
        await ctx.send(embed=self._build_user_stats_embed(title, stats, days))

    @nhmisc_usermodstats.command(name="channel")
    async def nhmisc_usermodstats_channel(
        self,
        ctx: commands.Context,
        target: str,
        channel_text: str,
        range_text: str,
    ) -> None:
        """Show moderator-only message activity stats for a user in one channel"""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        user_id = self._parse_user_id(target)
        days = self._parse_range_days(range_text)
        days = await self._cap_detail_days(ctx.guild, days)
        end_date = self._utc_today()
        channel = self._resolve_text_channel_or_thread(ctx.guild, channel_text)
        parent_channel_id = self._activity_parent_channel_id(channel)
        thread_id = self._activity_thread_id(channel)
        stats = await self._activity_store.get_user_channel_stats(
            ctx.guild.id,
            user_id,
            parent_channel_id,
            thread_id,
            thread_id is None,
            end_date,
            days,
        )

        title = (
            f"User channel activity: {self._format_user_reference(ctx.guild, user_id)} - "
            f"{self._format_activity_location(ctx.guild, parent_channel_id, thread_id)}"
        )
        await ctx.send(embed=self._build_user_channel_stats_embed(title, stats, days))

    @nhmisc_usermodstats.command(name="channels")
    async def nhmisc_usermodstats_channels(
        self, ctx: commands.Context, target: str, range_text: str
    ) -> None:
        """Show how a user's activity is distributed across channels"""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        user_id = self._parse_user_id(target)
        days = self._parse_range_days(range_text)
        days = await self._cap_detail_days(ctx.guild, days)
        end_date = self._utc_today()
        distribution = await self._activity_store.get_user_channel_distribution(
            ctx.guild.id, user_id, end_date, days
        )

        title = f"User channel distribution: {self._format_user_reference(ctx.guild, user_id)}"
        await ctx.send(
            embed=self._build_user_channel_distribution_embed(ctx.guild, title, distribution, days)
        )

    @commands.command(name="emojireport", ignore_extra=False)
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def nhmisc_emojireport(self, ctx: commands.Context) -> None:
        """Export lifetime usage and daily averages for every current server emoji"""
        self._require_emoji_intents("all")
        catalog = [
            (EmojiInfo(emoji.id, emoji.name, emoji.animated), emoji.created_at.date())
            for emoji in ctx.guild.emojis
        ]
        if not catalog:
            await ctx.send("This server has no custom emoji")
            return
        rows = await self._activity_store.get_emoji_report(ctx.guild.id, self._utc_today(), catalog)
        try:
            export = build_csv_export(
                ["Emoji", "Emoji ID", "Animated", "Messages", "Reaction balance", "Total uses",
                 "Tracking since (UTC)", "Tracking days", "Uses per day"],
                ((row.usage.emoji.name, str(row.usage.emoji_id), row.usage.emoji.animated,
                  row.usage.message_uses, row.usage.reaction_uses, row.usage.total,
                  row.tracked_since.isoformat(), row.tracked_days, f"{row.uses_per_day:.4f}")
                 for row in rows),
                ctx.guild.filesize_limit,
                "emoji-report",
            )
        except ExportTooLarge as error:
            raise commands.UserFeedbackCheckFailure(
                "The emoji report exceeds this server's attachment limit"
            ) from error
        unused = [row for row in rows if row.usage.total == 0]
        used = [row for row in rows if row.usage.total > 0]
        embed = discord.Embed(
            title=f"Emoji usage report - {ctx.guild.name}",
            description=(
                f"Current server emoji: {len(rows):,}\nZero recorded uses: {len(unused):,}\n"
                "The CSV lists all emoji, least used first. Rates include messages and the "
                "reaction balance. Days start at tracking, or creation for newer emoji (UTC)."
            ),
            color=discord.Color.blue(),
        )
        embed.add_field(
            name="Zero-use examples",
            value=" ".join(row.usage.emoji.mention for row in unused[:10]) or "None",
            inline=False,
        )
        embed.add_field(
            name="Lowest nonzero use rates",
            value="\n".join(
                f"{row.usage.emoji.mention} {row.uses_per_day:.4f}/day"
                for row in used[:10]
            ) or "No recorded usage",
            inline=False,
        )
        await ctx.send(
            embed=embed, file=discord.File(io.BytesIO(export.data), filename=export.filename),
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @commands.command(
        name="emojichart",
        usage="[channel_or_thread] [summary|days] [amount] [all|messages|reactions]",
    )
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def nhmisc_emojichart(self, ctx: commands.Context, *, arguments: str = "summary") -> None:
        """Chart server emoji usage since tracking began or over the last 1-30 days"""
        tokens = arguments.split()
        target = None
        if tokens and (
            tokens[0].startswith("<#")
            or (tokens[0].isdigit() and len(tokens[0]) >= DISCORD_SNOWFLAKE_MIN_DIGITS)
        ):
            target = self._resolve_text_channel_or_thread(ctx.guild, tokens.pop(0))
            if not target.permissions_for(ctx.author).view_channel:
                raise commands.UserFeedbackCheckFailure("You cannot view that channel or thread")
        period = tokens.pop(0).lower() if tokens else "summary"
        if period == "summary":
            days = None
        elif period.isdigit() and 1 <= int(period) <= 30:
            days = int(period)
        else:
            raise commands.UserFeedbackCheckFailure("Use summary or a day count from 1 through 30")
        amount_text = (
            tokens.pop(0) if tokens and tokens[0].isdigit()
            else str(DEFAULT_CHATCHART_USER_COUNT)
        )
        if not amount_text.isdigit() or not 1 <= int(amount_text) <= MAX_CHATCHART_USER_COUNT:
            raise commands.UserFeedbackCheckFailure("Amount must be between 1 and 20")
        amount = int(amount_text)
        mode = tokens.pop(0).lower() if tokens else "all"
        if mode not in {"all", "messages", "reactions"} or tokens:
            raise commands.UserFeedbackCheckFailure("Use all, messages, or reactions after amount")
        self._require_emoji_intents(mode)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        counts = await self._activity_store.get_emoji_counts(
            ctx.guild.id, self._utc_today(), days, target.id if target is not None else None
        )
        counts = sorted(counts, key=lambda row: (-self._emoji_chart_value(row, mode), row.emoji_id))
        counts = [row for row in counts if self._emoji_chart_value(row, mode) > 0]
        if not counts:
            await ctx.send("No recorded server emoji usage for this selection")
            return
        period_label = "Since tracking began" if days is None else f"Last {days} days (UTC)"
        location = f"#{target.name}" if target is not None else ctx.guild.name
        selected = counts[:amount]
        row_icons = await self._load_emoji_chart_icons(selected)
        file = render_ranked_donut_chart(
            [(f":{row.emoji.name}:", self._emoji_chart_value(row, mode)) for row in selected],
            other_count=sum(self._emoji_chart_value(row, mode) for row in counts[amount:]),
            title=f"Server emoji usage - {period_label}",
            context_label=location,
            center_unit="uses",
            donut_title=f"Emoji share ({mode})",
            filename="emojichart.png",
            row_icons=row_icons,
        )
        embed = discord.Embed(
            title=f"Emoji usage - {location}",
            description=(f"{period_label}\nMessages count each emoji once per message. "
                         "Reactions show additions minus removals, including super reactions."),
            color=discord.Color.blue(),
        )
        for index, row in enumerate(selected, start=1):
            embed.add_field(
                name=f"{index}. :{row.emoji.name}:",
                value=(f"{row.emoji.mention}\nMessages: {row.message_uses:,} | "
                       f"Reactions: {row.reaction_uses:,} | Total: {row.total:,}"),
                inline=False,
            )
        await ctx.send(embed=embed, file=file, allowed_mentions=discord.AllowedMentions.none())

    async def _load_emoji_chart_icons(self, rows: list[EmojiCount]) -> list[bytes | None]:
        timeout = aiohttp.ClientTimeout(total=6, connect=3)
        async with aiohttp.ClientSession(
            timeout=timeout, connector=aiohttp.TCPConnector(limit=4),
        ) as session:
            async def read_icon(row: EmojiCount) -> bytes | None:
                url = (
                    f"https://cdn.discordapp.com/emojis/{row.emoji_id}.webp"
                    "?size=64&quality=lossless"
                )
                try:
                    async with session.get(url, allow_redirects=False) as response:
                        if response.status != 200:
                            return None
                        data = bytearray()
                        async for chunk in response.content.iter_chunked(16 * 1024):
                            data.extend(chunk)
                            if len(data) > MAX_EMOJI_ICON_BYTES:
                                return None
                        return bytes(data)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    return None

            return list(await asyncio.gather(*(read_icon(row) for row in rows)))

    @staticmethod
    def _emoji_chart_value(row: EmojiCount, mode: str) -> int:
        if mode == "messages":
            return row.message_uses
        if mode == "reactions":
            return row.reaction_uses
        return row.total

    def _require_emoji_intents(self, mode: str) -> None:
        intents = self.bot.intents
        if not intents.emojis_and_stickers:
            raise commands.UserFeedbackCheckFailure(
                "Guild Expressions intent is required to keep the server emoji list up to date"
            )
        if mode in {"all", "messages"} and not (intents.guild_messages and intents.message_content):
            raise commands.UserFeedbackCheckFailure(
                "Guild Messages and Message Content intents are required to collect message emoji"
            )
        if mode in {"all", "reactions"} and not intents.guild_reactions:
            raise commands.UserFeedbackCheckFailure(
                "Guild Message Reactions intent is required to collect emoji reactions"
            )

    @commands.command(
        name="chatchart",
        usage="<days> [amount] | <channel_or_thread> <days> [amount]",
    )
    @commands.guild_only()
    @commands.has_permissions(manage_messages=True)
    async def nhmisc_chatchart(
        self,
        ctx: commands.Context,
        target_or_days: str | None = None,
        days_or_amount: int | None = None,
        amount: int | None = None,
    ) -> None:
        """Render a chart of user activity in the selected or current channel"""
        if target_or_days is None:
            await ctx.send_help(ctx.command)
            return
        await self._require_activity_staff(ctx)
        target, days, amount = self._resolve_chatchart_request(
            ctx,
            target_or_days,
            days_or_amount,
            amount,
        )
        if target is not ctx.channel and not target.permissions_for(ctx.author).view_channel:
            raise commands.UserFeedbackCheckFailure(
                "You cannot view that channel or thread"
            )
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Days must be at least 1")
        if not 1 <= amount <= MAX_CHATCHART_USER_COUNT:
            raise commands.UserFeedbackCheckFailure(
                f"Amount must be between 1 and {MAX_CHATCHART_USER_COUNT}"
            )

        days = await self._cap_detail_days(ctx.guild, days)
        channel_id = self._activity_parent_channel_id(target)
        counts = await self._activity_store.get_channel_user_counts(
            ctx.guild.id,
            channel_id,
            self._activity_thread_id(target),
            self._utc_today(),
            days,
        )
        if not counts:
            await ctx.send(f"No retained activity data for this channel in the last {days} days")
            return

        file = self._build_chatchart_file(
            ctx.guild,
            counts,
            days,
            self._chatchart_location_label(target),
            amount,
        )
        content = "One is a bit low, no? 🤨" if amount == 1 else None
        await ctx.send(
            content,
            file=file,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @nhmisc.command(name="topyapper")
    async def nhmisc_topyapper(
        self, ctx: commands.Context, days: int, amount: int
    ) -> None:
        """Show the most active users across this server"""
        await self._send_yapper_ranking(ctx, days, amount)

    @commands.command(name="selfchart")
    @commands.guild_only()
    async def selfchart(self, ctx: commands.Context) -> None:
        """Show your own simplified activity stats for the last 7 retained days"""
        days = await self._cap_detail_days(ctx.guild, 7)
        stats = await self._activity_store.get_user_stats(
            ctx.guild.id, ctx.author.id, self._utc_today(), days
        )
        embed = self._build_selfchart_embed(ctx.author, stats, days)
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())

    @commands.Cog.listener()
    async def on_thread_create(self, thread: discord.Thread) -> None:
        """Pin the starter message for a new post in a configured forum."""
        await self._forum_autopin.handle_thread_create(thread)

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        """Drop autopin configuration for a deleted forum."""
        await self._forum_autopin.handle_channel_delete(channel)

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member) -> None:
        """Snapshot configured sticky roles when a member leaves."""
        configured_roles = await self._sticky_roles.get_sticky_roles(member.guild.id)
        if not configured_roles:
            await self._send_sticky_debug_log(
                member.guild,
                (
                    "Sticky role snapshot write skipped\n"
                    f"User: {member.mention} (`{member.id}`)\n"
                    "Reason: no sticky roles are configured on this server."
                ),
            )
            return

        current_role_ids = {role.id for role in member.roles}
        saved_role_ids = configured_roles & current_role_ids
        await self._sticky_roles.replace_member_roles(
            member.guild.id,
            member.id,
            saved_role_ids,
        )
        await self._send_sticky_debug_log(
            member.guild,
            (
                "Sticky role snapshot written\n"
                f"User: {member.mention} (`{member.id}`)\n"
                f"Saved roles: {self._format_role_id_set(member.guild, saved_role_ids)}"
            ),
        )

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        """Restore saved sticky roles when a member rejoins."""
        saved_role_ids = await self._sticky_roles.get_member_roles(member.guild.id, member.id)
        if not saved_role_ids:
            await self._send_sticky_debug_log(
                member.guild,
                (
                    "Sticky role snapshot read\n"
                    f"User: {member.mention} (`{member.id}`)\n"
                    "Saved roles: none\n"
                    "Result: nothing to restore."
                ),
            )
            return

        configured_role_ids = await self._sticky_roles.get_sticky_roles(member.guild.id)
        roles: list[discord.Role] = []
        for role_id in sorted(saved_role_ids & configured_role_ids):
            role = member.guild.get_role(role_id)
            if role is not None and self._can_restore_role(member.guild, role):
                roles.append(role)

        restorable_role_ids = {role.id for role in roles}
        skipped_role_ids = saved_role_ids - restorable_role_ids
        if not roles:
            await self._send_sticky_debug_log(
                member.guild,
                (
                    "Sticky role snapshot read\n"
                    f"User: {member.mention} (`{member.id}`)\n"
                    f"Saved roles: {self._format_role_id_set(member.guild, saved_role_ids)}\n"
                    "Restorable roles: none\n"
                    f"Skipped roles: {self._format_role_id_set(member.guild, skipped_role_ids)}\n"
                    "Result: nothing restorable."
                ),
            )
            return

        result = "restored"
        try:
            await member.add_roles(*roles, reason="Restoring sticky roles")
        except discord.Forbidden:
            result = "failed: missing permissions"
            log.warning(
                "Missing permissions to restore sticky roles for member %s in guild %s",
                member.id,
                member.guild.id,
            )
        except discord.HTTPException:
            result = "failed: Discord API error"
            log.exception(
                "Failed to restore sticky roles for member %s in guild %s",
                member.id,
                member.guild.id,
            )
        await self._send_sticky_debug_log(
            member.guild,
            (
                "Sticky role snapshot read\n"
                f"User: {member.mention} (`{member.id}`)\n"
                f"Saved roles: {self._format_role_id_set(member.guild, saved_role_ids)}\n"
                f"Restorable roles: {self._format_role_id_set(member.guild, restorable_role_ids)}\n"
                f"Skipped roles: {self._format_role_id_set(member.guild, skipped_role_ids)}\n"
                f"Result: {result}."
            ),
        )

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role) -> None:
        """Clean up role-backed state when a Discord role is deleted."""
        definition = next(
            (
                definition
                for definition in await self._achievement_store.list_definitions(
                    role.guild.id
                )
                if definition.role_id == role.id
            ),
            None,
        )
        if definition is not None:
            await self._achievement_store.unbind_role(role.guild.id, role.id)
            await self._send_error_notice(
                role.guild,
                f"Stopped tracking deleted role {role.name} for "
                f"{definition.display_name}",
                ping=True,
                failure_action="publish deleted achievement role notice",
            )

        config_exists, saved_rows = await self._sticky_roles.get_role_state(
            role.guild.id, role.id
        )
        if not config_exists and saved_rows == 0:
            return

        channel = await self._private_error_channel(role.guild)
        if channel is None:
            log.warning(
                "Sticky role %s was deleted in guild %s but the error channel is unavailable",
                role.id,
                role.guild.id,
            )
            await self.report_operational_error(
                guild_id=role.guild.id,
                source="NHMisc",
                action="prompt deleted sticky role decision",
                error=RuntimeError("The error channel is unavailable"),
            )
            return

        await self._prompt_sticky_role_db_action(
            guild=role.guild,
            channel=channel,
            role_id=role.id,
            role_name=role.name,
            config_exists=config_exists,
            saved_rows=saved_rows,
            reason="Discord role deletion event",
            requester=None,
            ping=True,
        )

    @commands.Cog.listener("on_member_join")
    async def on_role_analytics_member_join(self, member: discord.Member) -> None:
        await self._role_analytics.member_joined(
            member.guild.id,
            member,
            member.guild.default_role.id,
        )

    @commands.Cog.listener("on_member_update")
    async def on_role_analytics_member_update(
        self, before: discord.Member, after: discord.Member
    ) -> None:
        before_role_ids = {role.id for role in before.roles}
        after_role_ids = {role.id for role in after.roles}
        if before_role_ids == after_role_ids:
            return
        await self._role_analytics.member_roles_changed(
            after.guild.id,
            after,
            after.guild.default_role.id,
        )

    @commands.Cog.listener("on_member_update")
    async def on_achievement_member_update(
        self, before: discord.Member, after: discord.Member
    ) -> None:
        if after.bot or not await self._achievement_store.is_bootstrapped(
            after.guild.id
        ):
            return
        before_role_ids = {role.id for role in before.roles}
        after_role_ids = {role.id for role in after.roles}
        changed_role_ids = before_role_ids ^ after_role_ids
        definitions = tuple(
            definition
            for definition in await self._achievement_store.list_definitions(
                after.guild.id
            )
            if definition.role_id is not None
        )
        protected_role_ids = set(GATE_TIER_ROLE_IDS) | {
            definition.role_id for definition in definitions
        }
        if not changed_role_ids & protected_role_ids:
            return

        corrected_roles: list[int] = []
        before_gate_roles = before_role_ids & set(GATE_TIER_ROLE_IDS)
        after_gate_roles = after_role_ids & set(GATE_TIER_ROLE_IDS)
        authorized_gate_roles = self._authorized_gate_role_edits.get(
            (after.guild.id, after.id)
        )
        authorized_gate_change = (
            before_gate_roles != after_gate_roles
            and authorized_gate_roles == frozenset(after_gate_roles)
        )
        restored_gate = False
        if before_gate_roles != after_gate_roles and not authorized_gate_change:
            completed_count = await self._achievement_store.get_gate_projection(
                after.guild.id,
                after.id,
            )
            expected_gate_roles = (
                {GATE_TIER_ROLE_IDS[completed_count - 1]}
                if 0 < completed_count <= len(GATE_TIER_ROLE_IDS)
                else set()
            )
            if after_gate_roles != expected_gate_roles:
                try:
                    restored_gate = await self._restore_gate_projection(
                        after.guild,
                        after,
                        completed_count,
                        reason="Revert unauthorized Gate role change",
                    )
                except (
                    commands.UserFeedbackCheckFailure,
                    discord.Forbidden,
                    discord.HTTPException,
                ):
                    log.exception(
                        "Failed to revert Gate role change for guild %s member %s",
                        after.guild.id,
                        after.id,
                    )
                    await self._send_guild_alert(
                        after.guild,
                        f"Failed to restore Gate roles for <@{after.id}>",
                    )
                    return
                if restored_gate:
                    corrected_roles.extend(after_gate_roles ^ expected_gate_roles)

        for definition in definitions:
            role_id = definition.role_id
            if role_id is None or role_id not in changed_role_ids:
                continue
            should_have_role = after.id in set(
                await self._achievement_store.projected_users_for_boolean(
                    after.guild.id,
                    definition.key,
                )
            )
            if (role_id in after_role_ids) == should_have_role:
                continue
            try:
                await self._edit_achievement_roles(
                    after.guild,
                    after,
                    add_role_ids=(role_id,) if should_have_role else (),
                    remove_role_ids=() if should_have_role else (role_id,),
                    reason="Revert unauthorized achievement role change",
                )
            except (
                commands.UserFeedbackCheckFailure,
                discord.Forbidden,
                discord.HTTPException,
            ):
                log.exception(
                    "Failed to restore achievement role %s for guild %s member %s",
                    role_id,
                    after.guild.id,
                    after.id,
                )
                await self._send_guild_alert(
                    after.guild,
                    f"Failed to restore <@&{role_id}> for <@{after.id}>",
                )
                return
            corrected_roles.append(role_id)

        if corrected_roles:
            rendered_roles = ", ".join(
                f"<@&{role_id}>" for role_id in sorted(set(corrected_roles))
            )
            await self._send_guild_alert(
                after.guild,
                f"Restored achievement roles for <@{after.id}>: {rendered_roles}",
            )
        if restored_gate:
            task = asyncio.create_task(
                self._notify_unauthorized_gate_actor(after.guild, after.id)
            )
            self._audit_log_tasks.add(task)
            task.add_done_callback(self._audit_log_tasks.discard)

    async def _notify_unauthorized_gate_actor(
        self, guild: discord.Guild, member_id: int
    ) -> None:
        permissions = getattr(guild.me, "guild_permissions", None)
        if permissions is None or not permissions.view_audit_log:
            log.warning(
                "Cannot attribute unauthorized Gate change in guild %s: "
                "View Audit Log is missing",
                guild.id,
            )
            return
        await asyncio.sleep(2)
        try:
            async for entry in guild.audit_logs(
                limit=8,
                action=discord.AuditLogAction.member_role_update,
            ):
                target = getattr(entry, "target", None)
                if target is None or target.id != member_id:
                    continue
                created_at = getattr(entry, "created_at", None)
                if created_at is None or (
                    datetime.now(timezone.utc) - created_at
                ).total_seconds() > 30:
                    continue
                actor = getattr(entry, "user", None)
                if actor is None or actor.bot:
                    continue
                delivered = await self._send_guild_alert(
                    guild,
                    f"<@{actor.id}> Gate roles must be changed through the bot. "
                    "Your manual role change was automatically reverted",
                    ping_user=actor,
                )
                if not delivered:
                    log.warning(
                        "Could not notify the moderator about a reverted Gate "
                        "change in guild %s because the alert channel is unavailable",
                        guild.id,
                    )
                return
        except (discord.Forbidden, discord.HTTPException):
            log.warning(
                "Could not notify the moderator about a reverted Gate change "
                "in guild %s",
                guild.id,
            )

    @commands.Cog.listener("on_member_remove")
    async def on_role_analytics_member_remove(self, member: discord.Member) -> None:
        await self._role_analytics.member_removed(member.guild.id, member.id)

    @commands.Cog.listener("on_guild_role_delete")
    async def on_role_analytics_role_delete(self, role: discord.Role) -> None:
        await self._role_analytics.role_deleted(role.guild.id, role.id)

    @commands.Cog.listener("on_resumed")
    async def on_role_analytics_resumed(self) -> None:
        await self._role_analytics.schedule_resumed_check(tuple(self.bot.guilds))

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        """Passively collect message activity counters."""
        guild = message.guild
        if guild is None:
            return
        if message.author.bot or message.webhook_id is not None:
            return
        try:
            if self._bot_proxy is not None:
                await self._bot_proxy.handle_message(message)
        except Exception as error:
            await self.report_operational_error(
                guild_id=guild.id,
                source="NHMisc",
                action="process Bot Proxy workflow input",
                error=error,
                channel_id=message.channel.id,
                thread_id=(
                    message.channel.id
                    if isinstance(message.channel, discord.Thread)
                    else None
                ),
                message_id=message.id,
            )
        if message.type not in {discord.MessageType.default, discord.MessageType.reply}:
            return

        now = datetime.now(timezone.utc)
        today = now.date()
        await self._close_stale_activity_days_for_guild(guild, send_reports=True)
        emoji_ids = {int(value) for value in CUSTOM_EMOJI_PATTERN.findall(message.content)}
        emojis = tuple(
            EmojiInfo(emoji.id, emoji.name, emoji.animated)
            for emoji in guild.emojis if emoji.id in emoji_ids
        ) if emoji_ids else ()
        await self._activity_store.record_message(
            guild.id,
            today,
            now.hour,
            message.author.id,
            self._activity_parent_channel_id(message.channel),
            self._activity_thread_id(message.channel),
            now,
            emojis=emojis,
        )

    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload: discord.RawReactionActionEvent) -> None:
        await self._record_emoji_reaction_event(payload, 1)

    @commands.Cog.listener()
    async def on_raw_reaction_remove(self, payload: discord.RawReactionActionEvent) -> None:
        await self._record_emoji_reaction_event(payload, -1)

    async def _record_emoji_reaction_event(
        self, payload: discord.RawReactionActionEvent, delta: int,
    ) -> None:
        if payload.guild_id is None or payload.emoji.id is None:
            return
        guild = self.bot.get_guild(payload.guild_id)
        if guild is None:
            return
        member = payload.member if delta > 0 else guild.get_member(payload.user_id)
        if member is not None and member.bot:
            return
        emoji = next((emoji for emoji in guild.emojis if emoji.id == payload.emoji.id), None)
        if emoji is None:
            return
        await self._close_stale_activity_days_for_guild(guild, send_reports=True)
        await self._activity_store.record_emoji_reaction(
            guild.id, self._utc_today(), payload.channel_id,
            EmojiInfo(emoji.id, emoji.name, emoji.animated), delta,
        )

    @commands.Cog.listener("on_guild_remove")
    async def on_emoji_guild_remove(self, guild: discord.Guild) -> None:
        await self._activity_store.delete_emoji_guild(guild.id)

    @commands.Cog.listener("on_guild_join")
    async def on_emoji_guild_join(self, guild: discord.Guild) -> None:
        await self._activity_store.begin_emoji_tracking(guild.id, self._utc_today())

    @commands.Cog.listener()
    async def on_voice_state_update(
        self,
        member: discord.Member,
        before: discord.VoiceState,
        after: discord.VoiceState,
    ) -> None:
        """Log voice channel joins, leaves, moves, and VC jumping."""
        if before.channel == after.channel:
            return

        guild = member.guild
        config = await self.config.guild(guild).all()
        log_channel = self._support.get_log_channel(guild, config["voice_log_channel"])
        event_timestamp = int(time.time())

        if log_channel is not None:
            if before.channel is None and after.channel is not None:
                await self._support.send_log_message(
                    log_channel,
                    (
                        f"{member.mention} ({member.id}) has joined a channel "
                        f"{after.channel.mention} at <t:{event_timestamp}:F>"
                    ),
                )
            elif before.channel is not None and after.channel is None:
                await self._support.send_log_message(
                    log_channel,
                    (
                        f"{member.mention} ({member.id}) has left a channel "
                        f"{before.channel.mention} at <t:{event_timestamp}:F>"
                    ),
                )
            elif before.channel is not None and after.channel is not None:
                move_log_content = (
                    f"{member.mention} ({member.id}) has moved from "
                    f"{before.channel.mention} to {after.channel.mention} "
                    f"at <t:{event_timestamp}:F>"
                )
                move_log_message = await self._support.send_log_message(
                    log_channel,
                    move_log_content,
                )
                if move_log_message is not None:
                    self._schedule_audit_log_edit(
                        move_log_message,
                        move_log_content,
                        guild,
                        member,
                        after.channel,
                        event_timestamp,
                    )

        if after.channel is None:
            return

        is_vcjumping = self._voice_visits.record_visit(
            (guild.id, member.id),
            after.channel.id,
            timestamp=time.monotonic(),
            visit_count=config["vcjumping_visit_count"],
            window_seconds=config["vcjumping_window_seconds"],
        )
        if is_vcjumping:
            alert_channel = self._support.get_log_channel(guild, config["alert_channel"])
            if alert_channel is None:
                return

            await self._support.send_log_message(
                alert_channel,
                (
                    f"{member.mention} is VC jumping "
                    f"({config['vcjumping_visit_count']} channel entries in "
                    f"{config['vcjumping_window_seconds']} seconds)."
                ),
            )

    async def _require_private_alert_channel(
        self,
        guild: discord.Guild,
    ) -> discord.TextChannel:
        return await self._support.require_private_log_channel(
            guild,
            "alert_channel",
            "alert",
        )

    async def _require_private_moderation_log_channel(
        self,
        guild: discord.Guild,
    ) -> discord.TextChannel:
        return await self._support.require_private_log_channel(
            guild,
            "moderation_log_channel",
            "moderator action",
        )


    async def _send_guild_alert(
        self,
        guild: discord.Guild,
        content: str,
        *,
        ping_user: discord.abc.Snowflake | None = None,
    ) -> bool:
        """Send to the configured enforcement alert channel."""
        return await self._support.send_configured_log(
            guild,
            "alert_channel",
            content,
            ping_user=ping_user,
        )

    async def _send_error_notice(
        self,
        guild: discord.Guild,
        content: str,
        *,
        ping: bool = False,
        channel: discord.abc.Messageable | None = None,
        failure_action: str = "publish error-channel notice",
    ) -> discord.Message | None:
        """Post a former maintenance notice to the shared error channel."""
        return await self._support.send_error_notice(
            guild.id,
            content,
            ping=ping,
            channel=channel,
            failure_action=failure_action,
        )

    async def _send_forum_autopin_alert(
        self,
        guild: discord.Guild,
        content: str,
        *,
        ping: bool = False,
    ) -> bool:
        return await self._send_error_notice(guild, content, ping=ping) is not None

    async def _private_error_channel(
        self, guild: discord.Guild
    ) -> discord.TextChannel | None:
        channel_id = await self._support.config.guild(guild).error_channel()
        channel = self._support.get_log_channel(guild, channel_id)
        if channel is None or self._channel_allows_everyone(channel, guild):
            return None
        return channel

    async def _send_moderation_log(
        self,
        guild: discord.Guild,
        content: str,
        *,
        log_failure: bool = True,
    ) -> bool:
        return await self._support.send_moderation_log(
            guild, content, log_failure=log_failure
        )

    def _schedule_audit_log_edit(
        self,
        message: discord.Message,
        base_content: str,
        guild: discord.Guild,
        member: discord.Member,
        after_channel: discord.VoiceChannel | discord.StageChannel,
        event_timestamp: int,
    ) -> None:
        task = asyncio.create_task(
            self._edit_move_log_with_moderator(
                message,
                base_content,
                guild,
                member,
                after_channel,
                event_timestamp,
            )
        )
        self._audit_log_tasks.add(task)
        task.add_done_callback(self._audit_log_tasks.discard)

    async def _edit_move_log_with_moderator(
        self,
        message: discord.Message,
        base_content: str,
        guild: discord.Guild,
        member: discord.Member,
        after_channel: discord.VoiceChannel | discord.StageChannel,
        event_timestamp: int,
    ) -> None:
        for attempt in range(5):
            if attempt > 0:
                await asyncio.sleep(2)

            moved_by = await self._get_voice_move_moderator(
                guild, member, after_channel, event_timestamp
            )
            if moved_by is None:
                continue

            try:
                timestamp_suffix = f" at <t:{event_timestamp}:F>"
                edited_content = base_content.replace(
                    timestamp_suffix,
                    f" moved by {self._format_user_label(moved_by)}{timestamp_suffix}",
                    1,
                )
                await message.edit(
                    content=edited_content,
                )
            except discord.HTTPException as error:
                log.exception("Failed to edit voice move log message %s", message.id)
                await self.report_operational_error(
                    guild_id=guild.id,
                    source="NHMisc",
                    action="edit voice move log",
                    error=error,
                    channel_id=getattr(message.channel, "id", None),
                    message_id=message.id,
                )
            return

    async def _get_voice_move_moderator(
        self,
        guild: discord.Guild,
        member: discord.Member,
        after_channel: discord.VoiceChannel | discord.StageChannel,
        event_timestamp: int,
    ) -> discord.User | discord.Member | None:
        me = guild.me
        if me is None or not me.guild_permissions.view_audit_log:
            return None

        event_time = datetime.fromtimestamp(event_timestamp, timezone.utc)
        try:
            async for entry in guild.audit_logs(
                limit=5,
                action=discord.AuditLogAction.member_move,
            ):
                created_at = entry.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)

                if abs((created_at - event_time).total_seconds()) > 15:
                    continue

                target_id = getattr(entry.target, "id", None)
                if target_id == member.id:
                    return entry.user

                extra = getattr(entry, "extra", None)
                extra_channel = getattr(extra, "channel", None)
                extra_count = getattr(extra, "count", None)
                if (
                    target_id is None
                    and getattr(extra_channel, "id", None) == after_channel.id
                    and str(extra_count) == "1"
                ):
                    return entry.user
        except discord.Forbidden:
            return None
        except discord.HTTPException as error:
            log.exception("Failed to read audit log for voice move in guild %s", guild.id)
            await self.report_operational_error(
                guild_id=guild.id,
                source="NHMisc",
                action="read voice move audit log",
                error=error,
            )
        return None

    def _format_user_label(self, user: discord.User | discord.Member) -> str:
        name = getattr(user, "display_name", None) or str(user)
        return f"{name} ({user.id})"


    async def _activity_midnight_loop(self) -> None:
        await self.bot.wait_until_ready()
        while True:
            try:
                await self._close_stale_activity_days_for_all_guilds(send_reports=True)
            except Exception as error:
                log.exception("Failed to close stale activity days")
                await self._report_operational_error_for_guilds(
                    "close stale activity days",
                    error,
                )
            try:
                now = datetime.now(timezone.utc)
                next_midnight = datetime.combine(
                    now.date() + timedelta(days=1),
                    datetime_time.min,
                    tzinfo=timezone.utc,
                ) + timedelta(seconds=5)
                await asyncio.sleep(max(1.0, (next_midnight - now).total_seconds()))
            except asyncio.CancelledError:
                raise

    async def _close_stale_activity_days_for_all_guilds(self, send_reports: bool) -> None:
        for guild in list(self.bot.guilds):
            await self._activity_store.begin_emoji_tracking(guild.id, self._utc_today())
            await self._close_stale_activity_days_for_guild(guild, send_reports=send_reports)
            await self._activity_store.prune_emoji_history(guild.id, self._utc_today())

    async def _close_stale_activity_days_for_guild(
        self, guild: discord.Guild, send_reports: bool
    ) -> None:
        today = self._utc_today()
        summaries = await self._activity_store.close_stale_days(
            guild.id, today, guild.member_count or 0
        )
        if not summaries:
            return

        config = await self.config.guild(guild).all()
        channel = self._support.get_log_channel(guild, config["activity_channel"])
        for summary in summaries:
            if send_reports and channel is not None:
                await self._send_activity_summary(channel, summary)
            await self._apply_activity_history_retention(
                guild.id, int(config["activity_history_retention_days"]), summary.date_utc
            )

        await self._apply_activity_detail_retention(
            guild.id, int(config["activity_detail_retention_days"])
        )
        await self._activity_store.prune_emoji_history(guild.id, today)

    async def _send_activity_summary(
        self, channel: discord.TextChannel, summary: DailySummary
    ) -> None:
        try:
            await channel.send(
                embed=self._build_daily_summary_embed(summary, title_prefix="Daily"),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            log.exception("Failed to send activity summary to channel %s", channel.id)

    async def get_member_activity_summary(
        self, guild_id: int, user_id: int, *, now: datetime | None = None
    ) -> dict:
        """Return observed counts within the configured UTC detail-retention window.

        The current day is partial. Collection gaps are unknown and missing
        user detail is not evidence of zero activity. Channels count parent
        channels, including any activity in their threads. No Discord history
        is fetched and the daily report channel does not control collection.
        """
        captured_at = now or datetime.now(timezone.utc)
        if captured_at.tzinfo is None:
            captured_at = captured_at.replace(tzinfo=timezone.utc)
        captured_at = captured_at.astimezone(timezone.utc)
        days = max(
            1, int(await self.config.guild_from_id(guild_id).activity_detail_retention_days())
        )
        start_date = captured_at.date() - timedelta(days=days - 1)
        summary = await self._activity_store.get_member_activity_summary(
            guild_id,
            user_id,
            start_date_utc=start_date,
            end_date_utc=captured_at.date(),
        )
        return {
            **summary,
            "window_start": datetime.combine(
                start_date, datetime_time.min, tzinfo=timezone.utc
            ).isoformat(),
            "window_end": captured_at.isoformat(),
            "captured_at": captured_at.isoformat(),
        }

    async def _apply_activity_detail_retention(self, guild_id: int, days: int) -> None:
        if days < 1:
            return
        cutoff = self._utc_today() - timedelta(days=days - 1)
        await self._activity_store.prune_detail_rows_older_than(guild_id, cutoff)

    async def _apply_activity_history_retention(
        self, guild_id: int, days: int, closed_date: date
    ) -> None:
        if days == -1:
            return
        if days == 0:
            await self._activity_store.delete_history_for_date(guild_id, closed_date)
            return
        cutoff = self._utc_today() - timedelta(days=days)
        await self._activity_store.prune_history_rows_older_than(guild_id, cutoff)

    async def _require_manage_guild(self, ctx: commands.Context) -> None:
        permissions = getattr(ctx.author, "guild_permissions", None)
        has_permission = bool(permissions and permissions.manage_guild)
        if has_permission or await self.bot.is_admin(ctx.author):
            return
        raise commands.UserFeedbackCheckFailure("You need Manage Server permission")

    async def _require_activity_staff(self, ctx: commands.Context) -> None:
        permissions = getattr(ctx.author, "guild_permissions", None)
        has_permission = bool(
            permissions and (permissions.manage_messages or permissions.manage_guild)
        )
        if has_permission or await self.bot.is_admin(ctx.author):
            return
        raise commands.UserFeedbackCheckFailure(
            "You need Manage Messages or Manage Server permission"
        )

    def _prepare_role_expression(
        self, guild: discord.Guild, expression: str
    ) -> tuple[object, str, tuple[int, ...]]:
        try:
            parsed = parse_role_expression(expression)
        except RoleExpressionSyntaxError as error:
            raise commands.UserFeedbackCheckFailure(
                "Invalid role expression"
            ) from error

        for role_id in role_ids(parsed):
            role = guild.get_role(role_id)
            if role is None:
                raise commands.UserFeedbackCheckFailure(
                    "Role expression contains an unknown role"
                )
            if role_id == guild.default_role.id or role.is_default():
                raise commands.UserFeedbackCheckFailure(
                    "The `@everyone` role cannot be used in role expressions"
                )

        predicate_sql, parameters = compile_role_expression(parsed)
        return parsed, predicate_sql, parameters

    async def _count_role_expression(
        self, guild: discord.Guild, expression: str
    ) -> int:
        _, predicate_sql, parameters = self._prepare_role_expression(
            guild, expression
        )
        try:
            return await self._role_analytics_store.count_matching(
                guild.id, predicate_sql, parameters
            )
        except AnalyticsUnavailableError as error:
            raise commands.UserFeedbackCheckFailure(
                "Role analytics are unavailable right now"
            ) from error

    async def _count_highest_role_buckets(
        self, guild: discord.Guild, ordered_role_ids: tuple[int, ...]
    ) -> list[int]:
        counts = []
        for index, role_id in enumerate(ordered_role_ids):
            higher_role_ids = ordered_role_ids[index + 1 :]
            expression = str(role_id)
            if higher_role_ids:
                higher_roles = " OR ".join(
                    str(higher_role_id) for higher_role_id in higher_role_ids
                )
                expression = f"{expression} AND NOT ({higher_roles})"
            counts.append(await self._count_role_expression(guild, expression))
        return counts

    def _require_private_role_export_channel(self, ctx: commands.Context) -> None:
        self._require_private_export_channel(
            ctx,
            export_name="Role export",
            feedback="Role export is unavailable in this channel",
        )

    def _require_private_achievement_export_channel(
        self, ctx: commands.Context
    ) -> None:
        self._require_private_export_channel(
            ctx,
            export_name="Achievement proof export",
            feedback="Achievement proof export is unavailable in this channel",
        )

    def _require_private_export_channel(
        self,
        ctx: commands.Context,
        *,
        export_name: str,
        feedback: str,
    ) -> None:
        if self._channel_is_public(ctx):
            log.info(
                "%s refused in public channel %s for guild %s",
                export_name,
                getattr(ctx.channel, "id", "unknown"),
                ctx.guild.id,
            )
            raise commands.UserFeedbackCheckFailure(feedback)

        missing_permissions: tuple[str, ...]
        if ctx.guild.me is None:
            missing_permissions = ("bot_member",)
        else:
            bot_permissions = ctx.channel.permissions_for(ctx.guild.me)
            missing_permissions = tuple(
                name
                for name in ("view_channel", "send_messages", "attach_files")
                if not bool(getattr(bot_permissions, name, False))
            )
        if missing_permissions:
            log.warning(
                "%s refused in channel %s for guild %s; missing bot permissions: %s",
                export_name,
                getattr(ctx.channel, "id", "unknown"),
                ctx.guild.id,
                ", ".join(missing_permissions),
            )
            raise commands.UserFeedbackCheckFailure(feedback)

    async def _repair_role_analytics_cache(self, guild: discord.Guild) -> None:
        await self._role_analytics_store.set_status(
            guild.id,
            SyncStatus.NEEDS_RECONCILIATION,
            "member_cache_mismatch",
        )
        self._role_analytics.schedule_guild_retry(guild, 0)

    def _parse_role_id(self, value: str) -> int:
        stripped = value.strip()
        if stripped.startswith("<@&") and stripped.endswith(">"):
            stripped = stripped[3:-1]
        if not stripped.isdigit():
            raise commands.UserFeedbackCheckFailure("Pass a role mention or raw Discord role ID")
        return int(stripped)

    def _can_restore_role(self, guild: discord.Guild, role: discord.Role) -> bool:
        me = guild.me
        if me is None:
            return False
        if role.is_default() or role.managed:
            return False
        if not me.guild_permissions.manage_roles:
            return False
        return role < me.top_role

    def _format_role_reference(self, guild: discord.Guild, role_id: int) -> str:
        role = guild.get_role(role_id)
        if role is None:
            return f"`{role_id}` (missing)"
        return f"{role.mention} (`{role_id}`)"

    def _format_role_id_set(self, guild: discord.Guild, role_ids: set[int]) -> str:
        if not role_ids:
            return "none"
        return ", ".join(
            self._format_role_reference(guild, role_id) for role_id in sorted(role_ids)
        )

    def _role_name_for_prompt(self, guild: discord.Guild, role_id: int) -> str | None:
        role = guild.get_role(role_id)
        if role is None:
            return None
        return role.name

    async def _prompt_sticky_role_db_action(
        self,
        *,
        guild: discord.Guild,
        channel: discord.abc.Messageable,
        role_id: int,
        role_name: str | None,
        config_exists: bool,
        saved_rows: int,
        reason: str,
        requester: discord.Member | discord.User | None,
        ping: bool = False,
    ) -> None:
        role_label = f"{role_name} (`{role_id}`)" if role_name else f"`{role_id}`"
        prompt = (
            "Sticky role DB entry needs a decision.\n"
            f"Role: {role_label}\n"
            f"Trigger: {reason}\n"
            f"Configured as sticky: {'yes' if config_exists else 'no'}\n"
            f"Saved user-role rows: {saved_rows}\n"
            "Reply with one of:\n"
            f"`remove {role_id}` - delete this role from sticky DB and saved users\n"
            f"`keep {role_id}` - stop configuring this role as sticky, but keep saved user rows\n"
            f"`change {role_id} <role mention or ID>` - move config and saved users to another role"
        )
        if ping:
            delivered = await self._send_error_notice(
                guild,
                prompt,
                ping=True,
                channel=channel,
                failure_action="prompt deleted sticky role decision",
            )
            if delivered is None:
                log.warning(
                    "Sticky role decision prompt was not delivered for role %s in guild %s",
                    role_id,
                    guild.id,
                )
                return
        else:
            await channel.send(prompt, allowed_mentions=discord.AllowedMentions.none())

        deadline = time.monotonic() + 300
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                await channel.send("Sticky role DB decision timed out. No changes were made.")
                return

            def check(message: discord.Message) -> bool:
                _, target_role_id, _ = _parse_sticky_db_decision(message.content)
                return (
                    message.channel.id == channel.id
                    and not message.author.bot
                    and target_role_id == role_id
                )

            try:
                message = await self.bot.wait_for("message", check=check, timeout=remaining)
            except asyncio.TimeoutError:
                await channel.send("Sticky role DB decision timed out. No changes were made.")
                return

            if not await self._can_answer_sticky_db_prompt(message, guild, requester):
                continue

            command, _, argument = _parse_sticky_db_decision(message.content)
            if command == "remove" and not argument:
                config_removed, rows_removed = await self._sticky_roles.remove_sticky_role(
                    guild.id, role_id
                )
                await channel.send(
                    "Sticky role DB entry removed.\n"
                    f"Config row removed: {'yes' if config_removed else 'no'}\n"
                    f"Saved user-role rows removed: {rows_removed}"
                )
                return
            if command == "keep" and not argument:
                config_removed = await self._sticky_roles.unconfigure_sticky_role(
                    guild.id, role_id
                )
                await channel.send(
                    "Sticky role config removed, saved user-role rows kept.\n"
                    f"Config row removed: {'yes' if config_removed else 'no'}\n"
                    f"Saved user-role rows kept: {saved_rows}"
                )
                return
            if command == "change" and argument:
                await self._handle_sticky_role_db_change(
                    channel, guild, role_id, argument
                )
                return

            await channel.send(
                f"Invalid response. Use `remove {role_id}`, `keep {role_id}`, or "
                f"`change {role_id} <role mention or ID>`."
            )

    async def _can_answer_sticky_db_prompt(
        self,
        message: discord.Message,
        guild: discord.Guild,
        requester: discord.Member | discord.User | None,
    ) -> bool:
        if requester is not None:
            return message.author.id == requester.id

        member = message.author
        if not isinstance(member, discord.Member):
            member = guild.get_member(message.author.id)
        permissions = getattr(member, "guild_permissions", None)
        if permissions and permissions.manage_guild:
            return True
        return await self.bot.is_admin(message.author)

    async def _handle_sticky_role_db_change(
        self,
        channel: discord.abc.Messageable,
        guild: discord.Guild,
        old_role_id: int,
        role_argument: str,
    ) -> None:
        if not role_argument:
            await channel.send("Missing replacement role. No changes were made.")
            return

        try:
            new_role_id = self._parse_role_id(role_argument)
        except commands.UserFeedbackCheckFailure as exc:
            await channel.send(f"{exc} No changes were made")
            return

        if new_role_id == old_role_id:
            await channel.send("Replacement role is the same role ID. No changes were made.")
            return

        new_role = guild.get_role(new_role_id)
        if new_role is None:
            await channel.send("Replacement role does not exist on this server. No changes were made.")
            return
        if not self._can_restore_role(guild, new_role):
            await channel.send(
                "I cannot restore the replacement role. Check Manage Roles and role hierarchy. "
                "No changes were made."
            )
            return

        config_moved, old_rows_removed, new_rows_inserted = await self._sticky_roles.replace_sticky_role(
            guild.id, old_role_id, new_role_id
        )
        await channel.send(
            "Sticky role DB entry changed.\n"
            f"Replacement role: {new_role.mention} (`{new_role.id}`)\n"
            f"Config moved: {'yes' if config_moved else 'no'}\n"
            f"Old saved user-role rows removed: {old_rows_removed}\n"
            f"New saved user-role rows inserted: {new_rows_inserted}",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _send_sticky_debug_log(self, guild: discord.Guild, content: str) -> None:
        config = await self.config.guild(guild).all()
        if not config["sticky_debug_logging_enabled"]:
            return
        log.info("Sticky role debug for guild %s\n%s", guild.id, content)

    async def _send_paginated_text(self, ctx: commands.Context, content: str) -> None:
        page = ""
        for line in content.splitlines():
            candidate = f"{page}\n{line}" if page else line
            if len(candidate) > 1900:
                await ctx.send(page, allowed_mentions=discord.AllowedMentions.none())
                page = line
            else:
                page = candidate
        if page:
            await ctx.send(page, allowed_mentions=discord.AllowedMentions.none())

    async def _send_yapper_ranking(
        self,
        ctx: commands.Context,
        days: int,
        amount: int,
    ) -> None:
        await self._require_activity_staff(ctx)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Days must be at least 1")
        if not 1 <= amount <= 20:
            raise commands.UserFeedbackCheckFailure(
                "Amount must be between 1 and 20"
            )

        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        days = await self._cap_detail_days(ctx.guild, days)
        end_date_utc = self._utc_today()
        counts = await self._activity_store.get_guild_user_counts(
            ctx.guild.id,
            end_date_utc,
            days,
            amount,
        )
        scope = "server"

        if not counts:
            await ctx.send(
                f"No retained activity data for this {scope} in the last {days} days",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return

        lines = [f"Top {len(counts)} yappers in this {scope} - last {days} days:"]
        for rank, count in enumerate(counts, start=1):
            member = ctx.guild.get_member(count.user_id)
            user = (
                f"{member.display_name} ({count.user_id})"
                if member is not None
                else str(count.user_id)
            )
            lines.append(f"{rank}. {user} — {count.message_count:,} messages")
        await self._send_paginated_text(ctx, "\n".join(lines))

    async def _confirm_retention_delete(self, ctx: commands.Context, warning: str) -> bool:
        await ctx.send(warning)

        def check(message: discord.Message) -> bool:
            return (
                message.author.id == ctx.author.id
                and message.channel.id == ctx.channel.id
                and message.content == RETENTION_CONFIRMATION
            )

        try:
            await self.bot.wait_for("message", check=check, timeout=60)
        except asyncio.TimeoutError:
            await ctx.send("Retention change cancelled")
            return False
        return True

    def _utc_today(self) -> date:
        return datetime.now(timezone.utc).date()

    def _history_retention_cutoff(self, days: int) -> date | None:
        if days == -1:
            return None
        if days == 0:
            return self._utc_today() + timedelta(days=1)
        return self._utc_today() - timedelta(days=days)

    async def _cap_detail_days(self, guild: discord.Guild, days: int) -> int:
        config = await self.config.guild(guild).all()
        retention = max(1, int(config["activity_detail_retention_days"]))
        return min(days, retention)

    def _parse_range_days(self, value: str) -> int:
        normalized = value.strip().lower()
        if not normalized.isdigit():
            raise commands.UserFeedbackCheckFailure("Range must be a positive number of days")
        days = int(normalized)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Range must be at least 1 day")
        return days

    def _parse_user_id(self, value: str) -> int:
        stripped = value.strip()
        if stripped.startswith("<@") and stripped.endswith(">"):
            stripped = stripped[2:-1]
            if stripped.startswith("!"):
                stripped = stripped[1:]
        if not stripped.isdigit():
            raise commands.UserFeedbackCheckFailure("Pass a user mention or raw Discord user ID")
        return int(stripped)

    def _resolve_text_channel_or_thread(
        self, guild: discord.Guild, value: str
    ) -> discord.TextChannel | discord.Thread:
        stripped = value.strip()
        if stripped.startswith("<#") and stripped.endswith(">"):
            stripped = stripped[2:-1]
        if not stripped.isdigit():
            raise commands.UserFeedbackCheckFailure("Pass a channel/thread mention or raw channel ID")

        channel_id = int(stripped)
        channel = guild.get_channel_or_thread(channel_id)
        if isinstance(channel, (discord.TextChannel, discord.Thread)):
            return channel
        raise commands.UserFeedbackCheckFailure("Channel or thread was not found in this server")

    def _resolve_chatchart_request(
        self,
        ctx: commands.Context,
        target_or_days: str,
        days_or_amount: int | None,
        amount: int | None,
    ) -> tuple[discord.TextChannel | discord.Thread, int, int]:
        token = str(target_or_days).strip()
        resolved_channel = None
        if token.isdigit() and len(token) >= DISCORD_SNOWFLAKE_MIN_DIGITS:
            resolved_channel = ctx.guild.get_channel_or_thread(int(token))

        is_channel_reference = (
            token.startswith("<#")
            or (token.isdigit() and len(token) >= DISCORD_SNOWFLAKE_MIN_DIGITS)
            or isinstance(resolved_channel, (discord.TextChannel, discord.Thread))
        )
        if is_channel_reference:
            target = self._resolve_text_channel_or_thread(ctx.guild, token)
            if days_or_amount is None:
                raise commands.UserFeedbackCheckFailure(
                    "Days must follow the channel or thread"
                )
            return (
                target,
                days_or_amount,
                amount if amount is not None else DEFAULT_CHATCHART_USER_COUNT,
            )

        if not token.isdigit():
            raise commands.UserFeedbackCheckFailure(
                "Pass a channel/thread mention, raw channel ID, or number of days"
            )
        if amount is not None:
            raise commands.UserFeedbackCheckFailure(
                "Too many arguments for current-channel chatchart"
            )
        return (
            ctx.channel,
            int(token),
            days_or_amount if days_or_amount is not None else DEFAULT_CHATCHART_USER_COUNT,
        )

    def _activity_parent_channel_id(self, channel: object) -> int:
        parent = getattr(channel, "parent", None)
        if isinstance(channel, discord.Thread) and parent is not None:
            return parent.id
        return channel.id

    def _activity_thread_id(self, channel: object) -> int | None:
        if isinstance(channel, discord.Thread):
            return channel.id
        return None

    def _format_channel(self, channel_id: int) -> str:
        return f"<#{channel_id}>"

    def _format_activity_location(
        self, guild: discord.Guild, channel_id: int, thread_id: int | None
    ) -> str:
        if thread_id is None:
            return self._format_channel(channel_id)
        return f"{self._format_channel(channel_id)} / {self._format_channel(thread_id)}"

    def _format_user_reference(self, guild: discord.Guild, user_id: int) -> str:
        member = guild.get_member(user_id)
        if member is not None:
            return f"{member.display_name} ({user_id})"
        return f"<@{user_id}> ({user_id})"

    def _format_int(self, value: int) -> str:
        return f"{value:,}"

    def _format_percent_of_server(self, active_users: int, member_count: int) -> str:
        if member_count <= 0:
            return "n/d"
        return f"{(active_users / member_count) * 100:.1f}%"

    def _format_top_channels(self, top_channels: list[TopChannel]) -> str:
        if not top_channels:
            return "n/d"
        return "\n".join(
            (
                f"{top.rank}. {self._format_channel(top.channel_id)} - "
                f"{self._format_int(top.message_count)} messages"
            )
            for top in top_channels
        )

    def _format_activity_locations(
        self, guild: discord.Guild, locations: list[ActivityLocation], total_messages: int
    ) -> str:
        if not locations:
            return "n/d"
        lines: list[str] = []
        listed_total = 0
        for location in locations:
            listed_total += location.message_count
            percent = (
                (location.message_count / total_messages) * 100.0
                if total_messages
                else 0.0
            )
            lines.append(
                f"{location.rank}. "
                f"{self._format_activity_location(guild, location.channel_id, location.thread_id)} - "
                f"{self._format_int(location.message_count)} ({percent:.1f}%)"
            )
        other_count = total_messages - listed_total
        if other_count > 0:
            percent = (other_count / total_messages) * 100.0 if total_messages else 0.0
            lines.append(f"Other - {self._format_int(other_count)} ({percent:.1f}%)")
        return "\n".join(lines)

    def _build_daily_summary_embed(
        self, summary: DailySummary, title_prefix: str
    ) -> discord.Embed:
        embed = discord.Embed(
            title=f"{title_prefix} activity summary - {summary.date_utc.isoformat()} UTC",
            color=discord.Color.blue(),
        )
        embed.add_field(
            name="Messages",
            value=self._format_int(summary.total_messages),
            inline=True,
        )
        embed.add_field(
            name="Active users",
            value=(
                f"{self._format_int(summary.active_users)} "
                f"({self._format_percent_of_server(summary.active_users, summary.member_count_at_close)})"
            ),
            inline=True,
        )
        embed.add_field(
            name="Thresholds",
            value=(
                f"10+: {self._format_int(summary.users_10_plus)}\n"
                f"50+: {self._format_int(summary.users_50_plus)}\n"
                f"100+: {self._format_int(summary.users_100_plus)}"
            ),
            inline=True,
        )
        peak_hour = self._format_peak_hour(summary)
        embed.add_field(
            name="Channels",
            value=(
                f"Active: {self._format_int(summary.channels_with_activity)}\n"
                f"Peak hour: {peak_hour}\n"
                f"Avg/user: {summary.messages_per_active_user:.1f}"
            ),
            inline=False,
        )
        embed.add_field(
            name="Top channels",
            value=self._format_top_channels(summary.top_channels),
            inline=False,
        )
        embed.add_field(
            name="Emoji of the Day",
            value=(summary.emoji_of_day.mention if summary.emoji_of_day is not None
                   else "No recorded usage"),
            inline=False,
        )
        return embed

    def _format_peak_hour(self, summary: DailySummary) -> str:
        if summary.peak_hour_utc is None:
            return "n/d"
        peak_time = datetime(
            summary.date_utc.year,
            summary.date_utc.month,
            summary.date_utc.day,
            summary.peak_hour_utc,
            tzinfo=timezone.utc,
        )
        return f"<t:{int(peak_time.timestamp())}:t>"

    def _build_timeline_embed(
        self, timeline: list[TimelineDay], top_channels: list[TopChannel], days: int
    ) -> discord.Embed:
        include_percent = days <= 7
        header = "Date       Msgs  Users  %Srv  10+ 50+ 100+" if include_percent else "Date       Msgs  Users  10+ 50+ 100+"
        lines = [header]
        summaries: list[DailySummary] = []
        for day in timeline:
            summary = day.summary
            if summary is None:
                if include_percent:
                    lines.append(f"{day.date_utc.isoformat()} n/d   n/d    n/d   n/d n/d n/d")
                else:
                    lines.append(f"{day.date_utc.isoformat()} n/d   n/d    n/d n/d n/d")
                continue
            summaries.append(summary)
            if include_percent:
                lines.append(
                    f"{day.date_utc.isoformat()} "
                    f"{summary.total_messages:<5} {summary.active_users:<6} "
                    f"{self._format_percent_of_server(summary.active_users, summary.member_count_at_close):<5} "
                    f"{summary.users_10_plus:<3} {summary.users_50_plus:<3} {summary.users_100_plus:<4}"
                )
            else:
                lines.append(
                    f"{day.date_utc.isoformat()} "
                    f"{summary.total_messages:<5} {summary.active_users:<6} "
                    f"{summary.users_10_plus:<3} {summary.users_50_plus:<3} {summary.users_100_plus:<4}"
                )

        table = "\n".join(lines)
        if len(table) > 3900:
            visible_lines = lines[:120]
            visible_lines.append("...")
            table = "\n".join(visible_lines)

        embed = discord.Embed(
            title=f"Activity timeline - last {days} closed days",
            color=discord.Color.blue(),
            description=f"```text\n{table}\n```",
        )
        if summaries:
            avg_messages = sum(summary.total_messages for summary in summaries) / len(summaries)
            avg_users = sum(summary.active_users for summary in summaries) / len(summaries)
            best = max(summaries, key=lambda summary: summary.total_messages)
            embed.add_field(
                name="Range",
                value=(
                    f"Avg/day: {avg_messages:.0f} msgs\n"
                    f"Avg active users: {avg_users:.0f}\n"
                    f"Best day: {best.date_utc.isoformat()} "
                    f"({self._format_int(best.total_messages)} msgs)"
                ),
                inline=False,
            )
        else:
            embed.add_field(name="Range", value="n/d", inline=False)
        embed.add_field(
            name="Top channels in range",
            value=self._format_top_channels(top_channels),
            inline=False,
        )
        return embed

    def _build_channel_timeline_embed(
        self, channel: discord.TextChannel, timeline: list[ChannelTimelineDay], days: int
    ) -> discord.Embed:
        lines = ["Date       Msgs"]
        numeric_counts: list[int] = []
        for day in timeline:
            if day.message_count is None:
                value = "n/d"
            else:
                numeric_counts.append(day.message_count)
                value = str(day.message_count)
            lines.append(f"{day.date_utc.isoformat()} {value}")

        table = "\n".join(lines)
        if len(table) > 3900:
            visible_lines = lines[:120]
            visible_lines.append("...")
            table = "\n".join(visible_lines)

        embed = discord.Embed(
            title=f"Channel activity - {channel.name} - last {days} days",
            color=discord.Color.blue(),
            description=f"```text\n{table}\n```",
        )
        if numeric_counts:
            total = sum(numeric_counts)
            active_days = sum(1 for value in numeric_counts if value > 0)
            embed.add_field(name="Total messages", value=self._format_int(total), inline=True)
            embed.add_field(name="Active days", value=self._format_int(active_days), inline=True)
            embed.add_field(
                name="Average per active day",
                value=f"{(total / active_days) if active_days else 0.0:.1f}",
                inline=True,
            )
        else:
            embed.add_field(name="Total messages", value="n/d", inline=True)
        return embed

    def _build_activity_consistency_embed(
        self, report: ActivityConsistencyReport, day: date
    ) -> discord.Embed:
        ok = report.user_day_mismatches == 0 and report.channel_day_mismatches == 0
        embed = discord.Embed(
            title=f"Activity consistency - {day.isoformat()} UTC",
            color=discord.Color.green() if ok else discord.Color.red(),
        )
        embed.add_field(
            name="Canonical rows",
            value=self._format_int(report.canonical_rows),
            inline=True,
        )
        embed.add_field(
            name="Canonical messages",
            value=self._format_int(report.canonical_messages),
            inline=True,
        )
        embed.add_field(
            name="User cache mismatches",
            value=self._format_int(report.user_day_mismatches),
            inline=True,
        )
        embed.add_field(
            name="Channel cache mismatches",
            value=self._format_int(report.channel_day_mismatches),
            inline=True,
        )
        embed.add_field(name="Status", value="OK" if ok else "Mismatch detected", inline=False)
        return embed

    def _build_activity_database_stats_embed(
        self, stats: ActivityDatabaseStats
    ) -> discord.Embed:
        file_mib = stats.file_size_bytes / 1024 / 1024
        sqlite_mib = stats.sqlite_size_bytes / 1024 / 1024
        lines = [f"{name} {self._format_int(count)}" for name, count in stats.table_rows]
        table = "\n".join(lines)
        if len(table) > 1000:
            table = "\n".join(lines[:18] + ["..."])

        embed = discord.Embed(title="Activity database size", color=discord.Color.blue())
        embed.add_field(
            name="File size",
            value=f"{self._format_int(stats.file_size_bytes)} bytes ({file_mib:.2f} MiB)",
            inline=False,
        )
        embed.add_field(
            name="SQLite pages",
            value=(
                f"{self._format_int(stats.page_count)} pages x "
                f"{self._format_int(stats.page_size)} bytes = {sqlite_mib:.2f} MiB"
            ),
            inline=False,
        )
        embed.add_field(name="Rows", value=f"```text\n{table}\n```", inline=False)
        embed.set_footer(text=stats.path)
        return embed

    def _build_user_stats_embed(self, title: str, stats: UserStats, days: int) -> discord.Embed:
        embed = discord.Embed(title=title, color=discord.Color.blue())
        embed.add_field(name="Range", value=f"last {days} days", inline=True)
        embed.add_field(name="Total messages", value=self._format_int(stats.total_messages), inline=True)
        embed.add_field(name="Active days", value=self._format_int(stats.active_days), inline=True)
        embed.add_field(
            name="Average per active day",
            value=f"{stats.average_per_active_day:.1f}",
            inline=True,
        )
        embed.add_field(
            name="Top channels",
            value=self._format_top_channels(stats.top_channels),
            inline=False,
        )
        embed.add_field(
            name="Daily breakdown",
            value=f"```text\n{self._format_daily_rows(stats.date_rows)}\n```",
            inline=False,
        )
        return embed

    def _build_user_channel_stats_embed(
        self, title: str, stats: UserStats, days: int
    ) -> discord.Embed:
        embed = discord.Embed(title=title, color=discord.Color.blue())
        embed.add_field(name="Range", value=f"last {days} days", inline=True)
        embed.add_field(name="Total messages", value=self._format_int(stats.total_messages), inline=True)
        embed.add_field(name="Active days", value=self._format_int(stats.active_days), inline=True)
        embed.add_field(
            name="Average per active day",
            value=f"{stats.average_per_active_day:.1f}",
            inline=True,
        )
        embed.add_field(
            name="Daily breakdown",
            value=f"```text\n{self._format_daily_rows(stats.date_rows)}\n```",
            inline=False,
        )
        return embed

    def _build_user_channel_distribution_embed(
        self,
        guild: discord.Guild,
        title: str,
        distribution: UserChannelDistribution,
        days: int,
    ) -> discord.Embed:
        embed = discord.Embed(title=title, color=discord.Color.blue())
        embed.add_field(name="Range", value=f"last {days} days", inline=True)
        embed.add_field(
            name="Total messages",
            value=self._format_int(distribution.total_messages),
            inline=True,
        )
        embed.add_field(
            name="Active days",
            value=self._format_int(distribution.active_days),
            inline=True,
        )
        embed.add_field(
            name="Locations used",
            value=self._format_int(distribution.locations_used),
            inline=True,
        )
        top_location = distribution.top_locations[0] if distribution.top_locations else None
        embed.add_field(
            name="Top location",
            value=(
                self._format_activity_location(guild, top_location.channel_id, top_location.thread_id)
                if top_location
                else "n/d"
            ),
            inline=True,
        )
        embed.add_field(
            name="Top locations in range",
            value=self._format_activity_locations(
                guild, distribution.top_locations, distribution.total_messages
            ),
            inline=False,
        )
        embed.add_field(
            name="Daily dominant location",
            value=self._format_daily_dominant_location_rows(guild, distribution.date_rows),
            inline=False,
        )
        return embed

    def _build_selfchart_embed(
        self, member: discord.Member | discord.User, stats: UserStats, days: int
    ) -> discord.Embed:
        embed = discord.Embed(
            title=f"Your activity - last {days} days",
            color=discord.Color.blue(),
        )
        embed.add_field(name="Total messages", value=self._format_int(stats.total_messages), inline=True)
        top_channel = stats.top_channels[0] if stats.top_channels else None
        embed.add_field(
            name="Top channel",
            value=(
                f"{self._format_channel(top_channel.channel_id)} - "
                f"{self._format_int(top_channel.message_count)} messages"
                if top_channel
                else "n/d"
            ),
            inline=True,
        )
        embed.add_field(
            name="Daily messages",
            value=f"```text\n{self._format_daily_rows(stats.date_rows)}\n```",
            inline=False,
        )
        return embed

    def _format_daily_rows(self, rows: list[tuple[date, int | None]]) -> str:
        lines = ["Date       Msgs"]
        for day, count in rows:
            value = "n/d" if count is None else str(count)
            lines.append(f"{day.isoformat()} {value}")
        return "\n".join(lines)

    def _format_daily_dominant_location_rows(
        self, guild: discord.Guild, rows: list[DailyDominantLocation]
    ) -> str:
        lines: list[str] = []
        for row in rows:
            if row.total_messages is None:
                lines.append(f"{row.date_utc.isoformat()}: n/d")
            elif row.total_messages == 0:
                lines.append(f"{row.date_utc.isoformat()}: 0")
            elif row.channel_id is not None and row.location_messages is not None:
                percent = (row.location_messages / row.total_messages) * 100.0
                lines.append(
                    f"{row.date_utc.isoformat()}: "
                    f"{self._format_int(row.total_messages)} msgs, "
                    f"{self._format_activity_location(guild, row.channel_id, row.thread_id)} "
                    f"{self._format_int(row.location_messages)} ({percent:.1f}%)"
                )
            else:
                lines.append(f"{row.date_utc.isoformat()}: {self._format_int(row.total_messages)} msgs")
        return self._join_limited_lines(lines)

    def _join_limited_lines(self, lines: list[str], limit: int = 1000) -> str:
        output: list[str] = []
        current_length = 0
        for line in lines:
            extra_length = len(line) + (1 if output else 0)
            if current_length + extra_length > limit:
                output.append("...")
                break
            output.append(line)
            current_length += extra_length
        return "\n".join(output) if output else "n/d"

    def _chatchart_location_label(self, channel: object) -> str:
        """Name the charted channel or thread for display inside the image."""
        name = getattr(channel, "name", None) or "unknown-channel"
        if self._activity_thread_id(channel) is None:
            return f"#{name}"
        parent_name = getattr(getattr(channel, "parent", None), "name", None)
        return f"#{parent_name} / {name}" if parent_name else name

    def _build_chatchart_file(
        self,
        guild: discord.Guild,
        counts: list[ChannelUserCount],
        days: int,
        location_label: str,
        amount: int,
    ) -> discord.File:
        top_counts = counts[:amount]
        other_count = sum(count.message_count for count in counts[len(top_counts):])
        rows: list[tuple[str, int]] = []
        for count in top_counts:
            member = guild.get_member(count.user_id)
            name = member.display_name if member is not None else str(count.user_id)
            rows.append((name, count.message_count))
        try:
            return render_ranked_donut_chart(
                rows,
                other_count=other_count,
                title=f"Messages by user - last {days} days",
                context_label=location_label,
                center_unit="messages",
                donut_title="Share by user",
                filename="chatchart.png",
            )
        except ImportError as exc:
            raise commands.UserFeedbackCheckFailure(
                "Matplotlib is required for chatchart but is not installed"
            ) from exc
