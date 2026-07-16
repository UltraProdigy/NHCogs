"""Discord-independent domain vocabulary for detection cases."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from collections.abc import Callable, Mapping
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from types import MappingProxyType
from uuid import uuid4


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    return value


class CaseStatus(str, Enum):
    PENDING = "pending"
    RESOLVING = "resolving"
    RESOLVED = "resolved"
    EXPIRED = "expired"


class ActionIntent(str, Enum):
    NONE = "none"
    REVIEW = "review"
    KICK = "kick"
    BAN = "ban"


class DeleteStatus(str, Enum):
    PENDING = "pending"
    PLANNED = "planned"
    DELETED = "deleted"
    ALREADY_GONE = "already_gone"
    FORBIDDEN = "forbidden"
    TRANSIENT_FAILURE = "transient_failure"


class OperationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ABANDONED = "abandoned"


@dataclass(frozen=True)
class AttachmentKey:
    case_id: str
    message_sequence: int
    position: int


@dataclass(frozen=True)
class DetectionSignal:
    detector: str
    reason: str
    action: ActionIntent
    decisive: bool
    metadata: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze(self.metadata))


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    guild_id: int
    user_id: int
    status: CaseStatus
    created_at: datetime
    expires_at: datetime
    resolution: str | None
    moderator_id: int | None
    resolved_at: datetime | None
    review_channel_id: int | None
    review_message_id: int | None
    resolving_since: datetime | None
    needs_attention: bool


@dataclass(frozen=True)
class ResolutionLease:
    case_id: str
    token: str
    claimed_at: datetime


@dataclass(frozen=True)
class EvidenceReservation:
    key: AttachmentKey
    status: str
    claim_token: str | None
    reserved_bytes: int
    error: str | None


@dataclass(frozen=True)
class MessageRecord:
    case_id: str
    sequence: int
    guild_id: int
    channel_id: int
    message_id: int
    content: str
    created_at: datetime
    jump_url: str | None
    admitted_by: str
    capture_status: str
    delete_status: DeleteStatus
    error: str | None


@dataclass(frozen=True)
class AttachmentRecord:
    key: AttachmentKey
    filename: str
    size: int
    content_type: str | None
    width: int | None
    height: int | None
    source_url: str
    evidence_path: str | None
    capture_status: str
    sha256: str | None
    perceptual_hash: str | None
    match_metadata: Mapping[str, object]
    learning_decision: str | None
    learning_metadata: Mapping[str, object]
    error: str | None
    publication_error: str | None = None
    description: str | None = None
    spoiler: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "match_metadata", _freeze(self.match_metadata))
        object.__setattr__(self, "learning_metadata", _freeze(self.learning_metadata))

    @property
    def case_id(self) -> str:
        return self.key.case_id

    @property
    def message_sequence(self) -> int:
        return self.key.message_sequence

    @property
    def position(self) -> int:
        return self.key.position


@dataclass(frozen=True)
class OperationRecord:
    operation_id: str
    case_id: str
    message_sequence: int | None
    operation_type: str
    status: OperationStatus
    attempts: int
    created_at: datetime
    updated_at: datetime
    retry_at: datetime | None
    last_error: str | None
    result: str | None
    actor_id: int | None
    idempotency_key: str
    claim_token: str | None
    claimed_at: datetime | None


@dataclass(frozen=True)
class OperationalFailureRecord:
    failure_id: str
    guild_id: int
    source: str
    summary: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrences: int
    case_id: str | None
    operation_id: str | None
    resolved_at: datetime | None
    acknowledged_at: datetime | None


@dataclass(frozen=True)
class EvidencePublicationRecord:
    case_id: str
    batch_index: int
    channel_id: int
    message_id: int
    attachment_keys: tuple[AttachmentKey, ...]


@dataclass(frozen=True)
class ProjectionEndpointRecord:
    case_id: str
    generation: int
    parent_channel_id: int | None
    summary_message_id: int | None
    thread_id: int | None
    state: str
    projected_revision: int
    last_verified_at: datetime | None
    last_error: str | None


@dataclass(frozen=True)
class TimelinePublicationRecord:
    logical_key: str
    case_id: str
    kind: str
    message_sequence: int
    chunk_index: int
    state: str
    revision: int
    channel_id: int | None
    message_id: int | None
    last_error: str | None
    claim_token: str | None
    claimed_at: datetime | None


@dataclass(frozen=True)
class CaseDeletionJob:
    case_id: str
    guild_id: int
    parent_channel_id: int | None
    summary_message_id: int | None
    thread_id: int | None
    legacy_publications: tuple[tuple[int, int], ...]
    remote_deleted: bool
    local_deleted: bool
    rows_deleted: bool
    attempts: int
    last_error: str | None


@dataclass(frozen=True)
class NewAttachment:
    position: int
    filename: str
    size: int
    content_type: str | None
    width: int | None
    height: int | None
    url: str
    description: str | None = None
    spoiler: bool = False


@dataclass(frozen=True)
class NewMessage:
    guild_id: int
    user_id: int
    channel_id: int
    message_id: int
    content: str
    created_at: datetime
    jump_url: str | None
    attachments: tuple[NewAttachment, ...]
    display_name: str | None = None
    avatar_url: str | None = None
    account_created_at: datetime | None = None
    guild_joined_at: datetime | None = None


@dataclass(frozen=True)
class CaseSubjectRecord:
    case_id: str
    display_name: str | None
    avatar_url: str | None
    account_created_at: datetime | None
    guild_joined_at: datetime | None


@dataclass(frozen=True)
class SignalRecord:
    case_id: str
    message_sequence: int
    signal: DetectionSignal


@dataclass(frozen=True)
class AppendResult:
    case: CaseRecord
    message: MessageRecord
    case_created: bool
    message_created: bool
    firstpost_claimed: bool = False


@dataclass(frozen=True)
class CaseSnapshot:
    case: CaseRecord
    messages: tuple[MessageRecord, ...]
    attachments: tuple[AttachmentRecord, ...]
    signals: tuple[SignalRecord, ...]
    operations: tuple[OperationRecord, ...]
    publications: tuple[EvidencePublicationRecord, ...] = ()
    subject: CaseSubjectRecord | None = None


ACTION_PRIORITY = MappingProxyType({
    ActionIntent.NONE: 0,
    ActionIntent.REVIEW: 1,
    ActionIntent.KICK: 2,
    ActionIntent.BAN: 3,
})


def effective_action(signals: tuple[DetectionSignal, ...]) -> ActionIntent:
    return max(
        (signal.action for signal in signals),
        key=ACTION_PRIORITY.__getitem__,
        default=ActionIntent.NONE,
    )


def new_case_expiry(created_at: datetime) -> datetime:
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("created_at must be timezone-aware")
    return created_at.astimezone(timezone.utc) + timedelta(hours=24)


def _to_timestamp(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    delta = value.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (
        delta.days * 86_400 * 1_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )


def _from_timestamp(value: int | None) -> datetime | None:
    if value is None:
        return None
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value)


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_json_value(item) for item in value), key=repr)
    return value


class DetectionCaseStore:
    """SQLite repository for atomic detection-case admission."""

    def __init__(
        self,
        database_path: str | Path,
        connection_factory: Callable[..., sqlite3.Connection] = sqlite3.connect,
    ):
        self.database_path = str(database_path)
        self.connection_factory = connection_factory

    def _connect(self) -> sqlite3.Connection:
        connection = self.connection_factory(self.database_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS detection_cases (
                    case_id TEXT PRIMARY KEY,
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    resolution TEXT,
                    moderator_id INTEGER,
                    resolved_at INTEGER,
                    review_channel_id INTEGER,
                    review_message_id INTEGER,
                    resolving_since INTEGER,
                    resolving_token TEXT,
                    needs_attention INTEGER NOT NULL DEFAULT 0
                );
                DROP INDEX IF EXISTS one_pending_case_per_user;
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_case_per_user
                    ON detection_cases(guild_id, user_id)
                    WHERE status IN ('pending', 'resolving');

                CREATE TABLE IF NOT EXISTS detection_case_subjects (
                    case_id TEXT PRIMARY KEY,
                    display_name TEXT,
                    avatar_url TEXT,
                    account_created_at INTEGER,
                    guild_joined_at INTEGER,
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS detection_messages (
                    case_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    guild_id INTEGER NOT NULL,
                    channel_id INTEGER NOT NULL,
                    message_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    jump_url TEXT,
                    admitted_by TEXT NOT NULL,
                    capture_status TEXT NOT NULL,
                    delete_status TEXT NOT NULL,
                    error TEXT,
                    UNIQUE(guild_id, message_id),
                    UNIQUE(case_id, sequence),
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS detection_signals (
                    case_id TEXT NOT NULL,
                    message_sequence INTEGER NOT NULL,
                    position INTEGER NOT NULL,
                    detector TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decisive INTEGER NOT NULL,
                    metadata TEXT NOT NULL,
                    PRIMARY KEY(case_id, message_sequence, position),
                    FOREIGN KEY(case_id, message_sequence)
                        REFERENCES detection_messages(case_id, sequence) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS firstpost_claims (
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    case_id TEXT NOT NULL,
                    message_sequence INTEGER NOT NULL,
                    claimed_at INTEGER NOT NULL,
                    PRIMARY KEY(guild_id, user_id),
                    FOREIGN KEY(case_id, message_sequence)
                        REFERENCES detection_messages(case_id, sequence) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS detection_attachments (
                    case_id TEXT NOT NULL,
                    message_sequence INTEGER NOT NULL,
                    position INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content_type TEXT,
                    width INTEGER,
                    height INTEGER,
                    source_url TEXT NOT NULL,
                    evidence_path TEXT,
                    capture_status TEXT NOT NULL,
                    sha256 TEXT,
                    perceptual_hash TEXT,
                    match_metadata TEXT NOT NULL,
                    learning_decision TEXT,
                    learning_metadata TEXT NOT NULL,
                    error TEXT,
                    publication_error TEXT,
                    description TEXT,
                    spoiler INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(case_id, message_sequence, position),
                    FOREIGN KEY(case_id, message_sequence)
                        REFERENCES detection_messages(case_id, sequence) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS detection_operations (
                    operation_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    message_sequence INTEGER,
                    operation_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    retry_at INTEGER,
                    last_error TEXT,
                    result TEXT,
                    actor_id INTEGER,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    claim_token TEXT,
                    claimed_at INTEGER,
                    effect_started_at INTEGER,
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE,
                    FOREIGN KEY(case_id, message_sequence)
                        REFERENCES detection_messages(case_id, sequence) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS operational_failures (
                    failure_id TEXT PRIMARY KEY,
                    guild_id INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    first_seen_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    case_id TEXT,
                    operation_id TEXT,
                    resolved_at INTEGER,
                    acknowledged_at INTEGER
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_operational_failure
                    ON operational_failures(guild_id, source, COALESCE(operation_id, ''),
                                            COALESCE(case_id, ''))
                    WHERE resolved_at IS NULL;
                CREATE INDEX IF NOT EXISTS operational_failures_visible
                    ON operational_failures(guild_id, acknowledged_at, resolved_at, last_seen_at);

                CREATE TABLE IF NOT EXISTS detection_evidence_reservations (
                    case_id TEXT NOT NULL,
                    message_sequence INTEGER NOT NULL,
                    position INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    claim_token TEXT,
                    reserved_bytes INTEGER NOT NULL,
                    actual_bytes INTEGER,
                    claimed_at INTEGER,
                    PRIMARY KEY(case_id, message_sequence, position),
                    FOREIGN KEY(case_id, message_sequence, position)
                        REFERENCES detection_attachments(case_id, message_sequence, position)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS detection_role_ownership (
                    case_id TEXT NOT NULL,
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    role_id INTEGER NOT NULL,
                    applied_at INTEGER NOT NULL,
                    PRIMARY KEY(case_id, role_id),
                    UNIQUE(guild_id, user_id, role_id),
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS detection_evidence_publications (
                    case_id TEXT NOT NULL,
                    batch_index INTEGER NOT NULL,
                    channel_id INTEGER NOT NULL,
                    message_id INTEGER NOT NULL,
                    attachment_keys TEXT NOT NULL,
                    PRIMARY KEY(case_id, batch_index),
                    UNIQUE(channel_id, message_id),
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS detection_projection_endpoints (
                    case_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL DEFAULT 1,
                    parent_channel_id INTEGER,
                    summary_message_id INTEGER,
                    thread_id INTEGER,
                    state TEXT NOT NULL DEFAULT 'unpublished',
                    projected_revision INTEGER NOT NULL DEFAULT 0,
                    last_verified_at INTEGER,
                    last_error TEXT,
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS detection_timeline_publications (
                    logical_key TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    message_sequence INTEGER NOT NULL DEFAULT 0,
                    chunk_index INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL DEFAULT 'pending',
                    revision INTEGER NOT NULL DEFAULT 0,
                    channel_id INTEGER,
                    message_id INTEGER,
                    last_error TEXT,
                    claim_token TEXT,
                    claimed_at INTEGER,
                    UNIQUE(case_id, kind, message_sequence, chunk_index),
                    UNIQUE(channel_id, message_id),
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS detection_timeline_by_case
                    ON detection_timeline_publications(
                        case_id, message_sequence, kind, chunk_index, logical_key
                    );

                CREATE TABLE IF NOT EXISTS detection_publication_claims (
                    case_id TEXT NOT NULL,
                    slot TEXT NOT NULL,
                    claim_token TEXT NOT NULL,
                    claimed_at INTEGER NOT NULL,
                    PRIMARY KEY(case_id, slot),
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS detection_case_deletions (
                    case_id TEXT PRIMARY KEY,
                    guild_id INTEGER NOT NULL,
                    scope_kind TEXT NOT NULL,
                    scope_id INTEGER NOT NULL,
                    requested_at INTEGER NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS detection_case_deletions_by_scope
                    ON detection_case_deletions(scope_kind, scope_id, guild_id, case_id);

                CREATE TABLE IF NOT EXISTS detection_case_deletion_jobs (
                    case_id TEXT PRIMARY KEY,
                    guild_id INTEGER NOT NULL,
                    parent_channel_id INTEGER,
                    summary_message_id INTEGER,
                    thread_id INTEGER,
                    legacy_publications TEXT NOT NULL DEFAULT '[]',
                    remote_deleted INTEGER NOT NULL DEFAULT 0,
                    local_deleted INTEGER NOT NULL DEFAULT 0,
                    rows_deleted INTEGER NOT NULL DEFAULT 0,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    requested_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS detection_case_deletion_jobs_due
                    ON detection_case_deletion_jobs(
                        remote_deleted, local_deleted, rows_deleted,
                        requested_at, guild_id, case_id
                    );

                CREATE TABLE IF NOT EXISTS detection_orphan_publications (
                    case_id TEXT NOT NULL,
                    channel_id INTEGER NOT NULL,
                    message_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(case_id, channel_id, message_id),
                    FOREIGN KEY(case_id) REFERENCES detection_cases(case_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS detection_orphan_publications_due
                    ON detection_orphan_publications(created_at, case_id);
                """
            )
            attachment_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(detection_attachments)")
            }
            if "description" not in attachment_columns:
                connection.execute(
                    "ALTER TABLE detection_attachments ADD COLUMN description TEXT"
                )
            if "spoiler" not in attachment_columns:
                connection.execute(
                    """ALTER TABLE detection_attachments
                       ADD COLUMN spoiler INTEGER NOT NULL DEFAULT 0"""
                )

    @staticmethod
    def _timeline_logical_key(
        case_id: str,
        kind: str,
        message_sequence: int,
        chunk_index: int,
    ) -> str:
        if not kind:
            raise ValueError("timeline publication kind must not be empty")
        if message_sequence < 0 or chunk_index < 0:
            raise ValueError("timeline publication positions must be non-negative")
        key = f"case:{case_id}:{kind}"
        if message_sequence:
            key += f":{message_sequence}"
        if chunk_index:
            key += f":{chunk_index}"
        return key

    def ensure_projection_endpoint(self, case_id: str) -> ProjectionEndpointRecord:
        with closing(self._connect()) as connection, connection:
            if connection.execute(
                "SELECT 1 FROM detection_case_deletions WHERE case_id = ?",
                (case_id,),
            ).fetchone() is not None:
                raise KeyError(case_id)
            connection.execute(
                """INSERT OR IGNORE INTO detection_projection_endpoints(case_id)
                   VALUES (?)""",
                (case_id,),
            )
            row = connection.execute(
                "SELECT * FROM detection_projection_endpoints WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            raise KeyError(case_id)
        return self._projection_endpoint_from_row(row)


    def activate_projection_endpoint(
        self,
        case_id: str,
        *,
        parent_channel_id: int,
        summary_message_id: int,
        thread_id: int,
        projected_revision: int,
        verified_at: datetime,
    ) -> ProjectionEndpointRecord:
        self.ensure_projection_endpoint(case_id)
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """UPDATE detection_projection_endpoints
                   SET parent_channel_id = ?, summary_message_id = ?, thread_id = ?,
                       state = 'active', projected_revision = ?, last_verified_at = ?,
                       last_error = NULL
                   WHERE case_id = ?
                     AND NOT EXISTS (
                         SELECT 1 FROM detection_case_deletions deletion
                         WHERE deletion.case_id = detection_projection_endpoints.case_id
                     )""",
                (
                    parent_channel_id,
                    summary_message_id,
                    thread_id,
                    projected_revision,
                    _to_timestamp(verified_at),
                    case_id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(case_id)
            row = connection.execute(
                "SELECT * FROM detection_projection_endpoints WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        return self._projection_endpoint_from_row(row)

    def ensure_timeline_publication(
        self,
        case_id: str,
        *,
        kind: str,
        message_sequence: int = 0,
        chunk_index: int = 0,
    ) -> TimelinePublicationRecord:
        logical_key = self._timeline_logical_key(
            case_id, kind, message_sequence, chunk_index
        )
        with closing(self._connect()) as connection, connection:
            if connection.execute(
                "SELECT 1 FROM detection_case_deletions WHERE case_id = ?",
                (case_id,),
            ).fetchone() is not None:
                raise KeyError(logical_key)
            connection.execute(
                """INSERT OR IGNORE INTO detection_timeline_publications
                   (logical_key, case_id, kind, message_sequence, chunk_index)
                   VALUES (?, ?, ?, ?, ?)""",
                (logical_key, case_id, kind, message_sequence, chunk_index),
            )
            row = connection.execute(
                "SELECT * FROM detection_timeline_publications WHERE logical_key = ?",
                (logical_key,),
            ).fetchone()
        if row is None:
            raise KeyError(logical_key)
        return self._timeline_publication_from_row(row)

    def complete_timeline_publication(
        self,
        logical_key: str,
        claim_token: str,
        *,
        channel_id: int,
        message_id: int,
        revision: int,
    ) -> TimelinePublicationRecord:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """UPDATE detection_timeline_publications
                   SET state = 'published', revision = ?, channel_id = ?, message_id = ?,
                       last_error = NULL, claim_token = NULL, claimed_at = NULL
                   WHERE logical_key = ?
                     AND claim_token = ?
                     AND NOT EXISTS (
                         SELECT 1 FROM detection_case_deletions deletion
                         WHERE deletion.case_id = detection_timeline_publications.case_id
                     )""",
                (revision, channel_id, message_id, logical_key, claim_token),
            )
            if cursor.rowcount != 1:
                raise KeyError(logical_key)
            row = connection.execute(
                "SELECT * FROM detection_timeline_publications WHERE logical_key = ?",
                (logical_key,),
            ).fetchone()
        return self._timeline_publication_from_row(row)

    def claim_timeline_publication(
        self,
        logical_key: str,
        now: datetime,
        *,
        replace_message_id: int | None = None,
    ) -> TimelinePublicationRecord | None:
        token = str(uuid4())
        stale_before = _to_timestamp(now - timedelta(minutes=5))
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT publication.*,
                          EXISTS(
                              SELECT 1 FROM detection_case_deletions deletion
                              WHERE deletion.case_id = publication.case_id
                          ) AS deleting
                   FROM detection_timeline_publications publication
                   WHERE publication.logical_key = ?""",
                (logical_key,),
            ).fetchone()
            if row is None or row["deleting"]:
                raise KeyError(logical_key)
            if row["state"] == "published" and (
                replace_message_id is None
                or row["message_id"] != replace_message_id
            ):
                return None
            cursor = connection.execute(
                """UPDATE detection_timeline_publications
                   SET state = 'pending', claim_token = ?, claimed_at = ?
                   WHERE logical_key = ?
                     AND (claim_token IS NULL OR claimed_at <= ?)
                     AND (
                         state = 'pending' OR
                         (state = 'published' AND message_id = ?)
                     )""",
                (
                    token,
                    _to_timestamp(now),
                    logical_key,
                    stale_before,
                    replace_message_id,
                ),
            )
            if cursor.rowcount != 1:
                return None
            claimed = connection.execute(
                "SELECT * FROM detection_timeline_publications WHERE logical_key = ?",
                (logical_key,),
            ).fetchone()
        return self._timeline_publication_from_row(claimed)

    def release_timeline_publication_claim(
        self, logical_key: str, claim_token: str
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """UPDATE detection_timeline_publications
                   SET claim_token = NULL, claimed_at = NULL
                   WHERE logical_key = ? AND claim_token = ?""",
                (logical_key, claim_token),
            )
            return cursor.rowcount == 1

    def list_timeline_publications(
        self, case_id: str
    ) -> tuple[TimelinePublicationRecord, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """SELECT * FROM detection_timeline_publications
                   WHERE case_id = ?
                   ORDER BY message_sequence, kind, chunk_index, logical_key""",
                (case_id,),
            ).fetchall()
        return tuple(self._timeline_publication_from_row(row) for row in rows)

    def verify_read_write(self) -> None:
        """Raise when the case database cannot complete a disposable write/read cycle."""
        self.initialize()
        probe_case_id = f"healthcheck:{uuid4()}"
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                connection.execute(
                    """INSERT INTO main.detection_cases
                       (case_id, guild_id, user_id, status, created_at, expires_at,
                        needs_attention)
                       VALUES (?, 0, 0, 'resolved', 0, 0, 0)""",
                    (probe_case_id,),
                )
                row = connection.execute(
                    "SELECT case_id FROM main.detection_cases WHERE case_id = ?",
                    (probe_case_id,),
                ).fetchone()
                if row is None or row[0] != probe_case_id:
                    raise sqlite3.DatabaseError(
                        "detection case database healthcheck failed"
                    )
            finally:
                connection.rollback()

    def append_message(
        self,
        new_message: NewMessage,
        signals: tuple[DetectionSignal, ...],
        initial_operations: tuple[tuple[str, str], ...]
        | Callable[[tuple[DetectionSignal, ...]], tuple[tuple[str, str], ...]] = (),
        *,
        claim_firstpost: bool = False,
    ) -> AppendResult | None:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            while True:
                existing = connection.execute(
                    "SELECT * FROM detection_messages WHERE guild_id = ? AND message_id = ?",
                    (new_message.guild_id, new_message.message_id),
                ).fetchone()
                if existing is not None:
                    case = self._case_from_row(
                        connection.execute(
                            "SELECT * FROM detection_cases WHERE case_id = ?",
                            (existing["case_id"],),
                        ).fetchone()
                    )
                    return AppendResult(case, self._message_from_row(existing), False, False)

                firstpost_claimed = False
                owned_signals = signals
                if claim_firstpost:
                    existing_claim = connection.execute(
                        "SELECT 1 FROM firstpost_claims WHERE guild_id = ? AND user_id = ?",
                        (new_message.guild_id, new_message.user_id),
                    ).fetchone()
                    firstpost_signals = tuple(
                        signal for signal in signals if signal.detector == "firstpost"
                    )
                    owned_signals = tuple(
                        signal for signal in signals if signal.detector != "firstpost"
                    )
                    if existing_claim is None:
                        firstpost_claimed = True
                        owned_signals += firstpost_signals
                    elif not owned_signals:
                        return None

                case_row = connection.execute(
                    """SELECT * FROM detection_cases
                       WHERE guild_id = ? AND user_id = ?
                         AND status IN ('pending', 'resolving')""",
                    (new_message.guild_id, new_message.user_id),
                ).fetchone()
                if case_row is not None and connection.execute(
                    "SELECT 1 FROM detection_case_deletions WHERE case_id = ?",
                    (case_row["case_id"],),
                ).fetchone() is not None:
                    return None
                if case_row is None or case_row["status"] != CaseStatus.RESOLVING.value:
                    break
                protected_effect = connection.execute(
                    """SELECT 1 FROM detection_operations
                       WHERE operation_id = ?
                         AND operation_type IN ('moderator_ban', 'moderator_kick')
                         AND effect_started_at IS NOT NULL""",
                    (case_row["resolving_token"],),
                ).fetchone()
                if protected_effect is not None:
                    break
                connection.execute(
                    """UPDATE detection_operations
                       SET status = 'abandoned', updated_at = ?, retry_at = NULL,
                           last_error = 'case received a new message before moderator effect',
                           claim_token = NULL, claimed_at = NULL
                       WHERE operation_id = ?
                         AND operation_type IN ('moderator_ban', 'moderator_kick')
                         AND effect_started_at IS NULL
                         AND status IN ('pending', 'running')""",
                    (
                        _to_timestamp(new_message.created_at),
                        case_row["resolving_token"],
                    ),
                )
                connection.execute(
                    """UPDATE detection_cases
                       SET status = 'pending', resolving_since = NULL, resolving_token = NULL
                       WHERE case_id = ? AND status = 'resolving'
                         AND resolving_token = ?""",
                    (case_row["case_id"], case_row["resolving_token"]),
                )
                case_row = connection.execute(
                    "SELECT * FROM detection_cases WHERE case_id = ?",
                    (case_row["case_id"],),
                ).fetchone()
                break
            case_created = case_row is None
            if case_created:
                case_id = str(uuid4())
                created_at = new_message.created_at.astimezone(timezone.utc)
                connection.execute(
                    """INSERT INTO detection_cases
                       (case_id, guild_id, user_id, status, created_at, expires_at, needs_attention)
                       VALUES (?, ?, ?, ?, ?, ?, 0)""",
                    (
                        case_id,
                        new_message.guild_id,
                        new_message.user_id,
                        CaseStatus.PENDING.value,
                        _to_timestamp(created_at),
                        _to_timestamp(new_case_expiry(created_at)),
                    ),
                )
                case_row = connection.execute(
                    "SELECT * FROM detection_cases WHERE case_id = ?", (case_id,)
                ).fetchone()

            case_id = case_row["case_id"]
            connection.execute(
                """INSERT INTO detection_case_subjects
                   (case_id, display_name, avatar_url, account_created_at, guild_joined_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(case_id) DO UPDATE SET
                     display_name = COALESCE(excluded.display_name, display_name),
                     avatar_url = COALESCE(excluded.avatar_url, avatar_url),
                     account_created_at = COALESCE(
                         excluded.account_created_at, account_created_at
                     ),
                     guild_joined_at = COALESCE(excluded.guild_joined_at, guild_joined_at)""",
                (
                    case_id,
                    new_message.display_name,
                    new_message.avatar_url,
                    (
                        _to_timestamp(new_message.account_created_at)
                        if new_message.account_created_at is not None
                        else None
                    ),
                    (
                        _to_timestamp(new_message.guild_joined_at)
                        if new_message.guild_joined_at is not None
                        else None
                    ),
                ),
            )
            sequence = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM detection_messages WHERE case_id = ?",
                (case_id,),
            ).fetchone()[0]
            admitted_by = next(
                (signal.detector for signal in owned_signals if signal.decisive), "unknown"
            )
            connection.execute(
                """INSERT INTO detection_messages
                   (case_id, sequence, guild_id, channel_id, message_id, content, created_at,
                    jump_url, admitted_by, capture_status, delete_status, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL)""",
                (
                    case_id,
                    sequence,
                    new_message.guild_id,
                    new_message.channel_id,
                    new_message.message_id,
                    new_message.content,
                    _to_timestamp(new_message.created_at),
                    new_message.jump_url,
                    admitted_by,
                    DeleteStatus.PENDING.value,
                ),
            )
            if firstpost_claimed:
                connection.execute(
                    """INSERT INTO firstpost_claims
                       (guild_id, user_id, case_id, message_sequence, claimed_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        new_message.guild_id,
                        new_message.user_id,
                        case_id,
                        sequence,
                        _to_timestamp(new_message.created_at),
                    ),
                )
            for position, signal in enumerate(owned_signals):
                connection.execute(
                    """INSERT INTO detection_signals
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        case_id,
                        sequence,
                        position,
                        signal.detector,
                        signal.reason,
                        signal.action.value,
                        signal.decisive,
                        json.dumps(_json_value(signal.metadata), separators=(",", ":")),
                    ),
                )
            for attachment in new_message.attachments:
                connection.execute(
                    """INSERT INTO detection_attachments
                       (case_id, message_sequence, position, filename, size, content_type,
                        width, height, source_url, evidence_path, capture_status, sha256,
                        perceptual_hash, match_metadata, learning_decision, learning_metadata,
                        error, publication_error, description, spoiler)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'pending', NULL, NULL, '{}',
                               NULL, '{}', NULL, NULL, ?, ?)""",
                    (
                        case_id,
                        sequence,
                        attachment.position,
                        attachment.filename,
                        attachment.size,
                        attachment.content_type,
                        attachment.width,
                        attachment.height,
                        attachment.url,
                        attachment.description,
                        attachment.spoiler,
                    ),
                )
            operation_time = _to_timestamp(new_message.created_at)
            resolved_initial_operations = (
                initial_operations(owned_signals)
                if callable(initial_operations)
                else initial_operations
            )
            for operation_type, idempotency_key in resolved_initial_operations:
                resolved_key = idempotency_key.format(
                    case_id=case_id, sequence=sequence
                )
                connection.execute(
                    """INSERT INTO detection_operations
                       (operation_id, case_id, message_sequence, operation_type, status, attempts,
                        created_at, updated_at, retry_at, last_error, idempotency_key)
                       VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, NULL, NULL, ?)""",
                    (
                        str(uuid4()),
                        case_id,
                        sequence,
                        operation_type,
                        operation_time,
                        operation_time,
                        resolved_key,
                    ),
                )
            message_row = connection.execute(
                "SELECT * FROM detection_messages WHERE case_id = ? AND sequence = ?",
                (case_id, sequence),
            ).fetchone()
            return AppendResult(
                self._case_from_row(case_row),
                self._message_from_row(message_row),
                case_created,
                True,
                firstpost_claimed,
            )

    def get_case(self, case_id: str) -> CaseSnapshot | None:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            case_row = connection.execute(
                "SELECT * FROM detection_cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if case_row is None:
                return None
            return self._snapshot(connection, case_row)


    def claim_firstpost(
        self,
        guild_id: int,
        user_id: int,
        case_id: str,
        message_sequence: int,
        signal: DetectionSignal | None,
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            claimed = connection.execute(
                """INSERT OR IGNORE INTO firstpost_claims
                   (guild_id, user_id, case_id, message_sequence, claimed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    guild_id,
                    user_id,
                    case_id,
                    message_sequence,
                    _to_timestamp(datetime.now(timezone.utc)),
                ),
            )
            if claimed.rowcount != 1:
                return False
            if signal is not None:
                next_position = connection.execute(
                    """SELECT COALESCE(MAX(position), -1) + 1 FROM detection_signals
                       WHERE case_id = ? AND message_sequence = ?""",
                    (case_id, message_sequence),
                ).fetchone()[0]
                connection.execute(
                    """INSERT INTO detection_signals VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        case_id,
                        message_sequence,
                        next_position,
                        signal.detector,
                        signal.reason,
                        signal.action.value,
                        signal.decisive,
                        json.dumps(_json_value(signal.metadata), separators=(",", ":")),
                    ),
                )
            return True

    def reserve_attachment_capture(
        self,
        case_id: str,
        message_sequence: int,
        position: int,
        reserved_bytes: int,
        now: datetime,
        *,
        stale_before: datetime,
        max_attachment_bytes: int,
        max_case_bytes: int,
    ) -> EvidenceReservation:
        if min(reserved_bytes, max_attachment_bytes, max_case_bytes) < 0:
            raise ValueError("evidence byte limits must be non-negative")
        key = AttachmentKey(case_id, message_sequence, position)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            attachment = connection.execute(
                """SELECT detection_attachments.capture_status
                   FROM detection_attachments
                   JOIN detection_cases USING (case_id)
                   WHERE detection_attachments.case_id = ?
                     AND detection_attachments.message_sequence = ?
                     AND detection_attachments.position = ?
                      AND (
                        detection_cases.status = 'pending'
                        OR (
                          detection_cases.status = 'resolving'
                          AND EXISTS (
                            SELECT 1 FROM detection_operations
                            WHERE detection_operations.operation_id = detection_cases.resolving_token
                              AND detection_operations.operation_type IN (
                                'moderator_ban', 'moderator_kick'
                              )
                              AND detection_operations.effect_started_at IS NOT NULL
                          )
                        )
                      )
                     AND NOT EXISTS (
                       SELECT 1 FROM detection_case_deletions
                       WHERE detection_case_deletions.case_id = detection_cases.case_id
                     )""",
                (case_id, message_sequence, position),
            ).fetchone()
            if attachment is None:
                return EvidenceReservation(key, "unavailable", None, 0, "case does not accept evidence")

            existing = connection.execute(
                """SELECT * FROM detection_evidence_reservations
                   WHERE case_id = ? AND message_sequence = ? AND position = ?""",
                (case_id, message_sequence, position),
            ).fetchone()
            if existing is not None and existing["state"] == "claimed":
                if existing["claimed_at"] > _to_timestamp(stale_before):
                    return EvidenceReservation(
                        key, "unavailable", None, 0, "evidence capture is already claimed"
                    )
                connection.execute(
                    """UPDATE detection_evidence_reservations
                       SET state = 'pending', claim_token = NULL, reserved_bytes = 0,
                           actual_bytes = NULL, claimed_at = NULL
                       WHERE case_id = ? AND message_sequence = ? AND position = ?""",
                    (case_id, message_sequence, position),
                )
                existing = None
            elif existing is not None and existing["state"] in ("captured", "too_large"):
                return EvidenceReservation(
                    key, existing["state"], None, int(existing["reserved_bytes"]), None
                )

            too_large_error = None
            if reserved_bytes > max_attachment_bytes:
                limit_mib = max_attachment_bytes // (1024 * 1024)
                too_large_error = f"attachment exceeds the {limit_mib} MiB evidence limit"
            else:
                active_bytes = connection.execute(
                    """SELECT COALESCE(SUM(CASE
                           WHEN state = 'claimed' THEN reserved_bytes
                           WHEN state = 'captured' THEN actual_bytes
                           ELSE 0 END), 0)
                       FROM detection_evidence_reservations
                       WHERE case_id = ?""",
                    (case_id,),
                ).fetchone()[0]
                if active_bytes + reserved_bytes > max_case_bytes:
                    limit_mib = max_case_bytes // (1024 * 1024)
                    too_large_error = (
                        f"attachment exceeds the remaining {limit_mib} MiB case evidence budget"
                    )

            if too_large_error is not None:
                connection.execute(
                    """INSERT INTO detection_evidence_reservations
                       (case_id, message_sequence, position, state, claim_token,
                        reserved_bytes, actual_bytes, claimed_at)
                       VALUES (?, ?, ?, 'too_large', NULL, ?, NULL, NULL)
                       ON CONFLICT(case_id, message_sequence, position) DO UPDATE SET
                         state = 'too_large', claim_token = NULL,
                         reserved_bytes = excluded.reserved_bytes,
                         actual_bytes = NULL, claimed_at = NULL""",
                    (case_id, message_sequence, position, reserved_bytes),
                )
                connection.execute(
                    """UPDATE detection_attachments
                       SET capture_status = 'too_large', evidence_path = NULL, error = ?
                       WHERE case_id = ? AND message_sequence = ? AND position = ?""",
                    (too_large_error, case_id, message_sequence, position),
                )
                connection.execute(
                    """UPDATE detection_messages SET capture_status = 'capture_incomplete'
                       WHERE case_id = ? AND sequence = ?""",
                    (case_id, message_sequence),
                )
                return EvidenceReservation(key, "too_large", None, reserved_bytes, too_large_error)

            token = str(uuid4())
            connection.execute(
                """INSERT INTO detection_evidence_reservations
                   (case_id, message_sequence, position, state, claim_token,
                    reserved_bytes, actual_bytes, claimed_at)
                   VALUES (?, ?, ?, 'claimed', ?, ?, NULL, ?)
                   ON CONFLICT(case_id, message_sequence, position) DO UPDATE SET
                     state = 'claimed', claim_token = excluded.claim_token,
                     reserved_bytes = excluded.reserved_bytes,
                     actual_bytes = NULL, claimed_at = excluded.claimed_at""",
                (
                    case_id,
                    message_sequence,
                    position,
                    token,
                    reserved_bytes,
                    _to_timestamp(now),
                ),
            )
            return EvidenceReservation(key, "claimed", token, reserved_bytes, None)

    def complete_attachment_capture(
        self,
        case_id: str,
        message_sequence: int,
        position: int,
        claim_token: str,
        actual_bytes: int,
        evidence_path: str,
        now: datetime,
        *,
        max_attachment_bytes: int,
        max_case_bytes: int,
    ) -> str | None:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            reservation = connection.execute(
                """SELECT * FROM detection_evidence_reservations
                   WHERE case_id = ? AND message_sequence = ? AND position = ?
                     AND state = 'claimed' AND claim_token = ?""",
                (case_id, message_sequence, position, claim_token),
            ).fetchone()
            if reservation is None:
                return None
            admission = connection.execute(
                """SELECT detection_attachments.capture_status
                   FROM detection_attachments
                   JOIN detection_cases USING (case_id)
                   WHERE detection_attachments.case_id = ?
                     AND detection_attachments.message_sequence = ?
                     AND detection_attachments.position = ?
                      AND (
                        detection_cases.status = 'pending'
                        OR (
                          detection_cases.status = 'resolving'
                          AND EXISTS (
                            SELECT 1 FROM detection_operations
                            WHERE detection_operations.operation_id = detection_cases.resolving_token
                              AND detection_operations.operation_type IN (
                                'moderator_ban', 'moderator_kick'
                              )
                              AND detection_operations.effect_started_at IS NOT NULL
                          )
                        )
                      )
                     AND detection_attachments.capture_status != 'captured'
                     AND NOT EXISTS (
                       SELECT 1 FROM detection_case_deletions
                       WHERE detection_case_deletions.case_id = detection_cases.case_id
                     )""",
                (case_id, message_sequence, position),
            ).fetchone()
            if admission is None:
                connection.execute(
                    """UPDATE detection_evidence_reservations
                       SET state = 'pending', claim_token = NULL, reserved_bytes = 0,
                           actual_bytes = NULL, claimed_at = NULL
                       WHERE case_id = ? AND message_sequence = ? AND position = ?
                         AND state = 'claimed' AND claim_token = ?""",
                    (case_id, message_sequence, position, claim_token),
                )
                return None
            other_bytes = connection.execute(
                """SELECT COALESCE(SUM(CASE
                       WHEN state = 'claimed' THEN reserved_bytes
                       WHEN state = 'captured' THEN actual_bytes
                       ELSE 0 END), 0)
                   FROM detection_evidence_reservations
                   WHERE case_id = ? AND NOT (
                     message_sequence = ? AND position = ?
                   )""",
                (case_id, message_sequence, position),
            ).fetchone()[0]
            if (
                actual_bytes < 0
                or actual_bytes > reservation["reserved_bytes"]
                or actual_bytes > max_attachment_bytes
                or other_bytes + actual_bytes > max_case_bytes
            ):
                error = "captured attachment exceeds its reserved evidence bytes"
                connection.execute(
                    """UPDATE detection_evidence_reservations
                       SET state = 'too_large', claim_token = NULL, actual_bytes = ?,
                           claimed_at = NULL
                       WHERE case_id = ? AND message_sequence = ? AND position = ?
                         AND state = 'claimed' AND claim_token = ?""",
                    (actual_bytes, case_id, message_sequence, position, claim_token),
                )
                connection.execute(
                    """UPDATE detection_attachments
                       SET capture_status = 'too_large', evidence_path = NULL, error = ?
                       WHERE case_id = ? AND message_sequence = ? AND position = ?""",
                    (error, case_id, message_sequence, position),
                )
                connection.execute(
                    """UPDATE detection_messages SET capture_status = 'capture_incomplete'
                       WHERE case_id = ? AND sequence = ?""",
                    (case_id, message_sequence),
                )
                return "too_large"
            connection.execute(
                """UPDATE detection_evidence_reservations
                   SET state = 'captured', claim_token = NULL, actual_bytes = ?, claimed_at = NULL
                   WHERE case_id = ? AND message_sequence = ? AND position = ?
                     AND state = 'claimed' AND claim_token = ?""",
                (actual_bytes, case_id, message_sequence, position, claim_token),
            )
            connection.execute(
                """UPDATE detection_attachments
                   SET capture_status = 'captured', evidence_path = ?, error = NULL
                   WHERE case_id = ? AND message_sequence = ? AND position = ?""",
                (evidence_path, case_id, message_sequence, position),
            )
            connection.execute(
                """UPDATE detection_messages
                   SET capture_status = CASE
                     WHEN EXISTS (
                       SELECT 1 FROM detection_attachments
                       WHERE case_id = ? AND message_sequence = ?
                         AND capture_status != 'captured'
                     ) THEN 'capture_incomplete'
                     ELSE 'captured'
                   END
                   WHERE case_id = ? AND sequence = ?""",
                (case_id, message_sequence, case_id, message_sequence),
            )
            return "captured"

    def release_attachment_capture(
        self,
        case_id: str,
        message_sequence: int,
        position: int,
        claim_token: str,
        capture_status: str,
        error: str | None,
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            released = connection.execute(
                """UPDATE detection_evidence_reservations
                   SET state = 'pending', claim_token = NULL, reserved_bytes = 0,
                       actual_bytes = NULL, claimed_at = NULL
                   WHERE case_id = ? AND message_sequence = ? AND position = ?
                     AND state = 'claimed' AND claim_token = ?""",
                (case_id, message_sequence, position, claim_token),
            )
            if released.rowcount != 1:
                return False
            connection.execute(
                """UPDATE detection_attachments
                   SET capture_status = ?, evidence_path = NULL, error = ?
                   WHERE case_id = ? AND message_sequence = ? AND position = ?""",
                (capture_status, error, case_id, message_sequence, position),
            )
            connection.execute(
                """UPDATE detection_messages SET capture_status = 'capture_incomplete'
                   WHERE case_id = ? AND sequence = ?""",
                (case_id, message_sequence),
            )
            return True

    def fail_pending_attachment_captures(
        self, case_id: str, message_sequence: int, error: str
    ) -> int:
        """Terminalize attachment capture when no reader could be started."""
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            failed = connection.execute(
                """UPDATE detection_attachments
                   SET capture_status = 'capture_failed', evidence_path = NULL, error = ?
                   WHERE case_id = ? AND message_sequence = ?
                     AND capture_status = 'pending'""",
                (error, case_id, message_sequence),
            )
            connection.execute(
                """UPDATE detection_evidence_reservations
                   SET state = 'pending', claim_token = NULL, reserved_bytes = 0,
                       actual_bytes = NULL, claimed_at = NULL
                   WHERE case_id = ? AND message_sequence = ?
                     AND state = 'claimed'""",
                (case_id, message_sequence),
            )
            connection.execute(
                """UPDATE detection_messages SET capture_status = 'capture_incomplete'
                   WHERE case_id = ? AND sequence = ?""",
                (case_id, message_sequence),
            )
            return failed.rowcount


    def update_attachment_publication_error(
        self,
        case_id: str,
        message_sequence: int,
        position: int,
        error: str | None,
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_attachments SET publication_error = ?
                   WHERE case_id = ? AND message_sequence = ? AND position = ?
                     AND capture_status = 'captured' AND evidence_path IS NOT NULL""",
                (error, case_id, message_sequence, position),
            )
            return result.rowcount == 1

    def update_attachment_scan(
        self,
        case_id: str,
        message_sequence: int,
        position: int,
        sha256: str | None,
        perceptual_hash: str | None,
        match_metadata: Mapping[str, object],
        error: str | None,
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_attachments
                   SET sha256 = ?, perceptual_hash = ?, match_metadata = ?,
                       error = CASE
                         WHEN ? IS NULL THEN error
                         WHEN error IS NULL THEN ?
                         ELSE error || '; ' || ?
                       END
                   WHERE case_id = ? AND message_sequence = ? AND position = ?""",
                (
                    sha256,
                    perceptual_hash,
                    json.dumps(_json_value(match_metadata), separators=(",", ":")),
                    error,
                    error,
                    error,
                    case_id,
                    message_sequence,
                    position,
                ),
            )
            return result.rowcount == 1

    def apply_attachment_decisions(
        self,
        case_id: str,
        decisions: Mapping[AttachmentKey, str],
        moderator_id: int,
        now: datetime,
        resolution: str | None = None,
    ) -> bool:
        """Persist stable-key image decisions and optionally resolve the case atomically."""

        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            case_row = connection.execute(
                "SELECT status, resolution FROM detection_cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if case_row is None:
                raise KeyError(case_id)
            current_decisions: dict[AttachmentKey, str | None] = {}
            for key, decision in decisions.items():
                if key.case_id != case_id:
                    raise ValueError("attachment key belongs to another case")
                row = connection.execute(
                    """SELECT learning_decision FROM detection_attachments
                       WHERE case_id = ? AND message_sequence = ? AND position = ?""",
                    (case_id, key.message_sequence, key.position),
                ).fetchone()
                if row is None:
                    raise KeyError(key)
                current_decisions[key] = row["learning_decision"]
            if case_row["status"] in (CaseStatus.RESOLVED.value, CaseStatus.EXPIRED.value):
                exact_noop = all(
                    current_decisions[key] == decision for key, decision in decisions.items()
                )
                resolution_matches = resolution is None or case_row["resolution"] == resolution
                if exact_noop and resolution_matches:
                    return False
                raise ValueError("detection case is already resolved")

            metadata = json.dumps(
                {"moderator_id": moderator_id, "reviewed_at": now.astimezone(timezone.utc).isoformat()},
                separators=(",", ":"),
            )
            for key, decision in decisions.items():
                if current_decisions[key] not in (None, decision):
                    raise ValueError("attachment already has a different decision")
                connection.execute(
                    """UPDATE detection_attachments
                       SET learning_decision = ?, learning_metadata = ?
                       WHERE case_id = ? AND message_sequence = ? AND position = ?
                         AND learning_decision IS NULL""",
                    (decision, metadata, case_id, key.message_sequence, key.position),
                )

            if resolution is not None:
                connection.execute(
                    """UPDATE detection_cases
                       SET status = 'resolved', resolution = ?, moderator_id = ?, resolved_at = ?,
                           resolving_since = NULL, resolving_token = NULL
                       WHERE case_id = ? AND status IN ('pending', 'resolving')""",
                    (resolution, moderator_id, _to_timestamp(now), case_id),
                )
            return True


    def claim_publication(self, case_id: str, slot: str, now: datetime) -> str | None:
        token = str(uuid4())
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM detection_case_deletions WHERE case_id = ?",
                (case_id,),
            ).fetchone() is not None:
                return None
            connection.execute(
                """DELETE FROM detection_publication_claims
                   WHERE case_id = ? AND slot = ? AND claimed_at <= ?""",
                (case_id, slot, _to_timestamp(now - timedelta(minutes=5))),
            )
            if slot != "primary":
                raise ValueError("unknown publication slot")
            published = connection.execute(
                "SELECT review_message_id FROM detection_cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if published is None:
                raise KeyError(case_id)
            if published["review_message_id"] is not None:
                return None
            result = connection.execute(
                """INSERT OR IGNORE INTO detection_publication_claims
                   (case_id, slot, claim_token, claimed_at) VALUES (?, ?, ?, ?)""",
                (case_id, slot, token, _to_timestamp(now)),
            )
            return token if result.rowcount == 1 else None

    def complete_primary_publication(
        self, case_id: str, token: str, channel_id: int, message_id: int
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            claim = connection.execute(
                """DELETE FROM detection_publication_claims
                   WHERE case_id = ? AND slot = 'primary' AND claim_token = ?""",
                (case_id, token),
            )
            if claim.rowcount != 1:
                return False
            result = connection.execute(
                """UPDATE detection_cases SET review_channel_id = ?, review_message_id = ?
                   WHERE case_id = ? AND review_message_id IS NULL
                     AND NOT EXISTS (
                         SELECT 1 FROM detection_case_deletions deletion
                         WHERE deletion.case_id = detection_cases.case_id
                     )""",
                (channel_id, message_id, case_id),
            )
            return result.rowcount == 1


    @staticmethod
    def _publication_membership(
        case_id: str, attachment_keys: tuple[AttachmentKey, ...]
    ) -> str:
        if any(key.case_id != case_id for key in attachment_keys):
            raise ValueError("publication attachment belongs to another case")
        if len(set(attachment_keys)) != len(attachment_keys):
            raise ValueError("publication attachment membership contains duplicates")
        return json.dumps(
            [[key.message_sequence, key.position] for key in attachment_keys],
            separators=(",", ":"),
        )

    def release_publication_claim(self, case_id: str, slot: str, token: str) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """DELETE FROM detection_publication_claims
                   WHERE case_id = ? AND slot = ? AND claim_token = ?""",
                (case_id, slot, token),
            )
            return result.rowcount == 1

    def renew_publication_claim(
        self, case_id: str, slot: str, token: str, now: datetime
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_publication_claims SET claimed_at = ?
                   WHERE case_id = ? AND slot = ? AND claim_token = ?""",
                (_to_timestamp(now), case_id, slot, token),
            )
            return result.rowcount == 1


    def update_message_delete(
        self,
        case_id: str,
        message_sequence: int,
        status: DeleteStatus,
        error: str | None,
        needs_attention: bool,
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                """UPDATE detection_messages SET delete_status = ?, error = ?
                   WHERE case_id = ? AND sequence = ? AND delete_status = 'pending'""",
                (status.value, error, case_id, message_sequence),
            )
            if result.rowcount == 1 and needs_attention:
                connection.execute(
                    "UPDATE detection_cases SET needs_attention = 1 WHERE case_id = ?",
                    (case_id,),
                )
            return result.rowcount == 1

    def mark_case_needs_attention(self, case_id: str) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_cases SET needs_attention = 1
                   WHERE case_id = ? AND needs_attention = 0""",
                (case_id,),
            )
            return result.rowcount == 1


    def clear_review_message(
        self, case_id: str, channel_id: int, message_id: int
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_cases
                   SET review_channel_id = NULL, review_message_id = NULL
                   WHERE case_id = ? AND review_channel_id = ? AND review_message_id = ?""",
                (case_id, channel_id, message_id),
            )
            return result.rowcount == 1


    def list_open_cases(self) -> tuple[CaseSnapshot, ...]:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            return tuple(
                self._snapshot(connection, row)
                for row in connection.execute(
                    """SELECT * FROM detection_cases
                       WHERE status IN ('pending', 'resolving') ORDER BY created_at, case_id"""
                )
            )

    def operational_counts(
        self, guild_id: int, now: datetime, stale_before: datetime
    ) -> Mapping[str, int]:
        """Return durable detection-case health counters for one guild."""
        with closing(self._connect()) as connection:
            row = connection.execute(
                """SELECT
                       COUNT(*) FILTER (WHERE status IN ('pending', 'resolving')) AS active_cases,
                       COUNT(*) FILTER (
                           WHERE status = 'pending' AND expires_at <= ?
                       ) AS due_cases,
                       COUNT(*) FILTER (
                           WHERE status = 'resolving' AND resolving_since <= ?
                       ) AS stale_resolving_cases,
                       COUNT(*) FILTER (
                           WHERE needs_attention = 1
                             AND status IN ('pending', 'resolving')
                       ) AS failed_containment
                   FROM detection_cases WHERE guild_id = ?""",
                (_to_timestamp(now), _to_timestamp(stale_before), guild_id),
            ).fetchone()
            forbidden_deletes = connection.execute(
                """SELECT COUNT(*) FROM detection_messages
                   WHERE guild_id = ? AND delete_status = 'forbidden'""",
                (guild_id,),
            ).fetchone()[0]
            outstanding_operations = connection.execute(
                """SELECT COUNT(*) FROM detection_operations AS operation
                   JOIN detection_cases AS detection_case USING (case_id)
                   WHERE detection_case.guild_id = ?
                     AND operation.status IN ('pending', 'running', 'failed')""",
                (guild_id,),
            ).fetchone()[0]
            privacy_deletion_jobs = connection.execute(
                """SELECT COUNT(*) FROM detection_case_deletion_jobs
                   WHERE guild_id = ?""",
                (guild_id,),
            ).fetchone()[0]
            return MappingProxyType(
                {
                    "active_cases": int(row["active_cases"]),
                    "due_cases": int(row["due_cases"]),
                    "stale_resolving_cases": int(row["stale_resolving_cases"]),
                    "failed_containment": int(row["failed_containment"]),
                    "forbidden_deletes": int(forbidden_deletes),
                    "outstanding_operations": int(outstanding_operations),
                    "privacy_deletion_jobs": int(privacy_deletion_jobs),
                }
            )

    def plan_user_case_deletion(self, user_id: int) -> tuple[tuple[int, str], ...]:
        """Durably tombstone every case owned by a user."""
        return self._plan_case_deletion("user", "user_id", user_id)

    def plan_guild_case_deletion(self, guild_id: int) -> tuple[tuple[int, str], ...]:
        """Durably tombstone every case owned by a guild."""
        return self._plan_case_deletion("guild", "guild_id", guild_id)

    def compact_terminal_case(self, case_id: str) -> bool:
        """Drop detailed terminal state while preserving its deletion endpoint."""
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            case = connection.execute(
                """SELECT 1 FROM detection_cases
                   WHERE case_id = ? AND status IN ('resolved', 'expired')""",
                (case_id,),
            ).fetchone()
            if case is None:
                return False
            pending = connection.execute(
                """SELECT 1 FROM detection_operations
                   WHERE case_id = ? AND status NOT IN ('succeeded', 'abandoned')
                   LIMIT 1""",
                (case_id,),
            ).fetchone()
            if pending is not None:
                return False
            connection.execute(
                "DELETE FROM detection_case_subjects WHERE case_id = ?", (case_id,)
            )
            connection.execute(
                "DELETE FROM detection_messages WHERE case_id = ?", (case_id,)
            )
            connection.execute(
                "DELETE FROM detection_operations WHERE case_id = ?", (case_id,)
            )
            connection.execute(
                "DELETE FROM detection_evidence_publications WHERE case_id = ?",
                (case_id,),
            )
            connection.execute(
                "DELETE FROM detection_timeline_publications WHERE case_id = ?",
                (case_id,),
            )
            connection.execute(
                "DELETE FROM detection_publication_claims WHERE case_id = ?",
                (case_id,),
            )
            connection.execute(
                "DELETE FROM detection_orphan_publications WHERE case_id = ?",
                (case_id,),
            )
            connection.execute(
                """UPDATE detection_cases
                   SET created_at = 0, expires_at = 0, resolution = NULL,
                       moderator_id = NULL, resolved_at = NULL,
                       review_channel_id = NULL, review_message_id = NULL,
                       resolving_since = NULL, resolving_token = NULL,
                       needs_attention = 0
                   WHERE case_id = ?""",
                (case_id,),
            )
            return True

    def _plan_case_deletion(
        self, scope_kind: str, column: str, value: int
    ) -> tuple[tuple[int, str], ...]:
        if column not in {"user_id", "guild_id"}:
            raise ValueError("unsupported detection case deletion scope")
        requested_at = _to_timestamp(datetime.now(timezone.utc))
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            cases = connection.execute(
                f"""SELECT case_id, guild_id, review_channel_id, review_message_id
                    FROM detection_cases WHERE {column} = ?
                    ORDER BY guild_id, case_id""",
                (value,),
            ).fetchall()
            for case in cases:
                endpoint = connection.execute(
                    """SELECT parent_channel_id, summary_message_id, thread_id
                       FROM detection_projection_endpoints WHERE case_id = ?""",
                    (case["case_id"],),
                ).fetchone()
                publications = [
                    [int(row["channel_id"]), int(row["message_id"])]
                    for row in connection.execute(
                        """SELECT channel_id, message_id
                           FROM detection_evidence_publications
                           WHERE case_id = ? ORDER BY batch_index""",
                        (case["case_id"],),
                    )
                ]
                publications.extend(
                    [int(row["channel_id"]), int(row["message_id"])]
                    for row in connection.execute(
                        """SELECT channel_id, message_id
                           FROM detection_orphan_publications
                           WHERE case_id = ? ORDER BY created_at, channel_id, message_id""",
                        (case["case_id"],),
                    )
                )
                connection.execute(
                    """INSERT OR IGNORE INTO detection_case_deletion_jobs
                       (case_id, guild_id, parent_channel_id, summary_message_id,
                        thread_id, legacy_publications, requested_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        case["case_id"],
                        case["guild_id"],
                        endpoint["parent_channel_id"] if endpoint else case["review_channel_id"],
                        endpoint["summary_message_id"] if endpoint else case["review_message_id"],
                        endpoint["thread_id"] if endpoint else None,
                        json.dumps(publications, separators=(",", ":")),
                        requested_at,
                    ),
                )
                connection.execute(
                    """INSERT OR IGNORE INTO detection_case_deletions
                       (case_id, guild_id, scope_kind, scope_id, requested_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        case["case_id"], case["guild_id"],
                        scope_kind, value, requested_at,
                    ),
                )
            return tuple(
                (int(row["guild_id"]), str(row["case_id"]))
                for row in cases
            )

    def list_planned_case_deletions(self) -> tuple[tuple[int, str], ...]:
        with closing(self._connect()) as connection:
            return tuple(
                (int(row[0]), str(row[1]))
                for row in connection.execute(
                    """SELECT guild_id, case_id FROM detection_case_deletion_jobs
                       ORDER BY requested_at, guild_id, case_id"""
                )
            )

    def get_case_deletion_job(self, case_id: str) -> CaseDeletionJob | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM detection_case_deletion_jobs WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            return None
        return self._case_deletion_job_from_row(row)

    def mark_case_deletion_remote(
        self, case_id: str, *, error: str | None = None
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """UPDATE detection_case_deletion_jobs
                   SET remote_deleted = CASE WHEN ? IS NULL THEN 1 ELSE remote_deleted END,
                       attempts = attempts + CASE WHEN ? IS NULL THEN 0 ELSE 1 END,
                       last_error = ?
                   WHERE case_id = ?""",
                (error, error, error, case_id),
            )
            return cursor.rowcount == 1

    def mark_case_deletion_local(self, case_id: str) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """UPDATE detection_case_deletion_jobs
                   SET local_deleted = 1 WHERE case_id = ?""",
                (case_id,),
            )
            return cursor.rowcount == 1

    def case_deletion_has_inflight_publications(self, case_id: str) -> bool:
        stale_before = _to_timestamp(
            datetime.now(timezone.utc) - timedelta(minutes=5)
        )
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """DELETE FROM detection_publication_claims
                   WHERE case_id = ? AND claimed_at <= ?""",
                (case_id, stale_before),
            )
            connection.execute(
                """UPDATE detection_timeline_publications
                   SET claim_token = NULL, claimed_at = NULL
                   WHERE case_id = ? AND claim_token IS NOT NULL AND claimed_at <= ?""",
                (case_id, stale_before),
            )
            return connection.execute(
                """SELECT 1
                   WHERE EXISTS (
                       SELECT 1 FROM detection_publication_claims
                       WHERE case_id = ?
                   ) OR EXISTS (
                       SELECT 1 FROM detection_timeline_publications
                       WHERE case_id = ? AND claim_token IS NOT NULL
                   )""",
                (case_id, case_id),
            ).fetchone() is not None

    def add_case_deletion_publication(
        self, case_id: str, channel_id: int, message_id: int
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT legacy_publications FROM detection_case_deletion_jobs
                   WHERE case_id = ?""",
                (case_id,),
            ).fetchone()
            if row is None:
                return False
            targets = [
                [int(existing_channel), int(existing_message)]
                for existing_channel, existing_message in json.loads(
                    row["legacy_publications"]
                )
            ]
            target = [channel_id, message_id]
            if target not in targets:
                targets.append(target)
            cursor = connection.execute(
                """UPDATE detection_case_deletion_jobs
                   SET legacy_publications = ?, remote_deleted = 0
                   WHERE case_id = ?""",
                (json.dumps(targets, separators=(",", ":")), case_id),
            )
            return cursor.rowcount == 1

    def record_orphan_publication(
        self,
        case_id: str,
        channel_id: int,
        message_id: int,
        now: datetime | None = None,
    ) -> bool:
        created_at = _to_timestamp(now or datetime.now(timezone.utc))
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO detection_orphan_publications
                   (case_id, channel_id, message_id, created_at)
                   SELECT case_id, ?, ?, ? FROM detection_cases WHERE case_id = ?""",
                (channel_id, message_id, created_at, case_id),
            )
            if cursor.rowcount == 1:
                return True
            return connection.execute(
                """SELECT 1 FROM detection_orphan_publications
                   WHERE case_id = ? AND channel_id = ? AND message_id = ?""",
                (case_id, channel_id, message_id),
            ).fetchone() is not None

    def list_orphan_publications(
        self,
    ) -> tuple[tuple[str, int, int, int], ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """SELECT orphan.case_id, detection_case.guild_id,
                          orphan.channel_id, orphan.message_id
                   FROM detection_orphan_publications orphan
                   JOIN detection_cases detection_case USING (case_id)
                   ORDER BY orphan.created_at, orphan.case_id,
                            orphan.channel_id, orphan.message_id"""
            ).fetchall()
        return tuple(
            (
                str(row["case_id"]),
                int(row["guild_id"]),
                int(row["channel_id"]),
                int(row["message_id"]),
            )
            for row in rows
        )

    def complete_orphan_publication(
        self, case_id: str, channel_id: int, message_id: int
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """DELETE FROM detection_orphan_publications
                   WHERE case_id = ? AND channel_id = ? AND message_id = ?""",
                (case_id, channel_id, message_id),
            )
            return cursor.rowcount == 1

    def case_accepts_evidence(self, guild_id: int, case_id: str) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """SELECT 1 FROM detection_cases
                   WHERE guild_id = ? AND case_id = ?
                     AND (
                       status = 'pending'
                       OR (
                         status = 'resolving'
                         AND EXISTS (
                           SELECT 1 FROM detection_operations
                           WHERE detection_operations.operation_id = detection_cases.resolving_token
                             AND detection_operations.operation_type IN (
                               'moderator_ban', 'moderator_kick'
                             )
                             AND detection_operations.effect_started_at IS NOT NULL
                         )
                       )
                     )
                      AND NOT EXISTS (
                       SELECT 1 FROM detection_case_deletions
                       WHERE detection_case_deletions.case_id = detection_cases.case_id
                     )""",
                (guild_id, case_id),
            ).fetchone()
            return row is not None

    def finalize_case_deletion(self, guild_id: int, case_id: str) -> bool:
        """Delete personal rows while preserving the non-personal retry job."""
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            job = connection.execute(
                """SELECT 1 FROM detection_case_deletion_jobs
                   WHERE guild_id = ? AND case_id = ?""",
                (guild_id, case_id),
            ).fetchone()
            if job is None:
                return False
            connection.execute(
                "DELETE FROM detection_cases WHERE guild_id = ? AND case_id = ?",
                (guild_id, case_id),
            )
            result = connection.execute(
                """UPDATE detection_case_deletion_jobs SET rows_deleted = 1
                   WHERE guild_id = ? AND case_id = ?""",
                (guild_id, case_id),
            )
            return result.rowcount == 1

    def complete_case_deletion_job(self, case_id: str) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """DELETE FROM detection_case_deletion_jobs
                   WHERE case_id = ? AND remote_deleted = 1
                     AND local_deleted = 1 AND rows_deleted = 1""",
                (case_id,),
            )
            return cursor.rowcount == 1

    def list_due_cases(self, now: datetime) -> tuple[CaseRecord, ...]:
        with closing(self._connect()) as connection:
            return tuple(
                self._case_from_row(row)
                for row in connection.execute(
                    """SELECT * FROM detection_cases
                       WHERE status = 'pending' AND expires_at <= ?
                         AND NOT EXISTS (
                           SELECT 1 FROM detection_case_deletions deletion
                           WHERE deletion.case_id = detection_cases.case_id
                         )
                       ORDER BY created_at, case_id""",
                    (_to_timestamp(now),),
                )
            )

    def list_reconcilable_cases(
        self, now: datetime, stale_before: datetime
    ) -> tuple[CaseRecord, ...]:
        with closing(self._connect()) as connection:
            return tuple(
                self._case_from_row(row)
                for row in connection.execute(
                    """SELECT * FROM detection_cases
                       WHERE ((status = 'pending' AND expires_at <= ?)
                          OR (
                            status = 'resolving'
                            AND expires_at <= ?
                            AND resolving_since <= ?
                          ))
                         AND NOT EXISTS (
                           SELECT 1 FROM detection_case_deletions deletion
                           WHERE deletion.case_id = detection_cases.case_id
                         )
                       ORDER BY created_at, case_id""",
                    (
                        _to_timestamp(now),
                        _to_timestamp(now),
                        _to_timestamp(stale_before),
                    ),
                )
            )

    def claim_resolution(
        self,
        case_id: str,
        now: datetime,
        stale_before: datetime | None = None,
        *,
        require_terminal_captures: bool = False,
    ) -> ResolutionLease | None:
        now_value = _to_timestamp(now)
        token = str(uuid4())
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            if stale_before is None:
                result = connection.execute(
                    """UPDATE detection_cases
                       SET status = 'resolving', resolving_since = ?, resolving_token = ?
                        WHERE case_id = ? AND status = 'pending'
                          AND NOT EXISTS (
                            SELECT 1 FROM detection_case_deletions deletion
                            WHERE deletion.case_id = detection_cases.case_id
                          )
                          AND (? = 0 OR NOT EXISTS (
                            SELECT 1 FROM detection_attachments attachment
                            WHERE attachment.case_id = detection_cases.case_id
                              AND attachment.capture_status = 'pending'
                          ))""",
                    (now_value, token, case_id, int(require_terminal_captures)),
                )
            else:
                result = connection.execute(
                    """UPDATE detection_cases
                       SET status = 'resolving', resolving_since = ?, resolving_token = ?
                       WHERE case_id = ?
                          AND NOT EXISTS (
                            SELECT 1 FROM detection_case_deletions deletion
                            WHERE deletion.case_id = detection_cases.case_id
                          )
                          AND (? = 0 OR NOT EXISTS (
                            SELECT 1 FROM detection_attachments attachment
                            WHERE attachment.case_id = detection_cases.case_id
                              AND attachment.capture_status = 'pending'
                          ))
                          AND (
                           status = 'pending' OR
                           (status = 'resolving' AND resolving_since <= ? AND NOT EXISTS (
                               SELECT 1 FROM detection_operations
                               WHERE operation_id = detection_cases.resolving_token
                                 AND operation_type IN ('moderator_ban', 'moderator_kick')
                           ))
                       )""",
                    (
                        now_value,
                        token,
                        case_id,
                        int(require_terminal_captures),
                        _to_timestamp(stale_before),
                    ),
                )
            return ResolutionLease(case_id, token, now) if result.rowcount == 1 else None

    def release_resolution(self, lease: ResolutionLease) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_cases
                   SET status = 'pending', resolving_since = NULL, resolving_token = NULL
                   WHERE case_id = ? AND status = 'resolving' AND resolving_token = ?""",
                (lease.case_id, lease.token),
            )
            return result.rowcount == 1

    def finish_resolution(
        self,
        lease: ResolutionLease,
        status: CaseStatus,
        resolution: str,
        moderator_id: int | None,
        now: datetime,
        decisions: Mapping[AttachmentKey, str] | None = None,
        final_operations: tuple[tuple[str, str], ...] = (),
    ) -> bool:
        if status not in (CaseStatus.RESOLVED, CaseStatus.EXPIRED):
            raise ValueError("status must be resolved or expired")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            owned = connection.execute(
                """SELECT 1 FROM detection_cases
                   WHERE case_id = ? AND status = 'resolving' AND resolving_token = ?""",
                (lease.case_id, lease.token),
            ).fetchone()
            if owned is None:
                return False
            metadata = json.dumps(
                {
                    "moderator_id": moderator_id,
                    "reviewed_at": now.astimezone(timezone.utc).isoformat(),
                },
                separators=(",", ":"),
            )

            for key, decision in (decisions or {}).items():
                if key.case_id != lease.case_id:
                    raise ValueError("attachment key belongs to another case")
                result = connection.execute(
                    """UPDATE detection_attachments
                       SET learning_decision = ?, learning_metadata = ?
                       WHERE case_id = ? AND message_sequence = ? AND position = ?
                         AND learning_decision IS NULL""",
                    (
                        decision,
                        metadata,
                        key.case_id,
                        key.message_sequence,
                        key.position,
                    ),
                )
                if result.rowcount != 1:
                    existing = connection.execute(
                        """SELECT learning_decision FROM detection_attachments
                           WHERE case_id = ? AND message_sequence = ? AND position = ?""",
                        (key.case_id, key.message_sequence, key.position),
                    ).fetchone()
                    if existing is None:
                        raise KeyError(key)
                    if existing["learning_decision"] != decision:
                        raise ValueError("attachment already has a different decision")
            now_value = _to_timestamp(now)
            for operation_type, idempotency_key in final_operations:
                connection.execute(
                    """INSERT OR IGNORE INTO detection_operations
                       (operation_id, case_id, message_sequence, operation_type, status,
                        attempts, created_at, updated_at, retry_at, last_error,
                        idempotency_key, claim_token, claimed_at)
                       VALUES (?, ?, NULL, ?, 'pending', 0, ?, ?, NULL, NULL, ?, NULL, NULL)""",
                    (
                        str(uuid4()), lease.case_id, operation_type,
                        now_value, now_value, idempotency_key,
                    ),
                )
            result = connection.execute(
                """UPDATE detection_cases
                   SET status = ?, resolution = ?, moderator_id = ?, resolved_at = ?,
                       resolving_since = NULL, resolving_token = NULL
                   WHERE case_id = ? AND status = 'resolving' AND resolving_token = ?""",
                (
                    status.value,
                    resolution,
                    moderator_id,
                    _to_timestamp(now),
                    lease.case_id,
                    lease.token,
                ),
            )
            return result.rowcount == 1

    def claim_moderator_action(
        self, case_id: str, action: str, actor_id: int, now: datetime
    ) -> OperationRecord | None:
        if action not in {"ban", "kick"}:
            raise ValueError("unsupported moderator action")
        idempotency_key = f"moderator-action:{case_id}"
        now_value = _to_timestamp(now)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            case = connection.execute(
                "SELECT status, resolving_token FROM detection_cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if case is None:
                raise KeyError(case_id)
            operation = connection.execute(
                "SELECT * FROM detection_operations WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if (
                operation is not None
                and case["status"] == CaseStatus.PENDING.value
                and operation["status"] == OperationStatus.ABANDONED.value
                and operation["effect_started_at"] is None
            ):
                connection.execute(
                    """DELETE FROM detection_operations
                       WHERE operation_id = ? AND status = 'abandoned'
                         AND effect_started_at IS NULL""",
                    (operation["operation_id"],),
                )
                operation = None
            if operation is None:
                if case["status"] != CaseStatus.PENDING.value:
                    return None
                operation_id = str(uuid4())
                connection.execute(
                    """INSERT INTO detection_operations
                       (operation_id, case_id, message_sequence, operation_type, status,
                        attempts, created_at, updated_at, retry_at, last_error, result,
                        actor_id, idempotency_key, claim_token, claimed_at)
                       VALUES (?, ?, NULL, ?, 'pending', 0, ?, ?, NULL, NULL, NULL,
                               ?, ?, NULL, NULL)""",
                    (
                        operation_id,
                        case_id,
                        f"moderator_{action}",
                        now_value,
                        now_value,
                        actor_id,
                        idempotency_key,
                    ),
                )
                updated = connection.execute(
                    """UPDATE detection_cases
                       SET status = 'resolving', resolving_since = ?, resolving_token = ?
                       WHERE case_id = ? AND status = 'pending'
                         AND NOT EXISTS (
                           SELECT 1 FROM detection_case_deletions deletion
                           WHERE deletion.case_id = detection_cases.case_id
                         )""",
                    (now_value, operation_id, case_id),
                )
                if updated.rowcount != 1:
                    return None
                operation = connection.execute(
                    "SELECT * FROM detection_operations WHERE operation_id = ?",
                    (operation_id,),
                ).fetchone()
            elif not (
                case["status"] == CaseStatus.RESOLVING.value
                and case["resolving_token"] == operation["operation_id"]
            ):
                return None
            return self._operation_from_row(operation)

    def complete_moderator_action(
        self, operation_id: str, token: str, now: datetime, result: str
    ) -> bool:
        now_value = _to_timestamp(now)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                """SELECT * FROM detection_operations
                   WHERE operation_id = ? AND status = 'running' AND claim_token = ?
                     AND operation_type IN ('moderator_ban', 'moderator_kick')""",
                (operation_id, token),
            ).fetchone()
            if operation is None:
                return False
            case_id = operation["case_id"]
            case = connection.execute(
                """SELECT 1 FROM detection_cases
                   WHERE case_id = ? AND status = 'resolving' AND resolving_token = ?""",
                (case_id, operation_id),
            ).fetchone()
            if case is None:
                return False
            completed = connection.execute(
                """UPDATE detection_operations
                   SET status = 'succeeded', updated_at = ?, retry_at = NULL,
                       last_error = NULL, result = ?, claim_token = NULL, claimed_at = NULL
                   WHERE operation_id = ? AND status = 'running' AND claim_token = ?""",
                (now_value, result, operation_id, token),
            )
            if completed.rowcount != 1:
                return False
            self._finalize_moderator_action_locked(connection, case_id, now_value)
            return True

    def reconcile_moderator_actions(self, now: datetime) -> tuple[str, ...]:
        now_value = _to_timestamp(now)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            case_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    """SELECT detection_cases.case_id
                       FROM detection_cases
                       JOIN detection_operations
                         ON detection_operations.operation_id = detection_cases.resolving_token
                       WHERE detection_cases.status = 'resolving'
                         AND detection_operations.operation_type IN (
                           'moderator_ban', 'moderator_kick'
                         )
                         AND detection_operations.status = 'succeeded'
                       ORDER BY detection_cases.created_at, detection_cases.case_id"""
                )
            )
            return tuple(
                case_id
                for case_id in case_ids
                if self._finalize_moderator_action_locked(connection, case_id, now_value)
            )

    def _finalize_moderator_action_locked(
        self, connection: sqlite3.Connection, case_id: str, now_value: int
    ) -> bool:
        operation = connection.execute(
            """SELECT detection_operations.*
               FROM detection_cases
               JOIN detection_operations
                 ON detection_operations.operation_id = detection_cases.resolving_token
               WHERE detection_cases.case_id = ?
                 AND detection_cases.status = 'resolving'
                 AND detection_operations.operation_type IN ('moderator_ban', 'moderator_kick')
                 AND detection_operations.status = 'succeeded'""",
            (case_id,),
        ).fetchone()
        if operation is None:
            return False
        if connection.execute(
            """SELECT 1 FROM detection_attachments
               WHERE case_id = ? AND capture_status = 'pending' LIMIT 1""",
            (case_id,),
        ).fetchone() is not None:
            return False
        pending_sources = connection.execute(
            """SELECT detection_messages.sequence, detection_signals.detector,
                      detection_signals.action, detection_signals.metadata
               FROM detection_messages
               JOIN detection_signals
                 ON detection_signals.case_id = detection_messages.case_id
                AND detection_signals.message_sequence = detection_messages.sequence
               WHERE detection_messages.case_id = ?
                 AND detection_messages.delete_status = 'pending'
               ORDER BY detection_messages.sequence, detection_signals.position""",
            (case_id,),
        ).fetchall()
        for row in pending_sources:
            metadata = json.loads(row["metadata"])
            if (
                row["action"] != ActionIntent.NONE.value
                or row["detector"] == "honeypot"
                or metadata.get("containment_required")
            ):
                return False
        if connection.execute(
            """SELECT 1 FROM detection_operations
               WHERE case_id = ? AND operation_type = 'cached_purge'
                 AND status NOT IN ('succeeded', 'abandoned') LIMIT 1""",
            (case_id,),
        ).fetchone() is not None:
            return False
        final_operations = [
            ("review_update", f"review-update:{case_id}"),
            ("evidence_cleanup", f"evidence-cleanup:{case_id}"),
        ]
        final_operations.extend(
            ("role_release", f"role-release:{case_id}:{int(row[0])}")
            for row in connection.execute(
                """SELECT role_id FROM detection_role_ownership
                   WHERE case_id = ? ORDER BY role_id""",
                (case_id,),
            )
        )
        for operation_type, idempotency_key in final_operations:
            connection.execute(
                """INSERT OR IGNORE INTO detection_operations
                   (operation_id, case_id, message_sequence, operation_type, status,
                    attempts, created_at, updated_at, retry_at, last_error,
                    idempotency_key, claim_token, claimed_at)
                   VALUES (?, ?, NULL, ?, 'pending', 0, ?, ?, NULL, NULL, ?, NULL, NULL)""",
                (
                    str(uuid4()), case_id, operation_type,
                    now_value, now_value, idempotency_key,
                ),
            )
        terminal = connection.execute(
                """UPDATE detection_cases
                   SET status = 'resolved', resolution = ?, moderator_id = ?, resolved_at = ?,
                       resolving_since = NULL, resolving_token = NULL
                   WHERE case_id = ? AND status = 'resolving' AND resolving_token = ?""",
                (
                    operation["result"]
                    if operation["result"].startswith("planned_")
                    else operation["operation_type"].removeprefix("moderator_"),
                    operation["actor_id"],
                    now_value,
                    case_id,
                    operation["operation_id"],
                ),
            )
        return terminal.rowcount == 1

    def ensure_operation(
        self,
        case_id: str,
        kind: str,
        idempotency_key: str,
        message_sequence: int | None = None,
        actor_id: int | None = None,
    ) -> OperationRecord:
        created_at = _to_timestamp(datetime.now(timezone.utc))
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT OR IGNORE INTO detection_operations
                   (operation_id, case_id, message_sequence, operation_type, status, attempts,
                    created_at, updated_at, retry_at, last_error, result, actor_id,
                    idempotency_key,
                    claim_token, claimed_at)
                   VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, NULL, NULL, NULL, ?, ?, NULL, NULL)""",
                (
                    str(uuid4()), case_id, message_sequence, kind,
                    created_at, created_at, actor_id, idempotency_key,
                ),
            )
            row = connection.execute(
                "SELECT * FROM detection_operations WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            return self._operation_from_row(row)

    def claim_due_operations(
        self, now: datetime, limit: int = 50, stale_before: datetime | None = None
    ) -> tuple[OperationRecord, ...]:
        if limit <= 0:
            return ()
        now_value = _to_timestamp(now)
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            operation_ids = tuple(
                row["operation_id"]
                for row in connection.execute(
                    """SELECT operation_id FROM detection_operations AS candidate
                       WHERE (
                         (status IN ('pending', 'failed')
                          AND (retry_at IS NULL OR retry_at <= ?))
                         OR (status = 'running' AND claimed_at <= ?)
                       )
                         AND NOT EXISTS (
                           SELECT 1 FROM detection_case_deletions deletion
                           WHERE deletion.case_id = candidate.case_id
                         )
                         AND (
                           operation_type != 'evidence_cleanup'
                           OR NOT EXISTS (
                             SELECT 1 FROM detection_operations AS dependency
                             WHERE dependency.case_id = candidate.case_id
                               AND dependency.operation_type = 'review_update'
                               AND dependency.status != 'succeeded'
                           )
                         )
                         AND (
                           operation_type NOT IN (
                             'moderation_action', 'role_apply', 'review_publish'
                           )
                           OR (
                             operation_type = 'moderation_action'
                             AND (
                               effect_started_at IS NOT NULL
                               OR NOT EXISTS (
                                 SELECT 1 FROM detection_messages AS source
                                 WHERE source.case_id = candidate.case_id
                                   AND source.sequence = candidate.message_sequence
                                   AND source.delete_status = 'pending'
                               )
                             )
                           )
                           OR (
                             operation_type IN ('role_apply', 'review_publish')
                             AND NOT EXISTS (
                               SELECT 1 FROM detection_operations AS dependency
                               WHERE dependency.case_id = candidate.case_id
                                 AND dependency.message_sequence = candidate.message_sequence
                                 AND dependency.operation_type = 'message_process'
                                 AND dependency.status NOT IN ('succeeded', 'abandoned')
                             )
                           )
                         )
                       ORDER BY attempts,
                                CASE status
                                  WHEN 'pending' THEN 0
                                  WHEN 'running' THEN 1
                                  ELSE 2
                                END,
                                operation_id
                       LIMIT ?""",
                    (
                        now_value,
                        _to_timestamp(stale_before) if stale_before is not None else -1,
                        limit,
                    ),
                )
            )
            if not operation_ids:
                return ()
            placeholders = ",".join("?" for _ in operation_ids)
            for operation_id in operation_ids:
                connection.execute(
                    """UPDATE detection_operations SET status = 'running',
                       attempts = attempts + 1, updated_at = ?, claimed_at = ?, claim_token = ?
                       WHERE operation_id = ?""",
                    (now_value, now_value, str(uuid4()), operation_id),
                )
            return tuple(
                self._operation_from_row(row)
                for row in connection.execute(
                    f"""SELECT * FROM detection_operations
                        WHERE operation_id IN ({placeholders}) ORDER BY operation_id""",
                    operation_ids,
                )
            )

    def record_operation_role_ownership(
        self,
        operation_id: str,
        token: str,
        case_id: str,
        guild_id: int,
        user_id: int,
        role_id: int,
        now: datetime,
    ) -> str | None:
        expected_key = f"role-apply:{case_id}:{role_id}"
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                """SELECT detection_cases.status AS case_status
                   FROM detection_operations
                   JOIN detection_cases USING (case_id)
                   WHERE operation_id = ? AND detection_operations.case_id = ?
                     AND operation_type = 'role_apply' AND idempotency_key = ?
                     AND detection_operations.status = 'running' AND claim_token = ?
                     AND effect_started_at IS NOT NULL""",
                (operation_id, case_id, expected_key, token),
            ).fetchone()
            if operation is None:
                return None
            result = connection.execute(
                """INSERT OR IGNORE INTO detection_role_ownership
                   (case_id, guild_id, user_id, role_id, applied_at) VALUES (?, ?, ?, ?, ?)""",
                (case_id, guild_id, user_id, role_id, _to_timestamp(now)),
            )
            if result.rowcount != 1:
                return None
            if operation["case_status"] == CaseStatus.PENDING.value:
                return "owned"
            operation_time = _to_timestamp(now)
            connection.execute(
                """INSERT OR IGNORE INTO detection_operations
                   (operation_id, case_id, message_sequence, operation_type, status, attempts,
                    created_at, updated_at, retry_at, last_error, idempotency_key)
                   VALUES (?, ?, NULL, 'role_release', 'pending', 0, ?, ?, NULL, NULL, ?)""",
                (
                    str(uuid4()),
                    case_id,
                    operation_time,
                    operation_time,
                    f"role-release:{case_id}:{role_id}",
                ),
            )
            return "release_required"

    def transfer_terminal_role_ownership(
        self,
        operation_id: str,
        token: str,
        case_id: str,
        guild_id: int,
        user_id: int,
        role_id: int,
        now: datetime,
    ) -> bool:
        expected_key = f"role-apply:{case_id}:{role_id}"
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                """SELECT 1 FROM detection_operations
                   JOIN detection_cases USING (case_id)
                   WHERE operation_id = ? AND case_id = ?
                     AND operation_type = 'role_apply' AND idempotency_key = ?
                     AND detection_operations.status = 'running'
                     AND claim_token = ? AND detection_cases.status = 'pending'""",
                (operation_id, case_id, expected_key, token),
            ).fetchone()
            if operation is None:
                return False
            result = connection.execute(
                """UPDATE detection_role_ownership
                   SET case_id = ?, applied_at = ?
                   WHERE guild_id = ? AND user_id = ? AND role_id = ?
                     AND case_id != ?
                      AND EXISTS (
                        SELECT 1 FROM detection_cases AS previous_case
                        WHERE previous_case.case_id = detection_role_ownership.case_id
                          AND previous_case.status IN ('resolved', 'expired')
                      )
                      AND NOT EXISTS (
                        SELECT 1 FROM detection_operations AS release
                        WHERE release.case_id = detection_role_ownership.case_id
                          AND release.operation_type = 'role_release'
                          AND release.idempotency_key = (
                            'role-release:' || detection_role_ownership.case_id || ':' || ?
                          )
                          AND release.effect_started_at IS NOT NULL
                          AND release.status != 'succeeded'
                      )""",
                (
                    case_id,
                    _to_timestamp(now),
                    guild_id,
                    user_id,
                    role_id,
                    case_id,
                    str(role_id),
                ),
            )
            return result.rowcount == 1

    def owned_role_ids(self, case_id: str) -> tuple[int, ...]:
        with closing(self._connect()) as connection:
            return tuple(
                int(row[0])
                for row in connection.execute(
                    "SELECT role_id FROM detection_role_ownership WHERE case_id = ? ORDER BY role_id",
                    (case_id,),
                )
            )

    def role_owner_case(self, guild_id: int, user_id: int, role_id: int) -> str | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """SELECT case_id FROM detection_role_ownership
                   WHERE guild_id = ? AND user_id = ? AND role_id = ?""",
                (guild_id, user_id, role_id),
            ).fetchone()
            return None if row is None else str(row[0])

    def release_role_ownership(self, case_id: str, role_id: int) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                "DELETE FROM detection_role_ownership WHERE case_id = ? AND role_id = ?",
                (case_id, role_id),
            )
            return result.rowcount == 1

    def claim_operation(self, operation_id: str, now: datetime) -> OperationRecord | None:
        now_value = _to_timestamp(now)
        token = str(uuid4())
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                """UPDATE detection_operations SET status = 'running',
                   attempts = attempts + 1, updated_at = ?, claimed_at = ?, claim_token = ?
                   WHERE operation_id = ? AND status IN ('pending', 'failed')
                     AND (retry_at IS NULL OR retry_at <= ?)
                     AND NOT EXISTS (
                       SELECT 1 FROM detection_case_deletions deletion
                       WHERE deletion.case_id = detection_operations.case_id
                     )
                     AND (
                       operation_type != 'evidence_cleanup'
                       OR NOT EXISTS (
                         SELECT 1 FROM detection_operations AS dependency
                         WHERE dependency.case_id = detection_operations.case_id
                           AND dependency.operation_type = 'review_update'
                           AND dependency.status != 'succeeded'
                       )
                     )""",
                (now_value, now_value, token, operation_id, now_value),
            )
            if result.rowcount != 1:
                return None
            row = connection.execute(
                "SELECT * FROM detection_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            return self._operation_from_row(row)

    def complete_operation(
        self,
        operation_id: str,
        token: str,
        now: datetime,
        result: str | None = None,
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_operations
                   SET status = 'succeeded', updated_at = ?, retry_at = NULL, last_error = NULL,
                       result = ?, claim_token = NULL, claimed_at = NULL
                   WHERE operation_id = ? AND status = 'running' AND claim_token = ?""",
                (_to_timestamp(now), result, operation_id, token),
            )
            return result.rowcount == 1

    def renew_operation_claim(self, operation_id: str, token: str, now: datetime) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_operations SET updated_at = ?, claimed_at = ?
                   WHERE operation_id = ? AND status = 'running' AND claim_token = ?""",
                (_to_timestamp(now), _to_timestamp(now), operation_id, token),
            )
            return result.rowcount == 1

    def start_operation_effect(self, operation_id: str, token: str, now: datetime) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_operations SET effect_started_at = COALESCE(effect_started_at, ?)
                   WHERE operation_id = ? AND status = 'running' AND claim_token = ?""",
                (_to_timestamp(now), operation_id, token),
            )
            return result.rowcount == 1

    def start_role_apply_effect(
        self, operation_id: str, token: str, now: datetime
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_operations
                   SET effect_started_at = COALESCE(effect_started_at, ?)
                   WHERE operation_id = ? AND operation_type = 'role_apply'
                     AND status = 'running' AND claim_token = ?
                     AND EXISTS (
                       SELECT 1 FROM detection_cases
                       WHERE detection_cases.case_id = detection_operations.case_id
                         AND detection_cases.status = 'pending'
                     )""",
                (_to_timestamp(now), operation_id, token),
            )
            return result.rowcount == 1

    def start_role_release_effect(
        self,
        operation_id: str,
        token: str,
        case_id: str,
        role_id: int,
        now: datetime,
    ) -> bool:
        expected_key = f"role-release:{case_id}:{role_id}"
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                """UPDATE detection_operations
                   SET effect_started_at = COALESCE(effect_started_at, ?)
                   WHERE operation_id = ? AND case_id = ?
                     AND operation_type = 'role_release' AND idempotency_key = ?
                     AND status = 'running' AND claim_token = ?
                     AND EXISTS (
                       SELECT 1 FROM detection_role_ownership
                       WHERE detection_role_ownership.case_id = ?
                         AND detection_role_ownership.role_id = ?
                     )""",
                (
                    _to_timestamp(now),
                    operation_id,
                    case_id,
                    expected_key,
                    token,
                    case_id,
                    role_id,
                ),
            )
            return result.rowcount == 1

    def operation_effect_started(self, operation_id: str) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT effect_started_at FROM detection_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            return row is not None and row[0] is not None

    def fail_operation(
        self, operation_id: str, token: str, error: str, now: datetime,
        retry_at: datetime | None, result: str | None = None,
    ) -> bool:
        status = OperationStatus.FAILED if retry_at is not None else OperationStatus.ABANDONED
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE detection_operations
                   SET status = ?, updated_at = ?, retry_at = ?, last_error = ?,
                       result = ?, claim_token = NULL, claimed_at = NULL
                   WHERE operation_id = ? AND status = 'running' AND claim_token = ?""",
                (
                    status.value,
                    _to_timestamp(now),
                    _to_timestamp(retry_at) if retry_at is not None else None,
                    error[:1000],
                    result,
                    operation_id,
                    token,
                ),
            )
            return result.rowcount == 1

    def record_operational_failure(
        self,
        *,
        guild_id: int,
        source: str,
        summary: str,
        occurred_at: datetime,
        case_id: str | None = None,
        operation_id: str | None = None,
    ) -> OperationalFailureRecord:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT * FROM operational_failures
                   WHERE guild_id = ? AND source = ?
                     AND COALESCE(operation_id, '') = COALESCE(?, '')
                     AND COALESCE(case_id, '') = COALESCE(?, '')
                     AND resolved_at IS NULL""",
                (guild_id, source, operation_id, case_id),
            ).fetchone()
            timestamp = _to_timestamp(occurred_at)
            if row is None:
                failure_id = str(uuid4())
                connection.execute(
                    """INSERT INTO operational_failures
                       (failure_id, guild_id, source, summary, first_seen_at,
                        last_seen_at, occurrences, case_id, operation_id)
                       VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                    (
                        failure_id,
                        guild_id,
                        source,
                        summary[:1000],
                        timestamp,
                        timestamp,
                        case_id,
                        operation_id,
                    ),
                )
            else:
                failure_id = row["failure_id"]
                connection.execute(
                    """UPDATE operational_failures
                       SET summary = ?, last_seen_at = ?, occurrences = occurrences + 1,
                           acknowledged_at = NULL
                       WHERE failure_id = ?""",
                    (summary[:1000], timestamp, failure_id),
                )
            return self._operational_failure_from_row(
                connection.execute(
                    "SELECT * FROM operational_failures WHERE failure_id = ?",
                    (failure_id,),
                ).fetchone()
            )

    def resolve_operational_failure(
        self, operation_id: str, resolved_at: datetime
    ) -> bool:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE operational_failures SET resolved_at = ?
                   WHERE operation_id = ? AND resolved_at IS NULL""",
                (_to_timestamp(resolved_at), operation_id),
            )
            return result.rowcount > 0

    def list_operational_failures(
        self, guild_id: int, *, include_resolved: bool = False, limit: int = 100
    ) -> tuple[OperationalFailureRecord, ...]:
        where = "guild_id = ? AND acknowledged_at IS NULL"
        if not include_resolved:
            where += " AND resolved_at IS NULL"
        with closing(self._connect()) as connection:
            return tuple(
                self._operational_failure_from_row(row)
                for row in connection.execute(
                    f"""SELECT * FROM operational_failures WHERE {where}
                        ORDER BY last_seen_at DESC LIMIT ?""",
                    (guild_id, limit),
                )
            )

    def clear_operational_failures(self, guild_id: int, acknowledged_at: datetime) -> int:
        with closing(self._connect()) as connection, connection:
            result = connection.execute(
                """UPDATE operational_failures SET acknowledged_at = ?
                   WHERE guild_id = ? AND acknowledged_at IS NULL""",
                (_to_timestamp(acknowledged_at), guild_id),
            )
            return result.rowcount

    def _snapshot(self, connection: sqlite3.Connection, case_row: sqlite3.Row) -> CaseSnapshot:
        messages = tuple(
            self._message_from_row(row)
            for row in connection.execute(
                "SELECT * FROM detection_messages WHERE case_id = ? ORDER BY sequence",
                (case_row["case_id"],),
            )
        )
        attachments = tuple(
            self._attachment_from_row(row)
            for row in connection.execute(
                """SELECT * FROM detection_attachments
                   WHERE case_id = ? ORDER BY message_sequence, position""",
                (case_row["case_id"],),
            )
        )
        signals = tuple(
            SignalRecord(
                row["case_id"],
                row["message_sequence"],
                DetectionSignal(
                    row["detector"], row["reason"], ActionIntent(row["action"]),
                    bool(row["decisive"]), json.loads(row["metadata"]),
                ),
            )
            for row in connection.execute(
                """SELECT * FROM detection_signals
                   WHERE case_id = ? ORDER BY message_sequence, position""",
                (case_row["case_id"],),
            )
        )
        operations = tuple(
            self._operation_from_row(row)
            for row in connection.execute(
                """SELECT * FROM detection_operations
                   WHERE case_id = ? ORDER BY created_at, operation_id""",
                (case_row["case_id"],),
            )
        )
        publications = tuple(
            EvidencePublicationRecord(
                row["case_id"],
                row["batch_index"],
                row["channel_id"],
                row["message_id"],
                tuple(
                    AttachmentKey(row["case_id"], sequence, position)
                    for sequence, position in json.loads(row["attachment_keys"])
                ),
            )
            for row in connection.execute(
                """SELECT * FROM detection_evidence_publications
                   WHERE case_id = ? ORDER BY batch_index""",
                (case_row["case_id"],),
            )
        )
        subject_row = connection.execute(
            "SELECT * FROM detection_case_subjects WHERE case_id = ?",
            (case_row["case_id"],),
        ).fetchone()
        subject = (
            CaseSubjectRecord(
                case_id=subject_row["case_id"],
                display_name=subject_row["display_name"],
                avatar_url=subject_row["avatar_url"],
                account_created_at=_from_timestamp(subject_row["account_created_at"]),
                guild_joined_at=_from_timestamp(subject_row["guild_joined_at"]),
            )
            if subject_row is not None
            else None
        )
        return CaseSnapshot(
            self._case_from_row(case_row),
            messages,
            attachments,
            signals,
            operations,
            publications,
            subject,
        )

    @staticmethod
    def _case_from_row(row: sqlite3.Row) -> CaseRecord:
        return CaseRecord(
            row["case_id"], row["guild_id"], row["user_id"], CaseStatus(row["status"]),
            _from_timestamp(row["created_at"]), _from_timestamp(row["expires_at"]),
            row["resolution"], row["moderator_id"], _from_timestamp(row["resolved_at"]),
            row["review_channel_id"], row["review_message_id"],
            _from_timestamp(row["resolving_since"]), bool(row["needs_attention"]),
        )

    @staticmethod
    def _message_from_row(row: sqlite3.Row) -> MessageRecord:
        return MessageRecord(
            row["case_id"], row["sequence"], row["guild_id"], row["channel_id"],
            row["message_id"], row["content"], _from_timestamp(row["created_at"]),
            row["jump_url"], row["admitted_by"], row["capture_status"],
            DeleteStatus(row["delete_status"]), row["error"],
        )

    @staticmethod
    def _case_deletion_job_from_row(row: sqlite3.Row) -> CaseDeletionJob:
        return CaseDeletionJob(
            case_id=row["case_id"],
            guild_id=row["guild_id"],
            parent_channel_id=row["parent_channel_id"],
            summary_message_id=row["summary_message_id"],
            thread_id=row["thread_id"],
            legacy_publications=tuple(
                (int(channel_id), int(message_id))
                for channel_id, message_id in json.loads(row["legacy_publications"])
            ),
            remote_deleted=bool(row["remote_deleted"]),
            local_deleted=bool(row["local_deleted"]),
            rows_deleted=bool(row["rows_deleted"]),
            attempts=row["attempts"],
            last_error=row["last_error"],
        )

    @staticmethod
    def _projection_endpoint_from_row(row: sqlite3.Row) -> ProjectionEndpointRecord:
        return ProjectionEndpointRecord(
            row["case_id"],
            row["generation"],
            row["parent_channel_id"],
            row["summary_message_id"],
            row["thread_id"],
            row["state"],
            row["projected_revision"],
            _from_timestamp(row["last_verified_at"]),
            row["last_error"],
        )

    @staticmethod
    def _timeline_publication_from_row(row: sqlite3.Row) -> TimelinePublicationRecord:
        return TimelinePublicationRecord(
            row["logical_key"],
            row["case_id"],
            row["kind"],
            row["message_sequence"],
            row["chunk_index"],
            row["state"],
            row["revision"],
            row["channel_id"],
            row["message_id"],
            row["last_error"],
            row["claim_token"],
            _from_timestamp(row["claimed_at"]),
        )

    @staticmethod
    def _attachment_from_row(row: sqlite3.Row) -> AttachmentRecord:
        return AttachmentRecord(
            AttachmentKey(row["case_id"], row["message_sequence"], row["position"]),
            row["filename"], row["size"], row["content_type"], row["width"], row["height"],
            row["source_url"], row["evidence_path"], row["capture_status"], row["sha256"],
            row["perceptual_hash"], json.loads(row["match_metadata"]),
            row["learning_decision"], json.loads(row["learning_metadata"]), row["error"],
            row["publication_error"],
            row["description"], bool(row["spoiler"]),
        )

    @staticmethod
    def _operation_from_row(row: sqlite3.Row) -> OperationRecord:
        return OperationRecord(
            row["operation_id"], row["case_id"], row["message_sequence"],
            row["operation_type"], OperationStatus(row["status"]), row["attempts"],
            _from_timestamp(row["created_at"]), _from_timestamp(row["updated_at"]),
            _from_timestamp(row["retry_at"]), row["last_error"], row["result"],
            row["actor_id"], row["idempotency_key"],
            row["claim_token"], _from_timestamp(row["claimed_at"]),
        )

    @staticmethod
    def _operational_failure_from_row(row: sqlite3.Row) -> OperationalFailureRecord:
        return OperationalFailureRecord(
            row["failure_id"], row["guild_id"], row["source"], row["summary"],
            _from_timestamp(row["first_seen_at"]), _from_timestamp(row["last_seen_at"]),
            row["occurrences"], row["case_id"], row["operation_id"],
            _from_timestamp(row["resolved_at"]), _from_timestamp(row["acknowledged_at"]),
        )
