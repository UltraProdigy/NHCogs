"""Discord-independent review projections for persisted detection cases."""

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone

from .detection_cases import (
    AttachmentKey,
    AttachmentRecord,
    CaseSnapshot,
    CaseStatus,
    DeleteStatus,
    DetectionCaseStore,
    MessageRecord,
    OperationRecord,
    OperationStatus,
)


_DECISIONS = {
    "tp": "true_positive",
    "fp": "false_positive",
    "ignore": "ignored",
}
_IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".webp", ".gif")
_DELETE_STATUS_LABELS = {
    DeleteStatus.PENDING: "Deletion not attempted yet",
    DeleteStatus.PLANNED: "Would be deleted (dry run)",
    DeleteStatus.DELETED: "Deleted",
    DeleteStatus.ALREADY_GONE: "Already gone",
    DeleteStatus.FORBIDDEN: "Could not delete: missing permissions",
    DeleteStatus.TRANSIENT_FAILURE: "Could not delete: temporary Discord error",
}


def _message_review_line(message: MessageRecord) -> str:
    return (
        f"Message {message.sequence} in <#{message.channel_id}>: "
        f"{_DELETE_STATUS_LABELS[message.delete_status]}"
    )


def _cached_purge_status(operation: OperationRecord) -> str:
    delete_status = next(
        (status for status in DeleteStatus if status.value == operation.result),
        None,
    )
    if delete_status is not None:
        return _DELETE_STATUS_LABELS[delete_status]
    if operation.result == "channel_unavailable":
        return "Could not delete: channel unavailable"
    if operation.result == "unsupported_channel":
        return "Could not delete: unsupported channel"
    if operation.status is OperationStatus.PENDING:
        return "Waiting for deletion"
    if operation.status is OperationStatus.RUNNING:
        return "Deletion in progress"
    if operation.status in {OperationStatus.FAILED, OperationStatus.ABANDONED}:
        return "Could not complete cleanup. See bot logs"
    return "Cleanup completed"


def case_custom_id(case_id: str, group: str, action: str) -> str:
    return f"honeypot:case:{case_id}:{group}:{action}"




@dataclass(frozen=True)
class CaseFeedbackItem:
    key: AttachmentKey
    filename: str
    decision: str | None
    detector_matched: bool

    @property
    def message_sequence(self) -> int:
        return self.key.message_sequence

    @property
    def position(self) -> int:
        return self.key.position


def available_image_review_actions(
    items: tuple[CaseFeedbackItem, ...],
) -> tuple[str, ...]:
    pending = tuple(item for item in items if item.decision is None)
    if not pending:
        return ()
    if all(item.detector_matched for item in pending):
        return ("tp", "fp", "ignore")
    return ("tp", "ignore")


def validate_image_review_action(
    items: tuple[CaseFeedbackItem, ...], action: str
) -> None:
    if action == "fp" and (
        not items or not all(item.detector_matched for item in items)
    ):
        raise ValueError("FP is only available for images flagged by the detector")


def bulk_image_confirmation_label(
    items: tuple[CaseFeedbackItem, ...], action: str
) -> str:
    validate_image_review_action(items, action)
    if action == "fp":
        return "Confirm All FP"
    if all(item.detector_matched for item in items):
        return "Confirm All TP"
    return "Confirm Add all"


@dataclass(frozen=True)
class CaseReviewField:
    name: str
    value: str


@dataclass(frozen=True)
class CaseReviewProjection:
    case_id: str
    user_id: int
    status: str
    resolution: str | None
    channel_ids: tuple[int, ...]
    needs_attention: bool
    message_count: int
    expires_at: datetime
    moderation_status: str
    moderation_actions: tuple[str, ...]
    incomplete_evidence: bool
    message_lines: tuple[str, ...]
    signal_lines: tuple[str, ...]
    feedback_lines: tuple[str, ...]
    cached_purge_lines: tuple[str, ...]
    operation_warning_lines: tuple[str, ...]
    feedback_items: tuple[CaseFeedbackItem, ...]
    moderator_id: int | None
    resolved_at: datetime | None
    title: str
    description: str
    thumbnail_url: str | None
    fields: tuple[CaseReviewField, ...]
    pages: tuple[tuple[CaseReviewField, ...], ...]


@dataclass(frozen=True)
class TimelineAttachmentProjection:
    key: AttachmentKey
    filename: str
    size: int
    content_type: str | None
    description: str | None
    spoiler: bool
    evidence_path: str | None
    capture_status: str
    publication_error: str | None
    match_metadata: Mapping[str, object]
    learning_decision: str | None


@dataclass(frozen=True)
class TimelineMessageProjection:
    sequence: int
    channel_id: int
    source_message_id: int
    created_at: datetime
    content: str
    jump_url: str | None
    delete_status: str
    signal_reasons: tuple[str, ...]
    attachments: tuple[TimelineAttachmentProjection, ...]


@dataclass(frozen=True)
class CaseTimelineProjection:
    case_id: str
    messages: tuple[TimelineMessageProjection, ...]
    case_notes: tuple[str, ...]


class CaseReviewService:
    """Async public boundary for idempotent persisted moderator decisions."""

    def __init__(self, store: DetectionCaseStore) -> None:
        self._store = store

    async def apply_bulk(
        self,
        case_id: str,
        action: str,
        moderator_id: int,
        *,
        expected_keys: tuple[AttachmentKey, ...] | None = None,
    ) -> CaseSnapshot:
        decision = self._decision(action)
        snapshot = await self._snapshot(case_id)
        feedback_items = case_feedback_items(snapshot)
        feedback_items = self._expected_items(feedback_items, expected_keys)
        pending = tuple(item for item in feedback_items if item.decision is None)
        if pending:
            validate_image_review_action(pending, action)
        decisions = {
            item.key: decision
            for item in pending
        }
        if not decisions:
            if feedback_items and all(
                item.decision == decision for item in feedback_items
            ):
                return snapshot
            raise ValueError("case has no unresolved image evidence")
        await asyncio.to_thread(
            self._store.apply_attachment_decisions,
            case_id,
            decisions,
            moderator_id,
            datetime.now(timezone.utc),
        )
        return await self._snapshot(case_id)


    async def apply_message(
        self,
        case_id: str,
        message_sequence: int,
        action: str,
        moderator_id: int,
        *,
        expected_keys: tuple[AttachmentKey, ...] | None = None,
    ) -> CaseSnapshot:
        decision = self._decision(action)
        snapshot = await self._snapshot(case_id)
        feedback_items = tuple(
            item
            for item in case_feedback_items(snapshot)
            if item.message_sequence == message_sequence
        )
        feedback_items = self._expected_items(feedback_items, expected_keys)
        pending = tuple(item for item in feedback_items if item.decision is None)
        if pending:
            validate_image_review_action(pending, action)
        decisions = {
            item.key: decision
            for item in pending
        }
        if not decisions:
            if feedback_items and all(
                item.decision == decision for item in feedback_items
            ):
                return snapshot
            raise ValueError("message has no unresolved image evidence")
        await asyncio.to_thread(
            self._store.apply_attachment_decisions,
            case_id,
            decisions,
            moderator_id,
            datetime.now(timezone.utc),
        )
        return await self._snapshot(case_id)

    async def apply_individual(
        self, key: AttachmentKey, action: str, moderator_id: int
    ) -> CaseSnapshot:
        snapshot = await self._snapshot(key.case_id)
        item = next(
            (item for item in case_feedback_items(snapshot) if item.key == key),
            None,
        )
        if item is None:
            raise ValueError("attachment is not captured image evidence")
        validate_image_review_action((item,), action)
        await asyncio.to_thread(
            self._store.apply_attachment_decisions,
            key.case_id,
            {key: self._decision(action)},
            moderator_id,
            datetime.now(timezone.utc),
        )
        return await self._snapshot(key.case_id)

    async def _snapshot(self, case_id: str) -> CaseSnapshot:
        snapshot = await asyncio.to_thread(self._store.get_case, case_id)
        if snapshot is None:
            raise KeyError(case_id)
        return snapshot

    @staticmethod
    def _expected_items(
        items: tuple[CaseFeedbackItem, ...],
        expected_keys: tuple[AttachmentKey, ...] | None,
    ) -> tuple[CaseFeedbackItem, ...]:
        if expected_keys is None:
            return items
        expected = set(expected_keys)
        selected = tuple(item for item in items if item.key in expected)
        if {item.key for item in selected} != expected:
            raise ValueError("confirmed image evidence is no longer available")
        return selected

    @staticmethod
    def _decision(action: str) -> str:
        try:
            return _DECISIONS[action]
        except KeyError as error:
            raise ValueError(f"unknown case review action: {action}") from error


def is_persisted_image_attachment(attachment: AttachmentRecord) -> bool:
    content_type = (attachment.content_type or "").lower()
    return content_type.startswith("image/") or attachment.filename.lower().endswith(
        _IMAGE_EXTENSIONS
    )


def case_feedback_items(snapshot: CaseSnapshot) -> tuple[CaseFeedbackItem, ...]:
    """Return captured image evidence in stable case/message/position order."""

    return tuple(
        CaseFeedbackItem(
            attachment.key,
            attachment.filename,
            attachment.learning_decision,
            bool(attachment.match_metadata.get("matched")),
        )
        for attachment in sorted(
            (
                attachment
                for attachment in snapshot.attachments
                if attachment.capture_status == "captured"
                and attachment.evidence_path is not None
                and is_persisted_image_attachment(attachment)
            ),
            key=lambda item: (item.message_sequence, item.position),
        )
    )


def _signal_reason(detector: str, reason: str) -> str:
    if (
        detector == "honeypot"
        and reason == "Message posted in a configured honeypot channel"
    ):
        return "Posted in honeypot channel"
    return reason


def render_timeline(snapshot: CaseSnapshot) -> CaseTimelineProjection:
    """Project the complete chronological case workspace from persisted state."""

    attachments_by_message: dict[int, list[AttachmentRecord]] = {}
    for attachment in sorted(
        snapshot.attachments,
        key=lambda item: (item.message_sequence, item.position),
    ):
        attachments_by_message.setdefault(attachment.message_sequence, []).append(attachment)

    reasons_by_message: dict[int, list[str]] = {}
    for signal in snapshot.signals:
        reason = _signal_reason(signal.signal.detector, signal.signal.reason)
        reasons = reasons_by_message.setdefault(signal.message_sequence, [])
        if reason not in reasons:
            reasons.append(reason)

    messages = tuple(
        TimelineMessageProjection(
            sequence=message.sequence,
            channel_id=message.channel_id,
            source_message_id=message.message_id,
            created_at=message.created_at,
            content=message.content,
            jump_url=message.jump_url,
            delete_status=_DELETE_STATUS_LABELS[message.delete_status],
            signal_reasons=tuple(reasons_by_message.get(message.sequence, ())),
            attachments=tuple(
                TimelineAttachmentProjection(
                    key=attachment.key,
                    filename=attachment.filename,
                    size=attachment.size,
                    content_type=attachment.content_type,
                    description=attachment.description,
                    spoiler=attachment.spoiler,
                    evidence_path=attachment.evidence_path,
                    capture_status=attachment.capture_status,
                    publication_error=attachment.publication_error,
                    match_metadata=attachment.match_metadata,
                    learning_decision=attachment.learning_decision,
                )
                for attachment in attachments_by_message.get(message.sequence, ())
            ),
        )
        for message in sorted(snapshot.messages, key=lambda item: item.sequence)
    )
    cached_purge_notes = tuple(
        f"Cached purge {index}: <#{operation.idempotency_key.rsplit(':', 2)[-2]}>: "
        f"{_cached_purge_status(operation)}"
        for index, operation in enumerate(
            (
                operation
                for operation in snapshot.operations
                if operation.operation_type == "cached_purge"
                and operation.status.value in {"failed", "abandoned"}
            ),
            start=1,
        )
    )
    operation_notes = tuple(
        _operation_warning(operation)
        for operation in snapshot.operations
        if operation.result == "ambiguous_role_ownership"
        or (
            operation.operation_type
            in {
                "review_publish",
                "role_release",
                "moderation_action",
                "moderator_ban",
                "moderator_kick",
            }
            and operation.status.value in {"failed", "abandoned"}
        )
    )
    case_notes = cached_purge_notes + operation_notes
    return CaseTimelineProjection(snapshot.case.case_id, messages, case_notes)


def _resolution_label(resolution: str) -> str:
    labels = {
        "ignore": "Ignored",
        "kick": "Kicked",
        "ban": "Banned",
        "images:tp": "Images marked true positive",
        "images:fp": "Images marked false positive",
        "images:ignore": "Images ignored",
    }
    return labels.get(resolution, resolution.replace("_", " ").capitalize())


def _operation_warning(operation: OperationRecord) -> str:
    if operation.result == "ambiguous_role_ownership":
        return (
            "Bot could not confirm that this case applied the temporary mute role. "
            "Review it manually."
        )
    if operation.operation_type == "role_release":
        return "Temporary mute could not be removed. See bot logs."
    if operation.operation_type in {"moderation_action", "moderator_ban", "moderator_kick"}:
        return "Moderation action failed. See bot logs."
    return "Case publication failed. See bot logs."


def _publication_warning(attachment: AttachmentRecord) -> str:
    error = attachment.publication_error or ""
    if "review destination upload limit" in error:
        return f"{attachment.filename}: {error}"
    return f"{attachment.filename}: Could not publish evidence. See bot logs."


def render_case(snapshot: CaseSnapshot) -> CaseReviewProjection:
    """Build the complete Discord-agnostic representation of one case snapshot."""

    channel_ids = tuple(dict.fromkeys(message.channel_id for message in snapshot.messages))
    needs_attention = snapshot.case.needs_attention or any(
        message.delete_status is DeleteStatus.FORBIDDEN for message in snapshot.messages
    )
    message_lines = tuple(_message_review_line(message) for message in snapshot.messages)
    signal_lines_list: list[str] = []
    seen_reasons: set[str] = set()
    for message in snapshot.messages:
        for signal in snapshot.signals:
            reason = _signal_reason(signal.signal.detector, signal.signal.reason)
            if signal.message_sequence != message.sequence or reason in seen_reasons:
                continue
            seen_reasons.add(reason)
            signal_lines_list.append(f"<#{message.channel_id}>: {reason}")
    signal_lines = tuple(signal_lines_list)
    moderation_operations = tuple(
        operation
        for operation in snapshot.operations
        if operation.operation_type == "moderation_action"
        or operation.operation_type
        in {"moderator_ban", "moderator_kick", "moderator_ignore"}
    )
    moderation_actions = ("ban", "kick", "ignore")
    if moderation_operations:
        moderation = moderation_operations[-1]
        action = moderation.result
        if action is None and moderation.operation_type.startswith("moderator_"):
            action = moderation.operation_type.removeprefix("moderator_")
        if moderation.result is not None and moderation.result.startswith("planned_"):
            moderation_status = (
                moderation.result.removeprefix("planned_").capitalize()
                + " planned (dry run)"
            )
        elif moderation.status is OperationStatus.SUCCEEDED:
            moderation_status = (action or "action").replace("_", " ").capitalize()
            moderation_actions = ()
        elif moderation.status in {OperationStatus.FAILED, OperationStatus.ABANDONED}:
            moderation_status = "Action failed. See bot logs"
            if (
                moderation.status is OperationStatus.FAILED
                and moderation.operation_type in {"moderator_ban", "moderator_kick"}
            ):
                moderation_actions = (
                    moderation.operation_type.removeprefix("moderator_"),
                )
            elif not (
                moderation.status is OperationStatus.ABANDONED
                and snapshot.case.status is CaseStatus.PENDING
            ):
                moderation_actions = ()
        else:
            moderation_status = "Action pending"
            moderation_actions = ()
    else:
        moderation_status = "none"
    incomplete_evidence = any(
        attachment.capture_status != "captured"
        for attachment in snapshot.attachments
    )
    feedback_items = case_feedback_items(snapshot)
    feedback_lines = tuple(
        f"{item.message_sequence}.{item.position + 1} {item.filename}: "
        f"{item.decision or 'pending'}"
        for item in feedback_items
    )
    cached_purge_operations = tuple(
        operation
        for operation in snapshot.operations
        if operation.operation_type == "cached_purge"
    )
    cached_purge_lines = tuple(
        f"{index}. <#{operation.idempotency_key.rsplit(':', 2)[-2]}>: "
        f"{_cached_purge_status(operation)}"
        for index, operation in enumerate(cached_purge_operations, start=1)
    )
    publication_warning_lines = tuple(
        f"{attachment.message_sequence}.{attachment.position + 1} "
        f"{_publication_warning(attachment)}"
        for attachment in snapshot.attachments
        if attachment.publication_error is not None
    )
    operation_warning_lines = tuple(
        _operation_warning(operation)
        for operation in snapshot.operations
        if operation.result == "ambiguous_role_ownership"
        or (
            operation.operation_type
            in {
                "review_publish",
                "role_release",
                "moderation_action",
                "moderator_ban",
                "moderator_kick",
            }
            and operation.status.value in {"failed", "abandoned"}
        )
    )
    title = "Detection case"
    subject = snapshot.subject
    identity_lines = []
    identity_lines.append(f"<@{snapshot.case.user_id}> ({snapshot.case.user_id})")
    if subject is not None and subject.account_created_at is not None:
        identity_lines.append(
            f"Account created <t:{int(subject.account_created_at.timestamp())}:R>"
        )
    if subject is not None and subject.guild_joined_at is not None:
        identity_lines.append(
            f"Joined server <t:{int(subject.guild_joined_at.timestamp())}:R>"
        )
    status_labels = {
        "pending": "Open",
        "resolving": "Resolving",
        "resolved": "Closed",
        "expired": "Expired",
    }
    identity_lines.append(
        f"Status: {status_labels.get(snapshot.case.status.value, snapshot.case.status.value)}"
    )
    resolution_lines: tuple[str, ...] = ()
    if snapshot.case.resolution is not None:
        resolution_lines += (_resolution_label(snapshot.case.resolution),)
    if snapshot.case.moderator_id is not None:
        reviewer = f"<@{snapshot.case.moderator_id}> ({snapshot.case.moderator_id})"
        if snapshot.case.resolved_at is not None:
            reviewer += f" • <t:{int(snapshot.case.resolved_at.timestamp())}:F>"
        resolution_lines += (reviewer,)
    summary_signal_lines = tuple(
        line[:300] for line in tuple(dict.fromkeys(signal_lines))[:2]
    )
    summary_publication_warnings = tuple(
        line[:300] for line in publication_warning_lines[:3]
    )
    summary_operation_warnings = tuple(
        line[:300] for line in operation_warning_lines[:3]
    )
    summary_resolution_lines = tuple(line[:300] for line in resolution_lines[:2])
    optional_fields: list[CaseReviewField] = []
    if moderation_status != "none":
        optional_fields.append(CaseReviewField("Moderation:", moderation_status))
    if sum(item.decision is None for item in feedback_items) > 25:
        optional_fields.append(CaseReviewField(
            "Review required:",
            "Too many images for one menu\nReview them in the thread",
        ))
    if incomplete_evidence:
        optional_fields.append(CaseReviewField("Evidence:", "Capture incomplete"))
    warning_lines = summary_publication_warnings + summary_operation_warnings
    if needs_attention:
        warning_lines += ("Staff attention required",)
    if warning_lines:
        optional_fields.extend(_field_chunks("Warnings:", warning_lines))
    standard_lines = [f"Messages: {len(snapshot.messages)}"]
    if snapshot.case.status.value in {"pending", "resolving"}:
        standard_lines.append(
            f"Expires: <t:{int(snapshot.case.expires_at.timestamp())}:R>"
        )
    standard_lines.append("")
    if summary_signal_lines:
        standard_lines.append("Signals:")
        standard_lines.extend(summary_signal_lines)
    description = "\n".join(identity_lines + standard_lines)[:4096]
    pages = _bounded_field_pages(
        (),
        (),
        (),
        (),
        (),
        (),
        summary_resolution_lines,
        needs_attention,
        "",
        tuple(optional_fields),
    )
    return CaseReviewProjection(
        case_id=snapshot.case.case_id,
        user_id=snapshot.case.user_id,
        status=snapshot.case.status.value,
        resolution=snapshot.case.resolution,
        channel_ids=channel_ids,
        needs_attention=needs_attention,
        message_count=len(snapshot.messages),
        expires_at=snapshot.case.expires_at,
        moderation_status=moderation_status,
        moderation_actions=moderation_actions,
        incomplete_evidence=incomplete_evidence,
        message_lines=message_lines,
        signal_lines=signal_lines,
        feedback_lines=feedback_lines,
        cached_purge_lines=cached_purge_lines,
        operation_warning_lines=operation_warning_lines,
        feedback_items=feedback_items,
        moderator_id=snapshot.case.moderator_id,
        resolved_at=snapshot.case.resolved_at,
        title=title,
        description=description,
        thumbnail_url=subject.avatar_url if subject is not None else None,
        fields=pages[0],
        pages=pages,
    )


def _field_chunks(name: str, lines: tuple[str, ...]) -> tuple[CaseReviewField, ...]:
    chunks: list[CaseReviewField] = []
    current: list[str] = []
    current_size = 0
    for line in lines:
        pieces = tuple(line[index : index + 1024] for index in range(0, len(line), 1024)) or ("",)
        for piece in pieces:
            added = len(piece) + (1 if current else 0)
            if current and current_size + added > 1024:
                chunks.append(CaseReviewField(name if not chunks else f"{name} (continued)", "\n".join(current)))
                current = []
                current_size = 0
                added = len(piece)
            current.append(piece)
            current_size += added
    if current:
        chunks.append(CaseReviewField(name if not chunks else f"{name} (continued)", "\n".join(current)))
    return tuple(chunks)


def _bounded_field_pages(
    signal_lines: tuple[str, ...],
    message_lines: tuple[str, ...],
    feedback_lines: tuple[str, ...],
    cached_purge_lines: tuple[str, ...],
    publication_warning_lines: tuple[str, ...],
    operation_warning_lines: tuple[str, ...],
    resolution_lines: tuple[str, ...],
    needs_attention: bool,
    case_summary: str,
    optional_fields: tuple[CaseReviewField, ...] = (),
) -> tuple[tuple[CaseReviewField, ...], ...]:
    fields: list[CaseReviewField] = []
    if case_summary:
        fields.append(CaseReviewField("Case details:", case_summary))
    if resolution_lines:
        fields.extend(_field_chunks("Resolution:", resolution_lines))
    fields.extend(optional_fields)
    for name, lines in (
        ("Signals:", signal_lines),
        ("Messages:", message_lines),
        ("Cached purge:", cached_purge_lines),
        ("Publication warnings:", publication_warning_lines),
        ("Operation warnings:", operation_warning_lines),
        ("Image feedback:", feedback_lines),
    ):
        fields.extend(_field_chunks(name, lines))
    pages: list[tuple[CaseReviewField, ...]] = []
    current: list[CaseReviewField] = []
    budget = 6000 - len("Detection case") - 4096
    for field in fields:
        size = len(field.name) + len(field.value)
        if current and (len(current) == 25 or size > budget):
            pages.append(tuple(current))
            current = []
            budget = 6000 - len("Detection case") - 4096
        current.append(field)
        budget -= size
    if current:
        pages.append(tuple(current))
    return tuple(pages or ((),))
