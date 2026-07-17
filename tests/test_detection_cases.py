from importlib import util
from contextlib import closing
from pathlib import Path
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from zoneinfo import ZoneInfo
from tempfile import TemporaryDirectory
from threading import Barrier, Event
import sqlite3
import sys
import unittest
from unittest import mock

from tests.detection_case_fixtures import capture_attachment, publish_primary


MODULE_PATH = Path(__file__).resolve().parents[1] / "Honeypot" / "detection_cases.py"
spec = util.spec_from_file_location("detection_cases_under_test", MODULE_PATH)
detection_cases_under_test = util.module_from_spec(spec)
sys.modules[spec.name] = detection_cases_under_test
assert spec.loader is not None
spec.loader.exec_module(detection_cases_under_test)


AttachmentKey = detection_cases_under_test.AttachmentKey
CaseStatus = detection_cases_under_test.CaseStatus
ActionIntent = detection_cases_under_test.ActionIntent
DeleteStatus = detection_cases_under_test.DeleteStatus
OperationStatus = detection_cases_under_test.OperationStatus
ACTION_PRIORITY = detection_cases_under_test.ACTION_PRIORITY
DetectionSignal = detection_cases_under_test.DetectionSignal
effective_action = detection_cases_under_test.effective_action
new_case_expiry = detection_cases_under_test.new_case_expiry
_to_timestamp = detection_cases_under_test._to_timestamp
_from_timestamp = detection_cases_under_test._from_timestamp
CaseRecord = detection_cases_under_test.CaseRecord
MessageRecord = detection_cases_under_test.MessageRecord
AttachmentRecord = detection_cases_under_test.AttachmentRecord
OperationRecord = detection_cases_under_test.OperationRecord
NewAttachment = detection_cases_under_test.NewAttachment
NewMessage = detection_cases_under_test.NewMessage
AppendResult = detection_cases_under_test.AppendResult
SignalRecord = detection_cases_under_test.SignalRecord
CaseSnapshot = detection_cases_under_test.CaseSnapshot
DetectionCaseStore = detection_cases_under_test.DetectionCaseStore
ResolutionLease = detection_cases_under_test.ResolutionLease


class DetectionCaseDomainTests(unittest.TestCase):
    def test_attachment_identity_uses_message_sequence_and_position(self):
        self.assertNotEqual(
            AttachmentKey("case-1", 1, 0),
            AttachmentKey("case-1", 2, 0),
        )
        self.assertNotEqual(
            AttachmentKey("case-1", 1, 0),
            AttachmentKey("case-1", 1, 1),
        )

    def test_enum_values_are_stable_storage_vocabulary(self):
        self.assertEqual(
            tuple(status.value for status in CaseStatus),
            ("pending", "resolving", "resolved", "expired"),
        )
        self.assertEqual(
            tuple(action.value for action in ActionIntent),
            ("none", "review", "kick", "ban"),
        )
        self.assertEqual(
            tuple(status.value for status in DeleteStatus),
            (
                "pending",
                "planned",
                "deleted",
                "already_gone",
                "forbidden",
                "transient_failure",
            ),
        )
        self.assertEqual(
            tuple(status.value for status in OperationStatus),
            ("pending", "running", "succeeded", "failed", "abandoned"),
        )

    def test_action_priority_is_immutable(self):
        with self.assertRaises(TypeError):
            ACTION_PRIORITY[ActionIntent.NONE] = 99

    def test_case_expiry_is_exactly_24_hours_after_creation(self):
        created_at = datetime(2026, 7, 13, 12, 30, tzinfo=timezone.utc)

        self.assertEqual(
            new_case_expiry(created_at),
            created_at + timedelta(hours=24),
        )

    def test_case_expiry_rejects_naive_datetime(self):
        with self.assertRaises(ValueError):
            new_case_expiry(datetime(2026, 7, 13, 12, 30))

    def test_case_expiry_is_24_elapsed_hours_across_dst_transition(self):
        created_at = datetime(2026, 3, 28, 12, tzinfo=ZoneInfo("Europe/Warsaw"))

        expiry = new_case_expiry(created_at)

        self.assertEqual(
            expiry.astimezone(timezone.utc) - created_at.astimezone(timezone.utc),
            timedelta(hours=24),
        )

    def test_timestamp_roundtrip_preserves_microseconds_far_from_epoch(self):
        value = datetime(3000, 1, 1, 0, 0, 0, 999999, tzinfo=timezone.utc)

        self.assertEqual(_from_timestamp(_to_timestamp(value)), value)

    def test_strongest_signal_selects_one_action(self):
        signals = (
            DetectionSignal("spam", "duplicate", ActionIntent.REVIEW, True, {}),
            DetectionSignal("image", "known TP", ActionIntent.BAN, True, {}),
            DetectionSignal("firstpost", "new account", ActionIntent.KICK, True, {}),
        )

        self.assertEqual(effective_action(signals), ActionIntent.BAN)

    def test_signal_metadata_is_a_recursive_defensive_copy(self):
        metadata = {
            "matches": [{"distance": 2}],
            "labels": {"known", "scam"},
        }
        signal = DetectionSignal(
            "image", "known TP", ActionIntent.BAN, True, metadata,
        )

        metadata["matches"][0]["distance"] = 99
        metadata["matches"].append({"distance": 3})
        metadata["labels"].add("changed")

        self.assertEqual(signal.metadata["matches"][0]["distance"], 2)
        self.assertEqual(len(signal.metadata["matches"]), 1)
        self.assertNotIn("changed", signal.metadata["labels"])
        with self.assertRaises(TypeError):
            signal.metadata["new"] = True
        with self.assertRaises(TypeError):
            signal.metadata["matches"][0]["distance"] = 7
        with self.assertRaises(AttributeError):
            signal.metadata["matches"].append({"distance": 4})

    def test_none_does_not_override_review(self):
        signals = (
            DetectionSignal("image", "logged only", ActionIntent.NONE, True, {}),
            DetectionSignal("firstpost", "first message", ActionIntent.REVIEW, True, {}),
        )

        self.assertEqual(effective_action(signals), ActionIntent.REVIEW)

    def test_empty_signals_have_no_action(self):
        self.assertEqual(effective_action(()), ActionIntent.NONE)

    def test_case_records_are_immutable_lifecycle_snapshots(self):
        created_at = datetime(2026, 7, 13, tzinfo=timezone.utc)
        case = CaseRecord(
            case_id="case-1",
            guild_id=10,
            user_id=20,
            status=CaseStatus.PENDING,
            created_at=created_at,
            expires_at=created_at + timedelta(hours=24),
            resolution=None,
            moderator_id=None,
            resolved_at=None,
            review_channel_id=None,
            review_message_id=None,
            resolving_since=None,
            needs_attention=False,
        )

        with self.assertRaises(FrozenInstanceError):
            case.status = CaseStatus.RESOLVED

    def test_message_records_keep_case_local_order_and_discord_identity(self):
        created_at = datetime(2026, 7, 13, tzinfo=timezone.utc)
        message = MessageRecord(
            case_id="case-1",
            sequence=2,
            guild_id=10,
            channel_id=30,
            message_id=40,
            content="evidence",
            created_at=created_at,
            jump_url="https://discord.test/messages/40",
            admitted_by="spam",
            capture_status="captured",
            delete_status=DeleteStatus.DELETED,
            error=None,
        )

        self.assertEqual((message.sequence, message.message_id), (2, 40))
        with self.assertRaises(FrozenInstanceError):
            message.delete_status = DeleteStatus.FORBIDDEN

    def test_attachment_records_keep_ordered_identity_and_evidence_results(self):
        attachment = AttachmentRecord(
            key=AttachmentKey("case-1", 2, 1),
            filename="proof.png",
            size=123,
            content_type="image/png",
            width=640,
            height=480,
            source_url="https://cdn/proof",
            evidence_path="case-1/2-1.png",
            capture_status="captured",
            sha256="abc",
            perceptual_hash="def",
            match_metadata={"distance": 2},
            learning_decision=None,
            learning_metadata={},
            error=None,
        )

        self.assertEqual(attachment.key, AttachmentKey("case-1", 2, 1))
        with self.assertRaises(FrozenInstanceError):
            attachment.capture_status = "capture_failed"

    def test_attachment_mapping_fields_are_recursive_defensive_copies(self):
        match_metadata = {"matches": [{"distance": 2}]}
        learning_metadata = {"labels": ["known"]}
        attachment = AttachmentRecord(
            key=AttachmentKey("case-1", 2, 1),
            filename="proof.png",
            size=123,
            content_type="image/png",
            width=None,
            height=None,
            source_url="https://cdn/proof",
            evidence_path=None,
            capture_status="pending",
            sha256=None,
            perceptual_hash=None,
            match_metadata=match_metadata,
            learning_decision=None,
            learning_metadata=learning_metadata,
            error=None,
        )

        match_metadata["matches"][0]["distance"] = 99
        learning_metadata["labels"].append("changed")

        self.assertEqual(attachment.match_metadata["matches"][0]["distance"], 2)
        self.assertEqual(attachment.learning_metadata["labels"], ("known",))


        with self.assertRaises(TypeError):
            attachment.match_metadata["matches"][0]["distance"] = 7
        with self.assertRaises(AttributeError):
            attachment.learning_metadata["labels"].append("other")

    def test_operation_records_keep_idempotent_attempt_results(self):
        started_at = datetime(2026, 7, 13, tzinfo=timezone.utc)
        operation = OperationRecord(
            operation_id="op-1",
            case_id="case-1",
            message_sequence=2,
            operation_type="delete",
            status=OperationStatus.FAILED,
            attempts=2,
            created_at=started_at,
            updated_at=started_at,
            retry_at=started_at + timedelta(minutes=1),
            last_error="temporary outage",
            result=None,
            actor_id=None,
            idempotency_key="delete:case-1:2",
            claim_token=None,
            claimed_at=None,
        )

        self.assertEqual((operation.status, operation.attempts), (OperationStatus.FAILED, 2))
        with self.assertRaises(FrozenInstanceError):
            operation.attempts = 3

    def test_new_message_keeps_ordered_attachment_input(self):
        created_at = datetime(2026, 7, 13, tzinfo=timezone.utc)
        attachments = (
            NewAttachment(0, "one.png", 100, "image/png", 10, 20, "https://cdn/one"),
            NewAttachment(1, "one.png", 100, "image/png", 10, 20, "https://cdn/two"),
        )
        message = NewMessage(
            guild_id=10,
            user_id=20,
            channel_id=30,
            message_id=40,
            content="evidence",
            created_at=created_at,
            jump_url=None,
            attachments=attachments,
        )

        self.assertEqual(message.attachments, attachments)
        self.assertEqual(tuple(item.position for item in message.attachments), (0, 1))
        with self.assertRaises(FrozenInstanceError):
            message.content = "changed"

    def test_append_result_and_snapshot_preserve_identity_and_signal_ownership(self):
        created_at = datetime(2026, 7, 13, tzinfo=timezone.utc)
        case = CaseRecord(
            "case-1", 10, 20, CaseStatus.PENDING, created_at,
            created_at + timedelta(hours=24), None, None, None, None, None, None, False,
        )
        message = MessageRecord(
            "case-1", 1, 10, 30, 40, "evidence", created_at, None,
            "spam", "pending", DeleteStatus.PENDING, None,
        )
        signal = SignalRecord(
            case_id="case-1",
            message_sequence=1,
            signal=DetectionSignal("spam", "duplicate", ActionIntent.REVIEW, True, {}),
        )
        append = AppendResult(case=case, message=message, case_created=True, message_created=False)
        snapshot = CaseSnapshot(
            case=case,
            messages=(message,),
            attachments=(),
            signals=(signal,),
            operations=(),
        )

        self.assertFalse(append.message_created)
        self.assertEqual(snapshot.signals[0].message_sequence, snapshot.messages[0].sequence)
        with self.assertRaises(FrozenInstanceError):
            append.message_created = True


class DetectionCaseStoreTests(unittest.TestCase):
    def test_store_has_no_unfenced_fixture_mutators(self):
        self.assertEqual(
            {
                name
                for name in {
                    "update_attachment_capture",
                    "set_evidence_publication",
                    "set_review_message",
                }
                if hasattr(DetectionCaseStore, name)
            },
            set(),
        )

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.database_path = Path(self.temp_dir.name) / "cases.sqlite3"
        self.store = DetectionCaseStore(self.database_path)
        self.store.initialize()

    def test_case_subject_identity_survives_store_restart(self):
        now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
        message = NewMessage(
            guild_id=10,
            user_id=20,
            channel_id=30,
            message_id=40,
            content="evidence",
            created_at=now,
            jump_url=None,
            attachments=(),
            display_name="Suspicious User",
            avatar_url="https://cdn.discord.test/avatar.png",
            account_created_at=now - timedelta(days=2),
            guild_joined_at=now - timedelta(hours=1),
        )
        case = self.store.append_message(message, ()).case

        reopened = DetectionCaseStore(self.database_path)
        reopened.initialize()
        subject = reopened.get_case(case.case_id).subject

        self.assertEqual(subject.display_name, "Suspicious User")
        self.assertEqual(subject.avatar_url, "https://cdn.discord.test/avatar.png")
        self.assertEqual(subject.account_created_at, now - timedelta(days=2))
        self.assertEqual(subject.guild_joined_at, now - timedelta(hours=1))

    def message(
        self, message_id, created_at, *, user_id=20, content="evidence", attachments=()
    ):
        return NewMessage(
            guild_id=10,
            user_id=user_id,
            channel_id=30,
            message_id=message_id,
            content=content,
            created_at=created_at,
            jump_url=f"https://discord.test/messages/{message_id}",
            attachments=attachments,
        )

    def test_late_message_preserves_completed_ignore_until_evidence_finishes(self):
        now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0,
            "proof.png",
            128,
            "image/png",
            32,
            16,
            "https://cdn.test/proof.png",
        )
        first = self.store.append_message(
            self.message(40, now, attachments=(attachment,)),
            (),
        )
        ignored = self.store.record_moderator_ignore(
            first.case.case_id,
            99,
            now + timedelta(seconds=1),
        )

        second = self.store.append_message(
            self.message(41, now + timedelta(seconds=2)),
            (),
        )
        waiting = self.store.get_case(first.case.case_id)

        self.assertEqual(ignored.result, "ignore")
        self.assertEqual(second.case.case_id, first.case.case_id)
        self.assertEqual(waiting.case.status, CaseStatus.RESOLVING)
        self.assertIn(
            ignored.operation_id,
            {operation.operation_id for operation in waiting.operations},
        )

        self.store.fail_pending_attachment_captures(
            first.case.case_id,
            first.message.sequence,
            "capture failed",
        )
        reconciled = self.store.reconcile_moderator_actions(
            now + timedelta(seconds=3)
        )
        resolved = self.store.get_case(first.case.case_id)

        self.assertEqual(reconciled, (first.case.case_id,))
        self.assertEqual(resolved.case.status, CaseStatus.RESOLVED)
        self.assertEqual(resolved.case.resolution, "ignore")

    def test_attachment_description_and_spoiler_survive_store_roundtrip(self):
        now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0,
            "warning.png",
            128,
            "image/png",
            32,
            16,
            "https://cdn.test/warning.png",
            description="suspicious payment form",
            spoiler=True,
        )

        appended = self.store.append_message(
            self.message(40, now, attachments=(attachment,)),
            (),
        )
        stored = self.store.get_case(appended.case.case_id).attachments[0]

        self.assertEqual(stored.description, "suspicious payment form")
        self.assertTrue(stored.spoiler)

    def test_initialize_adds_attachment_metadata_columns_to_existing_database(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.sqlite3"
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            connection.execute(
                """CREATE TABLE detection_attachments (
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
                    PRIMARY KEY(case_id, message_sequence, position)
                )"""
            )

        DetectionCaseStore(legacy_path).initialize()

        with closing(sqlite3.connect(legacy_path)) as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(detection_attachments)")
            }
        self.assertIn("description", columns)
        self.assertIn("spoiler", columns)

    def test_projection_endpoint_survives_store_restart(self):
        now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
        case = self.store.append_message(self.message(40, now), ()).case

        initial = self.store.ensure_projection_endpoint(case.case_id)
        active = self.store.activate_projection_endpoint(
            case.case_id,
            parent_channel_id=50,
            summary_message_id=60,
            thread_id=60,
            projected_revision=3,
            verified_at=now,
        )
        restarted = DetectionCaseStore(self.database_path)
        restarted.initialize()

        self.assertEqual(initial.state, "unpublished")
        self.assertEqual(active.generation, 1)
        self.assertEqual(active.summary_message_id, 60)
        self.assertEqual(active.thread_id, 60)
        self.assertEqual(restarted.ensure_projection_endpoint(case.case_id), active)

    def test_timeline_publications_use_semantic_identity_and_case_order(self):
        now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
        case = self.store.append_message(self.message(40, now), ()).case
        self.store.append_message(self.message(41, now + timedelta(seconds=1)), ())

        second = self.store.ensure_timeline_publication(
            case.case_id,
            kind="message",
            message_sequence=2,
        )
        first = self.store.ensure_timeline_publication(
            case.case_id,
            kind="message",
            message_sequence=1,
        )
        duplicate = self.store.ensure_timeline_publication(
            case.case_id,
            kind="message",
            message_sequence=1,
        )
        claimed = self.store.claim_timeline_publication(first.logical_key, now)
        self.assertIsNotNone(claimed)
        completed = self.store.complete_timeline_publication(
            first.logical_key,
            claimed.claim_token,
            channel_id=60,
            message_id=70,
            revision=2,
        )

        self.assertEqual(first, duplicate)
        self.assertEqual(first.logical_key, f"case:{case.case_id}:message:1")
        self.assertEqual(second.logical_key, f"case:{case.case_id}:message:2")
        self.assertEqual(completed.state, "published")
        self.assertEqual(
            [entry.message_sequence for entry in self.store.list_timeline_publications(case.case_id)],
            [1, 2],
        )

    def test_deletion_tombstone_fences_late_projection_writes(self):
        now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
        case = self.store.append_message(self.message(40, now), ()).case
        self.store.ensure_projection_endpoint(case.case_id)
        publication = self.store.ensure_timeline_publication(
            case.case_id,
            kind="message",
            message_sequence=1,
        )
        primary_token = self.store.claim_publication(case.case_id, "primary", now)
        self.assertIsNotNone(primary_token)

        self.store.plan_user_case_deletion(case.user_id)

        self.assertEqual(self.store.list_due_cases(now + timedelta(days=2)), ())
        self.assertEqual(
            self.store.list_reconcilable_cases(
                now + timedelta(days=2), now + timedelta(days=1)
            ),
            (),
        )
        self.assertIsNone(self.store.claim_resolution(case.case_id, now))

        with self.assertRaises(KeyError):
            self.store.activate_projection_endpoint(
                case.case_id,
                parent_channel_id=50,
                summary_message_id=60,
                thread_id=60,
                projected_revision=1,
                verified_at=now,
            )
        with self.assertRaises(KeyError):
            self.store.ensure_timeline_publication(
                case.case_id,
                kind="evidence",
                message_sequence=1,
            )
        with self.assertRaises(KeyError):
            self.store.complete_timeline_publication(
                publication.logical_key,
                "late-worker",
                channel_id=60,
                message_id=70,
                revision=1,
            )
        self.assertFalse(
            self.store.complete_primary_publication(
                case.case_id, primary_token, 50, 60
            )
        )

    def test_deletion_ignores_publication_claims_after_their_lease_expires(self):
        now = datetime.now(timezone.utc) - timedelta(minutes=6)
        case = self.store.append_message(self.message(40, now), ()).case
        publication = self.store.ensure_timeline_publication(
            case.case_id,
            kind="message",
            message_sequence=1,
        )
        self.assertIsNotNone(
            self.store.claim_publication(case.case_id, "primary", now)
        )
        self.assertIsNotNone(
            self.store.claim_timeline_publication(publication.logical_key, now)
        )
        self.store.plan_user_case_deletion(case.user_id)

        self.assertFalse(
            self.store.case_deletion_has_inflight_publications(case.case_id)
        )

    def test_messages_for_same_member_join_one_case_with_fixed_expiry(self):
        first_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        second_at = first_at + timedelta(hours=2)

        first = self.store.append_message(self.message(40, first_at), ())
        second = self.store.append_message(self.message(41, second_at), ())
        snapshot = self.store.get_case(first.case.case_id)

        self.assertTrue(first.case_created)
        self.assertTrue(first.message_created)
        self.assertFalse(second.case_created)
        self.assertEqual(second.case.case_id, first.case.case_id)
        self.assertEqual(first.case.created_at, first_at)
        self.assertEqual(first.case.expires_at, first_at + timedelta(hours=24))
        self.assertEqual([message.sequence for message in snapshot.messages], [1, 2])

    def test_started_moderator_effect_keeps_late_evidence_admissible(self):
        now = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        first = self.store.append_message(self.message(40, now), ())
        moderator = self.store.claim_moderator_action(
            first.case.case_id, "ban", 99, now
        )
        running = self.store.claim_operation(moderator.operation_id, now)
        self.assertTrue(
            self.store.start_operation_effect(
                running.operation_id, running.claim_token, now
            )
        )
        late = self.store.append_message(
            self.message(
                41,
                now + timedelta(seconds=1),
                attachments=(
                    NewAttachment(
                        0, "late.png", 8, "image/png", None, None, "late-url"
                    ),
                ),
            ),
            (),
        )

        self.assertTrue(
            self.store.case_accepts_evidence(
                late.case.guild_id, late.case.case_id
            )
        )

    def test_stale_resolution_is_not_expired_before_fixed_case_expiry(self):
        now = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case = self.store.append_message(self.message(40, now), ()).case
        self.assertIsNotNone(self.store.claim_resolution(case.case_id, now))

        self.assertEqual(
            self.store.list_reconcilable_cases(
                now + timedelta(minutes=10),
                now + timedelta(minutes=5),
            ),
            (),
        )

    def test_duplicate_message_is_idempotent_for_whole_aggregate(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0, "proof.png", 100, "image/png", 10, 20, "https://cdn/proof"
        )
        message = self.message(40, created_at, attachments=(attachment,))
        signal = DetectionSignal(
            "spam", "known text", ActionIntent.REVIEW, True, {"matches": ["known"]}
        )

        first = self.store.append_message(message, (signal,), (("delete", "delete:10:40"),))
        duplicate = self.store.append_message(message, (signal,), (("delete", "delete:10:40"),))
        snapshot = self.store.get_case(first.case.case_id)

        self.assertFalse(duplicate.case_created)
        self.assertFalse(duplicate.message_created)
        self.assertEqual(duplicate.message.sequence, first.message.sequence)
        self.assertEqual(
            (len(snapshot.messages), len(snapshot.signals), len(snapshot.attachments), len(snapshot.operations)),
            (1, 1, 1, 1),
        )

    def test_containment_updates_are_atomic_and_refuse_second_delete_transition(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0, "proof.png", 100, "image/png", 10, 20, "https://cdn/proof"
        )
        appended = self.store.append_message(
            self.message(40, created_at, attachments=(attachment,)),
            (DetectionSignal("forward_purge", "active", ActionIntent.REVIEW, True, {}),),
        )

        self.assertTrue(
            capture_attachment(
                self.store, appended.case.case_id, 1, 0, "case/1/proof.png"
            )
        )
        self.assertTrue(
            self.store.update_attachment_scan(
                appended.case.case_id,
                1,
                0,
                "sha",
                "phash",
                {"matched": True},
                None,
            )
        )
        self.assertTrue(
            self.store.update_message_delete(
                appended.case.case_id, 1, DeleteStatus.FORBIDDEN, "denied", True
            )
        )
        self.assertFalse(
            self.store.update_message_delete(
                appended.case.case_id, 1, DeleteStatus.DELETED, None, False
            )
        )
        self.assertTrue(publish_primary(self.store, appended.case.case_id, 50, 60))
        snapshot = self.store.get_case(appended.case.case_id)
        self.assertTrue(snapshot.case.needs_attention)
        self.assertEqual(
            (snapshot.case.review_channel_id, snapshot.case.review_message_id), (50, 60)
        )
        self.assertEqual(snapshot.messages[0].delete_status, DeleteStatus.FORBIDDEN)
        self.assertEqual(snapshot.messages[0].capture_status, "captured")
        self.assertEqual(snapshot.attachments[0].evidence_path, "case/1/proof.png")
        self.assertEqual(snapshot.attachments[0].sha256, "sha")
        self.assertTrue(snapshot.attachments[0].match_metadata["matched"])
        self.assertEqual(
            [signal.signal.detector for signal in snapshot.signals],
            ["forward_purge"],
        )

    def test_failed_message_delete_can_be_completed_by_a_retry(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        appended = self.store.append_message(self.message(40, created_at), ())
        case_id = appended.case.case_id
        self.assertTrue(
            self.store.update_message_delete(
                case_id, 1, DeleteStatus.FORBIDDEN, "denied", True
            )
        )

        self.assertTrue(
            self.store.complete_message_delete_retry(
                case_id, 1, DeleteStatus.DELETED
            )
        )

        message = self.store.get_case(case_id).messages[0]
        self.assertEqual(message.delete_status, DeleteStatus.DELETED)
        self.assertIsNone(message.error)

    def test_shared_sqlite_reservations_cap_concurrent_case_evidence(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        attachment_bytes = 8 * 1024 * 1024
        attachments = tuple(
            NewAttachment(
                position,
                f"proof-{position}.png",
                attachment_bytes,
                "image/png",
                10,
                20,
                f"https://cdn/proof-{position}",
            )
            for position in range(3)
        )
        first = self.store.append_message(
            self.message(40, created_at, attachments=attachments), ()
        )
        other_store = DetectionCaseStore(self.database_path)
        second = other_store.append_message(
            self.message(41, created_at + timedelta(seconds=1), attachments=attachments),
            (),
        )
        barrier = Barrier(6)

        def reserve(item):
            store, sequence, position = item
            barrier.wait()
            return store.reserve_attachment_capture(
                first.case.case_id,
                sequence,
                position,
                attachment_bytes,
                created_at + timedelta(minutes=1),
                stale_before=created_at,
                max_attachment_bytes=attachment_bytes,
                max_case_bytes=3 * attachment_bytes,
            )

        work = tuple(
            (self.store if sequence == first.message.sequence else other_store, sequence, position)
            for sequence in (first.message.sequence, second.message.sequence)
            for position in range(3)
        )
        with ThreadPoolExecutor(max_workers=6) as executor:
            reservations = tuple(executor.map(reserve, work))

        self.assertEqual(
            sum(reservation.status == "claimed" for reservation in reservations),
            3,
        )
        self.assertEqual(
            sum(reservation.status == "too_large" for reservation in reservations),
            3,
        )

    def test_stale_evidence_reservation_can_be_reclaimed_after_restart(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0, "proof.png", 100, "image/png", 10, 20, "https://cdn/proof"
        )
        appended = self.store.append_message(
            self.message(40, created_at, attachments=(attachment,)), ()
        )
        first = self.store.reserve_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            100,
            created_at,
            stale_before=created_at - timedelta(microseconds=1),
            max_attachment_bytes=100,
            max_case_bytes=100,
        )

        reclaimed = DetectionCaseStore(self.database_path).reserve_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            100,
            created_at + timedelta(minutes=5),
            stale_before=created_at,
            max_attachment_bytes=100,
            max_case_bytes=100,
        )

        self.assertEqual(first.status, "claimed")
        self.assertEqual(reclaimed.status, "claimed")
        self.assertNotEqual(reclaimed.claim_token, first.claim_token)

    def test_wrong_token_cannot_complete_evidence_reservation(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0, "proof.png", 100, "image/png", 10, 20, "https://cdn/proof"
        )
        appended = self.store.append_message(
            self.message(40, created_at, attachments=(attachment,)), ()
        )
        reservation = self.store.reserve_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            100,
            created_at,
            stale_before=created_at - timedelta(microseconds=1),
            max_attachment_bytes=100,
            max_case_bytes=100,
        )

        rejected = self.store.complete_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            "wrong-token",
            100,
            "case/1/proof.png",
            created_at + timedelta(seconds=1),
            max_attachment_bytes=100,
            max_case_bytes=100,
        )
        accepted = self.store.complete_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            reservation.claim_token,
            100,
            "case/1/proof.png",
            created_at + timedelta(seconds=1),
            max_attachment_bytes=100,
            max_case_bytes=100,
        )

        self.assertIsNone(rejected)
        self.assertEqual(accepted, "captured")
        self.assertEqual(
            self.store.get_case(appended.case.case_id).attachments[0].evidence_path,
            "case/1/proof.png",
        )

    def test_actual_evidence_bytes_above_reservation_are_rejected(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0, "proof.png", 100, "image/png", 10, 20, "https://cdn/proof"
        )
        appended = self.store.append_message(
            self.message(40, created_at, attachments=(attachment,)), ()
        )
        reservation = self.store.reserve_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            100,
            created_at,
            stale_before=created_at - timedelta(microseconds=1),
            max_attachment_bytes=100,
            max_case_bytes=100,
        )

        result = self.store.complete_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            reservation.claim_token,
            101,
            "case/1/proof.png",
            created_at + timedelta(seconds=1),
            max_attachment_bytes=100,
            max_case_bytes=100,
        )

        stored = self.store.get_case(appended.case.case_id).attachments[0]
        self.assertEqual(result, "too_large")
        self.assertEqual(stored.capture_status, "too_large")
        self.assertIsNone(stored.evidence_path)

    def test_late_capture_completion_cannot_attach_evidence_to_resolved_case(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0, "proof.png", 100, "image/png", 10, 20, "https://cdn/proof"
        )
        appended = self.store.append_message(
            self.message(40, created_at, attachments=(attachment,)), ()
        )
        reservation = self.store.reserve_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            100,
            created_at,
            stale_before=created_at - timedelta(microseconds=1),
            max_attachment_bytes=100,
            max_case_bytes=100,
        )
        lease = self.store.claim_resolution(
            appended.case.case_id, created_at + timedelta(seconds=1)
        )
        self.assertTrue(
            self.store.finish_resolution(
                lease,
                CaseStatus.RESOLVED,
                "ignore",
                99,
                created_at + timedelta(seconds=2),
            )
        )

        result = self.store.complete_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            reservation.claim_token,
            100,
            "case/1/proof.png",
            created_at + timedelta(seconds=3),
            max_attachment_bytes=100,
            max_case_bytes=100,
        )

        stored = self.store.get_case(appended.case.case_id).attachments[0]
        self.assertIsNone(result)
        self.assertEqual(stored.capture_status, "pending")
        self.assertIsNone(stored.evidence_path)

    def test_failed_evidence_capture_releases_bytes_for_retry(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0, "proof.png", 100, "image/png", 10, 20, "https://cdn/proof"
        )
        appended = self.store.append_message(
            self.message(40, created_at, attachments=(attachment,)), ()
        )
        first = self.store.reserve_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            100,
            created_at,
            stale_before=created_at - timedelta(microseconds=1),
            max_attachment_bytes=100,
            max_case_bytes=100,
        )

        released = self.store.release_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            first.claim_token,
            "capture_failed",
            "read failed",
        )
        failed = self.store.get_case(appended.case.case_id).attachments[0]
        retried = self.store.reserve_attachment_capture(
            appended.case.case_id,
            appended.message.sequence,
            0,
            100,
            created_at + timedelta(seconds=1),
            stale_before=created_at,
            max_attachment_bytes=100,
            max_case_bytes=100,
        )

        self.assertTrue(released)
        self.assertEqual(failed.capture_status, "capture_failed")
        self.assertEqual(retried.status, "claimed")
        self.assertNotEqual(retried.claim_token, first.claim_token)

    def test_snapshot_orders_children_and_preserves_signal_ownership(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        duplicate_names = (
            NewAttachment(1, "proof.png", 200, "image/png", None, None, "https://cdn/b"),
            NewAttachment(0, "proof.png", 100, "image/png", None, None, "https://cdn/a"),
        )
        first_signal = DetectionSignal(
            "spam", "first", ActionIntent.REVIEW, True,
            {"matches": [{"distance": 2}]},
        )
        second_signal = DetectionSignal(
            "links", "second", ActionIntent.BAN, True, {"domain": "bad.test"}
        )

        first = self.store.append_message(
            self.message(40, created_at, attachments=duplicate_names),
            (first_signal,),
            (("delete", "delete:10:40"),),
        )
        self.store.append_message(
            self.message(41, created_at + timedelta(minutes=1)),
            (second_signal,),
            (("delete", "delete:10:41"),),
        )
        snapshot = self.store.get_case(first.case.case_id)

        self.assertEqual([message.sequence for message in snapshot.messages], [1, 2])
        self.assertEqual(
            [
                (item.message_sequence, item.position, item.filename, item.source_url)
                for item in snapshot.attachments
            ],
            [
                (1, 0, "proof.png", "https://cdn/a"),
                (1, 1, "proof.png", "https://cdn/b"),
            ],
        )
        self.assertEqual(
            [(item.message_sequence, item.signal.detector) for item in snapshot.signals],
            [(1, "spam"), (2, "links")],
        )
        self.assertEqual(
            [(item.message_sequence, item.idempotency_key) for item in snapshot.operations],
            [(1, "delete:10:40"), (2, "delete:10:41")],
        )
        self.assertEqual(snapshot.signals[0].signal.metadata["matches"][0]["distance"], 2)
        with self.assertRaises(TypeError):
            snapshot.signals[0].signal.metadata["matches"][0]["distance"] = 9

    def test_active_and_open_queries_return_complete_snapshots(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        signal = DetectionSignal("spam", "known", ActionIntent.REVIEW, True, {})
        result = self.store.append_message(self.message(40, created_at), (signal,))

        open_cases = self.store.list_open_cases()
        active = open_cases[0]

        self.assertEqual(active, self.store.get_case(result.case.case_id))
        self.assertEqual(open_cases, (active,))
        self.assertIsNone(self.store.get_case("missing"))

    def test_list_due_cases_uses_persisted_expiry_and_stable_order(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        first = self.store.append_message(self.message(40, created_at, user_id=20), ()).case
        tied = self.store.append_message(self.message(41, created_at, user_id=21), ()).case
        later = self.store.append_message(
            self.message(42, created_at + timedelta(seconds=1), user_id=22), ()
        ).case

        due = self.store.list_due_cases(created_at + timedelta(hours=24))

        self.assertEqual(
            due,
            tuple(sorted((first, tied), key=lambda case: (case.created_at, case.case_id))),
        )
        self.assertNotIn(later, due)

    def test_only_one_concurrent_resolver_claims_a_pending_case(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id
        claimed_at = created_at + timedelta(minutes=1)

        barrier = Barrier(2)
        def claim(_):
            barrier.wait()
            return self.store.claim_resolution(case_id, claimed_at)
        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = tuple(
                executor.map(claim, range(2))
            )

        self.assertEqual(sum(claim is not None for claim in claims), 1)
        claimed = self.store.get_case(case_id).case
        self.assertEqual(claimed.status, CaseStatus.RESOLVING)
        self.assertEqual(claimed.resolving_since, claimed_at)

    def test_resolution_claim_closes_evidence_admission(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        attachment = NewAttachment(
            0, "proof.png", 100, "image/png", 10, 20, "https://cdn/proof"
        )
        appended = self.store.append_message(
            self.message(40, created_at, attachments=(attachment,)), ()
        )

        lease = self.store.claim_resolution(appended.case.case_id, created_at)

        self.assertIsNotNone(lease)
        self.assertFalse(
            self.store.case_accepts_evidence(10, appended.case.case_id)
        )
        self.assertFalse(
            capture_attachment(
                self.store,
                appended.case.case_id,
                appended.message.sequence,
                0,
                "case/1/proof.png",
            )
        )
        attachment_record = self.store.get_case(
            appended.case.case_id
        ).attachments[0]
        self.assertEqual(attachment_record.capture_status, "pending")
        self.assertIsNone(attachment_record.evidence_path)

    def test_append_revokes_ordinary_resolution_and_stale_finisher_cannot_close_case(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        first = self.store.append_message(self.message(40, created_at), ())
        other_store = DetectionCaseStore(self.database_path)
        lease = other_store.claim_resolution(first.case.case_id, created_at)

        second = self.store.append_message(
            self.message(41, created_at + timedelta(seconds=1)), ()
        )

        self.assertIsNotNone(lease)
        self.assertFalse(second.case_created)
        self.assertEqual(second.case.case_id, first.case.case_id)
        self.assertEqual(second.case.status, CaseStatus.PENDING)
        self.assertEqual(
            [message.message_id for message in self.store.get_case(first.case.case_id).messages],
            [40, 41],
        )
        self.assertFalse(
            other_store.finish_resolution(
                lease,
                CaseStatus.RESOLVED,
                "stale",
                None,
                created_at + timedelta(seconds=2),
            )
        )
        self.assertEqual(len(self.store.list_open_cases()), 1)

    def test_append_joins_case_while_started_moderator_effect_is_in_flight(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        first = self.store.append_message(self.message(40, created_at), ())
        operation = self.store.claim_moderator_action(
            first.case.case_id, "ban", 99, created_at
        )
        operation = self.store.claim_operation(operation.operation_id, created_at)
        self.assertTrue(
            self.store.start_operation_effect(
                operation.operation_id, operation.claim_token, created_at
            )
        )
        other_store = DetectionCaseStore(self.database_path)
        def append_during_effect():
            return other_store.append_message(
                self.message(41, created_at + timedelta(seconds=1)), ()
            )

        with ThreadPoolExecutor(max_workers=1) as executor:
            pending_append = executor.submit(append_during_effect)
            second = pending_append.result(timeout=1)
            completed = self.store.complete_moderator_action(
                operation.operation_id,
                operation.claim_token,
                created_at + timedelta(seconds=2),
                "banned",
            )

        self.assertTrue(completed)
        self.assertFalse(second.case_created)
        self.assertEqual(second.case.case_id, first.case.case_id)
        self.assertEqual(
            self.store.get_case(first.case.case_id).case.status,
            CaseStatus.RESOLVED,
        )
        self.assertEqual(
            [message.message_id for message in self.store.get_case(first.case.case_id).messages],
            [40, 41],
        )
        self.assertEqual(len(self.store.list_open_cases()), 0)

    def test_append_revokes_moderator_action_before_effect_starts(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        first = self.store.append_message(self.message(40, created_at), ())
        operation = self.store.claim_moderator_action(
            first.case.case_id, "kick", 99, created_at
        )
        operation = self.store.claim_operation(operation.operation_id, created_at)

        second = DetectionCaseStore(self.database_path).append_message(
            self.message(41, created_at + timedelta(seconds=1)), ()
        )

        self.assertEqual(second.case.case_id, first.case.case_id)
        self.assertEqual(second.case.status, CaseStatus.PENDING)
        self.assertFalse(
            self.store.start_operation_effect(
                operation.operation_id,
                operation.claim_token,
                created_at + timedelta(seconds=2),
            )
        )
        stored_operation = next(
            item
            for item in self.store.get_case(first.case.case_id).operations
            if item.operation_id == operation.operation_id
        )
        self.assertEqual(stored_operation.status, OperationStatus.ABANDONED)

    def test_abandoned_pre_effect_moderator_action_can_be_replaced(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        first = self.store.append_message(self.message(40, created_at), ())
        kick = self.store.claim_moderator_action(
            first.case.case_id, "kick", 98, created_at
        )
        running_kick = self.store.claim_operation(kick.operation_id, created_at)
        DetectionCaseStore(self.database_path).append_message(
            self.message(41, created_at + timedelta(seconds=1)), ()
        )

        ban = self.store.claim_moderator_action(
            first.case.case_id, "ban", 99, created_at + timedelta(seconds=2)
        )

        self.assertIsNotNone(ban)
        self.assertNotEqual(ban.operation_id, kick.operation_id)
        self.assertEqual(ban.operation_type, "moderator_ban")
        self.assertEqual(ban.actor_id, 99)
        self.assertEqual(ban.status, OperationStatus.PENDING)
        self.assertFalse(
            self.store.start_operation_effect(
                running_kick.operation_id,
                running_kick.claim_token,
                created_at + timedelta(seconds=3),
            )
        )

    def test_resolution_claim_reclaims_a_lease_at_the_stale_boundary(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id
        first_claim = created_at + timedelta(minutes=1)
        second_claim = created_at + timedelta(minutes=5)
        first_lease = self.store.claim_resolution(case_id, first_claim)

        self.assertFalse(self.store.claim_resolution(case_id, second_claim))
        self.assertFalse(
            self.store.claim_resolution(
                case_id, second_claim, stale_before=first_claim - timedelta(microseconds=1)
            )
        )
        second_lease = self.store.claim_resolution(case_id, second_claim, stale_before=first_claim)
        self.assertIsInstance(second_lease, ResolutionLease)
        self.assertNotEqual(first_lease.token, second_lease.token)
        self.assertEqual(self.store.get_case(case_id).case.resolving_since, second_claim)

    def test_release_resolution_returns_only_a_resolving_case_to_pending(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id
        self.assertFalse(self.store.release_resolution(ResolutionLease(case_id, "bad", created_at)))
        lease = self.store.claim_resolution(case_id, created_at)

        self.assertTrue(self.store.release_resolution(lease))

        released = self.store.get_case(case_id).case
        self.assertEqual(released.status, CaseStatus.PENDING)
        self.assertIsNone(released.resolving_since)

    def test_finish_resolution_records_terminal_result_and_cannot_repeat(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id
        resolved_at = created_at + timedelta(minutes=3)
        lease = self.store.claim_resolution(case_id, created_at)

        self.assertTrue(
            self.store.finish_resolution(
                lease, CaseStatus.RESOLVED, "banned", 99, resolved_at
            )
        )
        self.assertFalse(
            self.store.finish_resolution(
                lease, CaseStatus.EXPIRED, "expired", None, resolved_at
            )
        )
        terminal = self.store.get_case(case_id).case
        self.assertEqual(
            (terminal.status, terminal.resolution, terminal.moderator_id, terminal.resolved_at),
            (CaseStatus.RESOLVED, "banned", 99, resolved_at),
        )
        self.assertIsNone(terminal.resolving_since)
        self.assertFalse(self.store.release_resolution(lease))
        self.assertFalse(self.store.claim_resolution(case_id, resolved_at))

    def test_compact_terminal_case_keeps_only_deletion_index(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        appended = self.store.append_message(
            self.message(40, created_at),
            (DetectionSignal("spam", "duplicate", ActionIntent.REVIEW, True, {}),),
        )
        case_id = appended.case.case_id
        token = self.store.claim_publication(case_id, "primary", created_at)
        self.assertTrue(
            self.store.complete_primary_publication(case_id, token, 30, 50)
        )
        self.store.activate_projection_endpoint(
            case_id,
            parent_channel_id=30,
            summary_message_id=50,
            thread_id=60,
            projected_revision=1,
            verified_at=created_at,
        )
        lease = self.store.claim_resolution(case_id, created_at)
        self.assertTrue(
            self.store.finish_resolution(
                lease, CaseStatus.RESOLVED, "ignore", 99, created_at
            )
        )

        self.assertTrue(self.store.compact_terminal_case(case_id))

        compacted = self.store.get_case(case_id)
        self.assertEqual(compacted.case.status, CaseStatus.RESOLVED)
        self.assertEqual(compacted.messages, ())
        self.assertEqual(compacted.attachments, ())
        self.assertEqual(compacted.signals, ())
        self.assertEqual(compacted.operations, ())
        self.assertEqual(compacted.case.created_at, datetime.fromtimestamp(0, timezone.utc))
        self.assertEqual(compacted.case.expires_at, datetime.fromtimestamp(0, timezone.utc))
        self.assertIsNone(compacted.case.resolution)
        self.assertIsNone(compacted.case.moderator_id)
        self.assertIsNone(compacted.case.resolved_at)
        self.assertIsNone(compacted.case.review_channel_id)
        self.assertIsNone(compacted.case.review_message_id)
        self.assertFalse(compacted.case.needs_attention)
        self.assertIsNone(compacted.subject)
        planned = self.store.plan_user_case_deletion(20)
        self.assertEqual(planned, ((10, case_id),))
        deletion = self.store.get_case_deletion_job(case_id)
        self.assertEqual(
            (
                deletion.parent_channel_id,
                deletion.summary_message_id,
                deletion.thread_id,
            ),
            (30, 50, 60),
        )

    def test_finish_resolution_rejects_non_terminal_status(self):
        with self.assertRaises(ValueError):
            self.store.finish_resolution(
                ResolutionLease("missing", "bad", datetime(2026, 7, 13, tzinfo=timezone.utc)),
                CaseStatus.PENDING, "invalid", None,
                datetime(2026, 7, 13, tzinfo=timezone.utc),
            )

    def test_stale_resolution_worker_cannot_mutate_reclaimed_lease(self):
        now = datetime(2026, 7, 13, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, now), ()).case.case_id
        old = self.store.claim_resolution(case_id, now)
        new = self.store.claim_resolution(case_id, now + timedelta(minutes=1), stale_before=now)

        self.assertFalse(self.store.release_resolution(old))
        self.assertFalse(self.store.finish_resolution(old, CaseStatus.RESOLVED, "old", 1, now))
        self.assertTrue(self.store.finish_resolution(new, CaseStatus.RESOLVED, "new", 2, now))

    def test_ensure_operation_is_idempotent(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        append = self.store.append_message(self.message(40, created_at), ())

        first = self.store.ensure_operation(
            append.case.case_id, "notify", "notify:case", append.message.sequence
        )
        duplicate = self.store.ensure_operation(
            append.case.case_id, "different-kind", "notify:case"
        )

        self.assertEqual(duplicate, first)
        self.assertEqual(first.operation_type, "notify")
        self.assertEqual(first.status, OperationStatus.PENDING)
        self.assertEqual(first.attempts, 0)
        self.assertEqual(first.created_at, first.updated_at)

    def test_publication_claim_renewal_prevents_stale_reclaim(self):
        now = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, now), ()).case.case_id
        token = self.store.claim_publication(case_id, "primary", now)

        self.assertTrue(
            self.store.renew_publication_claim(
                case_id, "primary", token, now + timedelta(minutes=6)
            )
        )
        self.assertIsNone(
            self.store.claim_publication(
                case_id, "primary", now + timedelta(minutes=10)
            )
        )
    def test_claim_due_operations_filters_schedules_orders_and_limits(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id
        operations = tuple(
            self.store.ensure_operation(case_id, "work", f"work:{index}")
            for index in range(4)
        )
        now = created_at + timedelta(minutes=10)
        first = self.store.claim_due_operations(now, limit=2)
        second = self.store.claim_due_operations(now, limit=5)

        self.assertEqual(
            tuple(operation.operation_id for operation in first),
            tuple(sorted(operation.operation_id for operation in operations)[:2]),
        )
        self.assertEqual(len(second), 2)
        self.assertTrue(all(operation.status is OperationStatus.RUNNING for operation in first + second))
        self.assertTrue(all(operation.attempts == 1 for operation in first + second))
        self.assertTrue(all(operation.updated_at == now for operation in first + second))
        self.assertEqual(self.store.claim_due_operations(now), ())

    def test_pending_operation_is_not_starved_by_a_full_failed_batch(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id
        module = sys.modules[DetectionCaseStore.__module__]
        generated_ids = []
        for index in range(50):
            generated_ids.extend(
                (
                    f"00000000-0000-0000-0000-{index:012d}",
                    f"aaaaaaaa-aaaa-aaaa-aaaa-{index:012d}",
                )
            )
        generated_ids.append("ffffffff-ffff-ffff-ffff-ffffffffffff")
        with mock.patch.object(module, "uuid4", side_effect=generated_ids):
            for index in range(50):
                operation = self.store.ensure_operation(
                    case_id, "work", f"failed:{index}"
                )
                running = self.store.claim_operation(operation.operation_id, created_at)
                self.assertTrue(
                    self.store.fail_operation(
                        running.operation_id,
                        running.claim_token,
                        "permanent",
                        created_at,
                        created_at,
                    )
                )
            pending = self.store.ensure_operation(case_id, "work", "new-pending")

        claimed = self.store.claim_due_operations(
            created_at + timedelta(seconds=1), limit=50
        )

        self.assertIn(pending.operation_id, {item.operation_id for item in claimed})

    def test_due_operations_wait_for_message_processing_dependencies(self):
        now = datetime.now(timezone.utc)
        appended = self.store.append_message(
            self.message(91, now),
            (
                DetectionSignal(
                    "spam", "automatic ban", ActionIntent.BAN, True, {}
                ),
            ),
            (
                ("review_publish", "review:{case_id}:{sequence}"),
                ("message_process", "process:{case_id}:{sequence}"),
                ("moderation_action", "moderate:{case_id}:{sequence}"),
                ("role_apply", "role-apply:{case_id}:55"),
            ),
        )

        claimed = self.store.claim_due_operations(now)

        self.assertEqual(
            [operation.operation_type for operation in claimed],
            ["message_process"],
        )

    def test_evidence_cleanup_waits_for_terminal_review_update(self):
        now = datetime.now(timezone.utc)
        appended = self.store.append_message(self.message(91, now), ())
        lease = self.store.claim_resolution(appended.case.case_id, now)
        self.assertTrue(
            self.store.finish_resolution(
                lease,
                CaseStatus.RESOLVED,
                "ignore",
                99,
                now,
                final_operations=(
                    ("review_update", f"review-update:{appended.case.case_id}"),
                    ("evidence_cleanup", f"evidence-cleanup:{appended.case.case_id}"),
                ),
            )
        )

        first = self.store.claim_due_operations(now)

        self.assertEqual(
            [operation.operation_type for operation in first],
            ["review_update"],
        )
        self.assertTrue(
            self.store.complete_operation(
                first[0].operation_id,
                first[0].claim_token,
                now,
                "updated",
            )
        )
        second = self.store.claim_due_operations(now)
        self.assertEqual(
            [operation.operation_type for operation in second],
            ["evidence_cleanup"],
        )

    def test_append_atomically_claims_firstpost_signal_with_initial_outbox(self):
        now = datetime.now(timezone.utc)
        firstpost = DetectionSignal(
            "firstpost", "suspicious first message", ActionIntent.REVIEW, True, {}
        )

        appended = self.store.append_message(
            self.message(92, now),
            (firstpost,),
            (("message_process", "process:{case_id}:{sequence}"),),
            claim_firstpost=True,
        )
        snapshot = self.store.get_case(appended.case.case_id)

        self.assertTrue(appended.firstpost_claimed)
        self.assertEqual(
            [record.signal.detector for record in snapshot.signals],
            ["firstpost"],
        )
        self.assertEqual(
            [operation.operation_type for operation in snapshot.operations],
            ["message_process"],
        )

    def test_failed_operation_is_only_claimed_when_retry_is_due(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id
        operation = self.store.ensure_operation(case_id, "work", "retry-work")
        claimed = self.store.claim_due_operations(created_at)[0]
        retry_at = created_at + timedelta(minutes=5)
        self.store.fail_operation(claimed.operation_id, claimed.claim_token, "temporary", created_at, retry_at)

        self.assertEqual(self.store.claim_due_operations(retry_at - timedelta(microseconds=1)), ())
        retried = self.store.claim_due_operations(retry_at)
        self.assertEqual(retried[0].operation_id, operation.operation_id)
        self.assertEqual(retried[0].attempts, 2)

    def test_concurrent_operation_claimers_receive_disjoint_rows(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id
        for index in range(6):
            self.store.ensure_operation(case_id, "work", f"concurrent:{index}")

        barrier = Barrier(2)
        def claim(_):
            barrier.wait()
            return self.store.claim_due_operations(created_at, 3)
        with ThreadPoolExecutor(max_workers=2) as executor:
            batches = tuple(executor.map(claim, range(2)))

        identifiers = [operation.operation_id for batch in batches for operation in batch]
        self.assertEqual(len(identifiers), 6)
        self.assertEqual(len(set(identifiers)), 6)

    def test_complete_fail_and_abandon_operations_preserve_attempt_history(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id
        for key in ("complete", "retry", "abandon"):
            self.store.ensure_operation(case_id, "work", key)
        running = {operation.idempotency_key: operation for operation in self.store.claim_due_operations(created_at)}

        self.assertTrue(self.store.complete_operation(running["complete"].operation_id, running["complete"].claim_token, created_at))
        self.assertFalse(self.store.complete_operation(running["complete"].operation_id, running["complete"].claim_token, created_at))
        retry_at = created_at + timedelta(minutes=1)
        self.assertTrue(self.store.fail_operation(running["retry"].operation_id, running["retry"].claim_token, "x" * 5000, created_at, retry_at))
        self.assertTrue(self.store.fail_operation(running["abandon"].operation_id, running["abandon"].claim_token, "fatal", created_at, None))

        states = {
            operation.idempotency_key: operation
            for operation in self.store.get_case(case_id).operations
        }
        self.assertEqual(states["complete"].status, OperationStatus.SUCCEEDED)
        self.assertIsNone(states["complete"].retry_at)
        self.assertIsNone(states["complete"].last_error)
        self.assertEqual(states["retry"].status, OperationStatus.FAILED)
        self.assertEqual(states["retry"].retry_at, retry_at)
        self.assertLessEqual(len(states["retry"].last_error), 1000)
        self.assertEqual(states["abandon"].status, OperationStatus.ABANDONED)
        self.assertEqual({state.attempts for state in states.values()}, {1})
        retried = self.store.claim_due_operations(retry_at)
        self.assertEqual(tuple(operation.idempotency_key for operation in retried), ("retry",))
        self.assertEqual(retried[0].attempts, 2)

    def test_operational_failures_remain_visible_until_acknowledged(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, created_at), ()).case.case_id

        first = self.store.record_operational_failure(
            guild_id=10,
            source="review_publish",
            summary="Could not create the case thread",
            occurred_at=created_at,
            case_id=case_id,
            operation_id="op-1",
        )
        repeated = self.store.record_operational_failure(
            guild_id=10,
            source="review_publish",
            summary="Could not create the case thread",
            occurred_at=created_at + timedelta(seconds=10),
            case_id=case_id,
            operation_id="op-1",
        )

        self.assertEqual(first.failure_id, repeated.failure_id)
        self.assertEqual(repeated.occurrences, 2)
        self.assertEqual(len(self.store.list_operational_failures(10)), 1)
        self.assertTrue(self.store.resolve_operational_failure("op-1", created_at))
        self.assertEqual(self.store.list_operational_failures(10), ())
        self.assertEqual(self.store.clear_operational_failures(10, created_at), 1)

        recurring = self.store.record_operational_failure(
            guild_id=10,
            source="review_publish",
            summary="Thread creation failed again",
            occurred_at=created_at + timedelta(minutes=1),
            case_id=case_id,
            operation_id="op-1",
        )
        self.assertEqual(recurring.occurrences, 1)
        self.assertEqual(len(self.store.list_operational_failures(10)), 1)

    def test_stale_operation_worker_cannot_complete_reclaimed_work(self):
        now = datetime(2026, 7, 13, tzinfo=timezone.utc)
        case_id = self.store.append_message(self.message(40, now), ()).case.case_id
        self.store.ensure_operation(case_id, "work", "crash")
        old = self.store.claim_due_operations(now)[0]

        self.assertEqual(self.store.claim_due_operations(now + timedelta(minutes=1)), ())
        new = self.store.claim_due_operations(
            now + timedelta(minutes=1), stale_before=now
        )[0]

        self.assertNotEqual(old.claim_token, new.claim_token)
        self.assertEqual(new.claimed_at, now + timedelta(minutes=1))
        self.assertEqual(new.attempts, 2)
        self.assertFalse(self.store.complete_operation(old.operation_id, old.claim_token, now))
        self.assertFalse(self.store.fail_operation(old.operation_id, old.claim_token, "old", now, None))
        self.assertTrue(self.store.complete_operation(new.operation_id, new.claim_token, now))

    def test_concurrent_appends_share_case_and_receive_distinct_sequences(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        messages = (
            self.message(40, created_at),
            self.message(41, created_at + timedelta(seconds=1)),
        )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(lambda message: self.store.append_message(message, ()), messages))

        active = self.store.list_open_cases()[0]
        self.assertEqual({result.case.case_id for result in results}, {active.case.case_id})
        self.assertEqual({message.sequence for message in active.messages}, {1, 2})

    def test_get_case_never_returns_children_from_different_database_versions(self):
        created_at = datetime(2026, 7, 13, 12, tzinfo=timezone.utc)
        first = self.store.append_message(self.message(40, created_at), ())
        reader_reached_children = Event()
        resume_reader = Event()

        class PausingConnection(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if "SELECT * FROM detection_attachments" in sql:
                    reader_reached_children.set()
                    self.assert_reader_resumed()
                return super().execute(sql, parameters)

            @staticmethod
            def assert_reader_resumed():
                if not resume_reader.wait(5):
                    raise AssertionError("reader was not resumed")

        def connect_paused_reader(database_path, *, timeout):
            connection = sqlite3.connect(
                database_path, timeout=timeout, factory=PausingConnection
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
            return connection

        reader = DetectionCaseStore(
            self.database_path, connection_factory=connect_paused_reader
        )
        second_attachment = NewAttachment(
            0, "later.png", 100, "image/png", None, None, "https://cdn/later"
        )
        writer = DetectionCaseStore(self.database_path)

        with ThreadPoolExecutor(max_workers=1) as executor:
            snapshot_future = executor.submit(reader.get_case, first.case.case_id)
            self.assertTrue(reader_reached_children.wait(5))
            writer.append_message(
                self.message(
                    41,
                    created_at + timedelta(seconds=1),
                    attachments=(second_attachment,),
                ),
                (),
            )
            resume_reader.set()
            snapshot = snapshot_future.result(timeout=5)

        observed = (
            tuple(message.sequence for message in snapshot.messages),
            tuple(attachment.message_sequence for attachment in snapshot.attachments),
        )
        self.assertIn(observed, (((1,), ()), ((1, 2), (2,))))


if __name__ == "__main__":
    unittest.main()
