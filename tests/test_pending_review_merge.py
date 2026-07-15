import importlib.util
import asyncio
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.test_detection_cases import detection_cases_under_test as cases
from tests.detection_case_fixtures import capture_attachment, publish_evidence


def _load_case_review():
    name = "Honeypot.case_review"
    path = Path(__file__).parents[1] / "Honeypot" / "case_review.py"
    package = types.ModuleType("Honeypot")
    package.__path__ = [str(path.parent)]
    sys.modules.setdefault("Honeypot", package)
    sys.modules["Honeypot.detection_cases"] = cases
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


case_review = _load_case_review()


class CaseReviewProjectionTests(unittest.TestCase):
    def test_case_summary_keeps_persisted_user_identity_and_account_age(self):
        snapshot = self.snapshot(channels=(100,))
        subject = cases.CaseSubjectRecord(
            case_id=snapshot.case.case_id,
            display_name="Suspicious User",
            avatar_url="https://cdn.discord.test/avatar.png",
            account_created_at=datetime(2026, 7, 10, tzinfo=timezone.utc),
            guild_joined_at=datetime(2026, 7, 13, tzinfo=timezone.utc),
        )
        snapshot = cases.CaseSnapshot(
            case=snapshot.case,
            messages=snapshot.messages,
            attachments=snapshot.attachments,
            signals=snapshot.signals,
            operations=snapshot.operations,
            publications=snapshot.publications,
            subject=subject,
        )

        projection = case_review.render_case(snapshot)

        self.assertNotIn("Suspicious User", projection.description)
        self.assertIn("<@2> (2)", projection.description)
        self.assertIn("Account created <t:", projection.description)
        self.assertIn("Joined server <t:", projection.description)
        self.assertEqual(projection.thumbnail_url, subject.avatar_url)

    def test_terminal_summary_uses_short_status_and_omits_expiry(self):
        snapshot = self.snapshot()
        snapshot = cases.CaseSnapshot(
            cases.CaseRecord(
                **{
                    **snapshot.case.__dict__,
                    "status": cases.CaseStatus.RESOLVED,
                    "resolution": "ignore",
                }
            ),
            snapshot.messages,
            snapshot.attachments,
            snapshot.signals,
            snapshot.operations,
        )

        projection = case_review.render_case(snapshot)
        visible = projection.description + "\n" + "\n".join(
            field.value for field in projection.fields
        )

        self.assertIn("Status: Closed", visible)
        self.assertNotIn("Expires:", visible)

    def snapshot(
        self,
        *,
        channels=(20, 10, 20),
        delete_status=cases.DeleteStatus.DELETED,
        jump_url=None,
    ):
        now = datetime(2026, 7, 14, tzinfo=timezone.utc)
        case = cases.CaseRecord(
            "case-1", 1, 2, cases.CaseStatus.PENDING, now,
            now + timedelta(hours=24), None, None, None, None, None, None, False,
        )
        messages = tuple(
            cases.MessageRecord(
                "case-1", sequence, 1, channel_id, 100 + sequence, f"message {sequence}",
                now, jump_url, "spam", "captured", delete_status, None,
            )
            for sequence, channel_id in enumerate(channels, start=1)
        )
        attachments = (
            self.attachment(1, 0, "same.png"),
            self.attachment(1, 1, "same.png"),
            self.attachment(2, 0, "same.png"),
        )
        return cases.CaseSnapshot(case, messages, attachments, (), ())

    @staticmethod
    def attachment(message_sequence, position, filename):
        return cases.AttachmentRecord(
            cases.AttachmentKey("case-1", message_sequence, position), filename, 10,
            "image/png", None, None, "https://example.invalid/image",
            f"case/{message_sequence}/{position}-{filename}", "captured",
            None, None, {}, None, {}, None,
        )

    def test_review_lists_channels_in_first_occurrence_order(self):
        projection = case_review.render_case(self.snapshot())

        self.assertEqual(projection.channel_ids, (20, 10))

    def test_review_warns_when_any_message_may_be_public(self):
        projection = case_review.render_case(
            self.snapshot(delete_status=cases.DeleteStatus.FORBIDDEN)
        )

        self.assertTrue(projection.needs_attention)

    def test_case_attention_warning_does_not_assume_delete_failed(self):
        snapshot = self.snapshot(delete_status=cases.DeleteStatus.DELETED)
        snapshot = cases.CaseSnapshot(
            cases.CaseRecord(
                **{**snapshot.case.__dict__, "needs_attention": True}
            ),
            snapshot.messages,
            snapshot.attachments,
            snapshot.signals,
            snapshot.operations,
        )

        projection = case_review.render_case(snapshot)

        warning = next(
            field for field in projection.pages[0]
            if field.name == "Warnings:"
        )
        self.assertNotIn("delete", warning.value.lower())

    def test_review_projects_complete_persisted_case_status(self):
        snapshot = self.snapshot()
        incomplete = cases.AttachmentRecord(
            cases.AttachmentKey("case-1", 3, 0),
            "late.png",
            10,
            "image/png",
            None,
            None,
            "late",
            None,
            "capture_failed",
            None,
            None,
            {},
            None,
            {},
            "timeout",
        )
        signals = (
            cases.SignalRecord(
                "case-1",
                1,
                cases.DetectionSignal(
                    "spam", "same reason", cases.ActionIntent.REVIEW, True, {}
                ),
            ),
            cases.SignalRecord(
                "case-1",
                2,
                cases.DetectionSignal(
                    "firstpost", "same reason", cases.ActionIntent.REVIEW, True, {}
                ),
            ),
        )
        operation = cases.OperationRecord(
            "op-1",
            "case-1",
            None,
            "moderator_ban",
            cases.OperationStatus.SUCCEEDED,
            1,
            snapshot.case.created_at,
            snapshot.case.created_at,
            None,
            None,
            "ban",
            99,
            "moderator-action:case-1",
            None,
            None,
        )
        snapshot = cases.CaseSnapshot(
            snapshot.case,
            snapshot.messages,
            snapshot.attachments + (incomplete,),
            signals,
            (operation,),
        )

        projection = case_review.render_case(snapshot)

        self.assertEqual(projection.message_count, 3)
        self.assertEqual(projection.expires_at, snapshot.case.expires_at)
        self.assertIn("Ban", projection.moderation_status)
        self.assertNotIn("succeeded", projection.moderation_status)
        self.assertTrue(projection.incomplete_evidence)
        self.assertEqual(projection.signal_lines, ("<#20>: same reason",))
        visible = "\n".join(
            (projection.description,)
            + tuple(f"{field.name} {field.value}" for field in projection.fields)
        )
        self.assertIn("Messages: 3", visible)
        self.assertIn("Moderation: Ban", visible)
        timestamp = int(snapshot.case.expires_at.timestamp())
        self.assertIn(f"Expires: <t:{timestamp}:R>", visible)
        self.assertNotIn(f"<t:{timestamp}:F>", visible)
        self.assertIn("Evidence: Capture incomplete", visible)

    def test_open_summary_separates_standard_information_from_optional_effects(self):
        snapshot = self.snapshot()
        signal = cases.SignalRecord(
            "case-1",
            1,
            cases.DetectionSignal("honeypot", "bait", cases.ActionIntent.REVIEW, True, {}),
        )
        snapshot = cases.CaseSnapshot(
            snapshot.case, snapshot.messages, snapshot.attachments,
            (signal,), snapshot.operations,
        )
        projection = case_review.render_case(snapshot)

        self.assertNotIn("Standard information:", projection.description)
        self.assertNotIn(
            "Standard information:", [field.name for field in projection.fields]
        )
        self.assertIn("Expires: ", projection.description)
        self.assertIn("\n\nSignals:\n", projection.description)
        self.assertNotIn("Moderation:", [field.name for field in projection.fields])

        snapshot = self.snapshot()
        moderation = cases.OperationRecord(
            "op-effects", "case-1", 1, "moderation_action",
            cases.OperationStatus.SUCCEEDED, 1,
            snapshot.case.created_at, snapshot.case.created_at,
            None, None, "planned_kick", None, "moderation:case-1", None, None,
        )
        snapshot = cases.CaseSnapshot(
            snapshot.case, snapshot.messages, snapshot.attachments,
            snapshot.signals, (moderation,),
        )
        projection = case_review.render_case(snapshot)
        effects = [field for field in projection.fields if field.name == "Moderation:"]

        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0].value, "Kick planned (dry run)")

    def test_review_summary_uses_only_relative_discord_expiry(self):
        projection = case_review.render_case(self.snapshot())
        visible = "\n".join(
            (projection.description,)
            + tuple(field.value for field in projection.fields)
        )
        timestamp = int(projection.expires_at.timestamp())

        self.assertIn(f"Expires: <t:{timestamp}:R>", visible)
        self.assertNotIn(f"<t:{timestamp}:F>", visible)
        self.assertNotIn("Evidence capture: complete", visible)
        self.assertNotIn(projection.expires_at.isoformat(), visible)

    def test_review_message_index_uses_case_sequence_and_human_dry_run_status(self):
        projection = case_review.render_case(
            self.snapshot(
                channels=(20,),
                delete_status=cases.DeleteStatus.PLANNED,
                jump_url="https://discord.com/channels/1/20/101",
            )
        )

        self.assertEqual(
            projection.message_lines,
            (
            "Message 1 in <#20>: "
                "Would be deleted (dry run)",
            ),
        )

    def test_timeline_preserves_complete_message_context_and_attachment_metadata(self):
        snapshot = self.snapshot(channels=(20,))
        attachment = cases.AttachmentRecord(
            cases.AttachmentKey("case-1", 1, 0),
            "warning.png",
            10,
            "image/png",
            32,
            16,
            "https://cdn.invalid/warning.png",
            "case/1/0-warning.png",
            "captured",
            "sha",
            "phash",
            {"matched_filename": "known-scam.png", "hash_diff": 3},
            None,
            {},
            None,
            None,
            "suspicious payment form",
            True,
        )
        signal = cases.SignalRecord(
            "case-1",
            1,
            cases.DetectionSignal(
                "honeypot",
                "Message posted in a configured honeypot channel",
                cases.ActionIntent.REVIEW,
                True,
                {},
            ),
        )
        snapshot = cases.CaseSnapshot(
            snapshot.case,
            snapshot.messages,
            (attachment,),
            (signal,),
            snapshot.operations,
        )

        timeline = case_review.render_timeline(snapshot)
        message = timeline.messages[0]
        evidence = message.attachments[0]

        self.assertEqual(message.sequence, 1)
        self.assertEqual(message.channel_id, 20)
        self.assertEqual(message.content, "message 1")
        self.assertEqual(message.delete_status, "Deleted")
        self.assertEqual(message.signal_reasons, ("Posted in honeypot channel",))
        self.assertEqual(evidence.description, "suspicious payment form")
        self.assertTrue(evidence.spoiler)
        self.assertEqual(evidence.match_metadata["hash_diff"], 3)

    def test_resolved_summary_exposes_actor_and_time_without_operation_vocabulary(self):
        snapshot = self.snapshot(channels=(20,))
        resolved_at = snapshot.case.created_at + timedelta(minutes=5)
        case = cases.CaseRecord(
            **{
                **snapshot.case.__dict__,
                "status": cases.CaseStatus.RESOLVED,
                "resolution": "ignore",
                "moderator_id": 99,
                "resolved_at": resolved_at,
            }
        )
        operation = cases.OperationRecord(
            "op-1",
            "case-1",
            None,
            "review_publish",
            cases.OperationStatus.FAILED,
            2,
            snapshot.case.created_at,
            resolved_at,
            None,
            "HTTPException: secret implementation detail",
            None,
            None,
            "review-publish:case-1",
            None,
            None,
        )
        snapshot = cases.CaseSnapshot(
            case,
            snapshot.messages,
            snapshot.attachments,
            snapshot.signals,
            (operation,),
        )

        projection = case_review.render_case(snapshot)
        visible = projection.description + "\n" + "\n".join(
            field.value for page in projection.pages for field in page
        )

        self.assertEqual(projection.moderator_id, 99)
        self.assertEqual(projection.resolved_at, resolved_at)
        self.assertIn("<@99>", visible)
        self.assertNotIn("review_publish", visible)
        self.assertNotIn("HTTPException", visible)
        self.assertNotIn("case-1", visible)

    def test_review_keeps_user_id_but_hides_case_uuid(self):
        projection = case_review.render_case(self.snapshot())

        self.assertIn("<@2> (2)", projection.description)
        self.assertIn("Status: Open", projection.description)
        self.assertIn("Messages: 3", projection.description)
        self.assertIn("Expires:", projection.description)
        self.assertNotIn("case-1", projection.description)

    def test_honeypot_signal_uses_concise_reason(self):
        snapshot = self.snapshot(channels=(20,))
        snapshot = cases.CaseSnapshot(
            snapshot.case,
            snapshot.messages,
            snapshot.attachments,
            (
                cases.SignalRecord(
                    "case-1",
                    1,
                    cases.DetectionSignal(
                        "honeypot",
                        "Message posted in a configured honeypot channel",
                        cases.ActionIntent.REVIEW,
                        True,
                        {},
                    ),
                ),
            ),
            snapshot.operations,
        )

        projection = case_review.render_case(snapshot)

        self.assertEqual(
            projection.signal_lines,
            ("<#20>: Posted in honeypot channel",),
        )

    def test_cached_purge_lists_each_message_with_human_status(self):
        snapshot = self.snapshot()

        def operation(operation_id, channel_id, message_id, status, result):
            return cases.OperationRecord(
                operation_id,
                "case-1",
                None,
                "cached_purge",
                status,
                1,
                snapshot.case.created_at,
                snapshot.case.created_at,
                None,
                "HTTP 403" if status is cases.OperationStatus.FAILED else None,
                result,
                None,
                f"cached-purge:case-1:{channel_id}:{message_id}",
                None,
                None,
            )

        snapshot = cases.CaseSnapshot(
            snapshot.case,
            snapshot.messages,
            snapshot.attachments,
            snapshot.signals,
            (
                operation(
                    "op-1", 20, 101, cases.OperationStatus.SUCCEEDED, "deleted"
                ),
                operation(
                    "op-2", 30, 102, cases.OperationStatus.SUCCEEDED, "already_gone"
                ),
                operation(
                    "op-3", 40, 103, cases.OperationStatus.FAILED, "forbidden"
                ),
            ),
        )

        projection = case_review.render_case(snapshot)
        timeline = case_review.render_timeline(snapshot)

        self.assertEqual(
            projection.cached_purge_lines,
            (
                "1. <#20>: Deleted",
                "2. <#30>: Already gone",
                "3. <#40>: Could not delete: missing permissions",
            ),
        )
        self.assertEqual(
            timeline.case_notes,
            (
                "Cached purge 1: <#40>: Could not delete: missing permissions",
            ),
        )

    def test_feedback_items_keep_message_and_attachment_order(self):
        items = case_review.case_feedback_items(self.snapshot())

        self.assertEqual(
            [(item.message_sequence, item.position) for item in items],
            [(1, 0), (1, 1), (2, 0)],
        )

    def test_feedback_items_include_only_captured_image_evidence(self):
        snapshot = self.snapshot()
        pdf = cases.AttachmentRecord(
            cases.AttachmentKey("case-1", 3, 0),
            "invoice.pdf",
            10,
            "application/pdf",
            None,
            None,
            "https://example.invalid/invoice",
            "case/3/invoice.pdf",
            "captured",
            None,
            None,
            {},
            None,
            {},
            None,
        )
        incomplete_image = cases.AttachmentRecord(
            cases.AttachmentKey("case-1", 3, 1),
            "late.png",
            10,
            "image/png",
            None,
            None,
            "https://example.invalid/late",
            None,
            "capture_failed",
            None,
            None,
            {},
            None,
            {},
            "failed",
        )
        snapshot = cases.CaseSnapshot(
            snapshot.case,
            snapshot.messages,
            snapshot.attachments + (pdf, incomplete_image),
            snapshot.signals,
            snapshot.operations,
        )

        items = case_review.case_feedback_items(snapshot)

        self.assertEqual(
            [(item.message_sequence, item.position) for item in items],
            [(1, 0), (1, 1), (2, 0)],
        )

    def test_persistent_custom_ids_include_case_and_stable_attachment_key(self):
        self.assertEqual(
            case_review.case_custom_id("case-1", "resolve", "tp"),
            "honeypot:case:case-1:resolve:tp",
        )

    def test_large_case_projection_stays_within_discord_embed_limits(self):
        snapshot = self.snapshot(channels=tuple(range(100, 500)))
        long_resolution = "resolved " * 1000
        snapshot = cases.CaseSnapshot(
            cases.CaseRecord(
                **{
                    **snapshot.case.__dict__,
                    "resolution": long_resolution,
                    "needs_attention": True,
                }
            ),
            snapshot.messages,
            tuple(self.attachment(sequence, 0, "image-" + "x" * 200)
                  for sequence in range(1, 401)),
            tuple(
                cases.SignalRecord(
                    "case-1", sequence,
                    cases.DetectionSignal("spam", "reason " * 100, cases.ActionIntent.REVIEW, True, {}),
                )
                for sequence in range(1, 401)
            ),
            (),
        )

        projection = case_review.render_case(snapshot)

        self.assertLessEqual(len(projection.title), 256)
        self.assertLessEqual(len(projection.description), 4096)
        self.assertLessEqual(len(projection.fields), 25)
        self.assertTrue(all(len(field.value) <= 1024 for field in projection.fields))
        self.assertLessEqual(
            len(projection.title) + len(projection.description)
            + sum(len(field.name) + len(field.value) for field in projection.fields),
            6000,
        )
        self.assertTrue(projection.needs_attention)
        self.assertTrue(projection.resolution)
        self.assertNotIn(projection.case_id, projection.description)
        self.assertEqual(len(projection.pages), 1)
        self.assertTrue(
            all(
                len(page) <= 25
                and sum(len(field.name) + len(field.value) for field in page)
                + len(projection.title)
                + len(projection.description)
                <= 6000
                and all(len(field.value) <= 1024 for field in page)
                for page in projection.pages
            )
        )
        field_names = {
            field.name.removesuffix(" (continued)") for field in projection.fields
        }
        self.assertNotIn("Messages:", field_names)
        self.assertNotIn("Image feedback:", field_names)
        self.assertEqual(len(projection.message_lines), 400)
        self.assertEqual(len(projection.feedback_lines), 400)
        self.assertEqual(
            case_review.attachment_custom_id(cases.AttachmentKey("case-1", 2, 3), "fp"),
            "honeypot:case:case-1:images:2:3:fp",
        )


class CaseReviewServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = cases.DetectionCaseStore(Path(self.directory.name) / "cases.sqlite3")
        self.store.initialize()
        self.message_id = 99

    def create_case(self):
        self.message_id += 1
        now = datetime(2026, 7, 14, tzinfo=timezone.utc)
        appended = self.store.append_message(
            cases.NewMessage(
                1, 2, 20, self.message_id, "message", now, None,
                (
                    cases.NewAttachment(0, "same.png", 10, "image/png", None, None, "one"),
                    cases.NewAttachment(1, "same.png", 10, "image/png", None, None, "two"),
                ),
            ),
            (cases.DetectionSignal("spam", "match", cases.ActionIntent.REVIEW, True, {}),),
        )
        for position in (0, 1):
            capture_attachment(
                self.store,
                appended.case.case_id,
                appended.message.sequence,
                position,
                f"case/1/{position}-same.png",
            )
        return appended.case.case_id

    async def test_bulk_actions_persist_every_attachment_decision(self):
        expected = {
            "tp": "true_positive",
            "fp": "false_positive",
            "ignore": "ignored",
        }
        for action, decision in expected.items():
            with self.subTest(action=action):
                case_id = self.create_case()
                service = case_review.CaseReviewService(self.store)

                snapshot = await service.apply_bulk(case_id, action, moderator_id=7)

                self.assertEqual(
                    [item.learning_decision for item in snapshot.attachments],
                    [decision, decision],
                )
                self.assertEqual(snapshot.case.status, cases.CaseStatus.RESOLVED)

    async def test_bulk_tp_ignores_captured_pdf_evidence(self):
        now = datetime(2026, 7, 14, tzinfo=timezone.utc)
        appended = self.store.append_message(
            cases.NewMessage(
                1,
                2,
                20,
                999,
                "message",
                now,
                None,
                (
                    cases.NewAttachment(
                        0, "proof.png", 10, "image/png", None, None, "image"
                    ),
                    cases.NewAttachment(
                        1, "invoice.pdf", 10, "application/pdf", None, None, "pdf"
                    ),
                ),
            ),
            (cases.DetectionSignal("spam", "match", cases.ActionIntent.REVIEW, True, {}),),
        )
        for position, filename in ((0, "proof.png"), (1, "invoice.pdf")):
            capture_attachment(
                self.store,
                appended.case.case_id,
                appended.message.sequence,
                position,
                f"case/1/{position}-{filename}",
            )

        with self.assertRaisesRegex(ValueError, "captured image evidence"):
            await case_review.CaseReviewService(self.store).apply_individual(
                cases.AttachmentKey(
                    appended.case.case_id, appended.message.sequence, 1
                ),
                "tp",
                moderator_id=7,
            )
        snapshot = await case_review.CaseReviewService(self.store).apply_bulk(
            appended.case.case_id, "tp", moderator_id=7
        )

        self.assertEqual(
            [item.learning_decision for item in snapshot.attachments],
            ["true_positive", None],
        )

    async def test_message_bulk_action_only_updates_that_messages_images(self):
        case_id = self.create_case()
        now = datetime(2026, 7, 14, 12, 1, tzinfo=timezone.utc)
        appended = self.store.append_message(
            cases.NewMessage(
                1,
                2,
                21,
                1000,
                "second message",
                now,
                None,
                (
                    cases.NewAttachment(
                        0, "second.png", 10, "image/png", None, None, "three"
                    ),
                ),
            ),
            (cases.DetectionSignal("spam", "match", cases.ActionIntent.REVIEW, True, {}),),
        )
        capture_attachment(
            self.store,
            case_id,
            appended.message.sequence,
            0,
            "case/2/0-second.png",
        )

        snapshot = await case_review.CaseReviewService(self.store).apply_message(
            case_id, appended.message.sequence, "fp", moderator_id=7
        )

        self.assertEqual(
            [item.learning_decision for item in snapshot.attachments],
            [None, None, "false_positive"],
        )
        self.assertEqual(snapshot.case.status, cases.CaseStatus.PENDING)

    async def test_individual_action_uses_stable_attachment_key(self):
        case_id = self.create_case()
        service = case_review.CaseReviewService(self.store)
        key = cases.AttachmentKey(case_id, 1, 1)

        snapshot = await service.apply_individual(key, "fp", moderator_id=7)

        self.assertEqual(
            [item.learning_decision for item in snapshot.attachments],
            [None, "false_positive"],
        )
        self.assertEqual(snapshot.case.status, cases.CaseStatus.PENDING)

    async def test_repeated_bulk_action_is_idempotent(self):
        case_id = self.create_case()
        service = case_review.CaseReviewService(self.store)

        first = await service.apply_bulk(case_id, "tp", moderator_id=7)
        repeated = await service.apply_bulk(case_id, "tp", moderator_id=7)

        self.assertEqual(first, repeated)
        self.assertEqual(
            [item.learning_decision for item in repeated.attachments],
            ["true_positive", "true_positive"],
        )

    async def test_concurrent_repeated_bulk_action_is_idempotent(self):
        case_id = self.create_case()
        service = case_review.CaseReviewService(self.store)

        first, repeated = await asyncio.gather(
            service.apply_bulk(case_id, "tp", moderator_id=7),
            service.apply_bulk(case_id, "tp", moderator_id=7),
        )

        self.assertEqual(first, repeated)
        self.assertEqual(first.case.resolution, "images:tp")

    async def test_identical_individual_retry_after_bulk_resolution_is_a_noop(self):
        case_id = self.create_case()
        service = case_review.CaseReviewService(self.store)
        key = cases.AttachmentKey(case_id, 1, 0)
        resolved = await service.apply_bulk(case_id, "tp", moderator_id=7)

        repeated = await service.apply_individual(key, "tp", moderator_id=7)

        self.assertEqual(repeated, resolved)
        with self.assertRaises(ValueError):
            await service.apply_individual(key, "fp", moderator_id=7)

    def test_evidence_publication_identities_survive_store_restart(self):
        case_id = self.create_case()
        publish_evidence(self.store, case_id, 0, 50, 60)
        publish_evidence(self.store, case_id, 1, 50, 61)

        reopened = cases.DetectionCaseStore(Path(self.directory.name) / "cases.sqlite3")
        snapshot = reopened.get_case(case_id)

        self.assertEqual(
            [(item.batch_index, item.channel_id, item.message_id) for item in snapshot.publications],
            [(0, 50, 60), (1, 50, 61)],
        )


if __name__ == "__main__":
    unittest.main()
