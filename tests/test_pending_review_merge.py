import asyncio
import unittest
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from tests.test_imagescan_cleanup import honeypot


class _Embed:
    def __init__(self) -> None:
        self.color = None
        self.title = None

    def add_field(self, **kwargs) -> None:
        pass


class _ReviewView:
    def __init__(self, cog, target_id, guild_id, *args, **kwargs) -> None:
        self.cog = cog
        self.target_id = target_id
        self.guild_id = guild_id
        self.review_message = None
        self.active_key = None
        self.channel_ids = list(kwargs.get("channel_ids", []))
        self.message_fingerprint = kwargs.get("message_fingerprint")
        self.expires_at = SimpleNamespace(isoformat=lambda: "expiry")
        self.pending_mute_role_id = None
        self._resolution_started = False


class PendingReviewMergeTests(unittest.IsolatedAsyncioTestCase):
    def test_image_feedback_remains_available_for_24_hours(self) -> None:
        self.assertEqual(honeypot.IMAGE_SCAN_FEEDBACK_TIMEOUT_SECONDS, 24 * 60 * 60)

    def test_feedback_panel_labels_include_bulk_and_individual_actions(self) -> None:
        self.assertEqual(
            honeypot.IMAGE_SCAN_FEEDBACK_BULK_LABELS,
            ("All TP", "All FP", "Ignore all", "Individual"),
        )

    def test_joinwatch_routing_uses_only_joinwatch_channel(self) -> None:
        self.assertEqual(
            honeypot.joinwatch_channel_id({"joinwatch_channel": 123, "logs_channel": 456}),
            123,
        )
        self.assertIsNone(honeypot.joinwatch_channel_id({"logs_channel": 456}))

    def test_detector_feedback_includes_every_image_in_message_order(self) -> None:
        attachments = [
            SimpleNamespace(filename="same.png", content_type="image/png"),
            SimpleNamespace(filename="same.png", content_type="image/png"),
            SimpleNamespace(filename="three.png", content_type="image/png"),
            SimpleNamespace(filename="four.png", content_type="image/png"),
            SimpleNamespace(filename="five.png", content_type="image/png"),
            SimpleNamespace(filename="six.png", content_type="image/png"),
        ]
        snapshots = [{"data": f"image-{index}".encode()} for index in range(1, 7)]

        items = honeypot.imagescan_feedback_items(attachments, snapshots)

        self.assertEqual(
            items,
            [
                (attachment, index, snapshots[index - 1]["data"])
                for index, attachment in enumerate(attachments, start=1)
            ],
        )

    def test_detector_uses_first_four_images_as_trigger_batch(self) -> None:
        attachments = [
            SimpleNamespace(filename=f"image-{index}.png", content_type="image/png")
            for index in range(1, 7)
        ]

        trigger_batch, remaining = honeypot.imagescan_detector_batches(attachments)

        self.assertEqual(trigger_batch, attachments[:4])
        self.assertEqual(remaining, attachments[4:])

    async def test_detector_does_not_trigger_from_fifth_image_alone(self) -> None:
        cog = object.__new__(honeypot.Honeypot)
        cog._imagescan_load_samples = AsyncMock(
            return_value=[SimpleNamespace(decision="true_positive")]
        )
        cog._imagescan_model_state = AsyncMock(return_value={"valid": True, "effective_threshold": 20})
        cog._imagescan_increment_profile = AsyncMock()
        attachments = [
            SimpleNamespace(
                filename=f"image-{index}.png",
                content_type="image/png",
                read=AsyncMock(return_value=f"image-{index}".encode()),
            )
            for index in range(1, 7)
        ]
        message = SimpleNamespace(guild=SimpleNamespace(id=1), attachments=attachments)

        with (
            patch.object(honeypot, "image_hashes_from_bytes", side_effect=lambda data: {"data": data}),
            patch.object(
                honeypot,
                "match_image",
                side_effect=lambda hashes, samples, threshold: {
                    "matched": hashes["data"] == b"image-5",
                    "exact_decision": None,
                },
            ),
        ):
            detected = await cog._handle_imagescan_detector_message(
                message,
                {"imagescan_detector_enabled": True, "imagescan_detector_threshold": 20},
                None,
            )

        self.assertFalse(detected)
        for attachment in attachments[:4]:
            attachment.read.assert_awaited_once()
        for attachment in attachments[4:]:
            attachment.read.assert_not_awaited()
        profile = cog._imagescan_increment_profile.await_args.args[1]
        self.assertEqual(profile["images_considered"], 4)
        self.assertEqual(profile["images_ignored_over_limit"], 2)

    async def test_detector_scans_remaining_images_after_trigger_match(self) -> None:
        cog = object.__new__(honeypot.Honeypot)
        cog._imagescan_load_samples = AsyncMock(
            return_value=[SimpleNamespace(decision="true_positive")]
        )
        cog._imagescan_model_state = AsyncMock(return_value={"valid": True, "effective_threshold": 20})
        cog._imagescan_increment_profile = AsyncMock()
        cog._snapshot_attachments = AsyncMock(
            return_value=[{"data": f"image-{index}".encode()} for index in range(1, 7)]
        )
        cog._get_text_channel_or_thread = lambda *args: None
        cog._send_log = AsyncMock()
        attachments = [
            SimpleNamespace(
                filename=f"image-{index}.png",
                content_type="image/png",
                read=AsyncMock(return_value=f"image-{index}".encode()),
            )
            for index in range(1, 7)
        ]
        message = SimpleNamespace(
            id=10,
            guild=SimpleNamespace(id=1, name="Guild", icon=None),
            attachments=attachments,
            content="",
            created_at=None,
            author=SimpleNamespace(display_name="User", id=2, display_avatar=None),
            channel=SimpleNamespace(id=3, mention="#channel"),
        )
        embed = SimpleNamespace(
            add_field=lambda **kwargs: None,
            set_author=lambda **kwargs: None,
            set_thumbnail=lambda **kwargs: None,
            set_footer=lambda **kwargs: None,
        )

        with (
            patch.object(honeypot, "image_hashes_from_bytes", side_effect=lambda data: {"data": data}),
            patch.object(
                honeypot,
                "match_image",
                side_effect=lambda hashes, samples, threshold: {
                    "matched": hashes["data"] in {b"image-1", b"image-6"},
                    "exact_decision": None,
                    "score": 1,
                    "threshold": threshold,
                },
            ),
            patch.object(honeypot.discord, "Embed", return_value=embed),
            patch.object(honeypot.discord, "Color", SimpleNamespace(red=lambda: 1)),
            patch.object(honeypot, "ImageScanFeedbackView", return_value=SimpleNamespace()),
        ):
            detected = await cog._handle_imagescan_detector_message(
                message,
                {
                    "imagescan_detector_enabled": True,
                    "imagescan_detector_threshold": 20,
                    "imagescan_detector_action": "none",
                },
                None,
            )

        self.assertTrue(detected)
        for attachment in attachments:
            attachment.read.assert_awaited_once()
        profile = cog._imagescan_increment_profile.await_args.args[1]
        self.assertEqual(profile["images_considered"], 6)
        self.assertEqual(profile["images_ignored_over_limit"], 0)

    async def test_external_detection_scans_and_queues_all_images(self) -> None:
        cog = object.__new__(honeypot.Honeypot)
        cog._imagescan_is_image_attachment = lambda attachment: True
        cog._imagescan_load_samples = AsyncMock(
            return_value=[SimpleNamespace(decision="true_positive")]
        )
        cog._imagescan_model_state = AsyncMock(return_value={"valid": True, "effective_threshold": 20})
        attachments = [
            SimpleNamespace(filename=f"image-{index}.png")
            for index in range(1, 7)
        ]
        snapshots = [{"data": f"image-{index}".encode()} for index in range(1, 7)]
        message = SimpleNamespace(
            guild=SimpleNamespace(id=1),
            attachments=attachments,
        )
        embed = SimpleNamespace(add_field=lambda **kwargs: None)
        match = unittest.mock.Mock(
            return_value={"matched": False, "exact_decision": None}
        )

        with (
            patch.object(honeypot, "image_hashes_from_bytes", side_effect=lambda data: {"data": data}),
            patch.object(honeypot, "match_image", match),
            patch.object(
                honeypot,
                "ImageScanFeedbackView",
                side_effect=lambda cog, message, items: SimpleNamespace(items=items),
            ),
        ):
            panel = await cog._prepare_imagescan_learning_feedback(
                message,
                {"imagescan_detector_threshold": 20},
                embed,
                snapshots,
            )

        self.assertEqual(match.call_count, 6)
        self.assertEqual(
            panel.items,
            [
                (attachment, index, snapshots[index - 1]["data"])
                for index, attachment in enumerate(attachments, start=1)
            ],
        )

    async def test_feedback_sender_posts_one_panel_for_multiple_images(self) -> None:
        cog = object.__new__(honeypot.Honeypot)
        panel = SimpleNamespace(status_content=lambda: "panel")
        channel = SimpleNamespace(send=AsyncMock())
        message = SimpleNamespace(id=1)
        honeypot.discord.AllowedMentions = SimpleNamespace(none=lambda: None)

        await cog._send_imagescan_feedback_messages(channel, message, panel)

        channel.send.assert_awaited_once()
        self.assertIs(channel.send.await_args.kwargs["view"], panel)

    async def test_concurrent_reviews_for_one_user_create_one_card_and_merge_the_other(self) -> None:
        cog = object.__new__(honeypot.Honeypot)
        cog._views_lock = asyncio.Lock()
        cog._active_views = {}
        cog._review_creation_locks = {}
        cog._upsert_embed_field = lambda *args, **kwargs: None
        cog._format_review_channels = lambda *args, **kwargs: "channels"
        cog._attachment_files = lambda snapshots: []
        cog._store_pending_review = AsyncMock()
        cog._increment_stat = AsyncMock()
        cog._merge_into_active_review = AsyncMock(return_value=True)

        author = SimpleNamespace(id=7, roles=[])
        guild = SimpleNamespace(id=11, get_role=lambda role_id: None)
        first = SimpleNamespace(
            id=101,
            guild=guild,
            author=author,
            channel=SimpleNamespace(id=21),
            content="scam",
            attachments=[],
        )
        second = SimpleNamespace(
            id=102,
            guild=guild,
            author=author,
            channel=SimpleNamespace(id=22),
            content="scam",
            attachments=[],
        )

        send_started = asyncio.Event()
        release_send = asyncio.Event()
        sent_message = SimpleNamespace(id=500)

        async def send(**kwargs):
            send_started.set()
            await release_send.wait()
            return sent_message

        review_channel = SimpleNamespace(id=30, send=send)
        config = {"review_timeout_minutes": 60}

        honeypot.discord.utils = types.SimpleNamespace(format_dt=lambda *args, **kwargs: "later")
        honeypot.discord.Color = types.SimpleNamespace(gold=lambda: 1)
        with patch.object(honeypot, "ReviewView", _ReviewView):
            first_task = asyncio.create_task(
                cog._send_review(first, config, _Embed(), review_channel, None, [])
            )
            await send_started.wait()
            second_task = asyncio.create_task(
                cog._send_review(second, config, _Embed(), review_channel, None, [])
            )
            await asyncio.sleep(0)
            release_send.set()
            results = await asyncio.gather(first_task, second_task)

        self.assertEqual(results.count(False), 1)
        self.assertEqual(results.count(True), 1)
        cog._merge_into_active_review.assert_awaited_once()
        cog._store_pending_review.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
