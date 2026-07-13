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

    def test_approximate_detector_match_builds_grouped_feedback_item(self) -> None:
        attachment = SimpleNamespace(filename="hashdiff-12.png")
        other = SimpleNamespace(filename="other.png")
        data = b"approximate-image-bytes"
        matches = [
            (
                attachment,
                {"matched": True, "exact_decision": None, "score": 12, "threshold": 20},
                {},
            )
        ]

        items = honeypot.imagescan_feedback_items(
            [other, attachment],
            matches,
            [{"data": b"other"}, {"data": data}],
        )

        self.assertEqual(items, [(attachment, 2, data)])

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
