import unittest
from datetime import date, datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.test_activity_storage import activity_storage


class EmojiStorageTests(unittest.IsolatedAsyncioTestCase):
    async def test_report_includes_zero_use_emojis_and_uses_tracking_or_creation_date(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "activity.sqlite3"
            store = activity_storage.ActivityStore(path)
            await store.initialize()
            started = date(2026, 10, 1)
            today = date(2026, 10, 10)
            await store.begin_emoji_tracking(1, started)
            old = activity_storage.EmojiInfo(7, "old", False)
            new = activity_storage.EmojiInfo(8, "new", True)
            unused = activity_storage.EmojiInfo(9, "unused", False)
            for emoji in (old, new):
                await store.record_emoji_reaction(1, today, 100, emoji, 1)
            await store.prune_emoji_history(1, date(2026, 12, 1))
            store = activity_storage.ActivityStore(path)
            await store.initialize()
            await store.begin_emoji_tracking(1, today)
            rows = await store.get_emoji_report(1, today, [
                (old, date(2020, 1, 1)), (new, date(2026, 10, 9)),
                (unused, date(2020, 1, 1)),
            ])
            self.assertEqual([row.usage.emoji_id for row in rows], [9, 7, 8])
            self.assertEqual(rows[0].usage.total, 0)
            self.assertEqual(rows[1].tracked_since, started)
            self.assertEqual(rows[1].tracked_days, 10)
            self.assertAlmostEqual(rows[1].uses_per_day, 0.1)
            self.assertEqual(rows[2].tracked_days, 2)
            self.assertAlmostEqual(rows[2].uses_per_day, 0.5)

    async def test_daily_winner_counts_each_emoji_once_and_survives_daily_pruning(self):
        with TemporaryDirectory() as directory:
            store = activity_storage.ActivityStore(Path(directory) / "activity.sqlite3")
            await store.initialize()
            day = date(2026, 10, 9)
            first = activity_storage.EmojiInfo(7, "party", False)
            second = activity_storage.EmojiInfo(8, "hype", True)
            await store.record_message(
                1, day, 12, 42, 100, None, datetime(2026, 10, 9, 12, tzinfo=timezone.utc),
                emojis=(first, first, second),
            )
            await store.record_emoji_reaction(1, day, 200, second, 1)
            counts = await store.get_emoji_counts(1, day, 1)
            self.assertEqual(
                [(row.emoji_id, row.message_uses, row.reaction_uses) for row in counts],
                [(8, 1, 1), (7, 1, 0)],
            )
            summaries = await store.close_stale_days(1, date(2026, 10, 10), 100)
            self.assertEqual(summaries[0].emoji_of_day, second)
            await store.prune_emoji_history(1, date(2026, 11, 10))
            latest = await store.get_latest_summary(1)
            self.assertEqual(latest.emoji_of_day, second)
            self.assertEqual(await store.get_emoji_counts(1, date(2026, 11, 10), 30), [])
            all_time = await store.get_emoji_counts(1, date(2026, 11, 10), None)
            self.assertEqual([(row.emoji_id, row.total) for row in all_time], [(8, 2), (7, 1)])

    async def test_reaction_cycles_cancel_across_days_and_channels_remain_separate(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "activity.sqlite3"
            store = activity_storage.ActivityStore(path)
            await store.initialize()
            emoji = activity_storage.EmojiInfo(7, "party", False)
            for day, channel, delta in ((9, 100, 1), (10, 100, -1), (10, 200, 1)):
                await store.record_emoji_reaction(1, date(2026, 10, day), channel, emoji, delta)

            store = activity_storage.ActivityStore(path)
            await store.initialize()
            rows = await store.get_emoji_counts(1, date(2026, 10, 10), 2)
            self.assertEqual([(row.emoji_id, row.reaction_uses) for row in rows], [(7, 1)])
            self.assertEqual(await store.get_emoji_counts(1, date(2026, 10, 10), 2, 100), [])
            channel_rows = await store.get_emoji_counts(1, date(2026, 10, 10), None, 200)
            self.assertEqual(channel_rows[0].reaction_uses, 1)
            self.assertEqual(await store.get_emoji_counts(2, date(2026, 10, 10), None), [])
