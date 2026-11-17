import csv
import io
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from tests.test_chatchart import FakeContext, FakeTextChannel, nhmisc


class Embed:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.fields = []

    def add_field(self, **kwargs):
        self.fields.append(SimpleNamespace(**kwargs))


class EmojiTrackingTests(unittest.IsolatedAsyncioTestCase):
    async def test_guild_join_starts_measurement_before_first_emoji_use(self):
        with TemporaryDirectory() as directory:
            store = nhmisc.ActivityStore(Path(directory) / "activity.sqlite3")
            await store.initialize()
            cog = object.__new__(nhmisc.NHMisc)
            cog._activity_store = store
            cog._utc_today = lambda: date(2026, 10, 1)
            await cog.on_emoji_guild_join(SimpleNamespace(id=1))
            emoji = nhmisc.EmojiInfo(7, "old", False)
            await store.record_emoji_reaction(1, date(2026, 10, 10), 100, emoji, 1)
            report = await store.get_emoji_report(1, date(2026, 10, 10), [(emoji, date(2020, 1, 1))])
            self.assertEqual(report[0].tracked_days, 10)
            self.assertAlmostEqual(report[0].uses_per_day, 0.1)

    async def test_report_exports_all_current_emojis_including_zero_and_age_adjusted_rates(self):
        with TemporaryDirectory() as directory:
            store = nhmisc.ActivityStore(Path(directory) / "activity.sqlite3")
            await store.initialize()
            today = date(2026, 10, 10)
            await store.begin_emoji_tracking(1, date(2026, 10, 1))
            old = nhmisc.EmojiInfo(7, "old", False)
            await store.record_emoji_reaction(1, today, 100, old, 1)
            await store.record_emoji_reaction(1, today, 100, nhmisc.EmojiInfo(99, "removed", False), 1)
            catalog = [
                SimpleNamespace(id=7, name="old", animated=False, created_at=datetime(2020, 1, 1, tzinfo=timezone.utc)),
                SimpleNamespace(id=8, name="unused", animated=True, created_at=datetime(2026, 10, 9, tzinfo=timezone.utc)),
            ]
            ctx = FakeContext(SimpleNamespace(id=1, name="Test server", emojis=catalog, filesize_limit=8 * 1024 * 1024))
            cog = object.__new__(nhmisc.NHMisc)
            cog._activity_store = store
            cog._utc_today = lambda: today
            cog.bot = SimpleNamespace(intents=SimpleNamespace(
                guild_messages=True, message_content=True,
                guild_reactions=True, emojis_and_stickers=True))
            with mock.patch.object(nhmisc.discord, "Embed", Embed):
                await nhmisc.NHMisc.nhmisc_emojireport.callback(cog, ctx)
            rows = list(csv.DictReader(io.StringIO(ctx.sent[0]["file"].data.decode("utf-8"))))
            self.assertEqual([row["Emoji"] for row in rows], ["unused", "old"])
            self.assertEqual(rows[0]["Total uses"], "0")
            self.assertEqual(rows[0]["Tracking days"], "2")
            self.assertEqual(rows[1]["Tracking days"], "10")
            self.assertEqual(rows[1]["Uses per day"], "0.1000")
            for allowed in (False, True):
                permission_ctx = SimpleNamespace(author=SimpleNamespace(
                    guild_permissions=SimpleNamespace(manage_messages=allowed)))
                self.assertEqual(await nhmisc.NHMisc.nhmisc_emojireport.can_run(permission_ctx), allowed)

    async def test_message_dedup_and_reaction_add_remove_use_only_server_emojis(self):
        with TemporaryDirectory() as directory:
            store = nhmisc.ActivityStore(Path(directory) / "activity.sqlite3")
            await store.initialize()
            member = SimpleNamespace(id=42, bot=False)
            emojis = [SimpleNamespace(id=7, name="party", animated=False),
                      SimpleNamespace(id=8, name="hype", animated=True)]
            guild = SimpleNamespace(id=1, emojis=emojis, get_member=lambda user_id: member)
            cog = object.__new__(nhmisc.NHMisc)
            cog.bot = SimpleNamespace(get_guild=lambda guild_id: guild)
            cog._bot_proxy = None
            cog._activity_store = store
            cog._close_stale_activity_days_for_guild = mock.AsyncMock()
            message = SimpleNamespace(
                guild=guild, author=member, webhook_id=None, type=0,
                channel=SimpleNamespace(id=100),
                content="<:party:7> <:party:7> <a:hype:8> <:foreign:99> 😂",
            )
            await cog.on_message(message)
            today = datetime.now(timezone.utc).date()
            counts = await store.get_emoji_counts(1, today, 1)
            self.assertEqual([(row.emoji_id, row.message_uses) for row in counts], [(7, 1), (8, 1)])
            payload = SimpleNamespace(guild_id=1, channel_id=200, user_id=42,
                                      member=member, emoji=SimpleNamespace(id=8), burst=False)
            await cog.on_raw_reaction_add(payload)
            payload.burst = True
            await cog.on_raw_reaction_add(payload)
            await cog.on_raw_reaction_remove(payload)
            counts = await store.get_emoji_counts(1, today, None, 200)
            self.assertEqual(counts[0].reaction_uses, 1)
            payload.emoji.id = 99
            await cog.on_raw_reaction_add(payload)
            payload.emoji.id = None
            await cog.on_raw_reaction_add(payload)
            payload.emoji.id = 7
            payload.member = SimpleNamespace(bot=True)
            await cog.on_raw_reaction_add(payload)
            counts = await store.get_emoji_counts(1, today, None, 200)
            self.assertEqual([row.emoji_id for row in counts], [8])

    async def test_chart_requires_manage_messages(self):
        command = nhmisc.NHMisc.nhmisc_emojichart
        for allowed in (False, True):
            ctx = SimpleNamespace(author=SimpleNamespace(
                guild_permissions=SimpleNamespace(manage_messages=allowed)))
            self.assertEqual(await command.can_run(ctx), allowed)

    async def test_chart_selects_channel_and_period_and_renders_real_image(self):
        with TemporaryDirectory() as directory:
            store = nhmisc.ActivityStore(Path(directory) / "activity.sqlite3")
            await store.initialize()
            today = datetime.now(timezone.utc).date()
            emoji = nhmisc.EmojiInfo(7, "party", False)
            await store.record_emoji_reaction(1, today - timedelta(days=40), 100, emoji, 1)
            await store.record_emoji_reaction(1, today, 200, emoji, 1)
            await store.prune_emoji_history(1, today)
            channel = FakeTextChannel(100, "general")
            guild = SimpleNamespace(id=1, name="Test server", get_channel_or_thread=lambda _: channel)
            ctx = FakeContext(guild)
            cog = object.__new__(nhmisc.NHMisc)
            cog._activity_store = store
            cog._close_stale_activity_days_for_guild = mock.AsyncMock()
            cog._utc_today = lambda: today
            cog.bot = SimpleNamespace(intents=SimpleNamespace(
                guild_messages=True, message_content=True, guild_reactions=True,
                emojis_and_stickers=True))
            with (
                mock.patch.object(nhmisc.discord, "Embed", Embed),
                mock.patch.object(nhmisc.aiohttp, "ClientSession") as session_factory,
            ):
                session = mock.MagicMock()
                session_factory.return_value.__aenter__.return_value = session
                session.get.return_value.__aenter__.return_value.status = 404
                await nhmisc.NHMisc.nhmisc_emojichart.callback(cog, ctx, arguments="summary")
                self.assertTrue(ctx.sent[0]["file"].data.startswith(b"\x89PNG"))
                self.assertIn("Reactions: 2", ctx.sent[0]["embed"].fields[0].value)
                ctx.sent.clear()
                await nhmisc.NHMisc.nhmisc_emojichart.callback(cog, ctx, arguments="1 reactions")
                self.assertIn("Reactions: 1", ctx.sent[0]["embed"].fields[0].value)
                ctx.sent.clear()
                await nhmisc.NHMisc.nhmisc_emojichart.callback(
                    cog, ctx, arguments="<#100> 30 10 reactions")
                self.assertEqual(ctx.sent[0]["content"], "No recorded server emoji usage for this selection")
                for arguments in ("0", "31", "summary 21", "summary 10 invalid"):
                    with self.subTest(arguments=arguments), self.assertRaises(nhmisc.commands.UserFeedbackCheckFailure):
                        await nhmisc.NHMisc.nhmisc_emojichart.callback(cog, ctx, arguments=arguments)

    async def test_next_message_publishes_emoji_of_day_in_existing_daily_report(self):
        with TemporaryDirectory() as directory:
            store = nhmisc.ActivityStore(Path(directory) / "activity.sqlite3")
            await store.initialize()
            today = datetime.now(timezone.utc).date()
            yesterday = today - timedelta(days=1)
            emoji = nhmisc.EmojiInfo(7, "party", False)
            await store.record_message(
                1, yesterday, 12, 42, 100, None,
                datetime.combine(yesterday, datetime.min.time(), tzinfo=timezone.utc),
                emojis=(emoji,),
            )
            guild = SimpleNamespace(id=1, name="Test", member_count=100, emojis=[])
            report_channel = SimpleNamespace(send=mock.AsyncMock())
            cog = object.__new__(nhmisc.NHMisc)
            cog._activity_store = store
            cog._bot_proxy = None
            cog._utc_today = lambda: today
            cog.config = SimpleNamespace(guild=lambda _: SimpleNamespace(all=mock.AsyncMock(return_value={
                "activity_channel": 300, "activity_history_retention_days": -1,
                "activity_detail_retention_days": 31,
            })))
            cog._support = SimpleNamespace(get_log_channel=lambda *_: report_channel)
            message = SimpleNamespace(guild=guild, author=SimpleNamespace(id=42, bot=False),
                                      webhook_id=None, type=0, content="hello", channel=SimpleNamespace(id=100))
            with mock.patch.object(nhmisc.discord, "Embed", Embed):
                await cog.on_message(message)
            report_channel.send.assert_awaited_once()
            embed = report_channel.send.call_args.kwargs["embed"]
            self.assertEqual(
                [(field.name, field.value) for field in embed.fields if field.name == "Emoji of the Day"],
                [("Emoji of the Day", "<:party:7>")],
            )

    async def test_leaving_guild_deletes_emoji_counters(self):
        with TemporaryDirectory() as directory:
            store = nhmisc.ActivityStore(Path(directory) / "activity.sqlite3")
            await store.initialize()
            today = datetime.now(timezone.utc).date()
            emoji = nhmisc.EmojiInfo(7, "party", False)
            await store.record_emoji_reaction(1, today, 100, emoji, 1)
            await store.record_emoji_reaction(2, today, 200, emoji, 1)
            cog = object.__new__(nhmisc.NHMisc)
            cog._activity_store = store
            await cog.on_emoji_guild_remove(SimpleNamespace(id=1))
            self.assertEqual(await store.get_emoji_counts(1, today, None), [])
            self.assertEqual(await store.get_emoji_counts(1, today, 30), [])
            self.assertEqual(len(await store.get_emoji_counts(2, today, None)), 1)
