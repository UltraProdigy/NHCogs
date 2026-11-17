import io
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

import aiohttp
from PIL import Image

from tests.test_chatchart import FakeContext, nhmisc
from tests.test_emoji_tracking import Embed


class EmojiChartIconTests(unittest.TestCase):
    def test_chart_renders_icon_next_to_name_and_keeps_missing_icon_row(self):
        colour = (17, 231, 219, 255)
        buffer = io.BytesIO()
        Image.new("RGBA", (64, 64), colour).save(buffer, format="WEBP", lossless=True)
        chart = nhmisc.render_ranked_donut_chart(
            [(":party:", 20), (":missing:", 10)],
            other_count=5,
            title="Emoji usage",
            context_label="#general",
            center_unit="uses",
            donut_title="Emoji share",
            filename="emojichart.png",
            row_icons=[buffer.getvalue(), None],
        )
        with Image.open(io.BytesIO(chart.data)) as image:
            self.assertGreater(image.convert("RGBA").tobytes().count(bytes(colour)), 100)

    def test_animated_icon_uses_first_frame_in_png(self):
        first_colour = (17, 231, 219, 255)
        second_colour = (100, 8, 90, 255)
        buffer = io.BytesIO()
        Image.new("RGBA", (64, 64), first_colour).save(
            buffer, format="GIF", save_all=True,
            append_images=[Image.new("RGBA", (64, 64), second_colour)], duration=100,
        )
        chart = nhmisc.render_ranked_donut_chart(
            [(":animated:", 20)], other_count=0, title="Emoji usage",
            context_label=None, center_unit="uses", donut_title="Emoji share",
            filename="emojichart.png", row_icons=[buffer.getvalue()],
        )
        with Image.open(io.BytesIO(chart.data)) as image:
            pixels = image.convert("RGBA").tobytes()
            self.assertGreater(pixels.count(bytes(first_colour)), 100)
            self.assertEqual(pixels.count(bytes(second_colour)), 0)


class IconResponse:
    def __init__(self, data, status=200):
        self.status = status
        self.data = data
        self.content = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def iter_chunked(self, _size):
        yield self.data


class IconSession:
    def __init__(self, data):
        self.data = data
        self.status = 200
        self.urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def get(self, url, **_kwargs):
        self.urls.append(url)
        return IconResponse(self.data, self.status)


class EmojiChartDownloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_chart_downloads_selected_emoji_from_discord_and_embeds_it(self):
        colour = (17, 231, 219, 255)
        buffer = io.BytesIO()
        Image.new("RGBA", (64, 64), colour).save(buffer, format="WEBP", lossless=True)
        client = IconSession(buffer.getvalue())
        with TemporaryDirectory() as directory:
            store = nhmisc.ActivityStore(Path(directory) / "activity.sqlite3")
            await store.initialize()
            today = datetime.now(timezone.utc).date()
            await store.record_emoji_reaction(1, today, 100, nhmisc.EmojiInfo(7, "party", False), 1)
            cog = object.__new__(nhmisc.NHMisc)
            cog._activity_store = store
            cog._utc_today = lambda: today
            cog._close_stale_activity_days_for_guild = mock.AsyncMock()
            cog.bot = SimpleNamespace(intents=SimpleNamespace(
                guild_messages=True, message_content=True,
                guild_reactions=True, emojis_and_stickers=True))
            ctx = FakeContext(SimpleNamespace(id=1, name="Test server"))
            with (
                mock.patch.object(aiohttp, "ClientSession", return_value=client),
                mock.patch.object(nhmisc.discord, "Embed", Embed),
            ):
                await nhmisc.NHMisc.nhmisc_emojichart.callback(cog, ctx)
            with Image.open(io.BytesIO(ctx.sent[0]["file"].data)) as image:
                self.assertGreater(image.convert("RGBA").tobytes().count(bytes(colour)), 100)
            self.assertEqual(client.urls, [
                "https://cdn.discordapp.com/emojis/7.webp?size=64&quality=lossless"])
            client.status = 404
            ctx.sent.clear()
            with (
                mock.patch.object(aiohttp, "ClientSession", return_value=client),
                mock.patch.object(nhmisc.discord, "Embed", Embed),
            ):
                await nhmisc.NHMisc.nhmisc_emojichart.callback(cog, ctx)
            self.assertTrue(ctx.sent[0]["file"].data.startswith(b"\x89PNG"))
            self.assertEqual(ctx.sent[0]["embed"].fields[0].name, "1. :party:")
            self.assertIn("Reactions: 1", ctx.sent[0]["embed"].fields[0].value)
