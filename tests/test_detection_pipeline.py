import asyncio
import base64
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from importlib import util
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Event, get_ident
from types import ModuleType, SimpleNamespace
from unittest import mock
import sys
import unittest

from tests.detection_case_fixtures import (
    capture_attachment,
    publish_evidence,
    publish_primary,
)


PACKAGE_DIR = Path(__file__).resolve().parents[1] / "Honeypot"
_MISSING = object()


def _load_module(name: str, path: Path):
    spec = util.spec_from_file_location(name, path)
    module = util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _listener(*args, **kwargs):
    def apply(function):
        function.__cog_listener__ = True
        return function

    return apply


class _BoundLoop:
    def __init__(self, function, instance, options, before):
        self.function = function
        self.instance = instance
        self.options = options
        self.before = before
        self.started = False
        self.cancelled = False

    def start(self):
        if self.started:
            raise RuntimeError("loop already started")
        self.started = True

    def cancel(self):
        self.cancelled = True

    async def wait_before_start(self):
        await self.before(self.instance)


class _LoopStub:
    def __init__(self, function, options):
        self.function = function
        self.options = options
        self.before = None
        self.bound = {}

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return self.bound.setdefault(
            instance,
            _BoundLoop(self.function, instance, self.options, self.before),
        )

    def before_loop(self, function):
        self.before = function
        return function


class _Config:
    def register_guild(self, **defaults):
        self.defaults = defaults


class _Cog:
    def __init__(self, *, bot):
        self.bot = bot

    async def cog_load(self):
        self.base_loaded = True

    async def cog_unload(self):
        self.base_unloaded = True


@contextmanager
def _isolated_honeypot_modules(data_path: Path):
    names = (
        "discord",
        "discord.ext",
        "discord.ext.tasks",
        "redbot",
        "redbot.core",
        "redbot.core.commands",
        "redbot.core.bot",
        "redbot.core.data_manager",
        "redbot.core.i18n",
        "redbot.core.utils",
        "redbot.core.utils.chat_formatting",
        "AAA3A_utils",
        "Honeypot",
        "Honeypot.image_detector",
        "Honeypot.detection_cases",
        "Honeypot.detection_runtime",
        "Honeypot.honeypot",
    )
    previous = {name: sys.modules.get(name, _MISSING) for name in names}

    discord = ModuleType("discord")
    for name in (
        "AllowedMentions",
        "Attachment",
        "ButtonStyle",
        "Color",
        "Embed",
        "File",
        "Guild",
        "Interaction",
        "Member",
        "Message",
        "Object",
        "PermissionOverwrite",
        "Role",
        "SelectOption",
        "TextChannel",
        "Thread",
        "User",
    ):
        setattr(discord, name, object)
    discord.Forbidden = type("Forbidden", (Exception,), {})
    discord.HTTPException = type("HTTPException", (Exception,), {})
    discord.NotFound = type("NotFound", (discord.HTTPException,), {})
    discord.ButtonStyle = SimpleNamespace(danger=1, secondary=2, success=3, primary=4)
    discord.ui = SimpleNamespace(
        Button=object,
        Select=object,
        View=object,
        button=lambda *args, **kwargs: (lambda function: function),
    )
    discord.ext = ModuleType("discord.ext")
    tasks = SimpleNamespace(
        loop=lambda *args, **kwargs: (lambda function: _LoopStub(function, kwargs))
    )
    discord.ext.tasks = tasks

    def decorator(*args, **kwargs):
        def apply(function):
            function.command = decorator
            function.group = decorator
            return function

        return apply

    commands = SimpleNamespace(
        Cog=SimpleNamespace(listener=_listener),
        Context=object,
        Group=type("Group", (), {}),
        UserFeedbackCheckFailure=Exception,
        group=decorator,
        command=decorator,
        guild_only=lambda: (lambda function: function),
        admin_or_permissions=lambda **kwargs: (lambda function: function),
        bot_has_guild_permissions=lambda **kwargs: (lambda function: function),
        permissions_check=lambda predicate: (lambda function: function),
    )
    redbot = ModuleType("redbot")
    redbot.core = ModuleType("redbot.core")
    redbot.core.Config = SimpleNamespace(get_conf=lambda *args, **kwargs: _Config())
    redbot.core.commands = commands
    redbot.core.modlog = SimpleNamespace()
    redbot.core.bot = ModuleType("redbot.core.bot")
    redbot.core.bot.Red = object
    redbot.core.data_manager = ModuleType("redbot.core.data_manager")
    redbot.core.data_manager.cog_data_path = lambda cog: data_path
    redbot.core.i18n = ModuleType("redbot.core.i18n")
    redbot.core.i18n.Translator = lambda *args, **kwargs: (lambda text: text)
    redbot.core.i18n.cog_i18n = lambda translator: (lambda cls: cls)
    redbot.core.utils = ModuleType("redbot.core.utils")
    formatting = ModuleType("redbot.core.utils.chat_formatting")
    formatting.box = lambda text, *args, **kwargs: text

    def pagify(text, *, page_length=2000, **kwargs):
        pages = []
        start = 0
        while start < len(text):
            end = min(start + page_length, len(text))
            if end < len(text):
                boundary = max(text.rfind("\n", start, end), text.rfind(" ", start, end))
                end = boundary + 1 if boundary > start else end
            pages.append(text[start:end])
            start = end
        return pages

    formatting.pagify = pagify
    redbot.core.utils.chat_formatting = formatting
    aaa3a_utils = ModuleType("AAA3A_utils")
    aaa3a_utils.Cog = _Cog
    package = ModuleType("Honeypot")
    package.__path__ = [str(PACKAGE_DIR)]

    try:
        sys.modules.update(
            {
                "discord": discord,
                "discord.ext": discord.ext,
                "discord.ext.tasks": tasks,
                "redbot": redbot,
                "redbot.core": redbot.core,
                "redbot.core.commands": commands,
                "redbot.core.bot": redbot.core.bot,
                "redbot.core.data_manager": redbot.core.data_manager,
                "redbot.core.i18n": redbot.core.i18n,
                "redbot.core.utils": redbot.core.utils,
                "redbot.core.utils.chat_formatting": formatting,
                "AAA3A_utils": aaa3a_utils,
                "Honeypot": package,
            }
        )
        _load_module("Honeypot.image_detector", PACKAGE_DIR / "image_detector.py")
        _load_module("Honeypot.detection_cases", PACKAGE_DIR / "detection_cases.py")
        runtime = _load_module(
            "Honeypot.detection_runtime", PACKAGE_DIR / "detection_runtime.py"
        )

        async def test_bounded_reader(attachment, max_bytes):
            data = await attachment.read(use_cached=True)
            return data[: max_bytes + 1]

        runtime.read_attachment_bounded = test_bounded_reader
        yield _load_module("Honeypot.honeypot", PACKAGE_DIR / "honeypot.py")
    finally:
        for name, module in previous.items():
            if module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


class _Bot:
    def __init__(self, ready=True):
        self.ready = asyncio.Event()
        if ready:
            self.ready.set()

    async def wait_until_red_ready(self):
        await self.ready.wait()

    def add_view(self, view, *, message_id=None):
        self.restored_views = getattr(self, "restored_views", [])
        self.restored_views.append((view, message_id))

    def get_guild(self, guild_id):
        return None


class DetectionPipelineLifecycleTests(unittest.IsolatedAsyncioTestCase):

    async def test_load_ignores_stale_pending_reviews_when_there_are_no_open_cases(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                bot = _Bot()
                cog = honeypot.Honeypot(bot)

                class StaleConfig:
                    def __init__(self):
                        self.read_count = 0

                    async def all_guilds(self):
                        self.read_count += 1
                        return {
                            1: {
                                "pending_reviews": {
                                    "99": {
                                        "target_id": 2,
                                        "review_channel_id": 3,
                                        "expires_at": "2099-01-01T00:00:00+00:00",
                                    }
                                }
                            }
                        }

                class Store:
                    def initialize(self):
                        return None

                    def reconcile_moderator_actions(self, now):
                        return ()

                    def list_open_cases(self):
                        return ()

                    def list_due_cases(self, now):
                        return ()

                    def claim_due_operations(self, now, limit, stale_before):
                        return ()

                    def list_reconcilable_cases(self, now, stale_before):
                        return ()

                    def list_planned_case_deletions(self):
                        return ()

                    def list_orphan_publications(self):
                        return ()

                stale_config = StaleConfig()
                cog.config = stale_config
                cog._case_store = Store()
                cog._init_firstpost_seen_store = _async_noop
                cog._init_imagescan_store = _async_noop
                cog._flush_firstpost_seen_authors = _async_noop

                await cog.cog_load()
                try:
                    await cog._case_restore_task
                    await asyncio.sleep(0)

                    self.assertEqual(stale_config.read_count, 0)
                    self.assertEqual(getattr(bot, "restored_views", []), [])
                finally:
                    await cog.cog_unload()

    def test_honeypot_has_no_legacy_pending_review_members(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                forbidden = {
                    "_store_pending_review",
                    "_delete_pending_review",
                    "_restore_pending_reviews",
                    "_merge_into_active_review",
                    "_handle_imagescan_message",
                    "_handle_spam_message",
                    "_handle_firstpost_message",
                    "_handle_imagescan_detector_message",
                    "_prepare_imagescan_learning_feedback",
                    "_send_imagescan_feedback_messages",
                }

                self.assertEqual(
                    {name for name in forbidden if hasattr(honeypot.Honeypot, name)},
                    set(),
                )
                self.assertEqual(
                    {
                        name
                        for name in {
                            "imagescan_feedback_items",
                            "imagescan_detector_batches",
                            "ImageScanFeedbackSelect",
                            "ImageScanFeedbackView",
                        }
                        if hasattr(honeypot, name)
                    },
                    set(),
                )

    async def test_load_initializes_case_storage_before_restoring_and_starts_loops(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                initialize_started = Event()
                allow_initialize_finish = Event()
                restore_called = Event()
                initialize_observations = []
                event_loop_thread_id = get_ident()

                class Store:
                    def initialize(self):
                        initialize_observations.append(
                            (get_ident(), cog._detection_case_files_path.is_dir())
                        )
                        initialize_started.set()
                        if not allow_initialize_finish.wait(timeout=2):
                            raise TimeoutError("test did not release case-store initialization")

                    def reconcile_moderator_actions(self, now):
                        return ()

                    def list_open_cases(self):
                        restore_called.set()
                        return ()

                    def list_due_cases(self, now):
                        return ()

                    def claim_due_operations(self, now, limit, stale_before):
                        return ()

                    def list_reconcilable_cases(self, now, stale_before):
                        return ()

                    def list_planned_case_deletions(self):
                        return ()

                    def list_orphan_publications(self):
                        return ()

                cog._case_store = Store()
                cog._init_firstpost_seen_store = _async_noop
                cog._init_imagescan_store = _async_noop

                self.assertEqual(cog._detection_case_db_path, data_path / "detection_cases.sqlite")
                self.assertEqual(cog._detection_case_files_path, data_path / "detection_case_files")
                self.assertEqual(cog._case_views, {})
                self.assertFalse(cog._detection_case_files_path.exists())

                load_task = asyncio.create_task(cog.cog_load())
                try:
                    self.assertTrue(
                        await asyncio.to_thread(initialize_started.wait, 2),
                        "case-store initialization did not start",
                    )
                    self.assertFalse(load_task.done())
                    self.assertFalse(cog.detection_case_loop.started)
                    self.assertFalse(cog.detection_reconciliation_loop.started)
                    self.assertFalse(restore_called.is_set())
                finally:
                    allow_initialize_finish.set()

                await asyncio.wait_for(load_task, timeout=2)
                await cog._case_restore_task

                self.assertEqual(len(initialize_observations), 1)
                initialize_thread_id, evidence_directory_existed = initialize_observations[0]
                self.assertNotEqual(initialize_thread_id, event_loop_thread_id)
                self.assertTrue(evidence_directory_existed)
                self.assertTrue(restore_called.is_set())
                for loop_name in (
                    "joinwatch_auto_role_loop",
                    "purge_cache_cleanup_loop",
                    "firstpost_seen_flush_loop",
                    "detection_case_loop",
                    "detection_reconciliation_loop",
                ):
                    self.assertTrue(getattr(cog, loop_name).started, loop_name)
                self.assertEqual(cog.detection_case_loop.options, {"minutes": 1})
                self.assertEqual(cog.detection_reconciliation_loop.options, {"minutes": 5})

                await cog.cog_unload()

    async def test_unload_cancels_case_loops_and_case_restore(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                restore_started = asyncio.Event()
                restore_cleanup_finished = asyncio.Event()

                async def restore_until_cancelled():
                    restore_started.set()
                    try:
                        await asyncio.Event().wait()
                    finally:
                        restore_cleanup_finished.set()

                cog._init_firstpost_seen_store = _async_noop
                cog._init_imagescan_store = _async_noop
                cog._restore_detection_case_views = restore_until_cancelled
                cog._flush_firstpost_seen_authors = _async_noop

                await cog.cog_load()
                restore_task = cog._case_restore_task
                await asyncio.wait_for(restore_started.wait(), timeout=2)
                self.assertFalse(restore_task.done())

                try:
                    await cog.cog_unload()

                    for loop_name in (
                        "joinwatch_auto_role_loop",
                        "purge_cache_cleanup_loop",
                        "firstpost_seen_flush_loop",
                        "detection_case_loop",
                        "detection_reconciliation_loop",
                    ):
                        self.assertTrue(getattr(cog, loop_name).cancelled, loop_name)
                    self.assertTrue(restore_task.cancelled())
                    self.assertTrue(restore_cleanup_finished.is_set())
                    self.assertIsNone(cog._case_restore_task)
                finally:
                    restore_task.cancel()
                    await asyncio.gather(restore_task, return_exceptions=True)

    async def test_failed_case_restore_is_logged_and_cleared_on_unload(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                restore_failed = Event()

                class Store:
                    def initialize(self):
                        return None

                    def reconcile_moderator_actions(self, now):
                        return ()

                    def list_open_cases(self):
                        restore_failed.set()
                        raise RuntimeError("restore failed")

                    def list_due_cases(self, now):
                        return ()

                    def claim_due_operations(self, now, limit, stale_before):
                        return ()

                    def list_reconcilable_cases(self, now, stale_before):
                        return ()

                    def list_planned_case_deletions(self):
                        return ()

                    def list_orphan_publications(self):
                        return ()

                cog._case_store = Store()
                cog._init_firstpost_seen_store = _async_noop
                cog._init_imagescan_store = _async_noop
                cog._flush_firstpost_seen_authors = _async_noop

                with mock.patch.object(honeypot.log, "error") as log_error:
                    await cog.cog_load()
                    self.assertTrue(
                        await asyncio.to_thread(restore_failed.wait, 2),
                        "case restoration did not fail",
                    )
                    await asyncio.sleep(0)

                    log_error.assert_called_once()
                    self.assertIn("detection case", log_error.call_args.args[1])
                    await cog.cog_unload()

                self.assertIsNone(cog._case_restore_task)

    async def test_case_loops_wait_for_red_readiness(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                bot = _Bot(ready=False)
                cog = honeypot.Honeypot(bot)

                waiters = [
                    asyncio.create_task(cog.detection_case_loop.wait_before_start()),
                    asyncio.create_task(cog.detection_reconciliation_loop.wait_before_start()),
                ]
                await asyncio.sleep(0)
                self.assertTrue(all(not waiter.done() for waiter in waiters))

                bot.ready.set()
                await asyncio.gather(*waiters)


class DetectionSignalCollectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_detection_stats_cover_detector_hits_intents_and_catches(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._increment_stat = mock.AsyncMock()
                guild = SimpleNamespace(id=10)
                signals = (
                    honeypot.DetectionSignal(
                        "firstpost",
                        "young account",
                        honeypot.ActionIntent.REVIEW,
                        True,
                        {},
                    ),
                    honeypot.DetectionSignal(
                        "spam",
                        "duplicate",
                        honeypot.ActionIntent.BAN,
                        True,
                        {},
                    ),
                )

                await cog._record_detection_stats(guild, signals)

                keys = [call.args[1] for call in cog._increment_stat.await_args_list]
                self.assertEqual(
                    set(keys),
                    {
                        "detections",
                        "suspicious",
                        "firstpost_hits",
                        "firstpost_reviews",
                        "early_catches",
                        "spam_hits",
                        "spam_bans",
                        "spam_catches",
                    },
                )

    async def test_whitelist_bypass_only_increments_whitelisted_stat(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                cog._increment_stat = mock.AsyncMock()
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                guild = SimpleNamespace(id=10)
                message = SimpleNamespace(
                    id=40,
                    guild=guild,
                    author=SimpleNamespace(
                        id=20,
                        display_name="Allowed User",
                        display_avatar=None,
                        created_at=now,
                        joined_at=now,
                    ),
                    channel=SimpleNamespace(id=30),
                    content="allowed message",
                    created_at=now,
                    jump_url="https://discord.com/channels/10/30/40",
                    attachments=[],
                )
                signal = honeypot.DetectionSignal(
                    "honeypot",
                    "Message posted in a configured honeypot channel",
                    honeypot.ActionIntent.NONE,
                    True,
                    {"whitelist_bypass": True},
                )

                await cog._process_detected_message(
                    message,
                    {"review_enabled": True},
                    None,
                    (signal,),
                )

                self.assertEqual(
                    [call.args[1] for call in cog._increment_stat.await_args_list],
                    ["whitelisted"],
                )

    @staticmethod
    def _message(*, attachments=None, content="", channel_id=3, roles=()):
        return SimpleNamespace(
            id=42,
            guild=SimpleNamespace(id=1),
            author=SimpleNamespace(id=2, roles=list(roles)),
            channel=SimpleNamespace(id=channel_id),
            content=content,
            attachments=list(attachments or []),
        )

    async def test_active_forward_purge_collects_decisive_containment_signal(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = SimpleNamespace(
                    id=42,
                    guild=SimpleNamespace(id=1),
                    author=SimpleNamespace(id=2),
                    channel=SimpleNamespace(id=3),
                    content="",
                    attachments=[],
                )
                cog._is_forward_purge_active = mock.Mock(return_value=True)
                message.delete = mock.AsyncMock()

                signals = await cog._collect_detection_signals(message, {})

                self.assertEqual(len(signals), 1)
                signal = signals[0]
                self.assertEqual(signal.detector, "forward_purge")
                self.assertEqual(signal.action, honeypot.ActionIntent.REVIEW)
                self.assertTrue(signal.decisive)
                self.assertTrue(signal.metadata["containment_required"])
                message.delete.assert_not_awaited()

    async def test_forward_purge_retains_cheap_context_and_skips_image_and_effects(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = self._message(attachments=[object()] * 4)
                message.delete = mock.AsyncMock()
                cog._is_forward_purge_active = mock.Mock(return_value=True)
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._mark_firstpost_seen = mock.AsyncMock(return_value=True)
                cog._firstpost_loaded_guilds.add(message.guild.id)
                cog._initial_image_signal = mock.AsyncMock()
                cog._send_review = mock.AsyncMock()
                cog._send_log = mock.AsyncMock()
                cog._increment_stat = mock.AsyncMock()

                signals = await cog._collect_detection_signals(
                    message,
                    {
                        "spam_enabled": True,
                        "spam_action": "review",
                        "firstpost_enabled": True,
                        "firstpost_action": "kick",
                        "imagescan_detector_enabled": True,
                    },
                )

                self.assertEqual(
                    [signal.detector for signal in signals],
                    ["forward_purge", "spam", "firstpost"],
                )
                cog._initial_image_signal.assert_not_awaited()
                message.delete.assert_not_awaited()
                cog._send_review.assert_not_awaited()
                cog._send_log.assert_not_awaited()
                cog._increment_stat.assert_not_awaited()

    async def test_spam_and_firstpost_signals_are_both_collected_in_priority_order(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = self._message(attachments=[object()] * 4)
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._mark_firstpost_seen = mock.AsyncMock(return_value=True)
                cog._firstpost_loaded_guilds.add(message.guild.id)

                signals = await cog._collect_detection_signals(
                    message,
                    {
                        "spam_enabled": True,
                        "spam_action": "none",
                        "firstpost_enabled": True,
                        "firstpost_action": "kick",
                    },
                )

                self.assertEqual([signal.detector for signal in signals], ["spam", "firstpost"])
                self.assertEqual(signals[0].action, honeypot.ActionIntent.NONE)
                self.assertEqual(signals[1].action, honeypot.ActionIntent.KICK)
                cog._mark_firstpost_seen.assert_not_awaited()

    async def test_invalid_spam_action_defaults_to_review(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = self._message()
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])

                signals = await cog._collect_detection_signals(
                    message, {"spam_enabled": True, "spam_action": "invalid"}
                )

                self.assertEqual(signals[0].action, honeypot.ActionIntent.REVIEW)

    async def test_dry_run_preserves_spam_action_intent(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = self._message()
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])

                signals = await cog._collect_detection_signals(
                    message,
                    {"dry_run": True, "spam_enabled": True, "spam_action": "review"},
                )

                self.assertEqual(signals[0].action, honeypot.ActionIntent.REVIEW)

    async def test_collector_does_not_filter_protected_members(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = self._message()
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._is_protected_member = mock.AsyncMock(return_value=True)

                signals = await cog._collect_detection_signals(
                    message, {"spam_enabled": True, "spam_action": "review"}
                )

                self.assertEqual([signal.detector for signal in signals], ["spam"])
                cog._is_protected_member.assert_not_awaited()

    async def test_three_attachments_do_not_produce_a_firstpost_signal(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = self._message(attachments=[object()] * 3)
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._mark_firstpost_seen = mock.AsyncMock(return_value=True)
                cog._firstpost_loaded_guilds.add(message.guild.id)

                signals = await cog._collect_detection_signals(
                    message, {"firstpost_enabled": True}
                )

                self.assertEqual(signals, ())
                cog._mark_firstpost_seen.assert_not_awaited()

    async def test_collect_only_firstpost_does_not_reserve_before_case_append(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = self._message(attachments=[object()] * 4)
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._mark_firstpost_seen = mock.AsyncMock(return_value=True)
                cog._firstpost_loaded_guilds.add(message.guild.id)

                signals = await cog._collect_detection_signals(
                    message, {"firstpost_collect_enabled": True}
                )

                self.assertEqual(signals, ())
                cog._mark_firstpost_seen.assert_not_awaited()

    async def test_honeypot_channel_collects_signal_and_other_channel_does_not(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._suspicion_reasons = mock.AsyncMock(return_value=["young account"])
                config = {"honeypot_channels": [9], "action": "ban"}

                hit = await cog._collect_detection_signals(
                    self._message(channel_id=9), config
                )
                miss = await cog._collect_detection_signals(
                    self._message(channel_id=8), config
                )

                self.assertEqual([signal.detector for signal in hit], ["honeypot"])
                self.assertEqual(hit[0].action, honeypot.ActionIntent.BAN)
                self.assertEqual(miss, ())

    async def test_whitelist_bypass_still_collects_non_actionable_honeypot_signal(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                role = SimpleNamespace(id=7)

                signals = await cog._collect_detection_signals(
                    self._message(channel_id=9, roles=[role]),
                    {
                        "honeypot_channels": [9],
                        "whitelisted_roles": [7],
                        "whitelist_mode": "bypass",
                        "action": "ban",
                    },
                )

                self.assertEqual(signals[0].action, honeypot.ActionIntent.NONE)
                self.assertTrue(signals[0].metadata["whitelist_bypass"])

    async def test_forward_purge_is_preserved_for_whitelist_bypass_honeypot(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                role = SimpleNamespace(id=7)
                message = self._message(channel_id=9, roles=[role])
                cog._is_forward_purge_active = mock.Mock(return_value=True)
                cog._initial_image_signal = mock.AsyncMock()

                signals = await cog._collect_detection_signals(
                    message,
                    {
                        "honeypot_channels": [9],
                        "whitelisted_roles": [7],
                        "whitelist_mode": "bypass",
                    },
                )

                self.assertEqual(
                    [signal.detector for signal in signals],
                    ["forward_purge", "honeypot"],
                )
                self.assertEqual(signals[0].action, honeypot.ActionIntent.REVIEW)
                self.assertEqual(signals[1].action, honeypot.ActionIntent.NONE)
                cog._initial_image_signal.assert_not_awaited()

    async def test_image_signal_stops_after_first_match_and_returns_serializable_match(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await cog._init_imagescan_store()
                started = 0
                four_started = asyncio.Event()
                release_non_matches = asyncio.Event()

                def image_read(index):
                    async def read(*args, **kwargs):
                        nonlocal started
                        started += 1
                        if started == 4:
                            four_started.set()
                        if index != 3:
                            await release_non_matches.wait()
                        return f"image-{index}".encode()

                    return read

                attachments = [
                    SimpleNamespace(
                        filename=f"image-{index}.png",
                        content_type="image/png",
                        read=mock.AsyncMock(side_effect=image_read(index)),
                    )
                    for index in range(1, 7)
                ]
                for attachment in attachments:
                    async def read_bounded(max_bytes, *, _attachment=attachment):
                        data = await _attachment.read(use_cached=True)
                        return data[: max_bytes + 1]

                    attachment.read_bounded = read_bounded
                message = self._message(attachments=attachments)
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._imagescan_load_samples = mock.AsyncMock(
                    return_value=[SimpleNamespace(decision="true_positive")]
                )
                cog._imagescan_model_state = mock.AsyncMock(
                    return_value={"valid": True, "effective_threshold": 20}
                )
                cog._increment_stat = mock.AsyncMock()
                cog._snapshot_attachments = mock.AsyncMock()
                cog._send_review = mock.AsyncMock()
                cog._send_log = mock.AsyncMock()
                event_loop_thread = get_ident()
                match_threads = []

                def match(hashes, samples, threshold):
                    match_threads.append(get_ident())
                    return {
                        "matched": hashes["sha256"] == "image-3",
                        "exact_decision": "true_positive"
                        if hashes["sha256"] == "image-3"
                        else None,
                        "score": 0 if hashes["sha256"] == "image-3" else 3,
                    }

                with (
                    mock.patch.object(
                        honeypot,
                        "image_hashes_from_bytes",
                        side_effect=lambda data: {
                            "sha256": data.decode(),
                            "phash": "00",
                            "dhash": "00",
                            "ahash": "00",
                        },
                    ),
                    mock.patch.object(
                        honeypot,
                        "match_image",
                        side_effect=match,
                    ),
                ):
                    signal_task = asyncio.create_task(
                        cog._collect_detection_signals(
                            message,
                            {
                                "imagescan_detector_enabled": True,
                                "imagescan_detector_action": "invalid",
                            },
                        )
                    )
                    try:
                        await asyncio.sleep(0.05)
                        self.assertEqual(started, 4)
                        signals = await asyncio.wait_for(
                            asyncio.shield(signal_task), timeout=0.2
                        )
                        self.assertFalse(release_non_matches.is_set())
                    finally:
                        release_non_matches.set()
                        await signal_task

                self.assertEqual([signal.detector for signal in signals], ["image"])
                self.assertEqual(signals[0].action, honeypot.ActionIntent.REVIEW)
                self.assertEqual(
                    [match["position"] for match in signals[0].metadata["matches"]], [3]
                )
                self.assertEqual(signals[0].metadata["matches"][0]["exact_decision"], "true_positive")
                for attachment in attachments[:4]:
                    attachment.read.assert_awaited_once()
                for attachment in attachments[4:]:
                    attachment.read.assert_not_awaited()
                self.assertGreaterEqual(len(match_threads), 1)
                self.assertTrue(
                    all(thread_id != event_loop_thread for thread_id in match_threads)
                )
                profile = await asyncio.to_thread(
                    cog._imagescan_profile_sync, message.guild.id
                )
                self.assertEqual(profile["messages_scanned"], 1)
                self.assertEqual(profile["messages_with_images"], 1)
                self.assertGreaterEqual(profile["images_considered"], 1)
                self.assertEqual(profile["decision_ms_count"], 1)
                self.assertGreaterEqual(profile["download_ms_count"], 1)
                self.assertGreaterEqual(profile["hash_ms_count"], 1)
                self.assertGreaterEqual(profile["compare_ms_count"], 1)
                cog._increment_stat.assert_not_awaited()
                cog._snapshot_attachments.assert_not_awaited()
                cog._send_review.assert_not_awaited()
                cog._send_log.assert_not_awaited()

    async def test_four_negative_initial_images_do_not_scan_later_attachments(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                attachments = [
                    SimpleNamespace(
                        filename=f"image-{index}.png",
                        content_type="image/png",
                        read=mock.AsyncMock(return_value=f"image-{index}".encode()),
                    )
                    for index in range(1, 7)
                ]
                message = self._message(attachments=attachments)
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._imagescan_load_samples = mock.AsyncMock(
                    return_value=[SimpleNamespace(decision="true_positive")]
                )
                cog._imagescan_model_state = mock.AsyncMock(
                    return_value={"valid": True, "effective_threshold": 20}
                )
                cog._imagescan_increment_profile = mock.AsyncMock()
                with (
                    mock.patch.object(
                        honeypot,
                        "image_hashes_from_bytes",
                        side_effect=lambda data: {"sha256": data.decode()},
                    ),
                    mock.patch.object(
                        honeypot,
                        "match_image",
                        return_value={"matched": False, "score": None},
                    ),
                ):
                    signals = await cog._collect_detection_signals(
                        message,
                        {"imagescan_detector_enabled": True},
                    )

                self.assertNotIn(
                    (message.guild.id, message.id), cog._initial_image_scan_batches
                )

                self.assertEqual(signals, ())
                for attachment in attachments[:4]:
                    attachment.read.assert_awaited_once()
                for attachment in attachments[4:]:
                    attachment.read.assert_not_awaited()

    async def test_decisive_non_image_signal_skips_initial_image_reads(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                attachment = SimpleNamespace(
                    filename="image.png",
                    content_type="image/png",
                    read=mock.AsyncMock(),
                )
                message = self._message(attachments=[attachment])
                cog._is_forward_purge_active = mock.Mock(return_value=False)
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])

                signals = await cog._collect_detection_signals(
                    message,
                    {
                        "spam_enabled": True,
                        "spam_action": "none",
                        "imagescan_detector_enabled": True,
                    },
                )

                self.assertEqual([signal.detector for signal in signals], ["spam"])
                attachment.read.assert_not_awaited()



class ThreadBackedCasePublicationTests(unittest.IsolatedAsyncioTestCase):
    async def test_case_publication_serializes_overlapping_renders(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                first_started = asyncio.Event()
                release_first = asyncio.Event()
                active = 0
                max_active = 0
                calls = 0

                async def render(*args, **kwargs):
                    nonlocal active, max_active, calls
                    calls += 1
                    active += 1
                    max_active = max(max_active, active)
                    try:
                        if calls == 1:
                            first_started.set()
                            await release_first.wait()
                    finally:
                        active -= 1

                cog._publish_detection_case_serial = render
                first = asyncio.create_task(
                    cog._publish_detection_case("case-1", {}, None)
                )
                await asyncio.wait_for(first_started.wait(), timeout=1)
                second = asyncio.create_task(
                    cog._publish_detection_case("case-1", {}, None)
                )
                await asyncio.sleep(0)

                self.assertEqual(max_active, 1)
                release_first.set()
                await asyncio.gather(first, second)
                self.assertEqual(calls, 2)
                self.assertEqual(max_active, 1)

    async def test_reclaimed_timeline_publication_adopts_same_nonce_message(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime.now(timezone.utc)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10, 20, 30, 40, "content", now, None, ()
                    ),
                    (),
                )
                publication = await asyncio.to_thread(
                    cog._case_store.ensure_timeline_publication,
                    appended.case.case_id,
                    kind="message",
                    message_sequence=1,
                )
                stale = await asyncio.to_thread(
                    cog._case_store.claim_timeline_publication,
                    publication.logical_key,
                    now,
                )
                winner = await asyncio.to_thread(
                    cog._case_store.claim_timeline_publication,
                    publication.logical_key,
                    now + timedelta(minutes=6),
                )
                await asyncio.to_thread(
                    cog._case_store.complete_timeline_publication,
                    winner.logical_key,
                    winner.claim_token,
                    channel_id=60,
                    message_id=70,
                    revision=1,
                )
                sent = SimpleNamespace(id=70, delete=mock.AsyncMock())

                await cog._complete_case_timeline_publication(stale, sent, 60)

                sent.delete.assert_not_awaited()

    async def test_failed_orphan_compensation_is_retried_durably(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime.now(timezone.utc)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10, 20, 30, 40, "content", now, None, ()
                    ),
                    (),
                )
                orphan = SimpleNamespace(
                    id=70,
                    delete=mock.AsyncMock(
                        side_effect=honeypot.discord.HTTPException()
                    ),
                )

                await cog._compensate_case_publication(
                    appended.case.case_id, 60, orphan
                )
                await cog._compensate_case_publication(
                    appended.case.case_id, 60, orphan
                )

                self.assertEqual(
                    await asyncio.to_thread(
                        cog._case_store.list_orphan_publications
                    ),
                    ((appended.case.case_id, 10, 60, 70),),
                )
                recovered = SimpleNamespace(delete=mock.AsyncMock())
                channel = SimpleNamespace(
                    fetch_message=mock.AsyncMock(return_value=recovered)
                )
                cog.bot.get_guild = mock.Mock(return_value=SimpleNamespace(id=10))
                cog._fetch_text_channel_or_thread = mock.AsyncMock(
                    return_value=channel
                )

                await cog._retry_detection_orphan_publications()

                recovered.delete.assert_awaited_once()
                self.assertEqual(
                    await asyncio.to_thread(
                        cog._case_store.list_orphan_publications
                    ),
                    (),
                )

    async def test_timeline_card_keeps_source_url_and_human_image_match_details(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                attachment = SimpleNamespace(
                    key=honeypot.AttachmentKey("case-1", 1, 0),
                    filename="proof.png",
                    capture_status="captured",
                    match_metadata={
                        "matched_filename": "known-scam.png",
                        "hash_diff": 3,
                    },
                    learning_decision=None,
                    publication_error=None,
                )
                message = SimpleNamespace(
                    sequence=1,
                    channel_id=30,
                    created_at=datetime(2026, 7, 14, 12, tzinfo=timezone.utc),
                    delete_status="Deleted",
                    signal_reasons=("Image matched",),
                    content="suspicious",
                    jump_url="https://discord.com/channels/10/30/40",
                    attachments=(attachment,),
                )

                content = honeypot.Honeypot._case_timeline_message_content(message)

                self.assertIn(message.jump_url, content)
                self.assertIn("matched known-scam.png", content)
                self.assertIn("hash difference 3", content)

    async def test_long_timeline_message_preserves_fenced_content_source_and_attachment_details(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                source_url = "https://discord.com/channels/10/30/40"
                source_content = "before ``` embedded fence\n" + ("x" * 3500)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10,
                        20,
                        30,
                        40,
                        source_content,
                        now,
                        source_url,
                        (
                            honeypot.NewAttachment(
                                0,
                                "proof.png",
                                123,
                                "image/png",
                                640,
                                480,
                                "https://cdn.test/proof.png",
                                description="evidence",
                                spoiler=False,
                            ),
                        ),
                    ),
                    (),
                )
                await asyncio.to_thread(
                    cog._case_store.update_attachment_scan,
                    appended.case.case_id,
                    1,
                    0,
                    "sha256",
                    "phash",
                    {"matched_filename": "known-scam.png", "hash_diff": 3},
                    None,
                )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                next_id = 70

                async def send(*args, **kwargs):
                    nonlocal next_id
                    result = SimpleNamespace(id=next_id)
                    next_id += 1
                    return result

                thread = SimpleNamespace(
                    id=60,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    send=mock.AsyncMock(side_effect=send),
                    fetch_message=mock.AsyncMock(),
                )
                with mock.patch.object(
                    honeypot.discord,
                    "AllowedMentions",
                    SimpleNamespace(none=lambda: None),
                ):
                    await cog._publish_case_timeline(snapshot, thread, resolved=False)

                payloads = [
                    call.args[0]
                    for call in thread.send.await_args_list
                    if call.args[0].startswith("**Message 1")
                ]
                message_calls = [
                    call
                    for call in thread.send.await_args_list
                    if call.args[0].startswith("**Message 1")
                ]
                self.assertIsInstance(
                    message_calls[0].kwargs.get("view"),
                    honeypot.DetectionCaseView,
                )
                self.assertEqual(
                    message_calls[0].kwargs["view"].message_sequence,
                    1,
                )
                self.assertTrue(
                    all(
                        call.kwargs.get("view") is None
                        for call in message_calls[1:]
                    )
                )
                self.assertTrue(all(len(payload) <= 2000 for payload in payloads))
                self.assertTrue(all(payload.count("```") == 2 for payload in payloads))
                visible_content = "".join(
                    payload.split("```\n", 1)[1].split("\n```", 1)[0]
                    for payload in payloads
                ).replace("\u200b", "")
                rendered = "\n".join(payloads)
                self.assertEqual(visible_content, source_content)
                self.assertEqual(rendered.count(source_url), 1)
                self.assertNotIn("<#30>", rendered)
                self.assertNotIn("\n\n```\n", payloads[0])
                self.assertIn("proof.png", rendered)
                self.assertIn("matched known-scam.png", rendered)
                self.assertIn("hash difference 3", rendered)
                publications = sorted(
                    (
                        item
                        for item in await asyncio.to_thread(
                            cog._case_store.list_timeline_publications,
                            appended.case.case_id,
                        )
                        if item.kind == "message"
                    ),
                    key=lambda item: item.chunk_index,
                )
                self.assertEqual(
                    [item.chunk_index for item in publications],
                    list(range(len(payloads))),
                )
                self.assertTrue(
                    all(item.message_sequence == 1 for item in publications)
                )
                self.assertEqual(
                    len({item.logical_key for item in publications}),
                    len(publications),
                )

    async def test_each_timeline_message_receives_one_case_control_panel(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10, 20, 30, 40, "first", now, None, ()
                    ),
                    (),
                )
                await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10,
                        20,
                        30,
                        41,
                        "second",
                        now + timedelta(seconds=1),
                        None,
                        (),
                    ),
                    (),
                )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                next_id = 70

                async def send(*args, **kwargs):
                    nonlocal next_id
                    result = SimpleNamespace(id=next_id)
                    next_id += 1
                    return result

                thread = SimpleNamespace(
                    id=60,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    send=mock.AsyncMock(side_effect=send),
                    fetch_message=mock.AsyncMock(),
                )
                with mock.patch.object(
                    honeypot.discord,
                    "AllowedMentions",
                    SimpleNamespace(none=lambda: None),
                ):
                    await cog._publish_case_timeline(snapshot, thread, resolved=False)

                message_calls = [
                    call
                    for call in thread.send.await_args_list
                    if call.args and call.args[0].startswith("**Message ")
                ]
                self.assertEqual(len(message_calls), 2)
                self.assertTrue(
                    all(
                        isinstance(call.kwargs.get("view"), honeypot.DetectionCaseView)
                        for call in message_calls
                    )
                )
                self.assertTrue(
                    all(
                        call.kwargs["view"].case_id == appended.case.case_id
                        for call in message_calls
                    )
                )
                self.assertEqual(
                    [call.kwargs["view"].message_sequence for call in message_calls],
                    [1, 2],
                )

    async def test_incremental_timeline_publish_fills_earlier_gaps_in_order(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(10, 20, 30, 40, "first", now, None, ()),
                    (),
                )
                await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10, 20, 30, 41, "second", now + timedelta(seconds=1), None, ()
                    ),
                    (),
                )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                next_id = 70

                async def send(*args, **kwargs):
                    nonlocal next_id
                    result = SimpleNamespace(id=next_id)
                    next_id += 1
                    return result

                thread = SimpleNamespace(
                    id=60,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    send=mock.AsyncMock(side_effect=send),
                    fetch_message=mock.AsyncMock(),
                )

                with mock.patch.object(
                    honeypot.discord,
                    "AllowedMentions",
                    SimpleNamespace(none=lambda: None),
                ):
                    await cog._publish_case_timeline(
                        snapshot, thread, resolved=False, message_sequence=2
                    )

                payloads = [call.args[0] for call in thread.send.await_args_list]
                self.assertEqual(payloads[0], "**Case operation notes**\nNo current operation warnings.")
                self.assertTrue(payloads[1].startswith("**Message 1**"))
                self.assertTrue(payloads[2].startswith("**Message 2**"))
                thread.fetch_message.assert_not_awaited()

    async def test_incremental_timeline_does_not_edit_older_published_messages(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(10, 20, 30, 40, "first", now, None, ()),
                    (),
                )
                first_snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                next_id = 70

                async def send(*args, **kwargs):
                    nonlocal next_id
                    result = SimpleNamespace(id=next_id)
                    next_id += 1
                    return result

                fetched = {}

                async def fetch_message(message_id):
                    message = fetched.setdefault(
                        message_id, SimpleNamespace(id=message_id, edit=mock.AsyncMock())
                    )
                    return message

                thread = SimpleNamespace(
                    id=60,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    send=mock.AsyncMock(side_effect=send),
                    fetch_message=mock.AsyncMock(side_effect=fetch_message),
                )
                with mock.patch.object(
                    honeypot.discord,
                    "AllowedMentions",
                    SimpleNamespace(none=lambda: None),
                ):
                    await cog._publish_case_timeline(
                        first_snapshot, thread, resolved=False, message_sequence=1
                    )
                    await asyncio.to_thread(
                        cog._case_store.append_message,
                        honeypot.NewMessage(
                            10, 20, 30, 41, "second", now + timedelta(seconds=1), None, ()
                        ),
                        (),
                    )
                    second_snapshot = await asyncio.to_thread(
                        cog._case_store.get_case, appended.case.case_id
                    )
                    thread.fetch_message.reset_mock()
                    await cog._publish_case_timeline(
                        second_snapshot, thread, resolved=False, message_sequence=2
                    )

                fetched_ids = [call.args[0] for call in thread.fetch_message.await_args_list]
                self.assertNotIn(71, fetched_ids)
                new_payloads = [
                    call.args[0]
                    for call in thread.send.await_args_list
                    if call.args and call.args[0].startswith("**Message 2**")
                ]
                self.assertEqual(len(new_payloads), 1)

    async def test_first_publication_creates_one_summary_and_a_thread_timeline(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                bot = _Bot()
                cog = honeypot.Honeypot(bot)
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="copied scam content",
                        created_at=now,
                        jump_url="https://discord.test/channels/10/30/40",
                        attachments=(),
                    ),
                    (),
                )
                sent_messages = iter((SimpleNamespace(id=70), SimpleNamespace(id=71)))
                thread = SimpleNamespace(
                    id=60,
                    send=mock.AsyncMock(side_effect=lambda *args, **kwargs: next(sent_messages)),
                    fetch_message=mock.AsyncMock(),
                )
                summary = SimpleNamespace(
                    id=60,
                    edit=mock.AsyncMock(),
                    fetch_thread=mock.AsyncMock(side_effect=honeypot.discord.NotFound()),
                    create_thread=mock.AsyncMock(return_value=thread),
                )
                channel = SimpleNamespace(
                    id=50,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    send=mock.AsyncMock(return_value=summary),
                    fetch_message=mock.AsyncMock(return_value=summary),
                )
                summary.channel = channel
                guild = SimpleNamespace(
                    id=10,
                    get_channel=lambda channel_id: channel if channel_id == 50 else None,
                    get_thread=lambda thread_id: thread if thread_id == 60 else None,
                )
                bot.get_guild = lambda guild_id: guild
                cog._get_text_channel_or_thread = mock.Mock(
                    side_effect=lambda _guild, channel_id: channel if channel_id == 50 else thread
                )

                class Embed:
                    def __init__(self, **kwargs):
                        self.kwargs = kwargs
                        self.fields = []

                    def add_field(self, **kwargs):
                        self.fields.append(kwargs)

                with (
                    mock.patch.object(honeypot.discord, "Embed", Embed),
                    mock.patch.object(
                        honeypot.discord,
                        "Color",
                        SimpleNamespace(dark_red=lambda: 1, gold=lambda: 2),
                    ),
                    mock.patch.object(
                        honeypot.discord,
                        "AllowedMentions",
                        SimpleNamespace(none=lambda: None),
                    ),
                ):
                    await cog._publish_detection_case(
                        appended.case.case_id,
                        {"review_channel": 50},
                        None,
                    )

                endpoint = await asyncio.to_thread(
                    cog._case_store.get_projection_endpoint,
                    appended.case.case_id,
                )
                timeline = await asyncio.to_thread(
                    cog._case_store.list_timeline_publications,
                    appended.case.case_id,
                )
                channel.send.assert_awaited_once()
                self.assertEqual(
                    channel.send.await_args.kwargs["nonce"],
                    int(appended.case.case_id.replace("-", ""), 16)
                    & ((1 << 63) - 1),
                )
                self.assertNotIn("enforce_nonce", channel.send.await_args.kwargs)
                summary.fetch_thread.assert_awaited_once()
                summary.create_thread.assert_awaited_once()
                self.assertEqual(thread.send.await_count, 2)
                self.assertNotIn("enforce_nonce", thread.send.await_args_list[0].kwargs)
                self.assertNotIn("enforce_nonce", thread.send.await_args_list[1].kwargs)
                self.assertEqual(endpoint.summary_message_id, 60)
                self.assertEqual(endpoint.thread_id, 60)
                self.assertEqual(timeline[0].kind, "case_note")
                self.assertEqual(timeline[0].message_id, 70)
                payload = thread.send.await_args_list[1].args[0]
                source_url = "https://discord.test/channels/10/30/40"
                self.assertEqual(payload.count(source_url), 1)
                self.assertNotIn("<#30>", payload)
                self.assertIn(
                    "Signals:\n- Detection signal recorded\n```\n"
                    "copied scam content\n```",
                    payload,
                )

    async def test_thread_create_conflict_adopts_the_existing_attached_thread(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10, 20, 30, 40, "evidence", now, None, ()
                    ),
                    (),
                )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                thread = SimpleNamespace(id=60)
                summary = SimpleNamespace(
                    id=60,
                    channel=SimpleNamespace(id=50),
                    fetch_thread=mock.AsyncMock(
                        side_effect=[honeypot.discord.NotFound(), thread]
                    ),
                    create_thread=mock.AsyncMock(
                        side_effect=honeypot.discord.HTTPException()
                    ),
                )

                adopted = await cog._ensure_detection_case_thread(snapshot, summary)

                self.assertIs(adopted, thread)
                self.assertEqual(summary.fetch_thread.await_count, 2)
                endpoint = await asyncio.to_thread(
                    cog._case_store.get_projection_endpoint,
                    appended.case.case_id,
                )
                self.assertEqual(endpoint.thread_id, 60)

    async def test_evidence_batches_wait_until_every_attachment_is_terminal(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10,
                        20,
                        30,
                        40,
                        "copied content",
                        now,
                        None,
                        (
                            honeypot.NewAttachment(
                                0, "first.png", 5, "image/png", 10, 20, "https://cdn/first"
                            ),
                            honeypot.NewAttachment(
                                1, "second.png", 5, "image/png", 10, 20, "https://cdn/second"
                            ),
                        ),
                    ),
                    (),
                )
                evidence = data_path / "first.png"
                evidence.write_bytes(b"image")
                await asyncio.to_thread(
                    capture_attachment,
                    cog._case_store,
                    appended.case.case_id,
                    1,
                    0,
                    evidence,
                )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                message = snapshot.messages[0]
                message_attachments = tuple(
                    item for item in snapshot.attachments if item.message_sequence == 1
                )
                projected_message = SimpleNamespace(
                    attachments=message_attachments,
                    sequence=message.sequence,
                )
                thread = SimpleNamespace(
                    filesize_limit=8 * 1024 * 1024,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                )

                batches, oversized, _limit = cog._case_timeline_evidence_batches(
                    projected_message, thread
                )

                self.assertEqual(batches, ())
                self.assertEqual(oversized, ())

    async def test_timeline_chunks_image_evidence_into_ten_file_batches(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                attachments = tuple(
                    honeypot.NewAttachment(
                        position,
                        f"proof-{position}.png",
                        5,
                        "image/png",
                        10,
                        20,
                        f"https://cdn.test/{position}",
                        description=f"evidence {position}",
                        spoiler=position == 0,
                    )
                    for position in range(11)
                )
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10, 20, 30, 40, "copied content", now, None, attachments
                    ),
                    (),
                )
                for position in range(11):
                    evidence = data_path / f"proof-{position}.png"
                    evidence.write_bytes(b"image")
                    await asyncio.to_thread(
                        capture_attachment,
                        cog._case_store,
                        appended.case.case_id,
                        1,
                        position,
                        evidence,
                    )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                next_id = 70

                async def send(*args, **kwargs):
                    nonlocal next_id
                    result = SimpleNamespace(id=next_id)
                    next_id += 1
                    return result

                thread = SimpleNamespace(
                    id=60,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    send=mock.AsyncMock(side_effect=send),
                    fetch_message=mock.AsyncMock(),
                )
                created_files = []

                def make_file(path, **kwargs):
                    result = SimpleNamespace(path=path, **kwargs)
                    created_files.append(result)
                    return result

                with (
                    mock.patch.object(honeypot.discord, "File", side_effect=make_file),
                    mock.patch.object(
                        honeypot.discord,
                        "AllowedMentions",
                        SimpleNamespace(none=lambda: None),
                    ),
                ):
                    await cog._publish_case_timeline(snapshot, thread, resolved=False)

                self.assertEqual(thread.send.await_count, 4)
                self.assertNotIn("files", thread.send.await_args_list[1].kwargs)
                self.assertIsNone(thread.send.await_args_list[1].kwargs.get("view"))
                self.assertEqual(len(thread.send.await_args_list[2].kwargs["files"]), 10)
                self.assertEqual(len(thread.send.await_args_list[3].kwargs["files"]), 1)
                self.assertEqual(
                    thread.send.await_args_list[2].args[0],
                    "Message 1 attachments",
                )
                self.assertEqual(
                    thread.send.await_args_list[3].args[0],
                    "Message 1 attachments",
                )
                self.assertIsInstance(
                    thread.send.await_args_list[2].kwargs.get("view"),
                    honeypot.DetectionCaseView,
                )
                self.assertEqual(
                    thread.send.await_args_list[2].kwargs["view"].message_sequence,
                    1,
                )
                self.assertIsNone(thread.send.await_args_list[3].kwargs.get("view"))
                self.assertEqual(len(created_files), 11)
                self.assertTrue(created_files[0].spoiler)
                self.assertEqual(created_files[0].description, "evidence 0")
                publications = await asyncio.to_thread(
                    cog._case_store.list_timeline_publications,
                    appended.case.case_id,
                )
                self.assertEqual(
                    [item.kind for item in publications],
                    ["case_note", "evidence", "evidence", "message"],
                )
                self.assertTrue(all(item.state == "published" for item in publications))

    async def test_timeline_upload_limit_applies_to_each_file_not_batch_total(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                sizes = (14, 14, 11, 11)
                attachments = tuple(
                    honeypot.NewAttachment(
                        position,
                        f"proof-{position}.png",
                        size,
                        "image/png",
                        10,
                        20,
                        f"https://cdn.test/{position}",
                    )
                    for position, size in enumerate(sizes)
                )
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10, 20, 30, 40, "copied content", now, None, attachments
                    ),
                    (),
                )
                for position, size in enumerate(sizes):
                    evidence = data_path / f"proof-{position}.png"
                    evidence.write_bytes(b"x" * size)
                    await asyncio.to_thread(
                        capture_attachment,
                        cog._case_store,
                        appended.case.case_id,
                        1,
                        position,
                        evidence,
                    )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                next_id = 70

                async def send(*args, **kwargs):
                    nonlocal next_id
                    result = SimpleNamespace(id=next_id)
                    next_id += 1
                    return result

                thread = SimpleNamespace(
                    id=60,
                    guild=SimpleNamespace(filesize_limit=25),
                    send=mock.AsyncMock(side_effect=send),
                    fetch_message=mock.AsyncMock(),
                )
                with (
                    mock.patch.object(
                        honeypot.discord,
                        "File",
                        side_effect=lambda path, **kwargs: SimpleNamespace(
                            path=path, **kwargs
                        ),
                    ),
                    mock.patch.object(
                        honeypot.discord,
                        "AllowedMentions",
                        SimpleNamespace(none=lambda: None),
                    ),
                ):
                    await cog._publish_case_timeline(snapshot, thread, resolved=False)

                self.assertEqual(thread.send.await_count, 3)
                self.assertEqual(len(thread.send.await_args_list[2].kwargs["files"]), 4)

    async def test_evidence_rerender_replaces_batches_and_neutralizes_old_chunks(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                attachments = tuple(
                    honeypot.NewAttachment(
                        position,
                        f"proof-{position}.png",
                        5,
                        "image/png",
                        10,
                        20,
                        f"https://cdn.test/{position}",
                    )
                    for position in range(11)
                )
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10, 20, 30, 40, "copied content", now, None, attachments
                    ),
                    (),
                )
                for position in range(11):
                    evidence = data_path / f"proof-{position}.png"
                    evidence.write_bytes(b"image")
                    await asyncio.to_thread(
                        capture_attachment,
                        cog._case_store,
                        appended.case.case_id,
                        1,
                        position,
                        evidence,
                    )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                published = {}
                next_id = 70

                async def send(content, **kwargs):
                    nonlocal next_id
                    item = SimpleNamespace(
                        id=next_id,
                        content=content,
                        attachments=list(kwargs.get("files", ())),
                        view=kwargs.get("view"),
                    )

                    async def edit(**changes):
                        if "content" in changes:
                            item.content = changes["content"]
                        if "attachments" in changes:
                            item.attachments = list(changes["attachments"])
                        if "view" in changes:
                            item.view = changes["view"]
                        return item

                    item.edit = mock.AsyncMock(side_effect=edit)
                    published[next_id] = item
                    next_id += 1
                    return item

                thread = SimpleNamespace(
                    id=60,
                    filesize_limit=20,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    send=mock.AsyncMock(side_effect=send),
                    fetch_message=mock.AsyncMock(
                        side_effect=lambda message_id: published[message_id]
                    ),
                )
                with (
                    mock.patch.object(
                        honeypot.discord,
                        "File",
                        side_effect=lambda path, **kwargs: SimpleNamespace(
                            path=path, **kwargs
                        ),
                    ),
                    mock.patch.object(
                        honeypot.discord,
                        "AllowedMentions",
                        SimpleNamespace(none=lambda: None),
                    ),
                ):
                    await cog._publish_case_timeline(snapshot, thread, resolved=False)
                    first_send_count = thread.send.await_count
                    self.assertTrue(
                        all(
                            "nonce" in call.kwargs
                            for call in thread.send.await_args_list
                        )
                    )
                    (data_path / "proof-10.png").unlink()
                    await cog._publish_case_timeline(snapshot, thread, resolved=True)

                receipts = await asyncio.to_thread(
                    cog._case_store.list_timeline_publications,
                    appended.case.case_id,
                )
                evidence_receipts = sorted(
                    (item for item in receipts if item.kind == "evidence"),
                    key=lambda item: item.chunk_index,
                )
                first = published[evidence_receipts[0].message_id]
                obsolete = published[evidence_receipts[1].message_id]
                self.assertEqual(thread.send.await_count, first_send_count + 1)
                self.assertEqual(len(first.attachments), 10)
                self.assertIsInstance(first.view, honeypot.DetectionCaseView)
                self.assertEqual(first.view.message_sequence, 1)
                self.assertEqual(obsolete.attachments, [])
                self.assertIsNone(obsolete.view)
                self.assertIn("No additional attachments", obsolete.content)

    async def test_review_destination_requires_thread_publication_permissions(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                guild = SimpleNamespace(me=object())
                permissions = SimpleNamespace(
                    view_channel=True,
                    send_messages=True,
                    read_message_history=True,
                    create_public_threads=False,
                    send_messages_in_threads=True,
                    embed_links=True,
                    attach_files=True,
                    manage_threads=True,
                )
                channel = SimpleNamespace(
                    mention="#review",
                    permissions_for=lambda _member: permissions,
                )

                missing = cog._missing_channel_permissions(
                    guild,
                    channel,
                    read_history=True,
                    create_public_threads=True,
                    send_in_threads=True,
                    embed_links=True,
                    attach_files=True,
                    manage_threads=True,
                )

                self.assertIn("Create Public Threads", missing)

    async def test_archived_case_thread_is_reopened_before_publication(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                thread = SimpleNamespace(
                    archived=True,
                    locked=True,
                    edit=mock.AsyncMock(),
                )
                thread.edit.return_value = thread

                active = await cog._activate_detection_case_thread(thread)

                self.assertIs(active, thread)
                thread.edit.assert_awaited_once_with(
                    archived=False,
                    locked=False,
                    reason="Honeypot detection case update",
                )

    async def test_terminal_case_thread_is_locked_and_archived(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                thread = SimpleNamespace(edit=mock.AsyncMock())

                await cog._finalize_detection_case_thread(thread)

                thread.edit.assert_awaited_once_with(
                    archived=True,
                    locked=True,
                    reason="Honeypot detection case resolved",
                )

    async def test_terminal_timeline_has_one_durable_human_resolution_event(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._case_store.initialize()
                now = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
                appended = cog._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="evidence",
                        created_at=now,
                        jump_url=None,
                        attachments=(),
                    ),
                    (),
                )
                lease = cog._case_store.claim_resolution(
                    appended.case.case_id, now
                )
                self.assertTrue(
                    cog._case_store.finish_resolution(
                        lease,
                        honeypot.CaseStatus.RESOLVED,
                        "ignore",
                        99,
                        now,
                    )
                )
                snapshot = cog._case_store.get_case(appended.case.case_id)
                sent_messages = {}

                async def send(content, **_kwargs):
                    sent = SimpleNamespace(
                        id=70 + len(sent_messages),
                        content=content,
                        edit=mock.AsyncMock(),
                        delete=mock.AsyncMock(),
                    )
                    sent_messages[sent.id] = sent
                    return sent

                thread = SimpleNamespace(
                    id=60,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    send=mock.AsyncMock(side_effect=send),
                    fetch_message=mock.AsyncMock(
                        side_effect=lambda message_id: sent_messages[message_id]
                    ),
                )
                with mock.patch.object(
                    honeypot.discord,
                    "AllowedMentions",
                    SimpleNamespace(none=lambda: None),
                ):
                    await asyncio.gather(
                        cog._publish_case_timeline(snapshot, thread, resolved=True),
                        cog._publish_case_timeline(snapshot, thread, resolved=True),
                    )
                    await cog._publish_case_timeline(snapshot, thread, resolved=True)

                self.assertEqual(thread.send.await_count, 3)
                resolution_messages = [
                    message
                    for message in sent_messages.values()
                    if "Resolved" in message.content
                ]
                self.assertEqual(len(resolution_messages), 1)
                self.assertIn("Ignored", resolution_messages[0].content)
                self.assertIn("<@99>", resolution_messages[0].content)
                self.assertIn("<t:", resolution_messages[0].content)
                publications = cog._case_store.list_timeline_publications(
                    appended.case.case_id
                )
                self.assertEqual(
                    [item.kind for item in publications].count("resolution"), 1
                )


class JoinwatchRetryTests(unittest.IsolatedAsyncioTestCase):
    class _Store:
        def __init__(self, value):
            self.value = value

        async def __aenter__(self):
            return self.value

        async def __aexit__(self, exc_type, exc, traceback):
            return False

    async def test_assignment_and_role_retries_are_scheduled_one_minute_later(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                guild = SimpleNamespace(id=100)
                assignments = {"200": {"retry_count": 0}}
                roles = {"200": {"retry_count": 0}}
                guild_config = SimpleNamespace(
                    joinwatch_pending_role_assignments=lambda: self._Store(assignments),
                    joinwatch_pending_roles=lambda: self._Store(roles),
                )
                cog.config = SimpleNamespace(guild=lambda _guild: guild_config)
                cog._edit_joinwatch_alert_auto_role = mock.AsyncMock()
                now = datetime(2026, 7, 15, 12, tzinfo=timezone.utc)

                with mock.patch.object(
                    honeypot.discord,
                    "utils",
                    SimpleNamespace(format_dt=lambda value, style: value.isoformat()),
                    create=True,
                ):
                    assignment_result = await cog._reschedule_joinwatch_assignment_retry(
                        guild, "200", assignments["200"], now, "assignment failed"
                    )
                    role_result = await cog._reschedule_joinwatch_role_retry(
                        guild, "200", roles["200"], now, "action failed"
                    )

                self.assertTrue(assignment_result)
                self.assertTrue(role_result)
                self.assertEqual(
                    datetime.fromisoformat(assignments["200"]["apply_at"]),
                    now + timedelta(minutes=1),
                )
                self.assertEqual(
                    datetime.fromisoformat(roles["200"]["expires_at"]),
                    now + timedelta(minutes=1),
                )

    async def test_fifth_retry_is_the_last_and_a_sixth_is_not_scheduled(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                guild = SimpleNamespace(id=100)
                assignments = {"200": {"retry_count": 5}}
                guild_config = SimpleNamespace(
                    joinwatch_pending_role_assignments=lambda: self._Store(assignments),
                )
                cog.config = SimpleNamespace(guild=lambda _guild: guild_config)
                cog._edit_joinwatch_alert_auto_role = mock.AsyncMock()

                scheduled = await cog._reschedule_joinwatch_assignment_retry(
                    guild,
                    "200",
                    assignments["200"],
                    datetime(2026, 7, 15, 12, tzinfo=timezone.utc),
                    "still failing",
                )

                self.assertFalse(scheduled)
                self.assertNotIn("200", assignments)


class ForwardPurgeCoordinatorTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _message(
        honeypot,
        *,
        attachment_count=3,
        delete_error=None,
        message_id=300,
        channel_id=400,
    ):
        attachments = [
            SimpleNamespace(
                filename=f"proof-{position}.png",
                size=len(f"image-{position}".encode()),
                content_type="image/png",
                width=10,
                height=20,
                description=None,
                is_spoiler=lambda: False,
                url=f"https://cdn.test/proof-{position}.png",
                read=mock.AsyncMock(return_value=f"image-{position}".encode()),
            )
            for position in range(1, attachment_count + 1)
        ]
        for attachment in attachments:
            async def read_bounded(max_bytes, *, _attachment=attachment):
                data = await _attachment.read(use_cached=True)
                return data[: max_bytes + 1]

            attachment.read_bounded = read_bounded
        guild = SimpleNamespace(
            id=100,
            name="Guild",
            icon=None,
            get_channel=lambda channel_id: None,
            get_thread=lambda channel_id: None,
        )
        author = SimpleNamespace(
            id=200,
            bot=False,
            roles=[],
            display_name="User",
            display_avatar=None,
            created_at=datetime(2026, 7, 1, tzinfo=timezone.utc),
            joined_at=datetime(2026, 7, 2, tzinfo=timezone.utc),
        )
        message = SimpleNamespace(
            id=message_id,
            guild=guild,
            author=author,
            channel=SimpleNamespace(id=channel_id),
            content="forward evidence",
            attachments=attachments,
            created_at=datetime(2026, 7, 13, 12, tzinfo=timezone.utc),
            jump_url="https://discord.test/channels/100/400/300",
            webhook_id=None,
        )
        message.delete = mock.AsyncMock(side_effect=delete_error)
        return message

    @staticmethod
    def _configure_public_boundary(cog, config):
        cog.bot.cog_disabled_in_guild = mock.AsyncMock(return_value=False)
        cog.config = SimpleNamespace(
            guild=lambda guild: SimpleNamespace(all=mock.AsyncMock(return_value=config)),
            guild_from_id=lambda guild_id: SimpleNamespace(
                all=mock.AsyncMock(return_value=config)
            ),
        )
        cog._is_protected_member = mock.AsyncMock(return_value=False)
        cog._is_forward_purge_active = mock.Mock(return_value=True)
        cog._handle_spam_message = mock.AsyncMock()
        cog._handle_firstpost_message = mock.AsyncMock()
        cog._handle_imagescan_detector_message = mock.AsyncMock()
        cog._increment_stat = mock.AsyncMock()
        cog._purge_detection_case_cached_messages = mock.AsyncMock(return_value=0)
        cog._mark_firstpost_seen = mock.AsyncMock(return_value=False)

    async def test_whitelist_bypass_records_case_without_deleting_honeypot_message(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(
                    honeypot, attachment_count=0, channel_id=9
                )
                message.author.roles = [SimpleNamespace(id=7)]
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "honeypot_channels": [9],
                    "whitelisted_roles": [7],
                    "whitelist_mode": "bypass",
                    "action": "ban",
                    "fallback_action": "none",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                message.delete.assert_not_awaited()
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                self.assertEqual(snapshot.messages[0].delete_status.value, "pending")
                self.assertNotIn(
                    "review_publish",
                    {operation.operation_type for operation in snapshot.operations},
                )
                cog._publish_detection_case.assert_not_awaited()
                cog._increment_stat.assert_any_await(message.guild, "whitelisted")
    async def test_disabled_review_keeps_containment_but_suppresses_interactive_case(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0, channel_id=9)
                config = {
                    "enabled": True,
                    "review_enabled": False,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": 50,
                    "honeypot_channels": [9],
                    "whitelisted_roles": [],
                    "action": "review",
                    "fallback_action": "review",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._suspicion_reasons = mock.AsyncMock(return_value=["young account"])
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                message.delete.assert_awaited_once()
                cog._publish_detection_case.assert_not_awaited()
                self.assertNotIn(
                    "review_publish",
                    {operation.operation_type for operation in snapshot.operations},
                )
    async def test_admission_preserves_discord_attachment_description_and_spoiler(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1, channel_id=9)
                message.attachments[0].description = "suspicious payment form"
                message.attachments[0].is_spoiler = lambda: True
                message.author.roles = [SimpleNamespace(id=7)]
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "honeypot_channels": [9],
                    "whitelisted_roles": [7],
                    "whitelist_mode": "bypass",
                    "action": "ban",
                    "fallback_action": "none",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                self.assertEqual(
                    snapshot.attachments[0].description,
                    "suspicious payment form",
                )
                self.assertTrue(snapshot.attachments[0].spoiler)

    async def test_cancelling_coordinator_cancels_inflight_attachment_reads(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                read_started = asyncio.Event()
                read_stopped = asyncio.Event()
                release_read = asyncio.Event()

                async def blocked_read(*args, **kwargs):
                    read_started.set()
                    try:
                        await release_read.wait()
                    finally:
                        read_stopped.set()
                    return b"evidence"

                message.attachments[0].read = mock.AsyncMock(
                    side_effect=blocked_read
                )
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": False,
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()
                task = asyncio.create_task(cog.on_message(message))
                await asyncio.wait_for(read_started.wait(), timeout=1)

                try:
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    await asyncio.sleep(0)
                    self.assertTrue(read_stopped.is_set())
                finally:
                    release_read.set()

    async def test_concurrent_detection_preserves_message_arrival_order(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                first = self._message(
                    honeypot, attachment_count=0, message_id=300
                )
                second = self._message(
                    honeypot, attachment_count=0, message_id=301
                )
                second.guild = first.guild
                second.author = first.author
                second.created_at = first.created_at + timedelta(seconds=1)
                first_detection_started = asyncio.Event()
                release_first_detection = asyncio.Event()
                second_processed = asyncio.Event()
                signal = honeypot.DetectionSignal(
                    "spam", "duplicate", honeypot.ActionIntent.REVIEW, True, {}
                )

                async def collect(message, config):
                    if message.id == first.id:
                        first_detection_started.set()
                        await release_first_detection.wait()
                    return (signal,)

                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": True,
                    "spam_action": "review",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._collect_detection_signals = collect
                cog._scan_all_case_message_images = mock.AsyncMock()

                async def publish(*args, **kwargs):
                    second_processed.set()

                cog._publish_detection_case = mock.AsyncMock(side_effect=publish)
                first_task = asyncio.create_task(cog.on_message(first))
                await asyncio.wait_for(first_detection_started.wait(), timeout=1)
                second_task = asyncio.create_task(cog.on_message(second))
                try:
                    await asyncio.wait_for(second_processed.wait(), timeout=0.1)
                except TimeoutError:
                    pass
                release_first_detection.set()
                await asyncio.gather(first_task, second_task)

                snapshot = cog._case_store.get_active_case(
                    first.guild.id, first.author.id
                )
                self.assertEqual(
                    [message.message_id for message in snapshot.messages],
                    [first.id, second.id],
                )
                self.assertEqual(
                    snapshot.case.expires_at,
                    first.created_at + timedelta(hours=24),
                )

    async def test_next_message_is_admitted_while_previous_message_finishes(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                first = self._message(honeypot, attachment_count=0, message_id=300)
                second = self._message(honeypot, attachment_count=0, message_id=301)
                second.guild = first.guild
                second.author = first.author
                second.created_at = first.created_at + timedelta(seconds=1)
                first_scan_started = asyncio.Event()
                release_first_scan = asyncio.Event()
                signal = honeypot.DetectionSignal(
                    "honeypot", "bait", honeypot.ActionIntent.REVIEW, True, {}
                )

                config = {
                    "enabled": True,
                    "dry_run": True,
                    "logs_channel": None,
                    "review_channel": None,
                    "review_enabled": True,
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._collect_detection_signals = mock.AsyncMock(return_value=(signal,))
                cog._publish_detection_case = mock.AsyncMock()

                async def scan(message, *args, **kwargs):
                    if message.id == first.id:
                        first_scan_started.set()
                        await release_first_scan.wait()

                cog._scan_all_case_message_images = scan
                first_task = asyncio.create_task(cog.on_message(first))
                await asyncio.wait_for(first_scan_started.wait(), timeout=1)
                second_task = asyncio.create_task(cog.on_message(second))
                try:
                    async with asyncio.timeout(0.5):
                        while True:
                            snapshot = await asyncio.to_thread(
                                cog._case_store.get_active_case,
                                first.guild.id,
                                first.author.id,
                            )
                            if snapshot is not None and len(snapshot.messages) == 2:
                                break
                            await asyncio.sleep(0)
                    self.assertEqual(
                        [message.message_id for message in snapshot.messages],
                        [first.id, second.id],
                    )
                finally:
                    release_first_scan.set()
                    await asyncio.gather(first_task, second_task)

    async def test_firstpost_claim_is_persisted_with_containment(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                signal = honeypot.DetectionSignal(
                    "firstpost",
                    "suspicious first message",
                    honeypot.ActionIntent.REVIEW,
                    True,
                    {},
                )
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": False,
                    "firstpost_enabled": True,
                    "firstpost_collect_enabled": False,
                    "firstpost_action": "review",
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._firstpost_loaded_guilds.add(message.guild.id)
                cog._collect_detection_signals = mock.AsyncMock(
                    return_value=(signal,)
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()
                await cog.on_message(message)

                message.delete.assert_awaited_once()
                snapshot = cog._case_store.get_active_case(
                    message.guild.id, message.author.id
                )
                self.assertFalse(snapshot.case.needs_attention)
                self.assertEqual(
                    [item.signal.detector for item in snapshot.signals],
                    ["firstpost"],
                )

    async def test_restart_recovers_work_committed_with_message_admission(self):
        class SimulatedCrash(BaseException):
            pass

        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                crashed = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(crashed._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                message.guild.get_member = lambda user_id: message.author
                channel = SimpleNamespace(
                    fetch_message=mock.AsyncMock(return_value=message)
                )
                message.guild.get_channel = lambda channel_id: channel
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": True,
                    "spam_action": "ban",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(crashed, config)
                crashed._is_forward_purge_active.return_value = False
                crashed._spam_suspicion_reasons = mock.Mock(
                    return_value=["duplicate"]
                )
                with mock.patch.object(
                    crashed._case_store,
                    "claim_operation",
                    side_effect=SimulatedCrash(),
                ):
                    with self.assertRaises(SimulatedCrash):
                        await crashed.on_message(message)

                admitted = crashed._case_store.get_active_case(
                    message.guild.id, message.author.id
                )
                self.assertEqual(
                    {item.operation_type for item in admitted.operations},
                    {"message_process", "moderation_action", "review_publish"},
                )

                restarted = honeypot.Honeypot(_Bot())
                restarted.config = SimpleNamespace(
                    guild_from_id=lambda guild_id: SimpleNamespace(
                        all=mock.AsyncMock(return_value=config)
                    )
                )
                restarted.bot.get_guild = lambda guild_id: message.guild
                restarted._get_text_channel_or_thread = lambda guild, channel_id: channel
                restarted._execute_action = mock.AsyncMock(return_value=("banned", None))
                restarted._publish_detection_case = mock.AsyncMock()
                restarted._imagescan_load_samples = mock.AsyncMock(return_value=())
                restarted._imagescan_model_state = mock.AsyncMock(
                    return_value={"effective_threshold": 20}
                )
                with mock.patch.object(
                    honeypot,
                    "image_hashes_from_bytes",
                    return_value={"sha256": "recovered-image", "phash": "recovered-phash"},
                ), mock.patch.object(
                    honeypot,
                    "match_image",
                    return_value={"matched": False, "score": None},
                ):
                    await restarted._run_detection_reconciliation(
                        now=datetime.now(timezone.utc) + timedelta(minutes=10)
                    )

                message.delete.assert_awaited_once()
                restarted._execute_action.assert_awaited_once()
                restarted._publish_detection_case.assert_awaited()
                recovered = restarted._case_store.get_case(admitted.case.case_id)
                self.assertIn(recovered.case.status.value, {"resolved", "expired"})
                self.assertEqual(recovered.messages, ())
                self.assertEqual(recovered.attachments, ())
                self.assertEqual(recovered.signals, ())
                self.assertEqual(recovered.operations, ())

    async def test_firstpost_only_admission_persists_signal_before_pipeline_claim(self):
        class SimulatedCrash(BaseException):
            pass

        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                signal = honeypot.DetectionSignal(
                    "firstpost",
                    "suspicious first message",
                    honeypot.ActionIntent.REVIEW,
                    True,
                    {},
                )
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": False,
                    "firstpost_enabled": True,
                    "firstpost_collect_enabled": False,
                    "firstpost_action": "review",
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._firstpost_loaded_guilds.add(message.guild.id)
                cog._collect_detection_signals = mock.AsyncMock(return_value=(signal,))

                with mock.patch.object(
                    cog._case_store,
                    "claim_operation",
                    side_effect=SimulatedCrash(),
                ):
                    with self.assertRaises(SimulatedCrash):
                        await cog.on_message(message)

                snapshot = cog._case_store.get_active_case(
                    message.guild.id, message.author.id
                )
                self.assertEqual(
                    [record.signal.detector for record in snapshot.signals],
                    ["firstpost"],
                )

    async def test_forbidden_forward_delete_is_persisted_and_published_after_all_images_scan(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                forbidden = honeypot.discord.Forbidden("manage messages denied")
                message = self._message(honeypot, delete_error=forbidden)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertIsNotNone(snapshot)
                self.assertEqual(
                    [item.signal.detector for item in snapshot.signals],
                    ["forward_purge"],
                )
                self.assertTrue(snapshot.case.needs_attention)
                self.assertEqual(len(snapshot.messages), 1)
                self.assertEqual(snapshot.messages[0].delete_status.value, "forbidden")
                self.assertIn("Forbidden", snapshot.messages[0].error)
                self.assertEqual(len(snapshot.attachments), 3)
                self.assertTrue(all(item.evidence_path for item in snapshot.attachments))
                self.assertTrue(all(item.capture_status == "captured" for item in snapshot.attachments))
                scan_args = cog._scan_all_case_message_images.await_args.args
                self.assertEqual(scan_args[0], message)
                self.assertEqual((scan_args[2], scan_args[3]), (snapshot.case.case_id, 1))
                self.assertEqual(len(scan_args[4]), 3)
                self.assertEqual(cog._publish_detection_case.await_count, 2)
                message.delete.assert_awaited_once()
                cog._handle_spam_message.assert_not_awaited()
                cog._handle_firstpost_message.assert_not_awaited()
                cog._handle_imagescan_detector_message.assert_not_awaited()
                stat_names = [call.args[1] for call in cog._increment_stat.await_args_list]
                self.assertIn("forward_purge_delete_failures", stat_names)
                self.assertIn("delete_forbidden", stat_names)
                self.assertEqual(
                    cog._purge_detection_case_cached_messages.await_args.kwargs[
                        "exclude_message_id"
                    ],
                    message.id,
                )

    async def test_spam_only_delete_does_not_increment_forward_purge_stats(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": True,
                    "spam_action": "review", "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(
                    [item.signal.detector for item in snapshot.signals], ["spam"]
                )
                stat_names = [call.args[1] for call in cog._increment_stat.await_args_list]
                self.assertIn("purged_messages", stat_names)
                self.assertNotIn("forward_purge_deletes", stat_names)
                self.assertNotIn("forward_purge_delete_failures", stat_names)

    async def test_image_only_delete_does_not_increment_forward_purge_stats(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=6)
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": False,
                    "firstpost_enabled": False, "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": True,
                    "imagescan_detector_action": "review",
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._initial_image_signal = mock.AsyncMock(
                    return_value=honeypot.DetectionSignal(
                        "image", "known image", honeypot.ActionIntent.REVIEW, True, {}
                    )
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case_serial = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(
                    [item.signal.detector for item in snapshot.signals], ["image"]
                )
                scan_args = cog._scan_all_case_message_images.await_args.args
                self.assertEqual(scan_args[0], message)
                self.assertEqual(len(scan_args[4]), 6)
                stat_names = [call.args[1] for call in cog._increment_stat.await_args_list]
                self.assertIn("purged_messages", stat_names)
                self.assertNotIn("forward_purge_deletes", stat_names)
                self.assertNotIn("forward_purge_delete_failures", stat_names)

    async def test_capture_failures_count_failed_timeout_and_too_large_results(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=3)
                message.attachments[0].read = mock.AsyncMock(
                    side_effect=RuntimeError("read failed")
                )

                async def slow_read(*, use_cached):
                    await asyncio.sleep(0.1)
                    return b"late"

                message.attachments[1].read = mock.AsyncMock(side_effect=slow_read)
                message.attachments[2].size = 4
                message.attachments[2].read = mock.AsyncMock(return_value=b"12345")
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": True,
                    "spam_action": "review", "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                with mock.patch.object(
                    honeypot, "DETECTION_ATTACHMENT_TIMEOUT_SECONDS", 0.01
                ):
                    await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(
                    [item.capture_status for item in snapshot.attachments],
                    ["capture_failed", "capture_timeout", "too_large"],
                )
                failure_calls = [
                    call
                    for call in cog._increment_stat.await_args_list
                    if call.args[1] == "evidence_capture_failures"
                ]
                self.assertEqual(len(failure_calls), 1)
                self.assertEqual(failure_calls[0].args[2], 3)

    async def test_two_cogs_do_not_apply_an_aggregate_case_byte_limit(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                first_cog = honeypot.Honeypot(_Bot())
                second_cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(first_cog._case_store.initialize)
                await asyncio.to_thread(second_cog._case_store.initialize)
                first_message = self._message(honeypot, message_id=300, attachment_count=3)
                second_message = self._message(honeypot, message_id=301, attachment_count=3)
                attachment_bytes = 25 * 1024 * 1024
                started = 0
                six_started = asyncio.Event()
                release_reads = asyncio.Event()

                async def blocked_read(*, use_cached):
                    nonlocal started
                    started += 1
                    if started == 6:
                        six_started.set()
                    await release_reads.wait()
                    return b"captured"

                for attachment in first_message.attachments + second_message.attachments:
                    attachment.size = attachment_bytes
                    attachment.read = mock.AsyncMock(side_effect=blocked_read)

                first = await asyncio.to_thread(
                    first_cog._case_store.append_message,
                    first_cog._new_case_message(first_message),
                    (),
                )
                second = await asyncio.to_thread(
                    second_cog._case_store.append_message,
                    second_cog._new_case_message(second_message),
                    (),
                )
                first_capture = asyncio.create_task(
                    first_cog._capture_case_attachments(
                        first_message, first.case.case_id, first.message.sequence
                    )
                )
                second_capture = asyncio.create_task(
                    second_cog._capture_case_attachments(
                        second_message, second.case.case_id, second.message.sequence
                    )
                )

                await asyncio.wait_for(six_started.wait(), timeout=1)
                self.assertEqual(started, 6)
                release_reads.set()
                results = await asyncio.gather(first_capture, second_capture)

                statuses = [capture.status.value for captures in results for capture in captures]
                self.assertEqual(statuses.count("captured"), 6)
                self.assertEqual(statuses.count("too_large"), 0)
                self.assertEqual(
                    sum(
                        attachment.read.await_count
                        for attachment in first_message.attachments + second_message.attachments
                    ),
                    6,
                )

    async def test_capture_cleans_exact_file_when_actual_bytes_exceed_reservation(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                message.attachments[0].size = 4
                message.attachments[0].read = mock.AsyncMock(return_value=b"12345")
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(message),
                    (),
                )

                captures = await cog._capture_case_attachments(
                    message, appended.case.case_id, appended.message.sequence
                )

                case_root = (
                    cog._detection_case_files_path
                    / str(message.guild.id)
                    / appended.case.case_id
                )
                stored = (
                    await asyncio.to_thread(cog._case_store.get_case, appended.case.case_id)
                ).attachments[0]
                self.assertEqual(captures[0].status.value, "too_large")
                self.assertEqual(stored.capture_status, "too_large")
                self.assertIsNone(stored.evidence_path)
                self.assertEqual(
                    [path for path in case_root.rglob("*") if path.is_file()],
                    [],
                )

    async def test_production_capture_and_resolution_share_canonical_case_root(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                case_root = (
                    cog._detection_case_files_path
                    / str(message.guild.id)
                    / snapshot.case.case_id
                )
                evidence_path = Path(snapshot.attachments[0].evidence_path)
                self.assertTrue(evidence_path.is_relative_to(case_root / "1"))
                self.assertTrue(evidence_path.exists())
                stat_names = [call.args[1] for call in cog._increment_stat.await_args_list]
                self.assertIn("forward_purge_deletes", stat_names)
                cog._case_review_rerender = mock.AsyncMock()

                await cog.resolve_detection_case(snapshot.case.case_id, "expired")

                self.assertFalse(case_root.exists())

    async def test_user_deletion_waits_for_inflight_production_capture(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                capture_started = asyncio.Event()
                release_capture = asyncio.Event()

                async def blocked_read(*args, **kwargs):
                    capture_started.set()
                    await release_capture.wait()
                    return b"proof"

                message = self._message(honeypot, attachment_count=1)
                message.attachments[0].read = mock.AsyncMock(side_effect=blocked_read)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()
                capture_task = asyncio.create_task(cog.on_message(message))
                await asyncio.wait_for(capture_started.wait(), timeout=1)

                deletion_task = asyncio.create_task(
                    cog.red_delete_data_for_user(
                        requester="discord_deleted_user", user_id=message.author.id
                    )
                )
                completed, _pending = await asyncio.wait(
                    {deletion_task}, timeout=0.2
                )
                try:
                    self.assertEqual(completed, set())
                finally:
                    release_capture.set()
                await asyncio.gather(capture_task, deletion_task)

                self.assertIsNone(
                    cog._case_store.get_active_case(
                        message.guild.id, message.author.id
                    )
                )
                guild_root = cog._detection_case_files_path / str(message.guild.id)
                self.assertFalse(any(guild_root.glob("**/*")) if guild_root.exists() else False)

    async def test_cross_instance_deletion_rejects_late_capture_without_orphan(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                capture_cog = honeypot.Honeypot(_Bot())
                deletion_cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(capture_cog._case_store.initialize)
                await asyncio.to_thread(deletion_cog._case_store.initialize)
                capture_started = asyncio.Event()
                release_capture = asyncio.Event()
                real_capture = honeypot.detection_runtime.capture_attachment

                async def delayed_capture(*args, **kwargs):
                    capture_started.set()
                    await release_capture.wait()
                    return await real_capture(*args, **kwargs)

                message = self._message(honeypot, attachment_count=1)
                self._configure_public_boundary(
                    capture_cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                capture_cog._scan_all_case_message_images = mock.AsyncMock()
                capture_cog._publish_detection_case = mock.AsyncMock()

                with mock.patch.object(
                    honeypot.detection_runtime,
                    "capture_attachment",
                    new=delayed_capture,
                ):
                    capture_task = asyncio.create_task(capture_cog.on_message(message))
                    await asyncio.wait_for(capture_started.wait(), timeout=1)
                    snapshot = await asyncio.to_thread(
                        deletion_cog._case_store.get_active_case,
                        message.guild.id,
                        message.author.id,
                    )
                    case_root = (
                        capture_cog._detection_case_files_path
                        / str(message.guild.id)
                        / snapshot.case.case_id
                    )
                    self.assertFalse(case_root.exists())
                    try:
                        await deletion_cog.red_delete_data_for_user(
                            requester="discord_deleted_user",
                            user_id=message.author.id,
                        )
                        case_root.mkdir(parents=True)
                        unrelated_evidence = case_root / "other-capture.bin"
                        unrelated_evidence.write_bytes(b"other capture")
                    finally:
                        release_capture.set()
                    await capture_task

                self.assertIsNone(
                    deletion_cog._case_store.get_active_case(
                        message.guild.id, message.author.id
                    )
                )
                self.assertEqual(deletion_cog._case_store.list_planned_case_deletions(), ())
                self.assertEqual(
                    [path for path in case_root.rglob("*") if path.is_file()],
                    [unrelated_evidence],
                )
                self.assertEqual(unrelated_evidence.read_bytes(), b"other capture")
                capture_cog._scan_all_case_message_images.assert_not_awaited()

    async def test_duplicate_attachment_filenames_keep_ordered_evidence_and_hashes(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                payloads = (b"first-image", b"second-image")
                message.attachments = [
                    SimpleNamespace(
                        filename="proof.png",
                        size=len(payload),
                        content_type="image/png",
                        width=10,
                        height=20,
                        url=f"https://cdn.test/{position}/proof.png",
                        description=None,
                        is_spoiler=lambda: False,
                        read=mock.AsyncMock(return_value=payload),
                    )
                    for position, payload in enumerate(payloads)
                ]
                for attachment in message.attachments:
                    async def read_bounded(max_bytes, *, _attachment=attachment):
                        data = await _attachment.read(use_cached=True)
                        return data[: max_bytes + 1]

                    attachment.read_bounded = read_bounded
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._imagescan_load_samples = mock.AsyncMock(return_value=[])
                cog._imagescan_model_state = mock.AsyncMock(
                    return_value={"effective_threshold": 20}
                )
                cog._publish_detection_case = mock.AsyncMock()
                hashes_by_payload = {
                    b"first-image": {"sha256": "first-sha", "phash": "first-phash"},
                    b"second-image": {"sha256": "second-sha", "phash": "second-phash"},
                }

                with (
                    mock.patch.object(
                        honeypot,
                        "image_hashes_from_bytes",
                        side_effect=lambda data: hashes_by_payload[data],
                    ),
                    mock.patch.object(
                        honeypot,
                        "match_image",
                        side_effect=lambda hashes, samples, threshold: {
                            "sha256": hashes["sha256"]
                        },
                    ),
                ):
                    await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertIsNotNone(snapshot)
                self.assertEqual([item.position for item in snapshot.attachments], [0, 1])
                evidence_paths = [Path(item.evidence_path) for item in snapshot.attachments]
                self.assertEqual(len(set(evidence_paths)), 2)
                self.assertEqual([path.read_bytes() for path in evidence_paths], list(payloads))
                self.assertEqual(
                    [item.sha256 for item in snapshot.attachments],
                    ["first-sha", "second-sha"],
                )
                self.assertEqual(
                    [item.perceptual_hash for item in snapshot.attachments],
                    ["first-phash", "second-phash"],
                )
                self.assertEqual(
                    [dict(item.match_metadata) for item in snapshot.attachments],
                    [{"sha256": "first-sha"}, {"sha256": "second-sha"}],
                )

    async def test_successive_forward_messages_share_case_and_keep_ordered_channels(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": False,
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()
                first = self._message(honeypot, attachment_count=0)
                second = self._message(
                    honeypot,
                    attachment_count=0,
                    message_id=301,
                    channel_id=401,
                )

                await cog.on_message(first)
                await cog.on_message(second)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, first.guild.id, first.author.id
                )
                self.assertEqual(
                    [(item.sequence, item.channel_id, item.delete_status.value) for item in snapshot.messages],
                    [(1, 400, "deleted"), (2, 401, "deleted")],
                )
                self.assertEqual(cog._publish_detection_case.await_count, 4)
                self.assertEqual(
                    [
                        call.kwargs["exclude_message_id"]
                        for call in cog._purge_detection_case_cached_messages.await_args_list
                    ],
                    [300, 301],
                )

    async def test_text_projection_precedes_capture_and_evidence_refresh_follows_it(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                capture_started = asyncio.Event()
                release_capture = asyncio.Event()
                contained = asyncio.Event()
                projection_started = asyncio.Event()

                async def blocked_read(*, use_cached):
                    capture_started.set()
                    await release_capture.wait()
                    return b"image"

                async def delete():
                    contained.set()

                async def publish(*args, **kwargs):
                    projection_started.set()

                message.attachments[0].read = mock.AsyncMock(side_effect=blocked_read)
                message.delete = mock.AsyncMock(side_effect=delete)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "review_enabled": True,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock(side_effect=publish)

                processing = asyncio.create_task(cog.on_message(message))
                await asyncio.wait_for(capture_started.wait(), timeout=1)
                await asyncio.wait_for(contained.wait(), timeout=1)
                await asyncio.wait_for(projection_started.wait(), timeout=1)
                try:
                    self.assertFalse(processing.done())
                    self.assertEqual(cog._publish_detection_case.await_count, 1)
                finally:
                    release_capture.set()
                    await processing

                self.assertEqual(cog._publish_detection_case.await_count, 2)

    async def test_queued_message_with_ready_evidence_publishes_only_final_state(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": True,
                        "logs_channel": None,
                        "review_channel": None,
                        "review_enabled": True,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                        "imagescan_detector_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case_serial = mock.AsyncMock()
                for publication_lock in cog._detection_publication_locks:
                    await publication_lock.acquire()
                try:
                    processing = asyncio.create_task(cog.on_message(message))
                    await asyncio.sleep(0.1)
                finally:
                    for publication_lock in cog._detection_publication_locks:
                        publication_lock.release()
                await processing

                self.assertEqual(cog._publish_detection_case_serial.await_count, 1)

    async def test_saturated_capture_queue_does_not_delay_delete_or_retry_deleted_source(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                cog._detection_case_capture_slots = asyncio.Semaphore(0)
                message = self._message(honeypot, attachment_count=1)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                with mock.patch.object(
                    honeypot, "DETECTION_CAPTURE_START_TIMEOUT_SECONDS", 0.01
                ):
                    await cog.on_message(message)

                message.delete.assert_awaited_once()
                message.attachments[0].read.assert_not_awaited()
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "message_process"
                )
                self.assertEqual(
                    snapshot.attachments[0].capture_status, "capture_failed"
                )
                self.assertEqual(operation.status.value, "succeeded")
                self.assertIsNone(operation.retry_at)

    async def test_unavailable_attachment_reservation_keeps_message_process_retryable(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()
                cog._case_store.reserve_attachment_capture = mock.Mock(
                    return_value=SimpleNamespace(
                        status="unavailable",
                        claim_token=None,
                        error="evidence capture is already claimed",
                    )
                )

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "message_process"
                )
                self.assertEqual(snapshot.attachments[0].capture_status, "pending")
                self.assertEqual(operation.status.value, "failed")
                self.assertIsNotNone(operation.retry_at)
                self.assertIn("not terminal", operation.last_error)

    async def test_terminal_case_recovery_stops_retrying_pending_attachment_capture(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime.now(timezone.utc)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="evidence",
                        created_at=now,
                        jump_url="https://discord.test/messages/40",
                        attachments=(
                            honeypot.NewAttachment(
                                0,
                                "proof.png",
                                5,
                                "image/png",
                                10,
                                10,
                                "https://cdn.test/proof.png",
                            ),
                        ),
                    ),
                    (),
                    lambda signals: (("message_process", "message-process:{case_id}:{sequence}"),),
                )
                operation = next(
                    item
                    for item in cog._case_store.get_case(appended.case.case_id).operations
                    if item.operation_type == "message_process"
                )
                lease = cog._case_store.claim_resolution(appended.case.case_id, now)
                self.assertTrue(
                    cog._case_store.finish_resolution(
                        lease,
                        honeypot.CaseStatus.RESOLVED,
                        "ignore",
                        99,
                        now,
                    )
                )
                claimed = cog._case_store.claim_operation(operation.operation_id, now)

                await cog._execute_detection_case_operation(claimed, now)

                snapshot = cog._case_store.get_case(appended.case.case_id)
                persisted = next(
                    item
                    for item in snapshot.operations
                    if item.operation_id == operation.operation_id
                )
                self.assertEqual(snapshot.attachments[0].capture_status, "capture_failed")
                self.assertEqual(persisted.status.value, "succeeded")
                self.assertEqual(persisted.result, "case_terminal")
                self.assertIsNone(persisted.retry_at)

    async def test_publication_failure_happens_after_delete_and_leaves_retryable_operation(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock(
                    side_effect=RuntimeError("review unavailable")
                )

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(snapshot.messages[0].delete_status.value, "deleted")
                operation = next(
                    item for item in snapshot.operations if item.operation_type == "review_publish"
                )
                self.assertEqual(operation.status.value, "failed")
                self.assertIsNotNone(operation.retry_at)
                self.assertIn("review unavailable", operation.last_error)
                message.delete.assert_awaited_once()

    async def test_missing_publication_destination_is_durable_after_delete(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(snapshot.messages[0].delete_status.value, "deleted")
                operation = next(
                    item for item in snapshot.operations if item.operation_type == "review_publish"
                )
                self.assertEqual(operation.status.value, "failed")
                self.assertIsNotNone(operation.retry_at)
                self.assertIn("destination", operation.last_error.lower())
                message.delete.assert_awaited_once()

    async def test_dry_run_has_no_cached_or_forward_purge_side_effects(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                case_cached_purge = cog._purge_detection_case_cached_messages
                is_forward_purge_active = cog._is_forward_purge_active
                message = self._message(honeypot, attachment_count=0)
                message.created_at = datetime.now(timezone.utc)
                message.author.kick = mock.AsyncMock()
                message.author.ban = mock.AsyncMock()
                previous = self._message(
                    honeypot,
                    attachment_count=0,
                    message_id=299,
                    channel_id=401,
                )
                previous.created_at = datetime.now(timezone.utc)
                follow_up = self._message(
                    honeypot,
                    attachment_count=0,
                    message_id=301,
                    channel_id=401,
                )
                follow_up.created_at = datetime.now(timezone.utc)
                follow_up.author = message.author
                config = {
                    "enabled": True,
                    "dry_run": True,
                    "logs_channel": None,
                    "review_channel": None,
                    "honeypot_channels": [message.channel.id],
                    "action": "ban",
                    "fallback_action": "ban",
                    "spam_enabled": False,
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "purge_backward_seconds": 300,
                    "purge_forward_seconds": 300,
                }
                self._configure_public_boundary(
                    cog,
                    config,
                )
                cog._purge_detection_case_cached_messages = case_cached_purge
                cog._is_forward_purge_active = is_forward_purge_active
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()
                cog._record_recent_user_message(previous, config)

                await cog.on_message(message)
                await cog.on_message(follow_up)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(len(snapshot.messages), 1)
                self.assertEqual(snapshot.messages[0].delete_status.value, "planned")
                operations = [
                    item
                    for item in snapshot.operations
                    if item.operation_type == "cached_purge"
                ]
                self.assertEqual(len(operations), 1)
                self.assertEqual(operations[0].status.value, "succeeded")
                self.assertEqual(operations[0].result, "planned")
                self.assertEqual(operations[0].attempts, 1)
                self.assertIn(
                    f":{previous.channel.id}:{previous.id}",
                    operations[0].idempotency_key,
                )
                self.assertFalse(snapshot.case.needs_attention)
                message.delete.assert_not_awaited()
                follow_up.delete.assert_not_awaited()
                message.author.kick.assert_not_awaited()
                message.author.ban.assert_not_awaited()
                self.assertNotIn(
                    message.author.id,
                    cog._hot_purge_users.get(message.guild.id, {}),
                )

    async def test_dry_run_does_not_apply_review_role(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                role = SimpleNamespace(id=55)
                message.author.add_roles = mock.AsyncMock()
                message.guild.get_member = lambda user_id: message.author
                message.guild.get_role = lambda role_id: role
                cog.bot.get_guild = lambda guild_id: message.guild
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": True,
                        "logs_channel": None,
                        "review_channel": None,
                        "honeypot_channels": [message.channel.id],
                        "action": "review",
                        "fallback_action": "review",
                        "mute_role": role.id,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                message.author.add_roles.assert_not_awaited()
                self.assertFalse(
                    any(
                        operation.operation_type == "role_apply"
                        for operation in snapshot.operations
                    )
                )

    async def test_duplicate_discord_delivery_does_not_repeat_containment(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)
                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(len(snapshot.messages), 1)
                message.delete.assert_awaited_once()

    async def test_duplicate_delivery_does_not_repeat_cached_purge_or_stats(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": False,
                    "firstpost_enabled": False, "firstpost_collect_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._purge_detection_case_cached_messages = mock.AsyncMock(return_value=2)
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)
                await cog.on_message(message)

                cog._purge_detection_case_cached_messages.assert_awaited_once()
                purged_stats = [
                    call for call in cog._increment_stat.await_args_list
                    if call.args == (message.guild, "purged_messages", 2)
                ]
                cached_stats = [
                    call for call in cog._increment_stat.await_args_list
                    if call.args == (message.guild, "cached_purge_deletes", 2)
                ]
                self.assertEqual(len(purged_stats), 1)
                self.assertEqual(len(cached_stats), 1)
                self.assertEqual(cog._scan_all_case_message_images.await_count, 1)
                self.assertEqual(cog._publish_detection_case.await_count, 3)

    async def test_redelivery_resumes_a_preappended_pending_message(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True, "dry_run": False, "logs_channel": None,
                        "review_channel": None, "spam_enabled": False,
                        "firstpost_enabled": False, "firstpost_collect_enabled": False,
                    },
                )
                await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(message),
                    (cog._forward_purge_signal(message),),
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(snapshot.messages[0].delete_status.value, "deleted")
                self.assertEqual(snapshot.attachments[0].capture_status, "captured")
                self.assertIsNotNone(snapshot.attachments[0].evidence_path)
                message.delete.assert_awaited_once()
                message.attachments[0].read.assert_awaited_once()
                self.assertEqual(cog._publish_detection_case.await_count, 2)

    async def test_message_is_contained_while_old_moderator_effect_is_in_flight(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                first = self._message(
                    honeypot, attachment_count=0, message_id=299
                )
                second = self._message(honeypot, attachment_count=0)
                second.guild = first.guild
                second.author = first.author
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": False,
                    "firstpost_enabled": False, "firstpost_collect_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(first),
                    (cog._forward_purge_signal(first),),
                )
                now = datetime.now(timezone.utc)
                moderator = await asyncio.to_thread(
                    cog._case_store.claim_moderator_action,
                    appended.case.case_id,
                    "ban",
                    99,
                    now - timedelta(seconds=7),
                )
                moderator = await asyncio.to_thread(
                    cog._case_store.claim_operation,
                    moderator.operation_id,
                    now - timedelta(seconds=7),
                )
                self.assertTrue(
                    await asyncio.to_thread(
                        cog._case_store.start_operation_effect,
                        moderator.operation_id,
                        moderator.claim_token,
                        now - timedelta(seconds=6),
                    )
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await asyncio.wait_for(cog.on_message(second), timeout=1)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                self.assertEqual(
                    [message.message_id for message in snapshot.messages],
                    [first.id, second.id],
                )
                self.assertEqual(snapshot.messages[-1].delete_status.value, "deleted")
                second.delete.assert_awaited_once()

    async def test_capture_deadline_preserves_fast_result_and_times_out_only_slow_attachment(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                self.assertEqual(honeypot.DETECTION_ATTACHMENT_TIMEOUT_SECONDS, 15.0)
                self.assertEqual(honeypot.DETECTION_CAPTURE_DEADLINE_SECONDS, 20.0)
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                gate = asyncio.Event()
                fast = SimpleNamespace(
                    filename="fast.png", size=4, content_type="image/png",
                    width=None, height=None, url="https://cdn/fast",
                    description=None, is_spoiler=lambda: False,
                    read=mock.AsyncMock(return_value=b"fast"),
                )
                async def slow_read(*args, **kwargs):
                    await gate.wait()
                    return b"slow"
                slow = SimpleNamespace(
                    filename="slow.png", size=4, content_type="image/png",
                    width=None, height=None, url="https://cdn/slow",
                    description=None, is_spoiler=lambda: False,
                    read=mock.AsyncMock(side_effect=slow_read),
                )
                for attachment in (fast, slow):
                    async def read_bounded(max_bytes, *, _attachment=attachment):
                        data = await _attachment.read(use_cached=True)
                        return data[: max_bytes + 1]

                    attachment.read_bounded = read_bounded
                message = self._message(honeypot, attachment_count=0)
                message.attachments = [fast, slow]
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(message),
                    (honeypot.DetectionSignal(
                        "forward_purge", "active", honeypot.ActionIntent.REVIEW, True, {}
                    ),),
                )
                with mock.patch.object(honeypot, "DETECTION_CAPTURE_DEADLINE_SECONDS", 0.05):
                    captures = await cog._capture_case_attachments(
                        message, appended.case.case_id, 1
                    )

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                self.assertEqual([item.status.value for item in captures], ["captured", "capture_timeout"])
                self.assertTrue(Path(snapshot.attachments[0].evidence_path).exists())
                self.assertEqual(snapshot.attachments[1].capture_status, "capture_timeout")

    async def test_discord_accepted_attachment_is_not_rejected_by_fixed_local_limit(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                message.attachments[0].size = 25 * 1024 * 1024 + 1
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": True,
                    "spam_action": "review",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                message.attachments[0].read.assert_awaited_once()
                self.assertEqual(snapshot.attachments[0].capture_status, "captured")
                self.assertFalse(honeypot.render_case(snapshot).incomplete_evidence)

    async def test_all_discord_accepted_attachments_are_captured_without_case_byte_cap(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=5)
                reads_started = 0
                five_reads_started = asyncio.Event()
                release_reads = asyncio.Event()

                async def blocked_read(*, use_cached):
                    nonlocal reads_started
                    reads_started += 1
                    if reads_started == 5:
                        five_reads_started.set()
                    await release_reads.wait()
                    return b"image"

                for attachment in message.attachments:
                    attachment.size = 25 * 1024 * 1024
                    attachment.read = mock.AsyncMock(side_effect=blocked_read)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(message),
                    (honeypot.DetectionSignal(
                        "forward_purge", "active", honeypot.ActionIntent.REVIEW, True, {}
                    ),),
                )
                capture_task = asyncio.create_task(
                    cog._capture_case_attachments(
                        message, appended.case.case_id, appended.message.sequence
                    )
                )
                await asyncio.wait_for(five_reads_started.wait(), timeout=1)
                try:
                    self.assertEqual(reads_started, 5)
                    for attachment in message.attachments:
                        attachment.read.assert_awaited_once_with(use_cached=True)
                finally:
                    release_reads.set()
                captures = await capture_task

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                self.assertEqual(
                    [capture.status.value for capture in captures],
                    ["captured"] * 5,
                )
                self.assertEqual(
                    [attachment.capture_status for attachment in snapshot.attachments],
                    ["captured"] * 5,
                )
                self.assertFalse(honeypot.render_case(snapshot).incomplete_evidence)

    async def test_two_different_cases_start_attachment_capture_in_parallel(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                first_message = self._message(
                    honeypot, attachment_count=1, message_id=300
                )
                second_message = self._message(
                    honeypot, attachment_count=1, message_id=301
                )
                second_message.author.id = 201
                first_started = asyncio.Event()
                second_started = asyncio.Event()
                release_reads = asyncio.Event()

                async def first_read(*args, **kwargs):
                    first_started.set()
                    await release_reads.wait()
                    return b"first"

                async def second_read(*args, **kwargs):
                    second_started.set()
                    await release_reads.wait()
                    return b"second"

                first_message.attachments[0].size = len(b"first")
                first_message.attachments[0].read = mock.AsyncMock(
                    side_effect=first_read
                )
                second_message.attachments[0].size = len(b"second")
                second_message.attachments[0].read = mock.AsyncMock(
                    side_effect=second_read
                )
                first = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(first_message),
                    (),
                )
                second = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(second_message),
                    (),
                )
                first_task = asyncio.create_task(
                    cog._capture_case_attachments(
                        first_message, first.case.case_id, first.message.sequence
                    )
                )
                await asyncio.wait_for(first_started.wait(), timeout=1)
                second_task = asyncio.create_task(
                    cog._capture_case_attachments(
                        second_message, second.case.case_id, second.message.sequence
                    )
                )
                try:
                    await asyncio.wait_for(second_started.wait(), timeout=0.05)
                    captures_overlap = True
                except TimeoutError:
                    captures_overlap = False
                finally:
                    release_reads.set()
                results = await asyncio.gather(first_task, second_task)

                self.assertTrue(captures_overlap)
                self.assertEqual(
                    [capture.status.value for captures in results for capture in captures],
                    ["captured", "captured"],
                )

    async def test_scan_setup_failure_does_not_prevent_delete_or_publication(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                self._configure_public_boundary(
                    cog, {"enabled": True, "dry_run": False, "logs_channel": None,
                          "review_channel": None, "spam_enabled": False,
                          "firstpost_enabled": False, "firstpost_collect_enabled": False}
                )
                cog._imagescan_load_samples = mock.AsyncMock(side_effect=RuntimeError("model unavailable"))
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(snapshot.messages[0].delete_status.value, "deleted")
                self.assertIn("model unavailable", snapshot.attachments[0].error)
                self.assertEqual(cog._publish_detection_case.await_count, 2)

    async def test_missing_saved_review_message_is_replaced(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(message),
                    (honeypot.DetectionSignal(
                        "forward_purge", "active", honeypot.ActionIntent.REVIEW, True, {}
                    ),),
                )
                await asyncio.to_thread(
                    publish_primary, cog._case_store, appended.case.case_id, 50, 60
                )
                next_id = 70

                async def thread_send(*args, **kwargs):
                    nonlocal next_id
                    sent_message = SimpleNamespace(id=next_id)
                    next_id += 1
                    return sent_message

                thread = SimpleNamespace(
                    id=61,
                    send=mock.AsyncMock(side_effect=thread_send),
                    fetch_message=mock.AsyncMock(),
                )
                sent = SimpleNamespace(
                    id=61,
                    fetch_thread=mock.AsyncMock(side_effect=honeypot.discord.NotFound()),
                    create_thread=mock.AsyncMock(return_value=thread),
                )
                channel = SimpleNamespace(
                    id=50,
                    fetch_message=mock.AsyncMock(
                        side_effect=honeypot.discord.NotFound("missing")
                    ),
                    send=mock.AsyncMock(return_value=sent),
                )
                sent.channel = channel
                cog.bot.get_guild = mock.Mock(return_value=message.guild)
                cog._get_text_channel_or_thread = mock.Mock(return_value=channel)
                embed = SimpleNamespace(add_field=mock.Mock())

                with (
                    mock.patch.object(
                        honeypot.discord, "Color",
                        SimpleNamespace(gold=lambda: 1, dark_red=lambda: 2),
                    ),
                    mock.patch.object(honeypot.discord, "Embed", return_value=embed),
                    mock.patch.object(
                        honeypot.discord,
                        "AllowedMentions",
                        SimpleNamespace(none=lambda: None),
                    ),
                ):
                    await cog._publish_detection_case(
                        appended.case.case_id, {"review_channel": 50}, None
                    )

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                self.assertEqual(
                    (snapshot.case.review_channel_id, snapshot.case.review_message_id),
                    (50, 61),
                )
                channel.send.assert_awaited_once()
                self.assertEqual(thread.send.await_count, 2)

    async def test_restart_reprojects_primary_and_evidence_into_the_case_thread(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                original = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(original._case_store.initialize)
                message = self._message(honeypot, attachment_count=11)
                appended = await asyncio.to_thread(
                    original._case_store.append_message,
                    original._new_case_message(message),
                    (honeypot.DetectionSignal(
                        "forward_purge", "active", honeypot.ActionIntent.REVIEW, True, {}
                    ),),
                )
                case_id = appended.case.case_id
                for attachment in range(11):
                    evidence = data_path / f"evidence-{attachment}.png"
                    evidence.write_bytes(b"image")
                    await asyncio.to_thread(
                        capture_attachment,
                        original._case_store, case_id, 1, attachment, evidence,
                    )
                await asyncio.to_thread(
                    publish_primary, original._case_store, case_id, 50, 60
                )
                snapshot = await asyncio.to_thread(original._case_store.get_case, case_id)
                await asyncio.to_thread(
                    publish_evidence,
                    original._case_store,
                    case_id, 0, 50, 61,
                    tuple(item.key for item in snapshot.attachments[:10]),
                )
                await asyncio.to_thread(
                    publish_evidence,
                    original._case_store,
                    case_id, 1, 50, 62,
                    (snapshot.attachments[10].key,),
                )

                thread_messages = {}
                next_thread_id = 70

                async def thread_send(*args, **kwargs):
                    nonlocal next_thread_id
                    result = SimpleNamespace(id=next_thread_id, edit=mock.AsyncMock())
                    thread_messages[next_thread_id] = result
                    next_thread_id += 1
                    return result

                thread = SimpleNamespace(
                    id=60,
                    archived=False,
                    locked=False,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    edit=mock.AsyncMock(),
                    send=mock.AsyncMock(side_effect=thread_send),
                    fetch_message=mock.AsyncMock(
                        side_effect=lambda message_id: thread_messages[message_id]
                    ),
                )
                primary = SimpleNamespace(
                    id=60,
                    edit=mock.AsyncMock(),
                    fetch_thread=mock.AsyncMock(return_value=thread),
                )
                evidence_one = SimpleNamespace(edit=mock.AsyncMock())
                evidence_two = SimpleNamespace(edit=mock.AsyncMock())
                channel = SimpleNamespace(
                    id=50,
                    fetch_message=mock.AsyncMock(
                        side_effect=lambda message_id: {
                            60: primary, 61: evidence_one, 62: evidence_two
                        }[message_id]
                    ),
                    send=mock.AsyncMock(),
                )
                primary.channel = channel
                fresh = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(fresh._case_store.initialize)
                fresh.bot.get_guild = mock.Mock(return_value=message.guild)
                fresh._get_text_channel_or_thread = mock.Mock(return_value=channel)
                fresh.config = SimpleNamespace(
                    guild_from_id=lambda guild_id: SimpleNamespace(
                        all=mock.AsyncMock(return_value={"review_channel": 50})
                    )
                )
                embed = SimpleNamespace(add_field=mock.Mock())
                with (
                    mock.patch.object(
                        honeypot.discord, "Color",
                        SimpleNamespace(dark_red=lambda: 1, gold=lambda: 2),
                    ),
                    mock.patch.object(honeypot.discord, "Embed", return_value=embed),
                    mock.patch.object(
                        honeypot.discord,
                        "File",
                        side_effect=lambda *args, **kwargs: object(),
                    ),
                    mock.patch.object(
                        honeypot.discord,
                        "AllowedMentions",
                        SimpleNamespace(none=lambda: None),
                    ),
                    mock.patch.object(
                        honeypot, "DetectionCaseView",
                        side_effect=lambda *args, **kwargs: SimpleNamespace(resolved=kwargs["resolved"]),
                    ) as primary_view,
                ):
                    await fresh._case_review_service.apply_bulk(case_id, "tp", moderator_id=7)
                    await fresh._case_review_rerender(case_id)

                primary.edit.assert_awaited_once()
                evidence_one.edit.assert_not_awaited()
                evidence_two.edit.assert_not_awaited()
                channel.send.assert_not_awaited()
                self.assertEqual(thread.send.await_count, 5)
                thread.edit.assert_awaited_once_with(
                    archived=True,
                    locked=True,
                    reason="Honeypot detection case resolved",
                )
                self.assertTrue(
                    all(call.kwargs["resolved"] for call in primary_view.call_args_list)
                )
                evidence_calls = [
                    call
                    for call in thread.send.await_args_list
                    if call.args[0].startswith("Message 1 attachments")
                ]
                self.assertIsNotNone(evidence_calls[0].kwargs.get("view"))
                self.assertTrue(
                    all(call.kwargs.get("view") is None for call in evidence_calls[1:])
                )
                self.assertTrue(
                    all(
                        call.kwargs.get("view") is None
                        for call in thread.send.await_args_list
                        if call not in evidence_calls
                    )
                )




    async def test_concurrent_publishers_create_one_summary_and_one_thread_timeline(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                first = honeypot.Honeypot(_Bot())
                second = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(first._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                appended = await asyncio.to_thread(
                    first._case_store.append_message,
                    first._new_case_message(message),
                    (honeypot.DetectionSignal(
                        "forward_purge", "active", honeypot.ActionIntent.REVIEW, True, {}
                    ),),
                )
                evidence = data_path / "evidence.png"
                evidence.write_bytes(b"image")
                await asyncio.to_thread(
                    capture_attachment,
                    first._case_store, appended.case.case_id, 1, 0, evidence,
                )
                thread_messages = {}
                next_thread_id = 70

                async def thread_send(*args, **kwargs):
                    nonlocal next_thread_id
                    await asyncio.sleep(0)
                    result = SimpleNamespace(id=next_thread_id, edit=mock.AsyncMock())
                    thread_messages[next_thread_id] = result
                    next_thread_id += 1
                    return result

                thread = SimpleNamespace(
                    id=60,
                    guild=SimpleNamespace(filesize_limit=8 * 1024 * 1024),
                    send=mock.AsyncMock(side_effect=thread_send),
                    fetch_message=mock.AsyncMock(
                        side_effect=lambda message_id: thread_messages[message_id]
                    ),
                )
                thread_created = False

                async def fetch_thread():
                    if not thread_created:
                        raise honeypot.discord.NotFound()
                    return thread

                async def create_thread(**kwargs):
                    nonlocal thread_created
                    if thread_created:
                        raise honeypot.discord.HTTPException()
                    thread_created = True
                    return thread

                summary = SimpleNamespace(
                    id=60,
                    edit=mock.AsyncMock(),
                    fetch_thread=mock.AsyncMock(side_effect=fetch_thread),
                    create_thread=mock.AsyncMock(side_effect=create_thread),
                )
                channel = SimpleNamespace(id=50)
                summary.channel = channel
                channel.send = mock.AsyncMock(return_value=summary)
                channel.fetch_message = mock.AsyncMock(return_value=summary)
                for cog in (first, second):
                    cog.bot.get_guild = mock.Mock(return_value=message.guild)
                    cog._get_text_channel_or_thread = mock.Mock(return_value=channel)
                embed = SimpleNamespace(add_field=mock.Mock())
                with (
                    mock.patch.object(
                        honeypot.discord, "Color",
                        SimpleNamespace(dark_red=lambda: 1, gold=lambda: 2),
                    ),
                    mock.patch.object(honeypot.discord, "Embed", return_value=embed),
                    mock.patch.object(honeypot.discord, "File", side_effect=lambda *a, **k: object()),
                    mock.patch.object(
                        honeypot.discord, "AllowedMentions", SimpleNamespace(none=lambda: None)
                    ),
                ):
                    await asyncio.gather(
                        first._publish_detection_case(
                            appended.case.case_id, {"review_channel": 50}, None
                        ),
                        second._publish_detection_case(
                            appended.case.case_id, {"review_channel": 50}, None
                        ),
                    )

                snapshot = await asyncio.to_thread(
                    first._case_store.get_case, appended.case.case_id
                )
                timeline = await asyncio.to_thread(
                    first._case_store.list_timeline_publications,
                    appended.case.case_id,
                )
                self.assertEqual(channel.send.await_count, 1)
                self.assertEqual(thread.send.await_count, 3)
                self.assertEqual(snapshot.case.review_message_id, 60)
                self.assertEqual(len(timeline), 3)
                self.assertTrue(all(item.state == "published" for item in timeline))

    async def test_reclaimed_primary_publication_deletes_loser_orphan(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                loser = honeypot.Honeypot(_Bot())
                winner = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(loser._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                appended = await asyncio.to_thread(
                    loser._case_store.append_message,
                    loser._new_case_message(message),
                    (honeypot.DetectionSignal(
                        "spam", "active", honeypot.ActionIntent.REVIEW, True, {}
                    ),),
                )
                orphan = SimpleNamespace(id=61, delete=mock.AsyncMock())
                channel = SimpleNamespace(id=50)

                async def send(*args, **kwargs):
                    winner_token = await asyncio.to_thread(
                        winner._case_store.claim_publication,
                        appended.case.case_id,
                        "primary",
                        datetime.now(timezone.utc) + timedelta(minutes=6),
                    )
                    self.assertIsNotNone(winner_token)
                    self.assertTrue(
                        await asyncio.to_thread(
                            winner._case_store.complete_primary_publication,
                            appended.case.case_id,
                            winner_token,
                            channel.id,
                            60,
                        )
                    )
                    return orphan

                channel.send = mock.AsyncMock(side_effect=send)
                loser.bot.get_guild = mock.Mock(return_value=message.guild)
                loser._get_text_channel_or_thread = mock.Mock(return_value=channel)
                embed = SimpleNamespace(add_field=mock.Mock())
                with (
                    mock.patch.object(
                        honeypot.discord, "Color",
                        SimpleNamespace(dark_red=lambda: 1, gold=lambda: 2),
                    ),
                    mock.patch.object(honeypot.discord, "Embed", return_value=embed),
                ):
                    with self.assertRaisesRegex(RuntimeError, "lease was lost"):
                        await loser._publish_detection_case(
                            appended.case.case_id, {"review_channel": 50}, None
                        )

                snapshot = await asyncio.to_thread(
                    loser._case_store.get_case, appended.case.case_id
                )
                orphan.delete.assert_awaited_once()
                self.assertEqual(snapshot.case.review_channel_id, 50)
                self.assertEqual(snapshot.case.review_message_id, 60)




    async def test_rerender_uses_persisted_log_channel_without_configured_destination(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(message),
                    (honeypot.DetectionSignal(
                        "forward_purge", "active", honeypot.ActionIntent.REVIEW, True, {}
                    ),),
                )
                await asyncio.to_thread(
                    publish_primary, cog._case_store, appended.case.case_id, 90, 91
                )
                next_id = 92

                async def thread_send(*args, **kwargs):
                    nonlocal next_id
                    sent_message = SimpleNamespace(id=next_id)
                    next_id += 1
                    return sent_message

                thread = SimpleNamespace(
                    id=91,
                    send=mock.AsyncMock(side_effect=thread_send),
                    fetch_message=mock.AsyncMock(),
                )
                existing = SimpleNamespace(
                    id=91,
                    edit=mock.AsyncMock(),
                    channel=SimpleNamespace(id=90),
                    fetch_thread=mock.AsyncMock(return_value=thread),
                )
                log_channel = SimpleNamespace(
                    id=90,
                    fetch_message=mock.AsyncMock(return_value=existing),
                    send=mock.AsyncMock(),
                )
                cog.bot.get_guild = mock.Mock(return_value=message.guild)
                cog._get_text_channel_or_thread = mock.Mock(return_value=log_channel)
                embed = SimpleNamespace(add_field=mock.Mock())
                with (
                    mock.patch.object(
                        honeypot.discord, "Color",
                        SimpleNamespace(dark_red=lambda: 1, gold=lambda: 2),
                    ),
                    mock.patch.object(honeypot.discord, "Embed", return_value=embed),
                    mock.patch.object(
                        honeypot.discord,
                        "AllowedMentions",
                        SimpleNamespace(none=lambda: None),
                    ),
                ):
                    await cog._publish_detection_case(
                        appended.case.case_id, {"review_channel": None}, None
                    )

                existing.edit.assert_awaited_once()
                log_channel.send.assert_not_awaited()
                self.assertEqual(thread.send.await_count, 2)


    async def test_forward_route_hashes_and_persists_every_image_attachment(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=3)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": False,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                        "imagescan_detector_threshold": 20,
                    },
                )
                cog._imagescan_load_samples = mock.AsyncMock(return_value=[])
                cog._imagescan_model_state = mock.AsyncMock(
                    return_value={"effective_threshold": 20}
                )
                cog._publish_detection_case = mock.AsyncMock()
                with (
                    mock.patch.object(
                        honeypot,
                        "image_hashes_from_bytes",
                        side_effect=lambda data: {
                            "sha256": data.decode(),
                            "phash": f"phash-{data.decode()}",
                            "dhash": "dhash",
                            "ahash": "ahash",
                        },
                    ) as hashes,
                    mock.patch.object(
                        honeypot,
                        "match_image",
                        return_value={"matched": False, "score": None},
                    ),
                ):
                    await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(hashes.call_count, 3)
                self.assertEqual(
                    [item.sha256 for item in snapshot.attachments],
                    ["image-1", "image-2", "image-3"],
                )
                self.assertEqual(
                    [item.perceptual_hash for item in snapshot.attachments],
                    ["phash-image-1", "phash-image-2", "phash-image-3"],
                )

    async def test_forward_firstpost_state_is_consumed_only_after_case_append(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                cog._firstpost_loaded_guilds.add(100)
                message = self._message(honeypot, attachment_count=4)
                self._configure_public_boundary(
                    cog,
                    {
                        "enabled": True,
                        "dry_run": True,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": False,
                        "firstpost_enabled": True,
                        "firstpost_collect_enabled": False,
                    },
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(
                    [signal.signal.detector for signal in snapshot.signals],
                    ["forward_purge", "firstpost"],
                )

    async def test_forward_firstpost_store_failure_leaves_author_unseen_for_retry(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                other = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                await asyncio.to_thread(other._case_store.initialize)
                cog._firstpost_loaded_guilds.add(100)
                other._firstpost_loaded_guilds.add(100)
                cog._increment_stat = mock.AsyncMock()
                message = self._message(honeypot, attachment_count=4)
                config = {"firstpost_enabled": True, "firstpost_action": "review"}
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(message),
                    (honeypot.DetectionSignal(
                        "forward_purge", "active", honeypot.ActionIntent.REVIEW, True, {}
                    ),),
                )
                real_claim = cog._case_store.claim_firstpost
                with mock.patch.object(
                    cog._case_store, "claim_firstpost", side_effect=RuntimeError("sqlite failed")
                ):
                    with self.assertRaisesRegex(RuntimeError, "sqlite failed"):
                        await cog._reserve_forward_firstpost_signal(
                            message, config, appended.case.case_id, 1
                        )
                self.assertNotIn(
                    message.author.id, cog._firstpost_seen_authors[message.guild.id]
                )

                with mock.patch.object(cog._case_store, "claim_firstpost", side_effect=real_claim):
                    reserved = await cog._reserve_forward_firstpost_signal(
                        message, config, appended.case.case_id, 1
                    )

                self.assertTrue(reserved)
                self.assertIn(
                    message.author.id, cog._firstpost_seen_authors[message.guild.id]
                )

    async def test_spam_review_deletes_before_review_publication(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                publication_started = asyncio.Event()
                release_publication = asyncio.Event()

                async def publish(**kwargs):
                    publication_started.set()
                    await release_publication.wait()
                    return SimpleNamespace(id=900)

                logs_channel = SimpleNamespace(id=700, send=mock.AsyncMock(side_effect=publish))
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": 700,
                    "review_channel": None,
                    "spam_enabled": True,
                    "spam_action": "review",
                    "spam_min_channels": 2,
                    "spam_window_seconds": 10,
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                del cog._handle_spam_message
                cog._handle_firstpost_message.return_value = False
                cog._handle_imagescan_detector_message.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                honeypot.discord.Color = SimpleNamespace(
                    red=lambda: 1, orange=lambda: 2, dark_red=lambda: 3, gold=lambda: 4
                )
                honeypot.discord.Embed = lambda **kwargs: SimpleNamespace(
                    color=kwargs.get("color"),
                    add_field=lambda **field: None,
                    set_author=lambda **author: None,
                    set_thumbnail=lambda **thumbnail: None,
                    set_footer=lambda **footer: None,
                )
                cog._attachment_files = mock.Mock(return_value=[])
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._is_forward_purge_active.return_value = False
                cog._get_text_channel_or_thread = mock.Mock(
                    side_effect=lambda guild, channel_id: (
                        logs_channel if channel_id == logs_channel.id else None
                    )
                )

                first = self._message(
                    honeypot, attachment_count=1, message_id=299, channel_id=399
                )
                second = self._message(
                    honeypot, attachment_count=1, message_id=300, channel_id=400
                )
                first.guild.get_channel = lambda channel_id: (
                    logs_channel if channel_id == logs_channel.id else None
                )
                second.guild = first.guild

                cog._record_recent_user_message(first, config)
                task = asyncio.create_task(cog.on_message(second))
                await asyncio.wait_for(publication_started.wait(), timeout=1)
                try:
                    second.delete.assert_awaited_once()
                finally:
                    release_publication.set()
                    await task

    async def test_firstpost_review_delete_failure_is_visible(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                cog._firstpost_loaded_guilds.add(100)
                message = self._message(
                    honeypot,
                    attachment_count=4,
                    delete_error=honeypot.discord.Forbidden("manage messages denied"),
                )
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": False,
                    "firstpost_enabled": True, "firstpost_action": "review",
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(
                    [item.signal.detector for item in snapshot.signals], ["firstpost"]
                )
                self.assertTrue(snapshot.case.needs_attention)
                self.assertEqual(snapshot.messages[0].delete_status.value, "forbidden")
                stat_names = [call.args[1] for call in cog._increment_stat.await_args_list]
                self.assertNotIn("forward_purge_deletes", stat_names)
                self.assertNotIn("forward_purge_delete_failures", stat_names)

    async def test_none_signal_does_not_delete_without_stronger_signal(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                prior = self._message(
                    honeypot, attachment_count=1, message_id=299, channel_id=399
                )
                message = self._message(honeypot, attachment_count=1)
                prior.created_at = datetime.now(timezone.utc)
                message.created_at = prior.created_at
                prior_delete = mock.AsyncMock()
                cached_channel = SimpleNamespace(
                    get_partial_message=lambda message_id: SimpleNamespace(delete=prior_delete)
                )
                message.guild.get_channel = lambda channel_id: (
                    cached_channel if channel_id == prior.channel.id else None
                )
                cog.bot.get_guild = lambda guild_id: message.guild
                prior.guild = message.guild
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": True,
                    "spam_action": "none", "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(
                    side_effect=[[], ["duplicate"]]
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(prior)
                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(snapshot.signals[0].signal.action, honeypot.ActionIntent.NONE)
                self.assertEqual(snapshot.messages[0].delete_status.value, "pending")
                message.delete.assert_not_awaited()
                prior_delete.assert_not_awaited()

    async def test_honeypot_none_still_deletes_outside_dry_run(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0, channel_id=999)
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "honeypot_channels": [999],
                    "whitelisted_roles": [], "fallback_action": "none",
                    "action": "none", "spam_enabled": False,
                    "firstpost_enabled": False, "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._suspicion_reasons = mock.AsyncMock(return_value=[])
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                message.delete.assert_awaited_once()

    async def test_multiple_signals_execute_only_one_ban(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                cog._firstpost_loaded_guilds.add(100)
                message = self._message(honeypot, attachment_count=4)
                message.author.ban = mock.AsyncMock()
                message.guild.get_member = lambda user_id: message.author
                message.guild.me = SimpleNamespace(id=1)
                cog.bot.get_guild = lambda guild_id: message.guild
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": True,
                    "spam_action": "ban", "firstpost_enabled": True,
                    "firstpost_action": "ban", "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._missing_action_permission = mock.Mock(return_value=None)
                cog._ban_delete_message_seconds = mock.Mock(return_value=0)
                cog._schedule_post_ban_sweep = mock.Mock()
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()
                honeypot.modlog.create_case = mock.AsyncMock()

                await cog.on_message(message)

                message.author.ban.assert_awaited_once()
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(
                    [item.signal.detector for item in snapshot.signals],
                    ["spam", "firstpost"],
                )

    async def test_automatic_ban_uses_persisted_id_when_member_cache_misses(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                target = SimpleNamespace(id=20)
                guild = SimpleNamespace(
                    id=100,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: None,
                    ban=mock.AsyncMock(),
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                bot.fetch_user = mock.AsyncMock(return_value=target)
                cog = honeypot.Honeypot(bot)
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                message.guild = guild
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": True,
                    "spam_action": "ban", "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._missing_action_permission = mock.Mock(return_value=None)
                cog._ban_delete_message_seconds = mock.Mock(return_value=0)
                cog._schedule_post_ban_sweep = mock.Mock()
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()
                honeypot.modlog.create_case = mock.AsyncMock()

                await cog.on_message(message)

                guild.ban.assert_awaited_once()
                self.assertIs(guild.ban.await_args.args[0], target)
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, guild.id, message.author.id
                )
                operation = next(
                    item for item in snapshot.operations
                    if item.operation_type == "moderation_action"
                )
                self.assertEqual(operation.status.value, "succeeded")
                self.assertEqual(operation.result, "ban")

    async def test_automatic_kick_missing_member_is_terminal_and_classified(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                guild = SimpleNamespace(
                    id=100,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: None,
                    fetch_member=mock.AsyncMock(
                        side_effect=honeypot.discord.NotFound("member left")
                    ),
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                message.guild = guild
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": True,
                    "spam_action": "kick", "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._execute_action = mock.AsyncMock(
                    side_effect=AssertionError("missing member cannot be kicked")
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, guild.id, message.author.id
                )
                operation = next(
                    item for item in snapshot.operations
                    if item.operation_type == "moderation_action"
                )
                guild.fetch_member.assert_awaited_once_with(message.author.id)
                cog._execute_action.assert_not_awaited()
                self.assertEqual(operation.status.value, "succeeded")
                self.assertEqual(operation.result, "kick_missing")
                self.assertIsNone(operation.retry_at)

    async def test_automatic_dry_run_preserves_planned_action_kind(self):
        for action in ("ban", "kick"):
            with self.subTest(action=action), TemporaryDirectory() as directory:
                with _isolated_honeypot_modules(Path(directory)) as honeypot:
                    cog = honeypot.Honeypot(_Bot())
                    await asyncio.to_thread(cog._case_store.initialize)
                    message = self._message(honeypot, attachment_count=0)
                    message.guild.get_member = lambda user_id: message.author
                    cog.bot.get_guild = lambda guild_id: message.guild
                    config = {
                        "enabled": True,
                        "dry_run": True,
                        "logs_channel": None,
                        "review_channel": None,
                        "spam_enabled": True,
                        "spam_action": action,
                        "firstpost_enabled": False,
                        "firstpost_collect_enabled": False,
                        "imagescan_detector_enabled": False,
                    }
                    self._configure_public_boundary(cog, config)
                    cog._is_forward_purge_active.return_value = False
                    cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                    cog._execute_action = mock.AsyncMock(
                        side_effect=AssertionError("dry-run cannot execute moderation")
                    )
                    cog._scan_all_case_message_images = mock.AsyncMock()
                    cog._publish_detection_case = mock.AsyncMock()

                    await cog.on_message(message)

                    snapshot = await asyncio.to_thread(
                        cog._case_store.get_active_case,
                        message.guild.id,
                        message.author.id,
                    )
                    operation = next(
                        item
                        for item in snapshot.operations
                        if item.operation_type == "moderation_action"
                    )
                    self.assertEqual(operation.result, f"planned_{action}")
                    cog._execute_action.assert_not_awaited()

    async def test_automatic_ban_reclaim_observes_started_effect_without_repeating_it(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                now = datetime.now(timezone.utc)
                banned = False

                async def execute_action(*args, **kwargs):
                    nonlocal banned
                    banned = True
                    return ("banned", None)

                async def fetch_ban(target):
                    if not banned:
                        raise honeypot.discord.NotFound("not banned")
                    return SimpleNamespace(user=target)

                member = SimpleNamespace(id=20)
                guild = SimpleNamespace(
                    id=10,
                    get_member=lambda user_id: member,
                    fetch_ban=mock.AsyncMock(side_effect=fetch_ban),
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                execute = mock.AsyncMock(side_effect=execute_action)
                async def config_values():
                    return {"dry_run": False}

                config = SimpleNamespace(
                    guild_from_id=lambda guild_id: SimpleNamespace(all=config_values)
                )
                first = honeypot.Honeypot(bot)
                first.config = config
                first._execute_action = execute
                first._case_store.initialize()
                appended = first._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="evidence",
                        created_at=now,
                        jump_url="https://discord.test/messages/40",
                        attachments=(),
                    ),
                    (
                        honeypot.DetectionSignal(
                            "spam", "duplicate", honeypot.ActionIntent.BAN, True, {}
                        ),
                    ),
                )
                operation = first._case_store.ensure_operation(
                    appended.case.case_id,
                    "moderation_action",
                    f"moderation_action:{appended.case.case_id}:1:ban",
                    appended.message.sequence,
                )
                claimed = first._case_store.claim_operation(operation.operation_id, now)
                first._case_store.complete_operation = mock.Mock(
                    side_effect=RuntimeError("crash after Discord effect")
                )

                with self.assertRaisesRegex(RuntimeError, "crash after Discord effect"):
                    await first._execute_detection_case_operation(claimed, now)

                restarted = honeypot.Honeypot(bot)
                restarted.config = config
                restarted._execute_action = execute
                reclaimed = restarted._case_store.claim_due_operations(
                    now + timedelta(minutes=6),
                    stale_before=now + timedelta(minutes=5),
                )
                self.assertEqual(len(reclaimed), 1)

                await restarted._execute_detection_case_operation(
                    reclaimed[0], now + timedelta(minutes=6)
                )

                persisted = restarted._case_store.get_case(appended.case.case_id)
                completed = next(
                    item for item in persisted.operations
                    if item.operation_id == operation.operation_id
                )
                self.assertEqual(execute.await_count, 1)
                guild.fetch_ban.assert_awaited_once()
                self.assertEqual(completed.status.value, "succeeded")
                self.assertEqual(completed.result, "ban")

    async def test_moderation_starts_after_containment_without_waiting_for_capture(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                message.guild.get_member = lambda user_id: message.author
                cog.bot.get_guild = lambda guild_id: message.guild
                capture_started = asyncio.Event()
                release_capture = asyncio.Event()
                delete_called = asyncio.Event()
                action_started = asyncio.Event()
                release_action = asyncio.Event()

                async def read_attachment(*args, **kwargs):
                    capture_started.set()
                    await release_capture.wait()
                    return b"evidence"

                async def delete_message(*args, **kwargs):
                    delete_called.set()

                async def fail_action(*args, **kwargs):
                    action_started.set()
                    await release_action.wait()
                    raise RuntimeError("moderation failed")

                message.attachments[0].read = mock.AsyncMock(side_effect=read_attachment)
                message.attachments[0].size = len(b"evidence")
                message.delete = mock.AsyncMock(side_effect=delete_message)
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": True,
                    "spam_action": "ban",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._execute_action = mock.AsyncMock(side_effect=fail_action)
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                task = asyncio.create_task(cog.on_message(message))
                try:
                    await asyncio.wait_for(capture_started.wait(), timeout=1)
                    await asyncio.wait_for(action_started.wait(), timeout=1)
                    containment_preceded_action = delete_called.is_set()
                finally:
                    release_capture.set()
                    release_action.set()
                outcome = (await asyncio.gather(task, return_exceptions=True))[0]

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "moderation_action"
                )
                self.assertTrue(containment_preceded_action)
                self.assertIsNone(outcome)
                self.assertEqual(snapshot.messages[0].delete_status.value, "deleted")
                self.assertEqual(snapshot.attachments[0].capture_status, "captured")
                self.assertEqual(operation.status.value, "failed")
                self.assertIn("moderation failed", operation.last_error)

    async def test_blocked_review_role_starts_after_containment_before_capture_finishes(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                role = SimpleNamespace(id=55)
                message.author.roles = []
                message.guild.get_member = lambda user_id: message.author
                message.guild.get_role = lambda role_id: role
                cog.bot.get_guild = lambda guild_id: message.guild
                capture_started = asyncio.Event()
                source_deleted = asyncio.Event()
                cached_contained = asyncio.Event()
                role_started = asyncio.Event()
                capture_finished = asyncio.Event()
                release_capture = asyncio.Event()
                release_role = asyncio.Event()

                async def read_attachment(*args, **kwargs):
                    capture_started.set()
                    await release_capture.wait()
                    capture_finished.set()
                    return b"evidence"

                async def delete_message(*args, **kwargs):
                    source_deleted.set()

                async def purge_cached(*args, **kwargs):
                    cached_contained.set()
                    return 1

                async def block_role(*args, **kwargs):
                    role_started.set()
                    await release_role.wait()

                message.attachments[0].read = mock.AsyncMock(side_effect=read_attachment)
                message.attachments[0].size = len(b"evidence")
                message.delete = mock.AsyncMock(side_effect=delete_message)
                message.author.add_roles = mock.AsyncMock(side_effect=block_role)
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "mute_role": role.id,
                    "spam_enabled": True,
                    "spam_action": "review",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._purge_detection_case_cached_messages = mock.AsyncMock(
                    side_effect=purge_cached
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                task = asyncio.create_task(cog.on_message(message))
                await asyncio.wait_for(capture_started.wait(), timeout=1)
                await asyncio.wait_for(source_deleted.wait(), timeout=1)
                await asyncio.wait_for(cached_contained.wait(), timeout=1)
                try:
                    await asyncio.wait_for(role_started.wait(), timeout=0.05)
                    role_started_before_capture_finished = True
                except TimeoutError:
                    role_started_before_capture_finished = False

                release_capture.set()
                await asyncio.wait_for(role_started.wait(), timeout=1)
                release_role.set()
                await task
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )

                self.assertTrue(role_started_before_capture_finished)
                self.assertTrue(capture_finished.is_set())
                self.assertEqual(snapshot.attachments[0].capture_status, "captured")

    async def test_cached_purge_not_found_is_persisted_as_already_gone(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                prior = self._message(
                    honeypot, attachment_count=0, message_id=299, channel_id=399
                )
                message = self._message(honeypot, attachment_count=0)
                prior.created_at = datetime.now(timezone.utc)
                message.created_at = prior.created_at
                prior.guild = message.guild
                prior.author = message.author
                cached_delete = mock.AsyncMock(
                    side_effect=honeypot.discord.NotFound("already deleted")
                )
                cached_channel = SimpleNamespace(
                    get_partial_message=lambda message_id: SimpleNamespace(
                        delete=cached_delete
                    )
                )
                message.guild.get_channel = lambda channel_id: (
                    cached_channel if channel_id == prior.channel.id else None
                )
                cog.bot.get_guild = lambda guild_id: message.guild
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": True,
                    "spam_action": "review",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                del cog._purge_detection_case_cached_messages
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(
                    side_effect=[[], ["duplicate"]]
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(prior)
                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                operations = [
                    item
                    for item in snapshot.operations
                    if item.operation_type == "cached_purge"
                ]
                self.assertEqual(len(operations), 1)
                operation = operations[0]
                self.assertEqual(operation.status.value, "succeeded")
                self.assertEqual(operation.result, "already_gone")
                self.assertEqual(operation.attempts, 1)
                self.assertIn(f":{prior.channel.id}:{prior.id}", operation.idempotency_key)
                cached_delete.assert_awaited_once()

    async def test_cached_purge_missing_channel_is_terminal_and_moderator_visible(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(message),
                    (),
                )
                operation = await asyncio.to_thread(
                    cog._case_store.ensure_operation,
                    appended.case.case_id,
                    "cached_purge",
                    f"cached_purge:{appended.case.case_id}:399:299",
                    appended.message.sequence,
                )
                now = datetime.now(timezone.utc)
                operation = await asyncio.to_thread(
                    cog._case_store.claim_operation, operation.operation_id, now
                )
                message.guild.get_channel = lambda channel_id: None
                message.guild.get_thread = lambda channel_id: None
                cog.bot.get_guild = lambda guild_id: message.guild

                await cog._execute_detection_case_operation(operation, now)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                stored = next(
                    item for item in snapshot.operations if item.operation_id == operation.operation_id
                )
                projection = honeypot.render_case(snapshot)
                self.assertEqual(stored.status.value, "abandoned")
                self.assertEqual(stored.result, "channel_unavailable")
                self.assertIsNone(stored.retry_at)
                self.assertTrue(snapshot.case.needs_attention)
                self.assertTrue(
                    any(
                        "<#399>" in line
                        and "Could not delete: channel unavailable" in line
                        for line in projection.cached_purge_lines
                    )
                )

    async def test_cached_purge_unsupported_channel_is_terminal_and_moderator_visible(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    cog._new_case_message(message),
                    (),
                )
                operation = await asyncio.to_thread(
                    cog._case_store.ensure_operation,
                    appended.case.case_id,
                    "cached_purge",
                    f"cached_purge:{appended.case.case_id}:399:299",
                    appended.message.sequence,
                )
                now = datetime.now(timezone.utc)
                operation = await asyncio.to_thread(
                    cog._case_store.claim_operation, operation.operation_id, now
                )
                unsupported_channel = SimpleNamespace(id=399)
                message.guild.get_channel = lambda channel_id: unsupported_channel
                cog.bot.get_guild = lambda guild_id: message.guild

                await cog._execute_detection_case_operation(operation, now)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                stored = next(
                    item for item in snapshot.operations if item.operation_id == operation.operation_id
                )
                projection = honeypot.render_case(snapshot)
                self.assertEqual(stored.status.value, "abandoned")
                self.assertEqual(stored.result, "unsupported_channel")
                self.assertIsNone(stored.retry_at)
                self.assertTrue(snapshot.case.needs_attention)
                self.assertTrue(
                    any(
                        "<#399>" in line
                        and "Could not delete: unsupported channel" in line
                        for line in projection.cached_purge_lines
                    )
                )

    async def test_cached_purge_forbidden_requires_staff_attention(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                prior = self._message(
                    honeypot, attachment_count=0, message_id=299, channel_id=399
                )
                message = self._message(honeypot, attachment_count=0)
                prior.created_at = datetime.now(timezone.utc)
                message.created_at = prior.created_at
                prior.guild = message.guild
                prior.author = message.author
                cached_delete = mock.AsyncMock(
                    side_effect=honeypot.discord.Forbidden("missing permissions")
                )
                cached_channel = SimpleNamespace(
                    get_partial_message=lambda message_id: SimpleNamespace(
                        delete=cached_delete
                    )
                )
                message.guild.get_channel = lambda channel_id: (
                    cached_channel if channel_id == prior.channel.id else None
                )
                cog.bot.get_guild = lambda guild_id: message.guild
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": True,
                    "spam_action": "review",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                del cog._purge_detection_case_cached_messages
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(
                    side_effect=[[], ["duplicate"]]
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(prior)
                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "cached_purge"
                )
                projection = honeypot.render_case(snapshot)
                self.assertEqual(operation.status.value, "abandoned")
                self.assertEqual(operation.result, "forbidden")
                self.assertEqual(operation.attempts, 1)
                self.assertIn("Forbidden", operation.last_error)
                self.assertTrue(snapshot.case.needs_attention)
                self.assertTrue(projection.needs_attention)
                self.assertIn(
                    "Warnings:",
                    [field.name for field in projection.fields],
                )
                cached_delete.assert_awaited_once()

    async def test_cached_purge_exhausted_transient_retries_require_attention(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                prior = self._message(
                    honeypot, attachment_count=0, message_id=299, channel_id=399
                )
                message = self._message(honeypot, attachment_count=0)
                prior.created_at = datetime.now(timezone.utc)
                message.created_at = prior.created_at
                prior.guild = message.guild
                prior.author = message.author
                cached_delete = mock.AsyncMock(
                    side_effect=honeypot.discord.HTTPException()
                )
                cached_channel = SimpleNamespace(
                    get_partial_message=lambda message_id: SimpleNamespace(
                        delete=cached_delete
                    )
                )
                message.guild.get_channel = lambda channel_id: (
                    cached_channel if channel_id == prior.channel.id else None
                )
                cog.bot.get_guild = lambda guild_id: message.guild
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": True,
                    "spam_action": "review",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                del cog._purge_detection_case_cached_messages
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(
                    side_effect=[[], ["duplicate"]]
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(prior)
                await cog.on_message(message)

                first_snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case,
                    message.guild.id,
                    message.author.id,
                )
                first_operation = next(
                    item
                    for item in first_snapshot.operations
                    if item.operation_type == "cached_purge"
                )
                first_operation_id = first_operation.operation_id
                first_projection = honeypot.render_case(first_snapshot)
                self.assertEqual(first_operation.status.value, "failed")
                self.assertEqual(first_operation.result, "transient_failure")
                self.assertIsNotNone(first_operation.retry_at)
                self.assertFalse(first_snapshot.case.needs_attention)
                self.assertTrue(
                    any(
                        "Could not delete: temporary Discord error" in line
                        for line in first_projection.cached_purge_lines
                    )
                )

                for expected_attempt in (2, 3):
                    snapshot = await asyncio.to_thread(
                        cog._case_store.get_active_case,
                        message.guild.id,
                        message.author.id,
                    )
                    operation = next(
                        item
                        for item in snapshot.operations
                        if item.operation_type == "cached_purge"
                    )
                    claimed = await asyncio.to_thread(
                        cog._case_store.claim_operation,
                        operation.operation_id,
                        operation.retry_at,
                    )
                    await cog._execute_detection_case_operation(
                        claimed, operation.retry_at
                    )
                    snapshot = await asyncio.to_thread(
                        cog._case_store.get_active_case,
                        message.guild.id,
                        message.author.id,
                    )
                    operation = next(
                        item
                        for item in snapshot.operations
                        if item.operation_type == "cached_purge"
                    )
                    self.assertEqual(operation.attempts, expected_attempt)
                    self.assertEqual(operation.operation_id, first_operation_id)

                self.assertEqual(
                    sum(
                        item.operation_type == "cached_purge"
                        for item in snapshot.operations
                    ),
                    1,
                )
                self.assertEqual(operation.status.value, "abandoned")
                self.assertEqual(operation.result, "transient_failure")
                self.assertIsNone(operation.retry_at)
                self.assertIn("HTTPException", operation.last_error)
                self.assertTrue(snapshot.case.needs_attention)
                self.assertEqual(cached_delete.await_count, 9)

    async def test_moderation_retry_does_not_treat_missing_source_as_success(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=0)
                message.guild.get_member = lambda user_id: message.author
                message.guild.fetch_ban = mock.AsyncMock(
                    side_effect=honeypot.discord.NotFound("not banned")
                )
                cog.bot.get_guild = lambda guild_id: message.guild
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": True,
                    "spam_action": "ban",
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._execute_action = mock.AsyncMock(
                    return_value=(None, "initial moderation failure")
                )
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "moderation_action"
                )
                self.assertEqual(operation.status.value, "failed")
                channel = SimpleNamespace(
                    fetch_message=mock.AsyncMock(
                        side_effect=honeypot.discord.NotFound("source deleted")
                    )
                )
                message.guild.get_channel = lambda channel_id: channel
                message.guild.get_thread = lambda channel_id: None
                cog.config.guild_from_id = lambda guild_id: SimpleNamespace(
                    all=mock.AsyncMock(return_value=config)
                )
                cog._execute_action.reset_mock()
                cog._execute_action.return_value = (None, "retry moderation failure")
                now = operation.retry_at
                claimed = await asyncio.to_thread(
                    cog._case_store.claim_operation, operation.operation_id, now
                )

                await cog._execute_detection_case_operation(claimed, now)

                retried = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                operation = next(
                    item
                    for item in retried.operations
                    if item.operation_type == "moderation_action"
                )
                cog._execute_action.assert_awaited_once()
                self.assertEqual(operation.status.value, "failed")
                self.assertEqual(operation.attempts, 2)
                self.assertIn("retry moderation failure", operation.last_error)

    async def test_redelivery_resumes_durable_moderation_action_once(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                message = self._message(honeypot, attachment_count=1)
                message.guild.get_member = lambda user_id: message.author
                message.guild.fetch_ban = mock.AsyncMock(
                    side_effect=honeypot.discord.NotFound("not banned")
                )
                cog.bot.get_guild = lambda guild_id: message.guild
                enforced = mock.AsyncMock()
                attempts = 0

                async def execute(*args, **kwargs):
                    nonlocal attempts
                    attempts += 1
                    if attempts == 1:
                        raise RuntimeError("crash after append")
                    await enforced()
                    return ("banned", None)

                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": True,
                    "spam_action": "ban", "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._spam_suspicion_reasons = mock.Mock(return_value=["duplicate"])
                cog._execute_action = mock.AsyncMock(side_effect=execute)
                cog._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()

                await cog.on_message(message)
                failed = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                operation = next(
                    item for item in failed.operations
                    if item.operation_type == "moderation_action"
                )
                self.assertEqual(operation.status.value, "failed")

                await cog.on_message(message)

                completed = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                operation = next(
                    item for item in completed.operations
                    if item.operation_type == "moderation_action"
                )
                self.assertEqual(operation.status.value, "succeeded")
                self.assertEqual(operation.attempts, 2)
                self.assertEqual(operation.result, "ban")
                enforced.assert_awaited_once()
                message.attachments[0].read.assert_awaited_once()
                cog._scan_all_case_message_images.assert_awaited_once()

    async def test_too_large_capture_is_not_fallback_read_by_scanner(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = self._message(honeypot, attachment_count=1)
                message.attachments[0].read = mock.AsyncMock(
                    side_effect=AssertionError("too-large evidence must not be read")
                )
                capture = honeypot.detection_runtime.CaptureResult(
                    0,
                    honeypot.detection_runtime.CaptureStatus.TOO_LARGE,
                    None,
                    "over budget",
                )

                scans = await cog._scan_image_attachments(
                    message, (), 20, capture_results=(capture,)
                )

                message.attachments[0].read.assert_not_awaited()
                self.assertIn("over budget", scans[0]["error"])

    async def test_failed_or_timed_out_capture_is_not_fallback_read_by_scanner(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                for status in (
                    honeypot.detection_runtime.CaptureStatus.FAILED,
                    honeypot.detection_runtime.CaptureStatus.TIMEOUT,
                ):
                    with self.subTest(status=status.value):
                        message = self._message(honeypot, attachment_count=1)
                        message.attachments[0].read = mock.AsyncMock(
                            side_effect=AssertionError(
                                "failed evidence must not be read again"
                            )
                        )
                        capture = honeypot.detection_runtime.CaptureResult(
                            0, status, None, "capture unavailable"
                        )

                        scans = await cog._scan_image_attachments(
                            message, (), 20, capture_results=(capture,)
                        )

                        message.attachments[0].read.assert_not_awaited()
                        self.assertIn("capture unavailable", scans[0]["error"])

    async def test_concurrent_firstpost_messages_have_one_action_owner(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                other = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                await asyncio.to_thread(other._case_store.initialize)
                cog._firstpost_loaded_guilds.add(100)
                other._firstpost_loaded_guilds.add(100)
                first = self._message(
                    honeypot, attachment_count=4, message_id=300, channel_id=400
                )
                second = self._message(
                    honeypot, attachment_count=4, message_id=301, channel_id=401
                )
                second.guild = first.guild
                second.author = first.author
                first.guild.get_member = lambda user_id: first.author
                cog.bot.get_guild = lambda guild_id: first.guild
                other.bot.get_guild = lambda guild_id: first.guild
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": False,
                    "firstpost_enabled": True, "firstpost_action": "ban",
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": False,
                }
                self._configure_public_boundary(cog, config)
                self._configure_public_boundary(other, config)
                cog._is_forward_purge_active.return_value = False
                other._is_forward_purge_active.return_value = False
                cog._execute_action = mock.AsyncMock(return_value=("banned", None))
                other._execute_action = mock.AsyncMock(return_value=("banned", None))
                cog._scan_all_case_message_images = mock.AsyncMock()
                other._scan_all_case_message_images = mock.AsyncMock()
                cog._publish_detection_case = mock.AsyncMock()
                other._publish_detection_case = mock.AsyncMock()

                await asyncio.gather(cog.on_message(first), other.on_message(second))

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, first.guild.id, first.author.id
                )
                firstpost_signals = [
                    item for item in snapshot.signals
                    if item.signal.detector == "firstpost"
                ]
                self.assertEqual(len(firstpost_signals), 1)
                self.assertEqual(
                    cog._execute_action.await_count + other._execute_action.await_count, 1
                )

    async def test_image_trigger_scans_and_persists_remaining_images(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                await cog._init_imagescan_store()
                message = self._message(honeypot, attachment_count=6)
                config = {
                    "enabled": True, "dry_run": False, "logs_channel": None,
                    "review_channel": None, "spam_enabled": False,
                    "firstpost_enabled": False, "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": True,
                    "imagescan_detector_action": "review",
                    "imagescan_detector_threshold": 20,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._imagescan_load_samples = mock.AsyncMock(
                    return_value=[SimpleNamespace(decision="true_positive")]
                )
                cog._imagescan_model_state = mock.AsyncMock(
                    return_value={"valid": True, "effective_threshold": 20}
                )
                cog._publish_detection_case = mock.AsyncMock()

                with (
                    mock.patch.object(
                        honeypot,
                        "image_hashes_from_bytes",
                        side_effect=lambda data: {
                            "sha256": data.decode(), "phash": f"p-{data.decode()}"
                        },
                    ),
                    mock.patch.object(
                        honeypot,
                        "match_image",
                        side_effect=lambda hashes, samples, threshold: {
                            "matched": hashes["sha256"] == "image-1",
                            "score": 1,
                            "exact_decision": "true_positive"
                            if hashes["sha256"] == "image-1" else None,
                        },
                    ),
                ):
                    await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(
                    [item.sha256 for item in snapshot.attachments],
                    [f"image-{index}" for index in range(1, 7)],
                )
                self.assertEqual(
                    [dict(item.match_metadata) for item in snapshot.attachments],
                    [
                        {
                            "matched": index == 1,
                            "score": 1,
                            "exact_decision": "true_positive" if index == 1 else None,
                        }
                        for index in range(1, 7)
                    ],
                )
                for attachment in message.attachments:
                    attachment.read.assert_awaited_once()

    async def test_initial_scan_read_failure_is_retried_for_evidence_and_durable_scan(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                await cog._init_imagescan_store()
                message = self._message(honeypot, attachment_count=2)
                message.attachments[0].read.side_effect = [
                    OSError("temporary CDN failure"),
                    b"image-1",
                ]
                config = {
                    "enabled": True,
                    "dry_run": False,
                    "logs_channel": None,
                    "review_channel": None,
                    "spam_enabled": False,
                    "firstpost_enabled": False,
                    "firstpost_collect_enabled": False,
                    "imagescan_detector_enabled": True,
                    "imagescan_detector_action": "review",
                    "imagescan_detector_threshold": 20,
                }
                self._configure_public_boundary(cog, config)
                cog._is_forward_purge_active.return_value = False
                cog._imagescan_load_samples = mock.AsyncMock(
                    return_value=[SimpleNamespace(decision="true_positive")]
                )
                cog._imagescan_model_state = mock.AsyncMock(
                    return_value={"valid": True, "effective_threshold": 20}
                )
                cog._publish_detection_case = mock.AsyncMock()

                with (
                    mock.patch.object(
                        honeypot,
                        "image_hashes_from_bytes",
                        side_effect=lambda data: {
                            "sha256": data.decode(),
                            "phash": f"p-{data.decode()}",
                        },
                    ),
                    mock.patch.object(
                        honeypot,
                        "match_image",
                        side_effect=lambda hashes, samples, threshold: {
                            "matched": hashes["sha256"] == "image-2",
                            "score": 1,
                        },
                    ),
                ):
                    await cog.on_message(message)

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_active_case, message.guild.id, message.author.id
                )
                self.assertEqual(
                    [item.sha256 for item in snapshot.attachments],
                    ["image-1", "image-2"],
                )
                self.assertEqual(message.attachments[0].read.await_count, 2)
                self.assertNotIn(
                    (message.guild.id, message.id), cog._initial_image_scan_batches
                )

    async def test_failed_admission_releases_initial_scan_batch(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                message = self._message(honeypot, attachment_count=1)
                signal = honeypot.DetectionSignal(
                    "image",
                    "matched",
                    honeypot.ActionIntent.REVIEW,
                    True,
                    {},
                )
                cog._collect_detection_signals = mock.AsyncMock(return_value=(signal,))
                cog._process_detected_message = mock.AsyncMock(
                    side_effect=RuntimeError("admission failed")
                )
                cog._is_protected_member = mock.AsyncMock(return_value=False)
                cog._record_recent_user_message = mock.Mock()
                cog.bot.cog_disabled_in_guild = mock.AsyncMock(return_value=False)
                cog.config.guild = lambda guild: SimpleNamespace(
                    all=mock.AsyncMock(return_value={"enabled": True, "logs_channel": None})
                )
                batch_key = (message.guild.id, message.id)
                completed = asyncio.create_task(asyncio.sleep(0, result={"data": b"image"}))
                cog._initial_image_scan_batches[batch_key] = {0: completed}

                with self.assertRaisesRegex(RuntimeError, "admission failed"):
                    await cog.on_message(message)

                self.assertNotIn(batch_key, cog._initial_image_scan_batches)


class DetectionExpiryTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _config(values):
        async def all_values():
            return values

        return SimpleNamespace(guild_from_id=lambda guild_id: SimpleNamespace(all=all_values))

    @staticmethod
    def _append_case(honeypot, cog, created_at, *, message_id=40):
        cog._case_store.initialize()
        return cog._case_store.append_message(
            honeypot.NewMessage(
                guild_id=10,
                user_id=20,
                channel_id=30,
                message_id=message_id,
                content="evidence",
                created_at=created_at,
                jump_url=f"https://discord.test/messages/{message_id}",
                attachments=(),
            ),
            (),
        )

    async def test_resolution_failure_releases_the_case_lease(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                with mock.patch.object(
                    cog._case_store,
                    "finish_resolution",
                    side_effect=ValueError("conflicting decision"),
                ):
                    with self.assertRaisesRegex(ValueError, "conflicting decision"):
                        await cog.resolve_detection_case(
                            appended.case.case_id, "images:fp", moderator_id=99
                        )

                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                self.assertEqual(snapshot.case.status.value, "pending")

    async def test_evidence_cleanup_waits_for_terminal_review_projection(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                now = datetime.now(timezone.utc)
                cog = honeypot.Honeypot(_Bot())
                await asyncio.to_thread(cog._case_store.initialize)
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10,
                        20,
                        30,
                        40,
                        "evidence",
                        now,
                        None,
                        (
                            honeypot.NewAttachment(
                                0,
                                "proof.png",
                                5,
                                "image/png",
                                10,
                                10,
                                "https://cdn.test/proof.png",
                            ),
                        ),
                    ),
                    (),
                )
                evidence = (
                    honeypot.case_evidence_root(
                        cog._detection_case_files_path,
                        appended.case.guild_id,
                        appended.case.case_id,
                    )
                    / "1"
                    / "proof.png"
                )
                evidence.parent.mkdir(parents=True, exist_ok=True)
                evidence.write_bytes(b"image")
                await asyncio.to_thread(
                    capture_attachment,
                    cog._case_store,
                    appended.case.case_id,
                    1,
                    0,
                    evidence,
                )
                self.assertTrue(
                    await asyncio.to_thread(
                        publish_primary,
                        cog._case_store,
                        appended.case.case_id,
                        50,
                        60,
                    )
                )
                lease = await asyncio.to_thread(
                    cog._case_store.claim_resolution,
                    appended.case.case_id,
                    now,
                )
                self.assertTrue(
                    await asyncio.to_thread(
                        cog._case_store.finish_resolution,
                        lease,
                        honeypot.CaseStatus.RESOLVED,
                        "ignore",
                        99,
                        now,
                        None,
                        (
                            ("review_update", f"review-update:{appended.case.case_id}"),
                            (
                                "evidence_cleanup",
                                f"evidence-cleanup:{appended.case.case_id}",
                            ),
                        ),
                    )
                )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                cleanup = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "evidence_cleanup"
                )
                running = await asyncio.to_thread(
                    cog._case_store.claim_operation, cleanup.operation_id, now
                )

                self.assertTrue(evidence.exists())
                self.assertIsNone(running)
                stored = next(
                    item
                    for item in cog._case_store.get_case(
                        appended.case.case_id
                    ).operations
                    if item.operation_id == cleanup.operation_id
                )
                self.assertEqual(stored.status.value, "pending")
                self.assertIsNone(stored.retry_at)

    async def test_cancelled_operation_worker_stops_its_lease_heartbeat(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = self._config({})
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "review_publish",
                    f"review-publish:{appended.case.case_id}",
                )
                running = cog._case_store.claim_operation(
                    operation.operation_id, datetime.now(timezone.utc)
                )
                heartbeat_started = asyncio.Event()
                heartbeat_stopped = asyncio.Event()
                publication_started = asyncio.Event()

                async def heartbeat(_operation):
                    heartbeat_started.set()
                    try:
                        await asyncio.Event().wait()
                    finally:
                        heartbeat_stopped.set()

                async def blocked_publication(*args, **kwargs):
                    publication_started.set()
                    await asyncio.Event().wait()

                cog._renew_detection_operation = heartbeat
                cog._publish_detection_case = blocked_publication
                task = asyncio.create_task(
                    cog._execute_detection_case_operation(
                        running, datetime.now(timezone.utc)
                    )
                )
                await asyncio.wait_for(heartbeat_started.wait(), timeout=1)
                await asyncio.wait_for(publication_started.wait(), timeout=1)

                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await asyncio.sleep(0)

                self.assertTrue(heartbeat_stopped.is_set())

    async def test_reclaimed_effect_fences_the_stale_role_worker(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                now = datetime.now(timezone.utc)
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, cog, now)
                role = SimpleNamespace(id=77)
                member = SimpleNamespace(
                    roles=[], add_roles=mock.AsyncMock(), id=appended.case.user_id
                )
                guild = SimpleNamespace(
                    id=appended.case.guild_id,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                member.guild = guild
                cog.bot.get_guild = lambda guild_id: guild
                cog._is_joinwatch_active_role = mock.AsyncMock(return_value=False)
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:{role.id}",
                )
                stale = cog._case_store.claim_operation(operation.operation_id, now)
                self.assertTrue(
                    cog._case_store.start_operation_effect(
                        stale.operation_id, stale.claim_token, now
                    )
                )
                reclaimed = cog._case_store.claim_due_operations(
                    now + timedelta(minutes=10),
                    stale_before=now + timedelta(minutes=5),
                )[0]
                self.assertNotEqual(stale.claim_token, reclaimed.claim_token)

                await cog._execute_detection_case_operation(stale, now)

                member.add_roles.assert_not_awaited()

    async def test_terminal_case_fences_late_role_apply(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                now = datetime.now(timezone.utc)
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, cog, now)
                role = SimpleNamespace(id=77)
                member = SimpleNamespace(
                    roles=[], add_roles=mock.AsyncMock(), id=appended.case.user_id
                )
                guild = SimpleNamespace(
                    id=appended.case.guild_id,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                cog.bot.get_guild = lambda guild_id: guild
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:{role.id}",
                )
                running = cog._case_store.claim_operation(operation.operation_id, now)
                lease = cog._case_store.claim_resolution(
                    appended.case.case_id, now + timedelta(seconds=1)
                )
                self.assertTrue(
                    cog._case_store.finish_resolution(
                        lease,
                        honeypot.CaseStatus.EXPIRED,
                        "expired",
                        None,
                        now + timedelta(seconds=1),
                    )
                )

                await cog._execute_detection_case_operation(running, now)

                member.add_roles.assert_not_awaited()
                stored = next(
                    item
                    for item in cog._case_store.get_case(appended.case.case_id).operations
                    if item.operation_id == operation.operation_id
                )
                self.assertEqual(stored.result, "case_terminal")

    async def test_role_apply_compensates_when_case_resolves_during_discord_add(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                now = datetime.now(timezone.utc)
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, cog, now)
                role = SimpleNamespace(id=77)
                member = SimpleNamespace(id=appended.case.user_id, roles=[])

                async def add_role(added, **kwargs):
                    member.roles.append(added)
                    lease = cog._case_store.claim_resolution(
                        appended.case.case_id, now + timedelta(seconds=1)
                    )
                    self.assertTrue(
                        cog._case_store.finish_resolution(
                            lease,
                            honeypot.CaseStatus.EXPIRED,
                            "expired",
                            None,
                            now + timedelta(seconds=1),
                        )
                    )

                async def remove_role(removed, **kwargs):
                    member.roles.remove(removed)

                member.add_roles = mock.AsyncMock(side_effect=add_role)
                member.remove_roles = mock.AsyncMock(side_effect=remove_role)
                guild = SimpleNamespace(
                    id=appended.case.guild_id,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                member.guild = guild
                cog.bot.get_guild = lambda guild_id: guild
                cog._is_joinwatch_active_role = mock.AsyncMock(return_value=False)
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:{role.id}",
                )

                await cog._execute_detection_case_operation(
                    cog._case_store.claim_operation(operation.operation_id, now), now
                )

                self.assertNotIn(role, member.roles)
                member.remove_roles.assert_awaited_once()
                snapshot = cog._case_store.get_case(appended.case.case_id)
                release = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "role_release"
                )
                self.assertEqual(release.status.value, "succeeded")

    async def test_review_role_ownership_hands_off_to_the_next_case(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                now = datetime.now(timezone.utc)
                cog = honeypot.Honeypot(_Bot())
                first = self._append_case(honeypot, cog, now)
                role = SimpleNamespace(id=77)
                member = SimpleNamespace(id=first.case.user_id, roles=[])

                async def add_role(*args, **kwargs):
                    member.roles.append(role)

                async def remove_role(*args, **kwargs):
                    member.roles.remove(role)

                member.add_roles = mock.AsyncMock(side_effect=add_role)
                member.remove_roles = mock.AsyncMock(side_effect=remove_role)
                guild = SimpleNamespace(
                    id=first.case.guild_id,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                cog.bot.get_guild = lambda guild_id: guild
                first_apply = cog._case_store.ensure_operation(
                    first.case.case_id,
                    "role_apply",
                    f"role-apply:{first.case.case_id}:{role.id}",
                )
                await cog._execute_detection_case_operation(
                    cog._case_store.claim_operation(first_apply.operation_id, now), now
                )
                lease = cog._case_store.claim_resolution(
                    first.case.case_id, now + timedelta(seconds=1)
                )
                self.assertTrue(
                    cog._case_store.finish_resolution(
                        lease,
                        honeypot.CaseStatus.EXPIRED,
                        "expired",
                        None,
                        now + timedelta(seconds=1),
                        final_operations=(
                            (
                                "role_release",
                                f"role-release:{first.case.case_id}:{role.id}",
                            ),
                        ),
                    )
                )
                second = self._append_case(
                    honeypot, cog, now + timedelta(seconds=2), message_id=41
                )
                second_apply = cog._case_store.ensure_operation(
                    second.case.case_id,
                    "role_apply",
                    f"role-apply:{second.case.case_id}:{role.id}",
                )
                await cog._execute_detection_case_operation(
                    cog._case_store.claim_operation(
                        second_apply.operation_id, now + timedelta(seconds=2)
                    ),
                    now + timedelta(seconds=2),
                )

                self.assertEqual(
                    cog._case_store.owned_role_ids(second.case.case_id), (role.id,)
                )
                release = next(
                    item
                    for item in cog._case_store.get_case(first.case.case_id).operations
                    if item.operation_type == "role_release"
                )
                await cog._execute_detection_case_operation(
                    cog._case_store.claim_operation(
                        release.operation_id, now + timedelta(seconds=3)
                    ),
                    now + timedelta(seconds=3),
                )
                member.remove_roles.assert_not_awaited()
                self.assertIn(role, member.roles)

    async def test_role_release_cannot_remove_role_after_handoff_race(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                now = datetime.now(timezone.utc)
                cog = honeypot.Honeypot(_Bot())
                first = self._append_case(honeypot, cog, now)
                role = SimpleNamespace(id=77)
                member = SimpleNamespace(id=first.case.user_id, roles=[])

                async def add_role(added, **kwargs):
                    if added not in member.roles:
                        member.roles.append(added)

                member.add_roles = mock.AsyncMock(side_effect=add_role)
                member.remove_roles = mock.AsyncMock()
                guild = SimpleNamespace(
                    id=first.case.guild_id,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                cog.bot.get_guild = lambda guild_id: guild
                first_apply = cog._case_store.ensure_operation(
                    first.case.case_id,
                    "role_apply",
                    f"role-apply:{first.case.case_id}:{role.id}",
                )
                await cog._execute_detection_case_operation(
                    cog._case_store.claim_operation(first_apply.operation_id, now), now
                )
                lease = cog._case_store.claim_resolution(
                    first.case.case_id, now + timedelta(seconds=1)
                )
                self.assertTrue(
                    cog._case_store.finish_resolution(
                        lease,
                        honeypot.CaseStatus.EXPIRED,
                        "expired",
                        None,
                        now + timedelta(seconds=1),
                        final_operations=((
                            "role_release",
                            f"role-release:{first.case.case_id}:{role.id}",
                        ),),
                    )
                )
                release = next(
                    item
                    for item in cog._case_store.get_case(first.case.case_id).operations
                    if item.operation_type == "role_release"
                )
                release_started = asyncio.Event()
                allow_release = asyncio.Event()

                async def blocked_remove(*args, **kwargs):
                    release_started.set()
                    await allow_release.wait()
                    if role in member.roles:
                        member.roles.remove(role)
                    return True

                cog._remove_review_mute_role = blocked_remove
                release_worker = asyncio.create_task(
                    cog._execute_detection_case_operation(
                        cog._case_store.claim_operation(
                            release.operation_id, now + timedelta(seconds=2)
                        ),
                        now + timedelta(seconds=2),
                    )
                )
                await asyncio.wait_for(release_started.wait(), timeout=1)

                second = self._append_case(
                    honeypot, cog, now + timedelta(seconds=3), message_id=41
                )
                second_apply = cog._case_store.ensure_operation(
                    second.case.case_id,
                    "role_apply",
                    f"role-apply:{second.case.case_id}:{role.id}",
                )
                await cog._execute_detection_case_operation(
                    cog._case_store.claim_operation(
                        second_apply.operation_id, now + timedelta(seconds=3)
                    ),
                    now + timedelta(seconds=3),
                )
                allow_release.set()
                await release_worker

                pending = next(
                    item
                    for item in cog._case_store.get_case(second.case.case_id).operations
                    if item.operation_id == second_apply.operation_id
                )
                self.assertEqual(pending.status.value, "failed")
                retry = cog._case_store.claim_operation(
                    second_apply.operation_id,
                    pending.retry_at + timedelta(seconds=1),
                )
                await cog._execute_detection_case_operation(retry, pending.retry_at)

                self.assertIn(role, member.roles)
                self.assertEqual(
                    cog._case_store.owned_role_ids(second.case.case_id), (role.id,)
                )

    async def test_later_publication_failure_gets_new_durable_work(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                now = datetime.now(timezone.utc)
                cog = honeypot.Honeypot(_Bot())
                first = self._append_case(honeypot, cog, now)
                await cog._record_publication_failure(
                    first.case.case_id, RuntimeError("first failure")
                )
                snapshot = cog._case_store.get_case(first.case.case_id)
                first_operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "review_publish"
                )
                running = cog._case_store.claim_due_operations(
                    first_operation.retry_at
                )[0]
                self.assertTrue(
                    cog._case_store.complete_operation(
                        running.operation_id,
                        running.claim_token,
                        first_operation.retry_at,
                    )
                )
                self._append_case(
                    honeypot, cog, now + timedelta(seconds=1), message_id=41
                )

                await cog._record_publication_failure(
                    first.case.case_id, RuntimeError("later failure")
                )

                snapshot = cog._case_store.get_case(first.case.case_id)
                publication_operations = tuple(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "review_publish"
                )
                self.assertEqual(len(publication_operations), 2)
                self.assertEqual(
                    {item.status.value for item in publication_operations},
                    {"succeeded", "failed"},
                )

    async def test_case_projection_warns_about_failed_required_operations(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                now = datetime.now(timezone.utc)
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, cog, now)
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_release",
                    f"role-release:{appended.case.case_id}:77",
                )
                running = cog._case_store.claim_operation(operation.operation_id, now)
                self.assertTrue(
                    cog._case_store.fail_operation(
                        running.operation_id,
                        running.claim_token,
                        "missing permission",
                        now,
                        now + timedelta(minutes=5),
                    )
                )

                projection = honeypot.render_case(
                    cog._case_store.get_case(appended.case.case_id)
                )

                warnings = "\n".join(
                    field.value for page in projection.pages for field in page
                )
                self.assertIn("mute", warnings.lower())
                self.assertIn("bot logs", warnings.lower())
                self.assertNotIn("role_release", warnings)

    async def test_case_ignore_control_resolves_without_image_decisions(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = self._config({})
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                cog._activate_forward_purge(
                    appended.case.guild_id,
                    appended.case.user_id,
                    {"purge_forward_seconds": 60},
                )
                self.assertTrue(
                    cog._is_forward_purge_active(
                        appended.case.guild_id, appended.case.user_id
                    )
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(
                            manage_messages=True, ban_members=False
                        ),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(),
                        is_done=lambda: True,
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "ignore"
                )

                snapshot = cog._case_store.get_case(appended.case.case_id)
                interaction.response.defer.assert_awaited_once()
                self.assertEqual(snapshot.case.status.value, "resolved")
                self.assertEqual(snapshot.case.resolution, "ignore")
                self.assertEqual(
                    [item.learning_decision for item in snapshot.attachments], []
                )
                self.assertNotIn(
                    "moderator_action",
                    {item.operation_type for item in snapshot.operations},
                )
                self.assertFalse(
                    cog._is_forward_purge_active(
                        appended.case.guild_id, appended.case.user_id
                    )
                )

    async def test_ignore_waits_until_attachment_capture_finishes(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._case_store.initialize()
                now = datetime.now(timezone.utc)
                appended = cog._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="evidence",
                        created_at=now,
                        jump_url="https://discord.test/messages/40",
                        attachments=(
                            honeypot.NewAttachment(
                                0,
                                "proof.png",
                                5,
                                "image/png",
                                10,
                                10,
                                "https://cdn.test/proof.png",
                            ),
                        ),
                    ),
                    (),
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(manage_messages=True),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(),
                        is_done=lambda: True,
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "ignore"
                )

                snapshot = cog._case_store.get_case(appended.case.case_id)
                self.assertEqual(snapshot.case.status.value, "pending")
                self.assertIsNone(snapshot.case.resolution)
                interaction.followup.send.assert_awaited_once()
                self.assertIn(
                    "still processing",
                    interaction.followup.send.await_args.args[0].lower(),
                )

    async def test_bulk_tp_interaction_ignores_captured_pdf_evidence(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._case_store.initialize()
                appended = cog._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="evidence",
                        created_at=datetime.now(timezone.utc),
                        jump_url="https://discord.test/messages/40",
                        attachments=(
                            honeypot.NewAttachment(
                                0, "proof.png", 10, "image/png", None, None, "png-url"
                            ),
                            honeypot.NewAttachment(
                                1, "invoice.pdf", 10, "application/pdf", None, None, "pdf-url"
                            ),
                        ),
                    ),
                    (),
                )
                for position, filename in enumerate(("proof.png", "invoice.pdf")):
                    self.assertTrue(
                        capture_attachment(
                            cog._case_store,
                            appended.case.case_id,
                            appended.message.sequence,
                            position,
                            Path(directory) / filename,
                        )
                    )
                cog._execute_detection_case_operation = mock.AsyncMock()
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(manage_messages=True),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(),
                        send_message=mock.AsyncMock(),
                        is_done=lambda: False,
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_bulk_interaction(
                    interaction, appended.case.case_id, "tp"
                )

                snapshot = cog._case_store.get_case(appended.case.case_id)
                self.assertTrue(
                    all(
                        attachment.learning_decision is None
                        for attachment in snapshot.attachments
                    )
                )
                interaction.response.send_message.assert_awaited_once()

                await cog._case_review_bulk_interaction(
                    interaction,
                    appended.case.case_id,
                    "tp",
                    confirmed=True,
                )

                snapshot = cog._case_store.get_case(appended.case.case_id)
                decisions = {
                    attachment.filename: attachment.learning_decision
                    for attachment in snapshot.attachments
                }
                self.assertEqual(decisions["proof.png"], "true_positive")
                self.assertIsNone(decisions["invoice.pdf"])

    async def test_case_ban_control_executes_one_durable_action(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                member = SimpleNamespace(id=20, ban=mock.AsyncMock(), roles=[])
                guild = SimpleNamespace(
                    id=10,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: member,
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                bot.loop = asyncio.get_running_loop()
                cog = honeypot.Honeypot(bot)
                config = {"dry_run": False}
                cog.config = self._config(config)
                cog.config.guild = lambda target_guild: SimpleNamespace(
                    all=mock.AsyncMock(return_value=config)
                )
                cog._missing_action_permission = mock.Mock(return_value=None)
                cog._ban_delete_message_seconds = mock.Mock(return_value=0)
                cog._increment_stat = mock.AsyncMock()
                cog._cached_purge_user_messages = mock.AsyncMock(return_value=0)
                honeypot.modlog.create_case = mock.AsyncMock()
                honeypot.POST_BAN_SWEEP_DELAY_SECONDS = 0
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(
                            manage_messages=True, ban_members=True
                        ),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(), is_done=lambda: True
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "ban"
                )
                await asyncio.gather(*cog._post_ban_sweep_tasks)
                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "ban"
                )

                snapshot = cog._case_store.get_case(appended.case.case_id)
                operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "moderator_ban"
                )
                member.ban.assert_awaited_once()
                cog._cached_purge_user_messages.assert_awaited_once_with(
                    guild, member.id, config
                )
                cog._increment_stat.assert_any_await(guild, "banned")
                honeypot.modlog.create_case.assert_awaited_once()
                self.assertEqual(operation.status.value, "succeeded")
                self.assertEqual(operation.result, "ban")
                self.assertEqual(operation.attempts, 1)
                self.assertEqual(snapshot.case.status.value, "resolved")
                self.assertEqual(snapshot.case.resolution, "ban")
                self.assertEqual(snapshot.case.moderator_id, 99)

    async def test_moderator_ban_requires_confirmation_for_unreviewed_attachment(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                member = SimpleNamespace(id=20, roles=[], ban=mock.AsyncMock())
                guild = SimpleNamespace(
                    id=10,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: member,
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                cog._case_store.initialize()
                cog.config = self._config({"dry_run": True})
                honeypot.DetectionModerationConfirmationView.add_item = (
                    lambda view, item: setattr(
                        view, "children", getattr(view, "children", []) + [item]
                    )
                )
                honeypot.discord.ui.Button = lambda **kwargs: SimpleNamespace(**kwargs)
                now = datetime.now(timezone.utc)
                appended = cog._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="evidence",
                        created_at=now,
                        jump_url="https://discord.test/messages/40",
                        attachments=(
                            honeypot.NewAttachment(
                                0,
                                "proof.png",
                                5,
                                "image/png",
                                10,
                                10,
                                "https://cdn.test/proof.png",
                            ),
                        ),
                    ),
                    (),
                )
                response = SimpleNamespace(
                    defer=mock.AsyncMock(),
                    send_message=mock.AsyncMock(),
                    is_done=lambda: False,
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(ban_members=True),
                    ),
                    response=response,
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "ban"
                )

                response.defer.assert_not_awaited()
                response.send_message.assert_awaited_once()
                self.assertTrue(response.send_message.await_args.kwargs["ephemeral"])
                confirmation = response.send_message.await_args.kwargs["view"]
                self.assertEqual(
                    [item.label for item in confirmation.children],
                    ["Confirm Ban"],
                )
                snapshot = cog._case_store.get_case(appended.case.case_id)
                self.assertEqual(snapshot.case.status.value, "pending")
                self.assertEqual(snapshot.operations, ())

                confirmation_interaction = SimpleNamespace(
                    user=interaction.user,
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(),
                        is_done=lambda: True,
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )
                await confirmation.children[0].callback(confirmation_interaction)

                snapshot = cog._case_store.get_case(appended.case.case_id)
                operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "moderator_ban"
                )
                confirmation_interaction.response.defer.assert_awaited_once()
                self.assertEqual(operation.status.value, "succeeded")
                self.assertEqual(operation.result, "planned_ban")

    async def test_dry_run_moderator_ban_is_persisted_as_planned(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                member = SimpleNamespace(id=20, ban=mock.AsyncMock(), roles=[])
                guild = SimpleNamespace(
                    id=10,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: member,
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                cog.config = self._config({"dry_run": True})
                cog._execute_action = mock.AsyncMock(
                    side_effect=AssertionError("dry-run must not execute punishment")
                )
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(
                            manage_messages=True, ban_members=True
                        ),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(), is_done=lambda: True
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "ban"
                )

                snapshot = cog._case_store.get_case(appended.case.case_id)
                operation = next(
                    item for item in snapshot.operations
                    if item.operation_type == "moderator_ban"
                )
                member.ban.assert_not_awaited()
                cog._execute_action.assert_not_awaited()
                self.assertEqual(operation.status.value, "succeeded")
                self.assertEqual(operation.result, "planned_ban")
                self.assertEqual(snapshot.case.resolution, "planned_ban")
                self.assertEqual(
                    honeypot.render_case(snapshot).moderation_status,
                    "Ban planned (dry run)",
                )

    async def test_moderator_ban_uses_persisted_ids_when_member_cache_misses(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                target = SimpleNamespace(id=20)
                actor = SimpleNamespace(id=99)
                guild = SimpleNamespace(
                    id=10,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: None,
                    ban=mock.AsyncMock(),
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                bot.fetch_user = mock.AsyncMock(
                    side_effect=lambda user_id: target if user_id == 20 else actor
                )
                cog = honeypot.Honeypot(bot)
                cog.config = self._config({"dry_run": False})
                cog._missing_action_permission = mock.Mock(return_value=None)
                cog._ban_delete_message_seconds = mock.Mock(return_value=0)
                cog._schedule_post_ban_sweep = mock.Mock()
                cog._increment_stat = mock.AsyncMock()
                honeypot.modlog.create_case = mock.AsyncMock()
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=actor.id,
                        guild_permissions=SimpleNamespace(
                            manage_messages=False,
                            ban_members=True,
                            kick_members=False,
                        ),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(), is_done=lambda: True
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "ban"
                )

                guild.ban.assert_awaited_once()
                self.assertIs(guild.ban.await_args.args[0], target)
                self.assertEqual(
                    honeypot.modlog.create_case.await_args.kwargs["moderator"].id,
                    actor.id,
                )
                snapshot = cog._case_store.get_case(appended.case.case_id)
                operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "moderator_ban"
                )
                self.assertEqual(operation.status.value, "succeeded")
                self.assertEqual(operation.result, "ban")
                self.assertEqual(snapshot.case.status.value, "resolved")
                self.assertEqual(snapshot.case.resolution, "ban")
                self.assertEqual(snapshot.case.moderator_id, actor.id)

    async def test_moderator_kick_missing_member_finishes_with_explicit_result(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                guild = SimpleNamespace(
                    id=10,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: None,
                    fetch_member=mock.AsyncMock(
                        side_effect=honeypot.discord.NotFound("member left")
                    ),
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                cog.config = self._config({"dry_run": False})
                cog._execute_action = mock.AsyncMock(
                    side_effect=AssertionError("missing member cannot be kicked")
                )
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(
                            manage_messages=False,
                            ban_members=False,
                            kick_members=True,
                        ),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(), is_done=lambda: True
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "kick"
                )

                snapshot = cog._case_store.get_case(appended.case.case_id)
                operation = next(
                    item
                    for item in snapshot.operations
                    if item.operation_type == "moderator_kick"
                )
                guild.fetch_member.assert_awaited_once_with(snapshot.case.user_id)
                cog._execute_action.assert_not_awaited()
                self.assertEqual(operation.status.value, "succeeded")
                self.assertEqual(operation.result, "kick_missing")
                self.assertEqual(snapshot.case.status.value, "resolved")
                self.assertEqual(snapshot.case.resolution, "kick")
                self.assertEqual(snapshot.case.moderator_id, 99)

    async def test_moderator_actor_survives_failed_action_retry_and_resolution(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                member = SimpleNamespace(id=20, roles=[])
                guild = SimpleNamespace(
                    id=10,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: member,
                    fetch_ban=mock.AsyncMock(
                        side_effect=honeypot.discord.NotFound("not banned")
                    ),
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                cog.config = self._config({"dry_run": False})
                cog._execute_action = mock.AsyncMock(
                    side_effect=[("ban", "temporary failure"), ("ban", None)]
                )
                cog._case_review_rerender = mock.AsyncMock()
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(
                            manage_messages=False,
                            ban_members=True,
                            kick_members=False,
                        ),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(), is_done=lambda: True
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "ban"
                )

                failed_snapshot = cog._case_store.get_case(appended.case.case_id)
                failed = next(
                    item
                    for item in failed_snapshot.operations
                    if item.operation_type == "moderator_ban"
                )
                self.assertEqual(failed.status.value, "failed")
                self.assertEqual(failed.actor_id, 99)
                self.assertEqual(failed_snapshot.case.status.value, "resolving")
                claimed = cog._case_store.claim_operation(
                    failed.operation_id, failed.retry_at
                )
                await cog._execute_detection_case_operation(claimed, failed.retry_at)

                resolved = cog._case_store.get_case(appended.case.case_id)
                retried = next(
                    item
                    for item in resolved.operations
                    if item.operation_type == "moderator_ban"
                )
                self.assertEqual(retried.status.value, "succeeded")
                self.assertEqual(retried.attempts, 2)
                self.assertEqual(retried.actor_id, 99)
                self.assertEqual(resolved.case.status.value, "resolved")
                self.assertEqual(resolved.case.resolution, "ban")
                self.assertEqual(resolved.case.moderator_id, 99)

    async def test_moderator_ban_intent_fences_concurrent_ignore(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                ban_started = asyncio.Event()
                release_ban = asyncio.Event()

                async def blocked_ban(**kwargs):
                    ban_started.set()
                    await release_ban.wait()

                member = SimpleNamespace(
                    id=20,
                    ban=mock.AsyncMock(side_effect=blocked_ban),
                    roles=[],
                )
                guild = SimpleNamespace(
                    id=10,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: member,
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                cog.config = self._config({"dry_run": False})
                cog._missing_action_permission = mock.Mock(return_value=None)
                cog._ban_delete_message_seconds = mock.Mock(return_value=0)
                cog._schedule_post_ban_sweep = mock.Mock()
                cog._increment_stat = mock.AsyncMock()
                cog._case_review_rerender = mock.AsyncMock()
                honeypot.modlog.create_case = mock.AsyncMock()
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(
                            manage_messages=False,
                            ban_members=True,
                            kick_members=False,
                        ),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(), is_done=lambda: True
                    ),
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                action_task = asyncio.create_task(
                    cog._case_review_moderation_interaction(
                        interaction, appended.case.case_id, "ban"
                    )
                )
                await asyncio.wait_for(ban_started.wait(), timeout=1)
                ignored = await cog.resolve_detection_case(
                    appended.case.case_id, "ignore", moderator_id=100
                )
                release_ban.set()
                await action_task

                snapshot = cog._case_store.get_case(appended.case.case_id)
                self.assertFalse(ignored)
                member.ban.assert_awaited_once()
                self.assertEqual(snapshot.case.status.value, "resolved")
                self.assertEqual(snapshot.case.resolution, "ban")
                self.assertEqual(snapshot.case.moderator_id, 99)

    async def test_reconciliation_completes_started_moderator_ban_without_repeating_it(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                old = datetime.now(timezone.utc) - timedelta(minutes=10)
                member = SimpleNamespace(id=20, ban=mock.AsyncMock(), roles=[])
                guild = SimpleNamespace(
                    id=10,
                    me=SimpleNamespace(id=1),
                    get_member=lambda user_id: member,
                    fetch_ban=mock.AsyncMock(
                        return_value=SimpleNamespace(user=member)
                    ),
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                first = honeypot.Honeypot(bot)
                appended = self._append_case(honeypot, first, old)
                operation = first._case_store.claim_moderator_action(
                    appended.case.case_id, "ban", 99, old
                )
                claimed = first._case_store.claim_operation(
                    operation.operation_id, old
                )
                self.assertTrue(
                    first._case_store.start_operation_effect(
                        claimed.operation_id, claimed.claim_token, old
                    )
                )

                restarted = honeypot.Honeypot(bot)
                restarted.config = self._config({"dry_run": False})
                restarted._execute_action = mock.AsyncMock(
                    side_effect=AssertionError("ban effect must not repeat")
                )

                await restarted._run_detection_reconciliation()

                resolved = restarted._case_store.get_case(appended.case.case_id)
                persisted = next(
                    item
                    for item in resolved.operations
                    if item.operation_id == operation.operation_id
                )
                guild.fetch_ban.assert_awaited_once()
                self.assertEqual(guild.fetch_ban.await_args.args[0].id, member.id)
                restarted._execute_action.assert_not_awaited()
                member.ban.assert_not_awaited()
                self.assertEqual(persisted.status.value, "succeeded")
                self.assertEqual(persisted.result, "ban")
                self.assertEqual(persisted.attempts, 2)
                self.assertEqual(resolved.case.status.value, "resolved")
                self.assertEqual(resolved.case.resolution, "ban")
                self.assertEqual(resolved.case.moderator_id, 99)

    async def test_started_moderator_effect_waits_for_late_evidence_and_containment(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                now = datetime.now(timezone.utc)
                first = honeypot.Honeypot(_Bot())
                second = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, first, now)
                operation = first._case_store.claim_moderator_action(
                    appended.case.case_id, "ban", 99, now
                )
                claimed = first._case_store.claim_operation(operation.operation_id, now)
                self.assertTrue(
                    first._case_store.start_operation_effect(
                        claimed.operation_id, claimed.claim_token, now
                    )
                )

                late = second._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=31,
                        message_id=41,
                        content="late evidence",
                        created_at=now + timedelta(seconds=1),
                        jump_url="https://discord.test/messages/41",
                        attachments=(
                            honeypot.NewAttachment(
                                0, "late.png", 8, "image/png", None, None, "late-url"
                            ),
                        ),
                    ),
                    (
                        honeypot.DetectionSignal(
                            "spam", "late signal", honeypot.ActionIntent.REVIEW, True, {}
                        ),
                    ),
                )
                cached = second._case_store.ensure_operation(
                    late.case.case_id,
                    "cached_purge",
                    f"cached-purge:{late.case.case_id}:31:39",
                    late.message.sequence,
                )
                reservation = second._case_store.reserve_attachment_capture(
                    late.case.case_id,
                    late.message.sequence,
                    0,
                    8,
                    now + timedelta(seconds=1),
                    stale_before=now - timedelta(minutes=5),
                    max_attachment_bytes=1024,
                    max_case_bytes=2048,
                )
                self.assertEqual(reservation.status, "claimed")

                self.assertTrue(
                    first._case_store.complete_moderator_action(
                        claimed.operation_id, claimed.claim_token, now + timedelta(seconds=2), "ban"
                    )
                )
                waiting = first._case_store.get_case(appended.case.case_id)
                self.assertEqual(waiting.case.status.value, "resolving")
                self.assertEqual(
                    next(
                        item for item in waiting.operations
                        if item.operation_id == claimed.operation_id
                    ).status.value,
                    "succeeded",
                )

                evidence_path = str(Path(directory) / "late.png")
                self.assertEqual(
                    second._case_store.complete_attachment_capture(
                        late.case.case_id,
                        late.message.sequence,
                        0,
                        reservation.claim_token,
                        8,
                        evidence_path,
                        now + timedelta(seconds=3),
                        max_attachment_bytes=1024,
                        max_case_bytes=2048,
                    ),
                    "captured",
                )
                self.assertTrue(
                    second._case_store.update_message_delete(
                        late.case.case_id,
                        late.message.sequence,
                        honeypot.DeleteStatus.DELETED,
                        None,
                        False,
                    )
                )
                cached_claim = second._case_store.claim_operation(
                    cached.operation_id, now + timedelta(seconds=3)
                )
                self.assertTrue(
                    second._case_store.complete_operation(
                        cached_claim.operation_id,
                        cached_claim.claim_token,
                        now + timedelta(seconds=3),
                        "deleted",
                    )
                )

                self.assertEqual(
                    second._case_store.reconcile_moderator_actions(
                        now + timedelta(seconds=4)
                    ),
                    (appended.case.case_id,),
                )

                resolved = second._case_store.get_case(appended.case.case_id)
                self.assertEqual(resolved.case.status.value, "resolved")
                self.assertEqual(resolved.case.resolution, "ban")
                self.assertEqual(resolved.attachments[0].evidence_path, evidence_path)
                self.assertIn(
                    "evidence_cleanup", {item.operation_type for item in resolved.operations}
                )

    async def test_case_view_keeps_moderation_and_image_controls_separate(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                def add_item(view, item):
                    view.children = getattr(view, "children", []) + [item]

                honeypot.DetectionCaseView.add_item = add_item
                honeypot.discord.ui.Button = lambda **kwargs: SimpleNamespace(**kwargs)

                view = honeypot.DetectionCaseView(
                    honeypot.Honeypot(_Bot()),
                    "case-1",
                    has_image_feedback=True,
                )

                self.assertEqual(
                    [item.label for item in view.children],
                    [
                        "Ban",
                        "Kick",
                        "Ignore",
                        "All TP",
                        "All FP",
                        "Ignore",
                        "Individual",
                    ],
                )
                self.assertEqual(
                    [item.custom_id for item in view.children[:3]],
                    [
                        "honeypot:case:case-1:moderate:ban",
                        "honeypot:case:case-1:moderate:kick",
                        "honeypot:case:case-1:moderate:ignore",
                    ],
                )
                self.assertEqual(
                    [item.emoji for item in view.children[:3]],
                    ["🔨", "👢", "✅"],
                )
                self.assertEqual(
                    [item.style for item in view.children[:3]],
                    [
                        honeypot.discord.ButtonStyle.danger,
                        honeypot.discord.ButtonStyle.secondary,
                        honeypot.discord.ButtonStyle.success,
                    ],
                )

    async def test_message_view_only_offers_message_feedback(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                def add_item(view, item):
                    view.children = getattr(view, "children", []) + [item]

                honeypot.DetectionCaseView.add_item = add_item
                honeypot.discord.ui.Button = lambda **kwargs: SimpleNamespace(**kwargs)

                view = honeypot.DetectionCaseView(
                    honeypot.Honeypot(_Bot()),
                    "case-1",
                    has_image_feedback=True,
                    message_sequence=2,
                )

                self.assertEqual(
                    [item.label for item in view.children],
                    ["All TP", "All FP", "Ignore", "Individual"],
                )

    async def test_case_view_hides_individual_when_case_has_too_many_images(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                def add_item(view, item):
                    view.children = getattr(view, "children", []) + [item]

                honeypot.DetectionCaseView.add_item = add_item
                honeypot.discord.ui.Button = lambda **kwargs: SimpleNamespace(**kwargs)

                view = honeypot.DetectionCaseView(
                    honeypot.Honeypot(_Bot()),
                    "case-1",
                    has_image_feedback=True,
                    allow_individual=False,
                )

                self.assertNotIn("Individual", [item.label for item in view.children])

    async def test_case_summary_warns_and_hides_individual_above_25_images(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                bot = _Bot()
                cog = honeypot.Honeypot(bot)
                await asyncio.to_thread(cog._case_store.initialize)
                now = datetime.now(timezone.utc)
                attachments = tuple(
                    honeypot.NewAttachment(
                        position,
                        f"proof-{position}.png",
                        5,
                        "image/png",
                        10,
                        10,
                        f"https://cdn.test/proof-{position}.png",
                    )
                    for position in range(26)
                )
                appended = await asyncio.to_thread(
                    cog._case_store.append_message,
                    honeypot.NewMessage(
                        10, 20, 30, 40, "evidence", now, None, attachments
                    ),
                    (),
                )
                for position in range(26):
                    evidence = data_path / f"proof-{position}.png"
                    evidence.write_bytes(b"image")
                    capture_attachment(
                        cog._case_store,
                        appended.case.case_id,
                        1,
                        position,
                        evidence,
                    )
                snapshot = await asyncio.to_thread(
                    cog._case_store.get_case, appended.case.case_id
                )
                projection = honeypot.render_case(snapshot)
                visible = "\n".join(field.value for field in projection.fields)

                self.assertIn(
                    "Too many images for one menu\nReview them in the thread", visible
                )

                def add_item(view, item):
                    view.children = getattr(view, "children", []) + [item]

                honeypot.DetectionCaseView.add_item = add_item
                honeypot.discord.ui.Button = lambda **kwargs: SimpleNamespace(**kwargs)
                view = honeypot.DetectionCaseView(
                    cog,
                    appended.case.case_id,
                    has_image_feedback=True,
                    allow_individual=len(projection.feedback_items) <= 25,
                )
                self.assertNotIn("Individual", [item.label for item in view.children])

    def test_timeline_attachment_humanizes_decision_and_escapes_filename(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                attachment = SimpleNamespace(
                    capture_status="captured",
                    match_metadata={},
                    learning_decision="false_positive",
                    publication_error=None,
                    key=SimpleNamespace(position=0),
                    filename="[proof](https://evil.test).png",
                )

                line = honeypot.Honeypot._case_timeline_attachment_line(attachment)

                self.assertEqual(
                    line,
                    "- 1. `[proof](https://evil.test).png`\n  captured; False positive",
                )
                self.assertNotIn("decision:", line)

    def test_automatic_resolution_copy_is_grammatical(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                snapshot = SimpleNamespace(
                    case=SimpleNamespace(
                        resolution="expired",
                        moderator_id=None,
                        resolved_at=datetime(2026, 7, 15, tzinfo=timezone.utc),
                    )
                )

                content = honeypot.Honeypot._case_resolution_timeline_content(snapshot)

                self.assertIn("Resolved automatically", content)
                self.assertNotIn("by automatically", content)

    async def test_individual_image_action_opens_dropdown_and_routes_selected_image(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._case_store.initialize()
                now = datetime.now(timezone.utc)
                appended = cog._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="evidence",
                        created_at=now,
                        jump_url="https://discord.test/messages/40",
                        attachments=tuple(
                            honeypot.NewAttachment(
                                position,
                                filename,
                                5,
                                "image/png",
                                10,
                                10,
                                f"https://cdn.test/{filename}",
                            )
                            for position, filename in enumerate(
                                ("proof-one.png", "proof-two.png")
                            )
                        ),
                    ),
                    (),
                )
                for position, filename in enumerate(("proof-one.png", "proof-two.png")):
                    evidence = data_path / filename
                    evidence.write_bytes(b"image")
                    capture_attachment(
                        cog._case_store,
                        appended.case.case_id,
                        1,
                        position,
                        evidence,
                    )

                def add_item(view, item):
                    view.children = getattr(view, "children", []) + [item]

                honeypot.DetectionIndividualView.add_item = add_item
                honeypot.discord.ui.Select = lambda **kwargs: SimpleNamespace(**kwargs)
                honeypot.discord.ui.Button = lambda **kwargs: SimpleNamespace(**kwargs)
                honeypot.discord.SelectOption = lambda **kwargs: SimpleNamespace(**kwargs)
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(manage_messages=True),
                    ),
                    response=SimpleNamespace(
                        defer=mock.AsyncMock(),
                        send_message=mock.AsyncMock(),
                    ),
                )

                await cog._case_review_individual_prompt(
                    interaction, appended.case.case_id
                )

                interaction.response.defer.assert_not_awaited()
                interaction.response.send_message.assert_awaited_once()
                self.assertTrue(
                    interaction.response.send_message.await_args.kwargs["ephemeral"]
                )
                view = interaction.response.send_message.await_args.kwargs["view"]
                selector, tp, fp, ignore = view.children
                self.assertEqual(
                    [option.label for option in selector.options],
                    ["1.1 proof-one.png", "1.2 proof-two.png"],
                )
                self.assertEqual([tp.label, fp.label, ignore.label], ["TP", "FP", "Ignore"])
                self.assertTrue(all(button.disabled for button in (tp, fp, ignore)))

                selector.values = [selector.options[1].value]
                selection = SimpleNamespace(
                    response=SimpleNamespace(edit_message=mock.AsyncMock())
                )
                await selector.callback(selection)
                self.assertTrue(all(not button.disabled for button in (tp, fp, ignore)))
                self.assertEqual(
                    [getattr(option, "default", False) for option in selector.options],
                    [False, True],
                )

    async def test_case_ban_control_requires_ban_members_permission(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc)
                )
                response = SimpleNamespace(
                    defer=mock.AsyncMock(),
                    send_message=mock.AsyncMock(),
                    is_done=lambda: False,
                )
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        id=99,
                        guild_permissions=SimpleNamespace(
                            manage_messages=True,
                            ban_members=False,
                            kick_members=False,
                        ),
                    ),
                    response=response,
                    followup=SimpleNamespace(send=mock.AsyncMock()),
                )

                await cog._case_review_moderation_interaction(
                    interaction, appended.case.case_id, "ban"
                )

                snapshot = cog._case_store.get_case(appended.case.case_id)
                response.defer.assert_not_awaited()
                response.send_message.assert_awaited_once()
                self.assertEqual(snapshot.case.status.value, "pending")
                self.assertEqual(snapshot.operations, ())

    async def test_moderate_members_can_ignore_and_classify_case_evidence(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                interaction = SimpleNamespace(
                    user=SimpleNamespace(
                        guild_permissions=SimpleNamespace(
                            moderate_members=True,
                            manage_messages=False,
                            ban_members=False,
                            kick_members=False,
                        )
                    )
                )

                self.assertTrue(cog._case_review_has_permission(interaction))
                self.assertTrue(
                    cog._case_review_has_action_permission(interaction, "ignore")
                )

    async def test_startup_expires_overdue_case_before_restoring_views(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                created_at = datetime.now(timezone.utc) - timedelta(hours=25)
                first_cog = honeypot.Honeypot(_Bot())
                first_cog._case_store.initialize()
                appended = first_cog._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="evidence",
                        created_at=created_at,
                        jump_url="https://discord.test/messages/40",
                        attachments=(),
                    ),
                    (),
                )

                restarted = honeypot.Honeypot(_Bot())
                restarted._init_firstpost_seen_store = _async_noop
                restarted._init_imagescan_store = _async_noop
                restarted._restore_pending_reviews = _async_noop
                restored_statuses = []

                async def observe_restore():
                    snapshot = restarted._case_store.get_case(appended.case.case_id)
                    restored_statuses.append(snapshot.case.status.value)

                restarted._restore_detection_case_views = observe_restore
                await restarted.cog_load()
                try:
                    await asyncio.wait_for(restarted._case_restore_task, timeout=2)
                    snapshot = restarted._case_store.get_case(appended.case.case_id)

                    self.assertEqual(restored_statuses, ["expired"])
                    self.assertEqual(snapshot.case.status.value, "expired")
                    self.assertEqual(snapshot.case.resolution, "expired")
                finally:
                    await restarted.cog_unload()

    async def test_scheduler_and_moderator_cannot_resolve_same_case_twice(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc) - timedelta(hours=25)
                )

                outcomes = await asyncio.gather(
                    cog.resolve_detection_case(appended.case.case_id, "expired"),
                    cog.resolve_detection_case(
                        appended.case.case_id, "images:ignore", moderator_id=99
                    ),
                )
                snapshot = cog._case_store.get_case(appended.case.case_id)

                self.assertEqual(sum(outcomes), 1)
                self.assertIn(snapshot.case.status.value, {"expired", "resolved"})

    async def test_stale_resolving_case_is_reclaimed(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                now = datetime.now(timezone.utc)
                appended = self._append_case(honeypot, cog, now - timedelta(hours=25))
                cog._case_store.claim_resolution(
                    appended.case.case_id, now - timedelta(minutes=6)
                )

                resolved = await cog.resolve_detection_case(
                    appended.case.case_id, "expired", now=now
                )
                snapshot = cog._case_store.get_case(appended.case.case_id)

                self.assertTrue(resolved)
                self.assertEqual(snapshot.case.status.value, "expired")

    async def test_reconciliation_reclaims_stale_resolving_but_not_fresh_lease(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                now = datetime.now(timezone.utc)
                stale = self._append_case(
                    honeypot, cog, now - timedelta(hours=25), message_id=41
                )
                fresh = cog._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=21,
                        channel_id=30,
                        message_id=42,
                        content="fresh",
                        created_at=now - timedelta(hours=25),
                        jump_url="https://discord.test/messages/42",
                        attachments=(),
                    ),
                    (),
                )
                cog._case_store.claim_resolution(
                    stale.case.case_id, now - timedelta(minutes=7)
                )
                cog._case_store.claim_resolution(
                    fresh.case.case_id, now - timedelta(minutes=1)
                )

                await cog._run_detection_reconciliation()

                stale_snapshot = cog._case_store.get_case(stale.case.case_id)
                fresh_snapshot = cog._case_store.get_case(fresh.case.case_id)
                self.assertEqual(stale_snapshot.case.status.value, "expired")
                self.assertEqual(fresh_snapshot.case.status.value, "resolving")

    async def test_startup_restores_pending_case_view(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                first = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, first, datetime.now(timezone.utc))
                publish_primary(first._case_store, appended.case.case_id, 30, 77)

                bot = _Bot()
                restarted = honeypot.Honeypot(bot)
                restarted._case_review_rerender = mock.AsyncMock()
                await restarted._restore_detection_case_views()

                self.assertEqual(len(bot.restored_views), 1)
                view, message_id = bot.restored_views[0]
                self.assertEqual(view.case_id, appended.case.case_id)
                self.assertEqual(message_id, 77)
                restarted._case_review_rerender.assert_awaited_once_with(
                    appended.case.case_id
                )

    async def test_missing_discord_review_does_not_block_expiry(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = self._config({"logs_channel": None, "review_channel": None})
                appended = self._append_case(
                    honeypot, cog, datetime.now(timezone.utc) - timedelta(hours=25)
                )
                publish_primary(cog._case_store, appended.case.case_id, 30, 77)

                await cog._run_detection_case_expiry()
                snapshot = cog._case_store.get_case(appended.case.case_id)

                self.assertEqual(snapshot.case.status.value, "expired")
                operation = next(
                    item for item in snapshot.operations if item.operation_type == "review_update"
                )
                self.assertEqual(operation.status.value, "failed")
                self.assertIsNotNone(operation.retry_at)

    async def test_failed_role_release_creates_retry_operation(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                role = SimpleNamespace(id=55)

                async def remove_roles(*args, **kwargs):
                    raise honeypot.discord.HTTPException()

                member = SimpleNamespace(
                    id=20, roles=[role], remove_roles=remove_roles
                )
                guild = SimpleNamespace(
                    id=10,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                member.guild = guild
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                cog.config = self._config({"mute_role": 55})
                cog._is_joinwatch_active_role = mock.AsyncMock(return_value=False)
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                ownership = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:55",
                )
                owned_at = datetime.now(timezone.utc)
                ownership = cog._case_store.claim_operation(ownership.operation_id, owned_at)
                cog._case_store.start_operation_effect(
                    ownership.operation_id, ownership.claim_token, owned_at
                )
                cog._case_store.record_operation_role_ownership(
                    ownership.operation_id, ownership.claim_token,
                    appended.case.case_id, 10, 20, 55, owned_at,
                )
                cog._case_store.complete_operation(
                    ownership.operation_id, ownership.claim_token, owned_at
                )
                await cog.resolve_detection_case(appended.case.case_id, "expired")
                snapshot = cog._case_store.get_case(appended.case.case_id)

                self.assertEqual(snapshot.case.status.value, "expired")
                operation = next(
                    item for item in snapshot.operations if item.operation_type == "role_release"
                )
                self.assertEqual(operation.status.value, "failed")
                self.assertIsNotNone(operation.retry_at)

    async def test_expiry_does_not_remove_preexisting_unowned_role(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                role = SimpleNamespace(id=55)
                member = SimpleNamespace(
                    id=20,
                    roles=[role],
                    remove_roles=mock.AsyncMock(),
                )
                guild = SimpleNamespace(
                    id=10,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                member.guild = guild
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                cog.config = self._config({"mute_role": 55})
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:55",
                )
                claimed = cog._case_store.claim_operation(
                    operation.operation_id, datetime.now(timezone.utc)
                )
                await cog._execute_detection_case_operation(
                    claimed, datetime.now(timezone.utc)
                )
                await cog.resolve_detection_case(appended.case.case_id, "expired")
                snapshot = cog._case_store.get_case(appended.case.case_id)

                member.remove_roles.assert_not_awaited()
                self.assertNotIn(
                    "role_release",
                    {item.operation_type for item in snapshot.operations},
                )

    async def test_role_added_by_case_is_removed_once_on_expiry(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                role = SimpleNamespace(id=55)
                member = SimpleNamespace(id=20, roles=[])

                async def add_roles(added, **kwargs):
                    member.roles.append(added)

                async def remove_roles(removed, **kwargs):
                    member.roles.remove(removed)

                member.add_roles = mock.AsyncMock(side_effect=add_roles)
                member.remove_roles = mock.AsyncMock(side_effect=remove_roles)
                guild = SimpleNamespace(
                    id=10,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                member.guild = guild
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                cog.config = self._config({"mute_role": 55})
                cog._is_joinwatch_active_role = mock.AsyncMock(return_value=False)
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:55",
                )
                claimed = cog._case_store.claim_operation(
                    operation.operation_id, datetime.now(timezone.utc)
                )

                await cog._execute_detection_case_operation(
                    claimed, datetime.now(timezone.utc)
                )
                await cog.resolve_detection_case(appended.case.case_id, "expired")
                await cog.resolve_detection_case(appended.case.case_id, "expired")

                member.add_roles.assert_awaited_once()
                member.remove_roles.assert_awaited_once()
                self.assertNotIn(role, member.roles)

    async def test_live_operation_heartbeat_prevents_stale_reclaim(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._detection_heartbeat_interval_seconds = 0.05
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id, "review_update", "heartbeat-review"
                )
                claimed = cog._case_store.claim_operation(
                    operation.operation_id, datetime.now(timezone.utc)
                )
                started = asyncio.Event()
                release = asyncio.Event()

                async def blocked_review(case_id):
                    started.set()
                    await release.wait()

                cog._case_review_rerender = blocked_review
                worker = asyncio.create_task(
                    cog._execute_detection_case_operation(claimed, datetime.now(timezone.utc))
                )
                await started.wait()
                try:
                    await asyncio.sleep(0.15)
                    contenders = cog._case_store.claim_due_operations(
                        datetime.now(timezone.utc),
                        stale_before=datetime.now(timezone.utc) - timedelta(milliseconds=75),
                    )
                    self.assertEqual(contenders, ())
                finally:
                    release.set()
                    await worker

    async def test_role_apply_retry_observes_external_state_without_repeating_add(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                role = SimpleNamespace(id=55)
                member = SimpleNamespace(id=20, roles=[])

                async def add_roles(added, **kwargs):
                    member.roles.append(added)

                member.add_roles = mock.AsyncMock(side_effect=add_roles)
                guild = SimpleNamespace(
                    id=10,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:55",
                )
                now = datetime.now(timezone.utc)
                first = cog._case_store.claim_operation(operation.operation_id, now)
                real_record = cog._case_store.record_operation_role_ownership
                cog._case_store.record_operation_role_ownership = mock.Mock(
                    side_effect=RuntimeError("crash after Discord")
                )

                await cog._execute_detection_case_operation(first, now)
                cog._case_store.record_operation_role_ownership = real_record
                failed = cog._case_store.get_case(appended.case.case_id)
                retry_at = next(
                    item.retry_at for item in failed.operations
                    if item.operation_id == operation.operation_id
                )
                second = cog._case_store.claim_operation(
                    operation.operation_id, retry_at + timedelta(seconds=1)
                )
                await cog._execute_detection_case_operation(second, retry_at)

                member.add_roles.assert_awaited_once()
                self.assertEqual(
                    cog._case_store.owned_role_ids(appended.case.case_id), ()
                )

    async def test_role_apply_reclaim_does_not_own_ambiguously_present_role(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                role = SimpleNamespace(id=55)
                member = SimpleNamespace(
                    id=20,
                    roles=[],
                    add_roles=mock.AsyncMock(),
                    remove_roles=mock.AsyncMock(),
                )
                guild = SimpleNamespace(
                    id=10,
                    get_member=lambda user_id: member,
                    get_role=lambda role_id: role,
                )
                member.guild = guild
                bot = _Bot()
                bot.get_guild = lambda guild_id: guild
                cog = honeypot.Honeypot(bot)
                cog.config = self._config({"mute_role": 55})
                cog._is_joinwatch_active_role = mock.AsyncMock(return_value=False)
                now = datetime.now(timezone.utc)
                appended = self._append_case(honeypot, cog, now)
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:55",
                )
                first = cog._case_store.claim_operation(operation.operation_id, now)
                self.assertTrue(
                    cog._case_store.start_operation_effect(
                        first.operation_id, first.claim_token, now
                    )
                )
                self.assertTrue(
                    cog._case_store.fail_operation(
                        first.operation_id,
                        first.claim_token,
                        "crash before Discord add",
                        now,
                        now + timedelta(seconds=1),
                    )
                )
                member.roles.append(role)
                second = cog._case_store.claim_operation(
                    operation.operation_id, now + timedelta(seconds=1)
                )

                await cog._execute_detection_case_operation(
                    second, now + timedelta(seconds=1)
                )
                await cog.resolve_detection_case(appended.case.case_id, "expired")

                member.add_roles.assert_not_awaited()
                member.remove_roles.assert_not_awaited()
                snapshot = cog._case_store.get_case(appended.case.case_id)
                role_operation = next(
                    item for item in snapshot.operations
                    if item.operation_id == operation.operation_id
                )
                projection = honeypot.render_case(snapshot)
                self.assertEqual(role_operation.result, "ambiguous_role_ownership")
                self.assertTrue(snapshot.case.needs_attention)
                self.assertTrue(projection.needs_attention)
                self.assertTrue(
                    any(
                        "could not confirm that this case applied the temporary mute role"
                        in field.value.lower()
                        for page in projection.pages
                        for field in page
                    )
                )
                self.assertEqual(cog._case_store.owned_role_ids(appended.case.case_id), ())
                self.assertIn(role, member.roles)

    async def test_stale_operation_token_cannot_start_role_effect(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:55",
                )
                now = datetime.now(timezone.utc)
                old = cog._case_store.claim_operation(operation.operation_id, now)
                new = cog._case_store.claim_due_operations(
                    now + timedelta(minutes=6),
                    stale_before=now + timedelta(minutes=5),
                )[0]

                started = cog._case_store.start_operation_effect(
                    operation.operation_id, old.claim_token, now
                )

                self.assertFalse(started)
                self.assertFalse(
                    cog._case_store.operation_effect_started(operation.operation_id)
                )
                self.assertNotEqual(old.claim_token, new.claim_token)

    async def test_stale_worker_cannot_record_role_ownership_after_reclaim(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:55",
                )
                now = datetime.now(timezone.utc)
                old = cog._case_store.claim_operation(operation.operation_id, now)
                self.assertTrue(
                    cog._case_store.start_operation_effect(
                        operation.operation_id, old.claim_token, now
                    )
                )
                new = cog._case_store.claim_due_operations(
                    now + timedelta(minutes=6),
                    stale_before=now + timedelta(minutes=5),
                )[0]

                recorded = cog._case_store.record_operation_role_ownership(
                    operation.operation_id,
                    old.claim_token,
                    appended.case.case_id,
                    10,
                    20,
                    55,
                    now,
                )

                self.assertFalse(recorded)
                self.assertEqual(
                    cog._case_store.owned_role_ids(appended.case.case_id), ()
                )
                self.assertNotEqual(old.claim_token, new.claim_token)

    async def test_failed_review_edit_does_not_revert_expired_state(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = self._config({})
                cog._case_review_rerender = mock.AsyncMock(
                    side_effect=honeypot.discord.HTTPException()
                )
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                publish_primary(cog._case_store, appended.case.case_id, 30, 77)

                resolved = await cog.resolve_detection_case(
                    appended.case.case_id, "expired"
                )
                snapshot = cog._case_store.get_case(appended.case.case_id)

                self.assertTrue(resolved)
                self.assertEqual(snapshot.case.status.value, "expired")
                operation = next(
                    item for item in snapshot.operations if item.operation_type == "review_update"
                )
                self.assertEqual(operation.status.value, "failed")

    async def test_reconciliation_retries_due_operation(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = self._config({})
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                operation = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "review_update",
                    f"review-update:{appended.case.case_id}",
                )
                cog._case_review_rerender = mock.AsyncMock()

                await cog._run_detection_reconciliation()
                snapshot = cog._case_store.get_case(appended.case.case_id)
                completed = next(
                    item for item in snapshot.operations
                    if item.operation_id == operation.operation_id
                )

                self.assertEqual(completed.status.value, "succeeded")

    async def test_terminal_case_atomically_contains_required_operations(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = self._config({"mute_role": 55})
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                ownership = cog._case_store.ensure_operation(
                    appended.case.case_id,
                    "role_apply",
                    f"role-apply:{appended.case.case_id}:55",
                )
                owned_at = datetime.now(timezone.utc)
                ownership = cog._case_store.claim_operation(ownership.operation_id, owned_at)
                cog._case_store.start_operation_effect(
                    ownership.operation_id, ownership.claim_token, owned_at
                )
                cog._case_store.record_operation_role_ownership(
                    ownership.operation_id, ownership.claim_token,
                    appended.case.case_id, 10, 20, 55, owned_at,
                )
                cog._case_store.complete_operation(
                    ownership.operation_id, ownership.claim_token, owned_at
                )

                await cog.resolve_detection_case(appended.case.case_id, "expired")
                snapshot = cog._case_store.get_case(appended.case.case_id)

                self.assertEqual(snapshot.case.status.value, "expired")
                self.assertEqual(
                    {item.operation_type for item in snapshot.operations},
                    {"role_apply", "review_update", "role_release", "evidence_cleanup"},
                )

    async def test_evidence_cleanup_retries_then_removes_case_files(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = self._config({"mute_role": None})
                cog._case_review_rerender = mock.AsyncMock()
                appended = self._append_case(honeypot, cog, datetime.now(timezone.utc))
                case_directory = (
                    cog._detection_case_files_path
                    / str(appended.case.guild_id)
                    / appended.case.case_id
                )
                case_directory.mkdir(parents=True)
                evidence = case_directory / "proof.png"
                evidence.write_bytes(b"proof")

                real_unlink = Path.unlink
                attempts = 0

                def fail_once(path, *args, **kwargs):
                    nonlocal attempts
                    attempts += 1
                    if attempts == 1:
                        raise OSError("busy")
                    return real_unlink(path, *args, **kwargs)

                with mock.patch.object(Path, "unlink", fail_once):
                    await cog.resolve_detection_case(appended.case.case_id, "expired")
                failed = cog._case_store.get_case(appended.case.case_id)
                cleanup = next(
                    item for item in failed.operations
                    if item.operation_type == "evidence_cleanup"
                )
                self.assertEqual(failed.case.status.value, "expired")
                self.assertEqual(cleanup.status.value, "failed")
                self.assertTrue(evidence.exists())

                cleanup_now = cleanup.retry_at + timedelta(seconds=1)
                claimed = cog._case_store.claim_due_operations(cleanup_now)
                cleanup_claim = next(
                    item for item in claimed if item.operation_id == cleanup.operation_id
                )
                await cog._execute_detection_case_operation(cleanup_claim, cleanup_now)
                completed = cog._case_store.get_case(appended.case.case_id)
                self.assertFalse(evidence.exists())
                self.assertEqual(completed.operations, ())

    async def test_evidence_cleanup_treats_already_missing_sample_as_removed(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = self._config({"mute_role": None})
                cog._case_review_rerender = mock.AsyncMock()
                cog._case_store.initialize()
                now = datetime.now(timezone.utc)
                attachment = honeypot.NewAttachment(
                    0, "proof.png", 4, "image/png", None, None, "https://cdn/proof"
                )
                appended = cog._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=40,
                        content="evidence",
                        created_at=now,
                        jump_url="https://discord.test/messages/40",
                        attachments=(attachment,),
                    ),
                    (),
                )
                missing = (
                    cog._detection_case_files_path
                    / str(appended.case.guild_id)
                    / appended.case.case_id
                    / str(appended.message.sequence)
                    / "proof.png"
                )
                self.assertTrue(
                    capture_attachment(
                        cog._case_store,
                        appended.case.case_id,
                        appended.message.sequence,
                        0,
                        missing,
                    )
                )
                cog._case_review_rerender = mock.AsyncMock()
                cog._imagescan_add_file_sample = mock.AsyncMock(
                    return_value=("error", None)
                )

                await cog.resolve_detection_case(
                    appended.case.case_id, "images:tp", moderator_id=99
                )

                snapshot = cog._case_store.get_case(appended.case.case_id)
                self.assertEqual(snapshot.case.status.value, "resolved")
                self.assertEqual(snapshot.messages, ())
                self.assertEqual(snapshot.attachments, ())
                self.assertEqual(snapshot.operations, ())
                cog._imagescan_add_file_sample.assert_not_awaited()

    async def test_evidence_cleanup_refuses_path_outside_case_root(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = self._config({"mute_role": None})
                cog._case_review_rerender = mock.AsyncMock()
                cog._case_store.initialize()
                outside = Path(directory) / "do-not-delete.png"
                outside.write_bytes(b"safe")
                attachment = honeypot.NewAttachment(
                    0, "proof.png", 4, "image/png", None, None, "https://cdn/proof"
                )
                appended = cog._case_store.append_message(
                    honeypot.NewMessage(
                        guild_id=10,
                        user_id=20,
                        channel_id=30,
                        message_id=44,
                        content="evidence",
                        created_at=datetime.now(timezone.utc),
                        jump_url="https://discord.test/messages/44",
                        attachments=(attachment,),
                    ),
                    (),
                )
                capture_attachment(
                    cog._case_store,
                    appended.case.case_id,
                    appended.message.sequence,
                    0,
                    outside,
                )

                await cog.resolve_detection_case(appended.case.case_id, "expired")
                snapshot = cog._case_store.get_case(appended.case.case_id)
                cleanup = next(
                    item for item in snapshot.operations
                    if item.operation_type == "evidence_cleanup"
                )

                self.assertTrue(outside.exists())
                self.assertEqual(snapshot.case.status.value, "expired")
                self.assertEqual(cleanup.status.value, "failed")
                self.assertIn("escapes case root", cleanup.last_error)


class DetectionDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _append_case(
        honeypot,
        cog,
        *,
        guild_id=10,
        user_id=20,
        message_id=40,
        attachments=(),
        created_at=None,
    ):
        cog._case_store.initialize()
        return cog._case_store.append_message(
            honeypot.NewMessage(
                guild_id=guild_id,
                user_id=user_id,
                channel_id=30,
                message_id=message_id,
                content="evidence",
                created_at=created_at or datetime.now(timezone.utc),
                jump_url=f"https://discord.test/messages/{message_id}",
                attachments=attachments,
            ),
            (),
        )

    @staticmethod
    def _doctor_context():
        permissions = SimpleNamespace(
            kick_members=True,
            ban_members=True,
            manage_roles=True,
        )
        member = SimpleNamespace(guild_permissions=permissions)
        guild = SimpleNamespace(
            id=10,
            me=member,
            channels=[],
            threads=[],
            get_channel=lambda channel_id: None,
            get_thread=lambda channel_id: None,
            get_role=lambda role_id: None,
        )
        return SimpleNamespace(guild=guild, send=mock.AsyncMock())

    async def test_case_database_healthcheck_rejects_read_only_main_database(self):
        with TemporaryDirectory() as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                database_path = data_path / "health.sqlite"
                writable_store = honeypot.DetectionCaseStore(database_path)
                writable_store.initialize()
                writable_store.verify_read_write()

                def read_only_connection(_database_path, **kwargs):
                    return sqlite3.connect(
                        f"file:{database_path.as_posix()}?mode=ro",
                        uri=True,
                        **kwargs,
                    )

                read_only_store = honeypot.DetectionCaseStore(
                    database_path, connection_factory=read_only_connection
                )

                with self.assertRaises(sqlite3.OperationalError):
                    read_only_store.verify_read_write()

                with closing(sqlite3.connect(database_path)) as connection:
                    persistent_probes = connection.execute(
                        """SELECT case_id FROM detection_cases
                           WHERE case_id LIKE 'healthcheck:%'"""
                    ).fetchall()
                self.assertEqual(persistent_probes, [])

    async def test_duplicate_file_sample_keeps_existing_record_and_canonical_file(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._init_imagescan_store_sync()
                source = data_path / "source.png"
                source.write_bytes(
                    base64.b64decode(
                        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
                        "AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
                    )
                )

                first_status, first = await cog._imagescan_add_file_sample(
                    10, source, "true_positive", 99
                )
                canonical = Path(first["file_path"])
                canonical_bytes = canonical.read_bytes()
                second_status, _second = await cog._imagescan_add_file_sample(
                    10, source, "true_positive", 99
                )
                with closing(sqlite3.connect(cog._imagescan_db_path)) as connection:
                    row_count = connection.execute(
                        """SELECT COUNT(*) FROM imagescan_samples
                           WHERE guild_id = '10' AND active = 1"""
                    ).fetchone()[0]

                self.assertEqual((first_status, second_status), ("inserted", "duplicate"))
                self.assertEqual(row_count, 1)
                self.assertTrue(canonical.exists())
                self.assertEqual(canonical.read_bytes(), canonical_bytes)

    async def test_file_sample_commit_failure_removes_new_canonical_file(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._init_imagescan_store_sync()
                source = data_path / "source.png"
                source.write_bytes(
                    base64.b64decode(
                        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
                        "AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
                    )
                )
                real_connect = honeypot.sqlite3.connect
                canonical_was_published = []

                class CommitFailingConnection:
                    def __init__(self, connection):
                        object.__setattr__(self, "_connection", connection)

                    def __getattr__(self, name):
                        return getattr(self._connection, name)

                    def __setattr__(self, name, value):
                        setattr(self._connection, name, value)

                    def __enter__(self):
                        return self

                    def commit(self):
                        imports = cog._imagescan_files_path / "10" / "samples" / "imports"
                        canonical_was_published.append(
                            any(
                                path.is_file() and not path.name.startswith(".sample-")
                                for path in imports.glob("*")
                            )
                        )
                        self._connection.rollback()
                        raise sqlite3.OperationalError("injected commit failure")

                    def __exit__(self, exc_type, exc, traceback):
                        if exc_type is not None:
                            return self._connection.__exit__(exc_type, exc, traceback)
                        self.commit()

                    def close(self):
                        self._connection.close()

                def commit_failing_connect(*args, **kwargs):
                    return CommitFailingConnection(real_connect(*args, **kwargs))

                try:
                    with mock.patch.object(
                        honeypot.sqlite3,
                        "connect",
                        side_effect=commit_failing_connect,
                    ):
                        status, _sample = await cog._imagescan_add_file_sample(
                            10, source, "true_positive", 99
                        )
                except sqlite3.OperationalError:
                    status = "raised"

                with closing(real_connect(cog._imagescan_db_path)) as connection:
                    row_count = connection.execute(
                        "SELECT COUNT(*) FROM imagescan_samples WHERE guild_id = '10'"
                    ).fetchone()[0]
                imports = cog._imagescan_files_path / "10" / "samples" / "imports"
                canonical_files = [path for path in imports.glob("*") if path.is_file()]

                self.assertEqual(canonical_was_published, [True])
                self.assertEqual(row_count, 0)
                self.assertEqual(canonical_files, [])
                self.assertEqual(status, "error")

    async def test_file_sample_does_not_overwrite_untracked_canonical_file(self):
        with TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            data_path = Path(directory)
            with _isolated_honeypot_modules(data_path) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog._init_imagescan_store_sync()
                payload = base64.b64decode(
                    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
                    "AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
                )
                source = data_path / "source.png"
                source.write_bytes(payload)
                imports = cog._imagescan_files_path / "10" / "samples" / "imports"
                imports.mkdir(parents=True)
                canonical = imports / f"{sha256(payload).hexdigest()[:12]}-source.png"
                canonical.write_bytes(b"pre-existing canonical")

                status, _sample = await cog._imagescan_add_file_sample(
                    10, source, "true_positive", 99
                )

                with closing(sqlite3.connect(cog._imagescan_db_path)) as connection:
                    row_count = connection.execute(
                        "SELECT COUNT(*) FROM imagescan_samples WHERE guild_id = '10'"
                    ).fetchone()[0]
                self.assertEqual(status, "conflict")
                self.assertEqual(row_count, 0)
                self.assertEqual(canonical.read_bytes(), b"pre-existing canonical")

    async def test_doctor_reports_case_database_and_evidence_directory(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = SimpleNamespace(
                    guild=lambda guild: SimpleNamespace(
                        all=mock.AsyncMock(
                            return_value={
                                "enabled": False,
                                "action": "none",
                                "fallback_action": "none",
                                "whitelist_mode": "bypass",
                            }
                        )
                    )
                )
                ctx = self._doctor_context()

                await cog.honeypot_doctor(ctx)

                report = ctx.send.await_args.args[0]
                self.assertIn("Detection case database", report)
                self.assertIn("Detection case evidence directory", report)
                self.assertIn("Active detection cases: 0", report)
                self.assertIn("Due detection cases: 0", report)
                self.assertIn("Stale resolving cases: 0", report)
                self.assertIn("Failed containment cases: 0", report)
                self.assertIn("Outstanding durable operations: 0", report)

    async def test_doctor_checks_evidence_directory_off_event_loop_thread(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = SimpleNamespace(
                    guild=lambda guild: SimpleNamespace(
                        all=mock.AsyncMock(
                            return_value={
                                "enabled": False,
                                "action": "none",
                                "fallback_action": "none",
                                "whitelist_mode": "bypass",
                            }
                        )
                    )
                )
                ctx = self._doctor_context()
                event_loop_thread = get_ident()
                probe_threads = []
                named_temporary_file = honeypot.tempfile.NamedTemporaryFile

                def record_probe_thread(*args, **kwargs):
                    probe_threads.append(get_ident())
                    return named_temporary_file(*args, **kwargs)

                with mock.patch.object(
                    honeypot.tempfile,
                    "NamedTemporaryFile",
                    side_effect=record_probe_thread,
                ):
                    await cog.honeypot_doctor(ctx)

                self.assertEqual(len(probe_threads), 1)
                self.assertNotEqual(probe_threads[0], event_loop_thread)

    async def test_doctor_cleans_probe_after_evidence_directory_read_failure(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = SimpleNamespace(
                    guild=lambda guild: SimpleNamespace(
                        all=mock.AsyncMock(
                            return_value={
                                "enabled": False,
                                "action": "none",
                                "fallback_action": "none",
                                "whitelist_mode": "bypass",
                            }
                        )
                    )
                )
                ctx = self._doctor_context()

                with mock.patch.object(
                    honeypot.Path,
                    "read_bytes",
                    side_effect=OSError("injected probe read failure"),
                ):
                    await cog.honeypot_doctor(ctx)

                report = "\n".join(call.args[0] for call in ctx.send.await_args_list)
                self.assertIn("❌ Detection case evidence directory", report)
                self.assertEqual(
                    list(cog._detection_case_files_path.glob(".doctor-*")),
                    [],
                )

    async def test_doctor_paginates_every_visible_channel_permission_failure(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = SimpleNamespace(
                    guild=lambda guild: SimpleNamespace(
                        all=mock.AsyncMock(
                            return_value={
                                "enabled": False,
                                "action": "none",
                                "fallback_action": "none",
                                "whitelist_mode": "bypass",
                            }
                        )
                    )
                )
                ctx = self._doctor_context()
                channels = []
                for index in range(80):
                    permissions = SimpleNamespace(
                        view_channel=True,
                        read_message_history=True,
                        manage_messages=False,
                    )
                    channels.append(
                        SimpleNamespace(
                            mention=f"<#channel-{index:03d}-{'x' * 30}>",
                            purge=lambda: None,
                            permissions_for=lambda member, value=permissions: value,
                        )
                    )
                ctx.guild.channels = channels

                await cog.honeypot_doctor(ctx)

                pages = [call.args[0] for call in ctx.send.await_args_list]
                self.assertGreater(len(pages), 1)
                self.assertTrue(all(len(page) <= 2000 for page in pages))
                report = "\n".join(pages)
                positions = [report.index(channel.mention) for channel in channels]
                self.assertEqual(positions, sorted(positions))

    async def test_status_counts_open_cases_from_sqlite(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                self._append_case(honeypot, cog)
                cog.config = SimpleNamespace(
                    guild=lambda guild: SimpleNamespace(
                        all=mock.AsyncMock(
                            return_value={
                                "stats": {},
                                "joinwatch_pending_role_assignments": {},
                                "joinwatch_pending_roles": {},
                            }
                        )
                    )
                )
                ctx = SimpleNamespace(guild=SimpleNamespace(id=10), send=mock.AsyncMock())

                await cog.config_stats(ctx)

                report = ctx.send.await_args.args[0]
                self.assertIn("Active detection cases: 1", report)

    async def test_review_config_reports_fixed_case_lifetime_not_stale_timeout(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                cog.config = SimpleNamespace(
                    guild=lambda guild: SimpleNamespace(
                        all=mock.AsyncMock(
                            return_value={
                                "review_enabled": True,
                                "review_channel": None,
                                "review_timeout_minutes": 5,
                                "review_kick_fail_warning": "false",
                            }
                        )
                    )
                )
                cog._send_config_dump = mock.AsyncMock()
                ctx = SimpleNamespace(
                    guild=SimpleNamespace(id=10, get_channel=lambda channel_id: None)
                )

                await cog.config_review(ctx)

                settings = cog._send_config_dump.await_args.args[2]
                labels = [label for label, _value in settings]
                values = dict(settings)
                self.assertNotIn("Timeout", labels)
                self.assertEqual(values["Case lifetime"], "24 hours (fixed)")

    async def test_status_reports_due_stale_and_outstanding_durable_work(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                now = datetime.now(timezone.utc)
                due = self._append_case(
                    honeypot,
                    cog,
                    user_id=20,
                    message_id=40,
                    created_at=now - timedelta(hours=25),
                )
                stale = self._append_case(
                    honeypot, cog, user_id=21, message_id=41, created_at=now
                )
                cog._case_store.claim_resolution(
                    stale.case.case_id, now - timedelta(minutes=10)
                )
                cog._case_store.ensure_operation(
                    due.case.case_id,
                    "review_publish",
                    f"review-publish:{due.case.case_id}",
                )
                cog.config = SimpleNamespace(
                    guild=lambda guild: SimpleNamespace(
                        all=mock.AsyncMock(
                            return_value={
                                "stats": {},
                                "joinwatch_pending_role_assignments": {},
                                "joinwatch_pending_roles": {},
                            }
                        )
                    )
                )
                ctx = SimpleNamespace(guild=SimpleNamespace(id=10), send=mock.AsyncMock())

                await cog.config_stats(ctx)

                report = ctx.send.await_args.args[0]
                self.assertIn("Due detection cases: 1", report)
                self.assertIn("Stale resolving cases: 1", report)
                self.assertIn("Outstanding durable operations: 1", report)

    async def test_forbidden_delete_is_visible_in_stats(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, cog)
                cog._case_store.update_message_delete(
                    appended.case.case_id,
                    appended.message.sequence,
                    honeypot.DeleteStatus.FORBIDDEN,
                    "manage messages denied",
                    True,
                )
                guild_config = SimpleNamespace(
                    stats=mock.AsyncMock(return_value={}),
                    joinwatch_pending_role_assignments=mock.AsyncMock(return_value={}),
                    joinwatch_pending_roles=mock.AsyncMock(return_value={}),
                )
                cog.config = SimpleNamespace(guild=lambda guild: guild_config)
                ctx = SimpleNamespace(guild=SimpleNamespace(id=10), send=mock.AsyncMock())

                await cog.honeypot_mod_stats(ctx)

                report = ctx.send.await_args.args[0]
                self.assertIn("Forbidden message deletes: 1", report)

    async def test_terminal_case_is_not_current_failed_containment(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                appended = self._append_case(honeypot, cog)
                cog._case_store.update_message_delete(
                    appended.case.case_id,
                    appended.message.sequence,
                    honeypot.DeleteStatus.FORBIDDEN,
                    "manage messages denied",
                    True,
                )
                cog._case_review_rerender = mock.AsyncMock()
                await cog.resolve_detection_case(
                    appended.case.case_id, "expired"
                )
                guild_config = SimpleNamespace(
                    stats=mock.AsyncMock(return_value={}),
                    joinwatch_pending_role_assignments=mock.AsyncMock(return_value={}),
                    joinwatch_pending_roles=mock.AsyncMock(return_value={}),
                )
                cog.config = SimpleNamespace(guild=lambda guild: guild_config)
                ctx = SimpleNamespace(guild=SimpleNamespace(id=10), send=mock.AsyncMock())

                await cog.honeypot_mod_stats(ctx)

                report = ctx.send.await_args.args[0]
                self.assertIn("Failed containment cases: 0", report)
                self.assertIn("Forbidden message deletes: 0", report)

    async def test_resolved_case_copies_samples_before_evidence_cleanup(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                attachments = tuple(
                    honeypot.NewAttachment(
                        position,
                        filename,
                        5,
                        "image/png",
                        None,
                        None,
                        f"https://cdn.test/{filename}",
                    )
                    for position, filename in enumerate(("tp.png", "fp.png"))
                )
                appended = self._append_case(
                    honeypot, cog, attachments=attachments
                )
                case_directory = (
                    cog._detection_case_files_path
                    / str(appended.case.guild_id)
                    / appended.case.case_id
                    / str(appended.message.sequence)
                )
                case_directory.mkdir(parents=True)
                evidence_paths = []
                for position, filename in enumerate(("tp.png", "fp.png")):
                    evidence = case_directory / filename
                    evidence.write_bytes(filename.encode())
                    evidence_paths.append(evidence)
                    capture_attachment(
                        cog._case_store,
                        appended.case.case_id,
                        appended.message.sequence,
                        position,
                        evidence,
                    )
                snapshot = cog._case_store.get_case(appended.case.case_id)
                tp = next(item for item in snapshot.attachments if item.position == 0)
                fp = next(item for item in snapshot.attachments if item.position == 1)
                cog._case_store.apply_attachment_decisions(
                    appended.case.case_id,
                    {tp.key: "true_positive", fp.key: "false_positive"},
                    99,
                    datetime.now(timezone.utc),
                )
                copied = []

                async def copy_sample(guild_id, source_path, decision, moderator_id):
                    self.assertTrue(source_path.exists())
                    copied.append((source_path.read_bytes(), decision, moderator_id))
                    return "inserted", {}

                cog._imagescan_add_file_sample = copy_sample
                cog._case_review_rerender = mock.AsyncMock()

                await cog.resolve_detection_case(
                    appended.case.case_id, "ban", moderator_id=99
                )

                self.assertCountEqual(
                    copied,
                    [
                        (b"tp.png", "true_positive", 99),
                        (b"fp.png", "false_positive", 99),
                    ],
                )
                self.assertTrue(all(not path.exists() for path in evidence_paths))
                compacted = cog._case_store.get_case(appended.case.case_id)
                self.assertEqual(compacted.messages, ())
                self.assertEqual(compacted.attachments, ())
                self.assertEqual(compacted.operations, ())

    async def test_user_data_deletion_removes_cases_and_case_files(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                target = self._append_case(honeypot, cog, user_id=20, message_id=40)
                retained = self._append_case(honeypot, cog, user_id=21, message_id=41)
                target_directory = (
                    cog._detection_case_files_path
                    / str(target.case.guild_id)
                    / target.case.case_id
                )
                retained_directory = (
                    cog._detection_case_files_path
                    / str(retained.case.guild_id)
                    / retained.case.case_id
                )
                target_directory.mkdir(parents=True)
                retained_directory.mkdir(parents=True)
                (target_directory / "target.png").write_bytes(b"target")
                retained_evidence = retained_directory / "retained.png"
                retained_evidence.write_bytes(b"retained")

                delete_user_data = getattr(cog, "red_delete_data_for_user", None)
                if delete_user_data is None:
                    self.fail("Red user-data deletion hook is missing")
                await delete_user_data(
                    requester="discord_deleted_user", user_id=20
                )

                self.assertIsNone(cog._case_store.get_case(target.case.case_id))
                self.assertIsNotNone(cog._case_store.get_case(retained.case.case_id))
                self.assertFalse(target_directory.exists())
                self.assertTrue(retained_evidence.exists())

    async def test_user_data_deletion_removes_the_remote_case_workspace(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                bot = _Bot()
                cog = honeypot.Honeypot(bot)
                target = self._append_case(honeypot, cog, user_id=20, message_id=40)
                cog._case_store.activate_projection_endpoint(
                    target.case.case_id,
                    parent_channel_id=50,
                    summary_message_id=60,
                    thread_id=60,
                    projected_revision=1,
                    verified_at=datetime.now(timezone.utc),
                )
                thread = SimpleNamespace(delete=mock.AsyncMock())
                summary = SimpleNamespace(
                    fetch_thread=mock.AsyncMock(return_value=thread),
                    delete=mock.AsyncMock(),
                )
                parent = SimpleNamespace(
                    fetch_message=mock.AsyncMock(return_value=summary)
                )
                guild = SimpleNamespace(
                    get_channel=lambda channel_id: parent if channel_id == 50 else None,
                    get_thread=lambda _channel_id: None,
                )
                bot.get_guild = lambda guild_id: guild if guild_id == 10 else None

                await cog.red_delete_data_for_user(
                    requester="discord_deleted_user", user_id=20
                )

                thread.delete.assert_awaited_once()
                summary.delete.assert_awaited_once()
                self.assertIsNone(cog._case_store.get_case(target.case.case_id))

    async def test_remote_deletion_failure_keeps_only_a_minimal_retry_job(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                bot = _Bot()
                cog = honeypot.Honeypot(bot)
                target = self._append_case(honeypot, cog, user_id=20, message_id=40)
                cog._case_store.activate_projection_endpoint(
                    target.case.case_id,
                    parent_channel_id=50,
                    summary_message_id=60,
                    thread_id=60,
                    projected_revision=1,
                    verified_at=datetime.now(timezone.utc),
                )
                thread = SimpleNamespace(
                    delete=mock.AsyncMock(
                        side_effect=[honeypot.discord.Forbidden(), None]
                    )
                )
                summary = SimpleNamespace(
                    fetch_thread=mock.AsyncMock(return_value=thread),
                    delete=mock.AsyncMock(),
                )
                parent = SimpleNamespace(
                    fetch_message=mock.AsyncMock(return_value=summary)
                )
                guild = SimpleNamespace(
                    get_channel=lambda channel_id: parent if channel_id == 50 else None,
                    get_thread=lambda _channel_id: None,
                )
                bot.get_guild = lambda guild_id: guild if guild_id == 10 else None

                with self.assertRaises(honeypot.discord.Forbidden):
                    await cog.red_delete_data_for_user(
                        requester="discord_deleted_user", user_id=20
                    )

                self.assertIsNone(cog._case_store.get_case(target.case.case_id))
                job = cog._case_store.get_case_deletion_job(target.case.case_id)
                self.assertIsNotNone(job)
                self.assertFalse(job.remote_deleted)
                self.assertTrue(job.local_deleted)
                self.assertTrue(job.rows_deleted)
                self.assertFalse(hasattr(job, "user_id"))
                counts = cog._case_store.operational_counts(
                    10,
                    datetime.now(timezone.utc),
                    datetime.now(timezone.utc) - timedelta(minutes=5),
                )
                self.assertEqual(counts["privacy_deletion_jobs"], 1)

                await cog._retry_detection_case_deletions()

                self.assertEqual(thread.delete.await_count, 2)
                summary.delete.assert_awaited_once()
                self.assertIsNone(
                    cog._case_store.get_case_deletion_job(target.case.case_id)
                )
                counts = cog._case_store.operational_counts(
                    10,
                    datetime.now(timezone.utc),
                    datetime.now(timezone.utc) - timedelta(minutes=5),
                )
                self.assertEqual(counts["privacy_deletion_jobs"], 0)

    async def test_user_data_deletion_retries_filesystem_before_removing_personal_rows(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                target = self._append_case(honeypot, cog, user_id=20, message_id=40)
                target_directory = (
                    cog._detection_case_files_path
                    / str(target.case.guild_id)
                    / target.case.case_id
                )
                target_directory.mkdir(parents=True)
                evidence = target_directory / "target.png"
                evidence.write_bytes(b"target")

                with mock.patch.object(
                    honeypot.shutil, "rmtree", side_effect=OSError("busy")
                ):
                    with self.assertRaises(OSError):
                        await cog.red_delete_data_for_user(
                            requester="discord_deleted_user", user_id=20
                        )

                self.assertIsNotNone(cog._case_store.get_case(target.case.case_id))
                job = cog._case_store.get_case_deletion_job(target.case.case_id)
                self.assertIsNotNone(job)
                self.assertFalse(job.local_deleted)
                self.assertFalse(job.rows_deleted)
                self.assertTrue(evidence.exists())

                await cog.red_delete_data_for_user(
                    requester="discord_deleted_user", user_id=20
                )

                self.assertIsNone(cog._case_store.get_case(target.case.case_id))
                self.assertFalse(target_directory.exists())
                self.assertIsNone(
                    cog._case_store.get_case_deletion_job(target.case.case_id)
                )

    async def test_guild_data_deletion_removes_only_that_guilds_cases_and_files(self):
        with TemporaryDirectory() as directory:
            with _isolated_honeypot_modules(Path(directory)) as honeypot:
                cog = honeypot.Honeypot(_Bot())
                target = self._append_case(
                    honeypot, cog, guild_id=10, user_id=20, message_id=40
                )
                retained = self._append_case(
                    honeypot, cog, guild_id=11, user_id=20, message_id=41
                )
                target_directory = (
                    cog._detection_case_files_path
                    / str(target.case.guild_id)
                    / target.case.case_id
                )
                retained_directory = (
                    cog._detection_case_files_path
                    / str(retained.case.guild_id)
                    / retained.case.case_id
                )
                target_directory.mkdir(parents=True)
                retained_directory.mkdir(parents=True)
                (target_directory / "target.png").write_bytes(b"target")
                retained_evidence = retained_directory / "retained.png"
                retained_evidence.write_bytes(b"retained")

                guild_remove_listener = getattr(cog, "on_guild_remove", None)
                if guild_remove_listener is None:
                    self.fail("Guild removal listener is missing")
                self.assertTrue(
                    getattr(type(cog).on_guild_remove, "__cog_listener__", False)
                )
                await guild_remove_listener(SimpleNamespace(id=10))

                self.assertIsNone(cog._case_store.get_case(target.case.case_id))
                self.assertIsNotNone(cog._case_store.get_case(retained.case.case_id))
                self.assertFalse(target_directory.exists())
                self.assertTrue(retained_evidence.exists())


async def _async_noop(*args, **kwargs):
    return None


if __name__ == "__main__":
    unittest.main()
