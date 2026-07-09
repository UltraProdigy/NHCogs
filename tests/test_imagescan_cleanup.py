import shutil
import tempfile
import unittest
from importlib import util
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "Honeypot" / "honeypot.py"
spec = util.spec_from_file_location("Honeypot.honeypot", MODULE_PATH)
honeypot = util.module_from_spec(spec)


def _install_redbot_stubs() -> None:
    import sys
    import types

    discord = types.ModuleType("discord")
    discord.Attachment = object
    discord.Forbidden = Exception
    discord.HTTPException = Exception
    discord.Message = object
    discord.NotFound = Exception
    discord.TextChannel = object
    discord.Thread = object
    discord.File = object
    discord.Embed = object
    discord.Member = object
    discord.User = object
    discord.Role = object
    discord.Object = object
    discord.Interaction = object
    discord.ButtonStyle = types.SimpleNamespace(danger=1, secondary=2, success=3)
    discord.ui = types.SimpleNamespace(
        View=object,
        button=lambda *args, **kwargs: (lambda fn: fn),
    )
    discord.ext = types.ModuleType("discord.ext")
    class _LoopStub:
        def __init__(self, fn):
            self.fn = fn

        def __get__(self, instance, owner):
            return self

        def before_loop(self, fn):
            return fn

        def start(self):
            pass

        def cancel(self):
            pass

    discord.ext.tasks = types.SimpleNamespace(
        loop=lambda *args, **kwargs: (lambda fn: _LoopStub(fn))
    )
    sys.modules["discord"] = discord
    sys.modules["discord.ext"] = discord.ext
    sys.modules["discord.ext.tasks"] = discord.ext.tasks

    redbot = types.ModuleType("redbot")
    redbot.core = types.ModuleType("redbot.core")

    class _DummyCog:
        @classmethod
        def listener(cls, *args, **kwargs):
            def wrapper(fn):
                return fn

            return wrapper

    def _decorator(*args, **kwargs):
        def wrapper(fn):
            fn.command = _decorator
            fn.group = _decorator
            return fn

        return wrapper

    commands = types.SimpleNamespace(
        Cog=_DummyCog,
        Context=object,
        UserFeedbackCheckFailure=Exception,
        group=_decorator,
        command=_decorator,
        guild_only=lambda: (lambda fn: fn),
        admin_or_permissions=lambda **kwargs: (lambda fn: fn),
        bot_has_guild_permissions=lambda **kwargs: (lambda fn: fn),
        permissions_check=lambda predicate: (lambda fn: fn),
    )
    redbot.core.Config = types.SimpleNamespace(get_conf=lambda *args, **kwargs: None)
    redbot.core.commands = commands
    redbot.core.modlog = types.SimpleNamespace()
    redbot.core.bot = types.ModuleType("redbot.core.bot")
    redbot.core.bot.Red = object
    redbot.core.data_manager = types.ModuleType("redbot.core.data_manager")
    redbot.core.data_manager.cog_data_path = lambda cog: Path(tempfile.gettempdir())
    redbot.core.i18n = types.ModuleType("redbot.core.i18n")
    redbot.core.i18n.Translator = lambda *args, **kwargs: (lambda text: text)
    redbot.core.i18n.cog_i18n = lambda translator: (lambda cls: cls)
    redbot.core.utils = types.ModuleType("redbot.core.utils")
    redbot.core.utils.chat_formatting = types.ModuleType("redbot.core.utils.chat_formatting")
    redbot.core.utils.chat_formatting.box = lambda text, *args, **kwargs: text
    redbot.core.utils.chat_formatting.pagify = lambda text, *args, **kwargs: [text]
    sys.modules["redbot"] = redbot
    sys.modules["redbot.core"] = redbot.core
    sys.modules["redbot.core.commands"] = commands
    sys.modules["redbot.core.bot"] = redbot.core.bot
    sys.modules["redbot.core.data_manager"] = redbot.core.data_manager
    sys.modules["redbot.core.i18n"] = redbot.core.i18n
    sys.modules["redbot.core.utils"] = redbot.core.utils
    sys.modules["redbot.core.utils.chat_formatting"] = redbot.core.utils.chat_formatting

    aaa3a_utils = types.ModuleType("AAA3A_utils")
    aaa3a_utils.Cog = object
    sys.modules["AAA3A_utils"] = aaa3a_utils


_install_redbot_stubs()
import sys
import types

package = types.ModuleType("Honeypot")
package.__path__ = [str(MODULE_PATH.parent)]
sys.modules["Honeypot"] = package
sys.modules[spec.name] = honeypot
assert spec.loader is not None
spec.loader.exec_module(honeypot)


class ImageScanCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = (
            Path(__file__).resolve().parents[1]
            / ".test-tmp"
            / f"honeypot-cleanup-test-{self._testMethodName}"
        )
        shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _write_file(self, path: Path, size: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)

    def test_cleanup_plan_counts_event_directories_without_samples(self) -> None:
        guild_root = self.root / "123"
        self._write_file(guild_root / "samples" / "uploads" / "tp.png", 100)
        self._write_file(guild_root / "111" / "001.png", 10)
        self._write_file(guild_root / "222" / "001.png", 20)

        plan = honeypot.plan_imagescan_event_cache_cleanup(self.root, 123)

        self.assertEqual(plan["event_dirs"], 2)
        self.assertEqual(plan["files"], 2)
        self.assertEqual(plan["bytes"], 30)
        self.assertTrue((guild_root / "samples" / "uploads" / "tp.png").exists())

    def test_delete_removes_only_event_directories(self) -> None:
        guild_root = self.root / "123"
        self._write_file(guild_root / "samples" / "uploads" / "tp.png", 100)
        self._write_file(guild_root / "111" / "001.png", 10)

        plan = honeypot.plan_imagescan_event_cache_cleanup(self.root, 123, delete=True)

        self.assertEqual(plan["deleted_event_dirs"], 1)
        self.assertFalse((guild_root / "111").exists())
        self.assertTrue((guild_root / "samples" / "uploads" / "tp.png").exists())


if __name__ == "__main__":
    unittest.main()
