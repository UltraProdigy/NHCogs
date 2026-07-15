import asyncio
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
import errno
from importlib import util
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import ModuleType, SimpleNamespace
from unittest import mock
import sys
import unittest


class HTTPException(Exception):
    pass


class NotFound(HTTPException):
    pass


class Forbidden(HTTPException):
    pass


PACKAGE_DIR = Path(__file__).resolve().parents[1] / "Honeypot"
_MISSING = object()


def load_module(name: str, path: Path):
    spec = util.spec_from_file_location(name, path)
    module = util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@contextmanager
def isolated_runtime_modules():
    names = ("discord", "Honeypot", "Honeypot.detection_cases", "Honeypot.detection_runtime")
    previous = {name: sys.modules.get(name, _MISSING) for name in names}
    discord_stub = ModuleType("discord")
    discord_stub.HTTPException = HTTPException
    discord_stub.NotFound = NotFound
    discord_stub.Forbidden = Forbidden
    package = ModuleType("Honeypot")
    package.__path__ = [str(PACKAGE_DIR)]
    try:
        sys.modules["discord"] = discord_stub
        sys.modules["Honeypot"] = package
        detection_cases = load_module("Honeypot.detection_cases", PACKAGE_DIR / "detection_cases.py")
        detection_runtime = load_module("Honeypot.detection_runtime", PACKAGE_DIR / "detection_runtime.py")
        yield detection_cases, detection_runtime
    finally:
        for name, module in previous.items():
            if module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


with isolated_runtime_modules() as loaded_modules:
    detection_cases, detection_runtime = loaded_modules

CaptureStatus = detection_runtime.CaptureStatus
DeleteStatus = detection_cases.DeleteStatus
read_attachment_bounded = detection_runtime.read_attachment_bounded
cleanup_case_directory = detection_runtime.cleanup_case_directory
delete_message = detection_runtime.delete_message


async def _test_bounded_reader(attachment, max_bytes):
    return await attachment.read_bounded(max_bytes)


async def capture_attachments(*args, **kwargs):
    kwargs["reader"] = _test_bounded_reader
    return await detection_runtime.capture_attachments(*args, **kwargs)


class Attachment:
    def __init__(self, filename: str, data: bytes = b"data", delay: float = 0):
        self.filename = filename
        self.data = data
        self.delay = delay
        self.calls = []

    async def read(self, *, use_cached: bool = False):
        self.calls.append(use_cached)
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.data

    async def read_bounded(self, max_bytes: int):
        data = await self.read(use_cached=True)
        return data[: max_bytes + 1]


class FailingAttachment(Attachment):
    async def read(self, *, use_cached: bool = False):
        self.calls.append(use_cached)
        raise OSError("download failed " + "x" * 1_000)


class CachedFallbackAttachment(Attachment):
    async def read(self, *, use_cached: bool = False):
        self.calls.append(use_cached)
        if not use_cached:
            raise HTTPException("original CDN object unavailable")
        return self.data


class HostileFilenameAttachment(Attachment):
    @property
    def filename(self):
        raise RuntimeError("hostile filename")

    @filename.setter
    def filename(self, value):
        pass


class GatedReadAttachment(Attachment):
    def __init__(self, filename: str):
        super().__init__(filename)
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def read(self, *, use_cached: bool):
        self.calls.append(use_cached)
        self.started.set()
        await self.release.wait()
        return self.data


class CaptureAttachmentTests(unittest.IsolatedAsyncioTestCase):
    async def test_loading_runtime_restores_existing_module_entries(self):
        sentinel = ModuleType("sentinel_discord")
        previous = sys.modules.get("discord", _MISSING)
        sys.modules["discord"] = sentinel
        try:
            with isolated_runtime_modules() as (_, fresh_runtime):
                self.assertIsNot(fresh_runtime, detection_runtime)
                self.assertIsNot(sys.modules["discord"], sentinel)
            self.assertIs(sys.modules["discord"], sentinel)
        finally:
            if previous is _MISSING:
                sys.modules.pop("discord", None)
            else:
                sys.modules["discord"] = previous

    async def test_capture_statuses_are_stable_strings(self):
        self.assertEqual(
            tuple(status.value for status in CaptureStatus),
            ("captured", "capture_timeout", "capture_failed", "too_large"),
        )

    async def test_production_reader_uses_native_discord_attachment_read(self):
        attachment = Attachment("proof.png", b"native")

        data = await read_attachment_bounded(attachment, 10)

        self.assertEqual(data, b"native")
        self.assertEqual(attachment.calls, [False])

    async def test_production_reader_retries_with_cached_discord_proxy(self):
        attachment = CachedFallbackAttachment("proof.png", b"cached")

        data = await read_attachment_bounded(attachment, 10)

        self.assertEqual(data, b"cached")
        self.assertEqual(attachment.calls, [False, True])

    async def test_production_reader_rejects_actual_bytes_above_limit(self):
        attachment = Attachment("proof.png", b"12345")

        with self.assertRaises(detection_runtime.AttachmentTooLargeError):
            await read_attachment_bounded(attachment, 4)

    async def test_captures_duplicate_names_in_input_order_to_distinct_safe_paths(self):
        attachments = [
            Attachment("../../same.jpg", b"first", delay=0.02),
            Attachment("same.jpg", b"second"),
            Attachment("bad\x00/name\n.png", b"third"),
        ]
        with TemporaryDirectory() as directory:
            target = Path(directory) / "case"
            results = await capture_attachments(attachments, target, 1)

            self.assertEqual([result.position for result in results], [0, 1, 2])
            self.assertEqual([result.status for result in results], [CaptureStatus.CAPTURED] * 3)
            self.assertEqual([result.path.name for result in results], [
                "0000-same.jpg",
                "0001-same.jpg",
                "0002-name_.png",
            ])
            self.assertEqual([result.path.read_bytes() for result in results], [b"first", b"second", b"third"])
            self.assertTrue(all(result.path.resolve().is_relative_to(target.resolve()) for result in results))
            self.assertEqual([attachment.calls for attachment in attachments], [[True], [True], [True]])
            self.assertTrue(all(result.error is None for result in results))

            with self.assertRaises(FrozenInstanceError):
                results[0].status = CaptureStatus.FAILED

    async def test_slow_attachment_times_out_without_delaying_or_blocking_other_capture(self):
        slow = GatedReadAttachment("slow.jpg")
        with TemporaryDirectory() as directory:
            target = Path(directory)
            task = asyncio.create_task(
                capture_attachments([slow, Attachment("fast.jpg", b"fast")], target, 0.02)
            )
            await slow.started.wait()
            results = await task

            self.assertEqual(results[0].status, CaptureStatus.TIMEOUT)
            self.assertIsNone(results[0].path)
            self.assertEqual(results[1].status, CaptureStatus.CAPTURED)
            self.assertEqual(results[1].path.read_bytes(), b"fast")
            self.assertFalse((target / "0000-slow.jpg").exists())

    async def test_actual_bytes_above_bound_stop_without_publishing_file(self):
        with TemporaryDirectory() as directory:
            target = Path(directory)

            result, = await capture_attachments(
                [Attachment("lying.jpg", b"12345")],
                target,
                1,
                max_bytes=4,
            )

            self.assertEqual(result.status, CaptureStatus.TOO_LARGE)
            self.assertIsNone(result.path)
            self.assertFalse((target / "0000-lying.jpg").exists())

    async def test_timeout_during_thread_write_never_publishes_final_or_leaves_temp(self):
        real_write_bytes = Path.write_bytes
        write_started = Event()
        write_release = Event()
        write_finished = Event()

        def slow_write(path, data):
            if ".capture-" in path.name:
                write_started.set()
                write_release.wait(timeout=2)
            try:
                return real_write_bytes(path, data)
            finally:
                write_finished.set()

        with TemporaryDirectory() as directory, mock.patch.object(Path, "write_bytes", slow_write):
            target = Path(directory)
            task = asyncio.create_task(capture_attachments([Attachment("late.jpg", b"late")], target, 0.02))
            await asyncio.to_thread(write_started.wait, 1)
            results = await task
            self.assertEqual(results[0].status, CaptureStatus.TIMEOUT)
            write_release.set()
            self.assertTrue(await asyncio.to_thread(write_finished.wait, 1))
            for _ in range(20):
                if not list(target.iterdir()):
                    break
                await asyncio.sleep(0)
            self.assertEqual(list(target.iterdir()), [])

    async def test_external_cancellation_propagates_and_late_write_never_publishes(self):
        real_write_bytes = Path.write_bytes
        write_started = Event()
        write_release = Event()
        write_finished = Event()

        def gated_write(path, data):
            write_started.set()
            write_release.wait(timeout=2)
            try:
                return real_write_bytes(path, data)
            finally:
                write_finished.set()

        with TemporaryDirectory() as directory, mock.patch.object(Path, "write_bytes", gated_write):
            target = Path(directory)
            task = asyncio.create_task(capture_attachments([Attachment("cancel.jpg", b"late")], target, 5))
            await asyncio.to_thread(write_started.wait, 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            write_release.set()
            self.assertTrue(await asyncio.to_thread(write_finished.wait, 1))
            for _ in range(20):
                if not list(target.iterdir()):
                    break
                await asyncio.sleep(0)
            self.assertEqual(list(target.iterdir()), [])

    async def test_hostile_filename_failure_is_contained_to_that_attachment(self):
        with TemporaryDirectory() as directory:
            target = Path(directory)
            results = await capture_attachments(
                [HostileFilenameAttachment("ignored"), Attachment("good.jpg", b"good")], target, 1
            )
            self.assertEqual(results[0].status, CaptureStatus.FAILED)
            self.assertIn("hostile filename", results[0].error)
            self.assertEqual(results[1].status, CaptureStatus.CAPTURED)
            self.assertEqual(results[1].path.read_bytes(), b"good")

    async def test_escaping_final_symlink_failure_is_contained(self):
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside_directory:
            target = Path(directory)
            outside = Path(outside_directory) / "outside.jpg"
            outside.write_bytes(b"original")
            link = target / "0000-linked.jpg"
            try:
                link.symlink_to(outside)
            except OSError as error:
                if error.errno in {errno.EPERM, errno.EACCES, errno.ENOTSUP} or getattr(error, "winerror", None) == 1314:
                    self.skipTest(f"symlinks unavailable: {error}")
                raise

            results = await capture_attachments(
                [Attachment("linked.jpg", b"hostile"), Attachment("good.jpg", b"good")], target, 1
            )
            self.assertEqual(results[0].status, CaptureStatus.FAILED)
            self.assertEqual(outside.read_bytes(), b"original")
            self.assertEqual(results[1].status, CaptureStatus.CAPTURED)
            self.assertEqual(results[1].path.read_bytes(), b"good")

    async def test_read_failure_is_structured_and_error_is_bounded(self):
        with TemporaryDirectory() as directory:
            target = Path(directory)
            result, = await capture_attachments([FailingAttachment("bad.jpg")], target, 1)

            self.assertEqual(result.status, CaptureStatus.FAILED)
            self.assertIsNone(result.path)
            self.assertIn("OSError", result.error)
            self.assertLessEqual(len(result.error), 512)
            self.assertEqual(list(target.iterdir()), [])

    async def test_write_failure_is_structured_and_leaves_no_artifact(self):
        with TemporaryDirectory() as directory, mock.patch.object(
            Path, "write_bytes", side_effect=OSError("disk full")
        ):
            target = Path(directory)
            result, = await capture_attachments([Attachment("bad.jpg")], target, 1)

            self.assertEqual(result.status, CaptureStatus.FAILED)
            self.assertIsNone(result.path)
            self.assertIn("disk full", result.error)
            self.assertEqual(list(target.iterdir()), [])

    async def test_empty_input_returns_empty_tuple_and_creates_target(self):
        with TemporaryDirectory() as directory:
            target = Path(directory) / "new"
            self.assertEqual(await capture_attachments([], target, 1), ())
            self.assertTrue(target.is_dir())


class DeleteMessageTests(unittest.IsolatedAsyncioTestCase):
    async def test_success_reports_attempt_used(self):
        message = SimpleNamespace(delete=mock.AsyncMock(return_value=None))
        result = await delete_message(message)
        self.assertEqual(result.status, DeleteStatus.DELETED)
        self.assertEqual(result.attempts, 1)
        self.assertIsNone(result.error)
        with self.assertRaises(FrozenInstanceError):
            result.attempts = 2

    async def test_not_found_and_forbidden_are_terminal(self):
        for error, status in ((NotFound("gone"), DeleteStatus.ALREADY_GONE), (Forbidden("no"), DeleteStatus.FORBIDDEN)):
            with self.subTest(status=status):
                message = SimpleNamespace(delete=mock.AsyncMock(side_effect=error))
                sleep = mock.AsyncMock()
                result = await delete_message(message, attempts=3, sleep=sleep)
                self.assertEqual(result.status, status)
                self.assertEqual(result.attempts, 1)
                self.assertIn(type(error).__name__, result.error)
                sleep.assert_not_awaited()

    async def test_transient_http_errors_retry_and_sleep_only_between_attempts(self):
        message = SimpleNamespace(delete=mock.AsyncMock(side_effect=[HTTPException("one"), HTTPException("two"), None]))
        sleep = mock.AsyncMock()
        result = await delete_message(message, attempts=3, retry_delay=0.125, sleep=sleep)
        self.assertEqual(result.status, DeleteStatus.DELETED)
        self.assertEqual(result.attempts, 3)
        self.assertEqual(sleep.await_args_list, [mock.call(0.125), mock.call(0.125)])

    async def test_exhausted_transient_failure_is_structured_and_bounded(self):
        message = SimpleNamespace(delete=mock.AsyncMock(side_effect=HTTPException("x" * 1_000)))
        sleep = mock.AsyncMock()
        result = await delete_message(message, attempts=2, retry_delay=0, sleep=sleep)
        self.assertEqual(result.status, DeleteStatus.TRANSIENT_FAILURE)
        self.assertEqual(result.attempts, 2)
        self.assertLessEqual(len(result.error), 512)
        sleep.assert_awaited_once_with(0)

    async def test_rejects_invalid_retry_configuration_before_deleting(self):
        for attempts, delay in ((0, 0), (-1, 0), (1, -0.1)):
            with self.subTest(attempts=attempts, delay=delay):
                message = SimpleNamespace(delete=mock.AsyncMock())
                with self.assertRaises(ValueError):
                    await delete_message(message, attempts=attempts, retry_delay=delay)
                message.delete.assert_not_awaited()

    async def test_unexpected_exception_propagates(self):
        message = SimpleNamespace(delete=mock.AsyncMock(side_effect=RuntimeError("bug")))
        with self.assertRaisesRegex(RuntimeError, "bug"):
            await delete_message(message)

    async def test_cancellation_propagates(self):
        message = SimpleNamespace(delete=mock.AsyncMock(side_effect=asyncio.CancelledError()))
        with self.assertRaises(asyncio.CancelledError):
            await delete_message(message)


class CleanupCaseDirectoryTests(unittest.TestCase):
    def test_removes_exact_directory_tree_and_is_idempotent(self):
        with TemporaryDirectory() as directory:
            case_dir = Path(directory) / "case"
            sibling = Path(directory) / "keep"
            (case_dir / "nested").mkdir(parents=True)
            (case_dir / "nested" / "evidence.bin").write_bytes(b"evidence")
            sibling.mkdir()

            cleanup_case_directory(case_dir)
            cleanup_case_directory(case_dir)

            self.assertFalse(case_dir.exists())
            self.assertTrue(sibling.is_dir())
