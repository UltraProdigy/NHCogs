"""Runtime containment operations for detection cases."""

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import shutil
import unicodedata
from uuid import uuid4

import discord

from .detection_cases import DeleteStatus


_MAX_ERROR_LENGTH = 512
_INVALID_FILENAME_CHARACTERS = frozenset('<>:"/\\|?*')
BoundedReader = Callable[[object, int], Awaitable[bytes]]


class AttachmentTooLargeError(ValueError):
    pass


class CaptureStatus(str, Enum):
    CAPTURED = "captured"
    TIMEOUT = "capture_timeout"
    FAILED = "capture_failed"
    TOO_LARGE = "too_large"


@dataclass(frozen=True)
class CaptureResult:
    position: int
    status: CaptureStatus
    path: Path | None
    error: str | None


@dataclass(frozen=True)
class DeleteResult:
    status: DeleteStatus
    attempts: int
    error: str | None


def _bounded_error(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"[:_MAX_ERROR_LENGTH]


def _safe_filename(filename: object) -> str:
    leaf = str(filename or "attachment").replace("\\", "/").rsplit("/", 1)[-1]
    sanitized = "".join(
        "_" if character in _INVALID_FILENAME_CHARACTERS or unicodedata.category(character).startswith("C") else character
        for character in leaf
    ).rstrip(" .")
    return sanitized or "attachment"


def _capture_path(target_dir: Path, position: int, filename: object) -> Path:
    target = target_dir.resolve()
    path = target_dir / f"{position:04d}-{_safe_filename(filename)}"
    path.resolve().relative_to(target)
    return path


def _unlink(path: Path) -> None:
    # Best effort is sufficient: case-directory reconciliation removes any
    # orphaned temporary evidence that the OS still has locked here.
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def read_file_bounded(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as source:
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise AttachmentTooLargeError(
            f"attachment exceeds the {max_bytes} byte evidence limit"
        )
    return data


async def read_attachment_bounded(attachment: object, max_bytes: int) -> bytes:
    if max_bytes < 0:
        raise ValueError("attachment byte limit must be non-negative")
    read = getattr(attachment, "read", None)
    if not callable(read):
        raise RuntimeError("attachment has no Discord download interface")
    try:
        data = await read()
    except (discord.HTTPException, OSError):
        data = await read(use_cached=True)
    if not isinstance(data, bytes):
        data = bytes(data)
    if len(data) > max_bytes:
        raise AttachmentTooLargeError(
            f"attachment exceeds the {max_bytes} byte evidence limit"
        )
    return data


def _finish_cancelled_write(task: asyncio.Task[object], temp_path: Path) -> None:
    try:
        task.exception()
    except asyncio.CancelledError:
        pass
    _unlink(temp_path)


async def _capture_one(
    attachment: object,
    target_dir: Path,
    position: int,
    max_bytes: int,
    reader: BoundedReader,
) -> CaptureResult:
    temp_path: Path | None = None
    write_task: asyncio.Task[object] | None = None
    try:
        final_path = _capture_path(target_dir, position, getattr(attachment, "filename", "attachment"))
        temp_path = target_dir / f".capture-{position:04d}-{uuid4().hex}.tmp"
        data = await reader(attachment, max_bytes)
        if len(data) > max_bytes:
            raise AttachmentTooLargeError(
                f"attachment exceeds the {max_bytes} byte evidence limit"
            )
        write_task = asyncio.create_task(asyncio.to_thread(temp_path.write_bytes, data))
        try:
            await asyncio.shield(write_task)
        except asyncio.CancelledError:
            write_task.add_done_callback(lambda task: _finish_cancelled_write(task, temp_path))
            raise
        temp_path.replace(final_path)
        return CaptureResult(position, CaptureStatus.CAPTURED, final_path, None)
    except asyncio.CancelledError:
        raise
    except AttachmentTooLargeError as error:
        return CaptureResult(position, CaptureStatus.TOO_LARGE, None, _bounded_error(error))
    except Exception as error:
        return CaptureResult(position, CaptureStatus.FAILED, None, _bounded_error(error))
    finally:
        if temp_path is not None:
            _unlink(temp_path)


async def _capture_with_timeout(
    attachment: object,
    target_dir: Path,
    position: int,
    timeout_seconds: float,
    max_bytes: int = 25 * 1024 * 1024,
    reader: BoundedReader = read_attachment_bounded,
) -> CaptureResult:
    try:
        return await asyncio.wait_for(
            _capture_one(attachment, target_dir, position, max_bytes, reader),
            timeout=timeout_seconds,
        )
    except TimeoutError as error:
        return CaptureResult(position, CaptureStatus.TIMEOUT, None, _bounded_error(error))


async def capture_attachment(
    attachment: object,
    target_dir: Path,
    position: int,
    timeout_seconds: float,
    *,
    max_bytes: int = 25 * 1024 * 1024,
    reader: BoundedReader = read_attachment_bounded,
) -> CaptureResult:
    target_dir.mkdir(parents=True, exist_ok=True)
    return await _capture_with_timeout(
        attachment, target_dir, position, timeout_seconds, max_bytes, reader
    )




async def delete_message(
    message: object,
    attempts: int = 3,
    retry_delay: float = 0.25,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
) -> DeleteResult:
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    if retry_delay < 0:
        raise ValueError("retry_delay must be non-negative")

    for attempt in range(1, attempts + 1):
        try:
            await message.delete()
            return DeleteResult(DeleteStatus.DELETED, attempt, None)
        except discord.NotFound as error:
            return DeleteResult(DeleteStatus.ALREADY_GONE, attempt, _bounded_error(error))
        except discord.Forbidden as error:
            return DeleteResult(DeleteStatus.FORBIDDEN, attempt, _bounded_error(error))
        except discord.HTTPException as error:
            if attempt == attempts:
                return DeleteResult(DeleteStatus.TRANSIENT_FAILURE, attempt, _bounded_error(error))
            await sleep(retry_delay)

    raise AssertionError("unreachable")
