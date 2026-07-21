from __future__ import annotations

import logging
import re
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable


MAX_RECORDS = 20_000
MAX_BUFFER_BYTES = 32 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_RETENTION = timedelta(hours=24)

_REDACTED = "[REDACTED]"
_AUTHORIZATION_PATTERN = re.compile(
    r"(?i)([\"']?\bauthorization\b[\"']?\s*[:=]\s*)([\"']?)"
    r"(?:(?:bearer|basic)\s+)?[^\"'\r\n,;}]+"
)
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_WEBHOOK_PATTERN = re.compile(
    r"(?i)(https?://(?:canary\.|ptb\.)?(?:discord(?:app)?\.com)"
    r"/api(?:/v\d+)?/webhooks/\d+/)[^/?#\s]+"
)
_QUERY_SECRET_PATTERN = re.compile(
    r"(?i)([?&](?:access[_-]?token|api[_-]?key|auth|key|password|secret|token)=)"
    r"[^&#\s]+"
)
_NAMED_SECRET_PATTERN = re.compile(
    r"(?i)\b((?:access[_-]?token|api[_-]?key|password|secret|token)\s*[:=]\s*)"
    r"(?:['\"])?[^\s,'\";]+(?:['\"])?"
)
_DISCORD_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:mfa\.[A-Za-z0-9_-]{20,}|"
    r"[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})"
    r"(?![A-Za-z0-9_-])"
)


@dataclass(frozen=True)
class CapturedLogEntry:
    created_at: datetime
    level: int
    logger_name: str
    pathname: str
    text: str
    byte_size: int


@dataclass(frozen=True)
class LogSnapshot:
    started_at: datetime
    entries: tuple[CapturedLogEntry, ...]
    evicted_count: int


@dataclass(frozen=True)
class LogDump:
    content: bytes
    filename: str
    matching_count: int
    included_count: int
    omitted_count: int


def redact_log_text(text: str) -> str:
    redacted = _AUTHORIZATION_PATTERN.sub(
        lambda match: match.group(1) + match.group(2) + _REDACTED,
        text,
    )
    redacted = _BEARER_PATTERN.sub("Bearer " + _REDACTED, redacted)
    redacted = _WEBHOOK_PATTERN.sub(lambda match: match.group(1) + _REDACTED, redacted)
    redacted = _QUERY_SECRET_PATTERN.sub(
        lambda match: match.group(1) + _REDACTED,
        redacted,
    )
    redacted = _NAMED_SECRET_PATTERN.sub(
        lambda match: match.group(1) + _REDACTED,
        redacted,
    )
    return _DISCORD_TOKEN_PATTERN.sub(_REDACTED, redacted)


def _limit_utf8_head(text: str, maximum_bytes: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return text
    if maximum_bytes <= 0:
        return ""
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore")


class ReadOnlyLogBuffer(logging.Handler):
    def __init__(
        self,
        max_records: int = MAX_RECORDS,
        max_bytes: int = MAX_BUFFER_BYTES,
        retention: timedelta = MAX_RETENTION,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(logging.NOTSET)
        self._entries: deque[CapturedLogEntry] = deque()
        self._max_records = max_records
        self._max_bytes = max_bytes
        self._retention = retention
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._total_bytes = 0
        self._evicted_count = 0
        self._started_at = self._clock()
        self._buffer_lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            created_at = datetime.fromtimestamp(record.created, timezone.utc)
            message = self.format(record)
            pathname = redact_log_text(str(getattr(record, "pathname", "")))
            logger_name = redact_log_text(record.name)
            prefix = (
                f"[{created_at.isoformat()}] {record.levelname:<8} "
                f"[{logger_name}] {pathname}:{record.lineno}\n"
            )
            text = _limit_utf8_head(
                redact_log_text(prefix + message),
                MAX_RECORD_BYTES,
            )
            entry = CapturedLogEntry(
                created_at=created_at,
                level=record.levelno,
                logger_name=logger_name,
                pathname=pathname,
                text=text,
                byte_size=len(text.encode("utf-8")),
            )
            with self._buffer_lock:
                self._entries.append(entry)
                self._total_bytes += entry.byte_size
                self._evict_locked(self._clock())
        except Exception:
            return

    def snapshot(self) -> LogSnapshot:
        with self._buffer_lock:
            self._evict_locked(self._clock())
            return LogSnapshot(
                started_at=self._started_at,
                entries=tuple(self._entries),
                evicted_count=self._evicted_count,
            )

    def _evict_locked(self, now: datetime) -> None:
        oldest_allowed = now - self._retention
        while self._entries and (
            self._entries[0].created_at < oldest_allowed
            or len(self._entries) > self._max_records
            or self._total_bytes > self._max_bytes
        ):
            removed = self._entries.popleft()
            self._total_bytes -= removed.byte_size
            self._evicted_count += 1


def _is_honeypot_entry(entry: CapturedLogEntry) -> bool:
    logger_name = entry.logger_name.casefold()
    pathname = entry.pathname.replace("\\", "/").casefold()
    text = entry.text.replace("\\", "/").casefold()
    return (
        "honeypot" in logger_name
        or "/honeypot/" in pathname
        or "/honeypot/" in text
    )


def _render_dump_header(
    snapshot: LogSnapshot,
    *,
    scope: str,
    hours: int,
    minimum_level: int | None,
    now: datetime,
    matching_count: int,
    included: list[CapturedLogEntry],
    omitted_count: int,
) -> str:
    level_name = (
        "all" if minimum_level is None else logging.getLevelName(minimum_level).lower()
    )
    oldest = included[0].created_at.isoformat() if included else "none"
    newest = included[-1].created_at.isoformat() if included else "none"
    return (
        "Read-only Python logging dump\n"
        f"scope: {scope}\n"
        f"requested window: {hours} hour(s)\n"
        f"minimum level: {level_name}\n"
        f"generated at: {now.isoformat()}\n"
        f"capture started at: {snapshot.started_at.isoformat()}\n"
        f"matching records: {matching_count}\n"
        f"included records: {len(included)}\n"
        f"records evicted before request: {snapshot.evicted_count}\n"
        f"older matching records omitted: {omitted_count}\n"
        f"oldest included: {oldest}\n"
        f"newest included: {newest}\n\n"
    )


def build_log_dump(
    snapshot: LogSnapshot,
    *,
    scope: str,
    hours: int,
    minimum_level: int | None,
    upload_limit: int,
    now: datetime,
) -> LogDump:
    if scope not in {"bot", "honeypot"}:
        raise ValueError("scope must be 'bot' or 'honeypot'")
    if not 1 <= hours <= 24:
        raise ValueError("hours must be between 1 and 24")
    if upload_limit <= 0:
        raise ValueError("upload_limit must be positive")

    since = now - timedelta(hours=hours)
    matches = [
        entry
        for entry in snapshot.entries
        if entry.created_at >= since
        and (minimum_level is None or entry.level >= minimum_level)
        and (scope == "bot" or _is_honeypot_entry(entry))
    ]

    first_included = 0
    included = matches
    body_size = sum(entry.byte_size for entry in included)
    if included:
        body_size += 2 * (len(included) - 1)
    empty_body = "No matching log records are available."

    while True:
        omitted_count = first_included
        header = _render_dump_header(
            snapshot,
            scope=scope,
            hours=hours,
            minimum_level=minimum_level,
            now=now,
            matching_count=len(matches),
            included=included,
            omitted_count=omitted_count,
        )
        rendered_body_size = body_size if included else len(empty_body.encode("utf-8"))
        rendered_size = len(header.encode("utf-8")) + rendered_body_size + 1
        if rendered_size <= upload_limit or not included:
            break
        removed = included[0]
        first_included += 1
        included = matches[first_included:]
        body_size -= removed.byte_size
        if included:
            body_size -= 2

    body = "\n\n".join(entry.text for entry in included) if included else empty_body
    content = (header + body + "\n").encode("utf-8")
    return LogDump(
        content=content,
        filename=f"console-{scope}-{hours}h-{now:%Y%m%d-%H%M%SZ}.txt",
        matching_count=len(matches),
        included_count=len(included),
        omitted_count=len(matches) - len(included),
    )
