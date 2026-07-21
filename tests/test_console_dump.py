import importlib.util
import logging
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "Honeypot" / "console_dump.py"
SPEC = importlib.util.spec_from_file_location("honeypot_console_dump_test", MODULE_PATH)
console_dump = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = console_dump
SPEC.loader.exec_module(console_dump)


def make_record(
    *,
    name="red.test",
    level=logging.INFO,
    pathname="/srv/redbot/example.py",
    lineno=42,
    message="message",
    created_at=None,
    exc_info=None,
):
    record = logging.LogRecord(
        name,
        level,
        pathname,
        lineno,
        message,
        (),
        exc_info,
    )
    if created_at is not None:
        record.created = created_at.timestamp()
    return record


def make_entry(created_at, logger_name, pathname, level, message):
    text = (
        f"[{created_at.isoformat()}] {logging.getLevelName(level)} "
        f"[{logger_name}] {pathname}:1\n{message}"
    )
    return console_dump.CapturedLogEntry(
        created_at=created_at,
        level=level,
        logger_name=logger_name,
        pathname=pathname,
        text=text,
        byte_size=len(text.encode("utf-8")),
    )


class ReadOnlyLogBufferTests(unittest.TestCase):
    def test_emit_captures_metadata_and_redacts_authorization(self):
        now = datetime(2026, 7, 21, 10, tzinfo=timezone.utc)
        buffer = console_dump.ReadOnlyLogBuffer(clock=lambda: now)
        record = make_record(
            level=logging.ERROR,
            message="Authorization: Bearer secret-value",
            created_at=now,
        )

        buffer.emit(record)
        entry = buffer.snapshot().entries[0]

        self.assertEqual(entry.logger_name, "red.test")
        self.assertEqual(entry.level, logging.ERROR)
        self.assertIn("/srv/redbot/example.py:42", entry.text)
        self.assertIn("[REDACTED]", entry.text)
        self.assertNotIn("secret-value", entry.text)

    def test_emit_keeps_multiline_exception_traceback(self):
        now = datetime(2026, 7, 21, 10, tzinfo=timezone.utc)
        buffer = console_dump.ReadOnlyLogBuffer(clock=lambda: now)
        try:
            raise RuntimeError("thread creation failed")
        except RuntimeError:
            exc_info = sys.exc_info()
        record = make_record(
            name="discord.client",
            level=logging.ERROR,
            pathname="/venv/discord/client.py",
            lineno=508,
            message="Ignoring exception in on_message",
            created_at=now,
            exc_info=exc_info,
        )

        buffer.emit(record)
        text = buffer.snapshot().entries[0].text

        self.assertIn("Ignoring exception in on_message", text)
        self.assertIn("RuntimeError: thread creation failed", text)

    def test_redaction_covers_webhooks_query_secrets_and_discord_tokens(self):
        discord_token = "A" * 24 + "." + "B" * 6 + "." + "C" * 30
        original = (
            "https://discord.com/api/webhooks/123456/webhook-secret "
            "https://example.test/path?token=query-secret "
            f"bot={discord_token}"
        )

        redacted = console_dump.redact_log_text(original)

        self.assertNotIn("webhook-secret", redacted)
        self.assertNotIn("query-secret", redacted)
        self.assertNotIn(discord_token, redacted)
        self.assertGreaterEqual(redacted.count("[REDACTED]"), 3)

    def test_redaction_removes_complete_plain_and_structured_authorization_values(self):
        original = (
            "Authorization: Basic dXNlcjpwYXNz\n"
            '{"Authorization": "Bearer structured-secret"}\n'
            "Authorization=custom credential-value"
        )

        redacted = console_dump.redact_log_text(original)

        self.assertNotIn("dXNlcjpwYXNz", redacted)
        self.assertNotIn("structured-secret", redacted)
        self.assertNotIn("credential-value", redacted)
        self.assertEqual(redacted.count("[REDACTED]"), 3)

    def test_emit_redacts_metadata_and_bounds_the_complete_record(self):
        now = datetime(2026, 7, 21, 10, tzinfo=timezone.utc)
        buffer = console_dump.ReadOnlyLogBuffer(clock=lambda: now)
        record = make_record(
            name="token=logger-secret",
            pathname="/srv/token=path-secret/file.py",
            message="x" * (console_dump.MAX_RECORD_BYTES * 2),
            created_at=now,
        )

        buffer.emit(record)
        entry = buffer.snapshot().entries[0]

        self.assertNotIn("logger-secret", entry.logger_name)
        self.assertNotIn("path-secret", entry.pathname)
        self.assertNotIn("logger-secret", entry.text)
        self.assertNotIn("path-secret", entry.text)
        self.assertLessEqual(entry.byte_size, console_dump.MAX_RECORD_BYTES)

    def test_snapshot_evicts_expired_records_without_a_new_log(self):
        current = [datetime(2026, 7, 21, 10, tzinfo=timezone.utc)]
        buffer = console_dump.ReadOnlyLogBuffer(
            retention=timedelta(hours=1),
            clock=lambda: current[0],
        )
        buffer.emit(make_record(created_at=current[0], message="old"))
        current[0] += timedelta(hours=2)

        snapshot = buffer.snapshot()

        self.assertEqual(snapshot.entries, ())
        self.assertEqual(snapshot.evicted_count, 1)

    def test_count_and_byte_limits_evict_oldest_records(self):
        now = datetime(2026, 7, 21, 10, tzinfo=timezone.utc)
        count_buffer = console_dump.ReadOnlyLogBuffer(
            max_records=2,
            max_bytes=1024 * 1024,
            clock=lambda: now,
        )
        for index in range(3):
            count_buffer.emit(make_record(created_at=now, message=f"count-{index}"))

        count_snapshot = count_buffer.snapshot()
        self.assertEqual(len(count_snapshot.entries), 2)
        self.assertNotIn("count-0", "\n".join(item.text for item in count_snapshot.entries))
        self.assertEqual(count_snapshot.evicted_count, 1)

        byte_buffer = console_dump.ReadOnlyLogBuffer(
            max_records=100,
            max_bytes=300,
            clock=lambda: now,
        )
        for index in range(3):
            byte_buffer.emit(
                make_record(created_at=now, message=f"bytes-{index}-" + "x" * 120)
            )

        byte_snapshot = byte_buffer.snapshot()
        self.assertGreater(byte_snapshot.evicted_count, 0)
        self.assertIn("bytes-2", byte_snapshot.entries[-1].text)


class LogDumpTests(unittest.TestCase):
    def test_honeypot_scope_includes_foreign_logger_traceback(self):
        now = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)
        snapshot = console_dump.LogSnapshot(
            started_at=now - timedelta(hours=1),
            entries=(
                make_entry(
                    now,
                    "discord.client",
                    "/venv/discord/client.py",
                    logging.ERROR,
                    'File "/srv/cogs/Honeypot/honeypot.py", line 5962',
                ),
                make_entry(
                    now,
                    "red.other",
                    "/srv/cogs/Other/other.py",
                    logging.ERROR,
                    "unrelated",
                ),
            ),
            evicted_count=0,
        )

        dump = console_dump.build_log_dump(
            snapshot,
            scope="honeypot",
            hours=1,
            minimum_level=None,
            upload_limit=1024 * 1024,
            now=now,
        )

        text = dump.content.decode("utf-8")
        self.assertIn("discord.client", text)
        self.assertNotIn("unrelated", text)

    def test_dump_filters_by_time_and_optional_minimum_level(self):
        now = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)
        snapshot = console_dump.LogSnapshot(
            started_at=now - timedelta(hours=3),
            entries=(
                make_entry(
                    now - timedelta(minutes=30),
                    "red.a",
                    "/a.py",
                    logging.INFO,
                    "new-info",
                ),
                make_entry(
                    now - timedelta(minutes=20),
                    "red.a",
                    "/a.py",
                    logging.ERROR,
                    "new-error",
                ),
                make_entry(
                    now - timedelta(hours=2),
                    "red.a",
                    "/a.py",
                    logging.CRITICAL,
                    "old-critical",
                ),
            ),
            evicted_count=0,
        )

        dump = console_dump.build_log_dump(
            snapshot,
            scope="bot",
            hours=1,
            minimum_level=logging.ERROR,
            upload_limit=1024 * 1024,
            now=now,
        )

        text = dump.content.decode("utf-8")
        self.assertIn("new-error", text)
        self.assertNotIn("new-info", text)
        self.assertNotIn("old-critical", text)

    def test_dump_keeps_newest_records_that_fit_upload_limit(self):
        now = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)
        entries = tuple(
            make_entry(
                now - timedelta(minutes=3 - index),
                "red.a",
                "/a.py",
                logging.INFO,
                f"record-{index}-" + "x" * 180,
            )
            for index in range(3)
        )
        snapshot = console_dump.LogSnapshot(
            started_at=now - timedelta(hours=1),
            entries=entries,
            evicted_count=4,
        )

        dump = console_dump.build_log_dump(
            snapshot,
            scope="bot",
            hours=1,
            minimum_level=None,
            upload_limit=750,
            now=now,
        )

        text = dump.content.decode("utf-8")
        self.assertLessEqual(len(dump.content), 750)
        self.assertIn("record-2", text)
        self.assertIn("older matching records omitted:", text)
        self.assertIn("records evicted before request: 4", text)
        self.assertGreater(dump.omitted_count, 0)

    def test_empty_dump_contains_clear_metadata_only_result(self):
        now = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)
        snapshot = console_dump.LogSnapshot(now, (), 0)

        dump = console_dump.build_log_dump(
            snapshot,
            scope="bot",
            hours=1,
            minimum_level=None,
            upload_limit=1024 * 1024,
            now=now,
        )

        text = dump.content.decode("utf-8")
        self.assertIn("No matching log records are available.", text)
        self.assertEqual(dump.matching_count, 0)
        self.assertEqual(dump.included_count, 0)
