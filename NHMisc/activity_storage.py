from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path


@dataclass(frozen=True)
class TopChannel:
    channel_id: int
    message_count: int
    rank: int


@dataclass(frozen=True)
class DailySummary:
    date_utc: date
    total_messages: int
    active_users: int
    member_count_at_close: int
    users_10_plus: int
    users_50_plus: int
    users_100_plus: int
    channels_with_activity: int
    peak_hour_utc: int | None
    messages_per_active_user: float
    top_channels: list[TopChannel]


@dataclass(frozen=True)
class TimelineDay:
    date_utc: date
    summary: DailySummary | None


@dataclass(frozen=True)
class UserStats:
    date_rows: list[tuple[date, int | None]]
    total_messages: int
    active_days: int
    average_per_active_day: float
    top_channels: list[TopChannel]


@dataclass(frozen=True)
class ChannelUserCount:
    user_id: int
    message_count: int


class ActivityStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        async with self._lock:
            await asyncio.to_thread(self._initialize_sync)

    async def record_message(
        self,
        guild_id: int,
        date_utc: date,
        hour_utc: int,
        user_id: int,
        channel_id: int,
        thread_id: int | None,
        now_utc: datetime,
    ) -> None:
        async with self._lock:
            await asyncio.to_thread(
                self._record_message_sync,
                guild_id,
                date_utc,
                hour_utc,
                user_id,
                channel_id,
                thread_id,
                now_utc,
            )

    async def close_stale_days(
        self, guild_id: int, current_date_utc: date, member_count: int
    ) -> list[DailySummary]:
        async with self._lock:
            return await asyncio.to_thread(
                self._close_stale_days_sync, guild_id, current_date_utc, member_count
            )

    async def build_current_summary(
        self, guild_id: int, date_utc: date, member_count: int
    ) -> DailySummary | None:
        async with self._lock:
            return await asyncio.to_thread(
                self._build_summary_from_open_tables_sync, guild_id, date_utc, member_count
            )

    async def get_latest_summary(self, guild_id: int) -> DailySummary | None:
        async with self._lock:
            return await asyncio.to_thread(self._get_latest_summary_sync, guild_id)

    async def get_timeline(
        self, guild_id: int, end_date_utc: date, days: int
    ) -> list[TimelineDay]:
        async with self._lock:
            return await asyncio.to_thread(
                self._get_timeline_sync, guild_id, end_date_utc, days
            )

    async def get_timeline_top_channels(
        self, guild_id: int, end_date_utc: date, days: int, limit: int = 3
    ) -> list[TopChannel]:
        async with self._lock:
            return await asyncio.to_thread(
                self._get_timeline_top_channels_sync, guild_id, end_date_utc, days, limit
            )

    async def get_user_stats(
        self, guild_id: int, user_id: int, end_date_utc: date, days: int
    ) -> UserStats:
        async with self._lock:
            return await asyncio.to_thread(
                self._get_user_stats_sync, guild_id, user_id, end_date_utc, days
            )

    async def get_channel_user_counts(
        self,
        guild_id: int,
        channel_id: int,
        thread_id: int | None,
        end_date_utc: date,
        days: int,
    ) -> list[ChannelUserCount]:
        async with self._lock:
            return await asyncio.to_thread(
                self._get_channel_user_counts_sync,
                guild_id,
                channel_id,
                thread_id,
                end_date_utc,
                days,
            )

    async def count_detail_rows_older_than(self, guild_id: int, cutoff_date_utc: date) -> int:
        async with self._lock:
            return await asyncio.to_thread(
                self._count_rows_older_than_sync,
                "activity_user_channel_day",
                guild_id,
                cutoff_date_utc,
            )

    async def prune_detail_rows_older_than(self, guild_id: int, cutoff_date_utc: date) -> int:
        async with self._lock:
            return await asyncio.to_thread(
                self._prune_rows_older_than_sync,
                "activity_user_channel_day",
                guild_id,
                cutoff_date_utc,
            )

    async def count_history_rows_older_than(
        self, guild_id: int, cutoff_date_utc: date
    ) -> tuple[int, int]:
        async with self._lock:
            return await asyncio.to_thread(
                self._count_history_rows_older_than_sync, guild_id, cutoff_date_utc
            )

    async def prune_history_rows_older_than(
        self, guild_id: int, cutoff_date_utc: date
    ) -> tuple[int, int]:
        async with self._lock:
            return await asyncio.to_thread(
                self._prune_history_rows_older_than_sync, guild_id, cutoff_date_utc
            )

    async def delete_history_for_date(self, guild_id: int, date_utc: date) -> tuple[int, int]:
        async with self._lock:
            return await asyncio.to_thread(
                self._delete_history_for_date_sync, guild_id, date_utc
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _initialize_sync(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS activity_open_day (
                    guild_id INTEGER PRIMARY KEY,
                    date_utc TEXT NOT NULL,
                    started_at_utc TEXT NOT NULL,
                    last_seen_at_utc TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS activity_user_day (
                    guild_id INTEGER NOT NULL,
                    date_utc TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    message_count INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, date_utc, user_id)
                );

                CREATE TABLE IF NOT EXISTS activity_channel_day (
                    guild_id INTEGER NOT NULL,
                    date_utc TEXT NOT NULL,
                    channel_id INTEGER NOT NULL,
                    thread_id INTEGER NOT NULL,
                    message_count INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, date_utc, channel_id, thread_id)
                );

                CREATE TABLE IF NOT EXISTS activity_hour_day (
                    guild_id INTEGER NOT NULL,
                    date_utc TEXT NOT NULL,
                    hour_utc INTEGER NOT NULL,
                    message_count INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, date_utc, hour_utc)
                );

                CREATE TABLE IF NOT EXISTS activity_daily_summary (
                    guild_id INTEGER NOT NULL,
                    date_utc TEXT NOT NULL,
                    total_messages INTEGER NOT NULL,
                    active_users INTEGER NOT NULL,
                    member_count_at_close INTEGER NOT NULL,
                    users_10_plus INTEGER NOT NULL,
                    users_50_plus INTEGER NOT NULL,
                    users_100_plus INTEGER NOT NULL,
                    channels_with_activity INTEGER NOT NULL,
                    peak_hour_utc INTEGER,
                    messages_per_active_user REAL NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    PRIMARY KEY (guild_id, date_utc)
                );

                CREATE TABLE IF NOT EXISTS activity_daily_top_channels (
                    guild_id INTEGER NOT NULL,
                    date_utc TEXT NOT NULL,
                    channel_id INTEGER NOT NULL,
                    message_count INTEGER NOT NULL,
                    rank INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, date_utc, rank)
                );

                CREATE TABLE IF NOT EXISTS activity_user_channel_day (
                    guild_id INTEGER NOT NULL,
                    date_utc TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    channel_id INTEGER NOT NULL,
                    thread_id INTEGER NOT NULL,
                    message_count INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, date_utc, user_id, channel_id, thread_id)
                );

                CREATE INDEX IF NOT EXISTS idx_activity_user_channel_day_lookup
                    ON activity_user_channel_day (guild_id, user_id, date_utc);
                CREATE INDEX IF NOT EXISTS idx_activity_user_channel_day_channel_lookup
                    ON activity_user_channel_day (guild_id, channel_id, date_utc);
                CREATE INDEX IF NOT EXISTS idx_activity_daily_summary_date
                    ON activity_daily_summary (guild_id, date_utc);
                CREATE INDEX IF NOT EXISTS idx_activity_daily_top_channels_date
                    ON activity_daily_top_channels (guild_id, date_utc);
                """
            )

    def _record_message_sync(
        self,
        guild_id: int,
        date_utc: date,
        hour_utc: int,
        user_id: int,
        channel_id: int,
        thread_id: int | None,
        now_utc: datetime,
    ) -> None:
        date_key = date_utc.isoformat()
        stored_thread_id = thread_id or 0
        now_key = now_utc.isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO activity_open_day
                    (guild_id, date_utc, started_at_utc, last_seen_at_utc)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(guild_id) DO UPDATE SET
                    date_utc = excluded.date_utc,
                    last_seen_at_utc = excluded.last_seen_at_utc
                """,
                (guild_id, date_key, now_key, now_key),
            )
            self._increment_counter(
                conn,
                "activity_user_day",
                ("guild_id", "date_utc", "user_id"),
                (guild_id, date_key, user_id),
            )
            self._increment_counter(
                conn,
                "activity_channel_day",
                ("guild_id", "date_utc", "channel_id", "thread_id"),
                (guild_id, date_key, channel_id, stored_thread_id),
            )
            self._increment_counter(
                conn,
                "activity_hour_day",
                ("guild_id", "date_utc", "hour_utc"),
                (guild_id, date_key, hour_utc),
            )
            self._increment_counter(
                conn,
                "activity_user_channel_day",
                ("guild_id", "date_utc", "user_id", "channel_id", "thread_id"),
                (guild_id, date_key, user_id, channel_id, stored_thread_id),
            )

    def _increment_counter(
        self,
        conn: sqlite3.Connection,
        table: str,
        key_columns: tuple[str, ...],
        key_values: tuple[object, ...],
    ) -> None:
        columns = (*key_columns, "message_count")
        placeholders = ", ".join("?" for _ in columns)
        assignments = "message_count = message_count + 1"
        conn.execute(
            f"""
            INSERT INTO {table} ({", ".join(columns)})
            VALUES ({placeholders})
            ON CONFLICT({", ".join(key_columns)}) DO UPDATE SET {assignments}
            """,
            (*key_values, 1),
        )

    def _close_stale_days_sync(
        self, guild_id: int, current_date_utc: date, member_count: int
    ) -> list[DailySummary]:
        current_key = current_date_utc.isoformat()
        closed: list[DailySummary] = []
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT date_utc
                FROM activity_open_day
                WHERE guild_id = ? AND date_utc < ?
                ORDER BY date_utc ASC
                """,
                (guild_id, current_key),
            ).fetchall()
            for row in rows:
                day = date.fromisoformat(str(row[0]))
                summary = self._build_summary_from_open_tables_with_conn(
                    conn, guild_id, day, member_count
                )
                if summary is not None:
                    self._save_daily_summary_with_conn(conn, guild_id, summary)
                    closed.append(summary)
                self._delete_strict_daily_rows_with_conn(conn, guild_id, day)

            if rows:
                now_key = datetime.utcnow().isoformat()
                conn.execute(
                    """
                    UPDATE activity_open_day
                    SET date_utc = ?, started_at_utc = ?, last_seen_at_utc = ?
                    WHERE guild_id = ?
                    """,
                    (current_key, now_key, now_key, guild_id),
                )
        return closed

    def _build_summary_from_open_tables_sync(
        self, guild_id: int, date_utc: date, member_count: int
    ) -> DailySummary | None:
        with self._connection() as conn:
            return self._build_summary_from_open_tables_with_conn(
                conn, guild_id, date_utc, member_count
            )

    def _build_summary_from_open_tables_with_conn(
        self, conn: sqlite3.Connection, guild_id: int, date_utc: date, member_count: int
    ) -> DailySummary | None:
        date_key = date_utc.isoformat()
        row = conn.execute(
            """
            SELECT
                COALESCE(SUM(message_count), 0),
                COUNT(*),
                SUM(CASE WHEN message_count >= 10 THEN 1 ELSE 0 END),
                SUM(CASE WHEN message_count >= 50 THEN 1 ELSE 0 END),
                SUM(CASE WHEN message_count >= 100 THEN 1 ELSE 0 END)
            FROM activity_user_day
            WHERE guild_id = ? AND date_utc = ?
            """,
            (guild_id, date_key),
        ).fetchone()
        total_messages = int(row[0] or 0)
        active_users = int(row[1] or 0)
        if total_messages == 0 and active_users == 0:
            return None

        channel_count_row = conn.execute(
            """
            SELECT COUNT(DISTINCT channel_id)
            FROM activity_channel_day
            WHERE guild_id = ? AND date_utc = ?
            """,
            (guild_id, date_key),
        ).fetchone()
        peak_hour_row = conn.execute(
            """
            SELECT hour_utc
            FROM activity_hour_day
            WHERE guild_id = ? AND date_utc = ?
            ORDER BY message_count DESC, hour_utc ASC
            LIMIT 1
            """,
            (guild_id, date_key),
        ).fetchone()
        top_rows = conn.execute(
            """
            SELECT channel_id, SUM(message_count) AS total
            FROM activity_channel_day
            WHERE guild_id = ? AND date_utc = ?
            GROUP BY channel_id
            ORDER BY total DESC, channel_id ASC
            LIMIT 3
            """,
            (guild_id, date_key),
        ).fetchall()
        top_channels = [
            TopChannel(channel_id=int(channel_id), message_count=int(count), rank=index + 1)
            for index, (channel_id, count) in enumerate(top_rows)
        ]
        return DailySummary(
            date_utc=date_utc,
            total_messages=total_messages,
            active_users=active_users,
            member_count_at_close=max(0, int(member_count or 0)),
            users_10_plus=int(row[2] or 0),
            users_50_plus=int(row[3] or 0),
            users_100_plus=int(row[4] or 0),
            channels_with_activity=int(channel_count_row[0] or 0),
            peak_hour_utc=int(peak_hour_row[0]) if peak_hour_row else None,
            messages_per_active_user=(
                float(total_messages) / float(active_users) if active_users else 0.0
            ),
            top_channels=top_channels,
        )

    def _save_daily_summary_with_conn(
        self, conn: sqlite3.Connection, guild_id: int, summary: DailySummary
    ) -> None:
        date_key = summary.date_utc.isoformat()
        conn.execute(
            """
            INSERT INTO activity_daily_summary (
                guild_id, date_utc, total_messages, active_users, member_count_at_close,
                users_10_plus, users_50_plus, users_100_plus, channels_with_activity,
                peak_hour_utc, messages_per_active_user, created_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(guild_id, date_utc) DO UPDATE SET
                total_messages = excluded.total_messages,
                active_users = excluded.active_users,
                member_count_at_close = excluded.member_count_at_close,
                users_10_plus = excluded.users_10_plus,
                users_50_plus = excluded.users_50_plus,
                users_100_plus = excluded.users_100_plus,
                channels_with_activity = excluded.channels_with_activity,
                peak_hour_utc = excluded.peak_hour_utc,
                messages_per_active_user = excluded.messages_per_active_user,
                created_at_utc = excluded.created_at_utc
            """,
            (
                guild_id,
                date_key,
                summary.total_messages,
                summary.active_users,
                summary.member_count_at_close,
                summary.users_10_plus,
                summary.users_50_plus,
                summary.users_100_plus,
                summary.channels_with_activity,
                summary.peak_hour_utc,
                summary.messages_per_active_user,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.execute(
            "DELETE FROM activity_daily_top_channels WHERE guild_id = ? AND date_utc = ?",
            (guild_id, date_key),
        )
        conn.executemany(
            """
            INSERT INTO activity_daily_top_channels
                (guild_id, date_utc, channel_id, message_count, rank)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (guild_id, date_key, top.channel_id, top.message_count, top.rank)
                for top in summary.top_channels
            ],
        )

    def _delete_strict_daily_rows_with_conn(
        self, conn: sqlite3.Connection, guild_id: int, date_utc: date
    ) -> None:
        date_key = date_utc.isoformat()
        for table in ("activity_user_day", "activity_channel_day", "activity_hour_day"):
            conn.execute(
                f"DELETE FROM {table} WHERE guild_id = ? AND date_utc = ?",
                (guild_id, date_key),
            )

    def _get_latest_summary_sync(self, guild_id: int) -> DailySummary | None:
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT date_utc
                FROM activity_daily_summary
                WHERE guild_id = ?
                ORDER BY date_utc DESC
                LIMIT 1
                """,
                (guild_id,),
            ).fetchone()
            if row is None:
                return None
            return self._load_daily_summary_with_conn(conn, guild_id, date.fromisoformat(row[0]))

    def _get_timeline_sync(
        self, guild_id: int, end_date_utc: date, days: int
    ) -> list[TimelineDay]:
        with self._connection() as conn:
            timeline: list[TimelineDay] = []
            for offset in range(days):
                day = end_date_utc.fromordinal(end_date_utc.toordinal() - offset)
                timeline.append(
                    TimelineDay(day, self._load_daily_summary_with_conn(conn, guild_id, day))
                )
            return timeline

    def _load_daily_summary_with_conn(
        self, conn: sqlite3.Connection, guild_id: int, date_utc: date
    ) -> DailySummary | None:
        date_key = date_utc.isoformat()
        row = conn.execute(
            """
            SELECT total_messages, active_users, member_count_at_close, users_10_plus,
                   users_50_plus, users_100_plus, channels_with_activity,
                   peak_hour_utc, messages_per_active_user
            FROM activity_daily_summary
            WHERE guild_id = ? AND date_utc = ?
            """,
            (guild_id, date_key),
        ).fetchone()
        if row is None:
            return None
        top_rows = conn.execute(
            """
            SELECT channel_id, message_count, rank
            FROM activity_daily_top_channels
            WHERE guild_id = ? AND date_utc = ?
            ORDER BY rank ASC
            """,
            (guild_id, date_key),
        ).fetchall()
        return DailySummary(
            date_utc=date_utc,
            total_messages=int(row[0]),
            active_users=int(row[1]),
            member_count_at_close=int(row[2]),
            users_10_plus=int(row[3]),
            users_50_plus=int(row[4]),
            users_100_plus=int(row[5]),
            channels_with_activity=int(row[6]),
            peak_hour_utc=int(row[7]) if row[7] is not None else None,
            messages_per_active_user=float(row[8]),
            top_channels=[
                TopChannel(int(channel_id), int(count), int(rank))
                for channel_id, count, rank in top_rows
            ],
        )

    def _get_timeline_top_channels_sync(
        self, guild_id: int, end_date_utc: date, days: int, limit: int
    ) -> list[TopChannel]:
        start = date.fromordinal(end_date_utc.toordinal() - days + 1).isoformat()
        end = end_date_utc.isoformat()
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT channel_id, SUM(message_count) AS total
                FROM activity_daily_top_channels
                WHERE guild_id = ? AND date_utc BETWEEN ? AND ?
                GROUP BY channel_id
                ORDER BY total DESC, channel_id ASC
                LIMIT ?
                """,
                (guild_id, start, end, limit),
            ).fetchall()
        return [
            TopChannel(int(channel_id), int(count), index + 1)
            for index, (channel_id, count) in enumerate(rows)
        ]

    def _get_user_stats_sync(
        self, guild_id: int, user_id: int, end_date_utc: date, days: int
    ) -> UserStats:
        start_date = date.fromordinal(end_date_utc.toordinal() - days + 1)
        start = start_date.isoformat()
        end = end_date_utc.isoformat()
        with self._connection() as conn:
            count_rows = conn.execute(
                """
                SELECT date_utc, SUM(message_count)
                FROM activity_user_channel_day
                WHERE guild_id = ? AND user_id = ? AND date_utc BETWEEN ? AND ?
                GROUP BY date_utc
                """,
                (guild_id, user_id, start, end),
            ).fetchall()
            counts = {date.fromisoformat(row[0]): int(row[1]) for row in count_rows}
            available_days = self._load_available_detail_days(conn, guild_id, start_date, end_date_utc)
            date_rows: list[tuple[date, int | None]] = []
            for offset in range(days):
                day = date.fromordinal(end_date_utc.toordinal() - offset)
                if day in counts:
                    value: int | None = counts[day]
                elif day in available_days:
                    value = 0
                else:
                    value = None
                date_rows.append((day, value))

            top_rows = conn.execute(
                """
                SELECT channel_id, SUM(message_count) AS total
                FROM activity_user_channel_day
                WHERE guild_id = ? AND user_id = ? AND date_utc BETWEEN ? AND ?
                GROUP BY channel_id
                ORDER BY total DESC, channel_id ASC
                LIMIT 3
                """,
                (guild_id, user_id, start, end),
            ).fetchall()

        numeric_counts = [value for _, value in date_rows if value is not None]
        total_messages = sum(numeric_counts)
        active_days = sum(1 for value in numeric_counts if value > 0)
        return UserStats(
            date_rows=date_rows,
            total_messages=total_messages,
            active_days=active_days,
            average_per_active_day=(
                float(total_messages) / float(active_days) if active_days else 0.0
            ),
            top_channels=[
                TopChannel(int(channel_id), int(count), index + 1)
                for index, (channel_id, count) in enumerate(top_rows)
            ],
        )

    def _load_available_detail_days(
        self,
        conn: sqlite3.Connection,
        guild_id: int,
        start_date: date,
        end_date: date,
    ) -> set[date]:
        start = start_date.isoformat()
        end = end_date.isoformat()
        rows = conn.execute(
            """
            SELECT date_utc
            FROM activity_daily_summary
            WHERE guild_id = ? AND date_utc BETWEEN ? AND ?
            UNION
            SELECT date_utc
            FROM activity_open_day
            WHERE guild_id = ? AND date_utc BETWEEN ? AND ?
            UNION
            SELECT DISTINCT date_utc
            FROM activity_user_channel_day
            WHERE guild_id = ? AND date_utc BETWEEN ? AND ?
            """,
            (guild_id, start, end, guild_id, start, end, guild_id, start, end),
        ).fetchall()
        return {date.fromisoformat(row[0]) for row in rows}

    def _get_channel_user_counts_sync(
        self,
        guild_id: int,
        channel_id: int,
        thread_id: int | None,
        end_date_utc: date,
        days: int,
    ) -> list[ChannelUserCount]:
        start = date.fromordinal(end_date_utc.toordinal() - days + 1).isoformat()
        end = end_date_utc.isoformat()
        params: tuple[object, ...]
        thread_filter = ""
        if thread_id is not None:
            thread_filter = "AND thread_id = ?"
            params = (guild_id, channel_id, thread_id, start, end)
        else:
            params = (guild_id, channel_id, start, end)
        with self._connection() as conn:
            rows = conn.execute(
                f"""
                SELECT user_id, SUM(message_count) AS total
                FROM activity_user_channel_day
                WHERE guild_id = ? AND channel_id = ? {thread_filter} AND date_utc BETWEEN ? AND ?
                GROUP BY user_id
                ORDER BY total DESC, user_id ASC
                """,
                params,
            ).fetchall()
        return [ChannelUserCount(int(user_id), int(count)) for user_id, count in rows]

    def _count_rows_older_than_sync(
        self, table: str, guild_id: int, cutoff_date_utc: date
    ) -> int:
        with self._connection() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE guild_id = ? AND date_utc < ?",
                (guild_id, cutoff_date_utc.isoformat()),
            ).fetchone()
        return int(row[0] or 0)

    def _prune_rows_older_than_sync(
        self, table: str, guild_id: int, cutoff_date_utc: date
    ) -> int:
        with self._connection() as conn:
            cursor = conn.execute(
                f"DELETE FROM {table} WHERE guild_id = ? AND date_utc < ?",
                (guild_id, cutoff_date_utc.isoformat()),
            )
            return int(cursor.rowcount or 0)

    def _count_history_rows_older_than_sync(
        self, guild_id: int, cutoff_date_utc: date
    ) -> tuple[int, int]:
        with self._connection() as conn:
            summary_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM activity_daily_summary
                WHERE guild_id = ? AND date_utc < ?
                """,
                (guild_id, cutoff_date_utc.isoformat()),
            ).fetchone()[0]
            top_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM activity_daily_top_channels
                WHERE guild_id = ? AND date_utc < ?
                """,
                (guild_id, cutoff_date_utc.isoformat()),
            ).fetchone()[0]
        return int(summary_count or 0), int(top_count or 0)

    def _prune_history_rows_older_than_sync(
        self, guild_id: int, cutoff_date_utc: date
    ) -> tuple[int, int]:
        with self._connection() as conn:
            summary_cursor = conn.execute(
                """
                DELETE FROM activity_daily_summary
                WHERE guild_id = ? AND date_utc < ?
                """,
                (guild_id, cutoff_date_utc.isoformat()),
            )
            top_cursor = conn.execute(
                """
                DELETE FROM activity_daily_top_channels
                WHERE guild_id = ? AND date_utc < ?
                """,
                (guild_id, cutoff_date_utc.isoformat()),
            )
        return int(summary_cursor.rowcount or 0), int(top_cursor.rowcount or 0)

    def _delete_history_for_date_sync(self, guild_id: int, date_utc: date) -> tuple[int, int]:
        with self._connection() as conn:
            summary_cursor = conn.execute(
                "DELETE FROM activity_daily_summary WHERE guild_id = ? AND date_utc = ?",
                (guild_id, date_utc.isoformat()),
            )
            top_cursor = conn.execute(
                "DELETE FROM activity_daily_top_channels WHERE guild_id = ? AND date_utc = ?",
                (guild_id, date_utc.isoformat()),
            )
        return int(summary_cursor.rowcount or 0), int(top_cursor.rowcount or 0)
