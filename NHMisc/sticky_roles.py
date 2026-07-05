from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class StickyRoleStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        async with self._lock:
            await asyncio.to_thread(self._initialize_sync)

    async def add_sticky_role(self, guild_id: int, role_id: int) -> bool:
        async with self._lock:
            return await asyncio.to_thread(self._add_sticky_role_sync, guild_id, role_id)

    async def remove_sticky_role(self, guild_id: int, role_id: int) -> tuple[bool, int]:
        async with self._lock:
            return await asyncio.to_thread(self._remove_sticky_role_sync, guild_id, role_id)

    async def get_sticky_roles(self, guild_id: int) -> set[int]:
        async with self._lock:
            return await asyncio.to_thread(self._get_sticky_roles_sync, guild_id)

    async def replace_member_roles(self, guild_id: int, user_id: int, role_ids: set[int]) -> None:
        async with self._lock:
            await asyncio.to_thread(
                self._replace_member_roles_sync, guild_id, user_id, role_ids
            )

    async def get_member_roles(self, guild_id: int, user_id: int) -> set[int]:
        async with self._lock:
            return await asyncio.to_thread(self._get_member_roles_sync, guild_id, user_id)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
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
                CREATE TABLE IF NOT EXISTS sticky_role_config (
                    guild_id INTEGER NOT NULL,
                    role_id INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, role_id)
                );

                CREATE TABLE IF NOT EXISTS sticky_member_roles (
                    guild_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    role_id INTEGER NOT NULL,
                    PRIMARY KEY (guild_id, user_id, role_id)
                );

                CREATE INDEX IF NOT EXISTS idx_sticky_member_roles_user
                    ON sticky_member_roles (guild_id, user_id);

                CREATE INDEX IF NOT EXISTS idx_sticky_member_roles_role
                    ON sticky_member_roles (guild_id, role_id);
                """
            )

    def _add_sticky_role_sync(self, guild_id: int, role_id: int) -> bool:
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO sticky_role_config (guild_id, role_id)
                VALUES (?, ?)
                """,
                (guild_id, role_id),
            )
            return cursor.rowcount > 0

    def _remove_sticky_role_sync(self, guild_id: int, role_id: int) -> tuple[bool, int]:
        with self._connection() as conn:
            config_cursor = conn.execute(
                "DELETE FROM sticky_role_config WHERE guild_id = ? AND role_id = ?",
                (guild_id, role_id),
            )
            member_cursor = conn.execute(
                "DELETE FROM sticky_member_roles WHERE guild_id = ? AND role_id = ?",
                (guild_id, role_id),
            )
            return config_cursor.rowcount > 0, member_cursor.rowcount

    def _get_sticky_roles_sync(self, guild_id: int) -> set[int]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT role_id FROM sticky_role_config WHERE guild_id = ? ORDER BY role_id",
                (guild_id,),
            ).fetchall()
        return {int(row[0]) for row in rows}

    def _replace_member_roles_sync(
        self, guild_id: int, user_id: int, role_ids: set[int]
    ) -> None:
        with self._connection() as conn:
            conn.execute(
                "DELETE FROM sticky_member_roles WHERE guild_id = ? AND user_id = ?",
                (guild_id, user_id),
            )
            conn.executemany(
                """
                INSERT OR IGNORE INTO sticky_member_roles (guild_id, user_id, role_id)
                VALUES (?, ?, ?)
                """,
                ((guild_id, user_id, role_id) for role_id in sorted(role_ids)),
            )

    def _get_member_roles_sync(self, guild_id: int, user_id: int) -> set[int]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT role_id
                FROM sticky_member_roles
                WHERE guild_id = ? AND user_id = ?
                ORDER BY role_id
                """,
                (guild_id, user_id),
            ).fetchall()
        return {int(row[0]) for row in rows}

