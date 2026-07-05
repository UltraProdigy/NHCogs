from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StickyRoleMigrationPreview:
    guild_count: int
    user_count: int
    unique_role_count: int
    already_configured_role_count: int
    new_configured_role_count: int
    missing_config_role_count: int
    candidate_member_role_count: int
    existing_member_role_count: int
    new_member_role_count: int
    skipped_member_role_count: int
    already_configured_roles: list[tuple[int, int, str]]
    new_configured_roles: list[tuple[int, int, str]]
    missing_roles: list[tuple[int, int]]


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

    async def preview_migration(
        self,
        rows: list[tuple[int, int, int]],
        migration_roles: dict[int, dict[int, str]],
        missing_roles: set[tuple[int, int]],
    ) -> StickyRoleMigrationPreview:
        async with self._lock:
            return await asyncio.to_thread(
                self._preview_migration_sync, rows, migration_roles, missing_roles
            )

    async def apply_migration(
        self,
        rows: list[tuple[int, int, int]],
        migration_roles: dict[int, dict[int, str]],
        missing_roles: set[tuple[int, int]],
    ) -> StickyRoleMigrationPreview:
        async with self._lock:
            return await asyncio.to_thread(
                self._apply_migration_sync, rows, migration_roles, missing_roles
            )

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

    def _preview_migration_sync(
        self,
        rows: list[tuple[int, int, int]],
        migration_roles: dict[int, dict[int, str]],
        missing_roles: set[tuple[int, int]],
    ) -> StickyRoleMigrationPreview:
        with self._connection() as conn:
            return self._build_migration_preview(conn, rows, migration_roles, missing_roles)

    def _apply_migration_sync(
        self,
        rows: list[tuple[int, int, int]],
        migration_roles: dict[int, dict[int, str]],
        missing_roles: set[tuple[int, int]],
    ) -> StickyRoleMigrationPreview:
        with self._connection() as conn:
            preview = self._build_migration_preview(conn, rows, migration_roles, missing_roles)
            conn.executemany(
                """
                INSERT OR IGNORE INTO sticky_role_config (guild_id, role_id)
                VALUES (?, ?)
                """,
                (
                    (guild_id, role_id)
                    for guild_id, role_map in sorted(migration_roles.items())
                    for role_id in sorted(role_map)
                ),
            )
            conn.executemany(
                """
                INSERT OR IGNORE INTO sticky_member_roles (guild_id, user_id, role_id)
                VALUES (?, ?, ?)
                """,
                self._valid_migration_rows(rows, migration_roles),
            )
            return preview

    def _build_migration_preview(
        self,
        conn: sqlite3.Connection,
        rows: list[tuple[int, int, int]],
        migration_roles: dict[int, dict[int, str]],
        missing_roles: set[tuple[int, int]],
    ) -> StickyRoleMigrationPreview:
        role_pairs = {
            (guild_id, role_id)
            for guild_id, role_map in migration_roles.items()
            for role_id in role_map
        }
        valid_rows = self._valid_migration_rows(rows, migration_roles)
        existing_role_pairs = self._existing_role_pairs(conn, role_pairs)
        existing_member_rows = self._existing_member_rows(conn, valid_rows)

        already_configured_roles = [
            (guild_id, role_id, migration_roles[guild_id][role_id])
            for guild_id, role_id in sorted(existing_role_pairs)
        ]
        new_configured_roles = [
            (guild_id, role_id, migration_roles[guild_id][role_id])
            for guild_id, role_id in sorted(role_pairs - existing_role_pairs)
        ]

        row_guilds = {guild_id for guild_id, _, _ in rows}
        row_users = {(guild_id, user_id) for guild_id, user_id, _ in rows}
        row_roles = {role_id for _, _, role_id in rows}
        skipped_member_role_count = sum(
            1
            for guild_id, _, role_id in rows
            if role_id not in migration_roles.get(guild_id, {})
        )

        return StickyRoleMigrationPreview(
            guild_count=len(row_guilds),
            user_count=len(row_users),
            unique_role_count=len(row_roles),
            already_configured_role_count=len(already_configured_roles),
            new_configured_role_count=len(new_configured_roles),
            missing_config_role_count=len(missing_roles),
            candidate_member_role_count=len(rows),
            existing_member_role_count=len(existing_member_rows),
            new_member_role_count=len(valid_rows - existing_member_rows),
            skipped_member_role_count=skipped_member_role_count,
            already_configured_roles=already_configured_roles,
            new_configured_roles=new_configured_roles,
            missing_roles=sorted(missing_roles),
        )

    def _existing_role_pairs(
        self, conn: sqlite3.Connection, role_pairs: set[tuple[int, int]]
    ) -> set[tuple[int, int]]:
        if not role_pairs:
            return set()
        guild_ids = sorted({guild_id for guild_id, _ in role_pairs})
        placeholders = ",".join("?" for _ in guild_ids)
        rows = conn.execute(
            f"""
            SELECT guild_id, role_id
            FROM sticky_role_config
            WHERE guild_id IN ({placeholders})
            """,
            guild_ids,
        ).fetchall()
        return {(int(row[0]), int(row[1])) for row in rows} & role_pairs

    def _existing_member_rows(
        self, conn: sqlite3.Connection, rows: set[tuple[int, int, int]]
    ) -> set[tuple[int, int, int]]:
        if not rows:
            return set()
        guild_ids = sorted({guild_id for guild_id, _, _ in rows})
        placeholders = ",".join("?" for _ in guild_ids)
        existing_rows = conn.execute(
            f"""
            SELECT guild_id, user_id, role_id
            FROM sticky_member_roles
            WHERE guild_id IN ({placeholders})
            """,
            guild_ids,
        ).fetchall()
        return {(int(row[0]), int(row[1]), int(row[2])) for row in existing_rows} & rows

    def _valid_migration_rows(
        self,
        rows: list[tuple[int, int, int]],
        migration_roles: dict[int, dict[int, str]],
    ) -> set[tuple[int, int, int]]:
        return {
            (guild_id, user_id, role_id)
            for guild_id, user_id, role_id in rows
            if role_id in migration_roles.get(guild_id, {})
        }
