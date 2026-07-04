# Activity Summary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add passive Discord message activity analytics to NHMisc: daily UTC summaries, history timeline, moderator user stats, channel pie charts, and self stats.

**Architecture:** Keep Discord event handling in `NHMisc/nhmisc.py` and move SQLite persistence/report queries into a focused `NHMisc/activity_storage.py` module. Use `sqlite3` with `cog_data_path(self)` and `asyncio.to_thread`, matching the Honeypot pattern, so message events do not perform Discord REST reads and do not block the event loop.

**Tech Stack:** Red-DiscordBot cog API, discord.py events, stdlib `sqlite3`, stdlib `asyncio`, `matplotlib` with Agg backend for `chatchart`.

---

## Scope And Constraints

- Do not add project tests. The user explicitly decided this project should not get tests for this change.
- Do not fetch message history.
- Do not add legacy/migration shims unless persisted user data/config makes it necessary. This feature is new, so use forward-only schema creation.
- Do not implement command aliases.
- Do not implement `snapshot`.
- Keep `[p]selfchart` as a top-level command, not under `[p]nhmisc`.
- Preserve existing voice log behavior.

## Files

- Create `NHMisc/activity_storage.py`
  - Owns SQLite schema, message counter writes, UTC day close, retention pruning, and read models for commands.
- Modify `NHMisc/nhmisc.py`
  - Adds activity config defaults, event listener, midnight task, command handlers, embed formatting, and chart rendering glue.
- Modify `NHMisc/info.json`
  - Adds `matplotlib` requirement.
  - Updates end-user data statement because the cog will store user IDs in short-retention detail rows.

## Task 1: Storage Module

**Files:**
- Create: `NHMisc/activity_storage.py`

- [ ] **Step 1: Define read models and constants**

Create dataclasses for:

```python
DailySummary(date_utc, total_messages, active_users, member_count_at_close,
             users_10_plus, users_50_plus, users_100_plus, channels_with_activity,
             peak_hour_utc, messages_per_active_user, top_channels)
TopChannel(channel_id, message_count, rank)
TimelineDay(date_utc, summary)
UserStats(date_rows, total_messages, active_days, average_per_active_day, top_channels)
ChannelUserCount(user_id, message_count)
```

- [ ] **Step 2: Create schema initializer**

Use `sqlite3.connect(self._path)` and `CREATE TABLE IF NOT EXISTS` for:

```text
activity_open_day
activity_user_day
activity_channel_day
activity_hour_day
activity_daily_summary
activity_daily_top_channels
activity_user_channel_day
```

Add indexes for guild/date lookups and user/channel detail lookups.

- [ ] **Step 3: Add async wrappers around sync SQLite operations**

Expose methods:

```python
async def initialize(self) -> None
async def record_message(self, guild_id, date_utc, hour_utc, user_id, channel_id, thread_id, now_utc) -> list[str]
async def close_stale_days(self, guild_id, current_date_utc, member_count) -> list[DailySummary]
async def build_current_summary(self, guild_id, date_utc, member_count) -> DailySummary | None
async def get_latest_summary(self, guild_id) -> DailySummary | None
async def get_timeline(self, guild_id, end_date_utc, days) -> list[TimelineDay]
async def get_user_stats(self, guild_id, user_id, end_date_utc, days) -> UserStats
async def get_channel_user_counts(self, guild_id, channel_id, end_date_utc, days) -> list[ChannelUserCount]
async def count_detail_rows_older_than(self, guild_id, cutoff_date_utc) -> int
async def prune_detail_rows_older_than(self, guild_id, cutoff_date_utc) -> int
async def count_history_rows_older_than(self, guild_id, cutoff_date_utc) -> tuple[int, int]
async def prune_history_rows_older_than(self, guild_id, cutoff_date_utc) -> tuple[int, int]
```

- [ ] **Step 4: Implement day close semantics**

For each stale `activity_open_day`:

- aggregate daily summary from current-day tables;
- insert/update `activity_daily_summary`;
- insert/update top 3 rows in `activity_daily_top_channels`;
- delete strict daily rows from `activity_user_day`, `activity_channel_day`, and `activity_hour_day`;
- keep `activity_user_channel_day` until detail retention pruning deletes it;
- advance or delete `activity_open_day` depending on current date.

## Task 2: Cog Wiring And Background Close

**Files:**
- Modify: `NHMisc/nhmisc.py`

- [ ] **Step 1: Add imports and config defaults**

Add:

```python
import io
from datetime import date, timedelta
from redbot.core.data_manager import cog_data_path
```

Register guild config:

```python
activity_channel=None,
activity_detail_retention_days=31,
activity_history_retention_days=-1,
```

- [ ] **Step 2: Create and initialize storage**

In `__init__`, create:

```python
self._activity_store = ActivityStore(cog_data_path(self) / "activity.sqlite")
self._activity_task: asyncio.Task | None = None
```

In `cog_load`, initialize storage, close stale days for currently cached guilds, and start a background task.

In `cog_unload`, cancel the background task.

- [ ] **Step 3: Implement midnight UTC task**

Loop:

- wait until bot is ready;
- close stale days for all cached guilds once on startup;
- sleep until next UTC midnight plus a small delay;
- close stale days again and send summaries to configured channels.

- [ ] **Step 4: Implement `on_message`**

Ignore:

- DMs;
- bot messages;
- webhook messages;
- system messages.

For counted guild messages:

- resolve parent channel for threads;
- call `close_stale_days` before recording if stored open day is old;
- call `record_message`;
- avoid Discord REST calls.

## Task 3: Activity Commands

**Files:**
- Modify: `NHMisc/nhmisc.py`

- [ ] **Step 1: Add permission helpers**

Create helpers:

```python
def _has_staff_activity_permissions(ctx) -> bool
async def _require_manage_guild(ctx) -> None
async def _require_activity_staff(ctx) -> None
```

Use `manage_guild` for config commands and `manage_messages or manage_guild` for read-only moderator commands.

- [ ] **Step 2: Add `[p]nhmisc activity` group**

Commands:

```text
[p]nhmisc activity channel #reports
[p]nhmisc activity current
[p]nhmisc activity latest
[p]nhmisc activity timeline DAYS
[p]nhmisc activity retention DAYS
[p]nhmisc activity historyretention DAYS
```

- [ ] **Step 3: Implement retention confirmation**

When reducing retention would delete rows:

- report old retention, new retention, cutoff date, and exact rows that will be deleted;
- wait for same invoker to reply exactly `I understand`;
- timeout after about 60 seconds;
- only then prune and save the new config.

- [ ] **Step 4: Format daily/current/latest embeds**

Show:

- total messages;
- active users;
- active users as `%Srv` when member count exists;
- users with 10+/50+/100+ messages;
- active channels;
- average messages per active user;
- peak UTC hour;
- top 3 channels as Discord channel mentions.

- [ ] **Step 5: Format timeline**

Accept any positive `DAYS`, capped by retained history. Missing retained row displays `n/d`; existing zero displays `0`. Include `%Srv` only for ranges up to 7 days. Include top channels in range by summing retained daily top-3 rows.

## Task 4: User Stats And Charts

**Files:**
- Modify: `NHMisc/nhmisc.py`

- [ ] **Step 1: Implement `[p]nhmisc usermodstats <member-or-id> <range>`**

Accept member mention or raw Discord user ID. Supported initial ranges: `1d`, `7d`, `14d`, `30d`; cap to detail retention. Output total messages, active days, average per active day, top channels, and daily table. Missing detail day is `n/d`; explicit zero is `0`.

- [ ] **Step 2: Implement top-level `[p]selfchart`**

No arguments. Always use 7 days, capped by retained detail. Output caller-only total messages, daily messages, and top 1 channel.

- [ ] **Step 3: Implement `[p]nhmisc chatchart DAYS`**

Use only the invoking channel. Cap days to retained detail. Query user counts for that channel, build a Matplotlib pie chart with top users plus `Other`, and send it as a `discord.File`.

## Task 5: Metadata And Verification

**Files:**
- Modify: `NHMisc/info.json`

- [ ] **Step 1: Add dependency metadata**

Add `matplotlib` to `requirements`.

- [ ] **Step 2: Update user data statement**

State that the cog stores Discord user IDs and message-count aggregates for configurable retention, and historical summaries do not store user IDs.

- [ ] **Step 3: Run syntax verification**

Run:

```powershell
python -m compileall NHMisc
```

Expected: command completes with no syntax errors.

- [ ] **Step 4: Manual behavior checklist**

Verify by inspection:

- all new commands are under `[p]nhmisc` except `[p]selfchart`;
- no command aliases were added;
- no message history fetch exists;
- `on_message` ignores bots, webhooks, system messages, and DMs;
- channel output uses mentions outside code blocks;
- missing row renders as `n/d`, not `0`.
