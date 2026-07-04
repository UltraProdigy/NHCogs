# Activity Summary Design

## Goal

Add passive server activity analytics to the NHMisc Red-DiscordBot cog with near-zero Discord REST API usage. The cog records message activity from gateway events, sends an automatic daily summary at midnight UTC, supports manual summary commands, and keeps only aggregated historical data after each day closes.

## Current Context

NHMisc already uses `[p]nhmisc ...` as its command root and Red `Config` for guild settings. The new activity feature should follow that command surface and avoid turning the cog into a broad analytics archive. Existing project preference: no test suite for this repo unless the surrounding project later adopts one.

## Core Requirements

- Track message activity passively from `on_message`.
- Do not fetch message history.
- Avoid per-message Discord REST requests.
- Store current-day details in SQLite inside the cog data path.
- At midnight UTC, close the previous UTC day:
  - calculate a daily report,
  - send it to the configured activity report channel,
  - collapse detailed per-user data into aggregate daily rows,
  - delete detailed rows for the closed day.
- Provide manual commands for current-day preview and historical timeline.
- Use channel mentions for reported channels so Discord clients handle hidden-channel visibility.
- Implement the first slice as one full feature set: daily summaries, timeline, retention controls, `usermodstats`, and `chatchart`.

## Command Surface

```text
[p]nhmisc activity channel #reports
[p]nhmisc activity current
[p]nhmisc activity latest
[p]nhmisc activity timeline 7
[p]nhmisc activity retention 31
[p]nhmisc activity historyretention -1
[p]nhmisc usermodstats @user 7d
[p]nhmisc usermodstats 123456789012345678 30d
[p]selfchart
[p]nhmisc chatchart 7
```

`activity channel` sets the guild report channel.

`activity current` generates a preview for the current UTC day so far. It does not close the day and does not delete detail rows.

`activity latest` reposts the most recently closed daily summary from aggregate history.

`activity timeline DAYS` shows compact historical trend data for the last `DAYS` closed days. It accepts any positive number up to the available retained history cap.

`activity retention DAYS` configures how long moderator detail rows are retained. It affects `activity_user_channel_day`, and therefore `usermodstats` and any future `chatchart` feature.

`activity historyretention DAYS` configures how long daily aggregate summaries are retained:

- `-1`: retain historical daily summaries indefinitely;
- `0`: send the automatic daily summary and then delete the aggregate rows for that day;
- positive value: retain aggregate summaries for that many days.

`usermodstats` is a moderator-only lookup for one user's recent message distribution. It requires a separate short-retention detail table because it cannot be answered from anonymized daily summaries.

`[p]selfchart` shows the caller a simplified 7-day version of `usermodstats` for their own activity only. It is a top-level command without the `[p]nhmisc` prefix and does not accept arguments.

`chatchart DAYS` renders a pie chart for the current Discord channel from passively collected user/channel counters. It accepts only a number of days.

## Data Model

Use SQLite, not Red `Config`, for activity counters. Red `Config` remains only for guild settings such as report channel ID and retention values.

Match the Honeypot cog's local storage pattern:

- use Python stdlib `sqlite3`;
- store the database under Red's `cog_data_path(self)`;
- protect SQLite writes with an `asyncio.Lock`;
- avoid adding `aiosqlite` unless implementation later proves the synchronous calls are too heavy.

### Current-Day Detail Tables

`activity_user_day`

- `guild_id`
- `date_utc`
- `user_id`
- `message_count`

`activity_channel_day`

- `guild_id`
- `date_utc`
- `channel_id`
- `thread_id`
- `message_count`

`activity_hour_day`

- `guild_id`
- `date_utc`
- `hour_utc`
- `message_count`

These tables hold only open-day details. After a day closes, rows for that date are deleted.

### Historical Aggregate Tables

`activity_daily_summary`

- `guild_id`
- `date_utc`
- `total_messages`
- `active_users`
- `member_count_at_close`
- `users_10_plus`
- `users_50_plus`
- `users_100_plus`
- `channels_with_activity`
- `peak_hour_utc`
- `messages_per_active_user`
- `created_at_utc`

`activity_daily_top_channels`

- `guild_id`
- `date_utc`
- `channel_id`
- `message_count`
- `rank`

Keep top 3 channels per day. This supports the daily report and a useful approximate range aggregation without retaining all channel counters forever.

Thread/forum messages count toward the parent channel's activity. The thread ID is also stored as additional detail where available, so later reports can distinguish "activity in this parent channel" from "activity inside specific threads" without treating hidden thread names as public text.

### Optional Moderator Detail Retention

`activity_user_channel_day`

- `guild_id`
- `date_utc`
- `user_id`
- `channel_id`
- `thread_id`
- `message_count`

This table supports moderation tools such as `usermodstats` and future `chatchart`. It is not part of the strict daily-collapse privacy model, so it must have an explicit TTL. Recommended default: 31 days. The table still stores only counters, not message content.

The moderator detail retention value should be stored in Red `Config` per guild, with default `31` days. The command should cap accepted values to a reasonable maximum such as `365` days unless explicitly changed later.

The historical summary retention value should also be stored in Red `Config` per guild, with default `-1` for indefinite retention.

### Open-Day State

`activity_open_day`

- `guild_id`
- `date_utc`
- `started_at_utc`
- `last_seen_at_utc`

This table records which UTC day is currently being collected for each guild. It makes the feature resilient to bot restarts and shutdowns.

## Event Collection

`on_message` should ignore:

- DMs,
- bot messages,
- webhook messages,
- system messages.

For every counted guild message:

- ensure `activity_open_day` for the guild matches the current UTC date;
- if the stored day is older than the current UTC date, close stale days before counting the new message;
- increment current-day user counter,
- increment current-day channel counter,
- increment current-day hour counter.
- if the message is in a thread, increment the parent channel counter and store the thread ID as additional detail.

Use UTC date boundaries. The date key is based on the event handling time, not message fetch time, because no history fetch occurs.

## Startup Recovery

On cog load, after SQLite initialization:

1. Read `activity_open_day`.
2. Compare each guild's stored `date_utc` with the current UTC date.
3. If it is the same date, continue collecting into the existing rows.
4. If it is older than the current date, close that stored day using the same daily-close path as the midnight job.
5. If multiple dates of detail rows exist because the bot was offline for more than one UTC boundary, close each date in order.
6. After closing a stale day, delete that day's current-day detail rows.
7. Create or update `activity_open_day` for the current UTC date when the next message is counted.

Startup recovery should not fetch history for downtime. It only summarizes data that was already passively collected before shutdown.

The close path must be idempotent:

- `activity_daily_summary` should have a unique key on `(guild_id, date_utc)`;
- `activity_daily_top_channels` should be replaceable for `(guild_id, date_utc)`;
- if a summary already exists for a day, rerunning close should not duplicate rows or send duplicate reports unless explicitly requested by a manual repost command.

## Daily Close

A background loop should wake near midnight UTC and close all guilds with data for the previous UTC date.

For each guild/date:

1. Read current detail counters from SQLite.
2. Compute summary fields.
3. Read `guild.member_count` from cache/gateway state for denominator.
4. Save one row in `activity_daily_summary`.
5. Save top 3 channels in `activity_daily_top_channels`.
6. Send the report if an activity report channel is configured and available.
7. Delete current-day detail rows for that closed date.

If sending fails, still keep the aggregate summary and delete user-level details. `activity latest` can repost later.

After sending or attempting to send the daily report, apply historical summary retention:

- `-1`: keep `activity_daily_summary` and `activity_daily_top_channels`;
- `0`: delete aggregate rows for the closed day after the report send attempt;
- `N > 0`: delete aggregate rows older than `N` days.

If retention is `0`, commands that depend on historical aggregates such as `activity latest` and `activity timeline` should report that no retained history is available.

## Daily Report Format

The daily report should be a Discord embed.

Suggested fields:

- Total messages
- Active users
- Active users as percent of `member_count_at_close`
- Users with at least 10 / 50 / 100 messages
- Active channels
- Average messages per active user
- Peak UTC hour
- Top 3 channels

Top channels should be normal Discord channel mentions:

```text
1. <#channel_id> - 642 messages
2. <#channel_id> - 311 messages
3. <#channel_id> - 205 messages
```

Do not put channel mentions inside a code block.

## Timeline Format

Timeline should be compact and trend-oriented, not a full report for every day.

If a requested day has no retained summary row, display `n/d` for numeric columns instead of `0`. Missing row means `n/d`. Existing row with a zero value means `0`.

For `timeline 7`, include `%Srv` if it still fits:

```text
Date       Msgs  Users  %Srv  10+ 50+ 100+
2026-07-03 1842  126    18%   31  8   2
2026-07-02 1610  119    17%   28  6   1
```

For `timeline 14` and `timeline 30`, omit `%Srv` to reduce visual noise:

```text
Date       Msgs  Users  10+ 50+ 100+
2026-07-03 1842  126    31  8   2
2026-07-02 1610  119    28  6   1
```

Below the table, include range aggregates:

```text
Avg/day: 1,682 msgs
Avg active users: 119
Best day: 2026-07-01 (2,095 msgs)
```

Also include top channels in range by summing `activity_daily_top_channels`:

```text
Top channels in range:
1. <#123> - 8,420 messages
2. <#456> - 3,901 messages
3. <#789> - 2,114 messages
```

This is intentionally "top channels among daily top 3 entries", not a perfect all-channel aggregate. It is accurate enough for trends and avoids retaining all channel history indefinitely.

## Moderator User Stats

`[p]nhmisc usermodstats <member-or-user-id> <range>` shows recent activity for one user. This command is intended for moderators, not public analytics.

Permissions:

- require `manage_messages` or `manage_guild`;
- accept a member mention or raw Discord user ID;
- cap the range to the configured detail retention.

Supported initial ranges:

- `1d`
- `7d`
- `14d`
- `30d`

Suggested output:

- total messages in range;
- active days in range;
- average messages per active day;
- top channels for that user in range, as normal channel mentions;
- daily breakdown in a compact code block.

Do not include:

- days over 10 / 50 / 100 messages;
- per-hour message counts;
- burstiness or peak-hour analysis.

Moderator stats should stay at daily / 24-hour granularity plus channel totals.

Example:

```text
User: SomeUser (123456789012345678)
Range: last 7 days
Total messages: 183
Active days: 5
Average per active day: 36.6
```

Top channels:

```text
1. <#123> - 91 messages
2. <#456> - 64 messages
3. <#789> - 28 messages
```

Daily breakdown:

```text
Date       Msgs
2026-07-03 42
2026-07-02 18
2026-07-01 0
```

This command must not fetch message history. It only reads passively collected counters from SQLite.

If a day in the requested range has no retained detail row for the user, display `n/d` rather than `0`. Missing row means `n/d`. Existing row with a zero value means `0`.

## Self Stats

`[p]selfchart` shows a simplified self-service activity summary for the command invoker only.

Input:

- accepts no arguments;
- always uses the last 7 days;
- if fewer than 7 days are retained, use the available retained range and state that in the response;
- does not accept user mentions, raw user IDs, or day counts.

Suggested output:

- total messages in the 7-day range;
- messages for each day separately;
- top 1 channel for the caller in the range, as a normal channel mention;
- daily breakdown in a compact code block.

`selfchart` should not show moderation-only framing, flags, or other users' data. It must not fetch message history.

Like `usermodstats`, `selfchart` should display `n/d` for missing retained rows and `0` for existing rows with zero values.

## Permissions

Most activity analytics commands should be restricted to staff-level permissions because they expose server-wide activity patterns. `selfchart` is the exception because it only exposes the caller's own activity.

Recommended permissions:

- configuration commands such as `activity channel`, `activity retention`, and `activity historyretention`: require `manage_guild`;
- read-only server activity commands such as `activity current`, `activity latest`, and `activity timeline`: require `manage_messages` or `manage_guild`;
- moderator lookups such as `usermodstats`: require `manage_messages` or `manage_guild`;
- charting commands such as `chatchart`: require `manage_messages` or `manage_guild` initially, because they expose per-user channel activity.
- `selfchart`: available to regular guild users, but only for their own data.

## Privacy And Retention

The current-day detail tables contain `user_id`, so they must be short-lived.

Retention rules:

- Keep strict daily-summary user details only for the open UTC day.
- On daily close, delete strict daily-summary user details for the closed day.
- Historical summary rows do not contain user IDs.
- Historical top channel rows contain channel IDs only.
- If moderator tools are enabled, keep `activity_user_channel_day` only for the configured TTL, recommended default 31 days.
- Moderator detail retention must be explicit in documentation because it stores user IDs beyond daily close.

This balances useful server trend reporting with minimal long-term personal data retention.

### Retention Changes

`[p]nhmisc activity retention DAYS` changes the per-guild retention for `activity_user_channel_day`.

Increasing retention:

- update the configured value;
- do not backfill missing data;
- future passive counters are retained for the longer window.

Decreasing retention:

1. Compute the new cutoff date from `DAYS`.
2. Count rows in `activity_user_channel_day` older than the new cutoff for the guild.
3. If the count is `0`, update the config immediately and report that no stored detail rows needed deletion.
4. If the count is greater than `0`, show a warning before changing anything.

Warning content must include:

- the old retention value;
- the new retention value;
- the cutoff date;
- the exact number of detail rows that will be permanently deleted;
- a statement that the deletion cannot be undone;
- instruction to reply exactly with `I understand`.

Only the command invoker may confirm. Confirmation should time out, for example after 60 seconds. Any response other than exact `I understand` cancels the change and keeps both the config and database unchanged.

After successful confirmation:

1. delete rows older than the new cutoff;
2. update the configured retention value;
3. report how many rows were deleted.

The confirmation prompt appears only when the command detects rows that would actually be deleted.

`[p]nhmisc activity historyretention DAYS` changes retention for historical aggregate tables. It uses the same confirmation flow when reducing the value would delete existing summary rows or top-channel rows. The warning must report how many daily summary rows and top-channel rows will be permanently deleted.

## API Budget

The feature should be gateway-first:

- message counting comes from `on_message`,
- member denominator uses `guild.member_count`,
- report channels are resolved from cache via channel ID,
- no history fetches,
- no user fetches,
- no channel scans.

The only Discord API calls should be the summary send/edit operations and normal command responses.

## Charting / `chatchart`

`[p]nhmisc chatchart DAYS` is part of the full first slice, but it depends on the same moderator detail retention used by `usermodstats`.

The idea is useful, but it requires retaining per-user/per-channel counters for longer than one day, for example 31 days for `1mo`. That is covered by the explicit moderator detail retention table:

- per-user/per-channel daily counters retained according to `activity retention`,
- chart only for the channel where the command is invoked,
- accept only a numeric day count;
- if requested days exceed retained detail days, cap to the available retention window by default and state the effective range in the response,
- pie slices limited to top users plus `Other`,
- generated from passive counters only.

Investigation result:

- `!chatchart` does not appear to be a default Red-DiscordBot command.
- The likely source is the open-source `aikaterna/aikaterna-cogs` repo, cog `chatchart`.
- Repository: `https://github.com/aikaterna/aikaterna-cogs`
- Relevant file: `chatchart/chatchart.py`
- License: MIT.
- Chart generation uses `matplotlib` with the `agg` backend, renders into `BytesIO`, and sends the result as `discord.File`.

Recommendation: use the approach as reference, but do not copy the entire cog. Adding chart generation to NHMisc would introduce a new `matplotlib` dependency, which is relatively heavy for a small cog. If we implement charts, keep chart rendering behind a small helper and include MIT attribution if code is copied or closely adapted.

Decision: add `matplotlib` as a dependency and render charts with the `agg` backend into `BytesIO`, following the same general approach as `aikaterna/aikaterna-cogs`.
