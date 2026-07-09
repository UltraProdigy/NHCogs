# NHMisc

`NHMisc` is a Red-DiscordBot cog with small moderation and server-utility tools.

`[p]` means your bot prefix. If your bot prefix is `!`, then `[p]nhmisc status`
is typed as `!nhmisc status`.

## Installation

```ini
[p]repo add NHMisc https://github.com/Pxx500/NHMisc
[p]cog install NHMisc NHMisc
[p]load NHMisc
```

## Voice Logging

Voice logging sends messages when users join, leave, or move between voice channels.
Move logs are sent immediately. If Discord audit logs later show that a moderator moved
the member, the bot edits the move log and adds the moderator name and user ID.

```ini
[p]nhmisc channel #voice-logs
```

Sets the text channel used for voice join, leave, and move logs.

```ini
[p]nhmisc alert channel #alerts
```

Sets the alert channel used by higher-priority alerts, such as voice-channel jumping.

```ini
[p]nhmisc vcjumping visits 3
```

Sets how many voice-channel entries trigger a VC jumping alert. Entries do not need to be
different channels; entering the same channel repeatedly still counts.

```ini
[p]nhmisc vcjumping seconds 30
```

Sets the VC jumping detection window in seconds.

```ini
[p]nhmisc status
```

Shows the current voice log channel, alert channel, and VC jumping configuration.

Defaults:

- VC jumping entries: `3`
- VC jumping window: `30` seconds

## Sticky Roles

Sticky roles remember selected roles when a member leaves and restore them when the
member rejoins. Roles are stored by Discord role ID, so role name changes do not matter.

```ini
[p]nhmisc stickyroles add @Role
[p]nhmisc stickyroles add 123456789012345678
```

Marks a role as sticky. The role must exist on the server and the bot must be able to
assign it.

```ini
[p]nhmisc stickyroles remove @Role
[p]nhmisc stickyroles remove 123456789012345678
```

Removes a role from sticky-role tracking. Removing a sticky role also removes that role
from all saved sticky-role snapshots. If the role exists in the sticky role database,
the bot first asks whether to `remove`, `keep`, or `change <role mention or ID>`.

```ini
[p]nhmisc stickyroles list
```

Lists sticky roles configured for the server.

```ini
[p]nhmisc stickyroles scan
```

Scans the sticky role database for entries that need review: missing Discord roles and
saved user-role rows that are no longer configured as sticky. Choices are `remove`,
`keep`, or `change <role mention or ID>`.

```ini
[p]nhmisc stickyroles debuglogging toggle true
[p]nhmisc stickyroles debuglogging toggle false
```

Enables or disables sticky-role debug logs. When enabled, the bot logs sticky-role
snapshot writes on member leave and snapshot reads/restores on member join.

```ini
[p]nhmisc stickyroles debuglogging channel #sticky-debug
```

Sets the channel used for sticky-role debug logs.

This channel is also used for deleted-role prompts when Discord deletes a role that is
still present in the sticky role database.

## Activity Analytics

Activity analytics passively counts normal user messages from Discord gateway events.
The cog does not fetch message history and does not make Discord API requests per
message.

Ignored messages:

- direct messages;
- bot messages;
- webhook messages;
- system messages.

The bot stores counters in a local SQLite database in the cog data directory. Current-day
details are collapsed into daily summaries after the UTC day ends. Detailed user/channel
rows are retained only for the configured retention period.

### Daily Summary Channel

```ini
[p]nhmisc activity channel #activity-reports
```

Sets the channel where the bot posts automatic daily activity summaries. Summaries are
closed on UTC day boundaries. If the bot was offline at midnight, it closes stale days on
startup or on the next relevant activity command/message.

Daily summaries include:

- total messages;
- active users;
- active-user percentage of server members;
- users with at least 10, 50, and 100 messages;
- number of active channels;
- average messages per active user;
- peak hour shown as a Discord-localized timestamp;
- top 5 channels as Discord channel mentions.

### Activity Commands

```ini
[p]nhmisc activity current
```

Shows a preview of the current UTC day. This does not close the day and does not write a
final history row.

```ini
[p]nhmisc activity latest
```

Shows the latest retained closed daily summary.

```ini
[p]nhmisc activity timeline 7
```

Shows a compact table for the last closed days. You can pass any positive day count, for
example:

```ini
[p]nhmisc activity timeline 30
```

If a retained row does not exist for a day, the table shows `n/d`. If data exists and the
value is zero, it shows `0`.

```ini
[p]nhmisc activity channelstats #channel 30
```

Shows day-by-day message activity for one channel. Current and detail-retained days use
per-user/channel detail rows. Closed days use daily channel summaries retained by
history retention. Days with no retained data show `n/d`; retained days with no messages
show `0`.

```ini
[p]nhmisc activity retention 31
```

Sets how many days to keep detailed user/channel/thread rows. These rows power
`usermodstats`, `selfchart`, and `chatchart`.

If lowering retention would delete existing rows, the bot first reports how many rows
will be deleted and requires the same moderator to reply exactly:

```text
I understand
```

```ini
[p]nhmisc activity historyretention -1
```

Sets how long daily summary history is retained:

- `-1`: keep daily summary history indefinitely;
- `0`: send the daily summary, then delete that day's aggregate history;
- any positive number: keep that many days of daily summary history.

Reducing history retention also asks for `I understand` when it would permanently delete
existing summary rows.

```ini
[p]nhmisc activity verify
```

Checks today's open activity aggregates for internal consistency. This compares the
canonical per-user/channel/thread rows with the faster per-user and per-channel cache
rows. It does not read Honeypot data.

```ini
[p]nhmisc activity dbsize
```

Shows the activity SQLite file size in bytes and MiB, SQLite page usage, and row counts
for the main activity tables.

### Moderator Tools

```ini
[p]nhmisc usermodstats @User 7
```

Shows moderator-only message stats for one user.

You can also use a raw Discord user ID:

```ini
[p]nhmisc usermodstats 123456789012345678 30
```

Pass any positive number of days. The requested range is capped to the configured detail
retention.

The output includes total messages, active days, average messages per active day, top
channels, and a daily breakdown. Missing retained data is shown as `n/d`; real zeroes are
shown as `0`.

```ini
[p]nhmisc chatchart 7
```

Creates a pie chart of message activity for the channel where the command is used. If the
command is used in a thread, it charts that specific thread. The requested day count is
capped to the configured detail retention. The chart labels include the message count for
each shown user.

### User Command

```ini
[p]selfchart
```

Shows the caller's own simplified activity for the last 7 retained days:

- total messages;
- messages for each day;
- top 1 channel.

This command has no arguments and only shows the caller's own data.

## Permissions

Configuration commands require Manage Server or bot admin permissions.

Sticky-role commands require Manage Server or bot admin permissions.

Server-wide activity commands and moderator tools require Manage Messages, Manage
Server, or bot admin permissions.

`[p]selfchart` is available to regular guild users because it only returns the caller's
own activity.

## Stored Data

The cog stores Discord user IDs with passively collected message-count aggregates for
configurable short-term activity detail retention. Closed daily summary history stores
aggregate counts and channel IDs, but not user IDs.

The detailed activity row is keyed by UTC date, user ID, parent channel ID, thread ID,
and message count. A user can have multiple rows for the same day when they post in
multiple channels or threads. NHMisc does not store message content, message IDs, jump
URLs, attachment URLs, embeds, or deleted/edited message state. Honeypot's short-lived
moderation/deletion cache is separate and is not used for NHMisc statistics.

Sticky roles are stored in a local SQLite database as guild IDs, user IDs, and role IDs.
