# Honeypot

Honeypot is a Red-DiscordBot cog that protects your server by creating trap channels for self-bots, scammers,
spam accounts, and suspicious users. Messages posted in honeypot channels are deleted, logged, optionally purged,
and either punished automatically or sent to moderators for review. It also alerts moderators when new accounts join the server.

## Installation

```ini
[p]repo add Honeypot https://github.com/Pxx500/Honeypot
[p]cog install Honeypot Honeypot
[p]load Honeypot
```

Requires `AAA3A_utils`. Red will show the pip install command if missing.

## Quick Setup

```ini
[p]honeypot channel create
[p]honeypot channel logs #mod-logs
[p]honeypot core action ban
[p]honeypot core toggle true
```

## Commands

By default, only the server owner can use `!honeypot` and all subcommands. Red Permissions rules can allow other users or roles.

### core

| Command | Description |
|---------|-------------|
| `!honeypot core toggle <bool>` | Enable or disable the cog |
| `!honeypot core action <kick\|ban\|review\|none>` | Main action for suspicious posts |
| `!honeypot core fallback_action <review\|kick\|ban\|none>` | Action for non-suspicious posts |
| `!honeypot core dry_run <bool>` | Log what would happen without punishing |
| `!honeypot core whitelist_mode <bypass\|review\|fallback\|none>` | How whitelisted roles behave |
| `!honeypot core automated_kick_fail_warn <bool>` | Warn when the target has already left before the kick is applied |

### channel

| Command | Description |
|---------|-------------|
| `!honeypot channel create` | Create and add a new `#honeypot` channel at position 0 |
| `!honeypot channel add <channel>` | Add an existing honeypot channel |
| `!honeypot channel remove <channel>` | Remove a honeypot channel |
| `!honeypot channel list` | List honeypot channels |
| `!honeypot channel logs <channel>` | Set the logs channel |
| `!honeypot channel ping_role <role>` | Role to ping on detection |

### punishment

| Command | Description |
|---------|-------------|
| `!honeypot punishment mute_role <role>` | Temp mute role for users awaiting review |
| `!honeypot punishment delete_days <0-7>` | Days of messages to delete on ban |

### purge

| Command | Description |
|---------|-------------|
| `!honeypot purge toggle <bool>` | Delete recent messages from the user in the honeypot channel |
| `!honeypot purge minutes <1-60>` | Minutes of history to purge |

### fakeactivity

| Command | Description |
|---------|-------------|
| `!honeypot fakeactivity toggle <bool>` | Simulate activity in the honeypot channel to attract scammers |
| `!honeypot fakeactivity interval <1-120>` | Minutes between fake messages |
| `!honeypot fakeactivity add <message>` | Add a custom message |
| `!honeypot fakeactivity remove <index>` | Remove a message by index |
| `!honeypot fakeactivity list` | List custom messages |
| `!honeypot fakeactivity reset` | Reset to default messages |

### review

| Command | Description |
|---------|-------------|
| `!honeypot review toggle <bool>` | Send suspicious messages to moderator review instead of acting immediately |
| `!honeypot review channel <channel>` | Channel for review requests |
| `!honeypot review timeout <1-10080>` | Minutes before review expires |
| `!honeypot review kick_fail_warn <false\|true\|manual>` | How to handle a review kick when the target has already left |

### roles

| Command | Description |
|---------|-------------|
| `!honeypot roles add <role>` | Add a whitelisted role |
| `!honeypot roles remove <role>` | Remove a whitelisted role |
| `!honeypot roles list` | List whitelisted roles |

### keywords

| Command | Description |
|---------|-------------|
| `!honeypot keywords add <keyword>` | Add a scam keyword |
| `!honeypot keywords remove <keyword>` | Remove a scam keyword |
| `!honeypot keywords list` | List scam keywords |
| `!honeypot keywords reset` | Reset to defaults |
| `!honeypot keywords attachments add <regex>` | Add filename-base regex (triggers at 2+ matches) |
| `!honeypot keywords attachments remove <regex>` | Remove a filename regex |
| `!honeypot keywords attachments list` | List filename regexes |
| `!honeypot keywords attachments reset` | Reset to default patterns |

### joinwatch

| Command | Description |
|---------|-------------|
| `!honeypot joinwatch toggle <bool>` | Enable or disable the joinwatch module |
| `!honeypot joinwatch alert toggle <bool>` | Enable or disable joinwatch alert messages |
| `!honeypot joinwatch channel <channel>` | Channel for join alerts |
| `!honeypot joinwatch max_age <1-168>` | Max account age in hours to trigger alert |
| `!honeypot joinwatch autorole toggle <bool>` | Enable or disable automatic role assignment for young accounts |
| `!honeypot joinwatch autorole role <role>` | Role to apply to young accounts |
| `!honeypot joinwatch autorole timer <1-10080>` | Minutes before punishment if the role remains |
| `!honeypot joinwatch autorole action <none\|kick\|ban>` | Action when the auto-role is not removed in time |
| `!honeypot joinwatch autorole bantimers` | List active auto-role punishment timers |
| `!honeypot joinwatch autorole randomize toggle <bool>` | Enable or disable randomized delay before the auto-role is applied |
| `!honeypot joinwatch autorole randomize min_time <1-10080>` | Minimum minutes before applying the auto-role |
| `!honeypot joinwatch autorole randomize max_time <1-10080>` | Maximum minutes before applying the auto-role |

### bait

| Command | Description |
|---------|-------------|
| `!honeypot bait toggle <bool>` | Enable or disable the bait role trap |
| `!honeypot bait role <role>` | Set the bait role |
| `!honeypot bait action <kick\|ban>` | Action to take when users take the bait role |

### other

| Command | Description |
|---------|-------------|
| `!honeypot config all` | Show a compact summary of all configuration sections |
| `!honeypot config core` | Show core settings |
| `!honeypot config channel` | Show channel and ping role settings |
| `!honeypot config punishment` | Show punishment settings |
| `!honeypot config purge` | Show purge settings |
| `!honeypot config fakeactivity` | Show fake activity settings |
| `!honeypot config review` | Show review settings and pending review count |
| `!honeypot config roles` | Show whitelist role settings |
| `!honeypot config keywords` | Show keyword and attachment-pattern counts |
| `!honeypot config joinwatch` | Show joinwatch and joinwatch auto-role settings |
| `!honeypot config bait` | Show bait role settings |
| `!honeypot config stats` | Show stored stats and pending review/timer counts |
| `!honeypot stats` | Show public-facing stats |
| `!honeypot modstats` | Show detailed moderator statistics |
| `!honeypot resetstats` | Reset statistics |
| `!honeypot doctor` | Check config, channels, and permissions |

## Action & Fallback Logic

```
suspicious + action = kick/ban  → instant punishment
suspicious + action = review    → review (if review channel is set), otherwise fallback
suspicious + action = none      → skip to fallback
non-suspicious                  → fallback_action decides

fallback_action = review   → moderator review
fallback_action = kick/ban → instant punishment
fallback_action = none     → log only
```

## Whitelist Modes

| Mode | Behavior |
|------|----------|
| `bypass` | Log and skip (no action) |
| `review` | Force review regardless of suspicion |
| `fallback` | Skip instant action, go through fallback logic |
| `none` | Treat as normal user |

## Detection

A message is considered suspicious if:

- Account is under 7 days old
- Content contains scam keywords (customizable, see `!honeypot keywords`)
- Has attachments and account is under 14 days old
- Has 2+ generic attachment names (e.g. `image.jpeg`, `image(1).jpeg`, `1.jpeg`)
- Has 2+ attachments matching configured filename-base regexes

Default scam keywords: `free nitro`, `giveaway`, `steam gift`, `free discord`, `discord.gift`,
`claim your`, `you won`, `free vbucks`, `free robux`, `free coins`, `boost your server`,
`limited time`, `exclusive offer`, `free membership`, `hack`, `crack`, `generator`.

Default attachment patterns: `^image$` (matches `image.jpeg`), `^image ?\(\d+\)$`
(matches `image(1)`, `image (2)`) and `^\d+$` (matches `1.png`, `42.jpeg`).

## Review Flow

1. Message deleted from honeypot channel
2. Recent messages from that user purged (if enabled)
3. Mute role applied while review is pending (if configured)
4. Embed sent to review channel with Ban / Kick / Ignore buttons
5. Attachments copied into the review message
6. Moderators with `Moderate Members` permission can click buttons
7. If review expires, mute role is removed and review marked as timed out
8. Pending reviews survive bot restarts
9. If kicked or banned, the mute role is removed first so it does not linger

Any configured honeypot channel uses the same flow. If a user with the review
mute role or joinwatch auto-role posts in any honeypot channel, the bot treats it
as repeat honeypot activity and forces a ban with the reason `Suspicious Activity`.

## Stats

`stats` shows a compact public-facing summary: messages, bans,
sent-for-review cases, auto-roles applied, and auto role punishments.

`modstats` is the detailed moderator view. `Total detections` counts every
non-exempt message caught in the honeypot channel. `Suspicious detections`
counts only detections matching suspicious-account, keyword, or attachment
rules. `Reviews sent` counts cases sent to moderator review, while `Active
pending reviews` is the current number of unresolved review messages.

`Applied temporary mutes` and `Failed temporary mutes` are historical counters
for temporary review mutes. They do not mean those users are still muted.
The review mute role may be the same role as joinwatch auto-role. If that user
has an active joinwatch auto-role timer, review cleanup leaves the role in place
so it does not clear the joinwatch timer.

`Purged messages` counts extra recent messages removed by the purge step. It
does not include the original honeypot message, which is deleted separately as
part of every detection.

The `Joinwatch` stats section tracks non-bot joins while joinwatch is enabled.
`Young joins` counts accounts below the configured `joinwatch max_age`
threshold, and `Young join rate` is `Young joins / Total joins`. Auto-role
scheduled, clear, and punishment counters are historical. `Pending role applications`
is the current number of delayed role applications waiting to run, and
`Active auto-role timers` is the current number of users still waiting for staff
action or timeout after the role was applied.

## Config Dumps

Use `!honeypot config <section>` to inspect current settings without exposing raw
IDs or message contents. Config dumps resolve channels and roles when possible, show
missing IDs when objects were deleted, and summarize pending reviews or
joinwatch timers by count instead of exposing message contents.

## Joinwatch

When a user with an account younger than the configured threshold joins, an embed
is sent to the joinwatch channel when alerts are enabled. If joinwatch auto-role
is enabled, the cog also applies the configured role and starts a timer. Auto-role
can run even when alert messages are disabled.

Enable randomized auto-role delay to avoid applying the configured role immediately
when the user joins. When enabled, the cog schedules the role for a random time
between `min_time` and `max_time`. The punishment timer starts only after the role
is actually applied, not when the account joins.

Setup:

```ini
[p]honeypot joinwatch max_age 24
[p]honeypot joinwatch alert toggle true
[p]honeypot joinwatch autorole role @NewAccount
[p]honeypot joinwatch autorole randomize min_time 5
[p]honeypot joinwatch autorole randomize max_time 30
[p]honeypot joinwatch autorole randomize toggle true
[p]honeypot joinwatch autorole timer 1440
[p]honeypot joinwatch autorole action ban
[p]honeypot joinwatch autorole toggle true
```

If staff removes the auto-role before the timer expires, the timer is cleared and
no punishment is taken. If the timer expires and the user still has the role, the
cog applies the configured joinwatch action: `none`, `kick`, or `ban`.
Changing `joinwatch autorole timer` recalculates active timers immediately. If
the new timer is already expired for a user, the normal timeout action is handled
right away.

Joinwatch auto-role ignores bot owners, server mods, server admins, users with
`Manage Server`, and users whose top role is at or above the bot's top role.

## Bait Role

The bait role trap watches for users receiving a configured role. This is meant for
roles that should not be assigned to normal users, for example a fake verification,
reward, or access role used to catch automated accounts.

Setup:

```ini
[p]honeypot bait role @SuspiciousRole
[p]honeypot bait action ban
[p]honeypot bait toggle true
```

When the trap is enabled and a non-exempt user receives the bait role, the cog
immediately performs the configured bait action: `kick` or `ban`. It then sends a
log embed to the configured logs channel if one is available.

The bait trap ignores bot owners, server mods, server admins, users with
`Manage Server`, and users whose top role is at or above the bot's top role. If
the bait role is deleted or no bait role is configured, the trap does nothing.

## Permissions

- View Channel, Send Messages, Read Message History, Manage Messages (in honeypot channel)
- View Channel, Read Message History, Manage Messages (in every text, voice-chat, or thread channel where post-ban sweep should remove recent scammer messages; voice/stage channels also require Connect)
- Send Messages (in logs, review, and joinwatch channels)
- Kick Members (if using kick)
- Ban Members (if using ban)
- Manage Roles (if using review mute role or joinwatch auto-role)
- Manage Channels (if using `channel create`)
- Bot role must be above users it punishes, the review mute role, and the joinwatch auto-role

## Intents

- `GUILD_MEMBERS` (privileged) — required for `on_member_join` (joinwatch) and `on_member_update` (joinwatch auto-role and bait role)
- `MESSAGE_CONTENT` (privileged) — required for `on_message` (detection)

Both are enabled by default in RedBot v3.5+.

## Data Storage

Only guild configuration: channel IDs, role IDs, booleans, numeric settings, custom messages, and
pending review metadata. No persistent user data.

## Operational Notes

- Bot owners, mods, admins, users with `Manage Server`, and users at or above the bot's top role are ignored
- The purge only scans the honeypot channel, not the entire server
- Fake activity runs once per minute, only posts when the configured interval has elapsed
- When using review mode, a mute role is used as temporary containment until moderators decide
- `!honeypot doctor` checks all permissions and configuration at once
- Stats are per-server and reset with `resetstats`
