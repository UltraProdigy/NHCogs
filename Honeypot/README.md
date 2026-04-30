# Honeypot

Honeypot is a Red-DiscordBot cog that protects your server by creating a trap channel for self-bots, scammers,
spam accounts, and suspicious users. Messages posted in the honeypot channel are deleted, logged, optionally purged,
and either punished automatically or sent to moderators for review. Also alerts on new accounts joining the server.

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
[p]honeypot core enabled true
```

## Commands

Only the server owner can use `!honeypot` and all subcommands.

### core

| Command | Description |
|---------|-------------|
| `!honeypot core enabled <bool>` | Toggle the cog on/off |
| `!honeypot core action <kick\|ban\|review\|none>` | Main action for suspicious posts |
| `!honeypot core fallback_action <review\|kick\|ban\|none>` | Action for non-suspicious posts |
| `!honeypot core dry_run <bool>` | Log what would happen without punishing |
| `!honeypot core whitelist_mode <bypass\|review\|fallback\|none>` | How whitelisted roles behave |

### channel

| Command | Description |
|---------|-------------|
| `!honeypot channel create` | Create a new `#honeypot` channel at position 0 |
| `!honeypot channel set <channel>` | Use an existing channel as the honeypot |
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
| `!honeypot purge enabled <bool>` | Toggle auto-purge of recent messages |
| `!honeypot purge minutes <1-60>` | Minutes of history to purge |

### fakeactivity

| Command | Description |
|---------|-------------|
| `!honeypot fakeactivity enabled <bool>` | Toggle fake activity messages |
| `!honeypot fakeactivity interval <1-120>` | Minutes between fake messages |
| `!honeypot fakeactivity add <message>` | Add a custom message |
| `!honeypot fakeactivity remove <index>` | Remove a message by index |
| `!honeypot fakeactivity list` | List custom messages |
| `!honeypot fakeactivity reset` | Reset to default messages |

### review

| Command | Description |
|---------|-------------|
| `!honeypot review enabled <bool>` | Toggle moderator review |
| `!honeypot review channel <channel>` | Channel for review requests |
| `!honeypot review timeout <1-10080>` | Minutes before review expires |

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
| `!honeypot keywords attachments add <regex>` | Add filename-base regex (triggers at 4+ matches) |
| `!honeypot keywords attachments remove <regex>` | Remove a filename regex |
| `!honeypot keywords attachments list` | List filename regexes |
| `!honeypot keywords attachments reset` | Reset to default patterns |

### joinwatch

| Command | Description |
|---------|-------------|
| `!honeypot joinwatch enabled <bool>` | Toggle new-account join alerts |
| `!honeypot joinwatch channel <channel>` | Channel for join alerts |
| `!honeypot joinwatch min_age <1-168>` | Max account age in hours to trigger alert |

### other

| Command | Description |
|---------|-------------|
| `!honeypot stats` | Show detection statistics |
| `!honeypot resetstats` | Reset statistics |
| `!honeypot doctor` | Check config, channels, and permissions |

## Action & Fallback Logic

```
suspicious + action = kick/ban  → instant punishment
suspicious + action = review    → review (if channel set), otherwise fallback
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
- Has 4+ attachments with the same filename base (e.g. "image.png", "image.jpg")
- Has 4+ attachments matching configured filename-base regexes

Default scam keywords: `free nitro`, `giveaway`, `steam gift`, `free discord`, `discord.gift`,
`claim your`, `you won`, `free vbucks`, `free robux`, `free coins`, `boost your server`,
`limited time`, `exclusive offer`, `free membership`, `hack`, `crack`, `generator`.

Default attachment patterns: `^image ?\(\d+\)$` (matches `image(1)`, `image (2)`) and
`^[1-4]$` (matches `1.png`, `2.png`).

## Review Flow

1. Message deleted from honeypot channel
2. Recent messages from that user purged (if enabled)
3. Mute role applied while review is pending (if configured)
4. Embed sent to review channel with Kick / Ban / Ignore buttons
5. Attachments copied into the review message
6. Moderators with `Moderate Members` permission can click buttons
7. If review expires, mute role is removed and review marked as timed out
8. Pending reviews survive bot restarts
9. If kicked/banned, mute role is removed first (prevents role persistence bots from saving it)

## Joinwatch

When a user with an account younger than the configured threshold joins, an embed
is sent to the joinwatch channel. No buttons, no actions — just an alert.

## Permissions

- View Channel, Send Messages, Read Message History, Manage Messages (in honeypot channel)
- Send Messages (in logs, review, and joinwatch channels)
- Kick Members (if using kick)
- Ban Members (if using ban)
- Manage Roles (if using review mute role)
- Manage Channels (if using `channel create`)
- Bot role must be above users it punishes and above the mute role

## Intents

- `GUILD_MEMBERS` (privileged) — required for `on_member_join` (joinwatch)
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
