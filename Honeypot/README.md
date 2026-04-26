# Honeypot

Honeypot is a Red-DiscordBot cog that creates a visible trap channel for self-bots, scammers, spam accounts, and suspicious users. Messages posted in the configured honeypot channel are deleted, logged, optionally purged from recent history, and then either punished automatically or sent to moderators for review.

## Main Features

- Creates a dedicated `#honeypot` channel at the top of the server.
- Detects suspicious posts using links, scam keywords, new-account age, and attachments from newer accounts.
- Supports automatic `mute`, `kick`, or `ban` actions.
- Supports moderator review for less obvious cases.
- Applies the configured mute role while a user is waiting for moderator review.
- Deletes the triggering message immediately.
- Optionally purges recent messages from the same user in the honeypot channel.
- Supports whitelisted roles that are logged but not punished.
- Supports a ping role for alerts.
- Can post fake activity messages to make the trap channel look active.
- Creates Red modlog cases for punishment actions when possible.

## Installation

```ini
[p]repo add AAA3A-cogs https://github.com/AAA3A-AAA3A/AAA3A-cogs
[p]cog install AAA3A-cogs honeypot
[p]load honeypot
```

This cog also requires `AAA3A_utils`. If the dependency is missing, Red will show a load error with the required pip install command.

## Recommended Setup

1. Create the trap channel:

```ini
[p]sethoneypot createchannel
```

2. Set a logs channel:

```ini
[p]sethoneypot logschannel #mod-logs
```

3. Choose an action:

```ini
[p]sethoneypot action ban
```

4. If using `mute`, configure the mute role:

```ini
[p]sethoneypot muterole @Muted
```

5. Optionally configure review mode:

```ini
[p]sethoneypot reviewenabled true
[p]sethoneypot reviewchannel #mod-review
```

6. Optionally configure alert pings:

```ini
[p]sethoneypot pingrole @Moderators
```

7. Enable the cog:

```ini
[p]sethoneypot enabled true
```

## Commands

Only the server owner can use the `sethoneypot` command group.

### Core Commands

- `[p]sethoneypot` - Main configuration group.
- `[p]sethoneypot createchannel` - Creates and stores the honeypot channel.
- `[p]sethoneypot makechannel` - Alias for `createchannel`.
- `[p]sethoneypot showsettings [with_dev=False]` - Shows current settings.
- `[p]sethoneypot resetsetting <setting>` - Resets one setting.
- `[p]sethoneypot modalconfig [confirmation=False]` - Opens the generated modal configuration flow.

### Generated Settings Commands

- `[p]sethoneypot enabled <true|false>` - Enables or disables detection.
- `[p]sethoneypot action <mute|kick|ban>` - Sets the automatic punishment.
- `[p]sethoneypot honeypotchannel <channel>` - Sets the trap channel.
- `[p]sethoneypot logschannel <channel>` - Sets the logging channel.
- `[p]sethoneypot pingrole <role>` - Sets the role to ping on alerts.
- `[p]sethoneypot muterole <role>` - Sets the role used by the `mute` action.
- `[p]sethoneypot bandeletemessagedays <0-7>` - Sets how many days of messages are deleted on ban.
- `[p]sethoneypot purgeenabled <true|false>` - Enables recent-message purge in the honeypot channel.
- `[p]sethoneypot purgeminutes <1-60>` - Sets how far back the purge should look.
- `[p]sethoneypot fakeactivityenabled <true|false>` - Enables fake activity messages.
- `[p]sethoneypot fakeactivityinterval <1-120>` - Sets fake activity interval in minutes.
- `[p]sethoneypot reviewenabled <true|false>` - Enables moderator review for non-obvious cases.
- `[p]sethoneypot reviewchannel <channel>` - Sets the review queue channel.

### Whitelisted Roles

- `[p]sethoneypot whitelistedroles add <role>` - Adds a role that bypasses punishment.
- `[p]sethoneypot whitelistedroles remove <role>` - Removes a role from the whitelist.
- `[p]sethoneypot whitelistedroles list` - Lists whitelisted roles.
- `[p]sethoneypot wlroles ...` - Alias for `whitelistedroles`.

### Fake Activity Messages

- `[p]sethoneypot fakeactivity add <message>` - Adds a custom fake activity message.
- `[p]sethoneypot fakeactivity remove <index>` - Removes a custom message by list index.
- `[p]sethoneypot fakeactivity list` - Lists custom fake activity messages.
- `[p]sethoneypot fakeactivity reset` - Clears custom messages and returns to defaults.
- `[p]sethoneypot fakemsg ...` - Alias for `fakeactivity`.

## Detection Behavior

A message in the honeypot channel is considered suspicious if any of these are true:

- It contains an HTTP or HTTPS link.
- The author account is less than 7 days old.
- The content contains known scam keywords such as free Nitro, giveaway, generator, claim your, or similar phrases.
- It has attachments and the author account is less than 30 days old.

Suspicious messages are punished immediately using the configured automatic action.

Messages that are not obviously suspicious can be sent to the review channel if review mode is enabled. If review mode is disabled or no review channel is configured, the automatic action is used anyway.

## Review Flow

When review mode is enabled and a non-obvious message appears in the honeypot channel:

- The original message is deleted.
- Recent honeypot messages from that user may be purged.
- If a mute role is configured and the user does not already have it, the mute role is applied while review is pending.
- A review embed is sent to the configured review channel.
- Attachments are copied into the review message when possible.
- Moderators with `Moderate Members` permission can choose `Kick`, `Ban`, `Mute`, or `Ignore`.
- If moderators choose `Ignore`, the pending mute role is removed when it was applied by this review flow.
- Once a moderator acts, the review buttons are disabled and the embed records who reviewed it.

## Permissions Needed

The bot should have these permissions in the relevant channels and server:

- View Channel
- Send Messages
- Manage Messages
- Manage Channels, if using `createchannel`
- Kick Members, if using `kick`
- Ban Members, if using `ban`
- Manage Roles, if using `mute`
- Access to the configured logs and review channels

The bot role must be higher than users it needs to punish and higher than the configured mute role.

## Data Storage

The cog stores only guild configuration: channel IDs, role IDs, booleans, numeric settings, and custom fake activity messages. It does not persistently store user metadata.

## Operational Notes

- Users with whitelisted roles are still logged, but no punishment is applied.
- Bot owners, mods, admins, users with `Manage Server`, and users above or equal to the bot's top role are ignored.
- Triggering messages are deleted before punishment or review.
- In review mode, a configured mute role is used as temporary containment until moderators decide.
- The purge only scans recent messages in the honeypot channel, not the entire server.
- Fake activity runs once per minute internally and only posts when the configured interval has elapsed.
