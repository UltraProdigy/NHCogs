# NHMisc

NHMisc is a Red-DiscordBot cog reserved for miscellaneous small bot functionality.

## Installation

```ini
[p]repo add NHMisc https://github.com/Pxx500/NHMisc
[p]cog install NHMisc NHMisc
[p]load NHMisc
```

## Commands

### Voice logs

```ini
[p]voicelog channel #logs
[p]voicelog alert channel #alerts
[p]voicelog rapid channels 3
[p]voicelog rapid seconds 30
[p]voicelog status
```

Voice logs send a message to the configured log channel whenever a user joins, leaves, or
moves between voice channels. Alerts use the configured alert channel. Rapid switching
alerts trigger when a user visits the configured number of different voice channels within
the configured time window.

Defaults:

- Rapid channel count: `3`
- Rapid window: `30` seconds
