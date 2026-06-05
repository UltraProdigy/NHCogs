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
[p]nhmisc channel #logs
[p]nhmisc alert channel #alerts
[p]nhmisc vcjumping visits 3
[p]nhmisc vcjumping seconds 30
[p]nhmisc status
```

Voice logs send a message to the configured log channel whenever a user joins, leaves, or
moves between voice channels. Alerts use the configured alert channel. VC jumping
alerts trigger when a user enters any voice channel the configured number of times within
the configured time window. Re-entering the same voice channel still counts.

Defaults:

- VC jumping visit count: `3`
- VC jumping window: `30` seconds
