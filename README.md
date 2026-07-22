# NHCogs

Red-DiscordBot V3 cogs maintained for the NewHorizons Discord server.

## Available cogs

- [`Honeypot`](Honeypot/README.md) detects and reviews suspicious activity,
  captures moderation evidence, and supports automated containment.
- [`NHMisc`](NHMisc/README.md) provides voice logging, sticky roles, activity
  statistics, and other server utilities.

## Installation

`[p]` means your bot prefix.

```ini
[p]load downloader
[p]repo add NHCogs https://github.com/Pxx500/NHCogs
```

Install either or both cogs:

```ini
[p]cog install NHCogs Honeypot
[p]cog install NHCogs NHMisc
[p]load Honeypot
[p]load NHMisc
```

Each cog keeps its own requirements, metadata, documentation, and end-user data
statement in its directory.
