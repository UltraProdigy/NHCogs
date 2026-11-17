# NHCogs

Red-DiscordBot V3 cogs maintained for the NewHorizons Discord server.

Read the [NHBot privacy policy](PRIVACY.md) for data use, retention, and requests.
See the [NHBot Terms of Service](TERMS_OF_SERVICE.md) for use of the official bot service.

## Available cogs

The combined `NHCogs` extension loads the maintained cogs:

- [`Honeypot`](NHCogs/honeypot/README.md) detects and reviews suspicious activity,
  captures moderation evidence, and supports automated containment.
- [`NHMisc`](NHCogs/nhmisc/README.md) provides voice logging, sticky roles, activity
  statistics, and other server utilities.
- [`CustomCommands`](NHCogs/custom_commands/README.md) provides weighted text commands,
  Red-compatible placeholders, and thread-based moderator editing.
- [`GitHubTickets`](NHCogs/githubtickets/README.md) publishes pull request review tickets,
  manages developer expertise profiles, and routes reviewer requests.

The combined extension also provides shared technical error reporting. See the
[NHCogs command catalog](NHCogs/README.md) for its configuration commands.

## Installation

`[p]` means your bot prefix.

```ini
[p]load downloader
[p]repo add NHCogs https://github.com/Pxx500/NHCogs
```

```ini
[p]cog install NHCogs NHCogs
[p]load NHCogs
```


https://www.youtube.com/watch?v=3TNpOD6bov8&t=83s
