# Honeypot Redbot Cog

This repository contains the `Honeypot` cog for Red-DiscordBot V3.

Install with Red Downloader:

```ini
[p]load downloader
[p]repo add Honeypot https://github.com/Pxx500/Honeypot
[p]cog install Honeypot Honeypot
[p]load Honeypot
```

## Detection case review

Configure a normal text channel as the review destination. The bot posts one
summary message per case and creates a public thread from that message. Every
detected message and its captured attachments are copied into that thread in
chronological order. The review channel must allow the bot to view and send
messages, create public threads, send messages in threads, read message history,
embed links, attach files, and manage threads. Resolved cases receive a final
timeline entry and are then locked and archived.

SQLite remains the source of truth for case state. Captured attachment files are
kept locally until resolution cleanup; Discord messages and attachment uploads
are moderator-facing projections. Red user-data deletion and guild removal also
delete the case summary and thread before removing local evidence and database
rows. If Discord is temporarily unavailable or permissions are missing, the
deletion remains queued and is retried. Image-learning samples have separate
retention controls and may outlive the case evidence from which they were made.
