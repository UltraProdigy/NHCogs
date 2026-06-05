from __future__ import annotations

import logging
import time

import discord
from redbot.core import Config, commands

from .voice_activity import VoiceChannelVisitTracker


log = logging.getLogger("red.NHMisc")

DEFAULT_RAPID_CHANNEL_COUNT = 3
DEFAULT_RAPID_WINDOW_SECONDS = 30


class NHMisc(commands.Cog):
    """Miscellaneous small utilities for Red-DiscordBot."""

    def __init__(self, bot):
        super().__init__()
        self.bot = bot
        self.config = Config.get_conf(
            self,
            identifier=8597423150612235807,
            force_registration=True,
        )
        self.config.register_guild(
            voice_log_channel=None,
            rapid_channel_count=DEFAULT_RAPID_CHANNEL_COUNT,
            rapid_window_seconds=DEFAULT_RAPID_WINDOW_SECONDS,
        )
        self._voice_visits = VoiceChannelVisitTracker()

    @commands.group(name="voicelog", invoke_without_command=True)
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def voicelog(self, ctx: commands.Context) -> None:
        """Configure voice channel event logging."""
        await ctx.send_help()

    @voicelog.command(name="channel")
    async def voicelog_channel(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Set the text channel used for voice event logs."""
        missing_permissions = self._missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)

        await self.config.guild(ctx.guild).voice_log_channel.set(channel.id)
        await ctx.send(f"Voice log channel set to {channel.mention}.")

    @voicelog.group(name="rapid", invoke_without_command=True)
    async def voicelog_rapid(self, ctx: commands.Context) -> None:
        """Configure rapid voice channel switching detection."""
        await ctx.send_help()

    @voicelog_rapid.command(name="channels")
    async def voicelog_rapid_channels(self, ctx: commands.Context, count: int) -> None:
        """Set how many distinct voice channels trigger rapid-switch logging."""
        if count < 2:
            raise commands.UserFeedbackCheckFailure("Rapid channel count must be at least 2.")

        await self.config.guild(ctx.guild).rapid_channel_count.set(count)
        await ctx.send(f"Rapid voice switching will trigger after {count} different channels.")

    @voicelog_rapid.command(name="seconds")
    async def voicelog_rapid_seconds(self, ctx: commands.Context, seconds: int) -> None:
        """Set the rapid-switch detection time window in seconds."""
        if seconds < 1:
            raise commands.UserFeedbackCheckFailure("Rapid switching window must be at least 1 second.")

        await self.config.guild(ctx.guild).rapid_window_seconds.set(seconds)
        await ctx.send(f"Rapid voice switching window set to {seconds} seconds.")

    @voicelog.command(name="status")
    async def voicelog_status(self, ctx: commands.Context) -> None:
        """Show the current voice log configuration."""
        config = await self.config.guild(ctx.guild).all()
        channel = self._get_log_channel(ctx.guild, config["voice_log_channel"])
        channel_label = channel.mention if channel is not None else "not set"
        await ctx.send(
            "Voice log channel: {channel}\n"
            "Rapid switching: {count} different channels in {seconds} seconds.".format(
                channel=channel_label,
                count=config["rapid_channel_count"],
                seconds=config["rapid_window_seconds"],
            )
        )

    @commands.Cog.listener()
    async def on_voice_state_update(
        self,
        member: discord.Member,
        before: discord.VoiceState,
        after: discord.VoiceState,
    ) -> None:
        """Log voice channel joins, leaves, moves, and rapid channel switching."""
        if before.channel == after.channel:
            return

        guild = member.guild
        config = await self.config.guild(guild).all()
        log_channel = self._get_log_channel(guild, config["voice_log_channel"])
        if log_channel is None:
            return

        if before.channel is None and after.channel is not None:
            await self._send_voice_log(
                log_channel,
                f"{member.mention} has joined a channel {after.channel.mention}",
            )
        elif before.channel is not None and after.channel is None:
            await self._send_voice_log(
                log_channel,
                f"{member.mention} has left a channel {before.channel.mention}",
            )
        elif before.channel is not None and after.channel is not None:
            await self._send_voice_log(
                log_channel,
                (
                    f"{member.mention} has moved from {before.channel.mention} "
                    f"to {after.channel.mention}"
                ),
            )

        if after.channel is None:
            return

        is_rapid_switching = self._voice_visits.record_visit(
            (guild.id, member.id),
            after.channel.id,
            timestamp=time.monotonic(),
            channel_count=config["rapid_channel_count"],
            window_seconds=config["rapid_window_seconds"],
        )
        if is_rapid_switching:
            await self._send_voice_log(
                log_channel,
                (
                    f"{member.mention} is rapidly changing channels "
                    f"({config['rapid_channel_count']} different channels in "
                    f"{config['rapid_window_seconds']} seconds)."
                ),
            )

    def _get_log_channel(
        self, guild: discord.Guild, channel_id: int | None
    ) -> discord.TextChannel | None:
        if channel_id is None:
            return None

        channel = guild.get_channel(channel_id) or self.bot.get_channel(channel_id)
        if isinstance(channel, discord.TextChannel):
            return channel
        return None

    def _missing_log_permissions(
        self, guild: discord.Guild, channel: discord.TextChannel
    ) -> str | None:
        me = guild.me
        permissions = channel.permissions_for(me)
        if not permissions.view_channel:
            return f"I need permission to view {channel.mention}."
        if not permissions.send_messages:
            return f"I need permission to send messages in {channel.mention}."
        return None

    async def _send_voice_log(self, channel: discord.TextChannel, content: str) -> None:
        try:
            await channel.send(content, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            log.exception("Failed to send voice log message to channel %s", channel.id)
