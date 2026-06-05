from __future__ import annotations

import logging
import time

import discord
from redbot.core import Config, commands

from .voice_activity import VoiceChannelVisitTracker


log = logging.getLogger("red.NHMisc")

DEFAULT_VCJUMPING_VISIT_COUNT = 3
DEFAULT_VCJUMPING_WINDOW_SECONDS = 30


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
            alert_channel=None,
            vcjumping_visit_count=DEFAULT_VCJUMPING_VISIT_COUNT,
            vcjumping_window_seconds=DEFAULT_VCJUMPING_WINDOW_SECONDS,
        )
        self._voice_visits = VoiceChannelVisitTracker()

    @commands.group(name="nhmisc", invoke_without_command=True)
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def nhmisc(self, ctx: commands.Context) -> None:
        """Configure NHMisc."""
        await ctx.send_help()

    @nhmisc.command(name="channel")
    async def nhmisc_channel(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Set the text channel used for voice event logs."""
        missing_permissions = self._missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)

        await self.config.guild(ctx.guild).voice_log_channel.set(channel.id)
        await ctx.send(f"Voice log channel set to {channel.mention}.")

    @nhmisc.group(name="alert", invoke_without_command=True)
    async def nhmisc_alert(self, ctx: commands.Context) -> None:
        """Configure alert logging."""
        await ctx.send_help()

    @nhmisc_alert.command(name="channel")
    async def nhmisc_alert_channel(
        self, ctx: commands.Context, channel: discord.TextChannel
    ) -> None:
        """Set the text channel used for alert logs."""
        missing_permissions = self._missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)

        await self.config.guild(ctx.guild).alert_channel.set(channel.id)
        await ctx.send(f"Alert channel set to {channel.mention}.")

    @nhmisc.group(name="vcjumping", invoke_without_command=True)
    async def nhmisc_vcjumping(self, ctx: commands.Context) -> None:
        """Configure voice channel jumping detection."""
        await ctx.send_help()

    @nhmisc_vcjumping.command(name="visits", aliases=["channels"])
    async def nhmisc_vcjumping_visits(self, ctx: commands.Context, count: int) -> None:
        """Set how many voice channel entries trigger VC jumping alerts."""
        if count < 2:
            raise commands.UserFeedbackCheckFailure("VC jumping visit count must be at least 2.")

        await self.config.guild(ctx.guild).vcjumping_visit_count.set(count)
        await ctx.send(f"VC jumping alerts will trigger after {count} channel entries.")

    @nhmisc_vcjumping.command(name="seconds")
    async def nhmisc_vcjumping_seconds(self, ctx: commands.Context, seconds: int) -> None:
        """Set the VC jumping detection time window in seconds."""
        if seconds < 1:
            raise commands.UserFeedbackCheckFailure("VC jumping window must be at least 1 second.")

        await self.config.guild(ctx.guild).vcjumping_window_seconds.set(seconds)
        await ctx.send(f"VC jumping window set to {seconds} seconds.")

    @nhmisc.command(name="status")
    async def nhmisc_status(self, ctx: commands.Context) -> None:
        """Show the current voice log configuration."""
        config = await self.config.guild(ctx.guild).all()
        channel = self._get_log_channel(ctx.guild, config["voice_log_channel"])
        alert_channel = self._get_log_channel(ctx.guild, config["alert_channel"])
        channel_label = channel.mention if channel is not None else "not set"
        alert_channel_label = alert_channel.mention if alert_channel is not None else "not set"
        await ctx.send(
            "Voice log channel: {channel}\n"
            "Alert channel: {alert_channel}\n"
            "VC jumping: {count} channel entries in {seconds} seconds.".format(
                channel=channel_label,
                alert_channel=alert_channel_label,
                count=config["vcjumping_visit_count"],
                seconds=config["vcjumping_window_seconds"],
            )
        )

    @commands.Cog.listener()
    async def on_voice_state_update(
        self,
        member: discord.Member,
        before: discord.VoiceState,
        after: discord.VoiceState,
    ) -> None:
        """Log voice channel joins, leaves, moves, and VC jumping."""
        if before.channel == after.channel:
            return

        guild = member.guild
        config = await self.config.guild(guild).all()
        log_channel = self._get_log_channel(guild, config["voice_log_channel"])

        if log_channel is not None:
            if before.channel is None and after.channel is not None:
                await self._send_voice_log(
                    log_channel,
                    (
                        f"{member.mention} ({member.id}) has joined a channel "
                        f"{after.channel.mention} at <t:{int(time.time())}:F>"
                    ),
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

        is_vcjumping = self._voice_visits.record_visit(
            (guild.id, member.id),
            after.channel.id,
            timestamp=time.monotonic(),
            visit_count=config["vcjumping_visit_count"],
            window_seconds=config["vcjumping_window_seconds"],
        )
        if is_vcjumping:
            alert_channel = self._get_log_channel(guild, config["alert_channel"])
            if alert_channel is None:
                return

            await self._send_voice_log(
                alert_channel,
                (
                    f"{member.mention} is VC jumping "
                    f"({config['vcjumping_visit_count']} channel entries in "
                    f"{config['vcjumping_window_seconds']} seconds)."
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
