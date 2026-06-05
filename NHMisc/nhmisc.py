from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

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
        self._audit_log_tasks: set[asyncio.Task] = set()

    def cog_unload(self) -> None:
        for task in self._audit_log_tasks:
            task.cancel()

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
        event_timestamp = int(time.time())

        if log_channel is not None:
            if before.channel is None and after.channel is not None:
                await self._send_voice_log(
                    log_channel,
                    (
                        f"{member.mention} ({member.id}) has joined a channel "
                        f"{after.channel.mention} at <t:{event_timestamp}:F>"
                    ),
                )
            elif before.channel is not None and after.channel is None:
                await self._send_voice_log(
                    log_channel,
                    (
                        f"{member.mention} ({member.id}) has left a channel "
                        f"{before.channel.mention} at <t:{event_timestamp}:F>"
                    ),
                )
            elif before.channel is not None and after.channel is not None:
                move_log_content = (
                    f"{member.mention} ({member.id}) has moved from "
                    f"{before.channel.mention} to {after.channel.mention} "
                    f"at <t:{event_timestamp}:F>"
                )
                move_log_message = await self._send_voice_log(
                    log_channel,
                    move_log_content,
                )
                if move_log_message is not None:
                    self._schedule_audit_log_edit(
                        move_log_message,
                        move_log_content,
                        guild,
                        member,
                        after.channel,
                        event_timestamp,
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

    def _schedule_audit_log_edit(
        self,
        message: discord.Message,
        base_content: str,
        guild: discord.Guild,
        member: discord.Member,
        after_channel: discord.VoiceChannel | discord.StageChannel,
        event_timestamp: int,
    ) -> None:
        task = asyncio.create_task(
            self._edit_move_log_with_moderator(
                message,
                base_content,
                guild,
                member,
                after_channel,
                event_timestamp,
            )
        )
        self._audit_log_tasks.add(task)
        task.add_done_callback(self._audit_log_tasks.discard)

    async def _edit_move_log_with_moderator(
        self,
        message: discord.Message,
        base_content: str,
        guild: discord.Guild,
        member: discord.Member,
        after_channel: discord.VoiceChannel | discord.StageChannel,
        event_timestamp: int,
    ) -> None:
        for attempt in range(5):
            if attempt > 0:
                await asyncio.sleep(2)

            moved_by = await self._get_voice_move_moderator(
                guild, member, after_channel, event_timestamp
            )
            if moved_by is None:
                continue

            try:
                timestamp_suffix = f" at <t:{event_timestamp}:F>"
                edited_content = base_content.replace(
                    timestamp_suffix,
                    f" moved by {self._format_user_label(moved_by)}{timestamp_suffix}",
                    1,
                )
                await message.edit(
                    content=edited_content,
                )
            except discord.HTTPException:
                log.exception("Failed to edit voice move log message %s", message.id)
            return

    async def _get_voice_move_moderator(
        self,
        guild: discord.Guild,
        member: discord.Member,
        after_channel: discord.VoiceChannel | discord.StageChannel,
        event_timestamp: int,
    ) -> discord.User | discord.Member | None:
        me = guild.me
        if me is None or not me.guild_permissions.view_audit_log:
            return None

        event_time = datetime.fromtimestamp(event_timestamp, timezone.utc)
        try:
            async for entry in guild.audit_logs(
                limit=5,
                action=discord.AuditLogAction.member_move,
            ):
                created_at = entry.created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)

                if abs((created_at - event_time).total_seconds()) > 15:
                    continue

                target_id = getattr(entry.target, "id", None)
                if target_id == member.id:
                    return entry.user

                extra = getattr(entry, "extra", None)
                extra_channel = getattr(extra, "channel", None)
                extra_count = getattr(extra, "count", None)
                if (
                    target_id is None
                    and getattr(extra_channel, "id", None) == after_channel.id
                    and str(extra_count) == "1"
                ):
                    return entry.user
        except discord.Forbidden:
            return None
        except discord.HTTPException:
            log.exception("Failed to read audit log for voice move in guild %s", guild.id)
        return None

    def _format_user_label(self, user: discord.User | discord.Member) -> str:
        name = getattr(user, "display_name", None) or str(user)
        return f"{name} ({user.id})"

    async def _send_voice_log(
        self, channel: discord.TextChannel, content: str
    ) -> discord.Message | None:
        try:
            return await channel.send(content, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            log.exception("Failed to send voice log message to channel %s", channel.id)
        return None
