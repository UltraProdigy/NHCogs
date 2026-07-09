from __future__ import annotations

import asyncio
import io
import logging
import time
from datetime import date, datetime, time as datetime_time, timedelta, timezone

import discord
from redbot.core import Config, commands
from redbot.core.data_manager import cog_data_path

from .activity_storage import (
    ActivityStore,
    ChannelTimelineDay,
    ChannelUserCount,
    DailySummary,
    TimelineDay,
    TopChannel,
    UserStats,
)
from .sticky_roles import StickyRoleStore
from .voice_activity import VoiceChannelVisitTracker


log = logging.getLogger("red.NHMisc")

DEFAULT_VCJUMPING_VISIT_COUNT = 3
DEFAULT_VCJUMPING_WINDOW_SECONDS = 30
DEFAULT_ACTIVITY_DETAIL_RETENTION_DAYS = 31
DEFAULT_ACTIVITY_HISTORY_RETENTION_DAYS = -1
RETENTION_CONFIRMATION = "I understand"


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
            activity_channel=None,
            activity_detail_retention_days=DEFAULT_ACTIVITY_DETAIL_RETENTION_DAYS,
            activity_history_retention_days=DEFAULT_ACTIVITY_HISTORY_RETENTION_DAYS,
            sticky_debug_logging_enabled=False,
            sticky_debug_logging_channel=None,
        )
        self._voice_visits = VoiceChannelVisitTracker()
        self._audit_log_tasks: set[asyncio.Task] = set()
        self._activity_store = ActivityStore(cog_data_path(self) / "activity.sqlite")
        self._sticky_roles = StickyRoleStore(cog_data_path(self) / "sticky_roles.sqlite")
        self._activity_task: asyncio.Task | None = None

    async def cog_load(self) -> None:
        await self._activity_store.initialize()
        await self._sticky_roles.initialize()
        self._activity_task = asyncio.create_task(self._activity_midnight_loop())

    def cog_unload(self) -> None:
        for task in self._audit_log_tasks:
            task.cancel()
        if self._activity_task is not None:
            self._activity_task.cancel()

    @commands.group(name="nhmisc", invoke_without_command=True)
    @commands.guild_only()
    async def nhmisc(self, ctx: commands.Context) -> None:
        """Configure NHMisc."""
        await ctx.send_help()

    @nhmisc.command(name="channel")
    @commands.admin_or_permissions(manage_guild=True)
    async def nhmisc_channel(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Set the text channel used for voice event logs."""
        missing_permissions = self._missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)

        await self.config.guild(ctx.guild).voice_log_channel.set(channel.id)
        await ctx.send(f"Voice log channel set to {channel.mention}.")

    @nhmisc.group(name="alert", invoke_without_command=True)
    @commands.admin_or_permissions(manage_guild=True)
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
    @commands.admin_or_permissions(manage_guild=True)
    async def nhmisc_vcjumping(self, ctx: commands.Context) -> None:
        """Configure voice channel jumping detection."""
        await ctx.send_help()

    @nhmisc_vcjumping.command(name="visits")
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
    @commands.admin_or_permissions(manage_guild=True)
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

    @nhmisc.group(name="stickyroles", invoke_without_command=True)
    async def nhmisc_stickyroles(self, ctx: commands.Context) -> None:
        """Configure sticky role persistence."""
        await self._require_manage_guild(ctx)
        await ctx.send_help()

    @nhmisc_stickyroles.command(name="add")
    async def nhmisc_stickyroles_add(self, ctx: commands.Context, role: str) -> None:
        """Mark a role as sticky by role mention or raw role ID."""
        await self._require_manage_guild(ctx)
        role_id = self._parse_role_id(role)
        discord_role = ctx.guild.get_role(role_id)
        if discord_role is None:
            raise commands.UserFeedbackCheckFailure("That role does not exist on this server.")
        if not self._can_restore_role(ctx.guild, discord_role):
            raise commands.UserFeedbackCheckFailure(
                "I cannot restore that role. Check Manage Roles and role hierarchy."
            )

        added = await self._sticky_roles.add_sticky_role(ctx.guild.id, role_id)
        if added:
            await ctx.send(
                f"{discord_role.mention} is now sticky.",
                allowed_mentions=discord.AllowedMentions.none(),
            )
        else:
            await ctx.send(
                f"{discord_role.mention} is already sticky.",
                allowed_mentions=discord.AllowedMentions.none(),
            )

    @nhmisc_stickyroles.command(name="remove")
    async def nhmisc_stickyroles_remove(self, ctx: commands.Context, role: str) -> None:
        """Remove a sticky role by role mention or raw role ID."""
        await self._require_manage_guild(ctx)
        role_id = self._parse_role_id(role)
        config_exists, saved_rows = await self._sticky_roles.get_role_state(
            ctx.guild.id, role_id
        )
        if not config_exists and saved_rows == 0:
            await ctx.send(
                f"{self._format_role_reference(ctx.guild, role_id)} is not present in the sticky role DB.",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return

        await self._prompt_sticky_role_db_action(
            guild=ctx.guild,
            channel=ctx.channel,
            role_id=role_id,
            role_name=self._role_name_for_prompt(ctx.guild, role_id),
            config_exists=config_exists,
            saved_rows=saved_rows,
            reason="manual remove command",
            requester=ctx.author,
        )

    @nhmisc_stickyroles.command(name="list")
    async def nhmisc_stickyroles_list(self, ctx: commands.Context) -> None:
        """List sticky roles configured for this server."""
        await self._require_manage_guild(ctx)
        role_ids = await self._sticky_roles.get_sticky_roles(ctx.guild.id)
        if not role_ids:
            await ctx.send("No sticky roles are configured on this server.")
            return

        lines = ["Sticky roles:"]
        for role_id in sorted(role_ids):
            lines.append(f"- {self._format_role_reference(ctx.guild, role_id)}")
        await self._send_paginated_text(ctx, "\n".join(lines))

    @nhmisc_stickyroles.command(name="scan")
    async def nhmisc_stickyroles_scan(self, ctx: commands.Context) -> None:
        """Scan sticky role DB for role IDs missing from Discord."""
        await self._require_manage_guild(ctx)
        existing_role_ids = {role.id for role in ctx.guild.roles}
        orphaned_roles = await self._sticky_roles.get_orphaned_roles(
            ctx.guild.id, existing_role_ids
        )
        if not orphaned_roles:
            await ctx.send("No sticky role DB entries need review.")
            return

        await ctx.send(
            f"Found {len(orphaned_roles)} sticky role DB entries that need review. "
            "I will ask about them one by one."
        )
        for role_id, config_exists, saved_rows in orphaned_roles:
            await self._prompt_sticky_role_db_action(
                guild=ctx.guild,
                channel=ctx.channel,
                role_id=role_id,
                role_name=None,
                config_exists=config_exists,
                saved_rows=saved_rows,
                reason="manual orphan scan",
                requester=ctx.author,
            )

    @nhmisc_stickyroles.group(name="debuglogging", invoke_without_command=True)
    async def nhmisc_stickyroles_debuglogging(self, ctx: commands.Context) -> None:
        """Configure sticky role debug logging."""
        await self._require_manage_guild(ctx)
        await ctx.send_help()

    @nhmisc_stickyroles_debuglogging.command(name="toggle")
    async def nhmisc_stickyroles_debuglogging_toggle(
        self, ctx: commands.Context, enabled: bool
    ) -> None:
        """Enable or disable sticky role debug logging."""
        await self._require_manage_guild(ctx)
        await self.config.guild(ctx.guild).sticky_debug_logging_enabled.set(enabled)
        state = "enabled" if enabled else "disabled"
        await ctx.send(f"Sticky role debug logging {state}.")

    @nhmisc_stickyroles_debuglogging.command(name="channel")
    async def nhmisc_stickyroles_debuglogging_channel(
        self, ctx: commands.Context, channel: discord.TextChannel
    ) -> None:
        """Set the sticky role debug logging channel."""
        await self._require_manage_guild(ctx)
        missing_permissions = self._missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)

        await self.config.guild(ctx.guild).sticky_debug_logging_channel.set(channel.id)
        await ctx.send(f"Sticky role debug logging channel set to {channel.mention}.")

    @nhmisc.group(name="activity", invoke_without_command=True)
    async def nhmisc_activity(self, ctx: commands.Context) -> None:
        """Configure and inspect passive message activity summaries."""
        await ctx.send_help()

    @nhmisc_activity.command(name="channel")
    async def nhmisc_activity_channel(
        self, ctx: commands.Context, channel: discord.TextChannel
    ) -> None:
        """Set the channel used for automatic daily activity summaries."""
        await self._require_manage_guild(ctx)
        missing_permissions = self._missing_log_permissions(ctx.guild, channel)
        if missing_permissions is not None:
            raise commands.UserFeedbackCheckFailure(missing_permissions)

        await self.config.guild(ctx.guild).activity_channel.set(channel.id)
        await ctx.send(f"Activity summary channel set to {channel.mention}.")

    @nhmisc_activity.command(name="current")
    async def nhmisc_activity_current(self, ctx: commands.Context) -> None:
        """Preview the current UTC day's activity without closing it."""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        today = self._utc_today()
        summary = await self._activity_store.build_current_summary(
            ctx.guild.id, today, ctx.guild.member_count or 0
        )
        if summary is None:
            await ctx.send("No activity data has been collected for the current UTC day.")
            return

        await ctx.send(embed=self._build_daily_summary_embed(summary, title_prefix="Current day"))

    @nhmisc_activity.command(name="latest")
    async def nhmisc_activity_latest(self, ctx: commands.Context) -> None:
        """Repost the latest retained closed daily activity summary."""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        summary = await self._activity_store.get_latest_summary(ctx.guild.id)
        if summary is None:
            await ctx.send("No retained daily activity summary is available.")
            return

        await ctx.send(embed=self._build_daily_summary_embed(summary, title_prefix="Latest day"))

    @nhmisc_activity.command(name="timeline")
    async def nhmisc_activity_timeline(self, ctx: commands.Context, days: int) -> None:
        """Show a compact timeline for retained closed daily summaries."""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Days must be at least 1.")

        config = await self.config.guild(ctx.guild).all()
        history_retention = int(config["activity_history_retention_days"])
        if history_retention == 0:
            await ctx.send("Historical activity summaries are not retained on this server.")
            return
        if history_retention > 0 and days > history_retention:
            days = history_retention

        end_date = self._utc_today() - timedelta(days=1)
        timeline = await self._activity_store.get_timeline(ctx.guild.id, end_date, days)
        top_channels = await self._activity_store.get_timeline_top_channels(
            ctx.guild.id, end_date, days
        )
        await ctx.send(embed=self._build_timeline_embed(timeline, top_channels, days))

    @nhmisc_activity.command(name="channelstats")
    async def nhmisc_activity_channelstats(
        self, ctx: commands.Context, channel: discord.TextChannel, days: int
    ) -> None:
        """Show message activity for a channel day by day."""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Days must be at least 1.")

        config = await self.config.guild(ctx.guild).all()
        history_retention = int(config["activity_history_retention_days"])
        detail_retention = max(1, int(config["activity_detail_retention_days"]))
        if history_retention == 0:
            days = min(days, detail_retention)
        elif history_retention > 0:
            days = min(days, max(history_retention, detail_retention))

        timeline = await self._activity_store.get_channel_timeline(
            ctx.guild.id,
            channel.id,
            None,
            self._utc_today(),
            days,
        )
        await ctx.send(embed=self._build_channel_timeline_embed(channel, timeline, days))

    @nhmisc_activity.command(name="retention")
    async def nhmisc_activity_retention(self, ctx: commands.Context, days: int) -> None:
        """Set how many days of per-user/channel detail rows are retained."""
        await self._require_manage_guild(ctx)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Detail retention must be at least 1 day.")

        cutoff = self._utc_today() - timedelta(days=days - 1)
        rows_to_delete = await self._activity_store.count_detail_rows_older_than(
            ctx.guild.id, cutoff
        )
        if rows_to_delete:
            confirmed = await self._confirm_retention_delete(
                ctx,
                (
                    f"Changing detail retention to {days} days will permanently delete "
                    f"{rows_to_delete} user/channel detail rows older than {cutoff.isoformat()}.\n"
                    f"Reply with `{RETENTION_CONFIRMATION}` to continue."
                ),
            )
            if not confirmed:
                return
            deleted = await self._activity_store.prune_detail_rows_older_than(ctx.guild.id, cutoff)
            await ctx.send(f"Deleted {deleted} detail rows.")

        await self.config.guild(ctx.guild).activity_detail_retention_days.set(days)
        await ctx.send(f"Activity detail retention set to {days} days.")

    @nhmisc_activity.command(name="historyretention")
    async def nhmisc_activity_history_retention(self, ctx: commands.Context, days: int) -> None:
        """Set how many closed daily aggregate summaries are retained."""
        await self._require_manage_guild(ctx)
        if days < -1:
            raise commands.UserFeedbackCheckFailure(
                "History retention must be -1, 0, or a positive number of days."
            )

        cutoff = self._history_retention_cutoff(days)
        summary_rows = top_rows = channel_rows = 0
        if cutoff is not None:
            (
                summary_rows,
                top_rows,
                channel_rows,
            ) = await self._activity_store.count_history_rows_older_than(ctx.guild.id, cutoff)
        if summary_rows or top_rows or channel_rows:
            confirmed = await self._confirm_retention_delete(
                ctx,
                (
                    f"Changing history retention to {days} will permanently delete "
                    f"{summary_rows} daily summary rows, {top_rows} top-channel rows, "
                    f"and {channel_rows} channel summary rows "
                    f"older than {cutoff.isoformat()}.\n"
                    f"Reply with `{RETENTION_CONFIRMATION}` to continue."
                ),
            )
            if not confirmed:
                return
            (
                deleted_summary,
                deleted_top,
                deleted_channel,
            ) = await self._activity_store.prune_history_rows_older_than(ctx.guild.id, cutoff)
            await ctx.send(
                f"Deleted {deleted_summary} daily summary rows, {deleted_top} top-channel rows, "
                f"and {deleted_channel} channel summary rows."
            )

        await self.config.guild(ctx.guild).activity_history_retention_days.set(days)
        await ctx.send(f"Activity history retention set to {days}.")

    @nhmisc.command(name="usermodstats")
    async def nhmisc_usermodstats(
        self, ctx: commands.Context, target: str, range_text: str
    ) -> None:
        """Show moderator-only message activity stats for a user."""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        user_id = self._parse_user_id(target)
        days = self._parse_range_days(range_text)
        days = await self._cap_detail_days(ctx.guild, days)
        end_date = self._utc_today()
        stats = await self._activity_store.get_user_stats(ctx.guild.id, user_id, end_date, days)

        title = f"User activity: {self._format_user_reference(ctx.guild, user_id)}"
        await ctx.send(embed=self._build_user_stats_embed(title, stats, days))

    @nhmisc.command(name="chatchart")
    async def nhmisc_chatchart(self, ctx: commands.Context, days: int) -> None:
        """Render a pie chart of user activity in the current channel."""
        await self._require_activity_staff(ctx)
        await self._close_stale_activity_days_for_guild(ctx.guild, send_reports=True)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Days must be at least 1.")

        days = await self._cap_detail_days(ctx.guild, days)
        channel_id = self._activity_parent_channel_id(ctx.channel)
        counts = await self._activity_store.get_channel_user_counts(
            ctx.guild.id,
            channel_id,
            self._activity_thread_id(ctx.channel),
            self._utc_today(),
            days,
        )
        if not counts:
            await ctx.send(f"No retained activity data for this channel in the last {days} days.")
            return

        file = self._build_chatchart_file(ctx.guild, counts, days)
        await ctx.send(
            file=file,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @commands.command(name="selfchart")
    @commands.guild_only()
    async def selfchart(self, ctx: commands.Context) -> None:
        """Show your own simplified activity stats for the last 7 retained days."""
        days = await self._cap_detail_days(ctx.guild, 7)
        stats = await self._activity_store.get_user_stats(
            ctx.guild.id, ctx.author.id, self._utc_today(), days
        )
        embed = self._build_selfchart_embed(ctx.author, stats, days)
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member) -> None:
        """Snapshot configured sticky roles when a member leaves."""
        configured_roles = await self._sticky_roles.get_sticky_roles(member.guild.id)
        if not configured_roles:
            await self._send_sticky_debug_log(
                member.guild,
                (
                    "Sticky role snapshot write skipped\n"
                    f"User: {member.mention} (`{member.id}`)\n"
                    "Reason: no sticky roles are configured on this server."
                ),
            )
            return

        current_role_ids = {role.id for role in member.roles}
        saved_role_ids = configured_roles & current_role_ids
        await self._sticky_roles.replace_member_roles(
            member.guild.id,
            member.id,
            saved_role_ids,
        )
        await self._send_sticky_debug_log(
            member.guild,
            (
                "Sticky role snapshot written\n"
                f"User: {member.mention} (`{member.id}`)\n"
                f"Saved roles: {self._format_role_id_set(member.guild, saved_role_ids)}"
            ),
        )

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        """Restore saved sticky roles when a member rejoins."""
        saved_role_ids = await self._sticky_roles.get_member_roles(member.guild.id, member.id)
        if not saved_role_ids:
            await self._send_sticky_debug_log(
                member.guild,
                (
                    "Sticky role snapshot read\n"
                    f"User: {member.mention} (`{member.id}`)\n"
                    "Saved roles: none\n"
                    "Result: nothing to restore."
                ),
            )
            return

        configured_role_ids = await self._sticky_roles.get_sticky_roles(member.guild.id)
        roles: list[discord.Role] = []
        for role_id in sorted(saved_role_ids & configured_role_ids):
            role = member.guild.get_role(role_id)
            if role is not None and self._can_restore_role(member.guild, role):
                roles.append(role)

        restorable_role_ids = {role.id for role in roles}
        skipped_role_ids = saved_role_ids - restorable_role_ids
        if not roles:
            await self._send_sticky_debug_log(
                member.guild,
                (
                    "Sticky role snapshot read\n"
                    f"User: {member.mention} (`{member.id}`)\n"
                    f"Saved roles: {self._format_role_id_set(member.guild, saved_role_ids)}\n"
                    "Restorable roles: none\n"
                    f"Skipped roles: {self._format_role_id_set(member.guild, skipped_role_ids)}\n"
                    "Result: nothing restorable."
                ),
            )
            return

        result = "restored"
        try:
            await member.add_roles(*roles, reason="Restoring sticky roles")
        except discord.Forbidden:
            result = "failed: missing permissions"
            log.warning(
                "Missing permissions to restore sticky roles for member %s in guild %s",
                member.id,
                member.guild.id,
            )
        except discord.HTTPException:
            result = "failed: Discord API error"
            log.exception(
                "Failed to restore sticky roles for member %s in guild %s",
                member.id,
                member.guild.id,
            )
        await self._send_sticky_debug_log(
            member.guild,
            (
                "Sticky role snapshot read\n"
                f"User: {member.mention} (`{member.id}`)\n"
                f"Saved roles: {self._format_role_id_set(member.guild, saved_role_ids)}\n"
                f"Restorable roles: {self._format_role_id_set(member.guild, restorable_role_ids)}\n"
                f"Skipped roles: {self._format_role_id_set(member.guild, skipped_role_ids)}\n"
                f"Result: {result}."
            ),
        )

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role) -> None:
        """Ask how to handle sticky role DB rows when a Discord role is deleted."""
        config_exists, saved_rows = await self._sticky_roles.get_role_state(
            role.guild.id, role.id
        )
        if not config_exists and saved_rows == 0:
            return

        config = await self.config.guild(role.guild).all()
        channel = self._get_log_channel(role.guild, config["sticky_debug_logging_channel"])
        if channel is None:
            log.warning(
                "Sticky role %s was deleted in guild %s but no sticky debug channel is set",
                role.id,
                role.guild.id,
            )
            return

        await self._prompt_sticky_role_db_action(
            guild=role.guild,
            channel=channel,
            role_id=role.id,
            role_name=role.name,
            config_exists=config_exists,
            saved_rows=saved_rows,
            reason="Discord role deletion event",
            requester=None,
        )

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        """Passively collect message activity counters."""
        guild = message.guild
        if guild is None:
            return
        if message.author.bot or message.webhook_id is not None:
            return
        if message.type not in {discord.MessageType.default, discord.MessageType.reply}:
            return

        now = datetime.now(timezone.utc)
        today = now.date()
        await self._close_stale_activity_days_for_guild(guild, send_reports=True)
        await self._activity_store.record_message(
            guild.id,
            today,
            now.hour,
            message.author.id,
            self._activity_parent_channel_id(message.channel),
            self._activity_thread_id(message.channel),
            now,
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

    async def _activity_midnight_loop(self) -> None:
        await self.bot.wait_until_ready()
        while True:
            try:
                await self._close_stale_activity_days_for_all_guilds(send_reports=True)
            except Exception:
                log.exception("Failed to close stale activity days")
            try:
                now = datetime.now(timezone.utc)
                next_midnight = datetime.combine(
                    now.date() + timedelta(days=1),
                    datetime_time.min,
                    tzinfo=timezone.utc,
                ) + timedelta(seconds=5)
                await asyncio.sleep(max(1.0, (next_midnight - now).total_seconds()))
            except asyncio.CancelledError:
                raise

    async def _close_stale_activity_days_for_all_guilds(self, send_reports: bool) -> None:
        for guild in list(self.bot.guilds):
            await self._close_stale_activity_days_for_guild(guild, send_reports=send_reports)

    async def _close_stale_activity_days_for_guild(
        self, guild: discord.Guild, send_reports: bool
    ) -> None:
        today = self._utc_today()
        summaries = await self._activity_store.close_stale_days(
            guild.id, today, guild.member_count or 0
        )
        if not summaries:
            return

        config = await self.config.guild(guild).all()
        channel = self._get_log_channel(guild, config["activity_channel"])
        for summary in summaries:
            if send_reports and channel is not None:
                await self._send_activity_summary(channel, summary)
            await self._apply_activity_history_retention(
                guild.id, int(config["activity_history_retention_days"]), summary.date_utc
            )

        await self._apply_activity_detail_retention(
            guild.id, int(config["activity_detail_retention_days"])
        )

    async def _send_activity_summary(
        self, channel: discord.TextChannel, summary: DailySummary
    ) -> None:
        try:
            await channel.send(
                embed=self._build_daily_summary_embed(summary, title_prefix="Daily"),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            log.exception("Failed to send activity summary to channel %s", channel.id)

    async def _apply_activity_detail_retention(self, guild_id: int, days: int) -> None:
        if days < 1:
            return
        cutoff = self._utc_today() - timedelta(days=days - 1)
        await self._activity_store.prune_detail_rows_older_than(guild_id, cutoff)

    async def _apply_activity_history_retention(
        self, guild_id: int, days: int, closed_date: date
    ) -> None:
        if days == -1:
            return
        if days == 0:
            await self._activity_store.delete_history_for_date(guild_id, closed_date)
            return
        cutoff = self._utc_today() - timedelta(days=days)
        await self._activity_store.prune_history_rows_older_than(guild_id, cutoff)

    async def _require_manage_guild(self, ctx: commands.Context) -> None:
        permissions = getattr(ctx.author, "guild_permissions", None)
        has_permission = bool(permissions and permissions.manage_guild)
        if has_permission or await self.bot.is_admin(ctx.author):
            return
        raise commands.UserFeedbackCheckFailure("You need Manage Server permission.")

    async def _require_activity_staff(self, ctx: commands.Context) -> None:
        permissions = getattr(ctx.author, "guild_permissions", None)
        has_permission = bool(
            permissions and (permissions.manage_messages or permissions.manage_guild)
        )
        if has_permission or await self.bot.is_admin(ctx.author):
            return
        raise commands.UserFeedbackCheckFailure(
            "You need Manage Messages or Manage Server permission."
        )

    def _parse_role_id(self, value: str) -> int:
        stripped = value.strip()
        if stripped.startswith("<@&") and stripped.endswith(">"):
            stripped = stripped[3:-1]
        if not stripped.isdigit():
            raise commands.UserFeedbackCheckFailure("Pass a role mention or raw Discord role ID.")
        return int(stripped)

    def _can_restore_role(self, guild: discord.Guild, role: discord.Role) -> bool:
        me = guild.me
        if me is None:
            return False
        if role.is_default() or role.managed:
            return False
        if not me.guild_permissions.manage_roles:
            return False
        return role < me.top_role

    def _format_role_reference(self, guild: discord.Guild, role_id: int) -> str:
        role = guild.get_role(role_id)
        if role is None:
            return f"`{role_id}` (missing)"
        return f"{role.mention} (`{role_id}`)"

    def _format_role_id_set(self, guild: discord.Guild, role_ids: set[int]) -> str:
        if not role_ids:
            return "none"
        return ", ".join(
            self._format_role_reference(guild, role_id) for role_id in sorted(role_ids)
        )

    def _role_name_for_prompt(self, guild: discord.Guild, role_id: int) -> str | None:
        role = guild.get_role(role_id)
        if role is None:
            return None
        return role.name

    async def _prompt_sticky_role_db_action(
        self,
        *,
        guild: discord.Guild,
        channel: discord.abc.Messageable,
        role_id: int,
        role_name: str | None,
        config_exists: bool,
        saved_rows: int,
        reason: str,
        requester: discord.Member | discord.User | None,
    ) -> None:
        role_label = f"{role_name} (`{role_id}`)" if role_name else f"`{role_id}`"
        await channel.send(
            "Sticky role DB entry needs a decision.\n"
            f"Role: {role_label}\n"
            f"Trigger: {reason}\n"
            f"Configured as sticky: {'yes' if config_exists else 'no'}\n"
            f"Saved user-role rows: {saved_rows}\n"
            "Reply with one of:\n"
            "`remove` - delete this role from sticky DB and saved users\n"
            "`keep` - stop configuring this role as sticky, but keep saved user rows\n"
            "`change <role mention or ID>` - move config and saved users to another role",
            allowed_mentions=discord.AllowedMentions.none(),
        )

        deadline = time.monotonic() + 300
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                await channel.send("Sticky role DB decision timed out. No changes were made.")
                return

            def check(message: discord.Message) -> bool:
                return message.channel.id == channel.id and not message.author.bot

            try:
                message = await self.bot.wait_for("message", check=check, timeout=remaining)
            except asyncio.TimeoutError:
                await channel.send("Sticky role DB decision timed out. No changes were made.")
                return

            if not await self._can_answer_sticky_db_prompt(message, guild, requester):
                continue

            content = message.content.strip()
            command, _, argument = content.partition(" ")
            command = command.lower()
            if command == "remove" and not argument:
                config_removed, rows_removed = await self._sticky_roles.remove_sticky_role(
                    guild.id, role_id
                )
                await channel.send(
                    "Sticky role DB entry removed.\n"
                    f"Config row removed: {'yes' if config_removed else 'no'}\n"
                    f"Saved user-role rows removed: {rows_removed}"
                )
                return
            if command == "keep" and not argument:
                config_removed = await self._sticky_roles.unconfigure_sticky_role(
                    guild.id, role_id
                )
                await channel.send(
                    "Sticky role config removed, saved user-role rows kept.\n"
                    f"Config row removed: {'yes' if config_removed else 'no'}\n"
                    f"Saved user-role rows kept: {saved_rows}"
                )
                return
            if command == "change":
                await self._handle_sticky_role_db_change(
                    channel, guild, role_id, argument.strip()
                )
                return

            await channel.send(
                "Invalid response. Use `remove`, `keep`, or `change <role mention or ID>`."
            )

    async def _can_answer_sticky_db_prompt(
        self,
        message: discord.Message,
        guild: discord.Guild,
        requester: discord.Member | discord.User | None,
    ) -> bool:
        if requester is not None:
            return message.author.id == requester.id

        member = message.author
        if not isinstance(member, discord.Member):
            member = guild.get_member(message.author.id)
        permissions = getattr(member, "guild_permissions", None)
        if permissions and permissions.manage_guild:
            return True
        return await self.bot.is_admin(message.author)

    async def _handle_sticky_role_db_change(
        self,
        channel: discord.abc.Messageable,
        guild: discord.Guild,
        old_role_id: int,
        role_argument: str,
    ) -> None:
        if not role_argument:
            await channel.send("Missing replacement role. No changes were made.")
            return

        try:
            new_role_id = self._parse_role_id(role_argument)
        except commands.UserFeedbackCheckFailure as exc:
            await channel.send(f"{exc} No changes were made.")
            return

        if new_role_id == old_role_id:
            await channel.send("Replacement role is the same role ID. No changes were made.")
            return

        new_role = guild.get_role(new_role_id)
        if new_role is None:
            await channel.send("Replacement role does not exist on this server. No changes were made.")
            return
        if not self._can_restore_role(guild, new_role):
            await channel.send(
                "I cannot restore the replacement role. Check Manage Roles and role hierarchy. "
                "No changes were made."
            )
            return

        config_moved, old_rows_removed, new_rows_inserted = await self._sticky_roles.replace_sticky_role(
            guild.id, old_role_id, new_role_id
        )
        await channel.send(
            "Sticky role DB entry changed.\n"
            f"Replacement role: {new_role.mention} (`{new_role.id}`)\n"
            f"Config moved: {'yes' if config_moved else 'no'}\n"
            f"Old saved user-role rows removed: {old_rows_removed}\n"
            f"New saved user-role rows inserted: {new_rows_inserted}",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def _send_sticky_debug_log(self, guild: discord.Guild, content: str) -> None:
        config = await self.config.guild(guild).all()
        if not config["sticky_debug_logging_enabled"]:
            return

        channel = self._get_log_channel(guild, config["sticky_debug_logging_channel"])
        if channel is None:
            return

        try:
            await channel.send(content, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException:
            log.exception("Failed to send sticky role debug log to guild %s", guild.id)

    async def _send_paginated_text(self, ctx: commands.Context, content: str) -> None:
        page = ""
        for line in content.splitlines():
            candidate = f"{page}\n{line}" if page else line
            if len(candidate) > 1900:
                await ctx.send(page, allowed_mentions=discord.AllowedMentions.none())
                page = line
            else:
                page = candidate
        if page:
            await ctx.send(page, allowed_mentions=discord.AllowedMentions.none())

    async def _confirm_retention_delete(self, ctx: commands.Context, warning: str) -> bool:
        await ctx.send(warning)

        def check(message: discord.Message) -> bool:
            return (
                message.author.id == ctx.author.id
                and message.channel.id == ctx.channel.id
                and message.content == RETENTION_CONFIRMATION
            )

        try:
            await self.bot.wait_for("message", check=check, timeout=60)
        except asyncio.TimeoutError:
            await ctx.send("Retention change cancelled.")
            return False
        return True

    def _utc_today(self) -> date:
        return datetime.now(timezone.utc).date()

    def _history_retention_cutoff(self, days: int) -> date | None:
        if days == -1:
            return None
        if days == 0:
            return self._utc_today() + timedelta(days=1)
        return self._utc_today() - timedelta(days=days)

    async def _cap_detail_days(self, guild: discord.Guild, days: int) -> int:
        config = await self.config.guild(guild).all()
        retention = max(1, int(config["activity_detail_retention_days"]))
        return min(days, retention)

    def _parse_range_days(self, value: str) -> int:
        normalized = value.strip().lower()
        if not normalized.isdigit():
            raise commands.UserFeedbackCheckFailure("Range must be a positive number of days.")
        days = int(normalized)
        if days < 1:
            raise commands.UserFeedbackCheckFailure("Range must be at least 1 day.")
        return days

    def _parse_user_id(self, value: str) -> int:
        stripped = value.strip()
        if stripped.startswith("<@") and stripped.endswith(">"):
            stripped = stripped[2:-1]
            if stripped.startswith("!"):
                stripped = stripped[1:]
        if not stripped.isdigit():
            raise commands.UserFeedbackCheckFailure("Pass a user mention or raw Discord user ID.")
        return int(stripped)

    def _activity_parent_channel_id(self, channel: object) -> int:
        parent = getattr(channel, "parent", None)
        if isinstance(channel, discord.Thread) and parent is not None:
            return parent.id
        return getattr(channel, "id")

    def _activity_thread_id(self, channel: object) -> int | None:
        if isinstance(channel, discord.Thread):
            return channel.id
        return None

    def _format_channel(self, channel_id: int) -> str:
        return f"<#{channel_id}>"

    def _format_user_reference(self, guild: discord.Guild, user_id: int) -> str:
        member = guild.get_member(user_id)
        if member is not None:
            return f"{member.display_name} ({user_id})"
        return f"<@{user_id}> ({user_id})"

    def _format_int(self, value: int) -> str:
        return f"{value:,}"

    def _format_percent_of_server(self, active_users: int, member_count: int) -> str:
        if member_count <= 0:
            return "n/d"
        return f"{(active_users / member_count) * 100:.1f}%"

    def _format_top_channels(self, top_channels: list[TopChannel]) -> str:
        if not top_channels:
            return "n/d"
        return "\n".join(
            (
                f"{top.rank}. {self._format_channel(top.channel_id)} - "
                f"{self._format_int(top.message_count)} messages"
            )
            for top in top_channels
        )

    def _build_daily_summary_embed(
        self, summary: DailySummary, title_prefix: str
    ) -> discord.Embed:
        embed = discord.Embed(
            title=f"{title_prefix} activity summary - {summary.date_utc.isoformat()} UTC",
            color=discord.Color.blue(),
        )
        embed.add_field(
            name="Messages",
            value=self._format_int(summary.total_messages),
            inline=True,
        )
        embed.add_field(
            name="Active users",
            value=(
                f"{self._format_int(summary.active_users)} "
                f"({self._format_percent_of_server(summary.active_users, summary.member_count_at_close)})"
            ),
            inline=True,
        )
        embed.add_field(
            name="Thresholds",
            value=(
                f"10+: {self._format_int(summary.users_10_plus)}\n"
                f"50+: {self._format_int(summary.users_50_plus)}\n"
                f"100+: {self._format_int(summary.users_100_plus)}"
            ),
            inline=True,
        )
        peak_hour = self._format_peak_hour(summary)
        embed.add_field(
            name="Channels",
            value=(
                f"Active: {self._format_int(summary.channels_with_activity)}\n"
                f"Peak hour: {peak_hour}\n"
                f"Avg/user: {summary.messages_per_active_user:.1f}"
            ),
            inline=False,
        )
        embed.add_field(
            name="Top channels",
            value=self._format_top_channels(summary.top_channels),
            inline=False,
        )
        return embed

    def _format_peak_hour(self, summary: DailySummary) -> str:
        if summary.peak_hour_utc is None:
            return "n/d"
        peak_time = datetime(
            summary.date_utc.year,
            summary.date_utc.month,
            summary.date_utc.day,
            summary.peak_hour_utc,
            tzinfo=timezone.utc,
        )
        return f"<t:{int(peak_time.timestamp())}:t>"

    def _build_timeline_embed(
        self, timeline: list[TimelineDay], top_channels: list[TopChannel], days: int
    ) -> discord.Embed:
        include_percent = days <= 7
        header = "Date       Msgs  Users  %Srv  10+ 50+ 100+" if include_percent else "Date       Msgs  Users  10+ 50+ 100+"
        lines = [header]
        summaries: list[DailySummary] = []
        for day in timeline:
            summary = day.summary
            if summary is None:
                if include_percent:
                    lines.append(f"{day.date_utc.isoformat()} n/d   n/d    n/d   n/d n/d n/d")
                else:
                    lines.append(f"{day.date_utc.isoformat()} n/d   n/d    n/d n/d n/d")
                continue
            summaries.append(summary)
            if include_percent:
                lines.append(
                    f"{day.date_utc.isoformat()} "
                    f"{summary.total_messages:<5} {summary.active_users:<6} "
                    f"{self._format_percent_of_server(summary.active_users, summary.member_count_at_close):<5} "
                    f"{summary.users_10_plus:<3} {summary.users_50_plus:<3} {summary.users_100_plus:<4}"
                )
            else:
                lines.append(
                    f"{day.date_utc.isoformat()} "
                    f"{summary.total_messages:<5} {summary.active_users:<6} "
                    f"{summary.users_10_plus:<3} {summary.users_50_plus:<3} {summary.users_100_plus:<4}"
                )

        table = "\n".join(lines)
        if len(table) > 3900:
            visible_lines = lines[:120]
            visible_lines.append("...")
            table = "\n".join(visible_lines)

        embed = discord.Embed(
            title=f"Activity timeline - last {days} closed days",
            color=discord.Color.blue(),
            description=f"```text\n{table}\n```",
        )
        if summaries:
            avg_messages = sum(summary.total_messages for summary in summaries) / len(summaries)
            avg_users = sum(summary.active_users for summary in summaries) / len(summaries)
            best = max(summaries, key=lambda summary: summary.total_messages)
            embed.add_field(
                name="Range",
                value=(
                    f"Avg/day: {avg_messages:.0f} msgs\n"
                    f"Avg active users: {avg_users:.0f}\n"
                    f"Best day: {best.date_utc.isoformat()} "
                    f"({self._format_int(best.total_messages)} msgs)"
                ),
                inline=False,
            )
        else:
            embed.add_field(name="Range", value="n/d", inline=False)
        embed.add_field(
            name="Top channels in range",
            value=self._format_top_channels(top_channels),
            inline=False,
        )
        return embed

    def _build_channel_timeline_embed(
        self, channel: discord.TextChannel, timeline: list[ChannelTimelineDay], days: int
    ) -> discord.Embed:
        lines = ["Date       Msgs"]
        numeric_counts: list[int] = []
        for day in timeline:
            if day.message_count is None:
                value = "n/d"
            else:
                numeric_counts.append(day.message_count)
                value = str(day.message_count)
            lines.append(f"{day.date_utc.isoformat()} {value}")

        table = "\n".join(lines)
        if len(table) > 3900:
            visible_lines = lines[:120]
            visible_lines.append("...")
            table = "\n".join(visible_lines)

        embed = discord.Embed(
            title=f"Channel activity - {channel.name} - last {days} days",
            color=discord.Color.blue(),
            description=f"```text\n{table}\n```",
        )
        if numeric_counts:
            total = sum(numeric_counts)
            active_days = sum(1 for value in numeric_counts if value > 0)
            embed.add_field(name="Total messages", value=self._format_int(total), inline=True)
            embed.add_field(name="Active days", value=self._format_int(active_days), inline=True)
            embed.add_field(
                name="Average per active day",
                value=f"{(total / active_days) if active_days else 0.0:.1f}",
                inline=True,
            )
        else:
            embed.add_field(name="Total messages", value="n/d", inline=True)
        return embed

    def _build_user_stats_embed(self, title: str, stats: UserStats, days: int) -> discord.Embed:
        embed = discord.Embed(title=title, color=discord.Color.blue())
        embed.add_field(name="Range", value=f"last {days} days", inline=True)
        embed.add_field(name="Total messages", value=self._format_int(stats.total_messages), inline=True)
        embed.add_field(name="Active days", value=self._format_int(stats.active_days), inline=True)
        embed.add_field(
            name="Average per active day",
            value=f"{stats.average_per_active_day:.1f}",
            inline=True,
        )
        embed.add_field(
            name="Top channels",
            value=self._format_top_channels(stats.top_channels),
            inline=False,
        )
        embed.add_field(
            name="Daily breakdown",
            value=f"```text\n{self._format_daily_rows(stats.date_rows)}\n```",
            inline=False,
        )
        return embed

    def _build_selfchart_embed(
        self, member: discord.Member | discord.User, stats: UserStats, days: int
    ) -> discord.Embed:
        embed = discord.Embed(
            title=f"Your activity - last {days} days",
            color=discord.Color.blue(),
        )
        embed.add_field(name="Total messages", value=self._format_int(stats.total_messages), inline=True)
        top_channel = stats.top_channels[0] if stats.top_channels else None
        embed.add_field(
            name="Top channel",
            value=(
                f"{self._format_channel(top_channel.channel_id)} - "
                f"{self._format_int(top_channel.message_count)} messages"
                if top_channel
                else "n/d"
            ),
            inline=True,
        )
        embed.add_field(
            name="Daily messages",
            value=f"```text\n{self._format_daily_rows(stats.date_rows)}\n```",
            inline=False,
        )
        return embed

    def _format_daily_rows(self, rows: list[tuple[date, int | None]]) -> str:
        lines = ["Date       Msgs"]
        for day, count in rows:
            value = "n/d" if count is None else str(count)
            lines.append(f"{day.isoformat()} {value}")
        return "\n".join(lines)

    def _build_chatchart_file(
        self, guild: discord.Guild, counts: list[ChannelUserCount], days: int
    ) -> discord.File:
        try:
            import matplotlib

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError as exc:
            raise commands.UserFeedbackCheckFailure(
                "Matplotlib is required for chatchart but is not installed."
            ) from exc

        top_counts = counts[:10]
        other_count = sum(count.message_count for count in counts[10:])
        labels: list[str] = []
        values: list[int] = []
        for count in top_counts:
            member = guild.get_member(count.user_id)
            name = member.display_name if member is not None else str(count.user_id)
            labels.append(f"{name} ({count.message_count})")
            values.append(count.message_count)
        if other_count:
            labels.append(f"Other ({other_count})")
            values.append(other_count)

        figure, axis = plt.subplots(figsize=(8, 6))
        axis.pie(
            values,
            labels=labels,
            autopct=lambda percent: f"{percent:.1f}%" if percent >= 3 else "",
            startangle=90,
        )
        axis.axis("equal")
        axis.set_title(f"Messages by user - last {days} days")
        buffer = io.BytesIO()
        figure.savefig(buffer, format="png", bbox_inches="tight", dpi=160)
        plt.close(figure)
        buffer.seek(0)
        return discord.File(buffer, filename="chatchart.png")
