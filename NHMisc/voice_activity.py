from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Hashable


class VoiceChannelVisitTracker:
    """Track recent voice channel visits for rapid-switch detection."""

    def __init__(self) -> None:
        self._visits: dict[Hashable, deque[tuple[float, int]]] = defaultdict(deque)

    def record_visit(
        self,
        subject_id: Hashable,
        channel_id: int,
        *,
        timestamp: float,
        channel_count: int,
        window_seconds: int,
    ) -> bool:
        visits = self._visits[subject_id]
        visits.append((timestamp, channel_id))

        earliest_timestamp = timestamp - window_seconds
        while visits and visits[0][0] <= earliest_timestamp:
            visits.popleft()

        distinct_channel_ids = {visited_channel_id for _, visited_channel_id in visits}
        return len(distinct_channel_ids) >= channel_count
