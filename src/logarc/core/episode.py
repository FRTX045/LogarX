"""An episode: one stretch of one kind of activity.

This is the unit that becomes a box in the activity graph. It exists because a
single meaningful act — "probing for SQL injection" — is dozens of requests, and
a graph with one node per request is just the log again.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from logarc.core.activity import Outcome, Severity

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime, timedelta

    from logarc.core.activity import ActivityCategory, ActivityLabel
    from logarc.core.evidence import EvidenceRef


@dataclass(frozen=True, slots=True)
class Episode:
    """A contiguous run of requests sharing one activity category."""

    episode_id: str
    session_id: str
    client_ip: str

    activity: ActivityLabel
    """The most severe label seen in the run; what the episode is called."""

    start: datetime
    end: datetime
    request_count: int
    distinct_paths: int
    bytes_total: int
    status_histogram: Mapping[int, int]
    top_targets: tuple[str, ...]
    rule_ids: tuple[str, ...]
    outcome: Outcome

    evidence: tuple[EvidenceRef, ...]
    """A bounded sample of the source lines. A thousand-request episode must not
    carry a thousand references."""

    evidence_total: int
    """How many lines the episode actually covers, sampling aside."""

    @property
    def category(self) -> ActivityCategory:
        return self.activity.category

    @property
    def severity(self) -> Severity:
        return self.activity.severity

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    @property
    def label(self) -> str:
        """A short description for a graph node."""
        return self.activity.name


def derive_outcome(statuses: Sequence[int | None]) -> Outcome:
    """Decide whether an episode achieved anything, from its response codes.

    This is the distinction that changes a report: "47 injection attempts, all
    refused" and "47 attempts, three of which returned data" are the same
    activity and entirely different findings.
    """
    known = [status for status in statuses if status is not None]
    if not known:
        return Outcome.UNKNOWN

    succeeded = sum(status < 400 for status in known)
    if succeeded == 0:
        return Outcome.BLOCKED
    if succeeded == len(known):
        return Outcome.SUCCESS
    return Outcome.MIXED
