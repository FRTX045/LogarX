"""The full reconstruction, from stored events to activity graphs.

This is the O(k) half of the design: everything here works on one client's
events, which is a small number even when the case is enormous. See ADR-0002.

The order is fixed and each step is independently testable:

    events -> sessions -> labelled requests -> episodes -> graphs
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from logarc.core.window import EVERYTHING, TimeWindow
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules
from logarc.episode.builder import EpisodePolicy, segment
from logarc.graphbuild.build import build_behaviour_map, build_trace_graph
from logarc.sessionize.segmenter import SessionPolicy, sessionize

if TYPE_CHECKING:
    from logarc.core.activity import ActivityCategory
    from logarc.core.episode import Episode
    from logarc.core.evidence import EvidenceRef
    from logarc.core.graph import ActivityGraph
    from logarc.core.session import Session
    from logarc.detect.crs import DetectionIndex
    from logarc.detect.engine import LabelledEvent
    from logarc.storage.base import EventStore

__all__ = ["AnalysisPolicy", "AnalysisResult", "RequestAssignment", "analyse_ip"]


@dataclass(frozen=True, slots=True)
class AnalysisPolicy:
    """Every threshold a reconstruction depends on, in one place.

    Grouped so the whole set can be written into the case manifest as a unit —
    a result is only reproducible if the settings that produced it are known.
    """

    session: SessionPolicy = field(default_factory=SessionPolicy)
    episode: EpisodePolicy = field(default_factory=EpisodePolicy)

    def as_config(self) -> dict[str, Any]:
        return {**self.session.as_config(), **self.episode.as_config()}


@dataclass(frozen=True, slots=True)
class RequestAssignment:
    """One request, what the rules made of it, and where it ended up.

    The bridge between the two levels of the result: an episode says what
    happened, and this says which lines it is made of. Both the evidence panel
    and the accuracy measurement start here.
    """

    labelled: LabelledEvent
    episode_id: str

    @property
    def evidence(self) -> EvidenceRef:
        return self.labelled.event.evidence

    @property
    def category(self) -> ActivityCategory:
        """The category that reached the graph."""
        return self.labelled.label.category

    @property
    def categories(self) -> frozenset[ActivityCategory]:
        """Every category that matched, including any that were outranked.

        A request can honestly be two things. Keeping the losers separates a
        rule that never fired from one that fired and was outranked — different
        problems, with different fixes.
        """
        return frozenset(
            {self.labelled.label.category} | {label.category for label in self.labelled.all_labels}
        )


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """What one client did, at every level of detail."""

    client_ip: str
    sessions: tuple[Session, ...]
    episodes: tuple[Episode, ...]
    assignments: tuple[RequestAssignment, ...]
    trace: ActivityGraph
    behaviour: ActivityGraph
    ruleset_fingerprint: str
    policy: AnalysisPolicy
    window: TimeWindow = EVERYTHING
    """The stretch of time this covers.

    Carried so a report can say what it is a report *of*. The identifiers
    already differ between windows, which is what stops two reports being
    confused for one another; this is what lets a person read which is which
    without comparing them.
    """

    crs_fingerprint: str | None = None
    """Which CRS configuration contributed, or None when the case was not enriched.

    Recorded beside the ruleset fingerprint for the same reason: a finding is
    only reproducible if everything that produced it is named, and "CRS was not
    consulted" is as much a part of a result as which rules were."""

    @property
    def request_count(self) -> int:
        return sum(session.request_count for session in self.sessions)

    @property
    def hostile_episodes(self) -> tuple[Episode, ...]:
        return tuple(episode for episode in self.episodes if episode.category.is_hostile)

    def to_dict(self) -> dict[str, Any]:
        """The machine-readable form, for export and for other tools."""
        return {
            "client_ip": self.client_ip,
            "session_count": len(self.sessions),
            "episode_count": len(self.episodes),
            "request_count": self.request_count,
            "ruleset_fingerprint": self.ruleset_fingerprint,
            "crs_fingerprint": self.crs_fingerprint,
            "policy": self.policy.as_config(),
            # Empty for the whole case, which is what every report written
            # before this existed already means. A tool reading two of these has
            # the same problem a person does: without it, one client's two
            # reports differ in their numbers and agree in everything else.
            "window": self.window.tag,
            "trace": self.trace.to_dict(),
            "behaviour": self.behaviour.to_dict(),
        }


def analyse_ip(
    store: EventStore,
    client_ip: str,
    *,
    engine: RuleEngine | None = None,
    policy: AnalysisPolicy | None = None,
    crs: DetectionIndex | None = None,
    crs_fingerprint: str | None = None,
    window: TimeWindow | None = None,
) -> AnalysisResult:
    """Reconstruct what one client did.

    `crs` is the detection set from `logarc enrich`, if the case has one. It
    never changes a label a rule packed here asserted; it only names requests
    that would otherwise fall through to ordinary traffic.

    `window` narrows this to one stretch of time, and it narrows it at the
    bottom: the events are read for that stretch and everything above is built
    from what is left. Sessions are found again in the remainder, so a client
    with two visits either side of the window comes back with one. That is the
    honest answer to "what did this client do between these times" — the other
    reading, keeping the whole-case structure and hiding the parts outside,
    reports activities with request counts that include requests the window
    excludes.
    """
    engine = engine or RuleEngine(default_rules())
    policy = policy or AnalysisPolicy()

    window = window or EVERYTHING
    events = store.events_for_ip(client_ip, window=window)
    sessions = sessionize(events, policy.session, window=window)
    sessions.sort(key=lambda session: session.start)

    episodes: list[Episode] = []
    assignments: list[RequestAssignment] = []
    for session in sessions:
        labelled = engine.label_events(session.events, crs=crs)
        for part in segment(labelled, session_id=session.session_id, policy=policy.episode):
            episodes.append(part.episode)
            assignments.extend(
                RequestAssignment(labelled=item, episode_id=part.episode.episode_id)
                for item in part.members
            )

    return AnalysisResult(
        client_ip=client_ip,
        sessions=tuple(sessions),
        episodes=tuple(episodes),
        assignments=tuple(assignments),
        trace=build_trace_graph(episodes, client_ip=client_ip),
        behaviour=build_behaviour_map(episodes, client_ip=client_ip),
        ruleset_fingerprint=engine.fingerprint,
        policy=policy,
        window=window,
        crs_fingerprint=crs_fingerprint,
    )
