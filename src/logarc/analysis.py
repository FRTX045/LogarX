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
    from collections.abc import Iterator, Sequence

    from logarc.core.activity import ActivityCategory
    from logarc.core.episode import Episode
    from logarc.core.event import NormalizedEvent
    from logarc.core.evidence import EvidenceRef
    from logarc.core.graph import ActivityGraph, GraphNode
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
    site_hosts: tuple[str, ...] = ()
    """The domains the reader said are this site's own, as the engine read them.

    Provenance, beside `crs_fingerprint` rather than folded into
    `ruleset_fingerprint`, because it is an answer a person gave and not part of
    the ruleset. `rfi_offsite_url` is the only rule that reads it, and it is the
    only rule in the tree whose finding cannot be checked from the evidence line
    alone — so the report has to carry what it was compared against.
    """
    """Which CRS configuration contributed, or None when the case was not enriched.

    Recorded beside the ruleset fingerprint for the same reason: a finding is
    only reproducible if everything that produced it is named, and "CRS was not
    consulted" is as much a part of a result as which rules were."""

    rules_in_force: str = ""
    """Which rules produced this, in words: how many built in, any switched off
    by id, and each pack added by name. The fingerprint proves which rules; this
    says which, so a reader of a report does not need the ruleset to decode it.
    Empty when the engine was built from a bare list of rules."""

    crs_coverage: tuple[int, int] | None = None
    """`(replayed, requests)` when the CRS run behind `crs_fingerprint` was
    stopped part way, else `None`. Requests it never reached cannot carry a CRS
    finding, so a report built from it has to say how far CRS got."""

    @property
    def request_count(self) -> int:
        return sum(session.request_count for session in self.sessions)

    @property
    def hostile_episodes(self) -> tuple[Episode, ...]:
        return tuple(episode for episode in self.episodes if episode.category.is_hostile)

    def evidence_for(self, node: GraphNode, *, limit: int | None = None) -> tuple[EvidenceRef, ...]:
        """Every line behind one activity, in the order the client performed it.

        Read from the episodes the node names rather than from `node.evidence`,
        and that is the whole point of the method. `graphbuild.build` merges a
        behaviour node's references in episode order and cuts them at twenty, so
        that tuple carries the earliest burst of an activity and nothing at all
        of the latest, however long it ran. The episodes still hold the lot.

        Chronological, because the episodes are, and deliberately not sorted by
        source and line number. Sorted, a case holding two logs would show one
        file's whole story and then the other's, rather than the sequence the
        client actually performed — and on a forensic tool the order is part of
        the evidence.

        `limit` is the caller's, not this method's: how many lines can be read
        before a reader notices the wait is a question about whoever is waiting.
        A node naming an episode this result does not hold answers with nothing
        rather than raising — a graph and a result that disagree are better said
        by an empty panel than by a traceback.
        """
        named = set(node.episode_ids)
        refs = tuple(
            ref
            for episode in self.episodes
            if episode.episode_id in named
            for ref in episode.evidence
        )
        return refs if limit is None else refs[:limit]

    def requests_for(self, node: GraphNode) -> tuple[RequestAssignment, ...]:
        """Every request of one activity, in the order the client made them.

        All of them, where `evidence_for` stops at the episodes' sample: this is
        what a filter on the evidence searches, and a match past the sample is
        still a match. Built from the assignments, which hold every request once,
        so it costs a pass over the client's requests rather than a read of the log.
        """
        named = set(node.episode_ids)
        return tuple(item for item in self.assignments if item.episode_id in named)

    def to_dict(self) -> dict[str, Any]:
        """The machine-readable form, for export and for other tools."""
        return {
            "client_ip": self.client_ip,
            "session_count": len(self.sessions),
            "episode_count": len(self.episodes),
            "request_count": self.request_count,
            "ruleset_fingerprint": self.ruleset_fingerprint,
            "rules_in_force": self.rules_in_force,
            "crs_fingerprint": self.crs_fingerprint,
            # Always present, `None` for a complete run or none, for the reason
            # `site_hosts` below is.
            "crs_coverage": (
                {"replayed": self.crs_coverage[0], "requests": self.crs_coverage[1]}
                if self.crs_coverage is not None
                else None
            ),
            # Always present, empty when unanswered. A missing key would read as
            # a report written before this existed rather than as a question
            # nobody answered, and those mean different things to a reader
            # comparing two cases.
            "site_hosts": list(self.site_hosts),
            "policy": self.policy.as_config(),
            # Empty for the whole case, which is what every report written
            # before this existed already means. A tool reading two of these has
            # the same problem a person does: without it, one client's two
            # reports differ in their numbers and agree in everything else.
            "window": self.window.tag,
            "trace": self.trace.to_dict(),
            "behaviour": self.behaviour.to_dict(),
        }


def label_sessions(
    events: Sequence[NormalizedEvent],
    engine: RuleEngine,
    *,
    policy: SessionPolicy | None = None,
    crs: DetectionIndex | None = None,
    window: TimeWindow | None = None,
) -> Iterator[tuple[Session, list[LabelledEvent]]]:
    """Share session boundaries and labels between reconstruction and triage."""
    for session in sorted(sessionize(events, policy, window=window), key=lambda s: s.start):
        yield session, engine.label_events(session.events, crs=crs)


def analyse_ip(
    store: EventStore,
    client_ip: str,
    *,
    engine: RuleEngine | None = None,
    policy: AnalysisPolicy | None = None,
    crs: DetectionIndex | None = None,
    crs_fingerprint: str | None = None,
    crs_coverage: tuple[int, int] | None = None,
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
    sessions = []

    episodes: list[Episode] = []
    assignments: list[RequestAssignment] = []
    for session, labelled in label_sessions(
        events, engine, policy=policy.session, crs=crs, window=window
    ):
        sessions.append(session)
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
        site_hosts=tuple(sorted(engine.site_hosts)),
        rules_in_force=engine.described,
        crs_coverage=crs_coverage,
    )
