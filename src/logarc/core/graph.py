"""The activity graph: boxes and arrows, as plain data.

Deliberately free of layout and rendering. The same structure is drawn on a Qt
canvas, written to JSON for another tool, and embedded in a report — none of
which should require the others to exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

    from logarc.core.activity import ActivityCategory, Outcome, Severity
    from logarc.core.evidence import EvidenceRef


class GraphKind(StrEnum):
    """Which question the graph answers."""

    TRACE = "trace"
    """One node per episode, in time order: what happened, and in what sequence."""

    BEHAVIOUR = "behaviour"
    """One node per activity type, aggregated: how this client behaves."""


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One box."""

    node_id: str
    label: str
    category: ActivityCategory
    severity: Severity
    outcome: Outcome
    request_count: int
    distinct_paths: int
    bytes_total: int
    start: datetime
    end: datetime
    owasp: str | None
    top_targets: tuple[str, ...]
    rule_ids: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]
    evidence_total: int
    episode_ids: tuple[str, ...]
    episode_count: int = 1
    named_by: str = ""
    """The rule the node is named after, which `rule_ids`, sorted, cannot say.

    The window draws a reader's own rule's icon from it. Not exported: what
    the window draws is the window's business."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "label": self.label,
            "category": self.category.value,
            "severity": self.severity.name.lower(),
            "outcome": self.outcome.value,
            "owasp": self.owasp,
            "request_count": self.request_count,
            "distinct_paths": self.distinct_paths,
            "bytes_total": self.bytes_total,
            "episode_count": self.episode_count,
            "episode_ids": list(self.episode_ids),
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "top_targets": list(self.top_targets),
            "rule_ids": list(self.rule_ids),
            "evidence": [str(ref) for ref in self.evidence],
            "evidence_total": self.evidence_total,
        }


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """One arrow: this activity led to that one."""

    source: str
    target: str
    weight: int = 1
    gap_seconds: float | None = None
    """Time between the two activities. On an aggregated map this is the median
    across every observed transition."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "weight": self.weight,
            "gap_seconds": self.gap_seconds,
        }


@dataclass(frozen=True, slots=True)
class ActivityGraph:
    """A reconstruction of one client's activity."""

    kind: GraphKind
    client_ip: str
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "client_ip": self.client_ip,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }


def reciprocal_pairs(graph: ActivityGraph) -> frozenset[frozenset[str]]:
    """Node pairs joined by an edge each way.

    A behaviour map folds a trace by activity type, so a client that goes
    enumeration -> injection -> enumeration produces an edge in each direction
    between the same two nodes. Drawn between the same two points, both are the
    same line, and the second one drawn hides the first along with its label —
    so the map shows one transition where there are two, and the one it hides is
    whichever was drawn first, not the lighter one.

    Both renderers need the answer and neither should work it out for itself:
    the report cannot import the Qt canvas's module, and two copies of a rule
    about what a picture means is how the picture starts to disagree with
    itself. It is a fact about the graph, so it lives with the graph.

    A self-loop is excluded. `a -> a` is its own reverse, so it satisfies the
    rule read literally, and separating it would move a loop off the node it
    loops on.
    """
    directed = {(edge.source, edge.target) for edge in graph.edges}
    return frozenset(
        frozenset((source, target))
        for source, target in directed
        if source != target and (target, source) in directed
    )
