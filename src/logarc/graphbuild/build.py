"""Building the two graph views from one list of episodes.

Both answer different questions about the same evidence:

* The **trace** is chronological — one node per episode, arrows in time order.
  It reads as a sequence: browsing, then probing, then injection.
* The **behaviour map** is aggregated — one node per activity type, arrows
  weighted by how often that transition was observed. It reads as a habit.

The map is a fold over the trace, so having both costs almost nothing.

Neither links across a session boundary. A gap long enough to end a session is a
break in the story, not a transition within it, and drawing an arrow over it
would invent a continuity the evidence does not support.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import pairwise
from statistics import median
from typing import TYPE_CHECKING

from logarc.core.activity import Outcome
from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.episode import Episode

__all__ = ["build_behaviour_map", "build_trace_graph"]


def build_trace_graph(episodes: Sequence[Episode], *, client_ip: str) -> ActivityGraph:
    """One node per episode, linked in the order they happened."""
    nodes = tuple(_node_from_episode(episode) for episode in episodes)

    edges = tuple(
        GraphEdge(
            source=first.episode_id,
            target=second.episode_id,
            gap_seconds=(second.start - first.end).total_seconds(),
        )
        for first, second in pairwise(episodes)
        if first.session_id == second.session_id
    )
    return ActivityGraph(kind=GraphKind.TRACE, client_ip=client_ip, nodes=nodes, edges=edges)


def build_behaviour_map(episodes: Sequence[Episode], *, client_ip: str) -> ActivityGraph:
    """One node per activity type, with transitions weighted by frequency."""
    if not episodes:
        return ActivityGraph(kind=GraphKind.BEHAVIOUR, client_ip=client_ip)

    grouped: dict[str, list[Episode]] = defaultdict(list)
    for episode in episodes:
        grouped[episode.category.value].append(episode)

    nodes = tuple(_node_from_group(key, group) for key, group in grouped.items())

    gaps: dict[tuple[str, str], list[float]] = defaultdict(list)
    for first, second in pairwise(episodes):
        if first.session_id != second.session_id:
            continue
        gaps[(first.category.value, second.category.value)].append(
            (second.start - first.end).total_seconds()
        )

    edges = tuple(
        GraphEdge(
            source=source,
            target=target,
            weight=len(observed),
            gap_seconds=median(observed),
        )
        for (source, target), observed in gaps.items()
    )
    return ActivityGraph(kind=GraphKind.BEHAVIOUR, client_ip=client_ip, nodes=nodes, edges=edges)


def _node_from_episode(episode: Episode) -> GraphNode:
    return GraphNode(
        node_id=episode.episode_id,
        label=episode.label,
        category=episode.category,
        severity=episode.severity,
        outcome=episode.outcome,
        request_count=episode.request_count,
        distinct_paths=episode.distinct_paths,
        bytes_total=episode.bytes_total,
        start=episode.start,
        end=episode.end,
        owasp=episode.activity.owasp,
        top_targets=episode.top_targets,
        rule_ids=episode.rule_ids,
        evidence=episode.evidence,
        evidence_total=episode.evidence_total,
        episode_ids=(episode.episode_id,),
        named_by=episode.activity.rule_id,
    )


def _node_from_group(category: str, group: Sequence[Episode]) -> GraphNode:
    worst = max(group, key=lambda episode: episode.severity)
    targets: list[str] = []
    for episode in group:
        targets.extend(target for target in episode.top_targets if target not in targets)

    return GraphNode(
        node_id=category,
        label=worst.label,
        category=worst.category,
        severity=worst.severity,
        outcome=_combined_outcome(group),
        request_count=sum(episode.request_count for episode in group),
        distinct_paths=len(targets),
        bytes_total=sum(episode.bytes_total for episode in group),
        start=min(episode.start for episode in group),
        end=max(episode.end for episode in group),
        owasp=next((e.activity.owasp for e in group if e.activity.owasp), None),
        top_targets=tuple(targets[:5]),
        rule_ids=tuple(sorted({rule for episode in group for rule in episode.rule_ids})),
        evidence=tuple(ref for episode in group for ref in episode.evidence)[:20],
        evidence_total=sum(episode.evidence_total for episode in group),
        episode_ids=tuple(episode.episode_id for episode in group),
        episode_count=len(group),
        named_by=worst.activity.rule_id,
    )


def _combined_outcome(group: Sequence[Episode]) -> Outcome:
    """Summarise several episodes' outcomes into one.

    Any success at all makes the aggregate mixed rather than blocked: a report
    that says "blocked" when one attempt in fifty got through would be actively
    misleading.
    """
    outcomes = {episode.outcome for episode in group}
    if outcomes == {Outcome.UNKNOWN}:
        return Outcome.UNKNOWN
    if outcomes <= {Outcome.BLOCKED, Outcome.UNKNOWN}:
        return Outcome.BLOCKED
    if outcomes <= {Outcome.SUCCESS, Outcome.UNKNOWN}:
        return Outcome.SUCCESS
    return Outcome.MIXED
