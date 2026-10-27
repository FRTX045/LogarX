"""Reading a case for a front end to show.

The two decisions a reader's first click makes — what is in this case, and what
did this client do — with no Qt anywhere near them.

They used to live in `logarx.gui.app`, module-level and Qt-free on purpose, with
a comment saying so: inside worker closures the window had quietly disagreed with
the command line about what a case contains, and pulling them out was what let a
test hold both front ends to the same answer. The comment was right and the
placement was not. `gui.app` imports PyQt6, so "callable without a display" was
never true of anything that had to import the module first.

Out here it is true, which is the same move already made for `logarx.style` and
`logarx.timerange` and for the same reason: a decision about the evidence should
be checkable without starting a window.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarx.analysis import AnalysisPolicy, analyse_ip
from logarx.case import Case
from logarx.detect.ruleset import NO_EXTRA_RULES
from logarx.episode.builder import EpisodePolicy

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from logarx.analysis import AnalysisResult
    from logarx.core.graph import ActivityGraph, GraphNode
    from logarx.core.window import TimeWindow
    from logarx.detect.crs import CrsEvidence
    from logarx.detect.ruleset import RuleSet
    from logarx.storage.base import CaseOverview, IpSummary, TimeSlot

__all__ = [
    "CLIENT_LIMIT",
    "EVIDENCE_LIMIT",
    "CaseView",
    "node_for_episodes",
    "read_case",
    "reconstruct_client",
]

#: Clients listed at once. The table is for choosing from, not for reading in
#: full; a case with a third of a million clients would otherwise freeze the
#: window building rows nobody scrolls to.
CLIENT_LIMIT: Final = 500

#: Source lines a front end will put on screen for one activity.
#:
#: A limit on what can be *drawn*, which is the only limit this needs. It used to
#: be 25, sitting above an episode's twenty-reference sample and therefore never
#: binding — and that sample exists to keep an exported file small, a cost a
#: window that exports nothing until asked was paying anyway. Worse, the sample
#: is `events[:20]`, a prefix rather than a spread, so a fifty-request sweep was
#: read from its opening and never its end.
#:
#: 2,000 because filling the table happens on the interface thread: measured at
#: about 105ms for 500 rows, 670ms for 5,000 and 2.9s for 20,000, and a
#: three-second freeze is the hang `gui.workers` exists to prevent. At this
#: ceiling the fill takes about 500ms, and only for an activity holding two
#: thousand requests or more; the 49-request node this was checked against goes
#: from click to filled in 84ms. Reading the lines is not what costs —
#: `read_evidence` makes one streaming pass per source whether it is asked for
#: twenty lines or twenty thousand.
EVIDENCE_LIMIT: Final = 2_000


@dataclass(frozen=True, slots=True)
class CaseView:
    """Everything a freshly opened case needs, gathered in one visit.

    A record rather than a tuple because two of these figures look alike and
    are not: `listed` is what fits in the table, `whole.clients` is what the
    case holds. Confusing them is how a case of 119,880 clients came to
    describe itself as a case of 500.
    """

    listed: Sequence[IpSummary]
    """The rows for the table, capped at `CLIENT_LIMIT`."""

    crs: CrsEvidence

    whole: CaseOverview
    """The case itself: how many clients it holds and the stretch it covers.
    Never the window — this is what holds the date fields inside the case, so
    it has to keep describing the case while a narrower range is in force."""

    in_range: int
    """How many clients the range holds. The same as `whole.clients` when no
    range is in force. Counted, not measured off `listed`, which is capped."""

    bars: list[TimeSlot]


def read_case(path: Path, *, window: TimeWindow | None = None, buckets: int = 200) -> CaseView:
    """Read a case, or one stretch of it.

    The CRS evidence is read here rather than per reconstruction because it is a
    property of the case, not of the client being looked at, and a case is
    opened once against many clicks.
    """
    with Case.open(path) as case:
        narrowed = window is not None and not window.is_open
        listed = case.store.ip_summaries(
            limit=CLIENT_LIMIT, order_by="requests", window=window if narrowed else None
        )
        # Asked of the store, not worked out from `listed`. That list is the
        # busiest few hundred, and on a real case of 119,880 clients they
        # happened to cover eight days of a twenty-seven day case — so the date
        # fields stopped nineteen days short of traffic the band was drawing.
        whole = case.store.overview()
        # Counted once, when the case is opened. Measured at 0.029s on 200k
        # events and 0.077s on three million, against a reconstruction the
        # reader is waiting for anyway.
        return CaseView(
            listed=listed,
            crs=case.crs_evidence(),
            whole=whole,
            in_range=case.store.overview(window=window).clients if narrowed else whole.clients,
            bars=case.store.activity_over_time(buckets=buckets),
        )


def node_for_episodes(graph: ActivityGraph, episode_ids: frozenset[str]) -> GraphNode | None:
    """The activity in `graph` covering these episodes, if it draws one.

    Here with `read_case` and `reconstruct_client`, and Qt-free for the same
    reason: which activity a view switch lands on is a decision about the
    evidence, and it should be checkable without starting a window.

    Going from the map back to the trace, one behaviour node answers to several
    trace nodes — three enumeration episodes become one 35-request circle. The
    busiest wins, because that is the one that dominated what was being read,
    and `max` keeps the first of equals so two runs of the same case cannot ring
    different nodes.
    """
    covering = [node for node in graph.nodes if episode_ids.intersection(node.episode_ids)]
    if not covering:
        return None
    return max(covering, key=lambda node: node.request_count)


def reconstruct_client(
    path: Path,
    client_ip: str,
    crs: CrsEvidence,
    *,
    evidence_sample: int = EVIDENCE_LIMIT,
    window: TimeWindow | None = None,
    rules: RuleSet = NO_EXTRA_RULES,
) -> AnalysisResult:
    """Reconstruct one client, applying whatever CRS contributed to the case.

    `evidence_sample` is how many source references each episode keeps. A reading
    surface asks for as many as it can draw, because the engine's own default of
    twenty is a budget for an exported file rather than for a screen, and asking
    for more costs nothing to produce — it is a list slice, measured at the same
    90ms either way. What it buys is an activity read to its end rather than from
    its first twenty requests.

    The default is not lowered anywhere else: the CLI, the benchmark and the
    evaluation — which reconstructs every client in a corpus — go on using the
    engine's, and the window's `_export` asks for it back explicitly.

    `rules` is what the window holds from the reader's library. The same rules go
    to *Where to start*, so the queue and the graph agree.
    """
    with Case.open(path) as case:
        return analyse_ip(
            case.store,
            client_ip,
            # The case's own engine, so the window detects what the command line
            # and triage detect. Left to its default, `analyse_ip` builds an engine
            # with no `site_hosts`, and for two days the domain question was asked,
            # answered, saved — and then ignored by every reconstruction on screen.
            engine=case.rule_engine(rules),
            policy=AnalysisPolicy(episode=EpisodePolicy(evidence_sample=evidence_sample)),
            crs=crs.index,
            crs_fingerprint=crs.fingerprint,
            crs_coverage=crs.coverage,
            window=window,
        )
