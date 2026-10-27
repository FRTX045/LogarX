"""What a few rules find in a case: the lines each labels and the clients behind them.

For the rules tab, which shows it beside the pack on show while the reader edits.
Every label counts, not only the one that won, so a rule that fires and loses to
a stronger one still shows — the reader is asking whether their rule matches,
not whether it names the activity.

Labels sessions as a reconstruction does (`label_sessions`), so a window rule
counts the lines the graph would credit it with. The engine holds only the rules
on show: no rule's label depends on another rule's (window metrics read the
request, not its labels), and an engine of two rules reads a case far faster than
one of a hundred.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from time import monotonic
from typing import TYPE_CHECKING

from logarx.analysis import label_sessions
from logarx.case import Case
from logarx.sessionize.segmenter import SessionPolicy
from logarx.style import display_safe

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import datetime
    from pathlib import Path

    from logarx.core.event import NormalizedEvent
    from logarx.core.evidence import EvidenceRef
    from logarx.detect.rules import Rule

__all__ = ["Example", "Find", "FindsCancelled", "FindsProgress", "count_finds"]


@dataclass(frozen=True, slots=True)
class Example:
    """One line a rule labelled, as the Add a rule window lists it.

    `ref` names the line; client, time and request alone do not.
    """

    ref: EvidenceRef
    client: str
    when: datetime
    request: str
    status: int | None

    @classmethod
    def of(cls, event: NormalizedEvent) -> Example:
        request = display_safe(f"{event.method or '-'} {event.target or '-'}")
        return cls(event.evidence, event.client_ip, event.timestamp, request, event.status)


@dataclass(frozen=True, slots=True)
class Find:
    lines: int
    clients: int
    examples: tuple[Example, ...] = ()


@dataclass(frozen=True, slots=True)
class FindsProgress:
    done: int
    total: int
    finds: dict[str, Find]


class FindsCancelled(Exception):  # noqa: N818 - stopping is a normal outcome of a count
    """The count was stopped: the pack changed, or the dialog closed."""


def count_finds(
    case_path: Path,
    rules: Sequence[Rule],
    *,
    cancelled: Callable[[], bool] | None = None,
    report: Callable[[FindsProgress], None] | None = None,
    every: float = 0.25,
    examples: int = 0,
) -> dict[str, Find]:
    """Per rule id in `rules`, the lines it labels and how many clients they come from.

    With `examples`, up to that many of each rule's lines too, the first met:
    clients in the store's order, each client's lines in time order.
    """
    wanted = {rule.id for rule in rules}
    lines: Counter[str] = Counter()
    clients: Counter[str] = Counter()
    found: dict[str, list[Example]] = {rule_id: [] for rule_id in wanted}
    policy = SessionPolicy()
    with Case.open(case_path) as case:
        engine = case.engine_for(rules)
        total = case.store.overview().clients
        done = 0
        last = monotonic()
        for events in case.store.iter_clients():
            if cancelled is not None and cancelled():
                raise FindsCancelled
            ordered = sorted(events, key=lambda e: (e.timestamp, e.evidence.line_no))
            here: set[str] = set()
            for _, labelled in label_sessions(ordered, engine, policy=policy):
                for item in labelled:
                    for rule_id in {label.rule_id for label in item.all_labels} & wanted:
                        lines[rule_id] += 1
                        here.add(rule_id)
                        if len(found[rule_id]) < examples:
                            found[rule_id].append(Example.of(item.event))
            clients.update(here)
            done += 1
            if report is not None and monotonic() - last >= every:
                report(FindsProgress(done, total, _finds(wanted, lines, clients, found)))
                last = monotonic()
    if report is not None:
        report(FindsProgress(done, total, _finds(wanted, lines, clients, found)))
    return _finds(wanted, lines, clients, found)


def _finds(
    wanted: set[str],
    lines: Counter[str],
    clients: Counter[str],
    found: dict[str, list[Example]],
) -> dict[str, Find]:
    return {
        rule_id: Find(lines[rule_id], clients[rule_id], tuple(found[rule_id]))
        for rule_id in sorted(wanted)
    }
