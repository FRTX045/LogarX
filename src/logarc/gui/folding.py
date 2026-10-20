"""Which lines of an activity fold into one row, and what that row may claim.

Lines that repeat bury what matters: one tool can send the same request dozens
of times, and the evidence panel used to give every one of them a row. Folding
draws a run of them as one row with a count, which opens to show each line.

Qt-free, like `gui.evidence_view`. Whether a row may say 401 for five lines is the
decision that keeps the panel honest, and it is checked here without a window.

A folded row shows each column once. So the default rule folds only lines that
agree on every column the table shows apart from Line and Time. The looser rules
fold more, and the cells they cannot honestly fill say so instead of showing one
line's value (`gui.evidence_view.fold_cells`). Measured on the bundled log on
2026-10-20, trace view, 3,825 lines: the default leaves 3,629 rows and no fold
that hides a difference; same path leaves 3,553 and 18 that do.

Folding is a display decision. It changes nothing in the case, the reports or
any count reported anywhere.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Final, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable, Sequence

    from logarc.core.evidence import EvidenceRef
    from logarc.evidence import EvidenceLine

__all__ = ["DEFAULT_FOLD", "Fold", "FoldRule", "Spread", "fold", "log_order", "named", "spread"]

T = TypeVar("T")


class FoldRule(Enum):
    """What two neighbouring lines must share to be drawn as one row.

    Every rule includes the method: `POST /login` never folds with `GET /login`.
    The request is compared as logged, not decoded, so two lines the log wrote
    differently stay apart even when they decode to the same text.
    """

    OFF = "off"
    PATH = "path"
    REQUEST = "request"
    REQUEST_STATUS = "request_status"
    REQUEST_STATUS_SIZE = "request_status_size"

    @property
    def label(self) -> str:
        """The choice as Preferences offers it."""
        return _LABELS[self]

    @property
    def says(self) -> str:
        """What has to match, as the fold note says it: `request, status and size`."""
        return _SAYS[self]

    @property
    def stored(self) -> str:
        """The settings value. The enum's value, named for what it is for."""
        return str(self.value)


_LABELS: Final = {
    FoldRule.OFF: "Off",
    FoldRule.PATH: "Same path",
    FoldRule.REQUEST: "Same request",
    FoldRule.REQUEST_STATUS: "Same request and status",
    FoldRule.REQUEST_STATUS_SIZE: "Same request, status and size",
}
_SAYS: Final = {
    FoldRule.OFF: "",
    FoldRule.PATH: "path",
    FoldRule.REQUEST: "request",
    FoldRule.REQUEST_STATUS: "request and status",
    FoldRule.REQUEST_STATUS_SIZE: "request, status and size",
}

#: The one rule that never folds lines a row would misstate.
DEFAULT_FOLD: Final = FoldRule.REQUEST_STATUS_SIZE


def named(text: str) -> FoldRule:
    """The rule a stored value stands for.

    Anything unrecognised is the default rather than an error: settings outlive
    the code that wrote them, as `density.named` says for the band.
    """
    try:
        return FoldRule(str(text).strip().lower())
    except ValueError:
        return DEFAULT_FOLD


@dataclass(frozen=True, slots=True)
class Fold:
    """A run of lines drawn as one row: indices into the lines, in log order."""

    members: tuple[int, ...]

    @property
    def head(self) -> int:
        """The line the row is drawn from, and the one a closed row selects."""
        return self.members[0]

    def __len__(self) -> int:
        return len(self.members)


@dataclass(frozen=True, slots=True)
class Spread:
    """The values one column takes across a fold, most common first."""

    values: tuple[tuple[str, int], ...]

    @property
    def shared(self) -> bool:
        """Whether every line has the same value, the only case a row may show it."""
        return len(self.values) == 1

    def tip(self, limit: int = 10) -> str:
        """`401 x36 · 429 x2 · 302 x1`, and how many more past `limit`."""
        shown = " · ".join(f"{value} x{count}" for value, count in self.values[:limit])
        rest = len(self.values) - limit
        return shown + (f" and {rest} more" if rest > 0 else "")


def log_order(lines: Sequence[EvidenceLine]) -> list[int]:
    """Indices of `lines` in the order the log holds them: file, then line."""
    return sorted(
        range(len(lines)), key=lambda i: (lines[i].ref.source_file_id, lines[i].ref.line_no)
    )


def fold(
    lines: Sequence[EvidenceLine],
    rule: FoldRule,
    visit_of: Callable[[EvidenceRef], Hashable] | None = None,
) -> tuple[Fold, ...]:
    """Every line in exactly one fold, the folds in log order.

    Neighbours fold when `rule` calls them the same and they belong to the same
    visit. `visit_of` maps a line's reference to its episode; without it every
    line is in one visit, which is what a trace node is. On the behaviour map a
    node is many visits, and the same 401 at the end of one day and the start of
    the next would otherwise be one row whose times hide the days between.
    """
    runs: list[list[int]] = []
    last: tuple[object, ...] | None = None
    for index in log_order(lines):
        key = _key(rule, lines[index])
        whole = None if key is None else (key, visit_of(lines[index].ref) if visit_of else None)
        if runs and whole is not None and whole == last:
            runs[-1].append(index)
        else:
            runs.append([index])
        last = whole
    return tuple(Fold(tuple(run)) for run in runs)


def spread(items: Sequence[T], show: Callable[[T], str]) -> Spread:
    """How often each distinct value occurs, shown with `show`, most common first.

    Counted on the values themselves, not on what `show` makes of them: 7,744
    and 7,745 bytes both read `7.6 KB`, and are still two values.
    """
    counts = Counter(items)
    ordered = sorted(counts, key=lambda value: (-counts[value], items.index(value)))
    return Spread(tuple((show(value), counts[value]) for value in ordered))


def _key(rule: FoldRule, line: EvidenceLine) -> tuple[object, ...] | None:
    """What neighbours must share under `rule`; None for a line that never folds.

    A line that could not be read, or that the parser did not read, has no
    request to compare, and is itself a fact about the evidence.
    """
    event = line.event
    if rule is FoldRule.OFF or event is None:
        return None
    if rule is FoldRule.PATH:
        return (event.method, event.path)
    request = (event.method, event.target)
    if rule is FoldRule.REQUEST:
        return request
    if rule is FoldRule.REQUEST_STATUS:
        return (*request, event.status)
    return (*request, event.status, event.bytes_sent)
