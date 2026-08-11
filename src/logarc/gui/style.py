"""How a node should look, decided as plain data.

No Qt here on purpose. These are the judgements that decide whether a graph
misinforms — whether a critical finding reads as critical, whether a blocked
attempt can be told from a successful one — and they should be checkable
without starting a window.

Two channels, kept separate so neither has to carry two meanings:

* **Colour is severity.** Ordered from grey through to red, so the eye reads the
  scale the taxonomy defines.
* **The border is outcome.** Whether the activity achieved anything is the
  difference between "someone tried" and "someone succeeded", and it must not be
  a shade of the same colour that already means something else.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarc.core.activity import Outcome, Severity
from logarc.core.graph import GraphKind

if TYPE_CHECKING:
    from logarc.core.graph import GraphNode

__all__ = [
    "CAPTION_COLOUR",
    "Border",
    "NodeStyle",
    "edge_label",
    "format_gap",
    "node_radius",
    "outcome_border",
    "severity_colour",
    "style_for",
    "summarise",
]

#: Severity as a colour ramp. Chosen to stay distinguishable in greyscale — a
#: report gets printed, and a finding that only reads in colour does not survive
#: the printer.
_SEVERITY_COLOURS: Final[dict[Severity, str]] = {
    Severity.INFO: "#9aa5b1",
    Severity.LOW: "#4c8dae",
    Severity.MEDIUM: "#d8a33c",
    Severity.HIGH: "#d4693a",
    Severity.CRITICAL: "#b5273a",
}

#: Radius bounds. The lower one keeps a single request clickable; the upper one
#: keeps a busy episode from swallowing the canvas.
_MIN_RADIUS: Final = 22.0
_MAX_RADIUS: Final = 62.0

#: Characters of an activity name shown before it is cut. Past this a node is
#: wider than the space between columns and the graph stops being readable.
_LABEL_LIMIT: Final = 34


@dataclass(frozen=True, slots=True)
class Border:
    """The outline of a node: what the outcome was."""

    style: str
    """`solid`, `dashed` or `dotted` — a renderer maps this to its own pen."""

    width: float
    colour: str


#: Captions are drawn beneath the node, on the canvas ground rather than on the
#: fill. A label long enough to be meaningful does not fit inside a circle sized
#: by request count, and shrinking it until it did was making the graph
#: unreadable at the scale it is first shown at.
CAPTION_COLOUR: Final = "#1f2933"


@dataclass(frozen=True, slots=True)
class NodeStyle:
    """Everything a renderer needs to draw one box."""

    fill: str
    border: Border
    radius: float


_OUTCOME_BORDERS: Final[dict[Outcome, Border]] = {
    # Solid and heavy: it worked. This is the one an investigator must not miss.
    Outcome.SUCCESS: Border(style="solid", width=3.0, colour="#1f2933"),
    # Dashed: some of it worked, which is its own finding.
    Outcome.MIXED: Border(style="dashed", width=3.0, colour="#1f2933"),
    # Dotted and light: every request was refused.
    Outcome.BLOCKED: Border(style="dotted", width=1.5, colour="#616e7c"),
    Outcome.UNKNOWN: Border(style="solid", width=1.0, colour="#9aa5b1"),
}


def severity_colour(severity: Severity) -> str:
    """The fill for a finding of this severity."""
    return _SEVERITY_COLOURS[severity]


def outcome_border(outcome: Outcome) -> Border:
    """The outline for an activity that ended this way."""
    return _OUTCOME_BORDERS[outcome]


def node_radius(request_count: int) -> float:
    """Size by volume, compressed so the biggest episode stays on screen.

    Growth is by the square root of the count rather than the count itself: a
    thousand-request sweep is genuinely bigger than a five-request probe, but
    not two hundred times bigger, and drawing it that way would leave no room
    for anything else.
    """
    scaled = _MIN_RADIUS + 4.0 * math.sqrt(max(request_count, 0))
    return min(scaled, _MAX_RADIUS)


def style_for(node: GraphNode) -> NodeStyle:
    """The complete appearance of one node."""
    return NodeStyle(
        fill=severity_colour(node.severity),
        border=outcome_border(node.outcome),
        radius=node_radius(node.request_count),
    )


def summarise(node: GraphNode) -> str:
    """A short caption: what it was, how much of it, and whether it worked."""
    label = node.label if len(node.label) <= _LABEL_LIMIT else node.label[: _LABEL_LIMIT - 1] + "…"
    requests = "1 request" if node.request_count == 1 else f"{node.request_count:,} requests"
    return f"{label}\n{requests} · {node.outcome.value}"


def format_gap(seconds: float | None) -> str:
    """A time gap, written the way someone would say it out loud."""
    if seconds is None:
        return ""
    if seconds < 1:
        return f"{seconds:.1f}s"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int(seconds % 3600 // 60)}m"


def edge_label(kind: GraphKind, *, weight: int, gap_seconds: float | None) -> str:
    """What to write beside an arrow.

    On a behaviour map the weight is the finding. A transition seen twice is a
    habit and one seen once is an incident, and the difference is what turns a
    set of arrows into a shape — a cycle between three probe types says the
    client is a tool rotating through them, which no single episode reveals.
    Carried only as line thickness, as it was, that cannot be read as a number
    or compared between two clients' maps.

    A weight of one is left off. Every step of a trace has one by construction,
    so printing it would add a column of identical numbers to every arrow on the
    chronological view, and on a busy behaviour map it is one more thing to read
    past.
    """
    gap = format_gap(gap_seconds)
    if kind is GraphKind.TRACE or weight <= 1:
        return gap
    return f"x{weight:,}" + (f" · {gap}" if gap else "")
