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
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarc.core.activity import Outcome, Severity
from logarc.core.graph import GraphKind

if TYPE_CHECKING:
    from logarc.core.graph import GraphNode

__all__ = [
    "CAPTION_COLOUR",
    "EVIDENCE_INK",
    "EVIDENCE_MUTED",
    "SIZE_NOTE",
    "Border",
    "LegendItem",
    "NodeStyle",
    "Span",
    "edge_label",
    "format_gap",
    "format_requests",
    "highlight_spans",
    "node_radius",
    "outcome_border",
    "outcome_legend",
    "severity_colour",
    "severity_legend",
    "status_colour",
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

#: The ring drawn around the activity whose evidence is on screen.
#:
#: Added *outside* the node rather than replacing its outline, because the
#: outline is the outcome and overwriting it would trade one piece of
#: information for another. Without it the evidence panel fills and the canvas
#: says nothing about which of a dozen nodes it belongs to.
SELECTION_COLOUR: Final = "#2c6ea8"
SELECTION_WIDTH: Final = 3.0


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
    return f"{label}\n{format_requests(node.request_count)} · {node.outcome.value}"


@dataclass(frozen=True, slots=True)
class LegendItem:
    """One row of the key: a sample to draw, and what it means."""

    label: str
    colour: str
    border: Border | None = None
    """Set for outcome rows, where the outline carries the meaning rather than
    the fill."""


#: What the third channel means. Size has no swatch — it is a comparison, not a
#: value — so it has to be said in words or it is not explained at all.
SIZE_NOTE: Final = "Node size grows with the request count, by square root."


def severity_legend() -> tuple[LegendItem, ...]:
    """The colour ramp, read from the table the renderer draws from.

    Generated rather than written out, so a severity added to the taxonomy
    cannot end up on the canvas as a colour the key does not name.
    """
    return tuple(
        LegendItem(label=level.name.title(), colour=_SEVERITY_COLOURS[level])
        for level in sorted(Severity)
    )


def outcome_legend() -> tuple[LegendItem, ...]:
    """The border styles, likewise read from the table that draws them."""
    return tuple(
        LegendItem(
            label=outcome.value.title(),
            colour=_OUTCOME_BORDERS[outcome].colour,
            border=_OUTCOME_BORDERS[outcome],
        )
        for outcome in Outcome
    )


#: Reading the raw evidence line.
#:
#: The panel is ~330px, about fifty characters. A Combined line spends its first
#: forty-five on the client address and the timestamp — the address the reader
#: picked from the table themselves, and a time already printed in the heading
#: above. Unwrapped, that is the entire visible width, and every line of
#: evidence reads `... "GET` with the payload off the right-hand edge.
#:
#: So the line is wrapped and the parts worth reading are marked in place. The
#: text is never rebuilt: these are offsets into the string the panel was
#: handed, so the evidence stays the bytes that came out of the log.
EVIDENCE_INK: Final = "#1f2933"
EVIDENCE_MUTED: Final = "#8996a4"

#: `"METHOD target PROTOCOL" status`. Deliberately strict: the closing quote
#: must be followed by a three-digit status, which is what stops the `request`
#: field of a JSON log — where the quoted group is followed by `}` or a comma —
#: from being marked as though it were a Combined request line.
_REQUEST_LINE: Final = re.compile(r'"[A-Z]+\s+(?P<target>\S+)\s+[^"]*"\s+(?P<status>\d{3})(?!\d)')


@dataclass(frozen=True, slots=True)
class Span:
    """A stretch of the raw line worth marking, as offsets into that line."""

    start: int
    end: int
    role: str
    """`target` or `status` — the renderer maps this to an appearance."""


def highlight_spans(text: str) -> tuple[Span, ...]:
    """Which parts of a raw log line the eye should land on.

    Returns nothing at all for a line whose shape is not recognised. logarc also
    reads nginx, IIS W3C and JSON, and a highlight guessed wrong is worse than
    no highlight: it would point the reader at the wrong part of the evidence
    with the same confidence it points at the right one.
    """
    match = _REQUEST_LINE.search(text)
    if match is None:
        return ()
    return (
        Span(match.start("target"), match.end("target"), "target"),
        Span(match.start("status"), match.end("status"), "status"),
    )


def status_colour(code: str) -> str:
    """How prominently to draw a response status.

    **Not a traffic light.** Here a 2xx on an injection is the alarm — it says
    the payload was served — and the 403 beside it is the reassurance. Green for
    200 would tell the reader the opposite of what the line means, which is the
    one thing this panel must never do.

    So served stands out and refused recedes, which is the same distinction
    `Outcome` already draws on the canvas.
    """
    return EVIDENCE_INK if code[:1] in {"2", "3"} and code.isdigit() else EVIDENCE_MUTED


def format_requests(count: int) -> str:
    """A request count with its noun agreeing with it.

    Shared rather than written out at each call site: the evidence panel said
    "1 requests" while the caption on the node beside it said "1 request",
    because each formatted the same number itself.
    """
    return "1 request" if count == 1 else f"{count:,} requests"


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
