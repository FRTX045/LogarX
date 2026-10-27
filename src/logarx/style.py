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

Both channels are drawn from a `Theme`. `DARK` is the active one; `LIGHT` is the
palette LogarX used to have, kept so that switching back is one line rather than
an archaeology exercise.

**One theme serves both renderers.** The window and the exported report take the
same ramp, because a critical finding has to be the same red on screen as in the
file handed to someone who never opened the tool — the fault
`test_the_report_paints_a_finding_the_colour_the_window_paints_it` exists to
catch. The functions here take a `theme` argument so a caller *can* ask for the
other one, but nothing in the codebase does, and a renderer that starts to would
be reintroducing exactly that bug.
"""

from __future__ import annotations

import math
import re
import textwrap
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final
from urllib.parse import unquote, unquote_plus

from logarx.core.activity import Outcome, Severity
from logarx.core.graph import GraphKind

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime, timedelta

    from logarx.core.graph import GraphNode
    from logarx.sessionize.segmenter import SessionPolicy

__all__ = [
    "CAPTION_COLOUR",
    "DARK",
    "EVIDENCE_INK",
    "EVIDENCE_MUTED",
    "LIGHT",
    "NOTICE_TINT",
    "PAPER",
    "PAPER_EDGE",
    "PAPER_STRIPE",
    "PIN_COLOUR",
    "PIN_MARK",
    "RENAME_HINT",
    "SELECTION_COLOUR",
    "SELECTION_TINT",
    "SELECTION_WIDTH",
    "SESSION_GROUND",
    "SIZE_NOTE",
    "THEME",
    "Border",
    "LegendItem",
    "NodeStyle",
    "Span",
    "Theme",
    "decode_target",
    "display_safe",
    "edge_label",
    "format_bytes",
    "format_gap",
    "format_requests",
    "highlight_spans",
    "node_radius",
    "outcome_border",
    "outcome_legend",
    "plural",
    "session_caption",
    "session_heading_tip",
    "session_name",
    "session_place",
    "session_rule",
    "severity_colour",
    "severity_legend",
    "severity_text_colour",
    "shorten_agent",
    "status_colour",
    "style_for",
    "summarise",
]

#: Radius bounds. The lower one keeps a single request clickable; the upper one
#: keeps a busy episode from swallowing the canvas.
_MIN_RADIUS: Final = 22.0
_MAX_RADIUS: Final = 62.0

#: How a caption's label is broken up. Past this width a node is wider than the
#: space between columns and the graph stops being readable, and past two lines
#: the caption is taller than the node it belongs to.
#:
#: Wrapped rather than cut at a single limit. "Forced Browsing (repeated
#: refusal)" ellipsed to "Forced Browsing (repeated refusal…", which loses
#: exactly the words that tell it apart from the other Forced Browsing node two
#: columns along; a second line costs six pixels and keeps the distinction.
_LABEL_LINE: Final = 26
_LABEL_LINES: Final = 2


@dataclass(frozen=True, slots=True)
class Border:
    """The outline of a node: what the outcome was."""

    style: str
    """`solid`, `dashed` or `dotted` — a renderer maps this to its own pen."""

    width: float
    colour: str


@dataclass(frozen=True, slots=True)
class Theme:
    """Every colour the interface draws with, as one swappable record.

    Two of these exist. `LIGHT` is what LogarX always looked like — pale paper,
    dark ink. `DARK` is what it looks like now, and is the one both the window
    and the report draw from.

    The surfaces are still *pinned* — a theme is chosen here, not taken from the
    OS palette — for the reason the light one always was: the ink colours are
    derived against a known ground, and a ground that varies by machine makes
    those derivations meaningless. What changed is which ground is pinned.

    The severity ramp is shared with the report, which is a light document, so
    it has to survive both grounds. It does, and by a wider margin than the ramp
    it replaced: against white the old ramp ran 2.50 / 3.67 / 2.28 / 3.57 / 6.33
    and this one runs 4.39 / 2.77 / 2.37 / 3.26 / 3.87 — worse for critical,
    better for info, a wash overall. Neither clears 3:1 for all five on white,
    and neither needs to: in the report a severity is a swatch and a stroke
    *beside* its own name, never a fill drawn underneath text. The report gave
    that constraint up deliberately, which is what
    `test_the_report_never_prints_a_severity_on_a_colour_it_cannot_be_read_against`
    guards — dormant while the markup keeps the colour off the text, and armed
    the moment anyone puts it back.
    """

    #: The window itself: menus, panels, status bar. Deepest of the three.
    chrome: str
    #: What a document is read on — the canvas, both tables, the detail pane.
    surface: str
    #: Panel headings and chips, lifted just off the surface.
    raised: str
    #: Alternating table rows.
    stripe: str
    #: Hairline between rows. Separates without drawing attention to itself.
    line: str
    #: The frame around a document surface, so it reads as a sheet laid on the
    #: window rather than a hole cut through it.
    edge: str

    #: Primary text, and the captions drawn beneath a node.
    #:
    #: Captions sit on the canvas ground rather than on the node fill: a label
    #: long enough to mean something does not fit inside a circle sized by
    #: request count, and shrinking it until it did made the graph unreadable at
    #: the scale it first opens at.
    ink: str
    #: Secondary text. A comparison against the ink beside it, not permission to
    #: be unreadable — this clears WCAG AA on the surface, on the stripe and on
    #: the selection tint, and recedes by being quieter rather than fainter.
    muted: str
    #: Structural labels: column headings, legend captions. The quietest text
    #: that still has to be read, so it clears AA too.
    faint: str

    #: Logged IP addresses and host names. This identifies the subject, without
    #: suggesting that the address is safe, hostile, or a clickable link.
    identity: str
    #: Recorded times and durations, consistent across lists and detail panes.
    timestamp: str
    #: Incomplete coverage, provisional results and other actionable cautions.
    warning: str

    #: The ring drawn around the activity whose evidence is on screen, and the
    #: colour of anything else that means "this is the one you chose".
    #:
    #: Added *outside* the node rather than replacing its outline, because the
    #: outline carries the outcome and overwriting it would trade one piece of
    #: information for another.
    accent: str
    #: Text on top of an accent fill.
    on_accent: str
    #: The ground under the selected row of the evidence table.
    #:
    #: Every cell in that table sets its own colour — that is how a served
    #: status is told from a refused one — and an item's own colour wins over
    #: the palette's `HighlightedText`, so a strong selection colour cannot
    #: bring legible text with it. A tint the row's existing ink stays readable
    #: on marks the selection without fighting it.
    tint: str

    #: The arrows between nodes, and the text of an empty canvas.
    edge_ink: str
    #: The canvas grid. Barely there on purpose: it gives an empty canvas a
    #: ground so it reads as a workspace rather than a failed render.
    grid_dot: str
    #: Something is wrong with this piece of evidence and the reader has to see
    #: that rather than an empty row.
    alert: str

    #: Severity as a colour ramp.
    #:
    #: On light it descends from grey to red and stays distinguishable in
    #: greyscale, because a report gets printed. On dark that ordering cannot be
    #: kept — amber is intrinsically brighter than red at any saturation that
    #: still reads as red — so the dark ramp trades luminance ordering for hue
    #: separation, and holds one guarantee instead: nothing falls below 3:1 on
    #: the surface, and critical is never the faintest thing on the canvas.
    severity: Mapping[Severity, str]
    #: The same severity hues, adjusted for readable text rather than node fills.
    #: Small lettering must clear 4.5:1 even on a selected or striped table row.
    severity_text: Mapping[Severity, str]
    #: Outcome as an outline. A border is drawn at the fill's edge and its job
    #: is to read *against that fill*, which is why the dark theme keeps dark
    #: outlines: on dark every fill is bright.
    outcomes: Mapping[Outcome, Border]


#: What LogarX always looked like. Nothing selects it now; it is kept so that
#: going back is one line, and so the values it holds are not lost to history.
LIGHT: Final = Theme(
    chrome="#e4e7eb",
    surface="#f5f7fa",
    raised="#eaeef3",
    stripe="#eaeef3",
    line="#dde3ea",
    edge="#c3ccd6",
    ink="#1f2933",
    muted="#566470",
    faint="#616e7c",
    identity="#246a63",
    timestamp="#65518f",
    warning="#805b14",
    accent="#2c6ea8",
    on_accent="#ffffff",
    tint="#cfe0f5",
    edge_ink="#616e7c",
    grid_dot="#e6eaef",
    alert="#b5273a",
    severity={
        Severity.INFO: "#9aa5b1",
        Severity.LOW: "#4c8dae",
        Severity.MEDIUM: "#d8a33c",
        Severity.HIGH: "#d4693a",
        Severity.CRITICAL: "#b5273a",
    },
    severity_text={
        Severity.INFO: "#566470",
        Severity.LOW: "#246a63",
        Severity.MEDIUM: "#805b14",
        Severity.HIGH: "#99451f",
        Severity.CRITICAL: "#a72235",
    },
    outcomes={
        # Solid and heavy: it worked. This is the one an investigator must not
        # miss.
        Outcome.SUCCESS: Border(style="solid", width=3.0, colour="#1f2933"),
        # Dashed: some of it worked, which is its own finding.
        Outcome.MIXED: Border(style="dashed", width=3.0, colour="#1f2933"),
        # Dotted and light: every request was refused.
        Outcome.BLOCKED: Border(style="dotted", width=1.5, colour="#616e7c"),
        Outcome.UNKNOWN: Border(style="solid", width=1.0, colour="#9aa5b1"),
    },
)

#: The window's theme. Neutrals sit at hue 70° carrying a fraction of its
#: chroma — warm enough that the greys are not clinical, nowhere near enough to
#: tint the evidence — against a blue accent that no severity colour comes near.
#:
#: Derived in OKLCH so the steps between surfaces are perceptually even, then
#: resolved to sRGB. `LOW` is the one severity that moved hue rather than
#: lightness: the old `#4c8dae` sat in the accent's own family, and a selection
#: ring beside a Low node has to be unmistakably the ring.
#:
#: Graphite rather than near-black since 2026-10-21. Windows draws the title bar
#: above the window at about #202020, and a chrome of #080706 under it read as
#: two programs stacked. Lifted so the two meet; `faint` rose with the ground to
#: keep its contrast, and the grid dot fell so the canvas stays quiet.
DARK: Final = Theme(
    chrome="#1b1a19",
    surface="#222120",
    raised="#2b2a29",
    stripe="#282726",
    line="#363533",
    edge="#4a4846",
    ink="#efeeed",
    muted="#b2b1af",
    faint="#9a9997",
    identity="#79c9c0",
    timestamp="#b9ade3",
    warning="#d0a144",
    accent="#49a9ff",
    on_accent="#001226",
    tint="#123153",
    edge_ink="#8a8987",
    grid_dot="#5c5b59",
    alert="#ff8293",
    severity={
        Severity.INFO: "#6e7a85",
        Severity.LOW: "#4baaa5",
        Severity.MEDIUM: "#d0a144",
        Severity.HIGH: "#d47548",
        Severity.CRITICAL: "#e14d5f",
    },
    severity_text={
        Severity.INFO: "#b2b1af",
        Severity.LOW: "#4baaa5",
        Severity.MEDIUM: "#d0a144",
        Severity.HIGH: "#eba27b",
        Severity.CRITICAL: "#ff8293",
    },
    outcomes={
        # One colour for all four, light, and the style carries the meaning.
        #
        # An outline is stroked *on* the edge of a fill, so half its width lies
        # inside the node and half lies on the canvas behind it. It therefore has
        # to be seen against the canvas, and the canvas is the darkest surface in
        # the window. Two earlier attempts here got that backwards: first the
        # light theme's greys, carried over unchanged, which recede on paper and
        # came to 2.32:1 on an amber node; then a near-black chosen to read
        # against the fill, which does — 4.4:1 at worst — while measuring
        # **1.01:1 against the ground**, so the outer half of every outline was
        # drawn in the ground's own colour and simply was not there.
        #
        # The fill varies by severity and the ground does not, so the ground is
        # what an outline must be legible against: at 16.5:1 this one is, on
        # every node, whatever its severity. Recession is left to the two
        # channels that still carry it here — dotted rather than solid, thin
        # rather than heavy — which is also what this module says a border is
        # for: the outline is the outcome, and it "must not be a shade of the
        # same colour that already means something else".
        Outcome.SUCCESS: Border(style="solid", width=3.0, colour="#efeeed"),
        Outcome.MIXED: Border(style="dashed", width=3.0, colour="#efeeed"),
        Outcome.BLOCKED: Border(style="dotted", width=1.5, colour="#efeeed"),
        Outcome.UNKNOWN: Border(style="solid", width=1.0, colour="#efeeed"),
    },
)

#: Which one the window is drawing in. Everything below reads through this, so
#: switching back to light — or adding a runtime toggle — is this one line.
THEME: Final = DARK

#: The names the renderers already import, kept pointing at the active theme so
#: no call site has to know a theme exists. `PAPER` is a light-theme name for
#: what is now a dark surface; renaming it is a separate change from choosing a
#: different colour, and doing both at once would bury one in the other.
PAPER: Final = THEME.surface
PAPER_STRIPE: Final = THEME.stripe
PAPER_EDGE: Final = THEME.edge
CAPTION_COLOUR: Final = THEME.ink
SELECTION_COLOUR: Final = THEME.accent
SELECTION_TINT: Final = THEME.tint

#: How heavy the selection ring is. Not a colour, so it does not vary by theme.
SELECTION_WIDTH: Final = 3.0

#: The ground a warning strip is painted on: the MEDIUM severity amber sunk
#: almost to the chrome, so that a band of it across the window does not
#: out-shout the evidence beneath. Here rather than in the widget for the reason
#: every other colour is — `THEME` is meant to be every colour the interface
#: draws with, and a hex literal inside a widget is one no theme can reach.
#:
#: Measured against this ground: ink 14.4:1, muted 7.8:1, MEDIUM amber 7.0:1,
#: faint 4.8:1 — the four inks the strip actually uses, all clear of WCAG AA.
#: The obvious first choice, `#2a2113`, put faint at 4.53:1, which passes and
#: leaves nothing in hand; this one is a shade deeper and costs nothing.
#: `test_every_ink_on_the_banner_can_be_read_against_its_ground` holds all four.
NOTICE_TINT: Final = "#241d11"

#: Drawn beside a case held at the top of the recent list.
#:
#: A star rather than a pushpin, and a text glyph rather than an emoji. `📌` is
#: pictographic, so the font paints it in its own colours and the palette has no
#: say — it arrived as the only saturated red in that dialog, in an interface
#: where red is `THEME.alert` and means something is wrong with the evidence. A
#: case someone chose to keep at the top is not a problem.
PIN_MARK: Final = "★"

#: The accent, because pinning is a choice the reader made — the same thing the
#: ring around a selected node says elsewhere.
PIN_COLOUR: Final = THEME.accent

#: A bookmark category's ribbon, handed out in this order and kept by the
#: category, so a colour never moves when another category is deleted.
#:
#: The accent first, because the first category is the one a bookmark lands in
#: when the reader chose nothing. No red: `THEME.alert` means something is wrong
#: with the evidence, and a reader's own label is not that. Picked by measuring:
#: every pair at least 0.109 apart in OKLab, every one at least 0.127 from the
#: alert, and every one above 6:1 against each surface a ribbon is drawn on.
CATEGORY_COLOURS: Final = (
    THEME.accent,
    "#d0a144",
    "#79c9c0",
    "#b9ade3",
    "#8cc66a",
    "#e8e06a",
    "#ff9df0",
    "#a0e8ff",
)


def _blend(under: str, over: str, share: float) -> str:
    """`over` laid on `under` at `share` opacity, as the one opaque colour that
    results. Opaque because whatever is drawn on it has to match it exactly."""
    lower = [int(under[i : i + 2], 16) for i in (1, 3, 5)]
    upper = [int(over[i : i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(
        f"{round(low + share * (high - low)):02x}" for low, high in zip(lower, upper, strict=True)
    )


#: The inside of a session's box: the paper with a breath of the accent over
#: it, the blue the reader picked from the mockups on 2026-10-17.
#:
#: One opaque colour rather than a translucent fill, because everything written
#: inside a box sits on a patch that hides the arrow behind it, and that patch
#: has to be exactly this colour or every caption carries a dark square. A
#: translucent fill composites to this only where nothing else overlaps it.
#:
#: Measured against it: caption ink 15.55:1, muted 8.41:1, selection ring
#: 7.21:1, faintest severity (info) 4.11:1 — every floor the theme states for
#: the plain ground still holds, which
#: `test_everything_drawn_inside_a_box_still_reads_against_it` keeps true.
SESSION_GROUND: Final = _blend(THEME.surface, THEME.accent, 0.05)


@dataclass(frozen=True, slots=True)
class NodeStyle:
    """Everything a renderer needs to draw one box."""

    fill: str
    border: Border
    radius: float


def severity_colour(severity: Severity, *, theme: Theme = THEME) -> str:
    """The fill for a finding of this severity.

    `theme` exists so a caller *can* ask for the other palette; every caller
    takes the default, and the report deliberately among them. Screen and paper
    agreeing about what a severity looks like is an invariant with a test on it.
    """
    return theme.severity[severity]


def severity_text_colour(severity: Severity, *, theme: Theme = THEME) -> str:
    """A detection's severity as readable lettering, in the canvas's hue family."""
    return theme.severity_text[severity]


def outcome_border(outcome: Outcome, *, theme: Theme = THEME) -> Border:
    """The outline for an activity that ended this way."""
    return theme.outcomes[outcome]


def node_radius(request_count: int) -> float:
    """Size by volume, compressed so the biggest episode stays on screen.

    Growth is by the square root of the count rather than the count itself: a
    thousand-request sweep is genuinely bigger than a five-request probe, but
    not two hundred times bigger, and drawing it that way would leave no room
    for anything else.
    """
    scaled = _MIN_RADIUS + 4.0 * math.sqrt(max(request_count, 0))
    return min(scaled, _MAX_RADIUS)


def style_for(node: GraphNode, *, theme: Theme = THEME) -> NodeStyle:
    """The complete appearance of one node."""
    return NodeStyle(
        fill=severity_colour(node.severity, theme=theme),
        border=outcome_border(node.outcome, theme=theme),
        radius=node_radius(node.request_count),
    )


def summarise(node: GraphNode) -> str:
    """A short caption: what it was, how much of it, and whether it worked."""
    lines = (
        *_wrap_label(node.label),
        f"{format_requests(node.request_count)} · {node.outcome.value}",
    )
    return "\n".join(lines)


def _wrap_label(label: str) -> tuple[str, ...]:
    """An activity name over at most two lines, cut only if it needs a third."""
    lines = textwrap.wrap(label, width=_LABEL_LINE) or [""]
    if len(lines) <= _LABEL_LINES:
        return tuple(lines)
    kept = lines[:_LABEL_LINES]
    kept[-1] = kept[-1][: _LABEL_LINE - 1] + "…"
    return tuple(kept)


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
#:
#: Phrased as a key entry rather than a sentence. As "Node size grows with the
#: request count, by square root." it was 600px wide, and a flow layout asks for
#: no less than its widest single item: one explanatory sentence was setting the
#: minimum width of the whole legend, and through it the centre column. The
#: square root is kept because it is the part that stops a reader inferring that
#: a 1,000-request node is two hundred times a five-request one.
SIZE_NOTE: Final = "Size = request count, by square root"


def severity_legend(*, theme: Theme = THEME) -> tuple[LegendItem, ...]:
    """The colour ramp, read from the table the renderer draws from.

    Generated rather than written out, so a severity added to the taxonomy
    cannot end up on the canvas as a colour the key does not name.
    """
    return tuple(
        LegendItem(label=level.name.title(), colour=theme.severity[level])
        for level in sorted(Severity)
    )


def outcome_legend(*, theme: Theme = THEME) -> tuple[LegendItem, ...]:
    """The border styles, likewise read from the table that draws them."""
    return tuple(
        LegendItem(
            label=outcome.value.title(),
            colour=theme.outcomes[outcome].colour,
            border=theme.outcomes[outcome],
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
#: `Muted` is a comparison against the ink beside it, not permission to be
#: unreadable. What it colours is the response status — one of the two things a
#: row exists to show — and a refused request is still evidence, so it clears
#: WCAG AA on the surface, on the alternating stripe and on the selection tint,
#: and recedes by being quieter than the ink rather than by being hard to read.
#: `tests/gui/test_style.py` holds all three of those to 4.5:1 whichever theme
#: is active, which is what stops a palette change from quietly breaking it.
EVIDENCE_INK: Final = THEME.ink
EVIDENCE_MUTED: Final = THEME.muted

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

    Returns nothing at all for a line whose shape is not recognised. LogarX also
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


def status_colour(code: str, *, theme: Theme = THEME) -> str:
    """How prominently to draw a response status.

    **Not a traffic light.** Here a 2xx on an injection is the alarm — it says
    the payload was served — and the 403 beside it is the reassurance. Green for
    200 would tell the reader the opposite of what the line means, which is the
    one thing this panel must never do.

    So served stands out and refused recedes, which is the same distinction
    `Outcome` already draws on the canvas.
    """
    return theme.ink if code[:1] in {"2", "3"} and code.isdigit() else theme.muted


def display_safe(text: str) -> str:
    """Replace anything that could forge what the reader sees.

    Everything drawn in the evidence panel came out of a request, and the
    request was written by whoever is being investigated. Decoding turns their
    percent escapes back into the characters they stand for, and some of those
    characters do not merely *say* something — they *do* something:

    * `%0A` becomes a line break, and a line break lets an attacker compose
      what looks like a second log entry, complete with a status of their
      choosing, inside the panel a forensic finding is read from.
    * `%E2%80%AE` is a right-to-left override, which reverses how everything
      after it is drawn. A hostile path can be made to read as an innocent one
      while remaining exactly what it is.

    So every control and format character is replaced by its codepoint spelled
    out. Verbose on purpose: `<U+000A>` tells an analyst precisely what was in
    the request, which a blank space or a dropped character would not.
    """
    return "".join(
        f"<U+{ord(char):04X}>" if unicodedata.category(char) in {"Cc", "Cf"} else char
        for char in text
    )


def decode_target(target: str) -> str:
    """A request target as the attacker wrote it, readable and inert.

    `%27+OR+%271%27%3D%271` is a textbook tautology and reads as line noise;
    `' OR '1'='1` is the same thing and reads as the attack. Nobody should have
    to decode that in their head twenty-five times to work through one episode.

    The path and the query are decoded under different rules, because `+` means
    a space in a query string and means `+` in a path — one rule over the whole
    target corrupts whichever side it is wrong about. A malformed escape is left
    exactly as it was logged rather than guessed at, and one pass of decoding is
    all that happens, so a doubly-encoded payload keeps the percent signs that
    give the evasion away.
    """
    path, question, query = target.partition("?")
    decoded = unquote(path) + (question + unquote_plus(query) if question else "")
    return display_safe(decoded)


def format_bytes(count: int) -> str:
    """A response size, written the way someone would say it out loud.

    Worth the trouble because on a hostile request the size *is* a finding: a
    large body returned to an injection says data left the building. "10648" is
    a number to work out; "10.4 KB" is a size to recognise.
    """
    if count < 1024:
        return f"{count} B"
    if count < 1024 * 1024:
        return f"{count / 1024:.1f} KB"
    return f"{count / (1024 * 1024):.1f} MB"


def shorten_agent(agent: str, limit: int = 64) -> str:
    """A user agent with its middle taken out.

    The agent is more than half the width of a Combined line and is almost
    never what is being looked at — except when it is the entire finding, and
    those are short: `sqlmap/1.5.2` survives this untouched. What gets cut is
    the middle of a long browser string, which is boilerplate; what identifies
    the client sits at the ends. The whole value is a keystroke away in the raw
    line either way.
    """
    if len(agent) <= limit:
        return agent
    head, tail = (limit - 1) * 2 // 3, (limit - 1) // 3
    return f"{agent[:head]}…{agent[-tail:]}"


def plural(count: int, noun: str, many: str | None = None) -> str:
    """A count with its noun agreeing with it.

    The general form of `format_requests`, which existed first and for the same
    reason: two call sites formatting the same number disagreed about it. That
    fix stopped at one noun, and the window went on saying `500 client(s)`,
    `1 session(s)`, `68 path(s)` and `3 file(s)` — a bracketed `(s)` being what
    a program writes when nobody decided, and this one had decided.

    `many` is for a noun whose plural is not the singular plus an `s`;
    everything LogarX counts so far is regular, but `activity` is one edit away
    from being counted and would come out as `activities` here rather than
    wrongly.
    """
    if count == 1:
        return f"1 {noun}"
    return f"{count:,} {many if many is not None else noun + 's'}"


def format_requests(count: int) -> str:
    """A request count with its noun agreeing with it.

    Kept as its own name because it is the one every renderer reaches for, and
    a caption reading `plural(n, "request")` says less about what it is than
    the call it replaced.
    """
    return plural(count, "request")


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


def session_caption(index: int, total: int, nodes: Sequence[GraphNode]) -> str:
    """What a session's box says: which visit, how much happened, and when.

    `Session 2 of 69 · 2 activities · 09 Mar 01:55\u201302:26`. The count of
    sessions is the one the header gives, so the box and the header agree.
    `nodes` is never empty: a session is drawn because it has activities.
    """
    start = min(node.start for node in nodes)
    end = max(node.end for node in nodes)
    return (
        f"Session {index:,} of {total:,}"
        f" · {plural(len(nodes), 'activity', 'activities')}"
        f" · {_session_span(start, end)}"
    )


def session_place(index: int, total: int, nodes: Sequence[GraphNode]) -> str:
    """Which visit, and when: `Session 1 of 7 · 09 Mar 09:06\u201309:08`.

    The box's label without its count of activities, for the window that
    renames a session, where the count says nothing about which one it is.
    """
    start = min(node.start for node in nodes)
    end = max(node.end for node in nodes)
    return f"Session {index:,} of {total:,} · {_session_span(start, end)}"


def session_name(nodes: Sequence[GraphNode]) -> str:
    """LogarX's name for a session: the label of its most important activity.

    Most severe first, then a hostile kind over a benign one, which is the
    order an episode picks its own label by (`episode.builder._representative`),
    so a session and its activities agree about what mattered. Then the most
    requests, and on a full tie the earliest, which `nodes` lists first.

    `Unnamed session` for a blank label. Never seen on 2,504 sessions measured;
    it keeps a blank heading off the canvas should a rule ever have no name.
    """
    lead: GraphNode | None = None
    for node in nodes:
        if lead is None or (node.severity, node.category.is_hostile, node.request_count) > (
            lead.severity,
            lead.category.is_hostile,
            lead.request_count,
        ):
            lead = node
    label = lead.label.strip() if lead is not None else ""
    return label or "Unnamed session"


#: The last line of a session heading's tip, so the way to rename is found
#: where the name is read.
RENAME_HINT: Final = "Double-click the title to rename this session."


def session_heading_tip(rule: str, logarx_name: str, *, renamed: bool) -> str:
    """What resting the pointer on a session's heading says.

    For a name the reader gave, LogarX's own name comes first: a reader's
    words on the canvas must never be taken for something the log says. Then
    what a session is, `rule`, when the canvas was told; then how to rename.
    """
    parts = [f"Named by you. LogarX's name: {logarx_name}"] if renamed else []
    if rule:
        parts.append(rule)
    parts.append(RENAME_HINT)
    return "\n\n".join(parts)


def _session_span(start: datetime, end: datetime) -> str:
    """When a session ran, in the window's `09 Mar 01:55` form.

    One time for a session inside one minute, where a range from 09:42 to
    09:42 would read as a typing error; both days for one that crosses
    midnight, where 23:50 to 00:20 would read as running backwards.
    """
    if start.date() != end.date():
        return f"{start:%d %b %H:%M} \u2013 {end:%d %b %H:%M}"
    if (start.hour, start.minute) == (end.hour, end.minute):
        return f"{start:%d %b %H:%M}"
    return f"{start:%d %b %H:%M}\u2013{end:%H:%M}"


def session_rule(policy: SessionPolicy) -> str:
    """What a session is, in the thresholds it was cut with: the tip on a
    session box's label.

    Written as what every session holds to, not as what ends one. A time filter
    also cuts a visit at its edges, so "it ends after thirty minutes" would be
    wrong about the boxes at either end of a filtered trace, while "no pause
    inside it is longer" is true of all of them.
    """
    lines = [
        "A session is one visit from this address.",
        f"No pause inside it is longer than {_threshold(policy.idle_timeout)},",
    ]
    if policy.split_on_user_agent_change:
        lines.append("every request in it has the same user agent,")
    lines.append(f"and it lasts {_threshold(policy.max_duration)} at most.")
    return "\n".join(lines)


def _threshold(span: timedelta) -> str:
    """A threshold in the largest whole unit that states it exactly.

    Exactly, because it is quoted for a reader to check gaps against: ninety
    seconds rounded to two minutes would leave a gap of a hundred seconds
    looking as though it broke the rule that cut it.
    """
    seconds = int(span.total_seconds())
    if seconds % 3600 == 0:
        return plural(seconds // 3600, "hour")
    if seconds % 60 == 0:
        return plural(seconds // 60, "minute")
    return plural(seconds, "second")
