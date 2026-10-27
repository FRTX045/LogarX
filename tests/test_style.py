"""How a node is drawn, decided without Qt so it can be checked without a display."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import combinations, pairwise

import pytest

from colours import apart, chroma, contrast, hue_apart
from logarx.core.activity import ActivityCategory, Outcome, Severity
from logarx.core.evidence import EvidenceRef
from logarx.core.graph import GraphKind, GraphNode
from logarx.sessionize.segmenter import SessionPolicy
from logarx.style import (
    CAPTION_COLOUR,
    CATEGORY_COLOURS,
    DARK,
    EVIDENCE_INK,
    EVIDENCE_MUTED,
    LIGHT,
    PAPER,
    PAPER_STRIPE,
    RENAME_HINT,
    SELECTION_COLOUR,
    SELECTION_TINT,
    SESSION_GROUND,
    SIZE_NOTE,
    THEME,
    NodeStyle,
    decode_target,
    edge_label,
    format_bytes,
    format_gap,
    format_requests,
    highlight_spans,
    node_radius,
    outcome_border,
    outcome_legend,
    plural,
    session_caption,
    session_heading_tip,
    session_name,
    session_place,
    session_rule,
    severity_colour,
    severity_legend,
    severity_text_colour,
    shorten_agent,
    status_colour,
    style_for,
    summarise,
)


@pytest.mark.parametrize("theme", [DARK, LIGHT])
@pytest.mark.parametrize("surface", ["surface", "raised", "stripe", "tint"])
def test_semantic_text_stays_readable_on_normal_and_selected_surfaces(theme, surface):
    ground = getattr(theme, surface)
    for colour in (theme.identity, theme.timestamp, theme.warning, theme.alert):
        assert contrast(colour, ground) >= 4.5
    for severity in Severity:
        assert contrast(severity_text_colour(severity, theme=theme), ground) >= 4.5


START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)

COMBINED = (
    "100.66.0.118 - - [01/May/2024:04:06:02 +0000] "
    '"GET /product.php?id=1%27%20UNION%20SELECT%20pw%20FROM%20users-- HTTP/1.1" 200 1400 '
    '"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)


def node(
    *,
    severity: Severity = Severity.INFO,
    outcome: Outcome = Outcome.SUCCESS,
    category: ActivityCategory = ActivityCategory.BROWSING,
    requests: int = 1,
    label: str = "Page View",
) -> GraphNode:
    return GraphNode(
        node_id="n1",
        label=label,
        category=category,
        severity=severity,
        outcome=outcome,
        request_count=requests,
        distinct_paths=1,
        bytes_total=1024,
        start=START,
        end=START,
        owasp=None,
        top_targets=("/",),
        rule_ids=("benign:browsing",),
        evidence=(EvidenceRef("access.log", 1),),
        evidence_total=1,
        episode_ids=("s1/1",),
    )


def test_severity_reads_as_a_scale() -> None:
    """Colour has to order the same way severity does, or it misinforms."""
    colours = [severity_colour(level) for level in Severity]

    assert len(set(colours)) == len(colours), "each level needs its own colour"
    assert all(colour.startswith("#") and len(colour) == 7 for colour in colours)


def test_a_critical_finding_does_not_look_like_an_informational_one() -> None:
    assert severity_colour(Severity.CRITICAL) != severity_colour(Severity.INFO)


def test_outcome_is_carried_by_the_border_not_the_fill() -> None:
    """Severity owns colour, so outcome needs a channel of its own."""
    assert len({outcome_border(outcome).style for outcome in Outcome}) > 1


def test_a_blocked_attempt_is_drawn_differently_from_a_successful_one() -> None:
    """The distinction the whole reconstruction is built around."""
    assert outcome_border(Outcome.BLOCKED) != outcome_border(Outcome.SUCCESS)


def test_a_busier_activity_is_drawn_larger() -> None:
    assert node_radius(500) > node_radius(50) > node_radius(5)


def test_size_grows_slowly_enough_to_stay_on_screen() -> None:
    """A thousand-request episode must not be two hundred times a five-request one."""
    assert node_radius(10_000) < node_radius(10) * 6


def test_a_single_request_still_has_a_visible_size() -> None:
    assert node_radius(1) >= 20
    assert node_radius(0) >= 20


def test_a_style_carries_everything_needed_to_draw_one_node() -> None:
    style = style_for(node(severity=Severity.CRITICAL, outcome=Outcome.MIXED, requests=42))

    assert isinstance(style, NodeStyle)
    assert style.fill == severity_colour(Severity.CRITICAL)
    assert style.border == outcome_border(Outcome.MIXED)
    assert style.radius == node_radius(42)
    assert style.radius > 0


def test_hostile_and_ordinary_activity_are_told_apart_at_a_glance() -> None:
    attack = style_for(node(severity=Severity.HIGH, category=ActivityCategory.INJECTION))
    ordinary = style_for(node(severity=Severity.INFO, category=ActivityCategory.BROWSING))

    assert attack.fill != ordinary.fill


def test_a_summary_names_the_activity_and_its_weight() -> None:
    text = summarise(node(label="SQL Injection", requests=47, outcome=Outcome.MIXED))

    assert "SQL Injection" in text
    assert "47" in text
    assert "mixed" in text.lower()


def test_a_long_label_is_shortened_rather_than_overflowing() -> None:
    text = summarise(node(label="A" * 200))

    assert len(text.splitlines()[0]) < 60


def test_a_long_label_wraps_rather_than_losing_the_end_that_identifies_it() -> None:
    """`Forced Browsing (repeated refusal…` cut off at 34 characters, and what
    it cut was the part telling two otherwise identical captions apart. A second
    line costs six pixels of canvas; the distinction costs the reading."""
    text = summarise(node(label="Forced Browsing (repeated refusal)"))

    assert "refusal" in text
    assert "…" not in text
    assert len(text.splitlines()) == 3, "two lines of label, then the count"


def test_a_label_too_long_for_two_lines_still_ends_somewhere() -> None:
    """Wrapping is not licence to grow without limit — past two lines the
    caption is taller than the node it belongs to."""
    lines = summarise(node(label="A" * 200)).splitlines()

    assert len(lines) == 3
    assert lines[1].endswith("…")


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (None, ""),
        (0.4, "0.4s"),
        (45, "45s"),
        (90, "1m 30s"),
        (3600, "1h 0m"),
        (7325, "2h 2m"),
    ],
)
def test_a_gap_is_written_the_way_a_person_would_say_it(
    seconds: float | None, expected: str
) -> None:
    assert format_gap(seconds) == expected


def test_a_repeated_transition_says_how_often_it_was_seen() -> None:
    """On a behaviour map the weight is the finding: a transition seen twice is
    a habit, one seen once is an incident. It used to be carried only by line
    thickness, which cannot be read as a number and cannot be compared between
    two clients' maps."""
    label = edge_label(GraphKind.BEHAVIOUR, weight=2, gap_seconds=30.0)

    assert "2" in label
    assert "30s" in label


def test_a_transition_seen_once_says_nothing_about_its_count() -> None:
    """A number that is always the same is not information, and on a crowded
    map it is one more thing to read past."""
    assert "1" not in edge_label(GraphKind.BEHAVIOUR, weight=1, gap_seconds=30.0)


def test_a_trace_never_shows_a_weight() -> None:
    """Every step of a trace happened once by construction."""
    assert edge_label(GraphKind.TRACE, weight=1, gap_seconds=5.0) == format_gap(5.0)


def test_a_transition_with_no_recorded_gap_still_reports_its_weight() -> None:
    assert "3" in edge_label(GraphKind.BEHAVIOUR, weight=3, gap_seconds=None)


def test_the_legend_explains_every_severity_the_taxonomy_has() -> None:
    """The encoding is the product: colour is severity, border is outcome, size
    is volume. None of that was written anywhere a user could see it, so a
    dotted grey circle meant nothing to whoever was looking at one.

    Read from the same tables the renderer draws from, so adding a severity
    without explaining it fails here rather than quietly producing a colour
    nobody can name."""
    explained = {item.label for item in severity_legend()}

    assert explained == {level.name.title() for level in Severity}


def test_the_legend_explains_every_outcome() -> None:
    explained = {item.label for item in outcome_legend()}

    assert explained == {outcome.value.title() for outcome in Outcome}


def test_a_legend_entry_carries_what_it_takes_to_draw_the_sample() -> None:
    """A legend that describes a colour in words rather than showing it asks the
    reader to match a name against a picture, which is the work it exists to
    save."""
    for item in severity_legend():
        assert item.colour.startswith("#")
    for item in outcome_legend():
        assert item.border is not None
        assert item.border.style in {"solid", "dashed", "dotted"}


def test_the_legend_says_what_size_means() -> None:
    """Volume is the third channel and the only one with no swatch, so it has to
    be said in words or it is not explained at all."""
    assert "request" in SIZE_NOTE.lower()


# -- reading the raw evidence line ------------------------------------------


def _text_of(line: str, role: str) -> str:
    """The characters a span of this role covers, taken from the line itself."""
    span = next(s for s in highlight_spans(line) if s.role == role)
    return line[span.start : span.end]


def test_the_request_target_is_marked() -> None:
    """The payload is the evidence. In a 330px panel the line is cut off at
    `"GET` and every visible character is boilerplate the reader already knows —
    the client they picked and the time already in the heading."""
    assert _text_of(COMBINED, "target") == (
        "/product.php?id=1%27%20UNION%20SELECT%20pw%20FROM%20users--"
    )


def test_the_status_is_marked() -> None:
    assert _text_of(COMBINED, "status") == "200"


def test_spans_stay_inside_the_line_and_never_overlap() -> None:
    """They are offsets into the original text, applied to it rather than to a
    string rebuilt from it. An overlap or an out-of-range span would mean the
    panel is formatting something other than what it was handed."""
    spans = sorted(highlight_spans(COMBINED), key=lambda s: s.start)

    assert spans
    for span in spans:
        assert 0 <= span.start < span.end <= len(COMBINED)
    for earlier, later in pairwise(spans):
        assert earlier.end <= later.start


def test_a_line_in_an_unrecognised_shape_is_left_plain() -> None:
    """LogarX reads nginx, IIS and JSON too. A highlight guessed wrong is worse
    than none: it would point the eye at the wrong part of the evidence."""
    assert highlight_spans('{"remote_addr":"10.0.0.1","request":"GET / HTTP/1.1"}') == ()
    assert highlight_spans("") == ()
    assert highlight_spans("not a log line at all") == ()


def test_a_request_with_no_status_after_it_is_left_plain() -> None:
    """A truncated line must not have its user agent marked as a status code."""
    assert highlight_spans('1.2.3.4 - - [x] "GET /a HTTP/1.1"') == ()


def test_one_request_is_not_one_requests() -> None:
    """The panel wrote "1 requests" while the canvas beside it wrote "1 request",
    because each formatted the count itself."""
    assert format_requests(1) == "1 request"
    assert format_requests(0) == "0 requests"
    assert format_requests(1000) == "1,000 requests"


def test_a_served_request_stands_out_and_a_refused_one_recedes() -> None:
    """Traffic-light colours would invert the meaning here. A 200 on an
    injection is the alarm — it says the payload was served — and the 403 is
    the reassurance. Green-for-200 would tell the reader the opposite."""
    assert status_colour("200") == EVIDENCE_INK
    assert status_colour("302") == EVIDENCE_INK
    assert status_colour("403") == EVIDENCE_MUTED
    assert status_colour("500") == EVIDENCE_MUTED


def test_an_unreadable_status_is_not_guessed_at() -> None:
    assert status_colour("abc") == EVIDENCE_MUTED


@pytest.mark.parametrize("ground", [PAPER, PAPER_STRIPE, SELECTION_TINT])
def test_receding_evidence_still_clears_wcag_aa_on_every_ground(ground: str) -> None:
    """`Recedes` is a comparison, not permission to be unreadable. The muted
    grey was 2.81:1 on the paper and 2.25:1 on a selected row — and what it
    colours is the status, which is one of the two things a row exists to show.
    A refused request is still evidence.

    Three grounds because a row is drawn on any of them: the paper, the stripe
    of an alternating row, and the tint under the selected one.
    """
    assert contrast(EVIDENCE_MUTED, ground) >= 4.5
    assert contrast(EVIDENCE_INK, ground) >= 4.5


# -- making an attacker-controlled string safe to look at --------------------


def test_an_encoded_newline_cannot_forge_a_second_log_line() -> None:
    """The attack this guard exists for. Everything drawn here comes from the
    request, which the attacker wrote. Decode `%0A` into a real newline and they
    can compose a line that looks like another entry — a fabricated request,
    with a fabricated status, sitting in the evidence panel of a forensic tool.

    Nothing decoded may introduce a line break, at any width, ever.
    """
    forged = decode_target("/a%0A127.0.0.1 - - [x] %22GET /innocent%22 200 0")

    assert "\n" not in forged
    assert "\r" not in forged
    assert "<U+000A>" in forged


def test_a_direction_override_cannot_disguise_the_path() -> None:
    """U+202E reverses how the rest of the text is drawn, so a hostile path can
    be made to read as an innocent one while remaining exactly what it is."""
    disguised = decode_target("/admin%E2%80%AEcod.exe")

    assert "\u202e" not in disguised
    assert "<U+202E>" in disguised


def test_control_characters_are_named_rather_than_drawn() -> None:
    assert decode_target("/a%00b") == "/a<U+0000>b"
    assert decode_target("/a%1Bb") == "/a<U+001B>b"


def test_the_payload_reads_as_the_attack_it_is() -> None:
    """The reason for the whole exercise: an analyst should not have to decode
    a textbook tautology in their head."""
    assert decode_target("/search?q=%27+OR+%271%27%3D%271") == "/search?q=' OR '1'='1"


def test_a_plus_is_a_space_only_in_the_query() -> None:
    """`+` means space in a query string and means `+` in a path. Decoding the
    whole target with one rule corrupts one side or the other."""
    assert decode_target("/a+b?q=c+d") == "/a+b?q=c d"


def test_a_broken_escape_is_left_exactly_as_it_was_logged() -> None:
    """Guessing at what a malformed sequence meant would be inventing evidence."""
    assert decode_target("/a%ZZb") == "/a%ZZb"
    assert decode_target("/a%2") == "/a%2"


def test_a_double_encoded_payload_still_shows_its_percent_signs() -> None:
    """Decoding once is the honest reading of one pass of encoding. What is
    left over says the payload was encoded twice, which is the evasion — so
    the residue must survive rather than being decoded away."""
    assert decode_target("/search?q=%2527+OR+1%3D1") == "/search?q=%27 OR 1=1"


def test_a_target_with_nothing_to_decode_is_unchanged() -> None:
    assert decode_target("/products/shoes") == "/products/shoes"


@pytest.mark.parametrize(
    ("count", "expected"),
    [(0, "0 B"), (512, "512 B"), (10_648, "10.4 KB"), (1_400_000, "1.3 MB")],
)
def test_a_response_size_is_written_the_way_a_person_would_say_it(
    count: int, expected: str
) -> None:
    """A large response to an injection is the finding. "10648" is a number to
    decipher; "10.4 KB" is a size to recognise."""
    assert format_bytes(count) == expected


def test_a_scanner_signature_is_never_shortened_away() -> None:
    """The agent is usually noise and occasionally the whole finding. Scanner
    agents are short, so keeping the ends keeps them whole."""
    assert shorten_agent("sqlmap/1.5.2#stable (http://sqlmap.org)") == (
        "sqlmap/1.5.2#stable (http://sqlmap.org)"
    )


def test_a_long_browser_agent_keeps_its_head_and_tail() -> None:
    """The middle of a browser agent is boilerplate; what identifies the client
    sits at either end, and the whole string is one keystroke away in the raw
    line."""
    agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Claude/1.24012.9 Chrome/148.0.7778.280 "
        "Electron/42.7.0 Safari/537.36 MSIX"
    )

    short = shorten_agent(agent)

    assert len(short) < len(agent)
    assert short.startswith("Mozilla/5.0")
    assert short.endswith("MSIX")
    assert "…" in short


# -- the palette holds up ----------------------------------------------------
#
# The gap these close. The suite already held the evidence *ink* to a contrast
# ratio against its ground, but nothing checked the node fills — so the ramp
# could be retuned, or the ground moved under it, and the only thing that
# noticed would have been an investigator missing a finding.


@pytest.mark.parametrize("level", list(Severity))
def test_a_finding_is_visible_against_the_canvas_it_is_drawn_on(level: Severity) -> None:
    """WCAG 1.4.11: a graphical object carrying meaning needs 3:1 against what
    is behind it. A node's fill *is* the finding, and on the ramp this replaced
    `CRITICAL` sat at 3.02:1 on this ground — over the line by a hair while
    being the faintest thing on a canvas, which is the wrong place to be for the
    one severity that must not be missed.
    """
    assert contrast(severity_colour(level), PAPER) >= 3.0


def test_no_two_severities_can_be_mistaken_for_each_other() -> None:
    """Lightening a ramp is how two levels quietly become one colour.

    Measured as a distance rather than a contrast ratio: contrast compares
    luminance alone, so it reports two equally bright but differently coloured
    fills as identical, which is exactly the pair this needs to tell apart. The
    closest pair on this ramp is `High` and `Critical` at 0.096 — adjacent
    levels, and adjacent hues, so it is the pair to hold the line at.
    """
    for one, other in combinations(sorted(Severity), 2):
        distance = apart(severity_colour(one), severity_colour(other))
        assert distance >= 0.08, f"{one.name} and {other.name} look alike at {distance:.3f}"


#: Below this a colour has no hue worth comparing. `Info` is a near-grey at
#: 0.022 and computes to a blue hue 3° off the selection blue while being
#: obviously not blue; every severity that actually carries a hue is above 0.08.
_HAS_A_HUE = 0.05


@pytest.mark.parametrize("level", list(Severity))
def test_the_selection_ring_cannot_be_read_as_a_finding(level: Severity) -> None:
    """The ring says "this is the one you clicked" and is drawn immediately
    outside a fill that says "this is how bad it is". Two blues touching is a
    canvas where one colour means two things.

    Not hypothetical: `LOW` was `#4c8dae`, a blue 16° from the selection blue,
    and moved to teal at 58° for this reason. What found it was looking at a
    mockup, which is not something that happens on every change.

    Hue rather than overall distance, because overall distance does not see it:
    old and new `LOW` sit 0.129 and 0.137 from the accent, near enough identical,
    while being 16° and 58° away in hue. And hue only where there is enough
    chroma to have one, or this would fail on the grey that is not blue.
    """
    colour = severity_colour(level)
    if chroma(colour) < _HAS_A_HUE:
        assert apart(SELECTION_COLOUR, colour) >= 0.10, f"{level.name} is close to the ring"
        return
    separation = hue_apart(SELECTION_COLOUR, colour)
    assert separation >= 30.0, f"the ring is {separation:.0f}° from {level.name}"


def test_the_worst_finding_is_never_the_faintest_thing_on_the_canvas() -> None:
    """The defect that started this. On a dark ground the old `CRITICAL`
    `#b5273a` came to 3.02:1 — past the 3:1 floor by a hair, and dimmer than
    every other severity, so the one finding an investigator must not miss was
    the hardest one on the canvas to see.

    Stated as a rank rather than a ratio because that is the actual requirement.
    A ramp can clear every threshold and still put critical at the bottom.
    """
    ranked = sorted(Severity, key=lambda level: contrast(severity_colour(level), PAPER))

    assert ranked[0] is not Severity.CRITICAL, "critical is the faintest severity drawn"


def test_the_light_theme_still_holds_the_colours_it_always_had() -> None:
    """`LIGHT` is not live, and something not drawn is something free to rot.

    It is kept so that going back is one line, which is only true while it still
    holds what it held. These are the values LogarX shipped with.
    """
    assert [severity_colour(level, theme=LIGHT) for level in sorted(Severity)] == [
        "#9aa5b1",
        "#4c8dae",
        "#d8a33c",
        "#d4693a",
        "#b5273a",
    ]


def test_the_window_sits_on_graphite_to_meet_the_windows_title_bar() -> None:
    """Lifted from near-black, so the window and the frame Windows draws around
    it (about #202020) read as one piece rather than two programs stacked."""
    assert (DARK.chrome, DARK.surface, DARK.raised, DARK.stripe) == (
        "#1b1a19",
        "#222120",
        "#2b2a29",
        "#282726",
    )
    assert (DARK.line, DARK.edge, DARK.faint, DARK.tint, DARK.grid_dot) == (
        "#363533",
        "#4a4846",
        "#9a9997",
        "#123153",
        "#5c5b59",
    )


# -- counting things ---------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, "0 clients"),
        (1, "1 client"),
        (2, "2 clients"),
        (1500, "1,500 clients"),
    ],
)
def test_a_count_agrees_with_its_noun(count: int, expected: str) -> None:
    """`1 client(s)` is what a program writes when nobody decided. This one had
    decided — `format_requests` existed for exactly this — and then said
    `client(s)`, `session(s)`, `path(s)` and `file(s)` anyway."""
    assert plural(count, "client") == expected


def test_a_noun_that_does_not_just_take_an_s() -> None:
    """`activity` is counted in the status bar and the graph heading, and
    `2 activitys` would be worse than the bracket it replaced."""
    assert plural(2, "activity", "activities") == "2 activities"
    assert plural(1, "activity", "activities") == "1 activity"


def test_the_request_count_still_reads_the_way_it_did() -> None:
    """`format_requests` is `plural` underneath now. The output must not move."""
    assert format_requests(1) == "1 request"
    assert format_requests(51) == "51 requests"
    assert format_requests(1500) == "1,500 requests"


@pytest.mark.parametrize("outcome", list(Outcome))
def test_an_outcome_outline_reads_against_the_canvas_behind_it(outcome: Outcome) -> None:
    """An outline is stroked *on* the edge of a fill, so half its width lies
    inside the node and half lies on the canvas. It is the canvas half that
    decides whether the line is there at all, because the canvas is one known
    colour while the fill is whichever severity happened to occur.

    This test had it the other way round first, and passed while the graph was
    wrong: it held the outline to 3:1 against every *fill*, which a near-black
    clears comfortably at 4.4:1 — and that same near-black measures 1.01:1
    against the ground, so the outer half of every outline on the canvas was
    drawn in the ground's own colour. A test can hold the wrong surface and look
    thorough doing it.
    """
    assert contrast(outcome_border(outcome).colour, PAPER) >= 3.0


@pytest.mark.parametrize("level", list(Severity))
def test_an_outcome_outline_is_still_visible_where_it_crosses_the_fill(level: Severity) -> None:
    """The other half of the same line. Weaker than the 3:1 asked of the canvas
    side, because it does not have to carry the shape on its own — but a line
    that vanished completely against some severity would leave that node looking
    like it had no outcome at all.
    """
    assert contrast(outcome_border(Outcome.SUCCESS).colour, severity_colour(level)) >= 1.9


def test_the_outcome_channel_does_not_lean_on_colour() -> None:
    """`logarx.style` says on its own face that an outline "must not be a shade of
    the same colour that already means something else". Severity owns colour;
    outcome owns line style and weight. Holding the dark theme to that is what
    freed its outlines to be the one colour that reads on every fill.
    """
    borders = [outcome_border(outcome) for outcome in Outcome]

    assert len({border.colour for border in borders}) == 1, "outcome is not carried by hue"
    assert len({(border.style, border.width) for border in borders}) == len(borders)


# -- a session's box -------------------------------------------------------


def _spell(start: datetime, end: datetime) -> GraphNode:
    return replace(node(), start=start, end=end)


def test_a_session_box_says_which_visit_how_much_and_when() -> None:
    nodes = [
        _spell(datetime(2026, 3, 9, 1, 55, tzinfo=UTC), datetime(2026, 3, 9, 2, 1, tzinfo=UTC)),
        _spell(datetime(2026, 3, 9, 2, 20, tzinfo=UTC), datetime(2026, 3, 9, 2, 26, tzinfo=UTC)),
    ]

    caption = session_caption(2, 69, nodes)

    assert caption == "Session 2 of 69 · 2 activities · 09 Mar 01:55\u201302:26"


def test_a_session_inside_one_minute_gives_one_time() -> None:
    """A range from 09:42 to 09:42 reads as a typing error."""
    moment = datetime(2026, 3, 12, 9, 42, 5, tzinfo=UTC)

    caption = session_caption(1, 150, [_spell(moment, moment + timedelta(seconds=30))])

    assert caption == "Session 1 of 150 · 1 activity · 12 Mar 09:42"


def test_a_session_across_midnight_says_both_days() -> None:
    """23:50 to 00:20 on its own reads as running backwards."""
    nodes = [
        _spell(datetime(2026, 3, 9, 23, 50, tzinfo=UTC), datetime(2026, 3, 9, 23, 55, tzinfo=UTC)),
        _spell(datetime(2026, 3, 10, 0, 10, tzinfo=UTC), datetime(2026, 3, 10, 0, 20, tzinfo=UTC)),
    ]

    caption = session_caption(3, 3, nodes)

    assert caption == "Session 3 of 3 · 2 activities · 09 Mar 23:50 \u2013 10 Mar 00:20"


def test_a_session_is_explained_in_the_thresholds_that_cut_it() -> None:
    """What hovering a box's label says. Each line is something every session
    holds to, a time filter's clipped ones included, so it is true of whichever
    box the reader is pointing at."""
    assert session_rule(SessionPolicy()) == (
        "A session is one visit from this address.\n"
        "No pause inside it is longer than 30 minutes,\n"
        "every request in it has the same user agent,\n"
        "and it lasts 8 hours at most."
    )


def test_the_explanation_follows_the_thresholds_it_is_given() -> None:
    policy = SessionPolicy(
        idle_timeout=timedelta(minutes=1),
        max_duration=timedelta(hours=1),
        split_on_user_agent_change=False,
    )

    assert session_rule(policy) == (
        "A session is one visit from this address.\n"
        "No pause inside it is longer than 1 minute,\n"
        "and it lasts 1 hour at most."
    )


def test_a_threshold_of_odd_seconds_is_given_in_seconds() -> None:
    """Rounded to minutes, ninety seconds would be quoted as one or two minutes,
    and a gap of a minute and a half would then seem to break its own rule."""
    policy = SessionPolicy(idle_timeout=timedelta(seconds=90), max_duration=timedelta(minutes=90))

    assert "longer than 90 seconds,\n" in session_rule(policy)
    assert session_rule(policy).endswith("lasts 90 minutes at most.")


def test_a_box_ground_is_the_paper_with_a_breath_of_the_accent() -> None:
    """Derived rather than chosen, so it follows the theme. Pinned here so the
    blend cannot drift into a colour nobody measured."""
    assert SESSION_GROUND == "#24282b"


def test_everything_drawn_inside_a_box_still_reads_against_it() -> None:
    """The floors the theme already states for the plain ground, held again for
    the box ground: text at 4.5:1, every severity and every outline at 3:1.
    Measured 2026-10-17: caption 15.55, label 8.41, faintest severity 4.11."""
    assert contrast(CAPTION_COLOUR, SESSION_GROUND) >= 4.5
    assert contrast(THEME.muted, SESSION_GROUND) >= 4.5
    assert contrast(SELECTION_COLOUR, SESSION_GROUND) >= 3.0
    for level in Severity:
        assert contrast(severity_colour(level), SESSION_GROUND) >= 3.0, level
    for outcome in Outcome:
        assert contrast(outcome_border(outcome).colour, SESSION_GROUND) >= 3.0, outcome


def test_bookmark_categories_read_on_every_surface_and_apart_from_each_other() -> None:
    """A ribbon says which category; eight that look alike would say nothing.

    And none may be mistaken for the alert, which means trouble with the evidence.
    """
    assert len(CATEGORY_COLOURS) == 8
    assert CATEGORY_COLOURS[0] == THEME.accent
    for colour in CATEGORY_COLOURS:
        for ground in (THEME.surface, THEME.raised, THEME.stripe):
            assert contrast(colour, ground) >= 3.0, (colour, ground)
        assert apart(colour, THEME.alert) >= 0.1, colour
    for one, other in combinations(CATEGORY_COLOURS, 2):
        assert apart(one, other) >= 0.1, (one, other)


# -- a session's name --------------------------------------------------------


def _activity(
    label: str,
    severity: Severity = Severity.INFO,
    *,
    category: ActivityCategory = ActivityCategory.BROWSING,
    requests: int = 1,
    minute: int = 0,
) -> GraphNode:
    moment = START + timedelta(minutes=minute)
    return replace(
        node(severity=severity, category=category, requests=requests, label=label),
        start=moment,
        end=moment,
    )


def test_a_session_is_named_after_its_most_severe_activity() -> None:
    nodes = [_activity("Page View"), _activity("Webshell", Severity.HIGH, minute=1)]

    assert session_name(nodes) == "Webshell"


def test_at_equal_severity_a_hostile_kind_names_the_session() -> None:
    """The order an episode picks its own label by: severity, then which side."""
    benign = _activity("Crawler Traffic", Severity.LOW, category=ActivityCategory.CRAWLING)
    hostile = _activity(
        "Configuration File Probe", Severity.LOW, category=ActivityCategory.RECONNAISSANCE, minute=1
    )

    assert session_name([benign, hostile]) == "Configuration File Probe"


def test_then_the_one_with_more_requests() -> None:
    assert session_name([_activity("A", requests=2), _activity("B", requests=9, minute=1)]) == "B"


def test_a_full_tie_goes_to_the_earliest() -> None:
    assert session_name([_activity("First", minute=1), _activity("Second", minute=2)]) == "First"


def test_a_blank_label_is_an_unnamed_session() -> None:
    """Never seen on 2,504 sessions; it keeps a blank heading off the canvas."""
    assert session_name([_activity("   ")]) == "Unnamed session"


def test_the_place_is_the_number_and_the_time() -> None:
    nodes = [
        _spell(datetime(2026, 3, 9, 9, 6, tzinfo=UTC), datetime(2026, 3, 9, 9, 7, tzinfo=UTC)),
        _spell(datetime(2026, 3, 9, 9, 7, tzinfo=UTC), datetime(2026, 3, 9, 9, 8, tzinfo=UTC)),
    ]

    assert session_place(1, 7, nodes) == "Session 1 of 7 · 09 Mar 09:06\u201309:08"


def test_a_tip_for_logarxs_name_is_the_rule_then_the_hint() -> None:
    assert session_heading_tip("RULE", "X", renamed=False) == "RULE\n\n" + RENAME_HINT


def test_a_tip_for_a_readers_name_says_so_first() -> None:
    assert session_heading_tip("RULE", "Config probe", renamed=True) == (
        "Named by you. LogarX's name: Config probe\n\nRULE\n\n" + RENAME_HINT
    )


def test_a_tip_without_rules_keeps_the_rest() -> None:
    assert session_heading_tip("", "X", renamed=False) == RENAME_HINT
    assert RENAME_HINT == "Double-click the title to rename this session."


def test_severity_comes_before_which_side_a_kind_is_on() -> None:
    """A benign kind can be the more severe: `Scripted Client` is crawling."""
    scripted = _activity("Scripted Client", Severity.MEDIUM, category=ActivityCategory.CRAWLING)
    probe = _activity(
        "Configuration File Probe", Severity.LOW, category=ActivityCategory.RECONNAISSANCE, minute=1
    )

    assert session_name([probe, scripted]) == "Scripted Client"
