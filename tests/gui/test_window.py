"""Smoke tests for the window itself, run without a display.

The GUI is verified by hand against docs/manual-test-plan.md — a checklist
cannot be automated away. What *can* be automated is that it still constructs,
still draws a real reconstruction, and still survives a case with nothing in it.
Those are the failures that would otherwise be found by opening the app.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import QApplication, QSplitter

from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import ActivityGraph, GraphEdge, GraphKind, GraphNode
from logarc.detect.crs import CrsDetection, write_detections
from logarc.gui import app
from logarc.gui.app import MainWindow, read_case, reconstruct_client
from logarc.gui.canvas import MIN_FIT_SCALE, ActivityCanvas
from logarc.gui.evidence_panel import EvidencePanel
from logarc.gui.panels import ClientTable
from logarc.gui.style import format_bytes
from logarc.storage.case import CaseManifest

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
CLIENT = "203.0.113.66"


@pytest.fixture(scope="module")
def qt_app() -> QApplication:
    return QApplication.instance() or QApplication([])


@pytest.fixture(scope="module", autouse=True)
def settings_in_a_temp_file(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Point the window's preferences at a file nobody has to live with.

    `QSettings` resolves to `HKCU\\Software` on Windows, so without this the
    suite writes real preferences onto whichever machine ran it and reads its
    own leftovers back on the next run — which would make these tests pass or
    fail according to what a previous run happened to leave behind.

    Substituting the factory, not `QSettings.setDefaultFormat` and `setPath`:
    those were tried first and do not redirect the `QSettings(org, app)`
    constructor at all. It goes on resolving to the registry, and the isolation
    is imaginary while looking completely convincing.
    """
    from PyQt6.QtCore import QSettings

    ini = tmp_path_factory.mktemp("settings") / "logarc.ini"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(app, "_settings", lambda: QSettings(str(ini), QSettings.Format.IniFormat))
        yield ini


def _settled(qt_app: QApplication, timeout: float = 30.0) -> None:
    """Wait for the window's background work, then let its results land.

    Everything the window does off the interface thread comes back as a queued
    signal, so waiting for the pool is only half of it: without pumping the
    event loop afterwards the job has finished and nothing has been told.
    """
    from PyQt6.QtCore import QThreadPool

    pool = QThreadPool.globalInstance()
    assert pool is not None
    assert pool.waitForDone(int(timeout * 1000)), "background work did not finish"
    qt_app.processEvents()


def _long_trace(count: int) -> ActivityGraph:
    """A trace long enough that a wrap has something to fold.

    Built directly rather than segmented out of a log, so the premise this test
    rests on — that this graph wraps — cannot be quietly changed by a detection
    rule or a threshold somewhere else in the tree.
    """
    nodes = tuple(
        GraphNode(
            node_id=f"1.2.3.4#1/{index}",
            label="directory enumeration",
            category=ActivityCategory.ENUMERATION,
            severity=Severity.MEDIUM,
            outcome=Outcome.BLOCKED,
            request_count=5,
            distinct_paths=5,
            bytes_total=1,
            start=START + timedelta(minutes=index),
            end=START + timedelta(minutes=index, seconds=30),
            owasp=None,
            top_targets=("/a",),
            rule_ids=("r",),
            evidence=(EvidenceRef("access.log", index),),
            evidence_total=5,
            episode_ids=(f"1.2.3.4#1/{index}",),
        )
        for index in range(1, count + 1)
    )
    edges = tuple(
        GraphEdge(source=first.node_id, target=second.node_id) for first, second in pairwise(nodes)
    )
    return ActivityGraph(kind=GraphKind.TRACE, client_ip="1.2.3.4", nodes=nodes, edges=edges)


@pytest.fixture(scope="module")
def campaign(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A case with a recognisable attack in it, so the canvas has real work."""
    root = tmp_path_factory.mktemp("gui")
    lines = []
    at = 0
    for path in ("/", "/products", "/assets/app.css"):
        lines.append(_line(at, path))
        at += 15
    for index in range(30):
        lines.append(_line(at, f"/admin/{index}", status=404))
        at += 1
    for payload in ("id=1%27%20OR%20%271%27%3D%271", "id=1%20UNION%20SELECT%20NULL"):
        lines.append(_line(at, f"/product?{payload}", status=403))
        at += 3
    lines.append(_line(at, "/product?id=1%20UNION%20SELECT%20pw%20FROM%20users", size=1_400_000))

    log = root / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
    return root / "case"


@pytest.fixture(scope="module")
def recurring(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A client that returns to the same activity between other things.

    The `campaign` fixture cannot show what the behaviour map is for: every one
    of its categories happens once, so each behaviour node holds exactly one
    episode and reads the same as its trace node. That is why nothing caught the
    panel describing an episode while listing a node's evidence.

    Here enumeration is interrupted twice, which is what a scanner working
    through a wordlist actually looks like: three enumeration episodes on the
    trace, one 35-request node on the behaviour map.
    """
    root = tmp_path_factory.mktemp("recurring")
    lines = [_line(0, "/")]
    at = 10
    for burst, count in enumerate((12, 3, 20)):
        for index in range(count):
            lines.append(_line(at, f"/admin/b{burst}-{index}", status=404))
            at += 1
        lines.append(_line(at, "/.env", status=404))
        at += 2

    log = root / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
    return root / "case"


def _line(seconds: int, target: str, *, status: int = 200, size: int = 512) -> str:
    when = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    agent = "Mozilla/5.0 (X11; Linux x86_64)"
    return f'{CLIENT} - - [{when}] "GET {target} HTTP/1.1" {status} {size} "-" "{agent}"'


@pytest.fixture
def enriched(campaign: Path, tmp_path: Path) -> Path:
    """A copy of the campaign case that `logarc enrich` has been run over."""
    import shutil

    root = tmp_path / "enriched"
    shutil.copytree(campaign, root)
    write_detections(
        root,
        [
            CrsDetection(
                source_file_id="access.log",
                line_no=1,
                rule_id=942100,
                severity="critical",
                msg="SQL Injection Attack Detected via libinjection",
                matched_var="ARGS:id",
                transformed_value="1' UNION SELECT",
            )
        ],
    )
    manifest = CaseManifest.load(root)
    manifest.config["crs_fingerprint"] = "test-fingerprint"
    manifest.save(root)
    return root


def test_the_window_reads_the_crs_evidence_a_case_carries(enriched: Path) -> None:
    """Regression: the window passed no CRS to `analyse_ip` at all, so the same
    enriched case answered differently here than on the command line. Two front
    ends that disagree about the evidence are worse than one that offers the
    feature only in the other, because nothing tells you which answer is real."""
    _summaries, crs = read_case(enriched)

    assert crs.fingerprint == "test-fingerprint"
    assert crs.index is not None


def test_a_reconstruction_credits_the_crs_configuration_that_produced_it(
    enriched: Path,
) -> None:
    """The evidence has to reach the analysis, not merely be loaded beside it."""
    _summaries, crs = read_case(enriched)

    result = reconstruct_client(enriched, CLIENT, crs)

    assert result.crs_fingerprint == "test-fingerprint"


def test_an_unenriched_case_credits_nothing(campaign: Path) -> None:
    """The ordinary case, and the one that must not claim CRS took part."""
    _summaries, crs = read_case(campaign)

    result = reconstruct_client(campaign, CLIENT, crs)

    assert crs.index is None
    assert result.crs_fingerprint is None


def test_the_window_constructs(qt_app: QApplication) -> None:
    window = MainWindow()

    assert window.windowTitle().startswith("logarc")
    window.close()


def _laid_out(width: int = 1400) -> tuple[MainWindow, QSplitter]:
    """A shown window, with its splitter sized directly.

    `window.resize` does not reach the central widget under the offscreen
    platform this suite runs on — it reports the same width before and after,
    which makes a resize test look like it passed while measuring nothing.
    Sizing the splitter itself does work, and is what these tests are about.
    """
    window = MainWindow()
    window.show()
    splitter = window.centralWidget()
    assert isinstance(splitter, QSplitter)
    splitter.resize(width, 880)
    QApplication.processEvents()
    return window, splitter


def test_the_legend_does_not_dictate_how_wide_the_window_must_be(
    qt_app: QApplication,
) -> None:
    """The root of the frozen splitter. Laid out as one unbroken row, the key
    demanded 1,729px — wider than the 1,725px window it was sitting in. The
    centre column inherited that minimum, so both side panels were pinned at
    theirs, and with no slack anywhere a drag had nothing to give: the client
    panel could only be its minimum or collapsed, never anything between.

    A key is a set of small independent items. It should take as many rows as
    it needs and demand no more width than its widest single entry.
    """
    from logarc.gui.panels import LegendBar

    assert LegendBar().minimumSizeHint().width() < 320


def test_the_legend_uses_more_rows_when_it_is_given_less_width(
    qt_app: QApplication,
) -> None:
    """Wrapping, not clipping — every entry stays readable at any width."""
    from logarc.gui.panels import LegendBar

    bar = LegendBar()

    assert bar.heightForWidth(400) > bar.heightForWidth(1400)


def test_no_panel_starts_its_text_against_the_frame(qt_app: QApplication) -> None:
    """Zero margins put every caption and the first table column at x=0, and
    the frame cut the leading character off each: `500 client(s)…` opened with
    half a `5`."""
    window, _ = _laid_out()

    assert window._clients._caption.x() > 0, "the client caption is against the edge"
    assert window._evidence._heading.x() > 0, "the evidence heading is against the edge"
    assert window._heading.x() > 0, "the graph heading is against the edge"
    window.close()


def test_the_client_header_leaves_room_for_the_sort_indicator(qt_app: QApplication) -> None:
    """The chevron is drawn above the label, and the header was 16px tall for
    12px of text — four pixels for something that needs about seven, so the top
    edge cut it in half. Which column the table is sorted by is the one thing
    this header has to say beyond the six words in it.

    Height is what the widget can be asked for; that the chevron then lands
    inside it is checked by eye against `ui-review/02-case-open.png`.
    """
    from logarc.gui._qt import required
    from logarc.gui.panels import ClientTable

    table = ClientTable()
    table.resize(440, 600)
    table.show()
    QApplication.processEvents()
    header = required(table._table.horizontalHeader(), "column header")

    assert header.height() - header.fontMetrics().height() >= 12
    table.close()


def test_a_swatch_and_the_word_it_explains_cannot_be_split_across_rows(
    qt_app: QApplication,
) -> None:
    """Each was its own item in the flow, so a break could land between them —
    and at 1500px it did: the `Unknown` swatch ended one row and the word sat
    alone on the next. A colour on one line and its meaning on another is the
    one thing a key cannot do."""
    from logarc.gui.panels import LegendBar
    from logarc.gui.style import outcome_legend, severity_legend

    # Held, not discarded: a temporary bar takes its children with it and every
    # item would report an empty widget for reasons that have nothing to do with
    # what is being tested.
    bar = LegendBar()
    row = bar.flow

    # Two group captions, then one indivisible item per entry.
    assert row.count() == 2 + len(severity_legend()) + len(outcome_legend())
    for index in range(row.count()):
        item = row.itemAt(index)
        assert item is not None
        assert item.widget() is not None, "every item is one widget, so it wraps whole"


def test_the_side_panels_resize_continuously_rather_than_snapping(qt_app: QApplication) -> None:
    """A minimum wide enough to hold every column also forbids every width
    below it. With collapsing still allowed the panel could reach 0 or 430 and
    nothing in between, so dragging it either did nothing or jumped the whole
    way — which is what "stuck" means here.
    """
    window, splitter = _laid_out()

    reachable = set()
    for want in range(240, 520, 20):
        splitter.setSizes([want, 1400 - want - 320, 320])
        QApplication.processEvents()
        reachable.add(splitter.sizes()[0])

    assert len(reachable) >= 10, f"only these widths are reachable: {sorted(reachable)}"
    window.close()


def test_the_client_table_still_opens_wide_enough_for_every_column(
    qt_app: QApplication,
) -> None:
    """The regression this must not cause. A large minimum was what guaranteed
    the six columns fitted; with the minimum lowered so the panel can be
    resized, the opening size has to carry that guarantee instead."""
    window, splitter = _laid_out()

    assert splitter.sizes()[0] >= 420
    window.close()


def test_a_wider_window_gives_the_extra_room_to_the_graph(qt_app: QApplication) -> None:
    """Without stretch factors the splitter shares new space out proportionally,
    so widening the window fattens the side panels and the graph — the thing
    being read — gains almost nothing."""
    window, splitter = _laid_out(1400)
    before = splitter.sizes()

    splitter.resize(2000, 880)
    QApplication.processEvents()
    after = splitter.sizes()

    assert after[1] - before[1] > 500, "the canvas should take nearly all of the extra 600"
    assert abs(after[0] - before[0]) <= 20, "the client panel should keep its width"
    assert abs(after[2] - before[2]) <= 20, "the evidence panel should keep its width"
    window.close()


def test_cancel_reaches_the_flag_the_engine_polls(qt_app: QApplication) -> None:
    """A cancel button wired to nothing is worse than no button at all: the
    window would report a stop that never happened."""
    import threading

    window = MainWindow()
    stop = threading.Event()

    window._busy("Ingesting…", stop=stop)
    assert not window._cancel.isHidden()
    window._cancel.click()

    assert stop.is_set()
    window.close()


def test_cancel_is_offered_only_for_work_that_can_be_stopped(qt_app: QApplication) -> None:
    window = MainWindow()

    window._busy("Reconstructing…")

    assert window._cancel.isHidden()
    window.close()


def test_the_canvas_draws_a_real_reconstruction(qt_app: QApplication, campaign: Path) -> None:
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
    canvas = ActivityCanvas()

    canvas.show_graph(result.trace)

    assert result.trace.nodes
    assert len(canvas.scene().items()) > len(result.trace.nodes)


def test_both_graph_views_draw(qt_app: QApplication, campaign: Path) -> None:
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
    canvas = ActivityCanvas()

    for graph in (result.trace, result.behaviour):
        canvas.show_graph(graph)
        assert canvas.scene().items()
    assert result.behaviour.kind is GraphKind.BEHAVIOUR


def test_a_client_with_no_activity_does_not_break_the_canvas(
    qt_app: QApplication, campaign: Path
) -> None:
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, "192.0.2.99")
    canvas = ActivityCanvas()

    canvas.show_graph(result.trace)

    assert canvas.scene().items(), "an empty graph should still say so on screen"


def test_the_client_table_lists_and_sorts_by_number(qt_app: QApplication, campaign: Path) -> None:
    with Case.open(campaign) as case:
        summaries = case.store.ip_summaries(limit=50, order_by="requests")
    table = ClientTable()

    table.show_clients(summaries)

    assert summaries
    assert table._table.rowCount() == len(summaries)


#: A real Combined line. Its first 45 characters are the client address and the
#: timestamp — the address the reader chose from the table themselves, and a
#: time already printed in the heading — and the payload sits past character 60.
LONG_LINE = (
    "100.66.0.118 - - [01/May/2024:04:06:02 +0000] "
    '"GET /product.php?id=1%27%20UNION%20SELECT%20pw%20FROM%20users-- HTTP/1.1" 200 1400 '
    '"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)


def _injection_evidence(campaign: Path) -> tuple[object, list[object]]:
    """The activity whose evidence actually carries an encoded payload.

    A trace node rather than an episode: the panel is handed what the canvas
    drew, so that its heading and its rows cannot describe different things.
    """
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
        for node in result.trace.nodes:
            lines = case.read_evidence(node.evidence[:4])
            if any("%27" in (line.text or "") for line in lines):
                return node, lines
    raise AssertionError("the fixture no longer contains an encoded payload")


def test_the_canvas_will_not_shrink_a_graph_out_of_legibility(
    qt_app: QApplication, campaign: Path
) -> None:
    """A long trace fitted to the window width scales the nodes down until the
    labels cannot be read. Requiring a pan is better than showing a graph
    nobody can read."""
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
    canvas = ActivityCanvas()
    canvas.resize(400, 300)

    canvas.show_graph(result.trace)

    assert canvas.transform().m11() >= MIN_FIT_SCALE


def test_the_canvas_rings_the_activity_being_read(qt_app: QApplication, campaign: Path) -> None:
    """Clicking a node filled the evidence panel and left the canvas saying
    nothing about which of a dozen nodes it belonged to."""
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
    canvas = ActivityCanvas()
    canvas.show_graph(result.trace)
    before = len(canvas.graph_scene.items())

    canvas.highlight(result.trace.nodes[0].node_id)

    assert len(canvas.graph_scene.items()) == before + 1


def test_only_the_last_activity_clicked_stays_ringed(qt_app: QApplication, campaign: Path) -> None:
    """Drawn per click and left behind, every node ever clicked would look
    selected — worse than marking none of them."""
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
    canvas = ActivityCanvas()
    canvas.show_graph(result.trace)
    before = len(canvas.graph_scene.items())

    for node in result.trace.nodes[:3]:
        canvas.highlight(node.node_id)

    assert len(canvas.graph_scene.items()) == before + 1


def test_turning_wrap_off_redraws_the_trace_on_one_row(qt_app: QApplication) -> None:
    """The setting has to reach the layout, not merely be stored. A toggle that
    records a preference and leaves the canvas exactly as it was is broken in
    the one way the user can see."""
    canvas = ActivityCanvas()
    canvas.show_graph(_long_trace(12))
    assert len({item.pos().y() for item in canvas._nodes.values()}) > 1, "premise: it wrapped"

    canvas.set_wrap(False)

    assert len({item.pos().y() for item in canvas._nodes.values()}) == 1


def test_wrap_can_be_set_before_anything_is_drawn(qt_app: QApplication) -> None:
    """The window applies the remembered setting while it is being built, which
    is long before a case has been opened. It also has to still be in force for
    the graph drawn after that, rather than only triggering one redraw."""
    canvas = ActivityCanvas()

    canvas.set_wrap(False)
    canvas.show_graph(_long_trace(12))

    assert len({item.pos().y() for item in canvas._nodes.values()}) == 1


def test_the_ring_follows_the_node_across_a_wrap_toggle(qt_app: QApplication) -> None:
    """The evidence panel goes on showing the same episode across the redraw, so
    the canvas has to go on pointing at it — and at where it has moved to. A ring
    left at the old coordinates marks whichever node landed there instead, which
    is worse than marking none."""
    canvas = ActivityCanvas()
    graph = _long_trace(12)
    canvas.show_graph(graph)
    # The sixth, deliberately. A node on the first row of the fold keeps the
    # same coordinates when the fold is removed, so ringing one of those would
    # let a ring left at the old position pass as a ring that followed.
    ringed = graph.nodes[5].node_id
    canvas.highlight(ringed)
    was_at = canvas._nodes[ringed].pos()

    canvas.set_wrap(False)

    assert canvas._nodes[ringed].pos() != was_at, "premise: this node moved"
    assert canvas._halo is not None
    assert canvas._halo.pos() == canvas._nodes[ringed].pos()


def test_the_canvas_says_what_to_do_before_a_case_is_open(qt_app: QApplication) -> None:
    """`show_graph_placeholder` only ran when a case loaded, so on launch the
    largest region of the window was empty white paper inside dark chrome and
    only the status bar said anything. An empty screen reads as a rendering
    failure, not as an invitation."""
    window = MainWindow()

    assert window._canvas.graph_scene.items(), "the canvas opens with nothing on it"
    window.close()


def test_a_caption_is_the_same_size_however_far_the_graph_is_scaled(
    qt_app: QApplication,
) -> None:
    """`fit()` scales the scene and the captions went with it — about five
    pixels tall on a wrapped trace, smaller still on an unwrapped one. The graph
    was legible and its labels were not, which leaves a picture of circles.

    Every piece of text on the canvas is drawn at screen size instead, so only
    the geometry scales.
    """
    from PyQt6.QtWidgets import QGraphicsItem, QGraphicsSimpleTextItem

    canvas = ActivityCanvas()
    canvas.show_graph(_long_trace(12))

    texts = [
        item for item in canvas.graph_scene.items() if isinstance(item, QGraphicsSimpleTextItem)
    ]
    assert texts, "a trace this long has captions and edge labels"
    for text in texts:
        ignoring = item = text
        while item is not None:
            ignoring = item
            if item.flags() & QGraphicsItem.GraphicsItemFlag.ItemIgnoresTransformations:
                break
            item = item.parentItem()
        else:  # pragma: no cover - the loop breaks on the flag
            raise AssertionError(f"{ignoring.text()!r} scales with the graph")


def test_a_caption_is_not_crossed_by_the_arrows_behind_it(qt_app: QApplication) -> None:
    """The 49-request node's caption was drawn through its own circle and cut
    by an outgoing arrow. Each caption sits on a patch of the canvas ground,
    above the edges, so the words survive whatever passes behind them."""
    from PyQt6.QtWidgets import QGraphicsRectItem, QGraphicsSimpleTextItem

    canvas = ActivityCanvas()
    canvas.show_graph(_long_trace(12))

    for item in canvas.graph_scene.items():
        if isinstance(item, QGraphicsSimpleTextItem):
            backdrop = item.parentItem()
            assert isinstance(backdrop, QGraphicsRectItem), "text is drawn on a patch"
            assert backdrop.brush().color().alpha() > 0, "the patch is opaque"


def test_a_trace_too_wide_to_fit_opens_at_its_beginning(qt_app: QApplication) -> None:
    """Laid out straight, a long trace is wider than the window, so the fit
    clamps at the legibility floor and something has to be off screen. Left
    centred, what is off screen is both ends and the view opens midway through
    the timeline — there is only one place to start reading a chronology.
    """
    canvas = ActivityCanvas()
    canvas.resize(400, 300)
    canvas.set_wrap(False)

    canvas.show_graph(_long_trace(12))

    bar = canvas.horizontalScrollBar()
    assert bar.maximum() > bar.minimum(), "premise: it does not fit"
    assert bar.value() == bar.minimum()


def test_the_wrap_toggle_is_offered_only_where_it_does_something(qt_app: QApplication) -> None:
    """A behaviour map is a circle and has no rows to fold. A live control that
    does nothing reads as a fault in the tool."""
    window = MainWindow()

    window._show_behaviour()
    assert not window._wrap_action.isEnabled()

    window._show_trace()
    assert window._wrap_action.isEnabled()
    window.close()


def test_the_wrap_choice_outlives_the_window(
    qt_app: QApplication, settings_in_a_temp_file: Path
) -> None:
    """Checked by opening a second window rather than by reading the setting
    back: a preference that is stored and never applied is the failure worth
    catching, and reading the file would not catch it.

    The file is checked too, but for a different reason — that the window is
    still writing through the seam these tests substitute. Inline a `QSettings`
    at either call site and this file stays empty while the preference quietly
    goes to the real registry of whoever ran the suite.
    """
    app._settings().clear()
    first = MainWindow()
    assert first._wrap_action.isChecked(), "wrapping is the default"

    first._wrap_action.trigger()
    first.close()
    second = MainWindow()

    assert not second._wrap_action.isChecked()
    assert not second._canvas.wrap
    assert "false" in settings_in_a_temp_file.read_text(encoding="utf-8").lower()
    second.close()


def test_redrawing_the_graph_forgets_the_ring(qt_app: QApplication, campaign: Path) -> None:
    """The scene is cleared on redraw, so a kept reference would point at a
    deleted item and the next highlight would try to remove it."""
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
    canvas = ActivityCanvas()
    canvas.show_graph(result.trace)
    canvas.highlight(result.trace.nodes[0].node_id)

    canvas.show_graph(result.behaviour)
    canvas.highlight(result.behaviour.nodes[0].node_id)

    assert canvas.graph_scene.items()


def test_the_evidence_table_has_a_row_for_every_piece_of_evidence(
    qt_app: QApplication, campaign: Path
) -> None:
    """Twenty-five pieces of evidence were 175 rows of wrapped text that could
    only be read in the order they arrived. They are twenty-five rows now."""
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
        node = result.trace.nodes[0]
        lines = case.read_evidence(node.evidence[:5])
    panel = EvidencePanel()

    panel.show_evidence(node, lines)

    assert panel._table.rowCount() == len(lines)


def test_choosing_a_row_shows_that_request_in_full(qt_app: QApplication, campaign: Path) -> None:
    """The table truncates a payload however wide it is. This is where the
    reader goes for all of it — and for the original line."""
    node, lines = _injection_evidence(campaign)
    panel = EvidencePanel()
    panel.show_evidence(node, lines)  # type: ignore[arg-type]

    panel.select_row(0)

    detail = panel._detail.toPlainText()
    assert str(lines[0].ref) in detail  # type: ignore[attr-defined]
    assert lines[0].text in detail  # type: ignore[attr-defined]


def test_the_detail_follows_the_row_after_the_table_is_sorted(
    qt_app: QApplication, campaign: Path
) -> None:
    """Sorting moves rows; the mapping from a row to its evidence must move
    with them, or the detail describes a different request from the one
    highlighted — which is worse than showing nothing."""
    from PyQt6.QtCore import Qt as QtNS

    from logarc.gui.evidence_view import COLUMNS

    node, lines = _injection_evidence(campaign)
    panel = EvidencePanel()
    panel.show_evidence(node, lines)  # type: ignore[arg-type]

    panel._table.sortItems(COLUMNS.index("Size"), QtNS.SortOrder.DescendingOrder)
    panel.select_row(0)

    shown_source = panel._table.item(0, COLUMNS.index("Source"))
    assert shown_source is not None
    assert shown_source.text() in panel._detail.toPlainText()


def _merged(case: Path) -> tuple[object, object]:
    """The behaviour node that merges several episodes, and its evidence."""
    with Case.open(case) as opened:
        result = analyse_ip(opened.store, CLIENT)
        node = max(result.behaviour.nodes, key=lambda item: item.episode_count)
        return node, opened.read_evidence(node.evidence)


def test_the_panel_states_the_count_of_the_activity_it_is_drawn_beside(
    qt_app: QApplication, recurring: Path
) -> None:
    """The heading was built from `next(episode for episode in ... )` — the
    node's *first* episode — while the rows below it came from the whole node.
    So a behaviour circle drawn as 35 requests was captioned with the 12 of the
    first burst, above evidence drawn from all 35.

    Wrong in the direction that matters: it understates a sweep as a fraction of
    itself, and the panel is what gets quoted into a case file.
    """
    node, lines = _merged(recurring)
    panel = EvidencePanel()

    panel.show_evidence(node, lines)  # type: ignore[arg-type]

    heading = panel._heading.text()
    assert f"{node.request_count:,} requests" in heading  # type: ignore[attr-defined]
    assert "12 requests" not in heading, "the first episode's count, not the activity's"


def test_a_merged_activity_says_how_many_activities_it_merges(
    qt_app: QApplication, recurring: Path
) -> None:
    """A behaviour node is several visits to one activity. Saying so is the
    difference between `35 requests` and `35 requests across 3 activities`, and
    the second is what the map is for."""
    node, lines = _merged(recurring)
    panel = EvidencePanel()

    panel.show_evidence(node, lines)  # type: ignore[arg-type]

    assert "across 3 activities" in panel._heading.text()


def test_a_single_activity_does_not_count_itself(qt_app: QApplication, campaign: Path) -> None:
    """Every trace node holds one episode, and `across 1 activities` on all of
    them would be noise on the view that is open by default."""
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
        node = result.trace.nodes[0]
        lines = case.read_evidence(node.evidence)
    panel = EvidencePanel()

    panel.show_evidence(node, lines)  # type: ignore[arg-type]

    assert "activities" not in panel._heading.text()


def test_the_panel_says_how_much_of_the_evidence_is_on_screen(
    qt_app: QApplication, recurring: Path
) -> None:
    """An episode keeps a bounded sample of its references — twenty, by
    `DEFAULT_EVIDENCE_SAMPLE` — and the true count beside it. The table showed
    the sample and said nothing, so twenty rows under a heading reading 51
    requests left the reader to conclude either that thirty-one lines were
    missing or that the count was wrong. It is neither.
    """
    node, lines = _merged(recurring)
    panel = EvidencePanel()

    panel.show_evidence(node, lines)  # type: ignore[arg-type]

    assert f"showing {len(lines)} of {node.evidence_total} lines" in panel._heading.text()  # type: ignore[attr-defined]


def test_a_complete_list_says_so_rather_than_staying_silent(
    qt_app: QApplication, campaign: Path
) -> None:
    """`showing 3 of 3 lines` on a complete activity, not nothing.

    Printed only when the two counts differ, silence has to be read as a claim —
    and the reader has to know it is one. Saying it every time makes the line a
    fact about the table rather than a warning about it, and `3 of 3` is then
    positive confirmation that nothing is being held back.
    """
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
        node = next(
            item for item in result.trace.nodes if len(item.evidence) == item.evidence_total
        )
        lines = case.read_evidence(node.evidence)
    panel = EvidencePanel()

    panel.show_evidence(node, lines)

    assert f"showing {len(lines)} of {node.evidence_total} lines" in panel._heading.text()


def test_a_single_line_of_evidence_is_not_called_lines(
    qt_app: QApplication, campaign: Path
) -> None:
    """`showing 1 of 1 lines` is the same fault `format_requests` exists to
    stop, one noun along."""
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
        node = next(item for item in result.trace.nodes if item.evidence_total == 1)
        lines = case.read_evidence(node.evidence)
    panel = EvidencePanel()

    panel.show_evidence(node, lines)

    assert "showing 1 of 1 line" in panel._heading.text()
    assert "1 lines" not in panel._heading.text()


def test_the_busiest_matching_activity_is_the_one_carried_across(
    qt_app: QApplication, recurring: Path
) -> None:
    """Going back from the map to the trace, one behaviour node answers to
    three trace nodes. The ring lands on the one that dominated what was being
    read — and on the same one every run, because a forensic tool that ringed a
    different node on each pass would invite doubt about what else moved."""
    from logarc.gui.app import _node_for_episodes

    with Case.open(recurring) as case:
        result = analyse_ip(case.store, CLIENT)
    behaviour = max(result.behaviour.nodes, key=lambda item: item.episode_count)

    found = _node_for_episodes(result.trace, frozenset(behaviour.episode_ids))

    assert found is not None
    assert found.request_count == 20, "the busiest of the three enumeration episodes"


def test_an_activity_with_no_counterpart_leaves_nothing_ringed(
    qt_app: QApplication, recurring: Path
) -> None:
    """The other half of carrying a selection across: when the new graph has no
    node for it, the answer is no ring and an empty panel — not the previous
    graph's evidence left sitting beside a graph that does not show it."""
    from logarc.gui.app import _node_for_episodes

    with Case.open(recurring) as case:
        result = analyse_ip(case.store, CLIENT)

    assert _node_for_episodes(result.trace, frozenset({"nothing/1"})) is None


def test_switching_view_leaves_the_panel_describing_what_is_ringed(
    qt_app: QApplication, recurring: Path
) -> None:
    """The finding this began as. Trace → Behaviour redrew the canvas and left
    the panel alone, so the two halves of the window described different
    activities and nothing on screen said which one was being read.

    The panel now re-reads whatever the ring lands on, so both halves agree.
    """
    window = MainWindow()
    window._load_case(recurring)
    _settled(qt_app)
    window._clients._table.selectRow(0)
    _settled(qt_app)
    assert window._result is not None

    enumeration = max(window._result.trace.nodes, key=lambda item: item.request_count)
    window._show_evidence(enumeration.node_id)
    _settled(qt_app)
    assert f"{enumeration.request_count:,} requests" in window._evidence._heading.text()

    window._show_behaviour()
    _settled(qt_app)

    merged = max(window._result.behaviour.nodes, key=lambda item: item.episode_count)
    assert window._canvas._selected == merged.node_id, "the map is not ringing anything"
    assert f"{merged.request_count:,} requests" in window._evidence._heading.text()
    window.close()


def test_the_evidence_table_drops_a_size_column_it_has_no_sizes_for(
    qt_app: QApplication, campaign: Path
) -> None:
    """A column costs its heading's width whatever it holds, and plenty of log
    formats carry no response size at all — so `Size` sat empty on every row
    while `Request`, the column carrying the payload, wrapped to two lines.

    It comes back the moment one row has a size: this is about an empty column,
    not about hiding evidence.
    """
    from logarc.core.event import NormalizedEvent
    from logarc.evidence import EvidenceLine
    from logarc.gui.evidence_view import COLUMNS

    node, sized = _injection_evidence(campaign)
    ref = EvidenceRef("access.log", 1)
    sizeless = [
        EvidenceLine(
            ref=ref,
            source_path="a.log",
            text="raw",
            event=NormalizedEvent(
                timestamp=START, client_ip=CLIENT, evidence=ref, method="GET", path="/a", status=404
            ),
        )
    ]
    panel = EvidencePanel()

    panel.show_evidence(node, sizeless)  # type: ignore[arg-type]
    assert panel._table.isColumnHidden(COLUMNS.index("Size"))

    panel.show_evidence(node, sized)  # type: ignore[arg-type]
    assert not panel._table.isColumnHidden(COLUMNS.index("Size"))


def test_a_payload_cannot_forge_a_row_or_render_as_markup(
    qt_app: QApplication, campaign: Path
) -> None:
    """Everything in this table came out of a request. A decoded newline would
    draw over the row beneath it; a tooltip taken as rich text would render an
    attacker's markup inside the panel their case is read from."""
    from logarc.core.event import NormalizedEvent
    from logarc.evidence import EvidenceLine
    from logarc.gui.evidence_view import COLUMNS

    node, _ = _injection_evidence(campaign)
    ref = EvidenceRef("access.log", 1)
    hostile = EvidenceLine(
        ref=ref,
        source_path="a.log",
        text="raw",
        event=NormalizedEvent(
            timestamp=START,
            client_ip=CLIENT,
            evidence=ref,
            method="GET",
            path="/a",
            query="q=%0Aforged&t=%3Cimg%20src%3Dx%20onerror%3Dboom%3E",
            status=200,
        ),
    )
    panel = EvidencePanel()

    panel.show_evidence(node, [hostile])  # type: ignore[arg-type]

    assert panel._table.rowCount() == 1
    target = panel._table.item(0, COLUMNS.index("Request"))
    assert target is not None
    assert "\n" not in target.text()
    assert "<U+000A>" in target.text()
    assert "&lt;img" in target.toolTip()


def test_the_evidence_detail_does_not_depend_on_the_system_theme(
    qt_app: QApplication,
) -> None:
    """The panel writes dark text. If it also inherited the window background,
    a machine themed dark renders the evidence dark-on-dark — the one panel an
    investigator cannot do without, invisible, with nothing to indicate why."""
    from logarc.gui.evidence_panel import _INK, _PAPER

    # Held in a name: chaining off the constructor lets Python drop the panel
    # before the palette is read, and Qt deletes the widget underneath it.
    panel = EvidencePanel()
    palette = panel._detail.palette()

    assert palette.color(QPalette.ColorRole.Base).name() == _PAPER
    assert palette.color(QPalette.ColorRole.Text).name() == _INK


def test_the_decode_choice_outlives_the_window(qt_app: QApplication) -> None:
    """The one evidence preference left. `Show raw log lines` is retired: the
    detail pane prints the original line for the selected row always, which is
    strictly more than a global on-or-off could give."""
    app._settings().clear()
    first = MainWindow()
    assert first._decode_action.isChecked(), "decoding is the default"
    assert not hasattr(first, "_raw_action"), "the raw toggle is retired"

    first._decode_action.trigger()
    first.close()
    second = MainWindow()

    assert not second._decode_action.isChecked()
    second.close()


def test_a_cell_shows_its_text_and_still_sorts_on_its_number(
    qt_app: QApplication, campaign: Path
) -> None:
    """Qt keeps DisplayRole and EditRole in the same slot on a table item, so
    putting a sort key in EditRole replaces the text with the raw number: a
    timestamp rendered as `1.71454e+09` and a size as `512.0`. The key has to
    live somewhere else and the comparison has to be done by hand.

    The client table beside this one has carried the same fault unnoticed —
    its 4xx ratio shows `0` where it formats `0%` — because whole numbers look
    the same either way.
    """
    from logarc.gui.evidence_view import COLUMNS

    node, lines = _injection_evidence(campaign)
    panel = EvidencePanel()
    panel.show_evidence(node, lines)  # type: ignore[arg-type]

    shown = panel._table.item(0, COLUMNS.index("Time"))
    assert shown is not None
    assert ":" in shown.text(), f"a time of day, not {shown.text()!r}"
    assert "e+" not in shown.text()

    size = panel._table.item(0, COLUMNS.index("Size"))
    assert size is not None
    assert size.text().endswith(("B", "KB", "MB"))


def test_sorting_by_size_puts_the_largest_response_on_top(
    qt_app: QApplication, campaign: Path
) -> None:
    """The blue-team move this table exists for: which request got data out.
    Asserted on the resulting order rather than on a stored key, because the
    order is what the reader sees."""
    from PyQt6.QtCore import Qt as QtNS

    from logarc.gui.evidence_view import COLUMNS

    node, lines = _injection_evidence(campaign)
    panel = EvidencePanel()
    panel.show_evidence(node, lines)  # type: ignore[arg-type]

    panel._table.sortItems(COLUMNS.index("Size"), QtNS.SortOrder.DescendingOrder)

    biggest = max(line.event.bytes_sent or 0 for line in lines if line.event is not None)  # type: ignore[attr-defined]
    top = panel._table.item(0, COLUMNS.index("Size"))
    assert top is not None
    assert top.text() == format_bytes(biggest)


def test_the_evidence_table_does_not_depend_on_the_system_theme(
    qt_app: QApplication,
) -> None:
    """The detail pane is pinned to a pale ground for a reason; the table above
    it is read the same way and needs the same treatment, or a dark theme puts
    muted grey on dark grey."""
    from logarc.gui.evidence_panel import _INK, _PAPER

    panel = EvidencePanel()
    palette = panel._table.palette()

    assert palette.color(QPalette.ColorRole.Base).name() == _PAPER
    assert palette.color(QPalette.ColorRole.Text).name() == _INK


def test_the_framed_evidence_surface_is_still_paper_when_it_is_painted(
    qt_app: QApplication,
) -> None:
    """The frame around the evidence is a stylesheet, and this file already
    warns what that can cost: a stylesheet can replace what the palette says
    while `palette()` goes on reporting the old colour, so the two tests above
    would pass over an unreadable panel.

    So this one reads the pixels, under a dark theme, which is the case where
    losing the pinned ground would put muted grey on dark grey.
    """
    from PyQt6.QtGui import QColor

    from logarc.gui.evidence_panel import _PAPER

    was = qt_app.palette()
    try:
        dark = QPalette(was)
        dark.setColor(QPalette.ColorRole.Base, QColor("#1e1e1e"))
        dark.setColor(QPalette.ColorRole.Window, QColor("#1e1e1e"))
        qt_app.setPalette(dark)

        panel = EvidencePanel()
        panel.resize(400, 600)
        panel.show()
        QApplication.processEvents()
        painted = panel.grab().toImage()

        assert painted.pixelColor(200, 200).name() == _PAPER, "the table lost its ground"
        assert painted.pixelColor(200, 480).name() == _PAPER, "the detail lost its ground"
        panel.close()
    finally:
        qt_app.setPalette(was)


def test_the_client_table_shows_a_percentage_not_a_bare_number(
    qt_app: QApplication, campaign: Path
) -> None:
    """A fault this table has carried since it was written, found while giving
    the evidence table the same treatment.

    The 4xx column formats a ratio as `13%` and then puts the raw ratio in
    EditRole to sort on. On a table item EditRole and DisplayRole are one slot,
    so the number replaces the text and the column reads `0` — in the column an
    investigator sorts by when looking for something worth opening.
    """
    with Case.open(campaign) as case:
        summaries = case.store.ip_summaries(limit=50, order_by="requests")
    table = ClientTable()

    table.show_clients(summaries)

    ratio = table._table.item(0, 3)
    assert ratio is not None
    assert ratio.text().endswith("%"), f"a ratio, not {ratio.text()!r}"


def test_the_client_table_still_sorts_by_the_number(qt_app: QApplication, campaign: Path) -> None:
    """ "1,000" sorts before "9" as text. Showing the formatted value must not
    cost the numeric ordering."""
    from PyQt6.QtCore import Qt as QtNS

    with Case.open(campaign) as case:
        summaries = case.store.ip_summaries(limit=50, order_by="requests")
    table = ClientTable()
    table.show_clients(summaries)

    table._table.sortItems(1, QtNS.SortOrder.DescendingOrder)

    top = table._table.item(0, 1)
    assert top is not None
    assert top.text() == f"{max(s.request_count for s in summaries):,}"
