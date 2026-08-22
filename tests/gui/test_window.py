"""Smoke tests for the window itself, run without a display.

The GUI is verified by hand against docs/manual-test-plan.md — a checklist
cannot be automated away. What *can* be automated is that it still constructs,
still draws a real reconstruction, and still survives a case with nothing in it.
Those are the failures that would otherwise be found by opening the app.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from dragging import drag
from PyQt6.QtCore import QPoint
from PyQt6.QtGui import QFontMetrics, QPalette
from PyQt6.QtWidgets import QApplication, QSplitter

from conftest import contrast
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
from logarc.gui.notice_bar import QuarantineBanner
from logarc.gui.panels import ClientTable
from logarc.gui.progress import Progress
from logarc.gui.progress_card import IngestCard
from logarc.gui.quarantine_notice import notice_for
from logarc.gui.style import NOTICE_TINT, THEME, format_bytes
from logarc.storage.base import IpSummary
from logarc.storage.case import CaseManifest, SourceRecord

NEWLINE = chr(10)
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
    _summaries, crs, _, _ = read_case(enriched)

    assert crs.fingerprint == "test-fingerprint"
    assert crs.index is not None


def test_a_reconstruction_credits_the_crs_configuration_that_produced_it(
    enriched: Path,
) -> None:
    """The evidence has to reach the analysis, not merely be loaded beside it."""
    _summaries, crs, _, _ = read_case(enriched)

    result = reconstruct_client(enriched, CLIENT, crs)

    assert result.crs_fingerprint == "test-fingerprint"


def test_an_unenriched_case_credits_nothing(campaign: Path) -> None:
    """The ordinary case, and the one that must not claim CRS took part."""
    _summaries, crs, _, _ = read_case(campaign)

    result = reconstruct_client(campaign, CLIENT, crs)

    assert crs.index is None
    assert result.crs_fingerprint is None


def test_the_window_constructs(qt_app: QApplication) -> None:
    window = MainWindow()

    assert window.windowTitle().startswith("logarc")
    window.close()


def _widen(window: MainWindow, width: int) -> None:
    """Give the window's contents a width, under the offscreen platform.

    `window.resize` does not reach the central widget here — it reports the same
    width before and after, which makes a resize test look like it passed while
    measuring nothing. Resizing the central widget does work, and the layout
    inside it hands the width down to the splitter.

    Sizing the splitter *directly* used to work and no longer does: the notice
    strip put it inside a `QVBoxLayout`, and a layout re-imposes its own
    geometry on the next event pass, so the resize is silently undone. That is
    the failure this helper exists to keep from coming back — a test measuring
    552px before and 552px after, and calling it a pass.
    """
    frame = window.centralWidget()
    assert frame is not None
    frame.resize(width, 880)
    QApplication.processEvents()


def _laid_out(width: int = 1400) -> tuple[MainWindow, QSplitter]:
    """A shown window, with its contents sized to `width`."""
    window = MainWindow()
    window.show()
    _widen(window, width)
    return window, window._splitter


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

    _widen(window, 2000)
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


def _summaries(*addresses: str) -> list[object]:
    """Client summaries with chosen addresses, built rather than ingested.

    The premise these tests rest on is which addresses are in the table, and
    reading them out of a generated case would let a change to the generator
    quietly empty the assertions.
    """
    from logarc.storage.base import IpSummary

    return [
        IpSummary(
            client_ip=address,
            request_count=index * 7 + 3,
            first_seen=START,
            last_seen=START + timedelta(minutes=index + 1),
            distinct_paths=index + 1,
            client_error_ratio=index / 10,
            bytes_total=index * 1000 + 1,
        )
        for index, address in enumerate(addresses)
    ]


def _on_screen(table: ClientTable) -> list[str]:
    """The addresses a reader can actually see, in the order they are drawn."""
    seen = []
    for row in range(table._table.rowCount()):
        cell = table._table.item(row, 0)
        if cell is not None and not table._table.isRowHidden(row):
            seen.append(cell.text())
    return seen


def test_typing_an_address_narrows_the_client_list(qt_app: QApplication) -> None:
    """Sorting answers "which client is worth opening". It cannot answer "where
    is 203.0.113.66", which is the question a ticket or an abuse report brings."""
    table = ClientTable()
    table.show_clients(_summaries("203.0.3.9", "203.0.3.8", "198.51.100.4", "203.0.30.5"))

    table._filter.setText("203.0.3.")

    assert _on_screen(table) == ["203.0.3.9", "203.0.3.8"]


def test_a_neighbouring_block_is_not_swept_in(qt_app: QApplication) -> None:
    """`203.0.30.5` is a different /24 from `203.0.3.x`. A filter typed to
    isolate one block must not answer with another block's traffic."""
    table = ClientTable()
    table.show_clients(_summaries("203.0.3.9", "203.0.30.5"))

    table._filter.setText("203.0.3.")

    assert "203.0.30.5" not in _on_screen(table)


def test_clearing_the_filter_puts_the_whole_case_back(qt_app: QApplication) -> None:
    table = ClientTable()
    table.show_clients(_summaries("203.0.3.9", "198.51.100.4"))
    table._filter.setText("203.0.3.")

    table._filter.clear()

    assert _on_screen(table) == ["203.0.3.9", "198.51.100.4"]


def test_the_caption_keeps_the_size_of_the_case_on_screen(qt_app: QApplication) -> None:
    """A filtered list captioned "1 client" describes a case with one client in
    it. That is a lie about the evidence, and the panel is the only place the
    size of the case is stated."""
    table = ClientTable()
    table.show_clients(_summaries("203.0.3.9", "198.51.100.4", "198.51.100.7"))

    table._filter.setText("203.0.3.")

    assert table._caption.text() == "1 of 3 clients matches 203.0.3."


def test_filtering_does_not_reconstruct_a_different_client(qt_app: QApplication) -> None:
    """`client_chosen` starts a reconstruction. Hiding rows moves Qt's
    selection about, so a filter that let the signal through would abandon the
    client being read and start analysing whoever happened to survive the
    filter — triggered by typing."""
    table = ClientTable()
    table.show_clients(_summaries("203.0.3.9", "203.0.3.8", "198.51.100.4"))
    table._table.selectRow(0)

    chosen: list[str] = []
    table.client_chosen.connect(chosen.append)
    table._filter.setText("198.51")
    table._filter.setText("203.0.3.")
    table._filter.clear()

    assert chosen == [], f"typing in the filter reconstructed {chosen}"


def test_sorting_after_filtering_still_hides_the_right_rows(qt_app: QApplication) -> None:
    """Filtering and sorting are used together — narrow to a subnet, then order
    it by 4xx — so the two must not undo each other.

    Written expecting a bug that is not there: `setRowHidden` takes a row index,
    so sorting looked certain to leave the holes behind while the items moved
    through them. Probed rather than assumed, and QTableWidget carries the
    hidden flag along with the item it belongs to. The defensive re-apply this
    test was written to prove was removed once the probe showed it was dead
    code. The test stays: the property is one a reader depends on, and it would
    stop holding the moment this panel moved to a proxy model or rebuilt its
    rows on sort.
    """
    from PyQt6.QtCore import Qt

    table = ClientTable()
    table.show_clients(_summaries("203.0.3.9", "198.51.100.4", "203.0.3.8", "198.51.100.7"))
    table._filter.setText("203.0.3.")
    assert len(_on_screen(table)) == 2, "premise: the filter hides two of the four"

    # Descending, so every item actually changes row. Ascending left this data
    # in the order it was already in, and the test passed with the fix removed
    # — a sort that moves nothing cannot catch a bug about rows moving.
    table._table.sortItems(1, Qt.SortOrder.DescendingOrder)
    assert _on_screen(table)[0] != "203.0.3.9", "premise: the sort reordered the table"

    assert set(_on_screen(table)) == {"203.0.3.9", "203.0.3.8"}


def test_opening_another_case_does_not_carry_the_filter_across(qt_app: QApplication) -> None:
    """A filter left over from the last case hides most of the new one, and the
    reader has no reason to suspect a box they filled in for something else."""
    table = ClientTable()
    table.show_clients(_summaries("203.0.3.9", "198.51.100.4"))
    table._filter.setText("203.0.3.")

    table.show_clients(_summaries("10.1.1.1", "10.1.1.2"))

    assert table._filter.text() == ""
    # A set, because the table keeps whatever sort order it was left in and the
    # claim here is about what is visible, not about what order it is in.
    assert set(_on_screen(table)) == {"10.1.1.1", "10.1.1.2"}


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


#: Activity names of the length real ones reach, with the request counts that
#: set how wide a circle is drawn. `_long_trace` repeats one short label at one
#: size, which no arrangement of spacing can overlap — a graph made of those
#: cannot show whether captions collide.
_REAL_LABELS = (
    ("SQL Injection (always-true condition)", 3),
    ("Request Without User-Agent", 4),
    ("Non-idempotent Request", 1),
    ("SQL Injection (UNION SELECT)", 15),
    ("Static Asset", 4),
    ("Authentication", 1),
    ("Page View", 5),
)


def _dense_trace(sessions: tuple[int, ...] = (2, 1, 3, 2, 6, 1, 37)) -> ActivityGraph:
    """A trace shaped like the one in the reported screenshot.

    Six short sessions and a long tail. The tail is what matters: it wraps onto
    several rows, and a row's captions are what reach the next row's circles.
    """
    nodes = []
    edges = []
    for session, length in enumerate(sessions, start=1):
        previous = None
        for step in range(length):
            label, count = _REAL_LABELS[(session + step) % len(_REAL_LABELS)]
            node_id = f"127.0.0.1#{session}/{step}"
            nodes.append(
                GraphNode(
                    node_id=node_id,
                    label=label,
                    category=ActivityCategory.ENUMERATION,
                    severity=Severity.MEDIUM,
                    outcome=Outcome.BLOCKED if step % 2 else Outcome.MIXED,
                    request_count=count,
                    distinct_paths=count,
                    bytes_total=1,
                    start=START + timedelta(minutes=session * 10 + step),
                    end=START + timedelta(minutes=session * 10 + step, seconds=30),
                    owasp=None,
                    top_targets=("/a",),
                    rule_ids=("r",),
                    evidence=(EvidenceRef("access.log", step + 1),),
                    evidence_total=count,
                    episode_ids=(node_id,),
                )
            )
            if previous is not None:
                edges.append(GraphEdge(previous, node_id, weight=1, gap_seconds=1.0))
            previous = node_id
    return ActivityGraph(
        kind=GraphKind.TRACE, client_ip="127.0.0.1", nodes=tuple(nodes), edges=tuple(edges)
    )


def _texts(canvas: ActivityCanvas) -> list:
    from PyQt6.QtWidgets import QGraphicsSimpleTextItem

    return [
        item for item in canvas.graph_scene.items() if isinstance(item, QGraphicsSimpleTextItem)
    ]


def test_the_whole_drawing_scales_together_like_a_picture(qt_app: QApplication) -> None:
    """Text on this canvas used to be pinned to screen size, so that `fit()`
    could not shrink it into a smudge. That fixed one fault and created
    another: the geometry shrank while the words did not, so captions that
    cleared each other at full zoom piled into each other further out — 117
    overlapping pairs at 0.35 on a 52-activity trace, which is where a reader
    goes to see the shape of a long session.

    Scaling everything together is what removes the whole class: two things
    that do not touch at one zoom cannot touch at another, so overlap stops
    being a rendering problem and becomes a fixed property of the layout, fixed
    once in `layout.py`.

    The original fault is guarded by the test below instead, which is the
    honest place for it: the risk was never that captions scaled, it was that
    they ended up too small to read at the scale a graph opens at.
    """
    from PyQt6.QtWidgets import QGraphicsItem

    canvas = ActivityCanvas()
    canvas.show_graph(_long_trace(12))

    drawn = _texts(canvas)
    assert drawn, "a trace this long has captions and edge labels"
    for text in drawn:
        item = text
        while item is not None:
            assert not (item.flags() & QGraphicsItem.GraphicsItemFlag.ItemIgnoresTransformations), (
                f"{text.text()!r} is pinned to screen size and will collide when zoomed out"
            )
            item = item.parentItem()


def test_a_caption_is_still_readable_at_the_scale_a_graph_opens_at(
    qt_app: QApplication,
) -> None:
    """The fault that pinned captions to screen size in the first place: a
    wrapped trace fitted to the window drew them about five pixels tall, and a
    legible graph with illegible labels is a picture of circles.

    Now they scale, so the guarantee has to be made where it matters — at the
    scale a graph actually opens at. `fit()` will not go below `MIN_FIT_SCALE`,
    and the caption is sized so that at exactly that scale it is drawn the size
    it always was.
    """
    canvas = ActivityCanvas()
    canvas.resize(900, 700)
    canvas.show_graph(_long_trace(40))

    scale = canvas.transform().m11()
    assert scale <= MIN_FIT_SCALE + 0.01, "premise: a trace this long fits only at the floor"
    on_screen = [text.font().pointSizeF() * scale for text in _texts(canvas)]
    assert on_screen, "premise: something is captioned"
    assert min(on_screen) >= 7.0, f"smallest caption is {min(on_screen):.1f}pt on screen"


def test_nothing_written_on_the_canvas_lands_on_anything_else(
    qt_app: QApplication,
) -> None:
    """The reported fault, stated as the property that prevents it.

    Measured in scene coordinates, which is the whole point of the change: with
    everything scaling together this holds at every zoom at once, so the test
    does not have to enumerate zoom levels to be complete.
    """
    from PyQt6.QtWidgets import QGraphicsRectItem

    canvas = ActivityCanvas()
    canvas.show_graph(_dense_trace())

    captions = [
        child.sceneBoundingRect()
        for node in canvas._nodes.values()
        for child in node.childItems()
        if isinstance(child, QGraphicsRectItem)
    ]
    circles = [node.sceneBoundingRect() for node in canvas._nodes.values()]
    assert len(captions) >= 50, "premise: every activity is captioned"

    for index, one in enumerate(captions):
        for other in captions[index + 1 :]:
            assert not one.intersects(other), "two captions overlap"
        for circle in circles:
            assert not one.intersects(circle), "a caption is drawn under a circle"


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


def _activity(name: str) -> GraphNode:
    return GraphNode(
        node_id=name,
        label=name.replace("_", " "),
        category=ActivityCategory.ENUMERATION,
        severity=Severity.MEDIUM,
        outcome=Outcome.BLOCKED,
        request_count=9,
        distinct_paths=9,
        bytes_total=1,
        start=START,
        end=START + timedelta(seconds=30),
        owasp=None,
        top_targets=("/a",),
        rule_ids=("r",),
        evidence=(EvidenceRef("access.log", 1),),
        evidence_total=9,
        episode_ids=(f"1.2.3.4#1/{name}",),
    )


def _behaviour_map(*edges: GraphEdge) -> ActivityGraph:
    """A behaviour map over whichever activities those edges mention."""
    named = sorted({end for edge in edges for end in (edge.source, edge.target)})
    return ActivityGraph(
        kind=GraphKind.BEHAVIOUR,
        client_ip="203.0.113.5",
        nodes=tuple(_activity(name) for name in named),
        edges=edges,
    )


def _drawn_edges(canvas: ActivityCanvas) -> list[object]:
    from PyQt6.QtWidgets import QGraphicsPathItem

    return [
        item.path() for item in canvas.graph_scene.items() if isinstance(item, QGraphicsPathItem)
    ]


def test_two_transitions_between_the_same_pair_are_drawn_apart(qt_app: QApplication) -> None:
    """Drawn straight, the second arrow lands exactly on the first and its
    label is written over the one already there. The map showed one transition
    where there were two, and which one survived was the order they were listed
    in — on the view whose whole purpose is showing repetition."""
    canvas = ActivityCanvas()
    canvas.show_graph(
        _behaviour_map(
            GraphEdge("enumeration", "injection", weight=3, gap_seconds=1.0),
            GraphEdge("injection", "enumeration", weight=2, gap_seconds=2.0),
        )
    )

    one, other = _drawn_edges(canvas)

    apart = one.pointAtPercent(0.5) - other.pointAtPercent(0.5)  # type: ignore[attr-defined]
    assert apart.manhattanLength() > 20.0


def test_an_arrowhead_points_the_way_its_own_curve_arrives(qt_app: QApplication) -> None:
    """A head aimed down the straight line between the two circles is visibly
    turned against the curve it caps, and it is the head that tells a reader
    which way a transition ran."""
    import math

    from PyQt6.QtWidgets import QGraphicsPolygonItem

    canvas = ActivityCanvas()
    canvas.show_graph(
        _behaviour_map(
            GraphEdge("enumeration", "injection", weight=3, gap_seconds=1.0),
            GraphEdge("injection", "enumeration", weight=2, gap_seconds=2.0),
        )
    )

    curves = _drawn_edges(canvas)
    heads = [
        item.polygon()
        for item in canvas.graph_scene.items()
        if isinstance(item, QGraphicsPolygonItem)
    ]
    assert len(heads) == len(curves) == 2, "premise: two arrows, each with a head"

    for curve in curves:
        tip = curve.pointAtPercent(1.0)  # type: ignore[attr-defined]
        head = min(heads, key=lambda shape: (shape[0] - tip).manhattanLength())
        pointing = head[0] - (head[1] + head[2]) / 2
        arriving = tip - curve.pointAtPercent(0.97)  # type: ignore[attr-defined]

        between = abs(
            math.atan2(pointing.y(), pointing.x()) - math.atan2(arriving.y(), arriving.x())
        )
        assert math.degrees(min(between, 2 * math.pi - between)) < 3.0


def test_the_number_on_an_arrow_is_not_read_past(qt_app: QApplication) -> None:
    """It was `edge_ink` at 7.0pt — 5.5:1 against the ground where the caption
    beside it is 16.5:1, and half a point smaller. Legal by the 4.5:1 floor and
    unreadable anyway, because the eye is calibrated by the brighter text next
    to it. `muted` is 8.9:1: readable, and still one step below a caption, which
    is right — the activity is the subject and the transition is the detail.
    """
    from logarc.gui import canvas as canvas_module
    from logarc.gui.style import CAPTION_COLOUR, THEME

    assert contrast(canvas_module._LABEL_COLOUR, THEME.chrome) >= 8.0
    assert canvas_module._LABEL_SIZE >= 7.5
    assert contrast(canvas_module._LABEL_COLOUR, THEME.chrome) < contrast(
        CAPTION_COLOUR, THEME.chrome
    ), "a transition is the detail, not the subject"


def test_an_edge_with_no_counterpart_stays_straight(qt_app: QApplication) -> None:
    """A curve means "there are two here". A solitary edge that bows says
    something untrue about itself, and makes a calm map look busy."""
    canvas = ActivityCanvas()
    canvas.show_graph(_behaviour_map(GraphEdge("browsing", "enumeration", weight=1)))

    (solitary,) = _drawn_edges(canvas)

    straight = (solitary.pointAtPercent(0.0) + solitary.pointAtPercent(1.0)) / 2  # type: ignore[attr-defined]
    assert (solitary.pointAtPercent(0.5) - straight).manhattanLength() < 0.5  # type: ignore[attr-defined]


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


def test_the_heading_labels_each_fact_on_a_line_of_its_own(
    qt_app: QApplication, recurring: Path
) -> None:
    """The heading grew a fact at a time and the outcome stayed buried in the
    middle of the first line, between the request count and the timestamps —
    the one field that says whether any of it worked, in the position the eye
    reaches last. Labelled lines instead, each one a name and a value."""
    node, lines = _merged(recurring)
    panel = EvidencePanel()

    panel.show_evidence(node, lines)  # type: ignore[arg-type]

    heading = panel._heading.text()
    assert "Outcome: blocked" in heading
    assert "Matched by: directory_enumeration" in heading
    assert "outcome blocked" not in heading, "the old inline form"


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

    assert f"Showing {len(lines)} of {node.evidence_total} lines" in panel._heading.text()  # type: ignore[attr-defined]


def test_a_complete_list_says_so_rather_than_staying_silent(
    qt_app: QApplication, campaign: Path
) -> None:
    """`Showing 3 of 3 lines` on a complete activity, not nothing.

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

    assert f"Showing {len(lines)} of {node.evidence_total} lines" in panel._heading.text()


def test_a_single_line_of_evidence_is_not_called_lines(
    qt_app: QApplication, campaign: Path
) -> None:
    """`Showing 1 of 1 lines` is the same fault `format_requests` exists to
    stop, one noun along."""
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
        node = next(item for item in result.trace.nodes if item.evidence_total == 1)
        lines = case.read_evidence(node.evidence)
    panel = EvidencePanel()

    panel.show_evidence(node, lines)

    assert "Showing 1 of 1 line" in panel._heading.text()
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


def _reconstructed(qt_app: QApplication, case: Path) -> MainWindow:
    """A window with the first client of `case` reconstructed."""
    window = MainWindow()
    window._load_case(case)
    _settled(qt_app)
    window._clients._table.selectRow(0)
    _settled(qt_app)
    assert window._result is not None
    return window


def test_an_activity_that_fits_is_shown_whole(qt_app: QApplication, campaign: Path) -> None:
    """The panel showed twenty lines of a thirty-request sweep because an
    episode keeps twenty references — a bound chosen to keep an *exported file*
    small, paid by a window that exports nothing until asked.

    And `events[:20]` is a prefix, not a sample: the reader saw the opening of
    the sweep and never the end, which on an attack is where it starts working.
    """
    window = _reconstructed(qt_app, campaign)
    biggest = max(window._result.trace.nodes, key=lambda item: item.request_count)

    window._show_evidence(biggest.node_id)
    _settled(qt_app)

    assert window._evidence._table.rowCount() == biggest.evidence_total
    assert (
        f"Showing {biggest.evidence_total} of {biggest.evidence_total} lines"
        in window._evidence._heading.text()
    )
    window.close()


def test_a_merged_activity_shows_every_episode_not_just_the_first(
    qt_app: QApplication, recurring: Path
) -> None:
    """`graphbuild.build` cuts a behaviour node's merged references at twenty,
    and the merge runs in episode order — so the rows came from the earliest
    burst and the latest one was invisible however long it ran.

    The window gathers from the episodes the node names instead of from the
    trimmed tuple the graph carries, so nothing about the exported graph has to
    change for the panel to show the whole activity.
    """
    from logarc.gui.evidence_view import COLUMNS

    window = _reconstructed(qt_app, recurring)
    merged = max(window._result.behaviour.nodes, key=lambda item: item.episode_count)
    window._show_behaviour()
    _settled(qt_app)

    window._show_evidence(merged.node_id)
    _settled(qt_app)

    table = window._evidence._table
    assert table.rowCount() == merged.evidence_total
    shown = {
        table.item(row, COLUMNS.index("Request")).text()
        for row in range(table.rowCount())
        if table.item(row, COLUMNS.index("Request")) is not None
    }
    assert any("b2-" in request for request in shown), "the last burst is still missing"
    window.close()


def test_the_table_stops_at_what_it_can_draw_and_says_so(
    qt_app: QApplication, campaign: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Filling the table runs on the interface thread — twenty thousand rows is
    a three-second freeze, which is the hang `workers.py` exists to prevent. So
    there is a ceiling, and it is a limit on what can be *drawn* rather than on
    what is kept. Reached, it is stated rather than passed over in silence.
    """
    monkeypatch.setattr(app, "_EVIDENCE_LIMIT", 5)
    window = _reconstructed(qt_app, campaign)
    biggest = max(window._result.trace.nodes, key=lambda item: item.request_count)

    window._show_evidence(biggest.node_id)
    _settled(qt_app)

    assert window._evidence._table.rowCount() == 5
    assert f"Showing 5 of {biggest.evidence_total} lines" in window._evidence._heading.text()
    window.close()


def test_an_exported_graph_keeps_the_bounded_sample(
    qt_app: QApplication, campaign: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The window now reconstructs with every reference it can draw, and
    `_export` serialises what the window is holding — so without care the
    exported graph, and the report that embeds it, grow with the log.

    The deliverables keep the sample the engine's own default defines.
    """
    import json

    from logarc.episode.builder import DEFAULT_EVIDENCE_SAMPLE

    written = tmp_path / "graph.json"
    monkeypatch.setattr(
        "PyQt6.QtWidgets.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: (str(written), ""),
    )
    window = _reconstructed(qt_app, campaign)

    window._export("json")
    _settled(qt_app)

    exported = json.loads(written.read_text(encoding="utf-8"))
    counts = [len(node["evidence"]) for node in exported["trace"]["nodes"]]
    assert counts, "the export drew no nodes"
    assert max(counts) <= DEFAULT_EVIDENCE_SAMPLE
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
    qt_app: QApplication, campaign: Path
) -> None:
    """The frame around the evidence is a stylesheet, and this file already
    warns what that can cost: a stylesheet can replace what the palette says
    while `palette()` goes on reporting the old colour, so the two tests above
    would pass over an unreadable panel.

    So this one reads the pixels, under a system palette set to something else
    entirely — the case where losing the pinned ground would put the evidence on
    a colour nothing here was chosen against.

    Evidence is loaded first because an empty panel now hides its table and
    detail rather than standing them up as furniture over nothing. The points
    sampled are below the last row and below the last line, which is table and
    detail ground rather than a row, a stripe, or the selected row's tint.
    """
    from PyQt6.QtCore import QPoint
    from PyQt6.QtGui import QColor

    from logarc.gui.evidence_panel import _PAPER

    node, lines = _injection_evidence(campaign)

    was = qt_app.palette()
    try:
        hostile = QPalette(was)
        hostile.setColor(QPalette.ColorRole.Base, QColor("#1e1e1e"))
        hostile.setColor(QPalette.ColorRole.Window, QColor("#1e1e1e"))
        qt_app.setPalette(hostile)

        panel = EvidencePanel()
        panel.resize(400, 600)
        panel.show_evidence(node, lines)  # type: ignore[arg-type]
        panel.show()
        QApplication.processEvents()
        painted = panel.grab().toImage()

        # Sampled through the viewport, which is the content area: measuring
        # from the widget's own edge lands on a header, a frame or a scrollbar
        # instead of on the ground being checked.
        for widget, what in ((panel._table, "table"), (panel._detail, "detail")):
            viewport = widget.viewport()
            assert viewport is not None
            inside = QPoint(viewport.width() // 2, viewport.height() - 4)
            point = viewport.mapTo(panel, inside)
            assert painted.pixelColor(point).name() == _PAPER, f"the {what} lost its ground"
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


def test_the_detail_changes_when_a_different_activity_is_opened(
    qt_app: QApplication, campaign: Path
) -> None:
    """Clicking a second activity left the first one's request in the detail.

    `show_evidence` fills the table and then calls `select_row(0)`, and relied on
    `itemSelectionChanged` to carry that into the detail pane. Qt only emits
    that when the selection actually *changes* — and row 0 of the outgoing
    activity is row 0 of the incoming one, so on a panel that already had a row
    selected, nothing changed and nothing was emitted. The rows were the new
    activity's; the request printed beneath them was the old one's.

    Worst on a single-request activity, which is where it was found: with one
    row there is no other row to click, so the pane cannot be corrected and
    simply describes the wrong request for as long as it is open.
    """
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
        nodes = [node for node in result.trace.nodes if node.evidence]
        assert len(nodes) >= 2, "the fixture needs two activities to switch between"
        first, second = nodes[0], nodes[-1]
        first_lines = case.read_evidence(first.evidence)
        second_lines = case.read_evidence(second.evidence)

    panel = EvidencePanel()
    panel.show_evidence(first, first_lines)
    assert str(first_lines[0].ref) in panel._detail.toPlainText()

    panel.show_evidence(second, second_lines)

    detail = panel._detail.toPlainText()
    assert str(second_lines[0].ref) in detail, "the detail still describes the old activity"
    assert str(first_lines[0].ref) not in detail


def test_every_outcome_sample_actually_draws_something(qt_app: QApplication) -> None:
    """`Success` and `Mixed` were blank chips in the key.

    Their outline is the window's own darkest colour — right against a bright
    node, invisible against bare chrome — and the sample was a bordered box on
    the panel, so the border and the ground behind it were the same colour. The
    canvas was fine; only the thing explaining the canvas was wrong.

    Then it was a dark ring on a pale fill — honest, and still unreadable:
    twenty pixels of disc against two of edge, so all four read as a pale dot
    and the styles could only be told apart by magnifying the window. Which is
    how it survived a second round: it was checked at four times size.

    So the check is not "is it the right colour" — it was the right colour every
    time. It is whether enough of the sample stands out from the panel it sits
    on. `3:1` is WCAG's floor for a graphical object, and twelve pixels is about
    a fifth of the thinnest ring any outcome draws.
    """
    from PyQt6.QtWidgets import QLabel

    from logarc.gui.panels import LegendBar
    from logarc.gui.style import THEME, outcome_legend

    bar = LegendBar()
    samples = [
        label
        for label in bar.findChildren(QLabel)
        if label.pixmap() is not None and not label.pixmap().isNull()
    ]
    assert len(samples) == len(outcome_legend()), "one painted sample per outcome"

    for sample in samples:
        image = sample.pixmap().toImage()
        painted = [
            (x, y)
            for x in range(image.width())
            for y in range(image.height())
            if image.pixelColor(x, y).alpha() > 200
        ]
        legible = [
            point
            for point in painted
            if contrast(image.pixelColor(*point).name(), THEME.chrome) >= 3.0
        ]
        assert len(legible) >= 12, "the sample does not stand out from the panel"
        # And it is a ring, not a disc. This is the structural half of the fix:
        # a filled sample is read as its fill, and the outline — the only part
        # that differs between the four — becomes a detail on a boundary that
        # already has a hard edge. Mostly-empty is what makes the line the
        # subject.
        assert len(painted) * 2 < image.width() * image.height(), "the sample is filled in"


def test_clicking_an_activity_leaves_only_the_ring_behind(
    qt_app: QApplication, campaign: Path
) -> None:
    """One mark per selection, and it is the canvas's own.

    `_NodeItem` used to carry `ItemIsSelectable`, which nothing ever read: a
    click is taken off `itemAt` and answered with `node_selected`, and the
    activity being read is marked by `highlight`. What the flag did do was let
    Qt paint its own dashed rectangle around the item it considered selected —
    so the first click on an activity boxed it, and the box disappeared on the
    next click elsewhere. Two marks for one selection, and the spare one looks
    like the renderer going wrong.
    """
    from PyQt6.QtCore import Qt as QtNS
    from PyQt6.QtTest import QTest

    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
    canvas = ActivityCanvas()
    canvas.resize(600, 400)
    canvas.show_graph(result.trace)
    canvas.fit()

    target = result.trace.nodes[0]
    item = canvas._nodes[target.node_id]
    QTest.mouseClick(
        canvas.viewport(),
        QtNS.MouseButton.LeftButton,
        pos=canvas.mapFromScene(item.scenePos()),
    )

    assert canvas.graph_scene.selectedItems() == [], "Qt is marking the node as well"
    canvas.close()


# -- picking up a case that has been opened before ---------------------------


def test_opening_a_case_puts_it_at_the_top_of_the_list(
    qt_app: QApplication, campaign: Path
) -> None:
    """The whole point: yesterday's case is one click away rather than a folder
    to go looking for."""
    app._settings().clear()
    window = MainWindow()

    window._load_case(campaign)
    _settled(qt_app)

    remembered = window._recent_cases()
    assert remembered
    assert remembered[0].path == str(campaign)
    assert remembered[0].events > 0, "the snapshot is what the chooser draws from"
    window.close()


def test_a_case_that_will_not_open_is_not_remembered(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A list of cases that cannot be opened is worse than a short one: every
    entry in it is an invitation into the same failure.

    The failure path ends in a modal `QMessageBox`, which in a test with nobody
    to click it waits for ever — so the report is captured rather than shown.
    """
    app._settings().clear()
    reported: list[str] = []
    monkeypatch.setattr(
        MainWindow, "_report_error", lambda _self, message, _detail="": reported.append(message)
    )
    window = MainWindow()
    not_a_case = tmp_path / "just-a-folder"
    not_a_case.mkdir()

    window._load_case(not_a_case)
    _settled(qt_app)

    assert reported, "opening a folder that is not a case has to say so"
    assert window._recent_cases() == ()
    window.close()


def test_the_reopen_choice_outlives_the_window(qt_app: QApplication) -> None:
    app._settings().clear()
    first = MainWindow()
    assert not first._reopen_action.isChecked(), (
        "the chooser is what a launch opens on; reopening the last case is opt-in"
    )

    first._reopen_action.trigger()
    first.close()
    second = MainWindow()

    assert second._reopen_action.isChecked()
    second.close()


def test_a_launch_opens_on_the_chooser_rather_than_the_last_case(
    qt_app: QApplication, campaign: Path
) -> None:
    """What the chooser was picked for. Reopening the last case straight away
    is useful, and it is also a way to never see the list that was the point of
    building it — so it is offered, not assumed."""
    from logarc.gui.recent import RecentCase, Startup, now, startup_action

    entry = RecentCase(str(campaign), "case", now(), 10, ("access.log",))

    action, _ = startup_action((entry,), reopen_last=False, exists=lambda _p: True)

    assert action is Startup.CHOOSE


def test_forgetting_the_list_leaves_nothing_on_the_machine(
    qt_app: QApplication, campaign: Path
) -> None:
    """This tool records which investigations were opened here. One action has
    to take that back, and it has to reach the store rather than only the
    dialog that offered it."""
    app._settings().clear()
    window = MainWindow()
    window._load_case(campaign)
    _settled(qt_app)
    assert window._recent_cases()

    window._forget_recent()

    assert window._recent_cases() == ()
    assert MainWindow()._recent_cases() == (), "and it is gone for the next window too"
    window.close()


def test_a_pin_survives_closing_the_chooser_without_opening_anything(
    qt_app: QApplication, campaign: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tidying the list is a thing you do on its own. A pin that only stuck when
    a case happened to be opened afterwards would look like it had not worked."""
    from logarc.gui import app as app_module
    from logarc.gui import recent
    from logarc.gui.case_chooser import CaseChooser

    app._settings().clear()
    window = MainWindow()
    window._load_case(campaign)
    _settled(qt_app)
    assert window._recent_cases()

    def pin_then_close(self: CaseChooser) -> int:
        self._amend(recent.set_pinned(self.cases, str(campaign), pinned=True))
        return 0

    monkeypatch.setattr(app_module.CaseChooser, "exec", pin_then_close)
    window._show_recent()

    remembered = window._recent_cases()
    assert remembered[0].pinned
    assert MainWindow()._recent_cases()[0].pinned, "and the next window sees it too"
    window.close()


def test_forgetting_every_case_removes_the_key_rather_than_emptying_it(
    qt_app: QApplication, campaign: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`Forget these` is the privacy control the README leans on: the list
    "records which cases were opened here", and the button takes that back.

    It used to say so through a flag the window read as "wipe everything". Now
    it removes what is highlighted, so wiping the list is Ctrl+A and the same
    button — and the window has to notice that an emptied list means the key
    goes, not that an empty value gets stored in it. Storing one would satisfy
    every visible symptom and leave the record on the machine.
    """
    from logarc.gui import app as app_module
    from logarc.gui.case_chooser import CaseChooser

    app._settings().clear()
    window = MainWindow()
    window._load_case(campaign)
    _settled(qt_app)
    assert window._recent_cases(), "premise: something was recorded"
    assert app._settings().contains(app._RECENT_KEY), "premise: it reached the key"

    def select_all_and_forget(self: CaseChooser) -> int:
        self._table.selectAll()
        self._forget()
        assert self.cases == (), "premise: the chooser emptied itself"
        return 0

    monkeypatch.setattr(app_module.CaseChooser, "exec", select_all_and_forget)
    window._show_recent()

    assert not app._settings().contains(app._RECENT_KEY), (
        "an emptied list has to remove the key, not store an empty one"
    )
    assert not MainWindow()._recent_cases(), "and the next window sees nothing"
    window.close()


def test_forgetting_some_cases_keeps_the_rest_on_the_machine(
    qt_app: QApplication, campaign: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half: a partial removal is stored, not treated as a wipe."""
    from logarc.gui import app as app_module
    from logarc.gui import recent
    from logarc.gui.case_chooser import CaseChooser

    app._settings().clear()
    window = MainWindow()
    window._load_case(campaign)
    _settled(qt_app)

    kept = recent.RecentCase(
        path="D:/cases/kept",
        case_id="kept",
        opened_at=recent.now(),
        events=99,
        sources=("access.log",),
    )
    app._settings().setValue(
        app._RECENT_KEY, recent.dump(recent.remember(window._recent_cases(), kept))
    )
    assert len(MainWindow()._recent_cases()) == 2, "premise: two are recorded"

    def forget_the_first(self: CaseChooser) -> int:
        self._table.selectRow(0)
        self._forget()
        return 0

    monkeypatch.setattr(app_module.CaseChooser, "exec", forget_the_first)
    window._show_recent()

    remaining = MainWindow()._recent_cases()
    assert len(remaining) == 1
    assert app._settings().contains(app._RECENT_KEY)
    window.close()


# -- the strip that reports a case's unparsed lines ------------------------


def _one_source(name: str, *, read: int, quarantined: int) -> SourceRecord:
    return SourceRecord(
        file_id=name,
        original_path=f"/logs/{name}",
        sha256="0" * 64,
        size_bytes=read * 200,
        compression="none",
        log_format="apache-combined",
        lines_read=read,
        events_parsed=read - quarantined,
        lines_quarantined=quarantined,
    )


def test_a_clean_case_gets_no_banner(qt_app: QApplication) -> None:
    """Silence means the case holds everything its logs did."""
    banner = QuarantineBanner()
    banner.show_notice(notice_for([_one_source("a.log", read=1_000, quarantined=0)]))

    assert not banner.isVisible()


def test_a_damaged_case_gets_a_banner_that_names_the_count(qt_app: QApplication) -> None:
    banner = QuarantineBanner()
    banner.show_notice(notice_for([_one_source("a.log", read=51_268, quarantined=3_412)]))
    banner.show()

    assert banner.isVisible()
    assert "3,412" in banner.text()


def test_the_banner_can_be_dismissed(qt_app: QApplication) -> None:
    """It takes real estate in a window that needs it, so it has to close.

    Dismissal lasts until the case is opened again — the count is read from the
    manifest every time, so nothing has to remember the choice, and a case that
    is still incomplete says so again the next time it is looked at.
    """
    banner = QuarantineBanner()
    banner.show_notice(notice_for([_one_source("a.log", read=900, quarantined=12)]))
    banner.show()
    assert banner.isVisible(), "premise: the strip was up before it was dismissed"

    banner.dismiss()

    assert not banner.isVisible()


def test_a_second_case_replaces_what_the_banner_said(qt_app: QApplication) -> None:
    """The failure this guards: show a damaged case, then a clean one, and a
    strip that only ever learned to appear goes on reporting the first case's
    damage over the second case's evidence."""
    banner = QuarantineBanner()
    banner.show_notice(notice_for([_one_source("a.log", read=51_268, quarantined=3_412)]))
    banner.show()
    assert banner.isVisible(), "premise: the first case put the strip up"

    banner.show_notice(notice_for([_one_source("b.log", read=2_000, quarantined=0)]))

    assert not banner.isVisible()


def test_the_banner_shows_one_sentence_not_the_whole_paragraph(
    qt_app: QApplication,
) -> None:
    """The dead-file wording runs to a paragraph, because the dialog has room
    for it. A strip that took all of it would be five lines tall and take a
    third of the window; it takes the first sentence and leaves the rest to the
    dialog raised beside it."""
    notice = notice_for([_one_source("system.log", read=11_268, quarantined=11_268)])
    assert notice is not None
    assert "\n\n" in notice.detail, "premise: the dead-file detail is a paragraph"

    banner = QuarantineBanner()
    banner.show_notice(notice)

    assert "logarc formats" not in banner.text()
    assert "not one of its 11,268 lines parsed" in banner.text()


def test_every_ink_on_the_banner_can_be_read_against_its_ground(
    qt_app: QApplication,
) -> None:
    """An amber strip is worth nothing if the words on it are not legible.

    All four inks the strip actually paints, not just the headline: the caption
    beneath it carries the numbers, and the dismiss control has to be findable.
    """
    for ink in (THEME.ink, THEME.muted, THEME.faint, THEME.severity[Severity.MEDIUM]):
        assert contrast(ink, NOTICE_TINT) >= 4.5, f"{ink} on {NOTICE_TINT}"


def test_opening_a_case_reports_its_unparsed_lines(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the whole feature: the count reaches the window from the
    manifest, on open, without anyone having watched the ingest happen.

    That is the case a colleague opens a week later, and until now it drew
    exactly like a case that had lost nothing.
    """
    good = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'
    )
    log = tmp_path / "access.log"
    # Six good lines so the format can be detected, one that cannot parse.
    log.write_text("\n".join([good] * 6 + ["this is not a log line"]) + "\n", encoding="utf-8")

    case_dir = tmp_path / "case"
    with Case.create(case_dir) as case:
        case.ingest([log])

    # Premise: the manifest really did record the damage. Without this the test
    # could pass by the strip staying hidden for entirely the wrong reason.
    assert CaseManifest.load(case_dir).total_lines_quarantined == 1

    # Substituted so this test can never hang. `QMessageBox.exec` blocks, so a
    # regression that raised the dialog on an ordinary damaged case would stop
    # the suite dead rather than fail it — and a hung suite reports nothing.
    raised: list[str] = []
    monkeypatch.setattr(
        app, "warn_about_dead_files", lambda _parent, notice: raised.append(notice.headline)
    )

    window = MainWindow()
    window.show()
    window._load_case(case_dir)
    _settled(qt_app)

    assert window._notice.isVisible()
    assert "1 line could not be parsed" in window._notice.text()
    assert raised == [], "damage inside a log is a strip, never an interruption"
    window.close()


def test_opening_a_clean_case_leaves_the_window_quiet(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half, and the one that decides whether the strip means
    anything: a case with nothing quarantined must not show it."""
    good = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'
    )
    log = tmp_path / "clean.log"
    log.write_text("\n".join([good] * 6) + "\n", encoding="utf-8")

    case_dir = tmp_path / "case"
    with Case.create(case_dir) as case:
        case.ingest([log])

    assert CaseManifest.load(case_dir).total_lines_quarantined == 0, "premise: nothing failed"

    # Substituted so this test can never hang. `QMessageBox.exec` blocks, so a
    # regression that raised the dialog on an ordinary damaged case would stop
    # the suite dead rather than fail it — and a hung suite reports nothing.
    raised: list[str] = []
    monkeypatch.setattr(
        app, "warn_about_dead_files", lambda _parent, notice: raised.append(notice.headline)
    )

    window = MainWindow()
    window.show()
    window._load_case(case_dir)
    _settled(qt_app)

    assert not window._notice.isVisible()
    assert raised == []
    window.close()


GOOD_LINE = (
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'
)


def _case_with_a_dead_log(tmp_path: Path) -> Path:
    """A case where one log produced events and the other produced none.

    How a dead file actually arises: an explicit `--format` skips detection, so
    a log that is not that format is not refused up front — every one of its
    lines is quarantined instead, and the case is left holding half of what was
    handed to it. Detection would have caught this file on its own; naming a
    format is precisely what turns the refusal into silence.
    """
    apache = tmp_path / "access.log"
    apache.write_text("\n".join([GOOD_LINE] * 8) + "\n", encoding="utf-8")
    syslog = tmp_path / "system.log"
    syslog.write_text(
        "\n".join(["<134>Oct 10 13:55:36 web01 httpd: request served"] * 8) + "\n",
        encoding="utf-8",
    )

    case_dir = tmp_path / "case"
    with Case.create(case_dir) as case:
        case.ingest([apache, syslog], log_format="apache-combined")
    return case_dir


def test_a_log_that_produced_nothing_interrupts(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A strip is not enough for this one. With no events from a whole log the
    window behind shows a short client list — which is exactly what a quiet day
    of traffic looks like, so nothing on screen separates a working case from a
    broken ingest.

    The dialog is substituted rather than shown: `QMessageBox.exec` blocks, and
    a test that opens a real modal hangs until the suite is killed. What is
    being checked here is the wiring — that the window raises it, and for the
    right case.
    """
    case_dir = _case_with_a_dead_log(tmp_path)
    manifest = CaseManifest.load(case_dir)
    # Premise, and the whole reason the rule is per file: this case is only
    # half damaged, so a case-level test of "every line failed" stays silent
    # while a whole log contributes nothing.
    lines_read = sum(source.lines_read for source in manifest.sources)
    assert 0 < manifest.total_lines_quarantined < lines_read
    assert any(source.events_parsed == 0 for source in manifest.sources)

    raised: list[str] = []
    monkeypatch.setattr(
        app, "warn_about_dead_files", lambda _parent, notice: raised.append(notice.headline)
    )

    window = MainWindow()
    window.show()
    window._load_case(case_dir)
    _settled(qt_app)

    assert raised == ["system.log could not be read"]
    # And the strip is up behind it, so the case still says so once the dialog
    # has been dismissed.
    assert window._notice.isVisible()
    window.close()


def test_a_merely_damaged_case_does_not_interrupt(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The escalation has to have a floor, or every damaged case becomes a
    modal and the modal stops meaning anything."""
    log = tmp_path / "access.log"
    log.write_text("\n".join([GOOD_LINE] * 6 + ["this is not a log line"]) + "\n", encoding="utf-8")
    case_dir = tmp_path / "case"
    with Case.create(case_dir) as case:
        case.ingest([log])

    raised: list[str] = []
    monkeypatch.setattr(
        app, "warn_about_dead_files", lambda _parent, notice: raised.append(notice.headline)
    )

    window = MainWindow()
    window.show()
    window._load_case(case_dir)
    _settled(qt_app)

    assert raised == [], "a damaged log is a strip, not an interruption"
    assert window._notice.isVisible(), "premise: the strip still reported the damage"
    window.close()


def test_a_dismissed_strip_returns_when_the_case_is_opened_again(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The property the whole feature rests on, and the reason the count is read
    from the manifest rather than remembered from the ingest.

    Dismissal is for the reading you are in, not for the case. An investigator
    who closes the strip, works on something else and comes back has to be told
    again — otherwise the second reading of an incomplete case looks exactly
    like a complete one, which is the fault this was built to remove.

    Written after handing this to a person as a manual step. It is about what
    the window does, not about what a person perceives, so it belongs here.
    """
    good = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'
    )

    damaged_log = tmp_path / "damaged.log"
    damaged_log.write_text(
        "\n".join([good] * 6 + ["this is not a log line"]) + "\n", encoding="utf-8"
    )
    damaged = tmp_path / "damaged-case"
    with Case.create(damaged) as case:
        case.ingest([damaged_log])

    clean_log = tmp_path / "clean.log"
    clean_log.write_text("\n".join([good] * 6) + "\n", encoding="utf-8")
    clean = tmp_path / "clean-case"
    with Case.create(clean) as case:
        case.ingest([clean_log])

    raised: list[str] = []
    monkeypatch.setattr(
        app, "warn_about_dead_files", lambda _parent, notice: raised.append(notice.headline)
    )

    window = MainWindow()
    window.show()

    window._load_case(damaged)
    _settled(qt_app)
    assert window._notice.isVisible(), "premise: the damaged case put the strip up"

    window._notice.dismiss()
    assert not window._notice.isVisible(), "premise: dismissing hid it"

    # Somewhere else entirely, and that case is clean — so the strip staying
    # down here proves nothing on its own.
    window._load_case(clean)
    _settled(qt_app)
    assert not window._notice.isVisible()

    window._load_case(damaged)
    _settled(qt_app)

    assert window._notice.isVisible(), (
        "a dismissed strip must come back: the case is still incomplete, and the "
        "next reader did not watch the ingest"
    )
    assert "1 line could not be parsed" in window._notice.text()
    assert raised == []
    window.close()


# -- the card that reports a long ingest -----------------------------------


def _reading(**over: object) -> Progress:
    fields: dict[str, object] = {
        "file_name": "access.log",
        "file_index": 1,
        "file_count": 1,
        "lines": 1_482_119,
        "bytes_done": 1_432_000_000,
        "bytes_total": 2_310_000_000,
        "seconds": 30.0,
    }
    fields.update(over)
    return Progress(**fields)  # type: ignore[arg-type]


def test_the_card_shows_the_figures_it_is_given(qt_app: QApplication) -> None:
    card = IngestCard(None, on_cancel=lambda: None)
    card.update_progress(_reading(file_index=2, file_count=3))

    said = card.text()
    # The readout names the log on its own row and puts which-of-how-many in
    # the head, rather than folding both into one heading.
    assert "access.log" in said
    assert "2/3" in said
    assert "62%" in said
    assert "1,482,119" in said
    assert "about" in said, "thirty seconds in, the estimate is worth showing"
    # The bar agrees with the number printed beside it. An `or` here would let
    # the printed text carry the whole assertion and never test the bar at all.
    assert card._bar.maximum() > 0, "a measurable read draws a position"
    assert abs(card._bar.value() / card._bar.maximum() - 0.62) < 0.005
    card.close()


def test_the_card_invents_no_estimate_the_seam_withheld(qt_app: QApplication) -> None:
    """Half a second in, `Progress.remaining` is None on purpose. The card has
    to leave the gap rather than fill it — putting a number back here is exactly
    what the guard exists to prevent."""
    card = IngestCard(None, on_cancel=lambda: None)
    card.update_progress(_reading(lines=900, bytes_done=1_000, seconds=0.5))

    assert "about" not in card.text()
    card.close()


def test_a_log_of_unknown_size_leaves_the_bar_moving(qt_app: QApplication) -> None:
    """No position to draw, so the bar goes back to the indeterminate kind.
    Sitting at zero would read as an ingest that had stalled."""
    card = IngestCard(None, on_cancel=lambda: None)
    card.update_progress(_reading(bytes_done=0, bytes_total=0, lines=50, seconds=1.0))

    assert card._bar.maximum() == 0, "range (0, 0) is Qt's moving bar"
    assert "%" not in card.text()
    card.close()


def test_the_card_stops_claiming_a_position_when_the_size_becomes_unknown(
    qt_app: QApplication,
) -> None:
    """A measurable file followed by an unmeasurable one. A card that only ever
    learned to set a value would leave the last file's percentage standing over
    the next one's read."""
    card = IngestCard(None, on_cancel=lambda: None)
    card.update_progress(_reading())
    assert "62%" in card.text(), "premise: it had a position to show"

    card.update_progress(_reading(bytes_done=0, bytes_total=0))

    assert card._bar.maximum() == 0
    assert "62%" not in card.text()
    card.close()


def test_cancelling_says_it_is_waiting(qt_app: QApplication) -> None:
    """The read runs to the end of the batch in flight, which can take seconds.
    A card that changed nothing would read as a button that did nothing."""
    asked: list[bool] = []
    card = IngestCard(None, on_cancel=lambda: asked.append(True))

    card._cancel.click()

    assert asked == [True]
    assert not card._cancel.isEnabled(), "asking a second time cannot help"
    assert "STOPPING" in card.text(), "the state in the head has to change"
    card.close()


def test_the_card_names_the_cost_of_cancelling(qt_app: QApplication) -> None:
    """Cancelling is not free — the case is left un-finalised and cannot be
    analysed. That belongs beside the button, not in the documentation."""
    card = IngestCard(None, on_cancel=lambda: None)

    # On the face, not in a tooltip. A tooltip is shown only if somebody rests
    # the pointer on the control, and this sentence exists to be read *before*
    # that control is pressed.
    assert "un-finalised" in card._consequence.text()
    assert card._consequence.isVisibleTo(card)
    card.close()


def test_a_real_ingest_reports_progress_that_only_goes_forwards(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: real files, the real pipeline, real signals.

    A small log followed by a large one on purpose. That is the pair the first
    design got wrong — it inferred the file boundary from the byte count
    falling, and the whole of a tiny log reports fewer bytes than the first
    batch of a big one, so the boundary never showed up as a fall and the
    counts silently restarted.
    """
    from logarc.gui import app as app_module

    good = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'
    )
    small = tmp_path / "small.log"
    small.write_text("\n".join([good] * 30) + "\n", encoding="utf-8")
    large = tmp_path / "large.log"
    large.write_text("\n".join([good] * 120_000) + "\n", encoding="utf-8")
    case_dir = tmp_path / "case"

    monkeypatch.setattr(
        app_module.QFileDialog,
        "getOpenFileNames",
        lambda *_a, **_k: ([str(small), str(large)], ""),
    )
    monkeypatch.setattr(
        app_module.QFileDialog, "getExistingDirectory", lambda *_a, **_k: str(case_dir)
    )

    seen: list[Progress] = []
    window = MainWindow()
    original = window._show_ingest_progress

    def watch(snapshot: object) -> None:
        if isinstance(snapshot, Progress):
            seen.append(snapshot)
        original(snapshot)

    monkeypatch.setattr(window, "_show_ingest_progress", watch)

    window._ingest_new_case()
    _settled(qt_app)

    assert seen, "no progress was reported at all"
    lines = [item.lines for item in seen]
    assert lines == sorted(lines), f"the count went backwards: {lines[:12]}"
    assert seen[-1].lines >= 120_030, "the last report is short of what was read"
    assert {item.file_count for item in seen} == {2}
    assert {item.file_name for item in seen} == {"small.log", "large.log"}
    # Every snapshot is a whole-ingest figure, so none may exceed the whole.
    assert all(item.bytes_done <= item.bytes_total for item in seen)
    assert window._ingest_card is None, "the card has to go when the read ends"
    window.close()


def test_a_failed_ingest_takes_the_card_down_with_it(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A card left standing after a failure says the read is still going while
    nothing is running — worse than never having shown one."""
    from logarc.gui import app as app_module

    missing = tmp_path / "not-a-log.log"
    missing.write_text("nothing here parses as a log line\n" * 20, encoding="utf-8")
    case_dir = tmp_path / "case"

    monkeypatch.setattr(
        app_module.QFileDialog, "getOpenFileNames", lambda *_a, **_k: ([str(missing)], "")
    )
    monkeypatch.setattr(
        app_module.QFileDialog, "getExistingDirectory", lambda *_a, **_k: str(case_dir)
    )
    monkeypatch.setattr(MainWindow, "_report_error", lambda *_a, **_k: None)

    window = MainWindow()
    window._ingest_new_case()
    _settled(qt_app)

    assert window._ingest_card is None
    window.close()


# -- filling the client table a second time --------------------------------


def _client_summaries(count: int) -> list[IpSummary]:
    return [
        IpSummary(
            client_ip=f"203.0.113.{index % 250}",
            request_count=1_000 - index,
            first_seen=START,
            last_seen=START + timedelta(minutes=index),
            distinct_paths=index % 90,
            client_error_ratio=(index % 100) / 100,
            bytes_total=2_326 * index,
        )
        for index in range(count)
    ]


def test_showing_clients_again_is_not_hundreds_of_times_slower(
    qt_app: QApplication,
) -> None:
    """Opening a case that is already open froze the window for over a minute.

    The window was reloading it — which it should not — but reloading was never
    supposed to be expensive, and it was: `show_clients` took 63.99s of a 65.56s
    reopen, filling the same 500 rows it had filled in a fraction of a second
    the first time.

    The header sizes every column to its contents, and that mode re-measures the
    whole column on each cell that changes. Into an empty table Qt takes a fast
    path; replacing 3,000 cells that already exist it does not, and the cost goes
    quadratic. Measured at 0.20s for the first fill and 66.54s for the second.

    So this is about the second fill, not the first. The bound is deliberately
    loose — the gap being guarded is roughly three hundred-fold, and a slow
    machine moving 0.1s to 1s must not turn the suite red.
    """
    summaries = _client_summaries(500)
    table = ClientTable()
    table.resize(440, 800)
    table.show()
    qt_app.processEvents()

    table.show_clients(summaries)
    qt_app.processEvents()

    started = time.perf_counter()
    table.show_clients(summaries)
    qt_app.processEvents()
    again = time.perf_counter() - started

    assert again < 5.0, f"refilling the client table took {again:.1f}s"
    table.close()


def test_the_columns_are_still_sized_to_what_they_hold(qt_app: QApplication) -> None:
    """The reason the header sizes itself: with default widths three of the six
    columns hid behind a scrollbar, including the 4xx ratio the table is sorted
    by. Speeding the fill up must not give that back.

    Asserted against the width of the text, not against a total. The first
    version of this test compared the sum of the widths to the panel width, and
    it passed with the address column at 70px where it needs 162 — a sum can
    stay respectable while one column is squeezed and another balloons, which
    is exactly what happens here, because the last section stretches. Measured:
    correct gives [162, 66, 76, 54, 150, 100]; leaving the header in its
    fast-fill mode gives [70, 48, 59, 37, 59, 272].
    """
    summaries = _client_summaries(500)
    table = ClientTable()
    table.resize(440, 800)
    table.show()
    table.show_clients(summaries)
    qt_app.processEvents()

    widest_address = max((summary.client_ip for summary in summaries), key=len)
    metrics = QFontMetrics(table._table.font())
    needed = metrics.horizontalAdvance(widest_address)

    assert table._table.columnWidth(0) >= needed, (
        f"the address column is {table._table.columnWidth(0)}px for "
        f"{widest_address!r}, which needs {needed}px"
    )
    # And the timestamps, which are the other pair that hid.
    for column in (4, 5):
        assert table._table.columnWidth(column) >= 90, (
            f"column {column} is {table._table.columnWidth(column)}px, too narrow for a date"
        )
    table.close()


def test_choosing_the_case_already_open_does_not_read_it_again(
    qt_app: QApplication, campaign: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Picking the open case from the recent list re-read the whole thing.

    A finalised case cannot change, so the second read produces byte-for-byte
    what the first did. All it costs is time and the loss of whatever was on
    screen — the reconstruction being read is thrown away and the canvas goes
    back to inviting a client to be picked.
    """
    from logarc.gui import app as app_module
    from logarc.gui.case_chooser import CaseChooser

    app._settings().clear()
    window = MainWindow()
    window._load_case(campaign)
    _settled(qt_app)
    assert window._case_path == campaign, "premise: the case is open"

    reads: list[Path] = []
    original = app_module.read_case
    monkeypatch.setattr(app_module, "read_case", lambda path: reads.append(path) or original(path))

    def pick_the_open_one(self: CaseChooser) -> int:
        self.chosen_path = str(campaign)
        return 1

    monkeypatch.setattr(app_module.CaseChooser, "exec", pick_the_open_one)
    window._show_recent()
    _settled(qt_app)

    assert reads == [], f"the open case was read again: {reads}"
    window.close()


def test_choosing_the_case_already_open_says_so(
    qt_app: QApplication, campaign: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Doing nothing quietly is indistinguishable from a control that is
    broken. It has to say why nothing happened — and `logarc enrich` can add
    CRS evidence to an open case from a terminal, so a reader who came here to
    pick that up needs to know they did not."""
    from logarc.gui import app as app_module
    from logarc.gui.case_chooser import CaseChooser

    app._settings().clear()
    window = MainWindow()
    window._load_case(campaign)
    _settled(qt_app)

    def pick_the_open_one(self: CaseChooser) -> int:
        self.chosen_path = str(campaign)
        return 1

    monkeypatch.setattr(app_module.CaseChooser, "exec", pick_the_open_one)
    window._show_recent()
    _settled(qt_app)

    assert "already open" in window._status.text().lower(), window._status.text()
    window.close()


def test_choosing_a_different_case_still_reads_it(
    qt_app: QApplication, campaign: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard must not be a blanket refusal to load anything twice."""
    from logarc.gui import app as app_module
    from logarc.gui.case_chooser import CaseChooser

    good = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'
    )
    other_log = tmp_path / "other.log"
    other_log.write_text(NEWLINE.join([good] * 6) + NEWLINE, encoding="utf-8")
    other = tmp_path / "other-case"
    with Case.create(other) as case:
        case.ingest([other_log])

    app._settings().clear()
    window = MainWindow()
    window._load_case(campaign)
    _settled(qt_app)

    reads: list[Path] = []
    original = app_module.read_case
    monkeypatch.setattr(app_module, "read_case", lambda path: reads.append(path) or original(path))

    def pick_the_other(self: CaseChooser) -> int:
        self.chosen_path = str(other)
        return 1

    monkeypatch.setattr(app_module.CaseChooser, "exec", pick_the_other)
    window._show_recent()
    _settled(qt_app)

    assert reads == [other]
    assert window._case_path == other
    window.close()


# -- keeping an arrangement -----------------------------------------------


def _nudged(window: MainWindow) -> str:
    """Drag the first activity on the canvas, and say which one it was."""
    node_id = next(iter(window._canvas._nodes))
    drag(window._canvas, node_id, QPoint(70, -40))
    return node_id


def _where(window: MainWindow, node_id: str) -> tuple[float, float]:
    item = window._canvas._nodes[node_id]
    return (item.pos().x(), item.pos().y())


def test_the_arrangement_entries_are_dead_before_a_graph_is_drawn(
    qt_app: QApplication,
) -> None:
    """A live control that does nothing reads as a fault in the tool."""
    window = MainWindow()

    assert not window._undo_action.isEnabled()
    assert not window._save_layout_action.isEnabled()
    assert not window._reset_layout_action.isEnabled()
    window.close()


def test_saving_and_resetting_come_alive_with_the_graph(
    qt_app: QApplication, campaign: Path
) -> None:
    window = _reconstructed(qt_app, campaign)

    assert window._save_layout_action.isEnabled()
    assert window._reset_layout_action.isEnabled()
    assert not window._undo_action.isEnabled(), "nothing has been moved yet"
    window.close()


def test_undo_comes_alive_once_something_has_been_moved(
    qt_app: QApplication, campaign: Path
) -> None:
    window = _reconstructed(qt_app, campaign)

    _nudged(window)

    assert window._undo_action.isEnabled()
    window._undo_action.trigger()
    assert not window._undo_action.isEnabled(), "and goes back out when the stack empties"
    window.close()


def test_a_saved_arrangement_comes_back_on_the_next_open(
    qt_app: QApplication, campaign: Path, settings_in_a_temp_file: Path
) -> None:
    """Checked by opening a second window rather than by reading the setting
    back: an arrangement that is stored and never applied is the failure worth
    catching, and reading the file would not catch it."""
    app._settings().clear()
    first = _reconstructed(qt_app, campaign)
    moved = _nudged(first)
    placed = _where(first, moved)
    first._save_layout_action.trigger()
    first.close()

    second = _reconstructed(qt_app, campaign)

    assert _where(second, moved) == placed
    # The file is checked too, and for a different reason — that the window is
    # still writing through the seam these tests substitute. Inline a
    # `QSettings` at either call site and this file stays empty while every
    # arrangement quietly goes to the real registry of whoever ran the suite,
    # with the test above passing all the way through.
    assert "arrangements" in settings_in_a_temp_file.read_text(encoding="utf-8")
    second.close()


def test_an_arrangement_that_was_not_saved_does_not_come_back(
    qt_app: QApplication, campaign: Path, settings_in_a_temp_file: Path
) -> None:
    """Saving is a thing the reader does. Keeping every drag would make the
    canvas remember experiments they abandoned."""
    app._settings().clear()
    first = _reconstructed(qt_app, campaign)
    moved = _nudged(first)
    placed = _where(first, moved)
    first.close()

    second = _reconstructed(qt_app, campaign)

    assert _where(second, moved) != placed
    second.close()


def test_saving_on_the_behaviour_map_does_not_overwrite_the_trace(
    qt_app: QApplication, campaign: Path, settings_in_a_temp_file: Path
) -> None:
    """The two views file under different keys, and this is what that buys.

    Filed together, saving on the second view replaces what the first one saved.
    The nodes are named differently in each graph, so the trace would then find
    nothing of its own in the arrangement and quietly revert to the layout — the
    reader's work gone, with the save that destroyed it looking like a success.
    """
    app._settings().clear()
    window = _reconstructed(qt_app, campaign)
    moved = _nudged(window)
    placed = _where(window, moved)
    window._save_layout_action.trigger()

    window._show_behaviour()
    _settled(qt_app)
    _nudged(window)
    window._save_layout_action.trigger()
    window._show_trace()
    _settled(qt_app)

    assert _where(window, moved) == placed
    window.close()


def test_an_arrangement_saved_with_wrap_on_is_not_applied_with_it_off(
    qt_app: QApplication, campaign: Path, settings_in_a_temp_file: Path
) -> None:
    """A wrapped trace folds onto rows an unwrapped one does not have, so the
    saved coordinates put nodes where no row exists."""
    app._settings().clear()
    window = _reconstructed(qt_app, campaign)
    assert window._wrap_action.isChecked(), "premise: wrapping is on"
    moved = _nudged(window)
    placed = _where(window, moved)
    window._save_layout_action.trigger()

    window._wrap_action.trigger()
    _settled(qt_app)

    assert _where(window, moved) != placed
    window.close()


def test_a_saved_arrangement_survives_a_trip_through_the_other_view(
    qt_app: QApplication, campaign: Path, settings_in_a_temp_file: Path
) -> None:
    """Going to the behaviour map and back redraws the trace from the layout.
    Without the arrangement being reapplied, the reader's work is gone and
    nothing said so."""
    app._settings().clear()
    window = _reconstructed(qt_app, campaign)
    moved = _nudged(window)
    placed = _where(window, moved)
    window._save_layout_action.trigger()

    window._show_behaviour()
    _settled(qt_app)
    window._show_trace()
    _settled(qt_app)

    assert _where(window, moved) == placed
    window.close()


def test_reset_forgets_the_saved_arrangement_as_well(
    qt_app: QApplication, campaign: Path, settings_in_a_temp_file: Path
) -> None:
    """Otherwise there is no way to be rid of one: reset, reopen, and it is back,
    which reads as the reset having failed."""
    app._settings().clear()
    window = _reconstructed(qt_app, campaign)
    moved = _nudged(window)
    placed = _where(window, moved)
    window._save_layout_action.trigger()

    window._reset_layout_action.trigger()
    window._show_behaviour()
    _settled(qt_app)
    window._show_trace()
    _settled(qt_app)

    assert _where(window, moved) != placed
    window.close()


def test_reset_puts_the_nodes_back_where_the_layout_had_them(
    qt_app: QApplication, campaign: Path, settings_in_a_temp_file: Path
) -> None:
    app._settings().clear()
    window = _reconstructed(qt_app, campaign)
    home = dict(window._canvas.positions)
    _nudged(window)

    window._reset_layout_action.trigger()

    assert window._canvas.positions == home
    window.close()


def test_a_settings_value_nobody_can_read_still_opens_the_case(
    qt_app: QApplication, campaign: Path, settings_in_a_temp_file: Path
) -> None:
    """A view preference, not evidence. A window that will not open a case
    because of one is a far worse failure than a lost arrangement."""
    app._settings().clear()
    app._settings().setValue(app._LAYOUT_KEY, "{not json at all")

    window = _reconstructed(qt_app, campaign)

    assert window._canvas._nodes, "the graph is on the canvas"
    window.close()
