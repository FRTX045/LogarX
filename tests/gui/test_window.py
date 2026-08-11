"""Smoke tests for the window itself, run without a display.

The GUI is verified by hand against docs/manual-test-plan.md — a checklist
cannot be automated away. What *can* be automated is that it still constructs,
still draws a real reconstruction, and still survives a case with nothing in it.
Those are the failures that would otherwise be found by opening the app.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import QApplication

from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.core.graph import GraphKind
from logarc.detect.crs import CrsDetection, write_detections
from logarc.gui.app import MainWindow, read_case, reconstruct_client
from logarc.gui.canvas import MIN_FIT_SCALE, ActivityCanvas
from logarc.gui.panels import ClientTable, EvidencePanel
from logarc.storage.case import CaseManifest

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
CLIENT = "203.0.113.66"


@pytest.fixture(scope="module")
def qt_app() -> QApplication:
    return QApplication.instance() or QApplication([])


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


def test_the_evidence_panel_shows_the_raw_lines(qt_app: QApplication, campaign: Path) -> None:
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
        episode = result.episodes[0]
        lines = case.read_evidence(episode.evidence[:5])
    panel = EvidencePanel()

    panel.show_evidence(episode, lines)

    shown = panel._body.toPlainText()
    assert "access.log:" in shown
    assert CLIENT in shown


def test_the_evidence_panel_does_not_depend_on_the_system_theme(qt_app: QApplication) -> None:
    """The panel writes dark text. If it also inherits the window background, a
    machine themed dark renders the evidence dark-on-dark — the one panel an
    investigator cannot do without, invisible, with nothing to indicate why.

    Asserts the exact colour rather than "light enough". The offscreen platform
    this suite runs under always supplies a light default palette, so a
    brightness check would pass whether or not the panel set anything, and this
    fault would stay invisible to CI exactly as it is invisible on screen.
    """
    from logarc.gui.panels import _INK, _PAPER

    panel = EvidencePanel()
    palette = panel._body.palette()

    assert palette.color(QPalette.ColorRole.Base).name() == _PAPER
    assert palette.color(QPalette.ColorRole.Text).name() == _INK


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


def test_the_evidence_panel_opens_at_the_start_of_the_lines(
    qt_app: QApplication, campaign: Path
) -> None:
    """Appending leaves the view at the end of the last line written, which for
    a log line is the tail of a user agent. The investigator would be looking at
    "Safari/537.36" where the address and the request should be."""
    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
        episode = result.episodes[0]
        lines = case.read_evidence(episode.evidence[:5])
    panel = EvidencePanel()

    panel.show_evidence(episode, lines)

    assert panel._body.textCursor().position() == 0
    assert panel._body.horizontalScrollBar().value() == 0


def test_the_evidence_panel_reports_an_unreadable_source(
    qt_app: QApplication, campaign: Path
) -> None:
    """A case outlives its logs; the panel must say so rather than look empty."""
    from logarc.core.evidence import EvidenceRef
    from logarc.evidence import EvidenceLine

    with Case.open(campaign) as case:
        result = analyse_ip(case.store, CLIENT)
    panel = EvidencePanel()
    missing = [
        EvidenceLine(
            ref=EvidenceRef("access.log", 1),
            source_path="gone.log",
            note="cannot open log file gone.log",
        )
    ]

    panel.show_evidence(result.episodes[0], missing)

    assert "unavailable" in panel._body.toPlainText()


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
