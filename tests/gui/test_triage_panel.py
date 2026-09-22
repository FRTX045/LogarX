from datetime import UTC, datetime, timedelta

from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QTabWidget

from conftest import settled
from logarc.case import Case
from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.core.window import TimeWindow
from logarc.gui.app import MainWindow
from logarc.triage.scan import scan_case


def make_case(tmp_path, count=1):
    with Case.create(tmp_path / "case") as case:
        case.store.write(
            [
                NormalizedEvent(
                    datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=i),
                    f"192.0.2.{i}",
                    EvidenceRef("source", i + 1),
                    path="/etc/passwd",
                    method="GET",
                    status=200,
                    user_agent="Mozilla/5.0",
                )
                for i in range(count)
            ]
        )
        case.store.finalize()
    return case.root


def test_panel_pages_and_searches_all_clients(qt_app, tmp_path):
    from logarc.gui.triage import TriagePanel

    result = scan_case(make_case(tmp_path, 105))
    panel = TriagePanel()
    panel.show_result(result)
    settled(qt_app)
    assert panel.table.rowCount() == 100
    expected_rank = next(
        panel.table.item(index, 0).text()
        for index in range(panel.table.rowCount())
        if panel.table.item(index, 1).text() == "192.0.2.104"
    )
    assert panel.next_page.isEnabled()
    panel.next_page.click()
    settled(qt_app)
    assert panel.table.rowCount() == 5
    panel.search.setText("192.0.2.104")
    QTest.qWait(200)
    settled(qt_app)
    assert panel.table.rowCount() == 1
    assert panel.table.item(0, 1).text() == "192.0.2.104"
    assert panel.table.item(0, 0).text() == expected_rank
    assert "CRS not applied" in panel.notice.text()
    panel.close()


def test_reason_click_emits_original_evidence_and_escapes_log_fields(qt_app, tmp_path):
    from logarc.gui.triage import TriagePanel

    panel = TriagePanel()
    panel.show_result(scan_case(make_case(tmp_path)))
    settled(qt_app)
    selected = []
    panel.investigate.connect(lambda ip, refs: selected.append((ip, refs)))
    panel.table.selectRow(0)
    assert "Status" in panel.details.toPlainText()
    panel.open_client.click()
    assert selected == [("192.0.2.0", (EvidenceRef("source", 1),))]
    panel.queues.setCurrentIndex(1)
    settled(qt_app)
    assert "30" in panel.caption.text()
    panel.close()


def test_case_open_starts_scan_and_reason_opens_reconstruction(qt_app, tmp_path):
    window = MainWindow()
    window.report_error = lambda message, detail: (_ for _ in ()).throw(AssertionError(message))
    root = make_case(tmp_path)
    window._load_case(root)
    settled(qt_app)
    assert window._triage.table.rowCount() == 1
    assert isinstance(window._workspace, QTabWidget)
    window._triage.table.selectRow(0)
    window._triage.open_client.click()
    settled(qt_app)
    assert window._result.client_ip == "192.0.2.0"
    assert window._selected is not None
    assert EvidenceRef("source", 1) in window._selected.evidence
    assert window._workspace.currentIndex() == 1
    window.close()
    settled(qt_app)


def test_old_page_response_cannot_overwrite_new_query(qt_app, tmp_path, monkeypatch):
    from logarc.gui import triage
    from logarc.triage.scan import read_page

    result = scan_case(make_case(tmp_path, 2))
    callbacks = []
    monkeypatch.setattr(triage, "run_job", lambda work, **kw: callbacks.append((work, kw)))
    panel = triage.TriagePanel()
    panel.show_result(result)
    old = callbacks[-1]
    panel.search.setText("192.0.2.1")
    old[1]["on_done"](read_page(result.path, "suspicious"))
    assert panel.table.rowCount() == 0
    QTest.qWait(200)
    new = callbacks[-1]
    new[1]["on_done"](read_page(result.path, "suspicious", query="192.0.2.1"))
    old[1]["on_done"](read_page(result.path, "suspicious"))
    assert panel.table.rowCount() == 1
    assert panel.table.item(0, 1).text() == "192.0.2.1"
    panel.close()


def test_time_range_rebuilds_queue_and_discards_old_case_callbacks(qt_app, tmp_path):
    window = MainWindow()
    root = make_case(tmp_path, 2)
    window._load_case(root)
    settled(qt_app)
    window._apply_window(TimeWindow(start=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)))
    settled(qt_app)
    assert window._triage.table.rowCount() == 1
    assert window._triage.table.item(0, 1).text() == "192.0.2.1"
    window.close()


def test_all_clients_search_and_reconstruction_survive_blocked_scan_and_cancellation(
    qt_app, tmp_path, monkeypatch
):
    import threading
    import time

    from logarc.gui import triage
    from logarc.triage.scan import ScanCancelled

    started = threading.Event()

    def blocked(path, *, stop, **kwargs):
        started.set()
        assert stop.wait(15), "test did not cancel blocked scanner"
        raise ScanCancelled()

    monkeypatch.setattr(triage, "run_scan", blocked)
    window = MainWindow()
    window._load_case(make_case(tmp_path, 605))
    deadline = time.monotonic() + 10
    while not started.is_set():
        assert time.monotonic() < deadline
        QTest.qWait(20)
    panel = window._triage
    assert panel.queues.currentIndex() == 0
    panel.queues.setCurrentIndex(2)
    panel.search.setText("192.0.2.604")
    while panel.table.rowCount() != 1:
        assert time.monotonic() < deadline
        QTest.qWait(20)
    assert "not yet analyzed" in panel.table.item(0, 2).text().lower()
    assert panel._result is None
    panel.cancel.click()
    settled(qt_app)
    assert panel.table.rowCount() == 1
    panel.table.selectRow(0)
    panel.open_client.click()
    settled(qt_app)
    assert window._result.client_ip == "192.0.2.604"
    window.close()
    settled(qt_app)


def test_fullscreen_menu_shows_reconstruction_from_priorities(qt_app):
    window = MainWindow()
    window._workspace.setCurrentIndex(0)
    window._fullscreen_action.trigger()
    qt_app.processEvents()
    assert window._workspace.currentIndex() == 1
    window._full_screen.apply(False)
    window.close()


def test_scan_response_for_an_old_case_is_ignored(qt_app, tmp_path, monkeypatch):
    from logarc.gui import triage

    first = scan_case(make_case(tmp_path / "first", 1))
    second = scan_case(make_case(tmp_path / "second", 2))
    callbacks = []
    monkeypatch.setattr(triage, "run_job", lambda work, **kw: callbacks.append(kw))
    panel = triage.TriagePanel()
    panel.start(first.path.parents[1])
    old = callbacks[-1]
    panel.start(second.path.parents[1])
    latest = callbacks[-1]
    old["on_done"](first)
    assert panel._result is None
    latest["on_done"](second)
    assert panel._result == second
    old["on_error"]("old failure", "")
    assert "old failure" not in panel.notice.text()
    panel.shutdown()
    panel.close()


def test_each_reason_links_to_its_own_evidence(qt_app, tmp_path):
    from dataclasses import replace

    from PyQt6.QtCore import QUrl

    from logarc.gui.triage import TriagePanel
    from logarc.triage.profile import PriorityReason
    from logarc.triage.scan import read_page

    result = scan_case(make_case(tmp_path))
    row = read_page(result.path, "suspicious").rows[0]
    extra = PriorityReason("<b>Literal log text</b>", (EvidenceRef("source", 99),))
    panel = TriagePanel()
    panel._display([replace(row, reasons=(*row.reasons, extra))])
    panel.table.selectRow(0)
    selected = []
    panel.investigate.connect(lambda ip, refs: selected.append((ip, refs)))
    panel.details.anchorClicked.emit(QUrl(f"reason:{len(row.reasons)}"))
    assert selected == [(row.profile.client_ip, extra.evidence)]
    assert extra.text in panel.details.toPlainText()
    panel.close()


def test_reason_evidence_precedes_sample_and_stale_reads_are_discarded(
    qt_app, tmp_path, monkeypatch
):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from logarc.gui import app

    callbacks = []
    monkeypatch.setattr(app, "run_job", lambda work, **kw: callbacks.append((work, kw)))
    monkeypatch.setattr(app, "EVIDENCE_LIMIT", 2)
    refs = tuple(EvidenceRef("source", i) for i in range(1, 11))
    node = SimpleNamespace(node_id="activity", episode_ids=("episode",))
    graph = SimpleNamespace(nodes=[node])
    result = SimpleNamespace(
        trace=graph,
        behaviour=graph,
        evidence_for=lambda n, **kw: refs[: kw.get("limit", 10)],
        window=TimeWindow(),
    )
    result.assignments = [SimpleNamespace(evidence=ref, episode_id="episode") for ref in refs]
    window = MainWindow()
    window._case_path = tmp_path
    window._result = result
    requested = []
    monkeypatch.setattr(
        Case,
        "open",
        lambda path: nullcontext(
            SimpleNamespace(read_evidence=lambda refs: requested.extend(refs))
        ),
    )
    displayed = []
    monkeypatch.setattr(
        window._evidence, "show_evidence", lambda node, lines: displayed.append(lines)
    )
    window._show_evidence(node.node_id, evidence=(refs[-1],))
    old = callbacks[-1]
    old[0](lambda value: None)
    assert requested == [refs[-1], refs[0]]
    window._show_evidence(node.node_id, evidence=(refs[-2],))
    latest = callbacks[-1]
    latest[1]["on_done"](["latest"])
    old[1]["on_done"](["stale"])
    assert displayed == [["latest"]]
    window.close()


def test_same_client_reason_requests_cannot_finish_out_of_order(qt_app, tmp_path, monkeypatch):
    from logarc.gui import app

    window = MainWindow()
    window._case_path = make_case(tmp_path)
    callbacks = []
    monkeypatch.setattr(app, "run_job", lambda work, **kw: callbacks.append((work, kw)))
    window._reconstruct("192.0.2.0")
    old = callbacks[-1]
    window._reconstruct("192.0.2.0", evidence=(EvidenceRef("source", 1),))
    latest = callbacks[-1]
    old_result = old[0](lambda value: None)
    latest_result = latest[0](lambda value: None)
    latest[1]["on_done"](latest_result)
    old[1]["on_done"](old_result)
    assert window._result is latest_result[0]
    window.close()


def test_summary_responses_are_invalidated_before_debounce_and_on_range_or_case_change(
    qt_app, tmp_path, monkeypatch
):
    from logarc.gui import triage

    root = make_case(tmp_path, 2)
    other = make_case(tmp_path / "other", 1)
    callbacks = []
    monkeypatch.setattr(triage, "run_job", lambda work, **kw: callbacks.append((work, kw)))
    panel = triage.TriagePanel()
    panel.start(root)
    panel.queues.setCurrentIndex(2)
    old = callbacks[-1]
    stale = old[0](lambda _: None)
    panel.search.setText("192.0.2.1")
    old[1]["on_done"](stale)
    assert panel.table.rowCount() == 0
    QTest.qWait(200)
    latest = callbacks[-1]
    latest[1]["on_done"](latest[0](lambda _: None))
    assert panel.table.rowCount() == 1
    assert panel.table.item(0, 1).text() == "192.0.2.1"
    panel.start(root, TimeWindow(end=datetime(2026, 1, 1, tzinfo=UTC)))
    latest[1]["on_done"](latest[0](lambda _: None))
    assert panel.table.rowCount() == 0
    current = callbacks[-1]
    current[1]["on_done"](current[0](lambda _: None))
    assert panel.table.rowCount() == 0
    panel.start(other)
    old[1]["on_done"](stale)
    old[1]["on_error"]("stale failure", "")
    assert panel.table.rowCount() == 0
    assert "stale failure" not in panel.caption.text()
    panel.shutdown()
    panel.close()


def test_all_clients_uses_summary_query_after_completion_and_scan_failure(
    qt_app, tmp_path, monkeypatch
):
    from logarc.gui import triage

    root = make_case(tmp_path, 2)
    result = scan_case(root)
    callbacks = []
    monkeypatch.setattr(triage, "run_job", lambda work, **kw: callbacks.append((work, kw)))
    panel = triage.TriagePanel()
    panel.start(root)
    scan = callbacks[-1]
    panel.queues.setCurrentIndex(2)
    summary = callbacks[-1]
    summary[1]["on_done"](summary[0](lambda _: None))
    assert panel.table.rowCount() == 2
    scan[1]["on_error"]("scan failed", "detail")
    assert panel.table.rowCount() == 2
    panel.show_result(result)
    summary = callbacks[-1]
    page = summary[0](lambda _: None)
    assert page.rows[0].position == 1
    summary[1]["on_done"](page)
    assert "Open reconstruction" in panel.table.item(0, 2).text()
    panel.shutdown()
    panel.close()


def test_departing_case_clears_triage_before_new_load_finishes(qt_app, tmp_path, monkeypatch):
    from logarc.gui import app, triage

    window = MainWindow()
    root = make_case(tmp_path)
    window._load_case(root)
    settled(qt_app)
    callbacks = []
    monkeypatch.setattr(app, "run_job", lambda work, **kw: callbacks.append(kw))
    summary_jobs = []
    monkeypatch.setattr(triage, "run_job", lambda work, **kw: summary_jobs.append(kw))
    window._load_case(tmp_path / "pending")
    panel = window._triage
    assert not panel.isEnabled()
    assert panel.table.rowCount() == 0
    panel.queues.setCurrentIndex(2)
    panel.search.setText("old-client")
    QTest.qWait(200)
    panel._retry()
    assert summary_jobs == []
    assert panel._request is None and panel._result is None
    window.close()


def test_departure_rejects_old_evidence_and_old_load_errors_or_progress(
    qt_app, tmp_path, monkeypatch
):
    from logarc.gui import app, triage

    window = MainWindow()
    root = make_case(tmp_path)
    window._load_case(root)
    settled(qt_app)
    window._reconstruct("192.0.2.0")
    settled(qt_app)
    callbacks = []
    monkeypatch.setattr(app, "run_job", lambda work, **kw: callbacks.append(kw))
    monkeypatch.setattr(triage, "run_job", lambda *args, **kw: None)
    shown, failures = [], []
    monkeypatch.setattr(window._evidence, "show_evidence", lambda *args: shown.append(args))
    monkeypatch.setattr(window, "report_error", lambda *args: failures.append(args))
    window._show_evidence(window._result.trace.nodes[0].node_id)
    evidence = callbacks[-1]
    window._apply_window(TimeWindow(start=datetime(2026, 1, 1, tzinfo=UTC)))
    range_job = callbacks[-1]
    evidence["on_done"]([])
    evidence["on_error"]("old evidence", "")
    assert not shown and not failures
    window._load_case(tmp_path / "pending")
    old_load = callbacks[-1]
    window._load_case(tmp_path / "latest")
    for old in (range_job, old_load):
        old["on_progress"]("old progress")
        old["on_error"]("old failure", "")
    assert not failures
    assert "old progress" not in window._status.text()
    window.close()


def test_prioritization_waits_until_the_crs_question_is_answered(qt_app, tmp_path, monkeypatch):
    """Accepting CRS reloads the case and restarts the scan from nothing.

    So a scan begun while the offer is still on screen is work the reader will
    never see. It waits for an answer, and the reader keeps All clients in the
    meantime.
    """
    from PyQt6.QtWidgets import QDialog

    from logarc.gui import app as app_module

    monkeypatch.setattr(app_module.SidecarConfig, "check", lambda self: None)
    app_module._settings().setValue(app_module._CRS_KEY, "")
    case_dir = make_case(tmp_path)

    window = MainWindow()
    started: list[tuple[object, ...]] = []
    monkeypatch.setattr(window._triage, "start", lambda *args, **_: started.append(args))

    window._open_and_offer_crs(case_dir)
    settled(qt_app)
    assert started == [], "the scan began while the CRS offer was still unanswered"

    window._crs_answered(case_dir, QDialog.DialogCode.Rejected)
    settled(qt_app)
    assert started, "declining CRS left the case with no prioritization scan"


def test_the_scan_starts_only_once_the_window_knows_the_case(qt_app, tmp_path):
    """Two readers on one case silently cost an earlier test its `_case_path`.

    The scan is a third reader, in its own process against the same store, so
    it starts from `_load_case`'s result rather than beside it. Recording
    `_case_path` at the moment the scan is asked for pins that ordering without
    waiting for the scan itself.
    """
    case_dir = make_case(tmp_path, 3)
    window = MainWindow()
    seen: list[object] = []
    original = window._triage.start

    def record(path, *args, **kwargs):
        seen.append(window._case_path)
        return original(path, *args, **kwargs)

    window._triage.start = record
    window._load_case(case_dir)
    settled(qt_app)

    assert seen == [case_dir], "the scan was asked for before the window knew the case"
    assert window._case_path == case_dir
