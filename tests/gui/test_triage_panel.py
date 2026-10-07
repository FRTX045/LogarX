from dataclasses import replace
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
    assert "Responses: 200: 1." in panel.details.toPlainText()
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


def test_the_client_list_finds_any_client_while_the_scan_is_blocked_and_after_cancelling(
    qt_app, tmp_path, monkeypatch
):
    import threading
    import time

    from logarc.gui import triage
    from logarc.gui.panels import ClientTable
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
    clients = window._clients
    clients._filter.setText("192.0.2.604")
    QTest.qWait(ClientTable.SEARCH_DELAY_MS + 50)
    while clients._table.rowCount() != 1:
        assert time.monotonic() < deadline
        QTest.qWait(20)
    assert window._triage._result is None
    window._triage.cancel.click()
    settled(qt_app)
    clients._table.selectRow(0)
    settled(qt_app)
    assert window._result.client_ip == "192.0.2.604"
    window.close()
    settled(qt_app)


def test_where_to_start_offers_only_the_queues_that_analyse_clients(qt_app):
    from logarc.gui.triage import TriagePanel

    panel = TriagePanel()
    assert [panel.queues.tabText(i) for i in range(panel.queues.count())] == [
        "Suspicious activity",
        "Unusual activity",
    ]
    panel.close()


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


def test_a_client_search_answer_for_a_previous_case_is_dropped(qt_app, tmp_path, monkeypatch):
    import logarc.caseview
    from logarc.gui import app
    from logarc.gui.panels import ClientTable

    monkeypatch.setattr(ClientTable, "PAGE_SIZE", 1)
    monkeypatch.setattr(logarc.caseview, "CLIENT_LIMIT", 1)
    window = MainWindow()
    window._load_case(make_case(tmp_path / "first", 3))
    settled(qt_app)
    jobs = []
    monkeypatch.setattr(app, "run_job", lambda work, **kw: jobs.append((work, kw)))
    window._clients._filter.setText("192.0.2.2")
    QTest.qWait(ClientTable.SEARCH_DELAY_MS + 50)
    work, callbacks = jobs[-1]
    answer = work(lambda _: None)
    window._load_case(make_case(tmp_path / "second", 3))
    callbacks["on_done"](answer)
    table = window._clients._table
    assert "192.0.2.2" not in [table.item(row, 0).text() for row in range(table.rowCount())]
    callbacks["on_error"]("stale failure", "")
    assert "stale failure" not in window._clients._caption.text()
    window.close()
    settled(qt_app)


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


def test_prioritization_waits_until_crs_has_finished(qt_app, tmp_path, monkeypatch):
    """Finishing CRS reloads the case and restarts the scan from nothing.

    So a scan begun while CRS is still running is work the reader will never
    see. It waits for the run to end, and the reader keeps the client list in
    the meantime.
    """
    from logarc.detect.crs import AUTO_ENV, SidecarConfig
    from logarc.enrich import EnrichOutcome
    from logarc.gui import app as app_module

    monkeypatch.delenv(AUTO_ENV, raising=False)
    monkeypatch.setattr(app_module.SidecarConfig, "check", lambda self: None)
    case_dir = make_case(tmp_path)

    window = MainWindow()
    started: list[tuple[object, ...]] = []
    monkeypatch.setattr(window._triage, "start", lambda *args, **_: started.append(args))
    monkeypatch.setattr(window, "_run_crs", lambda _case: None)

    window._open_and_start_crs(case_dir)
    settled(qt_app)
    assert started == [], "the scan began while CRS was still running"

    finished = EnrichOutcome(
        replayed=1,
        covered=0,
        detections=(),
        path=case_dir / "crs.parquet",
        stopped=False,
        seconds=0.1,
        config=SidecarConfig(),
    )
    window._crs_finished(case_dir, finished)
    settled(qt_app)
    assert started, "a finished CRS run left the case with no prioritization scan"
    window.close()


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


def ingested_case(tmp_path):
    """A case read from a real log file, so its example requests can be opened."""
    source = tmp_path / "access.log"
    source.write_text(
        '203.0.113.9 - - [01/Jan/2026:00:00:00 +0000] "GET /etc/passwd HTTP/1.1" 200 10 "-" '
        '"Mozilla/5.0"\n',
        encoding="utf-8",
    )
    with Case.create(tmp_path / "case") as case:
        case.ingest([source])
    return case.root, source


def selected_panel(qt_app, root):
    from logarc.gui.triage import TriagePanel
    from logarc.triage.scan import read_page

    panel = TriagePanel()
    panel._request = (root, TimeWindow())
    panel._display(read_page(scan_case(root).path, "suspicious").rows)
    panel.table.selectRow(0)
    checked(qt_app, panel)
    return panel


def checked(qt_app, panel):
    """Let the debounced source check start, then wait for it to report back."""
    QTest.qWait(panel.SOURCE_CHECK_DELAY_MS + 50)
    settled(qt_app)


def first_example(row):
    number = next(i for i, reason in enumerate(row.reasons) if reason.examples)
    return number, row.reasons[number].examples[0]


def test_the_queue_shows_each_clients_key_observation(qt_app, tmp_path):
    from logarc.gui.recommendation import summary_for

    panel = selected_panel(qt_app, make_case(tmp_path))
    assert panel.table.horizontalHeaderItem(2).text() == "Key observation"
    assert panel.table.item(0, 2).text() == summary_for(panel._rows[0])
    assert panel.table.item(0, 2).text().startswith("Exploit evidence: ")
    assert panel.open_client.text() == "Inspect supporting requests"
    panel.close()


def test_details_share_a_draggable_divider_with_the_queue(qt_app):
    from PyQt6.QtCore import Qt

    from logarc.gui.triage import TriagePanel

    panel = TriagePanel()
    assert panel.split.orientation() == Qt.Orientation.Vertical
    assert (panel.split.widget(0), panel.split.widget(1)) == (panel.table, panel.details)
    assert not panel.split.childrenCollapsible()
    assert panel.details.maximumHeight() > 1000
    panel.resize(600, 900)
    panel.show()
    qt_app.processEvents()
    top, bottom = panel.split.sizes()
    assert abs(top - bottom) <= max(top, bottom) * 0.1
    panel.close()


def test_clicking_an_example_opens_exactly_that_request(qt_app, tmp_path):
    from PyQt6.QtCore import QUrl

    root, _ = ingested_case(tmp_path)
    panel = selected_panel(qt_app, root)
    row = panel._rows[0]
    number, example = first_example(row)
    opened = []
    panel.investigate.connect(lambda ip, refs: opened.append((ip, refs)))
    panel.details.anchorClicked.emit(QUrl(f"example:{number}:0"))
    assert opened == [(row.profile.client_ip, (example.evidence,))]
    assert "Cannot open" not in panel.details.toHtml()
    panel.close()


def test_inspect_opens_exactly_the_exploit_request_for_a_first_group_client(qt_app, tmp_path):
    panel = selected_panel(qt_app, make_case(tmp_path, count=2))
    row = panel._rows[0]
    lead = row.reasons[0]
    assert lead.kind == "exploit_evidence"
    assert len(lead.evidence) == 1
    other = (EvidenceRef("source", 99),)
    reasons = (lead, *(replace(reason, evidence=other) for reason in row.reasons[1:]))
    assert len(reasons) > 1
    panel._display([replace(row, reasons=reasons)])
    panel.table.selectRow(0)
    opened = []
    panel.investigate.connect(lambda ip, refs: opened.append((ip, refs)))
    panel.open_client.click()
    assert opened == [(row.profile.client_ip, lead.evidence)]
    assert opened[0][1] == tuple(example.evidence for example in row.profile.exploit_examples)
    panel.close()


def test_an_unreadable_source_stays_visible_and_opens_nothing(qt_app, tmp_path):
    from PyQt6.QtCore import QUrl

    panel = selected_panel(qt_app, make_case(tmp_path))
    row = panel._rows[0]
    number, example = first_example(row)
    text = panel.details.toPlainText()
    assert str(example.evidence) in text
    assert "Cannot open" in text
    opened = []
    panel.investigate.connect(lambda ip, refs: opened.append((ip, refs)))
    panel.details.anchorClicked.emit(QUrl(f"example:{number}:0"))
    assert opened == []
    panel.close()


def test_a_source_changed_since_ingest_still_opens_with_its_warning(qt_app, tmp_path):
    from PyQt6.QtCore import QUrl

    root, source = ingested_case(tmp_path)
    source.write_text(source.read_text(encoding="utf-8") + "appended later\n", encoding="utf-8")
    panel = selected_panel(qt_app, root)
    row = panel._rows[0]
    number, example = first_example(row)
    assert "Warning:" in panel.details.toPlainText()
    assert "Cannot open" not in panel.details.toPlainText()
    opened = []
    panel.investigate.connect(lambda ip, refs: opened.append((ip, refs)))
    panel.details.anchorClicked.emit(QUrl(f"example:{number}:0"))
    assert opened == [(row.profile.client_ip, (example.evidence,))]
    panel.close()


def test_a_late_source_check_for_another_row_is_ignored(qt_app, tmp_path, monkeypatch):
    from logarc.gui import triage
    from logarc.gui.recommendation import SourceStatus
    from logarc.triage.scan import read_page

    root = make_case(tmp_path, count=2)
    rows = read_page(scan_case(root).path, "suspicious").rows
    jobs = []
    monkeypatch.setattr(triage, "run_job", lambda work, **kw: jobs.append(kw))
    panel = triage.TriagePanel()
    panel._request = (root, TimeWindow())
    panel._display(rows)
    panel.table.selectRow(0)
    QTest.qWait(panel.SOURCE_CHECK_DELAY_MS + 50)
    first = jobs[-1]
    panel.table.selectRow(1)
    # Named by a line the second row shows, so only the guard can keep it out.
    _, example = first_example(rows[1])
    first["on_done"]({example.evidence: SourceStatus("stale answer", can_open=False)})
    assert "stale answer" not in panel.details.toPlainText()
    panel.close()


def test_show_full_request_expands_only_that_example(qt_app, tmp_path):
    from dataclasses import replace

    from PyQt6.QtCore import QUrl

    root, _ = ingested_case(tmp_path)
    panel = selected_panel(qt_app, root)
    row = panel._rows[0]
    number, example = first_example(row)
    long_path = "/catalog/" + "x" * 400
    reasons = list(row.reasons)
    reasons[number] = replace(reasons[number], examples=(replace(example, path=long_path),))
    panel._display([replace(row, reasons=tuple(reasons))])
    panel.table.selectRow(0)
    checked(qt_app, panel)
    assert long_path not in panel.details.toPlainText()
    assert "Show full request" in panel.details.toPlainText()
    panel.details.anchorClicked.emit(QUrl(f"expand:{number}:0"))
    assert long_path in panel.details.toPlainText().replace("\n", "")
    panel.close()


def test_a_click_on_the_key_observation_reads_the_row_without_leaving(qt_app, tmp_path):
    panel = selected_panel(qt_app, make_case(tmp_path))
    opened = []
    panel.investigate.connect(lambda ip, refs: opened.append((ip, refs)))
    panel.table.cellClicked.emit(0, 2)
    assert opened == []
    panel.table.cellDoubleClicked.emit(0, 2)
    assert [ip for ip, _ in opened] == [panel._rows[0].profile.client_ip]
    panel.close()


def test_moving_quickly_through_rows_checks_sources_once(qt_app, tmp_path, monkeypatch):
    from logarc.gui import triage
    from logarc.triage.scan import read_page

    root = make_case(tmp_path, count=3)
    rows = read_page(scan_case(root).path, "suspicious").rows
    jobs = []
    monkeypatch.setattr(triage, "run_job", lambda work, **kw: jobs.append(work))
    panel = triage.TriagePanel()
    panel._request = (root, TimeWindow())
    panel._display(rows)
    for index in (0, 1, 2, 1):
        panel.table.selectRow(index)
    assert jobs == []
    QTest.qWait(panel.SOURCE_CHECK_DELAY_MS + 50)
    assert len(jobs) == 1
    panel.close()


def test_a_stale_check_does_no_reading(qt_app, tmp_path, monkeypatch):
    from logarc.case import Case as RealCase
    from logarc.gui import triage
    from logarc.triage.scan import read_page

    root = make_case(tmp_path, count=2)
    rows = read_page(scan_case(root).path, "suspicious").rows
    works = []
    monkeypatch.setattr(triage, "run_job", lambda work, **kw: works.append(work))
    panel = triage.TriagePanel()
    panel._request = (root, TimeWindow())
    panel._display(rows)
    panel.table.selectRow(0)
    QTest.qWait(panel.SOURCE_CHECK_DELAY_MS + 50)
    panel.table.selectRow(1)
    opened = []
    monkeypatch.setattr(
        triage.Case, "open", lambda path: opened.append(path) or RealCase.open(path)
    )
    assert works[0](lambda value: None) == {}
    assert opened == []
    panel.close()


def test_rewriting_the_details_keeps_the_readers_place(qt_app, tmp_path):
    from dataclasses import replace

    from PyQt6.QtCore import QUrl

    root, _ = ingested_case(tmp_path)
    panel = selected_panel(qt_app, root)
    row = panel._rows[0]
    number, example = first_example(row)
    reasons = list(row.reasons)
    reasons[number] = replace(
        reasons[number], examples=(replace(example, path="/catalog/" + "x" * 400),) * 5
    )
    panel.resize(500, 500)
    panel.show()
    panel._display([replace(row, reasons=tuple(reasons))])
    panel.table.selectRow(0)
    checked(qt_app, panel)
    bar = panel.details.verticalScrollBar()
    assert bar.maximum() > 0
    bar.setValue(bar.maximum() // 2)
    kept = bar.value()
    panel.details.anchorClicked.emit(QUrl(f"expand:{number}:0"))
    assert bar.value() == kept
    panel.close()


def test_a_failed_source_check_says_the_sources_were_not_checked(qt_app, tmp_path, monkeypatch):
    from logarc.gui import triage

    root = make_case(tmp_path)
    panel = selected_panel(qt_app, root)
    monkeypatch.setattr(
        triage.Case, "open", lambda path: (_ for _ in ()).throw(OSError("disk gone"))
    )
    panel.table.clearSelection()
    panel._shown = None
    panel.table.selectRow(0)
    checked(qt_app, panel)
    assert "Sources could not be checked" in panel.details.toPlainText()
    panel.close()
