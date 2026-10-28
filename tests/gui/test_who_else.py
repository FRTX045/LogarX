from datetime import UTC, datetime, timedelta

from conftest import settled
from logarx.case import Case
from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.gui.app import MainWindow
from logarx.gui.who_else import WhoElseDialog, describe, unavailable
from logarx.triage.scan import RuleMatch, TriageProgress


def enumeration(ip, count, user_agent, first_line):
    """Distinct missing paths, one a second: what a directory wordlist looks like."""
    return [
        NormalizedEvent(
            datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=i),
            ip,
            EvidenceRef("source", first_line + i),
            path=f"/w{i}",
            method="GET",
            status=404,
            user_agent=user_agent,
            protocol="HTTP/1.1",
        )
        for i in range(count)
    ]


def make_case(tmp_path):
    """dirb and gobuster over one wordlist, and somebody browsing."""
    with Case.create(tmp_path / "case") as case:
        case.store.write(enumeration("192.0.2.30", 20, "Mozilla/5.0", 1))
        case.store.write(enumeration("192.0.2.31", 30, "gobuster/3.5", 100))
        case.store.write(
            [
                NormalizedEvent(
                    datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=i),
                    "192.0.2.1",
                    EvidenceRef("source", 200 + i),
                    path="/",
                    method="GET",
                    status=200,
                    user_agent="Mozilla/5.0",
                )
                for i in range(5)
            ]
        )
        case.store.finalize()
    return case.root


DIRB = RuleMatch("192.0.2.30", matched=20, won=20, requests=20)
GOBUSTER = RuleMatch("192.0.2.31", matched=30, won=0, requests=30)


def test_the_count_is_of_other_clients_only():
    """Looking at dirb, dirb is not somebody else."""
    assert describe("directory_enumeration", [GOBUSTER, DIRB], client_ip="192.0.2.30") == (
        "1 other client matched directory_enumeration in this time range."
    )
    assert describe("directory_enumeration", [DIRB], client_ip="192.0.2.30") == (
        "No other client matched directory_enumeration in this time range."
    )
    assert describe(
        "directory_enumeration", [GOBUSTER, DIRB], client_ip="192.0.2.30", name="Dir Scan"
    ) == ("1 other client matched Dir Scan in this time range.")


def test_no_answer_before_the_scan_finishes_is_never_worded_as_one():
    running = unavailable(TriageProgress(1204, 2761, ()), scanning=True)
    assert "1,204 of 2,761" in running
    stopped = unavailable(None, scanning=False)
    for text in (running, stopped):
        assert "no other" not in text.lower()
        assert "Triage" in text


def test_dialog_lists_others_and_opens_the_one_double_clicked(qt_app):
    dialog = WhoElseDialog()
    opened = []
    dialog.open_client.connect(opened.append)
    dialog.show_matches("directory_enumeration", [GOBUSTER, DIRB], client_ip="192.0.2.30")
    assert dialog.table.rowCount() == 1
    assert [dialog.table.item(0, column).text() for column in range(4)] == [
        "192.0.2.31",
        "30",
        "0",
        "30",
    ]
    dialog.table.cellDoubleClicked.emit(0, 1)
    assert opened == ["192.0.2.31"]
    dialog.show_unavailable("directory_enumeration", unavailable(None, scanning=False))
    assert dialog.table.rowCount() == 0
    assert dialog.table.isHidden()
    dialog.close()


def test_right_click_on_dirb_finds_gobuster_and_opens_it(qt_app, tmp_path):
    window = MainWindow()
    window.report_error = lambda message, detail: (_ for _ in ()).throw(AssertionError(message))
    window._load_case(make_case(tmp_path))
    settled(qt_app)
    assert window._triage.result is not None
    window._reconstruct("192.0.2.30")
    settled(qt_app)
    node = next(n for n in window._result.trace.nodes if "directory_enumeration" in n.rule_ids)
    window._show_evidence(node.node_id)
    settled(qt_app)

    window._who_else_menu.aboutToShow.emit()
    entries = {action.text(): action for action in window._who_else_menu.actions()}
    assert "Directory Enumeration" in entries
    assert entries["Directory Enumeration"].toolTip() == "directory_enumeration"
    entries["Directory Enumeration"].trigger()
    settled(qt_app)
    dialog = window._who_else_dialog
    assert dialog is not None
    assert dialog.table.rowCount() == 1
    assert dialog.table.item(0, 0).text() == "192.0.2.31"

    dialog.table.cellDoubleClicked.emit(0, 0)
    settled(qt_app)
    assert window._result.client_ip == "192.0.2.31"
    window.close()
    settled(qt_app)


def test_without_a_finished_scan_the_window_says_so(qt_app, tmp_path):
    window = MainWindow()
    window._load_case(make_case(tmp_path))
    settled(qt_app)
    window._reconstruct("192.0.2.30")
    settled(qt_app)
    node = next(n for n in window._result.trace.nodes if "directory_enumeration" in n.rule_ids)
    window._show_evidence(node.node_id)
    settled(qt_app)
    window._triage.shutdown()

    window._who_else("directory_enumeration")
    settled(qt_app)
    dialog = window._who_else_dialog
    assert dialog is not None
    assert dialog.table.isHidden()
    assert dialog.caption.text() == unavailable(None, scanning=False)
    window.close()
    settled(qt_app)


def test_menu_has_nothing_to_offer_without_a_selected_activity(qt_app):
    window = MainWindow()
    window._who_else_menu.aboutToShow.emit()
    actions = window._who_else_menu.actions()
    assert [action.text() for action in actions] == ["Select an activity first"]
    assert not actions[0].isEnabled()
    window.close()


def test_the_dialog_explains_its_columns_on_hover_not_in_a_footnote(qt_app):
    dialog = WhoElseDialog()
    dialog.show_matches(
        "benign:browsing", [GOBUSTER, DIRB], client_ip="192.0.2.30", name="Page View"
    )

    headers = [dialog.table.horizontalHeaderItem(i).text() for i in range(4)]
    assert headers == ["Client", "Matched", "Named", "Requests"]
    assert dialog.table.horizontalHeaderItem(1).toolTip()
    assert dialog.table.horizontalHeaderItem(2).toolTip()
    assert dialog.table.verticalHeader().isHidden()
    assert not hasattr(dialog, "note")
    assert dialog.windowTitle() == "Who else matched Page View?"
    dialog.close()


def test_a_rule_is_called_by_the_name_its_labels_carry() -> None:
    from types import SimpleNamespace

    from logarx.gui.who_else import rule_names

    browsing = SimpleNamespace(rule_id="benign:browsing", name="Page View")
    probe = SimpleNamespace(rule_id="config_probe", name="Configuration File Probe")
    result = SimpleNamespace(
        assignments=[
            SimpleNamespace(labelled=SimpleNamespace(label=probe, all_labels=[probe, browsing]))
        ]
    )

    assert rule_names(result) == {
        "config_probe": "Configuration File Probe",
        "benign:browsing": "Page View",
    }


def test_the_menu_names_rules_and_keeps_the_id_on_hover(qt_app):
    from types import SimpleNamespace

    window = MainWindow()
    browsing = SimpleNamespace(rule_id="benign:browsing", name="Page View")
    window._result = SimpleNamespace(
        assignments=[
            SimpleNamespace(labelled=SimpleNamespace(label=browsing, all_labels=[browsing]))
        ]
    )
    window._selected = SimpleNamespace(rule_ids=("benign:browsing", "gone_rule"))

    window._who_else_menu.aboutToShow.emit()

    actions = window._who_else_menu.actions()
    assert [action.text() for action in actions] == ["Page View", "gone_rule"]
    assert [action.toolTip() for action in actions] == ["benign:browsing", "gone_rule"]
    window._result = None
    window._selected = None
    window.close()
