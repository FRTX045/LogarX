"""Naming a client from the window: the two menus, the file, and an unreadable file."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QEvent
from PyQt6.QtWidgets import QApplication, QFileDialog, QMenu
from tables import column_of

from conftest import settled
from logarx import client_names
from logarx.case import Case
from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.gui import prefs
from logarx.gui.app import MainWindow
from logarx.gui.client_name_keeper import ClientNameKeeper
from logarx.gui.columns import CLIENT_ADDRESS

CLIENT = "192.0.2.0"
RENAME = "Rename this client…"


@pytest.fixture
def case_dir(tmp_path: Path) -> Path:
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
                for i in range(2)
            ]
        )
        case.store.finalize()
    return case.root


def opened(qt_app: QApplication, case_dir: Path) -> MainWindow:
    window = MainWindow()
    window.resize(1200, 800)
    window.show()
    window._load_case(case_dir)
    settled(qt_app)
    return window


def entries(menu: QMenu | None) -> list[str]:
    assert menu is not None
    return [action.text() for action in menu.actions()]


def sidebar_menu(window: MainWindow) -> QMenu | None:
    table = window._clients._table
    row = next(
        r for r in range(table.rowCount()) if table.item(r, 0).data(CLIENT_ADDRESS) == CLIENT
    )
    return window._clients._menu_at(table.visualItemRect(table.item(row, 0)).center())


def triage_menu(window: MainWindow) -> QMenu | None:
    panel = window._triage
    table = panel.table
    row = next(r for r in range(table.rowCount()) if table.item(r, 1).text() == CLIENT)
    return panel._menu_at(table.visualItemRect(table.item(row, 1)).center())


def choose(menu: QMenu | None, text: str) -> None:
    assert menu is not None
    next(action for action in menu.actions() if action.text() == text).trigger()


def name_in_the_window(window: MainWindow, name: str) -> None:
    dialog = window._client_names.dialog
    assert dialog is not None and dialog.isVisible()
    dialog.field.setText(name)
    dialog.rename_button.click()


def test_the_sidebar_menu_offers_rename(qt_app: QApplication, case_dir: Path) -> None:
    window = opened(qt_app, case_dir)

    assert entries(sidebar_menu(window)) == ["Bookmark this client…", RENAME]
    window.close()


def test_the_triage_menu_offers_rename(qt_app: QApplication, case_dir: Path) -> None:
    window = opened(qt_app, case_dir)

    assert entries(triage_menu(window)) == ["Bookmark this client…", RENAME]
    window.close()


def test_renaming_from_the_sidebar_writes_the_file(qt_app: QApplication, case_dir: Path) -> None:
    window = opened(qt_app, case_dir)

    choose(sidebar_menu(window), RENAME)
    name_in_the_window(window, "Office VPN")

    assert client_names.load(case_dir).names.name_for(CLIENT) == "Office VPN"
    window.close()


def test_renaming_from_triage_writes_the_same_file(qt_app: QApplication, case_dir: Path) -> None:
    window = opened(qt_app, case_dir)

    choose(triage_menu(window), RENAME)
    name_in_the_window(window, "Office VPN")

    assert client_names.load(case_dir).names.name_for(CLIENT) == "Office VPN"
    window.close()


def test_the_window_opens_on_the_current_name(qt_app: QApplication, case_dir: Path) -> None:
    client_names.apply(
        case_dir,
        lambda names: client_names.rename(names, CLIENT, "Office VPN", now=datetime.now(UTC)),
    )
    window = opened(qt_app, case_dir)

    choose(sidebar_menu(window), RENAME)

    dialog = window._client_names.dialog
    assert dialog is not None
    assert dialog.field.text() == "Office VPN"
    assert dialog.remove_button.isEnabled()
    dialog.remove_button.click()
    assert client_names.load(case_dir).names.name_for(CLIENT) is None
    window.close()


def test_saving_emits_changed(qt_app: QApplication, case_dir: Path) -> None:
    window = opened(qt_app, case_dir)
    heard: list[bool] = []
    window._client_names.changed.connect(lambda: heard.append(True))

    choose(sidebar_menu(window), RENAME)
    name_in_the_window(window, "Office VPN")

    assert heard == [True]
    window.close()


def test_an_unreadable_file_is_said_once(qt_app: QApplication, tmp_path: Path) -> None:
    (tmp_path / client_names.FILE_NAME).write_bytes(b"{")
    said: list[str] = []
    keeper = ClientNameKeeper(parent=None, case_path=lambda: tmp_path, say=said.append)

    assert keeper.names() == {}
    assert keeper.names() == {}
    settled(qt_app)

    assert len(said) == 1
    assert client_names.UNREADABLE_NAME in said[0]


def test_renaming_over_an_unreadable_file_says_so(qt_app: QApplication, tmp_path: Path) -> None:
    (tmp_path / client_names.FILE_NAME).write_bytes(b"{")
    said: list[str] = []
    keeper = ClientNameKeeper(parent=None, case_path=lambda: tmp_path, say=said.append)

    keeper.rename(CLIENT)
    settled(qt_app)

    assert len(said) == 1
    assert client_names.UNREADABLE_NAME in said[0]
    assert keeper.dialog is not None
    keeper.dialog.close()


def sidebar_text(window: MainWindow, address: str) -> str:
    table = window._clients._table
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is not None and item.data(CLIENT_ADDRESS) == address:
            return item.text()
    raise AssertionError(f"{address} is not listed")


def test_a_saved_name_shows_in_the_sidebar_at_once(qt_app: QApplication, case_dir: Path) -> None:
    window = opened(qt_app, case_dir)

    choose(sidebar_menu(window), RENAME)
    name_in_the_window(window, "Office VPN")

    assert sidebar_text(window, CLIENT) == "Office VPN"
    window.close()


def test_names_show_when_the_case_opens(qt_app: QApplication, case_dir: Path) -> None:
    client_names.apply(
        case_dir,
        lambda names: client_names.rename(names, CLIENT, "Office VPN", now=datetime.now(UTC)),
    )

    window = opened(qt_app, case_dir)

    assert sidebar_text(window, CLIENT) == "Office VPN"
    window.close()


def test_the_view_menu_switches_names_off_and_on(qt_app: QApplication, case_dir: Path) -> None:
    client_names.apply(
        case_dir,
        lambda names: client_names.rename(names, CLIENT, "Office VPN", now=datetime.now(UTC)),
    )
    window = opened(qt_app, case_dir)
    action = window._client_names_action
    assert action.isChecked()

    action.trigger()
    assert sidebar_text(window, CLIENT) == CLIENT
    assert window._prefs[prefs.SHOW_CLIENT_NAMES] is False

    action.trigger()
    assert sidebar_text(window, CLIENT) == "Office VPN"
    window.close()


def opened_on_client(qt_app: QApplication, case_dir: Path) -> MainWindow:
    window = opened(qt_app, case_dir)
    table = window._clients._table
    table.selectRow(
        next(r for r in range(table.rowCount()) if table.item(r, 0).data(CLIENT_ADDRESS) == CLIENT)
    )
    settled(qt_app)
    assert window._result is not None and window._result.client_ip == CLIENT
    return window


def name_it(case_dir: Path, name: str = "Office VPN") -> None:
    client_names.apply(
        case_dir, lambda names: client_names.rename(names, CLIENT, name, now=datetime.now(UTC))
    )


def test_heading_shows_the_name_and_the_address(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir, "Office <VPN>")
    window = opened_on_client(qt_app, case_dir)

    heading = window._heading.text()
    assert "Office &lt;VPN&gt;" in heading
    assert CLIENT in heading
    assert heading.index("Office") < heading.index(CLIENT)
    window.close()


def test_heading_shows_only_the_address_when_names_are_off(
    qt_app: QApplication, case_dir: Path
) -> None:
    name_it(case_dir)
    window = opened_on_client(qt_app, case_dir)

    window._client_names_action.trigger()

    assert "Office VPN" not in window._heading.text()
    assert CLIENT in window._heading.text()
    window.close()


def test_the_status_line_uses_the_name(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir)
    window = opened_on_client(qt_app, case_dir)

    assert window._status.text().startswith("Office VPN: ")
    window.close()


def test_a_name_saved_in_another_window_shows_after_activation(
    qt_app: QApplication, case_dir: Path
) -> None:
    window = opened(qt_app, case_dir)
    assert sidebar_text(window, CLIENT) == CLIENT

    name_it(case_dir)
    QApplication.sendEvent(window, QEvent(QEvent.Type.ActivationChange))

    assert sidebar_text(window, CLIENT) == "Office VPN"
    window.close()


def test_the_evidence_record_names_the_open_client(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir)
    window = opened_on_client(qt_app, case_dir)

    assert window._evidence._client_name == "Office VPN"
    window.close()


def test_a_who_else_dialog_opened_later_shows_names(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir)
    window = opened_on_client(qt_app, case_dir)
    assert window._who_else_dialog is None, "premise: no dialog yet"

    window._who_else("directory_enumeration")

    dialog = window._who_else_dialog
    assert dialog is not None
    assert dialog._names == {CLIENT: "Office VPN"}
    assert dialog._names_shown is True
    dialog.close()
    window.close()


def searched(qt_app: QApplication, window: MainWindow, text: str) -> list[tuple[str, str]]:
    """The rows a search of the whole case leaves listed, with their Match cells."""
    window._clients.set_query(text)
    settled(qt_app)
    table = window._clients._table
    match = column_of(table, "Match")
    return [
        (
            table.item(row, 0).data(CLIENT_ADDRESS),
            "" if table.isColumnHidden(match) else table.item(row, match).text(),
        )
        for row in range(table.rowCount())
        if not table.isRowHidden(row)
    ]


def test_typing_a_name_finds_a_client_with_no_matching_requests(
    qt_app: QApplication, case_dir: Path
) -> None:
    name_it(case_dir)
    window = opened(qt_app, case_dir)

    assert searched(qt_app, window, "office") == [(CLIENT, "by name")]
    window.close()


def test_a_client_found_both_ways_appears_once(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir, "passwd reader")
    window = opened(qt_app, case_dir)

    found = searched(qt_app, window, "passwd")

    assert found[0] == (CLIENT, "1, by name")
    assert [address for address, _ in found].count(CLIENT) == 1
    assert ("192.0.2.1", "1") in found
    window.close()


def test_a_name_with_a_digit_is_found(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir, "Attacker 2")
    window = opened(qt_app, case_dir)

    assert searched(qt_app, window, "attacker 2") == [(CLIENT, "by name")]
    window.close()


def test_a_filter_chip_turns_name_matching_off(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir)
    window = opened(qt_app, case_dir)

    assert searched(qt_app, window, "status:200 office") == []
    window.close()


def test_name_key_lists_only_named_clients(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir, "passwd reader")
    window = opened(qt_app, case_dir)

    assert searched(qt_app, window, "name:passwd") == [(CLIENT, "by name")]
    window.close()


def test_name_key_combines_with_a_status_filter(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir)
    window = opened(qt_app, case_dir)

    assert searched(qt_app, window, "name:office status:200") == [(CLIENT, "1, by name")]
    assert searched(qt_app, window, "name:office status:404") == []
    window.close()


def test_name_search_works_with_names_hidden(qt_app: QApplication, case_dir: Path) -> None:
    name_it(case_dir)
    window = opened(qt_app, case_dir)
    window._client_names_action.trigger()

    assert searched(qt_app, window, "office") == [(CLIENT, "by name")]
    window.close()


def test_a_single_address_without_name_matches_is_unchanged(
    qt_app: QApplication, case_dir: Path
) -> None:
    name_it(case_dir)
    window = opened(qt_app, case_dir)

    assert searched(qt_app, window, "192.0.2.1") == [("192.0.2.1", "")]
    window.close()


def test_the_exported_report_and_json_carry_the_name(
    qt_app: QApplication, case_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name_it(case_dir)
    window = opened_on_client(qt_app, case_dir)
    window._client_names_action.trigger()  # what the window shows does not decide the file
    report, data = tmp_path / "report.html", tmp_path / "graph.json"
    answers = iter([(str(report), ""), (str(data), "")])
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_a, **_k: next(answers))

    window._export("html")
    settled(qt_app)
    window._export("json")
    settled(qt_app)

    assert f"Office VPN ({CLIENT})" in report.read_text(encoding="utf-8")
    assert json.loads(data.read_text(encoding="utf-8"))["client_name"] == "Office VPN"
    window.close()
