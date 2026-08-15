"""The chooser that offers recently opened cases."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from logarc.gui.case_chooser import COLUMNS, CaseChooser
from logarc.gui.recent import RecentCase

WHEN = datetime(2026, 8, 15, 13, 4, tzinfo=UTC)


@pytest.fixture(scope="module")
def qt_app() -> QApplication:
    return QApplication.instance() or QApplication([])


def case(path: str, case_id: str = "case-001", events: int = 120) -> RecentCase:
    return RecentCase(
        path=path, case_id=case_id, opened_at=WHEN, events=events, sources=("views.log",)
    )


def test_every_case_gets_a_row(qt_app: QApplication, tmp_path) -> None:
    cases = tuple(case(str(tmp_path), f"case-{n}") for n in range(3))

    chooser = CaseChooser(cases, exists=lambda _p: True)

    assert chooser._table.rowCount() == 3


def test_the_folder_is_shown_because_names_repeat(qt_app: QApplication) -> None:
    """Two cases can be called the same thing. The folder is what tells them
    apart, and choosing from a name alone was the fault of the submenu this
    was picked over."""
    chooser = CaseChooser((case(r"D:\cases\alpha", "same"),), exists=lambda _p: True)

    row = [
        chooser._table.item(0, index).text()  # type: ignore[union-attr]
        for index in range(len(COLUMNS))
    ]

    assert any(r"D:\cases\alpha" in value for value in row)


def test_a_case_whose_folder_has_gone_cannot_be_opened(qt_app: QApplication) -> None:
    """Offering it would send the reader into a failure the list already knew
    about. It stays listed — the entry is a record of what was worked on — but
    it says so and cannot be chosen."""
    chooser = CaseChooser((case(r"D:\gone", "gone"),), exists=lambda _p: False)

    chooser._table.selectRow(0)

    assert chooser.chosen_path is None
    assert not chooser._open_button.isEnabled()
    name = chooser._table.item(0, COLUMNS.index("Case"))
    assert name is not None
    assert "missing" in name.text().lower()


def test_choosing_a_row_yields_its_folder(qt_app: QApplication) -> None:
    cases = (case(r"D:\cases\a", "a"), case(r"D:\cases\b", "b"))
    chooser = CaseChooser(cases, exists=lambda _p: True)

    chooser._table.selectRow(1)
    chooser._accept_selection()

    assert chooser.chosen_path == r"D:\cases\b"


def test_forgetting_clears_the_list(qt_app: QApplication) -> None:
    """A forensic tool records which investigations were opened on this machine.
    There has to be one action that takes that back."""
    chooser = CaseChooser((case(r"D:\cases\a", "a"),), exists=lambda _p: True)

    chooser._forget()

    assert chooser.forgotten
    assert chooser.chosen_path is None


def test_text_from_the_case_file_cannot_smuggle_control_characters(
    qt_app: QApplication,
) -> None:
    """`case_id` is read from a `case.json` on disk, which may have been edited
    since it was written. A cell is one line."""
    chooser = CaseChooser((case(r"D:\cases\a", "before\nafter"),), exists=lambda _p: True)

    shown = chooser._table.item(0, 0).text()  # type: ignore[union-attr]

    assert "\n" not in shown


# -- pinning, renaming, and dropping one entry -------------------------------


def pinned_case(path: str, case_id: str = "kept") -> RecentCase:
    return RecentCase(
        path=path,
        case_id=case_id,
        opened_at=WHEN,
        events=120,
        sources=("views.log",),
        pinned=True,
    )


def test_a_pinned_case_is_marked_in_the_list(qt_app: QApplication) -> None:
    chooser = CaseChooser((pinned_case(r"D:\a"), case(r"D:\b", "b")), exists=lambda _p: True)

    marks = [chooser._table.item(row, 0).text() for row in range(2)]  # type: ignore[union-attr]

    assert marks[0].strip(), "the pinned one carries a mark"
    assert not marks[1].strip(), "and the other does not"


def test_pinning_from_the_menu_moves_it_to_the_top(qt_app: QApplication) -> None:
    chooser = CaseChooser((case(r"D:\a", "a"), case(r"D:\b", "b")), exists=lambda _p: True)

    chooser._table.selectRow(1)
    chooser._toggle_pin()

    assert chooser.cases[0].case_id == "b"
    assert chooser.cases[0].pinned
    assert chooser.changed


def test_renaming_shows_the_new_name_and_leaves_the_case_alone(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The name belongs to this list. `case.json` is not touched, so a report
    exported before and one after agree about what the case is called."""
    from logarc.gui import case_chooser

    monkeypatch.setattr(case_chooser, "_ask_for_a_name", lambda *_a, **_k: "acme-breach (jan)")
    chooser = CaseChooser((case(r"D:\a", "case-001"),), exists=lambda _p: True)

    chooser._table.selectRow(0)
    chooser._rename()

    assert chooser.cases[0].display_name == "acme-breach (jan)"
    assert chooser.cases[0].case_id == "case-001"
    assert "acme-breach (jan)" in chooser._table.item(0, 1).text()  # type: ignore[union-attr]


def test_a_cancelled_rename_changes_nothing(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    from logarc.gui import case_chooser

    monkeypatch.setattr(case_chooser, "_ask_for_a_name", lambda *_a, **_k: None)
    chooser = CaseChooser((case(r"D:\a", "case-001"),), exists=lambda _p: True)

    chooser._table.selectRow(0)
    chooser._rename()

    assert chooser.cases[0].display_name == "case-001"
    assert not chooser.changed


def test_a_name_cannot_smuggle_a_line_break_into_a_row(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Typed by the reader rather than an attacker, but a cell is still one line
    and a pasted name can carry anything."""
    from logarc.gui import case_chooser

    monkeypatch.setattr(case_chooser, "_ask_for_a_name", lambda *_a, **_k: "before\nafter")
    chooser = CaseChooser((case(r"D:\a", "a"),), exists=lambda _p: True)

    chooser._table.selectRow(0)
    chooser._rename()

    assert "\n" not in chooser._table.item(0, 1).text()  # type: ignore[union-attr]


def test_dropping_one_entry_leaves_the_others(qt_app: QApplication) -> None:
    chooser = CaseChooser((case(r"D:\a", "a"), case(r"D:\b", "b")), exists=lambda _p: True)

    chooser._table.selectRow(0)
    chooser._remove()

    assert [entry.case_id for entry in chooser.cases] == ["b"]
    assert chooser._table.rowCount() == 1


def test_a_missing_case_can_still_be_pinned_and_dropped(qt_app: QApplication) -> None:
    """Its folder is gone, but the entry is a record of what was worked on and
    the reader has to be able to tidy it away."""
    chooser = CaseChooser((case(r"D:\gone", "gone"),), exists=lambda _p: False)

    chooser._table.selectRow(0)
    chooser._remove()

    assert chooser.cases == ()
