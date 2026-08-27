"""The chooser that offers recently opened cases."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QDialog

from colours import contrast
from logarc.gui.case_chooser import COLUMNS, CaseChooser
from logarc.gui.recent import RecentCase
from logarc.gui.style import PIN_COLOUR, PIN_MARK, THEME

WHEN = datetime(2026, 8, 15, 13, 4, tzinfo=UTC)


def case(path: str, case_id: str = "case-001", events: int = 120) -> RecentCase:
    return RecentCase(
        path=path, case_id=case_id, opened_at=WHEN, events=events, sources=("views.log",)
    )


def test_the_two_other_ways_out_are_not_mixed_up(qt_app: QApplication) -> None:
    """Each button sets one flag, and the window opens a different dialog for
    each — a folder picker for a case that already exists, an ingest for a new
    one. Swapping them sends the reader to the wrong dialog, and nothing else
    would notice: both flags are booleans on the same object."""
    chooser = CaseChooser((case("/a"),), exists=lambda _p: True)

    chooser._choose_other()

    assert chooser.wants_other_case
    assert not chooser.wants_new_case
    assert chooser.chosen_path is None

    again = CaseChooser((case("/a"),), exists=lambda _p: True)
    again._choose_new()

    assert again.wants_new_case
    assert not again.wants_other_case


@pytest.mark.parametrize("action", ["_toggle_pin", "_rename", "_remove", "_show_folder"])
def test_a_row_action_with_nothing_selected_does_nothing(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """The menu is opened by right-clicking a row, so a selection normally
    exists — but the same slots are reachable with none, and every one of them
    indexes `self.cases[row]`. Without the guard that is an exception out of a
    context menu; with it, nothing happens, which is the right nothing."""
    from logarc.gui import case_chooser

    monkeypatch.setattr(case_chooser, "_ask_for_a_name", lambda *_a, **_k: "new name")
    chooser = CaseChooser((case("/a"), case("/b")), exists=lambda _p: True)
    chooser._table.clearSelection()
    before = chooser.cases

    getattr(chooser, action)()

    assert chooser.cases == before
    assert not chooser.changed


def test_the_menu_offers_to_undo_what_is_already_done(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pinned case is offered "Unpin", not "Pin to the top". Inverted, the
    entry describes the state rather than the action, and clicking what reads as
    "pin this" unpins it."""
    from PyQt6.QtCore import QPoint
    from PyQt6.QtWidgets import QMenu

    labels: list[str] = []
    monkeypatch.setattr(QMenu, "exec", lambda self, *_a: None)
    monkeypatch.setattr(
        QMenu,
        "addAction",
        lambda self, text: (labels.append(text), QMenu.__bases__[0].addAction(self, text))[1],
    )

    chooser = CaseChooser((case("/a"), replace(case("/b"), pinned=True)), exists=lambda _p: True)
    chooser._table.selectRow(0)
    chooser._show_menu(QPoint(1, 1))
    unpinned_first = labels[0]

    labels.clear()
    # The pinned one sorts to the top, so row 0 is the pinned case there.
    pinned = CaseChooser((replace(case("/b"), pinned=True),), exists=lambda _p: True)
    pinned._table.selectRow(0)
    pinned._show_menu(QPoint(1, 1))

    assert unpinned_first == "Pin to the top"
    assert labels[0] == "Unpin"


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
    There has to be one action that takes that back.

    It used to be a flag the window read as "wipe everything". It is now the
    ordinary path — remove what is highlighted — reaching the same end, because
    `_refill` selects the only row there is.
    """
    chooser = CaseChooser((case(r"D:\cases\a", "a"),), exists=lambda _p: True)

    chooser._forget()

    assert chooser.cases == ()
    assert chooser.changed
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


# -- forgetting several at a time ------------------------------------------


def five() -> tuple[RecentCase, ...]:
    return tuple(case(rf"D:\cases\{name}", name) for name in ("a", "b", "c", "d", "e"))


def _select(chooser: CaseChooser, *rows: int) -> None:
    """Highlight several rows, the way Ctrl-click does.

    Not `selectRow` in a loop: that clears the previous selection each time and
    leaves exactly one row highlighted, which would let a test claiming three
    pass while exercising one. Found while drawing the demo for this.
    """
    table = chooser._table
    model = table.model()
    selection = table.selectionModel()
    assert model is not None and selection is not None
    table.clearSelection()
    for row in rows:
        selection.select(
            model.index(row, 0),
            selection.SelectionFlag.Select | selection.SelectionFlag.Rows,
        )
    assert len(selection.selectedRows()) == len(rows), "premise: all of them are selected"


def test_forgetting_several_leaves_the_others(qt_app: QApplication) -> None:
    chooser = CaseChooser(five(), exists=lambda _p: True)
    _select(chooser, 0, 2, 3)

    chooser._forget()

    assert [entry.case_id for entry in chooser.cases] == ["b", "e"]
    assert chooser.changed


def test_forgetting_does_not_close_the_chooser(qt_app: QApplication) -> None:
    """The whole point. A reader with several unwanted entries had to reopen
    this dialog once per entry, because the only visible control shut it."""
    chooser = CaseChooser(five(), exists=lambda _p: True)
    chooser.show()
    _select(chooser, 0)

    chooser._forget()

    assert chooser.isVisible()
    assert chooser.result() == QDialog.DialogCode.Rejected, "nothing was accepted"

    # Again, without reopening anything, which was impossible before.
    _select(chooser, 0)
    chooser._forget()

    assert len(chooser.cases) == 3
    assert chooser.isVisible()
    chooser.close()


def test_forgetting_every_row_empties_the_list(qt_app: QApplication) -> None:
    """Ctrl+A then the button. This is what keeps the promise that the record of
    what was investigated here can be taken off the machine — the button no
    longer wipes the list on its own, so the gesture has to reach the same end."""
    chooser = CaseChooser(five(), exists=lambda _p: True)
    chooser._table.selectAll()

    chooser._forget()

    assert chooser.cases == ()
    assert chooser.changed


def test_the_button_refuses_an_empty_selection(qt_app: QApplication) -> None:
    chooser = CaseChooser(five(), exists=lambda _p: True)
    chooser._table.clearSelection()

    assert not chooser._forget_button.isEnabled()

    chooser._forget()

    assert len(chooser.cases) == 5, "nothing selected, nothing removed"


def test_open_wants_exactly_one_case(qt_app: QApplication) -> None:
    """Selecting several is now ordinary, and `Open` has no answer for two.
    Disabled rather than opening the first, which would be a guess presented as
    a choice."""
    chooser = CaseChooser(five(), exists=lambda _p: True)

    _select(chooser, 1)
    assert chooser._open_button.isEnabled()

    _select(chooser, 1, 2)
    assert not chooser._open_button.isEnabled()

    chooser._accept_selection()
    assert chooser.chosen_path is None


def test_a_right_click_inside_a_selection_keeps_it(qt_app: QApplication) -> None:
    """Right-clicking one of several highlighted rows must not throw the rest
    away — the reader has just built that selection and is about to act on it.
    Outside the selection it replaces it, which is what every file list does."""
    chooser = CaseChooser(five(), exists=lambda _p: True)
    _select(chooser, 0, 1, 2)

    chooser._aim_menu_at(1)
    assert chooser._selected_rows() == (0, 1, 2)

    chooser._aim_menu_at(4)
    assert chooser._selected_rows() == (4,)


def test_the_per_row_commands_want_one_row(qt_app: QApplication) -> None:
    """Pin, rename and show-the-folder act on one case and have no meaning for
    three. They ask for one and get nothing rather than silently taking the
    first, which would act on a case the reader never singled out."""
    chooser = CaseChooser(five(), exists=lambda _p: True)
    _select(chooser, 1, 3)

    assert chooser._selected_row() is None

    before = chooser.cases
    chooser._toggle_pin()

    assert chooser.cases == before, "an ambiguous selection pins nothing"


def test_the_pin_mark_is_drawn_in_the_theme_rather_than_by_the_font(
    qt_app: QApplication,
) -> None:
    """An emoji is painted by the font, in its own colours, so the palette has
    no say over it. The pushpin arrived red — the one hue this interface
    reserves for `THEME.alert`, meaning something is wrong with the evidence —
    on a row that is merely being held at the top.
    """
    assert not any(0x1F300 <= ord(char) <= 0x1FAFF for char in PIN_MARK), (
        "a pictographic emoji brings its own colour and ignores PIN_COLOUR"
    )
    # Asserted against the palette, not against PIN_COLOUR: comparing the cell
    # to the constant that set it passes whatever that constant becomes, so it
    # proves the wiring and says nothing about the colour. Red is reserved.
    assert THEME.alert != PIN_COLOUR, (
        "red means something is wrong with this evidence; a pinned case is not that"
    )
    assert contrast(PIN_COLOUR, THEME.surface) >= 3.0, "the mark has to be visible"

    cases = list(five())
    cases[1] = replace(cases[1], pinned=True)
    chooser = CaseChooser(tuple(cases), exists=lambda _p: True)

    marked = chooser._table.item(1, 0)
    assert marked is not None
    assert marked.text() == PIN_MARK
    assert marked.foreground().color().name() == PIN_COLOUR

    unmarked = chooser._table.item(0, 0)
    assert unmarked is not None
    assert unmarked.text() == "", "premise: only the pinned row carries the mark"


def test_the_rows_keep_the_height_the_header_asks_for(qt_app: QApplication) -> None:
    """Forgetting a case redraws the table, and it used to come back tighter:
    33px rows becoming 20px on a redraw that removed nothing.
    `resizeRowsToContents` sizes to the text, and every row here is a single
    line of it, so it bought nothing and cost the dialog its proportions.

    Latent while the only way to trigger a redraw was a right-click command few
    people found. `Forget these` makes it the ordinary path.

    **Asserted against the header's own default rather than against the height
    before the redraw**, because the before-and-after form cannot see this
    fault. The suite runs offscreen, where there are no fonts and text measures
    97px whatever it says — so the rows were 97 before and 97 after, unchanged
    and wrong, while a real window went 33 to 20. Compared with the default,
    both platforms fail while the resize is there and both pass without it.
    """
    chooser = CaseChooser(five(), exists=lambda _p: True)
    chooser.show()
    qt_app.processEvents()

    header = chooser._table.verticalHeader()
    assert header is not None
    wanted = header.defaultSectionSize()

    for stage in ("on opening", "after a redraw"):
        heights = {chooser._table.rowHeight(row) for row in range(chooser._table.rowCount())}
        assert heights == {wanted}, f"{stage}: rows are {heights}, header asks for {wanted}"
        chooser._refill()
        qt_app.processEvents()

    chooser.close()
