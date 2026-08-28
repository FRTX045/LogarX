"""The screen where a reader writes a log format and tries it before saving.

Run without a display. What the preview *says* is tested next door; this is
about the screen around it — that a built-in cannot be edited into something
else, that saving reaches the library, and that a format saved here is
immediately choosable at ingest.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from logarc.gui.format_editor import FormatChoice, FormatEditor
from logarc.parsers.apache import COMBINED
from logarc.parsers.library import load_library, save_library
from logarc.parsers.registry import register_saved_formats
from logarc.parsers.spec import LogFormatSpec

PIPED = '%h|%t|"%r"|%>s|%b'
PIPED_LINE = '203.0.113.5|[10/Oct/2020:13:55:36 +0000]|"GET /.env HTTP/1.1"|404|0'


@pytest.fixture
def saved_office() -> LogFormatSpec:
    spec = LogFormatSpec(name="log-kantor", directive=PIPED, description="the office")
    save_library([spec])
    register_saved_formats()
    return spec


# -- what it lists ---------------------------------------------------------


def test_every_built_in_is_listed(qt_app: QApplication) -> None:
    editor = FormatEditor()

    assert "apache-combined" in editor.listed()


def test_a_saved_format_is_listed_too(qt_app: QApplication, saved_office: LogFormatSpec) -> None:
    editor = FormatEditor()

    assert "log-kantor" in editor.listed()


# -- built-ins are readable, not editable ----------------------------------


def test_selecting_a_built_in_fills_the_fields(qt_app: QApplication) -> None:
    editor = FormatEditor()

    editor.select("apache-combined")

    assert editor._directive.text() == COMBINED


def test_a_built_in_cannot_be_edited_or_deleted(qt_app: QApplication) -> None:
    """Registration order is preference order and built-ins come first, so an
    edited copy would never be reached — and a case recording the name would
    quietly start meaning something else."""
    editor = FormatEditor()

    editor.select("apache-combined")

    assert not editor._directive.isEnabled()
    assert not editor._save.isEnabled()
    assert not editor._delete.isEnabled()


def test_a_built_in_can_still_be_tried_against_a_log_line(qt_app: QApplication) -> None:
    """Reading is not editing. Checking whether a preset already reads your log
    is the first thing worth doing, and the cheapest."""
    editor = FormatEditor()
    editor.select("apache-combined")

    editor._sample.setPlainText(PIPED_LINE)

    assert not editor.preview().ok  # a piped line, so no — but it was tried
    assert editor._sample.isEnabled()


def test_a_saved_format_is_editable(qt_app: QApplication, saved_office: LogFormatSpec) -> None:
    editor = FormatEditor()

    editor.select("log-kantor")

    assert editor._directive.isEnabled()
    assert editor._delete.isEnabled()
    assert editor._note.text() == "the office"


# -- writing one -----------------------------------------------------------


def test_a_written_format_reaches_the_library(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._name.setText("log-kantor")
    editor._directive.setText(PIPED)
    editor._note.setText("the office")

    editor.save()

    assert load_library() == [
        LogFormatSpec(name="log-kantor", directive=PIPED, description="the office")
    ]


def test_a_written_format_can_be_used_straight_away(qt_app: QApplication) -> None:
    """Saved but not registered, it would be in the file and absent from every
    list that offers it — the reader would have to restart the application."""
    editor = FormatEditor()
    editor.start_new()
    editor._name.setText("log-kantor")
    editor._directive.setText(PIPED)

    editor.save()

    assert "log-kantor" in FormatChoice().offered()


def test_a_name_already_taken_by_a_built_in_is_refused(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._name.setText("apache-combined")
    editor._directive.setText(PIPED)

    saved = editor.save()

    assert not saved
    assert "apache-combined" in editor.trouble()
    assert load_library() == []


def test_a_directive_that_will_not_compile_is_refused(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._name.setText("broken")
    editor._directive.setText("no percent signs")

    saved = editor.save()

    assert not saved
    assert load_library() == []


def test_a_format_with_no_name_is_refused(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._directive.setText(PIPED)

    assert not editor.save()
    assert load_library() == []


def test_editing_a_saved_format_replaces_it_rather_than_adding_a_second(
    qt_app: QApplication, saved_office: LogFormatSpec
) -> None:
    editor = FormatEditor()
    editor.select("log-kantor")
    editor._directive.setText(f"{PIPED}|%{{Referer}}i")

    assert editor.save()
    assert [spec.name for spec in load_library()] == ["log-kantor"]
    assert load_library()[0].directive.endswith("%{Referer}i")


def test_a_saved_format_can_be_deleted(qt_app: QApplication, saved_office: LogFormatSpec) -> None:
    editor = FormatEditor()
    editor.select("log-kantor")

    editor.delete()

    assert load_library() == []
    assert "log-kantor" not in editor.listed()


# -- the preview, wired up -------------------------------------------------


def test_the_preview_follows_what_is_typed(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._sample.setPlainText(PIPED_LINE)

    editor._directive.setText(PIPED)

    assert editor.preview().ok
    assert dict(editor.preview().fields)["Path"] == "/.env"


def test_the_preview_shows_the_trouble_before_it_becomes_a_case(
    qt_app: QApplication,
) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._sample.setPlainText(PIPED_LINE)
    editor._directive.setText(COMBINED)

    assert not editor.preview().ok
    assert "does not" in editor._status.text().lower()


# -- choosing one at ingest ------------------------------------------------


def test_detecting_the_format_is_the_default(qt_app: QApplication) -> None:
    """It is what every ingest did before there was a choice, and it is right
    far more often than not. A default of 'pick one' would make the common
    case worse to serve the rare one."""
    chooser = FormatChoice()

    assert chooser.chosen() is None


def test_every_format_is_offered(qt_app: QApplication, saved_office: LogFormatSpec) -> None:
    chooser = FormatChoice()

    offered = chooser.offered()

    assert "apache-combined" in offered
    assert "log-kantor" in offered


def test_the_chosen_format_comes_back_by_name(
    qt_app: QApplication, saved_office: LogFormatSpec
) -> None:
    chooser = FormatChoice()

    chooser.choose("log-kantor")

    assert chooser.chosen() == "log-kantor"


# -- what showing the dialog must not do -----------------------------------


def test_showing_the_dialog_does_not_overwrite_a_half_written_format(
    qt_app: QApplication,
) -> None:
    """Found by looking at a screenshot, not by a test.

    `QListWidget` makes row 0 current the first time it is shown if nothing is,
    and that fired the selection handler, which loaded that format over the top
    of what had been typed. Nothing about the code says so — the wiped fields
    were simply there in the picture.
    """
    editor = FormatEditor()
    editor.start_new()
    editor._name.setText("log-kantor")
    editor._directive.setText(PIPED)

    editor.show()
    qt_app.processEvents()

    assert editor._name.text() == "log-kantor"
    assert editor._directive.text() == PIPED
    assert editor._name.isEnabled(), "the fields were switched to a built-in's"


def test_the_dialog_opens_on_something_rather_than_a_blank_right_hand_side(
    qt_app: QApplication,
) -> None:
    editor = FormatEditor()
    editor.show()
    qt_app.processEvents()

    assert editor._formats.currentRow() >= 0


def test_the_two_kinds_of_format_are_kept_apart_in_the_list(
    qt_app: QApplication, saved_office: LogFormatSpec
) -> None:
    """One ships with logarc and cannot be edited, the other is the reader's
    and can. Told apart only by what happens when you click them, the reader
    finds that out by being refused."""
    editor = FormatEditor()

    rows = [
        editor._formats.item(row).text()
        for row in range(editor._formats.count())
        if editor._formats.item(row) is not None
    ]

    assert "Built in" in rows
    assert "Saved by you" in rows
    assert rows.index("Built in") < rows.index("apache-combined")
    assert rows.index("Saved by you") < rows.index("log-kantor")


def test_a_heading_is_not_offered_as_a_format(
    qt_app: QApplication, saved_office: LogFormatSpec
) -> None:
    editor = FormatEditor()

    assert "Built in" not in editor.listed()
    assert "Saved by you" not in editor.listed()
    assert "log-kantor" in editor.listed()


# -- picking up what the library already holds ------------------------------


def test_a_format_saved_elsewhere_is_there_when_the_screen_opens(
    qt_app: QApplication,
) -> None:
    """Saved by `logarc formats add`, or in another window, or by hand.

    Nothing in the application installed saved formats at startup: they were
    registered only as a side effect of saving one *here*. So a reader who
    wrote a format on the command line opened the window and could not find
    it. Every test above hid this by calling `register_saved_formats` itself.
    """
    save_library([LogFormatSpec(name="log-kantor", directive=PIPED)])

    assert "log-kantor" in FormatEditor().listed()


def test_a_format_saved_elsewhere_is_offered_at_ingest(qt_app: QApplication) -> None:
    save_library([LogFormatSpec(name="log-kantor", directive=PIPED)])

    assert "log-kantor" in FormatChoice().offered()


def test_a_format_deleted_elsewhere_stops_being_offered(qt_app: QApplication) -> None:
    """The other half of the same reconciliation. A screen that only ever added
    would go on offering a format the file no longer holds, and choosing it
    would build a case from a definition the reader thought they had removed."""
    save_library([LogFormatSpec(name="log-kantor", directive=PIPED)])
    assert "log-kantor" in FormatChoice().offered(), "premise: it was offered"

    save_library([])

    assert "log-kantor" not in FormatChoice().offered()


def test_a_name_the_list_itself_uses_is_refused(qt_app: QApplication) -> None:
    """The list holds three kinds of row: the blank form, two group headings,
    and the formats. A format named after one of the others would be selected
    by the wrong branch and edited as something it is not."""
    editor = FormatEditor()

    for reserved in ("New format…", "Built in", "Saved by you"):
        editor.start_new()
        editor._name.setText(reserved)
        editor._directive.setText(PIPED)

        assert not editor.save(), f"{reserved!r} was accepted as a format name"

    assert load_library() == []
