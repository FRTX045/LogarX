"""The screen where a reader writes a log format and tries it before saving.

Run without a display. What the preview *says* is tested next door; this is
about the screen around it — that a built-in cannot be edited into something
else, that saving reaches the library, and that a format saved here is
immediately choosable at ingest.
"""

from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from logarc.gui.format_editor import FormatChoice, FormatEditor
from logarc.parsers.apache import COMBINED
from logarc.parsers.fieldnames import MAPPABLE
from logarc.parsers.library import FormatLibraryError, library_path, load_library, save_library
from logarc.parsers.registry import register_format, register_saved_formats, unregister_format
from logarc.parsers.spec import (
    ColumnsFormatSpec,
    JsonFormatSpec,
    LogFormatSpec,
    PatternFormatSpec,
)

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

    assert editor._rule.text() == COMBINED


def test_a_built_in_cannot_be_edited_or_deleted(qt_app: QApplication) -> None:
    """Registration order is preference order and built-ins come first, so an
    edited copy would never be reached — and a case recording the name would
    quietly start meaning something else."""
    editor = FormatEditor()

    editor.select("apache-combined")

    assert not editor._rule.isEnabled()
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

    assert editor._rule.isEnabled()
    assert editor._delete.isEnabled()
    assert editor._note.text() == "the office"


# -- writing one -----------------------------------------------------------


def test_a_written_format_reaches_the_library(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._name.setText("log-kantor")
    editor._rule.setText(PIPED)
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
    editor._rule.setText(PIPED)

    editor.save()

    assert "log-kantor" in FormatChoice().offered()


def test_a_name_already_taken_by_a_built_in_is_refused(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._name.setText("apache-combined")
    editor._rule.setText(PIPED)

    saved = editor.save()

    assert not saved
    assert "apache-combined" in editor.trouble()
    assert load_library() == []


def test_a_directive_that_will_not_compile_is_refused(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._name.setText("broken")
    editor._rule.setText("no percent signs")

    saved = editor.save()

    assert not saved
    assert load_library() == []


def test_a_format_with_no_name_is_refused(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._rule.setText(PIPED)

    assert not editor.save()
    assert load_library() == []


def test_editing_a_saved_format_replaces_it_rather_than_adding_a_second(
    qt_app: QApplication, saved_office: LogFormatSpec
) -> None:
    editor = FormatEditor()
    editor.select("log-kantor")
    editor._rule.setText(f"{PIPED}|%{{Referer}}i")

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

    editor._rule.setText(PIPED)

    assert editor.preview().ok
    assert dict(editor.preview().fields)["Path"] == "/.env"


def test_the_preview_shows_the_trouble_before_it_becomes_a_case(
    qt_app: QApplication,
) -> None:
    editor = FormatEditor()
    editor.start_new()
    editor._sample.setPlainText(PIPED_LINE)
    editor._rule.setText(COMBINED)

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
    editor._rule.setText(PIPED)

    editor.show()
    qt_app.processEvents()

    assert editor._name.text() == "log-kantor"
    assert editor._rule.text() == PIPED
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

    assert rows.index("CUSTOM") < rows.index("Untitled") < rows.index("log-kantor")
    assert rows.index("log-kantor") < rows.index("BUILT-IN") < rows.index("apache-combined")


def test_a_heading_is_not_offered_as_a_format(
    qt_app: QApplication, saved_office: LogFormatSpec
) -> None:
    editor = FormatEditor()

    assert "BUILT-IN" not in editor.listed()
    assert "CUSTOM" not in editor.listed()
    assert "Untitled" not in editor.listed()
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

    for reserved in ("Untitled", "CUSTOM", "BUILT-IN"):
        editor.start_new()
        editor._name.setText(reserved)
        editor._rule.setText(PIPED)

        assert not editor.save(), f"{reserved!r} was accepted as a format name"

    assert load_library() == []


def test_renaming_a_saved_format_renames_it_rather_than_leaving_a_twin(
    qt_app: QApplication, saved_office: LogFormatSpec
) -> None:
    """Changing the name of a format you are editing is a rename.

    The alternative — keeping the old one and adding a new — was written into a
    comment here and contradicted by the code beside it, so nobody had decided.
    Rename is the reading that matches the gesture: a reader who wanted two
    formats would have started a new one. Cases ingested under the old name are
    unaffected either way; each carries its own copy of the definition.
    """
    editor = FormatEditor()
    editor.select("log-kantor")

    editor._name.setText("log-kantor-lama")

    assert editor.save()
    assert [spec.name for spec in load_library()] == ["log-kantor-lama"]


# -- the corners ------------------------------------------------------------


def test_a_format_registered_from_code_is_shown_and_cannot_be_edited(
    qt_app: QApplication,
) -> None:
    """`register_format` takes a factory. There is code behind the name and no
    definition to show, let alone edit — and none to write into a case either,
    which is why it is listed rather than hidden: seeing it is how a reader
    learns the name their case will record."""

    class Nothing:
        name = "from-code"

        def parse_line(self, line: str, ref: object) -> None:
            return None

    register_format("from-code", Nothing)
    try:
        editor = FormatEditor()
        editor.select("from-code")

        assert "from-code" in editor.listed()
        assert editor._name.text() == "from-code"
        assert editor._rule.text() == ""
        assert not editor._rule.isEnabled()
        assert not editor._save.isEnabled()
    finally:
        unregister_format("from-code")


def test_a_damaged_library_does_not_stop_the_screen_opening(qt_app: QApplication) -> None:
    """A reader who has broken their library file is exactly the one who needs
    somewhere to write a format. The CLI reports the damage on every command;
    refusing to open here as well would leave them nowhere to go."""
    library_path().parent.mkdir(parents=True, exist_ok=True)
    library_path().write_text("{not json", encoding="utf-8")

    editor = FormatEditor()

    assert "apache-combined" in editor.listed()
    assert str(library_path()) in editor._status.text(), (
        "the screen opened but said nothing, so the reader has no idea their "
        "saved formats are missing rather than never written"
    )


def test_a_damaged_library_is_said_where_a_format_is_chosen_too(qt_app: QApplication) -> None:
    """The other screen reading it. Silence here is worse: the list simply has
    no saved formats in it, which is indistinguishable from having saved none."""
    library_path().parent.mkdir(parents=True, exist_ok=True)
    library_path().write_text("{not json", encoding="utf-8")

    chooser = FormatChoice()

    assert chooser.chosen() is None
    assert str(library_path()) in chooser._library_trouble


def test_a_library_that_will_not_take_a_write_is_reported_not_raised(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read-only config directory, a full disk. The screen has to say so
    where the reader is looking, not raise into the crash handler."""
    from logarc.gui import format_editor as module

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise FormatLibraryError("the library could not be written")

    monkeypatch.setattr(module, "save_library", refuse)

    editor = FormatEditor()
    editor.start_new()
    editor._name.setText("log-kantor")
    editor._rule.setText(PIPED)

    assert not editor.save()
    assert "could not be written" in editor.trouble()


def test_the_manage_button_reopens_the_chooser_on_what_was_written(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The chooser offers formats; the editor writes them. A format written
    without leaving the ingest flow has to be choosable in the list behind."""
    from logarc.gui import formats_and_rules

    def write_one(self: formats_and_rules.FormatsAndRules) -> int:
        save_library([LogFormatSpec(name="log-kantor", directive=PIPED)])
        return 1

    # The dialog Manage formats opens since the rules tab joined it.
    monkeypatch.setattr(formats_and_rules.FormatsAndRules, "exec", write_one)

    chooser = FormatChoice()
    assert "log-kantor" not in chooser.offered(), "premise: not there yet"

    chooser._manage()

    assert "log-kantor" in chooser.offered()


def test_the_chooser_keeps_what_was_chosen_when_the_list_is_rebuilt(
    qt_app: QApplication, saved_office: LogFormatSpec
) -> None:
    """Otherwise a trip to the editor silently resets the choice back to
    detection, and the ingest reads with something the reader did not pick."""
    chooser = FormatChoice()
    chooser.choose("log-kantor")

    chooser._fill()

    assert chooser.chosen() == "log-kantor"


# ---------------------------------------------------------------------------
# The other kind of format: a JSON mapping
# ---------------------------------------------------------------------------

GATEWAY_LINE = json.dumps(
    {
        "time": "2024-05-01T09:00:45+00:00",
        "remote_addr": "203.0.113.77",
        "request": "GET /admin/0.php HTTP/1.1",
        "status": 404,
        "trace_id": "abc123",
    }
)

SAVED_JSON = JsonFormatSpec(
    name="gateway",
    fields=(("timestamp", "time"), ("client_ip", "remote_addr"), ("status", "status")),
    description="the API gateway",
)


@pytest.fixture
def saved_gateway() -> JsonFormatSpec:
    save_library([SAVED_JSON])
    register_saved_formats()
    return SAVED_JSON


def test_both_kinds_of_format_can_be_started(qt_app: QApplication) -> None:
    """A single 'New format…' row could not say which kind, and asking after
    the fact means the reader types a directive into a screen that wanted a
    mapping."""
    editor = FormatEditor()

    rows = [
        editor._formats.item(row).text()
        for row in range(editor._formats.count())
        if editor._formats.item(row) is not None
    ]

    assert not [row for row in rows if row.startswith("New ")], "commands are not rows"
    assert [action.text() for action in editor.new_button.menu().actions()] == [
        "Text (LogFormat)",
        "JSON",
        "Table (CSV, TSV, W3C)",
        "Pattern (regular expression)",
    ]


def test_starting_a_json_format_shows_the_mapping_and_hides_the_directive(
    qt_app: QApplication,
) -> None:
    editor = FormatEditor()

    editor.start_new_json()

    assert editor._mapping.isVisible() or not editor.isVisible()
    assert not editor._rule.isVisible() or not editor.isVisible()
    assert editor.kind() == "json"


def test_selecting_a_text_format_switches_back(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_json()

    editor.select("apache-combined")

    assert editor.kind() == "logformat"
    assert editor._rule.text() == COMBINED


def test_a_saved_json_format_fills_the_mapping(
    qt_app: QApplication, saved_gateway: JsonFormatSpec
) -> None:
    editor = FormatEditor()

    editor.select("gateway")

    assert editor.kind() == "json"
    assert dict(editor.mapping()) == {
        "timestamp": "time",
        "client_ip": "remote_addr",
        "status": "status",
    }
    assert editor._note.text() == "the API gateway"


def test_the_mapping_offers_a_row_for_every_field_logarc_records(
    qt_app: QApplication,
) -> None:
    """Fixed rows rather than an add-a-row list: which fields can be mapped is
    the decision the reader is making, and a list they have to populate hides
    the ones they have not thought of."""
    editor = FormatEditor()
    editor.start_new_json()

    ours = [editor._mapping.item(row, 0).text() for row in range(editor._mapping.rowCount())]

    assert ours == list(MAPPABLE)


def test_the_mapping_is_guessed_from_the_pasted_line(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_json()
    editor._sample.setPlainText(GATEWAY_LINE)

    editor.guess()

    assert dict(editor.mapping())["client_ip"] == "remote_addr"
    assert editor.preview().ok


def test_guessing_from_a_line_that_is_not_json_says_so(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_json()
    editor._sample.setPlainText("203.0.113.5 - - [10/Oct/2000] ...")

    editor.guess()

    assert editor.mapping() == ()
    assert "JSON" in editor._status.text()


def test_a_json_format_written_here_reaches_the_library(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_json()
    editor._name.setText("gateway")
    editor._sample.setPlainText(GATEWAY_LINE)
    editor.guess()

    assert editor.save(), editor.trouble()
    saved = load_library()[0]
    assert isinstance(saved, JsonFormatSpec)
    assert dict(saved.fields)["client_ip"] == "remote_addr"


def test_a_mapping_without_a_timestamp_is_refused_with_a_message(
    qt_app: QApplication,
) -> None:
    editor = FormatEditor()
    editor.start_new_json()
    editor._name.setText("half")
    editor.set_mapping((("client_ip", "remote_addr"),))

    assert not editor.save()
    assert "timestamp" in editor.trouble()
    assert load_library() == []


def test_a_time_format_written_for_a_json_log_is_kept(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_json()
    editor._name.setText("odd")
    editor.set_mapping((("timestamp", "t"), ("client_ip", "ip")))
    editor._time_format.setText("%d/%b/%Y %H:%M:%S %z")

    assert editor.save(), editor.trouble()
    assert load_library()[0].time_format == "%d/%b/%Y %H:%M:%S %z"


def test_a_json_format_can_be_chosen_at_ingest_like_any_other(
    qt_app: QApplication, saved_gateway: JsonFormatSpec
) -> None:
    assert "gateway" in FormatChoice().offered()


def test_the_preview_reads_a_json_line_through_the_mapping(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_json()
    editor._sample.setPlainText(GATEWAY_LINE)
    editor.guess()

    result = editor.preview()

    assert result.ok
    assert dict(result.fields)["Path"] == "/admin/0.php"
    assert ("trace_id", "abc123") in result.extra


# ---------------------------------------------------------------------------
# The third kind: a table whose columns may be in the log
# ---------------------------------------------------------------------------

IIS_SAMPLE = "\n".join(
    [
        "#Software: Microsoft Internet Information Services 10.0",
        "#Fields: date time c-ip cs-method cs-uri-stem sc-status",
        "2024-05-01 09:00:45 203.0.113.77 GET /admin/0.php 404",
    ]
)

SAVED_TABLE = ColumnsFormatSpec(
    name="iis",
    fields=(("timestamp", "date+time"), ("client_ip", "c-ip"), ("status", "sc-status")),
    separator=" ",
    description="the web server",
)


def test_a_table_format_can_be_started(qt_app: QApplication) -> None:
    editor = FormatEditor()

    rows = [
        editor._formats.item(row).text()
        for row in range(editor._formats.count())
        if editor._formats.item(row) is not None
    ]

    assert "Untitled" in rows


def test_starting_a_table_shows_the_separator_and_the_columns(
    qt_app: QApplication,
) -> None:
    editor = FormatEditor()
    editor.show()
    qt_app.processEvents()

    editor.start_new_columns()

    assert editor.kind() == "columns"
    assert editor._separator.isVisible()
    assert editor._columns.isVisible()
    assert editor._mapping.isVisible()
    assert not editor._rule.isVisible()


def test_a_json_format_does_not_show_the_table_controls(qt_app: QApplication) -> None:
    """They mean nothing there, and a control that means nothing is a question
    the reader has to answer before they realise it was not being asked."""
    editor = FormatEditor()
    editor.show()
    qt_app.processEvents()

    editor.start_new_json()

    assert not editor._separator.isVisible()
    assert not editor._columns.isVisible()


def test_the_columns_and_the_mapping_are_guessed_from_the_pasted_lines(
    qt_app: QApplication,
) -> None:
    editor = FormatEditor()
    editor.start_new_columns()
    editor._sample.setPlainText(IIS_SAMPLE)

    editor.guess()

    assert dict(editor.mapping())["client_ip"] == "c-ip"
    assert dict(editor.mapping())["timestamp"] == "date+time"
    assert editor.preview().ok


def test_a_table_format_written_here_reaches_the_library(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_columns()
    editor._name.setText("iis")
    editor._sample.setPlainText(IIS_SAMPLE)
    editor.guess()

    assert editor.save(), editor.trouble()
    saved = load_library()[0]
    assert isinstance(saved, ColumnsFormatSpec)
    assert dict(saved.fields)["client_ip"] == "c-ip"


def test_a_saved_table_format_does_not_keep_the_columns_it_was_guessed_from(
    qt_app: QApplication,
) -> None:
    """IIS writes different fields on different servers. A format that froze
    one server's columns would read only that server's logs."""
    editor = FormatEditor()
    editor.start_new_columns()
    editor._name.setText("iis")
    editor._sample.setPlainText(IIS_SAMPLE)
    editor.guess()
    editor.save()

    assert load_library()[0].columns == ()


def test_columns_typed_in_by_hand_are_kept(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_columns()
    editor._name.setText("bare")
    editor._separator.setCurrentText("Comma")
    editor._columns.setText("when, who, code")
    editor.set_mapping((("timestamp", "when"), ("client_ip", "who")))

    assert editor.save(), editor.trouble()
    assert load_library()[0].columns == ("when", "who", "code")
    assert load_library()[0].separator == ","


def test_a_saved_table_format_fills_the_screen_back_in(qt_app: QApplication) -> None:
    save_library([SAVED_TABLE])
    register_saved_formats()

    editor = FormatEditor()
    editor.select("iis")

    assert editor.kind() == "columns"
    assert dict(editor.mapping())["client_ip"] == "c-ip"
    assert editor._note.text() == "the web server"


def test_a_table_mapping_without_a_timestamp_is_refused(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_columns()
    editor._name.setText("half")
    editor.set_mapping((("client_ip", "c-ip"),))

    assert not editor.save()
    assert "timestamp" in editor.trouble()
    assert load_library() == []


def test_guessing_a_table_from_lines_that_declare_no_columns_says_so(
    qt_app: QApplication,
) -> None:
    editor = FormatEditor()
    editor.start_new_columns()
    editor._sample.setPlainText("2024-05-01 09:00:45 203.0.113.77 GET / 404")

    editor.guess()

    assert "header" in editor._status.text().lower()


# ---------------------------------------------------------------------------
# The fourth kind: a regular expression
# ---------------------------------------------------------------------------

SYSLOG_LINE = (
    "2024 May  1 09:00:45 gw01 proxy[1234]: client=203.0.113.77 method=GET"
    " url=/admin/0.php status=404"
)

SYSLOG_PATTERN = (
    r"^(?P<timestamp>\d{4} \w+\s+\d+ \d\d:\d\d:\d\d) \S+ \S+: "
    r"client=(?P<client_ip>\S+) method=(?P<method>\S+) url=(?P<path>\S+) "
    r"status=(?P<status>\d+)"
)


def test_a_pattern_format_can_be_started(qt_app: QApplication) -> None:
    editor = FormatEditor()

    rows = [
        editor._formats.item(row).text()
        for row in range(editor._formats.count())
        if editor._formats.item(row) is not None
    ]

    assert "Untitled" in rows


def test_a_pattern_shows_one_rule_line_and_a_time_format(qt_app: QApplication) -> None:
    """Its named groups are the mapping, so there is no table to fill in — but
    a syslog stamp still needs telling apart from an ISO one."""
    editor = FormatEditor()
    editor.show()
    qt_app.processEvents()

    editor.start_new_pattern()

    assert editor.kind() == "pattern"
    assert editor._rule.isVisible()
    assert editor._time_format.isVisible()
    assert not editor._mapping.isVisible()
    assert not editor._guess.isVisible()


def test_the_preview_reads_a_line_through_the_pattern(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_pattern()
    editor._sample.setPlainText(SYSLOG_LINE)
    editor._time_format.setText("%Y %b %d %H:%M:%S")

    editor._rule.setText(SYSLOG_PATTERN)

    result = editor.preview()
    assert result.ok, editor._status.text()
    assert dict(result.fields)["Client"] == "203.0.113.77"
    assert dict(result.fields)["Path"] == "/admin/0.php"


def test_a_pattern_format_written_here_reaches_the_library(qt_app: QApplication) -> None:
    editor = FormatEditor()
    editor.start_new_pattern()
    editor._name.setText("gw-proxy")
    editor._rule.setText(SYSLOG_PATTERN)
    editor._time_format.setText("%Y %b %d %H:%M:%S")

    assert editor.save(), editor.trouble()
    saved = load_library()[0]
    assert isinstance(saved, PatternFormatSpec)
    assert saved.time_format == "%Y %b %d %H:%M:%S"


def test_a_pattern_naming_no_groups_is_refused_with_the_way_out(
    qt_app: QApplication,
) -> None:
    editor = FormatEditor()
    editor.start_new_pattern()
    editor._name.setText("bare")
    editor._rule.setText(r"\S+ \S+")

    assert not editor.save()
    assert "(?P<" in editor.trouble()
    assert load_library() == []


def test_a_saved_pattern_format_fills_the_screen_back_in(qt_app: QApplication) -> None:
    save_library(
        [
            PatternFormatSpec(
                name="gw",
                pattern=SYSLOG_PATTERN,
                time_format="%Y %b %d %H:%M:%S",
                description="the gateway",
            )
        ]
    )
    register_saved_formats()

    editor = FormatEditor()
    editor.select("gw")

    assert editor.kind() == "pattern"
    assert editor._rule.text() == SYSLOG_PATTERN
    assert editor._note.text() == "the gateway"


def test_manage_formats_opens_the_formats_and_rules_dialog(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ingest flow's way to the formats is the same dialog as the Case
    menu's, on its formats tab."""
    from logarc.gui import formats_and_rules

    opened_on: list[str] = []

    def shown(self: formats_and_rules.FormatsAndRules) -> int:
        opened_on.append(self.tabs.tabText(self.tabs.currentIndex()))
        return 0

    monkeypatch.setattr(formats_and_rules.FormatsAndRules, "exec", shown)

    FormatChoice()._manage()

    assert opened_on == [formats_and_rules.FORMATS_TAB]


# -- the list holds formats; New is a button ----------------------------------


@pytest.mark.parametrize(
    ("entry", "kind"),
    [
        ("Text (LogFormat)", "logformat"),
        ("JSON", "json"),
        ("Table (CSV, TSV, W3C)", "columns"),
        ("Pattern (regular expression)", "pattern"),
    ],
)
def test_each_new_entry_starts_its_kind_on_the_untitled_row(
    qt_app: QApplication, entry: str, kind: str
) -> None:
    editor = FormatEditor()
    editor.select("apache-combined")
    (action,) = [a for a in editor.new_button.menu().actions() if a.text() == entry]

    action.trigger()

    assert editor._formats.currentItem().text() == "Untitled"
    assert editor.kind() == kind
    assert editor._name.text() == ""


def test_a_saved_format_called_untitled_still_opens_as_itself(qt_app: QApplication) -> None:
    """The command line can save any name; the blank row is known by what it
    is, not by what it says."""
    save_library([LogFormatSpec(name="Untitled", directive=PIPED)])
    editor = FormatEditor()

    assert "Untitled" in editor.listed()
    editor.select("Untitled")
    assert editor._rule.text() == PIPED


def test_the_labels_are_short(qt_app: QApplication) -> None:
    from PyQt6.QtWidgets import QLabel

    editor = FormatEditor()
    words = {label.text() for label in editor.findChildren(QLabel)}

    assert {"Formats", "Name", "LogFormat", "Note", "Sample line"} <= words
    assert editor._guess.text() == "Guess fields"
    assert editor._guess.toolTip()
    assert editor._fields.horizontalHeaderItem(1).text() == "Value"
    editor.start_new_json()
    assert editor._mapping.horizontalHeaderItem(0).text() == "Field"
    assert editor._mapping.horizontalHeaderItem(1).text() == "Your log's key"
    editor.start_new_pattern()
    assert editor._rule_label.text() == "Regular expression"


def test_the_ingest_choice_is_short_and_explains_itself_on_hover(qt_app: QApplication) -> None:
    from PyQt6.QtWidgets import QLabel, QPushButton

    chooser = FormatChoice()

    assert chooser.windowTitle() == "Log format"
    assert "Format" in {label.text() for label in chooser.findChildren(QLabel)}
    assert "Apache and nginx" in chooser._choice.toolTip()
    assert "Manage\u2026" in {button.text() for button in chooser.findChildren(QPushButton)}
