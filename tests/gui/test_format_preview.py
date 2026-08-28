"""What the format editor shows when you paste a line and write a rule.

Free of Qt on purpose. This is the answer a reader will trust before saving a
format, so it is the part that can do harm: a preview that looked like it
worked, on a directive that reads nothing, produces a case with every line
quarantined and no sign of why.
"""

from __future__ import annotations

from logarc.gui.format_preview import preview
from logarc.parsers.apache import COMBINED

COMBINED_LINE = (
    '203.0.113.45 - - [10/Oct/2000:13:55:36 +0000] "GET /a?b=c HTTP/1.1" 200 2326 "-" "curl/8.0"'
)
PIPED = '%h|%t|"%r"|%>s|%b'
PIPED_LINE = '203.0.113.5|[10/Oct/2020:13:55:36 +0000]|"GET /.env HTTP/1.1"|404|0'


def fields(directive: str, sample: str) -> dict[str, str]:
    return dict(preview(directive, sample).fields)


# -- the working case ------------------------------------------------------


def test_a_matching_directive_shows_the_fields_it_read() -> None:
    read = fields(PIPED, PIPED_LINE)

    assert read["Client"] == "203.0.113.5"
    assert read["Path"] == "/.env"
    assert read["Status"] == "404"


def test_a_matching_directive_reports_success() -> None:
    assert preview(PIPED, PIPED_LINE).ok


def test_the_query_string_is_shown_apart_from_the_path() -> None:
    """They are separate fields in the event, and a reader checking a rule
    against a URL needs to see which half of it went where."""
    read = fields(COMBINED, COMBINED_LINE)

    assert read["Path"] == "/a"
    assert read["Query"] == "b=c"


def test_a_field_the_directive_does_not_write_is_shown_as_empty_not_omitted() -> None:
    """An absent row reads as 'I forgot to look'; an empty one reads as 'this
    format does not carry it', which is the thing the reader is deciding."""
    read = fields(PIPED, PIPED_LINE)

    assert "User agent" in read
    assert read["User agent"] == ""


# -- the ways it goes wrong ------------------------------------------------


def test_nothing_written_yet_asks_for_a_directive_rather_than_failing() -> None:
    result = preview("", PIPED_LINE)

    assert not result.ok
    assert not result.fields
    assert "directive" in result.status.lower()


def test_no_sample_line_yet_asks_for_one() -> None:
    result = preview(PIPED, "   ")

    assert not result.ok
    assert "line" in result.status.lower()


def test_a_directive_that_will_not_compile_says_why() -> None:
    result = preview("no percent signs", PIPED_LINE)

    assert not result.ok
    assert "no directives" in result.status


def test_a_directive_that_does_not_match_says_so_plainly() -> None:
    result = preview(COMBINED, PIPED_LINE)

    assert not result.ok
    assert not result.fields
    assert "does not" in result.status.lower()


def test_a_line_a_built_in_already_reads_says_which_one() -> None:
    """The most useful thing that can be said to someone writing a directive
    for a log that needed none: they are about to duplicate a built-in."""
    result = preview("%h %t", COMBINED_LINE)

    assert not result.ok
    assert "apache-combined" in result.status


def test_a_line_nothing_reads_gets_no_misleading_suggestion() -> None:
    result = preview("%h %t", "this is not a log line at all")

    assert not result.ok
    assert "apache" not in result.status


def test_a_directive_that_matches_but_yields_no_timestamp_is_not_a_success() -> None:
    """`parse_line` returns None when the timestamp cannot be read, so the line
    would be quarantined. Showing that as a match would be a lie the reader
    only finds out about after ingesting."""
    result = preview("%h %r", "203.0.113.5 GET")

    assert not result.ok


def test_a_line_pasted_with_its_newline_still_works() -> None:
    """Copying a line out of a log or a terminal brings the newline with it,
    and a rule that works would otherwise appear not to."""
    assert preview(PIPED, f"  {PIPED_LINE}\n").ok
