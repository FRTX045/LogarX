"""What the format editor shows when you paste a line and write a rule.

Free of Qt on purpose. This is the answer a reader will trust before saving a
format, so it is the part that can do harm: a preview that looked like it
worked, on a directive that reads nothing, produces a case with every line
quarantined and no sign of why.
"""

from __future__ import annotations

import json

from logarx.gui.format_preview import preview, preview_columns, preview_mapping
from logarx.parsers.apache import COMBINED

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
    assert "logformat" in result.status.lower()


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


# -- fields the canonical schema has no place for --------------------------


def test_a_header_the_schema_does_not_carry_is_still_shown() -> None:
    """The usual reason a site has its own format at all. A table that lists
    eleven fields and silently drops the twelfth reads as 'this was not
    captured' — the opposite of the truth, since it is kept in `extra`."""
    result = preview(f"{PIPED}|%{{X-Forwarded-For}}i", f"{PIPED_LINE}|198.51.100.9")

    assert result.ok
    assert ("req_header_x_forwarded_for", "198.51.100.9") in result.extra


def test_the_count_says_how_many_extra_fields_were_read() -> None:
    result = preview(f"{PIPED}|%{{X-Forwarded-For}}i", f"{PIPED_LINE}|198.51.100.9")

    assert "7 of 11" in result.status
    assert "1" in result.status.split("7 of 11")[1]


def test_a_format_with_no_extra_fields_says_nothing_about_them() -> None:
    result = preview(PIPED, PIPED_LINE)

    assert result.extra == ()
    assert result.status == "Read this line, and found 7 of 11 fields in it."


# -- the other kind: a mapping rather than a directive ---------------------

GATEWAY_LINE = json.dumps(
    {
        "time": "2024-05-01T09:00:45+00:00",
        "remote_addr": "203.0.113.77",
        "request": "GET /admin/0.php HTTP/1.1",
        "status": 404,
    }
)

GATEWAY_MAP = (
    ("timestamp", "time"),
    ("client_ip", "remote_addr"),
    ("request_line", "request"),
    ("status", "status"),
)


def test_a_mapping_that_reads_the_line_shows_its_fields() -> None:
    result = preview_mapping(GATEWAY_MAP, "", GATEWAY_LINE)

    assert result.ok
    assert dict(result.fields)["Client"] == "203.0.113.77"
    assert dict(result.fields)["Path"] == "/admin/0.php"


def test_nothing_mapped_yet_asks_for_a_mapping_rather_than_failing() -> None:
    result = preview_mapping((), "", GATEWAY_LINE)

    assert not result.ok
    assert "map" in result.status.lower()


def test_a_mapping_with_no_sample_line_asks_for_one() -> None:
    result = preview_mapping(GATEWAY_MAP, "", "   ")

    assert not result.ok
    assert "line" in result.status.lower()


def test_a_mapping_missing_its_timestamp_says_which_field_is_missing() -> None:
    result = preview_mapping((("client_ip", "remote_addr"),), "", GATEWAY_LINE)

    assert not result.ok
    assert "timestamp" in result.status


def test_a_mapping_that_reads_nothing_names_the_keys_the_line_has() -> None:
    """The most useful thing that can be said here. For a directive the answer
    is 'the fields are in another order'; for a mapping it is 'your log calls
    them these', and the reader can read it straight off."""
    wrong = (("timestamp", "ts"), ("client_ip", "src_addr"))

    result = preview_mapping(wrong, "", GATEWAY_LINE)

    assert not result.ok
    assert "remote_addr" in result.status


def test_a_sample_that_is_not_json_says_so_rather_than_naming_keys() -> None:
    result = preview_mapping(GATEWAY_MAP, "", '203.0.113.5 - - [10/Oct/2000] "GET /" 200 1')

    assert not result.ok
    assert "JSON" in result.status


def test_a_mapping_shows_the_keys_it_did_not_map_as_extras() -> None:
    line = json.dumps({**json.loads(GATEWAY_LINE), "trace_id": "abc123"})

    result = preview_mapping(GATEWAY_MAP, "", line)

    assert result.ok
    assert ("trace_id", "abc123") in result.extra


# -- the third kind: a table whose columns may be in the log ---------------

IIS_SAMPLE = "\n".join(
    [
        "#Software: Microsoft Internet Information Services 10.0",
        "#Fields: date time c-ip cs-method cs-uri-stem sc-status",
        "2024-05-01 09:00:45 203.0.113.77 GET /admin/0.php 404",
    ]
)

IIS_MAP = (
    ("timestamp", "date+time"),
    ("client_ip", "c-ip"),
    ("method", "cs-method"),
    ("path", "cs-uri-stem"),
    ("status", "sc-status"),
)


def test_a_table_reads_its_columns_out_of_the_pasted_lines() -> None:
    """The reader pastes a piece of the log, header and all, because for this
    kind the header is half the definition."""
    result = preview_columns(IIS_MAP, (), " ", "", IIS_SAMPLE)

    assert result.ok
    assert dict(result.fields)["Client"] == "203.0.113.77"
    assert dict(result.fields)["Path"] == "/admin/0.php"


def test_the_row_previewed_is_the_first_that_is_not_bookkeeping() -> None:
    """Pasting the header and reading it as data would say the format is
    broken when it is the reader who pasted more than one kind of line."""
    result = preview_columns(IIS_MAP, (), " ", "", IIS_SAMPLE)

    assert result.ok
    assert dict(result.fields)["Status"] == "404"


def test_a_table_with_nothing_mapped_asks_for_a_mapping() -> None:
    result = preview_columns((), (), " ", "", IIS_SAMPLE)

    assert not result.ok
    assert "map" in result.status.lower()


def test_a_table_with_no_pasted_lines_asks_for_some() -> None:
    result = preview_columns(IIS_MAP, (), " ", "", "  ")

    assert not result.ok
    assert "line" in result.status.lower()


def test_a_log_with_no_header_says_that_rather_than_listing_a_row_of_data() -> None:
    """Its first row is taken for a header, so the plain message lists that
    row's *values* as though they were column names — which reads as nonsense,
    and points at the mapping when the answer is to name the columns."""
    result = preview_columns(IIS_MAP, (), " ", "", "2024-05-01 09:00:45 203.0.113.77 GET / 404")

    assert not result.ok
    assert "no #Fields: header" in result.status
    assert "203.0.113.77" not in result.status


def test_a_table_mapping_that_names_a_missing_column_names_it() -> None:
    result = preview_columns(
        (("timestamp", "date+time"), ("client_ip", "src-addr")), (), " ", "", IIS_SAMPLE
    )

    assert not result.ok
    assert "src-addr" in result.status


def test_columns_given_by_hand_are_used_instead_of_the_log_s() -> None:
    result = preview_columns(
        (("timestamp", "when"), ("client_ip", "who")),
        ("when", "who", "code"),
        ",",
        "",
        "2024-05-01T09:00:45Z,203.0.113.5,404",
    )

    assert result.ok
    assert dict(result.fields)["Client"] == "203.0.113.5"


def test_a_table_shows_the_columns_it_did_not_map_as_extras() -> None:
    result = preview_columns(IIS_MAP, (), " ", "", IIS_SAMPLE)

    assert result.ok
    assert result.extra == ()  # every column of this sample is mapped
