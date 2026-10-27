"""Reading a log laid out as a table: IIS W3C, and CSV.

The third kind, and the one that brings a problem the first two did not have:
**the file declares its own columns.** A W3C log says `#Fields: date time c-ip
...` in its header, and CSV often names its columns in the first row. So the
definition a reader saves is not the whole answer — part of it is in the log.

That is settled by resolving the format against the file's opening lines before
anything reads it, in the process that opened the file. What travels to an
ingest worker and into the case is the resolved one, with the columns it
actually found written down. A worker starting halfway through a file has never
seen the header and could not have worked them out.
"""

from __future__ import annotations

import pytest

from logarc.core.evidence import EvidenceRef
from logarc.parsers.columns import ColumnsFormatError
from logarc.parsers.spec import ColumnsFormatSpec

REF = EvidenceRef(source_file_id="f", line_no=1)

#: An IIS 10 log, header and all, as IIS writes one.
IIS = [
    "#Software: Microsoft Internet Information Services 10.0",
    "#Version: 1.0",
    "#Date: 2024-05-01 09:00:45",
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username"
    " c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken",
    "2024-05-01 09:00:45 10.0.0.1 GET /admin/0.php - 80 - 203.0.113.77 curl/8.4.0 - 404 0 0 15",
    "2024-05-01 09:00:46 10.0.0.1 GET /item id=1 80 - 203.0.113.77 curl/8.4.0"
    " http://shop.example.com/ 200 0 0 8",
]

IIS_MAP = (
    ("timestamp", "date+time"),
    ("client_ip", "c-ip"),
    ("method", "cs-method"),
    ("path", "cs-uri-stem"),
    ("query", "cs-uri-query"),
    ("status", "sc-status"),
    ("user_agent", "cs(User-Agent)"),
    ("referer", "cs(Referer)"),
)

W3C = ColumnsFormatSpec(name="iis", fields=IIS_MAP)


def resolved(spec: ColumnsFormatSpec, lines: list[str]) -> ColumnsFormatSpec:
    """What ingest does before it reads a line: work the columns out."""
    return spec.resolved(lines)


# -- the file declaring its own columns ------------------------------------


def test_the_columns_are_read_from_the_files_own_header() -> None:
    spec = resolved(W3C, IIS)

    assert spec.columns[0] == "date"
    assert "cs(User-Agent)" in spec.columns


def test_a_resolved_format_reads_the_rows_under_that_header() -> None:
    parser = resolved(W3C, IIS).build()

    event = parser.parse_line(IIS[4], REF)

    assert event is not None
    assert event.client_ip == "203.0.113.77"
    assert event.method == "GET"
    assert event.path == "/admin/0.php"
    assert event.status == 404
    assert event.user_agent == "curl/8.4.0"


def test_the_two_halves_of_a_split_timestamp_are_joined() -> None:
    """W3C writes the date and the time in separate columns, so one of ours
    comes from two of theirs. Spelled `date+time`, which is unambiguous where
    a space would not be."""
    event = resolved(W3C, IIS).build().parse_line(IIS[4], REF)

    assert event is not None
    assert event.timestamp.year == 2024
    assert event.timestamp.hour == 9
    assert event.timestamp.minute == 0


def test_a_dash_is_absent_here_too() -> None:
    event = resolved(W3C, IIS).build().parse_line(IIS[4], REF)

    assert event is not None
    assert event.query is None
    assert event.referer is None


def test_a_column_the_mapping_did_not_claim_is_kept_as_evidence() -> None:
    event = resolved(W3C, IIS).build().parse_line(IIS[4], REF)

    assert event is not None
    assert event.extra["time-taken"] == "15"
    assert event.extra["s-ip"] == "10.0.0.1"


# -- the log's own bookkeeping ---------------------------------------------


def test_a_directive_line_is_neither_an_event_nor_a_failure() -> None:
    """Four of them open every IIS file. Quarantined, they would put a
    'lines could not be parsed' strip over every W3C case ever opened."""
    parser = resolved(W3C, IIS).build()

    for directive in IIS[:4]:
        assert parser.is_metadata(directive), directive
        assert parser.parse_line(directive, REF) is None


def test_an_ordinary_row_is_not_bookkeeping() -> None:
    assert not resolved(W3C, IIS).build().is_metadata(IIS[4])


def test_a_header_row_is_bookkeeping_when_the_columns_came_from_it() -> None:
    """A CSV naming its columns in the first row. Read as data it is one
    quarantined line per file, and the notice fires on every case."""
    rows = ["time,ip,verb,url,code", "2024-05-01T09:00:45Z,203.0.113.5,GET,/,200"]
    spec = resolved(
        ColumnsFormatSpec(
            name="csv",
            separator=",",
            fields=(("timestamp", "time"), ("client_ip", "ip"), ("status", "code")),
        ),
        rows,
    )

    parser = spec.build()

    assert parser.is_metadata(rows[0])
    assert not parser.is_metadata(rows[1])


# -- columns written out rather than read ----------------------------------


def test_columns_can_be_given_when_the_file_names_none() -> None:
    spec = ColumnsFormatSpec(
        name="headerless",
        separator=",",
        columns=("when", "who", "what", "code"),
        fields=(("timestamp", "when"), ("client_ip", "who"), ("status", "code")),
    )

    event = spec.build().parse_line("2024-05-01T09:00:45Z,203.0.113.5,/admin,404", REF)

    assert event is not None
    assert event.client_ip == "203.0.113.5"
    assert event.status == 404


def test_given_columns_are_not_overwritten_by_something_in_the_file() -> None:
    """The reader said what the columns are. A first row that happens to look
    like a header must not quietly replace their answer."""
    spec = ColumnsFormatSpec(
        name="headerless",
        separator=",",
        columns=("when", "who", "code"),
        fields=(("timestamp", "when"), ("client_ip", "who")),
    )

    assert resolved(spec, ["a,b,c", "2024-05-01T09:00:45Z,203.0.113.5,200"]).columns == (
        "when",
        "who",
        "code",
    )


def test_a_comma_separated_value_may_be_quoted() -> None:
    """Real CSV quotes a field holding the separator. W3C never does, so this
    costs those logs nothing."""
    spec = ColumnsFormatSpec(
        name="csv",
        separator=",",
        columns=("when", "who", "agent"),
        fields=(("timestamp", "when"), ("client_ip", "who"), ("user_agent", "agent")),
    )

    event = spec.build().parse_line(
        '2024-05-01T09:00:45Z,203.0.113.5,"Mozilla/5.0 (X11; Linux, x86_64)"', REF
    )

    assert event is not None
    assert event.user_agent == "Mozilla/5.0 (X11; Linux, x86_64)"


# -- rows that are not rows of this table ----------------------------------


def test_a_row_with_the_wrong_number_of_columns_is_refused() -> None:
    """Read by position against the wrong count, every field after the missing
    one is somebody else's value — and nothing downstream would notice. Refused
    loudly instead: the line is quarantined and the case says so.

    This is also what a log that redeclares its fields halfway through does,
    which W3C permits and this cannot follow: it quarantines from that point
    rather than misreading from it.
    """
    parser = resolved(W3C, IIS).build()

    assert parser.parse_line("2024-05-01 09:00:45 10.0.0.1 GET", REF) is None


def test_a_row_whose_time_will_not_parse_is_refused() -> None:
    parser = resolved(W3C, IIS).build()
    row = IIS[4].replace("2024-05-01 09:00:45", "not-a-date not-a-time")

    assert parser.parse_line(row, REF) is None


def test_a_blank_row_is_refused_rather_than_dated() -> None:
    assert resolved(W3C, IIS).build().parse_line("   ", REF) is None


# -- building one ----------------------------------------------------------


def test_a_format_that_never_learned_its_columns_is_refused_when_built() -> None:
    """Neither given nor found in the file. Caught here rather than at ingest,
    where it would quarantine every line and present as an empty case."""
    with pytest.raises(ColumnsFormatError, match="columns"):
        ColumnsFormatSpec(name="lost", fields=IIS_MAP).build()


def test_a_mapping_naming_a_column_the_file_does_not_have_is_refused() -> None:
    with pytest.raises(ColumnsFormatError, match="c-ip"):
        ColumnsFormatSpec(
            name="wrong",
            columns=("date", "time", "who"),
            fields=(("timestamp", "date+time"), ("client_ip", "c-ip")),
        ).build()


def test_a_format_with_no_timestamp_mapped_is_refused() -> None:
    with pytest.raises(ColumnsFormatError, match="timestamp"):
        ColumnsFormatSpec(name="no-time", columns=("who",), fields=(("client_ip", "who"),)).build()


def test_a_field_that_is_not_in_the_schema_is_refused_by_name() -> None:
    with pytest.raises(ColumnsFormatError, match="stauts"):
        ColumnsFormatSpec(
            name="typo",
            columns=("t", "ip", "code"),
            fields=(("timestamp", "t"), ("client_ip", "ip"), ("stauts", "code")),
        ).build()


# -- travelling ------------------------------------------------------------


def test_a_columns_format_survives_the_round_trip_through_json() -> None:
    import json

    from logarc.parsers.spec import spec_from_dict, spec_to_dict

    spec = resolved(W3C, IIS)

    assert spec_from_dict(json.loads(json.dumps(spec_to_dict(spec)))) == spec


def test_the_resolved_columns_are_what_the_case_records() -> None:
    """The reader's saved format says 'the columns are in the file'. The case
    has to say which columns were actually there, or re-reading it a year later
    depends on a file nobody kept."""
    spec = resolved(W3C, IIS)

    assert spec.columns
    assert spec.resolved(IIS) == spec, "resolving twice must not change it"


# -- the corners -----------------------------------------------------------


def test_blank_lines_before_the_header_are_stepped_over() -> None:
    """A log copied through an editor arrives with them."""
    spec = ColumnsFormatSpec(name="iis", fields=IIS_MAP).resolved(["", "   ", *IIS])

    assert "c-ip" in spec.columns


def test_a_file_that_declares_nothing_leaves_the_format_unresolved() -> None:
    """No lines at all — an empty log, or one read past its end. Resolving must
    hand back what it was given rather than inventing columns."""
    spec = ColumnsFormatSpec(name="iis", fields=IIS_MAP)

    assert spec.resolved([]) == spec
    assert spec.resolved(["", "  "]) == spec


def test_a_byte_count_that_is_not_a_number_costs_that_field_only() -> None:
    """W3C writes `-` for absent, but a truncated write leaves anything."""
    columns = ("date", "time", "c-ip", "sc-bytes")
    spec = ColumnsFormatSpec(
        name="bytes",
        columns=columns,
        fields=(("timestamp", "date+time"), ("client_ip", "c-ip"), ("bytes_sent", "sc-bytes")),
    )

    event = spec.build().parse_line("2024-05-01 09:00:45 203.0.113.5 truncated", REF)

    assert event is not None
    assert event.bytes_sent is None


def test_a_request_line_in_one_cell_is_split_like_any_other() -> None:
    """Some proxies write `GET /a HTTP/1.1` into a single column."""
    spec = ColumnsFormatSpec(
        name="proxy",
        separator=",",
        columns=("when", "who", "request"),
        fields=(("timestamp", "when"), ("client_ip", "who"), ("request_line", "request")),
    )

    event = spec.build().parse_line('2024-05-01T09:00:45Z,203.0.113.5,"GET /a?b=c HTTP/1.1"', REF)

    assert event is not None
    assert event.method == "GET"
    assert event.path == "/a"
    assert event.query == "b=c"
    assert event.protocol == "HTTP/1.1"


def test_a_two_part_request_line_in_a_cell_has_no_protocol() -> None:
    spec = ColumnsFormatSpec(
        name="proxy",
        separator=",",
        columns=("when", "who", "request"),
        fields=(("timestamp", "when"), ("client_ip", "who"), ("request_line", "request")),
    )

    event = spec.build().parse_line('2024-05-01T09:00:45Z,203.0.113.5,"GET /a"', REF)

    assert event is not None
    assert event.protocol is None


def test_a_request_line_that_will_not_split_is_kept_as_evidence() -> None:
    """A TLS handshake sent to a plaintext port. Routine in attack traffic and
    itself a signal, so the row is kept with the raw text beside the event."""
    spec = ColumnsFormatSpec(
        name="proxy",
        separator=",",
        columns=("when", "who", "request"),
        fields=(("timestamp", "when"), ("client_ip", "who"), ("request_line", "request")),
    )

    event = spec.build().parse_line('2024-05-01T09:00:45Z,203.0.113.5,"\x16\x03"', REF)

    assert event is not None
    assert event.method is None
    assert event.extra["malformed_request_line"] == "\x16\x03"


def test_a_row_with_no_client_address_is_refused() -> None:
    """No address, no event — the same rule every kind applies."""
    parser = resolved(W3C, IIS).build()
    row = IIS[4].replace("203.0.113.77", "-")

    assert parser.parse_line(row, REF) is None


def test_a_mapped_column_is_not_also_kept_among_the_extras() -> None:
    """It would be stored twice — once as the field it is and once beside it —
    and the evidence table would show the same value in two columns, one of
    them named after somebody else's schema."""
    event = resolved(W3C, IIS).build().parse_line(IIS[4], REF)

    assert event is not None
    assert set(event.extra) == {"s-ip", "s-port", "sc-substatus", "sc-win32-status", "time-taken"}


def test_a_mapped_column_the_file_does_not_have_is_simply_absent() -> None:
    """IIS logs whatever fields the administrator ticked, so a format written
    for the family names more columns than any one file carries. A referer that
    is not there is not an error; it is a log without referers."""
    minimal = [
        "#Fields: date time c-ip cs-method cs-uri-stem sc-status",
        "2024-05-01 09:00:45 203.0.113.5 GET /admin 404",
    ]
    spec = ColumnsFormatSpec(
        name="family",
        fields=(
            ("timestamp", "date+time"),
            ("client_ip", "c-ip"),
            ("status", "sc-status"),
            ("referer", "cs(Referer)"),
            ("user_agent", "cs(User-Agent)"),
        ),
    )

    event = spec.resolved(minimal).build().parse_line(minimal[1], REF)

    assert event is not None
    assert event.status == 404
    assert event.referer is None
    assert event.user_agent is None


def test_a_missing_column_for_a_required_field_is_still_refused() -> None:
    """Optional is optional; without a time and an address there is no event,
    and a typo there has to be caught rather than quietly yielding nothing."""
    with pytest.raises(ColumnsFormatError, match="c-ip"):
        ColumnsFormatSpec(
            name="typo",
            columns=("date", "time", "who"),
            fields=(("timestamp", "date+time"), ("client_ip", "c-ip")),
        ).build()


# -- where the path ends, and the client's port ------------------------------

CSV_ROWS = [
    "time,ip,verb,uri,code",
    "2024-05-01T09:00:45Z,203.0.113.5:51234,GET,/search?q=oak,200",
]


def _csv(*fields: tuple[str, str]) -> ColumnsFormatSpec:
    return resolved(
        ColumnsFormatSpec(
            name="csv",
            separator=",",
            fields=(("timestamp", "time"), ("client_ip", "ip"), ("method", "verb"), *fields),
        ),
        CSV_ROWS,
    )


def test_a_path_column_that_carries_its_query_is_split() -> None:
    event = _csv(("path", "uri")).build().parse_line(CSV_ROWS[1], REF)

    assert event is not None
    assert (event.path, event.query) == ("/search", "q=oak")


def test_a_url_column_is_read_as_its_host_path_and_query() -> None:
    rows = [CSV_ROWS[0], "2024-05-01T09:00:45Z,203.0.113.5,GET,http://shop.example.com/a?b=c,200"]
    spec = resolved(
        ColumnsFormatSpec(
            name="csv",
            separator=",",
            fields=(("timestamp", "time"), ("client_ip", "ip"), ("url", "uri")),
        ),
        rows,
    )

    event = spec.build().parse_line(rows[1], REF)

    assert event is not None
    assert (event.host, event.path, event.query) == ("shop.example.com", "/a", "b=c")


def test_a_client_column_written_with_a_port_is_the_address_alone() -> None:
    event = _csv(("path", "uri")).build().parse_line(CSV_ROWS[1], REF)

    assert event is not None
    assert event.client_ip == "203.0.113.5"
    assert event.extra["client_port"] == "51234"


# -- a log that encodes what it writes --------------------------------------

#: CloudFront percent-encodes spaces, `%` and a list of other characters in what
#: it writes, so a query the client had already encoded comes out encoded twice.
#: Constructed in the shape of AWS's standard log reference.
CLOUDFRONT_ROWS = [
    "#Version: 1.0",
    "#Fields: date\ttime\tc-ip\tcs-method\tcs-uri-stem\tsc-status\tcs(Referer)"
    "\tcs(User-Agent)\tcs-uri-query",
    "2024-05-01\t09:00:45\t203.0.113.5\tGET\t/%7Eadm\t404"
    "\thttp://shop.example.com/login?next=%252Fadmin\tMozilla/5.0%20(X11;%20Linux)"
    "\tnext=%252Fadmin%252Fusers",
]
CLOUDFRONT_MAP = (
    ("timestamp", "date+time"),
    ("client_ip", "c-ip"),
    ("method", "cs-method"),
    ("path", "cs-uri-stem"),
    ("query", "cs-uri-query"),
    ("status", "sc-status"),
    ("referer", "cs(Referer)"),
    ("user_agent", "cs(User-Agent)"),
)


def _cloudfront(escapes: str, rows: list[str] = CLOUDFRONT_ROWS) -> ColumnsFormatSpec:
    spec = ColumnsFormatSpec(name="cf", fields=CLOUDFRONT_MAP, separator="\t", escapes=escapes)
    return resolved(spec, rows)


def test_cloudfront_s_encoding_is_undone_once() -> None:
    """Undone twice, `%252F` would read as `/`: the client's own encoding, which
    is what a rule about double encoding is looking at, would be gone too."""
    event = _cloudfront("cloudfront").build().parse_line(CLOUDFRONT_ROWS[2], REF)

    assert event is not None
    assert event.path == "/~adm"
    assert event.query == "next=%2Fadmin%2Fusers"
    assert event.referer == "http://shop.example.com/login?next=%2Fadmin"
    assert event.user_agent == "Mozilla/5.0 (X11; Linux)"


def test_encoding_is_left_alone_unless_the_format_says_so() -> None:
    event = _cloudfront("").build().parse_line(CLOUDFRONT_ROWS[2], REF)

    assert event is not None
    assert event.path == "/%7Eadm"
    assert event.user_agent == "Mozilla/5.0%20(X11;%20Linux)"


def test_an_encoded_byte_that_is_not_utf8_is_kept() -> None:
    row = CLOUDFRONT_ROWS[2].replace("Mozilla/5.0%20(X11;%20Linux)", "caf%E9%20%C3%A9")
    event = _cloudfront("cloudfront").build().parse_line(row, REF)

    assert event is not None
    assert event.user_agent == "caf\u00e9 \u00c3\u00a9"


def test_the_escapes_travel_with_the_definition() -> None:
    """A case rebuilds its parser from what it recorded, to read evidence back.
    Recorded without the escapes, the evidence would read differently from the
    events built from it."""
    spec = _cloudfront("cloudfront")

    payload = spec.to_payload()

    assert payload["escapes"] == "cloudfront"
    assert ColumnsFormatSpec.from_payload(payload) == spec


def test_a_definition_without_escapes_writes_no_key_for_them() -> None:
    """An older logarc refuses a key it does not know."""
    assert "escapes" not in _cloudfront("").to_payload()


def test_an_escape_this_tool_does_not_know_is_refused() -> None:
    with pytest.raises(ColumnsFormatError, match="cloudfront"):
        ColumnsFormatSpec(name="cf", fields=CLOUDFRONT_MAP, escapes="iis").check()
