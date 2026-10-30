"""Reading a log by a regular expression the reader wrote.

The last kind, and the one that has to work when the other three do not: a
syslog-wrapped line, an appliance with a syntax of its own, a load balancer
that agrees with nobody. It is also the simplest, because the named groups
*are* the mapping — there is nothing else to configure.
"""

from __future__ import annotations

import pytest

from zodiarc.core.evidence import EvidenceRef
from zodiarc.parsers.pattern import PatternFormatError
from zodiarc.parsers.spec import PatternFormatSpec

REF = EvidenceRef(source_file_id="f", line_no=1)

#: A syslog-wrapped proxy line: nothing else in Zodiarc can read this. Written
#: with the year, as RFC 5424 syslog does — without one nothing can date it,
#: and Zodiarc refuses the format rather than putting every event in 1900.
SYSLOG = (
    "2024 May  1 09:00:45 gw01 proxy[1234]: "
    "client=203.0.113.77 method=GET url=/admin/0.php?id=1 status=404 took=15ms"
)

PATTERN = (
    r"^(?P<timestamp>\d{4} \w+\s+\d+ \d\d:\d\d:\d\d) \S+ \S+: "
    r"client=(?P<client_ip>\S+) method=(?P<method>\S+) url=(?P<path>[^?\s]+)"
    r"(?:\?(?P<query>\S*))? status=(?P<status>\d+) took=(?P<took>\S+)"
)

PROXY = PatternFormatSpec(name="gw-proxy", pattern=PATTERN, time_format="%Y %b %d %H:%M:%S")


# -- reading ---------------------------------------------------------------


def test_a_matching_line_becomes_an_event() -> None:
    event = PROXY.build().parse_line(SYSLOG, REF)

    assert event is not None
    assert event.client_ip == "203.0.113.77"
    assert event.method == "GET"
    assert event.path == "/admin/0.php"
    assert event.query == "id=1"
    assert event.status == 404


def test_the_named_groups_are_the_mapping_and_need_nothing_else() -> None:
    """No separate list of which group is which. A regex already names its
    parts, and asking the reader to name them twice is asking them to keep two
    things in step."""
    assert PROXY.fields == ()


def test_a_group_that_is_not_one_of_our_fields_is_kept_as_evidence() -> None:
    event = PROXY.build().parse_line(SYSLOG, REF)

    assert event is not None
    assert event.extra["took"] == "15ms"


def test_a_line_the_pattern_does_not_match_is_refused() -> None:
    assert PROXY.build().parse_line("2024 May  1 09:00:45 gw01 sshd[9]: accepted", REF) is None


def test_an_optional_group_that_did_not_match_is_absent() -> None:
    without_query = SYSLOG.replace("/admin/0.php?id=1", "/admin/0.php")

    event = PROXY.build().parse_line(without_query, REF)

    assert event is not None
    assert event.query is None


def test_a_dash_is_absent_here_too() -> None:
    spec = PatternFormatSpec(
        name="dashes",
        pattern=r"(?P<timestamp>\S+) (?P<client_ip>\S+) (?P<referer>\S+)",
    )

    event = spec.build().parse_line("2024-05-01T09:00:45Z 203.0.113.5 -", REF)

    assert event is not None
    assert event.referer is None


def test_a_request_line_group_is_split_like_any_other() -> None:
    spec = PatternFormatSpec(
        name="req",
        pattern=r'(?P<timestamp>\S+) (?P<client_ip>\S+) "(?P<request_line>[^"]*)"',
    )

    event = spec.build().parse_line('2024-05-01T09:00:45Z 203.0.113.5 "GET /a?b=c HTTP/1.1"', REF)

    assert event is not None
    assert event.method == "GET"
    assert event.path == "/a"
    assert event.query == "b=c"


# -- times -----------------------------------------------------------------


def test_a_time_format_is_used_when_one_is_given() -> None:
    """`May  1 09:00:45` is nothing ISO or epoch would read; the format is how
    the reader says what it is."""
    event = PROXY.build().parse_line(SYSLOG, REF)

    assert event is not None
    assert event.timestamp.year == 2024
    assert event.timestamp.month == 5
    assert event.timestamp.hour == 9


def test_an_iso_stamp_is_read_without_being_told() -> None:
    spec = PatternFormatSpec(name="iso", pattern=r"(?P<timestamp>\S+) (?P<client_ip>\S+)")

    event = spec.build().parse_line("2024-05-01T09:00:45Z 203.0.113.5", REF)

    assert event is not None
    assert event.timestamp.year == 2024


def test_a_line_whose_time_will_not_parse_is_refused() -> None:
    spec = PatternFormatSpec(name="iso", pattern=r"(?P<timestamp>\S+) (?P<client_ip>\S+)")

    assert spec.build().parse_line("last-tuesday 203.0.113.5", REF) is None


# -- building one ----------------------------------------------------------


def test_a_pattern_that_will_not_compile_is_refused_with_the_reason() -> None:
    with pytest.raises(PatternFormatError, match="unbalanced"):
        PatternFormatSpec(name="broken", pattern=r"(?P<timestamp>\S+))").build()


def test_a_pattern_with_no_timestamp_group_is_refused() -> None:
    """Caught here rather than at ingest, where it would quarantine every line
    of the log and present as an empty case."""
    with pytest.raises(PatternFormatError, match="timestamp"):
        PatternFormatSpec(name="no-time", pattern=r"(?P<client_ip>\S+)").build()


def test_a_pattern_with_no_client_group_is_refused() -> None:
    with pytest.raises(PatternFormatError, match="client_ip"):
        PatternFormatSpec(name="no-client", pattern=r"(?P<timestamp>\S+)").build()


def test_a_pattern_with_no_groups_at_all_says_how_to_name_them() -> None:
    """The mistake a reader makes once: a working regex with nothing named."""
    with pytest.raises(PatternFormatError, match=r"\(\?P<"):
        PatternFormatSpec(name="bare", pattern=r"\S+ \S+").build()


# -- travelling ------------------------------------------------------------


def test_a_pattern_format_survives_the_round_trip_through_json() -> None:
    import json

    from zodiarc.parsers.spec import spec_from_dict, spec_to_dict

    assert spec_from_dict(json.loads(json.dumps(spec_to_dict(PROXY)))) == PROXY


def test_a_pattern_without_escapes_writes_no_escapes_key() -> None:
    """Every definition written before the option existed has to read back
    exactly as it did, and an older Zodiarc has to keep reading what this one
    writes for it — so the key appears only when it says something."""
    from zodiarc.parsers.spec import spec_to_dict

    assert "escapes" not in spec_to_dict(PROXY)


def test_a_pattern_with_escapes_survives_the_round_trip() -> None:
    import json

    from zodiarc.parsers.spec import spec_from_dict, spec_to_dict

    spec = PatternFormatSpec(name="hap", pattern=PATTERN, escapes="haproxy")

    assert spec_from_dict(json.loads(json.dumps(spec_to_dict(spec)))) == spec


def test_an_unknown_escapes_value_is_refused_naming_the_known_one() -> None:
    spec = PatternFormatSpec(name="hap", pattern=PATTERN, escapes="nginx")

    with pytest.raises(PatternFormatError, match="haproxy"):
        spec.check()


def test_a_pattern_format_is_complete_without_a_file() -> None:
    """Unlike a table format, nothing about it is declared in the log."""
    assert PROXY.resolved(["anything"]) == PROXY


def test_a_pattern_log_has_no_bookkeeping_lines() -> None:
    assert not PROXY.build().is_metadata("# not a directive to this kind")


def test_a_pattern_is_anchored_so_it_cannot_find_its_fields_mid_line() -> None:
    r"""Measured, and the reason for anchoring.

    `(?P<timestamp>\d+) (?P<client_ip>\S+)` searched anywhere in the line
    found `1 09:00:45` inside `May  1 09:00:45 gw01 proxy…`, read the `1` as
    one second past the epoch, and produced an event dated 1970 that nothing
    downstream would have questioned.
    """
    loose = PatternFormatSpec(name="loose", pattern=r"(?P<timestamp>\d+) (?P<client_ip>\S+)")

    assert loose.build().parse_line("May  1 09:00:45 gw01 proxy: client=1.2.3.4", REF) is None


def test_a_reader_who_means_to_skip_a_prefix_says_so() -> None:
    """Anchoring costs nothing that `.*` does not buy back, and it makes the
    intent visible in the pattern rather than in its absence."""
    spec = PatternFormatSpec(
        name="skipping",
        pattern=r".*client=(?P<client_ip>\S+).*time=(?P<timestamp>\S+)",
    )

    event = spec.build().parse_line(
        "May  1 gw01: client=203.0.113.5 method=GET time=2024-05-01T09:00:45Z", REF
    )

    assert event is not None
    assert event.client_ip == "203.0.113.5"


def test_a_time_format_with_no_year_in_it_is_refused() -> None:
    """A syslog stamp says `May  1 09:00:45` and nothing about the year, so
    `strptime` supplies 1900 — and every event of the log lands there together.

    Read in a report that becomes "the attack occurred on 1 May 1900", which is
    the kind of number this tool exists not to emit. The ordering inside the
    file survives; the date does not, and a date is what evidence is pinned to.
    Refused when the format is written rather than once per line, so the reader
    hears it while they can still do something about it.
    """
    with pytest.raises(PatternFormatError, match="year"):
        PatternFormatSpec(
            name="syslog",
            pattern=r"(?P<timestamp>\w+\s+\d+ \d\d:\d\d:\d\d) (?P<client_ip>\S+)",
            time_format="%b %d %H:%M:%S",
        ).build()


def test_the_same_format_with_a_year_is_accepted() -> None:
    spec = PatternFormatSpec(
        name="syslog",
        pattern=r"(?P<timestamp>\d{4} \w+\s+\d+ \d\d:\d\d:\d\d) (?P<client_ip>\S+)",
        time_format="%Y %b %d %H:%M:%S",
    )

    event = spec.build().parse_line("2024 May  1 09:00:45 203.0.113.5", REF)

    assert event is not None
    assert event.timestamp.year == 2024


def test_a_two_digit_year_counts_as_a_year() -> None:
    spec = PatternFormatSpec(
        name="short",
        pattern=r"(?P<timestamp>\S+ \S+) (?P<client_ip>\S+)",
        time_format="%y-%m-%d %H:%M:%S",
    )

    event = spec.build().parse_line("24-05-01 09:00:45 203.0.113.5", REF)

    assert event is not None
    assert event.timestamp.year == 2024


def test_a_status_that_is_not_a_number_costs_that_field_only() -> None:
    spec = PatternFormatSpec(
        name="odd",
        pattern=r"(?P<timestamp>\S+) (?P<client_ip>\S+) (?P<status>\S+)",
    )

    event = spec.build().parse_line("2024-05-01T09:00:45Z 203.0.113.5 unknown", REF)

    assert event is not None
    assert event.status is None


def test_a_two_part_request_line_group_has_no_protocol() -> None:
    spec = PatternFormatSpec(
        name="req",
        pattern=r'(?P<timestamp>\S+) (?P<client_ip>\S+) "(?P<request_line>[^"]*)"',
    )

    event = spec.build().parse_line('2024-05-01T09:00:45Z 203.0.113.5 "GET /a"', REF)

    assert event is not None
    assert event.protocol is None


def test_a_request_line_group_that_will_not_split_is_kept_as_evidence() -> None:
    spec = PatternFormatSpec(
        name="req",
        pattern=r'(?P<timestamp>\S+) (?P<client_ip>\S+) "(?P<request_line>[^"]*)"',
    )

    event = spec.build().parse_line('2024-05-01T09:00:45Z 203.0.113.5 "\x16\x03"', REF)

    assert event is not None
    assert event.method is None
    assert event.extra["malformed_request_line"] == "\x16\x03"


def test_a_request_line_of_dashes_names_no_method_or_path() -> None:
    """Envoy writes a request it refused before routing as `- - HTTP/1.1`.
    Read as written, that is a request for the path `-` by the method `-`."""
    spec = PatternFormatSpec(
        name="req",
        pattern=r'(?P<timestamp>\S+) (?P<client_ip>\S+) "(?P<request_line>[^"]*)"',
    )

    event = spec.build().parse_line('2026-10-25T19:34:41Z 10.244.0.2 "- - HTTP/1.1"', REF)

    assert event is not None
    assert (event.method, event.path) == (None, None)
    assert event.protocol == "HTTP/1.1"
    assert event.extra["malformed_request_line"] == "- - HTTP/1.1"


def test_a_line_with_no_client_address_is_refused() -> None:
    spec = PatternFormatSpec(name="dash", pattern=r"(?P<timestamp>\S+) (?P<client_ip>\S+)")

    assert spec.build().parse_line("2024-05-01T09:00:45Z -", REF) is None


# -- where the path ends, and the client's port ------------------------------

TIME = r"^(?P<timestamp>\d{4} \w+\s+\d+ \d\d:\d\d:\d\d) \S+ \S+: client=(?P<client_ip>\S+) "


def _read(pattern: str, rest: str):
    spec = PatternFormatSpec(name="p", pattern=TIME + pattern, time_format="%Y %b %d %H:%M:%S")
    return spec.build().parse_line(f"2024 May  1 09:00:45 gw01 proxy[1234]: {rest}", REF)


def test_a_path_group_that_carries_its_query_is_split() -> None:
    """A reader's path group, written as one run of non-blanks, takes the
    query along with it; read as one path, no rule that reads the query would
    ever see it."""
    event = _read(r"url=(?P<path>\S+)", "client=203.0.113.77 url=/admin/0.php?id=1")

    assert event is not None
    assert (event.path, event.query) == ("/admin/0.php", "id=1")


def test_a_url_group_is_read_as_its_host_path_and_query() -> None:
    event = _read(r"url=(?P<url>\S+)", "client=203.0.113.77 url=https://shop.example.com/a?b=c")

    assert event is not None
    assert (event.host, event.path, event.query) == ("shop.example.com", "/a", "b=c")


def test_a_client_group_written_with_a_port_is_the_address_alone() -> None:
    event = _read(r"url=(?P<path>\S+)", "client=203.0.113.77:51234 url=/")

    assert event is not None
    assert event.client_ip == "203.0.113.77"
    assert event.extra["client_port"] == "51234"


def test_a_port_group_of_the_readers_own_is_not_overwritten() -> None:
    event = _read(
        r"port=(?P<client_port>\d+) url=(?P<path>\S+)",
        "client=[2001:db8::1]:443 port=9 url=/",
    )

    assert event is not None
    assert event.client_ip == "2001:db8::1"
    assert event.extra["client_port"] == "9"


# -- a log that escapes what it writes ----------------------------------------

#: HAProxy's shape, cut down: a request line and a header capture, both of which
#: it writes with `"` as `#22`, `#` as `#23` and `{ | }` as `#7B #7C #7D`.
HASHED = r'(?P<timestamp>\S+) (?P<client_ip>\S+) \{(?P<captured>[^}]*)\} "(?P<request_line>[^"]*)"'
HASHED_LINE = (
    "2026-10-25T19:17:38Z 10.244.0.1 {Mozilla #22quoted#22 #7Ba#7Cb#7D #E2#82#AC} "
    '"GET /p?x=#22><script>#23top HTTP/1.1"'
)


def test_haproxy_escapes_are_undone_in_every_group() -> None:
    """A `"` the client sent arrives as `#22`, and a rule looking for `">`
    would never see it. HAProxy writes `#` itself as `#23`, so undoing them is
    exact."""
    spec = PatternFormatSpec(name="hap", pattern=HASHED, escapes="haproxy")

    event = spec.build().parse_line(HASHED_LINE, REF)

    assert event is not None
    assert event.query == 'x="><script>#top'
    assert event.extra["captured"] == 'Mozilla "quoted" {a|b} €'


def test_escapes_are_left_alone_unless_asked() -> None:
    spec = PatternFormatSpec(name="plain", pattern=HASHED)

    event = spec.build().parse_line(HASHED_LINE, REF)

    assert event is not None
    assert event.query == "x=#22><script>#23top"


def test_an_escaped_byte_that_is_not_utf8_is_kept_rather_than_lost() -> None:
    spec = PatternFormatSpec(name="hap", pattern=HASHED, escapes="haproxy")

    event = spec.build().parse_line(
        '2026-10-25T19:17:38Z 10.244.0.1 {caf#E9} "GET / HTTP/1.1"', REF
    )

    assert event is not None
    assert event.extra["captured"] == "caf\u00e9"
