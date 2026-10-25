"""Tests for the Apache LogFormat directive compiler."""

import re
import time
from datetime import UTC, datetime

import pytest

from logarc.core.evidence import EvidenceRef
from logarc.parsers.apache import COMBINED, COMMON, VHOST_COMBINED
from logarc.parsers.logformat import LogFormatError, LogFormatParser

REF = EvidenceRef(source_file_id="f1", line_no=1)


def test_combined_format_parses_a_canonical_line() -> None:
    parser = LogFormatParser(COMBINED)
    line = (
        '203.0.113.45 - - [10/Oct/2000:13:55:36 -0700] "GET /search?q=shoes HTTP/1.1" '
        '200 2326 "http://example.com/home" "Mozilla/5.0 (X11; Linux x86_64)"'
    )

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.client_ip == "203.0.113.45"
    assert event.method == "GET"
    assert event.path == "/search"
    assert event.query == "q=shoes"
    assert event.protocol == "HTTP/1.1"
    assert event.status == 200
    assert event.bytes_sent == 2326
    assert event.referer == "http://example.com/home"
    assert event.user_agent == "Mozilla/5.0 (X11; Linux x86_64)"


def test_every_field_of_a_custom_format_reaches_the_event() -> None:
    """Pins down the whole of one parse, because the promoted fields are only
    part of it: a format with directives beyond the canonical set puts the rest
    in `extra`, and `extra` is the half that a change to how fields are read
    could drop while every combined-format test above stayed green.
    """
    parser = LogFormatParser(
        '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %D %{X-Forwarded-For}i',
        name="custom",
    )
    line = (
        "203.0.113.5 - alice [01/May/2024:04:06:33 +0000] "
        '"GET /a?b=%27 HTTP/1.1" 200 4523 "http://example.com/" '
        '"curl/8.0 \\"probe\\"" 15342 198.51.100.9'
    )

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.timestamp == datetime(2024, 5, 1, 4, 6, 33, tzinfo=UTC)
    assert event.client_ip == "203.0.113.5"
    assert event.method == "GET"
    assert event.path == "/a"
    assert event.query == "b=%27"
    assert event.protocol == "HTTP/1.1"
    assert event.status == 200
    assert event.bytes_sent == 4523
    assert event.referer == "http://example.com/"
    # Apache's escaping is undone: a payload hidden behind `\x` or `\"` would
    # otherwise slip past every signature that reads the user agent.
    assert event.user_agent == 'curl/8.0 "probe"'
    assert event.extra == {
        "remote_user": "alice",
        "duration_us": "15342",
        "req_header_x_forwarded_for": "198.51.100.9",
    }


def test_an_escaped_byte_in_a_bare_field_is_left_alone() -> None:
    """Only fields the format wrapped in quotes carry Apache's escaping. A bare
    one may hold a backslash that was never an escape, and expanding it would
    rewrite evidence."""
    parser = LogFormatParser("%h %t %U", name="bare")
    line = "203.0.113.5 [01/May/2024:04:06:33 +0000] /c:\\x41windows"

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.path == "/c:\\x41windows"


def test_timestamp_is_normalised_to_utc() -> None:
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 1 "-" "-"'

    event = parser.parse_line(line, REF)

    assert event is not None
    # 13:55:36 at UTC-7 is 20:55:36 UTC.
    assert event.timestamp == datetime(2000, 10, 10, 20, 55, 36, tzinfo=UTC)


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        ("+0000", datetime(2024, 5, 1, 4, 6, 33, tzinfo=UTC)),
        ("-0700", datetime(2024, 5, 1, 11, 6, 33, tzinfo=UTC)),
        ("+0900", datetime(2024, 4, 30, 19, 6, 33, tzinfo=UTC)),
        # Half-hour and three-quarter-hour zones exist and are the ones a
        # whole-hour shortcut gets wrong: India, Nepal, the Chatham Islands.
        ("+0530", datetime(2024, 4, 30, 22, 36, 33, tzinfo=UTC)),
        ("-0330", datetime(2024, 5, 1, 7, 36, 33, tzinfo=UTC)),
        ("+1245", datetime(2024, 4, 30, 15, 21, 33, tzinfo=UTC)),
    ],
)
def test_every_kind_of_utc_offset_lands_on_the_right_instant(
    offset: str, expected: datetime
) -> None:
    """Servers in different timezones have to sort against each other, so the
    offset is not decoration — reading it wrong reorders the evidence."""
    parser = LogFormatParser(COMBINED)
    line = f'1.2.3.4 - - [01/May/2024:04:06:33 {offset}] "GET / HTTP/1.1" 200 1 "-" "-"'

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.timestamp == expected


def test_a_normalised_timestamp_is_in_utc_not_merely_equal_to_it() -> None:
    """Two aware datetimes at the same instant compare equal whatever their
    zones, so equality alone would pass on a timestamp left in the log's own
    offset — and that is what gets written into the store and rendered."""
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [01/May/2024:04:06:33 +0530] "GET / HTTP/1.1" 200 1 "-" "-"'

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.timestamp.tzinfo is UTC
    assert event.timestamp.hour == 22


def test_line_that_does_not_match_the_format_is_rejected() -> None:
    parser = LogFormatParser(COMBINED)

    assert parser.parse_line("this is not an access log line", REF) is None


def test_absent_fields_marked_with_a_dash_become_none() -> None:
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 304 - "-" "-"'

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.bytes_sent is None
    assert event.referer is None
    assert event.user_agent is None


def test_request_without_query_string_has_no_query() -> None:
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 5 "-" "-"'

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.path == "/index.html"
    assert event.query is None


def test_malformed_request_line_is_preserved_rather_than_discarded() -> None:
    """TLS handshake bytes sent to a plaintext port produce an unsplittable
    request line. Discarding the line would discard the evidence."""
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"'

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.method is None
    assert event.path is None
    assert event.status == 400
    assert "malformed_request_line" in event.extra


def test_escaped_quotes_inside_a_quoted_field_are_decoded() -> None:
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "evil\\"agent"'

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.user_agent == 'evil"agent'


def test_escaped_control_bytes_are_decoded_so_rules_see_the_real_payload() -> None:
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET /a\\x00b HTTP/1.1" 200 5 "-" "-"'

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.path == "/a\x00b"


def test_backslash_in_an_unquoted_field_is_left_alone() -> None:
    """Only quoted fields carry Apache's escaping, so bare fields must not be
    decoded — a literal ``\\x41`` in a path is not the letter ``A``."""
    parser = LogFormatParser("%h %t %U %>s")
    line = "1.2.3.4 [10/Oct/2000:13:55:36 +0000] /a\\x41b 200"

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.path == "/a\\x41b"


def test_common_format_omits_referer_and_user_agent() -> None:
    parser = LogFormatParser(COMMON)
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 5'

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.status == 200
    assert event.referer is None
    assert event.user_agent is None


def test_vhost_combined_format_captures_the_virtual_host() -> None:
    parser = LogFormatParser(VHOST_COMBINED)
    line = (
        "shop.example.com:443 1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "
        '"GET / HTTP/1.1" 200 5 "-" "-"'
    )

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.host == "shop.example.com"
    assert event.client_ip == "1.2.3.4"


def test_split_url_and_query_directives_are_supported() -> None:
    parser = LogFormatParser("%h %t %m %U %q %H %>s")
    line = "1.2.3.4 [10/Oct/2000:13:55:36 +0000] GET /search ?q=a HTTP/1.1 200"

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.method == "GET"
    assert event.path == "/search"
    assert event.query == "q=a"


def test_custom_directives_are_kept_in_extra() -> None:
    parser = LogFormatParser('%h %t "%r" %>s %b %D')
    line = '1.2.3.4 [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 5 15000'

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.extra["duration_us"] == "15000"


def test_literal_percent_is_not_treated_as_a_directive() -> None:
    parser = LogFormatParser("%h %% %t")
    line = "1.2.3.4 % [10/Oct/2000:13:55:36 +0000]"

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.client_ip == "1.2.3.4"


def test_unsupported_directive_is_rejected_at_compile_time() -> None:
    with pytest.raises(LogFormatError, match="unsupported directive"):
        LogFormatParser("%h %t %Z")


def test_format_without_directives_is_rejected() -> None:
    with pytest.raises(LogFormatError, match="no directives"):
        LogFormatParser("plain text")


def test_line_with_an_unparseable_timestamp_is_rejected() -> None:
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [not-a-timestamp] "GET / HTTP/1.1" 200 5 "-" "-"'

    assert parser.parse_line(line, REF) is None


def test_trailing_carriage_return_does_not_break_matching() -> None:
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "-"\r'

    assert parser.parse_line(line, REF) is not None


# ---------------------------------------------------------------------------
# `%{...}t` — a time format of the site's own
# ---------------------------------------------------------------------------
#
# The compiler carried a branch for this from the beginning, with a comment
# giving `%{%Y-%m-%d}t` as its example, and the branch could not be reached:
# `t` was missing from the table it looked the directive up in, so every
# `%{...}t` was refused two lines earlier as unsupported. There is even a
# timestamp fallback that handles ISO-8601, written for input that could not
# arrive. Found by using the format library on a log from an appliance that
# writes ISO timestamps — a large class of logs, entirely shut out.


def test_an_iso_timestamp_is_read_from_a_custom_time_format() -> None:
    parser = LogFormatParser('%{%Y-%m-%dT%H:%M:%S%z}t %h "%r" %>s %b')

    event = parser.parse_line(
        '2024-05-01T09:00:45+0000 203.0.113.77 "GET /admin/0.php HTTP/1.1" 404 0', REF
    )

    assert event is not None
    assert event.timestamp == datetime(2024, 5, 1, 9, 0, 45, tzinfo=UTC)
    assert event.client_ip == "203.0.113.77"
    assert event.path == "/admin/0.php"


def test_a_custom_time_format_is_converted_to_utc_like_every_other() -> None:
    parser = LogFormatParser('%{%Y-%m-%dT%H:%M:%S%z}t %h "%r" %>s %b')

    event = parser.parse_line('2024-05-01T09:00:45+0700 203.0.113.77 "GET / HTTP/1.1" 200 12', REF)

    assert event is not None
    assert event.timestamp == datetime(2024, 5, 1, 2, 0, 45, tzinfo=UTC)


def test_a_custom_time_format_may_contain_spaces() -> None:
    """The reason the pattern has to be built from the format rather than
    matched as one non-blank run: `%d/%b/%Y %H:%M:%S` writes a space, and a
    field matched as `\\S+` stops at it and takes the rest of the line with it."""
    parser = LogFormatParser('[%{%d/%b/%Y %H:%M:%S}t] %h "%r" %>s %b')

    event = parser.parse_line('[01/May/2024 09:00:45] 203.0.113.77 "GET / HTTP/1.1" 200 12', REF)

    assert event is not None
    assert event.timestamp == datetime(2024, 5, 1, 9, 0, 45, tzinfo=UTC)


def test_a_custom_time_without_a_zone_is_read_as_utc() -> None:
    """Same rule the fallback already applied to a timestamp with no offset.
    Guessing the reader's local zone would make the same log parse to different
    instants on two machines, which is the one thing a case may not do."""
    parser = LogFormatParser('%{%Y-%m-%d %H:%M:%S}t %h "%r" %>s %b')

    event = parser.parse_line('2024-05-01 09:00:45 203.0.113.77 "GET / HTTP/1.1" 200 12', REF)

    assert event is not None
    assert event.timestamp == datetime(2024, 5, 1, 9, 0, 45, tzinfo=UTC)


def test_a_line_whose_time_does_not_fit_the_format_is_refused_not_crashed() -> None:
    parser = LogFormatParser('%{%Y-%m-%d}t %h "%r" %>s %b')

    assert parser.parse_line('not-a-date 203.0.113.77 "GET / HTTP/1.1" 200 12', REF) is None


def test_an_unsupported_strftime_directive_is_named() -> None:
    with pytest.raises(LogFormatError, match="%Q"):
        LogFormatParser('%{%Y-%Q}t %h "%r" %>s %b')


def test_apaches_named_time_tokens_are_refused_in_their_own_words() -> None:
    """`%{sec}t`, `%{msec}t`, `%{begin:%s}t`. They are Apache's own vocabulary
    rather than strftime, and reading one as a strftime pattern would compile
    to a regex matching the literal text `sec`."""
    with pytest.raises(LogFormatError, match="sec"):
        LogFormatParser('%{sec}t %h "%r" %>s %b')


def test_a_custom_time_format_can_be_quoted_like_any_other_field() -> None:
    parser = LogFormatParser('"%{%Y-%m-%dT%H:%M:%S%z}t" %h "%r" %>s %b')

    event = parser.parse_line(
        '"2024-05-01T09:00:45+0000" 203.0.113.77 "GET / HTTP/1.1" 200 12', REF
    )

    assert event is not None
    assert event.timestamp == datetime(2024, 5, 1, 9, 0, 45, tzinfo=UTC)


def test_the_plain_clf_time_is_untouched_by_all_of_this() -> None:
    """The fast path. `%t` reads a bracketed CLF stamp by slicing, which is an
    order of magnitude quicker than strptime and runs on every ordinary line."""
    parser = LogFormatParser(COMBINED)

    event = parser.parse_line(
        '203.0.113.45 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "curl/8"',
        REF,
    )

    assert event is not None
    assert event.timestamp == datetime(2000, 10, 10, 20, 55, 36, tzinfo=UTC)


def test_a_time_format_ending_in_a_bare_percent_is_refused() -> None:
    with pytest.raises(LogFormatError, match="bare"):
        LogFormatParser('%{%Y-%m-%d %}t %h "%r" %>s %b')


def test_an_argument_directive_that_is_not_supported_is_still_named() -> None:
    """`t` joining the table of argument-taking directives must not have taken
    the refusal with it: `%{...}` on a letter logarc does not read is a
    mistake worth naming."""
    with pytest.raises(LogFormatError, match=re.escape("%{anything}Q")):
        LogFormatParser('%h %{anything}Q "%r" %>s %b')


def test_an_empty_custom_time_field_refuses_the_line() -> None:
    """Apache writes `-` for a field it had nothing to put in. Without a time
    there is no event, so the line is quarantined rather than dated arbitrarily."""
    parser = LogFormatParser('%{%Y-%m-%d}t|%h|"%r"|%>s|%b')

    assert parser.parse_line('|203.0.113.5|"GET / HTTP/1.1"|200|12', REF) is None


def test_a_bracketed_time_that_is_not_clf_inside_still_falls_back() -> None:
    """The fallback's remaining job.

    It was written for custom `%{...}t` formats, which now compile a pattern of
    their own and never reach it. What is left is a plain `%t` — which always
    expects brackets, that being how Apache writes it — whose *contents* are
    not CLF, because the server writes `%t` and means something else by it.
    """
    parser = LogFormatParser('%t %h "%r" %>s %b')

    event = parser.parse_line('[2024-05-01 09:00:45] 203.0.113.5 "GET / HTTP/1.1" 200 12', REF)

    assert event is not None
    assert event.timestamp == datetime(2024, 5, 1, 9, 0, 45, tzinfo=UTC)


def test_a_byte_count_that_is_not_a_number_is_absent_rather_than_fatal() -> None:
    """Truncated and interleaved writes are routine in a log under attack. A
    field that cannot be read costs that field, never the line."""
    parser = LogFormatParser(COMMON)

    event = parser.parse_line(
        '203.0.113.5 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 not-a-number', REF
    )

    assert event is not None
    assert event.bytes_sent is None


def test_a_number_too_small_to_be_a_real_timestamp_is_not_one() -> None:
    """1e8 seconds is March 1973, before any web server existed. Below that a
    number is a field somebody misidentified as the time — and read as an
    instant in 1970 every event of the log lands there together, sorted and
    plotted and believed."""
    from logarc.parsers.times import read_time

    assert read_time(1) is None
    assert read_time("1") is None
    assert read_time(1_714_554_045) is not None


# ---------------------------------------------------------------------------
# Fields in brackets, and fields that hold lists
# ---------------------------------------------------------------------------
#
# Both are what Kubernetes ingress-nginx writes by default: the upstream's name
# in brackets, `[]` when there is no alternative, and its address, length,
# time and status as lists once a request is retried or redirected.

BRACKETED = '%h %t [%{upstream}e] "%r" %>s %b'


def test_a_bracketed_field_may_be_empty() -> None:
    """ingress-nginx writes `[$proxy_alternative_upstream_name]`, which is `[]`
    on nearly every line. A bare body needs one character, so the line was
    refused — the format would read only the canary requests."""
    parser = LogFormatParser(BRACKETED)

    event = parser.parse_line(
        '203.0.113.5 [01/May/2024:09:00:45 +0000] [] "GET / HTTP/1.1" 200 5', REF
    )

    assert event is not None
    assert "env_upstream" not in event.extra


def test_a_bracketed_field_reads_up_to_its_closing_bracket() -> None:
    """The brackets delimit the field the way quotes do, spaces included."""
    parser = LogFormatParser(BRACKETED)

    event = parser.parse_line(
        '203.0.113.5 [01/May/2024:09:00:45 +0000] [a b] "GET / HTTP/1.1" 200 5', REF
    )

    assert event is not None
    assert event.extra["env_upstream"] == "a b"


HEAD = '203.0.113.5 [01/May/2024:09:00:45 +0000] "GET / HTTP/1.1" 200 5'


def test_a_bare_header_may_hold_a_list() -> None:
    """Behind two proxies the forwarded-for header is two addresses, and Apache
    and nginx both write a repeated header joined by `, `. Unquoted, that was a
    space a bare field could not cross, and every proxied line was refused."""
    parser = LogFormatParser('%h %t "%r" %>s %b %{X-Forwarded-For}i')

    event = parser.parse_line(f"{HEAD} 198.51.100.4, 10.0.0.2", REF)

    assert event is not None
    assert event.extra["req_header_x_forwarded_for"] == "198.51.100.4, 10.0.0.2"


UPSTREAM = '%h %t "%r" %>s %b %{addr}e %{len}e %{time}e %{status}e %{id}e'


@pytest.mark.parametrize(
    ("tail", "addr", "length", "took", "status"),
    [
        # Retried: nginx joins the servers it tried with `, `.
        (
            "10.0.0.1:80, 10.0.0.2:80 0, 612 0.000, 0.004 502, 200 abc",
            "10.0.0.1:80, 10.0.0.2:80",
            "0, 612",
            "0.000, 0.004",
            "502, 200",
        ),
        # Redirected internally to another group: the groups are joined by ` : `.
        (
            "10.0.0.1:80 : 10.0.0.9:80 0 : 612 0.001 : 0.004 404 : 200 abc",
            "10.0.0.1:80 : 10.0.0.9:80",
            "0 : 612",
            "0.001 : 0.004",
            "404 : 200",
        ),
    ],
)
def test_lists_line_up_field_by_field(
    tail: str, addr: str, length: str, took: str, status: str
) -> None:
    """The lines an incident leaves: the upstream failed and nginx tried again.
    Each list has one entry per attempt, so the fields have to line up."""
    event = LogFormatParser(UPSTREAM).parse_line(f"{HEAD} {tail}", REF)

    assert event is not None
    assert event.extra["env_addr"] == addr
    assert event.extra["env_len"] == length
    assert event.extra["env_time"] == took
    assert event.extra["env_status"] == status
    assert event.extra["env_id"] == "abc"


def test_a_simple_directive_is_still_one_token() -> None:
    """Lists are for what a header or the server's own variable can hold, not
    for a status or a byte count."""
    parser = LogFormatParser('%h %t "%r" %>s %b')

    assert parser.parse_line(f"{HEAD}, 6", REF) is None


def test_a_comma_written_after_a_field_still_separates_it() -> None:
    """A list only runs on where a space follows the field. A format that puts
    its own `, ` after one reads exactly as it did."""
    parser = LogFormatParser('%h %t "%r" %>s %b %{a}e, %{b}e')

    event = parser.parse_line(f"{HEAD} x, y", REF)

    assert event is not None
    assert event.extra["env_a"] == "x"
    assert event.extra["env_b"] == "y"


def test_a_unit_written_after_a_field_still_ends_it() -> None:
    """Traefik writes its duration as `4ms`."""
    parser = LogFormatParser('%h %t "%r" %>s %b %{d}ems')

    event = parser.parse_line(f"{HEAD} 4ms", REF)

    assert event is not None
    assert event.extra["env_d"] == "4"


def test_a_crafted_list_is_refused_in_linear_time() -> None:
    """The forwarded-for header is the client's to write. With several list
    fields side by side, a list that could give its items back to its
    neighbour would try every way of sharing two hundred of them, and one
    request would stall the ingest of a log. Lists take what they can and keep
    it, so this costs one pass."""
    parser = LogFormatParser(
        '%h %t "%r" %>s %b %{X-Forwarded-For}i %{X-Real-IP}i %{Via}i %{Forwarded}i'
    )
    # Five plain tokens for four fields: no way of sharing the list reads it.
    line = f"{HEAD} {'a, ' * 200}v w x y z"

    started = time.perf_counter()
    event = parser.parse_line(line, REF)
    took = time.perf_counter() - started

    assert event is None
    assert took < 0.25, f"{took:.2f}s for one line"
