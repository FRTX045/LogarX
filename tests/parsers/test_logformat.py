"""Tests for the Apache LogFormat directive compiler."""

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
