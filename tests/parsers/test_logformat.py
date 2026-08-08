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


def test_timestamp_is_normalised_to_utc() -> None:
    parser = LogFormatParser(COMBINED)
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 1 "-" "-"'

    event = parser.parse_line(line, REF)

    assert event is not None
    # 13:55:36 at UTC-7 is 20:55:36 UTC.
    assert event.timestamp == datetime(2000, 10, 10, 20, 55, 36, tzinfo=UTC)


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
