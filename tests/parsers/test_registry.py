"""Tests for parser lookup and log format auto-detection."""

import pytest

from logarc.core.evidence import EvidenceRef
from logarc.parsers.apache import COMBINED, COMMON
from logarc.parsers.logformat import LogFormatParser
from logarc.parsers.registry import (
    UnknownFormatError,
    available_formats,
    detect_format,
    get_parser,
)

COMBINED_LINES = [
    '203.0.113.45 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '203.0.113.9 - - [10/Oct/2000:13:55:37 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8.0"',
    '198.51.100.2 - - [10/Oct/2000:13:55:38 +0000] "GET /a.css HTTP/1.1" 200 91 "-" "curl/8.0"',
]

COMMON_LINES = [
    '203.0.113.45 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 2326',
    '203.0.113.9 - - [10/Oct/2000:13:55:37 +0000] "POST /login HTTP/1.1" 302 0',
]

VHOST_LINES = [
    "a.example.com:443 203.0.113.45 - - [10/Oct/2000:13:55:36 +0000] "
    '"GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    "b.example.com:80 203.0.113.9 - - [10/Oct/2000:13:55:37 +0000] "
    '"GET /x HTTP/1.1" 404 0 "-" "curl/8.0"',
]

REF = EvidenceRef(source_file_id="f", line_no=1)


def test_known_format_can_be_looked_up_by_name() -> None:
    parser = get_parser("apache-combined")

    assert parser.name == "apache-combined"
    assert parser.parse_line(COMBINED_LINES[0], REF) is not None


def test_unknown_format_name_is_rejected_with_the_available_options() -> None:
    with pytest.raises(UnknownFormatError, match="apache-combined"):
        get_parser("nonsense")


def test_available_formats_lists_the_apache_presets() -> None:
    names = available_formats()

    assert "apache-common" in names
    assert "apache-combined" in names
    assert "apache-vhost-combined" in names


@pytest.mark.parametrize(
    ("sample", "expected"),
    [
        (COMBINED_LINES, "apache-combined"),
        (COMMON_LINES, "apache-common"),
        (VHOST_LINES, "apache-vhost-combined"),
    ],
)
def test_format_is_detected_from_a_sample(sample: list[str], expected: str) -> None:
    detection = detect_format(sample)

    assert detection is not None
    assert detection.name == expected
    assert detection.confidence == pytest.approx(1.0)


def test_detection_returns_nothing_for_input_that_is_not_a_web_log() -> None:
    assert detect_format(["hello", "world", "not a log at all"]) is None


def test_detection_tolerates_a_minority_of_unparseable_lines() -> None:
    """Real logs contain truncated and interleaved writes. A handful of bad
    lines must not stop the format being recognised."""
    sample = [*COMBINED_LINES, "<<< truncated write >>>"]

    detection = detect_format(sample)

    assert detection is not None
    assert detection.name == "apache-combined"
    assert 0.7 < detection.confidence < 1.0


def test_blank_lines_are_ignored_when_scoring() -> None:
    detection = detect_format(["", *COMBINED_LINES, "   ", ""])

    assert detection is not None
    assert detection.confidence == pytest.approx(1.0)


def test_detection_returns_nothing_for_an_empty_sample() -> None:
    assert detect_format([]) is None


def test_a_missing_field_does_not_satisfy_the_format() -> None:
    """Directives must consume at least one character, otherwise a line with a
    field omitted still matches and auto-detection picks the wrong format."""
    parser = LogFormatParser(COMBINED)
    # Status is absent, leaving two consecutive spaces.
    line = '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1"  2326 "-" "-"'

    assert parser.parse_line(line, REF) is None


def test_common_format_does_not_claim_combined_lines() -> None:
    parser = LogFormatParser(COMMON)

    assert parser.parse_line(COMBINED_LINES[0], REF) is None


def test_combined_format_does_not_claim_vhost_lines() -> None:
    parser = LogFormatParser(COMBINED)

    assert parser.parse_line(VHOST_LINES[0], REF) is None


def test_empty_query_directive_may_legitimately_match_nothing() -> None:
    """`%q` is the one directive that is empty when there is no query string."""
    parser = LogFormatParser("%h %t %U%q %>s")
    line = "1.2.3.4 [10/Oct/2000:13:55:36 +0000] /index.html 200"

    event = parser.parse_line(line, REF)

    assert event is not None
    assert event.path == "/index.html"
    assert event.query is None


def test_vhost_parser_extracts_the_virtual_host() -> None:
    parser = get_parser("apache-vhost-combined")

    event = parser.parse_line(VHOST_LINES[0], REF)

    assert event is not None
    assert event.host == "a.example.com"
