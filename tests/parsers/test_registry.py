"""Tests for parser lookup and log format auto-detection."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.parsers.apache import COMBINED, COMMON
from logarc.parsers.library import save_library
from logarc.parsers.logformat import LogFormatParser
from logarc.parsers.registry import (
    UnknownFormatError,
    available_formats,
    detect_format,
    get_parser,
    get_spec,
    register_format,
    register_logformat,
    register_saved_formats,
    register_spec,
    registered_formats,
    unregister_format,
)
from logarc.parsers.spec import LogFormatSpec

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

#: A format that is not an Apache directive at all, so registering it exercises
#: the seam rather than the LogFormat compiler.
JSON_LINES = [
    json.dumps({"ip": "203.0.113.7", "ts": "2024-05-01T12:00:00Z", "path": "/", "status": 200}),
    json.dumps({"ip": "203.0.113.7", "ts": "2024-05-01T12:00:05Z", "path": "/a", "status": 404}),
]


class JsonParser:
    """The smallest thing that satisfies the LogParser protocol."""

    name = "test-json"

    def parse_line(self, line: str, ref: EvidenceRef) -> NormalizedEvent | None:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not {"ip", "ts", "path"} <= payload.keys():
            return None
        return NormalizedEvent(
            timestamp=datetime.fromisoformat(payload["ts"].replace("Z", "+00:00")).astimezone(UTC),
            client_ip=payload["ip"],
            method=payload.get("method", "GET"),
            path=payload["path"],
            query=None,
            protocol=None,
            status=payload.get("status"),
            bytes_sent=None,
            referer=None,
            user_agent=None,
            host=None,
            evidence=ref,
        )


@pytest.fixture(autouse=True)
def restore_registry() -> Iterator[None]:
    """Registration is global, so a test that adds a format must undo it."""
    before = list(available_formats())
    yield
    for name in available_formats():
        if name not in before:
            unregister_format(name)


def test_a_custom_logformat_directive_can_be_registered() -> None:
    """The common case: a site with its own Apache or nginx LogFormat."""
    register_logformat("site-custom", '%h %t "%r" %>s %b')

    parser = get_parser("site-custom")

    assert parser.name == "site-custom"
    line = '203.0.113.4 [10/Oct/2000:13:55:36 +0000] "GET /x HTTP/1.1" 200 12'
    assert parser.parse_line(line, REF) is not None


def test_a_parser_that_is_not_logformat_based_can_be_registered() -> None:
    """The seam has to hold for a format Apache's directives cannot describe,
    or it is not an extension point, only a preset list."""
    register_format("test-json", JsonParser, description="one JSON object per line")

    parser = get_parser("test-json")
    event = parser.parse_line(JSON_LINES[0], REF)

    assert event is not None
    assert event.client_ip == "203.0.113.7"


def test_a_registered_format_takes_part_in_auto_detection() -> None:
    register_format("test-json", JsonParser)

    found = detect_format(JSON_LINES)

    assert found is not None
    assert found.name == "test-json"


def test_registering_over_an_existing_name_is_refused() -> None:
    """Silently shadowing a built-in would change what an existing case means."""
    with pytest.raises(ValueError, match="apache-combined"):
        register_logformat("apache-combined", "%h")


def test_registered_formats_carry_a_description_for_display() -> None:
    register_logformat("site-custom", '%h %t "%r" %>s %b')

    entry = next(item for item in registered_formats() if item.name == "site-custom")

    assert entry.description == '%h %t "%r" %>s %b'


def test_unregistering_removes_the_format() -> None:
    register_format("test-json", JsonParser)

    unregister_format("test-json")

    assert "test-json" not in available_formats()
    with pytest.raises(UnknownFormatError):
        get_parser("test-json")


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


# ---------------------------------------------------------------------------
# The definition behind a name
# ---------------------------------------------------------------------------


def test_a_built_in_format_carries_the_definition_behind_its_name() -> None:
    """A name only resolves where the definition is already known. Ingest has
    to send the definition itself to a worker, so the registry must be able to
    hand one over rather than only a built parser."""
    spec = get_spec("apache-combined")

    assert spec is not None
    assert spec.directive == COMBINED
    assert spec.name == "apache-combined"


def test_a_format_registered_from_a_definition_is_available_everywhere() -> None:
    register_spec(LogFormatSpec(name="log-kantor", directive='%h %t "%r" %>s %b'))

    assert "log-kantor" in available_formats()
    assert get_parser("log-kantor").name == "log-kantor"
    assert get_spec("log-kantor") == LogFormatSpec(name="log-kantor", directive='%h %t "%r" %>s %b')


def test_a_format_registered_by_handing_over_a_factory_has_no_definition() -> None:
    """`register_format` takes code, not data, and code cannot be written into
    a case or pickled to a worker. Saying so with `None` is what lets ingest
    fall back rather than pretend it carried something."""
    register_format("test-json", JsonParser)

    assert get_spec("test-json") is None


def test_asking_for_the_definition_of_a_format_that_is_not_there_is_refused() -> None:
    with pytest.raises(UnknownFormatError, match="nonsense"):
        get_spec("nonsense")


def test_detection_reports_the_definition_it_matched() -> None:
    detection = detect_format(COMBINED_LINES)

    assert detection is not None
    assert detection.spec is not None
    assert detection.spec.directive == COMBINED


def test_a_definition_registered_over_an_existing_name_is_refused() -> None:
    with pytest.raises(ValueError, match="apache-combined"):
        register_spec(LogFormatSpec(name="apache-combined", directive="%h"))


def test_saved_formats_reach_the_registry_when_they_are_installed() -> None:
    """The engine never reads the library itself. The CLI and the GUI install
    what the user saved; this is that step, and the reason `--format log-kantor`
    resolves at all."""
    save_library([LogFormatSpec(name="log-kantor", directive='%h %t "%r" %>s %b')])

    installed = register_saved_formats()

    assert [spec.name for spec in installed] == ["log-kantor"]
    assert get_parser("log-kantor").name == "log-kantor"


def test_installing_saved_formats_twice_is_not_an_error() -> None:
    """A GUI that opens a second window, or a CLI command that installs before
    delegating to another, must not fail on the second call."""
    save_library([LogFormatSpec(name="log-kantor", directive="%h %t")])

    register_saved_formats()
    register_saved_formats()

    assert available_formats().count("log-kantor") == 1


def test_a_saved_format_cannot_displace_a_built_in() -> None:
    """Registration order is preference order and the built-ins come first, so
    a case ingested as `apache-combined` keeps meaning what it meant. A saved
    format that collides is skipped rather than allowed to take the name."""
    save_library([LogFormatSpec(name="apache-combined", directive="%h")])

    installed = register_saved_formats()

    assert installed == []
    assert get_spec("apache-combined").directive == COMBINED
