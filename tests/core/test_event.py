"""Tests for the canonical event model."""

from datetime import UTC, datetime

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef

WHEN = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def _event(**overrides: object) -> NormalizedEvent:
    defaults: dict[str, object] = {
        "timestamp": WHEN,
        "client_ip": "1.2.3.4",
        "evidence": EvidenceRef(source_file_id="access.log", line_no=7),
    }
    return NormalizedEvent(**{**defaults, **overrides})  # type: ignore[arg-type]


def test_target_recombines_path_and_query_as_the_client_sent_it() -> None:
    event = _event(path="/search", query="q=shoes&page=2")

    assert event.target == "/search?q=shoes&page=2"


def test_target_omits_the_separator_when_there_is_no_query() -> None:
    event = _event(path="/index.html")

    assert event.target == "/index.html"


def test_target_is_empty_when_the_request_line_could_not_be_parsed() -> None:
    event = _event(path=None, extra={"malformed_request_line": "\x16\x03\x01"})

    assert event.target == ""


def test_evidence_ref_renders_as_file_and_line() -> None:
    assert str(EvidenceRef(source_file_id="access.log", line_no=42)) == "access.log:42"


def test_events_are_immutable() -> None:
    """Events are shared across analysis stages; nothing may mutate them in place."""
    event = _event(path="/a")

    try:
        event.path = "/b"  # type: ignore[misc]
    except AttributeError:
        return
    raise AssertionError("NormalizedEvent should be frozen")
