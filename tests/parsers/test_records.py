"""Which fields a format can record at all.

A field a log does not have is not the same as a field a client left out, and
detection has to be able to tell them apart: Apache's common format writes no
User-Agent on any line, and read as "every client sent none" every request in
it was reconnaissance. So a parser says what it can fill, and the case works
out from that what each of its files cannot.
"""

from __future__ import annotations

import pytest

from logarc.parsers.base import recorded
from logarc.parsers.fieldnames import OPTIONAL_FIELDS, recorded_by
from logarc.parsers.registry import get_spec
from logarc.parsers.spec import ColumnsFormatSpec, JsonFormatSpec, PatternFormatSpec

EVERYTHING = frozenset(OPTIONAL_FIELDS)


def _records(name: str) -> frozenset[str]:
    spec = get_spec(name)
    assert spec is not None
    return spec.build().records


def test_combined_records_everything_a_rule_reads() -> None:
    assert _records("apache-combined") == EVERYTHING - {"host"}


def test_common_records_no_referer_and_no_user_agent() -> None:
    assert _records("apache-common") == EVERYTHING - {"host", "referer", "user_agent"}


def test_a_virtual_host_format_records_the_host() -> None:
    assert "host" in _records("apache-vhost-common")


def test_haproxy_s_capture_block_is_not_read_as_a_user_agent() -> None:
    """Which captured header is which is configuration, not log."""
    assert {"referer", "user_agent"}.isdisjoint(_records("haproxy"))


def test_envoy_records_a_user_agent_but_no_referer() -> None:
    assert "user_agent" in _records("envoy")
    assert "referer" not in _records("envoy")


def test_a_request_line_records_its_four_parts() -> None:
    assert recorded_by(["request_line"]) == {"method", "path", "query", "protocol"}


def test_a_url_records_its_host_path_and_query() -> None:
    assert recorded_by(["url"]) == {"host", "path", "query"}


def test_a_path_records_a_query_too() -> None:
    """A mapped path that holds a `?` is split there (`read_target`)."""
    assert recorded_by(["path"]) == {"path", "query"}


def test_a_json_format_records_what_it_maps() -> None:
    spec = JsonFormatSpec(
        name="j",
        fields=(("timestamp", "t"), ("client_ip", "ip"), ("user_agent", "ua"), ("status", "s")),
    )

    assert spec.build().records == {"user_agent", "status"}


def test_a_table_records_only_the_columns_its_log_has() -> None:
    """IIS logs whatever fields the administrator ticked. A format written for
    the family maps a User-Agent; a file without that column has none."""
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem sc-status",
        "2024-05-01 09:00:45 203.0.113.5 GET / 200",
    ]
    spec = get_spec("iis-w3c")
    assert isinstance(spec, ColumnsFormatSpec)

    records = spec.resolved(lines).build().records

    assert records == {"method", "path", "query", "status"}


def test_a_pattern_records_its_named_groups() -> None:
    spec = PatternFormatSpec(
        name="p",
        pattern=r'(?P<timestamp>\S+) (?P<client_ip>\S+) "(?P<request_line>[^"]*)" (?P<extra_thing>\S+)',
    )

    assert spec.build().records == {"method", "path", "query", "protocol"}


def test_a_parser_that_does_not_say_is_read_as_recording_everything() -> None:
    """A parser a script registered before `records` existed keeps the old
    reading, where nothing is ever known to be unrecorded."""

    class Older:
        name = "older"

        def parse_line(self, line: str, ref: object) -> None:
            return None

    assert recorded(Older()) is None  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["apache-combined", "nginx-json", "istio"])
def test_recorded_reads_a_built_in_s_own_answer(name: str) -> None:
    spec = get_spec(name)
    assert spec is not None
    parser = spec.build()

    assert recorded(parser) == parser.records
