"""Tests for the format spec: a log format written down as data.

The spec is what a case stores and what a worker is sent, so the round trip
through JSON is not a convenience here — it is the contract that keeps a case
readable after the format it was ingested with has been edited or deleted.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from logarx.core.evidence import EvidenceRef
from logarx.parsers.apache import COMBINED
from logarx.parsers.spec import (
    SPEC_VERSION,
    FormatSpecError,
    LogFormatSpec,
    spec_from_dict,
    spec_to_dict,
)

REF = EvidenceRef(source_file_id="f", line_no=1)

COMBINED_LINE = (
    '203.0.113.45 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"'
)


def test_a_spec_builds_a_parser_that_reads_its_own_directive() -> None:
    parser = LogFormatSpec(name="site", directive=COMBINED).build()

    event = parser.parse_line(COMBINED_LINE, REF)

    assert event is not None
    assert event.client_ip == "203.0.113.45"
    assert parser.name == "site"


def test_a_spec_survives_the_round_trip_through_json() -> None:
    spec = LogFormatSpec(name="log-kantor", directive=COMBINED, description="the office")

    restored = spec_from_dict(json.loads(json.dumps(spec_to_dict(spec))))

    assert restored == spec


def test_a_written_definition_names_its_kind_and_version() -> None:
    payload = spec_to_dict(LogFormatSpec(name="site", directive=COMBINED))

    assert payload["kind"] == "logformat"
    assert payload["version"] == SPEC_VERSION


def test_a_definition_from_a_newer_logarx_is_refused_by_version() -> None:
    payload = spec_to_dict(LogFormatSpec(name="site", directive=COMBINED))
    payload["version"] = SPEC_VERSION + 1

    with pytest.raises(FormatSpecError) as raised:
        spec_from_dict(payload)

    assert str(SPEC_VERSION + 1) in str(raised.value)
    assert "newer" in str(raised.value)


def test_an_unknown_kind_names_the_kinds_this_logarx_reads() -> None:
    payload = spec_to_dict(LogFormatSpec(name="site", directive=COMBINED))
    payload["kind"] = "runes"

    with pytest.raises(FormatSpecError) as raised:
        spec_from_dict(payload)

    assert "runes" in str(raised.value)
    assert "logformat" in str(raised.value)


def test_a_definition_missing_a_field_is_refused() -> None:
    payload = spec_to_dict(LogFormatSpec(name="site", directive=COMBINED))
    del payload["directive"]

    with pytest.raises(FormatSpecError) as raised:
        spec_from_dict(payload)

    assert "directive" in str(raised.value)


def test_a_definition_carrying_an_unexpected_field_is_refused() -> None:
    """A hand-edited library file is the likely source, and a typo there would
    otherwise be accepted in silence and lose whatever the user meant to set."""
    payload = spec_to_dict(LogFormatSpec(name="site", directive=COMBINED))
    payload["directve"] = "%h"

    with pytest.raises(FormatSpecError) as raised:
        spec_from_dict(payload)

    assert "directve" in str(raised.value)


def test_a_definition_with_no_kind_at_all_is_refused() -> None:
    with pytest.raises(FormatSpecError) as raised:
        spec_from_dict({"version": SPEC_VERSION, "name": "site", "directive": COMBINED})

    assert "kind" in str(raised.value)


def test_a_spec_holding_an_uncompilable_directive_still_loads() -> None:
    """Loading is reading, not compiling.

    A case stores the definition it was ingested with. If a stored definition
    could refuse to *load*, one unreadable format would take the whole case
    down with it — where today the line text is still shown and only its fields
    are missing. So the compile failure is kept where it belongs, in `build`.
    """
    spec = spec_from_dict(
        {"version": SPEC_VERSION, "kind": "logformat", "name": "broken", "directive": "no percent"}
    )

    assert spec.directive == "no percent"
    with pytest.raises(ValueError, match="no directives"):
        spec.build()


@given(
    name=st.text(min_size=1, max_size=40),
    description=st.text(max_size=80),
)
def test_any_name_and_description_survive_the_round_trip(name: str, description: str) -> None:
    spec = LogFormatSpec(name=name, directive=COMBINED, description=description)

    assert spec_from_dict(json.loads(json.dumps(spec_to_dict(spec)))) == spec
