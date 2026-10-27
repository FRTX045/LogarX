"""What the evidence table says, decided without Qt.

The same seam `style.py` gives the canvas: these are the judgements that
decide whether a piece of evidence reads correctly — whether a served injection
stands out from a refused one, whether a payload is legible, whether a number
sorts as a number — and they should be checkable without starting a window.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from logarx.analysis import AnalysisResult, analyse_ip
from logarx.case import Case
from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.evidence import EvidenceLine
from logarx.gui.evidence_view import (
    COLUMNS,
    Cell,
    Filtered,
    RequestFilter,
    cells_for,
    filter_strip,
    no_results,
)
from logarx.style import EVIDENCE_INK, EVIDENCE_MUTED

if TYPE_CHECKING:
    from pathlib import Path

WHEN = datetime(2026, 8, 3, 22, 35, 18, tzinfo=UTC)


def line(
    *,
    target: str = "/search?q=%27+OR+%271%27%3D%271",
    status: int | None = 200,
    size: int | None = 10_648,
    agent: str = "curl/8.0",
) -> EvidenceLine:
    path, _, query = target.partition("?")
    ref = EvidenceRef("access.log", 36)
    return EvidenceLine(
        ref=ref,
        source_path="access.log",
        text=f'127.0.0.1 - - [x] "GET {target} HTTP/1.1" {status} {size}',
        event=NormalizedEvent(
            timestamp=WHEN,
            client_ip="127.0.0.1",
            evidence=ref,
            method="GET",
            path=path,
            query=query or None,
            status=status,
            bytes_sent=size,
            user_agent=agent,
        ),
    )


def cell(evidence: EvidenceLine, column: str, *, decode: bool = True) -> Cell:
    return cells_for(evidence, decode=decode)[COLUMNS.index(column)]


def test_every_column_gets_a_cell() -> None:
    """A short row would put values under the wrong headings."""
    assert len(cells_for(line(), decode=True)) == len(COLUMNS)


def test_the_source_reference_is_a_column_of_its_own() -> None:
    """Provenance is the point of the panel; it cannot live in a tooltip."""
    assert cell(line(), "Line").text == "access.log:36"


def test_the_request_reads_as_the_attack_it_is() -> None:
    """Written the way a request is written: the method is three characters and
    a column of its own costs its heading's width, which at a 400px panel left
    the payload 80px — the very fault this table exists to fix."""
    assert cell(line(), "Request").text == "GET /search?q=' OR '1'='1"


def test_the_target_can_be_shown_as_the_log_holds_it() -> None:
    assert cell(line(), "Request", decode=False).text == "GET /search?q=%27+OR+%271%27%3D%271"


def test_a_served_status_stands_out_and_a_refused_one_recedes() -> None:
    """A 2xx on an injection is the alarm, not the reassurance."""
    served = cell(line(status=200), "Status")
    refused = cell(line(status=403), "Status")

    assert served.colour == EVIDENCE_INK
    assert served.bold
    assert refused.colour == EVIDENCE_MUTED
    assert not refused.bold


def test_numbers_sort_as_numbers() -> None:
    """ "1,000" sorts before "9" as text, which would mis-rank the table — and
    sorting by size is how an analyst finds what returned the most data."""
    assert cell(line(size=1_400_000), "Size").sort_key == 1_400_000
    assert cell(line(status=404), "Status").sort_key == 404
    assert cell(line(), "Line").sort_key == 36


def test_a_size_reads_as_a_size() -> None:
    assert cell(line(size=10_648), "Size").text == "10.4 KB"


def test_the_time_is_the_one_the_request_arrived() -> None:
    assert cell(line(), "Time").text == "22:35:18"


def test_the_full_target_is_available_as_a_tooltip() -> None:
    """The column will be too narrow for a long payload however it is sized."""
    assert cell(line(), "Request").tooltip == "GET /search?q=' OR '1'='1"


def unparsed(text: str = "!! not a log line !!") -> EvidenceLine:
    return EvidenceLine(ref=EvidenceRef("access.log", 4), source_path="access.log", text=text)


def missing() -> EvidenceLine:
    return EvidenceLine(
        ref=EvidenceRef("gone.log", 9),
        source_path="gone.log",
        note="cannot open log file gone.log",
    )


def test_a_line_the_parser_rejects_still_gets_a_row() -> None:
    """A request that will not parse is itself a finding, and dropping it would
    leave a gap in the evidence with nothing to say a gap is there."""
    cells = cells_for(unparsed(), decode=True)

    assert len(cells) == len(COLUMNS)
    assert cells[COLUMNS.index("Line")].text == "access.log:4"
    assert "not a log line" in cells[COLUMNS.index("Request")].text


def test_an_unreadable_source_says_so_in_the_row() -> None:
    """A case outlives its logs. The row must report that, not look empty."""
    from logarx.gui.evidence_view import ALERT_COLOUR

    target = cells_for(missing(), decode=True)[COLUMNS.index("Request")]

    assert "unavailable" in target.text
    assert "gone.log" in target.text
    assert target.colour == ALERT_COLOUR


def test_a_control_character_in_a_raw_line_cannot_break_the_row() -> None:
    """A cell is one line. A log line carrying a newline — however it got
    there — would otherwise draw over the row beneath it."""
    target = cells_for(unparsed("before\nafter"), decode=True)[COLUMNS.index("Request")]

    assert "\n" not in target.text
    assert "<U+000A>" in target.text


def test_the_detail_carries_the_whole_request() -> None:
    """The table truncates; this is where the reader goes for all of it."""
    from logarx.gui.evidence_view import detail_for

    detail = detail_for(line(), decode=True)
    labels = {label for label, _value, _colour in detail.fields}

    assert detail.source == "access.log:36"
    assert labels >= {
        "Request (method + target)",
        "Client IP (logged address)",
        "Time (UTC)",
        "Response status",
        "Response size (bytes sent)",
        "User agent (reported software)",
    }
    assert any("' OR '1'='1" in value for _l, value, _c in detail.fields)


@pytest.mark.parametrize(
    ("status", "meaning"),
    [
        (200, "OK"),
        (302, "Found"),
        (403, "Forbidden"),
        (404, "Not Found"),
        (500, "Internal Server Error"),
    ],
)
def test_response_status_explains_the_server_code(status: int, meaning: str) -> None:
    from logarx.gui.evidence_view import detail_for

    fields = {
        label: value
        for label, value, _colour in detail_for(line(status=status), decode=True).fields
    }

    assert fields["Response status"] == f"{status} — {meaning}"


def test_an_unrecognized_status_is_preserved_without_inventing_a_meaning() -> None:
    from logarx.gui.evidence_view import detail_for

    fields = {
        label: value for label, value, _colour in detail_for(line(status=499), decode=True).fields
    }

    assert fields["Response status"] == "499"


def test_missing_response_fields_are_explained_and_known_size_is_still_shown() -> None:
    from logarx.gui.evidence_view import detail_for

    fields = {
        label: value for label, value, _colour in detail_for(line(status=None), decode=True).fields
    }
    assert fields["Response status"] == "Not recorded"
    assert fields["Response size (bytes sent)"] == "10.4 KB"
    fields = {
        label: value for label, value, _colour in detail_for(line(size=None), decode=True).fields
    }
    assert fields["Response size (bytes sent)"] == "Not recorded"


def test_optional_log_fields_have_explanatory_names() -> None:
    from dataclasses import replace

    from logarx.gui.evidence_view import detail_for

    evidence = line()
    assert evidence.event is not None
    evidence = replace(
        evidence,
        event=replace(
            evidence.event, protocol="HTTP/1.1", referer="https://example.com/", host="example.com"
        ),
    )
    fields = {label: value for label, value, _colour in detail_for(evidence, decode=True).fields}

    assert fields["HTTP version"] == "HTTP/1.1"
    assert fields["Referrer (previous page)"] == "https://example.com/"
    assert fields["Host (requested site)"] == "example.com"
    assert fields["Client IP (logged address)"] == "127.0.0.1"
    assert fields["Time (UTC)"] == "2026-08-03 22:35:18"


def test_the_detail_holds_the_original_line_byte_for_byte() -> None:
    """The proof. Everything else here is a reading of it, and a reading is
    only allowed while the thing it reads stays reachable and unaltered."""
    from logarx.gui.evidence_view import detail_for

    evidence = line()

    assert detail_for(evidence, decode=True).raw == evidence.text


def test_the_detail_shows_the_full_agent_not_a_shortened_one() -> None:
    """The table has no room and the detail has plenty. A scanner signature
    must never be cut in the one place it can be read in full."""
    from logarx.gui.evidence_view import detail_for

    agent = "Mozilla/5.0 " + "x" * 200

    detail = detail_for(line(agent=agent), decode=True)

    assert any(value == agent for _l, value, _c in detail.fields)


def test_an_integrity_warning_reaches_the_detail() -> None:
    """A source that changed size since ingest may not hold the line that
    produced the finding, and that has to be said next to the line."""
    from logarx.gui.evidence_view import detail_for

    evidence = EvidenceLine(
        ref=EvidenceRef("access.log", 1),
        source_path="access.log",
        text="raw",
        note="access.log has changed size since ingest",
        verified=False,
    )

    assert "changed size" in (detail_for(evidence, decode=True).note or "")


# -- a filtered view says so ------------------------------------------------------


def test_a_filtered_view_says_how_much_of_the_activity_it_shows() -> None:
    assert filter_strip(Filtered("status:200", 9, 3574), shown=9) == (
        "Filtered \N{MIDDLE DOT} 9 of 3,574 lines match status:200"
    )


def test_one_match_is_one_line_that_matches() -> None:
    assert filter_strip(Filtered("status:500", 1, 3574), shown=1) == (
        "Filtered \N{MIDDLE DOT} 1 of 3,574 lines matches status:500"
    )


def test_more_matches_than_the_panel_loads_says_which_are_shown() -> None:
    assert filter_strip(Filtered("status:404", 3555, 3574), shown=2000) == (
        "Filtered \N{MIDDLE DOT} 3,555 of 3,574 lines match status:404"
        " \N{MIDDLE DOT} showing the first 2,000"
    )


def test_nothing_found_says_what_was_searched() -> None:
    assert no_results(Filtered("status:401", 0, 3574)) == (
        "None of the 3,574 lines in this activity match status:401."
    )
    assert no_results(Filtered("status:401", 0, 1)) == (
        "The one line in this activity does not match status:401."
    )


# -- which requests a filter keeps -------------------------------------------------


def _visits(when: datetime, first_line: int, statuses: list[int]) -> list[NormalizedEvent]:
    return [
        NormalizedEvent(
            timestamp=when + timedelta(seconds=index),
            client_ip="203.0.113.9",
            evidence=EvidenceRef("access.log", first_line + index),
            method="GET",
            path=f"/page/{first_line + index}",
            status=status,
            user_agent="Mozilla/5.0",
        )
        for index, status in enumerate(statuses)
    ]


@pytest.fixture
def two_days(tmp_path: Path) -> AnalysisResult:
    """One visit late on the 11th and one early on the 12th: two activities."""
    with Case.create(tmp_path / "case") as case:
        case.store.write(_visits(datetime(2026, 3, 11, 11, 0, tzinfo=UTC), 1, [200, 200, 404]))
        case.store.write(_visits(datetime(2026, 3, 12, 9, 0, tzinfo=UTC), 10, [200, 500]))
        case.store.finalize()
        return analyse_ip(case.store, "203.0.113.9")


def test_a_filter_that_narrows_nothing_is_no_filter(two_days: AnalysisResult) -> None:
    for text in ("", "   ", "status:", "after:"):
        assert RequestFilter.read(text, two_days) is None, text
    assert RequestFilter.read("status:200", two_days) is not None
    assert RequestFilter.read("after:10:00", two_days) is not None, "a time of day is a filter"


def test_no_filter_reads_nothing_of_the_reconstruction() -> None:
    """Asked on every selection, filter or not: with nothing to filter by, it
    must not walk the client's activities to find that out."""
    untouchable = object()

    assert RequestFilter.read("", untouchable) is None  # type: ignore[arg-type]
    assert RequestFilter.read("status:", untouchable) is None  # type: ignore[arg-type]


def test_a_filter_keeps_the_requests_that_match(two_days: AnalysisResult) -> None:
    kept = RequestFilter.read("status:200", two_days)
    assert kept is not None

    lines = [item.evidence.line_no for item in two_days.assignments if kept.keeps(item)]

    assert lines == [1, 2, 10]


def test_a_time_of_day_is_read_on_each_activitys_own_day(two_days: AnalysisResult) -> None:
    """`after:10:00` on the 11th's visit is ten on the 11th, and on the 12th's,
    ten on the 12th. One day for both would keep the 12th's nine o'clock visit
    (read on the 11th) or drop the 11th's eleven o'clock one (read on the 12th)."""
    assert len(two_days.episodes) == 2, "premise: two activities, a day apart"
    kept = RequestFilter.read("after:10:00", two_days)
    assert kept is not None

    lines = [item.evidence.line_no for item in two_days.assignments if kept.keeps(item)]

    assert lines == [1, 2, 3]


def test_the_activities_a_filter_reaches(two_days: AnalysisResult) -> None:
    late, early = sorted(two_days.episodes, key=lambda episode: episode.start)

    def reached(text: str) -> frozenset[str]:
        kept = RequestFilter.read(text, two_days)
        assert kept is not None
        return kept.episodes(two_days.assignments)

    assert reached("status:500") == {early.episode_id}
    assert reached("status:200") == {late.episode_id, early.episode_id}
    assert reached("status:401") == frozenset()
