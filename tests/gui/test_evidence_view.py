"""What the evidence table says, decided without Qt.

The same seam `gui/style.py` gives the canvas: these are the judgements that
decide whether a piece of evidence reads correctly — whether a served injection
stands out from a refused one, whether a payload is legible, whether a number
sorts as a number — and they should be checkable without starting a window.
"""

from __future__ import annotations

from datetime import UTC, datetime

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.evidence import EvidenceLine
from logarc.gui.evidence_view import COLUMNS, Cell, cells_for
from logarc.gui.style import EVIDENCE_INK, EVIDENCE_MUTED

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
    assert cell(line(), "Source").text == "access.log:36"


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
    assert cell(line(), "Source").sort_key == 36


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
    assert cells[COLUMNS.index("Source")].text == "access.log:4"
    assert "not a log line" in cells[COLUMNS.index("Request")].text


def test_an_unreadable_source_says_so_in_the_row() -> None:
    """A case outlives its logs. The row must report that, not look empty."""
    from logarc.gui.evidence_view import ALERT_COLOUR

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
    from logarc.gui.evidence_view import detail_for

    detail = detail_for(line(), decode=True)
    labels = {label for label, _value, _colour in detail.fields}

    assert detail.source == "access.log:36"
    assert labels >= {"GET", "200", "ua"}
    assert any("' OR '1'='1" in value for _l, value, _c in detail.fields)


def test_the_detail_holds_the_original_line_byte_for_byte() -> None:
    """The proof. Everything else here is a reading of it, and a reading is
    only allowed while the thing it reads stays reachable and unaltered."""
    from logarc.gui.evidence_view import detail_for

    evidence = line()

    assert detail_for(evidence, decode=True).raw == evidence.text


def test_the_detail_shows_the_full_agent_not_a_shortened_one() -> None:
    """The table has no room and the detail has plenty. A scanner signature
    must never be cut in the one place it can be read in full."""
    from logarc.gui.evidence_view import detail_for

    agent = "Mozilla/5.0 " + "x" * 200

    detail = detail_for(line(agent=agent), decode=True)

    assert any(value == agent for _l, value, _c in detail.fields)


def test_an_integrity_warning_reaches_the_detail() -> None:
    """A source that changed size since ingest may not hold the line that
    produced the finding, and that has to be said next to the line."""
    from logarc.gui.evidence_view import detail_for

    evidence = EvidenceLine(
        ref=EvidenceRef("access.log", 1),
        source_path="access.log",
        text="raw",
        note="access.log has changed size since ingest",
        verified=False,
    )

    assert "changed size" in (detail_for(evidence, decode=True).note or "")
