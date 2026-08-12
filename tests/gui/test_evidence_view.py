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


def test_the_target_reads_as_the_attack_it_is() -> None:
    assert cell(line(), "Target").text == "/search?q=' OR '1'='1"


def test_the_target_can_be_shown_as_the_log_holds_it() -> None:
    assert cell(line(), "Target", decode=False).text == "/search?q=%27+OR+%271%27%3D%271"


def test_a_served_status_stands_out_and_a_refused_one_recedes() -> None:
    """A 2xx on an injection is the alarm, not the reassurance."""
    served = cell(line(status=200), "Status")
    refused = cell(line(status=403), "Status")

    assert served.colour == EVIDENCE_INK
    assert served.bold
    assert refused.colour == EVIDENCE_MUTED
    assert not refused.bold


def test_numbers_sort_as_numbers() -> None:
    """"1,000" sorts before "9" as text, which would mis-rank the table — and
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
    assert cell(line(), "Target").tooltip == "/search?q=' OR '1'='1"
