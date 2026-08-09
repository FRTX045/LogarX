"""Reading back the raw log lines a finding rests on.

The whole design turns on every node tracing to a source line. Until now
nothing could actually fetch one, so the claim was structural rather than
demonstrable.
"""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from logarc.case import Case
from logarc.core.evidence import EvidenceRef

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"',
    '198.51.100.9 - - [10/Oct/2020:13:56:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8"',
]


@pytest.fixture
def case(tmp_path: Path) -> Case:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as opened:
        opened.ingest([log])
    return Case.open(tmp_path / "case")


def test_a_reference_returns_the_line_it_points_at(case: Case) -> None:
    (line,) = case.read_evidence([EvidenceRef("access.log", 2)])

    assert line.available
    assert line.text == LINES[1]
    assert line.ref == EvidenceRef("access.log", 2)


def test_references_come_back_in_the_order_they_were_asked_for(case: Case) -> None:
    refs = [EvidenceRef("access.log", 3), EvidenceRef("access.log", 1)]

    lines = case.read_evidence(refs)

    assert [item.ref.line_no for item in lines] == [3, 1]
    assert [item.text for item in lines] == [LINES[2], LINES[0]]


def test_a_line_past_the_end_of_the_file_is_reported_not_raised(case: Case) -> None:
    (line,) = case.read_evidence([EvidenceRef("access.log", 9999)])

    assert not line.available
    assert line.text is None
    assert "only 3 lines" in (line.note or "")


def test_an_unknown_source_file_is_reported(case: Case) -> None:
    (line,) = case.read_evidence([EvidenceRef("nowhere.log", 1)])

    assert not line.available
    assert "not part of this case" in (line.note or "")


def test_a_source_that_has_gone_missing_is_reported_rather_than_crashing(
    case: Case, tmp_path: Path
) -> None:
    """Evidence outlives the file it came from. Saying so is the point."""
    (tmp_path / "access.log").unlink()

    (line,) = case.read_evidence([EvidenceRef("access.log", 1)])

    assert not line.available
    assert "cannot" in (line.note or "").lower() or "missing" in (line.note or "").lower()


def test_a_source_that_changed_since_ingest_is_flagged(case: Case, tmp_path: Path) -> None:
    """A line read out of an altered file is not the line that was ingested."""
    (tmp_path / "access.log").write_text("\n".join(LINES) + "\nextra\n", encoding="utf-8")

    (line,) = case.read_evidence([EvidenceRef("access.log", 1)])

    assert line.text == LINES[0]
    assert not line.verified
    assert "changed" in (line.note or "")


def test_an_unchanged_source_is_marked_verified(case: Case) -> None:
    (line,) = case.read_evidence([EvidenceRef("access.log", 1)])

    assert line.verified
    assert line.note is None


def test_a_compressed_source_is_read_too(tmp_path: Path) -> None:
    log = tmp_path / "access.log.gz"
    with gzip.open(log, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(LINES) + "\n")
    with Case.create(tmp_path / "case") as opened:
        opened.ingest([log])

    with Case.open(tmp_path / "case") as opened:
        (line,) = opened.read_evidence([EvidenceRef("access.log.gz", 2)])

    assert line.available
    assert line.text == LINES[1]


def test_many_references_to_one_file_are_all_resolved(case: Case) -> None:
    refs = [EvidenceRef("access.log", n) for n in (1, 2, 3, 2, 1)]

    lines = case.read_evidence(refs)

    assert [item.text for item in lines] == [LINES[0], LINES[1], LINES[2], LINES[1], LINES[0]]


def test_asking_for_nothing_returns_nothing(case: Case) -> None:
    assert case.read_evidence([]) == []


def test_the_line_names_the_file_it_came_from(case: Case, tmp_path: Path) -> None:
    (line,) = case.read_evidence([EvidenceRef("access.log", 1)])

    assert Path(line.source_path) == tmp_path / "access.log"
