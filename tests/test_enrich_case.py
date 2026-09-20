"""Enriching a case with CRS, watchably and stoppably.

The command line already did this, inline, with a spinner. The window needs the
same work with two things the spinner did not have to provide: a figure to draw
a bar from, and a way to stop that keeps what has been found. So the work moved
here and both callers share it — the rule being that anything the window can do
is also scriptable.

**Stopping does not raise, and that is the difference from ingest.** A cancelled
ingest raises `IngestCancelled` because a truncated case that looks complete is
the worst outcome available there. Enrichment only ever *adds* to a case, so a
partial result is a smaller true answer rather than a false one — it stops by
ending the stream cleanly, which is what lets the sidecar return the detections
it already has.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from logarc.case import Case
from logarc.detect.crs.sidecar import CrsDetection
from logarc.enrich import EnrichProgress, enrich_case

if TYPE_CHECKING:
    from collections.abc import Iterable

    from logarc.core.event import NormalizedEvent

START = datetime(2020, 10, 10, 13, 55, tzinfo=UTC)

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /a HTTP/1.1" 200 1 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:37 +0000] "GET /b HTTP/1.1" 200 1 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:38 +0000] "GET /c HTTP/1.1" 200 1 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:39 +0000] "GET /d HTTP/1.1" 200 1 "-" "curl/8.0"',
]


def a_case(root: Path, *, lines: list[str] | None = None) -> Path:
    log = root / "access.log"
    log.write_text("\n".join(lines if lines is not None else LINES) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
        case.finalize()
    return root / "case"


def detection(line_no: int) -> CrsDetection:
    return CrsDetection(
        source_file_id="access.log",
        line_no=line_no,
        rule_id=942100,
        severity="critical",
        msg="SQL Injection",
        matched_var="ARGS:q",
        transformed_value="1' OR 1=1",
        attack_family="attack-sqli",
    )


def replaying_everything(events: Iterable[NormalizedEvent], **_: object) -> list[CrsDetection]:
    """A sidecar that reports one detection per request it is handed."""
    return [detection(one.evidence.line_no) for one in events]


def test_progress_carries_a_denominator_the_bar_can_be_drawn_from(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without a total there is no bar, only a spinner.

    The command line could get away with one because a terminal has nowhere to
    draw a proportion. The manifest knows how many events were parsed, so the
    window does not have to guess or count first.
    """
    monkeypatch.setattr("logarc.enrich.run_sidecar", replaying_everything)
    seen: list[EnrichProgress] = []

    enrich_case(a_case(tmp_path), report=seen.append, every=1)

    assert seen, "nothing reported"
    assert [step.replayed for step in seen] == [1, 2, 3, 4]
    assert {step.total for step in seen} == {4}


def test_stopping_keeps_what_was_already_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The promise the dialog makes, and the reason it can make it."""
    monkeypatch.setattr("logarc.enrich.run_sidecar", replaying_everything)
    case = a_case(tmp_path)

    seen = 0

    def after_two() -> bool:
        nonlocal seen
        seen += 1
        return seen > 2

    outcome = enrich_case(case, should_stop=after_two, every=1)

    assert outcome.stopped is True
    assert outcome.replayed == 2
    assert len(outcome.detections) == 2
    assert outcome.path.exists(), "a stopped run still writes what it found"


def test_a_finished_run_is_not_reported_as_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("logarc.enrich.run_sidecar", replaying_everything)

    outcome = enrich_case(a_case(tmp_path), every=1)

    assert outcome.stopped is False
    assert outcome.replayed == 4
    assert outcome.covered == 4


def test_an_empty_case_is_refused_rather_than_enriched(tmp_path: Path) -> None:
    """Reported as "ingest first" rather than as a missing sidecar.

    Checking afterwards would send somebody to build a Go binary when their real
    problem is that they have not read a log yet.
    """
    (tmp_path / "empty.log").write_text("", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.finalize()

    with pytest.raises(ValueError, match="ingest"):
        enrich_case(tmp_path / "case")
