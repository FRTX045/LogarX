"""Tests for the ingest pipeline."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from logarc.ingest.pipeline import FormatDetectionError, ingest_file
from logarc.ingest.quarantine import Quarantine
from logarc.storage.event_store import ParquetEventStore

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "GET /a HTTP/1.1" 404 0 "-" "curl/8.0"',
    '198.51.100.9 - - [10/Oct/2020:13:56:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8.0"',
]


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def case(tmp_path: Path) -> Path:
    return tmp_path / "case"


def test_events_land_in_the_store_and_can_be_read_back(log: Path, case: Path) -> None:
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        ingest_file(log, store, quarantine)
    store.finalize()

    assert [e.path for e in store.events_for_ip("203.0.113.5")] == ["/", "/a"]


def test_result_reports_what_happened(log: Path, case: Path) -> None:
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(log, store, quarantine)

    assert result.lines_read == 3
    assert result.events_parsed == 3
    assert result.lines_quarantined == 0
    assert result.log_format == "apache-combined"
    assert len(result.sha256) == 64


def test_unparseable_lines_are_quarantined_rather_than_dropped(tmp_path: Path, case: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text("\n".join([*LINES, "<<< truncated write >>>"]) + "\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine)
        assert quarantine.count == 1

    assert result.events_parsed == 3
    assert result.lines_quarantined == 1


def test_blank_lines_are_ignored_without_being_treated_as_damage(
    tmp_path: Path, case: Path
) -> None:
    path = tmp_path / "access.log"
    path.write_text("\n".join([LINES[0], "", "   ", LINES[1]]) + "\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine)

    assert result.events_parsed == 2
    assert result.lines_quarantined == 0


def test_format_is_detected_when_not_specified(log: Path, case: Path) -> None:
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(log, store, quarantine)

    assert result.log_format == "apache-combined"


def test_an_explicit_format_overrides_detection(log: Path, case: Path) -> None:
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(log, store, quarantine, log_format="apache-common")

    # `common` cannot match combined lines, so every line is quarantined rather
    # than silently mis-parsed.
    assert result.log_format == "apache-common"
    assert result.events_parsed == 0
    assert result.lines_quarantined == 3


def test_undetectable_format_fails_loudly(tmp_path: Path, case: Path) -> None:
    """Guessing wrong would quarantine the whole log and look like an empty
    result, which is worse than refusing."""
    path = tmp_path / "not-a-log.txt"
    path.write_text("hello\nworld\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine, pytest.raises(FormatDetectionError, match="not-a-log"):
        ingest_file(path, store, quarantine)


def test_compressed_logs_ingest_the_same_way(tmp_path: Path, case: Path) -> None:
    path = tmp_path / "access.log.gz"
    path.write_bytes(gzip.compress(("\n".join(LINES) + "\n").encode()))

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        result = ingest_file(path, store, quarantine)
    store.finalize()

    assert result.events_parsed == 3
    assert result.compression == "gzip"
    assert len(store.events_for_ip("198.51.100.9")) == 1


def test_events_are_written_in_batches_so_memory_stays_bounded(tmp_path: Path, case: Path) -> None:
    path = tmp_path / "big.log"
    line = LINES[0]
    path.write_text("\n".join([line] * 25) + "\n", encoding="utf-8")

    written: list[int] = []
    store = ParquetEventStore(case)
    original_write = store.write

    def counting_write(events: object) -> None:
        batch = list(events)  # type: ignore[call-overload]
        written.append(len(batch))
        original_write(batch)

    store.write = counting_write  # type: ignore[method-assign]
    with Quarantine(case) as quarantine:
        ingest_file(path, store, quarantine, batch_size=10)

    assert written == [10, 10, 5]


def test_evidence_references_point_at_the_original_line_numbers(tmp_path: Path, case: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text("\n".join(["#comment", *LINES]) + "\n", encoding="utf-8")

    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        ingest_file(path, store, quarantine)
    store.finalize()

    events = store.events_for_ip("203.0.113.5")

    # The comment is line 1, so the first real event is line 2.
    assert [e.evidence.line_no for e in events] == [2, 3]


def test_progress_is_reported_while_reading(log: Path, case: Path) -> None:
    seen: list[int] = []
    store = ParquetEventStore(case)
    with Quarantine(case) as quarantine:
        ingest_file(
            log, store, quarantine, batch_size=1, on_progress=lambda done, _: seen.append(done)
        )

    assert seen == [1, 2, 3]
