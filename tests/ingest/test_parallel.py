"""Ingesting one log with several worker processes.

These really spawn processes. Mocking the pool would test the arithmetic and
miss the whole class of failure that matters here: on Windows a worker is
started by spawn rather than fork, so everything it touches crosses a pickle
boundary and its module is imported afresh. That is the failure this project has
already been bitten by once — it produces zero results while appearing to
succeed, which no assertion about counts would catch.

The property under test is always the same: **parallel ingest must store
exactly what sequential ingest stores.** Faster is worthless if a line goes
missing, and a lost line looks like a successful run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logarc.case import Case
from logarc.ingest.parallel import can_split

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def write_log(path: Path, lines: int, *, damaged: int = 0) -> Path:
    rows = []
    for n in range(lines):
        when = (START + timedelta(seconds=n)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        client = f"203.0.113.{n % 97}"
        rows.append(f'{client} - - [{when}] "GET /page/{n} HTTP/1.1" 200 512 "-" "Mozilla/5.0"')
    for index in range(damaged):
        rows.insert(min((index + 1) * 7, len(rows)), "this line is not a log line at all")
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def stored(case_root: Path) -> list[tuple[str, int, str]]:
    """Every event, as (client, line number, path) — the chain of custody."""
    with Case.open(case_root) as case:
        return sorted(
            (event.client_ip, event.evidence.line_no, event.path or "")
            for event in case.store.all_events()
        )


@pytest.fixture(autouse=True)
def split_small_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the parallel path on test-sized inputs.

    The real threshold is 32 MB, below which spawning costs more than parsing
    saves. Without this the tests would fall back to the sequential path and
    pass while proving nothing — the exact shape of vacuous test this file is
    written to avoid.
    """
    monkeypatch.setattr("logarc.ingest.parallel.MIN_PARALLEL_BYTES", 1)


def ingest(root: Path, log: Path, *, workers: int) -> tuple[list[tuple[str, int, str]], object]:
    with Case.create(root) as case:
        results = case.ingest([log], workers=workers)
        case.finalize()
    return stored(root), results[0]


def test_an_unrecognisable_log_fails_the_same_way_on_both_paths(tmp_path: Path) -> None:
    """Format detection is resolved before any worker starts, and it must refuse
    in the same words the sequential path refuses in.

    Untested until now, and the two paths held a copy each of the message. Two
    copies of a sentence are one edit away from disagreeing, and this one names
    the flag that fixes the problem — an investigator following the parallel
    path's advice would be following whatever it happened to still say.
    """
    from logarc.ingest.parallel import ingest_file_parallel
    from logarc.ingest.pipeline import FormatDetectionError

    log = tmp_path / "not-a-log.txt"
    log.write_text("this is prose\nand so is this\n", encoding="utf-8")

    with pytest.raises(FormatDetectionError) as raised:
        ingest_file_parallel(
            log, tmp_path / "case", file_id="not-a-log.txt", workers=2, batch_size=10
        )

    assert "--format" in str(raised.value), "the refusal has to name the way out"
    assert str(log) in str(raised.value)


@pytest.mark.slow
@pytest.mark.parametrize("workers", [2, 3])
def test_parallel_ingest_stores_exactly_what_sequential_does(tmp_path: Path, workers: int) -> None:
    """The one assertion the feature stands or falls on."""
    log = write_log(tmp_path / "access.log", 1_200)

    sequential, one = ingest(tmp_path / "seq", log, workers=1)
    parallel, many = ingest(tmp_path / "par", log, workers=workers)

    assert parallel == sequential
    assert many.events_parsed == one.events_parsed
    assert many.lines_read == one.lines_read


@pytest.mark.slow
def test_the_digest_is_the_same_however_many_workers_read_the_file(tmp_path: Path) -> None:
    """SHA-256 covers the file as stored and is what a finding is checked
    against. It must not depend on how the tool happened to read it."""
    log = write_log(tmp_path / "access.log", 600)

    _events, one = ingest(tmp_path / "seq", log, workers=1)
    _events, many = ingest(tmp_path / "par", log, workers=3)

    assert many.sha256 == one.sha256


@pytest.mark.slow
def test_damaged_lines_are_all_quarantined_whoever_finds_them(tmp_path: Path) -> None:
    """Each worker quarantines into its own file; the merge must lose none of
    them. Undercounting here would explain away a short event count with a
    number that is itself wrong."""
    log = write_log(tmp_path / "access.log", 400, damaged=6)

    _events, one = ingest(tmp_path / "seq", log, workers=1)
    _events, many = ingest(tmp_path / "par", log, workers=3)

    assert one.lines_quarantined == 6
    assert many.lines_quarantined == 6
    merged = (tmp_path / "par" / "quarantine" / "unparsed.jsonl").read_text(encoding="utf-8")
    assert len(merged.strip().splitlines()) == 6


@pytest.mark.slow
def test_a_compressed_log_still_ingests_when_workers_are_asked_for(tmp_path: Path) -> None:
    """gzip has no random access, so it cannot be split. Asking for workers must
    fall back rather than fail — the alternative is a flag that breaks on a file
    the tool otherwise reads happily."""
    import gzip

    plain = write_log(tmp_path / "access.log", 300)
    packed = tmp_path / "access.log.gz"
    packed.write_bytes(gzip.compress(plain.read_bytes()))

    _events, result = ingest(tmp_path / "gz", packed, workers=4)

    assert result.events_parsed == 300


@pytest.mark.slow
def test_the_parallel_path_is_the_one_being_exercised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guards every other test in this file.

    Sequential and parallel ingest produce identical results by design, so a
    fallback that fired when it should not would leave all of them passing
    while none of them tested anything. This is the one assertion that cannot
    be satisfied by the fallback.
    """
    import logarc.case as case_module

    calls: list[int] = []
    real = case_module.ingest_file_parallel

    def spy(*args: object, **kwargs: object) -> object:
        calls.append(int(kwargs["workers"]))  # type: ignore[call-overload]
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(case_module, "ingest_file_parallel", spy)
    log = write_log(tmp_path / "access.log", 300)

    ingest(tmp_path / "par", log, workers=3)

    assert calls == [3]


@pytest.mark.slow
def test_a_log_too_small_to_be_worth_splitting_stays_sequential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Below the threshold, spawning costs more than parsing saves."""
    import logarc.case as case_module

    monkeypatch.setattr("logarc.ingest.parallel.MIN_PARALLEL_BYTES", 1 << 30)
    called = False

    def spy(*_args: object, **_kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("should not have taken the parallel path")

    monkeypatch.setattr(case_module, "ingest_file_parallel", spy)
    log = write_log(tmp_path / "access.log", 100)

    _events, result = ingest(tmp_path / "seq", log, workers=4)

    assert not called
    assert result.events_parsed == 100


def test_a_compressed_log_is_not_splittable(tmp_path: Path) -> None:
    import gzip

    plain = write_log(tmp_path / "access.log", 50)
    packed = tmp_path / "access.log.gz"
    packed.write_bytes(gzip.compress(plain.read_bytes()))

    assert can_split(plain) is True
    assert can_split(packed) is False
