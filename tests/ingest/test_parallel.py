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

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logarc.case import Case
from logarc.ingest.parallel import can_split
from logarc.parsers.registry import register_spec, unregister_format
from logarc.parsers.spec import LogFormatSpec

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


def ingest(
    root: Path, log: Path, *, workers: int, max_line_bytes: int | None = None
) -> tuple[list[tuple[str, int, str]], object]:
    extra = {} if max_line_bytes is None else {"max_line_bytes": max_line_bytes}
    with Case.create(root) as case:
        results = case.ingest([log], workers=workers, **extra)
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


def test_the_line_length_bound_holds_on_the_parallel_path_too(tmp_path: Path) -> None:
    """A worker runs its own loop, not `ingest_file`.

    So the bound that stops a 16 MB line costing 5.5 GB to parse had to be put
    in two places, and a fix present in only one of them would mean `--workers`
    quietly reopened the hole — the shape of defect this whole suite exists to
    catch: the sequential path passing while the parallel one loses or eats
    something.
    """
    log = write_log(tmp_path / "access.log", 400)
    huge = (
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /'
        + "a" * 300_000
        + ' HTTP/1.1" 200 1 "-" "x"'
    )
    with log.open("a", encoding="utf-8") as handle:
        handle.write(huge + "\n")

    _events, one = ingest(tmp_path / "seq", log, workers=1, max_line_bytes=50_000)
    _events, many = ingest(tmp_path / "par", log, workers=3, max_line_bytes=50_000)

    assert one.lines_quarantined == 1
    assert many.lines_quarantined == 1, "the worker path must bound it too"
    assert one.events_parsed == many.events_parsed == 400


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


# ---------------------------------------------------------------------------
# A format the worker's own import cannot know about
# ---------------------------------------------------------------------------

#: Pipe-separated, so no built-in format matches it and auto-detection has
#: nothing to fall back on. Reading this log at all requires the definition the
#: parent process was given.
PIPED = '%h|%t|"%r"|%>s|%b'


def write_piped_log(path: Path, lines: int) -> Path:
    rows = []
    for n in range(lines):
        when = (START + timedelta(seconds=n)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        rows.append(f'203.0.113.{n % 97}|[{when}]|"GET /page/{n} HTTP/1.1"|200|512')
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def test_a_worker_parses_with_a_format_the_parent_invented(tmp_path: Path) -> None:
    """The centre of the whole design.

    A worker started by spawn re-imports `logarc.parsers.registry`, which builds
    itself from the three built-in presets and nothing else. A format registered
    here, in the parent, is simply not there in the child — so passing its
    *name* across cannot work, and the only fix is to send the definition.

    Written against the real pool rather than a mock, because the failure being
    prevented lives entirely in the pickle boundary.
    """
    log = write_piped_log(tmp_path / "access.log", lines=400)
    register_spec(LogFormatSpec(name="pipes", directive=PIPED))
    try:
        with Case.create(tmp_path / "case") as case:
            results = case.ingest([log], log_format="pipes", workers=3)
    finally:
        unregister_format("pipes")

    assert results[0].events_parsed == 400
    assert results[0].lines_quarantined == 0
    assert results[0].log_format == "pipes"


def test_a_parallel_ingest_records_the_definition_it_used(tmp_path: Path) -> None:
    """The same definition has to reach the case, not only the workers: it is
    what makes the case readable after the format is edited or deleted."""
    log = write_piped_log(tmp_path / "access.log", lines=400)
    register_spec(LogFormatSpec(name="pipes", directive=PIPED))
    try:
        with Case.create(tmp_path / "case") as case:
            case.ingest([log], log_format="pipes", workers=3)
    finally:
        unregister_format("pipes")

    with Case.open(tmp_path / "case") as reopened:
        source = reopened.manifest.sources[0]

    assert source.format_spec is not None
    assert source.format_spec["directive"] == PIPED


def test_parallel_and_sequential_record_the_same_definition(tmp_path: Path) -> None:
    log = write_piped_log(tmp_path / "access.log", lines=400)
    register_spec(LogFormatSpec(name="pipes", directive=PIPED))
    try:
        with Case.create(tmp_path / "seq") as case:
            case.ingest([log], log_format="pipes", workers=1)
        with Case.create(tmp_path / "par") as case:
            case.ingest([log], log_format="pipes", workers=3)
    finally:
        unregister_format("pipes")

    with Case.open(tmp_path / "seq") as one, Case.open(tmp_path / "par") as many:
        assert one.manifest.sources[0].format_spec == many.manifest.sources[0].format_spec


def test_the_default_worker_count_is_bounded_rather_than_the_core_count() -> None:
    """Measured 2026-09-15 on an 84 MB log, four physical cores behind eight
    logical, polling RSS across the whole process tree:

        workers   speed-up   peak RSS
              1      1.00x      326 MB
              2      1.86x      603 MB
              4      2.61x      969 MB
              6      2.75x    1,339 MB
              8      2.68x    1,448 MB

    Two things decide the default. Speed peaks at six and *falls* at eight, so
    "one worker per logical core" is slower than stopping earlier as well as
    hungrier. And memory grows faster than speed everywhere: four buys 2.61x for
    2.98x the memory, and going on to six buys 5% more speed for 38% more.

    So the default is capped rather than taken from the core count. A
    sixty-four-core server must not try sixty-four workers and ask for twenty
    gigabytes on a log it could have read in one process.
    """
    from logarc.ingest.parallel import DEFAULT_WORKERS, MAX_DEFAULT_WORKERS

    assert 1 <= DEFAULT_WORKERS <= MAX_DEFAULT_WORKERS
    assert (os.cpu_count() or 1) >= DEFAULT_WORKERS, "never more workers than cores"


def test_a_single_core_machine_does_not_try_to_split(monkeypatch: pytest.MonkeyPatch) -> None:
    """Spawning costs more than it saves when there is nowhere to spawn to."""
    from logarc.ingest import parallel

    monkeypatch.setattr(parallel.os, "cpu_count", lambda: 1)
    assert parallel.default_workers() == 1


def test_a_large_machine_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    from logarc.ingest import parallel

    monkeypatch.setattr(parallel.os, "cpu_count", lambda: 64)
    assert parallel.default_workers() == parallel.MAX_DEFAULT_WORKERS


def test_an_unknown_core_count_falls_back_to_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """`os.cpu_count()` is documented as returning None when it cannot tell.
    Reading that as "lots" would be the wrong way to be wrong."""
    from logarc.ingest import parallel

    monkeypatch.setattr(parallel.os, "cpu_count", lambda: None)
    assert parallel.default_workers() == 1
