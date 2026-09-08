"""Throughput and memory measurement.

Small sizes here — the point is that the harness reports true numbers, not that
this machine is fast. The figures for a paper come from running the command at
the sizes it is meant for.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logarc.evaluation.benchmark import BenchmarkError, run_benchmark
from logarc.evaluation.memory import peak_rss_bytes

EXCERPT = Path(__file__).parent.parent / "data" / "apache-shopfront"


def test_peak_memory_is_a_real_number_on_this_platform() -> None:
    reading = peak_rss_bytes()

    assert reading > 1_000_000, "a running Python process uses more than a megabyte"


def test_peak_memory_never_falls() -> None:
    """It is a high-water mark, not a current reading."""
    first = peak_rss_bytes()
    ballast = bytearray(64 * 1024 * 1024)
    second = peak_rss_bytes()
    del ballast

    assert second >= first
    assert peak_rss_bytes() >= second


@pytest.fixture(scope="module")
def measured(tmp_path_factory: pytest.TempPathFactory) -> list[object]:
    workdir = tmp_path_factory.mktemp("bench")
    return list(run_benchmark([1_000, 2_000], log=EXCERPT / "excerpt.log", workdir=Path(workdir)))


def test_every_requested_size_is_measured(measured: list) -> None:  # type: ignore[type-arg]
    assert [result.lines for result in measured] == [1_000, 2_000]


def test_the_result_names_the_log_it_measured(measured: list) -> None:  # type: ignore[type-arg]
    assert measured[0].source == "excerpt.log"


def test_throughput_is_reported(measured: list) -> None:  # type: ignore[type-arg]
    for result in measured:
        assert result.ingest_seconds > 0
        assert result.lines_per_second > 0
        assert result.megabytes_per_second > 0


def test_memory_is_measured_per_run_not_across_them(measured: list) -> None:  # type: ignore[type-arg]
    """Each size runs in its own process, so a peak cannot leak into the next."""
    for result in measured:
        assert result.peak_rss_bytes > 1_000_000


def test_the_store_is_smaller_than_the_log_it_came_from(measured: list) -> None:  # type: ignore[type-arg]
    for result in measured:
        assert result.store_bytes > 0
        assert result.compression_ratio > 1.0


def test_reconstruction_is_timed_separately_from_ingest(measured: list) -> None:  # type: ignore[type-arg]
    """The two-pass claim: ingest is paid once, analysis is paid per question."""
    for result in measured:
        assert result.analysed_ip
        assert result.analysed_requests > 0
        assert result.analyse_seconds >= 0


def test_results_serialise_for_a_paper_table(measured: list) -> None:  # type: ignore[type-arg]
    payload = measured[0].to_dict()

    assert payload["lines"] == 1_000
    assert payload["source"] == "excerpt.log"
    assert payload["lines_per_second"] > 0
    assert payload["peak_rss_mb"] > 0
    assert "generate_seconds" not in payload


def test_a_size_beyond_the_log_is_refused_not_padded(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkError, match="only"):
        list(run_benchmark([10_000_000], log=EXCERPT / "excerpt.log", workdir=tmp_path))


def test_a_size_that_is_not_a_count_is_refused(tmp_path: Path) -> None:
    """Zero and negative sizes must not reach the worker.

    A negative size fell through the prefix loop, read the whole log, and
    reported the size it was asked for beside a throughput derived from it.
    That is a row that looks like a measurement and is not one.
    """
    for size in (0, -1):
        with pytest.raises(BenchmarkError, match="at least one line"):
            list(run_benchmark([size], log=EXCERPT / "excerpt.log", workdir=tmp_path))


def test_one_bad_size_stops_the_whole_run(tmp_path: Path) -> None:
    """Sizes are sorted, so a negative one would otherwise be measured first."""
    with pytest.raises(BenchmarkError, match="at least one line"):
        list(run_benchmark([-1, 100], log=EXCERPT / "excerpt.log", workdir=tmp_path))


def test_a_missing_log_is_reported_rather_than_silently_skipped(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkError, match="not_a_log"):
        list(run_benchmark([10], log=tmp_path / "not_a_log.log", workdir=tmp_path))
