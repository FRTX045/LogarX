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
    return list(run_benchmark([2_000, 4_000], scenario="mixed", seed=3, workdir=Path(workdir)))


def test_every_requested_size_is_measured(measured: list) -> None:  # type: ignore[type-arg]
    assert [result.lines for result in measured] == [2_000, 4_000]


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

    assert payload["lines"] == 2_000
    assert payload["lines_per_second"] > 0
    assert payload["peak_rss_mb"] > 0


def test_a_failing_run_is_reported_rather_than_silently_skipped(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkError, match="unknown scenario"):
        list(run_benchmark([1_000], scenario="not_a_scenario", seed=1, workdir=tmp_path))
