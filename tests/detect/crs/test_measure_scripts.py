"""`tools/measure/` takes the CRS figures in crs/README.md.

The scripts are run by hand against the dataset tiers, which are not in the
repository, so nothing else would notice when a change to the sidecar's
interface broke one. Each is run here on a three-line case with a stand-in for
the sidecar process, which proves it still works with logarc, not that its
timings mean anything.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from types import ModuleType

import pytest
from fake_sidecar import FakeCrs, Record, union_rule

from logarc.case import Case
from logarc.core.event import NormalizedEvent
from logarc.detect.crs import sidecar
from logarc.detect.crs.sidecar import SidecarConfig

ROOT = Path(__file__).resolve().parents[3]
MEASURE = ROOT / "tools" / "measure"

LINES = [
    '203.0.113.5 - - [01/May/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "curl/8.0"',
    "203.0.113.5 - - [01/May/2024:10:00:01 +0000] "
    '"GET /search?q=1%27+UNION+SELECT+pw HTTP/1.1" 200 512 "-" "curl/8.0"',
    '198.51.100.7 - - [01/May/2024:10:00:02 +0000] "GET /about HTTP/1.1" 200 512 "-" "curl/8.0"',
]


def _script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"measure_{name}", MEASURE / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def case(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    root = tmp_path / "case"
    with Case.create(root) as made:
        made.ingest([log])
    return root


@pytest.fixture
def ruleset(tmp_path: Path) -> Path:
    (tmp_path / "ruleset" / "rules").mkdir(parents=True)
    return tmp_path / "ruleset"


def _build(tmp_path: Path, name: str) -> Path:
    binary = tmp_path / f"{name}.exe"
    binary.write_text("", encoding="utf-8")
    return binary


def test_crs_replay_times_every_setup_and_checks_they_agree(
    case: Path,
    ruleset: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    crs = FakeCrs()
    monkeypatch.setattr(subprocess, "Popen", crs)
    a, b = _build(tmp_path, "a"), _build(tmp_path, "b")
    # A case this small is one share whatever the worker count, so the count
    # cannot be seen in the processes started; it is checked where it is asked.
    asked: list[tuple[str, int | None]] = []
    replay = sidecar.run_sidecar

    def watched(
        events: Iterable[NormalizedEvent], *, config: SidecarConfig, workers: int | None
    ) -> list[sidecar.CrsDetection]:
        asked.append((config.binary.stem, workers))
        return replay(events, config=config, workers=workers)

    monkeypatch.setattr(sidecar, "run_sidecar", watched)

    code = _script("crs_replay").main(
        [
            str(case),
            *("--binary", str(a), "--binary", str(b)),
            *("--workers", "1", "--workers", "2"),
            *("--rules", str(ruleset), "--rounds", "2"),
        ]
    )
    printed = capsys.readouterr().out

    assert code == 0, printed
    assert [line.split("  ")[0] for line in printed.splitlines() if "median" in line] == [
        "a x1",
        "a x2",
        "b x1",
        "b x2",
    ]
    assert printed.count("same detections") == 4
    assert "detections in a x1's first run: 1" in printed
    assert {process.argv[0] for process in crs.processes} == {str(a), str(b)}
    # Every setup each round, and the second round starts one setup later.
    assert asked == [("a", 1), ("a", 2), ("b", 1), ("b", 2), ("a", 2), ("b", 1), ("b", 2), ("a", 1)]


def test_crs_replay_says_when_runs_found_different_things(
    case: Path,
    ruleset: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    shares: list[int] = []

    def only_the_first_time(records: list[Record]) -> list[str]:
        shares.append(len(records))
        return union_rule(records) if len(shares) == 1 else []

    monkeypatch.setattr(subprocess, "Popen", FakeCrs(answer=only_the_first_time))

    code = _script("crs_replay").main(
        [
            str(case),
            *("--binary", str(_build(tmp_path, "a")), "--rules", str(ruleset)),
            *("--workers", "1", "--rounds", "2"),
        ]
    )

    assert code == 1
    assert "DIFFERENT detections from a x1 in 1 of 2 runs" in capsys.readouterr().out


def test_crs_startup_starts_one_sidecar_per_round(
    ruleset: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    crs = FakeCrs()
    monkeypatch.setattr(subprocess, "Popen", crs)

    code = _script("crs_startup").main(
        ["--binary", str(_build(tmp_path, "a")), "--rules", str(ruleset), "--rounds", "3"]
    )

    assert code == 0
    assert crs.spawned == 3
    assert crs.all_closed()
    assert "a.exe: median" in capsys.readouterr().out


def test_memsum_reports_the_peak_of_the_total_and_of_each_process(tmp_path: Path) -> None:
    mb = 1024 * 1024
    samples = tmp_path / "mem.txt"
    samples.write_text(
        f"1:{10 * mb}:{20 * mb}:{10 * mb} 2:{30 * mb}:{40 * mb}:{30 * mb}\n"
        f"1:{50 * mb}:{60 * mb}:{50 * mb}\n",
        encoding="ascii",
    )

    summary = _script("memsum").summarise(samples)

    assert summary == (
        "2 processes at most; peak total working set 50 MB, peak total private 60 MB; "
        "per-process peak working set 30-50 MB"
    )


def test_ui_latency_starts() -> None:
    """It needs a real sidecar and a real event loop to measure anything, so
    this only proves it still imports what it uses."""
    pytest.importorskip("PyQt6")

    done = subprocess.run(
        [sys.executable, str(MEASURE / "ui_latency.py"), "--help"],
        capture_output=True,
        text=True,
    )

    assert done.returncode == 0, done.stderr
