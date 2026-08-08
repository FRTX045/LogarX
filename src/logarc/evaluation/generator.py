"""Synthetic access logs with a known answer.

Real logs cannot be used to measure accuracy, because nobody knows what is in
them — that is the problem the tool exists to solve. So the evaluation needs
traffic whose content is known by construction, and this writes it.

Clients are run concurrently and merged on time, the way a real server sees
them: a scanner's burst arrives interleaved with three people shopping, not
neatly after them. Interleaving is the whole difficulty of per-IP
reconstruction, and a generator that emitted one client at a time would hide it.

The merge is a heap over the currently active clients, so memory is bounded by
the number of clients rather than the length of the run. Ten million lines
generates in constant space.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from heapq import heappop, heappush
from random import Random
from typing import TYPE_CHECKING, Final

from logarc.evaluation.scenarios import SCENARIOS, Role, Scenario, Step
from logarc.evaluation.truth import TruthRecord, TruthWriter

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

__all__ = [
    "DEFAULT_SEED",
    "DEFAULT_START",
    "SCENARIOS",
    "GenerationError",
    "GenerationResult",
    "generate",
    "write_log",
]

DEFAULT_SEED: Final = 20240501
DEFAULT_START: Final = datetime(2024, 5, 1, 0, 0, tzinfo=UTC)

#: Written every this many lines, so a long run reports progress.
PROGRESS_INTERVAL: Final = 100_000

_MONTHS: Final = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)  # fmt: skip


class GenerationError(ValueError):
    """Raised when a log cannot be generated as asked."""


@dataclass(frozen=True, slots=True)
class GenerationResult:
    """What was written, for the caller to report."""

    path: Path
    truth_path: Path | None
    scenario: str
    seed: int
    lines: int
    bytes_written: int
    elapsed_seconds: float

    @property
    def megabytes(self) -> float:
        return self.bytes_written / 1_048_576


@dataclass(slots=True)
class _Live:
    """A client that is currently making requests."""

    role: Role
    client_ip: str
    user_agent: str
    steps: Iterator[Step]
    pending: Step
    activity: str
    instance_id: str


def generate(
    scenario: str,
    *,
    lines: int,
    seed: int = DEFAULT_SEED,
    start: datetime = DEFAULT_START,
) -> Iterator[tuple[str, TruthRecord]]:
    """Yield `(log line, what it really is)` pairs, in time order."""
    spec = _lookup(scenario)
    if lines < 0:
        raise GenerationError(f"cannot generate {lines} lines")

    rng = Random(seed)
    heap: list[tuple[float, int, _Live]] = []
    counters: dict[str, int] = {role.name: 0 for role in spec.mix}
    sequence = 0
    instances = 0
    clock = _Clock(start)

    for role in spec.mix:
        live, instances = _spawn(role, rng, counters, instances)
        heappush(heap, (rng.uniform(0.0, 60.0), sequence, live))
        sequence += 1

    for line_no in range(1, lines + 1):
        at, _, live = heappop(heap)
        step = live.pending

        yield (
            _format(live, step, clock.at(at)),
            TruthRecord(
                line_no=line_no,
                client_ip=live.client_ip,
                category=step.category,
                instance_id=live.instance_id,
            ),
        )

        following = next(live.steps, None)
        if following is None:
            # This client is finished. Another of the same kind takes its
            # place, so the mix stays constant for the whole run.
            live, instances = _spawn(live.role, rng, counters, instances)
            at += rng.uniform(1.0, 120.0)
            following = live.pending

        if following.activity != live.activity:
            instances += 1
            live.activity = following.activity
            live.instance_id = f"{live.client_ip}#{instances}"
        live.pending = following

        heappush(heap, (at + max(following.gap, 0.0), sequence, live))
        sequence += 1


def write_log(
    path: Path,
    *,
    scenario: str,
    lines: int,
    seed: int = DEFAULT_SEED,
    truth_path: Path | None = None,
    start: datetime = DEFAULT_START,
    on_progress: Callable[[int], None] | None = None,
) -> GenerationResult:
    """Write a synthetic log, and optionally the record of what it contains.

    Truth is optional because it is the expensive half and the benchmark has no
    use for it: measuring ingest throughput on ten million lines does not need
    to know what any of them were.
    """
    began = time.perf_counter()
    written = 0

    with (
        _open_truth(truth_path, scenario=scenario, seed=seed, source_file_id=path.name) as truth,
        path.open("wb") as handle,
    ):
        for line_no, (text, record) in enumerate(
            generate(scenario, lines=lines, seed=seed, start=start), start=1
        ):
            written += handle.write(text.encode("utf-8")) + handle.write(b"\n")
            if truth is not None:
                truth.write(record)
            if on_progress is not None and line_no % PROGRESS_INTERVAL == 0:
                on_progress(line_no)

    return GenerationResult(
        path=path,
        truth_path=truth_path,
        scenario=scenario,
        seed=seed,
        lines=lines,
        bytes_written=written,
        elapsed_seconds=time.perf_counter() - began,
    )


def describe_scenarios() -> list[tuple[str, str]]:
    """Every scenario and what it contains, for `--help` and the CLI listing."""
    return [(spec.name, spec.description) for spec in SCENARIOS.values()]


# -- internals ---------------------------------------------------------------


class _Clock:
    """Formats timestamps, reusing the text while the second has not changed.

    At ten million lines the timestamp is formatted ten million times and most
    of those share a second with the line before, so this is most of the cost
    of generation removed for one comparison.
    """

    __slots__ = ("_second", "_start", "_text")

    def __init__(self, start: datetime) -> None:
        self._start = start
        self._second = -1
        self._text = ""

    def at(self, offset: float) -> str:
        second = int(offset)
        if second != self._second:
            moment = self._start + timedelta(seconds=second)
            self._text = (
                f"{moment.day:02d}/{_MONTHS[moment.month - 1]}/{moment.year:04d}:"
                f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d} +0000"
            )
            self._second = second
        return self._text


def _lookup(scenario: str) -> Scenario:
    try:
        return SCENARIOS[scenario]
    except KeyError:
        known = ", ".join(sorted(SCENARIOS))
        raise GenerationError(f"unknown scenario {scenario!r}; choose one of {known}") from None


def _spawn(role: Role, rng: Random, counters: dict[str, int], instances: int) -> tuple[_Live, int]:
    """Start a new client of this role, at the next address in its range."""
    index = counters[role.name]
    counters[role.name] = index + 1
    client_ip = f"100.{role.octet}.{(index >> 8) & 0xFF}.{index & 0xFF}"

    actor = role.build(rng)
    first = next(actor.steps, None)
    if first is None:
        raise GenerationError(f"role {role.name!r} produced a client that does nothing")

    instances += 1
    return (
        _Live(
            role=role,
            client_ip=client_ip,
            user_agent=actor.user_agent,
            steps=actor.steps,
            pending=first,
            activity=first.activity,
            instance_id=f"{client_ip}#{instances}",
        ),
        instances,
    )


def _format(live: _Live, step: Step, stamp: str) -> str:
    """One line of Apache `combined`."""
    target = f"{step.path}?{step.query}" if step.query else step.path
    # Apache logs `-` rather than 0 when a response has no body, and a
    # generator that never emitted it would leave that path untested.
    size = str(step.size) if step.size else "-"
    referer = step.referer or "-"
    return (
        f"{live.client_ip} - - [{stamp}] "
        f'"{step.method} {target} HTTP/1.1" {step.status} {size} '
        f'"{referer}" "{live.user_agent}"'
    )


class _NoTruth:
    """Stands in for a truth writer when none was asked for."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *_: object) -> None:
        return None


def _open_truth(
    path: Path | None, *, scenario: str, seed: int, source_file_id: str
) -> TruthWriter | _NoTruth:
    if path is None:
        return _NoTruth()
    return TruthWriter(path, scenario=scenario, seed=seed, source_file_id=source_file_id)
