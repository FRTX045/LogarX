"""A stand-in for the CRS sidecar process, spoken to over fake pipes.

`run_sidecar` keeps each sidecar for a whole run and sends it one share after
another, each ended by `{"flush": N}`. This fake answers at that boundary the
way the real one does: the answers to everything before the marker, then
`{"flushed": N}`. By default it reports 942100 for any record whose target
holds `union` — a pure function of what it is sent, as the real sidecar is —
so what a test checks is the bookkeeping around it: who is sent what, by which
process, and who gets whose answer.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
from collections.abc import Callable, Iterator
from typing import Any

Record = dict[str, Any]


def union_rule(records: list[Record]) -> list[str]:
    """942100 for every record whose target holds `union`, as JSON lines."""
    return [
        json.dumps(
            {
                "line_no": record["line_no"],
                "rule_id": 942100,
                "severity": "CRITICAL",
                "msg": "SQL Injection Attack Detected via libinjection",
                "matched_var": "ARGS:q",
                "transformed_value": record["raw_target"],
                "attack_family": "attack-sqli",
                "paranoia_level": 1,
                "tags": ["attack-sqli"],
                "capec": [],
            }
        )
        for record in records
        if "union" in record["raw_target"].lower()
    ]


class _Stream:
    """The reading end of a fake pipe: lines until the process has exited."""

    def __init__(self) -> None:
        self._lines: queue.Queue[str | None] = queue.Queue()
        self.closed = False

    def put(self, line: str | None) -> None:
        self._lines.put(line)

    def __iter__(self) -> Iterator[str]:
        while (line := self._lines.get()) is not None:
            yield line + "\n"

    def close(self) -> None:
        self.closed = True


class _Input:
    """The writing end: each complete line is handed to the process as written."""

    def __init__(self, process: FakeProcess) -> None:
        self._process = process
        self._partial = ""
        self.closed = False

    def write(self, text: str) -> int:
        # As a real pipe does: writing to a process that has exited fails —
        # unless the fake is told this pipe takes the write anyway.
        exited = self._process.returncode is not None
        if self.closed or (exited and not self._process.crs.pipe_outlives_process):
            raise BrokenPipeError("stdin is closed")
        lines = (self._partial + text).split("\n")
        self._partial = lines.pop()
        for line in lines:
            self._process.receive(line)
        return len(text)

    def flush(self) -> None:
        if self.closed:
            raise BrokenPipeError("stdin is closed")

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._process.end_of_input()


class FakeProcess:
    """One sidecar: records accumulate until a flush marker, then are answered."""

    def __init__(self, crs: FakeCrs) -> None:
        self.crs = crs
        self._crs = crs
        self._pending: list[Record] = []
        self.stdin = _Input(self)
        self.stdout = _Stream()
        self.stderr = _Stream()
        self.returncode: int | None = None
        self.shares = 0
        if crs.fail_at_start is not None:
            self._exit(1, crs.fail_at_start)

    def receive(self, line: str) -> None:
        if self.returncode is not None or not line.strip():
            return
        data = json.loads(line)
        if set(data) != {"flush"}:
            self._pending.append(data)
            return
        records, self._pending = self._pending, []
        self.shares += 1
        if self._crs.fail_on_share == self._crs.total_shares() + 1:
            self._exit(2, "crs-sidecar: something broke mid-share")
            return
        for answer in self._crs.share(records):
            self.stdout.put(answer)
        self.stdout.put(json.dumps({"flushed": data["flush"]}))

    def end_of_input(self) -> None:
        if self.returncode is None:
            self._exit(0, "crs-sidecar: processed")

    def _exit(self, code: int, message: str) -> None:
        self.returncode = code
        self.stderr.put(message)
        self.stdout.put(None)
        self.stderr.put(None)

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("crs-sidecar", timeout or 0)
        return self.returncode

    def kill(self) -> None:
        self._crs.killed += 1
        if self.returncode is None:
            self._exit(-9, "killed")


class FakeCrs:
    """Stands in for `subprocess.Popen` of the sidecar, and keeps the books.

    `calls` is the size of each share, in the order they were answered;
    `spawned` the processes started. `answer` turns a share's records into the
    sidecar's output lines; `fail_at_start` makes every process exit at once
    with that message on stderr, as a sidecar that cannot load its rules does;
    `fail_on_share` makes the nth share across all processes kill its process
    before answering; `pipe_outlives_process` lets a write to a process that
    has exited succeed, the worst a pipe could do.
    """

    def __init__(self, answer: Callable[[list[Record]], list[str]] = union_rule) -> None:
        self.answer = answer
        self.sent: list[Record] = []
        self.calls: list[int] = []
        self.processes: list[FakeProcess] = []
        self.fail_at_start: str | None = None
        self.fail_on_share: int | None = None
        self.pipe_outlives_process = False
        self.killed = 0
        self._lock = threading.Lock()

    @property
    def spawned(self) -> int:
        return len(self.processes)

    def __call__(self, *_args: object, **_kwargs: object) -> FakeProcess:
        process = FakeProcess(self)
        with self._lock:
            self.processes.append(process)
        return process

    def share(self, records: list[Record]) -> list[str]:
        with self._lock:
            self.sent.extend(records)
            self.calls.append(len(records))
        return self.answer(records)

    def total_shares(self) -> int:
        return len(self.calls)

    def lines_sent(self) -> list[int]:
        return [record["line_no"] for record in self.sent]

    def all_closed(self) -> bool:
        return all(process.returncode is not None for process in self.processes)
