"""Replaying each distinct request through CRS once, however often it repeats.

Measured 2026-10-05 on `2026-09-20-medium`: 237,278 requests, of which only
73,427 (30.9%) differ in anything the sidecar sends it. The rest are the same
page, asset or API call made again, and each repeat cost a full CRS
transaction for an answer already known.

**Equal input, equal output** is what makes reusing the answer safe, and it
rests on two facts checked in the source rather than assumed. `crs/main.go`
opens a fresh transaction per record and closes it after, so nothing carries
from one request to the next. And of everything a record holds, only the
client address is not a property of the request — CRS reads it in exactly two
rules, 905100 and 905110, which exempt loopback connections. So an address CRS
could read as loopback keeps its own identity, and every other address is the
same address to CRS.

The fake sidecar here is a pure function of what it is sent, the way the real
one is: it reports 942100 for any record whose target holds `union`. What these
tests check is the bookkeeping around it — who is sent, and who gets whose
answer.
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
import threading
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from fake_sidecar import FakeCrs

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.crs import sidecar
from logarc.detect.crs.sidecar import SidecarConfig, run_sidecar

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

START = datetime(2024, 5, 1, tzinfo=UTC)
ATTACK = "/search?q=1' UNION SELECT pw"
OTHER_ATTACK = "/item?id=2 union all select 1"


def request(
    line_no: int,
    target: str = ATTACK,
    *,
    source: str = "access.log",
    client_ip: str = "203.0.113.5",
    method: str = "GET",
    protocol: str = "HTTP/1.1",
    status: int = 200,
    referer: str | None = None,
    user_agent: str = "curl/8.0",
) -> NormalizedEvent:
    path, _, query = target.partition("?")
    return NormalizedEvent(
        timestamp=START,
        client_ip=client_ip,
        evidence=EvidenceRef(source, line_no),
        method=method,
        path=path,
        query=query or None,
        protocol=protocol,
        status=status,
        referer=referer,
        user_agent=user_agent,
    )


@pytest.fixture
def crs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeCrs:
    fake = FakeCrs()
    monkeypatch.setattr(subprocess, "Popen", fake)
    return fake


@pytest.fixture
def config(tmp_path: Path) -> SidecarConfig:
    binary = tmp_path / "crs-sidecar"
    binary.write_text("", encoding="utf-8")
    (tmp_path / "rules").mkdir()
    return SidecarConfig(binary=binary, rules=tmp_path, conf=tmp_path)


def _where(found: list[sidecar.CrsDetection]) -> list[tuple[str, int]]:
    return [(item.source_file_id, item.line_no) for item in found]


def test_a_repeated_request_is_replayed_once(crs: FakeCrs, config: SidecarConfig) -> None:
    found = run_sidecar([request(1), request(2), request(3)], config=config)

    assert crs.lines_sent() == [1]
    assert _where(found) == [("access.log", 1), ("access.log", 2), ("access.log", 3)]


def test_every_repeat_gets_the_whole_answer_under_its_own_line(
    crs: FakeCrs, config: SidecarConfig
) -> None:
    """Only where it was found changes. The rest is the evidence itself, and a
    copy that dropped or altered any of it would be a different finding."""
    first, repeat = run_sidecar([request(1), request(9)], config=config)

    assert repeat == replace(first, line_no=9)


def test_a_repeat_in_another_source_is_credited_to_that_source(
    crs: FakeCrs, config: SidecarConfig
) -> None:
    """A detection is keyed by `(source_file_id, line_no)`. An answer reused
    across two logs has to land in the log the repeat came from."""
    found = run_sidecar([request(1), request(5, source="other.log")], config=config)

    assert crs.lines_sent() == [1]
    assert _where(found) == [("access.log", 1), ("other.log", 5)]


def test_repeats_are_recognised_across_batches(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Most repeats are minutes or hours apart, so far further apart than one
    batch. Remembering only within a batch would miss nearly all of them."""
    monkeypatch.setattr(sidecar, "_BATCH", 2)

    found = run_sidecar([request(n) for n in range(1, 6)], config=config)

    assert crs.lines_sent() == [1]
    assert [line for _, line in _where(found)] == [1, 2, 3, 4, 5]


@pytest.mark.parametrize(
    "differs",
    [
        {"target": OTHER_ATTACK},
        {"method": "POST"},
        {"protocol": "HTTP/1.0"},
        {"status": 404},
        {"referer": "http://shop.test/"},
        {"user_agent": "Mozilla/5.0"},
    ],
    ids=lambda differs: next(iter(differs)),
)
def test_a_request_differing_in_anything_crs_reads_is_replayed(
    differs: dict[str, Any], crs: FakeCrs, config: SidecarConfig
) -> None:
    run_sidecar([request(1), request(2, **differs)], config=config)

    assert crs.lines_sent() == [1, 2]


def test_ordinary_clients_share_an_answer_and_loopback_ones_never_do(
    crs: FakeCrs, config: SidecarConfig
) -> None:
    """CRS reads the client address only to exempt loopback (905100 and 905110),
    so to CRS every other address is the same one. An address it could read as
    loopback is replayed under its own identity — including the IPv4-mapped
    form, which Go's address matching treats as the IPv4 address it carries."""
    clients = ["203.0.113.5", "198.51.100.7", "127.0.0.1", "::1", "::ffff:127.0.0.1"]

    run_sidecar([request(n, client_ip=ip) for n, ip in enumerate(clients, 1)], config=config)

    assert crs.lines_sent() == [1, 3, 4, 5]


def test_the_answer_keeps_the_order_of_the_lines(crs: FakeCrs, config: SidecarConfig) -> None:
    """Fresh answers and remembered ones are interleaved in line order, which is
    the order the sidecar itself reports in."""
    events = [
        request(1),
        request(2, "/"),
        request(3),
        request(4, OTHER_ATTACK),
        request(5),
    ]

    found = run_sidecar(events, config=config)

    assert crs.lines_sent() == [1, 2, 4]
    assert [line for _, line in _where(found)] == [1, 3, 4, 5]


def test_what_is_remembered_is_bounded(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A case where nearly every request is different would otherwise grow the
    memory of answers without limit, on the one path that reads a whole case.
    Full, it is emptied and starts again: a repeat costs one more replay, and
    no answer is ever wrong."""
    monkeypatch.setattr(sidecar, "_BATCH", 1)
    monkeypatch.setattr(sidecar, "_REMEMBERED", 2)
    events = [request(1), request(2, OTHER_ATTACK), request(3, "/"), request(4, "/x"), request(5)]

    found = run_sidecar(events, config=config)

    # Sorted: batches overlap, so the sidecars are not called in line order.
    assert sorted(crs.lines_sent()) == [1, 2, 3, 4, 5], (
        "the first answer should have been forgotten"
    )
    assert [line for _, line in _where(found)] == [1, 2, 5]


def test_mapped_loopback_stays_apart_even_where_python_does_not_call_it_loopback(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`ipaddress` changed its answer within a minor version. Checked
    2026-10-05: `::ffff:127.0.0.1` is loopback to CPython 3.11.17 and 3.12.10
    and not to 3.11.4 or 3.12.3, and `requires-python` admits all four. The
    test above runs on whichever this is, so the older answer is put in place
    here — without it, dropping the explicit mapped check passes on any
    current interpreter."""
    monkeypatch.setattr(ipaddress.IPv6Address, "is_loopback", property(lambda self: self._ip == 1))
    assert not ipaddress.ip_address("::ffff:127.0.0.1").is_loopback

    run_sidecar([request(1), request(2, client_ip="::ffff:127.0.0.1")], config=config)

    assert crs.lines_sent() == [1, 2]


# -- several sidecars at once ---------------------------------------------
#
# Measured 2026-10-05 on `2026-09-20-medium`'s 73,427 distinct requests: one
# sidecar 72.3 s, two 39.3 s, four 25.5 s, each holding 55 MB at its peak, with
# the same detections. A sidecar starts in about 0.11 s and then costs about
# 0.6 ms a request, so a batch's fresh requests are split across processes
# rather than whole batches being run side by side — which would leave a case
# of one batch, most of them, with nothing to share.


class _BarrierCrs(FakeCrs):
    """A fake whose shares wait until `parties` sidecars are answering at once.

    Concurrency proven rather than timed: sent one after another, the first
    share waits alone and the barrier breaks, so the test fails on the fact
    and not on how fast this machine is."""

    def __init__(self, parties: int) -> None:
        super().__init__()
        self.barrier = threading.Barrier(parties, timeout=10)

    def share(self, records: list[dict[str, Any]]) -> list[str]:
        self.barrier.wait()
        return super().share(records)


def _many(count: int) -> list[NormalizedEvent]:
    """Distinct requests, one in three an attack the fake reports."""
    return [
        request(n, f"/p/{n}?q=1 union select {n}" if n % 3 == 0 else f"/p/{n}")
        for n in range(1, count + 1)
    ]


def test_a_large_batch_is_shared_between_sidecars(
    config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _BarrierCrs(parties=4)
    monkeypatch.setattr(subprocess, "Popen", fake)

    found = run_sidecar(_many(2_000), config=config, workers=4)

    assert sorted(fake.lines_sent()) == list(range(1, 2_001)), "every request, once"
    assert [line for _, line in _where(found)] == list(range(3, 2_001, 3))


def test_sharing_changes_nothing_but_the_time(crs: FakeCrs, config: SidecarConfig) -> None:
    """The same answers, in the same order, from one sidecar or four."""
    alone = run_sidecar(_many(2_000), config=config, workers=1)
    shared = run_sidecar(_many(2_000), config=config, workers=4)

    assert shared == alone


def test_six_sidecars_run_at_once_where_the_cores_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured 2026-10-06 on four cores behind eight threads: the medium
    build's 74,153 distinct requests in 24.8 s on four sidecars, 21.0 s on six,
    20.9 s on eight. Six takes the gain the extra threads have to give."""
    monkeypatch.setattr(os, "cpu_count", lambda: 16)

    assert sidecar.default_workers() == 6


def test_never_more_sidecars_than_cores(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "cpu_count", lambda: 4)
    assert sidecar.default_workers() == 4

    monkeypatch.setattr(os, "cpu_count", lambda: None)
    assert sidecar.default_workers() == 1, "a machine that cannot say gets one"


def test_a_small_batch_is_not_split(crs: FakeCrs, config: SidecarConfig) -> None:
    """Splitting costs a start-up per sidecar. Under a few hundred requests
    that is most of the work, so a small batch goes to one."""
    run_sidecar(_many(300), config=config, workers=4)

    assert len(crs.calls) == 1


# -- the next batch while the last one runs ---------------------------------
#
# Measured 2026-10-06 on `2026-10-06-medium`, 235,732 requests: of 31.8 s
# replaying them, 27.6 s was waiting on sidecars and 4.2 s was everything else
# — reading and keying the next 20,000 — during which no sidecar ran. And every
# batch waited for its slowest share before the next one began.


def test_the_next_batch_starts_while_the_last_is_still_running(
    config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proven the way sharing is: the first batch's sidecar cannot finish until
    a second one is running. Replayed one batch after the other, it waits
    alone and the barrier breaks."""
    monkeypatch.setattr(sidecar, "_BATCH", 1)
    fake = _BarrierCrs(parties=2)
    monkeypatch.setattr(subprocess, "Popen", fake)

    found = run_sidecar([request(1), request(2, OTHER_ATTACK)], config=config, workers=2)

    assert [line for _, line in _where(found)] == [1, 2]


def test_an_answer_remembered_when_a_batch_is_sent_outlives_the_memory_emptying(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fourth request repeats the first, whose answer is remembered when
    its batch is sent. Settling the third batch then empties the memory, before
    the fourth settles — and the repeat must still be answered, not lost."""
    monkeypatch.setattr(sidecar, "_BATCH", 1)
    monkeypatch.setattr(sidecar, "_REMEMBERED", 2)
    events = [request(1), request(2, OTHER_ATTACK), request(3, "/"), request(4)]

    found = run_sidecar(events, config=config, workers=1)

    assert sorted(crs.lines_sent()) == [1, 2, 3]
    assert [line for _, line in _where(found)] == [1, 2, 4]


def test_batching_changes_nothing_but_the_time(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One batch, or many with replays still in flight when the next is read:
    the same answers in the same order, repeats across batches included."""
    targets = [
        f"/p/{n % 20}?q=1 union select 1" if n % 3 == 0 else f"/p/{n % 20}" for n in range(60)
    ]
    events = [request(n, target) for n, target in enumerate(targets, 1)]

    whole = run_sidecar(events, config=config, workers=2)
    monkeypatch.setattr(sidecar, "_BATCH", 7)
    pieces = run_sidecar(events, config=config, workers=2)

    assert pieces == whole
    assert len(whole) == 20


# -- sidecars that live for the whole run -----------------------------------
#
# A sidecar used to start for every batch share: up to 288 on the large tier.
# Measured 2026-10-14, that start-up is 0.14 s on Go's regexp and 0.92 s with
# RE2 compiled to WebAssembly, whose matching is a third faster — so the faster
# engine only pays if each sidecar starts once and is sent share after share.


def test_a_sidecar_starts_only_when_a_share_finds_none_free(
    crs: FakeCrs, config: SidecarConfig
) -> None:
    """A three-line probe must not start six of them."""
    run_sidecar([request(1), request(2, OTHER_ATTACK), request(3, "/")], config=config, workers=6)

    assert crs.spawned == 1


def test_one_sidecar_answers_batch_after_batch(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Five batches, one share each, one worker: one process for all five."""
    monkeypatch.setattr(sidecar, "_BATCH", 1)

    found = run_sidecar(
        [request(n, f"/p/{n}?q=1 union select {n}") for n in range(1, 6)], config=config, workers=1
    )

    assert crs.spawned == 1
    assert crs.calls == [1, 1, 1, 1, 1]
    assert [line for _, line in _where(found)] == [1, 2, 3, 4, 5]


def test_never_more_sidecars_than_workers(
    config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _BarrierCrs(parties=4)
    monkeypatch.setattr(subprocess, "Popen", fake)
    monkeypatch.setattr(sidecar, "_BATCH", 1_000)

    run_sidecar(_many(8_000), config=config, workers=4)

    assert fake.spawned == 4
    assert len(fake.calls) > 4, "several batches, so sidecars were reused"


def test_every_sidecar_is_closed_when_the_run_ends(crs: FakeCrs, config: SidecarConfig) -> None:
    run_sidecar(_many(2_000), config=config, workers=4)

    assert crs.spawned >= 1
    assert crs.all_closed()
    assert all(process.stdin.closed for process in crs.processes)
    assert all(process.stdout.closed and process.stderr.closed for process in crs.processes)


def _finishing_within(seconds: float, call: Callable[[], object]) -> BaseException | None:
    """Run `call` on a thread and fail the test if it has not finished in time.

    A dead sidecar handed another share waits forever. Hung, a test is found
    an hour later as a CI timeout instead of by its name.
    """
    outcome: list[BaseException | None] = []

    def run() -> None:
        try:
            call()
        except BaseException as raised:
            outcome.append(raised)
        else:
            outcome.append(None)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(seconds)
    assert outcome, f"still running after {seconds} s"
    return outcome[0]


def test_a_sidecar_dying_mid_share_fails_the_run_with_its_own_words(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An answer cut short is not an empty answer: returning what arrived would
    look exactly like a share with nothing in it. The last share dies, so a run
    that read it as empty would end as if nothing had gone wrong."""
    monkeypatch.setattr(sidecar, "_BATCH", 1)
    crs.fail_on_share = 2
    events = [request(1), request(2, OTHER_ATTACK)]

    raised = _finishing_within(30, lambda: run_sidecar(events, config=config, workers=1))

    assert isinstance(raised, sidecar.CrsUnavailableError)
    assert "something broke mid-share" in str(raised)
    assert crs.all_closed()


def test_every_sidecar_is_closed_when_the_run_fails(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Six processes left running after a failed enrichment would hold the case
    open and the cores busy until the window closed."""
    monkeypatch.setattr(sidecar, "_BATCH", 1_000)
    crs.fail_on_share = 3

    raised = _finishing_within(30, lambda: run_sidecar(_many(8_000), config=config, workers=4))

    assert isinstance(raised, sidecar.CrsUnavailableError)
    assert crs.spawned >= 1
    assert crs.all_closed()


def test_two_shares_on_one_sidecar_keep_their_answers_apart(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flush marker is the only thing between one share's answers and the
    next one's; an attack in the first must not be credited to the second."""
    monkeypatch.setattr(sidecar, "_BATCH", 1)

    found = run_sidecar([request(1), request(2, "/plain")], config=config, workers=1)

    assert crs.spawned == 1
    assert _where(found) == [("access.log", 1)]


def test_an_answer_to_a_share_that_was_not_sent_stops_the_run(
    config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A flush answered with another share's number means Python and the
    sidecar are out of step, and every answer after it would be credited to the
    wrong lines. Read as a detection it failed with a `KeyError` that named
    nothing; it is a broken sidecar, and says so."""
    monkeypatch.setattr(subprocess, "Popen", FakeCrs(answer=lambda _records: ['{"flushed": 99}']))

    with pytest.raises(sidecar.CrsUnavailableError, match="out of step"):
        run_sidecar([request(1)], config=config)


def test_a_sidecar_that_died_refuses_the_next_share_at_once(
    crs: FakeCrs, config: SidecarConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second batch is already queued when the first one's sidecar dies,
    and goes to the same sidecar. Its output has ended once, and that end was
    read by the first share; the second must read it too, not wait forever for
    an answer — even through a pipe that took the write."""
    monkeypatch.setattr(sidecar, "_BATCH", 1)
    crs.fail_on_share = 1
    crs.pipe_outlives_process = True
    events = [request(1), request(2, OTHER_ATTACK)]

    raised = _finishing_within(30, lambda: run_sidecar(events, config=config, workers=1))

    assert isinstance(raised, sidecar.CrsUnavailableError)
