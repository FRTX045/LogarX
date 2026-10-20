"""Which evidence lines fold into one row, and what that row may claim. No Qt.

A folded row shows each column once, so the default rule folds only lines that
agree on every column the table shows apart from Line and Time. The cases are the
three the preview was decided on, from the bundled log: a password guess that
worked in the middle of a brute force, forty-six SQL injection payloads to one
path, and three cart posts that came back with three different sizes.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import pytest

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.evidence import EvidenceLine
from logarc.gui.folding import DEFAULT_FOLD, Fold, FoldRule, fold, log_order, named, spread

START = datetime(2026, 3, 10, 19, 12, 18, tzinfo=UTC)


def line(
    n: int,
    method: str,
    target: str,
    status: int | None,
    size: int | None,
    *,
    file: str = "excerpt.log",
    readable: bool = True,
) -> EvidenceLine:
    path, _, query = target.partition("?")
    ref = EvidenceRef(file, n)
    event = NormalizedEvent(
        timestamp=START + timedelta(seconds=n),
        client_ip="192.0.2.23",
        evidence=ref,
        method=method,
        path=path,
        query=query or None,
        status=status,
        bytes_sent=size,
    )
    return EvidenceLine(
        ref=ref,
        source_path=file,
        text=f"line {n}",
        event=event if readable else None,
        verified=True,
    )


def brute_force() -> list[EvidenceLine]:
    """192.0.2.23 on the bundled log: 401s, two 429s, and one 302 at line 2910."""
    statuses = [401] * 5 + [429] + [401] * 3 + [429] + [401] * 2 + [302] + [401] * 26
    return [
        line(2014 + i, "POST", "/login", s, None if s == 302 else (7740 if s == 429 else 7744))
        for i, s in enumerate(statuses)
    ]


def runs(found: tuple[Fold, ...]) -> list[int]:
    return [len(f) for f in found]


def test_the_default_keeps_the_successful_login_on_its_own_row() -> None:
    lines = brute_force()

    found = fold(lines, FoldRule.REQUEST_STATUS_SIZE)

    assert runs(found) == [5, 1, 3, 1, 2, 1, 26]
    assert lines[found[5].head].event.status == 302


def test_same_request_folds_the_success_into_the_failures() -> None:
    assert runs(fold(brute_force(), FoldRule.REQUEST)) == [39]


def test_same_path_folds_different_payloads_and_nothing_stricter_does() -> None:
    lines = [line(3133 + i, "GET", f"/search?q=oak' AND {i}={i}", 200, 2332 + i) for i in range(46)]

    assert runs(fold(lines, FoldRule.PATH)) == [46]
    for rule in (FoldRule.REQUEST, FoldRule.REQUEST_STATUS, FoldRule.REQUEST_STATUS_SIZE):
        assert runs(fold(lines, rule)) == [1] * 46


def test_request_and_status_folds_different_sizes_and_the_default_does_not() -> None:
    lines = [
        line(1724 + i, "POST", "/api/cart", 200, size) for i, size in enumerate((2328, 91, 152))
    ]

    assert runs(fold(lines, FoldRule.REQUEST_STATUS)) == [3]
    assert runs(fold(lines, FoldRule.REQUEST_STATUS_SIZE)) == [1, 1, 1]


def test_the_method_always_has_to_match() -> None:
    lines = [line(1, "GET", "/login", 200, 10), line(2, "POST", "/login", 200, 10)]

    assert runs(fold(lines, FoldRule.PATH)) == [1, 1]


def test_off_folds_nothing() -> None:
    assert runs(fold(brute_force(), FoldRule.OFF)) == [1] * 39


def test_a_fold_never_crosses_from_one_visit_to_the_next() -> None:
    """The Time column shows no date: one row over two visits would hide days."""
    lines = [line(n, "POST", "/login", 401, 7744) for n in (1, 2, 3, 4)]
    visit = {lines[0].ref: "a", lines[1].ref: "a", lines[2].ref: "b", lines[3].ref: "b"}

    assert runs(fold(lines, FoldRule.REQUEST_STATUS_SIZE, visit.__getitem__)) == [2, 2]


def test_an_unreadable_line_never_folds() -> None:
    lines = [
        line(1, "GET", "/", 200, 5),
        line(2, "GET", "/", 200, 5, readable=False),
        line(3, "GET", "/", 200, 5),
        line(4, "GET", "/", 200, 5),
    ]

    assert runs(fold(lines, FoldRule.REQUEST_STATUS_SIZE)) == [1, 1, 2]


def test_lines_fold_in_log_order_whatever_order_they_arrive_in() -> None:
    """`evidence_for` is chronological; a case of two files is file, then line."""
    lines = [
        line(5, "GET", "/a", 200, 1, file="b.log"),
        line(9, "GET", "/a", 200, 1, file="a.log"),
        line(8, "GET", "/a", 200, 1, file="a.log"),
    ]

    assert log_order(lines) == [2, 1, 0]
    assert [f.members for f in fold(lines, FoldRule.REQUEST_STATUS_SIZE)] == [(2, 1, 0)]


def test_the_default_never_folds_lines_a_row_would_misstate() -> None:
    """Over generated sequences: every fold the default makes agrees on request,
    status and size, the three columns a folded row shows once."""
    rng = random.Random(20261020)
    for _ in range(300):
        lines = [
            line(
                n,
                rng.choice(["GET", "POST"]),
                rng.choice(["/a", "/a?x=1", "/b"]),
                rng.choice([200, 401, None]),
                rng.choice([10, 11, None]),
            )
            for n in range(rng.randint(1, 30))
        ]
        for found in fold(lines, FoldRule.REQUEST_STATUS_SIZE):
            seen = {
                (e.method, e.target, e.status, e.bytes_sent)
                for e in (lines[i].event for i in found.members)
                if e is not None
            }
            assert len(seen) == 1


def test_a_spread_lists_values_most_common_first() -> None:
    statuses = [one.event.status for one in brute_force() if one.event is not None]

    found = spread(statuses, str)

    assert not found.shared
    assert found.tip() == "401 x36 · 429 x2 · 302 x1"
    assert spread([401, 401], str).shared


def test_a_long_spread_says_how_many_more_there_are() -> None:
    assert spread(list(range(12)), str).tip(limit=10).endswith("and 2 more")


@pytest.mark.parametrize("rule", list(FoldRule))
def test_every_rule_reads_back_from_what_it_stores(rule: FoldRule) -> None:
    assert named(rule.stored) is rule


def test_a_rule_this_build_does_not_know_reads_as_the_default() -> None:
    assert named("luxuriant") is DEFAULT_FOLD
    assert DEFAULT_FOLD is FoldRule.REQUEST_STATUS_SIZE
    assert DEFAULT_FOLD.label == "Same request, status and size"
