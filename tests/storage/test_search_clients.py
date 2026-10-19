"""Searching a case's requests for the clients that sent a match.

The case box asks the store, in SQL; the evidence box asks `Query.matches`, in
Python. A reader who opens a client from the case search must find in its
evidence exactly the lines the search counted, so most of this file is one
question asked of both: does every client get the same number of hits?
"""

from __future__ import annotations

import random
from contextlib import closing
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from test_event_store import START, event

from logarc.core.window import TimeWindow
from logarc.search import Scope, parse
from logarc.storage.event_store import ParquetEventStore

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from logarc.core.event import NormalizedEvent

# Requests that make decoding and lower-casing hard, one client each, so a
# disagreement names the request that caused it.
AWKWARD: list[tuple[str | None, str | None, str | None, int | None]] = [
    ("/search", "q=union+select", "GET", 200),
    ("/search", "q=union%20select", "GET", 200),
    ("/a+b", None, "GET", 200),
    ("/a%2Bb", None, "GET", 404),
    ("/%2541dmin", None, "GET", 404),
    ("/%zz/admin", None, "GET", 400),
    ("/admin%", None, "GET", 400),
    ("/caf%C3%A9", "x=%C3%A9", "POST", 200),
    ("/bad%C3%28", "y=%C3%28", "GET", 400),
    ("/%E2%80%AEtxt.exe", None, "GET", 404),
    ("/%ed%a0%80", None, "GET", 400),
    ("/ADMIN/Panel", None, "get", 200),
    ("/\u0130letisim", None, "GET", 200),
    ("/\u039f\u0394\u039f\u03a3", None, "GET", 200),
    ("/\u03bf\u03b4\u03bf\u03c2", None, "GET", 200),
    ("/\\xC3(", None, "GET", 400),
    (None, "q=orphan", "GET", 400),
    ("", "q=orphan", "GET", 400),
    ("/plain", "", "HEAD", 304),
    ("/odd-method", None, "P\u0131NG", 200),
    ("/odd-method", None, "M-SEARCH", 200),
    ("/no-status", None, "GET", None),
    ("/no-method", None, None, 200),
    ("/%2fetc%2fpasswd", "file=..%2F..%2Fetc%2Fpasswd", "GET", 500),
]

QUERIES = [
    "union select",
    '"union select"',
    "select",
    "a+b",
    "a b",
    "%41",
    "admin",
    "path:/admin",
    "path:%2541",
    "caf\u00e9",
    "%c3%a9",
    "%c3%28",
    "\u202e",
    "path:/ilet",
    "\u03bf\u03b4\u03bf\u03c3",
    "\\xc3",
    "orphan",
    "?q=orphan",
    "status:200",
    "status:4xx",
    "status:400 status:404",
    "status:4xx path:/a",
    "method:get",
    "method:POST",
    "method:ping",
    "method:head status:3xx",
    "etc/passwd",
    "../",
    "0.0.1 status:200",
    "10.0.0.1",
    "ip:10.0.0.1",
    "ip:10.0.0.2 ip:10.0.0.3",
    "nothing-has-this",
]


def awkward_events() -> list[NormalizedEvent]:
    return [
        event(
            f"10.0.0.{index}",
            offset_seconds=index,
            line_no=index + 1,
            path=path,
            query=query,
            method=method,
            status=status,
        )
        for index, (path, query, method, status) in enumerate(AWKWARD)
    ]


@pytest.fixture
def awkward(tmp_path: Path) -> Iterator[ParquetEventStore]:
    with closing(ParquetEventStore(tmp_path / "case")) as store:
        store.write(awkward_events())
        store.finalize()
        yield store


def store_hits(store: ParquetEventStore, text: str, **kwargs: object) -> dict[str, int]:
    page = store.search_clients(parse(text, Scope.CASE), limit=10_000, **kwargs)  # type: ignore[arg-type]
    return {row.client_ip: hits for row, hits in zip(page.rows, page.hits, strict=True)}


def python_hits(store: ParquetEventStore, text: str) -> dict[str, int]:
    """What the evidence box would count, on the events as the store gives them back."""
    query = parse(text, Scope.CASE)
    found: dict[str, int] = {}
    for item in store.all_events():
        if query.matches(item):
            found[item.client_ip] = found.get(item.client_ip, 0) + 1
    return found


# -- the store and the evidence box agree -------------------------------------------


@pytest.mark.parametrize("text", QUERIES)
def test_the_store_counts_what_the_evidence_box_keeps(
    awkward: ParquetEventStore, text: str
) -> None:
    assert store_hits(awkward, text) == python_hits(awkward, text)


#: Queries that must find nothing, each for a reason of its own: a query string
#: with no path has an empty target; a method outside ASCII never matches; and
#: one is there to be found nowhere.
FIND_NOTHING = {"orphan", "?q=orphan", "method:ping", "nothing-has-this"}


def test_the_corpus_is_not_trivially_agreed() -> None:
    """Agreement on queries that match nothing, or everything, proves nothing."""
    for text in QUERIES:
        query = parse(text, Scope.CASE)
        hits = sum(query.matches(item) for item in awkward_events())
        assert hits < len(AWKWARD), text
        assert (hits == 0) == (text in FIND_NOTHING), text


def test_random_requests_agree_too(tmp_path: Path) -> None:
    """Paths stitched from the pieces decoding and folding trip on, each a
    client of its own, searched for those pieces. Seeded, so a failure repeats."""
    pieces = ["%", "C3", "%C3", "%A9", "%28", "%2B", "+", "%25", "a", "/", "\u00e9",
              "\u0130", "\u03a3", "\u03c2", "%zz", "%e2%80%ae", "?", "=", "%20", " "]  # fmt: skip
    chooser = random.Random(20261018)
    events = []
    for index in range(400):
        path = "/" + "".join(chooser.choice(pieces) for _ in range(chooser.randint(1, 6)))
        query = "".join(chooser.choice(pieces) for _ in range(chooser.randint(0, 4)))
        events.append(event(f"10.1.{index // 250}.{index % 250}", line_no=index + 1,
                            path=path, query=query or None))  # fmt: skip
    with closing(ParquetEventStore(tmp_path / "case")) as store:
        store.write(events)
        store.finalize()
        for text in ["\u00e9", "c3", "%c3", "a+", "a ", "%", "\u03c3", "i", "%2b",
                     "path:%c3", "path:/a", "path:\u00e9", "\u202e", "%28", "path:+"]:  # fmt: skip
            assert store_hits(store, text) == python_hits(store, text), text


# -- what a page holds ------------------------------------------------------------


def test_most_hits_first_then_address_with_the_totals_of_the_whole_search(
    tmp_path: Path,
) -> None:
    with closing(ParquetEventStore(tmp_path / "case")) as store:
        store.write(
            [event("10.0.0.3", status=404, line_no=n, offset_seconds=n) for n in range(1, 4)]
            + [event("10.0.0.1", status=404, line_no=n, offset_seconds=n) for n in range(4, 6)]
            + [event("10.0.0.2", status=404, line_no=n, offset_seconds=n) for n in range(6, 8)]
            + [event("10.0.0.9", status=200, line_no=n, offset_seconds=n) for n in range(8, 20)]
        )
        store.finalize()

        first = store.search_clients(parse("status:404", Scope.CASE), limit=2)
        second = store.search_clients(parse("status:404", Scope.CASE), offset=2, limit=2)

    assert [row.client_ip for row in first.rows] == ["10.0.0.3", "10.0.0.1"]
    assert first.hits == (3, 2)
    assert [row.client_ip for row in second.rows] == ["10.0.0.2"]
    assert (first.total, first.requests) == (3, 7)
    assert (second.total, second.requests, second.offset) == (3, 7, 2)
    assert first.rows[0].request_count == 3, "the row describes the client, not its hits"
    assert first.rows[0].position == 2, "its place among every client, busiest first"


def test_nothing_matching_is_an_empty_page_that_says_so(awkward: ParquetEventStore) -> None:
    page = awkward.search_clients(parse("nothing-has-this", Scope.CASE))

    assert (page.rows, page.hits, page.total, page.requests) == ((), (), 0, 0)


def test_an_empty_case_answers_too(tmp_path: Path) -> None:
    with closing(ParquetEventStore(tmp_path / "case")) as store:
        store.finalize()
        page = store.search_clients(parse("status:200", Scope.CASE))

    assert (page.total, page.requests) == (0, 0)


# -- what narrows a search --------------------------------------------------------


def test_only_requests_in_the_range_are_counted(tmp_path: Path) -> None:
    """Both ends of the range are in it, as everywhere else in the store."""
    with closing(ParquetEventStore(tmp_path / "case")) as store:
        store.write([event("10.0.0.1", offset_seconds=n, line_no=n + 1) for n in range(10)])
        store.finalize()
        window = TimeWindow(START + timedelta(seconds=2), START + timedelta(seconds=5))

        page = store.search_clients(parse("index", Scope.CASE), window=window)

    assert page.hits == (4,)
    assert page.rows[0].request_count == 4, "the row describes the client in the range"


def test_after_is_inclusive_and_before_is_not(tmp_path: Path) -> None:
    with closing(ParquetEventStore(tmp_path / "case")) as store:
        store.write([event("10.0.0.1", offset_seconds=n, line_no=n + 1) for n in range(10)])
        store.finalize()

        page = store.search_clients(
            parse("after:2024-05-01T12:00:02 before:2024-05-01T12:00:05", Scope.CASE)
        )

    assert page.hits == (3,)


def test_a_search_can_be_held_to_some_clients(awkward: ParquetEventStore) -> None:
    """What `activity:` hands over: the clients the scan named."""
    held = store_hits(awkward, "status:200", clients=frozenset({"10.0.0.0", "10.0.0.7", "x"}))

    assert held == {"10.0.0.0": 1, "10.0.0.7": 1}
    assert store_hits(awkward, "status:200", clients=frozenset()) == {}


def test_the_clients_handed_over_are_not_left_behind(awkward: ParquetEventStore) -> None:
    """Held as a table for the search, and gone once it has answered."""
    for _ in range(2):
        store_hits(awkward, "status:200", clients=frozenset({"10.0.0.0", "10.0.0.7"}))

    left = (
        awkward._connect()
        .execute("SELECT count(*) FROM duckdb_views() WHERE view_name LIKE 'chosen_%'")
        .fetchone()
    )
    assert left == (0,)


def test_the_scans_clients_and_an_address_both_narrow(awkward: ParquetEventStore) -> None:
    held = store_hits(awkward, "status:200 10.0.0.7", clients=frozenset({"10.0.0.0", "10.0.0.7"}))

    assert held == {"10.0.0.7": 1}


def test_an_address_narrows_the_clients_whole_or_in_part(awkward: ParquetEventStore) -> None:
    """A whole address is that client and no other; part of one, any containing it."""
    assert set(store_hits(awkward, "10.0.0.1 status:200")) == {"10.0.0.1"}
    assert set(store_hits(awkward, "0.0.1 status:200")) == {
        "10.0.0.1",
        "10.0.0.11",
        "10.0.0.12",
        "10.0.0.13",
        "10.0.0.14",
        "10.0.0.19",
    }
    assert set(store_hits(awkward, "ip:10.0.0.1 status:200")) == {"10.0.0.1"}


def test_a_value_is_never_sql(awkward: ParquetEventStore) -> None:
    """Typed values are bound, never pasted into the statement."""
    assert store_hits(awkward, "path:'); DROP TABLE x; --") == {}
    assert store_hits(awkward, "') OR 1=1 --") == {}
    assert store_hits(awkward, "status:200"), "and the case still answers afterwards"


# -- what the box offers ----------------------------------------------------------


def test_the_values_in_a_range_with_how_many_clients_and_requests(tmp_path: Path) -> None:
    with closing(ParquetEventStore(tmp_path / "case")) as store:
        store.write(
            [
                event("10.0.0.1", status=404, line_no=1),
                event("10.0.0.1", status=404, line_no=2, offset_seconds=1),
                event("10.0.0.2", status=404, line_no=3, offset_seconds=2),
                event("10.0.0.2", status=200, line_no=4, offset_seconds=3, method="post"),
                event("10.0.0.3", status=None, line_no=5, offset_seconds=4, method="M-SEARCH"),
                event("10.0.0.4", status=500, line_no=6, offset_seconds=60),
                event("10.0.0.5", status=999, line_no=7, offset_seconds=61),
            ]
        )
        store.finalize()

        whole = store.value_counts()
        early = store.value_counts(window=TimeWindow(START, START + timedelta(seconds=30)))

    # 999 is not offered: `status:999` is not a filter the box can take.
    assert whole["status"] == [
        ("404", 2, 3),
        ("200", 1, 1),
        ("500", 1, 1),
        ("2xx", 1, 1),
        ("4xx", 2, 3),
        ("5xx", 1, 1),
    ]
    assert whole["method"] == [("GET", 4, 5), ("POST", 1, 1)], "M-SEARCH cannot be a chip"
    assert early["status"] == [("404", 2, 3), ("200", 1, 1), ("2xx", 1, 1), ("4xx", 2, 3)]
