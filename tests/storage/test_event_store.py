"""Tests for the Parquet/DuckDB event store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path

import pytest

from zodiarc.core.event import NormalizedEvent
from zodiarc.core.evidence import EvidenceRef
from zodiarc.core.window import EVERYTHING, TimeWindow
from zodiarc.storage.event_store import ParquetEventStore, StoreStateError

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def event(
    ip: str = "203.0.113.5",
    *,
    offset_seconds: int = 0,
    path: str = "/index.html",
    status: int | None = 200,
    line_no: int = 1,
    **overrides: object,
) -> NormalizedEvent:
    fields: dict[str, object] = {
        "timestamp": START + timedelta(seconds=offset_seconds),
        "client_ip": ip,
        "evidence": EvidenceRef(source_file_id="access.log", line_no=line_no),
        "method": "GET",
        "path": path,
        "status": status,
        "bytes_sent": 1024,
        "protocol": "HTTP/1.1",
    }
    fields.update(overrides)
    return NormalizedEvent(**fields)  # type: ignore[arg-type]


@pytest.fixture
def store(tmp_path: Path) -> ParquetEventStore:
    return ParquetEventStore(tmp_path / "case")


def test_events_come_back_for_the_ip_that_wrote_them(store: ParquetEventStore) -> None:
    store.write([event("1.1.1.1", path="/a"), event("2.2.2.2", path="/b")])
    store.finalize()

    found = store.events_for_ip("1.1.1.1")

    assert [e.path for e in found] == ["/a"]


def test_events_are_returned_in_time_order(store: ParquetEventStore) -> None:
    store.write(
        [
            event(offset_seconds=30, path="/third"),
            event(offset_seconds=10, path="/first"),
            event(offset_seconds=20, path="/second"),
        ]
    )
    store.finalize()

    found = store.events_for_ip("203.0.113.5")

    assert [e.path for e in found] == ["/first", "/second", "/third"]


def test_unknown_ip_returns_nothing(store: ParquetEventStore) -> None:
    store.write([event("1.1.1.1")])
    store.finalize()

    assert store.events_for_ip("9.9.9.9") == []


def test_every_field_survives_the_round_trip(store: ParquetEventStore) -> None:
    original = event(
        path="/search",
        query="q=shoes&page=2",
        referer="http://example.com/",
        user_agent="curl/8.0",
        host="shop.example.com",
        line_no=4321,
        extra={"duration_us": "15000"},
    )
    store.write([original])
    store.finalize()

    (restored,) = store.events_for_ip(original.client_ip)

    assert restored.timestamp == original.timestamp
    assert restored.method == original.method
    assert restored.path == original.path
    assert restored.query == original.query
    assert restored.protocol == original.protocol
    assert restored.status == original.status
    assert restored.bytes_sent == original.bytes_sent
    assert restored.referer == original.referer
    assert restored.user_agent == original.user_agent
    assert restored.host == original.host
    assert restored.extra == original.extra


def test_evidence_reference_survives_so_findings_stay_traceable(
    store: ParquetEventStore,
) -> None:
    store.write([event(line_no=98765)])
    store.finalize()

    (restored,) = store.events_for_ip("203.0.113.5")

    assert restored.evidence == EvidenceRef(source_file_id="access.log", line_no=98765)


def test_absent_optional_fields_stay_absent(store: ParquetEventStore) -> None:
    store.write([event(status=None, method=None, path=None, bytes_sent=None)])
    store.finalize()

    (restored,) = store.events_for_ip("203.0.113.5")

    assert restored.status is None
    assert restored.method is None
    assert restored.path is None
    assert restored.bytes_sent is None


def test_bytes_that_are_not_valid_utf8_are_stored_as_escapes(store: ParquetEventStore) -> None:
    """Parquet columns are UTF-8. Malformed bytes are rendered the way Apache
    renders them rather than dropped, so the evidence stays visible."""
    smuggled = "/caf\udce9\udcff"
    store.write([event(path=smuggled)])
    store.finalize()

    (restored,) = store.events_for_ip("203.0.113.5")

    assert restored.path == "/caf\\xe9\\xff"


def test_a_lone_surrogate_is_stored_as_the_escape_that_wrote_it(store: ParquetEventStore) -> None:
    """JSON can write `\\ud800`, and the decoder hands back half a character no
    UTF-8 column can hold. One such field failed the write of its whole batch,
    and the ingest with it."""
    store.write([event(user_agent="sqlmap\ud800/1.8", path="/caf\udce9")])
    store.finalize()

    (restored,) = store.events_for_ip("203.0.113.5")

    assert restored.user_agent == "sqlmap\\ud800/1.8"
    assert restored.path == "/caf\\xe9"


@pytest.mark.parametrize(
    ("field", "written"),
    [("status", 10**20), ("status", 2**31), ("bytes_sent", 10**20), ("bytes_sent", -(2**63) - 1)],
)
def test_a_number_too_wide_for_its_column_is_stored_as_unknown(
    store: ParquetEventStore, field: str, written: int
) -> None:
    """The request is kept and only the number is lost: a crafted byte count must
    not be able to take an attack line out of the analysis. It used to fail the
    write of its whole batch, and the ingest with it."""
    store.write([event(**{field: written}), event(offset_seconds=1, path="/next")])
    store.finalize()

    restored = store.events_for_ip("203.0.113.5")

    assert [e.path for e in restored] == ["/index.html", "/next"]
    assert getattr(restored[0], field) is None


def test_writes_accumulate_across_batches(store: ParquetEventStore) -> None:
    store.write([event(offset_seconds=1, path="/a")])
    store.write([event(offset_seconds=2, path="/b")])
    store.finalize()

    assert len(store.events_for_ip("203.0.113.5")) == 2


def test_ip_summaries_describe_each_client(store: ParquetEventStore) -> None:
    store.write(
        [
            event("1.1.1.1", offset_seconds=0, path="/a", status=200),
            event("1.1.1.1", offset_seconds=60, path="/b", status=404),
            event("1.1.1.1", offset_seconds=120, path="/b", status=404),
            # A server error. Not the client's fault, so it must not raise the
            # share the client list sorts suspicion by.
            event("1.1.1.1", offset_seconds=180, path="/c", status=503),
            event("2.2.2.2", offset_seconds=5, path="/a", status=200),
        ]
    )
    store.finalize()

    summaries = {s.client_ip: s for s in store.ip_summaries()}

    first = summaries["1.1.1.1"]
    assert first.request_count == 4
    assert first.distinct_paths == 3
    assert first.first_seen == START
    assert first.last_seen == START + timedelta(seconds=180)
    assert first.client_error_ratio == pytest.approx(2 / 4)
    assert summaries["2.2.2.2"].request_count == 1


def test_ip_summaries_are_ordered_by_request_count(store: ParquetEventStore) -> None:
    store.write([event("1.1.1.1"), event("2.2.2.2", line_no=2), event("2.2.2.2", line_no=3)])
    store.finalize()

    assert [s.client_ip for s in store.ip_summaries()] == ["2.2.2.2", "1.1.1.1"]


def test_ip_summaries_can_be_ordered_by_most_recent_activity(
    store: ParquetEventStore,
) -> None:
    store.write(
        [
            event("1.1.1.1", offset_seconds=0),
            event("2.2.2.2", offset_seconds=500, line_no=2),
            event("2.2.2.2", offset_seconds=600, line_no=3),
            event("3.3.3.3", offset_seconds=9000, line_no=4),
        ]
    )
    store.finalize()

    order = [s.client_ip for s in store.ip_summaries(order_by="recent")]

    assert order == ["3.3.3.3", "2.2.2.2", "1.1.1.1"]


def test_ip_summaries_can_be_ordered_by_client_error_ratio(
    store: ParquetEventStore,
) -> None:
    """The IP generating mostly 404s is the one worth looking at first."""
    store.write(
        [
            event("quiet", status=200),
            event("prober", status=404, line_no=2),
            event("prober", status=404, line_no=3),
        ]
    )
    store.finalize()

    assert store.ip_summaries(order_by="errors")[0].client_ip == "prober"


def test_an_unknown_sort_key_is_rejected(store: ParquetEventStore) -> None:
    store.finalize()

    with pytest.raises(ValueError, match="unknown sort"):
        store.ip_summaries(order_by="'; DROP TABLE events; --")


def test_ip_summaries_can_be_limited(store: ParquetEventStore) -> None:
    store.write([event(f"10.0.0.{n}", line_no=n) for n in range(1, 6)])
    store.finalize()

    assert len(store.ip_summaries(limit=2)) == 2


def test_querying_before_finalize_is_an_error(store: ParquetEventStore) -> None:
    store.write([event()])

    with pytest.raises(StoreStateError, match="finalize"):
        store.events_for_ip("203.0.113.5")


def test_writing_after_finalize_is_an_error(store: ParquetEventStore) -> None:
    store.write([event()])
    store.finalize()

    with pytest.raises(StoreStateError, match="finalised"):
        store.write([event()])


def test_finalizing_an_empty_store_produces_no_results(store: ParquetEventStore) -> None:
    store.finalize()

    assert store.ip_summaries() == []
    assert store.events_for_ip("1.1.1.1") == []


def test_a_finalised_case_can_be_reopened(tmp_path: Path) -> None:
    """Analysis happens long after ingest, in a different process."""
    path = tmp_path / "case"
    writer = ParquetEventStore(path)
    writer.write([event(path="/only")])
    writer.finalize()
    writer.close()

    reader = ParquetEventStore(path)

    assert [e.path for e in reader.events_for_ip("203.0.113.5")] == ["/only"]


def test_finalize_is_given_a_memory_ceiling_and_somewhere_to_spill(tmp_path: Path) -> None:
    """The sort in finalize covers the whole corpus, so it must be bounded.

    DuckDB will take most of the machine's memory before it spills. Left at the
    defaults, finalising ten million events peaked at 6.9 GB — the design says
    memory follows the batch size, not the file size, and that has to be
    arranged rather than assumed.
    """
    store = ParquetEventStore(tmp_path / "case", memory_limit="256MB")
    connection = store._connect()

    limit = connection.execute("SELECT current_setting('memory_limit')").fetchone()
    temp = connection.execute("SELECT current_setting('temp_directory')").fetchone()
    store.close()

    # Reported back in binary units, so 256MB comes out as 244.1 MiB. What
    # matters is that a ceiling in megabytes was applied at all: the default is
    # a large fraction of the machine, and would be reported in GiB.
    assert limit is not None
    assert limit[0].endswith("MiB"), limit[0]
    assert temp is not None
    assert Path(temp[0]).parent == tmp_path / "case" / "tmp"


def test_two_stores_on_one_case_spill_into_folders_of_their_own(tmp_path: Path) -> None:
    """DuckDB names its spill files the same in every process and every connection.

    So two readers of one case spilling into one folder write over and delete
    each other's files: measured on a 941,031-event case, 4 of 10 such readers
    crashed with an access violation and 4 more failed to delete a file the
    other had already removed. Two windows on one case, or two jobs of one
    window, are exactly that.
    """
    first = ParquetEventStore(tmp_path / "case")
    second = ParquetEventStore(tmp_path / "case")

    folders = [
        store._connect().execute("SELECT current_setting('temp_directory')").fetchone()
        for store in (first, second)
    ]
    first.close()
    second.close()

    assert folders[0] is not None and folders[1] is not None
    assert folders[0][0] != folders[1][0]


def test_a_store_that_never_spilled_leaves_nothing_in_the_shared_folder(tmp_path: Path) -> None:
    store = ParquetEventStore(tmp_path / "case")
    store.write([event("203.0.113.1")])
    store.finalize()
    reader = ParquetEventStore(tmp_path / "case")
    assert reader.events_for_ip("203.0.113.1")
    reader.close()

    shared = tmp_path / "case" / "tmp"
    assert not shared.exists() or list(shared.iterdir()) == []


def test_the_spill_directory_does_not_outlive_finalize(tmp_path: Path) -> None:
    """Sorting ten million rows can spill gigabytes; they are not evidence."""
    store = ParquetEventStore(tmp_path / "case")
    store.write([event(f"203.0.113.{n % 5}", offset_seconds=n, line_no=n + 1) for n in range(20)])
    store.finalize()
    store.close()

    assert not (tmp_path / "case" / "tmp").exists()
    assert store.events_for_ip("203.0.113.1")


def test_finalize_leaves_another_readers_spill_where_it_is(tmp_path: Path) -> None:
    store = ParquetEventStore(tmp_path / "case")
    store.write([event("203.0.113.1")])
    theirs = tmp_path / "case" / "tmp" / "spill-another-reader"
    theirs.mkdir(parents=True)
    (theirs / "duckdb_temp_storage_S64K-0.tmp").write_bytes(b"in use")

    store.finalize()
    store.close()

    assert (theirs / "duckdb_temp_storage_S64K-0.tmp").read_bytes() == b"in use"


def test_finalize_survives_a_sort_that_does_not_fit_in_memory(tmp_path: Path) -> None:
    """The path a real corpus takes, forced by a ceiling a small one exceeds.

    Two things only go wrong once the engine has actually spilled, and neither
    shows up on twenty rows: the partitioned write runs out of memory instead of
    spilling unless insertion order is let go of, and the scratch files cannot
    be removed by pointing the engine elsewhere, because it refuses to move off
    a temporary directory it has used.
    """
    store = ParquetEventStore(tmp_path / "case", memory_limit="256MB")
    for start in range(0, 120_000, 20_000):
        store.write(
            [
                event(
                    f"203.0.113.{n % 251}",
                    offset_seconds=n,
                    line_no=n + 1,
                    path=f"/page/{n}/" + "x" * 120,
                    query="q=" + "y" * 120,
                    user_agent="z" * 160,
                )
                for n in range(start, start + 20_000)
            ]
        )

    store.finalize()

    assert not (tmp_path / "case" / "tmp").exists()
    assert len(store.events_for_ip("203.0.113.1")) == len(range(1, 120_000, 251))
    store.close()


def test_two_writers_on_one_case_do_not_overwrite_each_other(tmp_path: Path) -> None:
    """Parallel ingest gives each worker its own store over the same case, and
    the staged shards used to be numbered per instance — so every worker wrote
    `part-000000.parquet` and all but the last were silently replaced.

    Silently is the whole problem: the case finalises, the counts look
    plausible, and the missing evidence is the evidence nobody knows to miss.
    """
    root = tmp_path / "case"
    first = ParquetEventStore(root, shard="w0")
    second = ParquetEventStore(root, shard="w1")

    first.write([event("1.1.1.1", path="/from-first", line_no=1)])
    second.write([event("2.2.2.2", path="/from-second", line_no=2)])
    first.finalize()

    assert [e.path for e in first.events_for_ip("1.1.1.1")] == ["/from-first"]
    assert [e.path for e in first.events_for_ip("2.2.2.2")] == ["/from-second"]
    first.close()
    second.close()


def test_a_store_without_a_shard_name_keeps_writing_where_it_always_did(
    tmp_path: Path,
) -> None:
    """The sequential path is the common one and must not change shape."""
    store = ParquetEventStore(tmp_path / "case")

    store.write([event("1.1.1.1", path="/a", line_no=1)])

    assert (tmp_path / "case" / "staging" / "part-000000.parquet").exists()
    store.close()


# -- narrowing a read to one stretch of time -------------------------------


def test_a_window_keeps_only_the_events_inside_it(store: ParquetEventStore) -> None:
    store.write([event(offset_seconds=n, line_no=n + 1) for n in (0, 30, 60, 90)])
    store.finalize()

    inside = store.events_for_ip(
        "203.0.113.5",
        window=TimeWindow(START + timedelta(seconds=30), START + timedelta(seconds=60)),
    )

    assert [e.timestamp for e in inside] == [
        START + timedelta(seconds=30),
        START + timedelta(seconds=60),
    ]


def test_a_window_includes_events_on_both_of_its_edges(store: ParquetEventStore) -> None:
    """The store has to agree with `TimeWindow.contains`, which counts both
    ends. A store that excluded them would drop the very request whose second
    the reader typed in."""
    store.write([event(offset_seconds=n, line_no=n + 1) for n in (0, 30, 60)])
    store.finalize()
    edges = TimeWindow(START, START + timedelta(seconds=60))

    inside = store.events_for_ip("203.0.113.5", window=edges)

    assert len(inside) == 3


def test_a_window_still_returns_events_in_time_order(store: ParquetEventStore) -> None:
    store.write([event(offset_seconds=n, line_no=n + 1) for n in (90, 0, 60, 30)])
    store.finalize()

    inside = store.events_for_ip("203.0.113.5", window=TimeWindow(START, START + timedelta(days=1)))

    assert [e.timestamp for e in inside] == sorted(e.timestamp for e in inside)


def test_a_window_holding_nothing_is_empty_not_an_error(store: ParquetEventStore) -> None:
    store.write([event(offset_seconds=0)])
    store.finalize()

    assert (
        store.events_for_ip(
            "203.0.113.5",
            window=TimeWindow(START + timedelta(days=9), START + timedelta(days=10)),
        )
        == []
    )


def test_an_open_window_reads_exactly_what_no_window_reads(store: ParquetEventStore) -> None:
    """The contract that keeps every existing case reading as it always did.
    Compared event by event, not by counting: a path that returned the right
    number of the wrong rows would pass a count."""
    store.write([event(offset_seconds=n, line_no=n + 1) for n in (0, 30, 60, 90)])
    store.finalize()

    assert store.events_for_ip("203.0.113.5", window=EVERYTHING) == store.events_for_ip(
        "203.0.113.5"
    )


# -- summarising one stretch of time ---------------------------------------


def busy(store: ParquetEventStore) -> None:
    """Two clients whose activity straddles the window used below."""
    store.write(
        [
            # 1.1.1.1 — three inside the window, two outside it
            event("1.1.1.1", offset_seconds=0, path="/before", status=200, line_no=1),
            event("1.1.1.1", offset_seconds=30, path="/a", status=404, line_no=2),
            event("1.1.1.1", offset_seconds=45, path="/b", status=404, line_no=3),
            event("1.1.1.1", offset_seconds=60, path="/a", status=200, line_no=4),
            # A server error, inside the window. It is not the client's fault
            # and must not raise the share the list sorts suspicion by.
            event("1.1.1.1", offset_seconds=55, path="/c", status=503, line_no=7),
            event("1.1.1.1", offset_seconds=200, path="/after", status=200, line_no=5),
            # 2.2.2.2 — entirely outside it
            event("2.2.2.2", offset_seconds=500, path="/x", status=200, line_no=6),
        ]
    )
    store.finalize()


WINDOW = TimeWindow(START + timedelta(seconds=30), START + timedelta(seconds=60))


def test_a_client_silent_in_the_window_is_not_listed(store: ParquetEventStore) -> None:
    busy(store)

    listed = {s.client_ip for s in store.ip_summaries(window=WINDOW)}

    assert listed == {"1.1.1.1"}


def test_the_numbers_are_the_windows_own_not_the_whole_cases(
    store: ParquetEventStore,
) -> None:
    """The test this feature turns on.

    A row saying 5 requests beside a graph saying 3 is two numbers for one thing
    on one screen, and it is what decided the shape of the whole feature. The
    only way that cannot happen is if the summary is computed from the same
    events the graph is built from — so this compares the two directly rather
    than against a number typed into the test.
    """
    busy(store)

    summary = next(s for s in store.ip_summaries(window=WINDOW) if s.client_ip == "1.1.1.1")
    events = store.events_for_ip("1.1.1.1", window=WINDOW)

    assert summary.request_count == len(events)
    assert summary.first_seen == min(e.timestamp for e in events)
    assert summary.last_seen == max(e.timestamp for e in events)
    assert summary.distinct_paths == len({e.path for e in events})
    assert summary.bytes_total == sum(e.bytes_sent or 0 for e in events)


def test_the_error_share_is_the_windows_own(store: ParquetEventStore) -> None:
    """Two of the four requests inside the window were refused by the server as
    the client's fault; a third was a 503, which is not. The client list sorts
    suspicion by this figure, so counting server errors into it would put the
    wrong client at the top, and a whole-case ratio shown against a window would
    do the same.
    """
    busy(store)

    summary = next(s for s in store.ip_summaries(window=WINDOW) if s.client_ip == "1.1.1.1")

    assert summary.client_error_ratio == pytest.approx(2 / 4)


def test_an_open_window_summarises_exactly_what_no_window_summarises(
    store: ParquetEventStore,
) -> None:
    """The contract that keeps an unfiltered case reading as it always did."""
    busy(store)

    assert store.ip_summaries(window=EVERYTHING) == store.ip_summaries()


def test_a_window_holding_nobody_lists_nobody(store: ParquetEventStore) -> None:
    busy(store)

    assert (
        store.ip_summaries(window=TimeWindow(START + timedelta(days=9), START + timedelta(days=10)))
        == []
    )


def test_a_window_still_honours_the_order_and_the_limit(store: ParquetEventStore) -> None:
    store.write(
        [
            event("1.1.1.1", offset_seconds=30, line_no=1),
            event("2.2.2.2", offset_seconds=31, line_no=2),
            event("2.2.2.2", offset_seconds=32, line_no=3),
            event("3.3.3.3", offset_seconds=33, line_no=4),
        ]
    )
    store.finalize()
    wide = TimeWindow(START, START + timedelta(seconds=60))

    busiest = store.ip_summaries(window=wide, order_by="requests", limit=2)

    assert [s.client_ip for s in busiest] == ["2.2.2.2", "1.1.1.1"]


# -- how large the case is -------------------------------------------------


def test_the_overview_counts_every_client_not_only_the_listed_ones(
    store: ParquetEventStore,
) -> None:
    """`ip_summaries` is capped so a window can draw a table from it. What the
    window says *about the case* cannot come from that list: a cap there makes a
    case of fifty thousand clients look like a case of five hundred.

    Six hundred clients, deliberately more than the five hundred the window
    lists. At fifty-nine this test passed with a `LIMIT 500` left in the query
    it is checking — the number has to be past every cap in the tool or it
    proves nothing about caps.
    """
    store.write(
        [event(f"10.{n // 250}.{n % 250}.1", offset_seconds=n, line_no=n + 1) for n in range(600)]
    )
    store.finalize()

    assert store.overview().clients == 600
    assert len(store.ip_summaries(limit=500)) == 500


def test_the_overview_reaches_the_clients_the_busiest_never_touch(
    store: ParquetEventStore,
) -> None:
    """The date fields are held inside this stretch, so it has to be the case's.

    Taken from the busiest clients alone it stops short of both ends. Measured
    on a real case of 119,880 clients: the busiest five hundred covered eight
    days of a twenty-seven day case, and nineteen days of it could not be
    selected at all — while the band above the fields went on drawing traffic
    across all of it.
    """
    busy = [event("10.0.0.1", offset_seconds=n, line_no=n + 1) for n in range(50)]
    early = [event("10.0.0.2", offset_seconds=-9_000, line_no=100)]
    late = [event("10.0.0.3", offset_seconds=9_000, line_no=101)]
    store.write(busy + early + late)
    store.finalize()

    overview = store.overview()

    assert overview.first_seen == START - timedelta(seconds=9_000)
    assert overview.last_seen == START + timedelta(seconds=9_000)


def test_the_overview_can_be_asked_about_one_stretch(store: ParquetEventStore) -> None:
    """What the range left of the case. Counted rather than inferred from a
    capped list, for the same reason the whole-case figure is."""
    store.write([event(f"10.0.0.{n}", offset_seconds=n * 600, line_no=n + 1) for n in range(1, 20)])
    store.finalize()

    narrow = TimeWindow(START + timedelta(seconds=600), START + timedelta(seconds=3_000))

    assert store.overview(window=narrow).clients == 5
    assert store.overview().clients == 19


def test_an_empty_case_has_an_empty_overview(store: ParquetEventStore) -> None:
    """A case is opened before it is read, and the window asks then."""
    store.finalize()

    overview = store.overview()

    assert overview.clients == 0
    assert overview.first_seen is None
    assert overview.last_seen is None


def test_the_overview_agrees_with_the_summaries_when_nothing_is_capped(
    store: ParquetEventStore,
) -> None:
    """Two ways of counting the same thing must not disagree."""
    store.write([event(f"10.0.0.{n}", offset_seconds=n * 7, line_no=n + 1) for n in range(1, 12)])
    store.finalize()

    every = store.ip_summaries()
    overview = store.overview()

    assert overview.clients == len(every)
    assert overview.first_seen == min(s.first_seen for s in every)
    assert overview.last_seen == max(s.last_seen for s in every)


# -- where the traffic sits, for the band ----------------------------------


def test_the_buckets_account_for_every_event(store: ParquetEventStore) -> None:
    """The band is drawn from these. A bucketing that loses events would draw a
    quiet stretch where the case is busy, and the reader would select the wrong
    window because of it."""
    store.write([event(offset_seconds=n * 7, line_no=n + 1) for n in range(50)])
    store.finalize()

    slots = store.activity_over_time(buckets=10)

    assert sum(slot.request_count for slot in slots) == 50


def test_the_band_starts_at_the_case_and_ends_at_the_case(store: ParquetEventStore) -> None:
    store.write([event(offset_seconds=n * 60, line_no=n + 1) for n in range(20)])
    store.finalize()

    slots = store.activity_over_time(buckets=8)

    assert slots[0].start <= START
    assert slots[-1].start <= START + timedelta(seconds=19 * 60)


def test_the_band_is_filled_to_roughly_the_width_asked_for(store: ParquetEventStore) -> None:
    """A case covering a few minutes has to fill the band too, or the control
    that exists to show where the traffic is shows one block.

    Roughly, and checked as a share rather than exactly: the step is the span
    divided by the count, and `time_bucket` aligns to whole steps from the
    epoch, so the ends can spill by one. Asserting merely "more than one" was
    too loose to notice a step as wide as the entire case.
    """
    store.write([event(offset_seconds=n * 10, line_no=n + 1) for n in range(30)])
    store.finalize()

    slots = store.activity_over_time(buckets=10)

    assert len(slots) >= 8


def test_a_case_with_one_event_does_not_fall_over(store: ParquetEventStore) -> None:
    """Span zero. Divided by it, the bucket width is undefined and the band
    never draws."""
    store.write([event(offset_seconds=0)])
    store.finalize()

    slots = store.activity_over_time(buckets=10)

    assert len(slots) == 1
    assert slots[0].request_count == 1


def test_a_quiet_stretch_comes_back_as_zero_rather_than_missing(
    store: ParquetEventStore,
) -> None:
    """A histogram with holes in it is not a histogram.

    Only non-empty buckets used to come back, which left the band unable to
    know how wide a bucket was: it inferred that from the narrowest gap between
    two that arrived. On a client with a handful of requests that gap is far
    wider than the bucket really is, and every request was drawn as a slab —
    six requests over two minutes became six blocks 21px wide, each claiming to
    have lasted half a minute.
    """
    store.write([event(offset_seconds=0, line_no=1), event(offset_seconds=1_000, line_no=2)])
    store.finalize()

    slots = store.activity_over_time(buckets=10)

    assert [slot.request_count for slot in slots] == [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]


def test_every_pair_of_buckets_is_exactly_one_step_apart(store: ParquetEventStore) -> None:
    """What makes the width knowable rather than guessable. With no holes, the
    gap between two neighbours *is* the bucket width."""
    store.write([event(offset_seconds=n, line_no=n + 1) for n in (0, 3, 4, 400, 401, 900)])
    store.finalize()

    slots = store.activity_over_time(buckets=20)

    steps = {b.start - a.start for a, b in pairwise(slots)}
    assert len(steps) == 1, f"buckets are not evenly spaced: {sorted(steps)}"


def test_filling_the_quiet_stretches_invents_no_requests(store: ParquetEventStore) -> None:
    store.write([event(offset_seconds=n * 97, line_no=n + 1) for n in range(11)])
    store.finalize()

    assert sum(slot.request_count for slot in store.activity_over_time(buckets=25)) == 11


def test_an_empty_case_has_an_empty_band(store: ParquetEventStore) -> None:
    store.finalize()

    assert store.activity_over_time() == []


def test_the_buckets_come_back_in_time_order(store: ParquetEventStore) -> None:
    store.write([event(offset_seconds=n * 13, line_no=n + 1) for n in (7, 1, 4, 9, 0)])
    store.finalize()

    slots = store.activity_over_time(buckets=5)

    assert [s.start for s in slots] == sorted(s.start for s in slots)


def test_the_band_can_be_asked_about_one_client(store: ParquetEventStore) -> None:
    """Asked about a client, the buckets hold only that client's requests."""
    store.write(
        [
            event("1.1.1.1", offset_seconds=0, line_no=1),
            event("1.1.1.1", offset_seconds=10, line_no=2),
            event("2.2.2.2", offset_seconds=5, line_no=3),
        ]
    )
    store.finalize()

    slots = store.activity_over_time(buckets=4, client_ip="1.1.1.1")

    assert sum(slot.request_count for slot in slots) == 2


def test_a_clients_band_spans_that_clients_own_life(store: ParquetEventStore) -> None:
    """Not the case's. The whole point of asking per client is that a client
    alive for ninety minutes fills the band instead of being a hairline in the
    middle of two days."""
    store.write(
        [
            event("1.1.1.1", offset_seconds=100, line_no=1),
            event("1.1.1.1", offset_seconds=200, line_no=2),
            event("2.2.2.2", offset_seconds=0, line_no=3),
            event("2.2.2.2", offset_seconds=9_000, line_no=4),
        ]
    )
    store.finalize()

    slots = store.activity_over_time(buckets=10, client_ip="1.1.1.1")

    assert slots[0].start >= START + timedelta(seconds=100 - 30)
    assert slots[-1].start <= START + timedelta(seconds=200)


def test_a_client_with_nothing_has_an_empty_band(store: ParquetEventStore) -> None:
    store.write([event("1.1.1.1", offset_seconds=0)])
    store.finalize()

    assert store.activity_over_time(client_ip="9.9.9.9") == []


def test_asking_about_nobody_is_the_whole_case(store: ParquetEventStore) -> None:
    store.write([event("1.1.1.1", line_no=1), event("2.2.2.2", offset_seconds=60, line_no=2)])
    store.finalize()

    assert store.activity_over_time(client_ip=None) == store.activity_over_time()
