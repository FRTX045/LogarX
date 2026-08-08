"""Tests for the Parquet/DuckDB event store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.storage.event_store import ParquetEventStore, StoreStateError

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
            event("2.2.2.2", offset_seconds=5, path="/a", status=200),
        ]
    )
    store.finalize()

    summaries = {s.client_ip: s for s in store.ip_summaries()}

    first = summaries["1.1.1.1"]
    assert first.request_count == 3
    assert first.distinct_paths == 2
    assert first.first_seen == START
    assert first.last_seen == START + timedelta(seconds=120)
    assert first.client_error_ratio == pytest.approx(2 / 3)
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
    assert Path(temp[0]) == tmp_path / "case" / "tmp"


def test_the_spill_directory_does_not_outlive_finalize(tmp_path: Path) -> None:
    """Sorting ten million rows can spill gigabytes; they are not evidence."""
    store = ParquetEventStore(tmp_path / "case")
    store.write([event(f"203.0.113.{n % 5}", offset_seconds=n, line_no=n + 1) for n in range(20)])
    store.finalize()
    store.close()

    assert not (tmp_path / "case" / "tmp").exists()
    assert store.events_for_ip("203.0.113.1")
