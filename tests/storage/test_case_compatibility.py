"""Cases remain readable when DuckDB's hash changes between versions."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb
import pyarrow.parquet as pq
import pytest

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.core.window import TimeWindow
from logarc.storage.event_store import BUCKETS, ParquetEventStore

START = datetime(2026, 1, 1, tzinfo=UTC)
IP = "192.0.2.31"


@pytest.fixture
def legacy_case(tmp_path: Path) -> Path:
    """An old index and a partition assigned by a different hash implementation.

    Move the actual event file, leaving its contents untouched. No test needs a
    particular installed DuckDB version or assumes its current hash value.
    """
    root = tmp_path / "case"
    store = ParquetEventStore(root)
    store.write(
        NormalizedEvent(
            timestamp=START + timedelta(days=n),
            client_ip=IP,
            evidence=EvidenceRef("access.log", n + 1),
            method="GET",
            path=f"/request-{n}",
            status=200,
        )
        for n in range(2)
    )
    store.finalize()
    store.close()
    with duckdb.connect() as connection:
        bucket = connection.execute("SELECT hash(?) % ?", [IP, BUCKETS]).fetchone()[0]
    (root / "events" / f"bucket={bucket}").rename(
        root / "events" / f"bucket={(bucket + 1) % BUCKETS}"
    )
    index = pq.read_table(root / "ip_index.parquet")
    if "bucket" in index.column_names:
        pq.write_table(index.drop(["bucket"]), root / "ip_index.parquet")
    return root


def test_old_case_reconstructs_all_requests_without_changing_its_files(legacy_case: Path) -> None:
    before = {p.relative_to(legacy_case): p.read_bytes() for p in legacy_case.rglob("*.parquet")}
    store = ParquetEventStore(legacy_case)
    try:
        assert [e.path for e in store.events_for_ip(IP)] == ["/request-0", "/request-1"]
        assert store.events_for_ip("192.0.2.99") == []
        assert [
            e.path
            for e in store.events_for_ip(IP, window=TimeWindow(start=START + timedelta(days=1)))
        ] == ["/request-1"]
        assert store.ip_summaries()[0].request_count == 2
    finally:
        store.close()
    assert {
        p.relative_to(legacy_case): p.read_bytes() for p in legacy_case.rglob("*.parquet")
    } == before


def test_old_case_client_timeline_keeps_every_request(legacy_case: Path) -> None:
    store = ParquetEventStore(legacy_case)
    try:
        assert sum(slot.request_count for slot in store.activity_over_time(client_ip=IP)) == 2
        assert store.activity_over_time(client_ip="192.0.2.99") == []
    finally:
        store.close()
