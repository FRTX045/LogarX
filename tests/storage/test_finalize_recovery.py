"""An interrupted write must never masquerade as a complete evidence store."""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.storage.event_store import ParquetEventStore, StoreStateError

IP = "192.0.2.31"


def request() -> NormalizedEvent:
    return NormalizedEvent(
        datetime(2026, 1, 1, tzinfo=UTC),
        IP,
        EvidenceRef("access.log", 1),
        method="GET",
        path="/proof",
    )


@pytest.mark.parametrize("after_partition", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_partition_is_unreadable_and_retry_preserves_evidence(
    tmp_path: Path, after_partition: bool, error: type[BaseException]
) -> None:
    writer = ParquetEventStore(tmp_path / "case")
    writer.write([request()])
    partition = writer._partition_and_sort

    def interrupted(*args: object) -> None:
        if after_partition:
            partition(*args)
        raise error("interrupted finalization")

    with (
        patch.object(writer, "_partition_and_sort", side_effect=interrupted),
        pytest.raises(error),
    ):
        writer.finalize()
    writer.close()
    reader = ParquetEventStore(writer.root)
    try:
        assert not reader.is_finalized
        with pytest.raises(StoreStateError):
            reader.events_for_ip(IP)
        with pytest.raises(StoreStateError):
            reader.write([request()])
        reader.finalize()
        assert reader.is_finalized
        assert reader.events_for_ip(IP) == [request()]
        assert reader.ip_summaries()[0].request_count == 1
        assert not list((reader.root / "staging").glob("*.parquet"))
        reader.finalize()
        assert reader.events_for_ip(IP) == [request()]
    finally:
        reader.close()


def test_failed_empty_index_is_not_mistaken_for_a_complete_empty_case(tmp_path: Path) -> None:
    store = ParquetEventStore(tmp_path / "case")
    write_index = store._write_empty_index

    def interrupted() -> None:
        write_index()
        raise OSError("failed before completion")

    with (
        patch.object(store, "_write_empty_index", side_effect=interrupted),
        pytest.raises(OSError),
    ):
        store.finalize()
    assert not store.is_finalized
    store.close()
    resumed = ParquetEventStore(store.root)
    try:
        resumed.finalize()
        assert resumed.is_finalized
        assert resumed.ip_summaries() == []
        assert list(resumed.all_events()) == []
    finally:
        resumed.close()


def test_legacy_partial_output_is_rejected_without_deleting_it(tmp_path: Path) -> None:
    store = ParquetEventStore(tmp_path / "case")
    store.write([request()])
    (store.root / "events").mkdir()
    before = next((store.root / "staging").glob("*.parquet")).read_bytes()
    assert not store.is_finalized
    with pytest.raises(StoreStateError):
        store.write([request()])
    with pytest.raises(StoreStateError):
        store.finalize()
    assert next((store.root / "staging").glob("*.parquet")).read_bytes() == before
    store.close()


def test_legacy_completed_case_needs_no_marker_or_migration(tmp_path: Path) -> None:
    store = ParquetEventStore(tmp_path / "case")
    store.write([request()])
    store.finalize()
    store.close()
    (store.root / ".finalized").unlink(missing_ok=True)
    reader = ParquetEventStore(store.root)
    try:
        assert reader.is_finalized
        assert reader.events_for_ip(IP) == [request()]
        reader.finalize()
        assert not (store.root / ".finalized").exists()
    finally:
        reader.close()


@pytest.mark.parametrize("after_index", [False, True])
def test_failed_index_keeps_staging_available_for_retry(tmp_path: Path, after_index: bool) -> None:
    store = ParquetEventStore(tmp_path / "case")
    store.write([request()])
    write_index = store._write_index

    def interrupted(*args: object) -> None:
        if after_index:
            write_index(*args)
        raise OSError("index write interrupted")

    with patch.object(store, "_write_index", side_effect=interrupted), pytest.raises(OSError):
        store.finalize()
    assert not store.is_finalized
    with pytest.raises(StoreStateError):
        store.ip_summaries()
    store.close()
    reader = ParquetEventStore(store.root)
    try:
        reader.finalize()
        assert reader.events_for_ip(IP) == [request()]
    finally:
        reader.close()


def test_failure_to_publish_completion_leaves_a_recoverable_store(tmp_path: Path) -> None:
    store = ParquetEventStore(tmp_path / "case")
    store.write([request()])
    touch = Path.touch

    def fail_publication(path: Path, *args: object, **kwargs: object) -> None:
        if path.name == ".finalized":
            raise OSError("cannot publish completion")
        touch(path, *args, **kwargs)

    with patch.object(Path, "touch", fail_publication), pytest.raises(OSError):
        store.finalize()
    assert not store.is_finalized
    store.finalize()
    try:
        assert store.events_for_ip(IP) == [request()]
    finally:
        store.close()


def test_partial_staging_cleanup_cannot_cause_a_subset_to_replace_complete_data(
    tmp_path: Path,
) -> None:
    import shutil
    from dataclasses import replace

    store = ParquetEventStore(tmp_path / "case")
    first = request()
    second = replace(first, evidence=EvidenceRef("access.log", 2), path="/second")
    store.write([first])
    store.write([second])
    remove = shutil.rmtree

    def partial_cleanup(path: Path, *args: object, **kwargs: object) -> None:
        if path == store.root / "staging":
            next(path.glob("*.parquet")).unlink()
            return
        remove(path, *args, **kwargs)

    with patch.object(shutil, "rmtree", partial_cleanup):
        store.finalize()
    store.close()
    assert list((store.root / "staging").glob("*.parquet"))
    reader = ParquetEventStore(store.root)
    try:
        assert reader.is_finalized
        reader.finalize()
        assert reader.events_for_ip(IP) == [first, second]
        assert reader.ip_summaries()[0].request_count == 2
    finally:
        reader.close()
