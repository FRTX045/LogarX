from test_profiles import events

from logarc.case import Case
from logarc.core.window import TimeWindow


def test_client_iterator_groups_all_clients_and_filters_at_storage(tmp_path):
    with Case.create(tmp_path / "case") as case:
        sample = events("192.0.2.2", 3) + events("192.0.2.1", 3)
        case.store.write(reversed(sample))
        case.store.finalize()
        groups = list(case.store.iter_clients(window=TimeWindow(start=sample[1].timestamp)))
        assert {group[0].client_ip for group in groups} == {"192.0.2.1", "192.0.2.2"}
        assert all(len(group) == 2 for group in groups)
        assert all(group[0].timestamp <= group[1].timestamp for group in groups)


def test_scan_cache_search_beyond_first_500_and_invalidation(tmp_path):
    from logarc.triage.scan import read_page, scan_case

    with Case.create(tmp_path / "case") as case:
        case.store.write([e for i in range(505) for e in events(f"192.0.2.{i}", 1)])
        case.store.write(events("203.0.113.9", 1, path="/etc/passwd"))
        case.store.finalize()
        root = case.root
    result = scan_case(root)
    assert result.clients == 506
    assert result.crs_present is False
    assert read_page(result.path, "suspicious").rows[0].profile.client_ip == "203.0.113.9"
    page = read_page(result.path, "all", query="192.0.2.504")
    assert page.total == 1
    assert page.rows[0].profile.client_ip == "192.0.2.504"
    assert scan_case(root).cached
    (root / "crs.jsonl").write_text("", encoding="utf-8")
    enriched = scan_case(root)
    assert not enriched.cached
    assert enriched.crs_present
    assert enriched.path != result.path


def test_cancelled_scan_does_not_publish_a_cache(tmp_path):
    import pytest

    from logarc.triage.scan import ScanCancelled, scan_case

    with Case.create(tmp_path / "case") as case:
        case.store.write(events())
        case.store.finalize()
    with pytest.raises(ScanCancelled):
        scan_case(case.root, cancelled=lambda: True)
    assert not list((case.root / "triage").glob("*.sqlite"))


def test_scan_spill_is_owned_and_does_not_share_reconstruction_scratch(tmp_path, monkeypatch):
    from logarc.storage.event_store import ParquetEventStore
    from logarc.triage.scan import scan_case

    with Case.create(tmp_path / "case") as case:
        case.store.write(events())
        case.store.finalize()
    shared = case.root / "tmp"
    shared.mkdir(exist_ok=True)
    sentinel = shared / "another-reader"
    sentinel.write_text("keep")
    paths = []
    connect = ParquetEventStore._connect

    def observed(store):
        paths.append(store._scratch)
        return connect(store)

    monkeypatch.setattr(ParquetEventStore, "_connect", observed)
    scan_case(case.root)
    assert paths
    assert all(path.is_relative_to(case.root / "triage") for path in paths)
    assert sentinel.read_text() == "keep"
    assert all(not path.exists() for path in paths)


def test_native_only_scan_skips_per_request_crs_queries(tmp_path, monkeypatch):
    from logarc.triage import scan

    with Case.create(tmp_path / "case") as case:
        case.store.write(events())
        case.store.finalize()

    def unexpected(*args):
        raise AssertionError("CRS has no detections to look up")

    monkeypatch.setattr(scan, "_client_crs", unexpected)
    assert scan.scan_case(case.root).clients == 1


def test_corrupt_cache_is_rebuilt(tmp_path):
    import sqlite3
    from contextlib import closing

    from logarc.triage.scan import scan_case

    with Case.create(tmp_path / "case") as case:
        case.store.write(events())
        case.store.finalize()
    result = scan_case(case.root)
    with closing(sqlite3.connect(result.path)) as connection:
        connection.execute("DROP TABLE ranking")
        connection.commit()
    assert not scan_case(case.root).cached


def test_keyboard_interrupt_during_direct_scan_cleans_scratch_and_preserves_completed_cache(
    tmp_path,
):
    import pytest

    from logarc.triage.scan import scan_case

    with Case.create(tmp_path / "case") as case:
        sample = events(count=3)
        case.store.write(sample)
        case.finalize()
    completed = scan_case(case.root)
    original = completed.path.read_bytes()

    def interrupt(progress):
        assert list((case.root / "triage").glob("scan-*/crs.sqlite"))
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        scan_case(case.root, window=TimeWindow(start=sample[1].timestamp), report=interrupt)
    assert completed.path.read_bytes() == original
    assert not list((case.root / "triage").glob("scan-*"))
    assert scan_case(case.root).cached
