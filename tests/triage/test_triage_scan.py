from test_profiles import events, scanned

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


def test_scan_labels_with_the_case_site_hosts(tmp_path):
    """Triage must label what reconstruction labels.

    `rfi_offsite_url` reports nothing until a reader has named the site's own
    domains, so a scan building its own engine silently misses every offsite
    URL the reconstruction reports for the same client.
    """
    from logarc.triage.scan import read_page, scan_case

    with Case.create(tmp_path / "case") as case:
        case.store.write(events("203.0.113.9", 1, query="url=http://evil.test/x"))
        case.store.finalize()
        case.set_site_hosts(["shop.test"])
        root = case.root

    rows = read_page(scan_case(root).path, "suspicious").rows
    assert [row.profile.client_ip for row in rows] == ["203.0.113.9"]


def test_who_else_matched_a_rule_includes_clients_it_did_not_name(tmp_path):
    """dirb and gobuster ran one wordlist; only dirb was labelled for it.

    Both come back for `directory_enumeration`, and the counts say which one the
    rule actually named, so the reader can see why gobuster's reconstruction
    calls the same activity something else.
    """
    from dataclasses import replace

    from logarc.triage.scan import RuleMatch, read_rule_matches, scan_case

    with Case.create(tmp_path / "case") as case:
        case.store.write(scanned("192.0.2.31"))
        case.store.write(
            [replace(event, user_agent="Mozilla/5.0") for event in scanned("192.0.2.30", 20)]
        )
        case.store.write(events("192.0.2.1", 5))
        case.store.finalize()
    result = scan_case(case.root)

    assert read_rule_matches(result.path, "directory_enumeration") == (
        RuleMatch("192.0.2.31", matched=30, won=0, requests=30),
        RuleMatch("192.0.2.30", matched=20, won=20, requests=20),
    )
    assert read_rule_matches(result.path, "no_such_rule") == ()


def test_an_index_without_rule_counts_is_rebuilt(tmp_path):
    """Read as empty, a missing table would answer that nobody else did it."""
    import sqlite3
    from contextlib import closing

    from logarc.triage.scan import scan_case

    with Case.create(tmp_path / "case") as case:
        case.store.write(events())
        case.store.finalize()
    result = scan_case(case.root)
    with closing(sqlite3.connect(result.path)) as connection:
        connection.execute("DROP TABLE rules")
        connection.commit()
    assert not scan_case(case.root).cached


def test_stored_profiles_keep_their_request_examples(tmp_path):
    import json
    from dataclasses import asdict, replace

    from test_profiles import probe_attack_engine

    from logarc.triage.profile import profile_client
    from logarc.triage.scan import _profile

    sample = events(count=4)
    sample[1] = replace(sample[1], query="probe")
    sample[2] = replace(sample[2], query="attack")
    profile = profile_client(sample, probe_attack_engine(tmp_path))
    assert profile.sequence_examples
    assert profile.exploit_examples
    assert _profile(json.loads(json.dumps(asdict(profile)))) == profile


def test_an_index_written_in_the_previous_layout_is_rebuilt(tmp_path, monkeypatch):
    """Read as current, it would hand back profiles without the facts reasons need."""
    from logarc.triage import scan

    with Case.create(tmp_path / "case") as case:
        case.store.write(events())
        case.store.finalize()
    monkeypatch.setattr(scan, "_LAYOUT", 2)
    old = scan.scan_case(case.root)
    monkeypatch.undo()
    current = scan.scan_case(case.root)
    assert not current.cached
    assert current.path != old.path


def test_an_index_written_in_layout_five_is_rebuilt(tmp_path, monkeypatch):
    """Read as current, it would show every client as having no exploit evidence."""
    from logarc.triage import scan

    with Case.create(tmp_path / "case") as case:
        case.store.write(events())
        case.store.finalize()
    monkeypatch.setattr(scan, "_LAYOUT", 5)
    old = scan.scan_case(case.root)
    monkeypatch.undo()
    current = scan.scan_case(case.root)
    assert not current.cached
    assert current.path != old.path


def test_suspicious_reasons_follow_the_code_not_the_cached_text(tmp_path):
    """A reworded reason must reach a case scanned before the rewording."""
    import sqlite3
    from contextlib import closing

    from logarc.triage.scan import read_page, scan_case

    with Case.create(tmp_path / "case") as case:
        case.store.write(events("203.0.113.9", 3, path="/etc/passwd"))
        case.store.finalize()
    result = scan_case(case.root)
    with closing(sqlite3.connect(result.path)) as connection:
        connection.execute(
            "UPDATE ranking SET reasons = ? WHERE queue = 'suspicious'",
            ('[{"text": "stale wording", "evidence": []}]',),
        )
        connection.commit()
    (row,) = read_page(result.path, "suspicious").rows
    assert row.reasons[0].kind == "support"
    assert "stale wording" not in {reason.text for reason in row.reasons}
