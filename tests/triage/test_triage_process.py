import threading
import time

import pytest
from test_profiles import events

from logarc.case import Case


def stubborn_worker(root, window, scratch, output, stop):
    (scratch / "spill").write_bytes(b"unfinished spill")
    from logarc.triage.scan import TriageProgress

    output.send(("progress", TriageProgress(0, 100, ())))
    time.sleep(30)


def test_active_cancel_terminates_only_owned_worker_and_cleans_scratch(tmp_path, monkeypatch):
    from logarc.triage import process
    from logarc.triage.scan import ScanCancelled

    monkeypatch.setattr(process, "_scan_worker", stubborn_worker)
    shared = tmp_path / "tmp"
    shared.mkdir()
    (shared / "other-reader").write_text("keep")
    stop = threading.Event()
    with pytest.raises(ScanCancelled):
        process.run_scan(tmp_path, report=lambda progress: stop.set(), stop=stop)
    assert not list((tmp_path / "triage").glob("worker-*"))
    assert (shared / "other-reader").read_text() == "keep"


def test_spawned_scan_returns_searchable_result_and_progress(tmp_path):
    from logarc.triage.process import run_scan
    from logarc.triage.scan import read_page

    with Case.create(tmp_path / "case") as case:
        case.store.write(events(path="/etc/passwd"))
        case.store.finalize()
    progress = []
    result = run_scan(case.root, report=progress.append, stop=threading.Event())
    assert result.clients == 1
    assert progress[-1].processed == 1
    assert read_page(result.path, "suspicious").total == 1
    assert not list((case.root / "triage").glob("worker-*"))


def test_cancel_before_spawn_does_not_start_work(tmp_path):
    from logarc.triage.process import run_scan
    from logarc.triage.scan import ScanCancelled

    stop = threading.Event()
    stop.set()
    with pytest.raises(ScanCancelled):
        run_scan(tmp_path, report=lambda progress: None, stop=stop)
    assert not (tmp_path / "triage").exists()


def test_worker_failure_is_reported_to_parent(tmp_path):
    from logarc.triage.process import run_scan

    with pytest.raises(RuntimeError, match="no case"):
        run_scan(tmp_path, report=lambda progress: None, stop=threading.Event())


def abruptly_exiting_worker(root, window, scratch, output, stop):
    import os

    from logarc.triage.scan import scan_case

    def exit_during_scan(progress):
        assert list(scratch.glob("scan-*/crs.sqlite"))
        output.send(("progress", progress))
        os._exit(23)

    scan_case(root, window=window, scratch_root=scratch, report=exit_during_scan)


def test_abrupt_child_exit_cleans_real_scan_files_and_preserves_completed_cache(
    tmp_path, monkeypatch
):
    from logarc.core.window import TimeWindow
    from logarc.triage import process
    from logarc.triage.scan import scan_case

    with Case.create(tmp_path / "case") as case:
        sample = events(count=3)
        case.store.write(sample)
        case.finalize()
    completed = scan_case(case.root)
    original = completed.path.read_bytes()
    progress = []
    monkeypatch.setattr(process, "_scan_worker", abruptly_exiting_worker)
    with pytest.raises(RuntimeError, match="exited"):
        process.run_scan(
            case.root,
            window=TimeWindow(start=sample[1].timestamp),
            report=progress.append,
            stop=threading.Event(),
        )
    assert len(progress) == 1
    assert progress[0].processed == 1
    assert not list((case.root / "triage").glob("worker-*"))
    assert completed.path.read_bytes() == original
    assert scan_case(case.root).cached
