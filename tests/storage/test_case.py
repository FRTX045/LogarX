"""Tests for the case manifest."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from logarc.storage.case import CaseManifest, CaseManifestError, SourceRecord

SOURCE = SourceRecord(
    file_id="access.log",
    original_path="/var/log/apache2/access.log",
    sha256="a" * 64,
    size_bytes=2048,
    compression="none",
    log_format="apache-combined",
    lines_read=100,
    events_parsed=98,
    lines_quarantined=2,
)


def test_manifest_round_trips_through_disk(tmp_path: Path) -> None:
    manifest = CaseManifest.create(case_id="case-001")
    manifest.sources.append(SOURCE)
    manifest.config["idle_timeout_seconds"] = 1800
    manifest.save(tmp_path)

    restored = CaseManifest.load(tmp_path)

    assert restored.case_id == "case-001"
    assert restored.sources == [SOURCE]
    assert restored.config["idle_timeout_seconds"] == 1800
    assert restored.created_at == manifest.created_at


def test_manifest_records_the_tool_version_that_produced_it(tmp_path: Path) -> None:
    """A finding is only reproducible if you know which build made it."""
    CaseManifest.create(case_id="c").save(tmp_path)

    written = json.loads((tmp_path / "case.json").read_text(encoding="utf-8"))

    assert written["tool_version"]


def test_manifest_is_written_as_readable_json(tmp_path: Path) -> None:
    """Investigators read this file directly, and it may be quoted in a report."""
    CaseManifest.create(case_id="c").save(tmp_path)

    text = (tmp_path / "case.json").read_text(encoding="utf-8")

    assert "\n  " in text


def test_created_at_is_timezone_aware_utc() -> None:
    manifest = CaseManifest.create(case_id="c")

    assert manifest.created_at.tzinfo is UTC


def test_loading_a_directory_without_a_manifest_reports_the_path(tmp_path: Path) -> None:
    with pytest.raises(CaseManifestError, match=r"case\.json"):
        CaseManifest.load(tmp_path)


def test_loading_a_corrupt_manifest_reports_the_problem(tmp_path: Path) -> None:
    (tmp_path / "case.json").write_text("{ not json", encoding="utf-8")

    with pytest.raises(CaseManifestError, match="could not be read"):
        CaseManifest.load(tmp_path)


def test_sources_are_recorded_with_their_integrity_hash(tmp_path: Path) -> None:
    manifest = CaseManifest.create(case_id="c")
    manifest.sources.append(SOURCE)
    manifest.save(tmp_path)

    written = json.loads((tmp_path / "case.json").read_text(encoding="utf-8"))

    assert written["sources"][0]["sha256"] == "a" * 64
    assert written["sources"][0]["original_path"] == "/var/log/apache2/access.log"


def test_totals_summarise_every_source() -> None:
    manifest = CaseManifest.create(case_id="c")
    manifest.sources.extend([SOURCE, SOURCE])

    assert manifest.total_events_parsed == 196
    assert manifest.total_lines_quarantined == 4


def test_timestamps_survive_serialisation_exactly(tmp_path: Path) -> None:
    manifest = CaseManifest(
        case_id="c",
        created_at=datetime(2024, 3, 1, 9, 30, 15, tzinfo=UTC),
        tool_version="1.2.3",
    )
    manifest.save(tmp_path)

    assert CaseManifest.load(tmp_path).created_at == manifest.created_at
