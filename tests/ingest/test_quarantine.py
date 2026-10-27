"""Tests for quarantined (unparseable) log lines."""

from __future__ import annotations

import json
from pathlib import Path

from logarx.ingest.quarantine import DIRECTORY_NAME, FILE_NAME, Quarantine


def test_nothing_is_written_when_no_lines_are_quarantined(tmp_path: Path) -> None:
    """A clean ingest should not litter the case with empty files."""
    with Quarantine(tmp_path) as quarantine:
        assert quarantine.count == 0

    assert not (tmp_path / "quarantine").exists()


def test_a_quarantined_line_is_recorded_with_its_origin(tmp_path: Path) -> None:
    with Quarantine(tmp_path) as quarantine:
        quarantine.record("access.log", 42, "<<< garbage >>>", reason="no format match")

    records = read_records(tmp_path)

    assert records == [
        {
            "source_file_id": "access.log",
            "line_no": 42,
            "reason": "no format match",
            "line": "<<< garbage >>>",
        }
    ]


def test_count_reflects_every_recorded_line(tmp_path: Path) -> None:
    with Quarantine(tmp_path) as quarantine:
        for line_no in range(1, 6):
            quarantine.record("access.log", line_no, "bad", reason="no format match")
        assert quarantine.count == 5


def test_lines_with_undecodable_bytes_are_still_recorded(tmp_path: Path) -> None:
    """The lines most worth quarantining are the malformed ones; serialising
    them must not be what fails."""
    with Quarantine(tmp_path) as quarantine:
        quarantine.record("access.log", 1, "bad \udce9 byte", reason="no format match")

    assert len(read_records(tmp_path)) == 1


def test_records_from_several_sources_share_one_file(tmp_path: Path) -> None:
    with Quarantine(tmp_path) as quarantine:
        quarantine.record("a.log", 1, "x", reason="r")
        quarantine.record("b.log", 2, "y", reason="r")

    assert {r["source_file_id"] for r in read_records(tmp_path)} == {"a.log", "b.log"}


def read_records(case_root: Path) -> list[dict[str, object]]:
    path = case_root / "quarantine" / "unparsed.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line]


def test_workers_write_to_separate_files_that_merge_into_one(tmp_path: Path) -> None:
    """Parallel ingest runs several quarantines over one case. Appending to a
    shared file from several processes is not guaranteed atomic on Windows, and
    a torn write would corrupt the record of exactly the lines that were already
    too damaged to parse.
    """
    first = Quarantine(tmp_path, shard="w0")
    second = Quarantine(tmp_path, shard="w1")

    first.record("access.log", 1, "broken one", reason="unparseable")
    second.record("access.log", 900, "broken two", reason="unparseable")
    first.close()
    second.close()

    assert first.path != second.path
    merged = Quarantine.merge(tmp_path)

    assert merged == 2
    lines = (tmp_path / DIRECTORY_NAME / FILE_NAME).read_text(encoding="utf-8").splitlines()
    assert {json.loads(line)["line_no"] for line in lines} == {1, 900}
    # The per-worker parts are cleaned up; two records of the same lines in the
    # same directory would double every count read back from it.
    assert not list((tmp_path / DIRECTORY_NAME).glob("unparsed-*.jsonl"))


def test_merging_a_clean_ingest_leaves_no_artefact(tmp_path: Path) -> None:
    """A case with nothing quarantined must not grow an empty file that reads
    like a problem."""
    assert Quarantine.merge(tmp_path) == 0
    assert not (tmp_path / DIRECTORY_NAME / FILE_NAME).exists()
