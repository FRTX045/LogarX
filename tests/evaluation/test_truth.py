"""The ground-truth sidecar: what the generator claims it wrote."""

from __future__ import annotations

from pathlib import Path

import pytest

from logarc.core.activity import ActivityCategory
from logarc.evaluation.truth import (
    TruthError,
    TruthRecord,
    TruthWriter,
    read_truth,
)


def record(line_no: int, category: ActivityCategory, instance: str) -> TruthRecord:
    return TruthRecord(
        line_no=line_no,
        client_ip="203.0.113.9",
        category=category,
        instance_id=instance,
    )


def test_records_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "sample.truth.jsonl"
    with TruthWriter(path, scenario="mixed", seed=7, source_file_id="sample.log") as writer:
        writer.write(record(1, ActivityCategory.BROWSING, "a#0"))
        writer.write(record(2, ActivityCategory.INJECTION, "a#1"))

    truth = read_truth(path)

    assert truth.scenario == "mixed"
    assert truth.seed == 7
    assert truth.source_file_id == "sample.log"
    assert truth.records == (
        record(1, ActivityCategory.BROWSING, "a#0"),
        record(2, ActivityCategory.INJECTION, "a#1"),
    )


def test_line_count_is_derived_rather_than_declared(tmp_path: Path) -> None:
    """The header is written before the body, so it cannot state a total.

    Deriving it means the count can never disagree with the records present.
    """
    path = tmp_path / "t.jsonl"
    with TruthWriter(path, scenario="s", seed=1, source_file_id="a.log") as writer:
        for line_no in range(1, 6):
            writer.write(record(line_no, ActivityCategory.BROWSING, "a#0"))

    assert read_truth(path).line_count == 5


def test_records_are_grouped_by_client(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    with TruthWriter(path, scenario="s", seed=1, source_file_id="a.log") as writer:
        writer.write(TruthRecord(1, "10.0.0.1", ActivityCategory.BROWSING, "a#0"))
        writer.write(TruthRecord(2, "10.0.0.2", ActivityCategory.INJECTION, "b#0"))
        writer.write(TruthRecord(3, "10.0.0.1", ActivityCategory.BROWSING, "a#0"))

    by_client = read_truth(path).by_client()

    assert sorted(by_client) == ["10.0.0.1", "10.0.0.2"]
    assert [item.line_no for item in by_client["10.0.0.1"]] == [1, 3]


def test_the_header_comes_first_so_the_body_can_stream(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    with TruthWriter(path, scenario="s", seed=1, source_file_id="a.log") as writer:
        writer.write(record(1, ActivityCategory.BROWSING, "a#0"))

    first = path.read_text(encoding="utf-8").splitlines()[0]
    assert '"kind": "logarc-truth"' in first


def test_reading_a_file_that_is_not_truth_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "not-truth.jsonl"
    path.write_text('{"hello": "world"}\n', encoding="utf-8")

    with pytest.raises(TruthError, match="not a logarc ground-truth file"):
        read_truth(path)


def test_reading_a_future_version_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_text('{"kind": "logarc-truth", "version": 99}\n', encoding="utf-8")

    with pytest.raises(TruthError, match="version 99"):
        read_truth(path)


def test_reading_an_empty_file_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")

    with pytest.raises(TruthError, match="empty"):
        read_truth(path)


def test_an_unknown_category_names_the_offending_line(tmp_path: Path) -> None:
    """A truth file edited by hand should fail loudly, pointing at the record."""
    path = tmp_path / "t.jsonl"
    path.write_text(
        '{"kind": "logarc-truth", "version": 1, "scenario": "s", "seed": 1,'
        ' "source_file_id": "a.log", "generated_at": "2024-01-01T00:00:00+00:00"}\n'
        '{"line_no": 1, "client_ip": "10.0.0.1", "category": "nonsense", "instance_id": "a#0"}\n',
        encoding="utf-8",
    )

    with pytest.raises(TruthError, match="line 2"):
        read_truth(path)
