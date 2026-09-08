"""The committed excerpt is the excerpt the numbers were measured on.

The evaluation figures in docs/evaluation.md are tied to bytes, not to a seed.
This checks the small piece of those bytes that lives in the repository.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from logarc.core.activity import ActivityCategory
from logarc.evaluation.truth import read_truth

EXCERPT = Path(__file__).parent.parent / "data" / "apache-shopfront"


def test_the_fixture_matches_its_recorded_checksums() -> None:
    recorded = dict(
        line.split()[::-1]
        for line in (EXCERPT / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        if line.strip()
    )

    assert set(recorded) == {"excerpt.log", "excerpt.truth.jsonl"}
    for name, digest in recorded.items():
        assert hashlib.sha256((EXCERPT / name).read_bytes()).hexdigest() == digest, name


def test_the_truth_describes_the_log_line_for_line() -> None:
    log_lines = (EXCERPT / "excerpt.log").read_bytes().split(b"\n")
    if log_lines[-1] == b"":
        log_lines.pop()
    truth = read_truth(EXCERPT / "excerpt.truth.jsonl")

    assert truth.scenario == "apache-shopfront-medium-excerpt"
    assert truth.line_count == len(log_lines)
    assert [record.line_no for record in truth.records] == list(range(1, len(log_lines) + 1))
    for record, line in zip(truth.records, log_lines, strict=True):
        assert line.split(b" ", 1)[0] == record.client_ip.encode()


def test_the_fixture_has_support_for_every_hostile_category() -> None:
    truth = read_truth(EXCERPT / "excerpt.truth.jsonl")
    present = {record.category for record in truth.records}

    assert {category for category in present if category.is_hostile} == {
        category for category in ActivityCategory if category.is_hostile
    }
