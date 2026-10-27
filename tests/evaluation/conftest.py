"""The excerpt, ingested once per module: ingest is the slow part of scoring."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from logarx.case import Case
from logarx.evaluation.truth import GroundTruth, read_truth

# Evaluation tests reuse the profile helpers in tests/triage.
sys.path.insert(0, str(Path(__file__).parent.parent / "triage"))

EXCERPT = Path(__file__).parent.parent / "data" / "apache-shopfront"


@pytest.fixture(scope="module")
def excerpt_case(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Case]:
    case_dir = tmp_path_factory.mktemp("excerpt") / "case"
    with Case.create(case_dir) as case:
        case.ingest([EXCERPT / "excerpt.log"])
    with Case.open(case_dir) as case:
        yield case


@pytest.fixture(scope="module")
def excerpt_truth() -> GroundTruth:
    return read_truth(EXCERPT / "excerpt.truth.jsonl")
