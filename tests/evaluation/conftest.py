"""The excerpt, ingested once per module: ingest is the slow part of scoring."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from logarc.case import Case
from logarc.evaluation.truth import GroundTruth, read_truth

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
