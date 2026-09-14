"""The published numbers, checked against the tool that produced them.

`docs/evaluation.md` and the README print figures that nobody could re-derive:
neither dataset build is committed, no evaluation output was, and the prose
tables were the only surviving record. That is how the last drift happened —
the episode builder changed on 25 August, nobody re-ran the evaluation, and a
boundary recall of 0.98 stayed published for weeks while the tool scored 0.27.

This closes that gap for the one corpus a fresh clone already has. The excerpt
and its truth are committed, so the whole chain is reproducible here: ingest,
evaluate, compare against the scores committed beside them.

The comparison covers the whole file, and every value in it except that floats
are compared to a tolerance. Every rule change fails this test and has to say
so out loud by updating the fixture — which is the gate that was missing, not
an inconvenience to be softened. Nothing here varies between runs: the
`*_seconds` fields are policy thresholds rather than measurements, and there
are no timestamps or durations in the output at all.

The tolerance is there because the first CI run of this test failed on Python
3.11 while passing on 3.12, and the entire difference was
`weighted_f1 = 0.9339779315899172` against `...174` — one unit in the last
place of a float, from summation arithmetic rather than from anything the tool
decided. `1e-9` is far tighter than any rule change could hide in: the smallest
real movement this suite has produced was 0.006, six million times larger.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from logarc.case import Case
from logarc.evaluation.scoring import evaluate as score_case
from logarc.evaluation.truth import read_truth

DATA = Path(__file__).resolve().parents[1] / "data" / "apache-shopfront"
LOG = DATA / "excerpt.log"
TRUTH = DATA / "excerpt.truth.jsonl"
PUBLISHED = DATA / "excerpt.scores.json"

REGENERATE = (
    "logarc ingest tests/data/apache-shopfront/excerpt.log --case <tmp> && "
    "logarc evaluate -c <tmp> -t tests/data/apache-shopfront/excerpt.truth.jsonl "
    "-o tests/data/apache-shopfront/excerpt.scores.json"
)


@pytest.fixture(scope="module")
def measured(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Score the committed excerpt exactly as the command line would."""
    root = tmp_path_factory.mktemp("published-scores")
    with Case.create(root / "case") as case:
        case.ingest([LOG])
        case.finalize()
    with Case.open(root / "case") as case:
        report = score_case(case.store, read_truth(TRUTH))
    return json.loads(json.dumps(report.to_dict()))


#: Tight enough that no rule change hides under it, loose enough that a float's
#: last bit does not fail a build. See the module docstring.
TOLERANCE = 1e-9


def _differences(measured: Any, published: Any, path: str = "") -> list[str]:
    """Every place the two disagree, floats to a tolerance and the rest exactly."""
    if isinstance(measured, float) or isinstance(published, float):
        if not isinstance(measured, int | float) or not isinstance(published, int | float):
            return [f"{path}: {measured!r} vs {published!r}"]
        if math.isclose(measured, published, rel_tol=TOLERANCE, abs_tol=TOLERANCE):
            return []
        return [f"{path}: {measured!r} vs {published!r}"]

    if isinstance(measured, dict) and isinstance(published, dict):
        found = []
        for key in sorted(set(measured) | set(published)):
            if key not in measured or key not in published:
                found.append(
                    f"{path}.{key}: only in {'measured' if key in measured else 'published'}"
                )
            else:
                found += _differences(measured[key], published[key], f"{path}.{key}")
        return found

    if isinstance(measured, list) and isinstance(published, list):
        if len(measured) != len(published):
            return [f"{path}: {len(measured)} entries vs {len(published)}"]
        found = []
        for index, (a, b) in enumerate(zip(measured, published, strict=True)):
            found += _differences(a, b, f"{path}[{index}]")
        return found

    return [] if measured == published else [f"{path}: {measured!r} vs {published!r}"]


def test_the_committed_scores_are_what_the_tool_produces_today(measured: dict) -> None:
    """The whole point: a number in the documentation that the code no longer
    produces should fail a build, not survive one."""
    published = json.loads(PUBLISHED.read_text(encoding="utf-8"))

    assert not _differences(measured, published), (
        "The evaluation no longer produces the committed scores.\n\n"
        "If a rule or a threshold changed, this is the test doing its job — the "
        "figures in docs/evaluation.md and the README are now stale too, and "
        "both need re-reading before the fixture is replaced.\n\n"
        f"Regenerate with:\n  {REGENERATE}\n\nWhat moved:\n  "
        + "\n  ".join(_differences(measured, published))
    )


def test_the_ruleset_fingerprint_is_recorded_with_the_scores(measured: dict) -> None:
    """Without it the numbers say what was scored and not what scored them,
    which is how two different rulesets come to share one published figure."""
    assert measured["ruleset_fingerprint"]
    assert measured["totals"]["lines_missing"] == 0, "every line of the excerpt was scored"
