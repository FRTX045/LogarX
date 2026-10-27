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
import os
from pathlib import Path
from typing import Any

import pytest

from logarx.case import Case
from logarx.detect.crs import SidecarConfig
from logarx.enrich import enrich_case
from logarx.evaluation.scoring import evaluate as score_case
from logarx.evaluation.truth import read_truth

DATA = Path(__file__).resolve().parents[1] / "data" / "apache-shopfront"
LOG = DATA / "excerpt.log"
TRUTH = DATA / "excerpt.truth.jsonl"
PUBLISHED = DATA / "excerpt.scores.json"

REGENERATE = (
    "logarx-dev ingest tests/data/apache-shopfront/excerpt.log --case <tmp> --no-crs && "
    "logarx-dev evaluate -c <tmp> -t tests/data/apache-shopfront/excerpt.truth.jsonl "
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


# -- the same excerpt, scored with CRS on ------------------------------------
#
# Added 2026-09-22. Until then every committed figure in this project was the
# native rules alone, and CRS appeared only as a second column in prose that
# nothing checked. A layer nobody measures is a layer that drifts.
#
# It is a *second* fixture rather than a replacement, because the two answer
# different questions and both are worth failing a build over. Since 2026-10-05
# this one is what a case scores by default, CRS running after every scan; the
# native one is what the rules packed here manage alone, which is still what a
# case scores wherever the sidecar is absent or turned off.
#
# Both hints ingest with `--no-crs` for that reason. The native fixture must not
# be scored from an enriched case, and the CRS one enriches in its own step so
# that a missing sidecar fails loudly there rather than as a notice.

CRS_PUBLISHED = DATA / "excerpt.scores.crs.json"

CRS_REGENERATE = (
    "logarx-dev ingest tests/data/apache-shopfront/excerpt.log --case <tmp> --no-crs && "
    "logarx-dev enrich --case <tmp> && "
    "logarx-dev evaluate -c <tmp> -t tests/data/apache-shopfront/excerpt.truth.jsonl "
    "-o tests/data/apache-shopfront/excerpt.scores.crs.json"
)


def test_the_crs_run_records_which_crs_produced_it() -> None:
    """**Provenance, and the reason this fixture could not just be committed.**

    `ruleset_fingerprint` has always answered "which rules produced this". With
    CRS in the picture a second thing produced it, and the first version of this
    fixture carried no trace of which. A CRS version bump would have moved every
    number here with nothing in the file saying why — the same failure the
    native fixture exists to prevent, one layer over.
    """
    published = json.loads(CRS_PUBLISHED.read_text(encoding="utf-8"))

    assert published.get("crs_fingerprint"), (
        f"the CRS-enriched scores name no CRS version.\n\nRegenerate with:\n  {CRS_REGENERATE}"
    )
    assert published["ruleset_fingerprint"], "and the native rules are still half of it"


def test_the_native_run_names_no_crs_at_all() -> None:
    """The other half of the same claim. A case nobody enriched has to say so,
    rather than leave a reader guessing whether CRS was on."""
    published = json.loads(PUBLISHED.read_text(encoding="utf-8"))

    assert published.get("crs_fingerprint") is None


#: Skipped where the Go sidecar is not built, which is most checkouts, and
#: required in CI — the same condition `tests/detect/crs/test_contract.py`
#: reads, written the same way so the two cannot drift apart.
_crs_unbuilt = not SidecarConfig().binary.exists() or not (SidecarConfig().rules / "rules").is_dir()
crs_needed = pytest.mark.skipif(
    _crs_unbuilt and os.environ.get("LOGARX_REQUIRE_CRS") != "1",
    reason="CRS sidecar or ruleset not built; see crs/README.md",
)


@pytest.fixture(scope="module")
def measured_with_crs(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Score the committed excerpt with CRS on, exactly as the command line would."""
    root = tmp_path_factory.mktemp("published-scores-crs")
    with Case.create(root / "case") as case:
        case.ingest([LOG])
        case.finalize()
    enrich_case(root / "case")
    with Case.open(root / "case") as case:
        evidence = case.crs_evidence()
        report = score_case(
            case.store,
            read_truth(TRUTH),
            engine=case.rule_engine(),
            crs=evidence.index,
            crs_fingerprint=evidence.fingerprint,
        )
    return json.loads(json.dumps(report.to_dict()))


@crs_needed
def test_the_committed_crs_scores_are_what_the_tool_produces_today(
    measured_with_crs: dict,
) -> None:
    """**The gate this project did not have.**

    Every committed figure here used to be the native rules alone. CRS existed
    as a second column in prose that nothing checked, so a CRS version bump, a
    mapping change or a rule that started firing on ordinary traffic could move
    what a user sees and fail no build.

    On this corpus CRS is a small gain — two more attacks caught, no extra false
    alarms, macro F1 0.786 to 0.796. That is not the whole story and this test
    does not pretend it is: the excerpt has too little ordinary traffic to show
    what CRS costs, and the larger corpus this project scores against measured
    1 false alarm native against 96 with CRS on. What this fixture guarantees is
    narrower and still worth having — that the figure cannot move without
    somebody saying so.
    """
    published = json.loads(CRS_PUBLISHED.read_text(encoding="utf-8"))

    assert not _differences(measured_with_crs, published), (
        "The CRS-enriched evaluation no longer produces the committed scores.\n\n"
        "A moved `crs_fingerprint` means the dependency changed and the figures "
        "quoted for CRS are stale. A moved score with the same fingerprint means "
        "this project changed what it does with CRS's findings.\n\n"
        f"Regenerate with:\n  {CRS_REGENERATE}\n\nWhat moved:\n  "
        + "\n  ".join(_differences(measured_with_crs, published))
    )


@crs_needed
def test_turning_crs_on_does_not_cost_precision_here(measured_with_crs: dict) -> None:
    """The one claim worth asserting rather than merely recording.

    Recall may rise when a second ruleset joins; precision on traffic the native
    rules already read correctly must not fall. That is the guard ADR-0008 put
    on the whole integration, and on this corpus it holds exactly — the native
    run and the CRS run both report zero false alarms.
    """
    native = json.loads(PUBLISHED.read_text(encoding="utf-8"))

    assert measured_with_crs["binary"]["false_positives"] <= native["binary"]["false_positives"]
    assert measured_with_crs["binary"]["true_positives"] >= native["binary"]["true_positives"]
