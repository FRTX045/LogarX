import pytest

from logarc.case import Case
from logarc.core.activity import ActivityCategory
from logarc.evaluation.truth import TruthRecord, TruthWriter


def fixture_case(tmp_path, categories=(ActivityCategory.BROWSING,)):
    source = tmp_path / "access.log"
    source.write_text(
        '192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n'
        * len(categories)
    )
    truth = tmp_path / "truth.jsonl"
    with TruthWriter(truth, scenario="fixture", seed=1, source_file_id="access.log") as writer:
        for line, category in enumerate(categories, 1):
            writer.write(TruthRecord(line, "192.0.2.1", category, "visit"))
    with Case.create(tmp_path / "case") as case:
        case.ingest([source])
        case.finalize()
        case.manifest.config.update(
            crs_paranoia_level=2, crs_revision="fixture", crs_fingerprint="fixture"
        )
        case.manifest.save(case.root)
        (case.root / "crs.jsonl").write_text("")
    return case.root, source, truth


def test_case_evaluation_verifies_sources_and_keeps_no_attack_recall_undefined(tmp_path):
    from logarc.evaluation.triage_study import evaluate_case

    case, source, truth = fixture_case(tmp_path)
    result = evaluate_case(case, source, truth, include_model=False)
    assert result["identity"]["crs_paranoia_level"] == 2
    assert result["identity"]["truth_sha256"]
    assert (
        result["report"]["comparisons"]["operational"]["suspicious"]["requests"]["maximum_recall"]
        is None
    )
    source.write_text(source.read_text() + "changed\n")
    with pytest.raises(ValueError, match="hash"):
        evaluate_case(case, source, truth, include_model=False)


def test_wrong_truth_ip_cannot_be_scored_against_a_case(tmp_path):
    from logarc.evaluation.triage_study import evaluate_case

    case, source, truth = fixture_case(tmp_path)
    truth.write_text(truth.read_text().replace("192.0.2.1", "192.0.2.9"))
    with pytest.raises(ValueError, match=r"truth.*line"):
        evaluate_case(case, source, truth, include_model=False)


def test_unknown_truth_excludes_whole_client_explicitly_instead_of_assuming_benign(tmp_path):
    from logarc.evaluation.triage_study import evaluate_case

    case, source, truth = fixture_case(tmp_path)
    truth.write_text(truth.read_text().replace('"browsing"', '"unknown"'))
    result = evaluate_case(case, source, truth, include_model=False)
    assert result["judgment_exclusions"] == {"192.0.2.1": "unknown request ground truth"}
    assert result["observed_clients"] == 1
    assert (
        result["report"]["comparisons"]["operational"]["suspicious"]["requests"]["population"] == 0
    )


def test_challenger_selection_uses_development_yield_then_declared_ties():
    from logarc.evaluation.priorities import choose_challenger

    metrics = {"yield10": 0.7, "yield25": 0.7, "yield50": 0.6, "quiet50": 0.2, "hits10": 7}
    cases = {"development": dict.fromkeys(("support", "weighted", "share"), metrics)}
    assert choose_challenger(cases) == "support"
    cases["development"]["weighted"] = {**metrics, "yield50": 0.8}
    assert choose_challenger(cases) == "weighted"


def test_explicit_hostile_truth_keeps_mixed_unknown_client_in_attack_recall(tmp_path):
    from logarc.evaluation.triage_study import evaluate_case

    hostile = next(category for category in ActivityCategory if category.is_hostile)
    case, source, truth = fixture_case(tmp_path, (hostile, ActivityCategory.UNKNOWN))
    result = evaluate_case(case, source, truth, include_model=False)
    assert not result["judgment_exclusions"]
    assert (
        result["report"]["comparisons"]["operational"]["suspicious"]["requests"]["positives"] == 1
    )
