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


def graded_fixture(tmp_path):
    """Three clients: a targeted one, a scanner that only probes, and a benign one whose
    search box matched an injection rule. Truth says which is which, line by line."""
    line = '{ip} - - [01/Jan/2026:00:00:{s:02d} +0000] "GET {path} HTTP/1.1" 200 10 "-" "{ua}"\n'
    rows = [
        ("192.0.2.10", "/", "Mozilla/5.0", ActivityCategory.BROWSING),
        (
            "192.0.2.10",
            "/?id=1%20UNION%20SELECT%20password%20FROM%20users",
            "Mozilla/5.0",
            ActivityCategory.INJECTION,
        ),
        ("192.0.2.20", "/", "sqlmap/1.7", ActivityCategory.RECONNAISSANCE),
        ("192.0.2.30", "/", "Mozilla/5.0", ActivityCategory.BROWSING),
        (
            "192.0.2.30",
            "/?q=1%20UNION%20SELECT%20name%20FROM%20products",
            "Mozilla/5.0",
            ActivityCategory.BROWSING,
        ),
    ]
    source = tmp_path / "access.log"
    source.write_text(
        "".join(
            line.format(ip=ip, s=i, path=path, ua=ua) for i, (ip, path, ua, _) in enumerate(rows)
        )
    )
    truth = tmp_path / "truth.jsonl"
    with TruthWriter(truth, scenario="fixture", seed=1, source_file_id="access.log") as writer:
        for number, (ip, _, _, category) in enumerate(rows, 1):
            writer.write(TruthRecord(number, ip, category, f"{ip}#1"))
    with Case.create(tmp_path / "case") as case:
        case.ingest([source])
        case.finalize()
        case.manifest.config.update(
            crs_paranoia_level=2, crs_revision="fixture", crs_fingerprint="fixture"
        )
        case.manifest.save(case.root)
        (case.root / "crs.jsonl").write_text("")
    return case.root, source, truth


def test_graded_study_grades_clients_from_truth_and_scores_every_method(tmp_path):
    from logarc.evaluation.graded import load_scores
    from logarc.evaluation.triage_study import evaluate_graded_case

    result = evaluate_graded_case(*graded_fixture(tmp_path))
    assert result["identity"]["crs_paranoia_level"] == 2
    assert result["low_support"] == ["192.0.2.10"]
    (targeted,) = result["targeted"]
    assert (targeted["ip"], targeted["grade"], targeted["hostile"], targeted["requests"]) == (
        "192.0.2.10",
        2,
        1,
        2,
    )
    assert set(targeted["ranks"]) == {"policy3", "c1", "c2"}
    scores = {name: load_scores(data) for name, data in result["methods"].items()}
    assert scores["policy3"].judged == 3
    assert scores["policy3"].targeted == 1
    assert scores["policy3"].yield_at[10] == pytest.approx(1 / 3)
    head = result["head"]["192.0.2.10"]
    assert {"base", "D", "Q", "R", "grade", "ranks"} <= set(head)
    assert [row["ip"] for row in result["benign_head"]] == ["192.0.2.30"]
    assert result["benign_head"][0]["reasons"]


def test_the_audit_flags_high_confidence_rules_that_matched_benign_truth(tmp_path):
    from logarc.evaluation.triage_study import evaluate_graded_case

    audit = evaluate_graded_case(*graded_fixture(tmp_path))["audit"]
    flagged = {rule for rule, row in audit["rules"].items() if row["flagged"]}
    assert flagged
    for rule in flagged:
        assert audit["rules"][rule]["benign_lines"] >= 1
    injection = [row for row in audit["rules"].values() if row["hostile_lines"] >= 1]
    assert injection
    assert audit["low_support_with_match"] == ["192.0.2.10"]
    assert audit["low_support_without_match"] == []


def test_exploit_study_counts_a_client_placed_by_crs_level_one_evidence(tmp_path):
    """The sqlmap client has no native exploit evidence; a level 1 detection places it first."""
    import json

    from logarc.evaluation.triage_study import evaluate_exploit_case

    root, source, truth = graded_fixture(tmp_path)
    detection = {
        "source_file_id": "access.log",
        "line_no": 3,
        "rule_id": 942100,
        "severity": "critical",
        "msg": "SQL Injection Attack Detected via libinjection",
        "matched_var": "ARGS:q",
        "transformed_value": "1 union select",
        "attack_family": "attack-sqli",
        "paranoia_level": 1,
    }
    (root / "crs.jsonl").write_text(json.dumps(detection) + "\n", encoding="utf-8")
    result = evaluate_exploit_case(root, source, truth)
    assert "192.0.2.20" in result["first_group"]["app"]
    assert result["first_group"]["exploit_first"] == result["first_group"]["app"]
    assert result["app_equals_exploit_first"] is True
    assert result["crs_only_first"] == ["192.0.2.20"]


def test_exploit_study_reports_orderings_identity_and_the_pre_exclusion_queue(tmp_path):
    from logarc.evaluation.triage_study import evaluate_exploit_case

    result = evaluate_exploit_case(*graded_fixture(tmp_path))
    assert {
        "identity",
        "judged",
        "judgment_exclusions",
        "methods",
        "first_group",
        "app_equals_exploit_first",
        "orderings_share_members",
        "queue",
        "crs_only_first",
        "targeted",
    } <= set(result)
    assert result["identity"]["policy_version"] == 5
    assert result["app_equals_exploit_first"] is True
    assert result["crs_only_first"] == []
    assert set(result["methods"]) == {"policy3", "exploit_first", "category_only"}
    assert set(result["first_group"]) == {"policy3", "exploit_first", "category_only", "app"}
    assert {"members", "policy3", "app"} <= set(result["queue"])
    (targeted,) = result["targeted"]
    assert targeted["ip"] == "192.0.2.10"
    assert set(targeted["ranks"]) == {"policy3", "exploit_first", "category_only", "app"}
    assert targeted["exploit_rules"]


def test_a_stopped_crs_run_is_not_a_complete_product_evaluation(tmp_path):
    from logarc.evaluation.triage_study import evaluate_case

    case, source, truth = fixture_case(tmp_path)
    with Case.open(case) as opened:
        opened.manifest.config.update(crs_replayed=0, crs_requests=1, crs_complete=False)
        opened.manifest.save(opened.root)

    with pytest.raises(ValueError, match="finished"):
        evaluate_case(case, source, truth, include_model=False)
