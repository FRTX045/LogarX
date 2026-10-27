from dataclasses import replace

import pytest

from logarx.core.evidence import EvidenceRef
from logarx.triage.profile import ClientProfile


def population():
    rows = []
    for index in range(100):
        value = 20 + index % 5
        rows.append(
            ClientProfile(
                f"192.0.2.{index}",
                value,
                0,
                (),
                0,
                0,
                {"requests": float(value), "peak_per_minute": float(value), "4xx_share": 0.0},
                {"path": value, "status": value, "bytes_sent": 0},
                {"requests": (EvidenceRef("source", index + 1),)},
            )
        )
    rows[-1] = replace(
        rows[-1],
        requests=10000,
        features={
            "requests": 10000.0,
            "peak_per_minute": 10000.0,
            "4xx_share": 1.0,
        },
        coverage={"path": 10000, "status": 10000, "bytes_sent": 0},
    )
    return rows


def test_budget_metrics_do_not_invent_recall_for_no_positives():
    from logarx.evaluation.triage import budget_scores

    scores = budget_scores(["a", "b", "c"], {"a": True, "b": False, "c": True}, budgets=(1, 2, 10))
    assert scores[0].precision == 1
    assert scores[0].recall == 0.5
    assert scores[1].precision == 0.5
    assert scores[2].reviewed == 3
    assert scores[2].precision == 2 / 3
    assert budget_scores(["a"], {"a": False})[0].recall is None
    assert budget_scores([], {"a": True})[0].precision is None


def test_short_queue_yield_uses_available_slots_not_returned_count():
    from logarx.evaluation.triage import budget_scores

    scores = budget_scores(["a"], {"a": True, "b": False, "c": True}, budgets=(2, 10))
    assert scores[0].precision == 1
    assert scores[0].yield_per_slot == 0.5
    assert scores[1].yield_per_slot == 1 / 3


def test_unjudged_clients_are_not_silently_counted_as_benign():
    from logarx.evaluation.triage import budget_scores

    with pytest.raises(ValueError, match="judgment"):
        budget_scores(["a", "b"], {"a": True})


def test_model_is_reproducible_and_excludes_identity_and_labels():
    pytest.importorskip("sklearn")
    from logarx.evaluation.triage import isolation_order

    profiles = population()
    first = isolation_order(profiles)
    assert first.status == "complete"
    assert first.order[0] == "192.0.2.99"
    assert first.scores == tuple(sorted(first.scores))
    modified = [
        replace(p, severity=4, categories=("injection",), hostile_requests=10) for p in profiles
    ]
    assert isolation_order(modified).scores == first.scores
    renamed = [replace(p, client_ip="renamed-" + p.client_ip) for p in profiles]
    assert isolation_order(renamed).scores == first.scores
    assert isolation_order(profiles).order == first.order
    assert first.metadata["random_state"] == 42
    assert first.metadata["features"]
    assert "sklearn_version" in first.metadata


def test_model_reports_insufficient_population_without_importing_sklearn():
    from logarx.evaluation.triage import isolation_order

    result = isolation_order(population()[:99])
    assert result.status == "insufficient population"
    assert result.order == ()


def test_comparison_keeps_security_and_unusual_judgments_separate():
    from logarx.evaluation.triage import compare_rankings

    profiles = population()
    suspicious = {p.client_ip: False for p in profiles}
    unusual = {p.client_ip: p.client_ip == "192.0.2.99" for p in profiles}
    result = compare_rankings(
        profiles,
        suspicious=suspicious,
        unusual=unusual,
        include_model=False,
        provenance={"suspicious": "no attacks in fixture", "unusual": "planted volume outlier"},
    )
    operational = result.comparisons["operational"]
    assert operational["suspicious"]["requests"].budgets[0].recall is None
    assert operational["unusual"]["statistics"].budgets[0].recall == 1
    assert result.provenance["unusual"] == "planted volume outlier"


def test_population_accounting_exposes_excluded_quiet_attacks_and_missing_statuses():
    from logarx.evaluation.triage import compare_rankings

    profiles = population()
    quiet = replace(profiles[0], requests=1, hostile_requests=1, severity=4)
    sparse = replace(profiles[1], coverage={"status": 1, "path": 20, "bytes_sent": 0})
    profiles[:2] = [quiet, sparse]
    truth = {
        p.client_ip: p.client_ip in {quiet.client_ip, profiles[-1].client_ip} for p in profiles
    }
    report = compare_rankings(
        profiles,
        suspicious=truth,
        include_model=False,
        provenance={"suspicious": "explicit fixture roles"},
    )
    operational = report.comparisons["operational"]["suspicious"]
    stats = operational["statistics"]
    assert stats.population == 100
    assert stats.positives == 2
    assert stats.eligible == 99
    assert stats.excluded_positives == 1
    assert stats.maximum_recall == 0.5
    assert operational["suspicious"].quiet_positives == 1
    assert operational["suspicious"].quiet_recall_at_50 == 1
    matched = report.comparisons["matched"]["suspicious"]
    assert matched["requests"].population == 98
    assert matched["requests"].positives == 1
    assert matched["errors"].eligible == 98
    assert matched["requests"].base_rate == 1 / 98


def test_model_seed_is_explicit_and_recorded():
    pytest.importorskip("sklearn")
    from logarx.evaluation.triage import isolation_order

    result = isolation_order(population(), random_state=7)
    assert result.metadata["random_state"] == 7
    assert result == isolation_order(population(), random_state=7)


def test_insufficient_statistics_are_unavailable_but_uniform_comparisons_are_complete():
    from logarx.evaluation.triage import compare_rankings

    def score(profiles):
        return compare_rankings(
            profiles,
            suspicious={p.client_ip: True for p in profiles},
            include_model=False,
            provenance={"suspicious": "fixture"},
        ).comparisons["operational"]["suspicious"]["statistics"]

    assert score(population()[:1]).status == "insufficient population"
    assert score(population()[:1]).budgets == ()
    uniform = [replace(population()[0], client_ip=str(i)) for i in range(100)]
    assert score(uniform).status == "complete"
    assert score(uniform).budgets[0].relevant == 0
