from triage_scenario import write_workload

from logarx.case import Case
from logarx.triage.scan import read_profiles, scan_case


def test_mixed_source_roles_include_missing_fields_without_relabeling_them_as_anomalies(tmp_path):
    source, roles, attacks, unusual = write_workload(tmp_path, "mixed")
    with Case.create(tmp_path / "case") as case:
        result = case.ingest([source])[0]
        case.finalize()
        assert result.events_parsed == len(source.read_text().splitlines())
    profiles = read_profiles(scan_case(case.root).path)
    assert len(profiles) == 132
    assert sum(unusual.values()) == 2
    assert not any(attacks.values())
    for profile in profiles:
        if roles[profile.client_ip] == "missing-fields":
            assert profile.coverage["status"] == profile.coverage["path"] == 0
            assert not unusual[profile.client_ip]


def test_attack_heavy_truth_is_independent_of_unusual_roles_and_uniform_has_no_positives(tmp_path):
    _, _, attacks, unusual = write_workload(tmp_path / "attack", "attack-heavy")
    assert sum(attacks.values()) == 90
    assert sum(unusual.values()) == 2
    assert not any(attacks[ip] and unusual[ip] for ip in attacks)
    _, _, attacks, unusual = write_workload(tmp_path / "uniform", "uniform")
    assert not any(attacks.values()) and not any(unusual.values())
