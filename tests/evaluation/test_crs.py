"""Scoring the rules against a corpus this project did not write.

The fixtures build a miniature coreruleset clone in `tmp_path`. Nothing here
touches a real clone: the tests are about how cases are read and sorted, and a
corpus that has to be downloaded first is a test that does not run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
import yaml

from logarc.core.activity import ActivityCategory
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules
from logarc.detect.rules import SignatureRule, load_rules
from logarc.evaluation.crs import (
    CrsError,
    ExclusionReason,
    load_crs_corpus,
    score_crs,
)

if TYPE_CHECKING:
    from pathlib import Path

#: What CRS sends when it is not testing the agent string. A case without it
#: would trip `absent_user_agent`, which would make every fixture a detection.
AGENT = "OWASP CRS test agent"

SQLI_DIR = "REQUEST-942-APPLICATION-ATTACK-SQLI"
LFI_DIR = "REQUEST-930-APPLICATION-ATTACK-LFI"


def stage(
    *,
    uri: str = "/get",
    method: str = "GET",
    data: str | None = None,
    headers: dict[str, str] | None = None,
    expect: bool = True,
    assertion: bool = True,
) -> dict[str, Any]:
    """One CRS test stage, in the shape the corpus writes them."""
    request: dict[str, Any] = {
        "dest_addr": "127.0.0.1",
        "method": method,
        "port": 80,
        "uri": uri,
        "version": "HTTP/1.1",
        "headers": {"Host": "localhost", "User-Agent": AGENT, **(headers or {})},
    }
    if data is not None:
        request["data"] = data

    log: dict[str, Any] = {}
    if assertion:
        log["expect_ids" if expect else "no_expect_ids"] = [942100]
    else:
        log["match_regex"] = 'id "942100"'
    return {"input": request, "output": {"log": log}}


def write_case(
    clone: Path,
    *,
    directory: str = SQLI_DIR,
    filename: str = "942100.yaml",
    rule_id: int = 942100,
    stages: list[dict[str, Any]],
    desc: str = "Simple SQL Injection",
) -> Path:
    """Write one case file into a miniature clone, creating it if needed."""
    root = clone / "tests" / "regression" / "tests" / directory
    root.mkdir(parents=True, exist_ok=True)
    path = root / filename
    path.write_text(
        yaml.safe_dump(
            {
                "meta": {"author": "test"},
                "rule_id": rule_id,
                "tests": [
                    {"test_id": number, "desc": desc, "stages": [item]}
                    for number, item in enumerate(stages, start=1)
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def clone(tmp_path: Path) -> Path:
    return tmp_path / "coreruleset"


def test_a_payload_in_the_query_string_is_scored(clone: Path) -> None:
    write_case(clone, stages=[stage(uri="/get?id=1' OR '1'='1")])

    report = score_crs(clone=clone)

    assert report.scoreable == 1
    assert report.detected == 1
    assert report.families[0].in_request_line == 1
    assert ActivityCategory.INJECTION in report.families[0].categories


def test_a_payload_in_a_request_body_is_excluded_because_an_access_log_has_none(
    clone: Path,
) -> None:
    write_case(clone, stages=[stage(method="POST", uri="/post", data="var=1234 OR 1=1")])

    corpus = load_crs_corpus(clone=clone)

    assert corpus.scoreable == ()
    assert corpus.by_reason() == {ExclusionReason.BODY_PAYLOAD: 1}


def test_a_payload_in_an_unlogged_header_is_excluded(clone: Path) -> None:
    """A combined log records Referer and User-Agent. It records no other header."""
    write_case(clone, stages=[stage(uri="/get", headers={"Cookie": "x=1' OR '1'='1"})])

    corpus = load_crs_corpus(clone=clone)

    assert corpus.scoreable == ()
    assert corpus.by_reason() == {ExclusionReason.UNLOGGED_HEADER: 1}


def test_a_user_agent_payload_is_scored_because_a_combined_log_records_it(clone: Path) -> None:
    """Excluding these would judge the tool against the common format.

    It ships for combined, parses both fields, and has three rules that match
    only there — so leaving them out would delete the families it is best at.
    """
    write_case(
        clone,
        directory="REQUEST-913-SCANNER-DETECTION",
        filename="913100.yaml",
        rule_id=913100,
        stages=[stage(uri="/get", headers={"User-Agent": "sqlmap/1.7"})],
    )

    report = score_crs(clone=clone, families=["913"])

    assert report.scoreable == 1
    assert report.detected == 1
    assert report.families[0].in_logged_header == 1
    assert report.families[0].in_request_line == 0


def test_a_referer_payload_is_scored_for_the_same_reason(clone: Path) -> None:
    write_case(clone, stages=[stage(uri="/get", headers={"Referer": "http://host/?id=1"})])

    corpus = load_crs_corpus(clone=clone)

    assert len(corpus.scoreable) == 1
    assert corpus.scoreable[0].in_request_line is False


def test_a_case_asserting_that_no_rule_should_fire_is_not_counted_as_a_miss(clone: Path) -> None:
    """These are CRS's own false-positive tests, not attacks to be caught."""
    write_case(
        clone,
        stages=[
            stage(uri="/get?id=1' OR '1'='1"),
            stage(uri="/get?code=firstname.dockery@host.tld", expect=False),
        ],
    )

    report = score_crs(clone=clone)

    assert report.scoreable == 1
    assert report.negatives_scored == 1
    assert report.negatives_fired == 0
    assert report.by_reason()[ExclusionReason.NEGATIVE_ASSERTION] == 1


def test_a_case_with_no_id_assertion_is_counted_as_unscoreable(clone: Path) -> None:
    write_case(clone, stages=[stage(uri="/get?id=1' OR '1'='1", assertion=False)])

    corpus = load_crs_corpus(clone=clone)

    assert corpus.scoreable == ()
    assert corpus.by_reason() == {ExclusionReason.NO_ASSERTION: 1}


def test_every_case_read_is_accounted_for_exactly_once(clone: Path) -> None:
    """The invariant that stops a filter change quietly shrinking the denominator."""
    write_case(
        clone,
        stages=[
            stage(uri="/get?id=1' OR '1'='1"),
            stage(method="POST", uri="/post", data="var=1"),
            stage(uri="/get", headers={"Cookie": "x=1"}),
            stage(uri="/get?id=2", expect=False),
            stage(uri="/get?id=3", assertion=False),
        ],
    )

    corpus = load_crs_corpus(clone=clone)

    assert corpus.total == 5
    assert len(corpus.scoreable) + len(corpus.excluded) == 5
    assert sum(corpus.by_reason().values()) == len(corpus.excluded)
    assert len(corpus.negatives) == corpus.by_reason()[ExclusionReason.NEGATIVE_ASSERTION]
    assert all(item.reason in ExclusionReason for item in corpus.excluded)


def test_the_uri_is_split_so_a_form_encoded_payload_reaches_the_query(clone: Path) -> None:
    """A `+` in a query is a space, and the engine only knows that for a query.

    Handing the whole URI over as a path would reintroduce the defect ADR-0005
    records finding in CSIC, where every form-encoded payload was invisible.
    """
    write_case(clone, stages=[stage(uri="/get?id=1%27+OR+%271%27%3D%271")])

    report = score_crs(clone=clone)

    assert report.detected == 1


def test_window_rules_cannot_fire_because_each_payload_is_labelled_alone(clone: Path) -> None:
    """A corpus of unrelated payloads is not a session, and must not read as one."""
    write_case(
        clone,
        stages=[stage(uri=f"/get?id={number}' OR '1'='1") for number in range(60)],
    )

    report = score_crs(clone=clone)

    signatures = {rule.id for rule in default_rules() if isinstance(rule, SignatureRule)}
    fired = {rule_id for item in report.detections for rule_id in item.rule_ids}
    assert fired
    assert fired <= signatures


def test_a_payload_no_rule_matches_is_a_miss_rather_than_a_benign_label(clone: Path) -> None:
    """Unmatched requests get a synthesised benign label, which is not a detection."""
    write_case(clone, stages=[stage(uri="/get?x=1")])

    report = score_crs(clone=clone)

    assert report.scoreable == 1
    assert report.detected == 0
    assert len(report.misses()) == 1
    assert report.misses()[0].categories == ()


def test_the_detection_rate_ignores_which_category_fired(clone: Path) -> None:
    """No mapping from a CRS family to one of this tool's categories is claimed."""
    write_case(clone, stages=[stage(uri="/get?file=../../../etc/passwd")])

    report = score_crs(clone=clone)

    assert report.detected == 1
    assert ActivityCategory.INJECTION not in report.families[0].categories
    assert ActivityCategory.PATH_TRAVERSAL in report.families[0].categories


def test_families_are_reported_separately(clone: Path) -> None:
    write_case(clone, stages=[stage(uri="/get?id=1' OR '1'='1")])
    write_case(
        clone,
        directory=LFI_DIR,
        filename="930100.yaml",
        rule_id=930100,
        stages=[stage(uri="/get?arg=../../../etc/passwd"), stage(uri="/get?arg=harmless")],
    )

    report = score_crs(clone=clone)

    scores = {item.family: item for item in report.families}
    assert scores["942"].scoreable == 1
    assert scores["930"].scoreable == 2
    assert scores["930"].detected == 1
    assert scores["930"].missed == 1


def test_a_family_with_no_visible_payloads_reports_a_zero_denominator_not_a_crash(
    clone: Path,
) -> None:
    write_case(clone, stages=[stage(method="POST", uri="/post", data="var=1")])

    report = score_crs(clone=clone)

    assert report.families[0].scoreable == 0
    assert report.families[0].detection_rate == 0.0
    assert report.families[0].visible_ratio == 0.0
    assert report.detection_rate == 0.0


def test_the_report_records_what_produced_it(clone: Path) -> None:
    """A rate nobody can re-derive is not a result."""
    write_case(clone, stages=[stage(uri="/get?id=1' OR '1'='1")])

    report = score_crs(clone=clone)

    assert report.ruleset_fingerprint == RuleEngine(default_rules()).fingerprint
    assert report.rule_count == len(default_rules())
    assert report.files_read == 1
    assert report.corpus_revision is None


def test_a_path_that_is_not_a_coreruleset_clone_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(CrsError, match="not a coreruleset clone"):
        load_crs_corpus(clone=tmp_path)


def test_a_case_file_that_is_not_yaml_names_the_file_in_the_error(clone: Path) -> None:
    write_case(clone, stages=[stage()])
    broken = clone / "tests" / "regression" / "tests" / SQLI_DIR / "942100.yaml"
    broken.write_text("tests: [\n  unterminated", encoding="utf-8")

    with pytest.raises(CrsError, match=r"942100\.yaml"):
        load_crs_corpus(clone=clone)


def test_a_case_with_an_unexpected_shape_is_counted_rather_than_crashing(clone: Path) -> None:
    """The corpus gains fields between releases; one of them must not stop the run."""
    root = clone / "tests" / "regression" / "tests" / SQLI_DIR
    root.mkdir(parents=True)
    (root / "942100.yaml").write_text(
        yaml.safe_dump({"rule_id": 942100, "tests": [{"test_id": 1, "stages": [{"novel": 1}]}]}),
        encoding="utf-8",
    )

    corpus = load_crs_corpus(clone=clone)

    assert corpus.by_reason() == {ExclusionReason.MALFORMED: 1}


def test_response_family_directories_are_not_read(clone: Path) -> None:
    write_case(clone, stages=[stage(uri="/get?id=1' OR '1'='1")])
    write_case(
        clone,
        directory="RESPONSE-951-DATA-LEAKAGES-SQL",
        filename="951100.yaml",
        rule_id=951100,
        stages=[stage(uri="/get?id=leak")],
    )

    corpus = load_crs_corpus(clone=clone, families=["942", "951"])

    assert corpus.files_read == 1
    assert corpus.total == 1


def test_extra_rule_packs_change_the_result(clone: Path, tmp_path: Path) -> None:
    """Proves the CLI's --rules option composes with this measurement."""
    write_case(clone, stages=[stage(uri="/get?wobble=1")])
    pack = tmp_path / "extra.yaml"
    pack.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "rules": [
                    {
                        "id": "wobble",
                        "name": "Wobble",
                        "category": "injection",
                        "severity": "high",
                        "match": {"any": [{"field": "query_decoded", "regex": "wobble"}]},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert score_crs(clone=clone).detected == 0

    engine = RuleEngine([*default_rules(), *load_rules([pack])])
    assert score_crs(clone=clone, engine=engine).detected == 1
