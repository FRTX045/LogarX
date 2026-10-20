"""The window, Where to start and a report are handed the same rules.

The constraint the rules tab rests on: once a reader has rules of their own,
every reading of a case must use them, or the queue ranks a client by one
ruleset and the graph explains it by another.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.caseview import reconstruct_client
from logarc.detect.ruleset import PackText, RuleSet
from logarc.report.html import render_report
from logarc.triage.scan import read_labels, scan_case

IP = "203.0.113.5"

HOUSE = PackText(
    "house",
    """\
version: 1
rules:
  - id: house_cgi_probe
    name: House rule CGI probe
    category: injection
    severity: high
    match:
      any:
        - {field: path_decoded, regex: "/cgi-bin/quux"}
""",
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text(
        f'{IP} - - [10/Oct/2020:13:55:00 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"\n'
        f'{IP} - - [10/Oct/2020:13:55:04 +0000] "GET /cgi-bin/quux.pl HTTP/1.1" 200 12 "-" '
        '"curl/8.0"\n',
        encoding="utf-8",
    )
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return tmp_path / "case"


def _read(root: Path, rules: RuleSet | None = None) -> str:
    with Case.open(root) as case:
        crs = case.crs_evidence()
    if rules is None:
        result = reconstruct_client(root, IP, crs)
    else:
        result = reconstruct_client(root, IP, crs, rules=rules)
    return json.dumps(result.to_dict())


def test_a_client_is_read_with_the_rules_it_is_handed(root: Path) -> None:
    assert "House rule CGI probe" in _read(root, RuleSet((HOUSE,)))


def test_without_them_the_same_client_is_read_with_the_built_ins(root: Path) -> None:
    """Otherwise the test above would pass on a built-in rule and prove nothing."""
    assert "House rule CGI probe" not in _read(root)


def test_the_result_says_which_rules_it_was_read_with(root: Path) -> None:
    written = json.loads(_read(root, RuleSet((HOUSE,))))

    assert written["rules_in_force"].endswith("added: house (1 rule)")


def test_the_report_names_the_rules_in_its_provenance(root: Path) -> None:
    rules = RuleSet((HOUSE,), frozenset({"http_library_user_agent"}))
    with Case.open(root) as case:
        page = render_report(
            analyse_ip(case.store, IP, engine=case.rule_engine(rules)), case.manifest
        )

    assert "<td>Rules</td>" in page
    assert "switched off (http_library_user_agent)" in page
    assert "added: house (1 rule)" in page


def test_where_to_start_labels_with_the_rules_it_is_handed(root: Path) -> None:
    result = scan_case(root, rules=RuleSet((HOUSE,)))

    assert "house_cgi_probe" in {rule for rule, _, _ in read_labels(result.path)}


def test_where_to_start_keeps_each_ruleset_s_results_apart(root: Path) -> None:
    """Keyed on the rules, so a change gets a fresh scan, and the old one stays
    on disk for switching back."""
    plain = scan_case(root)
    switched = scan_case(root, rules=RuleSet(switched_off=frozenset({"http_library_user_agent"})))

    assert plain.path != switched.path
    assert plain.path.exists()
    assert switched.path.exists()
