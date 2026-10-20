"""Which rules are in force: the built-in packs, less what a reader switched
off, plus their own. Built in one place so the window, Where to start and a
report cannot disagree about it."""

from __future__ import annotations

import pickle
from pathlib import Path

import pytest

from logarc.case import Case
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules
from logarc.detect.rules import RulePackError
from logarc.detect.ruleset import (
    NO_EXTRA_RULES,
    PackText,
    RuleSet,
    build_rules,
    built_in_packs,
    sort_out,
)

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


def _copying(rule_id: str, name: str = "copied") -> PackText:
    return PackText(name, HOUSE.text.replace("house_cgi_probe", rule_id))


def test_with_nothing_added_the_rules_are_the_built_in_ones() -> None:
    assert [rule.id for rule in build_rules().rules] == [rule.id for rule in default_rules()]


def test_the_built_in_packs_are_named_by_file() -> None:
    assert [pack.name for pack in built_in_packs()] == [
        "actions", "access", "files", "injection", "recon", "ssrf",
        "java", "nodejs", "perl", "php", "python", "shell", "windows",
    ]  # fmt: skip


def test_a_switched_off_rule_is_left_out() -> None:
    off = RuleSet(switched_off=frozenset({"sqli_union_select"}))

    ids = {rule.id for rule in build_rules(off).rules}

    assert "sqli_union_select" not in ids
    assert len(ids) == len(default_rules()) - 1


def test_an_id_no_built_in_rule_has_is_ignored() -> None:
    """A rule renamed in a later version leaves its old id in the file."""
    gone = RuleSet(switched_off=frozenset({"renamed_long_ago"}))

    assert len(build_rules(gone).rules) == len(default_rules())


def test_a_pack_adds_its_rules_after_the_built_in_ones() -> None:
    rules = build_rules(RuleSet((HOUSE,))).rules

    assert rules[-1].id == "house_cgi_probe"
    assert rules[-1].source_pack == "house.yaml"


def test_a_pack_copying_a_built_in_id_is_refused_naming_both() -> None:
    with pytest.raises(RulePackError) as raised:
        build_rules(RuleSet((_copying("sqli_union_select"),)))

    assert raised.value.rule_id == "sqli_union_select"
    assert "copied" in str(raised.value)
    assert "injection" in str(raised.value)
    assert "switch" in raised.value.reason


def test_switching_the_built_in_off_frees_its_id() -> None:
    replacing = RuleSet((_copying("sqli_union_select"),), frozenset({"sqli_union_select"}))

    rules = build_rules(replacing).rules

    assert [rule.source_pack for rule in rules if rule.id == "sqli_union_select"] == ["copied.yaml"]


def test_two_packs_sharing_an_id_are_refused() -> None:
    with pytest.raises(RulePackError, match="house") as raised:
        build_rules(RuleSet((HOUSE, _copying("house_cgi_probe", "again"))))

    assert raised.value.rule_id == "house_cgi_probe"


def test_a_pack_given_as_a_file_gets_the_same_check(tmp_path: Path) -> None:
    path = tmp_path / "copied.yaml"
    path.write_text(_copying("sqli_union_select").text, encoding="utf-8")

    with pytest.raises(RulePackError, match="built-in"):
        build_rules(extra_packs=[path])


def test_the_description_names_what_was_added_and_switched_off() -> None:
    described = build_rules(
        RuleSet((HOUSE,), frozenset({"http_library_user_agent", "renamed_long_ago"}))
    ).described

    assert described == (
        f"{len(default_rules()) - 1} built-in rules, 1 switched off "
        "(http_library_user_agent); added: house (1 rule)"
    )


def test_the_description_of_the_built_ins_alone() -> None:
    assert build_rules().described == f"{len(default_rules())} built-in rules"


def test_the_fingerprint_moves_with_a_pack_and_with_a_switch() -> None:
    """The report's provenance and the Where to start cache both key on it."""
    plain, added, switched = (
        RuleEngine(build_rules(ruleset).rules).fingerprint
        for ruleset in (
            NO_EXTRA_RULES,
            RuleSet((HOUSE,)),
            RuleSet(switched_off=frozenset({"http_library_user_agent"})),
        )
    )

    assert len({plain, added, switched}) == 3


def test_of_two_packs_sharing_an_id_the_later_one_is_left_out() -> None:
    again = _copying("house_cgi_probe", "again")

    kept, refused = sort_out([HOUSE, again])

    assert kept.packs == (HOUSE,)
    assert list(refused) == ["again"]
    assert "house" in str(refused["again"])


def test_a_rule_set_crosses_into_a_spawned_process() -> None:
    """It is handed to the scan worker as an argument, so it must pickle."""
    ruleset = RuleSet((HOUSE,), frozenset({"x"}))

    assert pickle.loads(pickle.dumps(ruleset)) == ruleset


def test_a_case_builds_its_engine_from_the_rules_it_is_handed(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text(
        '203.0.113.5 - - [10/Oct/2020:13:55:00 +0000] "GET / HTTP/1.1" 200 1 "-" "curl/8.0"\n',
        encoding="utf-8",
    )
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
        engine = case.rule_engine(RuleSet((HOUSE,)))

    assert "house_cgi_probe" in {rule.id for rule in engine.rules}
    assert engine.described.endswith("added: house (1 rule)")
