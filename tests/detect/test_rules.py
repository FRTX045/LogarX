"""Tests for loading and validating rule packs.

Rule packs are user-editable, so bad input must produce a message that says
which rule and what is wrong — not a stack trace from inside a regex compiler.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logarc.core.activity import ActivityCategory, Severity
from logarc.detect.rules import RulePackError, SignatureRule, WindowRule, load_rules

SIGNATURE_PACK = """
version: 1
rules:
  - id: sqli_union_select
    name: SQL Injection (UNION SELECT)
    category: injection
    owasp: "A03:2021"
    severity: high
    confidence: 0.9
    references: ["CAPEC-66"]
    match:
      any:
        - field: target_decoded
          regex: 'union\\s+select'
"""

WINDOW_PACK = """
version: 1
rules:
  - id: dir_enumeration
    name: Directory Enumeration
    category: enumeration
    severity: medium
    window:
      span_seconds: 60
      min_requests: 20
      conditions:
        - metric: distinct_paths
          op: ">="
          value: 15
"""


def write_pack(tmp_path: Path, text: str, name: str = "pack.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_a_signature_rule_loads_with_its_attributes(tmp_path: Path) -> None:
    (rule,) = load_rules([write_pack(tmp_path, SIGNATURE_PACK)])

    assert isinstance(rule, SignatureRule)
    assert rule.id == "sqli_union_select"
    assert rule.category is ActivityCategory.INJECTION
    assert rule.severity is Severity.HIGH
    assert rule.owasp == "A03:2021"
    assert rule.confidence == 0.9
    assert rule.references == ("CAPEC-66",)


def test_a_window_rule_loads_with_its_conditions(tmp_path: Path) -> None:
    (rule,) = load_rules([write_pack(tmp_path, WINDOW_PACK)])

    assert isinstance(rule, WindowRule)
    assert rule.window.span_seconds == 60
    assert rule.window.min_requests == 20
    assert rule.window.conditions[0].metric == "distinct_paths"


def test_several_packs_combine(tmp_path: Path) -> None:
    first = write_pack(tmp_path, SIGNATURE_PACK, "a.yaml")
    second = write_pack(tmp_path, WINDOW_PACK, "b.yaml")

    assert len(load_rules([first, second])) == 2


def test_a_directory_of_packs_can_be_loaded(tmp_path: Path) -> None:
    write_pack(tmp_path, SIGNATURE_PACK, "a.yaml")
    write_pack(tmp_path, WINDOW_PACK, "b.yaml")

    assert len(load_rules([tmp_path])) == 2


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    """Two rules with one id makes findings ambiguous to trace back."""
    first = write_pack(tmp_path, SIGNATURE_PACK, "a.yaml")
    second = write_pack(tmp_path, SIGNATURE_PACK, "b.yaml")

    with pytest.raises(RulePackError, match="sqli_union_select"):
        load_rules([first, second])


def test_an_invalid_regex_names_the_rule(tmp_path: Path) -> None:
    pack = """
version: 1
rules:
  - id: broken_pattern
    name: Broken
    category: injection
    severity: high
    match:
      any:
        - field: target_decoded
          regex: 'union('
"""

    with pytest.raises(RulePackError, match="broken_pattern"):
        load_rules([write_pack(tmp_path, pack)])


def test_an_unknown_category_names_the_rule_and_the_options(tmp_path: Path) -> None:
    pack = SIGNATURE_PACK.replace("category: injection", "category: mischief")

    with pytest.raises(RulePackError) as caught:
        load_rules([write_pack(tmp_path, pack)])

    assert "sqli_union_select" in str(caught.value)


def test_an_unknown_match_field_is_rejected(tmp_path: Path) -> None:
    """A typo in a field name would otherwise make a rule silently never fire."""
    pack = SIGNATURE_PACK.replace("field: target_decoded", "field: taget_decoded")

    with pytest.raises(RulePackError, match="taget_decoded"):
        load_rules([write_pack(tmp_path, pack)])


def test_a_rule_that_is_neither_signature_nor_window_is_rejected(tmp_path: Path) -> None:
    pack = """
version: 1
rules:
  - id: nothing
    name: Nothing
    category: injection
    severity: low
"""

    with pytest.raises(RulePackError, match="nothing"):
        load_rules([write_pack(tmp_path, pack)])


def test_malformed_yaml_names_the_file(tmp_path: Path) -> None:
    path = write_pack(tmp_path, "rules: [unclosed")

    with pytest.raises(RulePackError, match=r"pack\.yaml"):
        load_rules([path])


def test_a_missing_pack_is_reported(tmp_path: Path) -> None:
    with pytest.raises(RulePackError, match=r"gone\.yaml"):
        load_rules([tmp_path / "gone.yaml"])


def test_confidence_outside_zero_to_one_is_rejected(tmp_path: Path) -> None:
    pack = SIGNATURE_PACK.replace("confidence: 0.9", "confidence: 4")

    with pytest.raises(RulePackError, match="sqli_union_select"):
        load_rules([write_pack(tmp_path, pack)])


def test_each_condition_holds_its_own_compiled_pattern(tmp_path: Path) -> None:
    """Patterns were once cached in a side table keyed by `id()`. CPython
    reuses ids after garbage collection, so a condition could be handed another
    rule's pattern once the original was freed — matching the wrong thing with
    no error anywhere."""
    pack = """
version: 1
rules:
  - id: first
    name: First
    category: injection
    severity: high
    match:
      any:
        - field: path_decoded
          regex: 'alpha'
        - field: query_decoded
          regex: 'bravo'
  - id: second
    name: Second
    category: reconnaissance
    severity: low
    match:
      all:
        - field: path_decoded
          regex: 'charlie'
"""
    rules = load_rules([write_pack(tmp_path, pack)])

    for rule in rules:
        assert isinstance(rule, SignatureRule)
        for condition in rule.match.conditions:
            assert condition.compiled is not None
            assert condition.compiled.pattern == condition.regex


def test_rules_carry_the_pack_they_came_from(tmp_path: Path) -> None:
    """Reports state which ruleset produced a finding."""
    path = write_pack(tmp_path, SIGNATURE_PACK, "owasp.yaml")

    (rule,) = load_rules([path])

    assert rule.source_pack == "owasp.yaml"
