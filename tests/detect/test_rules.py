"""Tests for loading and validating rule packs.

Rule packs are user-editable, so bad input must produce a message that says
which rule and what is wrong — not a stack trace from inside a regex compiler.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logarc.core.activity import ActivityCategory, Severity
from logarc.detect.rulepacks import DEFAULT_RULEPACK_DIR
from logarc.detect.rules import (
    RulePackError,
    SignatureRule,
    WindowRule,
    load_pack_text,
    load_rules,
)

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


def write_pack(
    tmp_path: Path, text: str, name: str = "pack.yaml", *, parents: bool = False
) -> Path:
    if parents:
        tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_a_condition_with_no_predicate_says_what_one_needs(tmp_path: Path) -> None:
    """A condition naming a field and testing nothing would match every request
    that has that field at all — a rule that fires on everything, loaded without
    complaint. The refusal lists the six predicates rather than only refusing."""
    pack = write_pack(
        tmp_path,
        """
version: 1
rules:
  - id: empty_condition
    name: Tests Nothing
    category: injection
    severity: high
    match:
      any:
        - field: target_decoded
""",
    )

    with pytest.raises(RulePackError, match="exactly one of: regex, contains, equals"):
        load_rules([pack])


def test_a_condition_with_two_predicates_is_rejected(tmp_path: Path) -> None:
    """The other half of the same rule. Which of the two would win is an
    implementation detail nobody should have to know, so neither does."""
    pack = write_pack(
        tmp_path,
        """
version: 1
rules:
  - id: two_predicates
    name: Tests Twice
    category: injection
    severity: high
    match:
      any:
        - field: target_decoded
          regex: 'union'
          contains: 'select'
""",
    )

    with pytest.raises(RulePackError, match="exactly one of"):
        load_rules([pack])


def test_a_match_block_must_choose_any_or_all(tmp_path: Path) -> None:
    """`any` is or, `all` is and, and a block with both or neither has no
    meaning. Silently picking one would change what every condition under it
    does without the author having said so."""
    pack = write_pack(
        tmp_path,
        """
version: 1
rules:
  - id: both_combinators
    name: Both At Once
    category: injection
    severity: high
    match:
      any:
        - field: target_decoded
          contains: 'union'
      all:
        - field: method
          equals: 'POST'
""",
    )

    with pytest.raises(RulePackError, match="exactly one of: any, all"):
        load_rules([pack])


def test_an_unknown_window_metric_lists_the_ones_that_exist(tmp_path: Path) -> None:
    """A misspelt metric is the likeliest mistake in a window rule, and the
    reader cannot guess the vocabulary — so the refusal carries it."""
    pack = write_pack(
        tmp_path,
        WINDOW_PACK.replace("metric: distinct_paths", "metric: distinct_pathz"),
    )

    with pytest.raises(RulePackError, match="unknown window metric") as raised:
        load_rules([pack])
    assert "distinct_paths" in str(raised.value), "the refusal has to name the real one"


def test_an_unknown_severity_lists_the_levels_that_exist(tmp_path: Path) -> None:
    """Completes the family: field, metric, operator and now severity all name
    the vocabulary when they refuse. Severity is the one whose spelling a reader
    is most likely to guess at — `warn`, `warning`, `major` — and the levels
    are not written down anywhere they would look."""
    pack = write_pack(tmp_path, SIGNATURE_PACK.replace("severity: high", "severity: severe"))

    with pytest.raises(RulePackError, match="unknown severity") as raised:
        load_rules([pack])
    printed = str(raised.value)
    assert "critical" in printed
    assert "info" in printed


def test_an_unknown_operator_lists_the_ones_that_exist(tmp_path: Path) -> None:
    """`=>` for `>=` is a typo that reads as correct, and an operator that is
    merely rejected leaves the author guessing which spelling is wanted."""
    pack = write_pack(tmp_path, WINDOW_PACK.replace('op: ">="', 'op: "=>"'))

    with pytest.raises(RulePackError, match="unknown operator") as raised:
        load_rules([pack])
    assert ">=" in str(raised.value)


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


def test_packs_in_subdirectories_are_loaded(tmp_path: Path) -> None:
    """The packs are grouped into folders, so the loader has to go in.

    It used to look one level deep. A pack moved into a folder was not
    reported missing — it produced no rules at all, silently, and the tool
    went on analysing with a hole in its detection where that file had been.
    """
    write_pack(tmp_path, SIGNATURE_PACK, "flat.yaml")
    nested = tmp_path / "attack"
    nested.mkdir()
    write_pack(nested, WINDOW_PACK, "deep.yaml")

    assert len(load_rules([tmp_path])) == 2


def test_a_duplicate_id_across_folders_still_names_both_files(tmp_path: Path) -> None:
    """Folders make it easier to define the same rule twice by accident, so
    the check that catches it has to reach across them too."""
    write_pack(tmp_path / "a", SIGNATURE_PACK, "one.yaml", parents=True)
    write_pack(tmp_path / "b", SIGNATURE_PACK, "two.yaml", parents=True)

    with pytest.raises(RulePackError, match="sqli_union_select"):
        load_rules([tmp_path])


def test_a_directory_with_no_packs_is_refused(tmp_path: Path) -> None:
    """Zero rules is never a useful answer, and it is what a mistyped path or
    a wrong-extension file produces. Saying so beats analysing a case with a
    detection layer that quietly is not there."""
    (tmp_path / "rules.yml").write_text("version: 1\nrules: []\n", encoding="utf-8")

    with pytest.raises(RulePackError, match="no rule packs"):
        load_rules([tmp_path])


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


# -- a pack read from text, as the window holds it ---------------------------

SHOPFRONT = """\
version: 1
note: What misuse of our own shop's API looks like
rules:
  - id: shop_stock_polling
    name: Stock levels polled by a script
    category: crawling
    severity: low
    confidence: 0.7
    member:
      all:
        - {field: path, regex: "^/api/stock$"}
    window:
      span_seconds: 300
      min_requests: 3
      conditions:
        - {metric: request_count, op: ">=", value: 3}

  - id: shop_cart_emptied_by_api
    name: Cart emptied through the API
    category: api_call
    severity: info
    match:
      all:
        - {field: method, equals: DELETE}
        - {field: path, regex: "^/api/cart$"}
"""


@pytest.mark.parametrize(
    "path",
    sorted(DEFAULT_RULEPACK_DIR.rglob("*.yaml")),
    ids=lambda path: path.relative_to(DEFAULT_RULEPACK_DIR).as_posix(),
)
def test_a_pack_read_from_text_is_the_pack_read_from_its_file(path: Path) -> None:
    """The window holds packs as text and the command line reads files. Two
    loaders that disagreed would label the same request two ways."""
    from_text = load_pack_text(path.name, path.read_text(encoding="utf-8"))

    assert [rule.model_dump() for rule in from_text] == [
        rule.model_dump() for rule in load_rules([path])
    ]


def test_a_pack_may_say_what_it_is_for() -> None:
    (stock, cart) = load_pack_text("shopfront.yaml", SHOPFRONT)

    assert (stock.id, cart.id) == ("shop_stock_polling", "shop_cart_emptied_by_api")
    assert cart.source_pack == "shopfront.yaml"


def test_a_pack_still_refuses_a_key_it_does_not_know() -> None:
    with pytest.raises(RulePackError, match="notes"):
        load_pack_text("x.yaml", "version: 1\nnotes: misspelt\nrules: []\n")


def test_a_pack_with_no_rules_yet_reads_as_empty() -> None:
    """`rules:` with only comments under it is YAML for null. A new pack
    starts that way, and it is not a mistake."""
    assert load_pack_text("x.yaml", "version: 1\nrules:\n  # one day\n") == []


def test_one_pack_cannot_use_an_id_twice() -> None:
    twice = SHOPFRONT.replace("shop_stock_polling", "shop_cart_emptied_by_api")

    with pytest.raises(RulePackError, match="duplicate rule id") as raised:
        load_pack_text("shopfront.yaml", twice)

    assert raised.value.rule_id == "shop_cart_emptied_by_api"


@pytest.mark.parametrize(
    ("text", "line"),
    [
        # A missing colon: PyYAML reports the line after, where it looked for one.
        (
            "version: 1\nrules:\n  - id: a\n    name: Cart\n    severity info\n"
            "    category: api_call\n",
            5,
        ),
        # An unclosed brace: reported where the next one opens.
        (
            "version: 1\nrules:\n  - id: a\n    match:\n      all:\n"
            "        - {field: method, equals: DELETE\n        - {field: path}\n",
            6,
        ),
        # Indentation: reported where it goes wrong.
        ("version: 1\nrules:\n  - id: a\n    name: b\n   category: c\n", 5),
    ],
    ids=["missing colon", "unclosed brace", "indentation"],
)
def test_a_yaml_mistake_says_the_line_it_is_on(text: str, line: int) -> None:
    with pytest.raises(RulePackError) as raised:
        load_pack_text("x.yaml", text)

    assert raised.value.line == line


def test_a_rule_mistake_says_which_rule_and_which_condition() -> None:
    two_tests = SHOPFRONT.replace(
        "{field: method, equals: DELETE}", "{field: method, equals: DELETE, contains: DEL}"
    )

    with pytest.raises(RulePackError) as raised:
        load_pack_text("shopfront.yaml", two_tests)

    assert raised.value.rule_id == "shop_cart_emptied_by_api"
    assert raised.value.location == ("match", "all", 0)
    assert raised.value.reason.startswith("a condition needs exactly one of")


def test_a_bad_pattern_says_which_condition() -> None:
    broken = SHOPFRONT.replace('regex: "^/api/cart$"', 'regex: "^/api/(cart"')

    with pytest.raises(RulePackError) as raised:
        load_pack_text("shopfront.yaml", broken)

    assert raised.value.rule_id == "shop_cart_emptied_by_api"
    assert raised.value.location == ("match", "all", 1)


def test_the_validator_s_own_prefix_is_not_passed_on(tmp_path: Path) -> None:
    """ "Value error," names a pydantic class, not anything in the pack."""
    pack = tmp_path / "x.yaml"
    pack.write_text(
        SHOPFRONT.replace("{field: method, equals: DELETE}", "{field: method}"), encoding="utf-8"
    )

    with pytest.raises(RulePackError) as raised:
        load_rules([pack])

    assert "Value error" not in str(raised.value)
    assert "a condition needs exactly one of" in str(raised.value)


#: `SIGNATURE_PACK` with an icon named on its rule.
ICON_PACK = SIGNATURE_PACK.replace("    severity: high\n", "    severity: high\n    icon: skull\n")

#: `SIGNATURE_PACK`'s fingerprint before rules could name an icon, taken from
#: the code as it was. Equal to it with the field present and with an icon
#: named is the proof that an icon is no part of detection.
FINGERPRINT_BEFORE_ICONS = "005efefb08b39db814ecbf56b285c25d2c5ae29effee5fee33f6d6fd5f7b8316"


def test_a_rule_may_name_an_icon() -> None:
    (rule,) = load_pack_text("mine.yaml", ICON_PACK)
    assert rule.icon == "skull"


def test_a_rule_names_no_icon_unless_it_says_so() -> None:
    (rule,) = load_pack_text("mine.yaml", SIGNATURE_PACK)
    assert rule.icon is None


def test_an_icon_moves_no_fingerprint() -> None:
    """The fingerprint keys the Triage cache and is recorded in every report:
    counted, a new field would re-scan every case once, and each change of
    icon would again."""
    from logarc.detect.engine import RuleEngine

    plain = RuleEngine(load_pack_text("a.yaml", SIGNATURE_PACK)).fingerprint
    iconic = RuleEngine(load_pack_text("a.yaml", ICON_PACK)).fingerprint
    assert plain == iconic == FINGERPRINT_BEFORE_ICONS
