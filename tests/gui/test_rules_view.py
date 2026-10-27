"""What the rules tab says. Free of Qt: the judgements here are wording."""

from __future__ import annotations

import pytest

from logarx.detect.rules import RulePackError, load_pack_text
from logarx.detect.ruleset import PackText, RuleSet, build_rules
from logarx.gui.rules_view import (
    NEW_PACK_TEXT,
    ask_text,
    delete_question,
    error_line,
    in_words,
    packs_refused_notice,
    read_summary,
    rules_changed_notice,
)

PACK = """\
version: 1
rules:
  - id: shop_stock_polling
    name: Stock levels polled by a script
    category: crawling
    severity: low
    member:
      all:
        - {field: path, regex: "^/api/stock$"}
    window:
      span_seconds: 300
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


def _error(text: str) -> RulePackError:
    with pytest.raises(RulePackError) as raised:
        build_rules(RuleSet((PackText("shopfront", text),)))
    return raised.value


def _line_of(text: str, needle: str) -> int:
    return next(n for n, line in enumerate(text.splitlines(), 1) if needle in line)


def test_a_condition_with_two_tests_is_found_on_its_own_line() -> None:
    text = PACK.replace(
        "{field: method, equals: DELETE}", "{field: method, equals: DELETE, contains: X}"
    )

    assert error_line(text, _error(text)) == _line_of(text, "contains: X")


def test_a_bad_pattern_is_found_on_its_own_line() -> None:
    text = PACK.replace('"^/api/cart$"', '"^/api/(cart"')

    assert error_line(text, _error(text)) == _line_of(text, "(cart")


def test_a_wrong_value_is_found_on_its_key_s_line() -> None:
    text = PACK.replace("category: api_call", "category: api_calls")

    assert error_line(text, _error(text)) == _line_of(text, "api_calls")


def test_a_missing_key_falls_back_to_the_rule_s_id_line() -> None:
    text = PACK.replace("    name: Cart emptied through the API\n", "")

    assert error_line(text, _error(text)) == _line_of(text, "id: shop_cart_emptied_by_api")


def test_a_copied_built_in_id_is_found_on_its_id_line() -> None:
    text = PACK.replace("shop_cart_emptied_by_api", "sqli_union_select")

    assert error_line(text, _error(text)) == _line_of(text, "id: sqli_union_select")


def test_a_yaml_mistake_is_found_where_the_loader_said() -> None:
    text = PACK.replace("    severity: info\n", "    severity info\n")

    assert error_line(text, _error(text)) == _line_of(text, "severity info")


def test_a_rule_mistake_is_said_in_words() -> None:
    text = PACK.replace(
        "{field: method, equals: DELETE}", "{field: method, equals: DELETE, contains: X}"
    )

    assert in_words(_error(text)) == (
        "Rule shop_cart_emptied_by_api, first condition under match: a condition needs "
        "exactly one of: regex, contains, equals, any_of, min, max"
    )


def test_a_yaml_mistake_is_said_with_its_line() -> None:
    text = PACK.replace("    severity: info\n", "    severity info\n")

    assert in_words(_error(text)) == (
        f"Line {_line_of(text, 'severity info')}: could not find expected ':'"
    )


def test_a_copied_id_says_the_way_out() -> None:
    said = in_words(_error(PACK.replace("shop_cart_emptied_by_api", "sqli_union_select")))

    assert said.startswith("Rule sqli_union_select: this id belongs to a built-in rule")
    assert "switch the built-in one off" in said


def test_a_pack_that_reads_says_what_kinds_of_rule_it_holds() -> None:
    assert read_summary(load_pack_text("x.yaml", PACK)) == (
        "2 rules read: 1 about a single request, 1 about a run of requests."
    )


def test_an_empty_pack_says_where_rules_go() -> None:
    assert read_summary([]) == "No rules yet. Add them under rules:, as in the example."


def test_a_new_pack_reads_as_a_pack_with_no_rules() -> None:
    assert load_pack_text("x.yaml", NEW_PACK_TEXT) == []


def test_the_example_in_a_new_pack_loads_once_its_hashes_are_removed() -> None:
    """What the comment above it tells the reader to do. An example that did
    not load once uncommented would be the first mistake a new pack showed."""
    uncommented = "\n".join(
        line[1:] if line.startswith("#  ") else line for line in NEW_PACK_TEXT.splitlines()
    )

    assert [rule.id for rule in load_pack_text("x.yaml", uncommented)] == ["my_first_rule"]


@pytest.mark.parametrize(
    ("rules", "said"),
    [
        (2, "Delete shopfront? Its 2 rules stop applying."),
        (1, "Delete shopfront? Its one rule stops applying."),
        (None, "Delete shopfront? It does not load, so nothing in it applies now."),
    ],
)
def test_deleting_asks_in_the_panel(rules: int | None, said: str) -> None:
    assert delete_question("shopfront", rules) == said


def test_the_ask_bar_says_what_changed_and_why_it_matters() -> None:
    assert ask_text("Saved.") == "Saved. The open case was read with the old rules."


def test_the_window_says_the_rules_changed() -> None:
    assert rules_changed_notice().headline == "Rules changed since this case was read."
    assert rules_changed_notice().detail == (
        "The open client and Triage still use the old rules. Re-read to apply the new ones."
    )


@pytest.mark.parametrize(
    ("refused", "headline"),
    [
        (
            {"shopfront": "x"},
            "One of your rule packs did not load, so this case was read without it.",
        ),
        (
            {"a": "x", "b": "y"},
            "2 of your rule packs did not load, so this case was read without them.",
        ),
    ],
)
def test_the_window_names_packs_that_did_not_load(refused: dict[str, str], headline: str) -> None:
    notice = packs_refused_notice(refused)

    assert notice.headline == headline
    assert all(name in notice.detail for name in refused)
    assert "\n\n" not in notice.detail  # one paragraph: the strip shows only the first
