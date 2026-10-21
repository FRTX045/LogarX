"""Adding one rule to a reader's pack without disturbing anything already in it.

The pack may be hand-written: comments, its own indentation, keys after the
rules. The new rule goes in as whole lines, every old line stays, and every old
rule must read exactly as before, or nothing is returned.
"""

from __future__ import annotations

import pytest

from logarc.core.activity import ActivityCategory, Severity
from logarc.detect.rules import load_pack_text
from logarc.gui.rules_view import NEW_PACK_TEXT
from logarc.pack_append import CannotAppend, appended
from logarc.rule_draft import Condition, Draft, Test, rule_block

BLOCK = rule_block(
    Draft(
        name="Added",
        category=ActivityCategory.INJECTION,
        severity=Severity.HIGH,
        mode="all",
        conditions=(Condition("path", Test.EQUALS, "/added"),),
    ),
    "added",
)

TWO = """\
version: 1
note: Two of ours
rules:
  - id: one
    name: One
    category: injection
    severity: high
    match:
      all:
        - {field: path, equals: /one}

  - id: two
    name: Two
    category: injection
    severity: high
    match:
      all:
        - {field: path, equals: /two}
"""

REFUSED = "The pack is laid out in a way the form cannot add to."


def _ids(text: str) -> list[str]:
    return [rule.id for rule in load_pack_text("t.yaml", text)]


def _kept_in_order(old: list[str], new: list[str]) -> bool:
    remaining = iter(new)
    return all(line in remaining for line in old)


def test_a_rule_goes_after_the_last_one() -> None:
    result = appended(TWO, BLOCK)

    assert _ids(result) == ["one", "two", "added"]
    assert result.startswith(TWO)


def test_the_new_pack_example_takes_a_rule() -> None:
    result = appended(NEW_PACK_TEXT, BLOCK)

    assert _ids(result) == ["added"]
    assert _kept_in_order(NEW_PACK_TEXT.splitlines(), result.splitlines())


def test_comments_and_a_key_after_rules_are_kept() -> None:
    pack = """\
version: 1
rules:
  - id: one
    name: One
    category: injection
    severity: high
    match:
      all:
        - {field: path, equals: /one}
  # the second came later
  - id: two
    name: Two
    category: injection
    severity: high
    match:
      all:
        - {field: path, equals: /two}
  # nothing after this yet

note: later
"""
    result = appended(pack, BLOCK)

    assert _ids(result) == ["one", "two", "added"]
    assert _kept_in_order(pack.splitlines(), result.splitlines())
    assert result.endswith("note: later\n")


def test_a_trailing_comment_before_the_next_key_is_handled() -> None:
    pack = """\
version: 1
rules:
  - id: old
    name: Old
    category: injection
    severity: high
    match: {all: [{field: path, equals: /old}]}
# trailing comment
note: later
"""
    result = appended(pack, BLOCK)

    assert _ids(result) == ["old", "added"]
    lines = result.splitlines()
    assert lines.index('  - id: "added"') < lines.index("# trailing comment")


@pytest.mark.parametrize(
    ("line", "becomes"),
    [
        ("rules: []", "rules:"),
        ("rules: []   ", "rules:"),
        ("rules: [] # keep me", "rules: # keep me"),
        ("rules: null", "rules:"),
        ("rules: ~", "rules:"),
    ],
)
def test_an_empty_flow_list_is_opened(line: str, becomes: str) -> None:
    pack = f"version: 1\n{line}\nnote: after\n"

    result = appended(pack, BLOCK)

    assert _ids(result) == ["added"]
    lines = result.splitlines()
    assert lines[0] == "version: 1"
    assert lines[1] == becomes
    assert lines[-1] == "note: after"


def test_a_multiline_empty_list_is_refused() -> None:
    with pytest.raises(CannotAppend):
        appended("version: 1\nrules: [\n  # none yet\n]\n", BLOCK)


def test_an_anchored_list_takes_its_dashes_column() -> None:
    pack = TWO.replace("rules:\n", "rules: &items\n")

    result = appended(pack, BLOCK)

    assert _ids(result) == ["one", "two", "added"]
    assert '\n  - id: "added"\n' in result


def test_a_flow_list_with_rules_is_refused() -> None:
    pack = (
        "version: 1\nrules: [{id: one, name: One, category: injection, severity: high,"
        " match: {all: [{field: path, equals: /one}]}}]\n"
    )

    with pytest.raises(CannotAppend):
        appended(pack, BLOCK)


def test_a_block_scalar_left_open_is_refused() -> None:
    pack = """\
version: 1
rules:
  - id: old
    name: Old
    category: injection
    severity: high
    match:
      all:
        - field: path
          equals: |
            /old"""

    with pytest.raises(CannotAppend):
        appended(pack, BLOCK)


def test_four_space_indentation_is_followed() -> None:
    pack = """\
version: 1
rules:
    - id: one
      name: One
      category: injection
      severity: high
      match:
        all:
          - {field: path, equals: /one}
"""

    result = appended(pack, BLOCK)

    assert _ids(result) == ["one", "added"]
    assert '\n    - id: "added"\n' in result


def test_a_pack_without_rules_is_refused() -> None:
    with pytest.raises(CannotAppend):
        appended("version: 1\nnote: nothing\n", BLOCK)


def test_the_message_points_at_the_yaml_editor() -> None:
    with pytest.raises(CannotAppend) as raised:
        appended("version: 1\nrules: [\n]\n", BLOCK)

    assert str(raised.value) == REFUSED
