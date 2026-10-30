"""Add one rule to a pack's YAML without touching anything already in it.

For the Add a rule window. A reader's pack may be written by hand, and dumping
it again through a YAML writer would drop its comments and its layout, so the
new rule goes in as whole lines of text. Then the result is proved: it loads,
every old rule reads exactly as it did, the new one reads as the block alone
does, and every old line is still there in order. If any of that fails the pack
is one the form cannot add to, and the reader is sent to the YAML editor.

The one existing line that may change is a `rules:` whose value is an empty
`[]` or a null on the same line: the value is taken off it so the list can
open under it, and anything after the value, such as a comment, is kept.
"""

from __future__ import annotations

from textwrap import indent
from typing import Final

import yaml

from zodiarc.detect.rules import Rule, RulePackError, load_pack_text

__all__ = ["CannotAppend", "appended"]

_REFUSED: Final = "The pack is laid out in a way the form cannot add to."
_NULL: Final = "tag:yaml.org,2002:null"
_CHECKED_AS: Final = "check.yaml"


class CannotAppend(ValueError):  # noqa: N818 - named for what the window tells the reader
    """The pack's layout is not one the form can add to; nothing was changed."""


def appended(text: str, block: str) -> str:
    """`text` with `block` added as the last item of its `rules:` list.

    `block` is `rule_draft.rule_block`'s text: one list item, its dash at
    column 0. Raises `CannotAppend` rather than return a pack that changed in
    any way but the new rule.
    """
    lines = text.splitlines(keepends=True)
    key, value = _rules_of(text)
    rewritten: tuple[int, str] | None = None

    if isinstance(value, yaml.SequenceNode) and not value.flow_style and value.value:
        first, last = value.value[0], value.value[-1]
        column = lines[first.start_mark.line].rfind("-", 0, first.start_mark.column)
        if column < 0:
            raise CannotAppend(_REFUSED)
        after = _last_content_line(lines, last, floor=first.start_mark.line)
    elif _is_empty(value) and value.start_mark.index == value.end_mark.index:
        column, after = key.start_mark.column + 2, key.start_mark.line
    elif _is_empty(value) and value.start_mark.line == value.end_mark.line == key.start_mark.line:
        column, after = key.start_mark.column + 2, key.start_mark.line
        line = lines[after]
        rest = line[value.end_mark.column :]
        if not rest.strip():
            rest = rest[len(rest.rstrip("\r\n")) :]
        rewritten = (after, line[: value.start_mark.column].rstrip(" \t") + rest)
    else:
        raise CannotAppend(_REFUSED)

    before = [*lines[: after + 1]]
    if rewritten is not None:
        before[rewritten[0]] = rewritten[1]
    if before and not before[-1].endswith("\n"):
        before[-1] += "\n"
    result = "".join([*before, indent(block, " " * column), *lines[after + 1 :]])

    expected_old = [*lines]
    if rewritten is not None:
        expected_old[rewritten[0]] = rewritten[1]
    _verify(text, result, block, [line.rstrip("\r\n") for line in expected_old])
    return result


def _rules_of(text: str) -> tuple[yaml.Node, yaml.Node]:
    try:
        root = yaml.compose(text)
    except yaml.YAMLError as exc:
        raise CannotAppend(_REFUSED) from exc
    if isinstance(root, yaml.MappingNode):
        for key, value in root.value:
            if isinstance(key, yaml.ScalarNode) and key.value == "rules":
                return key, value
    raise CannotAppend(_REFUSED)


def _is_empty(value: yaml.Node) -> bool:
    """An empty flow list, or a null: a pack with no rules yet."""
    if isinstance(value, yaml.SequenceNode):
        return bool(value.flow_style) and not value.value
    return isinstance(value, yaml.ScalarNode) and value.tag == _NULL


def _last_content_line(lines: list[str], last: yaml.Node, *, floor: int) -> int:
    """The last line holding the last item, before any blank or comment lines.

    The item's end mark sits at the next token when one follows, which may be
    a later key at column 0; that line is not the item's.
    """
    line = last.end_mark.line - (1 if last.end_mark.column == 0 else 0)
    line = min(line, len(lines) - 1)
    while line > floor and (not lines[line].strip() or lines[line].lstrip().startswith("#")):
        line -= 1
    return line


def _verify(text: str, result: str, block: str, expected_old: list[str]) -> None:
    old = _rules(text)
    new = _rules(result)
    (alone,) = _rules("version: 1\nrules:\n" + indent(block, "  "))
    if len(new) != len(old) + 1:
        raise CannotAppend(_REFUSED)
    if [rule.model_dump() for rule in new[:-1]] != [rule.model_dump() for rule in old]:
        raise CannotAppend(_REFUSED)
    if new[-1].model_dump() != alone.model_dump():
        raise CannotAppend(_REFUSED)
    before, after = yaml.safe_load(text), yaml.safe_load(result)
    if any(before.get(key) != after.get(key) for key in ("version", "note")):
        raise CannotAppend(_REFUSED)
    remaining = iter(result.splitlines())
    if not all(line in remaining for line in expected_old):
        raise CannotAppend(_REFUSED)


def _rules(text: str) -> list[Rule]:
    try:
        return load_pack_text(_CHECKED_AS, text)
    except (RulePackError, yaml.YAMLError) as exc:
        raise CannotAppend(_REFUSED) from exc
