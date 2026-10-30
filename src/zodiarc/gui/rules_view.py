"""What the rules tab and the window say about rules. No Qt.

The judgements worth checking without a display: which line of a pack a mistake
is on, how the mistake is put in words, and what a strip says. The same split as
`gui.prefs` and `gui.quarantine_notice`.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Final

import yaml

from zodiarc.detect.rules import SequenceRule, SignatureRule, WindowRule
from zodiarc.gui.quarantine_notice import Notice
from zodiarc.style import plural

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from zodiarc.detect.rules import Rule, RulePackError

__all__ = [
    "NEW_PACK_TEXT",
    "ask_text",
    "delete_question",
    "error_line",
    "in_words",
    "packs_refused_notice",
    "read_summary",
    "rules_changed_notice",
]

#: How a new pack starts: no rules, and one commented example to copy.
#: Prose lines start `# `, example lines `#  `: removing the first character of
#: each example line leaves the rule indented under `rules:`.
NEW_PACK_TEXT: Final = """\
version: 1
note: What this pack is for, in a sentence.
rules:
# An example. Remove the # at the start of each line below to use it,
# then change it. Every option is in docs/writing-rules.md.
#  - id: my_first_rule
#    name: Cart emptied through the API
#    category: api_call
#    severity: info
#    match:
#      all:
#        - {field: method, equals: DELETE}
#        - {field: path, regex: "^/api/cart$"}
"""

_ORDINALS: Final = (
    "first",
    "second",
    "third",
    "fourth",
    "fifth",
    "sixth",
    "seventh",
    "eighth",
    "ninth",
    "tenth",
)

_KINDS: Final = (
    (SignatureRule, "a single request"),
    (WindowRule, "a run of requests"),
    (SequenceRule, "one request after another"),
)


def error_line(text: str, error: RulePackError) -> int | None:
    """The line of `text` to mark for `error`, counted from one, or None.

    A YAML mistake carries its line. A rule mistake names the rule and the path
    to the condition, so the rule is found by its `id:` and the path walked
    through the YAML's own nodes; where the path runs out (a key that is missing
    is on no line) the rule's `id:` line is the answer.
    """
    if error.line is not None:
        return error.line
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return None
    if error.rule_id is None:
        return _walk(root, error.location) if root is not None else None
    rules = _value(root, "rules")
    if not isinstance(rules, yaml.SequenceNode):
        return None
    found = [
        item
        for item in rules.value
        if isinstance(item, yaml.MappingNode)
        and isinstance(id_node := _value(item, "id"), yaml.ScalarNode)
        and id_node.value == error.rule_id
    ]
    if not found:
        return None
    # The last: of two rules sharing an id, the second is the one refused.
    return _walk(found[-1], error.location, fallback=_key_line(found[-1], "id"))


def _walk(
    node: yaml.Node, location: tuple[str | int, ...], *, fallback: int | None = None
) -> int | None:
    line = fallback
    for part in location:
        if isinstance(node, yaml.MappingNode) and isinstance(part, str):
            nxt = _value(node, part)
        elif (
            isinstance(node, yaml.SequenceNode) and isinstance(part, int) and part < len(node.value)
        ):
            nxt = node.value[part]
        else:
            nxt = None
        if nxt is None:
            break
        node = nxt
        line = node.start_mark.line + 1
    return line


def _value(node: yaml.Node | None, key: str) -> yaml.Node | None:
    if not isinstance(node, yaml.MappingNode):
        return None
    for k, v in node.value:
        if isinstance(k, yaml.ScalarNode) and k.value == key and isinstance(v, yaml.Node):
            return v
    return None


def _key_line(node: yaml.MappingNode, key: str) -> int | None:
    for k, _ in node.value:
        if isinstance(k, yaml.ScalarNode) and k.value == key:
            return k.start_mark.line + 1
    return None


def in_words(error: RulePackError) -> str:
    """The mistake as the status line says it: where, then what."""
    if error.rule_id is not None:
        where = f"Rule {error.rule_id}"
        if place := _place(error.location):
            where += f", {place}"
    elif error.line is not None:
        where = f"Line {error.line}"
    elif place := _place(error.location):
        where = place[0].upper() + place[1:]
    else:
        return error.reason
    return f"{where}: {error.reason}"


def _place(location: tuple[str | int, ...]) -> str:
    """`("match", "all", 0)` as "first condition under match"."""
    names = [
        part
        for part in location
        if isinstance(part, str) and part not in {"any", "all", "conditions"}
    ]
    numbers = [part for part in location if isinstance(part, int)]
    if numbers:
        index = numbers[-1]
        ordinal = _ORDINALS[index] if index < len(_ORDINALS) else f"number {index + 1}"
        return f"{ordinal} condition under {' '.join(names)}" if names else f"{ordinal} condition"
    if names:
        return f"the {names[-1]} key"
    return ""


def read_summary(rules: Sequence[Rule]) -> str:
    if not rules:
        return "No rules yet. Add them under rules:, as in the example."
    kinds = Counter(next(said for kind, said in _KINDS if isinstance(rule, kind)) for rule in rules)
    parts = [f"{count} about {said}" for _, said in _KINDS if (count := kinds[said])]
    return f"{plural(len(rules), 'rule')} read: {', '.join(parts)}."


def delete_question(name: str, rules: int | None) -> str:
    if rules is None:
        return f"Delete {name}? It does not load, so nothing in it applies now."
    if rules == 1:
        return f"Delete {name}? Its one rule stops applying."
    return f"Delete {name}? Its {rules} rules stop applying."


def ask_text(what: str) -> str:
    return f"{what} The open case was read with the old rules."


def rules_changed_notice() -> Notice:
    return Notice(
        "Rules changed since this case was read.",
        "The open client and Triage still use the old rules. Re-read to apply the new ones.",
        (),
    )


def packs_refused_notice(refused: Mapping[str, str]) -> Notice:
    count = len(refused)
    headline = (
        "One of your rule packs did not load, so this case was read without it."
        if count == 1
        else f"{count} of your rule packs did not load, so this case was read without them."
    )
    detail = " ".join(f"{name}: {problem}" for name, problem in refused.items())
    return Notice(headline, detail.replace("\n\n", " "), ())
