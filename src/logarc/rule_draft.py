"""A signature rule as the Add a rule window holds it: fields, not YAML.

The window keeps a `Draft`, asks `problems` whether it can be added, and writes
`rule_block`'s text into a pack. The checks are stricter than the loader's on
purpose: `contains: ""` and `regex: ""` load and match every request, and a
reader filling in a form should never be one blank box away from that.

Every string goes into the YAML through `_quoted`, JSON's ASCII escapes, which
YAML reads in double quotes. Written raw, U+0085 reads back as a line break, a
lone surrogate (what decoding `/%FF` leaves) is refused, and an id such as `on`
or `123` loads as a boolean or a number.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Literal

if TYPE_CHECKING:
    from collections.abc import Collection

    from logarc.core.activity import ActivityCategory, Severity

__all__ = [
    "FORM_FIELDS",
    "NUMERIC_FIELDS",
    "Condition",
    "Draft",
    "Test",
    "problems",
    "rule_block",
    "rule_id_for",
    "tests_for",
]


class Test(StrEnum):
    """What a condition asks of its field. The values are the pack's YAML keys."""

    __test__ = False  # a name pytest would otherwise try to collect

    CONTAINS = "contains"
    REGEX = "regex"
    EQUALS = "equals"
    ANY_OF = "any_of"
    MIN = "min"
    MAX = "max"


#: The fields the form offers, decoded first: the guide says to match decoded
#: unless you mean not to. The rest of `MATCH_FIELDS` stays YAML-only.
FORM_FIELDS: Final[tuple[str, ...]] = (
    "path_decoded",
    "query_decoded",
    "target_decoded",
    "user_agent_decoded",
    "referer_decoded",
    "method",
    "status",
    "bytes_sent",
    "host",
    "extension",
    "protocol",
    "path",
    "query",
    "target",
    "user_agent",
    "referer",
)

NUMERIC_FIELDS: Final = frozenset({"status", "bytes_sent"})

_TEXT_TESTS: Final = (Test.CONTAINS, Test.REGEX, Test.EQUALS, Test.ANY_OF)
_NUMBER_TESTS: Final = (Test.MIN, Test.MAX, Test.ANY_OF)


def tests_for(field: str) -> tuple[Test, ...]:
    """The tests the form offers for `field`, the first being the default."""
    return _NUMBER_TESTS if field in NUMERIC_FIELDS else _TEXT_TESTS


@dataclass(frozen=True, slots=True)
class Condition:
    field: str
    test: Test
    value: str


@dataclass(frozen=True, slots=True)
class Draft:
    """What the form holds. `None` for category or severity is "not chosen yet"."""

    name: str
    category: ActivityCategory | None
    severity: Severity | None
    mode: Literal["all", "any"]
    conditions: tuple[Condition, ...]
    confidence: str = ""
    owasp: str = ""
    references: str = ""


def rule_id_for(name: str, taken: Collection[str]) -> str:
    """An id from `name`, numbered past any in `taken`; empty when nothing is left."""
    stem = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    if not stem:
        return ""
    found, number = stem, 2
    while found in taken:
        found, number = f"{stem}_{number}", number + 1
    return found


def problems(draft: Draft) -> tuple[str, ...]:
    """Every reason the draft cannot be added yet, in the order the form asks."""
    found: list[str] = []
    if not draft.name.strip():
        found.append("Give the rule a name.")
    elif not rule_id_for(draft.name, ()):
        found.append("Use a letter or digit in the name, so the rule can have an id.")
    if draft.category is None:
        found.append("Choose what kind of activity it is.")
    if draft.severity is None:
        found.append("Choose a severity.")
    if not draft.conditions:
        found.append("Add at least one condition.")
    for number, condition in enumerate(draft.conditions, start=1):
        if problem := _condition_problem(condition):
            found.append(f"Condition {number}: {problem}")
    if draft.confidence.strip() and not _in_unit_range(draft.confidence):
        found.append("Confidence is a number from 0 to 1.")
    return tuple(found)


def rule_block(draft: Draft, rule_id: str) -> str:
    """The rule as one item of a pack's `rules:` list, its dash at column 0."""
    if problems(draft) or draft.category is None or draft.severity is None:
        raise ValueError("the draft has problems; check `problems` first")
    lines = [
        f"- id: {_quoted(rule_id)}",
        f"  name: {_quoted(draft.name.strip())}",
        f"  category: {draft.category.value}",
        f"  severity: {draft.severity.name.lower()}",
    ]
    if draft.confidence.strip():
        lines.append(f"  confidence: {_number(draft.confidence)}")
    if draft.owasp.strip():
        lines.append(f"  owasp: {_quoted(draft.owasp.strip())}")
    if references := _items(draft.references):
        lines.append(f"  references: [{', '.join(_quoted(item) for item in references)}]")
    lines += ["  match:", f"    {draft.mode}:"]
    lines += [
        f"      - {{field: {condition.field}, {condition.test.value}: {_value(condition)}}}"
        for condition in draft.conditions
    ]
    return "\n".join(lines) + "\n"


def _condition_problem(condition: Condition) -> str:
    if not condition.value.strip():
        return "give it a value."
    if condition.test is Test.ANY_OF and not all(
        part.strip() for part in condition.value.split(",")
    ):
        return "one of the values is blank."
    if condition.test in (Test.MIN, Test.MAX) and not _finite(condition.value):
        return "give a number."
    if condition.test is Test.REGEX:
        try:
            re.compile(condition.value)
        except re.error as exc:
            return str(exc)
    return ""


def _value(condition: Condition) -> str:
    if condition.test in (Test.MIN, Test.MAX):
        return _number(condition.value)
    if condition.test is Test.ANY_OF:
        return f"[{', '.join(_quoted(item) for item in _items(condition.value))}]"
    return _quoted(condition.value)


def _items(text: str) -> list[str]:
    return [part.strip() for part in text.split(",") if part.strip()]


def _quoted(text: str) -> str:
    return json.dumps(text)


def _finite(text: str) -> bool:
    try:
        return math.isfinite(float(text))
    except ValueError:
        return False


def _in_unit_range(text: str) -> bool:
    return _finite(text) and 0.0 <= float(text) <= 1.0


def _number(text: str) -> str:
    number = float(text)
    return str(int(number)) if number.is_integer() else repr(number)
