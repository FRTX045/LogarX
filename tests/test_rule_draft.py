"""A signature rule described as form fields: its checks, its id and its YAML.

The Add a rule window builds one of these from what the reader picked, and the
pack gets `rule_block`'s text. Checked against the loader, because the text is
only worth writing if it loads as the rule the form showed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from textwrap import indent

import pytest

from logarc import rule_draft
from logarc.core.activity import ActivityCategory, Severity
from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.engine import RuleEngine
from logarc.detect.rules import MATCH_FIELDS, SignatureRule, load_pack_text
from logarc.rule_draft import (
    FORM_FIELDS,
    Condition,
    Draft,
    LinePart,
    Test,
    conditions_from,
    line_parts,
    problems,
    rule_block,
    rule_id_for,
)

UPLOADS = Draft(
    name="Script run from the uploads folder",
    category=ActivityCategory.EXPLOITATION,
    severity=Severity.CRITICAL,
    mode="all",
    conditions=(
        Condition("path_decoded", Test.REGEX, r"^/uploads/.+\.php$"),
        Condition("status", Test.MIN, "200"),
        Condition("status", Test.MAX, "299"),
    ),
)


def _draft(*conditions: Condition, **changes: object) -> Draft:
    fields: dict[str, object] = {
        "name": "Probe",
        "category": ActivityCategory.INJECTION,
        "severity": Severity.HIGH,
        "mode": "all",
        "conditions": conditions or (Condition("path", Test.EQUALS, "/x"),),
    }
    fields.update(changes)
    return Draft(**fields)  # type: ignore[arg-type]


def _loaded(block: str) -> SignatureRule:
    (rule,) = load_pack_text("t.yaml", "version: 1\nrules:\n" + indent(block, "  "))
    assert isinstance(rule, SignatureRule)
    return rule


def _request(path: str) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 8, 23, tzinfo=UTC),
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", 1),
        method="GET",
        path=path,
        status=200,
    )


def _labels(rule: SignatureRule, event: NormalizedEvent) -> set[str]:
    (labelled,) = RuleEngine([rule]).label_events([event])
    return {label.rule_id for label in labelled.all_labels}


def test_an_id_is_made_from_the_name() -> None:
    assert rule_id_for("Script run from the uploads folder", ()) == (
        "script_run_from_the_uploads_folder"
    )


def test_a_taken_id_gets_a_number() -> None:
    assert rule_id_for("Probe", {"probe", "probe_2"}) == "probe_3"


@pytest.mark.parametrize("name", ["!!!", "ÜÜ"])
def test_a_name_with_nothing_to_make_an_id_from_is_refused(name: str) -> None:
    assert rule_id_for(name, ()) == ""
    assert "Use a letter or digit in the name, so the rule can have an id." in problems(
        _draft(name=name)
    )


@pytest.mark.parametrize(
    ("draft", "message"),
    [
        (_draft(Condition("path", Test.CONTAINS, "  ")), "Condition 1: give it a value."),
        (
            _draft(Condition("path", Test.EQUALS, "/a"), Condition("status", Test.ANY_OF, "200, ")),
            "Condition 2: one of the values is blank.",
        ),
        (_draft(Condition("status", Test.MIN, "two")), "Condition 1: give a number."),
        (
            _draft(Condition("path", Test.REGEX, "(")),
            "Condition 1: missing ), unterminated subpattern at position 0",
        ),
        (_draft(confidence="1.5"), "Confidence is a number from 0 to 1."),
        (_draft(conditions=()), "Add at least one condition."),
        (_draft(name="  "), "Give the rule a name."),
    ],
)
def test_blank_values_and_no_conditions_are_problems(draft: Draft, message: str) -> None:
    assert problems(draft) == (message,)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"category": None}, "Choose what kind of activity it is."),
        ({"severity": None}, "Choose a severity."),
    ],
)
def test_category_and_severity_must_be_chosen(change: dict[str, object], message: str) -> None:
    draft = _draft(**change)

    assert problems(draft) == (message,)
    with pytest.raises(ValueError):
        rule_block(draft, "x")


def test_a_good_draft_has_no_problems() -> None:
    assert problems(UPLOADS) == ()


def test_the_block_loads_as_the_rule_the_form_describes() -> None:
    rule = _loaded(rule_block(UPLOADS, "x"))

    assert rule.id == "x"
    assert rule.name == "Script run from the uploads folder"
    assert rule.category is ActivityCategory.EXPLOITATION
    assert rule.severity is Severity.CRITICAL
    assert rule.confidence == 1.0
    assert rule.match.all is not None
    assert [(c.field_name, c.regex, c.min, c.max) for c in rule.match.all] == [
        ("path_decoded", r"^/uploads/.+\.php$", None, None),
        ("status", None, 200.0, None),
        ("status", None, None, 299.0),
    ]


@pytest.mark.parametrize(
    "value", ['a"b', "a\\b", "a: b", "a #b", "{x}", " lead", "ünï", "a\u0085b", "a\x7fb", "/\udcff"]
)
def test_awkward_values_load_back_exactly(value: str) -> None:
    rule = _loaded(rule_block(_draft(Condition("path", Test.EQUALS, value), name="z" + value), "x"))

    assert rule.match.all is not None
    assert rule.match.all[0].equals == value
    assert rule.name == "z" + value


@pytest.mark.parametrize("name", ["on", "yes", "null", "123"])
def test_ids_yaml_would_retype_stay_strings(name: str) -> None:
    rule_id = rule_id_for(name, ())

    assert _loaded(rule_block(_draft(name=name), rule_id)).id == name


def test_any_of_is_written_as_strings() -> None:
    rule = _loaded(rule_block(_draft(Condition("status", Test.ANY_OF, "302, 303")), "x"))

    assert rule.match.all is not None
    assert rule.match.all[0].any_of == ["302", "303"]


def test_any_matches_a_request_that_meets_one_condition() -> None:
    either = (Condition("path", Test.EQUALS, "/a"), Condition("path", Test.EQUALS, "/b"))

    assert _labels(_loaded(rule_block(_draft(*either, mode="any"), "x")), _request("/b")) == {"x"}
    assert "x" not in _labels(_loaded(rule_block(_draft(*either), "x")), _request("/b"))


def test_optional_fields_are_written_only_when_given() -> None:
    bare = rule_block(_draft(), "x")

    assert "confidence" not in bare
    assert "owasp" not in bare
    assert "references" not in bare

    rule = _loaded(
        rule_block(_draft(confidence="0.8", owasp="A05:2025", references="CAPEC-66, T1"), "x")
    )

    assert rule.confidence == 0.8
    assert rule.owasp == "A05:2025"
    assert rule.references == ("CAPEC-66", "T1")


def test_tests_follow_the_field() -> None:
    # Through the module: pytest would collect a bare `tests_for` as a test.
    tests_for = rule_draft.tests_for

    assert tests_for("status") == (Test.MIN, Test.MAX, Test.ANY_OF)
    assert tests_for("bytes_sent") == (Test.MIN, Test.MAX, Test.ANY_OF)
    assert tests_for("path_decoded")[0] is Test.CONTAINS
    assert set(FORM_FIELDS) <= MATCH_FIELDS


def _line(target: str, *, status: int = 200) -> NormalizedEvent:
    path, _, query = target.partition("?")
    return NormalizedEvent(
        timestamp=datetime(2026, 8, 23, tzinfo=UTC),
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", 7),
        method="GET",
        path=path,
        query=query or None,
        status=status,
        user_agent="curl/8.4.0",
    )


def test_a_line_s_path_and_query_are_ticked() -> None:
    parts = line_parts(_line("/search?q=%3Cscript%3E"))

    assert [(part.field, part.value) for part in parts] == [
        ("path_decoded", "/search"),
        ("query_decoded", "q=<script>"),
        ("status", "200"),
        ("method", "GET"),
        ("user_agent_decoded", "curl/8.4.0"),
    ]
    assert {part.field for part in parts if part.ticked} == {"path_decoded", "query_decoded"}


def test_without_a_query_only_the_path_is_ticked() -> None:
    parts = line_parts(_line("/admin"))

    assert "query_decoded" not in [part.field for part in parts]
    assert [part.field for part in parts if part.ticked] == ["path_decoded"]


def test_status_becomes_is_one_of() -> None:
    assert conditions_from([LinePart("status", "200", ticked=True)]) == (
        Condition("status", Test.ANY_OF, "200"),
    )


def test_unticked_parts_make_no_condition() -> None:
    assert conditions_from([LinePart("method", "GET", ticked=False)]) == ()


def test_a_rule_from_a_line_matches_that_line() -> None:
    event = _line("/search?q=%3Cscript%3E")
    draft = _draft(*conditions_from(line_parts(event)))

    assert _labels(_loaded(rule_block(draft, "from_line")), event) == {"from_line"}


@pytest.mark.parametrize("pattern", ["a{4294967296}", "(" * 2000], ids=["repeat", "nested"])
def test_a_pattern_too_large_to_compile_is_a_problem(pattern: str) -> None:
    draft = _draft(Condition("path", Test.REGEX, pattern))

    assert problems(draft) == ("Condition 1: the pattern is too large to use.",)


def test_an_icon_is_written_after_the_severity() -> None:
    block = rule_block(_draft(icon="skull"), "probe")
    assert block.splitlines()[3:5] == ["  severity: high", '  icon: "skull"']
    assert _loaded(block).icon == "skull"


def test_no_icon_writes_no_line() -> None:
    block = rule_block(_draft(), "probe")
    assert "icon:" not in block
    assert _loaded(block).icon is None


def test_a_file_icon_loads_back_exactly() -> None:
    assert _loaded(rule_block(_draft(icon="file:my logo.svg"), "probe")).icon == "file:my logo.svg"
