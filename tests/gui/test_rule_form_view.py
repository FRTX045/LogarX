"""What the Add a rule window says, checked without a display."""

from __future__ import annotations

from logarc.core.activity import ActivityCategory
from logarc.gui.rule_form_view import (
    CATEGORY_LABELS,
    FIELD_LABELS,
    TEST_LABELS,
    finds_caption,
    id_caption,
    parts_heading,
)
from logarc.rule_draft import FORM_FIELDS, Test
from logarc.rule_finds import Find


def test_every_form_field_has_a_label() -> None:
    assert list(FIELD_LABELS) == list(FORM_FIELDS)
    assert FIELD_LABELS["path"] == "Path, as logged"


def test_every_test_has_a_label() -> None:
    assert set(TEST_LABELS) == set(Test)


def test_every_category_but_unknown_has_a_label() -> None:
    assert set(CATEGORY_LABELS) == set(ActivityCategory) - {ActivityCategory.UNKNOWN}


def test_finds_caption_while_running_and_after() -> None:
    assert finds_caption(Find(3, 1), running=True) == "3 matches from 1 client so far."
    assert finds_caption(Find(1, 2), running=False) == "1 match from 2 clients."
    assert finds_caption(None, running=False) == "Open a case to see what it matches."


def test_the_id_and_the_line_are_named() -> None:
    assert id_caption("probe") == "Saved with the id probe"
    assert parts_heading(42) == "Line 42: tick what makes it suspicious."
