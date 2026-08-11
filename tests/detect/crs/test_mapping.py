"""Tests for the CRS family to activity-category table.

The table is the contestable part of adopting CRS: it decides what a detection
is *called*, and a category change starts a new episode. These lock the bounds
rather than the opinions — an entry can be argued with, but the shape it has to
keep cannot.
"""

from __future__ import annotations

import pytest

from logarc.core.activity import ActivityCategory, Severity
from logarc.detect.crs.mapping import (
    _FAMILY_CATEGORY,
    _UNMAPPED,
    KNOWN_FAMILIES,
    RESCUE_CONFIDENCE,
    category_for_family,
    severity_for,
)


@pytest.mark.parametrize(
    ("family", "category"),
    [
        ("attack-sqli", ActivityCategory.INJECTION),
        ("attack-xss", ActivityCategory.INJECTION),
        ("attack-injection-php", ActivityCategory.INJECTION),
        ("attack-rce", ActivityCategory.INJECTION),
        ("attack-lfi", ActivityCategory.PATH_TRAVERSAL),
        ("attack-ssrf", ActivityCategory.SSRF),
        ("attack-reputation-scanner", ActivityCategory.RECONNAISSANCE),
        ("attack-injection-java", ActivityCategory.INJECTION),
    ],
)
def test_a_mapped_family_names_a_category(family: str, category: ActivityCategory) -> None:
    assert category_for_family(family) is category


def test_a_tag_that_reads_like_a_catch_all_is_withheld() -> None:
    """Regression, found on real traffic rather than reasoned out.

    `attack-generic` sounds like family 934 and belongs to 905 and rule 911100,
    "Method is not allowed by policy". Mapped to `injection`, seven `CONNECT`
    proxy-abuse requests in 365 lines of real 2010 WordPress traffic were
    reported as injection attempts. 934's own payloads carry
    `attack-injection-generic`.
    """
    assert category_for_family("attack-generic") is None
    assert category_for_family("attack-injection-generic") is ActivityCategory.INJECTION


@pytest.mark.parametrize("family", sorted(_UNMAPPED))
def test_a_withheld_family_names_nothing(family: str) -> None:
    """These are still reported as evidence; they just may not rename a request.

    `attack-protocol` is the important one — it is the largest group in the
    request rules and fires on request lines that are merely unusual, so letting
    it override ordinary traffic would turn a benign corpus hostile in bulk.
    """
    assert category_for_family(family) is None


def test_every_family_the_ruleset_carries_is_accounted_for() -> None:
    """Mapped or withheld, but never overlooked.

    The first draft of this table came from a grep that truncated at the hyphen,
    so `attack-injection-php` was absent and every PHP payload silently went
    unrescued while the feature looked like it worked. A CRS version that adds a
    tag should fail here rather than quietly narrowing coverage.
    """
    classified = set(_FAMILY_CATEGORY) | set(_UNMAPPED)

    assert KNOWN_FAMILIES - classified == set()
    assert classified - KNOWN_FAMILIES == set()


def test_an_unrecognised_family_is_a_no_op_rather_than_an_error() -> None:
    """CRS gains tags between releases; a version bump must not become a crash."""
    assert category_for_family("attack-something-invented-later") is None
    assert category_for_family(None) is None


def test_a_rescued_label_is_less_certain_than_any_hostile_rule() -> None:
    """A rescue infers a category through the table; a rule asserted one. Where
    both appear the difference should be visible."""
    assert RESCUE_CONFIDENCE < 1.0


@pytest.mark.parametrize(
    ("word", "severity"),
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("error", Severity.HIGH),
        ("warning", Severity.MEDIUM),
        ("notice", Severity.LOW),
    ],
)
def test_crs_severity_words_read_onto_the_ladder(word: str, severity: Severity) -> None:
    assert severity_for(word) is severity


def test_an_unknown_severity_does_not_fall_to_the_floor() -> None:
    """INFO would hide the detection beneath the benign classifications, and a
    rule severe enough to carry a message is not INFO."""
    assert severity_for("unheard-of") is Severity.MEDIUM
    assert severity_for(None) is Severity.MEDIUM
