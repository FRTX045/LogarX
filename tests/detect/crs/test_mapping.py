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
    _RULE_CATEGORY,
    _UNMAPPED,
    KNOWN_FAMILIES,
    RESCUE_CONFIDENCE,
    category_for,
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


@pytest.mark.parametrize(
    ("rule_id", "category"),
    [
        # Path traversal proper, and reading a file the server did not mean to
        # serve. Both are `path_traversal` in this taxonomy.
        (930100, ActivityCategory.PATH_TRAVERSAL),
        (930110, ActivityCategory.PATH_TRAVERSAL),
        (930120, ActivityCategory.PATH_TRAVERSAL),
        (930121, ActivityCategory.PATH_TRAVERSAL),
        # Restricted files: source, manifests, credentials, VCS history. Asking
        # for `/.env` is not traversal, and this project already calls it
        # reconnaissance in `config_file_exposure`.
        (930130, ActivityCategory.RECONNAISSANCE),
        (930140, ActivityCategory.RECONNAISSANCE),
    ],
)
def test_the_lfi_family_is_split_by_rule(rule_id: int, category: ActivityCategory) -> None:
    """`attack-lfi` covers two behaviours and the family tag cannot tell them apart.

    Mapping the whole family to `path_traversal` put every `/.env`,
    `/Dockerfile` and `/.htaccess` probe in the wrong category and made CRS
    contradict the native rule that had already classified the same URL. On one
    labelled corpus that was eight of the twelve rescues that were wrong.
    """
    assert category_for(rule_id, "attack-lfi") is category


def test_a_rule_override_cannot_resurrect_a_withheld_family() -> None:
    """The bound the whole table rests on, kept as the override layer is added.

    An override may redirect a detection that was already allowed to speak. It
    may not give a voice to a family that was deliberately silenced, or
    `attack-protocol` would return through the back door on any rule id that
    happened to be listed.
    """
    assert category_for(930130, "attack-protocol") is None
    assert category_for(930130, "attack-something-invented-later") is None
    assert category_for(930130, None) is None


def test_an_unlisted_rule_falls_back_to_its_family() -> None:
    assert category_for(942100, "attack-sqli") is ActivityCategory.INJECTION
    assert category_for(0, "attack-ssrf") is ActivityCategory.SSRF


def test_every_override_names_a_category_its_family_could_have_named() -> None:
    """An override that changes nothing is a dead entry and should be removed."""
    for rule_id, category in _RULE_CATEGORY.items():
        assert category_for(rule_id, "attack-lfi") is category
        assert category is not _FAMILY_CATEGORY["attack-lfi"], (
            f"override for {rule_id} matches the family default and is redundant"
        )


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
