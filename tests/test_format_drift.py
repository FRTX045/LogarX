"""Noticing that a case was read with a format that has since been edited.

The case reads back correctly either way — it carries its own copy. This is
only about telling the investigator that the format they are looking at today
is not the one this case was made with, because otherwise the two would be
silently assumed to be the same thing.
"""

from __future__ import annotations

from dataclasses import replace

from logarc.formats import drifted_sources
from logarc.parsers.apache import COMBINED, COMMON
from logarc.parsers.spec import LogFormatSpec, spec_to_dict
from logarc.storage.case import SourceRecord

JANUARY = LogFormatSpec(name="log-kantor", directive=COMMON)
JUNE = LogFormatSpec(name="log-kantor", directive=COMBINED)

SOURCE = SourceRecord(
    file_id="access.log",
    original_path="/logs/access.log",
    sha256="a" * 64,
    size_bytes=2048,
    compression="none",
    log_format="log-kantor",
    lines_read=100,
    events_parsed=100,
    lines_quarantined=0,
    format_spec=spec_to_dict(JANUARY),
)


def test_an_edited_format_is_reported() -> None:
    (drift,) = drifted_sources([SOURCE], library=[JUNE])

    assert drift.file_id == "access.log"
    assert drift.name == "log-kantor"
    assert drift.stored == JANUARY
    assert drift.current == JUNE


def test_an_unchanged_format_is_not_reported() -> None:
    assert drifted_sources([SOURCE], library=[JANUARY]) == []


def test_a_deleted_format_is_not_reported() -> None:
    """There is nothing to compare against, and the case reads correctly from
    its own copy. Warning here would train the user to dismiss warnings."""
    assert drifted_sources([SOURCE], library=[]) == []


def test_a_source_with_no_stored_definition_is_not_reported() -> None:
    """A case from before definitions were stored has only a name. It cannot be
    known whether the format changed, and guessing either way would be wrong."""
    older = replace(SOURCE, format_spec=None)

    assert drifted_sources([older], library=[JUNE]) == []


def test_a_stored_definition_this_logarc_cannot_read_is_not_reported() -> None:
    """Written by a newer logarc. Nothing can be said about whether it drifted,
    and the evidence path already handles the line itself."""
    from_the_future = replace(SOURCE, format_spec={"version": 99, "kind": "logformat"})

    assert drifted_sources([from_the_future], library=[JUNE]) == []


def test_every_drifted_source_is_reported_not_only_the_first() -> None:
    other = replace(SOURCE, file_id="access.log.1")

    drifts = drifted_sources([SOURCE, other], library=[JUNE])

    assert [drift.file_id for drift in drifts] == ["access.log", "access.log.1"]


def test_the_saved_library_is_read_when_none_is_given() -> None:
    """How the GUI and the CLI actually call it: they hold the manifest, and
    the library is whatever the user has saved right now."""
    from logarc.parsers.library import save_library

    save_library([JUNE])

    (drift,) = drifted_sources([SOURCE])

    assert drift.current == JUNE
