"""Tests for the saved-format library.

The library is the only part of this feature the engine never reads: a case
carries its own copy of the format it was ingested with, so losing this file
costs the user their saved definitions and nothing else. These tests hold that
line — and hold the file to being reported when damaged rather than quietly
replaced with an empty one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from logarc.parsers.apache import COMBINED, COMMON
from logarc.parsers.library import (
    LIBRARY_NAME,
    FormatLibraryError,
    library_path,
    load_library,
    logarc_home,
    save_library,
)
from logarc.parsers.spec import LogFormatSpec

OFFICE = LogFormatSpec(name="log-kantor", directive=COMBINED, description="the office")
GATEWAY = LogFormatSpec(name="gateway", directive=COMMON)


def test_a_saved_format_comes_back() -> None:
    save_library([OFFICE, GATEWAY])

    assert load_library() == [OFFICE, GATEWAY]


def test_the_library_lives_under_logarc_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOGARC_HOME", str(tmp_path / "elsewhere"))

    assert logarc_home() == tmp_path / "elsewhere"
    assert library_path() == tmp_path / "elsewhere" / LIBRARY_NAME


def test_no_library_file_means_no_saved_formats() -> None:
    """A first run is not an error, and must not be reported as one."""
    assert not library_path().exists()

    assert load_library() == []


def test_saving_creates_the_directory_it_needs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOGARC_HOME", str(tmp_path / "not" / "yet" / "there"))

    save_library([OFFICE])

    assert load_library() == [OFFICE]


def test_a_damaged_library_names_the_file_rather_than_reporting_none() -> None:
    """Starting from empty would throw away the user's saved work at exactly
    the moment they most need to be told something is wrong with it."""
    path = library_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(FormatLibraryError) as raised:
        load_library()

    assert str(path) in str(raised.value)


def test_an_entry_this_logarc_cannot_read_names_the_file() -> None:
    path = library_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "formats": [{"version": 1, "kind": "runes", "name": "x"}]}),
        encoding="utf-8",
    )

    with pytest.raises(FormatLibraryError) as raised:
        load_library()

    assert str(path) in str(raised.value)
    assert "runes" in str(raised.value)


def test_a_library_from_a_newer_logarc_is_refused_by_version() -> None:
    path = library_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 99, "formats": []}), encoding="utf-8")

    with pytest.raises(FormatLibraryError) as raised:
        load_library()

    assert "99" in str(raised.value)


def test_two_saved_formats_cannot_share_a_name() -> None:
    """The name is how a case finds its way back to the library entry to
    compare against, so a duplicate would make the drift check meaningless."""
    with pytest.raises(FormatLibraryError, match="log-kantor"):
        save_library([OFFICE, LogFormatSpec(name="log-kantor", directive=COMMON)])


def test_a_format_with_no_name_is_refused() -> None:
    with pytest.raises(FormatLibraryError, match="name"):
        save_library([LogFormatSpec(name="  ", directive=COMMON)])


def test_a_saved_format_that_cannot_compile_is_refused() -> None:
    """Loading tolerates a broken definition because a case may hold one.
    Saving does not: nothing forces a user to store one, and catching it here
    is the difference between a message and a log that quarantines every line."""
    with pytest.raises(FormatLibraryError, match="no directives"):
        save_library([LogFormatSpec(name="empty", directive="no percent signs here")])


def test_a_file_that_cannot_be_written_is_the_library_s_own_error() -> None:
    """A read-only folder or a full disk fails in the filesystem. Every caller
    handles the library's error and says so; an `OSError` reached none of them."""
    library_path().mkdir(parents=True)

    with pytest.raises(FormatLibraryError, match="could not be written"):
        save_library([OFFICE])


def test_the_file_is_json_a_person_can_read_and_edit() -> None:
    save_library([OFFICE])

    text = library_path().read_text(encoding="utf-8")

    assert "\n" in text, "written on one line, so it cannot be edited by hand"
    assert json.loads(text)["formats"][0]["directive"] == COMBINED


def test_the_suite_cannot_reach_the_real_library(tmp_path: Path) -> None:
    """Proves the autouse fixture in `tests/conftest.py` is actually in force.

    Every other test here writes a library file. Without the redirect they
    would write the user's own, and the ones that assert on its contents would
    pass or fail on what that user happened to have saved.
    """
    assert tmp_path in library_path().parents


def test_without_an_override_the_library_sits_in_the_platform_config_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LOGARC_HOME", raising=False)

    assert logarc_home().name == "logarc"
    assert logarc_home() != Path("logarc"), "resolved to a bare relative path"
