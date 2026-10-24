"""The names a reader gives sessions: one small file of notes in the case folder."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from logarc.bookmarks import FILE_NAME as BOOKMARKS_FILE
from logarc.core.evidence import EvidenceRef
from logarc.session_names import (
    EMPTY,
    FILE_NAME,
    UNREADABLE_NAME,
    Names,
    SessionKey,
    SessionNameWriteError,
    apply,
    forget,
    load,
    rename,
    tidy,
)

KEY = SessionKey("192.0.2.22", EvidenceRef("access.log", 1234))
OTHER = SessionKey("192.0.2.22", EvidenceRef("access.log", 2000))
NOW = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
LOGARC = "Configuration File Probe"


def named(name: str, key: SessionKey = KEY) -> Any:
    """A change naming `key`, as the Rename session window makes one."""
    return lambda names: rename(names, key, name, logarc_name=LOGARC, now=NOW)


def write(folder: Path, content: Any) -> None:
    (folder / FILE_NAME).write_text(json.dumps(content), encoding="utf-8")


def read(folder: Path) -> Any:
    return json.loads((folder / FILE_NAME).read_text(encoding="utf-8"))


# -- naming ---------------------------------------------------------------------


def test_no_file_names_nothing_and_is_no_problem(tmp_path: Path) -> None:
    loaded = load(tmp_path)

    assert loaded.names == EMPTY
    assert loaded.problem is None
    assert loaded.names.name_for(KEY) is None


def test_a_rename_is_read_back(tmp_path: Path) -> None:
    apply(tmp_path, named("Scanner"))

    assert load(tmp_path).names.name_for(KEY) == "Scanner"
    assert load(tmp_path).names.name_for(OTHER) is None


def test_the_file_is_the_documented_shape(tmp_path: Path) -> None:
    apply(tmp_path, named("Scanner hunting for config files"))

    assert read(tmp_path) == {
        "version": 1,
        "sessions": [
            {
                "client": "192.0.2.22",
                "first": "access.log:1234",
                "name": "Scanner hunting for config files",
                "named": "2026-10-24T10:00:00+00:00",
            }
        ],
    }


def test_logarcs_own_name_removes_the_readers(tmp_path: Path) -> None:
    """A pencil on logarc's own words would claim authorship of nothing."""
    apply(tmp_path, named("Scanner"))

    apply(tmp_path, named(f"  {LOGARC} "))

    assert load(tmp_path).names.name_for(KEY) is None
    assert read(tmp_path)["sessions"] == []


def test_a_blank_name_removes_the_readers(tmp_path: Path) -> None:
    apply(tmp_path, named("Scanner"))

    apply(tmp_path, named("   "))

    assert load(tmp_path).names.name_for(KEY) is None


def test_forgetting_removes_the_readers(tmp_path: Path) -> None:
    apply(tmp_path, named("Scanner"))
    apply(tmp_path, named("Mine", OTHER))

    apply(tmp_path, lambda names: forget(names, KEY))

    assert load(tmp_path).names.name_for(KEY) is None
    assert load(tmp_path).names.name_for(OTHER) == "Mine"


def test_spaces_are_collapsed_and_trimmed(tmp_path: Path) -> None:
    assert tidy("  Scanner \t looking\n ") == "Scanner looking"

    apply(tmp_path, named("  Scanner   looking  "))

    assert load(tmp_path).names.name_for(KEY) == "Scanner looking"


def test_a_name_over_sixty_characters_is_refused() -> None:
    assert rename(EMPTY, KEY, "x" * 60, logarc_name=LOGARC, now=NOW).name_for(KEY) == "x" * 60
    with pytest.raises(ValueError, match="60"):
        rename(EMPTY, KEY, "x" * 61, logarc_name=LOGARC, now=NOW)


def test_the_last_of_two_entries_for_one_key_wins_and_a_rename_leaves_one(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "version": 1,
            "sessions": [
                {"client": "192.0.2.22", "first": "access.log:1234", "name": "Old"},
                {"client": "192.0.2.22", "first": "access.log:1234", "name": "Newer"},
            ],
        },
    )
    assert load(tmp_path).names.name_for(KEY) == "Newer"

    apply(tmp_path, named("Newest"))

    assert [entry["name"] for entry in read(tmp_path)["sessions"]] == ["Newest"]


def test_what_this_version_does_not_understand_is_written_back(tmp_path: Path) -> None:
    unusable = [
        {"client": "192.0.2.22", "first": "nonsense", "name": "No line"},
        {"client": "192.0.2.22", "first": "access.log:7", "name": "  "},
        {"client": "", "first": "access.log:8", "name": "No client"},
        "not even an entry",
    ]
    write(
        tmp_path,
        {
            "version": 1,
            "colour": 3,
            "sessions": [
                {"client": "192.0.2.22", "first": "access.log:2000", "name": "Mine", "note": "x"},
                *unusable,
            ],
        },
    )
    loaded = load(tmp_path).names
    assert loaded.name_for(OTHER) == "Mine"
    assert loaded.name_for(SessionKey("192.0.2.22", EvidenceRef("access.log", 7))) is None

    apply(tmp_path, named("Scanner"))

    after = read(tmp_path)
    assert after["colour"] == 3
    assert {"client": "192.0.2.22", "first": "access.log:2000", "name": "Mine", "note": "x"} in (
        after["sessions"]
    )
    for entry in unusable:
        assert entry in after["sessions"]
    assert load(tmp_path).names.name_for(KEY) == "Scanner"


# -- the file -----------------------------------------------------------------


def test_an_unreadable_file_names_nothing_and_says_why(tmp_path: Path) -> None:
    (tmp_path / FILE_NAME).write_bytes(b"{oops")

    loaded = load(tmp_path)

    assert loaded.problem
    assert loaded.names == EMPTY


def test_a_file_that_is_not_an_object_is_unreadable(tmp_path: Path) -> None:
    write(tmp_path, ["a list"])

    assert load(tmp_path).problem


def test_the_next_rename_sets_an_unreadable_file_aside(tmp_path: Path) -> None:
    (tmp_path / FILE_NAME).write_bytes(b"{oops")
    apply(tmp_path, named("Scanner"))
    assert (tmp_path / UNREADABLE_NAME).read_bytes() == b"{oops"
    assert load(tmp_path).names.name_for(KEY) == "Scanner"

    (tmp_path / FILE_NAME).write_bytes(b"second")
    apply(tmp_path, named("Again"))

    assert (tmp_path / UNREADABLE_NAME).read_bytes() == b"{oops"
    assert (tmp_path / "session-names.unreadable.2.json").read_bytes() == b"second"


def test_a_folder_that_refuses_writes_raises_and_keeps_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apply(tmp_path, named("Scanner"))
    before = (tmp_path / FILE_NAME).read_bytes()

    def refuse(*_: object) -> None:
        raise PermissionError("Access is denied")

    monkeypatch.setattr(Path, "replace", refuse)
    with pytest.raises(SessionNameWriteError):
        apply(tmp_path, named("Again"))
    assert (tmp_path / FILE_NAME).read_bytes() == before
    assert sorted(path.name for path in tmp_path.iterdir()) == [FILE_NAME]


def test_two_windows_each_keep_what_the_other_saved(tmp_path: Path) -> None:
    """Each window's copy is stale by the time it saves; the file is read again."""
    first_window = load(tmp_path).names
    second_window = load(tmp_path).names
    assert first_window == second_window == EMPTY

    apply(tmp_path, named("From the first", KEY))
    apply(tmp_path, named("From the second", OTHER))

    names = load(tmp_path).names
    assert names.name_for(KEY) == "From the first"
    assert names.name_for(OTHER) == "From the second"


def test_bookmarks_are_not_touched(tmp_path: Path) -> None:
    (tmp_path / BOOKMARKS_FILE).write_bytes(b'{"version": 1}')

    apply(tmp_path, named("Scanner"))

    assert (tmp_path / BOOKMARKS_FILE).read_bytes() == b'{"version": 1}'


def test_names_compare_by_what_they_hold() -> None:
    assert Names(entries=()) == EMPTY


# -- which session a name belongs to ---------------------------------------------


def lines(*numbers: int) -> frozenset[EvidenceRef]:
    return frozenset(EvidenceRef("access.log", number) for number in numbers)


def test_a_name_belongs_to_the_session_that_holds_its_line() -> None:
    """A name given under a time filter is keyed on the clipped session's first
    line; the whole visit holds that line, so it keeps the name once the filter
    goes."""
    names = rename(EMPTY, KEY, "Scanner", logarc_name=LOGARC, now=NOW)

    assert names.name_in("192.0.2.22", lines(1200, 1234, 1300)) == "Scanner"
    assert names.name_in("192.0.2.22", lines(1200, 1300)) is None
    assert names.name_in("192.0.2.99", lines(1234)) is None


def test_the_name_given_last_wins_inside_one_session() -> None:
    names = rename(EMPTY, KEY, "Earlier", logarc_name=LOGARC, now=NOW)
    names = rename(names, OTHER, "Later", logarc_name=LOGARC, now=NOW)

    assert names.name_in("192.0.2.22", lines(1234, 2000)) == "Later"


def test_renaming_a_session_replaces_every_name_inside_it() -> None:
    names = rename(EMPTY, KEY, "Under one filter", logarc_name=LOGARC, now=NOW)
    names = rename(names, OTHER, "Under another", logarc_name=LOGARC, now=NOW)
    whole = SessionKey("192.0.2.22", EvidenceRef("access.log", 1000))

    renamed = rename(
        names, whole, "The whole visit", logarc_name=LOGARC, now=NOW, within=lines(1000, 1234, 2000)
    )

    assert [entry.name for entry in renamed.entries] == ["The whole visit"]
    assert forget(names, whole, within=lines(1000, 1234, 2000)).entries == ()
