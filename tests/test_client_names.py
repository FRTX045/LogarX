"""The names a reader gives client addresses: one small file of notes in the case folder."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from logarx.bookmarks import FILE_NAME as BOOKMARKS_FILE
from logarx.client_names import (
    EMPTY,
    FILE_NAME,
    UNREADABLE_NAME,
    ClientNameWriteError,
    Names,
    apply,
    forget,
    labelled,
    load,
    matching,
    rename,
    shown,
)
from logarx.session_names import FILE_NAME as SESSION_NAMES_FILE

CLIENT = "203.0.113.47"
OTHER = "198.51.100.7"
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def named(name: str, client: str = CLIENT) -> Any:
    """A change naming `client`, as the Rename client window makes one."""
    return lambda names: rename(names, client, name, now=NOW)


def write(folder: Path, content: Any) -> None:
    (folder / FILE_NAME).write_text(json.dumps(content), encoding="utf-8")


def read(folder: Path) -> Any:
    return json.loads((folder / FILE_NAME).read_text(encoding="utf-8"))


# -- naming ---------------------------------------------------------------------


def test_no_file_names_nothing_and_is_no_problem(tmp_path: Path) -> None:
    loaded = load(tmp_path)

    assert loaded.names == EMPTY
    assert loaded.problem is None
    assert loaded.names.name_for(CLIENT) is None


def test_a_rename_is_read_back(tmp_path: Path) -> None:
    apply(tmp_path, named("Office VPN"))

    assert load(tmp_path).names.name_for(CLIENT) == "Office VPN"
    assert load(tmp_path).names.name_for(OTHER) is None


def test_the_file_is_the_documented_shape(tmp_path: Path) -> None:
    apply(tmp_path, named("Office VPN"))

    assert read(tmp_path) == {
        "version": 1,
        "names": [{"client": CLIENT, "name": "Office VPN", "named": "2026-10-29T12:00:00+00:00"}],
    }


def test_a_blank_name_removes_it(tmp_path: Path) -> None:
    apply(tmp_path, named("Office VPN"))

    apply(tmp_path, named("   "))

    assert load(tmp_path).names.name_for(CLIENT) is None
    assert read(tmp_path)["names"] == []


def test_forgetting_removes_it(tmp_path: Path) -> None:
    apply(tmp_path, named("Office VPN"))
    apply(tmp_path, named("Monitor", OTHER))

    apply(tmp_path, lambda names: forget(names, CLIENT))

    assert load(tmp_path).names.name_for(CLIENT) is None
    assert load(tmp_path).names.name_for(OTHER) == "Monitor"


def test_spaces_are_collapsed_and_trimmed(tmp_path: Path) -> None:
    apply(tmp_path, named("  Office \t  VPN\n "))

    assert load(tmp_path).names.name_for(CLIENT) == "Office VPN"


def test_a_name_over_sixty_characters_is_refused() -> None:
    assert rename(EMPTY, CLIENT, "x" * 60, now=NOW).name_for(CLIENT) == "x" * 60
    with pytest.raises(ValueError, match="60"):
        rename(EMPTY, CLIENT, "x" * 61, now=NOW)


def test_the_last_of_two_entries_for_one_address_wins_and_a_rename_leaves_one(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        {
            "version": 1,
            "names": [
                {"client": CLIENT, "name": "Old"},
                {"client": CLIENT, "name": "Newer"},
            ],
        },
    )
    assert load(tmp_path).names.name_for(CLIENT) == "Newer"
    assert load(tmp_path).names.as_map() == {CLIENT: "Newer"}

    apply(tmp_path, named("Newest"))

    assert [entry["name"] for entry in read(tmp_path)["names"]] == ["Newest"]


def test_what_this_version_does_not_understand_is_written_back(tmp_path: Path) -> None:
    unusable = [
        {"client": CLIENT, "name": "  "},
        {"client": "", "name": "No client"},
        {"client": OTHER},
        "not even an entry",
    ]
    write(
        tmp_path,
        {
            "version": 1,
            "colour": 3,
            "names": [{"client": OTHER, "name": "Monitor", "note": "x"}, *unusable],
        },
    )
    assert load(tmp_path).names.name_for(OTHER) == "Monitor"

    apply(tmp_path, named("Office VPN"))

    after = read(tmp_path)
    assert after["colour"] == 3
    assert {"client": OTHER, "name": "Monitor", "note": "x"} in after["names"]
    for entry in unusable:
        assert entry in after["names"]
    assert load(tmp_path).names.name_for(CLIENT) == "Office VPN"


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
    apply(tmp_path, named("Office VPN"))
    assert (tmp_path / UNREADABLE_NAME).read_bytes() == b"{oops"
    assert load(tmp_path).names.name_for(CLIENT) == "Office VPN"

    (tmp_path / FILE_NAME).write_bytes(b"second")
    apply(tmp_path, named("Again"))

    assert (tmp_path / UNREADABLE_NAME).read_bytes() == b"{oops"
    assert (tmp_path / "client-names.unreadable.2.json").read_bytes() == b"second"


def test_a_folder_that_refuses_writes_raises_and_keeps_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apply(tmp_path, named("Office VPN"))
    before = (tmp_path / FILE_NAME).read_bytes()

    def refuse(*_: object) -> None:
        raise PermissionError("Access is denied")

    monkeypatch.setattr(Path, "replace", refuse)
    with pytest.raises(ClientNameWriteError):
        apply(tmp_path, named("Again"))
    assert (tmp_path / FILE_NAME).read_bytes() == before
    assert sorted(path.name for path in tmp_path.iterdir()) == [FILE_NAME]


def test_two_windows_each_keep_what_the_other_saved(tmp_path: Path) -> None:
    """Each window's copy is stale by the time it saves; the file is read again."""
    assert load(tmp_path).names == load(tmp_path).names == EMPTY

    apply(tmp_path, named("From the first", CLIENT))
    apply(tmp_path, named("From the second", OTHER))

    names = load(tmp_path).names
    assert names.name_for(CLIENT) == "From the first"
    assert names.name_for(OTHER) == "From the second"


def test_session_names_and_bookmarks_are_not_touched(tmp_path: Path) -> None:
    (tmp_path / BOOKMARKS_FILE).write_bytes(b'{"version": 1}')
    (tmp_path / SESSION_NAMES_FILE).write_bytes(b'{"version": 1}')

    apply(tmp_path, named("Office VPN"))

    assert (tmp_path / BOOKMARKS_FILE).read_bytes() == b'{"version": 1}'
    assert (tmp_path / SESSION_NAMES_FILE).read_bytes() == b'{"version": 1}'


def test_names_compare_by_what_they_hold() -> None:
    assert Names(entries=()) == EMPTY


# -- finding and showing ----------------------------------------------------------


def test_two_addresses_may_share_a_name() -> None:
    names = rename(EMPTY, CLIENT, "Corporate NAT", now=NOW)
    names = rename(names, OTHER, "Corporate NAT", now=NOW)

    assert names.as_map() == {CLIENT: "Corporate NAT", OTHER: "Corporate NAT"}


def test_matching_is_a_case_insensitive_phrase() -> None:
    names = rename(EMPTY, "10.0.0.1", "Office VPN", now=NOW)
    names = rename(names, "10.0.0.2", "Attacker 2", now=NOW)

    for typed in ("office", "OFFICE vpn", " office   vpn ", '"office vpn"'):
        assert names.matching(typed) == {"10.0.0.1"}, typed
    assert names.matching("attacker 2") == {"10.0.0.2"}
    assert names.matching("vpn office") == frozenset()
    assert names.matching("") == frozenset()
    assert matching(names.as_map(), "office") == {"10.0.0.1"}


def test_labelled_and_shown() -> None:
    assert labelled("10.0.0.1", "Office VPN") == "Office VPN (10.0.0.1)"
    assert labelled("10.0.0.1", None) == "10.0.0.1"
    given = {"10.0.0.1": "Office VPN"}
    assert shown("10.0.0.1", given, on=True) == "Office VPN"
    assert shown("10.0.0.1", given, on=False) == "10.0.0.1"
    assert shown("10.0.0.2", given, on=True) == "10.0.0.2"
