"""A case's bookmarks: the file they live in, and the changes made to it.

Checked without a display, as `logarc.bookmarks` has no Qt: what is kept, what is
set aside, and what two windows writing one file end up with are decisions, not
drawing.
"""

from __future__ import annotations

import json
from dataclasses import replace as changed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from logarc.bookmarks import (
    DEFAULT,
    EMPTY,
    FILE_NAME,
    NAME_LIMIT,
    UNREADABLE_NAME,
    Bookmark,
    BookmarkWriteError,
    CategoryError,
    Kind,
    add,
    add_category,
    apply,
    delete_category,
    load,
    matches,
    parse_ref,
    remove,
    rename_category,
    replace,
)
from logarc.core.evidence import EvidenceRef
from logarc.core.window import TimeWindow

SAVED = datetime(2026, 10, 19, 14, 2, 11, tzinfo=UTC)


def client_mark(client: str, *, note: str = "", category: str = DEFAULT, id: str = "") -> Bookmark:
    return Bookmark(
        id=id or f"c-{client}",
        kind=Kind.CLIENT,
        category=category,
        said="50 requests",
        note=note,
        saved=SAVED,
        client=client,
    )


def activity_mark(
    *, line: EvidenceRef, note: str = "", category: str = DEFAULT, id: str = "a-1"
) -> Bookmark:
    return Bookmark(
        id=id,
        kind=Kind.ACTIVITY,
        category=category,
        said="Credential Attack · 6 requests",
        note=note,
        saved=SAVED,
        client="192.0.2.23",
        line=line,
        at=datetime(2026, 3, 10, 19, 12, 18, tzinfo=UTC),
    )


def raw_mark(**fields: Any) -> dict[str, Any]:
    return {
        "id": "a",
        "kind": "client",
        "category": DEFAULT,
        "client": "10.0.0.9",
        "said": "",
        "note": "",
        "saved": "2026-10-19T14:02:11Z",
        **fields,
    }


def write(folder: Path, content: Any) -> None:
    (folder / FILE_NAME).write_text(json.dumps(content), encoding="utf-8")


def read(folder: Path) -> Any:
    return json.loads((folder / FILE_NAME).read_text(encoding="utf-8"))


# -- the file -----------------------------------------------------------------


def test_no_file_is_an_empty_shelf_and_no_problem(tmp_path: Path) -> None:
    loaded = load(tmp_path)
    assert loaded.shelf == EMPTY
    assert loaded.problem is None
    assert [c.name for c in EMPTY.categories] == [DEFAULT]


def test_a_shelf_survives_a_round_trip(tmp_path: Path) -> None:
    mark = activity_mark(line=EvidenceRef("access:2024.log", 2014), note="lockout held")
    apply(tmp_path, lambda shelf: add(shelf, mark))
    assert load(tmp_path).shelf.bookmarks == (mark,)


def test_a_search_keeps_its_range_and_the_whole_case_reads_as_none(tmp_path: Path) -> None:
    narrowed = TimeWindow(
        datetime(2026, 3, 9, 14, 0, tzinfo=UTC), datetime(2026, 3, 9, 15, 0, tzinfo=UTC)
    )
    marks = [
        Bookmark(
            id=name,
            kind=Kind.SEARCH,
            category=DEFAULT,
            said="path:/admin",
            note="",
            saved=SAVED,
            query="path:/admin",
            range=window,
        )
        for name, window in (("narrow", narrowed), ("whole", None))
    ]
    apply(tmp_path, lambda shelf: add(add(shelf, marks[0]), marks[1]))
    assert load(tmp_path).shelf.bookmarks == tuple(marks)
    assert [entry["range"] for entry in read(tmp_path)["bookmarks"]][1] is None


def test_times_are_written_as_utc(tmp_path: Path) -> None:
    apply(tmp_path, lambda shelf: add(shelf, client_mark("10.0.0.1")))
    assert read(tmp_path)["bookmarks"][0]["saved"] == "2026-10-19T14:02:11Z"


def test_fields_this_version_does_not_know_survive_a_save(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "version": 1,
            "future": [1],
            "categories": [{"name": DEFAULT, "colour": 0, "icon": "x"}],
            "bookmarks": [raw_mark(id="a", pinned=True), {"kind": "hologram", "id": "b"}],
        },
    )
    apply(tmp_path, lambda shelf: add(shelf, client_mark("10.0.0.1")))
    stored = read(tmp_path)
    assert stored["future"] == [1]
    assert stored["categories"][0]["icon"] == "x"
    assert {"kind": "hologram", "id": "b"} in stored["bookmarks"]
    assert next(b for b in stored["bookmarks"] if b["id"] == "a")["pinned"] is True


def test_a_bookmark_in_a_category_the_file_does_not_list_still_has_one(tmp_path: Path) -> None:
    write(tmp_path, {"version": 1, "categories": [], "bookmarks": [raw_mark(category="Lost")]})
    shelf = load(tmp_path).shelf
    assert [c.name for c in shelf.categories] == [DEFAULT, "Lost"]


def test_an_unreadable_file_is_set_aside_not_overwritten(tmp_path: Path) -> None:
    (tmp_path / FILE_NAME).write_bytes(b"{not json")
    loaded = load(tmp_path)
    assert loaded.problem
    assert loaded.shelf == EMPTY
    apply(tmp_path, lambda shelf: add(shelf, client_mark("10.0.0.1")))
    assert (tmp_path / UNREADABLE_NAME).read_bytes() == b"{not json"
    assert [b["client"] for b in read(tmp_path)["bookmarks"]] == ["10.0.0.1"]


def test_a_second_unreadable_file_does_not_replace_the_first_one_set_aside(
    tmp_path: Path,
) -> None:
    (tmp_path / UNREADABLE_NAME).write_bytes(b"first")
    (tmp_path / FILE_NAME).write_bytes(b"second")
    apply(tmp_path, lambda shelf: add(shelf, client_mark("10.0.0.1")))
    assert (tmp_path / UNREADABLE_NAME).read_bytes() == b"first"
    assert (tmp_path / "bookmarks.unreadable.2.json").read_bytes() == b"second"


def test_a_change_reads_the_file_again_so_two_windows_keep_both(tmp_path: Path) -> None:
    load(tmp_path)  # the first window opens the case
    load(tmp_path)  # and so does the second
    apply(tmp_path, lambda shelf: add(shelf, client_mark("10.0.0.1")))
    apply(tmp_path, lambda shelf: add(shelf, client_mark("10.0.0.2")))
    assert {b.client for b in load(tmp_path).shelf.bookmarks} == {"10.0.0.1", "10.0.0.2"}


def test_a_folder_that_cannot_be_written_raises_and_keeps_the_old_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apply(tmp_path, lambda shelf: add(shelf, client_mark("10.0.0.1")))
    before = (tmp_path / FILE_NAME).read_bytes()

    def refuse(*_: object) -> None:
        raise PermissionError("Access is denied")

    monkeypatch.setattr(Path, "replace", refuse)
    with pytest.raises(BookmarkWriteError):
        apply(tmp_path, lambda shelf: add(shelf, client_mark("10.0.0.2")))
    assert (tmp_path / FILE_NAME).read_bytes() == before
    assert sorted(path.name for path in tmp_path.iterdir()) == [FILE_NAME]


def test_the_write_replaces_the_file_in_one_step(tmp_path: Path) -> None:
    replaced: list[tuple[str, str]] = []
    real = Path.replace

    def watched(source: Path, target: Path) -> Path:
        replaced.append((source.name, Path(target).name))
        return real(source, target)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "replace", watched)
        apply(tmp_path, lambda shelf: add(shelf, client_mark("10.0.0.1")))
    assert replaced == [(f"{FILE_NAME}.tmp", FILE_NAME)]


# -- anchors and finding ----------------------------------------------------------


def test_a_line_anchor_splits_on_the_last_colon() -> None:
    assert parse_ref("C:logs:a.log:12") == EvidenceRef("C:logs:a.log", 12)
    assert parse_ref("excerpt.log:2014") == EvidenceRef("excerpt.log", 2014)
    assert parse_ref("a.log:x") is None
    assert parse_ref("a.log:0") is None
    assert parse_ref("nocolon") is None


def test_an_ipv6_client_and_a_colon_in_the_file_name_survive_a_round_trip(
    tmp_path: Path,
) -> None:
    mark = Bookmark(
        id="r",
        kind=Kind.REQUEST,
        category=DEFAULT,
        said="",
        note="",
        saved=SAVED,
        client="2001:db8::1",
        line=EvidenceRef("C:logs:a.log", 7),
    )
    apply(tmp_path, lambda shelf: add(shelf, mark))
    assert load(tmp_path).shelf.bookmarks == (mark,)


def test_the_same_target_is_found_whatever_the_note() -> None:
    line = EvidenceRef("a.log", 3)
    shelf = add(EMPTY, activity_mark(line=line, note="first"))
    assert shelf.same_as(activity_mark(line=line, note="second", id="other")) is not None
    assert shelf.same_as(activity_mark(line=EvidenceRef("a.log", 4), id="other")) is None
    assert shelf.same_as(client_mark("192.0.2.23")) is None


def replace_saved(mark: Bookmark, *, hour: int) -> Bookmark:
    return changed(mark, saved=mark.saved.replace(hour=hour))


def test_the_newest_bookmark_of_a_client_names_its_mark() -> None:
    older = client_mark("10.0.0.1", category=DEFAULT, id="old")
    newer = replace_saved(client_mark("10.0.0.1", category="Login", id="new"), hour=15)
    shelf = add(add(EMPTY, older), newer)
    found = shelf.newest_for("10.0.0.1")
    assert found is not None and found.id == "new"


def test_a_filter_matches_every_word_in_any_field_ignoring_case() -> None:
    mark = client_mark("192.0.2.23", note="Same /login rhythm", category="Login attacks")
    assert matches(mark, "LOGIN rhythm")
    assert matches(mark, "192.0.2 attacks")
    assert matches(mark, "")
    assert not matches(mark, "login scanner")


# -- changes ------------------------------------------------------------------------


def test_adding_in_a_new_category_makes_it() -> None:
    shelf = add(EMPTY, client_mark("10.0.0.1", category="Login attacks"))
    assert [c.name for c in shelf.categories] == [DEFAULT, "Login attacks"]


def test_a_category_typed_in_another_case_joins_the_one_that_exists() -> None:
    shelf = add(
        add_category(EMPTY, "Login attacks"), client_mark("10.0.0.1", category="login ATTACKS")
    )
    assert [c.name for c in shelf.categories] == [DEFAULT, "Login attacks"]
    assert shelf.bookmarks[0].category == "Login attacks"


def test_replace_and_remove_go_by_id() -> None:
    shelf = add(EMPTY, client_mark("10.0.0.1", note="first"))
    shelf = replace(shelf, client_mark("10.0.0.1", note="second"))
    assert [b.note for b in shelf.bookmarks] == ["second"]
    assert remove(shelf, "c-10.0.0.1").bookmarks == ()


def test_names_are_unique_ignoring_case_non_empty_and_at_most_sixty() -> None:
    shelf = add_category(EMPTY, "Login attacks")
    for bad in ("", "   ", "LOGIN ATTACKS", "x" * (NAME_LIMIT + 1)):
        with pytest.raises(CategoryError):
            add_category(shelf, bad)
    assert add_category(shelf, "  x  ").categories[-1].name == "x"
    assert add_category(shelf, "y" * NAME_LIMIT).categories[-1].name == "y" * NAME_LIMIT


def test_deleting_a_category_moves_its_bookmarks_to_the_first() -> None:
    shelf = add(EMPTY, client_mark("10.0.0.1", category="Login attacks"))
    shelf = delete_category(shelf, "login attacks")
    assert [c.name for c in shelf.categories] == [DEFAULT]
    assert [b.category for b in shelf.bookmarks] == [DEFAULT]


def test_the_first_category_cannot_be_deleted_but_can_be_renamed() -> None:
    shelf = add(EMPTY, client_mark("10.0.0.1"))
    with pytest.raises(CategoryError):
        delete_category(shelf, DEFAULT)
    renamed = rename_category(shelf, DEFAULT, "To check")
    assert [c.name for c in renamed.categories] == ["To check"]
    assert [b.category for b in renamed.bookmarks] == ["To check"]


def test_a_rename_may_change_only_the_case_but_not_take_another_name() -> None:
    shelf = add_category(add_category(EMPTY, "Login"), "Scanners")
    assert rename_category(shelf, "Login", "login").categories[1].name == "login"
    with pytest.raises(CategoryError):
        rename_category(shelf, "Login", "SCANNERS")


def test_colours_are_kept_when_a_category_before_them_goes() -> None:
    shelf = add_category(add_category(EMPTY, "One"), "Two")
    two = shelf.colour_of("Two")
    shelf = delete_category(shelf, "One")
    assert shelf.colour_of("Two") == two
    # and the freed colour is the next one handed out
    three = add_category(shelf, "Three").category("Three")
    assert three is not None and three.colour == 1
