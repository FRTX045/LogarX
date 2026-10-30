"""Which cases are offered, and what happens when the window opens.

Qt-free, like `style.py` and `gui/evidence_view.py`: the rule for what to do
at startup is a decision, not a drawing, and a decision should be checkable
without starting a window.
"""

from __future__ import annotations

from datetime import UTC, datetime

from zodiarc.gui.recent import (
    RecentCase,
    Startup,
    dump,
    forget,
    forget_one,
    load,
    remember,
    set_label,
    set_pinned,
    startup_action,
)

WHEN = datetime(2026, 8, 15, 13, 4, tzinfo=UTC)


def case(path: str = r"D:\cases\case-001", case_id: str = "case-001") -> RecentCase:
    return RecentCase(
        path=path,
        case_id=case_id,
        opened_at=WHEN,
        events=120,
        sources=("views.log",),
    )


def test_the_newest_case_is_offered_first() -> None:
    kept = remember((case(r"D:\a", "a"),), case(r"D:\b", "b"))

    assert [entry.case_id for entry in kept] == ["b", "a"]


def test_reopening_a_case_moves_it_up_rather_than_listing_it_twice() -> None:
    """Deduplicated by path, not by name: two cases can share a case id, and
    the same folder appearing twice in the list is the fault this prevents."""
    start = (case(r"D:\a", "a"), case(r"D:\b", "b"), case(r"D:\c", "c"))

    kept = remember(start, case(r"D:\c", "c"))

    assert [entry.case_id for entry in kept] == ["c", "a", "b"]
    assert len(kept) == 3


def test_the_list_does_not_grow_without_limit() -> None:
    kept: tuple[RecentCase, ...] = ()
    for index in range(25):
        kept = remember(kept, case(rf"D:\case-{index}", f"case-{index}"))

    assert len(kept) == 10
    assert kept[0].case_id == "case-24"


def test_the_list_survives_a_round_trip() -> None:
    original = (case(r"D:\a", "a"), case(r"D:\b", "b"))

    assert load(dump(original)) == original


def test_an_unreadable_setting_is_an_empty_list_not_a_crash() -> None:
    """A preference is not worth failing to start over. Whatever is in there —
    truncated JSON, a value from an older version, something else's key — the
    application opens and offers nothing."""
    assert load("") == ()
    assert load("not json at all") == ()
    assert load('{"unexpected": "shape"}') == ()
    assert load('[{"path": "D:/a"}]') == ()


def test_the_last_case_is_reopened_when_it_is_still_there() -> None:
    action, entry = startup_action(
        (case(r"D:\a", "a"),), reopen_last=True, exists=lambda _path: True
    )

    assert action is Startup.OPEN_LAST
    assert entry is not None
    assert entry.case_id == "a"


def test_a_last_case_that_has_moved_offers_the_list_instead_of_nothing() -> None:
    """The failure that would otherwise be silent: the setting says reopen, the
    folder is gone, and the window comes up empty with no explanation."""
    action, entry = startup_action(
        (case(r"D:\gone", "gone"),), reopen_last=True, exists=lambda _path: False
    )

    assert action is Startup.CHOOSE
    assert entry is None


def test_the_list_is_offered_when_reopening_is_turned_off() -> None:
    action, _entry = startup_action((case(),), reopen_last=False, exists=lambda _path: True)

    assert action is Startup.CHOOSE


def test_a_first_run_offers_nothing_at_all() -> None:
    """Nothing has been opened, so a chooser would be an empty table in front of
    an empty window. The canvas already says what to do."""
    action, _entry = startup_action((), reopen_last=True, exists=lambda _path: True)

    assert action is Startup.WAIT


# -- pinning, renaming, and removing one entry -------------------------------


def test_a_pinned_case_holds_the_top_however_much_is_opened_after_it() -> None:
    """The case you are living in, kept reachable through a busy week."""
    cases = remember((case(r"D:\a", "a"),), case(r"D:\b", "b"))
    cases = set_pinned(cases, r"D:\a", pinned=True)

    cases = remember(cases, case(r"D:\c", "c"))

    assert [entry.case_id for entry in cases] == ["a", "c", "b"]


def test_a_pinned_case_is_not_pushed_off_the_end() -> None:
    """The cap exists to stop the list becoming an archive. A pin is a statement
    that this one is not part of that."""
    cases = remember((), case(r"D:\keep", "keep"))
    cases = set_pinned(cases, r"D:\keep", pinned=True)

    for index in range(20):
        cases = remember(cases, case(rf"D:\other-{index}", f"other-{index}"))

    assert any(entry.case_id == "keep" for entry in cases)
    assert cases[0].case_id == "keep"


def test_reopening_a_pinned_and_renamed_case_keeps_both() -> None:
    """`remember` is handed a fresh snapshot read off the case, which knows
    nothing about a pin or a name given here. Taking it at face value would
    silently undo both the moment the case was opened again."""
    cases = remember((), case(r"D:\a", "case-001"))
    cases = set_pinned(cases, r"D:\a", pinned=True)
    cases = set_label(cases, r"D:\a", "acme-breach (jan)")

    cases = remember(cases, case(r"D:\a", "case-001"))

    assert cases[0].pinned
    assert cases[0].label == "acme-breach (jan)"


def test_a_renamed_case_is_shown_by_its_new_name_and_still_knows_its_own() -> None:
    """The rename is a label in this list. `case.json` is untouched, so a report
    exported before and one exported after agree about what the case is called."""
    cases = set_label((case(r"D:\a", "case-001"),), r"D:\a", "acme-breach (jan)")

    assert cases[0].display_name == "acme-breach (jan)"
    assert cases[0].case_id == "case-001"


def test_clearing_a_name_falls_back_to_the_one_the_case_carries() -> None:
    cases = set_label((case(r"D:\a", "case-001"),), r"D:\a", "renamed")

    cases = set_label(cases, r"D:\a", "")

    assert cases[0].display_name == "case-001"


def test_one_entry_can_be_dropped_without_forgetting_the_rest() -> None:
    cases = (case(r"D:\a", "a"), case(r"D:\b", "b"))

    kept = forget_one(cases, r"D:\a")

    assert [entry.case_id for entry in kept] == ["b"]


def test_pins_and_names_survive_being_stored() -> None:
    cases = set_label(
        set_pinned((case(r"D:\a", "case-001"),), r"D:\a", pinned=True), r"D:\a", "renamed"
    )

    assert load(dump(cases)) == cases


def test_a_stored_entry_from_before_pinning_still_loads() -> None:
    """Written by the version that had neither. It must open, unpinned and under
    its own name, rather than being dropped as unreadable."""
    older = '[{"path": "D:/a", "case_id": "a", "opened_at": "2026-08-15T13:04:00+00:00",'
    older += ' "events": 12, "sources": ["access.log"]}]'

    (entry,) = load(older)

    assert entry.case_id == "a"
    assert not entry.pinned
    assert entry.display_name == "a"


def test_forget_drops_every_path_it_is_given() -> None:
    cases = (case("a", "a"), case("b", "b"), case("c", "c"), case("d", "d"))

    left = forget(cases, {"a", "c"})

    assert [item.path for item in left] == ["b", "d"]


def test_forget_given_nothing_changes_nothing() -> None:
    """The button is disabled on an empty selection, but a list helper that
    quietly emptied itself when asked for nothing would be a bad surprise."""
    cases = (case("a", "a"), case("b", "b"))

    assert forget(cases, ()) == cases


def test_forget_ignores_a_path_that_is_not_in_the_list() -> None:
    cases = (case("a", "a"), case("b", "b"))

    assert [item.path for item in forget(cases, {"a", "z"})] == ["b"]


def test_forget_everything_leaves_an_empty_list() -> None:
    """Ctrl+A, then the button. This is how the whole list is still wiped, and
    the README's promise that the record can be removed rests on it."""
    cases = (case("a", "a"), case("b", "b"))

    assert forget(cases, {"a", "b"}) == ()
