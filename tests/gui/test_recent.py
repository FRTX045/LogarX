"""Which cases are offered, and what happens when the window opens.

Qt-free, like `gui/style.py` and `gui/evidence_view.py`: the rule for what to do
at startup is a decision, not a drawing, and a decision should be checkable
without starting a window.
"""

from __future__ import annotations

from datetime import UTC, datetime

from logarc.gui.recent import RecentCase, Startup, dump, load, remember, startup_action

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
