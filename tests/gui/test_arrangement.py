"""Where the investigator put the nodes, and how to take it back.

Qt-free, like `gui/recent.py` and `style.py`: what an undo means and which
saved arrangement belongs to which graph are decisions, and a decision should be
checkable without starting a window.
"""

from __future__ import annotations

import json

import pytest

from logarx.core.graph import GraphKind
from logarx.gui.arrangement import (
    LIMIT,
    Move,
    MoveHistory,
    dump,
    forget,
    key,
    load,
    moved_from,
    notice,
    remember,
)

CASE = r"D:\cases\one"


def move(node_id: str = "a", before: tuple[float, float] = (0.0, 0.0)) -> Move:
    return Move(node_id=node_id, before=before, after=(before[0] + 10.0, before[1] + 10.0))


# -- the undo stack --------------------------------------------------------


def test_a_fresh_history_has_nothing_to_undo() -> None:
    history = MoveHistory()

    assert not history.can_undo
    assert history.undo() is None


def test_one_move_recorded_is_one_move_returned() -> None:
    history = MoveHistory()
    recorded = move()
    history.record(recorded)

    assert history.can_undo
    assert history.undo() == recorded
    assert not history.can_undo


def test_moves_come_back_in_the_order_they_would_be_taken_back() -> None:
    """Last in, first out. Undoing the oldest drag first would rearrange the
    graph into a state the investigator never saw."""
    history = MoveHistory()
    first, second, third = move("a"), move("b"), move("c")
    for recorded in (first, second, third):
        history.record(recorded)

    assert [history.undo(), history.undo(), history.undo()] == [third, second, first]


def test_a_drag_that_ends_where_it_started_is_not_recorded() -> None:
    """A click is a drag of zero distance. Recorded, every click would put an
    entry on the stack that undoes to the position it is already in — so `Undo`
    would look broken until the reader had pressed it as many times as they had
    clicked."""
    history = MoveHistory()
    history.record(Move(node_id="a", before=(4.0, 5.0), after=(4.0, 5.0)))

    assert not history.can_undo


def test_clearing_drops_everything() -> None:
    history = MoveHistory()
    history.record(move())
    history.clear()

    assert not history.can_undo


def test_the_stack_has_no_ceiling() -> None:
    """Asked for: undo as far back as the session goes."""
    history = MoveHistory()
    for index in range(500):
        history.record(move(f"n{index}"))

    assert sum(1 for _ in iter(history.undo, None)) == 500


# -- what a saved arrangement is keyed by ----------------------------------


def test_the_same_graph_gets_the_same_key() -> None:
    first = key(r"D:\cases\one", "10.0.0.1", GraphKind.TRACE, wrap=True)
    second = key(r"D:\cases\one", "10.0.0.1", GraphKind.TRACE, wrap=True)

    assert first == second


@pytest.mark.parametrize(
    "other",
    [
        (r"D:\cases\two", "10.0.0.1", GraphKind.TRACE, True),
        (r"D:\cases\one", "10.0.0.2", GraphKind.TRACE, True),
        (r"D:\cases\one", "10.0.0.1", GraphKind.BEHAVIOUR, True),
        (r"D:\cases\one", "10.0.0.1", GraphKind.TRACE, False),
    ],
    ids=["case", "client", "kind", "wrap"],
)
def test_a_different_graph_gets_a_different_key(
    other: tuple[str, str, GraphKind, bool],
) -> None:
    """Four things decide where a node sits. Positions saved under one of them
    describe nothing under another — a wrapped trace folds onto rows an
    unwrapped one does not have."""
    mine = key(r"D:\cases\one", "10.0.0.1", GraphKind.TRACE, wrap=True)
    path, client, kind, wrap = other

    assert key(path, client, kind, wrap=wrap) != mine


def test_two_graphs_cannot_be_run_together_into_one_key() -> None:
    """The parts have to be separated before they are hashed.

    Run together, the case at `...\\one` viewed for client `1.2` and the case at
    `...\\one1` viewed for client `.2` are the same string. One investigator's
    arrangement would then load onto the other's graph, silently, and the nodes
    would sit at coordinates that describe a case they are not looking at.
    """
    assert key(CASE, "1.2", GraphKind.TRACE, wrap=True) != key(
        CASE + "1", ".2", GraphKind.TRACE, wrap=True
    )


# -- the store -------------------------------------------------------------


def test_positions_survive_a_round_trip() -> None:
    store = {"k": {"a": (1.5, -2.5), "b": (0.0, 300.0)}}

    assert load(dump(store)) == store


@pytest.mark.parametrize("text", ["", "   ", "{", "[]", "null", '"hello"', "3"], ids=repr)
def test_unreadable_settings_mean_nothing_was_saved(text: str) -> None:
    """A view preference, not evidence. A value that cannot be read has to mean
    "no arrangement yet"; raising here would stop the window opening a case."""
    assert load(text) == {}


def test_an_entry_of_the_wrong_shape_is_dropped_without_taking_the_rest() -> None:
    text = json.dumps(
        {
            "good": {"a": [1.0, 2.0]},
            "short": {"a": [1.0]},
            "wordy": {"a": ["x", "y"]},
            "flat": [1.0, 2.0],
        }
    )

    assert load(text) == {"good": {"a": (1.0, 2.0)}}


def test_a_node_of_the_wrong_shape_is_dropped_without_taking_its_neighbours() -> None:
    text = json.dumps({"k": {"a": [1.0, 2.0], "b": "nonsense"}})

    assert load(text) == {"k": {"a": (1.0, 2.0)}}


def test_a_boolean_is_not_a_coordinate() -> None:
    """`bool` is an `int` in Python, so a plain number check lets `true` through
    as `1.0` — a node placed at a coordinate nobody wrote, in a graph that looks
    like it loaded cleanly."""
    assert load(json.dumps({"k": {"a": [True, False], "b": [1.0, 2.0]}})) == {
        "k": {"b": (1.0, 2.0)}
    }


def test_remembering_keeps_what_was_remembered() -> None:
    store = remember({}, "k", {"a": (1.0, 2.0)})

    assert store == {"k": {"a": (1.0, 2.0)}}


def test_remembering_the_same_graph_again_replaces_it() -> None:
    store = remember({}, "k", {"a": (1.0, 2.0)})
    store = remember(store, "k", {"a": (9.0, 9.0)})

    assert store == {"k": {"a": (9.0, 9.0)}}


def test_the_oldest_arrangement_is_the_one_dropped() -> None:
    """One settings value holds them all, so the list cannot grow without
    bound. The one the reader touched longest ago is the one they will miss
    least."""
    store: dict[str, dict[str, tuple[float, float]]] = {}
    for index in range(LIMIT + 3):
        store = remember(store, f"k{index}", {"a": (float(index), 0.0)})

    assert len(store) == LIMIT
    assert "k0" not in store
    assert "k2" not in store
    assert f"k{LIMIT + 2}" in store


def test_saving_again_moves_an_arrangement_out_of_reach_of_the_cap() -> None:
    """Otherwise the arrangement someone re-saves every day is evicted on the
    same schedule as one they set once and forgot."""
    store: dict[str, dict[str, tuple[float, float]]] = {}
    for index in range(LIMIT):
        store = remember(store, f"k{index}", {"a": (float(index), 0.0)})
    store = remember(store, "k0", {"a": (1.0, 1.0)})
    store = remember(store, "fresh", {"a": (2.0, 2.0)})

    assert "k0" in store
    assert "k1" not in store


def test_forgetting_takes_one_and_leaves_the_rest() -> None:
    store = remember(remember({}, "keep", {"a": (1.0, 2.0)}), "drop", {"b": (3.0, 4.0)})

    assert forget(store, "drop") == {"keep": {"a": (1.0, 2.0)}}


def test_forgetting_something_never_saved_is_not_an_error() -> None:
    store = remember({}, "keep", {"a": (1.0, 2.0)})

    assert forget(store, "absent") == store


def test_two_time_ranges_file_their_arrangements_apart() -> None:
    """A graph read over one stretch has different activities in it from the
    same graph read over another — different names, different counts. Filed
    together, saving one would replace the other and neither would find its own
    nodes on the way back."""
    early = key(CASE, "10.0.0.1", GraphKind.TRACE, wrap=True, window="20240502T012530-025700")
    late = key(CASE, "10.0.0.1", GraphKind.TRACE, wrap=True, window="20240502T030000-040000")

    assert early != late


def test_the_whole_case_keeps_the_key_it_always_had() -> None:
    """An arrangement saved before ranges existed has to still be found."""
    assert key(CASE, "10.0.0.1", GraphKind.TRACE, wrap=True) == key(
        CASE, "10.0.0.1", GraphKind.TRACE, wrap=True, window=""
    )


# -- which activities are not where they were kept -------------------------


def test_nothing_has_moved_when_everything_is_where_it_was_kept() -> None:
    where = {"n0": (0.0, 0.0), "n1": (10.0, 20.0)}
    assert moved_from(where, dict(where)) == ()


def test_a_node_somewhere_else_is_reported_by_id() -> None:
    kept = {"n0": (0.0, 0.0), "n1": (10.0, 20.0)}
    now = {"n0": (0.0, 0.0), "n1": (11.0, 20.0)}
    assert moved_from(now, kept) == ("n1",)


def test_every_node_that_moved_is_reported_in_a_settled_order() -> None:
    """Sorted, so neither the count nor the ids depend on dictionary order,
    which is insertion order, which is whatever order the graph was drawn in.
    """
    kept = {"n2": (0.0, 0.0), "n0": (0.0, 0.0), "n1": (0.0, 0.0)}
    now = {"n2": (5.0, 0.0), "n0": (5.0, 0.0), "n1": (0.0, 0.0)}
    assert moved_from(now, kept) == ("n0", "n2")


def test_a_node_the_baseline_does_not_name_has_not_moved() -> None:
    """It has nowhere to have moved *from*.

    Counted as moved, a case re-ingested with a different rule pack would open
    already offering to save an arrangement nobody had touched: the new
    activities are not in the saved one, and every one of them would read as a
    move.
    """
    assert moved_from({"n0": (1.0, 1.0)}, {}) == ()


def test_a_node_that_has_gone_is_not_a_move_either() -> None:
    """The other way round. An activity the baseline names and the graph no
    longer has cannot have been moved, because it is not on the canvas to move.
    """
    assert moved_from({}, {"n0": (1.0, 1.0)}) == ()


def test_one_activity_is_counted_in_the_singular() -> None:
    assert notice(1) == "You moved 1 activity. The layout is not saved."


def test_several_activities_are_counted_in_the_plural() -> None:
    """`activities`, not `activitys`. The window already says `1 session(s)`
    nowhere, and this is the noun that would have made it start again.
    """
    assert notice(2) == "You moved 2 activities. The layout is not saved."
