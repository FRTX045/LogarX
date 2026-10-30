"""Where the investigator put the nodes, and how to take it back.

No Qt, for the same reason `gui.recent` and `zodiarc.style` have none: what an undo
means, and which saved arrangement belongs to which graph, are decisions — and a
decision should be checkable without a display.

A saved arrangement is a *view preference*, not evidence. Nothing here is ever
allowed to stop a case being opened: a settings value that cannot be read means
"nothing was saved yet", not an exception on the path that draws the window.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from zodiarc.style import plural

if TYPE_CHECKING:
    from zodiarc.core.graph import GraphKind

__all__ = [
    "LIMIT",
    "Move",
    "MoveHistory",
    "Positions",
    "Store",
    "dump",
    "forget",
    "key",
    "load",
    "moved_from",
    "notice",
    "remember",
]

#: Where a node sits, by node id.
Positions = dict[str, tuple[float, float]]

#: Every saved arrangement, newest first, by `key`.
Store = dict[str, Positions]

#: How many arrangements are kept. One settings value holds them all, so the
#: list cannot grow without bound; twenty covers the graphs in play on a case
#: and leaves the value small enough to write in one go.
LIMIT: Final = 20

#: What joins the parts of a key before they are hashed. A byte that cannot
#: occur in a path, an address or a graph kind, so no two different graphs can
#: be run together into the same string.
_JOIN: Final = "\x00"


@dataclass(frozen=True, slots=True)
class Move:
    """One drag: an activity, where it was, and where it was let go."""

    node_id: str
    before: tuple[float, float]
    after: tuple[float, float]

    @property
    def is_a_move(self) -> bool:
        """Whether anything actually moved.

        A click is a drag of zero distance. Recorded, every click would put an
        entry on the stack that undoes to the position the node is already in,
        and `Undo` would look broken until it had been pressed as many times as
        the reader had clicked.
        """
        return self.before != self.after


class MoveHistory:
    """Drags, in the order they would be taken back.

    No ceiling. Undo was asked for as "as far back as the session goes", and a
    move is three floats and a string — a thousand of them is noise beside the
    scene they describe.
    """

    def __init__(self) -> None:
        self._moves: list[Move] = []

    @property
    def can_undo(self) -> bool:
        return bool(self._moves)

    def record(self, move: Move) -> None:
        if move.is_a_move:
            self._moves.append(move)

    def undo(self) -> Move | None:
        """The most recent drag, removed from the stack, or `None` if empty."""
        return self._moves.pop() if self._moves else None

    def clear(self) -> None:
        self._moves.clear()


def key(case_path: str, client_ip: str, kind: GraphKind, *, wrap: bool, window: str = "") -> str:
    r"""Which graph an arrangement belongs to.

    Five things decide where a node sits, and positions saved under one of them
    describe nothing under another: a wrapped trace folds onto rows an unwrapped
    one does not have, a behaviour map has different nodes entirely, and a graph
    read over one stretch of time has different activities in it — different
    names and different counts — from the same graph read over another.

    `window` is a `TimeWindow.tag`, empty for the whole case. Empty leaves the
    key exactly what it was before ranges existed, so an arrangement saved then
    is still found now.

    Hashed rather than spelled out because a case path carries `\` and `:` and
    a client address carries `:` in its IPv6 form, and because a fixed-width key
    keeps the stored value's size a function of the node count alone.
    """
    parts = _JOIN.join((case_path, client_ip, str(kind), "wrap" if wrap else "flat", window))
    return hashlib.sha1(parts.encode("utf-8"), usedforsecurity=False).hexdigest()


def load(text: str) -> Store:
    """Read the store, keeping whatever parts of it still make sense.

    Entry by entry and node by node. A single position written by a version
    that shaped them differently should cost that node its place, not cost the
    reader every arrangement they ever saved.
    """
    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(raw, dict):
        return {}

    store: Store = {}
    for name, entry in raw.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            continue
        positions = {
            node_id: point
            for node_id, value in entry.items()
            if isinstance(node_id, str) and (point := _point(value)) is not None
        }
        if positions:
            store[name] = positions
    return store


def _point(value: Any) -> tuple[float, float] | None:
    """Two real numbers, or nothing.

    `bool` is an `int` in Python, and `True` would arrive here as `1.0` — a
    node placed at a coordinate nobody wrote. Rejected explicitly.
    """
    if not isinstance(value, list | tuple) or len(value) != 2:
        return None
    if any(isinstance(number, bool) or not isinstance(number, int | float) for number in value):
        return None
    return (float(value[0]), float(value[1]))


def dump(store: Store) -> str:
    """The store as one settings value."""
    return json.dumps(
        {name: {k: list(v) for k, v in entry.items()} for name, entry in store.items()}
    )


def remember(store: Store, name: str, positions: Positions) -> Store:
    """Save one arrangement, newest first, dropping the oldest past `LIMIT`.

    Re-saving moves an arrangement back to the front. Otherwise the one someone
    sets again every day would be evicted on the same schedule as one they set
    once and forgot.
    """
    kept = {name: dict(positions)}
    for existing, entry in store.items():
        if existing != name and len(kept) < LIMIT:
            kept[existing] = entry
    return kept


def forget(store: Store, name: str) -> Store:
    """Drop one arrangement. Dropping one that was never saved is not an error."""
    return {existing: entry for existing, entry in store.items() if existing != name}


def moved_from(current: Positions, kept: Positions) -> tuple[str, ...]:
    """Which activities sit somewhere other than where `kept` puts them.

    The whole of "is this arrangement unsaved?", and derived rather than kept,
    because the state that would be kept is not the state being asked about.
    `MoveHistory` answers "has anything been dragged" — and a reader who drags a
    node and drags it back has dragged something and has nothing to save.

    An activity `kept` does not name has not moved: there is nowhere for it to
    have moved *from*. Counted, a case re-ingested against a different rule pack
    would open already offering to save an arrangement nobody had touched, since
    every activity the saved one predates would read as a move. The same holds
    the other way: one `kept` names and the graph no longer has is not on the
    canvas to be moved.

    Sorted, so neither the count nor the ids depend on dictionary order — which
    is insertion order, and insertion order is whatever order the graph happened
    to be drawn in.

    Compared exactly. Both sides come off the same `setPos`/`pos()` round trip
    with no arithmetic in between, so there is no float noise to absorb, and a
    tolerance here would hide a small move rather than forgive one.
    """
    return tuple(
        sorted(
            node_id
            for node_id, where in current.items()
            if node_id in kept and kept[node_id] != where
        )
    )


def notice(count: int) -> str:
    """What to say when `count` activities have been moved and not kept.

    Here rather than in the widget that draws it, for the reason the whole
    module is here: the wording is a judgement, and a judgement should be
    checkable without starting a window. `gui.quarantine_notice` and
    `gui.notice_bar` are already split along this line.
    """
    return f"You moved {plural(count, 'activity', 'activities')}. The layout is not saved."
