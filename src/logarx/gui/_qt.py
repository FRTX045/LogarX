"""Narrowing Qt accessors that the stubs type as optional.

PyQt6's stubs mark a great many accessors `T | None` — a table's header, a
window's status bar, the global thread pool — where Qt in fact creates the
object on first access and never hands back nothing. Sprinkling `assert` or
`cast` at each call site would either vanish under `-O` or silence a real bug
somewhere else later.

`required` raises instead. It costs one comparison, keeps the type checker
honest, and if Qt ever does return None the failure names itself rather than
surfacing as an AttributeError three frames away.
"""

from __future__ import annotations

from typing import TypeVar

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTableWidgetItem

__all__ = ["SORT_KEY", "SortableItem", "required"]

_T = TypeVar("_T")


def required(value: _T | None, what: str = "widget") -> _T:
    """Return `value`, refusing None."""
    if value is None:  # pragma: no cover - Qt creates these on demand
        raise RuntimeError(f"Qt did not provide a required {what}")
    return value


#: Where a cell keeps the number it is ordered by. Past `UserRole`, and past
#: whatever a widget stores there itself.
SORT_KEY = Qt.ItemDataRole.UserRole + 1


class SortableItem(QTableWidgetItem):
    """A cell that shows its text and sorts on a number kept beside it.

    The obvious way to make a column sort numerically is to put the number in
    `EditRole`, and it is wrong: Qt keeps `DisplayRole` and `EditRole` in one
    slot on a table item, so the number **replaces the text**. Both of this
    application's tables did it, and both were quietly showing raw values —
    a time of day as `1714564875`, and the 4xx ratio an investigator sorts the
    client list by as `0.8888888888888888` rather than `89%`.

    So the key lives in a role of its own and the comparison is made here.
    Sorting is unchanged; the text survives.
    """

    def __lt__(self, other: QTableWidgetItem) -> bool:
        mine, theirs = self.data(SORT_KEY), other.data(SORT_KEY)
        if mine is None or theirs is None:
            return super().__lt__(other)
        if isinstance(mine, str) and isinstance(theirs, str):
            # A client's address, kept so the column sorts by it whatever name it shows.
            return mine < theirs
        return float(mine) < float(theirs)
