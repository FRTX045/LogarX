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

__all__ = ["required"]

_T = TypeVar("_T")


def required(value: _T | None, what: str = "widget") -> _T:
    """Return `value`, refusing None."""
    if value is None:  # pragma: no cover - Qt creates these on demand
        raise RuntimeError(f"Qt did not provide a required {what}")
    return value
