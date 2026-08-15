"""The cases opened lately, and what to do with them when the window opens.

No Qt, for the same reason `gui.style` and `gui.evidence_view` have none: what
the window does on startup is a decision, and a decision should be checkable
without a display.

Each entry carries a **snapshot** of the case rather than a pointer to be read
later. The chooser has to draw before it has touched a disk: a case sitting on a
share that is no longer mounted turns `Path.exists` into a stall, and doing that
once per row would hang the window before it drew anything. Disk is touched for
the one case being opened, not for the list.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

__all__ = ["LIMIT", "RecentCase", "Startup", "dump", "load", "remember", "startup_action"]

#: How many to keep. Long enough to cover the cases in play, short enough that
#: the chooser stays a list rather than an archive to search.
LIMIT: Final = 10


@dataclass(frozen=True, slots=True)
class RecentCase:
    """One case that has been opened, as it was when it was last opened."""

    path: str
    """Where the case directory was. The identity of an entry: two cases can
    share a `case_id`, and it is the folder that gets reopened."""

    case_id: str
    opened_at: datetime
    events: int
    sources: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "case_id": self.case_id,
            "opened_at": self.opened_at.isoformat(),
            "events": self.events,
            "sources": list(self.sources),
        }


class Startup(StrEnum):
    """What the window should do with the list when it opens."""

    OPEN_LAST = "open-last"
    CHOOSE = "choose"
    WAIT = "wait"
    """Offer nothing. The canvas already carries the instruction, and a chooser
    with no rows in front of an empty window is a dialog that says nothing."""


def remember(cases: Iterable[RecentCase], entry: RecentCase) -> tuple[RecentCase, ...]:
    """`entry` first, then the rest, deduplicated by path and capped.

    By path rather than by case id: two cases may be named the same, and it is
    the folder that gets reopened. Reopening yesterday's case should move it to
    the top, not put the same folder in the list twice.
    """
    rest = [case for case in cases if case.path != entry.path]
    return (entry, *rest)[:LIMIT]


def dump(cases: Iterable[RecentCase]) -> str:
    return json.dumps([case.as_dict() for case in cases])


def load(raw: str) -> tuple[RecentCase, ...]:
    """Read the stored list, or give up quietly.

    A preference is never worth failing to start over. Truncated JSON, a value
    written by an older version, another program's key at the same name — all of
    them come back as an empty list and the application opens.
    """
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return ()
    if not isinstance(payload, list):
        return ()

    cases = []
    for item in payload:
        parsed = _one(item)
        if parsed is not None:
            cases.append(parsed)
    return tuple(cases)


def _one(item: object) -> RecentCase | None:
    if not isinstance(item, dict):
        return None
    try:
        return RecentCase(
            path=str(item["path"]),
            case_id=str(item["case_id"]),
            opened_at=datetime.fromisoformat(str(item["opened_at"])),
            events=int(item["events"]),
            sources=tuple(str(name) for name in item["sources"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def now() -> datetime:
    """The timestamp an entry is stamped with, to the second."""
    return datetime.now(UTC).replace(microsecond=0)


def startup_action(
    cases: Iterable[RecentCase],
    *,
    reopen_last: bool,
    exists: Callable[[str], bool],
) -> tuple[Startup, RecentCase | None]:
    """What to do with the list when the window opens.

    `exists` is passed in rather than called on a `Path` here, both to keep this
    module free of the filesystem and because it is the one call in this path
    that can be slow.

    The case worth naming: the setting says reopen and the folder has since
    moved. Doing nothing would leave an empty window with no account of why the
    case that was open yesterday is not open now, so the list is offered instead.
    """
    ordered = tuple(cases)
    if not ordered:
        return Startup.WAIT, None
    if reopen_last and exists(ordered[0].path):
        return Startup.OPEN_LAST, ordered[0]
    return Startup.CHOOSE, None
