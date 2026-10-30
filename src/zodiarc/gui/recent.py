"""The cases opened lately, and what to do with them when the window opens.

No Qt, for the same reason `zodiarc.style` and `gui.evidence_view` have none: what
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
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

__all__ = [
    "LIMIT",
    "RecentCase",
    "Startup",
    "dump",
    "forget",
    "forget_one",
    "load",
    "remember",
    "set_label",
    "set_pinned",
    "startup_action",
]

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

    pinned: bool = False
    """Held at the top of the list, and exempt from the cap. The cap exists to
    stop the list becoming an archive; a pin says this one is not part of that."""

    label: str = ""
    """A name given to this entry *here*, or empty to use the case's own.

    Deliberately not written back to `case.json`. The case id is printed in the
    provenance table of every exported report, so renaming the case itself would
    leave a report written yesterday and one written today disagreeing about
    what the same case is called. This name belongs to the list, not the case.
    """

    @property
    def display_name(self) -> str:
        return self.label or self.case_id

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "case_id": self.case_id,
            "opened_at": self.opened_at.isoformat(),
            "events": self.events,
            "sources": list(self.sources),
            "pinned": self.pinned,
            "label": self.label,
        }


class Startup(StrEnum):
    """What the window should do with the list when it opens."""

    OPEN_LAST = "open-last"
    CHOOSE = "choose"
    WAIT = "wait"
    """Offer nothing. The canvas already carries the instruction, and a chooser
    with no rows in front of an empty window is a dialog that says nothing."""


def remember(cases: Iterable[RecentCase], entry: RecentCase) -> tuple[RecentCase, ...]:
    """`entry` first, then the rest, deduplicated by path, pinned held on top.

    Deduplicated by path rather than by case id: two cases may be named the
    same, and it is the folder that gets reopened.

    `entry` arrives as a fresh snapshot read off the case, which knows nothing
    about a pin or a name given here — so anything the list already knew about
    that folder is carried across. Taking the snapshot at face value would
    silently undo both the moment the case was opened again.
    """
    existing = tuple(cases)
    previous = next((case for case in existing if case.path == entry.path), None)
    if previous is not None:
        entry = replace(entry, pinned=previous.pinned, label=previous.label)

    rest = [case for case in existing if case.path != entry.path]
    return _arrange((entry, *rest))


def _arrange(cases: Iterable[RecentCase]) -> tuple[RecentCase, ...]:
    """Pinned first, then the rest by recency, with only the rest capped."""
    ordered = tuple(cases)
    pinned = tuple(case for case in ordered if case.pinned)
    loose = tuple(case for case in ordered if not case.pinned)
    return pinned + loose[:LIMIT]


def _amend(
    cases: Iterable[RecentCase], path: str, change: Callable[[RecentCase], RecentCase]
) -> tuple[RecentCase, ...]:
    return _arrange(change(case) if case.path == path else case for case in cases)


def set_pinned(cases: Iterable[RecentCase], path: str, *, pinned: bool) -> tuple[RecentCase, ...]:
    """Hold a case at the top of the list, or stop holding it."""
    return _amend(cases, path, lambda case: replace(case, pinned=pinned))


def set_label(cases: Iterable[RecentCase], path: str, label: str) -> tuple[RecentCase, ...]:
    """Name a case in this list. An empty name falls back to the case's own."""
    return _amend(cases, path, lambda case: replace(case, label=label.strip()))


def forget(cases: Iterable[RecentCase], paths: Iterable[str]) -> tuple[RecentCase, ...]:
    """Drop every entry whose path is in `paths`, leaving the rest in order.

    Takes a set of paths rather than one, because `Forget these` acts on a
    selection: removing them one at a time would re-sort and re-cap the list
    between each, so which entries survived would depend on the order they
    happened to be taken out in.
    """
    unwanted = set(paths)
    return _arrange(case for case in cases if case.path not in unwanted)


def forget_one(cases: Iterable[RecentCase], path: str) -> tuple[RecentCase, ...]:
    """Drop one entry, leaving the others."""
    return forget(cases, (path,))


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
            # Absent in anything written before pinning existed. Defaulted
            # rather than required, so an older list opens instead of being
            # dropped as unreadable.
            pinned=bool(item.get("pinned", False)),
            label=str(item.get("label", "")),
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
