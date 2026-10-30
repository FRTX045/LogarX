"""The names a reader gives sessions on the graph.

No Qt, for the reason `bookmarks` has none: what is kept, what is set aside, and
what two windows writing one file end up with are decisions, and a decision
should be checkable without a display.

The file is `session-names.json` in the case folder, beside `bookmarks.json` and
like it outside the manifest. A reader's name for a session is a note, not
evidence: it says what they made of a visit, never what the log holds.

A name is kept against its client and the first request of the session it was
given to, `file:line`, never against the session's number: numbers shift when a
time filter cuts a client's visits differently, and log lines do not. It then
belongs to whichever session holds that line. A filter that cuts the line off
shows Zodiarc's name for what is left, and the reader's comes back with the
whole visit; a name given while a filter clipped the visit is kept against a
line the whole visit still holds, so it survives the filter being cleared.

A reader's names are the one thing here nobody can regenerate, so the file
keeps `bookmarks.json`'s rules:

- Read entry by entry. What this version does not understand — a field, or a
  whole entry — is carried and written back as it was, not dropped.
- Changed by re-reading. `apply` reads the file again, applies one change and
  writes it, so two windows on one case each keep what the other saved.
- Written whole, then swapped in, so a crash mid-write leaves the old file.
- A file that cannot be read at all is set aside, never overwritten.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from dataclasses import replace as changed
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from zodiarc.bookmarks import NAME_LIMIT, parse_ref
from zodiarc.core.evidence import EvidenceRef

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Mapping
    from pathlib import Path

__all__ = [
    "EMPTY",
    "FILE_NAME",
    "UNREADABLE_NAME",
    "Entry",
    "Loaded",
    "Names",
    "SessionKey",
    "SessionNameWriteError",
    "apply",
    "forget",
    "load",
    "rename",
    "tidy",
]

FILE_NAME: Final = "session-names.json"
#: Where a file that could not be read goes, once a name is saved over it.
UNREADABLE_NAME: Final = "session-names.unreadable.json"
_VERSION: Final = 1
_ENTRY_KEYS: Final = frozenset({"client", "first", "name", "named"})


class SessionNameWriteError(OSError):
    """The case folder would not take the file. Nothing was changed."""


@dataclass(frozen=True, slots=True)
class SessionKey:
    """Which session: the client, and the first request of its visit."""

    client: str
    first: EvidenceRef


@dataclass(frozen=True, slots=True)
class Entry:
    key: SessionKey
    name: str
    #: When it was named. `None` for an entry written by hand without one.
    named: datetime | None
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Names:
    """Everything one case's file holds."""

    entries: tuple[Entry, ...]
    #: Entries this version could not use, written back exactly as they were.
    kept: tuple[Any, ...] = ()
    extra: Mapping[str, Any] = field(default_factory=dict)

    def name_for(self, key: SessionKey) -> str | None:
        """The name kept against exactly `key`; the last, if a hand edit left two."""
        found = [entry.name for entry in self.entries if entry.key == key]
        return found[-1] if found else None

    def name_in(self, client: str, lines: Collection[EvidenceRef]) -> str | None:
        """The reader's name for the session of `client` holding these `lines`.

        The name given last, should the session hold the lines of two: one given
        under a time filter and one given to the whole visit, say.
        """
        found = [
            entry.name
            for entry in self.entries
            if entry.key.client == client and entry.key.first in lines
        ]
        return found[-1] if found else None


EMPTY: Final = Names(entries=())


@dataclass(frozen=True, slots=True)
class Loaded:
    names: Names
    #: Why the file could not be read, or `None` when it could (or is absent).
    problem: str | None


# -- changes --------------------------------------------------------------------


def tidy(name: str) -> str:
    """`name` with every run of spaces made one, and none at either end."""
    return " ".join(name.split())


def forget(names: Names, key: SessionKey, *, within: Collection[EvidenceRef] = ()) -> Names:
    """`names` without the reader's name for `key`: Zodiarc's shows again.

    `within` is every line of the session being renamed: a name kept against any
    of them would otherwise still name it.
    """

    def inside(entry: Entry) -> bool:
        return entry.key == key or (entry.key.client == key.client and entry.key.first in within)

    return changed(names, entries=tuple(entry for entry in names.entries if not inside(entry)))


def rename(
    names: Names,
    key: SessionKey,
    name: str,
    *,
    zodiarc_name: str,
    now: datetime,
    within: Collection[EvidenceRef] = (),
) -> Names:
    """Name the session `key` as the reader asked.

    A name that comes out blank, or the same as `zodiarc_name`, takes the
    reader's name away instead: a pencil on Zodiarc's own words would claim
    authorship of nothing. Every earlier name for the session goes either way,
    those kept against `key` and any against a line in `within`, so the session
    ends with one name.
    """
    wanted = tidy(name)
    if len(wanted) > NAME_LIMIT:
        raise ValueError(f"A session name is at most {NAME_LIMIT} characters.")
    without = forget(names, key, within=within)
    if not wanted or wanted == tidy(zodiarc_name):
        return without
    entry = Entry(key=key, name=wanted, named=now)
    return changed(without, entries=(*without.entries, entry))


# -- reading and writing -----------------------------------------------------------


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def _entry_from(raw: Any) -> Entry | None:
    if not isinstance(raw, dict):
        return None
    client, first, name = raw.get("client"), raw.get("first"), raw.get("name")
    if not isinstance(client, str) or not client or not isinstance(first, str):
        return None
    ref = parse_ref(first)
    if ref is None or not isinstance(name, str) or not tidy(name):
        return None
    named = _time(raw.get("named"))
    extra = {key: value for key, value in raw.items() if key not in _ENTRY_KEYS}
    if named is None and "named" in raw:
        # Unreadable as a time, so carried as it was rather than lost.
        extra["named"] = raw["named"]
    return Entry(key=SessionKey(client, ref), name=tidy(name), named=named, extra=extra)


def _entry_to(entry: Entry) -> dict[str, Any]:
    written: dict[str, Any] = {
        **entry.extra,
        "client": entry.key.client,
        "first": str(entry.key.first),
        "name": entry.name,
    }
    if entry.named is not None:
        written["named"] = entry.named.isoformat()
    return written


def _names_from(raw: Any) -> Names:
    if not isinstance(raw, dict):
        raise ValueError("the file does not hold a JSON object")
    entries: list[Entry] = []
    kept: list[Any] = []
    listed = raw.get("sessions")
    for item in listed if isinstance(listed, list) else []:
        entry = _entry_from(item)
        if entry is None:
            kept.append(item)
        else:
            entries.append(entry)
    extra = {key: value for key, value in raw.items() if key not in {"version", "sessions"}}
    return Names(entries=tuple(entries), kept=tuple(kept), extra=extra)


def _dump(names: Names) -> bytes:
    content = {
        **names.extra,
        "version": _VERSION,
        "sessions": [*(_entry_to(entry) for entry in names.entries), *names.kept],
    }
    return (json.dumps(content, ensure_ascii=False, indent=1) + "\n").encode("utf-8")


def _read(path: Path) -> Loaded:
    """Read the file; an `OSError` is let through, a file that is not ours is a problem."""
    if not path.exists():
        return Loaded(EMPTY, None)
    data = path.read_bytes()
    try:
        return Loaded(_names_from(json.loads(data.decode("utf-8"))), None)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return Loaded(EMPTY, str(error) or type(error).__name__)


def load(case_dir: Path) -> Loaded:
    """The case's session names. Never raises: an unreadable file is a `problem`."""
    try:
        return _read(case_dir / FILE_NAME)
    except OSError as error:
        return Loaded(EMPTY, error.strerror or str(error))


def _set_aside(path: Path) -> None:
    target = path.with_name(UNREADABLE_NAME)
    number = 2
    while target.exists():
        target = path.with_name(f"session-names.unreadable.{number}.json")
        number += 1
    path.replace(target)


def _write(path: Path, names: Names) -> None:
    temporary = path.with_name(f"{FILE_NAME}.tmp")
    try:
        temporary.write_bytes(_dump(names))
        temporary.replace(path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def apply(case_dir: Path, change: Callable[[Names], Names]) -> Names:
    """Read the file again, make one change, write it; return what was written.

    Read again rather than trusting the copy in hand, so a second window on the
    same case keeps what the first one saved. A file that cannot be read is set
    aside first, never written over. Raises `SessionNameWriteError` when the
    folder cannot be written, and changes nothing then.
    """
    path = case_dir / FILE_NAME
    try:
        loaded = _read(path)
        names = change(loaded.names)
        if loaded.problem is not None:
            _set_aside(path)
        _write(path, names)
    except OSError as error:
        raise SessionNameWriteError(error.errno, error.strerror or str(error)) from error
    return names
