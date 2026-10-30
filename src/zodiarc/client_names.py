"""The names a reader gives client addresses.

No Qt, for the reason `session_names` has none: what is kept, what is set aside,
and what two windows writing one file end up with are decisions, and a decision
should be checkable without a display.

The file is `client-names.json` in the case folder, beside `session-names.json`
and `bookmarks.json`, and like them outside the manifest. A reader's name for an
address is a note, not evidence: it says what they made of a client, never what
the log holds. Nothing that reads the log, the store or a finding sees it; it is
applied where an address is shown, and a report always shows the address beside
it.

A name is kept against the address exactly as the case stores it. Unlike a
session, an address does not shift under a time filter, so nothing more is needed
to find it again.

A reader's names are the one thing here nobody can regenerate, so the file
keeps `session-names.json`'s rules:

- Read entry by entry. What this version does not understand, a field or a
  whole entry, is carried and written back as it was, not dropped.
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

from zodiarc.bookmarks import NAME_LIMIT
from zodiarc.search import fold
from zodiarc.session_names import tidy

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

__all__ = [
    "EMPTY",
    "FILE_NAME",
    "UNREADABLE_NAME",
    "ClientNameWriteError",
    "Entry",
    "Loaded",
    "Names",
    "apply",
    "forget",
    "labelled",
    "load",
    "matching",
    "rename",
    "shown",
]

FILE_NAME: Final = "client-names.json"
#: Where a file that could not be read goes, once a name is saved over it.
UNREADABLE_NAME: Final = "client-names.unreadable.json"
_VERSION: Final = 1
_ENTRY_KEYS: Final = frozenset({"client", "name", "named"})


class ClientNameWriteError(OSError):
    """The case folder would not take the file. Nothing was changed."""


@dataclass(frozen=True, slots=True)
class Entry:
    client: str
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

    def name_for(self, client: str) -> str | None:
        """The name kept against `client`; the last, if a hand edit left two."""
        return self.as_map().get(client)

    def as_map(self) -> dict[str, str]:
        """Every named address and its name, the last entry for an address winning."""
        return {entry.client: entry.name for entry in self.entries}

    def matching(self, text: str) -> frozenset[str]:
        """The addresses whose name holds `text`; see `matching`."""
        return matching(self.as_map(), text)


EMPTY: Final = Names(entries=())


@dataclass(frozen=True, slots=True)
class Loaded:
    names: Names
    #: Why the file could not be read, or `None` when it could (or is absent).
    problem: str | None


# -- finding and showing ----------------------------------------------------------


def matching(names: Mapping[str, str], text: str) -> frozenset[str]:
    """The addresses in `names` whose name holds `text` as one phrase.

    What a filter box asks of names. Case does not count, runs of spaces are
    one, and quotes are dropped, so `"office vpn"` typed as a phrase finds
    `Office VPN`. Words keep their order: `vpn office` does not. Nothing typed
    finds nothing.
    """
    wanted = fold(tidy(text.replace('"', " ")))
    if not wanted:
        return frozenset()
    return frozenset(client for client, name in names.items() if wanted in fold(tidy(name)))


def labelled(address: str, name: str | None) -> str:
    """How a report names a client: the name with the address beside it.

    A report cannot be switched back to addresses, and its reader checks it
    against the log, so the address is never left out.
    """
    return f"{name} ({address})" if name else address


def shown(address: str, names: Mapping[str, str], *, on: bool) -> str:
    """What the window shows for `address`: its name while names are `on`."""
    return (names.get(address) or address) if on else address


# -- changes --------------------------------------------------------------------


def forget(names: Names, client: str) -> Names:
    """`names` without a name for `client`: the address shows again."""
    return changed(names, entries=tuple(e for e in names.entries if e.client != client))


def rename(names: Names, client: str, name: str, *, now: datetime) -> Names:
    """Name `client` as the reader asked; a name that comes out blank removes it.

    Every earlier name for the address goes either way, so it ends with one.
    """
    wanted = tidy(name)
    if len(wanted) > NAME_LIMIT:
        raise ValueError(f"A client name is at most {NAME_LIMIT} characters.")
    without = forget(names, client)
    if not wanted:
        return without
    return changed(without, entries=(*without.entries, Entry(client, wanted, now)))


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
    client, name = raw.get("client"), raw.get("name")
    if not isinstance(client, str) or not client or not isinstance(name, str) or not tidy(name):
        return None
    named = _time(raw.get("named"))
    extra = {key: value for key, value in raw.items() if key not in _ENTRY_KEYS}
    if named is None and "named" in raw:
        # Unreadable as a time, so carried as it was rather than lost.
        extra["named"] = raw["named"]
    return Entry(client=client, name=tidy(name), named=named, extra=extra)


def _entry_to(entry: Entry) -> dict[str, Any]:
    written: dict[str, Any] = {**entry.extra, "client": entry.client, "name": entry.name}
    if entry.named is not None:
        written["named"] = entry.named.isoformat()
    return written


def _names_from(raw: Any) -> Names:
    if not isinstance(raw, dict):
        raise ValueError("the file does not hold a JSON object")
    entries: list[Entry] = []
    kept: list[Any] = []
    listed = raw.get("names")
    for item in listed if isinstance(listed, list) else []:
        entry = _entry_from(item)
        if entry is None:
            kept.append(item)
        else:
            entries.append(entry)
    extra = {key: value for key, value in raw.items() if key not in {"version", "names"}}
    return Names(entries=tuple(entries), kept=tuple(kept), extra=extra)


def _dump(names: Names) -> bytes:
    content = {
        **names.extra,
        "version": _VERSION,
        "names": [*(_entry_to(entry) for entry in names.entries), *names.kept],
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
    """The case's client names. Never raises: an unreadable file is a `problem`."""
    try:
        return _read(case_dir / FILE_NAME)
    except OSError as error:
        return Loaded(EMPTY, error.strerror or str(error))


def _set_aside(path: Path) -> None:
    target = path.with_name(UNREADABLE_NAME)
    number = 2
    while target.exists():
        target = path.with_name(f"client-names.unreadable.{number}.json")
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
    aside first, never written over. Raises `ClientNameWriteError` when the
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
        raise ClientNameWriteError(error.errno, error.strerror or str(error)) from error
    return names
