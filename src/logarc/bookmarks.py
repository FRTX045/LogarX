"""What a reader saved in a case to come back to: bookmarks, in categories.

No Qt, for the same reason `gui.recent` and `gui.arrangement` have none: what is
kept, what is set aside, and what two windows writing one file end up with are
decisions, and a decision should be checkable without a display.

The file is `bookmarks.json` in the case folder, beside the manifest and never
inside it. The manifest is the chain-of-custody record — which files were read,
with which rules — and a reader's marks are not that: they change all the time
and must never be mistaken for evidence.

A reader's notes are the one thing here nobody can regenerate, so the file is
read tolerantly and written carefully:

- Read entry by entry. What this version does not understand — a field, or a
  whole entry — is carried and written back as it was, not dropped.
- Changed by re-reading. `apply` reads the file again, applies one change and
  writes it, so two windows on one case each add what they add rather than the
  second writing over the first.
- Written whole, then swapped in, so a crash mid-write leaves the old file.
- A file that cannot be read at all is set aside, never overwritten.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from dataclasses import replace as changed
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from logarc.core.evidence import EvidenceRef
from logarc.core.window import TimeWindow
from logarc.style import CATEGORY_COLOURS

__all__ = [
    "DEFAULT",
    "EMPTY",
    "FILE_NAME",
    "NAME_LIMIT",
    "NOTE_LIMIT",
    "UNREADABLE_NAME",
    "Bookmark",
    "BookmarkWriteError",
    "Category",
    "CategoryError",
    "Kind",
    "Loaded",
    "Shelf",
    "add",
    "add_category",
    "apply",
    "delete_category",
    "load",
    "matches",
    "new_id",
    "parse_ref",
    "remove",
    "rename_category",
    "replace",
    "utc_now",
]

FILE_NAME: Final = "bookmarks.json"
#: Where a file that could not be read goes, once a bookmark is saved over it.
UNREADABLE_NAME: Final = "bookmarks.unreadable.json"
#: The category a bookmark goes to when the reader chose none.
DEFAULT: Final = "Bookmarked"
NOTE_LIMIT: Final = 2000
NAME_LIMIT: Final = 60
_VERSION: Final = 1


class Kind(StrEnum):
    """What a bookmark points at."""

    CLIENT = "client"
    ACTIVITY = "activity"
    REQUEST = "request"
    SEARCH = "search"


class CategoryError(ValueError):
    """A category name that cannot be used, said so a reader can act on it."""


class BookmarkWriteError(OSError):
    """The bookmarks file could not be written; nothing was changed."""


@dataclass(frozen=True, slots=True)
class Category:
    name: str
    #: An index into `CATEGORY_COLOURS`, kept so the colour never moves.
    colour: int
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Bookmark:
    """One saved thing.

    `said` is what the target showed when it was saved, so the list reads without
    opening anything and a target that has gone still says what it was. An
    activity is anchored on its earliest log line, `line`: activity ids are
    positional and change with the range, a log line never does.
    """

    id: str
    kind: Kind
    category: str
    said: str
    note: str
    saved: datetime
    client: str | None = None
    line: EvidenceRef | None = None
    #: When `line` happened, so opening it can tell whether it is in the range.
    at: datetime | None = None
    query: str | None = None
    #: The range a search was made in; `None` is the whole case.
    range: TimeWindow | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    @property
    def target(self) -> tuple[object, ...]:
        """What this bookmark points at, whatever it says about it."""
        return (self.kind, self.client, self.line, self.query, self.range)


@dataclass(frozen=True, slots=True)
class Shelf:
    """Everything one case's file holds."""

    categories: tuple[Category, ...]
    bookmarks: tuple[Bookmark, ...]
    #: Entries this version could not read, written back exactly as they were.
    kept: tuple[Mapping[str, Any], ...] = ()
    extra: Mapping[str, Any] = field(default_factory=dict)

    def category(self, name: str) -> Category | None:
        """The category of that name, ignoring case."""
        folded = name.strip().casefold()
        return next((c for c in self.categories if c.name.casefold() == folded), None)

    def colour_of(self, name: str) -> str:
        found = self.category(name)
        index = found.colour if found is not None else 0
        return CATEGORY_COLOURS[index % len(CATEGORY_COLOURS)]

    def by_id(self, bookmark_id: str) -> Bookmark | None:
        return next((b for b in self.bookmarks if b.id == bookmark_id), None)

    def same_as(self, bookmark: Bookmark) -> Bookmark | None:
        """A bookmark already pointing at what `bookmark` points at."""
        return next((b for b in self.bookmarks if b.target == bookmark.target), None)

    def newest_for(self, client: str) -> Bookmark | None:
        """The newest bookmark on `client`, of any kind, if there is one."""
        theirs = [b for b in self.bookmarks if b.client == client]
        return max(theirs, key=lambda b: b.saved) if theirs else None


EMPTY: Final = Shelf(categories=(Category(DEFAULT, 0),), bookmarks=())


@dataclass(frozen=True, slots=True)
class Loaded:
    shelf: Shelf
    #: Why the file could not be read, or `None` when it could (or is absent).
    problem: str | None


# -- small helpers ------------------------------------------------------------------


def new_id() -> str:
    return uuid.uuid4().hex


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def parse_ref(text: str) -> EvidenceRef | None:
    """`file:line` back into a reference, split on the last colon.

    The last, because a file id can hold colons of its own — a Windows drive, or a
    name a log rotation wrote — and the line number never can.
    """
    name, colon, number = text.rpartition(":")
    if not colon or not name or not number.isdigit():
        return None
    line = int(number)
    return EvidenceRef(name, line) if line >= 1 else None


def matches(bookmark: Bookmark, text: str) -> bool:
    """Whether every word of `text` is somewhere in what the bookmark says."""
    words = text.casefold().split()
    if not words:
        return True
    hay = " ".join(
        (
            bookmark.said,
            bookmark.note,
            bookmark.client or "",
            bookmark.category,
            bookmark.query or "",
        )
    ).casefold()
    return all(word in hay for word in words)


# -- categories and changes ------------------------------------------------------------


def _valid_name(name: str) -> str:
    stripped = " ".join(name.split())
    if not stripped:
        raise CategoryError("A category needs a name.")
    if len(stripped) > NAME_LIMIT:
        raise CategoryError(f"A category name is at most {NAME_LIMIT} characters.")
    return stripped


def _next_colour(shelf: Shelf) -> int:
    used = {category.colour for category in shelf.categories}
    free = [index for index in range(len(CATEGORY_COLOURS)) if index not in used]
    return free[0] if free else len(shelf.categories) % len(CATEGORY_COLOURS)


def add_category(shelf: Shelf, name: str) -> Shelf:
    clean = _valid_name(name)
    if shelf.category(clean) is not None:
        raise CategoryError(f"There is already a category called {clean}.")
    made = Category(clean, _next_colour(shelf))
    return changed(shelf, categories=(*shelf.categories, made))


def rename_category(shelf: Shelf, old: str, new: str) -> Shelf:
    found = shelf.category(old)
    if found is None:
        raise CategoryError(f"There is no category called {old}.")
    clean = _valid_name(new)
    clash = shelf.category(clean)
    if clash is not None and clash is not found:
        raise CategoryError(f"There is already a category called {clash.name}.")
    return changed(
        shelf,
        categories=tuple(
            changed(category, name=clean) if category is found else category
            for category in shelf.categories
        ),
        bookmarks=tuple(
            changed(b, category=clean) if b.category == found.name else b for b in shelf.bookmarks
        ),
    )


def delete_category(shelf: Shelf, name: str) -> Shelf:
    """Remove a category; its bookmarks move to the first."""
    found = shelf.category(name)
    if found is None:
        raise CategoryError(f"There is no category called {name}.")
    first = shelf.categories[0]
    if found is first:
        raise CategoryError(
            f"{first.name} is where bookmarks go when no category is chosen,"
            " so it cannot be deleted. It can be renamed."
        )
    return changed(
        shelf,
        categories=tuple(c for c in shelf.categories if c is not found),
        bookmarks=tuple(
            changed(b, category=first.name) if b.category == found.name else b
            for b in shelf.bookmarks
        ),
    )


def _in_category(shelf: Shelf, bookmark: Bookmark) -> tuple[Shelf, Bookmark]:
    """Make the bookmark's category if it is new, and spell it as the shelf does."""
    found = shelf.category(bookmark.category)
    if found is None:
        shelf = add_category(shelf, bookmark.category)
        found = shelf.categories[-1]
    return shelf, changed(bookmark, category=found.name)


def add(shelf: Shelf, bookmark: Bookmark) -> Shelf:
    shelf, placed = _in_category(shelf, bookmark)
    return changed(shelf, bookmarks=(*shelf.bookmarks, placed))


def replace(shelf: Shelf, bookmark: Bookmark) -> Shelf:
    """Put `bookmark` where the one with its id was, or add it."""
    if shelf.by_id(bookmark.id) is None:
        return add(shelf, bookmark)
    shelf, placed = _in_category(shelf, bookmark)
    return changed(
        shelf, bookmarks=tuple(placed if b.id == bookmark.id else b for b in shelf.bookmarks)
    )


def remove(shelf: Shelf, bookmark_id: str) -> Shelf:
    return changed(shelf, bookmarks=tuple(b for b in shelf.bookmarks if b.id != bookmark_id))


# -- the file ---------------------------------------------------------------------------


def _time_text(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment.astimezone(UTC) if moment.tzinfo is not None else None


_BOOKMARK_KEYS: Final = frozenset(
    {"id", "kind", "category", "said", "note", "saved", "client", "line", "at", "query", "range"}
)


def _range_from(value: Any) -> tuple[bool, TimeWindow | None]:
    """`(readable, range)`; `None` is the whole case."""
    if value is None:
        return True, None
    if not isinstance(value, dict):
        return False, None
    start = _time(value.get("start")) if value.get("start") is not None else None
    end = _time(value.get("end")) if value.get("end") is not None else None
    if (value.get("start") is not None and start is None) or (
        value.get("end") is not None and end is None
    ):
        return False, None
    try:
        return True, TimeWindow(start, end)
    except ValueError:
        return False, None


def _bookmark_from(raw: Any) -> Bookmark | None:
    if not isinstance(raw, dict):
        return None
    try:
        kind = Kind(str(raw.get("kind")))
    except ValueError:
        return None
    ident, category, saved = raw.get("id"), raw.get("category"), _time(raw.get("saved"))
    said, note = raw.get("said", ""), raw.get("note", "")
    if not (isinstance(ident, str) and ident and isinstance(category, str) and category.strip()):
        return None
    if saved is None or not isinstance(said, str) or not isinstance(note, str):
        return None
    client = raw.get("client")
    if client is not None and not isinstance(client, str):
        return None
    line = parse_ref(raw["line"]) if isinstance(raw.get("line"), str) else None
    if raw.get("line") is not None and line is None:
        return None
    at = _time(raw.get("at"))
    if raw.get("at") is not None and at is None:
        return None
    query = raw.get("query")
    readable, window = _range_from(raw.get("range"))
    needs = {
        Kind.CLIENT: client is not None,
        Kind.ACTIVITY: client is not None and line is not None,
        Kind.REQUEST: client is not None and line is not None,
        Kind.SEARCH: isinstance(query, str) and readable,
    }
    if not needs[kind]:
        return None
    return Bookmark(
        id=ident,
        kind=kind,
        category=category,
        said=said,
        note=note,
        saved=saved,
        client=client,
        line=line,
        at=at,
        query=query if kind is Kind.SEARCH else None,
        range=window if kind is Kind.SEARCH else None,
        extra={key: value for key, value in raw.items() if key not in _BOOKMARK_KEYS},
    )


def _bookmark_to(bookmark: Bookmark) -> dict[str, Any]:
    written: dict[str, Any] = {
        **bookmark.extra,
        "id": bookmark.id,
        "kind": bookmark.kind.value,
        "category": bookmark.category,
        "said": bookmark.said,
        "note": bookmark.note,
        "saved": _time_text(bookmark.saved),
    }
    if bookmark.client is not None:
        written["client"] = bookmark.client
    if bookmark.line is not None:
        written["line"] = str(bookmark.line)
    if bookmark.at is not None:
        written["at"] = _time_text(bookmark.at)
    if bookmark.kind is Kind.SEARCH:
        written["query"] = bookmark.query
        window = bookmark.range
        written["range"] = (
            None
            if window is None
            else {
                "start": _time_text(window.start) if window.start is not None else None,
                "end": _time_text(window.end) if window.end is not None else None,
            }
        )
    return written


def _shelf_from(raw: Any) -> Shelf:
    if not isinstance(raw, dict):
        raise ValueError("the file does not hold a JSON object")
    shelf = Shelf(categories=(), bookmarks=())
    listed = raw.get("categories")
    for entry in listed if isinstance(listed, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            continue
        name = " ".join(entry["name"].split())
        if not name or shelf.category(name) is not None:
            continue
        colour = entry.get("colour")
        if isinstance(colour, bool) or not isinstance(colour, int) or colour < 0:
            # Unusable: the next free one, as a category made now would get.
            colour = _next_colour(shelf)
        extra = {key: value for key, value in entry.items() if key not in {"name", "colour"}}
        shelf = changed(shelf, categories=(*shelf.categories, Category(name, colour, extra)))
    if not shelf.categories:
        shelf = changed(shelf, categories=EMPTY.categories)
    kept: list[Mapping[str, Any]] = []
    entries = raw.get("bookmarks")
    for entry in entries if isinstance(entries, list) else []:
        bookmark = _bookmark_from(entry)
        if bookmark is None:
            kept.append(entry)
            continue
        shelf = add(shelf, bookmark)
    extra = {
        key: value
        for key, value in raw.items()
        if key not in {"version", "categories", "bookmarks"}
    }
    return changed(shelf, kept=tuple(kept), extra=extra)


def _dump(shelf: Shelf) -> bytes:
    content = {
        **shelf.extra,
        "version": _VERSION,
        "categories": [{**c.extra, "name": c.name, "colour": c.colour} for c in shelf.categories],
        "bookmarks": [*(_bookmark_to(b) for b in shelf.bookmarks), *shelf.kept],
    }
    return (json.dumps(content, ensure_ascii=False, indent=1) + "\n").encode("utf-8")


def _read(path: Path) -> Loaded:
    """Read the file; an `OSError` is let through, a file that is not ours is a problem."""
    if not path.exists():
        return Loaded(EMPTY, None)
    data = path.read_bytes()
    try:
        return Loaded(_shelf_from(json.loads(data.decode("utf-8"))), None)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return Loaded(EMPTY, str(error) or type(error).__name__)


def load(case_dir: Path) -> Loaded:
    """The case's bookmarks. Never raises: an unreadable file is a `problem`."""
    try:
        return _read(case_dir / FILE_NAME)
    except OSError as error:
        return Loaded(EMPTY, error.strerror or str(error))


def _set_aside(path: Path) -> None:
    target = path.with_name(UNREADABLE_NAME)
    number = 2
    while target.exists():
        target = path.with_name(f"bookmarks.unreadable.{number}.json")
        number += 1
    path.replace(target)


def _write(path: Path, shelf: Shelf) -> None:
    temporary = path.with_name(f"{FILE_NAME}.tmp")
    try:
        temporary.write_bytes(_dump(shelf))
        temporary.replace(path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def apply(case_dir: Path, change: Callable[[Shelf], Shelf]) -> Shelf:
    """Read the file again, make one change, write it; return what was written.

    Read again rather than trusting the copy in hand, so a second window on the
    same case keeps what the first one saved. A file that cannot be read is set
    aside first — never written over. Raises `BookmarkWriteError` when the folder
    cannot be written, and changes nothing then; a `CategoryError` from `change`
    passes through, also before anything is written.
    """
    path = case_dir / FILE_NAME
    try:
        loaded = _read(path)
        shelf = change(loaded.shelf)
        if loaded.problem is not None:
            _set_aside(path)
        _write(path, shelf)
    except OSError as error:
        raise BookmarkWriteError(error.errno, error.strerror or str(error)) from error
    return shelf
