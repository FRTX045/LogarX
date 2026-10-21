"""The small filter language both search boxes speak.

`status:404 path:/admin union select` — a token that names a filter the box knows,
with a value it can read, is a filter; every other token is text to find in the
request. The evidence box reads it over one activity's lines; the client box reads
it over the whole case, where the event store answers the same question in SQL.

**A token is a filter only when it is fully understood.** A typo such as
`stat:404`, or `status:abc`, is searched as the text it is: it finds nothing, and
the panel says so. Read as a near miss instead, it would be a filter nobody asked
for, narrowing the evidence without a word on screen.

Matching is defined here once. Text and paths match the value as logged *or* as
the panel shows it decoded — `unquote` on the path and `unquote_plus` on the query,
one pass, which is how `style.decode_target` reads them — and the logged value
stands when its bytes are not valid UTF-8. That last rule is the SQL's: DuckDB's
`url_decode` refuses such input outright, so the store keeps the raw value there,
and so must this, or the two searches would disagree about the same request.

No Qt here, so every rule is checked without a display.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from enum import Enum
from typing import TYPE_CHECKING, Final
from urllib.parse import unquote, unquote_plus

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from logarc.core.event import NormalizedEvent

__all__ = [
    "ANY_DAY",
    "Query",
    "Scope",
    "Suggestion",
    "decoded_path",
    "decoded_target",
    "evidence_part",
    "fold",
    "is_time",
    "is_whole_address",
    "labels_for_activity",
    "parse",
    "suggestions",
    "tokens",
    "understood",
    "value_counts",
    "without_time",
]


class Scope(Enum):
    """Which box a query was typed into, and so which filters it may use."""

    EVIDENCE = "evidence"
    """One activity of one client: no address to choose, no activity to name."""

    CASE = "case"
    """Every client in the range."""

    @property
    def keys(self) -> frozenset[str]:
        if self is Scope.EVIDENCE:
            return _REQUEST_KEYS
        return _REQUEST_KEYS | {"ip", "activity"}


_REQUEST_KEYS: Final = frozenset({"status", "path", "method", "after", "before"})

_STATUS: Final = re.compile(r"[1-5]\d\d")
_CLASS: Final = re.compile(r"[1-5]xx", re.IGNORECASE)
_METHOD: Final = re.compile(r"[A-Za-z]+")
_ADDRESS: Final = re.compile(r"[0-9A-Fa-f.:]+")

#: A stand-in date for asking whether a query filters anything at all. A time
#: of day is a filter on every day, so any real date answers that; it is
#: never the date a time is read on.
ANY_DAY: Final = date(2000, 1, 1)
_DAY: Final = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_STAMP: Final = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{1,2}):(\d{2})(?::(\d{2}))?")
_CLOCK: Final = re.compile(r"(\d{1,2}):(\d{2})(?::(\d{2}))?")


def tokens(text: str) -> list[str]:
    """Split on whitespace, keeping a double-quoted run together, quotes included.

    An unclosed quote runs to the end: a phrase still being typed is one token,
    not a scatter of words that each narrow the result.
    """
    found: list[str] = []
    current: list[str] = []
    quoted = False
    for char in text:
        if char == '"':
            quoted = not quoted
            current.append(char)
        elif char.isspace() and not quoted:
            if current:
                found.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        found.append("".join(current))
    return found


def understood(token: str, scope: Scope) -> bool:
    """Whether `token` is a filter this box reads, with a value it can use.

    Only these become chips. A time of day counts: it is read on a date the box
    supplies when the query is parsed.
    """
    split = _split(token)
    if split is None:
        return False
    key, value = split
    return key in scope.keys and _valid(key, value)


def _split(token: str) -> tuple[str, str] | None:
    key, colon, value = token.partition(":")
    if not colon or not key or key.startswith('"'):
        return None
    return key.lower(), _unquoted(value)


def _unquoted(value: str) -> str:
    if value.startswith('"'):
        value = value[1:]
        if value.endswith('"'):
            value = value[:-1]
    return value


def _valid(key: str, value: str) -> bool:
    if not value:
        return False
    if key == "status":
        return bool(_STATUS.fullmatch(value) or _CLASS.fullmatch(value))
    if key == "method":
        return bool(_METHOD.fullmatch(value))
    if key in ("after", "before"):
        return _moment(value, date(2000, 1, 1)) is not None
    if key == "ip":
        return bool(_ADDRESS.fullmatch(value))
    return key in ("path", "activity")


def _moment(value: str, day: date | None) -> datetime | None:
    """A UTC moment from a date, a date and time, or a time of day on `day`."""
    try:
        if match := _DAY.fullmatch(value):
            year, month, dom = (int(part) for part in match.groups())
            return datetime(year, month, dom, tzinfo=UTC)
        if match := _STAMP.fullmatch(value):
            year, month, dom, hour, minute = (int(part) for part in match.groups()[:5])
            second = int(match.group(6) or 0)
            return datetime(year, month, dom, hour, minute, second, tzinfo=UTC)
        if match := _CLOCK.fullmatch(value):
            if day is None:
                return None
            clock = time(int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))
            return datetime.combine(day, clock, tzinfo=UTC)
    except ValueError:
        return None
    return None


def is_whole_address(text: str) -> bool:
    """Whether `text` is a complete IPv4 address rather than part of one."""
    parts = text.split(".")
    return len(parts) == 4 and all(
        part.isdigit() and len(part) <= 3 and int(part) <= 255 for part in parts
    )


def _looks_like_address(token: str) -> bool:
    """A bare token the client box has always read as an address.

    Digits with dots, or hex with colons, or digits alone. `fe80` alone is a word:
    read as an address it would turn every hex-looking word into an address search.
    """
    if not _ADDRESS.fullmatch(token) or not any(char.isdigit() for char in token):
        return False
    return "." in token or ":" in token or token.isdigit()


@dataclass(frozen=True, slots=True)
class Query:
    """A parsed query. Same key twice is either; different keys and words are all."""

    text: str = ""
    statuses: tuple[int, ...] = ()
    classes: tuple[int, ...] = ()
    """Hundreds: 4 for `status:4xx`."""
    paths: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    after: datetime | None = None
    """Inclusive."""
    before: datetime | None = None
    """Exclusive, so `after:12:00 before:12:05` is five minutes, not five and a second."""
    words: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    activities: tuple[str, ...] = ()
    """Read at the client level, from the Where to start scan; `matches` ignores them."""

    @property
    def is_empty(self) -> bool:
        return not (self.has_request_filters or self.ips or self.activities)

    @property
    def has_request_filters(self) -> bool:
        """Whether anything here narrows requests, rather than whole clients."""
        return bool(
            self.statuses
            or self.classes
            or self.paths
            or self.methods
            or self.after
            or self.before
            or self.words
        )

    @property
    def is_address_only(self) -> bool:
        """An address search and nothing else: the client box's search before this one."""
        return bool(self.ips) and not (self.has_request_filters or self.activities)

    def matches(self, event: NormalizedEvent) -> bool:
        """Whether this one request passes every filter and contains every word."""
        if (self.statuses or self.classes) and not (
            event.status is not None
            and (event.status in self.statuses or event.status // 100 in self.classes)
        ):
            return False
        if self.paths:
            path = event.path or ""
            found = (fold(path), fold(decoded_path(path)))
            if not any(wanted in side for wanted in self.paths for side in found):
                return False
        if self.methods and not _method_in(event.method, self.methods):
            return False
        if self.after is not None and event.timestamp < self.after:
            return False
        if self.before is not None and event.timestamp >= self.before:
            return False
        if self.ips and not any(_address_matches(event.client_ip, ip) for ip in self.ips):
            return False
        if self.words:
            raw = fold(event.target)
            shown = fold(decoded_target(event.path or "", event.query))
            if not all(word in raw or word in shown for word in self.words):
                return False
        return True


def fold(text: str) -> str:
    """Lower case, the same way the event store's SQL does.

    The case box asks DuckDB and the evidence box asks Python, so the two must
    agree on every request. Over all of Unicode their `lower` differs in exactly
    two places (measured: Python 3.12, DuckDB 1.5.5): Python writes a dotted
    capital I as `i` plus a combining dot, and a capital sigma ending a word as
    the final form. Both are folded here to plain `i` and the ordinary sigma,
    which is also what a reader typing would expect to match. The store applies
    the same final step to DuckDB's `lower`.
    """
    return text.replace("\u0130", "i").lower().replace("\u03c2", "\u03c3")


def _method_in(method: str | None, wanted: tuple[str, ...]) -> bool:
    """Whether `method` is one of `wanted`, compared in ASCII.

    A method filter can only be typed in letters a to z. Python's `upper` turns
    some letters outside ASCII into ASCII (a dotless i into `I`) and DuckDB's does
    not, so a method outside ASCII matches nothing, in both.
    """
    return method is not None and method.isascii() and method.upper() in wanted


def labels_for_activity(labels: Iterable[tuple[str, str, str]], value: str) -> frozenset[str]:
    """The rules an `activity:` value names: a category, or part of a rule's name.

    `labels` is what the Where to start scan saw, `(rule id, name, category)`.
    Read from there rather than from the rule packs, a detection only CRS made
    is named by the category CRS gave it, and a request nothing matched by the
    fallback that named it. A category may be typed with a space for its
    underscore: `path traversal`.
    """
    wanted = fold(value.strip())
    if not wanted:
        return frozenset()
    category = wanted.replace(" ", "_")
    return frozenset(
        rule for rule, name, kind in labels if kind == category or wanted in fold(name)
    )


def _address_matches(client_ip: str, wanted: str) -> bool:
    return client_ip == wanted if is_whole_address(wanted) else wanted in client_ip


def parse(text: str, scope: Scope, *, day: date | None = None) -> Query:
    """Read `text` as a query typed into `scope`'s box.

    `day` is the date a time of day is read on: the activity's for the evidence
    box, the range's start for the client box. Without one, a time of day is not
    applied — never guessed.
    """
    statuses: list[int] = []
    classes: list[int] = []
    paths: list[str] = []
    methods: list[str] = []
    after: datetime | None = None
    before: datetime | None = None
    words: list[str] = []
    ips: list[str] = []
    activities: list[str] = []
    for token in tokens(text):
        split = _split(token)
        if split is not None and split[0] in scope.keys and not split[1]:
            continue  # `status:` with the value still to come
        if not understood(token, scope):
            if scope is Scope.CASE and _looks_like_address(token):
                ips.append(token)
            else:
                words.append(fold(_unquoted(token)))
            continue
        assert split is not None
        key, value = split
        if key == "status":
            if _CLASS.fullmatch(value):
                classes.append(int(value[0]))
            else:
                statuses.append(int(value))
        elif key == "path":
            paths.append(fold(value))
        elif key == "method":
            methods.append(value.upper())
        elif key == "after":
            after = _moment(value, day) or after
        elif key == "before":
            before = _moment(value, day) or before
        elif key == "ip":
            ips.append(value)
        else:
            activities.append(value.lower())
    return Query(
        text=text,
        statuses=tuple(statuses),
        classes=tuple(classes),
        paths=tuple(paths),
        methods=tuple(methods),
        after=after,
        before=before,
        words=tuple(word for word in words if word),
        ips=tuple(ips),
        activities=tuple(activities),
    )


def evidence_part(text: str) -> str:
    """What of a case search the evidence box can take: its filters on requests.

    Addresses and activities chose the client, and a time chose the range;
    inside one client they have nothing left to say. A key still waiting for its
    value goes too.
    """
    kept: list[str] = []
    for token in tokens(text):
        split = _split(token)
        if split is not None and split[0] in Scope.CASE.keys:
            if not split[1]:
                continue
            if split[0] in _CLIENT_KEYS and understood(token, Scope.CASE):
                continue
        elif _looks_like_address(token):
            continue
        kept.append(token)
    return " ".join(kept)


def without_time(text: str) -> str:
    """`text` without its `after:` and `before:`, which the case box makes the range."""
    return " ".join(token for token in tokens(text) if not is_time(token))


def is_time(token: str) -> bool:
    """Whether `token` is a whole `after:` or `before:` filter."""
    split = _split(token)
    return split is not None and split[0] in ("after", "before") and understood(token, Scope.CASE)


#: The case box's filters that choose clients or the range, not requests.
_CLIENT_KEYS: Final = frozenset({"ip", "activity", "after", "before"})


def decoded_path(path: str) -> str:
    """The path as the panel shows it: one pass of `unquote`, raw when not UTF-8."""
    try:
        return unquote(path, errors="strict")
    except UnicodeDecodeError:
        return path


def _decoded_query(query: str) -> str:
    try:
        return unquote_plus(query, errors="strict")
    except UnicodeDecodeError:
        return query


def decoded_target(path: str, query: str | None) -> str:
    """Path and query decoded under their own rules, joined as `NormalizedEvent.target`."""
    if not path:
        return ""
    return decoded_path(path) + (f"?{_decoded_query(query)}" if query else "")


# -- what the suggestion list offers ----------------------------------------------


@dataclass(frozen=True, slots=True)
class Suggestion:
    """One row of the list under a search box."""

    completion: str
    """What choosing it puts in the box."""
    note: str
    """What it means, or how much of it there is."""
    selectable: bool = True
    """False for a row that only explains, such as "any text"."""


#: Every filter with a line saying what it takes, in the order a reader reaches for
#: them. The examples are values the reader could type as they stand.
_NOTES: Final[dict[str, str]] = {
    "ip": "an address, or part of one \u2014 198.51.100",
    "status": "response code \u2014 404, 2xx",
    "path": "part of the path \u2014 /admin, .env",
    "method": "GET, POST, HEAD",
    "activity": "what the rules named it \u2014 injection (per client, from Triage)",
    "after": "at or after a time \u2014 after:14:05, after:2026-03-09",
    "before": "before a time \u2014 before:14:30, before:2026-03-10",
}
_ORDER: Final = ("ip", "status", "path", "method", "activity", "after", "before")
_ANY_TEXT: Final = Suggestion("any text", "searches the request itself \u2014 union select", False)
_TITLES: Final = {Scope.EVIDENCE: "FILTER BY", Scope.CASE: "SEARCH CLIENTS BY"}


def suggestions(
    fragment: str,
    scope: Scope,
    values: Mapping[str, Sequence[tuple[str, str]]],
    *,
    values_title: str = "VALUES",
) -> tuple[str, tuple[Suggestion, ...]]:
    """`(title, rows)` for the list under a box, given the token being typed.

    Nothing typed: every filter, and a reminder that plain text works. Part of a
    key: the filters it begins. A key and its colon: the values `values` holds for
    it, narrowed by whatever follows the colon. Anything else: nothing, and the
    list closes.
    """
    keys = [key for key in _ORDER if key in scope.keys]
    if not fragment:
        rows = tuple(Suggestion(f"{key}:", _NOTES[key]) for key in keys)
        return _TITLES[scope], (*rows, _ANY_TEXT)
    key, colon, partial = fragment.partition(":")
    key = key.lower()
    if not colon:
        rows = tuple(Suggestion(f"{k}:", _NOTES[k]) for k in keys if k.startswith(key))
        return (_TITLES[scope], rows) if rows else ("", ())
    if key not in scope.keys or not values.get(key):
        return "", ()
    wanted = partial.lower()
    rows = tuple(
        Suggestion(f"{key}:{value}", note)
        for value, note in values[key]
        if value.lower().startswith(wanted)
    )
    return (values_title, rows) if rows else ("", ())


def value_counts(events: Iterable[NormalizedEvent], key: str) -> list[tuple[str, int]]:
    """How often each value of `key` occurs: most common first, then by value.

    For `status`, the classes follow the codes: `4xx` is often the useful one, and
    a reader can see what it adds up to.
    """
    counts: Counter[str] = Counter()
    for event in events:
        # Only what the box can make a filter of: offering `status:999` or
        # `method:M-SEARCH` would complete to text that finds nothing.
        if key == "status" and event.status is not None and 100 <= event.status <= 599:
            counts[str(event.status)] += 1
        elif key == "method" and event.method and _METHOD.fullmatch(event.method):
            counts[event.method.upper()] += 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    if key != "status":
        return ranked
    classes: Counter[str] = Counter()
    for code, count in counts.items():
        classes[f"{code[0]}xx"] += count
    return ranked + sorted(classes.items())
