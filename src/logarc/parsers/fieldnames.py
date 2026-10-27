"""Which of a log's own names mean which of ours, and a guess at the answer.

Shared by every format kind that maps by name rather than by position — JSON
objects and column tables both. They differ in where the names come from, and
not at all in what the names mean: `remote_addr` in a JSON log and `c-ip` in a
W3C one are the same field, and a candidate list per kind would drift.

Guessing is worth doing for these kinds and is not worth doing for a positional
one: a JSON key and a column heading say what they hold, where `%h` and `%v` do
not. A key nothing recognises is left out rather than guessed at, and the
proposal is always shown before it is saved — a wrong guess is worse than none,
because the reader accepts it and finds out at ingest, when every line has been
quarantined and the case looks empty.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = [
    "JOIN",
    "MAPPABLE",
    "OPTIONAL_FIELDS",
    "REQUIRED",
    "guess_mapping",
    "normalise",
    "recorded_by",
]

#: Every field of ours a name may be mapped to. `request_line` is here for the
#: logs that write `GET /a HTTP/1.1` whole; it is split into method, path,
#: query and protocol exactly as `%r` is, so the same traffic reconstructs the
#: same way whichever kind of format read it. `url` is for the logs that write
#: a whole URL, scheme and host included — Google's `requestUrl` — and is read
#: as host, path and query (`parsers.base.read_target`).
MAPPABLE: Final[tuple[str, ...]] = (
    "timestamp",
    "client_ip",
    "request_line",
    "url",
    "method",
    "path",
    "query",
    "protocol",
    "status",
    "bytes_sent",
    "referer",
    "user_agent",
    "host",
)

#: Without these there is no event: everything downstream is ordered by time
#: and grouped by address.
REQUIRED: Final[tuple[str, ...]] = ("timestamp", "client_ip")

#: The fields of an event a format may or may not record at all, which is a
#: different thing from a line leaving one empty. Apache's common format has no
#: User-Agent on any line; a combined line with `-` there is a client that sent
#: none. Only the second is evidence of anything (`parsers.base.recorded`).
OPTIONAL_FIELDS: Final[tuple[str, ...]] = (
    "method",
    "path",
    "query",
    "protocol",
    "status",
    "bytes_sent",
    "referer",
    "user_agent",
    "host",
)

#: What one mapped name of ours fills beyond itself. A request line is split
#: into four, a whole URL into three, and a path is split at a `?` it holds.
_FILLS: Final[dict[str, frozenset[str]]] = {
    "request_line": frozenset({"method", "path", "query", "protocol"}),
    "url": frozenset({"host", "path", "query"}),
    "path": frozenset({"path", "query"}),
}


def recorded_by(mapped: Iterable[str]) -> frozenset[str]:
    """The event fields a format that maps `mapped` can fill."""
    fields: set[str] = set()
    for name in mapped:
        fields |= _FILLS.get(name, {name})
    return frozenset(fields) & frozenset(OPTIONAL_FIELDS)


#: Joins two of their names into one of ours, for the W3C habit of writing the
#: date and the time in separate columns. A space would be ambiguous — a name
#: may contain one — where this cannot be mistaken for part of a name.
JOIN: Final = "+"

#: Names seen in the wild, per field of ours, best first. Nginx and Apache JSON
#: spellings, W3C column headings, and the shapes ECS and Elastic write.
_CANDIDATES: Final[dict[str, tuple[str, ...]]] = {
    "timestamp": ("time", "timestamp", "ts", "time_local", "time_iso8601", "eventtime",
                  "start_time", "date", "datetime"),
    "client_ip": ("remote_addr", "client_ip", "clientip", "c_ip", "remote_ip", "src_ip",
                  "source_ip", "ip"),
    "request_line": ("request", "request_line", "cs_request"),
    "url": ("url", "request_url", "requesturl", "full_url"),
    "method": ("request_method", "cs_method", "method", "http_method", "verb"),
    "path": ("request_uri", "cs_uri_stem", "uri_stem", "uri", "path", "http_path"),
    "query": ("query_string", "cs_uri_query", "uri_query", "query", "args"),
    "protocol": ("server_protocol", "cs_version", "protocol", "http_version"),
    "status": ("status", "sc_status", "status_code", "response_status", "http_status", "code"),
    "bytes_sent": ("body_bytes_sent", "sc_bytes", "bytes_sent", "response_size", "bytes",
                   "size", "content_length"),
    "referer": ("http_referer", "cs_referer", "referer", "referrer"),
    "user_agent": ("http_user_agent", "cs_user_agent", "user_agent", "useragent", "agent"),
    "host": ("http_host", "cs_host", "host", "server_name", "vhost", "domain"),
}  # fmt: skip

#: Leaf names that name a shape rather than a field. ECS and everything that
#: copies it writes `user_agent.original` and `url.original`, where the leaf
#: says nothing and the parent says all of it — so a path ending in one of
#: these is also offered under its parent's name.
_GENERIC_LEAVES: Final[frozenset[str]] = frozenset(
    {"original", "value", "text", "raw", "full", "name", "address"}
)

_UNINTERESTING: Final = re.compile(r"[^a-z0-9]+")


def normalise(name: str) -> str:
    """One of their names, in the spelling the candidate lists use.

    `cs(User-Agent)`, `http_user_agent` and `User Agent` all arrive here as
    `cs_user_agent`, `http_user_agent` and `user_agent`, which is as far as
    normalising can honestly go: the prefixes mean something in W3C and
    flattening them away would make `cs-host` and `s-ip` indistinguishable.
    """
    return _UNINTERESTING.sub("_", name.lower()).strip("_")


def _spellings(name: str) -> list[str]:
    """The names a path or column might be recognised under, best first."""
    leaf = name.rsplit(".", 1)[-1]
    found = [normalise(name), normalise(leaf)]
    if normalise(leaf) in _GENERIC_LEAVES and "." in name:
        found.append(normalise(name.rsplit(".", 2)[-2]))
    return found


def guess_mapping(names: Sequence[str]) -> tuple[tuple[str, str], ...]:
    """Propose a mapping from the names a log uses, for the reader to correct.

    `names` are dotted paths for a JSON log and column headings for a table.
    """
    known: dict[str, str] = {}
    for name in names:
        for spelling in _spellings(name):
            known.setdefault(spelling, name)

    mapping: list[tuple[str, str]] = []
    taken: set[str] = set()

    # W3C writes the date and the time in separate columns, so one of ours
    # comes from two of theirs. Settled before the general pass, which would
    # otherwise take `time` for the whole timestamp and leave the date behind.
    date, time = known.get("date"), known.get("time")
    if date is not None and time is not None and date != time:
        mapping.append(("timestamp", f"{date}{JOIN}{time}"))
        taken.update({date, time})

    for ours, candidates in _CANDIDATES.items():
        if any(ours == already for already, _theirs in mapping):
            continue
        for candidate in candidates:
            found = known.get(candidate)
            if found is not None and found not in taken:
                mapping.append((ours, found))
                taken.add(found)
                break
    return tuple(mapping)
