"""The contract every log format adapter implements, and what they share.

`split_request_line` lives here rather than in any one format because every
kind reads a request line the same way: `%r` in a directive, `request` in a
JSON log, `cs-request` in a table, and a `request_line` group in a pattern all
split into the same four fields, and the same traffic has to reconstruct the
same way whichever kind of format read it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final, Protocol

if TYPE_CHECKING:
    from zodiarc.core.event import NormalizedEvent
    from zodiarc.core.evidence import EvidenceRef

#: The front of an absolute URL: a scheme, then `://`. RFC 3986's scheme grammar.
_ABSOLUTE: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")

#: A client written with a port that cannot be part of the address: IPv4 then a
#: port, or IPv6 in brackets with or without one. A bare IPv6 address is not
#: here on purpose — `2001:db8::1:443` ends either in a port or in its own last
#: group, and nothing in the text says which.
_PORTED_CLIENT: Final = re.compile(
    r"(?P<v4>\d{1,3}(?:\.\d{1,3}){3}):(?P<v4port>\d{1,5})"
    r"|\[(?P<v6>[0-9A-Fa-f:.]+(?:%[\w.\-]+)?)\](?::(?P<v6port>\d{1,5}))?"
)


class LogParser(Protocol):
    """Turns lines of one log format into `NormalizedEvent`.

    Implementations must be safe to share across threads and processes after
    construction: ingest builds one parser and hands it to every worker.
    """

    name: str

    def parse_line(self, line: str, ref: EvidenceRef) -> NormalizedEvent | None:
        """Parse one line.

        Returns `None` when the line is not in this format — the caller
        quarantines it rather than failing the run. A line that *is* in the
        format but has unusable individual fields should still be returned with
        those fields absent, because partial evidence is still evidence.
        """
        ...

    def is_metadata(self, line: str) -> bool:
        """Whether this line is the log's own bookkeeping rather than a request.

        A W3C `#Fields:` directive, a CSV header row. Such a line is neither
        parsed nor quarantined — the same treatment a blank line gets — because
        quarantining it would put a "lines could not be parsed" strip over every
        case of that shape, and that notice exists to mean something went wrong.

        Most formats have no such lines and answer `False` for everything, and
        a parser written before this method existed is read as saying so — see
        `skips`, which every caller goes through.
        """
        ...

    @property
    def records(self) -> frozenset[str]:
        """Which of `fieldnames.OPTIONAL_FIELDS` this format can fill at all.

        Not which a given line filled: a combined line with `-` for the
        User-Agent records one, and its client sent none. Apache's common
        format records none, and nothing about its clients follows from that.
        Read through `recorded`, which answers for a parser that predates this.
        """
        ...


def split_request_line(raw: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Split ``GET /a?b=c HTTP/1.1`` into method, path, query and protocol.

    Returns all-`None` for a request line that cannot be split. That is not an
    error worth discarding the line over: malformed request lines are routine
    in attack traffic (TLS handshakes sent to a plaintext port, deliberately
    corrupted verbs) and are themselves a signal. The caller keeps the raw text.
    """
    parts = raw.split(" ")
    if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
        method, protocol = parts[0], parts[-1]
        target = " ".join(parts[1:-1])
    elif len(parts) == 2:
        method, target, protocol = parts[0], parts[1], None
    else:
        return None, None, None, None

    path, separator, query = target.partition("?")
    return method, path, (query if separator else None), protocol


def read_target(
    path: str | None, query: str | None, url: str | None, host: str | None
) -> tuple[str | None, str | None, str | None]:
    """The path, query and host a request was for, from whichever a format gave.

    Two things a format may hand over as a "path" are more than one. Caddy's
    `request.uri`, Traefik's `RequestPath` and Cloudflare's `ClientRequestURI`
    carry the query as well, so a path with a `?` and no query of its own is
    split there — where `split_request_line` splits a `%r`. And Google's
    `requestUrl` is a whole URL, so a `url` gives up its host (when the format
    names no host of its own) and is then read as a path.

    A *path* that is absolute stays absolute. A client that sends
    `GET http://evil.example/ HTTP/1.1` is probing for a proxy, Caddy logs it
    as sent, an Apache log keeps it the same way, and the same request has to
    read the same whichever format wrote it. Only a field that *is* a URL by
    definition is taken apart.
    """
    if path is None and url is not None:
        path = url
        if (front := _ABSOLUTE.match(url)) is not None:
            rest = url[front.end() :]
            cut = min((at for at in (rest.find("/"), rest.find("?")) if at >= 0), default=len(rest))
            authority, path = rest[:cut], rest[cut:]
            if not path.startswith("/"):
                path = f"/{path}"
            if host is None and authority:
                host = authority.rpartition("@")[2]
    if path is not None and query is None and "?" in path:
        path, _separator, query = path.partition("?")
    return path, query, host


def split_client(written: str) -> tuple[str, str | None]:
    """The client's address, and its port when the address came with one.

    Google's `remoteIp` "can include port information". Kept whole, each new
    port would be a new client and one visitor would read as many. Only a port
    that cannot be part of the address is taken off: see `_PORTED_CLIENT`.
    """
    if ":" not in written:
        return written, None
    found = _PORTED_CLIENT.fullmatch(written)
    if found is None:
        return written, None
    if found["v4"] is not None:
        return found["v4"], found["v4port"]
    return found["v6"], found["v6port"]


def skips(parser: LogParser, line: str) -> bool:
    """Whether `parser` calls this line the log's own bookkeeping.

    Asked through here rather than directly, so a parser that predates
    `is_metadata` — one registered by a script with `register_format` — keeps
    working and is read as having no bookkeeping lines, which is true of every
    format that is not a table.
    """
    answer = getattr(parser, "is_metadata", None)
    return bool(answer(line)) if answer is not None else False


def recorded(parser: LogParser) -> frozenset[str] | None:
    """The fields `parser` can fill, or `None` when it does not say.

    `None` rather than a guess, for a parser registered by a script before
    `records` existed: nothing is then known to be missing from its log, which
    is how every log was read before.
    """
    answer = getattr(parser, "records", None)
    return frozenset(answer) if answer is not None else None
