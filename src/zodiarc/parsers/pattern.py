r"""Reads a log by a regular expression the reader wrote.

The last kind, and the one that has to work when the other three do not: a
syslog-wrapped line, an appliance with a syntax of its own, a load balancer
that agrees with nobody. It is also the simplest, because **the named groups
are the mapping**. A regex already names its parts; asking the reader to name
them a second time in a separate list would be asking them to keep two things
in step, and the second one would drift.

So a group called `client_ip` is the client address, a group called `took` is
kept beside the event as evidence, and there is nothing else to configure.

**Anchored at the start of the line**, like the directive compiler's. Left
unanchored it was measured doing real harm: `(?P<timestamp>\d+) (?P<client_ip>\S+)`
found `1 09:00:45` inside `May  1 09:00:45 gw01 proxy…`, read the `1` as one
second past the epoch, and produced events dated 1970 that nothing downstream
would question. A pattern describes the line, not a fragment of it; a reader
who wants to skip a prefix says so with `.*`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from zodiarc.core.event import NormalizedEvent
from zodiarc.parsers.base import read_target, split_client, split_request_line
from zodiarc.parsers.fieldnames import MAPPABLE, REQUIRED, recorded_by
from zodiarc.parsers.times import TimeFormatError, check_time_format, read_time

if TYPE_CHECKING:
    from zodiarc.core.evidence import EvidenceRef

__all__ = ["ESCAPES", "PatternFormatError", "PatternParser"]

#: The ways a log may escape what it writes, as `PatternFormatSpec.escapes`
#: names them. `haproxy`: every byte outside 32-126, and `#` and `"` (and in
#: header captures `{ | }`), written as `#` and two hex digits.
ESCAPES: Final[tuple[str, ...]] = ("", "haproxy")

_HASH_RUN: Final = re.compile(r"(?:#[0-9A-Fa-f]{2})+")


class PatternFormatError(ValueError):
    """Raised when a pattern cannot be compiled or cannot yield an event."""


def _bytes_back(run: re.Match[str]) -> str:
    """A run of `#XX` as the bytes it stands for.

    A run, not each escape alone: a UTF-8 character outside ASCII is several
    bytes, and decoded one at a time `€` would come back as three Latin-1
    characters. Bytes that are not UTF-8 are kept as Latin-1, which loses none.
    """
    raw = bytes.fromhex(run.group().replace("#", ""))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _unhash(text: str) -> str:
    """Undo HAProxy's escaping. Exact, because it writes `#` itself as `#23`."""
    return _HASH_RUN.sub(_bytes_back, text) if "#" in text else text


def _clean(raw: str | None) -> str | None:
    """A group as a field, treating `-` and empty as absent."""
    if raw is None:
        return None
    text = raw.strip()
    return None if text in ("", "-") else text


def _as_int(raw: str | None) -> int | None:
    text = _clean(raw)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


class PatternParser:
    """Parses lines of one log by a named-group regular expression.

    Immutable after construction and holding a compiled pattern, so a single
    parser can be shared across ingest workers.
    """

    def __init__(
        self, pattern: str, *, name: str = "pattern", time_format: str = "", escapes: str = ""
    ) -> None:
        try:
            self._pattern = re.compile(pattern)
        except re.error as exc:
            raise PatternFormatError(f"this pattern will not compile: {exc}") from exc

        if escapes not in ESCAPES:
            known = ", ".join(repr(value) for value in ESCAPES if value)
            raise PatternFormatError(
                f"escapes {escapes!r} is not one Zodiarc knows; it knows {known}, or none at all"
            )
        self._unescape = escapes == "haproxy"

        named = set(self._pattern.groupindex)
        if not named:
            raise PatternFormatError(
                "this pattern names no groups. Name the parts you want with "
                "(?P<client_ip>...), using Zodiarc's own field names: "
                f"{', '.join(MAPPABLE)}"
            )
        missing = [field for field in REQUIRED if field not in named]
        if missing:
            raise PatternFormatError(
                f"a pattern needs a group for {' and '.join(REQUIRED)}; "
                f"{', '.join(missing)} is missing. It names: {', '.join(sorted(named))}"
            )

        try:
            check_time_format(time_format)
        except TimeFormatError as exc:
            raise PatternFormatError(str(exc)) from exc

        self.name = name
        self.records = recorded_by(named)
        self._time_format = time_format
        self._extra_groups = tuple(sorted(named - set(MAPPABLE)))

    def is_metadata(self, line: str) -> bool:
        """A pattern log has no bookkeeping this kind could recognise.

        A line the pattern does not match is refused and quarantined, which is
        the honest answer: nothing here can tell a comment from a line the
        reader's regex simply got wrong.
        """
        del line
        return False

    def parse_line(self, line: str, ref: EvidenceRef) -> NormalizedEvent | None:
        """Parse one line, or return `None` if the pattern does not read it."""
        match = self._pattern.match(line)
        if match is None:
            return None
        found = match.groupdict()
        if self._unescape:
            # Before anything reads a group, so a rule sees the `"` the client
            # sent rather than `#22`, and `-` is still recognised as absent.
            found = {group: _unhash(text) if text else text for group, text in found.items()}

        timestamp = read_time(found.get("timestamp"), self._time_format)
        if timestamp is None:
            return None
        written = _clean(found.get("client_ip"))
        if written is None:
            return None
        client_ip, client_port = split_client(written)

        method = _clean(found.get("method"))
        protocol = _clean(found.get("protocol"))
        path, query, host = read_target(
            _clean(found.get("path")),
            _clean(found.get("query")),
            _clean(found.get("url")),
            _clean(found.get("host")),
        )

        extra = {
            group: text
            for group in self._extra_groups
            if (text := _clean(found.get(group))) is not None
        }
        if client_port is not None:
            extra.setdefault("client_port", client_port)

        if (request_line := _clean(found.get("request_line"))) is not None:
            method, path, query, protocol = split_request_line(request_line)
            # Envoy writes a request it refused before routing as `- - HTTP/1.1`:
            # no method and no path, not a request for `-`.
            method, path = _clean(method), _clean(path)
            if method is None:
                extra["malformed_request_line"] = request_line

        return NormalizedEvent(
            timestamp=timestamp,
            client_ip=client_ip,
            evidence=ref,
            method=method,
            path=path,
            query=query.lstrip("?") if query else None,
            protocol=protocol,
            status=_as_int(found.get("status")),
            bytes_sent=_as_int(found.get("bytes_sent")),
            referer=_clean(found.get("referer")),
            user_agent=_clean(found.get("user_agent")),
            host=host,
            extra=extra,
        )
