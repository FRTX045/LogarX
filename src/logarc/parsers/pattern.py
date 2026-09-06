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
from typing import TYPE_CHECKING

from logarc.core.event import NormalizedEvent
from logarc.parsers.base import split_request_line
from logarc.parsers.fieldnames import MAPPABLE, REQUIRED
from logarc.parsers.times import TimeFormatError, check_time_format, read_time

if TYPE_CHECKING:
    from logarc.core.evidence import EvidenceRef

__all__ = ["PatternFormatError", "PatternParser"]


class PatternFormatError(ValueError):
    """Raised when a pattern cannot be compiled or cannot yield an event."""


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

    def __init__(self, pattern: str, *, name: str = "pattern", time_format: str = "") -> None:
        try:
            self._pattern = re.compile(pattern)
        except re.error as exc:
            raise PatternFormatError(f"this pattern will not compile: {exc}") from exc

        named = set(self._pattern.groupindex)
        if not named:
            raise PatternFormatError(
                "this pattern names no groups. Name the parts you want with "
                "(?P<client_ip>...), using logarc's own field names: "
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

        timestamp = read_time(found.get("timestamp"), self._time_format)
        if timestamp is None:
            return None
        client_ip = _clean(found.get("client_ip"))
        if client_ip is None:
            return None

        method = _clean(found.get("method"))
        path = _clean(found.get("path"))
        query = _clean(found.get("query"))
        protocol = _clean(found.get("protocol"))

        extra = {
            group: text
            for group in self._extra_groups
            if (text := _clean(found.get(group))) is not None
        }

        if (request_line := _clean(found.get("request_line"))) is not None:
            method, path, query, protocol = split_request_line(request_line)
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
            host=_clean(found.get("host")),
            extra=extra,
        )
