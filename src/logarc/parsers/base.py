"""The contract every log format adapter implements, and what they share.

`split_request_line` lives here rather than in any one format because every
kind reads a request line the same way: `%r` in a directive, `request` in a
JSON log, `cs-request` in a table, and a `request_line` group in a pattern all
split into the same four fields, and the same traffic has to reconstruct the
same way whichever kind of format read it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from logarc.core.event import NormalizedEvent
    from logarc.core.evidence import EvidenceRef


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


def skips(parser: LogParser, line: str) -> bool:
    """Whether `parser` calls this line the log's own bookkeeping.

    Asked through here rather than directly, so a parser that predates
    `is_metadata` — one registered by a script with `register_format` — keeps
    working and is read as having no bookkeeping lines, which is true of every
    format that is not a table.
    """
    answer = getattr(parser, "is_metadata", None)
    return bool(answer(line)) if answer is not None else False
