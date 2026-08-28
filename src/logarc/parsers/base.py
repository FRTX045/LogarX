"""The contract every log format adapter implements."""

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

        Most formats have no such lines and answer `False` for everything.
        """
        ...
