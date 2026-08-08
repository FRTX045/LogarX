"""The contract every log format adapter implements."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from logarc.core.event import NormalizedEvent
    from logarc.core.evidence import EvidenceRef


@runtime_checkable
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
