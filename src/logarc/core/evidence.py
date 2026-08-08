"""Links from derived findings back to the raw log lines that produced them."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """Points at one line of one source file.

    Every event, and therefore every episode and every node in an activity
    graph, carries these. Without them a finding is an assertion; with them it
    is reproducible from the original evidence.
    """

    source_file_id: str
    line_no: int

    def __str__(self) -> str:
        return f"{self.source_file_id}:{self.line_no}"
