"""The canonical event schema.

`NormalizedEvent` is the only type that crosses the parser boundary. Every log
format is adapted into it, and nothing downstream knows which format an event
came from. See ADR-0001.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from zodiarc.core.evidence import EvidenceRef


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """One request, in a form independent of the log format it came from.

    Only `timestamp`, `client_ip` and `evidence` are guaranteed. Everything else
    is optional because real logs are messy: attack traffic in particular
    produces malformed request lines, absent status codes and truncated fields.
    Discarding those lines would discard exactly the evidence that matters, so
    they are kept with the unparseable parts preserved in `extra`.
    """

    timestamp: datetime
    """Timezone-aware, always normalised to UTC so events from servers in
    different timezones sort correctly against each other."""

    client_ip: str
    evidence: EvidenceRef

    method: str | None = None
    path: str | None = None
    query: str | None = None
    protocol: str | None = None
    status: int | None = None
    bytes_sent: int | None = None
    referer: str | None = None
    user_agent: str | None = None
    host: str | None = None

    extra: Mapping[str, str] = field(default_factory=dict)
    """Format-specific fields with no place in the canonical schema, plus the
    raw request line when it could not be split."""

    @property
    def target(self) -> str:
        """Path and query recombined, as the client originally requested it."""
        if not self.path:
            return ""
        return f"{self.path}?{self.query}" if self.query else self.path
