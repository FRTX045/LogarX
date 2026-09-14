"""The case manifest: what was ingested, from where, and under what settings.

This is what makes a finding reproducible. Given the manifest and the original
files, another investigator can re-run the analysis and expect the same result —
or show that they cannot, which is equally informative.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from logarc import __version__

__all__ = ["CaseManifest", "CaseManifestError", "SourceRecord"]

MANIFEST_NAME: Final = "case.json"


class CaseManifestError(RuntimeError):
    """Raised when a case manifest is missing or unreadable."""


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """One ingested log file, with the integrity record for it."""

    file_id: str
    """Short name used in evidence references; unique within a case."""

    original_path: str
    sha256: str
    size_bytes: int
    compression: str
    log_format: str
    lines_read: int
    events_parsed: int
    lines_quarantined: int

    lines_filtered: int = 0
    """Lines skipped because they belong to a client the ingest was not asked
    for. Zero for an ordinary ingest, and defaulted so a `case.json` written
    before this field existed still loads."""

    only_clients: list[str] = field(default_factory=list)
    """The addresses this file was narrowed to, sorted; empty when it was not.

    The case's own record that it holds part of a log rather than all of it. A
    partial case that reads as a complete one is the failure this tool is built
    against, so this is written down beside the integrity record rather than
    reported once and lost."""

    format_spec: dict[str, Any] | None = None
    """The format definition this file was read with, as it was written down.

    The case's own copy, so that editing or deleting the saved format it came
    from cannot make this case unreadable. Defaulted to `None`, which is what
    lets a `case.json` written before this field existed still load: the key is
    simply absent, and the reader falls back to looking `log_format` up.
    """


@dataclass
class CaseManifest:
    """Everything needed to reproduce a case's analysis."""

    case_id: str
    created_at: datetime
    tool_version: str
    sources: list[SourceRecord] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    """Every threshold the analysis was run with, recorded so that a result can
    be reproduced without knowing which defaults applied at the time."""

    @classmethod
    def create(cls, case_id: str) -> CaseManifest:
        return cls(
            case_id=case_id,
            created_at=datetime.now(UTC).replace(microsecond=0),
            tool_version=__version__,
        )

    @property
    def total_events_parsed(self) -> int:
        return sum(source.events_parsed for source in self.sources)

    @property
    def total_lines_quarantined(self) -> int:
        return sum(source.lines_quarantined for source in self.sources)

    @property
    def total_lines_filtered(self) -> int:
        return sum(source.lines_filtered for source in self.sources)

    @property
    def filtered_clients(self) -> tuple[str, ...]:
        """Every address any source was narrowed to, sorted and deduplicated.

        Empty when the case holds whole logs. One narrowed source is enough to
        make the case partial, which is why this unions rather than intersects:
        the question it answers is "is there a log here that was not read in
        full", and the answer has to be yes if any of them was not.
        """
        found: set[str] = set()
        for source in self.sources:
            found.update(source.only_clients)
        return tuple(sorted(found))

    @property
    def is_filtered(self) -> bool:
        return bool(self.filtered_clients)

    def save(self, case_root: Path) -> Path:
        case_root.mkdir(parents=True, exist_ok=True)
        path = case_root / MANIFEST_NAME
        payload = {
            "case_id": self.case_id,
            "created_at": self.created_at.isoformat(),
            "tool_version": self.tool_version,
            "sources": [asdict(source) for source in self.sources],
            "config": self.config,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
        return path

    @classmethod
    def load(cls, case_root: Path) -> CaseManifest:
        path = case_root / MANIFEST_NAME
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise CaseManifestError(f"no {MANIFEST_NAME} in {case_root}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise CaseManifestError(f"{path} could not be read: {exc}") from exc

        return cls(
            case_id=payload["case_id"],
            created_at=datetime.fromisoformat(payload["created_at"]),
            tool_version=payload["tool_version"],
            sources=[SourceRecord(**source) for source in payload.get("sources", [])],
            config=payload.get("config", {}),
        )
