"""A case: one investigation's evidence, on disk.

This is the layer both the CLI and the GUI drive. Keeping the workflow here
rather than in either interface is what makes the rule "anything the GUI can do
is scriptable" true by construction instead of by discipline.
"""

from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING

from logarc.evidence import EvidenceLine, read_evidence
from logarc.ingest.pipeline import DEFAULT_BATCH_SIZE, IngestResult, ingest_file
from logarc.ingest.quarantine import Quarantine
from logarc.storage.case import MANIFEST_NAME, CaseManifest, SourceRecord
from logarc.storage.event_store import ParquetEventStore

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from logarc.core.evidence import EvidenceRef

__all__ = ["Case", "CaseError"]


class CaseError(RuntimeError):
    """Raised when a case cannot be created, opened or added to."""


class Case:
    """An open case directory, holding the manifest and the event store."""

    def __init__(self, root: Path, manifest: CaseManifest) -> None:
        self.root = root
        self.manifest = manifest
        self.store = ParquetEventStore(root)

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def create(cls, root: Path | str, case_id: str | None = None) -> Case:
        """Start a new case in an empty or non-existent directory."""
        root = Path(root)
        if (root / MANIFEST_NAME).exists():
            raise CaseError(
                f"a case already exists at {root}; refusing to overwrite gathered evidence"
            )
        root.mkdir(parents=True, exist_ok=True)
        manifest = CaseManifest.create(case_id or root.name)
        manifest.save(root)
        return cls(root, manifest)

    @classmethod
    def open(cls, root: Path | str) -> Case:
        """Open an existing case for analysis."""
        root = Path(root)
        if not (root / MANIFEST_NAME).exists():
            raise CaseError(f"no case at {root}; expected a {MANIFEST_NAME} there")
        return cls(root, CaseManifest.load(root))

    def close(self) -> None:
        self.store.close()

    # -- evidence ----------------------------------------------------------

    def read_evidence(self, refs: Sequence[EvidenceRef]) -> list[EvidenceLine]:
        """Fetch the raw source lines behind a set of references.

        Lives on the case rather than in the interface layers because it is
        what makes a finding checkable, and both the CLI and the GUI need it to
        say the same thing about the same evidence.
        """
        return read_evidence(self.manifest, refs)

    def __enter__(self) -> Case:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        # Only finalise a clean run: a case half-written because ingest raised
        # should stay open so the failure is visible rather than sealed in.
        if exc is None and not self.store.is_finalized and self.manifest.sources:
            self.finalize()
        self.close()

    # -- ingest ------------------------------------------------------------

    def ingest(
        self,
        paths: Sequence[Path],
        *,
        log_format: str | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        on_progress: Callable[[int, int], None] | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> list[IngestResult]:
        """Read logs into the case and record them in the manifest.

        `should_cancel` lets a caller stop a long ingest; it raises
        `IngestCancelled` and the case is left un-finalised, so a stopped run
        cannot be mistaken for a complete one.
        """
        if self.store.is_finalized:
            raise CaseError(
                f"case at {self.root} is already finalised; start a new case to add more logs"
            )

        results: list[IngestResult] = []
        try:
            with Quarantine(self.root) as quarantine:
                for path in paths:
                    result = ingest_file(
                        Path(path),
                        self.store,
                        quarantine,
                        file_id=self._allocate_file_id(Path(path)),
                        log_format=log_format,
                        batch_size=batch_size,
                        on_progress=on_progress,
                        should_cancel=should_cancel,
                    )
                    results.append(result)
                    self.manifest.sources.append(_to_source_record(result))
        finally:
            # Saved even when the run is cut short. Events sitting in the store
            # that the manifest does not name would be evidence with no chain of
            # custody, which is the one thing the manifest exists to prevent.
            self.manifest.save(self.root)
        return results

    def finalize(self) -> None:
        """Close ingest and build the read-side structures."""
        self.store.finalize()
        self.manifest.save(self.root)

    def _allocate_file_id(self, path: Path) -> str:
        """Pick an id that is unique within the case.

        Rotated logs are routinely all named `access.log`, so falling back to
        the bare filename would make evidence references ambiguous about which
        file a line came from.
        """
        taken = {source.file_id for source in self.manifest.sources}
        if path.name not in taken:
            return path.name
        for suffix in range(2, len(taken) + 3):
            candidate = f"{path.stem}({suffix}){path.suffix}"
            if candidate not in taken:
                return candidate
        raise AssertionError("unreachable: the loop covers more names than can be taken")


def _to_source_record(result: IngestResult) -> SourceRecord:
    return SourceRecord(
        file_id=result.file_id,
        original_path=result.original_path,
        sha256=result.sha256,
        size_bytes=result.size_bytes,
        compression=result.compression,
        log_format=result.log_format,
        lines_read=result.lines_read,
        events_parsed=result.events_parsed,
        lines_quarantined=result.lines_quarantined,
    )
