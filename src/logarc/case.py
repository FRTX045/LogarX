"""A case: one investigation's evidence, on disk.

This is the layer both the CLI and the GUI drive. Keeping the workflow here
rather than in either interface is what makes the rule "anything the GUI can do
is scriptable" true by construction instead of by discipline.
"""

from __future__ import annotations

from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING

from logarc.detect.crs.store import CrsEvidence
from logarc.evidence import EvidenceLine, read_evidence
from logarc.ingest.parallel import ingest_file_parallel, worth_splitting
from logarc.ingest.pipeline import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_LINE_BYTES,
    IngestResult,
    ingest_file,
)
from logarc.ingest.quarantine import Quarantine
from logarc.ingest.reader import Compression
from logarc.parsers.spec import spec_to_dict
from logarc.storage.case import MANIFEST_NAME, CaseManifest, SourceRecord
from logarc.storage.event_store import ParquetEventStore

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Sequence

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

    def crs_evidence(self) -> CrsEvidence:
        """What CRS contributed to this case, if it was enriched.

        Here rather than in the interface layers for the same reason
        `read_evidence` is: both the CLI and the GUI need it, and when each
        worked it out for itself the GUI got it wrong — it passed no CRS at all,
        so the same case answered differently depending on which front end
        asked. One accessor makes that particular disagreement impossible
        rather than merely fixed.
        """
        return CrsEvidence.of(self.root, self.manifest.config)

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

    @property
    def is_filtered(self) -> bool:
        """Whether any log in this case was read only in part.

        The window, the reports and `list-ips` all have to be able to say so:
        a case holding one client's traffic answers "who else was there" with
        silence, and silence reads exactly like nobody.
        """
        return self.manifest.is_filtered

    @property
    def filtered_clients(self) -> tuple[str, ...]:
        """Every address this case was narrowed to, sorted; empty if it was not."""
        return self.manifest.filtered_clients

    def ingest(
        self,
        paths: Sequence[Path],
        *,
        log_format: str | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        only_clients: Collection[str] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
        should_cancel: Callable[[], bool] | None = None,
        workers: int = 1,
    ) -> list[IngestResult]:
        """Read logs into the case and record them in the manifest.

        `should_cancel` lets a caller stop a long ingest; it raises
        `IngestCancelled` and the case is left un-finalised, so a stopped run
        cannot be mistaken for a complete one.

        `workers` above one parses the file in byte ranges across processes.
        It is silently ignored for a file that cannot benefit — a compressed log
        has no random access, and a small one is finished before the workers
        have started. Falling back rather than refusing keeps `--workers` from
        being a flag that breaks on files the tool otherwise reads happily.

        Cancellation is not offered on the parallel path. A stop would have to
        reach several processes and leave the case in a state each of them
        agreed on, and claiming a cancel that only sometimes arrives is worse
        than not offering one; the sequential path keeps it.
        """
        if self.store.is_finalized:
            raise CaseError(
                f"case at {self.root} is already finalised; start a new case to add more logs"
            )

        results: list[IngestResult] = []
        try:
            with Quarantine(self.root) as quarantine:
                for path in paths:
                    source = Path(path)
                    file_id = self._allocate_file_id(source)
                    if should_cancel is None and worth_splitting(source, workers=workers):
                        result = self._ingest_in_parallel(
                            source,
                            file_id=file_id,
                            log_format=log_format,
                            batch_size=batch_size,
                            max_line_bytes=max_line_bytes,
                            only_clients=only_clients,
                            workers=workers,
                            on_progress=on_progress,
                        )
                    else:
                        result = ingest_file(
                            source,
                            self.store,
                            quarantine,
                            file_id=file_id,
                            log_format=log_format,
                            batch_size=batch_size,
                            max_line_bytes=max_line_bytes,
                            only_clients=only_clients,
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

    def _ingest_in_parallel(
        self,
        path: Path,
        *,
        file_id: str,
        log_format: str | None,
        batch_size: int,
        max_line_bytes: int,
        only_clients: Collection[str] | None,
        workers: int,
        on_progress: Callable[[int, int], None] | None,
    ) -> IngestResult:
        """Run the parallel path and shape its counts into an `IngestResult`.

        The store this case holds stays out of it: workers open their own,
        because a `ParquetEventStore` carries a database connection and cannot
        cross a process boundary.
        """
        counts, sha256, size_bytes, resolved, duration = ingest_file_parallel(
            path,
            self.root,
            file_id=file_id,
            log_format=log_format,
            workers=workers,
            batch_size=batch_size,
            max_line_bytes=max_line_bytes,
            only_clients=only_clients,
            on_progress=on_progress,
        )
        return IngestResult(
            file_id=file_id,
            original_path=str(path),
            sha256=sha256,
            size_bytes=size_bytes,
            compression=Compression.NONE.value,
            log_format=resolved.name,
            format_spec=resolved.spec,
            lines_read=counts.lines_read,
            events_parsed=counts.events_parsed,
            lines_quarantined=counts.lines_quarantined,
            lines_filtered=counts.lines_filtered,
            only_clients=tuple(sorted(only_clients or ())),
            duration_seconds=duration,
        )

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
        format_spec=spec_to_dict(result.format_spec) if result.format_spec else None,
        lines_read=result.lines_read,
        events_parsed=result.events_parsed,
        lines_quarantined=result.lines_quarantined,
        lines_filtered=result.lines_filtered,
        only_clients=list(result.only_clients),
    )
