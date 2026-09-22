"""A case: one investigation's evidence, on disk.

This is the layer both the CLI and the GUI drive. Keeping the workflow here
rather than in either interface is what makes the rule "anything the GUI can do
is scriptable" true by construction instead of by discipline.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, ClassVar

from logarc.detect.crs.store import CrsEvidence
from logarc.detect.engine import _URL_IN_PARAM, RuleEngine, _bare_host
from logarc.detect.rulepacks import default_rules
from logarc.detect.rules import load_rules
from logarc.evidence import EvidenceLine, read_evidence
from logarc.ingest.parallel import (
    DEFAULT_WORKERS,
    ingest_file_parallel,
    worth_splitting,
)
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
    from collections.abc import Callable, Iterable, Sequence

    from logarc.core.evidence import EvidenceRef

__all__ = ["Case", "CaseError", "SiteHostSuggestion"]

#: How many events `suggest_site_hosts` reads before it stops looking.
#:
#: It is proposing an answer for a person to confirm, not measuring anything, so
#: it does not have to see the whole case — and it runs while somebody is
#: waiting for a dialog, so it must not be able to take long on a large one.
_SCAN_BUDGET = 20_000


@dataclass(frozen=True, slots=True)
class SiteHostSuggestion:
    """What to propose when asking a case which domains are its own."""

    hosts: tuple[str, ...]
    """Every host the log names, commonest first. Empty when it records none —
    `apache-combined` does not, and that is most of the logs there are."""

    urls_seen: int
    """Requests in the scanned prefix carrying a URL in a query parameter."""

    worth_asking: bool
    """Whether to put the question at all.

    False when the case already has an answer, and false when nothing in it
    passes a URL around — on that log the answer changes nothing and the
    dialog is noise.
    """


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

    # -- the site's own domains --------------------------------------------

    #: Where the answer lives in the manifest's config, beside `crs_fingerprint`.
    SITE_HOSTS_KEY: ClassVar[str] = "site_hosts"

    @property
    def site_hosts(self) -> tuple[str, ...]:
        """The domains the reader said belong to this site.

        Empty means nobody has been asked, or somebody was asked and declined —
        the two are deliberately the same thing here, because `rfi_offsite_url`
        treats both as "say nothing" and no rule should behave differently for a
        question that was skipped than for one never put.
        """
        stored = self.manifest.config.get(self.SITE_HOSTS_KEY) or []
        return tuple(str(name) for name in stored)

    def set_site_hosts(self, names: Iterable[str]) -> None:
        """Record the answer, reduced, and save it.

        Reduced on the way *in* rather than at every comparison, so what the
        file holds is what the engine will actually use. A reader who pastes
        `https://shop.test/` into a box asking for a domain has answered the
        question correctly and should not be quietly wrong.

        An empty list clears the key rather than storing `[]`, so a case that
        was never asked and a case whose answer was withdrawn read the same on
        disk as well as in memory.
        """
        reduced = sorted({host for host in (_bare_host(name) for name in names) if host})
        if reduced:
            self.manifest.config[self.SITE_HOSTS_KEY] = reduced
        else:
            self.manifest.config.pop(self.SITE_HOSTS_KEY, None)
        self.manifest.save(self.root)

    def suggest_site_hosts(self) -> SiteHostSuggestion:
        """Read the case and work out what to propose, and whether to ask at all.

        Both halves matter. Proposing turns the question into a confirmation on
        any log that records a Host; deciding whether to ask keeps it off the
        screen entirely on the logs where the answer would change nothing, which
        is most of them. A prompt that never changes anything is the kind people
        learn to dismiss without reading, and then dismiss the one that mattered.

        Bounded on purpose. `_SCAN_BUDGET` events is a fraction of a second on
        a case of any size, and the result is a suggestion a person confirms —
        not a measurement, so it does not need to be exhaustive. The failure
        mode of the bound is that a log whose only URL-carrying request sits
        past it goes unasked, which costs a finding rather than inventing one.
        """
        if self.site_hosts:
            return SiteHostSuggestion(hosts=(), urls_seen=0, worth_asking=False)

        hosts: Counter[str] = Counter()
        urls = 0
        for index, event in enumerate(self.store.all_events()):
            if index >= _SCAN_BUDGET:
                break
            host = _bare_host(event.host)
            if host:
                hosts[host] += 1
            if event.query and _URL_IN_PARAM.search("?" + event.query):
                urls += 1
        return SiteHostSuggestion(
            # Every host the log names, commonest first — a site behind a vhost
            # log often answers to two or three, and naming one of them while
            # leaving out the `www.` is exactly the wrong answer to give.
            hosts=tuple(name for name, _ in hosts.most_common()),
            urls_seen=urls,
            worth_asking=urls > 0,
        )

    def rule_engine(self, extra_packs: Sequence[Path] = ()) -> RuleEngine:
        """The engine this case is analysed with, knowing its own domains.

        Here rather than in the CLI and the GUI separately, for the reason
        `crs_evidence` is: when each front end built its own, they disagreed
        about the same case. One rule in the tree now depends on a per-case
        answer, so an engine built without the case is an engine that quietly
        detects less.

        Extra packs are added to the bundled rules rather than replacing them,
        and `load_rules` refuses a duplicate id, so a pack copying a bundled
        rule to edit it fails loudly instead of shadowing it.
        """
        rules = list(default_rules())
        if extra_packs:
            rules.extend(load_rules(list(extra_packs)))
        return RuleEngine(rules, site_hosts=self.site_hosts)

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
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        on_progress: Callable[[int, int], None] | None = None,
        should_cancel: Callable[[], bool] | None = None,
        workers: int = DEFAULT_WORKERS,
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
                    # Evidence must reopen the source independently of the launch folder.
                    source = Path(path).absolute()
                    file_id = self._allocate_file_id(source)
                    if should_cancel is None and worth_splitting(source, workers=workers):
                        result = self._ingest_in_parallel(
                            source,
                            file_id=file_id,
                            log_format=log_format,
                            batch_size=batch_size,
                            max_line_bytes=max_line_bytes,
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
    )
