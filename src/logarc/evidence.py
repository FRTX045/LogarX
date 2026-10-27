"""Fetching the raw log lines a finding rests on.

Every episode and every graph node carries `EvidenceRef`s, which is what makes a
finding checkable rather than merely asserted. This is the other half of that
promise: turning a reference back into the line of text it points at.

Two things are deliberate.

**Sources are read, never trusted blindly.** A case outlives the logs it was
built from — they get rotated, archived, edited. A line pulled out of a file
that has changed since ingest is not the line that produced the finding, so the
size recorded at ingest is checked and any discrepancy is reported alongside the
text rather than left for the reader to discover.

**Nothing here raises for a missing source.** An investigator opening a case a
year later, on a machine that never had the original logs, should see "this line
came from access.log:4021, which is not available here" — not a traceback.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from logarc.core.evidence import EvidenceRef
from logarc.ingest.reader import LogSourceError, open_log
from logarc.parsers.logformat import LogFormatError
from logarc.parsers.registry import UnknownFormatError, get_parser
from logarc.parsers.spec import FormatSpecError, spec_from_dict

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.event import NormalizedEvent
    from logarc.parsers.base import LogParser
    from logarc.storage.case import CaseManifest, SourceRecord

__all__ = ["EvidenceLine", "read_evidence"]


@dataclass(frozen=True, slots=True)
class EvidenceLine:
    """One source line, or an account of why it could not be read."""

    ref: EvidenceRef
    source_path: str
    text: str | None = None
    note: str | None = None

    event: NormalizedEvent | None = None
    """The line as the case's own parser reads it, or `None` when that parser
    cannot make sense of it.

    Parsed here rather than wherever it is displayed, and with the parser the
    manifest records for this file — the one that produced the finding in the
    first place. An interface that re-read the same bytes its own way could
    disagree with the engine about what the request was, and a reader looking
    at the two would have nothing to tell them which was which.

    `None` is not a failure to report: a line the parser rejects is itself
    worth seeing, so the text survives and the fields are simply absent.
    """

    verified: bool = False
    """The source is still the size it was when ingested.

    False does not mean the text is wrong; it means nothing here can promise it
    is right, which is a different claim and the one worth making.
    """

    @property
    def available(self) -> bool:
        return self.text is not None

    @property
    def warning(self) -> str | None:
        """What has to travel beside this line wherever it is written out, or
        None when its source is still the size it was at ingest."""
        if self.verified:
            return None
        return self.note or "the source could not be checked against the case"


def read_evidence(manifest: CaseManifest, refs: Sequence[EvidenceRef]) -> list[EvidenceLine]:
    """Resolve `refs` to source lines, in the order given.

    Grouped by file and read in one streaming pass each, so showing twenty
    references from a two-gigabyte log costs one sequential scan rather than
    twenty seeks — and never holds the file in memory.
    """
    if not refs:
        return []

    sources = {record.file_id: record for record in manifest.sources}

    wanted: dict[str, set[int]] = defaultdict(set)
    for ref in refs:
        if ref.source_file_id in sources:
            wanted[ref.source_file_id].add(ref.line_no)

    resolved: dict[tuple[str, int], EvidenceLine] = {}
    for file_id, line_numbers in wanted.items():
        resolved.update(_read_source(sources[file_id], line_numbers))

    return [resolved.get((ref.source_file_id, ref.line_no)) or _unknown(ref) for ref in refs]


def _unknown(ref: EvidenceRef) -> EvidenceLine:
    return EvidenceLine(
        ref=ref,
        source_path="",
        note=f"{ref.source_file_id} is not part of this case",
    )


def _read_source(
    record: SourceRecord, line_numbers: set[int]
) -> dict[tuple[str, int], EvidenceLine]:
    path = Path(record.original_path)
    verified, drift = _check_unchanged(record, path)

    try:
        return _scan(record, path, line_numbers, verified=verified, drift=drift)
    except LogSourceError as exc:
        return {
            (record.file_id, number): EvidenceLine(
                ref=EvidenceRef(record.file_id, number),
                source_path=record.original_path,
                note=str(exc),
            )
            for number in line_numbers
        }


def _parser_for(record: SourceRecord) -> LogParser | None:
    """The parser this file was ingested with, if it can still be resolved.

    The case's own copy of the definition comes first. That is what it is for:
    a user who edits or deletes a saved format must not silently lose the
    fields of every case that was read with it, and the name alone cannot
    survive either of those.

    Falling back to the name covers two cases that are both real. A `case.json`
    written before definitions were stored has only a name; and a format
    registered by handing over a factory has no definition to store, which is
    the plugin the older wording described.

    Returns `None` rather than raising when neither works. The line is still
    shown; only its fields are missing.
    """
    if record.format_spec is not None:
        try:
            return spec_from_dict(record.format_spec).build()
        except (FormatSpecError, LogFormatError):
            # A definition from a newer logarc, or one that no longer compiles.
            # Both leave the line readable, which is the guarantee that matters.
            return None
    try:
        return get_parser(record.log_format)
    except (UnknownFormatError, KeyError):
        return None


def _scan(
    record: SourceRecord,
    path: Path,
    line_numbers: set[int],
    *,
    verified: bool,
    drift: str | None,
) -> dict[tuple[str, int], EvidenceLine]:
    found: dict[tuple[str, int], EvidenceLine] = {}
    highest = max(line_numbers)
    seen = 0
    parser = _parser_for(record)

    with open_log(path) as stream:
        for number, text in stream:
            seen = number
            if number in line_numbers:
                ref = EvidenceRef(record.file_id, number)
                found[record.file_id, number] = EvidenceLine(
                    ref=ref,
                    source_path=record.original_path,
                    text=text,
                    note=drift,
                    event=parser.parse_line(text, ref) if parser else None,
                    verified=verified,
                )
            if number >= highest:
                break

    for number in line_numbers - {line_no for _, line_no in found}:
        found[record.file_id, number] = EvidenceLine(
            ref=EvidenceRef(record.file_id, number),
            source_path=record.original_path,
            note=f"{path.name} has only {seen} lines",
        )
    return found


def _check_unchanged(record: SourceRecord, path: Path) -> tuple[bool, str | None]:
    """Cheap integrity check: has the file changed size since ingest?

    Size rather than the recorded SHA-256, because rehashing a multi-gigabyte
    log every time a node is clicked would make the evidence panel unusable, and
    truncation or appending is the common case. Full verification belongs in a
    deliberate integrity command, not in a mouse click.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return False, None
    if size == record.size_bytes:
        return True, None
    return False, (
        f"{path.name} has changed size since ingest "
        f"({record.size_bytes:,} bytes then, {size:,} now); "
        "this line may not be the one the finding was built from"
    )
