"""Ground truth: what a log is known to contain.

A claim that the tool is accurate needs something to be accurate *about*. This
is that something: a sidecar beside a log, recording for every line which
activity produced it. The BlackHat-Dataset shopfront builds write it from the
ledger of the client that made each request; `convert-csic` writes it from
CSIC's own labels.

It is JSON Lines rather than one JSON document because both ends stream: at a
million lines a truth file that has to be held in memory before it can be
written is a truth file that cannot be written. The first line is a header, the
rest are one record per log line, and both ends of the pipe work line by line.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final

from logarx.core.activity import ActivityCategory

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path
    from typing import IO

__all__ = [
    "GRANULARITIES",
    "TRUTH_KIND",
    "TRUTH_VERSION",
    "GroundTruth",
    "TruthError",
    "TruthRecord",
    "TruthWriter",
    "read_truth",
]

TRUTH_KIND: Final = "logarx-truth"
TRUTH_VERSION: Final = 1

#: Kinds read as truth. The tool was called logarc until 2026-10-28, and the
#: dataset project and every truth file made before then say so.
_READ_KINDS: Final = frozenset({TRUTH_KIND, "logarc-truth"})

#: What a truth file is able to say about each request.
#:
#: `category` means the source knows which activity produced the line, which is
#: only true of traffic generated on purpose. `binary` means it knows the line
#: is an attack but not what kind — all a labelled public dataset can offer.
#: Recorded so that scoring a binary file per category fails loudly instead of
#: quietly reporting nonsense.
GRANULARITIES: Final = ("category", "binary")


class TruthError(ValueError):
    """Raised when a ground-truth file is missing, malformed or unreadable."""


@dataclass(frozen=True, slots=True)
class TruthRecord:
    """What one line of the generated log was meant to be."""

    line_no: int
    client_ip: str
    category: ActivityCategory

    instance_id: str
    """Which occurrence of an activity this line belongs to.

    Consecutive lines sharing one id are one intended episode. This is what
    makes it possible to ask not only "was each request classified correctly"
    but "were the boundaries between activities found in the right places".
    """

    def as_json(self) -> dict[str, Any]:
        return {
            "line_no": self.line_no,
            "client_ip": self.client_ip,
            "category": self.category.value,
            "instance_id": self.instance_id,
        }


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """A whole truth file, read into memory for scoring."""

    scenario: str
    seed: int
    source_file_id: str
    generated_at: datetime
    records: tuple[TruthRecord, ...]
    granularity: str = "category"

    @property
    def line_count(self) -> int:
        return len(self.records)

    @property
    def is_binary(self) -> bool:
        """True when the source only knows attack-or-not."""
        return self.granularity == "binary"

    def by_client(self) -> Mapping[str, Sequence[TruthRecord]]:
        """Group records by client, preserving line order within each."""
        grouped: defaultdict[str, list[TruthRecord]] = defaultdict(list)
        for item in self.records:
            grouped[item.client_ip].append(item)
        return grouped


class TruthWriter:
    """Streams a truth file as its records are produced.

    The header carries no total, because it is written before the body exists.
    A count that is derived on read cannot contradict the records it describes.
    """

    def __init__(
        self,
        path: Path,
        *,
        scenario: str,
        seed: int,
        source_file_id: str,
        granularity: str = "category",
    ) -> None:
        if granularity not in GRANULARITIES:
            raise TruthError(
                f"unknown granularity {granularity!r}; choose {' or '.join(GRANULARITIES)}"
            )
        self._path = path
        self._header = {
            "kind": TRUTH_KIND,
            "version": TRUTH_VERSION,
            "scenario": scenario,
            "seed": seed,
            "source_file_id": source_file_id,
            "granularity": granularity,
            "generated_at": datetime.now(UTC).isoformat(),
        }
        self._handle: IO[str] | None = None

    def __enter__(self) -> TruthWriter:
        self._handle = self._path.open("w", encoding="utf-8", newline="\n")
        self._handle.write(json.dumps(self._header) + "\n")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def write(self, record: TruthRecord) -> None:
        if self._handle is None:
            raise TruthError("truth writer used outside its context manager")
        self._handle.write(json.dumps(record.as_json()) + "\n")


def read_truth(path: Path) -> GroundTruth:
    """Load a truth file, refusing anything that is not one."""
    with path.open("r", encoding="utf-8") as handle:
        first = handle.readline()
        if not first.strip():
            raise TruthError(f"{path} is empty; expected a ground-truth file")

        header = _decode(first, path, line_no=1)
        if header.get("kind") not in _READ_KINDS:
            raise TruthError(f"{path} is not a LogarX ground-truth file")
        version = header.get("version")
        if version != TRUTH_VERSION:
            raise TruthError(
                f"{path} is version {version}; this build reads version {TRUTH_VERSION}"
            )

        records = tuple(
            _to_record(_decode(line, path, line_no=number), path, line_no=number)
            for number, line in enumerate(handle, start=2)
            if line.strip()
        )

    granularity = str(header.get("granularity", "category"))
    if granularity not in GRANULARITIES:
        raise TruthError(f"{path} declares an unknown granularity {granularity!r}")

    return GroundTruth(
        scenario=str(header.get("scenario", "unknown")),
        seed=int(header.get("seed", 0)),
        source_file_id=str(header.get("source_file_id", "")),
        generated_at=_to_datetime(header.get("generated_at")),
        records=records,
        granularity=granularity,
    )


def _decode(line: str, path: Path, *, line_no: int) -> dict[str, Any]:
    try:
        decoded = json.loads(line)
    except json.JSONDecodeError as exc:
        raise TruthError(f"{path} line {line_no} is not valid JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise TruthError(f"{path} line {line_no} is not a JSON object")
    return decoded


def _to_record(raw: dict[str, Any], path: Path, *, line_no: int) -> TruthRecord:
    try:
        category = ActivityCategory(raw["category"])
    except (KeyError, ValueError) as exc:
        raise TruthError(f"{path} line {line_no} has an unusable category: {exc}") from exc
    try:
        return TruthRecord(
            line_no=int(raw["line_no"]),
            client_ip=str(raw["client_ip"]),
            category=category,
            instance_id=str(raw["instance_id"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TruthError(f"{path} line {line_no} is missing a field: {exc}") from exc


def _to_datetime(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return datetime.now(UTC)
