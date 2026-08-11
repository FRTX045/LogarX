"""Where a case keeps the CRS detections it was enriched with.

One JSONL file beside the manifest, written once by `logarc enrich` and read by
every analysis afterwards. Not folded into the event store: detections are
optional, regenerable, and a different shape from events — several per request
or none — so keeping them separate leaves the parquet schema alone and makes an
un-enriched case simply a case without the file.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final

from logarc.detect.crs.sidecar import CrsDetection

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["CRS_FILE", "DetectionIndex", "is_enriched", "load_detections", "write_detections"]

CRS_FILE: Final = "crs.jsonl"


def is_enriched(case_root: Path) -> bool:
    """Whether CRS has been run over this case.

    Distinct from "are there detections", and the distinction matters: a corpus
    of ordinary traffic is enriched and yields nothing, which is a result rather
    than an absence. Keying the "CRS not consulted" warning on an empty index
    would announce a failure every time CRS correctly found no attacks.
    """
    return (Path(case_root) / CRS_FILE).exists()


#: Detections for one request, keyed as `EvidenceRef` identifies it.
DetectionIndex = Mapping[tuple[str, int], Sequence[CrsDetection]]


def write_detections(case_root: Path, detections: Iterable[CrsDetection]) -> Path:
    """Write the detection set for a case, replacing any previous one."""
    path = Path(case_root) / CRS_FILE
    with path.open("w", encoding="utf-8") as handle:
        for detection in detections:
            handle.write(json.dumps(detection.to_dict()) + "\n")
    return path


def load_detections(case_root: Path) -> dict[tuple[str, int], list[CrsDetection]]:
    """Read a case's detections, indexed by source file and line.

    An absent file yields an empty index rather than an error. That is the
    normal state of a case nobody has enriched, and the caller — not this — is
    responsible for saying so out loud.
    """
    path = Path(case_root) / CRS_FILE
    index: dict[tuple[str, int], list[CrsDetection]] = defaultdict(list)
    if not path.exists():
        return dict(index)

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            data = json.loads(line)
            detection = CrsDetection.from_json(data, source_file_id=data["source_file_id"])
            index[detection.source_file_id, detection.line_no].append(detection)
    return dict(index)
