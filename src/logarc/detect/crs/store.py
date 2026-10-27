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
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from logarc.detect.crs.sidecar import CrsDetection

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "COMPLETE_KEY",
    "CRS_FILE",
    "REPLAYED_KEY",
    "REQUESTS_KEY",
    "CrsEvidence",
    "DetectionIndex",
    "is_enriched",
    "load_detections",
    "recorded_coverage",
    "write_detections",
]

CRS_FILE: Final = "crs.jsonl"

#: Where the manifest's config records how the last enrichment ended: whether it
#: finished, the requests it replayed, and the requests the case held. Finishing
#: is recorded rather than worked out from the two counts, because the total is
#: the manifest's figure and nothing here checks it against the store.
COMPLETE_KEY: Final = "crs_complete"
REPLAYED_KEY: Final = "crs_replayed"
REQUESTS_KEY: Final = "crs_requests"


def is_enriched(case_root: Path) -> bool:
    """Whether CRS has been run over this case.

    Distinct from "are there detections", and the distinction matters: a corpus
    of ordinary traffic is enriched and yields nothing, which is a result rather
    than an absence. Keying the "CRS not consulted" warning on an empty index
    would announce a failure every time CRS correctly found no attacks.
    """
    return (Path(case_root) / CRS_FILE).exists()


def recorded_coverage(config: Mapping[str, Any]) -> tuple[int, int] | None:
    """`(replayed, requests)` if the enrichment `config` records was stopped part
    way, else `None`.

    Reads the manifest only, so a caller asking whether a case's CRS run
    finished does not load every detection to find out. A case enriched before
    completion was recorded reads as complete: nothing is left that could say
    otherwise.
    """
    if config.get(COMPLETE_KEY) is not False:
        return None
    return int(config.get(REPLAYED_KEY) or 0), int(config.get(REQUESTS_KEY) or 0)


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


@dataclass(frozen=True, slots=True)
class CrsEvidence:
    """What CRS contributed to a case: the detections, and what produced them.

    The two travel together because they are only meaningful together, and
    because every interface needs both. They used to be assembled separately at
    each call site, and the GUI simply never assembled them — so the same
    enriched case reported different findings in the window than on the command
    line. A tool whose two front ends disagree about the evidence is worse than
    one that offers the feature in only one of them, because nothing says which
    answer is the real one.
    """

    index: DetectionIndex | None
    """Detections to apply, or `None` when there are none to apply.

    `None` rather than an empty mapping because that is what `analyse_ip` takes
    for "no CRS input", and an enrichment that found nothing is genuinely
    nothing to apply — the fact that it *ran* is carried by `fingerprint`.
    """

    fingerprint: str | None
    """The CRS configuration credited with the result, or `None` if CRS took no
    part in it."""

    coverage: tuple[int, int] | None = None
    """`(replayed, requests)` when the enrichment was stopped part way, else
    `None`, as `recorded_coverage` reads it.

    The requests it never reached carry no detection, which is also what a
    request CRS read and passed carries, so without this a partial check reads
    as a clean one.
    """

    @property
    def partial(self) -> bool:
        return self.coverage is not None

    @classmethod
    def of(cls, case_root: Path, config: Mapping[str, Any]) -> CrsEvidence:
        """Read what a case on disk carries.

        Presence of the detection file decides, not the manifest. The manifest
        records that `enrich` once ran; only the file says it still applies. A
        case whose `crs.jsonl` was deleted would otherwise analyse on the
        bundled rules while still naming a CRS configuration — a finding
        crediting something that did not produce it.
        """
        root = Path(case_root)
        if not is_enriched(root):
            return cls(index=None, fingerprint=None)
        fingerprint = config.get("crs_fingerprint")
        return cls(
            index=load_detections(root) or None,
            fingerprint=str(fingerprint) if fingerprint is not None else None,
            coverage=recorded_coverage(config),
        )
