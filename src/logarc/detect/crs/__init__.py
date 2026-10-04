"""CRS as a second opinion on a single request.

The bundled rule packs classify *behaviour*; OWASP CRS enumerates payload
*syntax*, which is a different job and one it does far better — `score-crs`
measured this project's signatures at 12.3% of the access-log-visible payloads
in CRS's own regression corpus, and ADR-0007's follow-up established that the
misses arrive in plain text with no rule expressing them.

So CRS is added rather than substituted. It supplies signature breadth; it
cannot supply the other three things `detect/` does — behaviour across requests,
`ActivityCategory` assignment, or a label for the traffic no rule matched.
"""

from logarc.detect.crs.mapping import (
    KNOWN_FAMILIES,
    RESCUE_CONFIDENCE,
    category_for,
    category_for_family,
    severity_for,
)
from logarc.detect.crs.sidecar import (
    CrsDetection,
    CrsUnavailableError,
    SidecarConfig,
    binary_name,
    default_binary,
    host_speaks_for,
    primary_site_host,
    run_sidecar,
)
from logarc.detect.crs.store import (
    CRS_FILE,
    CrsEvidence,
    DetectionIndex,
    is_enriched,
    load_detections,
    write_detections,
)

__all__ = [
    "CRS_FILE",
    "KNOWN_FAMILIES",
    "RESCUE_CONFIDENCE",
    "CrsDetection",
    "CrsEvidence",
    "CrsUnavailableError",
    "DetectionIndex",
    "SidecarConfig",
    "binary_name",
    "category_for",
    "category_for_family",
    "default_binary",
    "host_speaks_for",
    "is_enriched",
    "load_detections",
    "primary_site_host",
    "run_sidecar",
    "severity_for",
    "write_detections",
]
