"""What the sidecar detects on the CRS regression corpus, pinned.

The sidecar is built from code this project does not write: Coraza, and the
RE2 engine that evaluates CRS's regular expressions (`crs/wasm.go`). Either can
change what CRS reports with nothing here changing. A regex engine that reads
one pattern differently from Go's would add or lose detections quietly, and the
contract tests replay four requests, too few to notice. This replays every
request the corpus holds and compares the answer with the one recorded.

Counts per rule and a digest are recorded rather than the detections, because
the detections carry attack payloads verbatim and a virus scanner quarantined a
file of them.

After a deliberate change, such as a Coraza or ruleset upgrade, regenerate the
record and read the per-rule diff before committing it:

    python tests/detect/crs/test_corpus_detections.py

Skipped like the contract tests when the sidecar is not built, and required in
CI by `LOGARC_REQUIRE_CRS=1`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from logarc.core.event import NormalizedEvent
from logarc.detect.crs import SidecarConfig, run_sidecar
from logarc.evaluation.crs_corpus import _as_event, _cases

CONFIG = SidecarConfig()

CORPUS = CONFIG.rules / "tests" / "regression" / "tests"

RECORDED = Path(__file__).parents[2] / "data" / "crs-corpus-detections.json"

REQUIRE_ENV = "LOGARC_REQUIRE_CRS"

_unbuilt = not CONFIG.binary.exists() or not CORPUS.is_dir()

pytestmark = pytest.mark.skipif(
    _unbuilt and os.environ.get(REQUIRE_ENV) != "1",
    reason=f"CRS sidecar or ruleset not built; see crs/README.md (set {REQUIRE_ENV}=1 to require)",
)


def corpus_events() -> list[NormalizedEvent]:
    """Every request in the corpus, every family, in a fixed order.

    All of them, not only those `score-crs` counts as within an access log's
    reach: the point is what the sidecar does, and the more rules a request
    exercises the more a change in the engine can show up.
    """
    families = sorted(
        {
            found.group(1)
            for folder in CORPUS.iterdir()
            if (found := re.search(r"-(9\d\d)-", folder.name))
        }
    )
    events: list[NormalizedEvent] = []
    for family in families:
        for payload, _ in _cases(CORPUS, family):
            events.append(_as_event(payload, len(events) + 1))
    return events


def replay_corpus() -> dict[str, Any]:
    events = corpus_events()
    found = run_sidecar(events, config=CONFIG)
    lines = sorted(json.dumps(one.to_dict(), sort_keys=True) for one in found)
    by_rule = Counter(one.rule_id for one in found)
    return {
        "crs_revision": CONFIG.revision(),
        "requests": len(events),
        "detections": len(found),
        "digest": hashlib.sha256("\n".join(lines).encode()).hexdigest(),
        "by_rule": {str(rule): by_rule[rule] for rule in sorted(by_rule)},
    }


def test_the_corpus_is_detected_exactly_as_recorded() -> None:
    recorded = json.loads(RECORDED.read_text(encoding="utf-8"))

    now = replay_corpus()

    assert now["crs_revision"] == recorded["crs_revision"], (
        "the ruleset is not the one the record was made with; regenerate it (module docstring)"
    )
    assert now["requests"] == recorded["requests"]
    # Per rule first, because that names what moved; the digest then catches a
    # change no count shows, such as a detection moving to another request or
    # naming a different variable.
    assert now["by_rule"] == recorded["by_rule"]
    assert now["digest"] == recorded["digest"]


if __name__ == "__main__":
    # Bytes, so Windows writes the same `\n` endings as everywhere else:
    # `tests/data` is stored exactly as written.
    RECORDED.write_bytes((json.dumps(replay_corpus(), indent=2) + "\n").encode("utf-8"))
    print(f"wrote {RECORDED}")
