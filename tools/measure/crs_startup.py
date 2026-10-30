"""How long a sidecar takes to start, answer one request and stop.

    python tools/measure/crs_startup.py [--binary EXE] [--rounds N]

The price of each sidecar zodiarc starts, so it decides whether sidecars can be
started per share of requests or must live for a whole run. Measured through
`run_sidecar`, so it starts the binary exactly as zodiarc does.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from zodiarc.core.event import NormalizedEvent
from zodiarc.core.evidence import EvidenceRef
from zodiarc.detect.crs.sidecar import SidecarConfig, run_sidecar

REQUEST = NormalizedEvent(
    timestamp=datetime(2024, 5, 1, tzinfo=UTC),
    client_ip="203.0.113.5",
    evidence=EvidenceRef("access.log", 1),
    method="GET",
    path="/index.html",
    query=None,
    protocol="HTTP/1.1",
    status=200,
    referer=None,
    user_agent="curl/8.0",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", type=Path, help="a sidecar build (default: the checkout's)")
    parser.add_argument("--rules", type=Path, help="the CRS ruleset (default: the checkout's)")
    parser.add_argument("--rounds", type=int, default=10)
    args = parser.parse_args(argv)

    config = SidecarConfig()
    if args.binary is not None:
        config = replace(config, binary=args.binary)
    if args.rules is not None:
        config = replace(config, rules=args.rules)

    took = []
    for _ in range(args.rounds):
        started = time.perf_counter()
        run_sidecar([REQUEST], config=config, workers=1)
        took.append(time.perf_counter() - started)
    print(
        f"{config.binary.name}: median {statistics.median(took):.2f} s, "
        f"min {min(took):.2f} s, max {max(took):.2f} s, over {args.rounds} runs"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
