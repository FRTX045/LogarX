"""One benchmark run, in a process of its own.

Run as a module — `python -m logarc.evaluation.bench_worker` — and never
imported by the orchestrator. That is deliberate on two counts:

* peak resident memory is a high-water mark for the life of a process, so
  measuring several sizes in one process would report the largest run's peak
  for every run after it;
* Arrow and DuckDB keep allocator state between calls, so a second ingest in
  the same process is not measuring the same thing as the first.

Writes one line of JSON to stdout and nothing else, so the parent can read the
result without parsing prose.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.evaluation.generator import write_log
from logarc.evaluation.memory import peak_rss_bytes

__all__ = ["measure"]


def measure(*, lines: int, scenario: str, seed: int, workdir: Path) -> dict[str, Any]:
    """Generate, ingest, and reconstruct one client; time each part."""
    workdir.mkdir(parents=True, exist_ok=True)
    log = workdir / f"bench-{lines}.log"
    case_dir = workdir / f"case-{lines}"

    generated = write_log(log, scenario=scenario, lines=lines, seed=seed, truth_path=None)

    began = time.perf_counter()
    with Case.create(case_dir) as case:
        results = case.ingest([log])
    ingest_seconds = time.perf_counter() - began

    with Case.open(case_dir) as case:
        summaries = case.store.ip_summaries(limit=1, order_by="requests")
        busiest = summaries[0].client_ip if summaries else ""
        clients = len(case.store.ip_summaries(limit=1_000_000, order_by="requests"))

        began = time.perf_counter()
        analysis = analyse_ip(case.store, busiest) if busiest else None
        analyse_seconds = time.perf_counter() - began

    return {
        "lines": lines,
        "scenario": scenario,
        "seed": seed,
        "bytes_read": generated.bytes_written,
        "generate_seconds": generated.elapsed_seconds,
        "ingest_seconds": ingest_seconds,
        "peak_rss_bytes": peak_rss_bytes(),
        "store_bytes": _tree_size(case_dir),
        "clients": clients,
        "quarantined": sum(result.lines_quarantined for result in results),
        "analysed_ip": busiest,
        "analysed_requests": analysis.request_count if analysis else 0,
        "analysed_episodes": len(analysis.episodes) if analysis else 0,
        "analyse_seconds": analyse_seconds,
    }


def _tree_size(root: Path) -> int:
    return sum(item.stat().st_size for item in root.rglob("*") if item.is_file())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lines", type=int, required=True)
    parser.add_argument("--scenario", default="mixed")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--workdir", type=Path, required=True)
    args = parser.parse_args()

    print(
        json.dumps(
            measure(
                lines=args.lines,
                scenario=args.scenario,
                seed=args.seed,
                workdir=args.workdir,
            )
        )
    )


if __name__ == "__main__":
    main()
