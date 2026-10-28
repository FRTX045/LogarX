"""Time CRS replay of one case, for each sidecar build and worker count given.

    python tools/measure/crs_replay.py CASE [--binary EXE ...] [--workers N ...]

Every pairing of a build and a worker count runs once per round, in an order
rotated each round, so no setup always runs first on a cold disk cache or last
on a hot CPU. Prints each run as it ends, then each setup's median with every
run behind it, and whether every run reported exactly what the first run of the
first setup did: a faster build that finds something else is not a faster build
of the same thing. Exits 1 if any run differed.

crs/README.md's RE2 table was measured this way: two builds, six sidecars,
three rounds, on each of three tiers.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter
from dataclasses import replace
from pathlib import Path

from logarx.case import Case
from logarx.detect.crs.sidecar import SidecarConfig, run_sidecar


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("case", type=Path, help="a case directory")
    parser.add_argument(
        "--binary", type=Path, action="append", help="a sidecar build; repeat to compare builds"
    )
    parser.add_argument(
        "--workers", type=int, action="append", help="sidecars at once; repeat to compare counts"
    )
    parser.add_argument("--rules", type=Path, help="the CRS ruleset (default: the checkout's)")
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args(argv)

    base = SidecarConfig()
    if args.rules is not None:
        base = replace(base, rules=args.rules)
    binaries: list[Path] = args.binary or [base.binary]
    if len({binary.stem for binary in binaries}) < len(binaries):
        parser.error("two builds share a file name; name them apart to tell their results apart")
    counts: list[int | None] = args.workers or [None]
    setups = [
        (f"{binary.stem} x{workers}" if workers else binary.stem, binary, workers)
        for binary in binaries
        for workers in counts
    ]

    with Case.open(args.case) as case:
        events = list(case.store.all_events())

    took: dict[str, list[float]] = {name: [] for name, _, _ in setups}
    answers: dict[str, list[Counter[str]]] = {name: [] for name, _, _ in setups}
    for round_no in range(args.rounds):
        shift = round_no % len(setups)
        for name, binary, workers in setups[shift:] + setups[:shift]:
            started = time.perf_counter()
            found = run_sidecar(events, config=replace(base, binary=binary), workers=workers)
            took[name].append(time.perf_counter() - started)
            answers[name].append(Counter(json.dumps(d.to_dict(), sort_keys=True) for d in found))
            print(f"round {round_no + 1}  {name}  {took[name][-1]:.1f} s", flush=True)

    first = setups[0][0]
    reference = answers[first][0]
    width = max(len(name) for name, _, _ in setups)
    print(f"{len(events):,} events, {args.rounds} rounds")
    differed = False
    for name, _, _ in setups:
        runs = ", ".join(f"{t:.1f}" for t in took[name])
        unlike = sum(answer != reference for answer in answers[name])
        differed |= unlike > 0
        verdict = (
            "same detections"
            if not unlike
            else f"DIFFERENT detections from {first} in {unlike} of {len(answers[name])} runs"
        )
        print(f"{name:{width}}  median {statistics.median(took[name]):.1f} s  ({runs})  {verdict}")
    print(f"detections in {first}'s first run: {sum(reference.values()):,}")
    return 1 if differed else 0


if __name__ == "__main__":
    sys.exit(main())
