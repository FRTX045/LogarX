"""Cut the test fixture out of a pinned LogarX Dataset build.

Run by hand, with the build folder as the argument:

    python tests/data/apache-shopfront/cut_excerpt.py samples/apache-shopfront/2026-09-07-medium

It keeps every line of a fixed set of hostile clients, chosen so that each
hostile category the tool knows appears at least once, plus the first
ORDINARY_CLIENTS ordinary clients in order of first appearance that have at
most ORDINARY_MAX_LINES lines. The cap keeps out the handful of clients that
run all week, the fixed-address browser personas and the search-engine
crawlers, which would otherwise be most of the fixture. Lines are kept
in log order and renumbered from 1, so the result is a valid truth file in its
own right. Lines whose truth category is `unknown` are dropped: they are the
dataset's deliberate malformed-request noise, and a fixture exists to be
scored, not quarantined.

Bytes in, bytes out. A real log can carry bytes that are not UTF-8, and a
fixture that has been through a text decoder is not the log Apache wrote.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

HOSTILE_CATEGORIES = frozenset(
    {
        "reconnaissance",
        "enumeration",
        "injection",
        "path_traversal",
        "access_control",
        "credential_attack",
        "ssrf",
        "exploitation",
    }
)

#: Every line of these clients is kept. Chosen from the 2026-09-07-medium build
#: so that every hostile category has support: sqlmap (injection), the
#: credential hunter, the patient and webshell operators (exploitation,
#: access_control, path_traversal), the metadata hunter (ssrf), one full
#: dirb-sized enumerator, nmap's probing, and one shopper who also probed.
HOSTILE_CLIENTS = (
    "192.0.2.31",
    "192.0.2.23",
    "192.0.2.22",
    "198.51.100.21",
    "198.51.100.22",
    "198.51.100.23",
    "198.51.100.24",
    "198.51.100.32",
    "192.0.2.231",
    "203.0.113.6",
    "203.0.113.41",
    "100.113.232.186",
)

#: Ordinary clients kept, in order of first appearance in the log, and the
#: most lines one of them may have. A shopper session is fifty to two hundred
#: lines; anything larger is a persistent bot or a week-long browser persona.
ORDINARY_CLIENTS = 40
ORDINARY_MAX_LINES = 300


def cut(build: Path, out: Path) -> tuple[int, int]:
    """Write excerpt.log, excerpt.truth.jsonl and SHA256SUMS into `out`.

    Returns (lines kept, clients kept).
    """
    log_lines = (build / "access.log").read_bytes().split(b"\n")
    if log_lines and log_lines[-1] == b"":
        log_lines.pop()
    truth_lines = (build / "truth.jsonl").read_text(encoding="utf-8").splitlines()
    header = json.loads(truth_lines[0])
    records = [json.loads(line) for line in truth_lines[1:] if line.strip()]
    if len(records) != len(log_lines):
        raise SystemExit(f"{build}: {len(log_lines)} log lines but {len(records)} truth records")

    categories: dict[str, set[str]] = defaultdict(set)
    first_seen: dict[str, int] = {}
    volume: dict[str, int] = defaultdict(int)
    for record in records:
        categories[record["client_ip"]].add(record["category"])
        first_seen.setdefault(record["client_ip"], record["line_no"])
        volume[record["client_ip"]] += 1

    ordinary = [
        ip
        for ip in sorted(categories, key=first_seen.__getitem__)
        if not (categories[ip] & HOSTILE_CATEGORIES)
        and "unknown" not in categories[ip]
        and volume[ip] <= ORDINARY_MAX_LINES
    ][:ORDINARY_CLIENTS]
    keep = set(HOSTILE_CLIENTS) | set(ordinary)

    out_log: list[bytes] = []
    out_truth: list[str] = []
    for line, record in zip(log_lines, records, strict=True):
        if record["client_ip"] not in keep or record["category"] == "unknown":
            continue
        out_log.append(line)
        out_truth.append(
            json.dumps(
                {
                    "line_no": len(out_log),
                    "client_ip": record["client_ip"],
                    "category": record["category"],
                    "instance_id": record["instance_id"],
                },
                separators=(",", ":"),
            )
        )

    header = {
        **header,
        "scenario": f"{header['scenario']}-excerpt",
        "source_file_id": "excerpt.log",
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "excerpt.log").write_bytes(b"\n".join(out_log) + b"\n")
    (out / "excerpt.truth.jsonl").write_bytes(
        ("\n".join([json.dumps(header, separators=(",", ":")), *out_truth]) + "\n").encode()
    )
    sums = "".join(
        f"{hashlib.sha256((out / name).read_bytes()).hexdigest()}  {name}\n"
        for name in ("excerpt.log", "excerpt.truth.jsonl")
    )
    (out / "SHA256SUMS").write_bytes(sums.encode())
    return len(out_log), len(keep)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path, help="a dataset build folder")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    lines, clients = cut(args.build, args.out)
    print(f"kept {lines} lines from {clients} clients into {args.out}")


if __name__ == "__main__":
    main()
