"""A controlled unusualness fixture, independent of attack classifications.

Three legitimate clients make an unusually concentrated burst, transfer large
responses, or repeatedly receive 404s. The other clients browse four paths.
These labels test the intended comparison, not real-world anomaly accuracy.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path


def write_scenario(directory: Path) -> tuple[Path, dict[str, bool]]:
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "access.log"
    labels = {}
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with source.open("w", encoding="utf-8") as output:
        for index in range(1, 124):
            ip = f"192.0.2.{index}"
            labels[ip] = index > 120
            count = 20 if index > 120 else 20 + index % 5
            for request in range(count):
                when = start + timedelta(seconds=request * (1 if index == 121 else 90))
                stamp = when.strftime("%d/%b/%Y:%H:%M:%S %z")
                size = 10_000_000 if index == 122 else 500 + 50 * (index % 5)
                status = 404 if index == 123 else 200
                output.write(
                    f'{ip} - - [{stamp}] "GET /product/{request % 4} HTTP/1.1" '
                    f'{status} {size} "-" "Mozilla/5.0"\n'
                )
    return source, labels


def write_workload(directory: Path, kind: str):
    """Assign scenario roles before emitting traffic, independently of any ranking.

    These scenarios test retrieval tradeoffs, not representative accuracy. Routine
    crawlers, shared addresses and broken links deliberately compete with planted
    investigation targets. Attack-heavy traffic is a separate security judgment.
    """
    if kind not in ("mixed", "isolated", "moderate", "uniform", "attack-heavy"):
        raise ValueError(kind)
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "access.log"
    roles = {}
    start = datetime(2026, 1, 1, tzinfo=UTC)
    for index in range(132):
        role = "browsing"
        if kind != "uniform":
            if 80 <= index < 100:
                role = "crawler"
            elif 100 <= index < 110:
                role = "shared-address"
            elif 110 <= index < 120:
                role = "benign-404"
            elif 120 <= index < 130:
                role = "missing-fields"
            elif index == 130 and kind != "moderate":
                role = "isolated-extreme"
            elif index == 131 and kind != "isolated":
                role = "several-moderate-deviations"
            if kind == "attack-heavy" and index < 90:
                role = "routine-injection"
        roles[f"192.0.2.{index + 1}"] = role
    unusual = {
        ip: role in ("isolated-extreme", "several-moderate-deviations")
        for ip, role in roles.items()
    }
    attacks = {ip: role == "routine-injection" for ip, role in roles.items()}
    with source.open("w", encoding="utf-8") as stream:
        for index, (ip, role) in enumerate(roles.items()):
            count = 60 if kind == "uniform" else 60 + index % 31
            if role in ("crawler", "shared-address", "several-moderate-deviations"):
                count = 200 + index % 31
            for request in range(count):
                gap = 90
                if role == "crawler":
                    gap = 3
                elif role in ("shared-address", "several-moderate-deviations"):
                    gap = 8
                stamp = (start + timedelta(seconds=request * gap)).strftime("%d/%b/%Y:%H:%M:%S %z")
                path = f"/product/{request % 8}"
                status, size = "200", str(500 + (index % 7) * 100)
                if kind == "uniform":
                    size = "500"
                if role == "crawler":
                    path = f"/catalog/{request}"
                elif role == "shared-address":
                    path = f"/product/{request % 50}"
                elif role == "benign-404":
                    path, status = f"/retired/{request % 10}", "404"
                elif role == "isolated-extreme":
                    size = "10000000"
                elif role == "several-moderate-deviations":
                    path = f"/api/{request % 100}"
                    size = "5000"
                    status = "500" if request % 4 == 0 else "200"
                elif role == "routine-injection":
                    path = "/search?q=1%20UNION%20SELECT%20password%20FROM%20users"
                    status = "403"
                request_line = f"GET {path} HTTP/1.1"
                if role == "missing-fields":
                    request_line, status, size = "-", "-", "-"
                agent = (
                    "Googlebot/2.1" if role == "crawler" else f"Mozilla/5.0 workload-{request % 3}"
                )
                stream.write(f'{ip} - - [{stamp}] "{request_line}" {status} {size} "-" "{agent}"\n')
    return source, roles, attacks, unusual
