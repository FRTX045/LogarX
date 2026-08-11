"""The one test that needs the Go binary.

Everything else about CRS integration is testable with a synthetic detection
set. This is not: it checks that the sidecar's JSON contract still holds, which
guards against CRS or Coraza changing underneath rather than against this code.

Skipped when the sidecar has not been built, which is how CI runs — see
`crs/README.md` for the build.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.crs import SidecarConfig, run_sidecar

CONFIG = SidecarConfig()

pytestmark = pytest.mark.skipif(
    not CONFIG.binary.exists() or not (CONFIG.rules / "rules").is_dir(),
    reason="CRS sidecar or ruleset not built; see crs/README.md",
)


def event(target: str, line_no: int) -> NormalizedEvent:
    path, _, query = target.partition("?")
    return NormalizedEvent(
        timestamp=datetime(2024, 5, 1, tzinfo=UTC),
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", line_no),
        method="GET",
        path=path,
        query=query or None,
        protocol="HTTP/1.1",
        status=200,
        user_agent="curl/8.0",
    )


def test_a_known_payload_still_fires_the_rule_it_is_famous_for() -> None:
    """942100 is libinjection, the highest-yield SQLi rule CRS has. If Coraza
    ever stops loading it, everything downstream quietly gets worse."""
    detections = run_sidecar([event("/search?q=1%27%20UNION%20SELECT%20pw", 1)], config=CONFIG)

    assert 942100 in {item.rule_id for item in detections}
    assert {item.attack_family for item in detections} == {"attack-sqli"}


def test_ordinary_traffic_produces_nothing() -> None:
    """At paranoia level 1 a plain page request must be silent. If this starts
    failing, the paranoia level is wrong for a tool where a false positive
    splits an episode."""
    assert run_sidecar([event("/index.html", 1)], config=CONFIG) == []


def test_a_payload_the_bundled_rules_miss_is_caught() -> None:
    """The reason for the whole integration: 932140 accounted for 150 of the
    1,001 misses recorded in ADR-0007's follow-up."""
    target = "/get?foo=for%20%25variable%20in%20%28set%29%20do%20command"

    detections = run_sidecar([event(target, 4)], config=CONFIG)

    assert 932140 in {item.rule_id for item in detections}


def test_detections_carry_the_line_they_came_from() -> None:
    """Without this a finding cannot be tied back to a log line, which is the
    property the whole evidence chain rests on."""
    detections = run_sidecar(
        [event("/index.html", 1), event("/search?q=1%27%20UNION%20SELECT%20pw", 2)],
        config=CONFIG,
    )

    assert {item.line_no for item in detections} == {2}
    assert {item.source_file_id for item in detections} == {"access.log"}
