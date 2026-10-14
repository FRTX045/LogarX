"""The one test that needs the Go binary.

Everything else about CRS integration is testable with a synthetic detection
set. This is not: it checks that the sidecar's JSON contract still holds, which
guards against CRS or Coraza changing underneath rather than against this code.

Skipped locally when the sidecar has not been built — see `crs/README.md`. CI
builds it and sets `LOGARC_REQUIRE_CRS=1`, which turns the skip off so a build
that quietly failed surfaces as a failure here.

That switch exists because the skip is otherwise self-concealing: the only
cross-language boundary in the project would go unverified on every run, and
the evidence of it would be four lines of "skipped" that a green tick hides.
"""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.crs import SidecarConfig, run_sidecar

CONFIG = SidecarConfig()

REQUIRE_ENV = "LOGARC_REQUIRE_CRS"

_unbuilt = not CONFIG.binary.exists() or not (CONFIG.rules / "rules").is_dir()

# One condition, read two ways, rather than a second copy of it in the CI file:
# when the sidecar is required and missing, the tests run and fail on the real
# `CrsUnavailableError`, which names what is absent and how to build it.
pytestmark = pytest.mark.skipif(
    _unbuilt and os.environ.get(REQUIRE_ENV) != "1",
    reason=f"CRS sidecar or ruleset not built; see crs/README.md (set {REQUIRE_ENV}=1 to require)",
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
    """At the paranoia level this runs — 2, see `crs/main.go` — a plain page
    request must be silent. If this starts failing, the level is wrong for a
    tool where a false positive splits an episode: a detection can name an
    activity, and naming one starts a new episode. PL3 is where that happens;
    it reads a plain `GET /` as "Unix Shell Code Found in Request"."""
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


#: Requests whose file path only CRS's word lists recognise, each with the rule
#: that names it. The lists are written with forward slashes, and the rules
#: clean the path with `t:normalizePath` or `t:normalizePathWin` before
#: looking. Coraza cleans it with Go's `path/filepath`, which on Windows turns
#: every `/` into `\`, so on the Windows sidecar none of these fired and every
#: one passed as harmless; on Linux they all fired. `crs/paths.go` cleans
#: paths the same way on both.
PATHS_CRS_READS = [
    pytest.param("/get?file=/etc/passwd", None, None, 930120, id="os-file-in-a-parameter"),
    pytest.param("/.git/config", None, None, 930130, id="restricted-file"),
    pytest.param("/get?cmd=/bin/bash", None, None, 932160, id="unix-shell"),
    pytest.param("/get", "cat /root/.ssh/id_rsa", None, 930121, id="os-file-in-the-user-agent"),
    pytest.param(
        "/get", None, "http://example.com/?f=/etc/shadow", 932161, id="unix-shell-in-the-referer"
    ),
]


@pytest.mark.parametrize(("target", "user_agent", "referer", "rule_id"), PATHS_CRS_READS)
def test_a_file_path_is_recognised_on_every_system(
    target: str, user_agent: str | None, referer: str | None, rule_id: int
) -> None:
    request = replace(
        event(target, 1),
        user_agent=user_agent or "curl/8.0",
        referer=referer,
    )

    assert rule_id in {item.rule_id for item in run_sidecar([request], config=CONFIG)}


def test_a_flush_marker_is_answered_before_the_input_ends() -> None:
    """A sidecar that lives for a whole run is sent one share after another.
    After each share comes `{"flush": N}`, and the answers to everything before
    it, then `{"flushed": N}`, must arrive while the input is still open. Twice,
    so the second share is answered by the same process."""
    import json
    import queue
    import subprocess
    import threading

    from logarc.detect.crs.sidecar import as_record

    process = subprocess.Popen(
        [
            str(CONFIG.binary),
            "--rules",
            str(CONFIG.rules),
            "--conf",
            str(CONFIG.conf),
            "--paranoia",
            str(CONFIG.paranoia),
            "--host",
            CONFIG.host,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )
    assert process.stdin is not None and process.stdout is not None
    lines: queue.Queue[str] = queue.Queue()
    reader = threading.Thread(
        target=lambda: [lines.put(line) for line in process.stdout], daemon=True
    )
    reader.start()

    def share(line_no: int, target: str) -> list[dict[str, object]]:
        assert process.stdin is not None
        process.stdin.write(json.dumps(as_record(event(target, line_no))) + "\n")
        process.stdin.write(json.dumps({"flush": line_no}) + "\n")
        process.stdin.flush()
        answers = []
        while True:
            answer = json.loads(lines.get(timeout=30))
            if answer == {"flushed": line_no}:
                return answers
            answers.append(answer)

    try:
        first = share(1, "/search?q=1%27%20UNION%20SELECT%20pw")
        second = share(2, "/index.html")
    finally:
        process.stdin.close()
        process.wait(timeout=30)
        reader.join(timeout=30)
        process.stdout.close()

    assert 942100 in {answer["rule_id"] for answer in first}
    assert {answer["line_no"] for answer in first} == {1}
    assert second == []
    assert process.returncode == 0


def test_a_protocol_newer_than_the_sidecar_is_refused_at_once() -> None:
    """logarc names the protocol it speaks with `--protocol`. A binary asked
    for one it does not know must exit saying so, before reading a line,
    rather than be sent input it cannot answer and leave the run waiting."""
    import subprocess

    result = subprocess.run(
        [
            str(CONFIG.binary),
            "--rules",
            str(CONFIG.rules),
            "--conf",
            str(CONFIG.conf),
            "--protocol",
            "3",
        ],
        input="",
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 2
    assert "speaks protocol 2" in result.stderr
