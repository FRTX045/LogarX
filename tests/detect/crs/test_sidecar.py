"""Tests for driving the CRS sidecar.

Everything here runs without the Go binary, because that is how CI runs and
because the parts worth guarding — what is sent, what is parsed back, and what
is said when the sidecar is absent — do not need it.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.crs.sidecar import (
    _BATCH,
    BINARY_ENV,
    CrsDetection,
    CrsUnavailableError,
    SidecarConfig,
    as_record,
    default_binary,
    run_sidecar,
)
from logarc.detect.crs.store import is_enriched, load_detections, write_detections

START = datetime(2024, 5, 1, tzinfo=UTC)


def event(*, path: str = "/search", query: str | None = "q=1", line_no: int = 7) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=START,
        client_ip="203.0.113.5",
        evidence=EvidenceRef("access.log", line_no),
        method="GET",
        path=path,
        query=query,
        protocol="HTTP/1.1",
        status=200,
        user_agent="curl/8.0",
    )


def detection(**overrides: object) -> CrsDetection:
    fields: dict[str, object] = {
        "source_file_id": "access.log",
        "line_no": 7,
        "rule_id": 942100,
        "severity": "critical",
        "msg": "SQL Injection Attack Detected via libinjection",
        "matched_var": "ARGS:q",
        "transformed_value": "1' UNION SELECT",
        "attack_family": "attack-sqli",
    }
    fields.update(overrides)
    return CrsDetection(**fields)  # type: ignore[arg-type]


def test_the_request_line_is_sent_whole() -> None:
    """CRS parses `ARGS` itself, and most of its rules target them. Handing it a
    pre-split path would leave those rules nothing to match against."""
    record = as_record(event(path="/search", query="q=1%27+UNION+SELECT"))

    assert record["raw_target"] == "/search?q=1%27+UNION+SELECT"
    assert record["line_no"] == 7


def test_a_record_carries_the_fields_a_combined_log_has() -> None:
    record = as_record(event())

    assert set(record) == {
        "line_no",
        "client_ip",
        "method",
        "raw_target",
        "protocol",
        "status",
        "referer",
        "user_agent",
    }


def test_a_detection_round_trips_through_json() -> None:
    original = detection()

    restored = CrsDetection.from_json(
        json.loads(json.dumps(original.to_dict())), source_file_id="access.log"
    )

    assert restored == original


def test_a_detection_names_itself_apart_from_the_bundled_rules() -> None:
    """`crs:942100` rather than `942100`, so a reader can tell at a glance where
    a finding came from."""
    assert detection().label_id == "crs:942100"


def test_missing_fields_do_not_break_parsing() -> None:
    """The sidecar omits `attack_family` for rules that carry no attack tag."""
    parsed = CrsDetection.from_json({"line_no": 3, "rule_id": 920100}, source_file_id="access.log")

    assert parsed.attack_family is None
    assert parsed.tags == ()


def test_an_absent_sidecar_says_how_to_build_one(tmp_path: Path) -> None:
    """This is the first error a new user meets; a bare "not found" makes an
    unbuilt optional component look broken."""
    config = SidecarConfig(binary=tmp_path / "nope", rules=tmp_path)

    with pytest.raises(CrsUnavailableError) as raised:
        config.check()

    assert "go build" in str(raised.value)


def test_an_absent_ruleset_says_where_to_clone_it(tmp_path: Path) -> None:
    binary = tmp_path / "crs-sidecar"
    binary.write_text("", encoding="utf-8")
    config = SidecarConfig(binary=binary, rules=tmp_path / "absent")

    with pytest.raises(CrsUnavailableError) as raised:
        config.check()

    assert "git clone" in str(raised.value)


def test_the_binary_name_follows_the_interpreter_not_the_build_host() -> None:
    """A Windows interpreter cannot spawn an ELF, and this project is developed
    with a Windows venv over a Linux toolchain."""
    import sys

    expected = "crs-sidecar.exe" if sys.platform == "win32" else "crs-sidecar"

    assert default_binary().name == expected


def test_an_explicit_binary_path_overrides_the_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(BINARY_ENV, str(tmp_path / "elsewhere"))

    assert default_binary() == tmp_path / "elsewhere"


def test_the_fingerprint_changes_when_the_paranoia_level_does(tmp_path: Path) -> None:
    """Retuning must invalidate a stored detection set rather than silently
    mixing two settings in one case."""
    quiet = SidecarConfig(rules=tmp_path, conf=tmp_path, paranoia=1)
    loud = SidecarConfig(rules=tmp_path, conf=tmp_path, paranoia=3)

    assert quiet.fingerprint() != loud.fingerprint()


def test_the_recorded_config_names_what_produced_a_result(tmp_path: Path) -> None:
    recorded = SidecarConfig(rules=tmp_path, conf=tmp_path, paranoia=2).as_config()

    assert recorded["crs_paranoia_level"] == 2
    assert recorded["crs_fingerprint"]


def test_detections_survive_a_round_trip_through_a_case(tmp_path: Path) -> None:
    write_detections(tmp_path, [detection(), detection(rule_id=942190, line_no=9)])

    index = load_detections(tmp_path)

    assert len(index[("access.log", 7)]) == 1
    assert index[("access.log", 9)][0].rule_id == 942190


def test_an_unenriched_case_reads_as_empty_rather_than_missing(tmp_path: Path) -> None:
    """The normal state of a case nobody has enriched. Saying so is the caller's
    job, not this one's."""
    assert load_detections(tmp_path) == {}


def test_an_enriched_case_is_distinguishable_from_one_with_no_findings(
    tmp_path: Path,
) -> None:
    """Regression: the two used to be indistinguishable, and conflating them
    breaks in both directions.

    Keyed on an empty index, a clean corpus — which is exactly what CRS should
    return nothing for — would announce "CRS not consulted" on every run. Keyed
    on the manifest alone, a case whose detections were deleted would report a
    CRS fingerprint for an analysis CRS took no part in.
    """
    assert is_enriched(tmp_path) is False

    write_detections(tmp_path, [])

    assert is_enriched(tmp_path) is True
    assert load_detections(tmp_path) == {}


def _fake_run(stdout: str = "", stderr: str = "", returncode: int = 0):
    def run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], returncode, stdout, stderr)

    return run


def working_config(tmp_path: Path) -> SidecarConfig:
    binary = tmp_path / "crs-sidecar"
    binary.write_text("", encoding="utf-8")
    (tmp_path / "rules").mkdir(exist_ok=True)
    return SidecarConfig(binary=binary, rules=tmp_path, conf=tmp_path)


def test_a_failing_sidecar_reports_its_own_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-zero exit means the replay did not happen. Returning an empty
    detection set would look exactly like a clean corpus."""
    monkeypatch.setattr(subprocess, "run", _fake_run(stderr="cannot load rules", returncode=1))

    with pytest.raises(CrsUnavailableError) as raised:
        run_sidecar([event()], config=working_config(tmp_path))

    assert "cannot load rules" in str(raised.value)


def test_an_unreadable_line_costs_one_detection_not_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Losing one detection beats losing the whole enrichment."""
    good = json.dumps(detection().to_dict())
    monkeypatch.setattr(subprocess, "run", _fake_run(stdout=f"not json\n{good}\n\n"))

    found = run_sidecar([event()], config=working_config(tmp_path))

    assert [item.rule_id for item in found] == [942100]


def test_the_revision_follows_a_symbolic_head(tmp_path: Path) -> None:
    """A fresh clone writes `ref: refs/heads/main`, not a bare sha, and the
    revision is what makes a measurement re-derivable."""
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "refs" / "heads" / "main").write_text("d694d465951e\n", encoding="utf-8")

    assert SidecarConfig(rules=tmp_path, conf=tmp_path).revision() == "d694d465951e"


def test_a_detached_head_is_read_directly(tmp_path: Path) -> None:
    """`git checkout <sha>` — how the pinned ruleset is actually used."""
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("d694d465951e\n", encoding="utf-8")

    assert SidecarConfig(rules=tmp_path, conf=tmp_path).revision() == "d694d465951e"


def test_a_ruleset_that_is_not_a_checkout_has_no_revision(tmp_path: Path) -> None:
    assert SidecarConfig(rules=tmp_path, conf=tmp_path).revision() is None


def test_a_case_is_streamed_rather_than_gathered_before_the_first_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The store streams `all_events()` precisely so a case bigger than memory
    can be enriched. Gathering them here would undo that, and the failure would
    be invisible on any case small enough to test by hand.

    Measured at the moment of the first invocation rather than by peak memory:
    how many events had to exist for work to begin is the property that decides
    whether a twelve-million-line case is enrichable, and it is exact.
    """
    pulled = 0
    pulled_at_first_call: list[int] = []
    records_sent: list[int] = []

    def events() -> Iterator[NormalizedEvent]:
        nonlocal pulled
        for line_no in range(1, _BATCH + 2):  # one more than a single batch holds
            pulled += 1
            yield event(line_no=line_no)

    def run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        pulled_at_first_call.append(pulled)
        records_sent.append(len(str(kwargs["input"]).splitlines()))
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)

    run_sidecar(events(), config=working_config(tmp_path))

    assert pulled_at_first_call[0] <= _BATCH
    # Streaming must not be bought by dropping the tail.
    assert sum(records_sent) == _BATCH + 1


def test_every_record_reaches_the_sidecar_under_its_own_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A detection is keyed by `(source_file_id, line_no)`, so a case holding
    two logs must not have one's findings attributed to the other."""
    monkeypatch.setattr(
        subprocess, "run", _fake_run(stdout=json.dumps(detection(line_no=1).to_dict()))
    )
    first = event(line_no=1)
    second = NormalizedEvent(
        timestamp=START,
        client_ip="203.0.113.9",
        evidence=EvidenceRef("other.log", 1),
        method="GET",
        path="/",
    )

    found = run_sidecar([first, second], config=working_config(tmp_path))

    assert {item.source_file_id for item in found} == {"access.log", "other.log"}
