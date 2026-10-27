"""Tests for driving the CRS sidecar.

Everything here runs without the Go binary, because that is how CI runs and
because the parts worth guarding — what is sent, what is parsed back, and what
is said when the sidecar is absent — do not need it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fake_sidecar import FakeCrs

import logarx.detect.crs.sidecar as sidecar_module
from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.detect.crs.sidecar import (
    AUTO_ENV,
    BINARY_ENV,
    CrsDetection,
    CrsUnavailableError,
    SidecarConfig,
    as_record,
    default_binary,
    host_speaks_for,
    primary_site_host,
    run_sidecar,
    runs_by_default,
)
from logarx.detect.crs.store import (
    CRS_FILE,
    CrsEvidence,
    is_enriched,
    load_detections,
    write_detections,
)

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


def test_the_packaged_application_is_not_told_to_run_go_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`cd crs && go build` is good advice from a source tree and useless from a bundle.

    The packaged Windows build ships the sidecar inside it, and its user has no
    Go toolchain and no `crs/` directory to build in. If the sidecar is missing
    from a bundle, that copy of the application is damaged, so the message says
    so and points at reinstalling. It still must not read as "LogarX is broken":
    everything else works without CRS.
    """
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    config = SidecarConfig(binary=tmp_path / "nope", rules=tmp_path)

    with pytest.raises(CrsUnavailableError) as raised:
        config.check()

    message = str(raised.value)
    assert "go build" not in message
    assert "reinstall" in message.lower()
    assert "everything else works" in message.lower()


def test_the_packaged_application_finds_its_own_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bundle carries `crs/` and `vendor/coreruleset/` under the folder
    PyInstaller unpacks it to, in the same layout as the source tree."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    monkeypatch.delenv(BINARY_ENV, raising=False)

    config = SidecarConfig()

    assert config.binary.parent == tmp_path / "crs"
    assert config.conf == tmp_path / "crs"
    assert config.rules == tmp_path / "vendor" / "coreruleset"


def test_a_source_checkout_still_finds_the_repository_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.delenv(BINARY_ENV, raising=False)

    config = SidecarConfig()

    assert config.binary.parent.name == "crs"
    assert (config.binary.parent.parent / "src" / "logarx").is_dir()
    assert config.rules.parts[-2:] == ("vendor", "coreruleset")


def test_an_absent_ruleset_says_where_to_clone_it(tmp_path: Path) -> None:
    binary = tmp_path / "crs-sidecar"
    binary.write_text("", encoding="utf-8")
    config = SidecarConfig(binary=binary, rules=tmp_path / "absent")

    with pytest.raises(CrsUnavailableError) as raised:
        config.check()

    assert "git clone" in str(raised.value)


@pytest.mark.parametrize("missing", ["sidecar", "ruleset"])
def test_a_source_checkout_missing_crs_is_pointed_at_setup_crs(
    tmp_path: Path, missing: str
) -> None:
    """Either half missing, the first thing said is the one command that fetches
    the pinned ruleset and builds the sidecar; the manual steps follow it."""
    binary = tmp_path / "crs-sidecar"
    if missing == "ruleset":
        binary.write_text("", encoding="utf-8")
    config = SidecarConfig(binary=binary, rules=tmp_path / "absent")

    with pytest.raises(CrsUnavailableError) as raised:
        config.check()

    assert "logarx-dev setup-crs" in str(raised.value)


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


def test_the_fingerprint_changes_when_the_sidecar_reads_requests_differently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The binary is part of what CRS reports, not only the rules: until
    `crs/paths.go` the Windows build missed every rule that looks for a file
    path. A case enriched before a change like that and one enriched after must
    not claim one configuration."""
    config = SidecarConfig(rules=tmp_path, conf=tmp_path)
    before = config.fingerprint()

    monkeypatch.setattr(sidecar_module, "SIDECAR_REVISION", sidecar_module.SIDECAR_REVISION + 1)

    assert config.fingerprint() != before


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


def test_an_unenriched_case_carries_no_crs_evidence(tmp_path: Path) -> None:
    evidence = CrsEvidence.of(tmp_path, {})

    assert evidence.index is None
    assert evidence.fingerprint is None


def test_an_enriched_case_carries_both_its_index_and_its_fingerprint(tmp_path: Path) -> None:
    write_detections(tmp_path, [detection()])

    evidence = CrsEvidence.of(tmp_path, {"crs_fingerprint": "abc123"})

    assert evidence.fingerprint == "abc123"
    assert evidence.index is not None
    assert evidence.index[("access.log", 7)][0].rule_id == 942100


def test_deleting_the_detections_withdraws_the_fingerprint(tmp_path: Path) -> None:
    """The manifest records that `enrich` once ran; only the detection file says
    it still applies. Reading the manifest alone would let a case whose
    `crs.jsonl` was deleted analyse on the bundled rules while still naming a
    CRS configuration — a result crediting something that did not produce it,
    which is the one failure the fingerprint exists to prevent."""
    write_detections(tmp_path, [detection()])
    config = {"crs_fingerprint": "abc123"}
    (tmp_path / CRS_FILE).unlink()

    assert CrsEvidence.of(tmp_path, config).fingerprint is None


def test_an_enrichment_that_found_nothing_still_counts_as_applied(tmp_path: Path) -> None:
    """A clean corpus is exactly what CRS should return nothing for. Reporting
    it as un-enriched would say CRS was never consulted, which is false."""
    write_detections(tmp_path, [])

    evidence = CrsEvidence.of(tmp_path, {"crs_fingerprint": "abc123"})

    assert evidence.fingerprint == "abc123"
    # No detections is not the same as no enrichment, but `analyse_ip` wants
    # `None` for "nothing to apply" either way.
    assert evidence.index is None


def _answering(*lines: str) -> FakeCrs:
    """A sidecar that answers every share with the same output lines."""
    return FakeCrs(answer=lambda _records: list(lines))


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
    fake = FakeCrs()
    fake.fail_at_start = "cannot load rules"
    monkeypatch.setattr(subprocess, "Popen", fake)

    with pytest.raises(CrsUnavailableError) as raised:
        run_sidecar([event()], config=working_config(tmp_path))

    assert "cannot load rules" in str(raised.value)


#: What the go-re2 v1.6.0 sidecar printed on a newer Intel CPU, shortened.
GO_PANIC = (
    "panic: wasm error: invalid table access\n"
    "\twasm stack trace:\n"
    "\t\t.$24(i32,i32,i32,i32)\n"
    "\n"
    "goroutine 1 [running]:\n"
    "github.com/wasilibs/go-re2/internal.newRE(0x2ca2dfdf12c0, {0xdee01100?, 0x2ca2df8f8d38?})\n"
    "\tgithub.com/wasilibs/go-re2@v1.6.0/internal/re2_wazero.go:288 +0x265\n"
    "main.main()\n"
    "\tcrs/main.go:275 +0x24d"
)


def test_a_sidecar_that_crashes_is_reported_in_one_line_with_its_output_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The window and the command line show the message, and a Go panic is a
    stack of forty lines a reader can do nothing with: in the window it ran off
    the bottom of the screen. The first line says what happened; the whole of it
    is kept for whoever reports it."""
    fake = FakeCrs()
    fake.fail_at_start = GO_PANIC
    monkeypatch.setattr(subprocess, "Popen", fake)

    with pytest.raises(CrsUnavailableError) as raised:
        run_sidecar([event()], config=working_config(tmp_path))

    message = str(raised.value)
    assert "\n" not in message
    assert message.startswith("CRS stopped unexpectedly")
    assert "panic: wasm error: invalid table access" in message
    assert raised.value.detail == GO_PANIC


def test_an_unreadable_line_costs_one_detection_not_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Losing one detection beats losing the whole enrichment."""
    good = json.dumps(detection().to_dict())
    monkeypatch.setattr(subprocess, "Popen", _answering("not json", good, ""))

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


def test_a_bundled_ruleset_names_its_revision_without_git(tmp_path: Path) -> None:
    """The packaged application carries the rules without their `.git`, so the
    build writes the revision beside them. Without it every CRS finding from the
    packaged app would record `crs_revision: null`."""
    (tmp_path / "REVISION").write_text("d694d465951e\n", encoding="utf-8")

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

    The next batch is read while the last is replayed, so by the time a sidecar
    is called the stream may be up to two batches in, never three: settling the
    first batch waits for its answer before a third is read. Three batches in
    all, so gathering the stream first is told apart from streaming it. The
    bound was once one batch, and it raced the read-ahead: a worker thread that
    started late saw the next batch's first event already pulled.
    """
    batch = 50
    monkeypatch.setattr("logarx.detect.crs.sidecar._BATCH", batch)
    pulled = 0
    pulled_at_first_call: list[int] = []
    records_sent: list[int] = []

    def events() -> Iterator[NormalizedEvent]:
        nonlocal pulled
        for line_no in range(1, 3 * batch + 1):
            pulled += 1
            # Each its own page: identical requests are replayed once, and this
            # is about streaming, not about repeats.
            yield event(path=f"/page/{line_no}", line_no=line_no)

    def answer(records: list[dict[str, object]]) -> list[str]:
        pulled_at_first_call.append(pulled)
        records_sent.append(len(records))
        return []

    monkeypatch.setattr(subprocess, "Popen", FakeCrs(answer=answer))

    run_sidecar(events(), config=working_config(tmp_path))

    assert pulled_at_first_call[0] <= 2 * batch
    # Streaming must not be bought by dropping the tail.
    assert sum(records_sent) == 3 * batch


def test_every_record_reaches_the_sidecar_under_its_own_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A detection is keyed by `(source_file_id, line_no)`, so a case holding
    two logs must not have one's findings attributed to the other."""
    monkeypatch.setattr(subprocess, "Popen", _answering(json.dumps(detection(line_no=1).to_dict())))
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


# -- telling CRS which host is the site's own --------------------------------
#
# CRS 931130 decides whether a URL in a parameter is off-domain with
# `!@endsWith .%{request_headers.host}`. Apache does not log the Host header,
# so the sidecar synthesises one, and until 2026-09-23 it was always
# `localhost` — which made every outbound URL look foreign. These pin how the
# case's own answer now reaches it.


def test_one_host_covering_the_rest_is_the_one_crs_is_given() -> None:
    """CRS compares with `endsWith`, so `shop.test` already covers
    `www.shop.test` and `cdn.shop.test`. The host that covers the most of the
    others is the right one to hand it."""
    assert primary_site_host(["www.shop.test", "shop.test", "cdn.shop.test"]) == "shop.test"
    assert primary_site_host(["shop.test"]) == "shop.test"


def test_no_answer_hands_crs_nothing() -> None:
    assert primary_site_host([]) is None


def test_unrelated_hosts_resolve_the_same_way_every_run() -> None:
    """Two hosts that do not cover each other cannot both be the Host header.
    The choice is arbitrary but it must be stable — shortest, then alphabetical
    — or the same case would fingerprint differently on two runs."""
    assert primary_site_host(["other.example", "shop.test"]) == "shop.test"
    assert primary_site_host(["b.test", "a.test"]) == "a.test"


def test_a_host_speaks_for_itself_and_its_subdomains_and_nothing_else() -> None:
    """931130's own comparison, `@endsWith .<host>`, restated as the condition
    for trusting what it said. Told `shop.test`, it judged `cdn.shop.test` as
    the site's own and `shopcdn.net` as foreign — so a site that named both
    cannot have been judged correctly, whichever one CRS was given."""
    assert host_speaks_for("shop.test", ["shop.test", "www.shop.test", "cdn.shop.test"])
    assert not host_speaks_for("shop.test", ["shop.test", "shopcdn.net"])
    # The domain bought to be misread, and a suffix without its dot.
    assert not host_speaks_for("shop.test", ["shop.test", "shop.test.evil.test"])
    assert not host_speaks_for("shop.test", ["shop.test", "myshop.test"])


def test_a_host_the_reader_did_not_name_speaks_for_nobody() -> None:
    """Covering is not enough. `localhost` is the placeholder every unanswered
    case was enriched with, and a host the reader has since withdrawn is no
    better — and with nothing named there is nobody to speak for."""
    assert not host_speaks_for("localhost", ["shop.test"])
    assert not host_speaks_for("test", ["shop.test"]), "a parent that was never named"
    assert not host_speaks_for("shop.test", [])
    assert not host_speaks_for(None, ["shop.test"])


def test_the_host_is_part_of_what_produced_a_detection() -> None:
    """**It changes what CRS reports, so it belongs in the fingerprint.**

    Two cases enriched with different hosts produce different 931130 results
    from the same rules and the same paranoia level. Leaving the host out would
    let them claim the same configuration.
    """
    base = SidecarConfig()

    assert replace(base, host="shop.test").fingerprint() != base.fingerprint()
    assert replace(base, host="shop.test").as_config()["crs_host"] == "shop.test"
    assert base.as_config()["crs_host"] == "localhost"


def test_crs_runs_on_a_new_case_unless_somebody_says_otherwise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On by default, in the window and on the command line alike. The switch
    is only consulted for the run nobody asked for: `logarx-dev enrich` and the
    window's own menu item still run CRS when they are told to."""
    monkeypatch.delenv(AUTO_ENV, raising=False)

    assert runs_by_default()


@pytest.mark.parametrize("off", ["off", "OFF", "0", "false", "no", " off "])
def test_one_variable_turns_the_automatic_run_off_everywhere(
    off: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """For a machine where CRS has no business running by itself — a shared
    analysis box, a script that times ingest, this project's own test suite."""
    monkeypatch.setenv(AUTO_ENV, off)

    assert not runs_by_default()


@pytest.mark.parametrize("on", ["on", "1", "yes", "", "anything"])
def test_only_a_clear_no_turns_it_off(on: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo leaves CRS running rather than silently skipping it. The cost of
    the wrong guess is one slower scan, against a case missing detections
    nobody knows are missing."""
    monkeypatch.setenv(AUTO_ENV, on)

    assert runs_by_default()
