"""Reading back the raw log lines a finding rests on.

The whole design turns on every node tracing to a source line. Until now
nothing could actually fetch one, so the claim was structural rather than
demonstrable.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from zodiarc.case import Case
from zodiarc.core.evidence import EvidenceRef
from zodiarc.parsers.registry import register_spec, unregister_format
from zodiarc.parsers.spec import LogFormatSpec, PatternFormatSpec

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.0"',
    '198.51.100.9 - - [10/Oct/2020:13:56:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8"',
]


@pytest.fixture
def case(tmp_path: Path) -> Case:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as opened:
        opened.ingest([log])
    return Case.open(tmp_path / "case")


def test_a_reference_returns_the_line_it_points_at(case: Case) -> None:
    (line,) = case.read_evidence([EvidenceRef("access.log", 2)])

    assert line.available
    assert line.text == LINES[1]
    assert line.ref == EvidenceRef("access.log", 2)


def test_references_come_back_in_the_order_they_were_asked_for(case: Case) -> None:
    refs = [EvidenceRef("access.log", 3), EvidenceRef("access.log", 1)]

    lines = case.read_evidence(refs)

    assert [item.ref.line_no for item in lines] == [3, 1]
    assert [item.text for item in lines] == [LINES[2], LINES[0]]


def test_a_line_past_the_end_of_the_file_is_reported_not_raised(case: Case) -> None:
    (line,) = case.read_evidence([EvidenceRef("access.log", 9999)])

    assert not line.available
    assert line.text is None
    assert "only 3 lines" in (line.note or "")


def test_an_unknown_source_file_is_reported(case: Case) -> None:
    (line,) = case.read_evidence([EvidenceRef("nowhere.log", 1)])

    assert not line.available
    assert "not part of this case" in (line.note or "")


def test_a_source_that_has_gone_missing_is_reported_rather_than_crashing(
    case: Case, tmp_path: Path
) -> None:
    """Evidence outlives the file it came from. Saying so is the point."""
    (tmp_path / "access.log").unlink()

    (line,) = case.read_evidence([EvidenceRef("access.log", 1)])

    assert not line.available
    assert "cannot" in (line.note or "").lower() or "missing" in (line.note or "").lower()


def test_a_source_that_changed_since_ingest_is_flagged(case: Case, tmp_path: Path) -> None:
    """A line read out of an altered file is not the line that was ingested."""
    (tmp_path / "access.log").write_text("\n".join(LINES) + "\nextra\n", encoding="utf-8")

    (line,) = case.read_evidence([EvidenceRef("access.log", 1)])

    assert line.text == LINES[0]
    assert not line.verified
    assert "changed" in (line.note or "")
    assert line.warning == line.note


def test_a_line_that_could_not_be_checked_still_carries_a_warning() -> None:
    """Unverified with no account of why is still unverified. Whatever writes
    the line out has something to say beside it."""
    from zodiarc.evidence import EvidenceLine

    line = EvidenceLine(ref=EvidenceRef("access.log", 1), source_path="a.log", text="x")

    assert line.warning


def test_an_unchanged_source_is_marked_verified(case: Case) -> None:
    (line,) = case.read_evidence([EvidenceRef("access.log", 1)])

    assert line.verified
    assert line.note is None
    assert line.warning is None


def test_a_compressed_source_is_read_too(tmp_path: Path) -> None:
    log = tmp_path / "access.log.gz"
    with gzip.open(log, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(LINES) + "\n")
    with Case.create(tmp_path / "case") as opened:
        opened.ingest([log])

    with Case.open(tmp_path / "case") as opened:
        (line,) = opened.read_evidence([EvidenceRef("access.log.gz", 2)])

    assert line.available
    assert line.text == LINES[1]


def test_many_references_to_one_file_are_all_resolved(case: Case) -> None:
    refs = [EvidenceRef("access.log", n) for n in (1, 2, 3, 2, 1)]

    lines = case.read_evidence(refs)

    assert [item.text for item in lines] == [LINES[0], LINES[1], LINES[2], LINES[1], LINES[0]]


def test_asking_for_nothing_returns_nothing(case: Case) -> None:
    assert case.read_evidence([]) == []


def test_the_line_names_the_file_it_came_from(case: Case, tmp_path: Path) -> None:
    (line,) = case.read_evidence([EvidenceRef("access.log", 1)])

    assert Path(line.source_path) == tmp_path / "access.log"


def test_a_line_comes_back_parsed_by_the_case_s_own_parser(case: Case) -> None:
    """The panel needs fields, not a string to re-parse by eye.

    Parsed here rather than in the interface, with the parser the manifest
    records for that file — the same one that produced the finding. A second,
    interface-side reading of the same bytes could disagree with the engine
    about what the request was, and the reader would have no way to tell which
    of the two they were looking at.
    """
    (line,) = case.read_evidence([EvidenceRef("access.log", 2)])

    assert line.event is not None
    assert line.event.method == "GET"
    assert line.event.path == "/.env"
    assert line.event.status == 404
    assert line.event.user_agent == "curl/8.0"


def test_a_line_the_parser_cannot_read_still_comes_back(case: Case, tmp_path: Path) -> None:
    """Partial evidence is still evidence, and a line the parser rejects is
    itself worth seeing — so the raw text survives and the fields are simply
    absent, rather than the lookup failing."""
    root = tmp_path / "broken"
    log = root / "access.log"
    root.mkdir()
    log.write_text("\n".join([*LINES, "this is not a log line at all"]) + "\n", encoding="utf-8")
    with Case.create(root / "case") as opened:
        opened.ingest([log])
    with Case.open(root / "case") as opened:
        (line,) = opened.read_evidence([EvidenceRef("access.log", 4)])

    assert line.available
    assert line.text == "this is not a log line at all"
    assert line.event is None


# ---------------------------------------------------------------------------
# A case outliving the format it was ingested with
# ---------------------------------------------------------------------------

#: Pipe-separated, so nothing built in can read it. Removing this format from
#: the registry leaves the case with only its own copy to work from.
PIPED = '%h|%t|"%r"|%>s|%b'

PIPED_LINES = [
    '203.0.113.5|[10/Oct/2020:13:55:36 +0000]|"GET / HTTP/1.1"|200|2326',
    '203.0.113.5|[10/Oct/2020:13:55:40 +0000]|"GET /.env HTTP/1.1"|404|0',
]


def test_a_case_still_reads_its_fields_after_its_format_is_deleted(tmp_path: Path) -> None:
    """The reason the case carries a copy at all.

    A user who edits or deletes a saved format must not silently lose the
    fields of every case that was read with it. Before the case stored the
    definition, the name was all it had, and this returned a line with no
    parsed event attached.
    """
    log = tmp_path / "access.log"
    log.write_text("\n".join(PIPED_LINES) + "\n", encoding="utf-8")

    register_spec(LogFormatSpec(name="pipes", directive=PIPED))
    try:
        with Case.create(tmp_path / "case") as opened:
            opened.ingest([log], log_format="pipes")
    finally:
        # The user deleted the format between ingesting and re-opening.
        unregister_format("pipes")

    with Case.open(tmp_path / "case") as reopened:
        (line,) = reopened.read_evidence([EvidenceRef("access.log", 2)])

    assert line.available
    assert line.text == PIPED_LINES[1]
    assert line.event is not None, "the line came back with no parsed fields"
    assert line.event.status == 404


def test_an_unresolvable_format_still_returns_the_line_itself(tmp_path: Path) -> None:
    """The older guarantee, unchanged: a format that cannot be resolved at all
    costs the fields, never the line. A case whose record predates stored
    definitions still lands here."""
    log = tmp_path / "access.log"
    log.write_text("\n".join(PIPED_LINES) + "\n", encoding="utf-8")

    register_spec(LogFormatSpec(name="pipes", directive=PIPED))
    try:
        with Case.create(tmp_path / "case") as opened:
            opened.ingest([log], log_format="pipes")
    finally:
        unregister_format("pipes")

    # Strip the stored copy, leaving a case shaped like one from before.
    manifest_path = tmp_path / "case" / "case.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["sources"][0]["format_spec"] = None
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with Case.open(tmp_path / "case") as reopened:
        (line,) = reopened.read_evidence([EvidenceRef("access.log", 2)])

    assert line.available
    assert line.text == PIPED_LINES[1]
    assert line.event is None


PIPED_PATTERN = PatternFormatSpec(
    name="pipes-pattern",
    pattern=(
        r'(?P<client_ip>[^|]+)\|\[(?P<timestamp>[^\]]+)\]\|"(?P<request_line>[^"]*)"'
        r"\|(?P<status>\d+)\|(?P<bytes_sent>\d+)"
    ),
    time_format="%d/%b/%Y:%H:%M:%S %z",
)


def _piped_case(tmp_path: Path, *, stored: dict[str, object] | None = None) -> Path:
    """A case read with `PIPED_PATTERN`, which is then no longer held here. With
    `stored`, the case's own copy of the definition is replaced by it."""
    log = tmp_path / "access.log"
    log.write_text("\n".join(PIPED_LINES) + "\n", encoding="utf-8")
    register_spec(PIPED_PATTERN)
    try:
        with Case.create(tmp_path / "case") as opened:
            opened.ingest([log], log_format="pipes-pattern")
    finally:
        unregister_format("pipes-pattern")
    if stored is not None:
        manifest_path = tmp_path / "case" / "case.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["sources"][0]["format_spec"] = stored
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path / "case"


def test_a_case_s_own_pattern_is_never_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A case is a folder anyone can hand over, and a regular expression can be
    written to take hours on one short line. Opening someone else's case must not
    run theirs: the lines come back, without the fields."""
    case = _piped_case(tmp_path)

    def refuse(_spec: object) -> object:
        raise AssertionError("a pattern stored in the case was compiled")

    monkeypatch.setattr(PatternFormatSpec, "build", refuse)
    with Case.open(case) as reopened:
        (line,) = reopened.read_evidence([EvidenceRef("access.log", 2)])

    assert line.text == PIPED_LINES[1]
    assert line.event is None


def test_a_case_s_pattern_that_will_not_compile_costs_the_fields_not_the_line(
    tmp_path: Path,
) -> None:
    stored = {
        "version": 1,
        "kind": "pattern",
        "name": "pipes-pattern",
        "pattern": "(?P<client_ip>(",
    }
    case = _piped_case(tmp_path, stored=stored)

    with Case.open(case) as reopened:
        (line,) = reopened.read_evidence([EvidenceRef("access.log", 2)])

    assert line.text == PIPED_LINES[1]
    assert line.event is None


def test_a_pattern_this_zodiarc_holds_word_for_word_still_reads_the_fields(
    tmp_path: Path,
) -> None:
    """The case's copy is used when it is identical to one held here, a built-in
    or the reader's own: then it is not the case's pattern being run."""
    case = _piped_case(tmp_path)
    register_spec(PIPED_PATTERN)
    try:
        with Case.open(case) as reopened:
            (line,) = reopened.read_evidence([EvidenceRef("access.log", 2)])
    finally:
        unregister_format("pipes-pattern")

    assert line.event is not None
    assert line.event.status == 404
