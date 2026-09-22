"""Tests for the case-level workflow that CLI and GUI both drive."""

from __future__ import annotations

from pathlib import Path

import pytest

from logarc.case import Case, CaseError
from logarc.ingest.pipeline import IngestCancelled

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '198.51.100.9 - - [10/Oct/2020:13:56:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8.0"',
]


def write_log(path: Path, lines: list[str] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines or LINES) + "\n", encoding="utf-8")
    return path


def test_ingesting_a_log_makes_its_events_queryable(tmp_path: Path) -> None:
    log = write_log(tmp_path / "access.log")

    with Case.create(tmp_path / "case") as case:
        case.ingest([log])

    with Case.open(tmp_path / "case") as case:
        assert [e.path for e in case.store.events_for_ip("203.0.113.5")] == ["/"]


def test_the_manifest_records_every_ingested_source(tmp_path: Path) -> None:
    log = write_log(tmp_path / "access.log")

    with Case.create(tmp_path / "case") as case:
        case.ingest([log])

    manifest = Case.open(tmp_path / "case").manifest
    assert len(manifest.sources) == 1
    source = manifest.sources[0]
    assert source.file_id == "access.log"
    assert source.original_path == str(log)
    assert source.events_parsed == 2
    assert len(source.sha256) == 64


def test_several_logs_ingest_into_one_case(tmp_path: Path) -> None:
    first = write_log(tmp_path / "a.log", [LINES[0]])
    second = write_log(tmp_path / "b.log", [LINES[1]])

    with Case.create(tmp_path / "case") as case:
        case.ingest([first, second])

    with Case.open(tmp_path / "case") as case:
        assert {s.client_ip for s in case.store.ip_summaries()} == {
            "203.0.113.5",
            "198.51.100.9",
        }


def test_logs_with_the_same_name_get_distinct_evidence_ids(tmp_path: Path) -> None:
    """Rotated logs are routinely all called access.log. Evidence references
    must still say which file a line came from."""
    first = write_log(tmp_path / "day1" / "access.log", [LINES[0]])
    second = write_log(tmp_path / "day2" / "access.log", [LINES[1]])

    with Case.create(tmp_path / "case") as case:
        case.ingest([first, second])

    ids = {source.file_id for source in Case.open(tmp_path / "case").manifest.sources}
    assert len(ids) == 2


def test_case_id_defaults_to_the_directory_name(tmp_path: Path) -> None:
    with Case.create(tmp_path / "operation-badger") as case:
        assert case.manifest.case_id == "operation-badger"


def test_creating_a_case_where_one_exists_is_refused(tmp_path: Path) -> None:
    """Overwriting a case would destroy evidence already gathered."""
    root = tmp_path / "case"
    with Case.create(root) as case:
        case.ingest([write_log(tmp_path / "access.log")])

    with pytest.raises(CaseError, match="already exists"):
        Case.create(root)


def test_opening_a_directory_that_is_not_a_case_is_refused(tmp_path: Path) -> None:
    with pytest.raises(CaseError):
        Case.open(tmp_path / "nowhere")


def test_ingest_records_quarantined_lines_in_the_manifest(tmp_path: Path) -> None:
    log = write_log(tmp_path / "access.log", [*LINES, "<<< garbage >>>"])

    with Case.create(tmp_path / "case") as case:
        case.ingest([log])

    assert Case.open(tmp_path / "case").manifest.total_lines_quarantined == 1


def test_a_cancelled_ingest_leaves_the_case_unfinalised(tmp_path: Path) -> None:
    """A case stopped halfway must not read as a complete one. Finalising is
    what says "this is all of it", so a cancel has to leave it undone."""
    log = write_log(tmp_path / "access.log", LINES * 10)

    case = Case.create(tmp_path / "case")
    with pytest.raises(IngestCancelled), case:
        case.ingest([log], batch_size=5, should_cancel=lambda: True)

    with Case.open(tmp_path / "case") as reopened:
        assert not reopened.store.is_finalized


def test_a_cancelled_ingest_still_records_the_files_that_completed(tmp_path: Path) -> None:
    """Events in the store that the manifest does not name are evidence with no
    chain of custody — exactly the gap the manifest exists to close."""
    first = write_log(tmp_path / "a.log", LINES)
    second = write_log(tmp_path / "b.log", LINES * 10)
    checks = 0

    def stop() -> bool:
        nonlocal checks
        checks += 1
        return checks > 1

    case = Case.create(tmp_path / "case")
    with pytest.raises(IngestCancelled), case:
        case.ingest([first, second], batch_size=5, should_cancel=stop)

    manifest = Case.open(tmp_path / "case").manifest
    assert [source.file_id for source in manifest.sources] == ["a.log"]


def test_ingesting_into_an_already_finalised_case_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "case"
    log = write_log(tmp_path / "access.log")
    with Case.create(root) as case:
        case.ingest([log])

    with pytest.raises(CaseError, match="finalised"), Case.open(root) as reopened:
        reopened.ingest([log])


def test_the_domains_a_reader_names_survive_closing_the_case(tmp_path: Path) -> None:
    """The answer belongs to the case, not to the session that gave it.

    It is asked once, after the first scan, and every reconstruction afterwards
    has to use it — including ones run tomorrow, from the command line, by
    somebody who never saw the dialog.
    """
    case = Case.create(tmp_path / "case")
    case.ingest([write_log(tmp_path / "access.log")])
    case.set_site_hosts(["HTTPS://Shop.Test/", "www.shop.test"])
    case.close()

    reopened = Case.open(tmp_path / "case")

    # Stored reduced, so the file holds what the comparison will actually use
    # rather than what somebody typed into a box.
    assert reopened.site_hosts == ("shop.test", "www.shop.test")


def test_a_case_nobody_answered_names_no_domains(tmp_path: Path) -> None:
    case = Case.create(tmp_path / "case")
    case.ingest([write_log(tmp_path / "access.log")])

    assert case.site_hosts == ()


def test_naming_no_domains_clears_an_earlier_answer(tmp_path: Path) -> None:
    """A reader who got it wrong has to be able to take it back, and taking it
    back has to mean the rule goes quiet again rather than half-applying."""
    case = Case.create(tmp_path / "case")
    case.ingest([write_log(tmp_path / "access.log")])
    case.set_site_hosts(["shop.test"])

    case.set_site_hosts([])

    assert case.site_hosts == ()
    assert Case.open(tmp_path / "case").site_hosts == ()


# -- proposing an answer to the domain question ------------------------------

VHOST = [
    "shop.test:443 203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "
    '"GET /page?url=https://cdn.other.test/x.txt HTTP/1.1" 200 120 "-" "curl/8.0"',
    "shop.test:443 203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "
    '"GET /cart HTTP/1.1" 200 900 "-" "curl/8.0"',
]

NO_URLS = [
    "shop.test:443 203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "
    '"GET /cart HTTP/1.1" 200 900 "-" "curl/8.0"',
    "shop.test:443 203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "
    '"GET /search?q=socks HTTP/1.1" 200 900 "-" "curl/8.0"',
]


def _scanned(tmp_path: Path, lines: list[str], log_format: str | None = None) -> Case:
    """Ingest and finalise, then reopen — the state the question is asked in.

    `suggest_site_hosts` reads the event store, which refuses until the case is
    finalised. Both front ends already reach it that way: the GUI asks after
    `with Case.create(...)` has closed, and the CLI after `ingest` returned.
    """
    with Case.create(tmp_path / "case") as case:
        case.ingest([write_log(tmp_path / "log", lines)], log_format=log_format)
    return Case.open(tmp_path / "case")


def test_a_log_that_passes_urls_around_is_worth_asking_about(tmp_path: Path) -> None:
    """The question is put only where the answer would change something."""
    case = _scanned(tmp_path, VHOST, "apache-vhost-combined")

    suggestion = case.suggest_site_hosts()

    assert suggestion.worth_asking
    assert suggestion.hosts == ("shop.test",)
    assert suggestion.urls_seen == 1


def test_a_log_that_passes_no_urls_is_not_worth_asking_about(tmp_path: Path) -> None:
    """**Most logs are this one.** A shop whose requests carry no URLs in their
    parameters gets no dialog, because answering would change nothing — and a
    question that never changes anything is the kind of prompt people learn to
    dismiss without reading."""
    case = _scanned(tmp_path, NO_URLS, "apache-vhost-combined")

    assert not case.suggest_site_hosts().worth_asking


def test_a_log_with_no_host_field_proposes_nothing_but_still_asks(tmp_path: Path) -> None:
    """`apache-combined` records no Host, which is most of the logs there are.

    There is nothing to propose, and the question is still worth putting —
    the reader knows the answer even though the log does not.
    """
    case = _scanned(
        tmp_path,
        [
            "203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "
            '"GET /page?url=https://cdn.other.test/x.txt HTTP/1.1" 200 120 "-" "curl/8.0"',
        ],
    )

    suggestion = case.suggest_site_hosts()

    assert suggestion.worth_asking
    assert suggestion.hosts == ()


def test_a_case_that_already_has_an_answer_is_not_asked_again(tmp_path: Path) -> None:
    case = _scanned(tmp_path, VHOST, "apache-vhost-combined")
    case.set_site_hosts(["shop.test"])

    assert not case.suggest_site_hosts().worth_asking
