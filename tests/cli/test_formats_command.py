"""Tests for `logarc formats`.

Until now there was no way to write a log format down. `register_logformat`
existed and was reachable only from a Python script that imported logarc, so a
format vanished with the process that made it — and `logarc formats` printed
that a custom directive "is supported by passing its directive string", which
nothing accepted. These commands are what makes that sentence true.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarc.cli.main import app
from logarc.parsers.apache import COMBINED
from logarc.parsers.library import library_path, load_library, save_library
from logarc.parsers.spec import LogFormatSpec

runner = CliRunner()

#: Pipe-separated: no built-in reads it, so nothing here can pass by accident.
PIPED = '%h|%t|"%r"|%>s|%b'

PIPED_LINES = [
    '203.0.113.5|[10/Oct/2020:13:55:36 +0000]|"GET / HTTP/1.1"|200|2326',
    '203.0.113.9|[10/Oct/2020:13:55:40 +0000]|"GET /.env HTTP/1.1"|404|0',
]


@pytest.fixture
def piped_log(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text("\n".join(PIPED_LINES) + "\n", encoding="utf-8")
    return log


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


def test_the_bare_command_still_lists_the_built_in_formats() -> None:
    """It was a command and is now a group; running it with no subcommand must
    keep doing what it did, or every existing habit and doc line breaks."""
    result = runner.invoke(app, ["formats"])

    assert result.exit_code == 0
    assert "apache-combined" in result.stdout


def test_a_saved_format_is_listed_and_marked_as_the_user_s() -> None:
    save_library([LogFormatSpec(name="log-kantor", directive=PIPED)])

    result = runner.invoke(app, ["formats"])

    assert result.exit_code == 0
    assert "log-kantor" in result.stdout
    assert "saved" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Adding
# ---------------------------------------------------------------------------


def test_a_format_can_be_added_and_comes_back_in_the_library() -> None:
    result = runner.invoke(app, ["formats", "add", "log-kantor", PIPED])

    assert result.exit_code == 0, result.stdout
    assert load_library() == [LogFormatSpec(name="log-kantor", directive=PIPED)]


def test_an_added_format_keeps_the_note_written_with_it() -> None:
    runner.invoke(app, ["formats", "add", "log-kantor", PIPED, "--note", "the office server"])

    assert load_library()[0].description == "the office server"


def test_a_directive_that_will_not_compile_is_refused_with_a_message() -> None:
    result = runner.invoke(app, ["formats", "add", "broken", "no percent signs"])

    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert load_library() == []


def test_a_name_that_collides_with_a_built_in_is_refused() -> None:
    """Registration order is preference order and the built-ins come first, so
    a saved format of the same name would never be reached — and a case
    recording `apache-combined` would start meaning something else."""
    result = runner.invoke(app, ["formats", "add", "apache-combined", PIPED])

    assert result.exit_code != 0
    assert "apache-combined" in result.output
    assert load_library() == []


def test_adding_a_name_that_is_already_saved_is_refused_unless_replacing() -> None:
    runner.invoke(app, ["formats", "add", "log-kantor", PIPED])

    result = runner.invoke(app, ["formats", "add", "log-kantor", COMBINED])

    assert result.exit_code != 0
    assert load_library()[0].directive == PIPED


def test_replacing_a_saved_format_is_possible_when_asked_for() -> None:
    runner.invoke(app, ["formats", "add", "log-kantor", PIPED])

    result = runner.invoke(app, ["formats", "add", "log-kantor", COMBINED, "--replace"])

    assert result.exit_code == 0, result.stdout
    assert load_library()[0].directive == COMBINED


# ---------------------------------------------------------------------------
# Showing and removing
# ---------------------------------------------------------------------------


def test_show_prints_the_definition_behind_a_name() -> None:
    result = runner.invoke(app, ["formats", "show", "apache-combined"])

    assert result.exit_code == 0
    assert "%{User-Agent}i" in result.stdout


def test_show_of_an_unknown_name_fails_cleanly() -> None:
    result = runner.invoke(app, ["formats", "show", "nonsense"])

    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_a_saved_format_can_be_removed() -> None:
    runner.invoke(app, ["formats", "add", "log-kantor", PIPED])

    result = runner.invoke(app, ["formats", "remove", "log-kantor"])

    assert result.exit_code == 0, result.stdout
    assert load_library() == []


def test_removing_a_built_in_is_refused() -> None:
    result = runner.invoke(app, ["formats", "remove", "apache-combined"])

    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_removing_a_name_that_was_never_saved_fails_cleanly() -> None:
    result = runner.invoke(app, ["formats", "remove", "nonsense"])

    assert result.exit_code != 0
    assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# Trying a directive against a real log
# ---------------------------------------------------------------------------


def test_check_shows_what_a_directive_pulls_out_of_a_real_log(piped_log: Path) -> None:
    """Writing a directive blind is guesswork. This is the CLI's answer to
    that: point it at the log and see the fields before saving anything."""
    result = runner.invoke(app, ["formats", "check", PIPED, "--log", str(piped_log)])

    assert result.exit_code == 0, result.stdout
    assert "203.0.113.5" in result.stdout
    assert "/.env" in result.stdout
    assert "2 of 2" in result.stdout


def test_check_says_plainly_when_a_directive_reads_nothing(piped_log: Path) -> None:
    result = runner.invoke(app, ["formats", "check", COMBINED, "--log", str(piped_log)])

    assert result.exit_code != 0
    assert "0 of 2" in result.stdout or "0 of 2" in result.output


def test_check_on_a_directive_that_will_not_compile_fails_cleanly(piped_log: Path) -> None:
    result = runner.invoke(app, ["formats", "check", "no percent", "--log", str(piped_log)])

    assert result.exit_code != 0
    assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# The point of all of it: ingesting with a format the user wrote
# ---------------------------------------------------------------------------


def test_a_log_can_be_ingested_with_a_saved_format(tmp_path: Path, piped_log: Path) -> None:
    """End to end, through the command line only. Before this, a log in a
    custom format could not be read by any means the tool offered."""
    runner.invoke(app, ["formats", "add", "log-kantor", PIPED])

    result = runner.invoke(
        app, ["ingest", str(piped_log), "--case", str(tmp_path / "case"), "--format", "log-kantor"]
    )

    assert result.exit_code == 0, result.stdout
    manifest = json.loads((tmp_path / "case" / "case.json").read_text(encoding="utf-8"))
    assert manifest["sources"][0]["events_parsed"] == 2
    assert manifest["sources"][0]["format_spec"]["directive"] == PIPED


def test_a_damaged_library_warns_without_stopping_an_unrelated_command(tmp_path: Path) -> None:
    """A corrupt formats.json must not make the rest of the tool unusable. It
    is the user's own editable file; breaking it should cost them their saved
    formats for the moment, not the ability to read an ordinary log."""
    library_path().parent.mkdir(parents=True, exist_ok=True)
    library_path().write_text("{not json", encoding="utf-8")
    log = tmp_path / "access.log"
    plain = '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 26 "-" "curl/8"'
    log.write_text(plain + "\n", encoding="utf-8")

    result = runner.invoke(app, ["ingest", str(log), "--case", str(tmp_path / "case")])

    assert result.exit_code == 0, result.output
    assert str(library_path()) in result.output
    assert "warning" in result.output.lower()


# ---------------------------------------------------------------------------
# JSON logs
# ---------------------------------------------------------------------------

GATEWAY_LINES = [
    json.dumps(
        {
            "time": "2024-05-01T09:00:45+00:00",
            "remote_addr": "203.0.113.77",
            "request": "GET /admin/0.php HTTP/1.1",
            "status": 404,
            "body_bytes_sent": 0,
            "http_user_agent": "curl/8.4.0",
        }
    ),
    json.dumps(
        {
            "time": "2024-05-01T09:00:46+00:00",
            "remote_addr": "203.0.113.77",
            "request": "GET /admin/1.php HTTP/1.1",
            "status": 404,
            "body_bytes_sent": 0,
            "http_user_agent": "curl/8.4.0",
        }
    ),
]


@pytest.fixture
def json_log(tmp_path: Path) -> Path:
    log = tmp_path / "gateway.jsonl"
    log.write_text("\n".join(GATEWAY_LINES) + "\n", encoding="utf-8")
    return log


def test_a_json_log_s_keys_are_guessed_and_shown(json_log: Path) -> None:
    """JSON keys are self-describing, so the mapping is worth proposing — and
    showing it is what keeps the proposal honest."""
    result = runner.invoke(app, ["formats", "check-json", "--log", str(json_log)])

    assert result.exit_code == 0, result.output
    assert "remote_addr" in result.stdout
    assert "203.0.113.77" in result.stdout
    assert "2 of 2" in result.stdout


def test_a_guessed_mapping_can_be_saved_in_one_step(json_log: Path) -> None:
    result = runner.invoke(app, ["formats", "add-json", "gateway", "--log", str(json_log)])

    assert result.exit_code == 0, result.output
    saved = load_library()[0]
    assert dict(saved.fields)["client_ip"] == "remote_addr"
    assert dict(saved.fields)["timestamp"] == "time"


def test_a_mapping_can_be_written_out_instead_of_guessed() -> None:
    result = runner.invoke(
        app,
        [
            "formats",
            "add-json",
            "gateway",
            "--map",
            "timestamp=ts",
            "--map",
            "client_ip=src",
            "--map",
            "status=code",
        ],
    )

    assert result.exit_code == 0, result.output
    assert dict(load_library()[0].fields) == {
        "timestamp": "ts",
        "client_ip": "src",
        "status": "code",
    }


def test_a_written_mapping_overrides_what_was_guessed(json_log: Path) -> None:
    """The guess is a starting point. A reader correcting one field must not
    have to write out the other seven."""
    result = runner.invoke(
        app,
        [
            "formats",
            "add-json",
            "gateway",
            "--log",
            str(json_log),
            "--map",
            "client_ip=http_x_real_ip",
        ],
    )

    assert result.exit_code == 0, result.output
    saved = dict(load_library()[0].fields)
    assert saved["client_ip"] == "http_x_real_ip"
    assert saved["timestamp"] == "time", "the rest of the guess was thrown away"


def test_a_mapping_missing_its_timestamp_is_refused_with_the_guess_shown() -> None:
    """Refused here rather than at ingest, where it would quarantine every line
    and present as an empty case."""
    result = runner.invoke(app, ["formats", "add-json", "half", "--map", "client_ip=src"])

    assert result.exit_code != 0
    assert "timestamp" in result.output
    assert "Traceback" not in result.output
    assert load_library() == []


def test_a_map_that_is_not_a_pair_fails_cleanly() -> None:
    result = runner.invoke(app, ["formats", "add-json", "bad", "--map", "just-a-word"])

    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_a_log_holding_no_json_at_all_says_so(tmp_path: Path, piped_log: Path) -> None:
    result = runner.invoke(app, ["formats", "check-json", "--log", str(piped_log)])

    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_a_json_log_can_be_ingested_end_to_end(tmp_path: Path, json_log: Path) -> None:
    runner.invoke(app, ["formats", "add-json", "gateway", "--log", str(json_log)])

    result = runner.invoke(
        app, ["ingest", str(json_log), "--case", str(tmp_path / "case"), "--format", "gateway"]
    )

    assert result.exit_code == 0, result.output
    manifest = json.loads((tmp_path / "case" / "case.json").read_text(encoding="utf-8"))
    assert manifest["sources"][0]["events_parsed"] == 2
    assert manifest["sources"][0]["format_spec"]["kind"] == "json"


def test_a_json_format_is_listed_beside_the_others(json_log: Path) -> None:
    runner.invoke(app, ["formats", "add-json", "gateway", "--log", str(json_log)])

    result = runner.invoke(app, ["formats"])

    assert result.exit_code == 0
    assert "gateway" in result.stdout
    assert "remote_addr" in result.stdout, "the mapping is the definition; show it"


def test_show_describes_a_json_format_by_its_mapping(json_log: Path) -> None:
    runner.invoke(app, ["formats", "add-json", "gateway", "--log", str(json_log)])

    result = runner.invoke(app, ["formats", "show", "gateway"])

    assert result.exit_code == 0
    assert "json" in result.stdout
    assert "remote_addr" in result.stdout
