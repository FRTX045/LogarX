"""Writing a reconstruction out as a file, whoever asked for it.

The window and the command line both did this by hand, and had two copies of
the same two-branch decision. What is checked here is the thing neither copy
could check on its own: that the extension a format is named for is the
extension of what it actually writes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logarx.analysis import analyse_ip
from logarx.case import Case
from logarx.report.export import FORMATS, named, write_reconstruction, write_text
from logarx.report.html import render_report

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
ATTACKER = "203.0.113.66"
AGENT = "Mozilla/5.0 (X11; Linux x86_64)"


def line(seconds: int, target: str, *, status: int = 200) -> str:
    when = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ATTACKER} - - [{when}] "GET {target} HTTP/1.1" {status} 512 "-" "{AGENT}"'


@pytest.fixture
def campaign(tmp_path: Path) -> Case:
    lines = [line(0, "/"), line(20, "/products")]
    at = 60
    for index in range(25):
        lines.append(line(at, f"/admin/{index}", status=404))
        at += 1
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return Case.open(tmp_path / "case")


# -- the formats on offer -------------------------------------------------


def test_every_format_is_named_for_the_extension_it_writes(campaign: Case, tmp_path: Path) -> None:
    """The property neither copy of this could check on its own.

    A dialog that suggests `graph.json` and a writer that puts HTML in it hands
    the reader a file that lies about itself, and nothing downstream would catch
    it: both halves would look right where they were written.
    """
    result = analyse_ip(campaign.store, ATTACKER)
    # What the content has to look like for the extension to be honest. Asserting
    # `written.suffix == fmt.suffix` would be circular: the target is built from
    # that suffix, so it cannot come back any other way.
    looks_like = {
        ".json": lambda text: json.loads(text)["client_ip"] == ATTACKER,
        ".html": lambda text: text.lstrip().lower().startswith("<!doctype html"),
    }

    for fmt in FORMATS:
        assert fmt.suffix in looks_like, f"nothing knows what a {fmt.suffix} should contain"
        target = tmp_path / f"out{fmt.suffix}"

        written = write_reconstruction(result, campaign.manifest, kind=fmt.kind, target=target)
        text = written.read_text(encoding="utf-8")

        assert text, f"{fmt.kind} wrote an empty file"
        assert looks_like[fmt.suffix](text), (
            f"{fmt.kind} is named {fmt.suffix} and did not write one"
        )


def test_a_format_nobody_offers_is_refused_by_name(campaign: Case) -> None:
    """And the message names what is on offer.

    "unknown format" alone leaves the reader to guess, and the guess they make
    is usually the extension rather than the name.
    """
    with pytest.raises(ValueError, match="html") as raised:
        named("pdf")

    assert "pdf" in str(raised.value), "it does not say what was asked for"
    assert "json" in str(raised.value), "nor all of what it could have been"


def test_the_formats_are_offered_in_a_settled_order() -> None:
    """A dialog reads top to bottom and is remembered by position."""
    assert [fmt.kind for fmt in FORMATS] == ["html", "json"]


# -- what each one writes -------------------------------------------------


def test_json_is_the_reconstruction_as_the_result_reports_it(
    campaign: Case, tmp_path: Path
) -> None:
    result = analyse_ip(campaign.store, ATTACKER)
    target = tmp_path / "graph.json"

    write_reconstruction(result, campaign.manifest, kind="json", target=target)

    assert json.loads(target.read_text(encoding="utf-8")) == json.loads(
        json.dumps(result.to_dict())
    )


def test_html_is_what_the_renderer_makes_of_it(campaign: Case, tmp_path: Path) -> None:
    """The same renderer, not a second path to the same artefact."""
    result = analyse_ip(campaign.store, ATTACKER)
    target = tmp_path / "report.html"

    write_reconstruction(result, campaign.manifest, kind="html", target=target)

    assert target.read_text(encoding="utf-8") == render_report(result, campaign.manifest)


def test_the_path_written_is_the_path_handed_back(campaign: Case, tmp_path: Path) -> None:
    """Both callers say where the file went, and neither should have to work it
    out again from what it passed in."""
    result = analyse_ip(campaign.store, ATTACKER)
    target = tmp_path / "somewhere" / "report.html"
    target.parent.mkdir()

    assert write_reconstruction(result, campaign.manifest, kind="html", target=target) == target


# -- writing the file ------------------------------------------------------------


def test_a_byte_that_was_not_utf_8_is_written_as_the_byte_it_was(tmp_path: Path) -> None:
    """A log line is read keeping any byte that is not UTF-8, as a lone
    surrogate, and UTF-8 cannot write one: the export failed. It is written as
    the byte, spelled as Apache spells one it cannot print."""
    target = tmp_path / "out.txt"

    write_text(target, "GET /search?q=\udcff")

    assert target.read_text(encoding="utf-8") == "GET /search?q=\\xff"


def test_a_failed_write_leaves_the_file_that_was_there(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    target.write_text("the report from before", encoding="utf-8")

    with pytest.raises(UnicodeEncodeError):
        write_text(target, "caf\u00e9", encoding="ascii")

    assert target.read_text(encoding="utf-8") == "the report from before"
    assert [path.name for path in tmp_path.iterdir()] == ["out.txt"]


def test_a_bookmarked_line_with_a_byte_that_was_not_utf_8_is_reported(
    campaign: Case, tmp_path: Path
) -> None:
    from logarx.bookmarks import DEFAULT, EMPTY, Bookmark, Kind, add
    from logarx.core.evidence import EvidenceRef
    from logarx.evidence import EvidenceLine

    result = analyse_ip(campaign.store, ATTACKER)
    ref = EvidenceRef("access.log", 1)
    mark = Bookmark(
        id="r-1",
        kind=Kind.REQUEST,
        category=DEFAULT,
        said="GET /search",
        note="",
        saved=START,
        client=ATTACKER,
        line=ref,
    )
    raw = EvidenceLine(
        ref=ref, source_path="access.log", text="GET /search?q=\udcff", verified=True
    )
    target = tmp_path / "report.html"

    write_reconstruction(
        result,
        campaign.manifest,
        kind="html",
        target=target,
        shelf=add(EMPTY, mark),
        lines={ref: raw},
    )

    assert "GET /search?q=\\xff" in target.read_text(encoding="utf-8")
