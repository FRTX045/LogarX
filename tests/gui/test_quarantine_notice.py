"""What the window says about lines that never became events.

No display needed: the judgement is words, plus a decision about how loudly to
say them, and both are plain data. That is why it is not in the widget.
"""

from __future__ import annotations

from logarx.gui.quarantine_notice import notice_for
from logarx.storage.case import SourceRecord


def source(
    name: str,
    *,
    read: int,
    quarantined: int,
    parsed: int | None = None,
    log_format: str = "apache-combined",
) -> SourceRecord:
    """One ingested file's counts.

    `parsed` defaults to whatever was not quarantined, which is the ordinary
    case. It is settable because it is *not* always that: `ingest_file` counts
    blank lines as read while parsing and quarantining neither, so a file of
    whitespace has `lines_read` above zero and both other counts at zero. That
    file is the one the dead-file rule must not mistake for a parser failure.
    """
    return SourceRecord(
        file_id=name,
        original_path=f"/logs/{name}",
        sha256="0" * 64,
        size_bytes=read * 200,
        compression="none",
        log_format=log_format,
        lines_read=read,
        events_parsed=read - quarantined if parsed is None else parsed,
        lines_quarantined=quarantined,
    )


def test_a_clean_case_says_nothing() -> None:
    """Silence is the signal. `Quarantine` writes no file when there is nothing
    to put in it, precisely so no empty artefact reads as a problem; the window
    follows the same rule."""
    assert notice_for([source("access.log", read=51_268, quarantined=0)]) is None


def test_a_case_with_no_sources_says_nothing() -> None:
    assert notice_for([]) is None


def test_a_damaged_case_names_the_count_and_its_denominator() -> None:
    notice = notice_for([source("access.log", read=51_268, quarantined=3_412)])

    assert notice is not None
    assert "3,412" in notice.headline
    # The denominator is named, not implied: 3,412 of 51,268 is 6.7%, and a
    # reader who divides has to reach the number the sentence claims.
    assert "51,268" in notice.detail
    assert "6.7%" in notice.detail


def test_one_bad_line_is_singular() -> None:
    notice = notice_for([source("access.log", read=900, quarantined=1)])

    assert notice is not None
    assert "1 line could not be parsed" in notice.headline


def test_a_share_too_small_to_round_is_not_reported_as_zero() -> None:
    """3 lines in 5 million is 0.00006%, which `f"{x:.1f}%"` renders as "0.0%" —
    a figure saying nothing failed, in the same sentence as a headline saying
    three did. A reader believes the number over the noun."""
    notice = notice_for([source("access.log", read=5_000_000, quarantined=3)])

    assert notice is not None
    assert "0.0%" not in notice.detail
    assert "under 0.1%" in notice.detail


def test_damage_spread_over_several_files_is_totalled() -> None:
    notice = notice_for(
        [
            source("monday.log", read=1_000, quarantined=40),
            source("tuesday.log", read=1_000, quarantined=2),
        ]
    )

    assert notice is not None
    assert "42" in notice.headline
    assert "2,000" in notice.detail
    assert not notice.is_blocking, "both files still produced events"


def test_a_file_that_produced_nothing_is_escalated() -> None:
    """The case this exists for. Four good logs and one syslog: the case is 80%
    fine, so a case-level test stays quiet while a whole file contributes
    nothing — a result that looks complete and is not."""
    notice = notice_for(
        [
            source("access.log", read=40_000, quarantined=0),
            source("system.log", read=11_268, quarantined=11_268),
        ]
    )

    assert notice is not None
    assert notice.is_blocking
    assert notice.dead_files == ("system.log",)
    # The diagnosis is the format, not the count: it is what tells the reader
    # the parser was wrong rather than the log being empty.
    assert "apache-combined" in notice.detail
    assert "11,268" in notice.detail
    # The way out is named where the reader is: the window, not a command
    # line the packaged application does not have (ADR-0012).
    assert "Case → New from logs…" in notice.detail
    assert "LogarX formats" not in notice.detail


def test_every_file_failing_is_the_same_rule() -> None:
    """No separate case-level branch. One file dead or all of them dead is the
    same condition counted per file."""
    notice = notice_for(
        [
            source("a.log", read=500, quarantined=500),
            source("b.log", read=700, quarantined=700),
        ]
    )

    assert notice is not None
    assert notice.is_blocking
    assert notice.dead_files == ("a.log", "b.log")


def test_a_file_of_only_blank_lines_is_not_called_dead() -> None:
    """`lines_read` counts blanks, which are neither parsed nor quarantined, so
    a file of whitespace has `events_parsed == 0` while having refused nothing.

    Tested alongside a genuinely damaged file, because that is the only way to
    reach the dead-file rule at all — on its own the blank file quarantines
    nothing and the notice is silent for a different reason, which would let
    this pass without the rule being exercised.

    Judging deadness on `events_parsed == 0` alone would name padding.log here
    and send the reader to fix a format that is not broken.
    """
    notice = notice_for(
        [
            source("access.log", read=1_000, quarantined=8),
            source("padding.log", read=200, quarantined=0, parsed=0),
        ]
    )

    assert notice is not None
    assert not notice.is_blocking
    assert notice.dead_files == ()
    assert "8 lines could not be parsed" in notice.headline


def test_the_dead_file_wording_agrees_with_how_many_there_are() -> None:
    """One file is "it", several are "them". Caught by reading the sentence the
    real window produced, not by any test that existed at the time."""
    one = notice_for(
        [
            source("access.log", read=900, quarantined=0),
            source("system.log", read=640, quarantined=640),
        ]
    )
    assert one is not None
    assert "Nothing from it is in this case." in one.detail
    assert "Nothing from them" not in one.detail

    several = notice_for(
        [
            source("a.log", read=500, quarantined=500),
            source("b.log", read=700, quarantined=700),
        ]
    )
    assert several is not None
    assert "Nothing from them is in this case." in several.detail
    assert "2 logs produced no events at all" in several.detail
