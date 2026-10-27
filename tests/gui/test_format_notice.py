"""What the window says when a case's format has been edited since.

Free of Qt, like the quarantine wording beside it, because this is the sentence
that can mislead rather than the drawing of it. The specific risk here: saying
anything that sounds like the case is wrong. It is not — it reads exactly as it
was ingested, and the wording has to make that the first thing the reader sees.
"""

from __future__ import annotations

from logarx.formats import FormatDrift
from logarx.gui.format_notice import drift_notice
from logarx.parsers.apache import COMBINED, COMMON
from logarx.parsers.spec import LogFormatSpec

JANUARY = LogFormatSpec(name="log-kantor", directive=COMMON)
JUNE = LogFormatSpec(name="log-kantor", directive=COMBINED)

DRIFT = FormatDrift(file_id="access.log", name="log-kantor", stored=JANUARY, current=JUNE)


def test_nothing_to_report_says_nothing() -> None:
    """A strip permanently reporting that no format changed is an artefact, in
    the hardest place on screen to ignore."""
    assert drift_notice([]) is None


def test_the_headline_names_the_format_that_changed() -> None:
    notice = drift_notice([DRIFT])

    assert notice is not None
    assert "log-kantor" in notice.headline


def test_the_detail_says_the_case_is_unaffected_before_anything_else() -> None:
    """The reader's first thought on seeing a warning about their case is that
    their case is broken. This one is not, and the sentence has to say so
    before it says anything else."""
    notice = drift_notice([DRIFT])

    assert notice is not None
    first_sentence = notice.detail.split(".")[0]
    assert "still reads" in first_sentence


def test_the_detail_shows_both_definitions() -> None:
    """Which is the whole use of the notice. Told only that something changed,
    the reader has to go and diff two things by hand."""
    notice = drift_notice([DRIFT])

    assert notice is not None
    assert COMMON in notice.detail
    assert COMBINED in notice.detail


def test_a_drift_notice_never_interrupts() -> None:
    """The case is intact, so there is nothing to stop the reader for. Only a
    log that produced no events earns a dialog."""
    notice = drift_notice([DRIFT])

    assert notice is not None
    assert not notice.is_blocking


def test_several_drifted_files_are_counted_rather_than_listed_one_by_one() -> None:
    others = [
        FormatDrift(file_id=f"access.log.{n}", name="log-kantor", stored=JANUARY, current=JUNE)
        for n in range(4)
    ]

    notice = drift_notice([DRIFT, *others])

    assert notice is not None
    assert "5" in notice.headline


def test_two_different_formats_are_both_named() -> None:
    gateway_before = LogFormatSpec(name="gateway", directive=COMMON)
    gateway_after = LogFormatSpec(name="gateway", directive=COMBINED)
    second = FormatDrift(
        file_id="gateway.log", name="gateway", stored=gateway_before, current=gateway_after
    )

    notice = drift_notice([DRIFT, second])

    assert notice is not None
    assert "log-kantor" in notice.detail
    assert "gateway" in notice.detail
