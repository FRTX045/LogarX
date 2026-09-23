"""Offering CRS when a scan finishes, and showing it running.

The offer is the only place this tool asks a question whose answer is a
trade-off rather than a preference, so what it does *not* say matters as much as
what it does. An earlier draft quoted two figures at the reader; both were
measured on corpora that have since been replaced, and one had a denominator of
five. The dialog now describes the shape of the trade and leaves the numbers to
the screen that reports the reader's own log.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from logarc.enrich import EnrichProgress
from logarc.gui.crs import CrsCard, CrsOffer, CrsUnavailable

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


def test_the_offer_quotes_no_figures_at_all(qt_app: QApplication) -> None:
    """The rule that survived two wrong numbers reaching a draft.

    A figure in a dialog gets no footnote and no reader who knows what it was
    measured on. This is a crude check — no run of digits that looks like a
    statistic — and crude is the point: it fails when somebody adds one back.
    """
    offer = CrsOffer()

    words = offer.spoken()

    assert "0.6" not in words
    assert "81" not in words
    assert "%" not in words


def test_the_offer_says_both_halves_of_the_trade(qt_app: QApplication) -> None:
    """Selling it as "more accurate" would be selling something measurement
    does not support: on this project's own corpus CRS finds more *and* reports
    far more ordinary traffic as attacks."""
    words = CrsOffer().spoken().lower()

    assert "catches" in words, "the gain is missing"
    assert "suspicious" in words or "ordinary" in words, "the cost is missing"


def test_what_a_dialog_says_keeps_each_widget_on_its_own_line(qt_app: QApplication) -> None:
    """The last label and the first checkbox used to be joined with nothing
    between them, so a sentence ran straight into "Remember this choice" and a
    phrase spanning the seam could match text no reader ever sees."""
    lines = CrsOffer().spoken().splitlines()

    assert "Remember this choice" in lines


def test_a_ticked_box_is_what_makes_the_answer_stick(qt_app: QApplication) -> None:
    offer = CrsOffer()

    assert offer.remembered() is False

    offer.tick_remember()

    assert offer.remembered() is True


def test_the_card_draws_the_proportion_it_is_given(qt_app: QApplication) -> None:
    """The loading bar, and the reason `EnrichProgress` carries a denominator.

    A bar that cannot say how far through it is may as well be a spinner, and a
    spinner is what the command line already had.
    """
    card = CrsCard(None, on_stop=lambda: None)

    card.update_progress(EnrichProgress(replayed=96_400, total=236_505))

    assert card.bar().maximum() == 236_505
    assert card.bar().value() == 96_400
    assert "96,400" in card.spoken()
    assert "236,505" in card.spoken()


def test_the_card_promises_that_stopping_keeps_what_was_found(qt_app: QApplication) -> None:
    """Said on the face rather than in a tooltip, because it is the whole reason
    the Stop button is safe to press. `enrich_case` ends the stream rather than
    raising, which is what makes the promise true."""
    assert "keeps" in CrsCard(None, on_stop=lambda: None).spoken().lower()


def test_stopping_asks_once_and_says_so(qt_app: QApplication) -> None:
    asked = 0

    def stop() -> None:
        nonlocal asked
        asked += 1

    card = CrsCard(None, on_stop=stop)
    card.press_stop()

    assert asked == 1
    assert "stopping" in card.spoken().lower()


def test_a_missing_sidecar_reads_as_complete_rather_than_broken(qt_app: QApplication) -> None:
    """The common case — the Go sidecar is optional and usually absent. A case
    without CRS is finished, not failed, and the wording has to say so before it
    says anything about installing."""
    words = CrsUnavailable("crs-sidecar not found").spoken().lower()

    assert "complete without it" in words
    assert "optional" in words
