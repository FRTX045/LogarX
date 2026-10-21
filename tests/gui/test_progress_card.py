"""The two cards a long job puts over the window, in the window's own type.

Until 2026-10-21 the reading card was set entirely in monospace and lower case
(`source`, `parsed`, `READING`), which made it the one screen in the
application that looked like a terminal. The labels and sentences now take the
interface face; the figures stay monospace, because digits of one width are
what let a column of them be read without reading it.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication

from logarc.gui.crs import CrsCard
from logarc.gui.progress import Progress
from logarc.gui.progress_card import IngestCard
from logarc.gui.theme import MONO_FAMILIES, ui_font


def _reading() -> Progress:
    return Progress(
        file_name="access.log",
        file_index=1,
        file_count=1,
        lines=1_482_119,
        bytes_done=1_432_000_000,
        bytes_total=2_310_000_000,
        seconds=30.0,
    )


def _monospace(font: QFont) -> bool:
    return bool(set(font.families()) & set(MONO_FAMILIES))


def test_the_card_names_its_rows_in_words(qt_app: QApplication) -> None:
    card = IngestCard(None, on_cancel=lambda: None)
    card.update_progress(_reading())

    said = card.text()
    assert said.startswith("Reading logs")
    for name in ("File access.log", "Read ", "Lines 1,482,119", "Speed ", "Time left "):
        assert name in said
    assert "READING" not in said
    assert "parsed" not in said
    card.close()


def test_words_are_in_the_interface_face_and_figures_in_monospace(qt_app: QApplication) -> None:
    card = IngestCard(None, on_cancel=lambda: None)
    card.update_progress(_reading())

    assert not _monospace(card._state.font())
    assert not _monospace(card._consequence.font())
    assert not _monospace(card._cancel.font())
    for key, name in card._names.items():
        assert not _monospace(name.font()), key
        assert _monospace(card._values[key].font()), key
    assert _monospace(card._percent.font())
    card.close()


def test_the_cost_of_cancelling_is_a_sentence(qt_app: QApplication) -> None:
    card = IngestCard(None, on_cancel=lambda: None)

    assert card._consequence.text() == "Cancelling leaves the case unfinished."
    assert card._consequence.isVisibleTo(card)
    card.close()


def test_stopping_is_said_in_sentence_case(qt_app: QApplication) -> None:
    card = IngestCard(None, on_cancel=lambda: None)

    card._cancel.click()

    assert card._state.text() == "Stopping…"
    assert not card._cancel.isEnabled()
    card.close()


def test_cancel_is_drawn_like_every_other_button(qt_app: QApplication) -> None:
    """The application stylesheet draws buttons; a sheet of its own made this
    one the only square, grey-on-black button in the window."""
    card = IngestCard(None, on_cancel=lambda: None)

    assert card._cancel.styleSheet() == ""
    card.close()


def test_the_cards_follow_the_chosen_text_size(qt_app: QApplication) -> None:
    original = qt_app.font()
    large = ui_font(original)
    large.setPointSizeF(14)
    qt_app.setFont(large)
    try:
        reading = IngestCard(None, on_cancel=lambda: None)
        crs = CrsCard(None, on_stop=lambda: None)

        assert reading._state.font().pointSizeF() >= 14
        assert all(name.font().pointSizeF() >= 13 for name in reading._names.values())
        assert reading._consequence.font().pointSizeF() >= 12
        # `mono_font(9.0)` reads like a fixed size and is not one: it never
        # goes below the interface size less a point.
        assert crs._counts.font().pointSizeF() >= 13
        reading.close()
        crs.close()
    finally:
        qt_app.setFont(original)
