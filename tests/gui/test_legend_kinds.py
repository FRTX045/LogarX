"""The legend names the kinds of activity on the graph, each with its icon."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QLabel

from zodiarc.core.activity import ActivityCategory
from zodiarc.gui.icon_set import IconChoice
from zodiarc.gui.icons import first_drawable
from zodiarc.gui.panels import LegendBar
from zodiarc.style import THEME

INJECTION, BROWSING = ActivityCategory.INJECTION, ActivityCategory.BROWSING


def test_the_legend_lists_exactly_the_kinds_on_the_graph(qt_app: QApplication) -> None:
    legend = LegendBar()
    legend.show_kinds([INJECTION, BROWSING, INJECTION], IconChoice())
    assert legend.kinds() == ("Browsing", "Injection"), "each once, in the kinds' own order"


def test_a_new_graph_replaces_the_kinds(qt_app: QApplication) -> None:
    legend = LegendBar()
    legend.show_kinds([INJECTION], IconChoice())
    legend.show_kinds([ActivityCategory.SSRF], IconChoice())
    assert legend.kinds() == ("SSRF",)


def test_no_graph_no_kinds(qt_app: QApplication) -> None:
    legend = LegendBar()
    legend.show_kinds([INJECTION], IconChoice())
    legend.show_kinds([], IconChoice())
    assert legend.kinds() == ()
    words = [label.text() for label in legend.findChildren(QLabel)]
    assert "Kind" not in words, "no heading over nothing"


def test_the_heading_comes_with_the_kinds(qt_app: QApplication) -> None:
    legend = LegendBar()
    legend.show_kinds([INJECTION], IconChoice())
    assert "Kind" in [label.text() for label in legend.findChildren(QLabel)]


def test_the_legend_shows_the_readers_kind_icon(qt_app: QApplication) -> None:
    legend = LegendBar()
    legend.show_kinds([INJECTION], IconChoice(kinds={INJECTION: "bug"}))
    (drawn,) = legend.kind_icons()
    size = drawn.width()
    assert drawn.toImage() == first_drawable(["bug"], THEME.ink, size).toImage()


def test_fourteen_kinds_do_not_widen_the_legend(qt_app: QApplication) -> None:
    """The legend once demanded more width than the window it sat in, and froze
    the splitter. Each kind is one entry that wraps whole, so fourteen of them
    ask for no more than the widest one."""
    legend = LegendBar()
    legend.show_kinds(list(ActivityCategory), IconChoice())
    assert legend.minimumSizeHint().width() < 320
