"""The wrapping row: the graph key's, and the Bookmarks tab's buttons.

Measured on fixed-size items, so the numbers are the layout's and not a font's.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QRect
from PyQt6.QtWidgets import QApplication, QWidget

from logarc.gui.flow import FlowLayout

GAP = 8


def row(
    *widths: int, right: bool = False, one_row: bool = False
) -> tuple[QWidget, FlowLayout, list[QWidget]]:
    host = QWidget()
    layout = FlowLayout(host, spacing=GAP, right=right, one_row=one_row)
    layout.setContentsMargins(0, 0, 0, 0)
    items = []
    for width in widths:
        item = QWidget()
        item.setFixedSize(width, 20)
        layout.addWidget(item)
        items.append(item)
    return host, layout, items


def test_by_default_it_asks_for_its_widest_item_and_starts_rows_at_the_left(
    qt_app: QApplication,
) -> None:
    """The graph key's behaviour, which it was written for."""
    _host, layout, items = row(60, 80, 70)
    assert layout.sizeHint().width() == layout.minimumSize().width() == 80
    layout.setGeometry(QRect(0, 0, 400, 20))
    assert [item.x() for item in items] == [0, 68, 156]


def test_asked_for_one_row_it_prefers_one_row_and_needs_only_its_widest(
    qt_app: QApplication,
) -> None:
    _host, layout, _items = row(60, 80, 70, one_row=True)
    assert layout.sizeHint().width() == 60 + 80 + 70 + 2 * GAP
    assert layout.minimumSize().width() == 80


def test_given_exactly_the_width_it_asked_for_it_keeps_one_row(qt_app: QApplication) -> None:
    """Beside a stretching neighbour it is handed its hint to the pixel."""
    _host, layout, items = row(60, 80, 70, right=True, one_row=True)
    asked = layout.sizeHint().width()
    layout.setGeometry(QRect(0, 0, asked, 20))
    assert [item.y() for item in items] == [0, 0, 0]
    assert layout.heightForWidth(asked) == 20


def test_set_to_the_right_a_row_ends_at_the_right_edge(qt_app: QApplication) -> None:
    _host, layout, items = row(60, 60, 60, right=True)
    layout.setGeometry(QRect(0, 0, 400, 20))
    assert items[-1].geometry().right() == 399
    assert [item.y() for item in items] == [0, 0, 0]
    assert items[1].x() - items[0].geometry().right() == GAP + 1


def test_narrower_than_a_row_it_wraps_and_each_row_ends_at_the_right(qt_app: QApplication) -> None:
    _host, layout, items = row(60, 80, 70, right=True)
    layout.setGeometry(QRect(0, 0, 150, 100))
    assert items[0].y() == items[1].y() == 0
    assert items[2].y() == 20 + GAP
    assert items[1].geometry().right() == items[2].geometry().right() == 149
    assert layout.heightForWidth(150) == 20 + GAP + 20
