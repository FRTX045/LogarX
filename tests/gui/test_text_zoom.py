"""Zooming the interface text while the window is open."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QListWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)

from logarc.gui import theme
from logarc.gui.app import MainWindow
from logarc.gui.theme import caption_font, mono_font, set_text_points, ui_font


@pytest.fixture
def themed(qt_app: QApplication) -> Iterator[QApplication]:
    """The shared application with the theme's stylesheet and an 11 pt font.

    The stylesheet is what stops Qt passing an application font change on to
    widgets that already exist, so these tests need it in force. Put back
    afterwards so the rest of the suite runs on the plain application.
    """
    font, sheet = qt_app.font(), qt_app.styleSheet()
    qt_app.setStyleSheet(theme._CONTROLS)
    chosen = ui_font(font)
    chosen.setPointSizeF(11)
    qt_app.setFont(chosen)
    yield qt_app
    qt_app.setStyleSheet(sheet)
    qt_app.setFont(font)


def _polished(*widgets: QWidget) -> None:
    for widget in widgets:
        widget.ensurePolished()


def _sample() -> tuple[QWidget, QTableWidget, QLabel, QLabel, QTableWidgetItem]:
    """A window holding a table, a plain label and a caption, all drawn once."""
    holder = QWidget()
    layout = QVBoxLayout(holder)
    table = QTableWidget(1, 1)
    item = QTableWidgetItem("192.0.2.1")
    item.setFont(mono_font(table.font().pointSizeF()))
    table.setItem(0, 0, item)
    plain = QLabel("plain")
    caption = QLabel("caption")
    caption.setFont(caption_font(caption.font()))
    for widget in (table, plain, caption):
        layout.addWidget(widget)
    _polished(holder, table, plain, caption, table.horizontalHeader())
    return holder, table, plain, caption, item


def _sizes(root: QWidget) -> dict[int, float]:
    """Every widget and item font under `root`, keyed by the object."""
    sizes = {}
    for widget in [root, *root.findChildren(QWidget)]:
        sizes[id(widget)] = widget.font().pointSizeF()
        if isinstance(widget, QTableWidget):
            for row in range(widget.rowCount()):
                for column in range(widget.columnCount()):
                    item = widget.item(row, column)
                    if item is not None and item.data(Qt.ItemDataRole.FontRole) is not None:
                        sizes[id(item)] = item.font().pointSizeF()
    return sizes


def test_plain_widgets_and_tables_follow_a_live_change(themed: QApplication) -> None:
    holder, table, plain, _caption, _item = _sample()
    try:
        assert set_text_points(themed, 14) == 14
        assert table.font().pointSizeF() == 14
        assert required_header(table).font().pointSizeF() == 14
        assert plain.font().pointSizeF() == 14
    finally:
        holder.close()


def test_explicit_fonts_shift_by_the_same_step(themed: QApplication) -> None:
    holder, _table, _plain, caption, item = _sample()
    before = caption.font().pointSizeF(), item.font().pointSizeF()
    try:
        set_text_points(themed, 14)
        assert (caption.font().pointSizeF(), item.font().pointSizeF()) == (
            before[0] + 3,
            before[1] + 3,
        )
        set_text_points(themed, 9)
        assert (caption.font().pointSizeF(), item.font().pointSizeF()) == (
            before[0] - 2,
            before[1] - 2,
        )
    finally:
        holder.close()


def test_zooming_down_and_back_restores_every_font(themed: QApplication) -> None:
    window = MainWindow()
    try:
        _polished(window, *window.findChildren(QWidget))
        widgets = window.findChildren(QWidget)  # held, so no id is reused
        before = _sizes(window)
        set_text_points(themed, 8)
        smaller = _sizes(window)
        assert smaller[id(window)] == before[id(window)] - 3
        set_text_points(themed, 11)
        after = _sizes(window)
        assert {key: after[key] for key in before} == before
        assert widgets
    finally:
        window.close()


def test_the_size_in_force_is_clamped_and_unchanged_sizes_do_nothing(
    themed: QApplication,
) -> None:
    holder, _table, _plain, caption, _item = _sample()
    try:
        assert set_text_points(themed, 40) == 16
        assert caption.font().pointSizeF() == 15
        assert set_text_points(themed, 16) == 16
        assert caption.font().pointSizeF() == 15
    finally:
        holder.close()


def test_injected_system_item_view_font_does_not_survive_a_zoom(themed: QApplication) -> None:
    QApplication.setFont(QFont("Segoe UI", 9), "QAbstractItemView")
    set_text_points(themed, 12)
    for view in (QTableWidget(), QTreeWidget(), QListWidget()):
        view.ensurePolished()
        assert view.font().pointSizeF() == 12, type(view).__name__


def test_a_second_top_level_window_follows(themed: QApplication) -> None:
    first, *_ = _sample()
    second = QWidget()
    label = QLabel("elsewhere", second)
    label.setFont(caption_font(label.font()))
    _polished(second, label)
    try:
        set_text_points(themed, 13)
        assert label.font().pointSizeF() == 12
    finally:
        first.close()
        second.close()


def required_header(table: QTableWidget) -> QWidget:
    header = table.horizontalHeader()
    assert header is not None
    return header
