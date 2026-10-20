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


# -- things measured or drawn from text --------------------------------------


def test_evidence_heading_redraws_at_the_new_size(themed: QApplication) -> None:
    from test_narrow_columns import lines, node

    from logarc.gui.evidence_panel import EvidencePanel

    panel = EvidencePanel()
    try:
        panel.show_evidence(node(5), lines())
        set_text_points(themed, 14)
        panel.follow_text_size()
        title = panel._heading.font().pointSizeF() + 3
        assert f"font-size:{title:.1f}pt" in panel._heading.text()
    finally:
        panel.close()


def test_following_the_text_size_with_nothing_shown_draws_nothing(themed: QApplication) -> None:
    from logarc.gui.evidence_panel import EvidencePanel

    panel = EvidencePanel()
    try:
        panel.follow_text_size()
        assert panel.shown_node() is None
    finally:
        panel.close()


def test_the_no_results_title_follows_the_zoom(themed: QApplication) -> None:
    from logarc.gui.evidence_panel import EvidencePanel

    panel = EvidencePanel()
    try:
        title = next(
            label for label in panel.findChildren(QLabel) if label.text() == "No results found"
        )
        _polished(panel, *panel.findChildren(QWidget))
        assert title.font().pointSizeF() == 14
        set_text_points(themed, 13)
        assert title.font().pointSizeF() == 16
    finally:
        panel.close()


def test_timeline_caption_follows_the_app_font(themed: QApplication) -> None:
    from logarc.gui.timeline import caption_font as timeline_caption

    assert timeline_caption().pointSizeF() == 11
    set_text_points(themed, 15)
    assert timeline_caption().pointSizeF() == 15


def test_date_fields_widen_with_the_text(themed: QApplication) -> None:
    from PyQt6.QtGui import QFontMetrics

    from logarc.gui.time_filter import _ARROW, TimeFilterBar

    bar = TimeFilterBar()
    try:
        _polished(bar, *bar.findChildren(QWidget))
        narrow = bar._from.minimumWidth()
        set_text_points(themed, 15)
        wide = QFontMetrics(bar._from.font()).horizontalAdvance("2024-05-02  00:00") + _ARROW
        assert bar._from.minimumWidth() == wide > narrow
        assert bar._to.minimumWidth() == wide
    finally:
        bar.close()


def test_client_header_keeps_room_for_its_sort_arrow(themed: QApplication) -> None:
    from logarc.gui.panels import ClientTable

    panel = ClientTable()
    try:
        header = required_header(panel._table)
        _polished(panel, *panel.findChildren(QWidget))
        set_text_points(themed, 15)
        assert header.minimumHeight() == header.fontMetrics().height() + 14
    finally:
        panel.close()


def test_bookmark_category_keeps_room_for_eight_characters(themed: QApplication) -> None:
    from logarc.gui.bookmarks_tab import BookmarksTab

    tab = BookmarksTab()
    try:
        _polished(tab, *tab.findChildren(QWidget))
        set_text_points(themed, 15)
        assert tab.category.minimumWidth() == tab.category.fontMetrics().averageCharWidth() * 8
    finally:
        tab.close()


def test_client_rows_shown_after_a_zoom_match_their_table(themed: QApplication) -> None:
    from datetime import UTC, datetime

    from logarc.gui.panels import ClientTable
    from logarc.storage.base import IpSummary

    panel = ClientTable()
    try:
        set_text_points(themed, 14)
        now = datetime(2026, 10, 20, tzinfo=UTC)
        panel.show_clients([IpSummary("192.0.2.123", 5, now, now, 3, 0.2, 1000)])
        address = panel._table.item(0, 0)
        assert address is not None
        assert address.font().pointSizeF() == panel._table.font().pointSizeF() == 14
    finally:
        panel.close()


def test_unset_columns_refit_after_a_zoom_and_dragged_ones_stay(themed: QApplication) -> None:
    from logarc.gui.columns import ColumnWidths

    table = QTableWidget(1, 3)
    for column in range(3):
        table.setItem(0, column, QTableWidgetItem("a fairly long value"))
    ColumnWidths(table)
    header = required_header(table)
    _polished(table, header)
    header.resizeSection(1, 77)
    fitted = table.columnWidth(0)
    try:
        set_text_points(themed, 16)
        assert table.columnWidth(0) > fitted
        assert table.columnWidth(1) == 77
    finally:
        table.close()
