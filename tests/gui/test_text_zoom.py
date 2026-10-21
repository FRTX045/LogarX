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


# -- the controls --------------------------------------------------------------


@pytest.fixture
def window(themed: QApplication) -> Iterator[MainWindow]:
    from logarc.gui import app, prefs

    shown = MainWindow()
    shown.show()
    themed.processEvents()
    yield shown
    shown.close()
    app._settings().remove(prefs.TEXT_POINTS)


def _wheel(target: QWidget, dy: int) -> None:
    from PyQt6.QtCore import QPoint, QPointF
    from PyQt6.QtGui import QWheelEvent

    middle = QPointF(target.rect().center())
    event = QWheelEvent(
        middle,
        QPointF(target.mapToGlobal(middle.toPoint())),
        QPoint(),
        QPoint(0, dy),
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.ControlModifier,
        Qt.ScrollPhase.NoScrollPhase,
        False,
    )
    QApplication.sendEvent(target, event)


def test_shortcuts_step_and_reset(window: MainWindow, themed: QApplication) -> None:
    from PyQt6.QtTest import QTest

    from logarc.gui.theme import automatic_points_for

    ctrl = Qt.KeyboardModifier.ControlModifier
    QTest.keyClick(window, Qt.Key.Key_Equal, ctrl)
    assert themed.font().pointSizeF() == 12
    assert window._zoom_note.text() == "Text 12 pt"
    QTest.keyClick(window, Qt.Key.Key_Minus, ctrl)
    QTest.keyClick(window, Qt.Key.Key_Minus, ctrl)
    assert themed.font().pointSizeF() == 10
    QTest.keyClick(window, Qt.Key.Key_0, ctrl)
    assert themed.font().pointSizeF() == automatic_points_for(themed)


def test_the_view_menu_offers_the_zoom(window: MainWindow) -> None:
    texts = [action.text() for action in window._zoom_actions]
    assert texts == ["Zoom &in", "Zoom &out", "&Reset zoom"]
    for action in window._zoom_actions:
        assert action in window.actions(), "zoom must still answer in full screen"
    shortcuts = [s.toString() for s in window._zoom_actions[0].shortcuts()]
    assert "Ctrl+=" in shortcuts


def test_limits_disable_the_action(window: MainWindow) -> None:
    zoom_in, zoom_out, _reset = window._zoom_actions
    window._set_text_points(16)
    assert not zoom_in.isEnabled()
    assert zoom_out.isEnabled()
    window._set_text_points(8)
    assert zoom_in.isEnabled()
    assert not zoom_out.isEnabled()


def test_zoom_is_remembered(window: MainWindow) -> None:
    from logarc.gui import app, prefs

    window._zoom_text(-2)
    assert prefs.text_points_in(app._settings().value, automatic=12) == 9


def test_ctrl_wheel_accumulates_small_steps(window: MainWindow, themed: QApplication) -> None:
    details = window._triage.details
    before = details.font().pointSizeF()
    for _ in range(7):
        _wheel(details.viewport(), 15)
    assert themed.font().pointSizeF() == 11
    _wheel(details.viewport(), 15)
    assert themed.font().pointSizeF() == 12
    assert details.font().pointSizeF() == before + 1, "the browser zoomed by itself too"


def test_wheel_over_the_graph_is_left_to_the_graph(
    window: MainWindow, themed: QApplication
) -> None:
    scale = window._canvas.transform().m11()
    _wheel(window._canvas.viewport(), 120)
    assert themed.font().pointSizeF() == 11
    assert window._canvas.transform().m11() != scale


def test_zooming_keeps_background_progress_and_cancellation(window: MainWindow) -> None:
    from threading import Event

    stop = Event()
    window._busy("Processing logs", stop=stop)
    window._zoom_text(1)
    assert window._stop is stop
    assert window._status.text() == "Processing logs"
    assert not window._progress.isHidden()
    window._request_cancel()
    assert stop.is_set()


def test_the_size_note_never_covers_the_status_line(
    window: MainWindow, themed: QApplication
) -> None:
    from conftest import fired

    window._status.setText("100.66.0.0: 8 activities")
    for points in (9, 14):
        window._set_text_points(points)
        themed.processEvents()
    bar = window.statusBar()
    assert not (window._status.isVisible() and bar.currentMessage()), "drawn on top of each other"
    assert window._status.isVisible()
    assert window._zoom_note.text() == "Text 14 pt"
    fired(window._zoom_note_timer)
    assert window._zoom_note.text() == ""


def test_tree_and_list_item_fonts_move_with_the_zoom(themed: QApplication) -> None:
    from PyQt6.QtWidgets import QListWidgetItem, QTreeWidgetItem

    tree = QTreeWidget()
    tree.setColumnCount(2)
    node = QTreeWidgetItem(tree, ["heading", "192.0.2.1"])
    QTreeWidgetItem(node, ["child", "192.0.2.2"])
    child = node.child(0)
    assert child is not None
    child.setFont(1, mono_font())
    node.setFont(0, caption_font(QFont()))
    entries = QListWidget()
    entry = QListWidgetItem("suggestion", entries)
    entry.setFont(caption_font(QFont()))
    before = (node.font(0).pointSizeF(), child.font(1).pointSizeF(), entry.font().pointSizeF())
    try:
        set_text_points(themed, 14)
        assert (
            node.font(0).pointSizeF(),
            child.font(1).pointSizeF(),
            entry.font().pointSizeF(),
        ) == (
            before[0] + 3,
            before[1] + 3,
            before[2] + 3,
        )
    finally:
        tree.close()
        entries.close()


def test_a_zoom_in_the_window_redraws_the_evidence_heading(window: MainWindow) -> None:
    from test_narrow_columns import lines, node

    window._evidence.show_evidence(node(5), lines())
    window._set_text_points(14)
    heading = window._evidence._heading
    assert f"font-size:{heading.font().pointSizeF() + 3:.1f}pt" in heading.text()


def test_reset_forgets_the_saved_size_so_automatic_keeps_adapting(window: MainWindow) -> None:
    from logarc.gui import app, prefs

    stored = app._settings()
    stored.setValue(prefs.LEGACY_TEXT_SIZE, "compact")
    window._zoom_text(-2)
    assert app._settings().value(prefs.TEXT_POINTS) is not None
    window._reset_text_zoom()
    assert app._settings().value(prefs.TEXT_POINTS) is None
    assert app._settings().value(prefs.LEGACY_TEXT_SIZE) is None
    assert prefs.text_points_in(app._settings().value, automatic=13) == 13


@pytest.mark.parametrize("points", [15, 16])
def test_format_editor_rows_fit_their_text(themed: QApplication, points: int) -> None:
    from logarc.gui.format_editor import FormatEditor

    editor = FormatEditor()
    try:
        set_text_points(themed, points)
        for table in (editor._mapping, editor._fields):
            rows = table.verticalHeader()
            assert rows is not None
            assert rows.defaultSectionSize() >= table.fontMetrics().height() + 8
    finally:
        editor.close()


def test_format_editor_rows_stay_tight_at_ordinary_sizes(themed: QApplication) -> None:
    from logarc.gui.format_editor import FormatEditor

    editor = FormatEditor()
    try:
        rows = editor._fields.verticalHeader()
        assert rows is not None
        assert rows.defaultSectionSize() == 26
    finally:
        editor.close()


@pytest.mark.parametrize("points", [15, 16])
def test_rule_editor_rows_fit_their_text(themed: QApplication, points: int) -> None:
    from logarc.gui.rules_editor import RulesEditor

    editor = RulesEditor()
    try:
        tables = editor.findChildren(QTableWidget)
        assert tables
        set_text_points(themed, points)
        for table in tables:
            rows = table.verticalHeader()
            assert rows is not None
            assert rows.defaultSectionSize() >= table.fontMetrics().height() + 8
    finally:
        editor.close()


def test_rule_editor_rows_stay_tight_at_ordinary_sizes(themed: QApplication) -> None:
    from logarc.gui.rules_editor import RulesEditor

    editor = RulesEditor()
    try:
        for table in editor.findChildren(QTableWidget):
            rows = table.verticalHeader()
            assert rows is not None
            assert rows.defaultSectionSize() == 26
    finally:
        editor.close()


def test_a_partial_wheel_turn_is_forgotten_after_a_pause(
    window: MainWindow, themed: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    from logarc.gui import wheel_zoom

    clock = [100.0]
    monkeypatch.setattr(wheel_zoom, "_now", lambda: clock[0])
    details = window._triage.details
    for _ in range(4):
        _wheel(details.viewport(), 15)
    clock[0] += 5.0
    for _ in range(4):
        _wheel(details.viewport(), 15)
    assert themed.font().pointSizeF() == 11, "two half turns a pause apart made a step"
    for _ in range(4):
        _wheel(details.viewport(), 15)
    assert themed.font().pointSizeF() == 12, "one whole turn without a pause still steps"
