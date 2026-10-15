"""Readers decide which parts of a selected request to show."""

from __future__ import annotations

from dataclasses import replace

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

from logarc.gui.evidence_details import EvidenceDetails
from logarc.gui.evidence_view import Detail
from logarc.gui.theme import mono_font
from logarc.style import EVIDENCE_INK, EVIDENCE_MUTED, PAPER


@pytest.fixture
def record() -> Detail:
    return Detail(
        source="access.log:1282",
        fields=(
            ("Request (method + target)", "GET /about", EVIDENCE_INK),
            ("Client IP (logged address)", "198.51.100.231", EVIDENCE_MUTED),
            ("Time (UTC)", "2026-03-09 01:31:17", EVIDENCE_MUTED),
            ("HTTP version", "HTTP/1.1", EVIDENCE_MUTED),
            ("Response status", "200 — OK", EVIDENCE_INK),
            ("Response size (bytes sent)", "2.4 KB", EVIDENCE_MUTED),
            ("User agent (reported software)", "UptimeRobot/2.0", EVIDENCE_MUTED),
        ),
        raw='<b>literal log evidence</b> "GET /about HTTP/1.1" 200',
        note=None,
    )


@pytest.fixture
def view(qt_app: QApplication, record: Detail):
    widget = EvidenceDetails(mono_font(12))
    widget.resize(400, 300)
    widget.show_detail(record)
    widget.show()
    qt_app.processEvents()
    yield widget
    widget.close()


def test_every_section_starts_closed_including_request(view: EvidenceDetails) -> None:
    assert len(view.sections) == 5
    for section in view.sections.values():
        assert section.isVisible()
        assert not section.button.isChecked()
        assert section.content.isHidden()
        assert section.button.arrowType() == Qt.ArrowType.RightArrow


def test_sections_open_and_close_independently(view: EvidenceDetails) -> None:
    source, request = view.sections["source"], view.sections["request"]
    source.button.click()
    request.button.click()
    assert source.content.isVisible()
    assert request.content.isVisible()
    assert "GET /about" in request.content.toPlainText()
    source.button.click()
    assert source.content.isHidden()
    assert request.content.isVisible()
    assert request.button.arrowType() == Qt.ArrowType.DownArrow


def test_section_choices_survive_selecting_another_request(
    view: EvidenceDetails, record: Detail
) -> None:
    view.sections["response"].button.click()
    second = replace(record, source="access.log:2000", raw="a different original line")
    view.show_detail(second)
    assert view.sections["response"].content.isVisible()
    assert view.sections["request"].content.isHidden()
    assert view.sections["source"].content.isHidden()
    view.sections["source"].button.click()
    assert "access.log:2000" in view.sections["source"].content.toPlainText()
    assert "access.log:1282" not in view.sections["source"].content.toPlainText()
    view.sections["raw"].button.click()
    assert view.sections["raw"].content.toPlainText().endswith(second.raw)


def test_sections_can_be_toggled_with_the_keyboard(view: EvidenceDetails) -> None:
    request = view.sections["request"]
    request.button.setFocus()
    QTest.keyClick(request.button, Qt.Key.Key_Space)
    assert request.content.isVisible()
    QTest.keyClick(request.button, Qt.Key.Key_Space)
    assert request.content.isHidden()


def test_source_warnings_remain_visible_when_source_is_closed(
    view: EvidenceDetails, record: Detail
) -> None:
    view.show_detail(replace(record, note="The source changed since ingest"))
    assert view.sections["source"].content.isHidden()
    assert view.warning.isVisible()
    assert "source changed" in view.warning.text()
    view.show_detail(record)
    assert view.warning.isHidden()


def test_original_evidence_remains_literal_and_selectable(
    view: EvidenceDetails, record: Detail
) -> None:
    raw = view.sections["raw"]
    raw.button.click()
    assert raw.content.toPlainText().endswith(record.raw)
    raw.content.selectAll()
    assert record.raw in raw.content.textCursor().selectedText()
    assert raw.content.isReadOnly()
    assert raw.content.palette().color(QPalette.ColorRole.Base).name() == PAPER


def test_clearing_hides_old_details_but_keeps_section_choices(
    view: EvidenceDetails, record: Detail
) -> None:
    view.sections["request"].button.click()
    view.clear()
    assert all(section.isHidden() for section in view.sections.values())
    assert all(not section.content.toPlainText() for section in view.sections.values())
    view.show_detail(record)
    assert view.sections["request"].content.isVisible()
    assert view.sections["source"].content.isHidden()


def test_long_requests_wrap_inside_the_shared_scroller(
    qt_app: QApplication, view: EvidenceDetails, record: Detail
) -> None:
    target = "GET /" + "x" * 4_000
    view.show_detail(replace(record, fields=(("Request (method + target)", target, EVIDENCE_INK),)))
    request = view.sections["request"]
    request.button.click()
    qt_app.processEvents()
    qt_app.processEvents()
    assert target in request.content.toPlainText()
    assert request.content.height() > view.height()
    assert view.verticalScrollBar().maximum() > 0
    assert not view.horizontalScrollBar().isVisible()
    assert request.content.width() <= view.viewport().width()


def test_the_panel_allocates_room_for_choosing_sections(
    qt_app: QApplication, record: Detail
) -> None:
    from logarc.gui.evidence_panel import EvidencePanel

    panel = EvidencePanel()
    panel.resize(480, 780)
    panel._show_detail(record)
    panel.show()
    qt_app.processEvents()
    assert panel._detail.height() >= panel.height() * 0.3
    panel.close()
