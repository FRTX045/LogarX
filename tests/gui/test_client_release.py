"""Letting go of the client being read, by pressing its row again.

Run without a display. What is checked is which signal a press produces and what
the window does with it — not how the row looks, which is a question for a real
screen.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QEvent, QPointF, Qt
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QApplication

from logarc.gui.panels import ClientTable
from logarc.storage.base import IpSummary

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def qt_app() -> QApplication:
    return QApplication.instance() or QApplication([])


def summary(ip: str, requests: int = 10) -> IpSummary:
    return IpSummary(
        client_ip=ip,
        request_count=requests,
        first_seen=START,
        last_seen=START + timedelta(minutes=5),
        distinct_paths=3,
        client_error_ratio=0.5,
        bytes_total=1024,
    )


def listed(qt_app: QApplication) -> ClientTable:
    panel = ClientTable()
    panel.show_clients([summary("1.1.1.1"), summary("2.2.2.2", 5)])
    return panel


def address(panel: ClientTable, row: int) -> str:
    """Whose row that is. Read rather than assumed: the table sorts itself, so
    the order rows were handed over in is not the order they sit in."""
    cell = panel._table.item(row, 0)
    assert cell is not None
    return cell.text()


def press(panel: ClientTable, row: int, button: Qt.MouseButton = Qt.MouseButton.LeftButton) -> None:
    table = panel._table
    at = table.visualItemRect(table.item(row, 0)).center()
    QApplication.sendEvent(
        table.viewport(),
        QMouseEvent(
            QEvent.Type.MouseButtonPress,
            QPointF(at),
            table.viewport().mapToGlobal(at).toPointF(),
            button,
            button,
            Qt.KeyboardModifier.NoModifier,
        ),
    )


def test_pressing_a_row_chooses_that_client(qt_app: QApplication) -> None:
    panel = listed(qt_app)
    chosen: list[str] = []
    panel.client_chosen.connect(chosen.append)

    wanted = address(panel, 0)

    press(panel, 0)

    assert chosen == [wanted]


def test_pressing_the_row_already_chosen_lets_go_of_it(qt_app: QApplication) -> None:
    """The way out of a client, and out of the band drawn against its life."""
    panel = listed(qt_app)
    press(panel, 0)
    released: list[int] = []
    panel.client_released.connect(lambda: released.append(1))

    press(panel, 0)

    assert released
    assert not panel._table.selectionModel().hasSelection()


def test_pressing_a_different_row_moves_rather_than_lets_go(qt_app: QApplication) -> None:
    panel = listed(qt_app)
    press(panel, 0)
    chosen: list[str] = []
    released: list[int] = []
    panel.client_chosen.connect(chosen.append)
    panel.client_released.connect(lambda: released.append(1))

    wanted = address(panel, 1)

    press(panel, 1)

    assert chosen == [wanted]
    assert released == []


def test_the_right_button_does_not_let_go(qt_app: QApplication) -> None:
    """The context menu is opened with it, and a menu that also dropped what it
    was opened on would be unusable."""
    panel = listed(qt_app)
    press(panel, 0)
    released: list[int] = []
    panel.client_released.connect(lambda: released.append(1))

    press(panel, 0, Qt.MouseButton.RightButton)

    assert released == []
    assert panel._table.selectionModel().hasSelection()


def test_refilling_the_list_says_nothing_at_all(qt_app: QApplication) -> None:
    """A refill is the window rebuilding its own furniture, not the reader
    choosing or dropping anything.

    Left to speak, it does both and gets one of them wrong: shrinking the list
    moves the selection onto a surviving row and emits `client_chosen` with
    whatever address that row still held — a client from the list being replaced.
    Opening a second case would then ask the new one to reconstruct a client of
    the old.
    """
    panel = ClientTable()
    panel.show_clients([summary(f"1.1.1.{n}") for n in range(4)])
    press(panel, 3)
    chosen: list[str] = []
    released: list[int] = []
    panel.client_chosen.connect(chosen.append)
    panel.client_released.connect(lambda: released.append(1))

    panel.show_clients([summary("9.9.9.9")])

    assert chosen == []
    assert released == []


def test_an_emptied_list_says_nothing_either(qt_app: QApplication) -> None:
    """A range holding nobody empties the table. That is an answer the window
    already gives in its own words; the table saying the reader let go on top of
    it would be a second, wrong account of the same thing."""
    panel = ClientTable()
    panel.show_clients([summary("1.1.1.1"), summary("2.2.2.2")])
    press(panel, 0)
    released: list[int] = []
    panel.client_released.connect(lambda: released.append(1))

    panel.show_clients([])

    assert released == []
