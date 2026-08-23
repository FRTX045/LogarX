"""Letting go of the client being read, from the window's side.

`test_client_release.py` covers the gesture and the signal it produces. This
covers what the window does with it — which is where the feature was broken
while every test of the signal was green.

Run without a display. What is checked is state the window keeps, not how any
of it looks.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QEvent, QPointF, Qt, QThreadPool
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QApplication

from logarc.case import Case
from logarc.gui.app import MainWindow

START = datetime(2024, 5, 1, 0, 0, tzinfo=UTC)

#: Busy all day, so the case's own span is this client's span.
ALL_DAY = "10.0.0.1"

#: Two minutes in the middle of it. Selecting this one is what makes the band
#: visibly narrow, and letting go of it is what has to widen the band again.
BRIEF = "10.0.0.2"


@pytest.fixture(scope="module")
def qt_app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _line(client: str, seconds: int, target: str) -> str:
    when = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    agent = "Mozilla/5.0 (X11; Linux x86_64)"
    return f'{client} - - [{when}] "GET {target} HTTP/1.1" 200 512 "-" "{agent}"'


@pytest.fixture(scope="module")
def case(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Two clients whose lives are different lengths.

    They have to differ, or the band would read the same whether it followed
    the client or the case and this file would prove nothing.
    """
    root = tmp_path_factory.mktemp("letting-go")
    lines = [_line(ALL_DAY, n * 600, f"/page/{n}") for n in range(144)]
    lines += [_line(BRIEF, 43_200 + n, f"/admin/{n}") for n in range(120)]

    log = root / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
    return root / "case"


def _settled(qt_app: QApplication, timeout: float = 30.0) -> None:
    pool = QThreadPool.globalInstance()
    assert pool is not None
    assert pool.waitForDone(int(timeout * 1000)), "background work did not finish"
    qt_app.processEvents()


def _opened(qt_app: QApplication, case: Path) -> MainWindow:
    window = MainWindow()
    window._load_case(case)
    _settled(qt_app)
    assert window._clients._table.rowCount() == 2, "premise: both clients are listed"
    return window


def _row_of(window: MainWindow, client_ip: str) -> int:
    table = window._clients._table
    for row in range(table.rowCount()):
        cell = table.item(row, 0)
        if cell is not None and cell.text() == client_ip:
            return row
    raise AssertionError(f"{client_ip} is not listed")


def _press(window: MainWindow, client_ip: str) -> None:
    """The whole gesture on that client's row: button down, button up.

    Both halves. `QAbstractItemView` finishes selecting on the release, so a
    test that sends only the press asks the widget a question the reader's hand
    never asks it.
    """
    table = window._clients._table
    at = table.visualItemRect(table.item(_row_of(window, client_ip), 0)).center()
    where = table.viewport().mapToGlobal(at).toPointF()
    for kind, held in (
        (QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton),
        (QEvent.Type.MouseButtonRelease, Qt.MouseButton.NoButton),
    ):
        QApplication.sendEvent(
            table.viewport(),
            QMouseEvent(
                kind,
                QPointF(at),
                where,
                Qt.MouseButton.LeftButton,
                held,
                Qt.KeyboardModifier.NoModifier,
            ),
        )


def _band(window: MainWindow) -> tuple[datetime | None, datetime | None]:
    strip = window._time_filter._band
    return strip._first, strip._last


# -- the gesture, end to end ----------------------------------------------


def test_pressing_the_open_client_again_puts_the_case_back(
    qt_app: QApplication, case: Path
) -> None:
    """The reader's way out of a client, and out of the band drawn on its life.

    Driven through the widget rather than by calling the handler, because the
    defect this covers lived between the two: the handler was right, the
    gesture never reached it intact.
    """
    window = _opened(qt_app, case)
    whole = _band(window)

    _press(window, BRIEF)
    _settled(qt_app)
    assert window._result is not None, "premise: the press opened the client"
    assert _band(window) != whole, "premise: the band followed the client"

    _press(window, BRIEF)
    _settled(qt_app)

    assert window._result is None
    assert _band(window) == whole
    assert not window._clients._table.selectionModel().hasSelection()
