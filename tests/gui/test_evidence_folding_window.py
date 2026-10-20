"""The window folds evidence by the reader's preference, and folding changes nothing else.

The case is the bookmarks one: the sweeper signs in three times and is refused,
then a fourth attempt is answered 302. Folded by the default rule that is two
rows, the refusals and the one that got in.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QFileDialog
from tables import column_of
from test_bookmarks_window import make_case, reconstruct, show, sign_in
from test_case_search_window import SWEEPER, opened

from conftest import settled
from logarc.case import Case
from logarc.gui import prefs
from logarc.gui.folding import FoldRule

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from logarc.gui.app import MainWindow


@pytest.fixture
def window(qt_app: QApplication, tmp_path: Path) -> Iterator[MainWindow]:
    shown = opened(qt_app, make_case(tmp_path / "case"))
    shown.resize(1400, 900)
    shown.show()
    settled(qt_app)
    yield shown
    shown.close()
    settled(qt_app)


def test_the_window_folds_by_default_and_unfolds_when_told(
    qt_app: QApplication, window: MainWindow
) -> None:
    reconstruct(qt_app, window, SWEEPER)
    show(qt_app, window, sign_in(window))
    table = window._evidence._table
    status = column_of(table, "Status")

    assert table.rowCount() == 2
    assert [table.item(row, status).text() for row in range(2)] == ["401", "302"]

    window._apply_preferences({**window._prefs, prefs.FOLD: FoldRule.OFF})
    assert table.rowCount() == 4


def test_two_visits_to_the_same_activity_fold_apart(qt_app: QApplication, tmp_path: Path) -> None:
    """The behaviour view puts both visits in one activity; folding keeps them apart."""
    start = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
    stamps = [start + timedelta(seconds=s) for s in (0, 2)]
    stamps += [start + timedelta(hours=2, seconds=s) for s in (0, 2)]
    log = tmp_path / "visits.log"
    log.write_text(
        "".join(
            f'{SWEEPER} - - [{at:%d/%b/%Y:%H:%M:%S +0000}] "POST /login HTTP/1.1" 401 512 '
            '"-" "Mozilla/5.0"\n'
            for at in stamps
        ),
        encoding="utf-8",
    )
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    shown = opened(qt_app, tmp_path / "case")
    try:
        reconstruct(qt_app, shown, SWEEPER)
        shown._show_behaviour()
        settled(qt_app)
        assert shown._result is not None
        (node,) = (n for n in shown._result.behaviour.nodes if "/login" in n.top_targets)
        assert len(node.episode_ids) == 2, "premise: one activity, two visits"

        show(qt_app, shown, node)

        table = shown._evidence._table
        request = column_of(table, "Request")
        requests = [table.item(row, request).text() for row in range(table.rowCount())]
        assert requests == ["2x  POST /login", "2x  POST /login"]
    finally:
        shown.close()
        settled(qt_app)


def test_the_report_is_the_same_folded_or_not(
    qt_app: QApplication,
    window: MainWindow,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Folding is a display decision: what the case exports must not move."""
    reconstruct(qt_app, window, SWEEPER)
    show(qt_app, window, sign_in(window))
    assert window._evidence._table.rowCount() == 2, "premise: the sign-in is folded"
    folded, unfolded = tmp_path / "folded.html", tmp_path / "unfolded.html"
    answers = iter([(str(folded), ""), (str(unfolded), "")])
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_a, **_k: next(answers))

    window._export("html")
    settled(qt_app)
    window._apply_preferences({**window._prefs, prefs.FOLD: FoldRule.OFF})
    window._export("html")
    settled(qt_app)

    assert folded.read_bytes() == unfolded.read_bytes()
