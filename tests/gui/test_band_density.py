"""How finely the traffic band is counted, from the window's side.

`test_density.py` covers the arithmetic. This covers what the window does with
it: that the setting reaches the store, that changing it recounts what is on
screen, and that it is still there next launch.

Run without a display.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication

from conftest import settled
from logarc.case import Case
from logarc.gui import app, prefs
from logarc.gui.app import MainWindow
from logarc.gui.density import Density

START = datetime(2024, 5, 1, 0, 0, tzinfo=UTC)

#: Busy for the whole two hours the case covers.
CLIENT = "10.0.0.1"

#: Forty seconds of it, near the end. Its band and the case's are therefore
#: different lists — and without that, a test asking which of the two the band
#: was handed cannot tell them apart, and passes whichever it was given.
BRIEF = "10.0.0.2"


@pytest.fixture(autouse=True)
def settings(tmp_path: Path) -> object:
    """Somewhere harmless. Without this the suite writes the real registry of
    whoever ran it, and the reader's own preferences change under them."""
    ini = tmp_path / "logarc.ini"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(app, "_settings", lambda: QSettings(str(ini), QSettings.Format.IniFormat))
        yield ini


def _line(seconds: int, target: str, client: str = CLIENT) -> str:
    when = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    agent = "Mozilla/5.0 (X11; Linux x86_64)"
    return f'{client} - - [{when}] "GET {target} HTTP/1.1" 200 512 "-" "{agent}"'


@pytest.fixture(scope="module")
def case(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Busy enough that a finer counting has something finer to find.

    One request every four seconds for two hours: at the coarse setting several
    share a bucket, at the fine setting they do not. A sparser case would come
    back the same at every setting and the comparison would prove nothing.
    """
    root = tmp_path_factory.mktemp("density")
    log = root / "access.log"
    lines = [_line(n * 4, f"/page/{n % 40}") for n in range(1_800)]
    # A second client, alive for forty seconds of the two hours. Its band is a
    # different list from the case's, which is what lets a test tell which of
    # the two the band is holding.
    lines += [_line(6_000 + n, f"/admin/{n}", BRIEF) for n in range(40)]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
    return root / "case"


def _opened(qt_app: QApplication, case: Path) -> MainWindow:
    window = MainWindow()
    # Given a size, because the bucket count is read off the band's width and an
    # unshown window reports nothing. The floor in `gui.density` covers that
    # case; this test is about the widths above it.
    window.resize(1400, 900)
    window.show()
    qt_app.processEvents()
    window._load_case(case)
    settled(qt_app)
    return window


def _bars(window: MainWindow) -> int:
    return len(window._time_filter._band._bars)


def _open(qt_app: QApplication, window: MainWindow, client_ip: str) -> None:
    """Read that client.

    Found by address rather than by row, because the table sorts itself and the
    row a client lands on is not the order it was handed over in.
    """
    table = window._clients._table
    for row in range(table.rowCount()):
        cell = table.item(row, 0)
        if cell is not None and cell.text() == client_ip:
            table.selectRow(row)
            settled(qt_app)
            return
    raise AssertionError(f"{client_ip} is not listed")


def _choose(qt_app: QApplication, window: MainWindow, density: Density) -> None:
    """Change the counting the way the dialog does.

    Through `_apply_preferences`, not by reaching into a widget: that is the
    one path a reader's choice takes now, and a test that took another would
    stop covering the path they use.
    """
    window._apply_preferences({**window._prefs, prefs.DENSITY: density})
    settled(qt_app)


def test_a_finer_setting_draws_more_bars(qt_app: QApplication, case: Path) -> None:
    """The whole point of the setting. If the two came back the same, the
    control would be a menu entry that does nothing."""
    window = _opened(qt_app, case)

    _choose(qt_app, window, Density.COARSE)
    coarse = _bars(window)
    _choose(qt_app, window, Density.FINE)
    fine = _bars(window)

    assert fine > coarse, f"coarse gave {coarse} bars and fine gave {fine}"
    window.close()


def test_the_band_is_counted_against_its_own_width(qt_app: QApplication, case: Path) -> None:
    """Not against a fixed number. A count that ignores the width is right for
    one window size and wrong for every other — 200 buckets is a histogram at
    900px and a row of hairlines at 600."""
    narrow = _opened(qt_app, case)
    narrow.resize(700, 900)
    qt_app.processEvents()
    _choose(qt_app, narrow, Density.MEDIUM)
    few = _bars(narrow)
    narrow.close()

    wide = _opened(qt_app, case)
    wide.resize(1800, 900)
    qt_app.processEvents()
    _choose(qt_app, wide, Density.MEDIUM)
    many = _bars(wide)
    wide.close()

    assert many > few, f"a 700px window gave {few} bars and an 1800px one gave {many}"


def test_the_setting_survives_a_restart(qt_app: QApplication) -> None:
    first = MainWindow()
    assert first._density is Density.FINE, "fine is the default"

    first._apply_preferences({**first._prefs, prefs.DENSITY: Density.COARSE})
    first.close()

    second = MainWindow()
    assert second._density is Density.COARSE
    second.close()


def test_changing_it_recounts_the_client_being_read(qt_app: QApplication, case: Path) -> None:
    """The band follows whoever is open, so the setting has to reach that band
    too — not only the one drawn when the case was opened."""
    window = _opened(qt_app, case)
    _choose(qt_app, window, Density.COARSE)
    _open(qt_app, window, CLIENT)
    assert window._result is not None, "premise: a client is being read"
    coarse = _bars(window)

    _choose(qt_app, window, Density.FINE)

    assert _bars(window) > coarse
    assert window._result is not None, "the client is still being read"
    window.close()


def test_opening_a_client_counts_it_at_the_setting_in_force(
    qt_app: QApplication, case: Path
) -> None:
    """A client's band is drawn two ways, and both have to honour the setting.

    Changing the setting while one is open recounts it; opening one while the
    setting already stands is the other way, and it is the one a reader takes
    every time. Left at a fixed number there, the menu would appear to work —
    change it with a client open and the band redraws — and then quietly ignore
    itself for every client opened afterwards.
    """
    coarse_window = _opened(qt_app, case)
    _choose(qt_app, coarse_window, Density.COARSE)
    _open(qt_app, coarse_window, CLIENT)
    coarse = _bars(coarse_window)
    coarse_window.close()

    fine_window = _opened(qt_app, case)
    _choose(qt_app, fine_window, Density.FINE)
    _open(qt_app, fine_window, CLIENT)
    fine = _bars(fine_window)
    fine_window.close()

    assert fine > coarse, f"opened coarse gave {coarse} bars and fine gave {fine}"


def test_a_recount_that_lands_after_the_reader_let_go_hands_the_case_back(
    qt_app: QApplication, case: Path
) -> None:
    """A recount is a job like any other, so it can outlive what it was asked
    about.

    Change the setting while a client is open, let go of that client before the
    answer comes back, and the band was handed the client's traffic anyway —
    drawn against a life nobody is reading, with the graph showing the invitation
    to pick somebody.
    """
    window = _opened(qt_app, case)
    # The short-lived client, not the one that fills the case. Read against the
    # busy one, this test proves nothing: its band and the case's are the same
    # list, so the band holds the right answer whichever it was handed.
    _open(qt_app, window, BRIEF)
    assert window._result is not None, "premise: a client is being read"
    assert window._time_filter._band._bars != window._case_bars, (
        "premise: this client's band is not the case's"
    )

    window._apply_preferences({**window._prefs, prefs.DENSITY: Density.COARSE})
    window._let_go_of_client()
    settled(qt_app)

    assert window._result is None
    assert window._time_filter._band._bars == window._case_bars, (
        "the band was handed a client's traffic after the reader let go of them"
    )
    window.close()
