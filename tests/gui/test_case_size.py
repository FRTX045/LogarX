"""What the window says about the size and reach of the case it has open.

The client list is capped, because a case of a hundred thousand clients cannot
be a hundred thousand rows. Everything the window says *about the case* has to
come from somewhere else, and this is where that is checked.

Found on a real case of 119,880 clients: the window called it a case of 500,
and its date fields covered the eight days the busiest five hundred happened to
span rather than the twenty-seven the case does — nineteen days of it could not
be selected at all, while the band above the fields went on drawing traffic
across every one of them.

Run without a display.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from conftest import settled
from logarc.case import Case
from logarc.core.window import TimeWindow
from logarc.gui import app
from logarc.gui.app import MainWindow

#: Noon, so the quiet client two hours earlier is still the same day and the
#: dates in any failure message read plainly.
START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)

#: The three that fill the table, all inside half an hour.
BUSY = ("10.0.0.1", "10.0.0.2", "10.0.0.3")

#: One request each, hours either side of the busy ones. These are the clients
#: a capped listing never sees, and the reach of the case is theirs.
EARLY = "10.0.0.4"
LATE = "10.0.0.5"

EARLY_AT = START - timedelta(hours=2)
LATE_AT = START + timedelta(hours=5)

#: Small enough that the fixture does not need five hundred clients to prove
#: what a cap does. `read_case` reads it when it runs, so patching the module
#: attribute is enough.
CAP = 2


@pytest.fixture(autouse=True)
def capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app, "_CLIENT_LIMIT", CAP)


def _line(client: str, when: datetime, target: str) -> str:
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    agent = "Mozilla/5.0 (X11; Linux x86_64)"
    return f'{client} - - [{stamp}] "GET {target} HTTP/1.1" 200 512 "-" "{agent}"'


@pytest.fixture(scope="module")
def case(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Five clients: three busy ones close together, two quiet ones far apart.

    The shape that matters. Ordered by request count the busy three come first,
    so a cap keeps exactly them — and their span is a fraction of the case's.
    """
    root = tmp_path_factory.mktemp("case-size")
    lines = [
        _line(client, START + timedelta(seconds=n * 30), f"/page/{n}")
        for client in BUSY
        for n in range(30)
    ]
    lines.append(_line(EARLY, EARLY_AT, "/"))
    lines.append(_line(LATE, LATE_AT, "/"))

    log = root / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
    return root / "case"


def _opened(qt_app: QApplication, case: Path) -> MainWindow:
    window = MainWindow()
    window._load_case(case)
    settled(qt_app)
    assert window._clients._table.rowCount() == CAP, "premise: the listing is capped"
    return window


def _naive(when: datetime) -> datetime:
    return when.replace(tzinfo=None)


# -- how far the reader can select ----------------------------------------


def test_the_date_fields_reach_both_ends_of_the_case(qt_app: QApplication, case: Path) -> None:
    """Not the ends of whichever clients happened to be listed.

    The band draws the whole case, so a reader can see traffic outside a range
    the fields refuse to reach — and dragging onto it is silently clipped back,
    which reads as the band having broken.
    """
    window = _opened(qt_app, case)
    fields = window._time_filter

    assert _naive(fields._from.minimumDateTime().toPyDateTime()) <= _naive(EARLY_AT)
    assert _naive(fields._to.maximumDateTime().toPyDateTime()) >= _naive(LATE_AT)
    window.close()


def test_a_range_reaching_the_quiet_ends_is_shown_as_asked_for(
    qt_app: QApplication, case: Path
) -> None:
    """The other half of the same thing.

    Held inside a stretch that stops short, a range naming the ends of the case
    is clipped to the middle of it and then *displayed* clipped — so the fields
    disagree with the band beside them about what was asked for.

    Asserted on the fields rather than on `chosen`, which answers `EVERYTHING`
    for a range covering the whole of whatever it thinks the case is. Under the
    fault that is true of the clipped range too, and the test passes over it.
    """
    window = _opened(qt_app, case)
    fields = window._time_filter

    fields.set_window(TimeWindow(EARLY_AT, LATE_AT))

    assert _naive(fields._from.dateTime().toPyDateTime()) <= _naive(EARLY_AT)
    assert _naive(fields._to.dateTime().toPyDateTime()) >= _naive(LATE_AT)
    window.close()


# -- what the window says the case is -------------------------------------


def test_the_window_counts_every_client_not_the_rows_it_drew(
    qt_app: QApplication, case: Path
) -> None:
    window = _opened(qt_app, case)

    assert window._all_clients == 5
    window.close()


def test_the_caption_names_the_case_rather_than_the_table(qt_app: QApplication, case: Path) -> None:
    """The panel is the only place a reader learns how large the case is. Its
    own wording already says so — and it was being handed the row count."""
    window = _opened(qt_app, case)

    assert "5 clients" in window._clients._caption.text()
    window.close()


def test_narrowing_the_range_counts_what_the_range_holds(qt_app: QApplication, case: Path) -> None:
    """Not the rows that fitted. A range holding forty thousand clients and one
    holding five hundred would otherwise read the same."""
    window = _opened(qt_app, case)

    window._apply_window(TimeWindow(START - timedelta(minutes=1), START + timedelta(minutes=20)))
    settled(qt_app)

    assert window._listed == 3, "the three busy clients, not the two rows drawn"
    assert window._all_clients == 5
    window.close()
