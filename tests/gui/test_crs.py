"""Running CRS when a scan finishes, and showing it running.

Since 2026-10-05 nothing asks first. CRS runs after every scan unless the reader
turned it off in Preferences or the machine sets `ZODIARC_CRS=off`, and the card
it shows can stop it. The dialog that used to ask is gone; what it said about
the trade lives on as the note under that preference.

What the window owes the reader either way is the prioritization scan. CRS
holds it back, because finishing reloads the case and a scan begun before that
would be thrown away — so every way CRS can end, including failing, has to let
it go.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QDialog

from conftest import settled
from zodiarc.case import Case
from zodiarc.core.event import NormalizedEvent
from zodiarc.core.evidence import EvidenceRef
from zodiarc.detect.crs import AUTO_ENV, CrsUnavailableError
from zodiarc.enrich import EnrichProgress
from zodiarc.gui import app as app_module
from zodiarc.gui import prefs
from zodiarc.gui.app import MainWindow
from zodiarc.gui.crs import CrsCard, CrsUnavailable

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


def _case(tmp_path: Path) -> Path:
    from datetime import UTC, datetime

    with Case.create(tmp_path / "case") as case:
        case.store.write(
            [
                NormalizedEvent(
                    datetime(2026, 1, 1, tzinfo=UTC),
                    "192.0.2.1",
                    EvidenceRef("source", 1),
                    path="/",
                    method="GET",
                    status=200,
                    user_agent="Mozilla/5.0",
                )
            ]
        )
        case.store.finalize()
    return case.root


class _Watched:
    """A window with its two exits recorded: CRS started, and the scan started."""

    def __init__(self, window: MainWindow, monkeypatch: pytest.MonkeyPatch) -> None:
        self.window = window
        self.crs: list[Path] = []
        self.scans: list[tuple[object, ...]] = []
        self.missing: list[str] = []
        self.errors: list[str] = []
        monkeypatch.setattr(window, "_run_crs", self.crs.append)
        monkeypatch.setattr(window._triage, "start", lambda *args, **_: self.scans.append(args))
        monkeypatch.setattr(window, "_crs_missing", self.missing.append)
        monkeypatch.setattr(
            window, "report_error", lambda message, _detail, **_: self.errors.append(message)
        )


@pytest.fixture
def watched(qt_app: QApplication, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Watched]:
    """A window on a machine where CRS is installed and nobody has turned it off.

    `tests/conftest.py` sets `ZODIARC_CRS=off` for the whole suite, so that a
    test which ingests through the window does not also run CRS. These tests
    are about exactly that run, so they take the switch back off.
    """
    monkeypatch.delenv(AUTO_ENV, raising=False)
    monkeypatch.setattr(app_module.SidecarConfig, "check", lambda self: None)
    window = MainWindow()
    try:
        yield _Watched(window, monkeypatch)
    finally:
        settled(qt_app)
        window.close()


def _dialogs(qt_app: QApplication) -> list[QDialog]:
    return [w for w in qt_app.topLevelWidgets() if isinstance(w, QDialog) and w.isVisible()]


def test_a_finished_scan_runs_crs_without_asking(
    watched: _Watched, qt_app: QApplication, tmp_path: Path
) -> None:
    """The decision, made 2026-10-05: on by default, no question."""
    case_dir = _case(tmp_path)

    watched.window._open_and_start_crs(case_dir)
    settled(qt_app)

    assert watched.crs == [case_dir]
    assert _dialogs(qt_app) == [], "something still asked before running CRS"


def test_the_scan_waits_while_crs_runs(
    watched: _Watched, qt_app: QApplication, tmp_path: Path
) -> None:
    """Finishing CRS reloads the case, and the reload starts the scan. One begun
    now would be work the reader never sees."""
    watched.window._open_and_start_crs(_case(tmp_path))
    settled(qt_app)

    assert watched.scans == []


def test_turned_off_in_preferences_it_is_not_run(
    watched: _Watched, qt_app: QApplication, tmp_path: Path
) -> None:
    """Through `_apply_preferences`, which is what OK in the dialog calls, so
    the switch is the one a reader actually flips. It takes effect on the next
    scan, with no restart."""
    window = watched.window
    window._apply_preferences({**window._prefs, prefs.RUN_CRS: False})

    window._open_and_start_crs(_case(tmp_path))
    settled(qt_app)

    assert watched.crs == []
    assert watched.scans, "with CRS off, nothing let the prioritization scan start"


def test_the_machine_wide_switch_wins_over_the_preference(
    watched: _Watched, qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`ZODIARC_CRS=off` is for a machine, the preference for a reader. The
    machine is the narrower claim — somebody set it for a reason the reader
    may not know — so it wins, and the preference still reads as on."""
    monkeypatch.setenv(AUTO_ENV, "off")
    assert watched.window._prefs[prefs.RUN_CRS] is True

    watched.window._open_and_start_crs(_case(tmp_path))
    settled(qt_app)

    assert watched.crs == []
    assert watched.scans


def test_a_missing_sidecar_is_said_and_the_scan_starts(
    watched: _Watched, qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def absent(self: object) -> None:
        raise CrsUnavailableError("crs-sidecar not found")

    monkeypatch.setattr(app_module.SidecarConfig, "check", absent)

    watched.window._open_and_start_crs(_case(tmp_path))
    settled(qt_app)

    assert watched.missing == ["crs-sidecar not found"]
    assert watched.crs == []
    assert watched.scans


def test_a_reader_who_silenced_the_notice_is_not_told_again(
    watched: _Watched, qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The missing-sidecar notice's "Don't mention this again". It survives
    the offer going away, because it was never an answer about running CRS."""

    def absent(self: object) -> None:
        raise CrsUnavailableError("crs-sidecar not found")

    monkeypatch.setattr(app_module.SidecarConfig, "check", absent)
    app_module._settings().setValue(app_module._CRS_KEY, "quiet")
    try:
        watched.window._open_and_start_crs(_case(tmp_path))
        settled(qt_app)
    finally:
        app_module._settings().remove(app_module._CRS_KEY)

    assert watched.missing == []
    assert watched.scans


def test_a_crs_run_that_fails_still_lets_the_scan_start(
    watched: _Watched, qt_app: QApplication, tmp_path: Path
) -> None:
    """**Found while making CRS the default.** A failed run closed its card and
    reported the error, and nothing released the scan it was holding back — so
    Where to start stayed empty for that case. Rare while CRS needed a yes;
    with every scan running it, one broken sidecar would empty it every time."""
    watched.window._open_and_start_crs(_case(tmp_path))
    settled(qt_app)
    assert watched.scans == []

    watched.window._crs_failed("CRS stopped unexpectedly.", "")
    settled(qt_app)

    assert watched.errors == ["CRS did not finish."]
    assert watched.scans, "a failed CRS run left the case with no prioritization scan"


def test_the_card_draws_the_proportion_it_is_given(qt_app: QApplication) -> None:
    """The loading bar, and the reason `EnrichProgress` carries a denominator.

    A bar that cannot say how far through it is may as well be a spinner, and a
    spinner is what the command line already had.
    """
    card = CrsCard(None, on_stop=lambda: None)

    card.update_progress(EnrichProgress(replayed=96_400, total=236_505))

    assert card.bar().maximum() == 236_505
    assert card.bar().value() == 96_400
    assert "96,400" in card.spoken()
    assert "236,505" in card.spoken()


def test_the_card_promises_that_stopping_keeps_what_was_found(qt_app: QApplication) -> None:
    """Said on the face rather than in a tooltip, because it is the whole reason
    the Stop button is safe to press. `enrich_case` ends the stream rather than
    raising, which is what makes the promise true."""
    assert "keeps" in CrsCard(None, on_stop=lambda: None).spoken().lower()


def test_stopping_asks_once_and_says_so(qt_app: QApplication) -> None:
    asked = 0

    def stop() -> None:
        nonlocal asked
        asked += 1

    card = CrsCard(None, on_stop=stop)
    card.press_stop()

    assert asked == 1
    assert "stopping" in card.spoken().lower()


def test_a_missing_sidecar_reads_as_complete_rather_than_broken(qt_app: QApplication) -> None:
    """The common case — the Go sidecar is optional and usually absent. A case
    without CRS is finished, not failed, and the wording has to say so before it
    says anything about installing."""
    words = CrsUnavailable("crs-sidecar not found").spoken().lower()

    assert "complete without it" in words
    assert "optional" in words


def test_a_run_that_returns_no_outcome_still_lets_the_scan_start(
    watched: _Watched, qt_app: QApplication, tmp_path: Path
) -> None:
    """The same hole on the other exit: `_crs_finished` returned early on a
    result it did not recognise, holding the scan as surely as a failure did."""
    case_dir = _case(tmp_path)
    watched.window._open_and_start_crs(case_dir)
    settled(qt_app)

    watched.window._crs_finished(case_dir, None)
    settled(qt_app)

    assert watched.scans


# -- running it by hand, from the Case menu --------------------------------
#
# With the preference off, or `ZODIARC_CRS=off`, the window used to have no way
# to run CRS on one case at all — only `zodiarc-dev enrich` could. The old offer's
# "You can run it later instead" had no route behind it in the window either.


def _opened(watched: _Watched, qt_app: QApplication, tmp_path: Path) -> Path:
    case_dir = _case(tmp_path)
    watched.window._load_case(case_dir)
    settled(qt_app)
    assert watched.window._case_path == case_dir
    return case_dir


def test_the_case_menu_runs_crs_whatever_the_preference_says(
    watched: _Watched, qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both switches are about the run nobody asked for. This one was asked
    for, by somebody pressing it."""
    monkeypatch.setenv(AUTO_ENV, "off")
    window = watched.window
    window._apply_preferences({**window._prefs, prefs.RUN_CRS: False})
    case_dir = _opened(watched, qt_app, tmp_path)

    window._crs_action.trigger()

    assert watched.crs == [case_dir]


def test_with_no_case_open_it_says_so_rather_than_nothing(
    watched: _Watched, qt_app: QApplication
) -> None:
    watched.window._crs_action.trigger()

    assert watched.crs == []
    assert "open a case" in watched.window._status.text().lower()


def test_asked_for_by_hand_a_missing_sidecar_is_said_even_when_silenced(
    watched: _Watched, qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The notice's "Don't mention this again" silences it after a scan, which
    nobody asked for. Somebody who just asked for CRS is owed the answer."""

    def absent(self: object) -> None:
        raise CrsUnavailableError("crs-sidecar not found")

    _opened(watched, qt_app, tmp_path)
    monkeypatch.setattr(app_module.SidecarConfig, "check", absent)
    app_module._settings().setValue(app_module._CRS_KEY, "quiet")
    try:
        watched.window._crs_action.trigger()
    finally:
        app_module._settings().remove(app_module._CRS_KEY)

    assert watched.missing == ["crs-sidecar not found"]
    assert watched.crs == []


def test_a_failed_run_asked_for_by_hand_does_not_redo_the_scan(
    watched: _Watched, qt_app: QApplication, tmp_path: Path
) -> None:
    """No scan was held for this run — the case was open and scanned before it
    started — so a failure has nothing to release. Restarting the scan anyway
    would clear Where to start and redo work that was already on screen."""
    _opened(watched, qt_app, tmp_path)
    scans_before = len(watched.scans)

    watched.window._crs_action.trigger()
    watched.window._crs_failed("CRS stopped unexpectedly.", "")
    settled(qt_app)

    assert len(watched.scans) == scans_before
