"""The main window.

Holds no analysis. Every action here calls the same `logarc.case` and
`logarc.analysis` functions the CLI calls, on a worker thread, and displays what
comes back, so the two front ends cannot disagree about what a case contains.

Two results here have no command-line equivalent, both on purpose. `_export`
offers PNG, which `report.export` deliberately does not carry because it is a
picture of the canvas rather than a serialisation of the reconstruction. And the
time filter reconstructs over a window, which `analyze`, `evidence` and `export`
have no option for. Every other analysis this window can ask for, a command can
ask for too — saying which two are the exceptions is cheaper than a reader
finding out. Window state is a separate matter: preferences, saved arrangements
and the recent-case list belong to the window and have no command behind them.
"""

from __future__ import annotations

import sys
import threading
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QSettings, Qt
from PyQt6.QtGui import QAction, QColor, QImage, QKeyEvent, QKeySequence, QPainter
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabBar,
    QVBoxLayout,
    QWidget,
)

from logarc import __version__
from logarc.case import Case
from logarc.caseview import (
    EVIDENCE_LIMIT,
    node_for_episodes,
    read_case,
    reconstruct_client,
)
from logarc.core.graph import GraphKind
from logarc.core.window import EVERYTHING, TimeWindow
from logarc.detect.crs import CrsEvidence, CrsUnavailableError, SidecarConfig
from logarc.enrich import EnrichOutcome, EnrichProgress, enrich_case
from logarc.episode.builder import DEFAULT_EVIDENCE_SAMPLE
from logarc.formats import drifted_sources
from logarc.gui import crash, prefs, recent
from logarc.gui._qt import required
from logarc.gui.arrangement_bar import ArrangementBar
from logarc.gui.arrangement_keeper import ArrangementKeeper, Showing
from logarc.gui.canvas import ActivityCanvas
from logarc.gui.case_chooser import CaseChooser
from logarc.gui.crs import CrsCard, CrsOffer, CrsUnavailable
from logarc.gui.density import Density, buckets_for
from logarc.gui.evidence_panel import EvidencePanel
from logarc.gui.format_editor import FormatChoice, FormatEditor
from logarc.gui.format_notice import drift_notice
from logarc.gui.full_screen import FullScreen
from logarc.gui.notice_bar import NoticeBanner, warn_about_dead_files
from logarc.gui.panels import ClientTable, LegendBar
from logarc.gui.preferences import PreferencesDialog
from logarc.gui.progress import Progress, Reading
from logarc.gui.progress_card import IngestCard
from logarc.gui.quarantine_notice import notice_for
from logarc.gui.recent import RecentCase
from logarc.gui.theme import GAP, MONO_FAMILIES, PAD, TIGHT, apply_theme, heading_font
from logarc.gui.time_filter import TimeFilterBar
from logarc.gui.workers import run_job
from logarc.ingest.pipeline import IngestCancelled
from logarc.ingest.quarantine import DIRECTORY_NAME as QUARANTINE_DIR
from logarc.report import export
from logarc.storage.case import CaseManifest
from logarc.style import THEME, format_requests, plural
from logarc.timerange import nobody_here, summary

if TYPE_CHECKING:
    from collections.abc import Callable

    from logarc.analysis import AnalysisResult
    from logarc.core.graph import GraphNode
    from logarc.storage.base import TimeSlot

__all__ = ["MainWindow", "main"]

#: Where the window remembers how it was left. The reader's preferences are
#: catalogued in `gui.prefs`, which owns their keys; what is named here is the
#: state the window keeps that nobody chose — where things were put, and what
#: was opened.
_SETTINGS = ("logarc", "logarc")

#: The cases opened here, and whether to reopen the last one on start.
#:
#: Worth saying plainly: this records *what was investigated* rather than how
#: the window looked doing it. `Forget these` in the chooser removes it, and the
#: README says so. `arrangement_keeper.LAYOUT_KEY` is the other one — a saved
#: arrangement is keyed by activity id, and a trace's activity ids carry the
#: client's address.
_RECENT_KEY = "cases/recent"

#: What to do about CRS when a scan finishes: unset asks, "always" and "never"
#: are the answers a ticked "Remember this choice" writes, and "quiet" means the
#: sidecar is absent and the reader asked to stop being told so.
_CRS_KEY = "crs/after-ingest"

#: The two views, in the order the tab bar shows them. One list rather than a
#: pair of indices spelled out at each end, so a tab and the view it selects
#: cannot drift apart.
_TABS: tuple[GraphKind, ...] = (GraphKind.TRACE, GraphKind.BEHAVIOUR)
_TAB_NAMES = {GraphKind.TRACE: "Trace", GraphKind.BEHAVIOUR: "Behaviour"}

#: The evidence face, spelled for Qt's rich text rather than for `QFont`. The
#: heading is a `QLabel` of markup, so the family list has to travel as CSS.
_MONO_CSS = ",".join(f"'{family}'" for family in MONO_FAMILIES)


def _settings() -> QSettings:
    """Where the window's preferences live — the one place that decides.

    A function rather than the constructor spelled out at each call site, so
    there is a single seam a test can point somewhere harmless. `QSettings`
    resolves to `HKCU\\Software` on Windows, and a suite that wrote real
    preferences onto the machine running it would both dirty that machine and
    read its own leftovers back on the next run.
    """
    return QSettings(*_SETTINGS)


class MainWindow(QMainWindow):
    """Open a case, pick a client, read what it did."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"logarc {__version__}")
        self.resize(1400, 880)

        self._case_path: Path | None = None
        # One piece of state for the range, changed in one place. The graph,
        # the client list and an exported report all have to agree about it.
        self._window: TimeWindow = EVERYTHING
        self._all_clients = 0
        self._listed = 0
        # What each client did over the *whole* case, captured when it was
        # opened. A filtered list cannot answer that question about itself,
        # and the summary line has to say `16 of 19` rather than `16 of 16`.
        self._whole_counts: dict[str, int] = {}
        # The case's own traffic, kept so the band can be handed back whenever
        # no client is being read.
        self._case_bars: list[TimeSlot] = []
        # Every preference, read once through the catalogue rather than key by
        # key, so the dialog opens showing what is in force. The density is
        # read before the menu is built, because the menu shows what is in
        # force rather than deciding it.
        self._prefs = prefs.read(_settings().value)
        self._density = prefs.density_in(self._prefs)
        self._result: AnalysisResult | None = None
        # Who the window is waiting to hear about, and over which stretch. A
        # reconstruction that arrives describing anything else is stale and is
        # thrown away — see the guard in `_reconstruct`.
        self._awaiting: tuple[str, TimeWindow] | None = None
        # What CRS contributed to the open case. Empty until one is opened, so
        # a reconstruction before then applies nothing rather than failing.
        self._crs = CrsEvidence(index=None, fingerprint=None)
        self._kind = GraphKind.TRACE
        # The activity whose evidence is in the panel, so a redraw can put the
        # reader back on it in the graph that replaces this one.
        self._selected: GraphNode | None = None
        self._stop: threading.Event | None = None
        # Up only while an ingest is running.
        self._ingest_card: IngestCard | None = None
        self._crs_card: CrsCard | None = None
        self._crs_offer: CrsOffer | CrsUnavailable | None = None

        self._notice = NoticeBanner()
        # Its own strip rather than a paragraph added to the one above. The two
        # say different things — one that the case is short of its logs, the
        # other that it is complete but was made with a format that has since
        # been edited — and a reader who has taken in the first should be able
        # to dismiss it without losing the second.
        self._format_notice = NoticeBanner()
        self._clients = ClientTable()
        self._canvas = ActivityCanvas()
        self._legend = LegendBar()
        self._evidence = EvidencePanel()
        self._clients.client_chosen.connect(self._reconstruct)
        self._clients.client_released.connect(self._release_requested)
        self._canvas.node_selected.connect(self._show_evidence)

        self._build_layout()
        self._build_menu()
        # What the reader left set at the last launch, put back. The menu used
        # to do this as a side effect of checking its own boxes; with the menu
        # entries gone it is said outright.
        self._restore_preferences()

        self._status = QLabel("Open a case, or ingest logs into a new one.")
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.hide()
        self._cancel = QPushButton("Cancel")
        self._cancel.hide()
        self._cancel.clicked.connect(self._request_cancel)
        status_bar = required(self.statusBar())
        status_bar.addWidget(self._status, 1)
        status_bar.addPermanentWidget(self._progress)
        status_bar.addPermanentWidget(self._cancel)

    # -- construction ------------------------------------------------------

    def _build_layout(self) -> None:
        # Empty until there is a client to name. What goes here is the subject
        # of the graph below it, and before a case is open the canvas itself is
        # carrying the only instruction the window has to give.
        self._heading = QLabel("")
        self._heading.setTextFormat(Qt.TextFormat.RichText)
        self._heading.setFont(heading_font(self._heading.font()))

        self._build_tabs()

        # Under the canvas rather than over it. The note beside `Undo` in the
        # Edit menu says why: a strip floating on the graph covers a patch of it,
        # has to be moved on every resize, and swallows clicks meant for whatever
        # node is underneath.
        self._arrangement_bar = ArrangementBar()
        # Handed the canvas rather than owning it: every part of the window uses
        # that. What it owns is the store, the key, the strip and the question
        # asked before an arrangement nobody kept is lost.
        self._arrangements_kept = ArrangementKeeper(
            self._canvas,
            self._arrangement_bar,
            settings=_settings,
            say=self._idle,
            parent=self,
            showing=self._showing_now,
        )
        self._full_screen = FullScreen(self, self._canvas, cover=self._what_to_cover)
        self._arrangement_bar.save_requested.connect(self._arrangements_kept.save)
        self._arrangement_bar.reset_requested.connect(self._arrangements_kept.reset)

        centre = QWidget()
        column = QVBoxLayout(centre)
        # Matching the panels either side, and what lets the canvas read as a
        # framed document rather than a hole cut in the window.
        column.setContentsMargins(PAD, TIGHT, PAD, TIGHT)
        column.setSpacing(TIGHT)
        column.addWidget(self._tabs)
        column.addWidget(self._heading)
        column.addWidget(self._canvas)
        column.addWidget(self._arrangement_bar)
        column.addWidget(self._legend)

        splitter = self._build_splitter(centre)
        # Kept as an attribute for the tests that size it directly, now that
        # the strip sits between it and the window.
        self._splitter = splitter

        # Above the splitter rather than inside a panel: the strip is about the
        # whole case, and every panel beneath it is about one part of one.
        frame = QWidget()
        stack = QVBoxLayout(frame)
        stack.setContentsMargins(0, 0, 0, 0)
        stack.setSpacing(0)
        stack.addWidget(self._notice)
        stack.addWidget(self._format_notice)
        # Beside the notice for the same reason, and it matters more here than
        # it looks: the range governs the client list as well as the graph, so
        # sitting over the graph alone it would claim to narrow one of the two
        # things it narrows. Inside the middle column it also forced that column
        # wider than the client table could spare — measured at 279 pixels for a
        # table that needs 420 to show its columns.
        self._time_filter = TimeFilterBar()
        self._time_filter.changed.connect(self._apply_window)
        stack.addWidget(self._time_filter)
        stack.addWidget(splitter, 1)
        self.setCentralWidget(frame)

    def _build_tabs(self) -> None:
        """The bar that says which of the two readings is in front of you.

        Lifted out of `_build_layout` because it is the one block there that
        genuinely closes over itself: it builds `self._tabs`, dresses it, fills
        it and wires it, and hands nothing else back to the layout around it.
        """
        # Which view you are looking at, said on screen rather than only in a
        # menu. Trace and behaviour are two readings of one reconstruction and
        # the window drew them into the same rectangle with nothing to tell them
        # apart, so the only way to know which was in front of you was to open
        # the View menu and look at which entry was ticked.
        self._tabs = QTabBar()
        self._tabs.setDrawBase(False)
        # Sized to their words, not to the column. Left to expand, two tabs
        # split the whole width of the canvas into two half-window slabs, which
        # reads as a pair of buttons rather than as a choice between two views —
        # and at that size the selected one is not obviously selected.
        self._tabs.setExpanding(False)
        # Drawn here rather than left to the style, which had it backwards.
        #
        # Under Fusion in document mode the selected tab takes the page colour
        # and the unselected one takes the button colour. On a light palette
        # those differ and it reads correctly; on this one the page colour is
        # the chrome the bar already sits on, so the selected tab vanished into
        # the background and the *unselected* tab was the one drawn as a raised
        # box. The bar was confidently indicating the view you were not looking
        # at, which is worse than the menu-only state it replaced.
        self._tabs.setStyleSheet(f"""
            QTabBar::tab {{
                background: transparent;
                color: {THEME.muted};
                border: 1px solid transparent;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
                padding: {TIGHT}px {GAP}px;
                margin-right: 2px;
            }}
            QTabBar::tab:hover {{ color: {THEME.ink}; }}
            QTabBar::tab:selected {{
                background: {THEME.raised};
                color: {THEME.ink};
                border: 1px solid {THEME.edge};
                border-top: 2px solid {THEME.accent};
            }}
        """)
        for kind in _TABS:
            self._tabs.addTab(_TAB_NAMES[kind])
        self._tabs.currentChanged.connect(self._tab_chosen)
        # Nothing to switch between until a client has been reconstructed.
        self._tabs.setVisible(False)

    def _build_splitter(self, centre: QWidget) -> QSplitter:
        """The three columns, given the middle one.

        The other block in `_build_layout` worth its own name, and the better
        of the two: it takes an argument and returns a widget rather than
        reaching into `self` for both ends, so what it needs and what it
        produces are both visible from the call.
        """
        # Small enough to leave the panel adjustable, which is the whole point
        # of a splitter. A floor of 430 was set here to stop the client table
        # being squeezed until three of its six columns hid — it worked, and it
        # also meant the panel could be 430 or, by collapsing, 0, and nothing
        # in between. Dragging it therefore did nothing until it jumped the
        # whole way, which reads as a broken handle rather than a wide minimum.
        self._clients.setMinimumWidth(220)
        self._evidence.setMinimumWidth(200)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._clients)
        splitter.addWidget(centre)
        splitter.addWidget(self._evidence)

        # What should actually have been protecting the table: extra width goes
        # to the graph, and the side panels keep whatever the investigator set
        # them to. That holds the columns open without forbidding any width.
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 0)
        # No collapsing to nothing. A panel dragged to zero leaves a handle
        # against the window edge that is hard to find and harder to explain,
        # and with a minimum in place the last part of that drag was a jump
        # anyway. Continuous down to the minimum, and no further.
        splitter.setChildrenCollapsible(False)
        splitter.setSizes([440, 560, 400])
        return splitter

    def _build_menu(self) -> None:
        menu_bar = required(self.menuBar())
        case_menu = required(menu_bar.addMenu("&Case"))
        self._add(case_menu, "&Open case…", self._open_case, QKeySequence.StandardKey.Open)
        recently = self._add(case_menu, "&Recently opened…", self._show_recent)
        recently.setShortcut(QKeySequence("Ctrl+Shift+O"))
        recently.setStatusTip("Pick up a case that has been opened on this machine before.")
        self._add(case_menu, "Ingest logs into a &new case…", self._ingest_new_case)
        self._add(case_menu, "Log &formats…", self._manage_formats).setStatusTip(
            "See the log formats logarc reads, and write your own."
        )
        case_menu.addSeparator()
        self._add(case_menu, "E&xit", self.close, QKeySequence.StandardKey.Quit)

        # What is done to the graph, and the door to the preferences. `Edit`
        # rather than `View` because `Ctrl+Z` is the first thing anyone looks
        # for there, and because it leaves `View` answering one question.
        edit_menu = required(menu_bar.addMenu("&Edit"))

        # Where an activity was dragged to, and how to be rid of it. In the menu
        # with every other control rather than on the canvas: a strip floating
        # over the graph covers a patch of it, has to be moved on every resize,
        # and swallows clicks meant for whatever node is underneath.
        self._undo_action = self._add(edit_menu, "&Undo node move", self._arrangements_kept.undo)
        self._undo_action.setShortcut(QKeySequence.StandardKey.Undo)
        self._undo_action.setStatusTip("Put the last activity you moved back where it was.")
        self._save_layout_action = self._add(
            edit_menu, "&Save this arrangement", self._arrangements_kept.save
        )
        self._save_layout_action.setShortcut(QKeySequence.StandardKey.Save)
        self._save_layout_action.setStatusTip(
            "Remember where you have put the activities on this graph."
        )
        self._reset_layout_action = self._add(
            edit_menu, "&Reset layout", self._arrangements_kept.reset
        )
        self._reset_layout_action.setShortcut(QKeySequence("Ctrl+Shift+R"))
        self._reset_layout_action.setStatusTip(
            "Put every activity back where it was laid out, and forget the saved arrangement."
        )
        self._arrangements_kept.offer(
            self._save_layout_action, self._undo_action, self._reset_layout_action
        )
        self._canvas.arrangement_changed.connect(self._arrangements_kept.refresh)
        self._arrangements_kept.refresh()
        edit_menu.addSeparator()

        preferences = self._add(edit_menu, "&Preferences…", self._show_preferences)
        preferences.setShortcut(QKeySequence("Ctrl+,"))
        preferences.setStatusTip("Change how the graph, the evidence and the launch behave.")

        # One question: what is being shown. It held eleven entries answering
        # four — two switches, four actions, four preferences, and one setting
        # about what happens at launch, which is not a view at all.
        view_menu = required(menu_bar.addMenu("&View"))
        self._trace_action = self._add(view_menu, "&Trace (chronological)", self._show_trace)
        self._behaviour_action = self._add(view_menu, "&Behaviour map", self._show_behaviour)
        for action in (self._trace_action, self._behaviour_action):
            action.setCheckable(True)
        self._trace_action.setChecked(True)
        view_menu.addSeparator()
        self._fit_action = self._add(view_menu, "&Fit to window", self._canvas.fit)
        view_menu.addSeparator()
        self._fullscreen_action = self._add(
            view_menu, "F&ull screen", self._full_screen.from_the_menu
        )
        self._fullscreen_action.setCheckable(True)
        self._fullscreen_action.setShortcut(QKeySequence("F11"))
        self._fullscreen_action.setStatusTip("Give the whole screen to the activity graph.")
        # On the window as well as in the menu. Full screen hides the menu bar,
        # and a shortcut that lived only on a hidden menu would stop answering
        # exactly when it is one of the two ways back.
        self.addAction(self._fullscreen_action)
        self._full_screen.offer(self._fullscreen_action)
        self._canvas.expand_requested.connect(self._full_screen.from_the_canvas)

        # The same actions again, offered where the reader's hand already is.
        # Qt builds the menu from them, so each entry carries the shortcut it
        # already has and greys out exactly when its twin in the menu bar does
        # — because it is not a twin, it is the same object. A menu built by
        # hand here would be a second list to keep in step, and the first thing
        # to fall out of step would be which entries are dead.
        #
        # After the View menu, not with the Edit one: `_fit_action` is made
        # there, and added before it exists this would be adding `None`.
        on_the_canvas = QAction(self._canvas)
        on_the_canvas.setSeparator(True)
        self._canvas.addActions(
            [
                self._save_layout_action,
                self._undo_action,
                self._reset_layout_action,
                on_the_canvas,
                self._fit_action,
            ]
        )
        self._canvas.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)

        export_menu = required(menu_bar.addMenu("&Export"))
        self._add(export_menu, "&HTML report…", lambda: self._export("html"))
        self._add(export_menu, "&JSON graph…", lambda: self._export("json"))
        self._add(export_menu, "&PNG image…", lambda: self._export("png"))

    def _add(
        self,
        menu: QMenu,
        text: str,
        # `object` rather than `None`: QWidget.close returns a bool, and a menu
        # action does not care what its slot hands back.
        slot: Callable[[], object],
        shortcut: QKeySequence.StandardKey | None = None,
    ) -> QAction:
        action = QAction(text, self)
        action.triggered.connect(slot)
        if shortcut is not None:
            action.setShortcut(shortcut)
        menu.addAction(action)
        return action

    # -- case --------------------------------------------------------------

    def _open_case(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Open case directory")
        if chosen:
            self._load_case(Path(chosen))

    def _ingest_new_case(self) -> None:
        logs, _ = QFileDialog.getOpenFileNames(
            self, "Choose log files", "", "Logs (*.log *.txt *.gz *.bz2);;All files (*)"
        )
        if not logs:
            return
        # Asked before the case folder, because it is a question about the
        # logs just chosen. Cancelling here abandons the ingest rather than
        # falling back to detection: a reader who opened this screen has a
        # format in mind, and quietly doing the other thing would produce a
        # case that looks right and was read by something they did not pick.
        chooser = FormatChoice(self)
        if not chooser.exec():
            return
        log_format = chooser.chosen()

        target = QFileDialog.getExistingDirectory(self, "Choose an empty folder for the case")
        if not target:
            return

        paths = [Path(item) for item in logs]
        case_dir = Path(target)
        stop = threading.Event()
        sizes = [path.stat().st_size for path in paths]

        def work(report: Callable[[object], None]) -> IngestCancelled | None:
            report(f"Ingesting {plural(len(paths), 'file')}…")
            reading = Reading([path.name for path in paths], sizes)
            try:
                with Case.create(case_dir) as case:
                    # One call per file rather than one call for all of them.
                    # `Case.ingest` reports progress per file and never says
                    # which, so a caller drawing a whole-ingest figure would
                    # have to guess where each one ended — and the obvious
                    # guess, the byte count falling, misses a small log
                    # followed by a large one entirely. Looping here means the
                    # boundary is known rather than inferred, and the two forms
                    # are otherwise identical: same manifest, same digests,
                    # same stored events.
                    for index, path in enumerate(paths):
                        if index:
                            reading.next_file()
                        case.ingest(
                            [path],
                            log_format=log_format,
                            on_progress=lambda lines, read: report(
                                reading.advance(lines=lines, bytes_read=read)
                            ),
                            should_cancel=stop.is_set,
                        )
            except IngestCancelled as cancelled:
                # Caught outside the `with`, so the case still sees the failure
                # on the way out and leaves itself un-finalised. Returned rather
                # than re-raised: a stop the investigator asked for should not
                # be presented as a crash.
                return cancelled
            return None

        self._ingest_card = IngestCard(self, on_cancel=self._request_cancel)
        self._ingest_card.show()
        self._busy(f"Ingesting into {case_dir}…", stop=stop)
        run_job(
            work,
            on_done=lambda outcome: self._ingest_finished(case_dir, outcome),
            on_error=self._ingest_failed,
            on_progress=self._status.setText,
            on_advance=self._show_ingest_progress,
        )

    def _manage_formats(self) -> None:
        """Open the format library.

        Modal, and nothing is applied on the way out: the dialog writes what
        the reader saved as they save it, so there is no pending state for
        closing the window to discard or apply by accident.
        """
        FormatEditor(self).exec()

    def _show_ingest_progress(self, snapshot: object) -> None:
        if self._ingest_card is not None and isinstance(snapshot, Progress):
            self._ingest_card.update_progress(snapshot)
            self._status.setText(f"{snapshot.lines:,} lines parsed")

    def _close_ingest_card(self) -> None:
        """Take the card down. Called on every way out of an ingest.

        A card left standing after a failure is worse than never having shown
        one: it says the read is still going while nothing is running.
        """
        if self._ingest_card is not None:
            self._ingest_card.close()
            self._ingest_card = None

    def _ingest_failed(self, message: str, detail: str) -> None:
        self._close_ingest_card()
        self.report_error(message, detail)

    def _ingest_finished(self, case_dir: Path, outcome: object) -> None:
        self._close_ingest_card()
        if not isinstance(outcome, IngestCancelled):
            self._load_case(case_dir)
            self._offer_crs(case_dir)
            return

        self._idle(f"Cancelled after {outcome.lines_read:,} lines.")
        QMessageBox.information(
            self,
            "Ingest cancelled",
            f"Stopped after {outcome.lines_read:,} lines.\n\n"
            f"{case_dir} holds what had been read by then and was not finalised, so it "
            "cannot be analysed. It is left in place rather than deleted — delete the "
            "folder yourself if you want to start over.",
        )

    # -- CRS, offered once a scan has something to enrich --------------------

    def _offer_crs(self, case_dir: Path) -> None:
        """Ask whether to run CRS, unless the reader has already answered.

        Availability is checked before the offer rather than after it, so that
        somebody without the sidecar is told their case is complete instead of
        being asked a question and then refused.
        """
        answered = str(_settings().value(_CRS_KEY, "") or "")
        if answered == "never":
            return

        try:
            SidecarConfig().check()
        except CrsUnavailableError as exc:
            if answered != "quiet":
                self._crs_missing(str(exc))
            return

        if answered == "always":
            self._run_crs(case_dir)
            return

        offer = CrsOffer(self)
        # Held on the window, not only in the closure: a dialog whose last
        # Python reference is a lambda argument is collectable the moment this
        # method returns, and it is `show()` rather than `exec()` precisely so
        # that this method does return.
        self._crs_offer = offer
        offer.finished.connect(lambda result: self._crs_answered(case_dir, result))
        offer.show()

    def _crs_answered(self, case_dir: Path, result: int) -> None:
        offer, self._crs_offer = self._crs_offer, None
        if offer is None:
            return
        wanted = result == QDialog.DialogCode.Accepted
        if offer.remembered():
            _settings().setValue(_CRS_KEY, "always" if wanted else "never")
        if wanted:
            self._run_crs(case_dir)

    def _crs_missing(self, reason: str) -> None:
        told = CrsUnavailable(reason, self)
        self._crs_offer = told
        told.finished.connect(lambda _result: self._crs_missing_closed())
        told.show()

    def _crs_missing_closed(self) -> None:
        told, self._crs_offer = self._crs_offer, None
        if isinstance(told, CrsUnavailable) and told.remembered():
            _settings().setValue(_CRS_KEY, "quiet")

    def _run_crs(self, case_dir: Path) -> None:
        stop = threading.Event()

        def work(report: Callable[[object], None]) -> object:
            report("Replaying requests through CRS…")
            return enrich_case(case_dir, report=report, should_stop=stop.is_set)

        self._crs_card = CrsCard(self, on_stop=stop.set)
        self._crs_card.show()
        self._busy("Running OWASP CRS…", stop=stop)
        run_job(
            work,
            on_done=lambda outcome: self._crs_finished(case_dir, outcome),
            on_error=self._crs_failed,
            on_progress=self._status.setText,
            on_advance=self._show_crs_progress,
        )

    def _show_crs_progress(self, snapshot: object) -> None:
        if self._crs_card is not None and isinstance(snapshot, EnrichProgress):
            self._crs_card.update_progress(snapshot)

    def _close_crs_card(self) -> None:
        if self._crs_card is not None:
            self._crs_card.close()
            self._crs_card = None

    def _crs_failed(self, message: str, detail: str) -> None:
        self._close_crs_card()
        self.report_error(message, detail)

    def _crs_finished(self, case_dir: Path, outcome: object) -> None:
        """Reload, so the findings CRS added are the ones on screen.

        A case is reopened rather than patched in place: the enrichment was
        written to the case by the engine, and re-reading is the only way the
        window is showing what the case holds rather than what it remembers.
        """
        self._close_crs_card()
        if not isinstance(outcome, EnrichOutcome):
            return
        self._load_case(case_dir)
        # Requests flagged, not detections found: one request can match several
        # CRS rules, and the larger number would read as the more alarming
        # result while describing the same traffic.
        stopped = " Stopped early." if outcome.stopped else ""
        self._idle(
            f"CRS read {outcome.replayed:,} "
            f"{plural(outcome.replayed, 'request')} and flagged "
            f"{outcome.covered:,}.{stopped}"
        )

    # -- the cases opened before -------------------------------------------

    def _recent_cases(self) -> tuple[RecentCase, ...]:
        return recent.load(str(_settings().value(_RECENT_KEY, "")))

    def _remember_case(self, entry: RecentCase) -> None:
        """Record a case, having opened it.

        Only ever called from the success path. A list of cases that cannot be
        opened is worse than a short one — every entry in it invites the reader
        into the same failure.
        """
        _settings().setValue(_RECENT_KEY, recent.dump(recent.remember(self._recent_cases(), entry)))

    def _forget_recent(self) -> None:
        _settings().remove(_RECENT_KEY)

    def _show_recent(self) -> None:
        """The chooser, on demand. With the last case reopening on start it
        would otherwise only appear on a first run or after a folder moved."""
        cases = self._recent_cases()
        if not cases:
            self._open_case()
            return

        chooser = CaseChooser(cases, exists=lambda path: Path(path).exists())
        chooser.exec()

        # Stored before anything else is decided. A pin, a name or a removal is
        # worth keeping whether or not a case was opened afterwards — closing
        # the chooser without opening anything is a perfectly ordinary way to
        # tidy the list.
        if chooser.changed:
            if chooser.cases:
                _settings().setValue(_RECENT_KEY, recent.dump(chooser.cases))
            else:
                # Removed, not stored empty. This list is a record of what was
                # investigated on this machine and `Forget these` is what takes
                # it back; an empty value would satisfy every visible symptom
                # and leave the key sitting there.
                self._forget_recent()
                self._idle("Forgot the list of cases opened here.")

        if chooser.wants_other_case:
            self._open_case()
        elif chooser.wants_new_case:
            self._ingest_new_case()
        elif chooser.chosen_path:
            self._open_from_chooser(Path(chooser.chosen_path))

    def _open_from_chooser(self, path: Path) -> None:
        """Load `path`, unless it is the case already open.

        A finalised case cannot change, so reading it again produces exactly
        what is already on screen — at the cost of the reconstruction being
        read, which is thrown away, and of the wait.

        Said rather than done silently. Nothing happening is indistinguishable
        from a control that does not work, and there is one reason somebody
        might mean it: `logarc enrich` can add CRS evidence to a case from a
        terminal while the window holds it, and reopening is how that gets
        picked up. A reader who came here for that has to learn they did not.
        """
        if self._case_path is not None and path == self._case_path:
            self._idle(f"{path} is already open.")
            return
        self._load_case(path)

    def offer_start(self) -> None:
        """What to do with the list when the window opens.

        Called after `show()` rather than from `__init__`, so the window is on
        screen before anything modal appears in front of it.
        """
        action, entry = recent.startup_action(
            self._recent_cases(),
            reopen_last=bool(self._prefs["cases/reopen_last"]),
            exists=lambda path: Path(path).exists(),
        )
        if action is recent.Startup.OPEN_LAST and entry is not None:
            self._load_case(Path(entry.path))
        elif action is recent.Startup.CHOOSE:
            self._show_recent()

    def _load_case(self, path: Path) -> None:
        # Read here, on the interface thread. The worker must not reach into a
        # widget to ask how wide it is while the window is free to resize it.
        buckets = self._buckets()

        def work(report: Callable[[str], None]) -> Any:
            report(f"Opening {path}…")
            view = read_case(path, buckets=buckets)
            # Snapshotted here, on the worker, and stored with the entry. The
            # chooser has to draw before it has touched a disk: a case on a share
            # that is no longer mounted would otherwise stall the list once per
            # row before the window appeared.
            manifest = CaseManifest.load(path)
            snapshot = RecentCase(
                path=str(path),
                case_id=manifest.case_id,
                opened_at=recent.now(),
                events=manifest.total_events_parsed,
                sources=tuple(source.file_id for source in manifest.sources),
            )
            # Built here, on the worker: it is arithmetic over the source
            # records, and the manifest is already in hand. `done` only shows it.
            notice = notice_for(manifest.sources)
            # Reads the user's saved-format library, which is a file on disk, so
            # it belongs on the worker beside the rest of the reading. The engine
            # never does this: the case was read from its own copy long before.
            drifted = drift_notice(drifted_sources(manifest.sources))
            return view, snapshot, notice, drifted

        self._busy(f"Opening {path}…")

        def done(loaded: Any) -> None:
            view, snapshot, notice, drifted = loaded
            summaries = view.listed
            self._remember_case(snapshot)
            self._case_path = path
            self._crs = view.crs
            # A fresh case is read whole. Opening one already narrowed would
            # hide part of it with nothing on screen saying so.
            self._window = EVERYTHING
            self._awaiting = None
            # The case's own figures, not the table's. `summaries` is the
            # busiest few hundred; taken from it, a case of a hundred thousand
            # clients reports itself as a case of five hundred, and its date
            # fields stop wherever those five hundred happened to stop.
            self._all_clients = view.whole.clients
            self._listed = view.in_range
            # Unfiltered by construction: a case is opened whole.
            self._whole_counts = {s.client_ip: s.request_count for s in summaries}
            self._case_bars = view.bars
            self._time_filter.set_bars(view.bars)
            self._time_filter.set_span(
                (view.whole.first_seen, view.whole.last_seen)
                if view.whole.first_seen is not None and view.whole.last_seen is not None
                else None
            )
            self._result = None
            self._selected = None
            self._canvas.show_graph_placeholder()
            # The canvas is already saying "Select a client to reconstruct what
            # it did" across the middle of the window. Repeating it above the
            # canvas and inviting an activity selection beside it made three
            # messages for one state, two of them about steps that cannot be
            # taken yet.
            self._evidence.clear(prompt=False)
            self._notice.show_notice(notice, quarantine_dir=path / QUARANTINE_DIR)
            # No quarantine folder: nothing was refused. Passing one would offer
            # a button that opens a directory holding nothing to do with this.
            self._format_notice.show_notice(drifted)
            self._heading.setText("")
            self._tabs.setVisible(False)
            self._clients.show_clients(summaries, total=view.whole.clients)
            self._say_what_is_left()
            self._idle(
                # Not "listed": the table holds the busiest few hundred of
                # them, and the caption beside it is where that is said.
                f"{path} — {plural(view.whole.clients, 'client')}"
                + (", CRS applied" if view.crs.fingerprint else "")
            )
            # Last, after the window has finished loading, never before. A modal
            # raised mid-load sits over a half-drawn case, so the reader has to
            # dismiss it before they can see the thing it is talking about.
            if notice is not None and notice.is_blocking:
                warn_about_dead_files(self, notice)

        run_job(work, on_done=done, on_error=self.report_error, on_progress=self._status.setText)

    # -- the stretch of time being read ------------------------------------

    def _apply_window(self, window: TimeWindow) -> None:
        """Read the case over a different stretch of time.

        Both halves, always. Narrowing only the graph leaves the client row
        saying 19 requests beside a heading saying 16 — two numbers for one
        thing on one screen, which is the failure this feature was shaped
        around.
        """
        if self._case_path is None or window == self._window:
            return
        self._window = window
        # Nothing in flight describes this range: each was asked over the range
        # before it. `_reselect` asks again below if the reader is still on
        # somebody, which is what puts a fresh answer back on the way.
        self._awaiting = None
        # The control is told what is in force, not asked. Typing in the fields
        # keeps them right by accident; every other way the range can be set
        # would otherwise leave them naming a stretch nobody is reading.
        self._time_filter.set_window(window)
        path = self._case_path
        buckets = self._buckets()

        def work(report: Callable[[str], None]) -> Any:
            report("Reading the selected time range…")
            return read_case(path, window=window, buckets=buckets)

        self._busy("Reading the selected time range…")

        def done(loaded: Any) -> None:
            summaries = loaded.listed
            # What the range holds, not what fitted in the table.
            self._listed = loaded.in_range
            # `show_clients` is silent for the whole rebuild — the table owns
            # that, because it is the one that knows when it is replacing its
            # own furniture. This used to block the signals from out here, which
            # left two mechanisms for one rule.
            self._clients.show_clients(summaries, total=self._all_clients)
            self._say_what_is_left()
            if not summaries:
                # An answer, not a failure, and often the one being looked for.
                self._result = None
                self._selected = None
                self._evidence.clear(prompt=False)
                self._tabs.setVisible(False)
                self._heading.setText("")
                self._canvas.show_graph_placeholder(nobody_here(window))
                self._idle(nobody_here(window))
                return
            self._idle(f"{self._listed:,} of {self._all_clients:,} clients in this range")
            # The client the reader was on, if this range still holds them. The
            # table has been rebuilt, so the selection has to be found again.
            if self._result is not None:
                self._reselect(self._result.client_ip)

        run_job(work, on_done=done, on_error=self.report_error, on_progress=self._status.setText)

    def _say_what_is_left(self, result: AnalysisResult | None = None) -> None:
        """The line beside the control: what the range left of the case.

        Both counts once a client is reconstructed, so one line carries the two
        numbers that have to agree — what the range did to the list, and what it
        did to the graph.
        """
        whole = self._whole_counts.get(result.client_ip) if result is not None else None
        self._time_filter.say(
            summary(
                self._window,
                clients=self._listed,
                all_clients=self._all_clients,
                requests=result.request_count if result is not None else None,
                all_requests=whole,
            )
        )

    def _showing_now(self) -> Showing | None:
        """What the canvas is showing, for whatever needs to know.

        Asked for rather than pushed. Five things decide which arrangement
        belongs to a graph and each changes at its own moment — the case on
        open, the client on selection, the kind on a tab, the range on the date
        fields. Told each time, there would be four places that must remember;
        asked, there are none.
        """
        if self._case_path is None or self._result is None:
            return None
        return Showing(
            case_path=str(self._case_path),
            client_ip=self._result.client_ip,
            kind=self._kind,
            window_tag=self._window.tag,
        )

    def _reselect(self, client_ip: str) -> None:
        """Put the reader back on the client they were reading, if it is listed.

        The reconstruction is asked for outright rather than left to the
        selection signal. After a narrower range the client can land on the row
        it was already on, and `selectRow` on the current row changes nothing
        and emits nothing — so the graph went on showing the reconstruction it
        had, over a range that was no longer in force.
        """
        if self._clients.select_quietly(client_ip):
            self._reconstruct(client_ip)
            return
        # Gone from this range. The graph would otherwise go on showing a
        # reconstruction of a client the list no longer offers.
        self._let_go_of_client()

    def _release_requested(self) -> None:
        """The reader pressed the row they were already on.

        Asked here rather than inside `_let_go_of_client`, because that runs on
        two paths and only one of them is the reader leaving: a narrower range
        drops a client from the list and lets go of it on their behalf. Asking
        there would offer to keep an arrangement for a graph that is going
        whatever the answer, and cancelling would leave the window reading a
        client the list no longer has.
        """
        if not self._arrangements_kept.may_leave():
            if self._result is not None:
                self._clients.select_quietly(self._result.client_ip)
            return
        self._let_go_of_client()

    def _let_go_of_client(self) -> None:
        """Stop reading whoever was being read.

        Two ways in: the reader presses the row they are already on, or a
        narrower range drops that client from the list. Both leave the window
        with nobody selected, and the same things have to be true afterwards —
        so they say it once here rather than agreeing with each other by hand.
        """
        self._result = None
        # Nobody is wanted, so nothing may arrive. Without this the answer to a
        # question asked a moment ago comes back and puts the client, the band
        # and the heading straight back on screen — the gesture appearing to do
        # nothing at all.
        self._awaiting = None
        self._selected = None
        self._evidence.clear(prompt=False)
        self._tabs.setVisible(False)
        self._heading.setText("")
        self._canvas.show_graph_placeholder()
        # Nobody is being read, so the question is the case's again.
        self._time_filter.set_bars(self._case_bars)
        self._say_what_is_left()
        # The status line still named the client. Left standing it is the only
        # thing on screen claiming one is open, and it names one that is not.
        self._idle(plural(self._listed, "client"))

    # -- reconstruction ----------------------------------------------------

    def _reconstruct(self, client_ip: str) -> None:
        if self._case_path is None:
            return
        # Only a different client is leaving this one. `_reselect` calls this
        # again for the *same* client whenever the range moves, and asking there
        # would say the reader is leaving a client they are still on.
        leaving = self._result is not None and self._result.client_ip != client_ip
        if leaving and not self._arrangements_kept.may_leave():
            # The selection has already moved: `client_chosen` comes from
            # `itemSelectionChanged`, which fires before the window hears about
            # it. Refusing the move means putting the row back as well.
            if self._result is not None:
                self._clients.select_quietly(self._result.client_ip)
            return
        path = self._case_path
        # Read once here, on the interface thread, rather than from inside the
        # worker: the job must not reach back into window state while the window
        # is free to change it.
        crs = self._crs
        window = self._window
        buckets = self._buckets()
        self._awaiting = (client_ip, window)

        def work(report: Callable[[str], None]) -> tuple[AnalysisResult, list[TimeSlot]]:
            report(f"Reconstructing {client_ip}…")
            result = reconstruct_client(path, client_ip, crs, window=window)
            # This client's own traffic, across its own life — not the range in
            # force. Built from the reconstruction it would only ever cover that
            # range, so the whole band would be lit and there would be nothing
            # to see outside the selection, which is the one thing a reader
            # needs to see. Measured at 0.037s, and it does not grow with the
            # case: three million events came back in 0.039s.
            with Case.open(path) as case:
                return result, case.store.activity_over_time(buckets=buckets, client_ip=client_ip)

        self._busy(f"Reconstructing {client_ip}…")

        def done(loaded: tuple[AnalysisResult, list[TimeSlot]]) -> None:
            result, bars = loaded
            # Only what the window is still waiting for. Jobs finish in whatever
            # order they finish, and one can be started by something as ordinary
            # as refilling the client table — so without this, the graph and the
            # client list can end up describing different ranges, or different
            # clients.
            #
            # Both halves of the question, because staleness arrives on two
            # axes. Asking only about the range let a reconstruction that was
            # already in flight land after the reader had let go of the client,
            # putting the graph, the heading and the band straight back: the
            # range had not changed, so the answer looked current.
            #
            # A guard on arrival rather than only on departure: it holds however
            # the stale job was started, which is what makes it worth having.
            if (result.client_ip, result.window) != self._awaiting:
                return
            self._result = result
            # The band becomes this client's own history: when it worked, when
            # it went quiet, across its own life rather than the case's.
            self._time_filter.set_bars(bars)
            # Forgotten before the redraw below, or the new client's graph would
            # be searched for the activity the last one was being read at.
            self._selected = None
            self._evidence.clear()
            self._tabs.setVisible(True)
            # The address, then three counts. Not a sentence.
            #
            # `100.66.2.0 — 69 requests across 1 session, reduced to 9
            # activities` reads as prose and is scanned as prose: the numbers
            # are what the line is for, and they were buried among connectives
            # at one weight with the address. Separated values put the three
            # counts where the eye can take them one at a time, and dropping the
            # address to monospace makes it an address rather than the first
            # word of a sentence.
            self._heading.setText(
                f'<span style="font-family:{_MONO_CSS}">'
                f"<b>{result.client_ip}</b></span>"
                # Normal weight, explicitly: the label itself is set in the
                # heading face, which is DemiBold, and without this the counts
                # carry the same emphasis as the address they belong to.
                f'<span style="color:{THEME.muted};font-weight:normal">&nbsp;&nbsp;'
                f"{format_requests(result.request_count)}"
                f" · {plural(len(result.sessions), 'session')}"
                f" · {plural(len(result.episodes), 'activity', 'activities')}</span>"
            )
            self._redraw()
            self._say_what_is_left(result)
            self._idle(f"{client_ip}: {plural(len(result.episodes), 'activity', 'activities')}")

        run_job(work, on_done=done, on_error=self.report_error, on_progress=self._status.setText)

    def _redraw(self) -> None:
        """Draw the current view, and keep the reader's place across it.

        `show_graph` drops the ring, so without this a view switch left the
        evidence panel describing an activity from the graph that is no longer
        on screen, with nothing marked to say so — the two halves of the window
        describing different things, which is the hazard `ActivityCanvas.set_wrap`
        already guards against for its own redraw.
        """
        if self._result is None:
            return
        graph = self._result.trace if self._kind is GraphKind.TRACE else self._result.behaviour
        was_reading = self._selected
        self._canvas.show_graph(graph, positions=self._arrangements_kept.saved_positions())
        self._arrangements_kept.refresh()
        if was_reading is None:
            return
        # Found by episode, not by node id: the two graphs number their nodes
        # differently, and one behaviour node answers to several trace nodes.
        carried = node_for_episodes(graph, frozenset(was_reading.episode_ids))
        if carried is None:
            self._selected = None
            self._evidence.clear()
            return
        self._show_evidence(carried.node_id)

    def _show_trace(self) -> None:
        self._kind = GraphKind.TRACE
        self._trace_action.setChecked(True)
        self._behaviour_action.setChecked(False)
        self._sync_tabs()
        self._redraw()

    def _show_behaviour(self) -> None:
        self._kind = GraphKind.BEHAVIOUR
        self._trace_action.setChecked(False)
        self._behaviour_action.setChecked(True)
        self._sync_tabs()
        self._redraw()

    def _sync_tabs(self) -> None:
        """Move the tab bar to match the view, without it answering back.

        The tab and the menu entry are two controls over one piece of state, so
        each has to be able to set it without the other treating that as a fresh
        instruction — otherwise selecting a tab calls `_show_behaviour`, which
        moves the tab, which fires `currentChanged` again. Blocked rather than
        guarded by a flag, because `blockSignals` says what it is doing at the
        point it happens.
        """
        wanted = _TABS.index(self._kind)
        if self._tabs.currentIndex() == wanted:
            return
        blocked = self._tabs.blockSignals(True)
        self._tabs.setCurrentIndex(wanted)
        self._tabs.blockSignals(blocked)

    def _tab_chosen(self, index: int) -> None:
        """The tab bar asking for a view."""
        if _TABS[index] is GraphKind.TRACE:
            self._show_trace()
        else:
            self._show_behaviour()

    # -- where the reader put the activities --------------------------------

    def _what_to_cover(self) -> list[QWidget | None]:
        """Everything the graph takes the screen from.

        Named by the window rather than known by `FullScreen`, because these are
        the window's widgets. `menuBar` and `statusBar` are asked for at the
        moment of covering rather than held: they are methods, and Qt is free to
        answer with something else.
        """
        return [
            self._clients,
            self._evidence,
            self._time_filter,
            self._notice,
            self._format_notice,
            self._tabs,
            self._heading,
            self._legend,
            self.menuBar(),
            self.statusBar(),
        ]

    def keyPressEvent(self, event: QKeyEvent | None) -> None:  # noqa: N802 - Qt's naming
        """Escape comes back, and only from full screen.

        Whether this press is that is `FullScreen`'s to answer, since it is the
        one holding the state the question turns on.
        """
        if self._full_screen.leaves_on(event):
            return
        super().keyPressEvent(event)

    def _restore_preferences(self) -> None:
        """Put what is in force into the widgets, without writing it again.

        Not `_apply_preferences`: nothing has been chosen here, and writing the
        settings back on every launch would rewrite a file for no reason. The
        band's counting needs no applying — `_buckets` reads it when it asks.
        """
        self._apply_wrap(bool(self._prefs["view/wrap_traces"]))
        self._apply_band(bool(self._prefs["view/traffic_band"]))
        self._apply_evidence_view(bool(self._prefs["view/decode_targets"]))

    def _show_preferences(self) -> None:
        """Open the preferences, and apply them only if the reader says OK.

        The dialog is handed what is in force and hands values back. It applies
        nothing itself, which is what makes Cancel mean *nothing happened*
        rather than *something to be undone*.
        """
        dialog = PreferencesDialog(self._prefs, self)
        if dialog.exec() != int(QDialog.DialogCode.Accepted.value):
            return
        self._apply_preferences(dialog.chosen())

    def _apply_preferences(self, chosen: dict[str, bool | Density]) -> None:
        """Put every setting in force and write them all down.

        All of them together rather than one signal each: they are decided in
        one go now, and applying them one at a time was how the window and the
        menu came to hold two copies of the same answer.
        """
        self._prefs = dict(chosen)
        self._apply_wrap(bool(chosen["view/wrap_traces"]))
        self._apply_band(bool(chosen["view/traffic_band"]))
        self._apply_evidence_view(bool(chosen["view/decode_targets"]))
        self._apply_density(prefs.density_in(chosen))
        # Carried across rather than read by the keeper on every ask. It holds
        # this as a plain attribute, so without this line the switch goes one
        # way only: off from the dialog, and never back on from Preferences.
        self._arrangements_kept.ask_before_leaving = bool(chosen[prefs.ASK_UNSAVED_ARRANGEMENT])
        prefs.write(_settings().setValue, self._prefs)

    def _apply_band(self, showing: bool) -> None:
        """Draw the traffic above the fields, or stop drawing it."""
        self._time_filter.show_band(showing)

    def _buckets(self) -> int:
        """How many buckets to ask for, at the counting now in force.

        Reckoned from the band's own width rather than from a fixed number: a
        count that ignores the width is right at one window size and wrong at
        every other. `gui.density` holds the arithmetic and the floor that
        covers a window Qt has not laid out yet.
        """
        return buckets_for(self._time_filter.band_width(), self._density)

    def _apply_density(self, density: Density) -> None:
        """Count the traffic more finely, or less."""
        if density is self._density:
            return
        self._density = density
        self._recount_traffic()

    def _recount_traffic(self) -> None:
        """Ask for the traffic again, at the counting now in force.

        Both bands, because there are two: the case's, kept so it can be handed
        back when nobody is being read, and the open client's, which is what is
        on screen while somebody is. Counting only the one showing would leave
        the other at the old setting, to reappear at it the moment the reader
        let go.
        """
        if self._case_path is None:
            return
        path = self._case_path
        buckets = self._buckets()
        client = self._result.client_ip if self._result is not None else None

        def work(report: Callable[[str], None]) -> tuple[list[TimeSlot], list[TimeSlot]]:
            report("Counting the traffic…")
            with Case.open(path) as case:
                whole = case.store.activity_over_time(buckets=buckets)
                mine = (
                    case.store.activity_over_time(buckets=buckets, client_ip=client)
                    if client is not None
                    else []
                )
            return whole, mine

        def done(counted: tuple[list[TimeSlot], list[TimeSlot]]) -> None:
            whole, mine = counted
            self._case_bars = whole
            # Whoever is being read still owns the band — but only if they are
            # still the one being read. A recount is a job like any other and
            # can outlive what it was asked about: let go of the client while
            # one is in flight, and the band was handed that client's traffic
            # anyway, drawn against a life nobody was reading.
            reading = self._result.client_ip if self._result is not None else None
            self._time_filter.set_bars(mine if mine and reading == client else whole)

        run_job(work, on_done=done, on_error=self.report_error)

    def _apply_wrap(self, wrap: bool) -> None:
        """Fold long traces or stop folding them.

        A behaviour map is a circle and has nothing to fold, so this decides
        nothing while one is on screen — the choice is kept and applies again
        the moment the trace comes back.
        """
        # The arrangement for the wrap being switched *to*, handed over with the
        # instruction. `set_wrap` redraws once; asking it to redraw and then
        # redrawing again to place the nodes would double the cost of a toggle
        # on the graphs where it is already slowest.
        self._canvas.set_wrap(wrap, positions=self._arrangements_kept.saved_positions(wrap=wrap))

    def _apply_evidence_view(self, decode: bool) -> None:
        """How targets are shown in the evidence panel.

        The `Show raw log lines` toggle that used to live beside this is gone:
        the detail pane prints the original line for the selected row always,
        which is strictly more than a global on-or-off could give.
        """
        self._evidence.set_decode(decode)

    # -- evidence ----------------------------------------------------------

    def _show_evidence(self, node_id: str) -> None:
        if self._result is None or self._case_path is None:
            return
        # Ringed before the lookup, so the canvas answers the click even when
        # the episode behind it cannot be found and nothing fills the panel.
        self._canvas.highlight(node_id)
        graph = self._result.trace if self._kind is GraphKind.TRACE else self._result.behaviour
        node = next((item for item in graph.nodes if item.node_id == node_id), None)
        if node is None:
            return
        self._selected = node

        path = self._case_path
        # Which lines are behind an activity is `AnalysisResult`'s to answer, not
        # the window's: it is a fact about the reconstruction, checkable without
        # a display, and getting it wrong shows the reader the wrong evidence.
        # What stays here is the ceiling, which is a question about how long
        # somebody will sit watching a panel fill.
        refs = self._result.evidence_for(node, limit=EVIDENCE_LIMIT)

        def work(_: Callable[[str], None]) -> Any:
            with Case.open(path) as case:
                return case.read_evidence(refs)

        run_job(
            work,
            on_done=lambda lines: self._evidence.show_evidence(node, lines),
            on_error=self.report_error,
        )

    # -- export ------------------------------------------------------------

    def _export(self, kind: str) -> None:
        if self._result is None or self._case_path is None:
            QMessageBox.information(self, "Nothing to export", "Reconstruct a client first.")
            return

        # What each format is called and what it suggests saving as comes from
        # `report.export`, so the extension offered here cannot drift from the
        # extension actually written. PNG is not in that list — it is a picture
        # of the canvas rather than a serialisation of the reconstruction, and
        # only something holding a canvas can produce one.
        if kind == "png":
            title, suggested, mask = "PNG image", "graph.png", "PNG (*.png)"
        else:
            fmt = export.named(kind)
            title, suggested, mask = fmt.label, fmt.suggested, fmt.mask
        chosen, _ = QFileDialog.getSaveFileName(self, f"Export {title}", suggested, mask)
        if not chosen:
            return

        target = Path(chosen)
        client_ip = self._result.client_ip
        case_path = self._case_path
        crs = self._crs

        if kind == "png":
            self._export_png(target)
            return

        def work(_: Callable[[str], None]) -> str:
            # Reconstructed again at the engine's own sample rather than
            # serialising what the window is holding. The window asks for every
            # reference it can draw, and both of these carry those references
            # into a file — the JSON directly, the report by embedding it — so
            # writing what is on screen would grow a deliverable by the size of
            # the log it came from.
            #
            # The same pipeline, on the same case, at the same policy but for
            # this one number: the graph written is the graph drawn, and only
            # its list of references is shorter.
            bounded = reconstruct_client(
                case_path, client_ip, crs, evidence_sample=DEFAULT_EVIDENCE_SAMPLE
            )
            with Case.open(case_path) as case:
                written = export.write_reconstruction(
                    bounded, case.manifest, kind=kind, target=target
                )
            return str(written)

        run_job(
            work,
            on_done=lambda written: self._idle(f"Written to {written}"),
            on_error=self.report_error,
        )

    def _export_png(self, target: Path) -> None:
        """Rendered here rather than on a worker: painting needs the GUI thread."""
        scene = self._canvas.graph_scene
        bounds = scene.sceneRect()
        image = QImage(
            int(bounds.width()) or 1, int(bounds.height()) or 1, QImage.Format.Format_ARGB32
        )
        # The canvas ground, not white. `scene.render` paints the items and not
        # the view's background brush, so this fill *is* the exported image's
        # ground — and the captions are drawn in the theme's ink, which on this
        # theme is near-white. Filled white, every label on the exported graph
        # would have been white on white: an export that silently loses half of
        # what it is an export of, and looks fine until someone reads it.
        image.fill(QColor(THEME.surface))
        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        scene.render(painter)
        painter.end()
        if image.save(str(target)):
            self._idle(f"Written to {target}")
        else:
            self.report_error(f"Could not write {target}", "")

    # -- status ------------------------------------------------------------

    def _busy(self, message: str, *, stop: threading.Event | None = None) -> None:
        """Show that work is running, and offer to stop it when it can be."""
        self._stop = stop
        self._status.setText(message)
        self._progress.show()
        self._cancel.setEnabled(True)
        self._cancel.setVisible(stop is not None)

    def _idle(self, message: str) -> None:
        self._stop = None
        self._status.setText(message)
        self._progress.hide()
        self._cancel.hide()

    def _request_cancel(self) -> None:
        if self._stop is None:  # pragma: no cover - the button is hidden then
            return
        self._stop.set()
        # Disabled rather than hidden: the ingest keeps running until the batch
        # in flight finishes, and a button that vanishes would suggest otherwise.
        self._cancel.setEnabled(False)
        if self._ingest_card is not None:
            self._ingest_card.stopping()
        self._status.setText("Stopping after the batch in flight…")

    def report_error(self, message: str, detail: str) -> None:
        self._progress.hide()
        self._status.setText(message)
        if detail:
            # The window gets a sentence; the terminal keeps the traceback, so a
            # failure is never only a dialog nobody wrote down.
            print(detail, file=sys.stderr)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("logarc")
        box.setText(message)
        if detail:
            box.setDetailedText(detail)
        box.exec()


def main() -> int:
    """Entry point for the `logarc-gui` command."""
    # Reused if one is already up. There never is in production; it is what
    # lets this function be called from a test at all, and an entry point that
    # cannot be called is an entry point nothing checks.
    running = QApplication.instance()
    app = running if isinstance(running, QApplication) else QApplication(sys.argv)
    app.setApplicationName("logarc")
    apply_theme(app)
    try:
        window = MainWindow()
    except Exception:
        traceback.print_exc()
        return 1
    # The net goes up as soon as there is somewhere to show a problem. Before
    # it, a mistake anywhere in the interface reached Qt's own handler, which
    # ends the process without printing anything at all — see `gui.crash`.
    crash.install(window.report_error)
    window.show()
    window.offer_start()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
