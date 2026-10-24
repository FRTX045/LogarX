"""The main window coordinates case reading, prioritization and reconstruction.

Analysis stays in Qt-independent modules. Workers return results for the
window to display, and case/range guards discard answers no longer requested.
"""

from __future__ import annotations

import multiprocessing
import sys
import threading
import traceback
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QPoint, QSettings, Qt, QTimer
from PyQt6.QtGui import (
    QAction,
    QActionGroup,
    QCloseEvent,
    QColor,
    QImage,
    QKeyEvent,
    QKeySequence,
    QPainter,
)
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from logarc import rules_library
from logarc.bookmarks import (
    Kind,
    said_for_activity,
    said_for_client,
    said_for_request,
    said_for_search,
    to_csv,
)
from logarc.case import Case, CaseError
from logarc.caseview import (
    EVIDENCE_LIMIT,
    node_for_episodes,
    read_case,
    reconstruct_client,
)
from logarc.core.graph import GraphKind
from logarc.core.window import EVERYTHING, TimeWindow
from logarc.detect.crs import CrsEvidence, CrsUnavailableError, SidecarConfig, runs_by_default
from logarc.detect.ruleset import NO_EXTRA_RULES, BuiltInPack, RuleSet, built_in_packs
from logarc.enrich import EnrichOutcome, EnrichProgress, crs_config, enrich_case
from logarc.episode.builder import DEFAULT_EVIDENCE_SAMPLE
from logarc.formats import drifted_sources
from logarc.gui import crash, prefs, recent
from logarc.gui._qt import required
from logarc.gui.add_rule import AddRuleDialog
from logarc.gui.arrangement_bar import ArrangementBar
from logarc.gui.arrangement_keeper import ArrangementKeeper, Showing
from logarc.gui.bookmark_keeper import BookmarkKeeper, Draft
from logarc.gui.bookmarks_tab import BookmarksTab
from logarc.gui.canvas import ActivityCanvas
from logarc.gui.case_chooser import CaseChooser
from logarc.gui.client_filter import awaiting_scan, is_whole_address
from logarc.gui.crs import CrsCard, CrsUnavailable
from logarc.gui.crs_notice import stale_crs_notice
from logarc.gui.density import Density, buckets_for
from logarc.gui.disclosure import Disclosure
from logarc.gui.display import configure_display
from logarc.gui.evidence_panel import EvidencePanel
from logarc.gui.evidence_view import Filtered, RequestFilter
from logarc.gui.format_editor import FormatChoice
from logarc.gui.format_notice import drift_notice
from logarc.gui.formats_and_rules import FormatsAndRules
from logarc.gui.full_screen import FullScreen
from logarc.gui.help import open_user_guide, show_about, show_shortcuts
from logarc.gui.icon_set import IconChoice, rule_icons
from logarc.gui.icons import read_kind_icons
from logarc.gui.notice_bar import NoticeBanner, warn_about_dead_files
from logarc.gui.panels import ClientTable, LegendBar
from logarc.gui.preferences import PreferencesDialog
from logarc.gui.progress import Progress, Reading
from logarc.gui.progress_card import IngestCard
from logarc.gui.quarantine_notice import notice_for
from logarc.gui.recent import RecentCase
from logarc.gui.rules_view import packs_refused_notice, rules_changed_notice
from logarc.gui.site_hosts import SiteHostsOffer
from logarc.gui.splitter import PanelSplitter
from logarc.gui.text_size import MAX_POINTS, MIN_POINTS, stepped
from logarc.gui.theme import (
    GAP,
    MONO_FAMILIES,
    PAD,
    TIGHT,
    apply_theme,
    automatic_points_for,
    colour_text,
    heading_font,
    set_text_points,
)
from logarc.gui.time_filter import TimeFilterBar
from logarc.gui.triage import TriagePanel
from logarc.gui.wheel_zoom import CtrlWheel
from logarc.gui.who_else import WhoElseDialog, rule_names, unavailable
from logarc.gui.window_controls import install_window_controls
from logarc.gui.workers import run_job
from logarc.ingest.pipeline import IngestCancelled
from logarc.ingest.quarantine import DIRECTORY_NAME as QUARANTINE_DIR
from logarc.report import export
from logarc.search import Scope, evidence_part, labels_for_activity, parse, value_counts
from logarc.storage.base import ClientMatchPage, IpSummaryPage
from logarc.storage.case import CaseManifest
from logarc.style import THEME, format_requests, plural
from logarc.timerange import nobody_here, summary
from logarc.triage.scan import (
    read_activity_clients,
    read_activity_counts,
    read_labels,
    read_rule_matches,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import date, datetime

    from logarc.analysis import AnalysisResult
    from logarc.core.evidence import EvidenceRef
    from logarc.core.graph import GraphNode
    from logarc.evidence import EvidenceLine
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

#: "quiet" once the sidecar was found absent and the reader asked to stop being
#: told so. Whether CRS runs at all is a preference now, `prefs.RUN_CRS`; this
#: key held that answer too while a dialog asked, which is why the preference
#: still reads a "never" left here.
_CRS_KEY = "crs/after-ingest"

#: Whether to stop asking which domains a site owns. Global, because the answer
#: itself is per case and saved with it — what a reader suppresses is the
#: question, not an answer.
_SITE_HOSTS_KEY = "site-hosts/after-ingest"

#: The two views, in the order the tab bar shows them. One list rather than a
#: pair of indices spelled out at each end, so a tab and the view it selects
#: cannot drift apart.
_TABS: tuple[GraphKind, ...] = (GraphKind.TRACE, GraphKind.BEHAVIOUR)
_TAB_NAMES = {GraphKind.TRACE: "Trace", GraphKind.BEHAVIOUR: "Behaviour"}

#: What each workspace tab is for, said on hover. The tab names are short;
#: these carry what a reader new to the tool needs.
_WORKSPACE_TIPS: tuple[str, ...] = (
    "Clients ranked by how suspicious or unusual their traffic is: where to start reading.",
    "What the selected client did, drawn as a graph of activities.",
    "What you saved in this case to come back to.",
)

#: The evidence face, spelled for Qt's rich text rather than for `QFont`. The
#: heading is a `QLabel` of markup, so the family list has to travel as CSS.
_MONO_CSS = ",".join(f"'{family}'" for family in MONO_FAMILIES)

#: How far before a `before:` typed in the client box the range ends. The range
#: counts both its ends and `before:` counts neither, so the range keeps every
#: moment up to the one it names.
_JUST_BEFORE = timedelta(microseconds=1)

#: Said when opening a bookmark moved the range: what it points at is outside
#: the stretch that was set, and the time bar puts that back in one step.
_WIDENED = "Range set to All time to show the bookmark."


def _raw_lines(case: Case, refs: Sequence[EvidenceRef]) -> dict[EvidenceRef, str]:
    """The log lines behind `refs`, as written; one that cannot be read is left out."""
    return {line.ref: line.text for line in case.read_evidence(refs) if line.text is not None}


def _crs_config_now(site_hosts: Sequence[str]) -> SidecarConfig | None:
    """The configuration running CRS on a case would use here, or None when it
    cannot run here at all. Reads the disk, so it is asked on the worker."""
    config = crs_config(site_hosts)
    try:
        config.check()
    except CrsUnavailableError:
        return None
    return config


def _open_add_rule(dialog: AddRuleDialog) -> None:
    """Run the Add a rule window. A seam for tests, which cannot answer a modal one."""
    dialog.exec()


def _settings() -> QSettings:
    """Where the window's preferences live — the one place that decides.

    A function rather than the constructor spelled out at each call site, so
    there is a single seam a test can point somewhere harmless. `QSettings`
    resolves to `HKCU\\Software` on Windows, and a suite that wrote real
    preferences onto the machine running it would both dirty that machine and
    read its own leftovers back on the next run.
    """
    return QSettings(*_SETTINGS)


def _whole(phrase: str) -> str:
    """`phrase` as rich text that a wrapping label will not break inside."""
    return phrase.replace(" ", "&nbsp;")


class MainWindow(QMainWindow):
    """Open a case, pick a client, read what it did."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("logarc")
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
        self._reconstruction_request = object()
        self._evidence_request = object()
        # The evidence filter's answer for the canvas: which episodes hold a line
        # it keeps, for which reconstruction and which text. Kept so that a
        # switch between Trace and Behaviour fades the new graph without asking.
        self._fade_request = object()
        self._filter_hits: tuple[AnalysisResult, str, frozenset[str]] | None = None
        # A client opened from a search of requests, to be shown at the first
        # activity holding a match once the canvas knows which those are.
        self._open_first_match: AnalysisResult | None = None
        # What the client box offers after `status:`, `method:` and
        # `activity:`: counted over the range, and named by the finished scan.
        self._range_values: dict[str, list[tuple[str, str]]] = {}
        self._activity_values: list[tuple[str, str]] = []
        self._values_request = object()
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
        self._crs_notice: CrsUnavailable | None = None
        self._site_hosts_offer: SiteHostsOffer | None = None

        self._notice = NoticeBanner()
        # Its own strip rather than a paragraph added to the one above. The two
        # say different things — one that the case is short of its logs, the
        # other that it is complete but was made with a format that has since
        # been edited — and a reader who has taken in the first should be able
        # to dismiss it without losing the second.
        self._format_notice = NoticeBanner()
        # A third, for the same reason: a case checked with an older CRS is
        # complete and intact, and says so with an offer to run CRS again.
        self._older_crs = NoticeBanner()
        # A fourth, about the rules this case was read with: a pack of the
        # reader's that did not load, or rules changed since the case was read.
        self._rules_notice = NoticeBanner()
        self._rules: RuleSet = NO_EXTRA_RULES
        self._built_in_rules: tuple[BuiltInPack, ...] | None = None
        """The reader's rules as last read from their library. Every reading of
        the open case — the client on screen, its report, Where to start — is
        handed these, so the three agree."""
        self._rules_refused: dict[str, str] = {}
        self._rules_stale = False
        self._clients = ClientTable()
        self._triage = TriagePanel()
        self._triage.investigate.connect(lambda ip, refs: self._reconstruct(ip, evidence=refs))
        self._triage.finished.connect(self._scan_finished)
        self._load_generation = 0
        # Set while a CRS decision is outstanding. Enriching reloads the
        # case and restarts the scan from nothing, so a scan begun under
        # an open offer is work the reader would never see.
        self._scan_held = False
        self._canvas = ActivityCanvas()
        self._canvas.set_icons(self._icon_choice())
        self._legend = LegendBar()
        self._canvas.graph_changed.connect(self._show_kinds)
        self._evidence = EvidencePanel()
        self._evidence.filter_changed.connect(self._filter_changed)
        self._clients.client_chosen.connect(self._reconstruct)
        self._clients.client_released.connect(self._release_requested)
        # Counts client-list searches, so an answer for an earlier text, case or
        # range is recognised as stale when it lands.
        self._client_search = 0
        self._clients.filter_edited.connect(self._forget_client_search)
        self._clients.page_requested.connect(self._search_clients)
        self._clients.range_typed.connect(self._move_range)
        self._canvas.node_selected.connect(self._show_evidence)
        # The open case's bookmarks. The keeper owns the file, the save box and
        # the tab's list; the window is handed to it as the one that knows how
        # to open a client, a line or a search, and checks what is still there.
        #
        # Bound methods, never lambdas. PyQt holds a lambda strongly and some of
        # these panels are themselves held from C for good, so a lambda here
        # closing over the window would keep it alive as long as the process
        # runs; `test_window_lifetime` is where that was found.
        self._bookmarks_tab = BookmarksTab()
        self._bookmarks = BookmarkKeeper(self, self._bookmarks_tab, self, say=self._idle)
        self._bookmarks.changed.connect(self._bookmarks_changed)
        self._clients.bookmark_requested.connect(self._bookmark_client)
        self._clients.bookmark_search_requested.connect(self._bookmark_search_from_button)
        self._triage.bookmark_requested.connect(self._bookmark_client)
        self._evidence.bookmark_requested.connect(self._bookmark_activity_from_button)
        self._evidence.bookmark_line_requested.connect(self._bookmark_line)
        self._evidence.make_rule_requested.connect(self._make_rule)

        self._build_layout()
        self._build_menu()
        self._window_controls = install_window_controls(self)
        # What the reader left set at the last launch, put back. The menu used
        # to do this as a side effect of checking its own boxes; with the menu
        # entries gone it is said outright.
        self._restore_preferences()

        # The canvas says what to do; this says what is the case.
        self._status = QLabel("No case open")
        # It repeats what the reader typed, a category's name among it.
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        colour_text(self._status, THEME.muted)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setTextVisible(False)
        self._progress.setFixedSize(320, 16)
        self._progress.setAccessibleName("Loading progress")
        self._progress.setStyleSheet(
            f"QProgressBar {{ background: {THEME.stripe};"
            f" border: 1px solid {THEME.faint}; border-radius: 3px; }}"
            f"QProgressBar::chunk {{ background: {THEME.accent};"
            " width: 64px; }"
        )
        self._progress.hide()
        self._cancel = QPushButton("Cancel")
        self._cancel.hide()
        self._cancel.clicked.connect(self._request_cancel)
        status_bar = required(self.statusBar())
        status_bar.addWidget(self._progress)
        status_bar.addWidget(self._status, 1)
        # The text size after a zoom, for two seconds. Its own permanent label:
        # a status bar message would hide the status line and a scan's progress
        # while it showed, and after a second zoom left them drawn underneath.
        self._zoom_note = QLabel("")
        self._zoom_note_timer = QTimer(self)
        self._zoom_note_timer.setSingleShot(True)
        self._zoom_note_timer.setInterval(2000)
        self._zoom_note_timer.timeout.connect(self._zoom_note.clear)
        status_bar.addPermanentWidget(self._zoom_note)
        status_bar.addPermanentWidget(self._cancel)

    # -- construction ------------------------------------------------------

    def _build_layout(self) -> None:
        # Empty until there is a client to name. What goes here is the subject
        # of the graph below it, and before a case is open the canvas itself is
        # carrying the only instruction the window has to give.
        self._heading = QLabel("")
        self._heading.setTextFormat(Qt.TextFormat.RichText)
        self._heading.setFont(heading_font(self._heading.font()))
        # The heading gives way to the switch beside it, onto a second line,
        # when the graph's column is dragged narrow. Unwrapped it held its
        # width and the switch lost "Behaviour" to two scroll arrows.
        self._heading.setWordWrap(True)

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
        # The switch beside the client it describes, rather than a row of tabs
        # of its own above it: one line says whose graph this is and how it is
        # drawn.
        heading_row = QHBoxLayout()
        heading_row.setContentsMargins(0, 0, 0, 0)
        heading_row.setSpacing(GAP)
        heading_row.addWidget(self._heading, 1)
        heading_row.addWidget(self._tabs)
        column.addLayout(heading_row)
        column.addWidget(self._canvas)
        column.addWidget(self._arrangement_bar)
        self._graph_key = Disclosure("Legend", self._legend)
        column.addWidget(self._graph_key)

        self._workspace = QTabWidget()
        self._workspace.addTab(self._triage, "Triage")
        self._workspace.addTab(centre, "Activity")
        self._workspace.addTab(self._bookmarks_tab, "Bookmarks")
        for index, explained in enumerate(_WORKSPACE_TIPS):
            self._workspace.setTabToolTip(index, explained)
        self._workspace.setCurrentIndex(1)
        splitter = self._build_splitter(self._workspace)
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
        stack.addWidget(self._older_crs)
        stack.addWidget(self._rules_notice)
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
        # Two words, always whole: never scrolled, never elided.
        self._tabs.setUsesScrollButtons(False)
        self._tabs.setElideMode(Qt.TextElideMode.ElideNone)
        # Drawn here rather than left to the style, which had it backwards.
        #
        # Under Fusion in document mode the selected tab takes the page colour
        # and the unselected one takes the button colour. On a light palette
        # those differ and it reads correctly; on this one the page colour is
        # the chrome the bar already sits on, so the selected tab vanished into
        # the background and the *unselected* tab was the one drawn as a raised
        # box. The bar was confidently indicating the view you were not looking
        # at, which is worse than the menu-only state it replaced.
        #
        # Since 2026-10-21 a segmented control: two halves of one outlined pill,
        # the chosen half filled. Tabs read as places to go; this is a way of
        # drawing the same thing, and it now sits on the heading's own row.
        self._tabs.setStyleSheet(f"""
            QTabBar::tab {{
                background: transparent;
                color: {THEME.muted};
                border: 1px solid {THEME.edge};
                padding: 3px {GAP + 2}px;
                margin: 0;
            }}
            QTabBar::tab:first {{
                border-top-left-radius: 4px;
                border-bottom-left-radius: 4px;
            }}
            QTabBar::tab:last {{
                border-top-right-radius: 4px;
                border-bottom-right-radius: 4px;
                border-left: none;
            }}
            QTabBar::tab:hover {{ color: {THEME.ink}; }}
            QTabBar::tab:selected {{ background: {THEME.tint}; color: {THEME.ink}; }}
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

        splitter = PanelSplitter(Qt.Orientation.Horizontal)
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
        # 480 rather than 440: a search adds a Match column, and at 440 it left
        # Last cut to `15…`. The reader can still drag it narrower.
        splitter.setSizes([480, 520, 400])
        return splitter

    def _build_menu(self) -> None:
        menu_bar = required(self.menuBar())
        # New before Open, as in every other application; the longer story of
        # each entry is its status tip, not its name.
        case_menu = required(menu_bar.addMenu("&Case"))
        fresh = self._add(
            case_menu, "&New from logs…", self._ingest_new_case, QKeySequence.StandardKey.New
        )
        fresh.setStatusTip("Read log files into a new case.")
        self._add(case_menu, "&Open…", self._open_case, QKeySequence.StandardKey.Open)
        recently = self._add(case_menu, "Open &recent…", self._show_recent)
        recently.setShortcut(QKeySequence("Ctrl+Shift+O"))
        recently.setStatusTip("Pick up a case opened on this machine before.")
        case_menu.addSeparator()
        self._add(case_menu, "Formats and &rules…", self._manage_formats).setStatusTip(
            "The log formats logarc reads and the rules that say what a line means."
        )
        self._crs_action = self._add(case_menu, "Run &CRS scan", self._run_crs_now)
        self._crs_action.setStatusTip(
            "Replay this case through OWASP CRS now. Stopping keeps what it found."
        )
        case_menu.addSeparator()
        # No shortcut. `StandardKey.Quit` has no binding on Windows and Qt
        # printed it as the word itself, so the entry read "Exit    Exit".
        self._add(case_menu, "E&xit", self.close)

        # What is done to the graph, and the door to the preferences. `Edit`
        # rather than `View` because `Ctrl+Z` is the first thing anyone looks
        # for there, and because it leaves `View` answering one question.
        edit_menu = required(menu_bar.addMenu("&Edit"))

        # Where an activity was dragged to, and how to be rid of it. In the menu
        # with every other control rather than on the canvas: a strip floating
        # over the graph covers a patch of it, has to be moved on every resize,
        # and swallows clicks meant for whatever node is underneath.
        self._undo_action = self._add(edit_menu, "&Undo move", self._arrangements_kept.undo)
        self._undo_action.setShortcut(QKeySequence.StandardKey.Undo)
        self._undo_action.setStatusTip("Put the last activity you moved back where it was.")
        self._save_layout_action = self._add(
            edit_menu, "&Save layout", self._arrangements_kept.save
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
            "Put every activity back where it was laid out, and forget the saved layout."
        )
        self._arrangements_kept.offer(
            self._save_layout_action, self._undo_action, self._reset_layout_action
        )
        self._canvas.arrangement_changed.connect(self._arrangements_kept.refresh)
        self._arrangements_kept.refresh()
        edit_menu.addSeparator()

        # Whatever has the keyboard: a log line, an activity, a client or a
        # search. On the window as well as in the menu, like full screen, so it
        # still answers while the menu bar is hidden.
        self._bookmark_action = self._add(edit_menu, "&Bookmark…", self._bookmark_focused)
        self._bookmark_action.setShortcut(QKeySequence("Ctrl+D"))
        self._bookmark_action.setStatusTip(
            "Save what you are looking at to this case's bookmarks, with a note."
        )
        self.addAction(self._bookmark_action)
        edit_menu.addSeparator()

        preferences = self._add(edit_menu, "&Preferences…", self._show_preferences)
        preferences.setShortcut(QKeySequence("Ctrl+,"))
        preferences.setStatusTip("Change how the graph, the evidence and the launch behave.")

        # One question: what is being shown. It held eleven entries answering
        # four — two switches, four actions, four preferences, and one setting
        # about what happens at launch, which is not a view at all.
        view_menu = required(menu_bar.addMenu("&View"))
        self._trace_action = self._add(view_menu, "&Trace", self._show_trace)
        self._trace_action.setStatusTip("The client's activities in the order they happened.")
        self._behaviour_action = self._add(view_menu, "&Behaviour", self._show_behaviour)
        self._behaviour_action.setStatusTip(
            "Each kind of activity once, with how the client moved between them."
        )
        # One group, so the menu draws them as the single choice they are.
        views = QActionGroup(self)
        views.setExclusive(True)
        for action in (self._trace_action, self._behaviour_action):
            action.setCheckable(True)
            views.addAction(action)
        self._trace_action.setChecked(True)
        view_menu.addSeparator()
        self._timeline_action = self._add(view_menu, "&Timeline", self._timeline_from_menu)
        self._timeline_action.setCheckable(True)
        self._timeline_action.setStatusTip(
            "Show or hide the traffic timeline above the date fields."
        )
        view_menu.addSeparator()
        self._fit_action = self._add(view_menu, "&Fit to window", self._canvas.fit)
        view_menu.addSeparator()
        # The interface text, everywhere but the graph, which zooms with the
        # wheel on its own. On the window too, like full screen below, so the
        # keys still answer when full screen has hidden the menu bar.
        zoom_in = self._add(view_menu, "Zoom &in", lambda: self._zoom_text(1))
        zoom_in.setShortcuts(
            [QKeySequence(QKeySequence.StandardKey.ZoomIn), QKeySequence("Ctrl+=")]
        )
        zoom_out = self._add(view_menu, "Zoom &out", lambda: self._zoom_text(-1))
        zoom_out.setShortcuts([QKeySequence(QKeySequence.StandardKey.ZoomOut)])
        reset = self._add(view_menu, "&Reset zoom", self._reset_text_zoom)
        reset.setShortcut(QKeySequence("Ctrl+0"))
        self._zoom_actions = (zoom_in, zoom_out, reset)
        for action in self._zoom_actions:
            action.setStatusTip(
                "Make the interface text larger or smaller. The graph zooms with the mouse wheel."
            )
            self.addAction(action)
        self._enable_zoom(QApplication.font().pointSizeF())
        running = QApplication.instance()
        if isinstance(running, QApplication):
            CtrlWheel(running, self, skip=self._canvas).stepped.connect(self._zoom_text)
        view_menu.addSeparator()
        self._fullscreen_action = self._add(view_menu, "F&ull screen", self._fullscreen_from_menu)
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
        # One entry per rule, filled when the menu opens: a right-click selects
        # the activity under it first, so the rules are that activity's. They
        # are the names its evidence panel lists under "Matched by", because a
        # node can carry several and only the reader knows which one they mean.
        self._who_else_menu = QMenu("Who else did this?", self)
        self._who_else_menu.aboutToShow.connect(self._fill_who_else)
        self._who_else_dialog: WhoElseDialog | None = None
        about_this = QAction(self._canvas)
        about_this.setSeparator(True)
        # Its own action rather than the Edit menu's: that one bookmarks
        # whatever has the keyboard, and a right-click means the activity under
        # the pointer. No shortcut, or Ctrl+D would belong to two actions and
        # Qt would run neither.
        self._bookmark_node_action = QAction("Bookmark this activity…", self)
        self._bookmark_node_action.triggered.connect(self._bookmark_node)
        self._canvas.addActions(
            [
                self._bookmark_node_action,
                required(self._who_else_menu.menuAction(), "action"),
                about_this,
                self._save_layout_action,
                self._undo_action,
                self._reset_layout_action,
                on_the_canvas,
                self._fit_action,
            ]
        )
        self._canvas.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)

        export_menu = required(menu_bar.addMenu("&Export"))
        # What each writes, then the file it writes it as.
        self._add(export_menu, "&Report (HTML)…", lambda: self._export("html")).setStatusTip(
            "A self-contained report of the client on screen, with its evidence."
        )
        self._add(export_menu, "&Graph (JSON)…", lambda: self._export("json")).setStatusTip(
            "The client's activity graph as data."
        )
        self._add(export_menu, "&Image (PNG)…", lambda: self._export("png")).setStatusTip(
            "A picture of the graph as it is drawn now."
        )
        export_menu.addSeparator()
        self._add(export_menu, "&Bookmarks (CSV)…", self._export_bookmarks).setStatusTip(
            "Write every bookmark in this case to a CSV file, with its note and log line."
        )

        help_menu = required(menu_bar.addMenu("&Help"))
        guide = self._add(help_menu, "&User guide", open_user_guide)
        guide.setShortcut(QKeySequence("F1"))
        guide.setStatusTip("Open the desktop guide in your browser.")
        self._add(help_menu, "&Keyboard shortcuts", self._show_shortcuts).setStatusTip(
            "Every key the menus answer to."
        )
        help_menu.addSeparator()
        self._add(help_menu, "&About logarc", self._show_about)

    def _show_shortcuts(self) -> None:
        show_shortcuts(self, required(self.menuBar()))

    def _show_about(self) -> None:
        show_about(self)

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
        chosen = QFileDialog.getExistingDirectory(self, "Open case folder")
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
            report(f"Reading {plural(len(paths), 'file')}…")
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
        self._busy(f"Reading logs into {case_dir}…", stop=stop)
        run_job(
            work,
            on_done=lambda outcome: self._ingest_finished(case_dir, outcome),
            on_error=self._ingest_failed,
            on_progress=self._status.setText,
            on_advance=self._show_ingest_progress,
        )

    def _manage_formats(self) -> None:
        """Open the formats and rules dialog on its formats tab."""
        self._formats_and_rules(on_rules=False)

    def _manage_rules(self) -> None:
        """Open the formats and rules dialog on its rules tab."""
        self._formats_and_rules(on_rules=True)

    def _formats_and_rules(self, *, on_rules: bool) -> None:
        """Modal, and nothing is applied on the way out: each tab writes what the
        reader saved as they save it, so there is no pending state for closing
        the window to discard or apply by accident.

        A rules change with a case open is asked about inside the dialog. One
        the reader put off is the strip's to say."""
        dialog = FormatsAndRules(self, case_path=self._case_path, on_rules=on_rules)
        dialog.rules.read_again.connect(self._read_again_with_new_rules)
        dialog.exec()
        if dialog.rules.stale:
            self._rules_changed()

    def _make_rule(self, line: EvidenceLine) -> None:
        """The Add a rule window, started from a line of the client on show.

        The window asks Re-read now or Later itself; both answers come here.
        """
        if self._built_in_rules is None:
            # About 170 ms, so loaded once, on first use rather than at start.
            self._built_in_rules = built_in_packs()
        dialog = AddRuleDialog(
            self,
            case_path=self._case_path,
            library=rules_library.in_force(built_in=self._built_in_rules),
            built_in=self._built_in_rules,
            line=line,
        )
        dialog.read_again.connect(self._read_again_with_new_rules)
        dialog.later.connect(self._rules_changed)
        _open_add_rule(dialog)

    def _read_again_with_new_rules(self) -> None:
        """Re-read after a rules change. Stale until the new rules have loaded, so
        a library that fails to load leaves the strip saying so."""
        self._rules_changed()
        self._read_again()

    def _rules_changed(self) -> None:
        """The reader's rules changed, and the open case was read with the old ones."""
        if self._case_path is None:
            return
        self._rules_stale = True
        self._say_rules()

    def _say_rules(self) -> None:
        """The rules strip: rules changed since the case was read, a pack of the
        reader's that did not load, or nothing. The first is the one to act on."""
        if self._case_path is None:
            self._rules_notice.show_notice(None)
        elif self._rules_stale:
            self._rules_notice.show_notice(
                rules_changed_notice(), action=("Re-read", self._read_again)
            )
        elif self._rules_refused:
            self._rules_notice.show_notice(
                packs_refused_notice(self._rules_refused),
                action=("Formats and rules…", self._manage_rules),
            )
        else:
            self._rules_notice.show_notice(None)

    def _read_again(self) -> None:
        """Read the open case again with the rules in the reader's library now:
        the client on screen, and Where to start."""
        path = self._case_path
        if path is None:
            return

        def done(library: rules_library.Library) -> None:
            if path != self._case_path:
                return
            self._take_rules(library)
            self._triage.start(path, self._window, self._rules)
            if self._result is not None:
                self._reconstruct(self._result.client_ip)

        run_job(
            # The library is files on disk, and checking it builds every rule.
            lambda _report: rules_library.in_force(),
            on_done=done,
            on_error=self.report_error,
        )

    def _take_rules(self, library: rules_library.Library) -> None:
        self._rules = library.ruleset
        self._rules_refused = library.refused
        self._rules_stale = False
        self._say_rules()
        # The icons the reader's rules name follow their rules at once, though
        # the case read with the old ones still waits for Re-read: an icon is
        # not a finding.
        self._canvas.set_icons(self._icon_choice())
        self._show_kinds()

    def _show_kinds(self) -> None:
        """The legend's kinds: those on the canvas now, in the icons in force."""
        self._legend.show_kinds(self._canvas.kinds_on_show, self._canvas.icons)

    def _icon_choice(self) -> IconChoice:
        """The icons in force: the reader's for each kind, and their rules'."""
        return IconChoice(kinds=read_kind_icons(_settings().value), rules=rule_icons(self._rules))

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
            # Asked *before* the case is opened, not alongside it. `_load_case`
            # reads the same store on a worker, and `suggest_site_hosts` reads
            # it here — two readers on one case, which cost this test its
            # `_case_path` and reported no error while doing it. Serialised, the
            # answer is also in hand before the view is built, so the findings
            # it unlocks are on screen the first time rather than after a
            # reload.
            self._ask_site_hosts(case_dir)
            return

        self._idle(f"Stopped after {outcome.lines_read:,} lines.")
        QMessageBox.information(
            self,
            "Reading stopped",
            f"Stopped after {outcome.lines_read:,} lines.\n\n"
            f"{case_dir} holds a partial case that cannot be analysed. It is left in "
            "place; delete the folder to start over.",
        )

    # -- the site's own domains, asked once and only where it matters --------

    def _ask_site_hosts(self, case_dir: Path) -> None:
        """Put the domain question, then hand over to the CRS one either way.

        Chained rather than shown alongside: both arrive at the end of the same
        ingest and both are modal, so together they would stack. This one goes
        first because it is instant and CRS can start a five-minute job — a
        reader should finish answering before anything begins running.

        It is skipped entirely unless the case holds requests that pass URLs
        around, which most do not. A prompt that changes nothing is the kind
        people learn to dismiss without reading, and then dismiss the one that
        mattered.
        """
        if str(_settings().value(_SITE_HOSTS_KEY, "") or "") == "never":
            self._open_and_start_crs(case_dir)
            return

        try:
            with Case.open(case_dir) as opened:
                suggestion = opened.suggest_site_hosts()
        except (CaseError, OSError):
            # Not worth a dialog of its own: opening the case is the very next
            # thing that happens, and it reports its own failures properly.
            self._open_and_start_crs(case_dir)
            return

        if not suggestion.worth_asking:
            self._open_and_start_crs(case_dir)
            return

        offer = SiteHostsOffer(suggestion, self)
        # Held on the window rather than only in the closure, for the reason
        # `_crs_offer` is: a dialog whose last Python reference is a lambda
        # argument is collectable the moment this method returns.
        self._site_hosts_offer = offer
        offer.finished.connect(lambda result: self._site_hosts_answered(case_dir, result))
        offer.show()

    def _site_hosts_answered(self, case_dir: Path, result: int) -> None:
        """Save the answer to the case, reload, then ask about CRS.

        Skipping writes nothing at all. A case that was skipped and one that was
        never asked have to read the same on disk, because `rfi_offsite_url`
        treats both as "say nothing" and no rule should behave differently for a
        question that was declined than for one never put.
        """
        offer, self._site_hosts_offer = self._site_hosts_offer, None
        if offer is None:
            return

        if result == QDialog.DialogCode.Accepted and offer.answer():
            try:
                with Case.open(case_dir) as opened:
                    opened.set_site_hosts(offer.answer())
            except (CaseError, OSError) as exc:
                self.report_error("The domains could not be saved.", str(exc))

        if offer.remembered():
            _settings().setValue(_SITE_HOSTS_KEY, "never")

        self._open_and_start_crs(case_dir)

    def _open_and_start_crs(self, case_dir: Path) -> None:
        """Every way out of the domain question ends here.

        One place rather than five returns each remembering to do both, because
        forgetting either is silent: a case that never opens, or a case CRS
        never reads.
        """
        self._load_case(case_dir, hold_scan=True)
        if not self._start_crs(case_dir):
            self._release_scan()

    # -- CRS, run once a scan has something to enrich ------------------------

    def _release_scan(self) -> None:
        """Start the scan the CRS question was holding back.

        Called once no decision can invalidate a scan any more. Safe before the
        case has finished loading: clearing the flag is enough, because
        `_load_case` starts the scan itself when its own read comes back.

        Only a scan that was held is started. A CRS run asked for from the Case
        menu held nothing — the case was already open and scanned — and a
        failure there restarting the scan would clear Where to start and redo
        work that was already on screen.
        """
        held, self._scan_held = self._scan_held, False
        if held and self._case_path is not None:
            self._triage.start(self._case_path, self._window, self._rules)

    def _start_crs(self, case_dir: Path) -> bool:
        """Run CRS on a case that has just been read, unless it is turned off.

        True when a run started, and the scan it holds back is now its to
        release. Availability is checked first, so that somebody without the
        sidecar is told their case is complete rather than shown a card that
        fails.
        """
        if not self._prefs[prefs.RUN_CRS] or not runs_by_default():
            return False

        try:
            SidecarConfig().check()
        except CrsUnavailableError as exc:
            if str(_settings().value(_CRS_KEY, "") or "") != "quiet":
                self._crs_missing(str(exc))
            # No enrichment can follow, so nothing will invalidate a scan
            # and the caller need not hold one back behind this notice.
            return False

        self._run_crs(case_dir)
        return True

    def _run_crs_now(self) -> None:
        """CRS on the open case, because the reader asked for it.

        Neither switch applies: the preference and `LOGARC_CRS` decide the run
        nobody asked for, and this one was asked for. For the same reason a
        missing sidecar is said even when its notice was silenced — that
        silenced the notice after a scan, not the answer to a question.
        """
        if self._case_path is None:
            self._status.setText("Open a case first.")
            colour_text(self._status, THEME.muted)
            return
        try:
            SidecarConfig().check()
        except CrsUnavailableError as exc:
            self._crs_missing(str(exc))
            return
        self._run_crs(self._case_path)

    def _crs_missing(self, reason: str) -> None:
        told = CrsUnavailable(reason, self)
        # Held on the window, not only in the closure: a dialog whose last
        # Python reference is a lambda argument is collectable the moment this
        # method returns, and it is `show()` rather than `exec()` precisely so
        # that this method does return.
        self._crs_notice = told
        told.finished.connect(lambda _result: self._crs_missing_closed())
        told.show()

    def _crs_missing_closed(self) -> None:
        told, self._crs_notice = self._crs_notice, None
        if told is not None and told.remembered():
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
        """Say that CRS did not finish, in words a reader can act on.

        In this order: it did not finish; why, in a line; that the case is as
        it was; how to try again. The job's message is `Type: reason`, and the
        type is the program talking to itself. Whatever the sidecar printed is
        in `detail`, behind Show Details: on 2026-10-15 a Go panic was the whole
        of this dialog's text and ran off the bottom of the screen.
        """
        self._close_crs_card()
        reason = message.partition(": ")[2] or message
        self.report_error(
            "CRS did not finish.",
            detail,
            explanation=(
                f"{reason}\n\nNothing in the case was changed, and everything else in it "
                "works. To try again: Case → Run CRS scan."
            ),
        )
        # The case is as it was before CRS started, and complete. Without this
        # the scan CRS was holding back never ran, and Where to start stayed
        # empty — once rare, then every case's fate the day CRS became the
        # default and a sidecar broke.
        self._release_scan()

    def _crs_finished(self, case_dir: Path, outcome: object) -> None:
        """Reload, so the findings CRS added are the ones on screen.

        A case is reopened rather than patched in place: the enrichment was
        written to the case by the engine, and re-reading is the only way the
        window is showing what the case holds rather than what it remembers.
        """
        self._close_crs_card()
        if not isinstance(outcome, EnrichOutcome):
            self._release_scan()
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

    def _name_the_window(self, path: Path | None) -> None:
        """`<case> — logarc`, the case called what the recent list calls it."""
        entry = next((e for e in self._recent_cases() if path and e.path == str(path)), None)
        self.setWindowTitle(f"{entry.display_name} — logarc" if entry else "logarc")

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
                self._idle("Recent cases list cleared.")

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

    def _load_case(self, path: Path, *, hold_scan: bool = False) -> None:
        self._forget_client_search()
        self._load_generation += 1
        generation = self._load_generation
        self._scan_held = hold_scan
        self._triage.shutdown()
        self._awaiting = None
        self._evidence_request = object()
        self._case_path = None
        # Named again only once this one has opened: a title still naming the
        # last case would claim it is the one on screen.
        self._name_the_window(None)
        self._evidence.clear(prompt=False)
        # The last case's bookmarks go now, not when this one arrives: until
        # then nothing on screen may carry a ribbon from another case.
        self._bookmarks.load(None)
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
            # Here too: it reads the CRS configuration files and the ruleset's
            # revision, and checks the sidecar is there to run again.
            older = stale_crs_notice(
                manifest.config if view.crs.fingerprint is not None else None,
                _crs_config_now(manifest.config.get(Case.SITE_HOSTS_KEY) or ()),
            )
            # The reader's rules, read here for the reason the format library is:
            # they are files on disk. Every reading of this case is handed them.
            library = rules_library.in_force()
            return view, snapshot, notice, drifted, older, library

        self._busy(f"Opening {path}…")

        def done(loaded: Any) -> None:
            if generation != self._load_generation:
                return
            view, snapshot, notice, drifted, older, library = loaded
            summaries = view.listed
            self._remember_case(snapshot)
            self._name_the_window(path)
            self._time_filter.set_case_open(True)
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
            self._forget_filter()
            self._selected = None
            self._canvas.show_graph_placeholder()
            # The canvas already says "Select an IP". Repeating it above the
            # canvas and inviting an activity selection beside it made three
            # messages for one state, two of them about steps that cannot be
            # taken yet.
            self._evidence.clear(prompt=False)
            self._notice.show_notice(notice, quarantine_dir=path / QUARANTINE_DIR)
            # No quarantine folder: nothing was refused. Passing one would offer
            # a button that opens a directory holding nothing to do with this.
            self._format_notice.show_notice(drifted)
            # Looked up when pressed, not bound now, so the button always runs
            # what the window would run from the Case menu.
            self._older_crs.show_notice(
                older, action=("Run CRS again", lambda: self._run_crs_now())
            )
            self._take_rules(library)
            self._heading.setText("")
            self._tabs.setVisible(False)
            self._clients.show_clients(summaries, total=view.whole.clients)
            self._clients.set_open_client(None)
            self._bookmarks.load(path)
            self._activity_values = []
            self._count_values()
            self._workspace.setCurrentIndex(0)
            if not self._scan_held:
                self._triage.start(path, rules=self._rules)
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

        run_job(
            work,
            on_done=done,
            on_error=lambda message, detail: (
                self.report_error(message, detail) if generation == self._load_generation else None
            ),
            on_progress=lambda message: (
                self._status.setText(message) if generation == self._load_generation else None
            ),
        )

    # -- the stretch of time being read ------------------------------------

    def _apply_window(
        self, window: TimeWindow, *, carry: bool = False, then: Callable[[], None] | None = None
    ) -> None:
        """Read the case over a different stretch of time.

        Both halves, always. Narrowing only the graph leaves the client row
        saying 19 requests beside a heading saying 16 — two numbers for one
        thing on one screen, which is the failure this feature was shaped
        around.

        `carry` when the client box's `after:` or `before:` moved it: the rest
        of the box goes back once the new range is listed, as it stands then.

        `then` runs once the new range is listed, or at once when `window` is
        already the range. Opening a bookmark asks for a range and for something
        to do in it, and the second must not run against the first's list.
        """
        if self._case_path is None:
            return
        if window == self._window:
            if then is not None:
                then()
            return
        self._forget_client_search()
        self._load_generation += 1
        generation = self._load_generation
        self._evidence_request = object()
        self._evidence.clear(prompt=False)
        self._window = window
        self._activity_values = []
        self._triage.start(self._case_path, window, self._rules)
        self._count_values()
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
            if generation != self._load_generation:
                return
            summaries = loaded.listed
            # What the range holds, not what fitted in the table.
            self._listed = loaded.in_range
            # `show_clients` is silent for the whole rebuild — the table owns
            # that, because it is the one that knows when it is replacing its
            # own furniture. This used to block the signals from out here, which
            # left two mechanisms for one rule.
            kept = self._clients.query_without_times() if carry else ""
            self._clients.show_clients(summaries, total=self._all_clients)
            if kept:
                self._clients.set_query(kept)
            self._say_what_is_left()
            if not summaries:
                # An answer, not a failure, and often the one being looked for.
                self._result = None
                self._forget_filter()
                self._selected = None
                self._evidence.clear(prompt=False)
                self._tabs.setVisible(False)
                self._heading.setText("")
                self._canvas.show_graph_placeholder(nobody_here(window))
                self._idle(nobody_here(window))
            else:
                self._idle(f"{self._listed:,} of {self._all_clients:,} clients in this range")
                # The client the reader was on, if this range still holds them.
                # The table has been rebuilt, so the selection has to be found
                # again.
                if self._result is not None:
                    self._reselect(self._result.client_ip)
            # Last, so a reconstruction it asks for supersedes the one above.
            if then is not None:
                then()

        run_job(
            work,
            on_done=done,
            on_error=lambda message, detail: (
                self.report_error(message, detail) if generation == self._load_generation else None
            ),
            on_progress=lambda message: (
                self._status.setText(message) if generation == self._load_generation else None
            ),
        )

    def _say_what_is_left(self, result: AnalysisResult | None = None) -> None:
        """The line beside the control: what the range left of the case.

        Both counts once a client is reconstructed, so one line carries the two
        numbers that have to agree — what the range did to the list, and what it
        did to the graph.
        """
        if self._window.is_open:
            # Nothing to add at All time: the fields show the whole span and the
            # button is named for it. "whole case" stood alone at the far right.
            self._time_filter.say("")
            return
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
        self._forget_filter()
        self._clients.set_open_client(None)
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

    def _forget_client_search(self) -> None:
        """Make any client-list search still running answer to nobody."""
        self._client_search += 1

    def _search_clients(self, query: str, offset: int) -> None:
        """Answer the client list's request for one page of the case or of a search.

        Over the range in force, so a page or a search describes the same clients
        the unfiltered list does. One address is looked up as it always was, a
        complete one exactly; anything else is a search of the clients' requests,
        narrowed to the clients the scan saw an `activity:` on.
        """
        if self._case_path is None:
            return
        self._client_search += 1
        generation = self._client_search
        path, window = self._case_path, self._window
        narrowed = window is not None and not window.is_open
        wanted = parse(query, Scope.CASE, day=self._first_day())
        index = self._triage.result
        if wanted.activities and index is None:
            # Asked again by `_scan_finished`, so the reader need not.
            self._clients.show_pending(
                query, awaiting_scan(self._triage.progress, scanning=self._triage.scanning)
            )
            return
        single = wanted.is_empty or (wanted.is_address_only and len(wanted.ips) == 1)

        def work(_: Callable[[str], None]) -> IpSummaryPage | ClientMatchPage:
            with Case.open(path) as case:
                if single:
                    address = wanted.ips[0] if wanted.ips else ""
                    return case.store.ip_summary_page(
                        query=address,
                        offset=offset,
                        limit=ClientTable.PAGE_SIZE,
                        window=window if narrowed else None,
                        exact=is_whole_address(address),
                    )
                clients: frozenset[str] | None = None
                if wanted.activities and index is not None:
                    labels = read_labels(index.path)
                    rules = frozenset().union(
                        *(labels_for_activity(labels, value) for value in wanted.activities)
                    )
                    clients = read_activity_clients(index.path, rules)
                page = case.store.search_clients(
                    wanted,
                    offset=offset,
                    limit=ClientTable.PAGE_SIZE,
                    window=window if narrowed else None,
                    clients=clients,
                )
            if wanted.is_address_only:
                # Several addresses are still an address search, listed and
                # captioned as one: busiest first, no Match column.
                return IpSummaryPage(page.rows, page.total, page.offset)
            return page

        def done(page: IpSummaryPage | ClientMatchPage) -> None:
            if generation != self._client_search:
                return
            if isinstance(page, ClientMatchPage):
                self._clients.show_matches(page, query, counted=wanted.has_request_filters)
            else:
                self._clients.show_page(page, query)

        def failed(message: str, detail: str) -> None:
            if generation == self._client_search:
                self._clients.show_failure(query, message)

        run_job(work, on_done=done, on_error=failed)

    def _first_day(self) -> date | None:
        """The day a time of day typed in the client box is read on: the range's first."""
        if self._window.start is not None:
            return self._window.start.date()
        span = self._time_filter.span
        return span[0].date() if span is not None else None

    def _move_range(self, times: str) -> None:
        """`after:` and `before:` finished in the client box: move the range to them.

        The rest of the box is searched again once the new range is listed. A
        range that would end before it starts is refused where it was typed,
        and the range stays as it was.
        """
        span = self._time_filter.span
        if self._case_path is None or span is None:
            return
        asked = parse(times, Scope.CASE, day=self._first_day())
        start = asked.after if asked.after is not None else self._window.start
        end = asked.before - _JUST_BEFORE if asked.before is not None else self._window.end
        try:
            window = TimeWindow(start, end).clamped_to(*span)
        except ValueError:
            self._clients.show_failure(
                self._clients.query_text(), "the range would end before it starts"
            )
            return
        # The whole case is said as an open range, as the date fields say it.
        if window == TimeWindow(*span):
            window = EVERYTHING
        if window == self._window:
            self._clients.set_query(self._clients.query_without_times())
            return
        self._apply_window(window, carry=True)

    def _count_values(self) -> None:
        """Count what the client box offers after `status:` and `method:`, over the range."""
        self._range_values = {}
        self._offer_values()
        path, window = self._case_path, self._window
        if path is None:
            return
        self._values_request = request = object()

        def work(_: Callable[[str], None]) -> dict[str, list[tuple[str, int, int]]]:
            with Case.open(path) as case:
                return case.store.value_counts(window=None if window.is_open else window)

        def done(counted: dict[str, list[tuple[str, int, int]]]) -> None:
            if request is not self._values_request or path != self._case_path:
                return
            self._range_values = {
                key: [
                    (value, f"{plural(clients, 'client')} \u00b7 {plural(requests, 'request')}")
                    for value, clients, requests in rows
                ]
                for key, rows in counted.items()
            }
            self._offer_values()

        # Without them the box still searches; it only has fewer values to offer,
        # and a search that cannot run says so where it was typed.
        run_job(work, on_done=done, on_error=lambda _message, _detail: None)

    def _offer_values(self) -> None:
        values = {**self._range_values, "activity": self._activity_values}
        title = "VALUES IN THE CASE" if self._window.is_open else "VALUES IN THIS RANGE"
        self._clients.set_suggestion_values(values, title)

    def _scan_finished(self) -> None:
        """The scan has an answer: offer its activities, and answer a search waiting on it."""
        index = self._triage.result
        if index is None:
            return
        path = index.path

        def work(_: Callable[[str], None]) -> list[tuple[str, int]]:
            return read_activity_counts(path)

        def done(counts: list[tuple[str, int]]) -> None:
            if self._triage.result is index:
                self._activity_values = [
                    (name, plural(clients, "client")) for name, clients in counts
                ]
                self._offer_values()

        run_job(work, on_done=done, on_error=lambda _message, _detail: None)
        if parse(self._clients.query_text(), Scope.CASE).activities:
            self._clients.search_again()

    # -- reconstruction ----------------------------------------------------

    def _reconstruct(
        self,
        client_ip: str,
        *,
        evidence: tuple[EvidenceRef, ...] = (),
        activity_of: EvidenceRef | None = None,
        note: str = "",
    ) -> None:
        """Read `client_ip` over the range in force, and draw it.

        `evidence` shows the activity holding those lines with them first;
        `activity_of` shows the activity holding that one line, as it comes.
        `note` is said after the line that says what was read.
        """
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
        self._clients.set_open_client(client_ip)
        path = self._case_path
        # Read once here, on the interface thread, rather than from inside the
        # worker: the job must not reach back into window state while the window
        # is free to change it.
        crs = self._crs
        window = self._window
        rules = self._rules
        buckets = self._buckets()
        # The requests a search found this client by, if one did: a new
        # client is read through the same filter.
        carried = evidence_part(self._clients.query_text())
        self._awaiting = (client_ip, window)
        self._reconstruction_request = request = object()

        def current() -> bool:
            return (
                request is self._reconstruction_request
                and path == self._case_path
                and (client_ip, window) == self._awaiting
            )

        def work(report: Callable[[str], None]) -> tuple[AnalysisResult, list[TimeSlot]]:
            report(f"Opening {client_ip}…")
            result = reconstruct_client(path, client_ip, crs, window=window, rules=rules)
            # This client's own traffic, across its own life — not the range in
            # force. Built from the reconstruction it would only ever cover that
            # range, so the whole band would be lit and there would be nothing
            # to see outside the selection, which is the one thing a reader
            # needs to see. Measured at 0.037s, and it does not grow with the
            # case: three million events came back in 0.039s.
            with Case.open(path) as case:
                return result, case.store.activity_over_time(buckets=buckets, client_ip=client_ip)

        self._busy(f"Opening {client_ip}…")

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
            if not current() or (result.client_ip, result.window) != (client_ip, window):
                return
            if self._result is None or self._result.client_ip != result.client_ip:
                self._forget_filter()
                if carried:
                    self._evidence.set_filter_text(carried)
                    # Lines asked for by name are shown instead, below.
                    asked = evidence or activity_of is not None
                    self._open_first_match = None if asked else result
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
                f'<span style="font-family:{_MONO_CSS};color:{THEME.identity}">'
                f"<b>{result.client_ip}</b></span>"
                # Normal weight, explicitly: the label itself is set in the
                # heading face, which is DemiBold, and without this the counts
                # carry the same emphasis as the address they belong to.
                # Each count is one unbreakable piece, so a narrow column
                # wraps the heading between counts and never between a
                # number and its noun.
                f'<span style="color:{THEME.muted};font-weight:normal">&nbsp; '
                f"{_whole(format_requests(result.request_count))}"
                f" · {_whole(plural(len(result.sessions), 'session'))}"
                f" · {_whole(plural(len(result.episodes), 'activity', 'activities'))}</span>"
            )
            self._redraw()
            self._workspace.setCurrentIndex(1)
            # This client's bookmarked lines, ribboned through every refill.
            self._evidence.set_marks(self._bookmarks.line_marks(result.client_ip))
            held = evidence or ((activity_of,) if activity_of is not None else ())
            if held:
                self._show_holding(result, held, evidence=evidence)
            self._say_what_is_left(result)
            read = f"{client_ip}: {plural(len(result.episodes), 'activity', 'activities')}"
            self._idle(f"{read}. {note}" if note else read)

        run_job(
            work,
            on_done=done,
            on_error=lambda message, detail: (
                self.report_error(message, detail) if current() else None
            ),
            on_progress=lambda message: self._status.setText(message) if current() else None,
        )

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
        self._canvas.show_graph(
            graph,
            positions=self._arrangements_kept.saved_positions(),
            session_policy=self._result.policy.session,
        )
        self._mark_graph()
        self._arrangements_kept.refresh()
        self._refade()
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

    def _fullscreen_from_menu(self) -> None:
        self._workspace.setCurrentIndex(1)
        self._full_screen.from_the_menu()

    def _what_to_cover(self) -> list[QWidget | None]:
        """Everything the graph takes the screen from.

        Named by the window rather than known by `FullScreen`, because these are
        the window's widgets. `menuBar` and `statusBar` are asked for at the
        moment of covering rather than held: they are methods, and Qt is free to
        answer with something else.
        """
        return [
            self._workspace.tabBar(),
            self._clients,
            self._evidence,
            self._time_filter,
            self._notice,
            self._format_notice,
            self._older_crs,
            self._tabs,
            self._heading,
            self._graph_key,
            self.menuBar(),
            self.statusBar(),
        ]

    def changeEvent(self, event: QEvent | None) -> None:  # noqa: N802 - Qt's naming
        """Coming back to the window reads the bookmarks again.

        Another window on the same case may have saved some meanwhile; the keeper
        redraws only when the file says something it is not already showing.
        """
        if event is not None and event.type() == QEvent.Type.ActivationChange:
            self._bookmarks.refresh()
        super().changeEvent(event)

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
        self._apply_sessions(bool(self._prefs["view/session_boxes"]))
        self._apply_band(bool(self._prefs["view/traffic_band"]))
        self._apply_evidence_view(bool(self._prefs["view/decode_targets"]))
        self._evidence.set_fold_rule(prefs.fold_rule_in(self._prefs))

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

    def _apply_preferences(self, chosen: dict[str, prefs.Value]) -> None:
        """Put every setting in force and write them all down.

        All of them together rather than one signal each: they are decided in
        one go now, and applying them one at a time was how the window and the
        menu came to hold two copies of the same answer.
        """
        self._prefs = dict(chosen)
        self._apply_wrap(bool(chosen["view/wrap_traces"]))
        self._apply_sessions(bool(chosen["view/session_boxes"]))
        self._apply_band(bool(chosen["view/traffic_band"]))
        self._apply_evidence_view(bool(chosen["view/decode_targets"]))
        self._evidence.set_fold_rule(prefs.fold_rule_in(chosen))
        self._apply_density(prefs.density_in(chosen))
        # Carried across rather than read by the keeper on every ask. It holds
        # this as a plain attribute, so without this line the switch goes one
        # way only: off from the dialog, and never back on from Preferences.
        self._arrangements_kept.ask_before_leaving = bool(chosen[prefs.ASK_UNSAVED_ARRANGEMENT])
        prefs.write(_settings().setValue, self._prefs)

    def _apply_band(self, showing: bool) -> None:
        """Draw the traffic above the fields, or stop drawing it."""
        self._time_filter.show_band(showing)
        # The action uses triggered, so synchronizing its check does not apply
        # or save the preference again.
        self._timeline_action.setChecked(showing)

    def _zoom_text(self, by: int) -> None:
        """One zoom step: `by` is +1 or -1, from the keys, the View menu or Ctrl+wheel."""
        self._set_text_points(stepped(QApplication.font().pointSizeF(), by))

    def _reset_text_zoom(self) -> None:
        """Back to the size logarc picks for this desktop, and keep picking it.

        Both saved sizes are forgotten rather than the automatic one written
        down, so a later desktop with more or less room starts at its own size.
        """
        running = QApplication.instance()
        if isinstance(running, QApplication):
            self._set_text_points(automatic_points_for(running), remember=False)
            stored = _settings()
            stored.remove(prefs.TEXT_POINTS)
            stored.remove(prefs.LEGACY_TEXT_SIZE)

    def _set_text_points(self, points: float, *, remember: bool = True) -> None:
        """Put a text size in force in every window, remember it, and say so briefly."""
        running = QApplication.instance()
        if not isinstance(running, QApplication):
            return
        chosen = set_text_points(running, points)
        for window in QApplication.topLevelWidgets():
            if isinstance(window, MainWindow):
                window._follow_text_size(chosen)
        if remember:
            _settings().setValue(prefs.TEXT_POINTS, int(chosen))
        self._zoom_note.setText(f"Text {int(chosen)} pt")
        self._zoom_note_timer.start()

    def _follow_text_size(self, points: float) -> None:
        self._evidence.follow_text_size()
        self._enable_zoom(points)

    def _enable_zoom(self, points: float) -> None:
        zoom_in, zoom_out, _reset = self._zoom_actions
        zoom_in.setEnabled(points < MAX_POINTS)
        zoom_out.setEnabled(points > MIN_POINTS)

    def _timeline_from_menu(self) -> None:
        """Use the same saved choice as the Preferences dialog."""
        self._apply_preferences(
            {**self._prefs, "view/traffic_band": self._timeline_action.isChecked()}
        )

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

    def _apply_sessions(self, shown: bool) -> None:
        """Box each session on the trace, or stop.

        A behaviour map has no sessions to box, so this decides nothing while
        one is on screen; the choice holds for the trace when it comes back.
        """
        self._canvas.set_sessions(shown)

    def _apply_evidence_view(self, decode: bool) -> None:
        """How targets are shown in the evidence panel.

        The `Show raw log lines` toggle that used to live beside this is gone:
        the detail pane prints the original line for the selected row always,
        which is strictly more than a global on-or-off could give.
        """
        self._evidence.set_decode(decode)

    # -- evidence ----------------------------------------------------------

    def _fill_who_else(self) -> None:
        self._who_else_menu.clear()
        node = self._selected
        if node is None or not node.rule_ids:
            required(
                self._who_else_menu.addAction("Select an activity first"), "action"
            ).setEnabled(False)
            return
        # Named as the evidence panel's activity is, with the id on hover for a
        # reader who searches by it. An id with no label in this result is
        # still offered, by its id.
        names = rule_names(self._result) if self._result is not None else {}
        for rule_id in node.rule_ids:
            action = required(self._who_else_menu.addAction(names.get(rule_id, rule_id)), "action")
            action.setToolTip(rule_id)
            action.triggered.connect(lambda _checked=False, rule=rule_id: self._who_else(rule))

    def _who_else(self, rule_id: str) -> None:
        """List the other clients `rule_id` matched, from the finished scan's index."""
        if self._result is None:
            return
        client_ip = self._result.client_ip
        name = rule_names(self._result).get(rule_id, rule_id)
        if self._who_else_dialog is None:
            self._who_else_dialog = WhoElseDialog(self)
            self._who_else_dialog.open_client.connect(self._reconstruct)
            self._who_else_dialog.bookmark_requested.connect(self._bookmark_client)
        dialog = self._who_else_dialog
        index = self._triage.result
        if index is None:
            dialog.show_unavailable(
                name, unavailable(self._triage.progress, scanning=self._triage.scanning)
            )
        else:
            path = index.path
            dialog.show_unavailable(name, "Looking up other clients…")

            def work(_: Callable[[object], None]) -> Any:
                return read_rule_matches(path, rule_id)

            def done(matches: Any) -> None:
                # The range can move while this runs, and a new scan replaces
                # the index; an answer from the old one is about other traffic.
                if self._triage.result is index:
                    dialog.show_matches(rule_id, matches, client_ip=client_ip, name=name)

            def failed(message: str, _detail: str) -> None:
                if self._triage.result is index:
                    dialog.show_unavailable(name, f"Could not read the scan's results: {message}.")

            run_job(work, on_done=done, on_error=failed)
        dialog.show()
        dialog.raise_()

    def _show_evidence(self, node_id: str, *, evidence: tuple[EvidenceRef, ...] = ()) -> None:
        if self._result is None or self._case_path is None:
            return
        if self._result.window != self._window:
            return
        # Ringed before the lookup, so the canvas answers the click even when
        # the episode behind it cannot be found and nothing fills the panel.
        self._canvas.highlight(node_id)
        graph = self._result.trace if self._kind is GraphKind.TRACE else self._result.behaviour
        node = next((item for item in graph.nodes if item.node_id == node_id), None)
        if node is None:
            return
        self._selected = node
        self._evidence_request = request = object()
        result = self._result

        path = self._case_path
        # Which lines are behind an activity is `AnalysisResult`'s to answer, not
        # the window's: it is a fact about the reconstruction, checkable without
        # a display, and getting it wrong shows the reader the wrong evidence.
        # What stays here is the ceiling, which is a question about how long
        # somebody will sit watching a panel fill.
        text = self._evidence.filter_text()
        kept = RequestFilter.read(text, result)
        limit = EVIDENCE_LIMIT
        wanted = set(evidence)
        supporting = (
            {
                assignment.evidence
                for assignment in result.assignments
                if assignment.evidence in wanted
                and assignment.episode_id in node.episode_ids
                and (kept is None or kept.keeps(assignment))
            }
            if wanted
            else set()
        )

        def work(_: Callable[[str], None]) -> Any:
            # Off the interface thread: a filter reads every request the activity
            # holds, not the sample, and an activity can hold a great many.
            held = result.requests_for(node)
            values = {
                key: [
                    (value, plural(count, "line"))
                    for value, count in value_counts((item.labelled.event for item in held), key)
                ]
                for key in ("status", "method")
            }
            filtered: Filtered | None = None
            if kept is None:
                pool = result.evidence_for(node, limit=limit)
            else:
                pool = tuple(item.evidence for item in held if kept.keeps(item))
                filtered = Filtered(text, len(pool), len(held))
            refs = tuple(dict.fromkeys((*[ref for ref in evidence if ref in supporting], *pool)))
            # Which visit each line belongs to: repeats fold only within one.
            visits = {item.evidence: item.episode_id for item in held}
            with Case.open(path) as case:
                return case.read_evidence(refs[:limit]), values, filtered, visits

        def current() -> bool:
            return (
                request is self._evidence_request
                and path == self._case_path
                and result is self._result
                and node is self._selected
            )

        def done(answer: Any) -> None:
            if not current():
                return
            lines, values, filtered, visits = answer
            self._evidence.set_suggestion_values(values)
            self._evidence.show_evidence(node, lines, filtered=filtered, visits=visits)
            # The line asked for by name, wherever the table's order put it.
            if evidence:
                self._evidence.select_line(evidence[0])

        run_job(
            work,
            on_done=done,
            on_error=lambda message, detail: (
                self.report_error(message, detail) if current() else None
            ),
        )

    # -- the evidence filter -------------------------------------------------

    def _filter_changed(self, _text: str) -> None:
        """The reader changed the evidence filter: fade the canvas again, refill the panel."""
        self._refade()
        if self._selected is not None:
            self._show_evidence(self._selected.node_id)

    def _forget_filter(self) -> None:
        """Start without a filter. It belongs to the client it was typed on."""
        self._evidence.set_filter_text("")
        self._filter_hits = None
        self._fade_request = object()
        self._open_first_match = None

    def _refade(self) -> None:
        """Fade the activities on the canvas that hold no line the filter keeps.

        Worked out off the interface thread, because it reads every request the
        client made; remembered for the reconstruction and the text, so a switch
        between Trace and Behaviour fades the new graph at once.
        """
        result = self._result
        text = self._evidence.filter_text()
        self._fade_request = request = object()
        if result is None:
            return
        hits = self._filter_hits
        if hits is not None and hits[0] is result and hits[1] == text:
            self._canvas.set_matching(self._holding(hits[2]))
            return
        self._filter_hits = None
        kept = RequestFilter.read(text, result)
        if kept is None:
            self._canvas.set_matching(None)
            return

        def work(_: Callable[[str], None]) -> frozenset[str]:
            return kept.episodes(result.assignments)

        def current() -> bool:
            return request is self._fade_request and result is self._result

        def done(episodes: frozenset[str]) -> None:
            if current():
                self._filter_hits = (result, text, episodes)
                holding = self._holding(episodes)
                self._canvas.set_matching(holding)
                self._open_first(result, holding)

        run_job(
            work,
            on_done=done,
            on_error=lambda message, detail: (
                self.report_error(message, detail) if current() else None
            ),
        )

    def _open_first(self, result: AnalysisResult, holding: frozenset[str]) -> None:
        """Show the earliest of `holding`, once, for a client opened from a search.

        Not if the reader has already chosen an activity: theirs stands.
        """
        if self._open_first_match is not result:
            return
        self._open_first_match = None
        if self._selected is not None or not holding:
            return
        graph = result.trace if self._kind is GraphKind.TRACE else result.behaviour
        first = min(
            (node for node in graph.nodes if node.node_id in holding),
            key=lambda node: (node.start, node.node_id),
        )
        self._show_evidence(first.node_id)

    def _holding(self, episodes: frozenset[str]) -> frozenset[str]:
        """The activities on screen made of any of `episodes`."""
        result = self._result
        if result is None:
            return frozenset()
        graph = result.trace if self._kind is GraphKind.TRACE else result.behaviour
        return frozenset(
            node.node_id for node in graph.nodes if episodes.intersection(node.episode_ids)
        )

    def _show_holding(
        self,
        result: AnalysisResult,
        refs: tuple[EvidenceRef, ...],
        *,
        evidence: tuple[EvidenceRef, ...] = (),
    ) -> None:
        """Show the activity holding `refs` in the graph on screen, `evidence` first.

        Brought into view as well: it was asked for from elsewhere, and a graph
        too large to frame readably opens on its beginning. The lines still obey
        the evidence filter, as lines carried in from Where to start do.
        """
        wanted = set(refs)
        episodes = frozenset(a.episode_id for a in result.assignments if a.evidence in wanted)
        graph = result.trace if self._kind is GraphKind.TRACE else result.behaviour
        node = node_for_episodes(graph, episodes)
        if node is not None:
            self._show_evidence(node.node_id, evidence=evidence)
            self._canvas.bring_into_view(node.node_id)

    # -- bookmarks -----------------------------------------------------------

    def _bookmarks_changed(self) -> None:
        """Count them on the tab and mark them everywhere, after any change."""
        count = len(self._bookmarks.shelf.bookmarks)
        self._workspace.setTabText(
            self._workspace.indexOf(self._bookmarks_tab),
            f"Bookmarks ({count})" if count else "Bookmarks",
        )
        self._clients.set_marks(self._bookmarks.client_marks())
        result = self._result
        self._evidence.set_marks(
            self._bookmarks.line_marks(result.client_ip) if result is not None else {}
        )
        self._mark_graph()

    def _mark_graph(self) -> None:
        """Ribbon the activities on the canvas that hold a bookmarked activity's line."""
        result = self._result
        if result is None:
            self._canvas.set_marks({})
            return
        graph = result.trace if self._kind is GraphKind.TRACE else result.behaviour
        self._canvas.set_marks(self._bookmarks.node_marks(result, graph))

    def _under(self, widget: QWidget) -> QPoint:
        """Just below `widget`, in the window's coordinates: where its save box opens."""
        return widget.mapTo(self, QPoint(0, widget.height() + 2))

    def _bookmark_search_from_button(self) -> None:
        self._bookmark_search(anchor=self._under(self._clients.search_bookmark))

    def _bookmark_activity_from_button(self) -> None:
        self._bookmark_activity(anchor=self._under(self._evidence.bookmark_button))

    def _bookmark_node(self) -> None:
        """The canvas's right-click entry: the activity under the pointer, now selected."""
        self._bookmark_activity()

    def _bookmark_focused(self) -> None:
        """Ctrl+D: bookmark what has the keyboard.

        The selected log line in the evidence, the selected client in the list
        or the queue, the search in the client box. Anywhere else, including the
        canvas, the activity being read; else the client being read.
        """
        focus = QApplication.focusWidget()

        def inside(widget: QWidget) -> bool:
            return focus is not None and (focus is widget or widget.isAncestorOf(focus))

        if inside(self._evidence):
            line = self._evidence.selected_line()
            if line is not None:
                self._bookmark_line(line)
                return
        elif inside(self._clients):
            if self._clients.box_has_focus():
                if self._clients.answered_search() is not None:
                    self._bookmark_search()
                    return
            elif (chosen := self._clients.selected_client()) is not None:
                self._bookmark_client(chosen)
                return
        elif inside(self._triage) and (queued := self._triage.selected_client()) is not None:
            self._bookmark_client(queued)
            return
        if self._selected is not None:
            self._bookmark_activity()
        elif self._result is not None:
            self._bookmark_client(self._result.client_ip)
        else:
            self._idle("Nothing to bookmark yet.")

    def _bookmark_client(self, client_ip: str, anchor: QPoint | None = None) -> None:
        """Bookmark a client, said as the list says it: its requests, and when.

        Looked up rather than read off the list, which holds the busiest few
        hundred: a client from the queue or Who else may not be on it. Over the
        range in force, else the whole case when it has nothing there.
        """
        path, window = self._case_path, self._window

        def draft(said: str) -> Draft:
            return Draft(Kind.CLIENT, "Bookmark this client", said, client=client_ip)

        if path is None:
            self._bookmarks.bookmark(draft(""), anchor)
            return

        def work(_: Callable[[str], None]) -> str:
            with Case.open(path) as case:
                for over in dict.fromkeys((None if window.is_open else window, None)):
                    page = case.store.ip_summary_page(
                        query=client_ip, offset=0, limit=1, window=over, exact=True
                    )
                    if page.rows:
                        row = page.rows[0]
                        return said_for_client(row.request_count, row.first_seen, row.last_seen)
            return ""

        def done(said: str) -> None:
            if path == self._case_path:
                self._bookmarks.bookmark(draft(said), anchor)

        # Without the figures the bookmark is still worth saving.
        run_job(work, on_done=done, on_error=lambda _message, _detail: done(""))

    def _bookmark_activity(self, anchor: QPoint | None = None) -> None:
        """Bookmark the activity being read, anchored on its earliest log line.

        A line rather than the activity's id, which is only good for this
        reconstruction: a range or a rule change can merge or split activities,
        and the one holding the line is then the one the bookmark means.
        """
        node, result = self._selected, self._result
        if node is None or result is None:
            self._idle("Select an activity first, then bookmark it.")
            return

        def work(_: Callable[[str], None]) -> object:
            # Off the interface thread, as the evidence panel's own pass is:
            # an activity can hold a great many requests.
            held = result.requests_for(node)
            return held[0] if held else None

        def done(first: Any) -> None:
            if node is not self._selected or result is not self._result:
                return
            self._bookmarks.bookmark(
                Draft(
                    Kind.ACTIVITY,
                    "Bookmark this activity",
                    said_for_activity(node),
                    client=result.client_ip,
                    line=first.evidence if first is not None else None,
                    at=first.labelled.event.timestamp if first is not None else None,
                ),
                anchor,
            )

        run_job(work, on_done=done, on_error=self.report_error)

    def _bookmark_line(self, line: EvidenceLine, anchor: QPoint | None = None) -> None:
        """Bookmark one log line of the client being read."""
        if self._result is None:
            return
        self._bookmarks.bookmark(
            Draft(
                Kind.REQUEST,
                "Bookmark this line",
                said_for_request(line.ref, line.event),
                client=self._result.client_ip,
                line=line.ref,
                at=line.event.timestamp if line.event is not None else None,
            ),
            anchor,
        )

    def _bookmark_search(self, anchor: QPoint | None = None) -> None:
        """Bookmark the client box's search, with the range it was answered over."""
        answered = self._clients.answered_search()
        if answered is None:
            self._idle("Search clients first, then bookmark the search.")
            return
        query, clients, requests = answered
        self._bookmarks.bookmark(
            Draft(
                Kind.SEARCH,
                "Bookmark this search",
                said_for_search(query, clients, requests),
                query=query,
                range=None if self._window.is_open else self._window,
            ),
            anchor,
        )

    # The window's side of `bookmark_keeper.Opener`.

    def open_client(self, ip: str) -> None:
        """Open a bookmarked client, over the whole case if it has nothing in the range."""
        path, window = self._case_path, self._window
        if path is None:
            return
        if window.is_open:
            self._open_on(ip)
            return

        def work(_: Callable[[str], None]) -> bool:
            with Case.open(path) as case:
                page = case.store.ip_summary_page(
                    query=ip, offset=0, limit=1, window=window, exact=True
                )
            return bool(page.rows)

        def done(present: bool) -> None:
            if (path, window) != (self._case_path, self._window):
                return
            if present:
                self._open_on(ip)
            else:
                self._apply_window(EVERYTHING, then=lambda: self._open_on(ip, note=_WIDENED))

        run_job(work, on_done=done, on_error=self.report_error)

    def open_line(
        self, ip: str, ref: EvidenceRef, *, whole_activity: bool, at: datetime | None
    ) -> None:
        """Open a bookmarked activity or request, over the whole case if it is outside the range.

        A line with no known time is treated as outside: a range that might hide
        it would open on nothing.
        """
        if self._case_path is None:
            return
        evidence = () if whole_activity else (ref,)
        activity_of = ref if whole_activity else None
        window = self._window
        if not window.is_open and (at is None or not window.contains(at)):
            self._apply_window(
                EVERYTHING,
                then=lambda: self._open_on(
                    ip, evidence=evidence, activity_of=activity_of, note=_WIDENED
                ),
            )
            return
        self._open_on(ip, evidence=evidence, activity_of=activity_of)

    def open_search(self, query: str, window: TimeWindow) -> None:
        """Run a bookmarked search again, over the range it was answered in."""
        if self._case_path is None:
            return
        self._apply_window(window, then=lambda: self._clients.set_query(query))

    def check_targets(
        self,
        clients: frozenset[str],
        done: Callable[[frozenset[str], frozenset[str]], None],
    ) -> None:
        """Which of `clients` the case holds, and its log files, for what is gone."""
        path = self._case_path
        if path is None:
            return

        def work(_: Callable[[str], None]) -> tuple[frozenset[str], frozenset[str]]:
            with Case.open(path) as case:
                present = case.store.clients_present(clients) if clients else frozenset()
                return present, frozenset(source.file_id for source in case.manifest.sources)

        # Unanswered, nothing reads as gone: the keeper only marks what it knows.
        run_job(
            work,
            on_done=lambda found: done(*found),
            on_error=lambda _message, _detail: None,
        )

    def _open_on(
        self,
        ip: str,
        *,
        evidence: tuple[EvidenceRef, ...] = (),
        activity_of: EvidenceRef | None = None,
        note: str = "",
    ) -> None:
        """Show `ip`, and the line or activity asked for, in the range now in force.

        Read again only when it is not the client already on screen: the same
        client in the same range is shown where it is.
        """
        self._clients.select_quietly(ip)
        result = self._result
        here = (ip, self._window)
        if result is not None and (result.client_ip, result.window) == here == self._awaiting:
            self._workspace.setCurrentIndex(1)
            held = evidence or ((activity_of,) if activity_of is not None else ())
            if held:
                self._show_holding(result, held, evidence=evidence)
            if note:
                self._idle(note)
            return
        self._reconstruct(ip, evidence=evidence, activity_of=activity_of, note=note)

    # -- export ------------------------------------------------------------

    def _export(self, kind: str) -> None:
        if self._result is None or self._case_path is None:
            QMessageBox.information(self, "Nothing to export", "Open a client first.")
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
        rules = self._rules
        shelf = self._bookmarks.shelf

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
                case_path, client_ip, crs, evidence_sample=DEFAULT_EVIDENCE_SAMPLE, rules=rules
            )
            with Case.open(case_path) as case:
                # A request bookmark's own line goes in the report beside its
                # note; an activity's is only where it starts, so it does not.
                requests = [
                    b.line
                    for b in shelf.bookmarks
                    if b.kind is Kind.REQUEST and b.client == client_ip and b.line is not None
                ]
                written = export.write_reconstruction(
                    bounded,
                    case.manifest,
                    kind=kind,
                    target=target,
                    shelf=shelf,
                    lines=_raw_lines(case, requests),
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

    def _export_bookmarks(self) -> None:
        """Every bookmark in the case as a CSV, with the log line behind each one."""
        shelf, path = self._bookmarks.shelf, self._case_path
        if path is None or not shelf.bookmarks:
            QMessageBox.information(
                self,
                "Nothing to export",
                "Open a case first." if path is None else "This case has no bookmarks yet.",
            )
            return
        chosen, _ = QFileDialog.getSaveFileName(
            self, "Export bookmarks", "bookmarks.csv", "CSV (*.csv)"
        )
        if not chosen:
            return
        target = Path(chosen)

        def work(_: Callable[[str], None]) -> str:
            with Case.open(path) as case:
                lines = _raw_lines(case, [b.line for b in shelf.bookmarks if b.line is not None])
            # With a byte-order mark: without one a spreadsheet reads the file in
            # the machine's own code page, and an address or a note in anything
            # but plain English comes out garbled. The rows end themselves.
            target.write_text(to_csv(shelf, lines), encoding="utf-8-sig", newline="")
            return str(target)

        run_job(
            work,
            on_done=lambda written: self._idle(f"Written to {written}"),
            on_error=self.report_error,
        )

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802
        self._load_generation += 1
        self._triage.shutdown()
        self._awaiting = None
        super().closeEvent(event)

    # -- status ------------------------------------------------------------

    def _busy(self, message: str, *, stop: threading.Event | None = None) -> None:
        """Show that work is running, and offer to stop it when it can be."""
        self._stop = stop
        self._status.setText(message)
        colour_text(self._status, THEME.accent)
        self._progress.show()
        self._cancel.setEnabled(True)
        self._cancel.setVisible(stop is not None)

    def _idle(self, message: str) -> None:
        self._stop = None
        self._status.setText(message)
        colour_text(self._status, THEME.muted)
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
        colour_text(self._status, THEME.warning)

    def report_error(self, message: str, detail: str, *, explanation: str = "") -> None:
        """`message` in the status line and the dialog; `explanation` under it
        in the dialog; `detail` behind Show Details and in the terminal."""
        self._progress.hide()
        self._status.setText(message)
        colour_text(self._status, THEME.alert)
        if detail:
            # The window gets a sentence; the terminal keeps the traceback, so a
            # failure is never only a dialog nobody wrote down. Written so that
            # the writing cannot fail, or the dialog below would not come up.
            crash.write_down(detail, sys.stderr)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("logarc")
        box.setText(message)
        if explanation:
            box.setInformativeText(explanation)
        if detail:
            box.setDetailedText(detail)
        box.exec()


def main() -> int:
    """Entry point for the `logarc-gui` command."""
    multiprocessing.freeze_support()
    configure_display()
    # Reused if one is already up. There never is in production; it is what
    # lets this function be called from a test at all, and an entry point that
    # cannot be called is an entry point nothing checks.
    running = QApplication.instance()
    app = running if isinstance(running, QApplication) else QApplication(sys.argv)
    app.setApplicationName("logarc")
    apply_theme(
        app, points=prefs.text_points_in(_settings().value, automatic=automatic_points_for(app))
    )
    try:
        window = MainWindow()
    except Exception:
        traceback.print_exc()
        return 1
    # The net goes up as soon as there is somewhere to show a problem. Before
    # it, a mistake anywhere in the interface reached Qt's own handler, which
    # ends the process without printing anything at all — see `gui.crash`.
    previous = crash.install(window.report_error)
    window.show()
    window.offer_start()
    code = app.exec()
    # The window goes now, while the application is still there. Left to
    # Python, `app` was released before `window` on the way out of this
    # function, and a widget destroyed after its application crashed the exit
    # with an access violation: 151 of 1,440 runs of this shape, under load.
    # The net reports to the window, so it comes down first.
    sys.excepthook = previous
    sip.delete(window)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
