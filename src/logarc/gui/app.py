"""The main window.

Holds no analysis. Every action here calls the same `logarc.case` and
`logarc.analysis` functions the CLI calls, on a worker thread, and displays what
comes back — which is what makes "anything the GUI can do is scriptable" true by
construction rather than by promise.
"""

from __future__ import annotations

import sys
import threading
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QSettings, Qt
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
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
from logarc.analysis import AnalysisPolicy, analyse_ip
from logarc.case import Case
from logarc.core.graph import GraphKind
from logarc.core.window import EVERYTHING, TimeWindow
from logarc.detect.crs import CrsEvidence
from logarc.episode.builder import DEFAULT_EVIDENCE_SAMPLE, EpisodePolicy
from logarc.gui import arrangement, recent
from logarc.gui._qt import required
from logarc.gui.canvas import ActivityCanvas
from logarc.gui.case_chooser import CaseChooser
from logarc.gui.evidence_panel import EvidencePanel
from logarc.gui.notice_bar import QuarantineBanner, warn_about_dead_files
from logarc.gui.panels import ClientTable, LegendBar
from logarc.gui.progress import Progress, Reading
from logarc.gui.progress_card import IngestCard
from logarc.gui.quarantine_notice import notice_for
from logarc.gui.recent import RecentCase
from logarc.gui.style import THEME, format_requests, plural
from logarc.gui.theme import GAP, MONO_FAMILIES, PAD, TIGHT, apply_theme, heading_font
from logarc.gui.time_filter import TimeFilterBar
from logarc.gui.timerange import nobody_here, summary
from logarc.gui.workers import run_job
from logarc.ingest.pipeline import IngestCancelled
from logarc.ingest.quarantine import DIRECTORY_NAME as QUARANTINE_DIR
from logarc.report.html import render_report
from logarc.storage.case import CaseManifest

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import datetime

    from logarc.analysis import AnalysisResult
    from logarc.core.graph import ActivityGraph, GraphNode
    from logarc.storage.base import IpSummary

__all__ = ["MainWindow", "main", "read_case", "reconstruct_client"]

#: Clients listed at once. The table is for choosing from, not for reading in
#: full; a case with a third of a million clients would otherwise freeze the
#: window building rows nobody scrolls to.
_CLIENT_LIMIT = 500

#: Source lines the window will put on screen for one activity.
#:
#: A limit on what can be *drawn*, which is the only limit this panel actually
#: needs. It used to be 25, sitting above an episode's twenty-reference sample
#: and therefore never binding — and that sample exists to keep an exported file
#: small, a cost a window that exports nothing until asked was paying anyway.
#: Worse, the sample is `events[:20]`, a prefix rather than a spread, so a
#: fifty-request sweep was read from its opening and never its end.
#:
#: 2,000 because filling the table happens on the interface thread: measured at
#: about 105ms for 500 rows, 670ms for 5,000 and 2.9s for 20,000, and a
#: three-second freeze is the hang `gui.workers` exists to prevent. At this
#: ceiling the fill takes about 500ms, and only for an activity holding two
#: thousand requests or more; the 49-request node this was checked against goes
#: from click to filled in 84ms. Reading the lines is not what costs —
#: `read_evidence` makes one streaming pass per source whether it is asked for
#: twenty lines or twenty thousand.
_EVIDENCE_LIMIT = 2_000

#: Where the window remembers how it was left. One key so far: whether long
#: traces are folded. Worth persisting for the same reason an editor persists
#: word wrap — it is a reading preference, and being asked for it again every
#: launch is the annoyance the setting exists to remove.
_SETTINGS = ("logarc", "logarc")
_WRAP_KEY = "view/wrap_traces"

#: Where the arrangements the reader saved are kept. One value holding all
#: of them, capped in `gui.arrangement`, so a single read on open answers for
#: every graph rather than one read per case in the settings tree.
#:
#: Like `_RECENT_KEY`, this records *what was investigated*: the coordinates are
#: keyed by activity id, and a trace's activity ids are built from the client's
#: address. `Reset layout` removes the arrangement for the graph in front of the
#: reader, which is the control they have over it.
_LAYOUT_KEY = "view/arrangements"
_DECODE_KEY = "view/decode_targets"

#: The cases opened here, and whether to reopen the last one on start.
#:
#: Worth saying plainly: this records *what was investigated* rather than how
#: the window looked doing it. `Forget these` in the chooser removes it, and the
#: README says so. `_LAYOUT_KEY` is the other one — a saved arrangement is keyed
#: by activity id, and a trace's activity ids carry the client's address.
_RECENT_KEY = "cases/recent"
_REOPEN_KEY = "cases/reopen_last"

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


def _remembered(key: str, *, default: bool) -> bool:
    """A remembered yes/no, normalised rather than trusted.

    Both stores hand these back as text — the registry keeps `REG_SZ "false"`,
    an ini file the characters `false` — and a non-empty string is truthy, so
    reading one at face value turns every setting back on for anyone who ever
    turned it off.
    """
    value = _settings().value(key, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"false", "0", ""}


# Module-level and Qt-free on purpose. These are the two decisions the window
# makes about a case, and while they lived inside worker closures the GUI could
# — and did — quietly disagree with the CLI about what a case contains. Out
# here they are callable without a display, so a test can hold both front ends
# to the same answer.
def read_case(
    path: Path, *, window: TimeWindow | None = None
) -> tuple[Sequence[IpSummary], CrsEvidence, tuple[datetime, datetime] | None]:
    """Everything a freshly opened case needs, gathered in one visit.

    The CRS evidence is read here rather than per reconstruction because it is a
    property of the case, not of the client being looked at, and a case is
    opened once against many clicks.

    The third value is the stretch the case covers — the whole of it, never the
    window. It is what holds the fields inside the case, so it has to keep
    describing the case even while a narrower window is being shown.
    """
    with Case.open(path) as case:
        whole = case.store.ip_summaries(limit=_CLIENT_LIMIT, order_by="requests")
        listed = (
            whole
            if window is None or window.is_open
            else case.store.ip_summaries(limit=_CLIENT_LIMIT, order_by="requests", window=window)
        )
        span = (
            (min(s.first_seen for s in whole), max(s.last_seen for s in whole)) if whole else None
        )
        return listed, case.crs_evidence(), span


def _node_for_episodes(graph: ActivityGraph, episode_ids: frozenset[str]) -> GraphNode | None:
    """The activity in `graph` covering these episodes, if it draws one.

    Out here with `read_case` and `reconstruct_client`, and Qt-free for the same
    reason: which activity a view switch lands on is a decision about the
    evidence, and it should be checkable without starting a window.

    Going from the map back to the trace, one behaviour node answers to several
    trace nodes — three enumeration episodes become one 35-request circle. The
    busiest wins, because that is the one that dominated what was being read,
    and `max` keeps the first of equals so two runs of the same case cannot ring
    different nodes.
    """
    covering = [node for node in graph.nodes if episode_ids.intersection(node.episode_ids)]
    if not covering:
        return None
    return max(covering, key=lambda node: node.request_count)


def reconstruct_client(
    path: Path,
    client_ip: str,
    crs: CrsEvidence,
    *,
    evidence_sample: int = _EVIDENCE_LIMIT,
    window: TimeWindow | None = None,
) -> AnalysisResult:
    """Reconstruct one client, applying whatever CRS contributed to the case.

    `evidence_sample` is how many source references each episode keeps. The
    window asks for as many as it can draw, because the engine's own default of
    twenty is a budget for an exported file rather than for a reading surface,
    and asking for more costs nothing to produce — it is a list slice, measured
    at the same 90ms either way. What it buys is an activity read to its end
    rather than from its first twenty requests.

    The default is not lowered anywhere else: the CLI, the benchmark and the
    evaluation — which reconstructs every client in a corpus — go on using the
    engine's, and `_export` asks for it back explicitly.
    """
    with Case.open(path) as case:
        return analyse_ip(
            case.store,
            client_ip,
            policy=AnalysisPolicy(episode=EpisodePolicy(evidence_sample=evidence_sample)),
            crs=crs.index,
            crs_fingerprint=crs.fingerprint,
            window=window,
        )


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
        self._result: AnalysisResult | None = None
        #: What CRS contributed to the open case. Empty until one is opened, so
        #: a reconstruction before then applies nothing rather than failing.
        self._crs = CrsEvidence(index=None, fingerprint=None)
        self._kind = GraphKind.TRACE
        #: The activity whose evidence is in the panel, so a redraw can put the
        #: reader back on it in the graph that replaces this one.
        self._selected: GraphNode | None = None
        self._stop: threading.Event | None = None
        #: Up only while an ingest is running.
        self._ingest_card: IngestCard | None = None

        self._notice = QuarantineBanner()
        self._clients = ClientTable()
        self._canvas = ActivityCanvas()
        self._legend = LegendBar()
        self._evidence = EvidencePanel()
        self._clients.client_chosen.connect(self._reconstruct)
        self._canvas.node_selected.connect(self._show_evidence)

        self._build_layout()
        self._build_menu()

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

        centre = QWidget()
        column = QVBoxLayout(centre)
        # Matching the panels either side, and what lets the canvas read as a
        # framed document rather than a hole cut in the window.
        column.setContentsMargins(PAD, TIGHT, PAD, TIGHT)
        column.setSpacing(TIGHT)
        column.addWidget(self._tabs)
        column.addWidget(self._heading)
        column.addWidget(self._canvas)
        column.addWidget(self._legend)

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

    def _build_menu(self) -> None:
        menu_bar = required(self.menuBar())
        case_menu = required(menu_bar.addMenu("&Case"))
        self._add(case_menu, "&Open case…", self._open_case, QKeySequence.StandardKey.Open)
        recently = self._add(case_menu, "&Recently opened…", self._show_recent)
        recently.setShortcut(QKeySequence("Ctrl+Shift+O"))
        recently.setStatusTip("Pick up a case that has been opened on this machine before.")
        self._add(case_menu, "Ingest logs into a &new case…", self._ingest_new_case)
        case_menu.addSeparator()
        self._add(case_menu, "E&xit", self.close, QKeySequence.StandardKey.Quit)

        view_menu = required(menu_bar.addMenu("&View"))
        self._trace_action = self._add(view_menu, "&Trace (chronological)", self._show_trace)
        self._behaviour_action = self._add(view_menu, "&Behaviour map", self._show_behaviour)
        for action in (self._trace_action, self._behaviour_action):
            action.setCheckable(True)
        self._trace_action.setChecked(True)
        view_menu.addSeparator()

        # Alt+Z, because that is what an editor uses for word wrap and this is
        # the same choice about the same trade: fold the long line and read it,
        # or keep it straight and scroll.
        self._wrap_action = self._add(view_menu, "&Wrap long traces", self._apply_wrap)
        self._wrap_action.setCheckable(True)
        self._wrap_action.setChecked(_remembered(_WRAP_KEY, default=True))
        self._wrap_action.setShortcut(QKeySequence("Alt+Z"))
        self._wrap_action.setStatusTip(
            "Fold a long session onto further rows so the captions stay readable, "
            "or lay it out on one line and pan along it."
        )
        self._canvas.set_wrap(self._wrap_action.isChecked())

        self._add(view_menu, "&Fit to window", self._canvas.fit)
        view_menu.addSeparator()

        # Where an activity was dragged to, and how to be rid of it. In the menu
        # with every other control rather than on the canvas: a strip floating
        # over the graph covers a patch of it, has to be moved on every resize,
        # and swallows clicks meant for whatever node is underneath.
        self._undo_action = self._add(view_menu, "&Undo node move", self._undo_move)
        self._undo_action.setShortcut(QKeySequence.StandardKey.Undo)
        self._undo_action.setStatusTip("Put the last activity you moved back where it was.")
        self._save_layout_action = self._add(
            view_menu, "&Save this arrangement", self._save_arrangement
        )
        self._save_layout_action.setShortcut(QKeySequence.StandardKey.Save)
        self._save_layout_action.setStatusTip(
            "Remember where you have put the activities on this graph."
        )
        self._reset_layout_action = self._add(view_menu, "&Reset layout", self._reset_layout)
        self._reset_layout_action.setShortcut(QKeySequence("Ctrl+Shift+R"))
        self._reset_layout_action.setStatusTip(
            "Put every activity back where it was laid out, and forget the saved arrangement."
        )
        self._canvas.arrangement_changed.connect(self._sync_arrangement_actions)
        self._sync_arrangement_actions()
        view_menu.addSeparator()

        # How the evidence beside the graph is read. Both are preferences about
        # presentation, never about which evidence is shown: the `file:line`
        # reference is printed whatever either of these is set to.
        self._decode_action = self._add(view_menu, "&Decode URL escapes", self._apply_evidence_view)
        self._decode_action.setCheckable(True)
        self._decode_action.setChecked(_remembered(_DECODE_KEY, default=True))
        self._decode_action.setStatusTip(
            "Show request targets as the attacker wrote them — %27+OR+%271%27%3D%271 "
            "reads as ' OR '1'='1 — or exactly as the log holds them."
        )

        self._apply_evidence_view()
        view_menu.addSeparator()

        self._reopen_action = self._add(
            view_menu, "Reopen the &last case on start", self._apply_reopen
        )
        self._reopen_action.setCheckable(True)
        # Off by default: a launch opens on the list. Reopening the last case
        # straight away is genuinely useful and is also a way never to see the
        # chooser at all, which is the thing it was built to be.
        self._reopen_action.setChecked(_remembered(_REOPEN_KEY, default=False))
        self._reopen_action.setStatusTip(
            "Open the case you were last working on as soon as the window appears, "
            "or start with the list of recent cases instead."
        )

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
        self._report_error(message, detail)

    def _ingest_finished(self, case_dir: Path, outcome: object) -> None:
        self._close_ingest_card()
        if not isinstance(outcome, IngestCancelled):
            self._load_case(case_dir)
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
            reopen_last=self._reopen_action.isChecked(),
            exists=lambda path: Path(path).exists(),
        )
        if action is recent.Startup.OPEN_LAST and entry is not None:
            self._load_case(Path(entry.path))
        elif action is recent.Startup.CHOOSE:
            self._show_recent()

    def _apply_reopen(self) -> None:
        _settings().setValue(_REOPEN_KEY, self._reopen_action.isChecked())

    def _load_case(self, path: Path) -> None:
        def work(report: Callable[[str], None]) -> Any:
            report(f"Opening {path}…")
            summaries, crs, span = read_case(path)
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
            return summaries, crs, span, snapshot, notice

        self._busy(f"Opening {path}…")

        def done(loaded: Any) -> None:
            summaries, crs, span, snapshot, notice = loaded
            self._remember_case(snapshot)
            self._case_path = path
            self._crs = crs
            # A fresh case is read whole. Opening one already narrowed would
            # hide part of it with nothing on screen saying so.
            self._window = EVERYTHING
            self._all_clients = len(summaries)
            self._listed = len(summaries)
            # Unfiltered by construction: a case is opened whole.
            self._whole_counts = {s.client_ip: s.request_count for s in summaries}
            self._time_filter.set_span(span)
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
            self._heading.setText("")
            self._tabs.setVisible(False)
            self._clients.show_clients(summaries)
            self._say_what_is_left()
            self._idle(
                f"{path} — {plural(len(summaries), 'client')} listed"
                + (", CRS applied" if crs.fingerprint else "")
            )
            # Last, after the window has finished loading, never before. A modal
            # raised mid-load sits over a half-drawn case, so the reader has to
            # dismiss it before they can see the thing it is talking about.
            if notice is not None and notice.is_blocking:
                warn_about_dead_files(self, notice)

        run_job(work, on_done=done, on_error=self._report_error, on_progress=self._status.setText)

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
        # The control is told what is in force, not asked. Typing in the fields
        # keeps them right by accident; every other way the range can be set
        # would otherwise leave them naming a stretch nobody is reading.
        self._time_filter.set_window(window)
        path = self._case_path

        def work(report: Callable[[str], None]) -> Any:
            report("Reading the selected time range…")
            return read_case(path, window=window)

        self._busy("Reading the selected time range…")

        def done(loaded: Any) -> None:
            summaries, _, _ = loaded
            self._listed = len(summaries)
            self._clients.show_clients(summaries)
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
            self._idle(f"{len(summaries)} of {self._all_clients} clients in this range")
            # The client the reader was on, if this range still holds them. The
            # table has been rebuilt, so the selection has to be found again.
            if self._result is not None:
                self._reselect(self._result.client_ip)

        run_job(work, on_done=done, on_error=self._report_error, on_progress=self._status.setText)

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

    def _reselect(self, client_ip: str) -> None:
        """Put the reader back on the client they were reading, if it is listed.

        The reconstruction is asked for outright rather than left to the
        selection signal. After a narrower range the client can land on the row
        it was already on, and `selectRow` on the current row changes nothing
        and emits nothing — so the graph went on showing the reconstruction it
        had, over a range that was no longer in force.
        """
        table = self._clients._table
        for row in range(table.rowCount()):
            cell = table.item(row, 0)
            if cell is not None and cell.text() == client_ip:
                blocked = table.blockSignals(True)
                table.selectRow(row)
                table.blockSignals(blocked)
                self._reconstruct(client_ip)
                return
        # Gone from this range. The graph would otherwise go on showing a
        # reconstruction of a client the list no longer offers.
        self._result = None
        self._selected = None
        self._evidence.clear(prompt=False)
        self._tabs.setVisible(False)
        self._heading.setText("")
        self._canvas.show_graph_placeholder()

    # -- reconstruction ----------------------------------------------------

    def _reconstruct(self, client_ip: str) -> None:
        if self._case_path is None:
            return
        path = self._case_path
        # Read once here, on the interface thread, rather than from inside the
        # worker: the job must not reach back into window state while the window
        # is free to change it.
        crs = self._crs
        window = self._window

        def work(report: Callable[[str], None]) -> AnalysisResult:
            report(f"Reconstructing {client_ip}…")
            return reconstruct_client(path, client_ip, crs, window=window)

        self._busy(f"Reconstructing {client_ip}…")

        def done(result: AnalysisResult) -> None:
            self._result = result
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

        run_job(work, on_done=done, on_error=self._report_error, on_progress=self._status.setText)

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
        self._canvas.show_graph(graph, positions=self._saved_arrangement())
        self._sync_arrangement_actions()
        if was_reading is None:
            return
        # Found by episode, not by node id: the two graphs number their nodes
        # differently, and one behaviour node answers to several trace nodes.
        carried = _node_for_episodes(graph, frozenset(was_reading.episode_ids))
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
        # Greyed out on the other view rather than hidden: a behaviour map is a
        # circle and has nothing to fold, and a live control that does nothing
        # reads as a fault. The choice itself is kept, and applies again here.
        self._wrap_action.setEnabled(True)
        self._redraw()

    def _show_behaviour(self) -> None:
        self._kind = GraphKind.BEHAVIOUR
        self._trace_action.setChecked(False)
        self._behaviour_action.setChecked(True)
        self._sync_tabs()
        self._wrap_action.setEnabled(False)
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

    def _arrangement_key(self, *, wrap: bool | None = None) -> str | None:
        """Which saved arrangement belongs to what is on the canvas now.

        `None` before there is a graph, which is also when the menu entries are
        dead — so nothing downstream has to guess what an arrangement for no
        client would even mean.
        """
        if self._case_path is None or self._result is None:
            return None
        return arrangement.key(
            str(self._case_path),
            self._result.client_ip,
            self._kind,
            wrap=self._canvas.wrap if wrap is None else wrap,
            window=self._window.tag,
        )

    def _arrangements(self) -> arrangement.Store:
        return arrangement.load(str(_settings().value(_LAYOUT_KEY, "")))

    def _saved_arrangement(self, *, wrap: bool | None = None) -> arrangement.Positions | None:
        name = self._arrangement_key(wrap=wrap)
        return None if name is None else self._arrangements().get(name)

    def _undo_move(self) -> None:
        self._canvas.undo_move()

    def _save_arrangement(self) -> None:
        """Remember where the activities have been put on this graph."""
        name = self._arrangement_key()
        if name is None:  # pragma: no cover - the entry is dead without a graph
            return
        store = arrangement.remember(self._arrangements(), name, self._canvas.positions)
        _settings().setValue(_LAYOUT_KEY, arrangement.dump(store))
        self._idle("Arrangement saved.")

    def _reset_layout(self) -> None:
        """Put every activity back, and forget the arrangement that was saved.

        Both, because otherwise there is no way to be rid of a saved
        arrangement: reset, reopen the case, and it is back — which reads as the
        reset having failed rather than as having done half of what it says.
        """
        self._canvas.reset_layout()
        name = self._arrangement_key()
        if name is not None:
            _settings().setValue(
                _LAYOUT_KEY, arrangement.dump(arrangement.forget(self._arrangements(), name))
            )
        self._idle("Layout reset.")

    def _sync_arrangement_actions(self) -> None:
        """Grey out what there is nothing to do with.

        A live control that does nothing reads as a fault in the tool, and
        `Undo` is the one that changes most: it comes alive on the first drag
        and goes back out when the stack empties.
        """
        drawn = self._result is not None and bool(self._canvas._nodes)
        self._undo_action.setEnabled(drawn and self._canvas.can_undo)
        self._save_layout_action.setEnabled(drawn)
        self._reset_layout_action.setEnabled(drawn)

    def _apply_wrap(self) -> None:
        """Fold long traces or stop folding them, and remember which."""
        wrap = self._wrap_action.isChecked()
        # The arrangement for the wrap being switched *to*, handed over with the
        # instruction. `set_wrap` redraws once; asking it to redraw and then
        # redrawing again to place the nodes would double the cost of a toggle
        # on the graphs where it is already slowest.
        self._canvas.set_wrap(wrap, positions=self._saved_arrangement(wrap=wrap))
        _settings().setValue(_WRAP_KEY, wrap)

    def _apply_evidence_view(self) -> None:
        """How targets are shown in the evidence panel, and remember it.

        The `Show raw log lines` toggle that used to live beside this is gone:
        the detail pane prints the original line for the selected row always,
        which is strictly more than a global on-or-off could give.
        """
        decode = self._decode_action.isChecked()
        self._evidence.set_decode(decode)
        _settings().setValue(_DECODE_KEY, decode)

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
        # Gathered from the episodes the node names, not from `node.evidence`.
        # `graphbuild.build` cuts a behaviour node's merged references at twenty
        # and merges in episode order, so that tuple holds the earliest burst
        # and nothing of the latest however long it ran. The episodes still have
        # the lot, and taking it here leaves the exported graph untouched.
        refs = tuple(
            ref
            for episode in self._result.episodes
            if episode.episode_id in node.episode_ids
            for ref in episode.evidence
        )[:_EVIDENCE_LIMIT]

        def work(_: Callable[[str], None]) -> Any:
            with Case.open(path) as case:
                return case.read_evidence(refs)

        run_job(
            work,
            on_done=lambda lines: self._evidence.show_evidence(node, lines),
            on_error=self._report_error,
        )

    # -- export ------------------------------------------------------------

    def _export(self, kind: str) -> None:
        if self._result is None or self._case_path is None:
            QMessageBox.information(self, "Nothing to export", "Reconstruct a client first.")
            return

        filters = {
            "html": ("HTML report", "report.html", "HTML (*.html)"),
            "json": ("JSON graph", "graph.json", "JSON (*.json)"),
            "png": ("PNG image", "graph.png", "PNG (*.png)"),
        }
        title, suggested, mask = filters[kind]
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
            if kind == "json":
                import json

                target.write_text(json.dumps(bounded.to_dict(), indent=2), encoding="utf-8")
            else:
                with Case.open(case_path) as case:
                    target.write_text(render_report(bounded, case.manifest), encoding="utf-8")
            return str(target)

        run_job(
            work,
            on_done=lambda written: self._idle(f"Written to {written}"),
            on_error=self._report_error,
        )

    def _export_png(self, target: Path) -> None:
        """Rendered here rather than on a worker: painting needs the GUI thread."""
        from PyQt6.QtGui import QColor, QImage, QPainter

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
            self._report_error(f"Could not write {target}", "")

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

    def _report_error(self, message: str, detail: str) -> None:
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
    app = QApplication(sys.argv)
    app.setApplicationName("logarc")
    apply_theme(app)
    try:
        window = MainWindow()
    except Exception:
        traceback.print_exc()
        return 1
    window.show()
    window.offer_start()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
