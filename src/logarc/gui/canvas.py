"""The activity canvas: boxes and arrows on a QGraphicsView.

Draws what `graphbuild.layout` decided and `gui.style` described, and does no
deciding of its own. That split is what keeps the appearance of a finding
testable without a display.

QGraphicsView rather than an embedded browser: the graphs here are tens of
nodes, a scene graph handles that without a rendering engine, and QtWebEngine
would add hundreds of megabytes to a build whose point is that an investigator
can run it without installing anything. See ADR-0006.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetricsF,
    QPainter,
    QPainterPath,
    QPen,
    QPolygonF,
    QTransform,
    QWheelEvent,
)
from PyQt6.QtWidgets import (
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsPolygonItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
)

from logarc.core.graph import reciprocal_pairs
from logarc.graphbuild.layout import _COLUMN, _ROW, Point, layout_graph
from logarc.gui.style import (
    CAPTION_COLOUR,
    PAPER,
    PAPER_EDGE,
    SELECTION_COLOUR,
    SELECTION_WIDTH,
    THEME,
    edge_label,
    style_for,
    summarise,
)

if TYPE_CHECKING:
    from PyQt6.QtGui import QMouseEvent

    from logarc.core.graph import ActivityGraph, GraphNode

__all__ = ["MIN_FIT_SCALE", "STARTUP_MESSAGE", "WAITING_MESSAGE", "ActivityCanvas"]

#: What the canvas says while it has no graph. Two waits, two questions: before
#: a case is open there is no client to pick yet, and telling the reader to pick
#: one would point at an empty table.
STARTUP_MESSAGE: Final = "Open a case, or ingest logs into a new one."
WAITING_MESSAGE: Final = "Select a client to reconstruct what it did."

#: How far `fit` may shrink a graph. A long session trace is a wide, flat chain,
#: and fitting one to the window scales the whole scene down until the captions
#: inside the nodes are a grey smudge. Below this the graph stops carrying the
#: information it exists to carry, so the view stops at this scale and lets the
#: investigator pan instead. Requiring a pan is a smaller failure than
#: presenting a picture nobody can read.
MIN_FIT_SCALE: Final = 0.55

#: The scale text is sized against. Every caption is drawn `1 / _LEGIBLE_AT`
#: times larger in scene units, so that when the view sits at this scale the
#: words come out at exactly the point size they are written as — and a graph
#: that opens at the fit floor is captioned the size it always was.
#:
#: Tied to `MIN_FIT_SCALE` rather than chosen separately: the floor exists
#: because below it a graph stops carrying what it exists to carry, and the
#: captions are most of that.
_LEGIBLE_AT: Final = MIN_FIT_SCALE

#: How much clear ground a caption keeps around it, in scene units. Small: the
#: point is that captions do not touch, not that they stand apart.
_CAPTION_MARGIN: Final = 12.0

#: The size an activity's caption is written at, before `_LEGIBLE_AT` turns it
#: into scene units. Named because the layout has to measure the same text at
#: the same size the canvas will draw it, and two literals would drift.
_CAPTION_POINTS: Final = 7.5


def _spread(positions: dict[str, Point], graph: ActivityGraph) -> dict[str, Point]:
    """Stretch an abstract layout until this font's captions fit inside it.

    `layout.py` positions nodes in abstract units and says renderers scale from
    there. It cannot do better, because how wide a caption comes out is a fact
    about the font the platform hands us — the same 26 characters measure about
    190 units in Segoe UI and 475 under Qt's offscreen platform, which has no
    fonts at all. A spacing constant chosen against one of those is wrong for
    the other, and the failure it produces is captions written over each other.

    So the constant states the intent and this measures the reality: whatever
    the font, the columns end up at least a caption wide and the rows at least
    a caption tall. On a display where the numbers in `layout.py` already
    suffice this changes nothing, because the factor cannot go below one.
    """
    if not positions:
        return positions

    font = QFont()
    font.setPointSizeF(_CAPTION_POINTS / _LEGIBLE_AT)
    metrics = QFontMetricsF(font)
    widest = tallest = 0.0
    for node in graph.nodes:
        # Line by line. `summarise` has already broken the caption where it
        # wants it, and the single-argument `boundingRect` measures a newline
        # as a character rather than as a break — which reports one long line
        # and a stretch factor of 1.0, leaving the overlap it was meant to fix.
        lines = summarise(node).split("\n")
        widest = max(widest, max(metrics.horizontalAdvance(line) for line in lines))
        tallest = max(tallest, len(lines) * metrics.lineSpacing() + style_for(node).radius)

    across = max(1.0, (widest + _CAPTION_MARGIN) / _COLUMN)
    down = max(1.0, (tallest + _CAPTION_MARGIN) / _ROW)
    if across == 1.0 and down == 1.0:
        return positions
    return {
        node_id: Point(x=point.x * across, y=point.y * down) for node_id, point in positions.items()
    }


_PEN_STYLES: Final = {
    "solid": Qt.PenStyle.SolidLine,
    "dashed": Qt.PenStyle.DashLine,
    "dotted": Qt.PenStyle.DotLine,
}

#: The arrows between nodes, and the words on an empty canvas. From the theme:
#: a grey picked to sit on pale paper is close to invisible on a dark ground,
#: and these arrows are what make a trace a sequence rather than a scatter.
_EDGE_COLOUR: Final = THEME.edge_ink
_ARROW_LENGTH: Final = 12.0
_ARROW_WIDTH: Final = 7.0

#: How far a bowed edge leaves the straight line, in scene units. Only a pair
#: that leads both ways is bowed, so the curve carries meaning of its own: it
#: says *there are two arrows here*, and everywhere else the map stays straight.
_BOW: Final = 34.0

#: The numbers written on the arrows. Not `edge_ink`, which they were: at 5.5:1
#: against the ground they were three times dimmer than the captions beside
#: them and half a point smaller, and the eye — calibrated by the captions —
#: read straight past them. `muted` is 8.9:1, a value the theme already defines
#: rather than one invented here, sitting between the arrows' grey and the
#: caption's ink. Still a step below a caption, which is right: the activity is
#: the subject and the transition is the detail.
_LABEL_COLOUR: Final = THEME.muted
_LABEL_SIZE: Final = 7.5

#: Both written as pixels at `_LEGIBLE_AT`, and divided by it alongside the
#: point size — the space around a caption has to scale with the caption, or it
#: closes up at one zoom and gapes at another.
_CAPTION_GAP: Final = 6.0
_TEXT_PADDING: Final = 2.0
_ZOOM_STEP: Final = 1.15
_MIN_SCALE: Final = 0.15
_MAX_SCALE: Final = 6.0

#: The canvas grid: how far apart the dots sit, in scene units, and how wide
#: they are drawn on screen.
#:
#: A ground for the graph to sit on. Without one the largest region of the
#: window is an unbroken rectangle of one colour, which reads as a surface that
#: failed to draw rather than as a surface with nothing on it yet — the same
#: complaint that made an empty canvas look broken when it was pale.
#:
#: The pitch is in scene units so the grid pans with the graph and belongs to
#: it. The dot width is divided by the zoom before it is used, so a dot stays
#: the same size on screen however far in the view is — a texture, not another
#: thing that grows when the graph does.
_GRID_PITCH: Final = 24.0
_GRID_DOT: Final = 1.6

#: Below this zoom the dots are closer together on screen than they are wide,
#: and the grid stops reading as texture and starts reading as a wash over the
#: evidence. Drawn only while it is still a grid.
_GRID_MIN_SCALE: Final = 0.45


def _steps(start: float, stop: float) -> list[float]:
    """Grid lines from `start` up to `stop`, one pitch apart.

    Bounded rather than a bare `while`: the visible rectangle grows without
    limit as the view zooms out, and this is called on every repaint. The cap is
    far past any sane viewport and exists so a stray transform cannot turn a
    background paint into a hang.
    """
    count = min(int((stop - start) / _GRID_PITCH) + 1, 400)
    return [start + index * _GRID_PITCH for index in range(max(count, 0))]


class _NodeItem(QGraphicsEllipseItem):
    """One activity. Carries its node id so a click can be traced back."""

    def __init__(self, node: GraphNode, radius: float) -> None:
        super().__init__(QRectF(-radius, -radius, radius * 2, radius * 2))
        self.node_id = node.node_id
        # Deliberately *not* `ItemIsSelectable`.
        #
        # Nothing here ever asked Qt which item was selected — a click is read
        # off `itemAt` in `mousePressEvent` and answered with `node_selected`,
        # and the activity being read is marked by `highlight`, which draws its
        # own ring. The flag bought nothing and cost a dashed rectangle: Qt
        # paints one around a selected item, so the first click on an activity
        # boxed it, and the box vanished on the next click somewhere else.
        # Two marks for one selection, one of which looks like a rendering
        # fault.
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setZValue(1)


class ActivityCanvas(QGraphicsView):
    """Pan, zoom, and click a node to see what it is made of."""

    node_selected = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(QColor(PAPER)))
        # Framed, so the pinned light ground reads as a document lying on the
        # window rather than as a hole cut through it. Border only: the ground
        # itself stays the background brush above, where a test can see it.
        self.setStyleSheet(f"QGraphicsView {{ border: 1px solid {PAPER_EDGE}; }}")
        self._graph: ActivityGraph | None = None
        self._nodes: dict[str, _NodeItem] = {}
        self._halo: QGraphicsEllipseItem | None = None
        self._selected: str | None = None
        self._wrap = True
        # Something to read from the moment the window opens. Left to the case
        # being loaded, the largest region of the window spent the whole of
        # startup as blank paper inside dark chrome, which reads as a renderer
        # that failed rather than as a tool waiting to be given something.
        self.show_graph_placeholder(STARTUP_MESSAGE)

    def drawBackground(self, painter: QPainter | None, rect: QRectF) -> None:  # noqa: N802
        """The ground under the graph: the theme's colour, then its grid.

        On the *view* rather than the scene, deliberately. `QGraphicsScene.render`
        — which is what `Export ▸ PNG image` calls — paints the scene's
        background and its items, and never the view's. So an exported graph
        gets the flat fill `_export_png` gives it and none of this, which is the
        right answer: a grid is an on-screen affordance for panning, and printing
        it into a deliverable would put texture behind evidence.
        """
        super().drawBackground(painter, rect)
        if painter is None:  # pragma: no cover - Qt always supplies one
            return
        scale = self.transform().m11()
        if scale < _GRID_MIN_SCALE:
            return

        pen = QPen(QColor(THEME.grid_dot))
        # In scene units, so the division cancels the zoom and the dot lands the
        # same size on screen at every magnification.
        pen.setWidthF(_GRID_DOT / scale)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)

        first_x = math.floor(rect.left() / _GRID_PITCH) * _GRID_PITCH
        first_y = math.floor(rect.top() / _GRID_PITCH) * _GRID_PITCH
        points = [
            QPointF(x, y)
            for x in _steps(first_x, rect.right())
            for y in _steps(first_y, rect.bottom())
        ]
        if points:
            painter.drawPoints(*points)

    @property
    def graph_scene(self) -> QGraphicsScene:
        """The scene, without the optionality the stubs put on `scene()`."""
        return self._scene

    @property
    def wrap(self) -> bool:
        """Whether a long trace is folded onto further rows."""
        return self._wrap

    def set_wrap(self, wrap: bool) -> None:
        """Fold long traces onto further rows, or lay each one out on one line.

        Redraws at once, and puts the ring back on whatever was being read — at
        the coordinates the node has moved to. The evidence panel beside the
        canvas goes on showing that episode across the redraw, so a canvas that
        stopped pointing at it, or pointed at where it used to be, would leave
        the two halves of the window describing different activities.

        Safe to call before anything is drawn: the window applies the remembered
        setting while it is still being built, which is long before a case has
        been opened.
        """
        if wrap == self._wrap:
            return
        self._wrap = wrap
        if self._graph is None:
            return
        selected = self._selected
        self.show_graph(self._graph)
        if selected is not None:
            self.highlight(selected)

    # -- drawing -----------------------------------------------------------

    def highlight(self, node_id: str) -> None:
        """Ring the activity whose evidence is being read.

        One ring at a time, moved rather than added to: drawn per click and left
        behind, every node ever clicked would look selected, which is worse than
        marking none of them.
        """
        if self._halo is not None:
            self._scene.removeItem(self._halo)
            self._halo = None

        item = self._nodes.get(node_id)
        if item is None:
            self._selected = None
            return
        self._selected = node_id

        radius = item.rect().width() / 2 + SELECTION_WIDTH + 2.0
        halo = QGraphicsEllipseItem(QRectF(-radius, -radius, radius * 2, radius * 2))
        halo.setPos(item.pos())
        pen = QPen(QColor(SELECTION_COLOUR))
        pen.setWidthF(SELECTION_WIDTH)
        halo.setPen(pen)
        halo.setBrush(QBrush(Qt.BrushStyle.NoBrush))
        # Under the node so the outcome border stays the outermost thing read,
        # and above the edges so the ring is not cut by an arrow passing behind.
        halo.setZValue(0.5)
        self._scene.addItem(halo)
        self._halo = halo

    def show_graph(self, graph: ActivityGraph) -> None:
        """Replace whatever is on the canvas with `graph`."""
        self._graph = graph
        self._scene.clear()
        self._nodes.clear()
        self._halo = None
        self._selected = None

        positions = _spread(layout_graph(graph, wrap=self._wrap), graph)
        if not positions:
            self._show_message("This client has no reconstructed activity.")
            return

        by_id = {node.node_id: node for node in graph.nodes}
        # Resolved once for the whole graph rather than per edge: the question is
        # about the graph, and asking it inside the loop would be quadratic in
        # the edge count for an answer that cannot change while drawing.
        paired = reciprocal_pairs(graph)
        for edge in graph.edges:
            if edge.source in positions and edge.target in positions:
                self._draw_edge(
                    positions[edge.source],
                    positions[edge.target],
                    by_id[edge.source],
                    by_id[edge.target],
                    label=edge_label(graph.kind, weight=edge.weight, gap_seconds=edge.gap_seconds),
                    weight=edge.weight,
                    paired=frozenset((edge.source, edge.target)) in paired,
                )
        for node in graph.nodes:
            self._draw_node(node, positions[node.node_id])

        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(-80, -80, 80, 80))
        self.fit()

    def show_graph_placeholder(self, text: str = WAITING_MESSAGE) -> None:
        """Clear the canvas back to its waiting state.

        The wording is a parameter because the two waits are different
        questions: before a case is open there is no client to pick.
        """
        self._graph = None
        self._scene.clear()
        self._nodes.clear()
        self._halo = None
        self._selected = None
        self._show_message(text)

    def _show_message(self, text: str) -> None:
        item = QGraphicsSimpleTextItem(text)
        item.setBrush(QBrush(QColor(_EDGE_COLOUR)))
        self._scene.addItem(item)
        self._scene.setSceneRect(item.boundingRect().adjusted(-40, -40, 40, 40))
        self.fit()

    def _draw_node(self, node: GraphNode, position: Point) -> None:
        style = style_for(node)
        item = _NodeItem(node, style.radius)
        item.setBrush(QBrush(QColor(style.fill)))
        pen = QPen(QColor(style.border.colour))
        pen.setStyle(_PEN_STYLES[style.border.style])
        pen.setWidthF(style.border.width)
        item.setPen(pen)
        item.setPos(position.x, position.y)
        item.setToolTip(_tooltip(node))
        self._scene.addItem(item)
        self._nodes[node.node_id] = item

        # Below the circle, not inside it. An activity name long enough to mean
        # something does not fit in a node sized by request count, and the
        # version that did fit was a smudge at the scale the graph opens at.
        #
        # Anchored on the rim of the circle, and the room it needs is bought in
        # `layout.py` rather than by exempting the words from the zoom: the
        # spacing there is set so a caption of this size clears its neighbours
        # and the circles either side of it.
        self._canvas_text(
            summarise(node),
            colour=CAPTION_COLOUR,
            point_size=_CAPTION_POINTS,
            anchor=QPointF(0.0, style.radius),
            gap=_CAPTION_GAP,
            parent=item,
        )

    def _canvas_text(
        self,
        text: str,
        *,
        colour: str,
        point_size: float,
        anchor: QPointF,
        gap: float = 0.0,
        parent: QGraphicsItem | None = None,
    ) -> QGraphicsRectItem:
        """Text on the canvas, scaling with the drawing it belongs to.

        The whole picture grows and shrinks together, the way zooming a
        photograph does. That is what makes overlap a property of the layout
        rather than of the zoom: two captions that clear each other at one scale
        clear each other at every scale, so the spacing in `layout.py` can be
        set once and the question never comes back.

        This is a reversal, and the reason is worth keeping. Text here used to
        be pinned to screen size, because `fit()` — which exists to frame a
        whole graph — drew captions about five pixels tall on a wrapped trace,
        and a legible graph with illegible labels is a picture of circles.
        Pinning fixed that and produced the opposite fault: the geometry shrank
        while the words did not, so captions that were clear at full zoom piled
        into one another further out — 117 overlapping pairs at 0.35 on a
        52-activity trace, which is exactly the zoom someone uses to see the
        shape of a long session.

        The original fault is answered by `_LEGIBLE_AT` instead, which is where
        it belongs: the risk was never that captions scaled, it was that they
        became too small to read at the scale a graph opens at.

        The backdrop stays. A caption used to be crossed by whatever arrow
        passed behind it, and that is still true without a patch of ground
        beneath the words.
        """
        backdrop = QGraphicsRectItem(parent)
        backdrop.setBrush(QBrush(QColor(PAPER)))
        backdrop.setPen(QPen(Qt.PenStyle.NoPen))
        # Above the edges, below the nodes: the words survive an arrow passing
        # behind them without hiding the circle they describe.
        backdrop.setZValue(0.6)
        backdrop.setPos(anchor)
        if parent is None:
            self._scene.addItem(backdrop)

        label = QGraphicsSimpleTextItem(text, backdrop)
        label.setBrush(QBrush(QColor(colour)))
        font = QFont()
        font.setPointSizeF(point_size / _LEGIBLE_AT)
        label.setFont(font)
        bounds = label.boundingRect()
        padding = _TEXT_PADDING / _LEGIBLE_AT
        label.setPos(padding, padding)
        backdrop.setRect(
            0.0,
            0.0,
            bounds.width() + padding * 2,
            bounds.height() + padding * 2,
        )

        # In scene units, like everything else here, so the centring and the gap
        # hold at every zoom by scaling rather than by being exempt from it.
        backdrop.setTransform(
            QTransform().translate(-(bounds.width() + padding * 2) / 2, gap / _LEGIBLE_AT)
        )
        return backdrop

    def _draw_edge(
        self,
        start: Point,
        end: Point,
        source: GraphNode,
        target: GraphNode,
        *,
        label: str,
        weight: int,
        paired: bool = False,
    ) -> None:
        # Stop the line at each circle's edge rather than its centre, so the
        # arrowhead lands where the eye expects it.
        begin = QPointF(start.x, start.y)
        finish = QPointF(end.x, end.y)
        angle = math.atan2(finish.y() - begin.y(), finish.x() - begin.x())
        begin += QPointF(
            math.cos(angle) * style_for(source).radius, math.sin(angle) * style_for(source).radius
        )
        finish -= QPointF(
            math.cos(angle) * style_for(target).radius, math.sin(angle) * style_for(target).radius
        )

        middle = (begin + finish) / 2
        path = QPainterPath(begin)
        arriving = angle
        if paired:
            # Perpendicular to the direction of travel, so A->B leaves one way
            # and B->A the other, symmetrically, without either edge needing to
            # know the other exists. A quadratic control point at twice the bow
            # puts the apex of the curve at the bow itself, which is where the
            # label goes — and is what separates the pair's two numbers.
            away = QPointF(-math.sin(angle), math.cos(angle))
            control = middle + away * (_BOW * 2)
            path.quadTo(control, finish)
            anchor = middle + away * _BOW
            # A quadratic arrives along `finish - control`. Left pointing down
            # the straight line instead, the head is turned about twenty degrees
            # against the curve it caps — and the head is what says which way
            # the transition ran.
            approach = finish - control
            arriving = math.atan2(approach.y(), approach.x())
        else:
            path.lineTo(finish)
            anchor = middle
        line = QGraphicsPathItem(path)
        pen = QPen(QColor(_EDGE_COLOUR))
        # A transition seen many times is drawn heavier, which is the only thing
        # separating a habit from a one-off on the behaviour map.
        pen.setWidthF(min(1.0 + math.log1p(weight), 5.0))
        line.setPen(pen)
        line.setZValue(0)
        self._scene.addItem(line)

        head = QPolygonF(
            [
                finish,
                finish
                - QPointF(
                    math.cos(arriving - math.pi / 8) * _ARROW_LENGTH,
                    math.sin(arriving - math.pi / 8) * _ARROW_LENGTH,
                ),
                finish
                - QPointF(
                    math.cos(arriving + math.pi / 8) * _ARROW_LENGTH,
                    math.sin(arriving + math.pi / 8) * _ARROW_LENGTH,
                ),
            ]
        )
        arrow = QGraphicsPolygonItem(head)
        arrow.setPen(pen)
        arrow.setBrush(QBrush(QColor(_EDGE_COLOUR)))
        arrow.setZValue(0)
        self._scene.addItem(arrow)

        if label:
            self._canvas_text(
                label,
                colour=_LABEL_COLOUR,
                point_size=_LABEL_SIZE,
                anchor=QPointF(anchor.x(), anchor.y() - _ARROW_WIDTH * 2),
            )

    # -- interaction -------------------------------------------------------

    def mousePressEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802 - Qt's naming
        super().mousePressEvent(event)
        if event is None:  # pragma: no cover - Qt always supplies one
            return
        item = self.itemAt(event.pos())
        while item is not None and not isinstance(item, _NodeItem):
            item = item.parentItem()
        if isinstance(item, _NodeItem):
            self.node_selected.emit(item.node_id)

    def wheelEvent(self, event: QWheelEvent | None) -> None:  # noqa: N802 - Qt's naming
        if event is None:  # pragma: no cover - Qt always supplies one
            return
        step = _ZOOM_STEP if event.angleDelta().y() > 0 else 1 / _ZOOM_STEP
        scale = self.transform().m11() * step
        if _MIN_SCALE <= scale <= _MAX_SCALE:
            self.scale(step, step)

    def fit(self) -> None:
        """Frame the whole graph, down to the point where it stays readable."""
        if not self._scene.items():
            return
        self.fitInView(self._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        scale = self.transform().m11()
        if scale < MIN_FIT_SCALE:
            self.resetTransform()
            self.scale(MIN_FIT_SCALE, MIN_FIT_SCALE)
            # Clamped, so the graph is wider than the window and something has
            # to be off screen. Open on the beginning rather than on whatever
            # the view was centred over: with an unwrapped trace that clamps on
            # every draw, centring hides both ends and starts the reader in the
            # middle of a chronology.
            self.centerOn(self._scene.sceneRect().topLeft())


def _tooltip(node: GraphNode) -> str:
    parts = [
        node.label,
        f"{node.request_count:,} requests over {node.distinct_paths:,} path(s)",
        f"outcome: {node.outcome.value}",
        f"severity: {node.severity.name.lower()}",
    ]
    if node.owasp:
        parts.append(f"OWASP {node.owasp}")
    if node.top_targets:
        parts.append("targets: " + ", ".join(node.top_targets[:3]))
    parts.append(f"{node.start:%Y-%m-%d %H:%M:%S} → {node.end:%H:%M:%S}")
    return "\n".join(parts)
