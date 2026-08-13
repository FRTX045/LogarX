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

from logarc.graphbuild.layout import Point, layout_graph
from logarc.gui.style import (
    CAPTION_COLOUR,
    SELECTION_COLOUR,
    SELECTION_WIDTH,
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

_PEN_STYLES: Final = {
    "solid": Qt.PenStyle.SolidLine,
    "dashed": Qt.PenStyle.DashLine,
    "dotted": Qt.PenStyle.DotLine,
}

#: The canvas ground. Pinned rather than taken from the palette so a finding
#: reads the same on screen as in the exported report — see the evidence panel,
#: which pins the same colour for the same reason.
_PAPER: Final = "#f5f7fa"

_EDGE_COLOUR: Final = "#616e7c"
_ARROW_LENGTH: Final = 12.0
_ARROW_WIDTH: Final = 7.0

#: Both in screen pixels: text on this canvas is drawn at screen size, so the
#: space around it has to be measured the same way or it closes up as the graph
#: is scaled down.
_CAPTION_GAP: Final = 6.0
_TEXT_PADDING: Final = 2.0
_ZOOM_STEP: Final = 1.15
_MIN_SCALE: Final = 0.15
_MAX_SCALE: Final = 6.0


class _NodeItem(QGraphicsEllipseItem):
    """One activity. Carries its node id so a click can be traced back."""

    def __init__(self, node: GraphNode, radius: float) -> None:
        super().__init__(QRectF(-radius, -radius, radius * 2, radius * 2))
        self.node_id = node.node_id
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
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
        self.setBackgroundBrush(QBrush(QColor("#f5f7fa")))
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

        positions = layout_graph(graph, wrap=self._wrap)
        if not positions:
            self._show_message("This client has no reconstructed activity.")
            return

        by_id = {node.node_id: node for node in graph.nodes}
        for edge in graph.edges:
            if edge.source in positions and edge.target in positions:
                self._draw_edge(
                    positions[edge.source],
                    positions[edge.target],
                    by_id[edge.source],
                    by_id[edge.target],
                    label=edge_label(graph.kind, weight=edge.weight, gap_seconds=edge.gap_seconds),
                    weight=edge.weight,
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
        # Anchored on the rim of the circle; the gap and the centring are applied
        # in screen pixels by `_screen_text`, so they do not shrink with the zoom
        # the way a scene-unit offset did — which is how a caption ended up drawn
        # through the node it belongs to.
        self._screen_text(
            summarise(node),
            colour=CAPTION_COLOUR,
            point_size=7.5,
            anchor=QPointF(0.0, style.radius),
            gap=_CAPTION_GAP,
            parent=item,
        )

    def _screen_text(
        self,
        text: str,
        *,
        colour: str,
        point_size: float,
        anchor: QPointF,
        gap: float = 0.0,
        parent: QGraphicsItem | None = None,
    ) -> QGraphicsRectItem:
        """Text on the canvas, at the size the screen draws it.

        Everything written on this canvas used to scale with the scene, so
        `fit()` — which exists to frame the whole graph — was also what made the
        graph's labels unreadable, about five pixels tall on a wrapped trace.
        The geometry is what carries the comparison and should scale; the words
        are words at any zoom.

        Flagged on the patch rather than the text, with the text as its child:
        children of an item that ignores transformations share its unscaled
        space, so one flag and one transform carry both the backdrop and the
        centring. That patch is the second half of the fix — a caption used to
        be crossed by whatever arrow passed behind it.
        """
        backdrop = QGraphicsRectItem(parent)
        backdrop.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIgnoresTransformations, True)
        backdrop.setBrush(QBrush(QColor(_PAPER)))
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
        font.setPointSizeF(point_size)
        label.setFont(font)
        bounds = label.boundingRect()
        label.setPos(_TEXT_PADDING, _TEXT_PADDING)
        backdrop.setRect(
            0.0,
            0.0,
            bounds.width() + _TEXT_PADDING * 2,
            bounds.height() + _TEXT_PADDING * 2,
        )

        # In screen pixels, because the item ignores the view's transform: the
        # centring and the gap hold at every zoom.
        backdrop.setTransform(
            QTransform().translate(-(bounds.width() + _TEXT_PADDING * 2) / 2, gap)
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

        path = QPainterPath(begin)
        path.lineTo(finish)
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
                    math.cos(angle - math.pi / 8) * _ARROW_LENGTH,
                    math.sin(angle - math.pi / 8) * _ARROW_LENGTH,
                ),
                finish
                - QPointF(
                    math.cos(angle + math.pi / 8) * _ARROW_LENGTH,
                    math.sin(angle + math.pi / 8) * _ARROW_LENGTH,
                ),
            ]
        )
        arrow = QGraphicsPolygonItem(head)
        arrow.setPen(pen)
        arrow.setBrush(QBrush(QColor(_EDGE_COLOUR)))
        arrow.setZValue(0)
        self._scene.addItem(arrow)

        if label:
            middle = (begin + finish) / 2
            self._screen_text(
                label,
                colour=_EDGE_COLOUR,
                point_size=7.0,
                anchor=QPointF(middle.x(), middle.y() - _ARROW_WIDTH * 2),
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
