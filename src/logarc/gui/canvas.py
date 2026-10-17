"""The activity canvas: boxes and arrows on a QGraphicsView.

Draws what `graphbuild.layout` decided and `logarc.style` described, and does no
deciding of its own. That split is what keeps the appearance of a finding
testable without a display.

QGraphicsView rather than an embedded browser: the graphs here are tens of
nodes, a scene graph handles that without a rendering engine, and QtWebEngine
would add hundreds of megabytes to a build whose point is that an investigator
can run it without installing anything. See ADR-0006.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetricsF,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
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
    QGraphicsSceneMouseEvent,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QToolButton,
)

from logarc.core.graph import GraphKind, reciprocal_pairs
from logarc.graphbuild.layout import COLUMN, ROW, Point, layout_graph, sessions_in
from logarc.gui.arrangement import Move, MoveHistory, Positions
from logarc.style import (
    CAPTION_COLOUR,
    PAPER,
    PAPER_EDGE,
    SELECTION_COLOUR,
    SELECTION_WIDTH,
    SESSION_GROUND,
    THEME,
    edge_label,
    session_caption,
    style_for,
    summarise,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtGui import QMouseEvent, QResizeEvent

    from logarc.core.graph import ActivityGraph, GraphNode

__all__ = ["MIN_FIT_SCALE", "STARTUP_MESSAGE", "WAITING_MESSAGE", "ActivityCanvas"]

#: What the canvas says while it has no graph. Two waits, two questions: before
#: a case is open there is no client to pick yet, and telling the reader to pick
#: one would point at an empty table.
STARTUP_MESSAGE: Final = "Open a case, or ingest logs into a new one."
WAITING_MESSAGE: Final = "Select an IP."

#: Leave more room around the empty-canvas message than around an activity graph.
_PLACEHOLDER_SCALE: Final = 0.75

#: The short IP prompt is enlarged more by fitting. Keep it 60% smaller without
#: shrinking the longer startup instruction.
_IP_PROMPT_SCALE: Final = _PLACEHOLDER_SCALE * 0.4

#: How far `fit` may shrink a graph. A long session trace is a wide, flat chain,
#: and fitting one to the window scales the whole scene down until the captions
#: inside the nodes are a grey smudge. Below this the graph stops carrying the
#: information it exists to carry, so the view stops at this scale and lets the
#: investigator pan instead. Requiring a pan is a smaller failure than
#: presenting a picture nobody can read.
MIN_FIT_SCALE: Final = 0.8

#: How far the corner button sits from the canvas edge. Small, because the
#: patch it covers is a patch of graph given up.
_EXPAND_INSET: Final = 12

#: The corner button's own colours, named here so they can be measured.
#:
#: They are read against `PAPER`, not against the window chrome. The button is
#: a window control by function and a canvas resident by position, and it
#: shipped styled for the first: `raised` on `surface` is 1.08:1, with a
#: 1.83:1 edge. It was drawn, it was on top, and it took its own press — and it
#: still could not be found.
#:
#: What carries it is the edge and the mark, not the fill. On a ground this
#: dark the fill has almost nowhere to go: `stripe` is 1.19:1, barely better
#: than what it replaces. `muted` gives the edge 8.9:1 and `ink` gives the mark
#: 13.9:1 against that fill, and those two are what make it findable.
_EXPAND_GROUND: Final = THEME.stripe
_EXPAND_EDGE: Final = THEME.muted
_EXPAND_INK: Final = THEME.ink

#: The drawn mark, the button around it, and the pen that draws it. Fixed
#: rather than fitted to its contents: the size then owes nothing to the font
#: or the platform style, so the button is the same on this machine and on the
#: CI runners, where a size that came out different once already turned a
#: passing suite red.
_EXPAND_ICON: Final = 16
_EXPAND_SIDE: Final = 30
_EXPAND_MARGIN: Final = 2
_EXPAND_ARM: Final = 4
_EXPAND_PEN: Final = 2.0

#: Reference scale for scene typography. Keep geometry stable while raising
#: the minimum viewing scale: a 7.5pt caption now opens at about 11pt or larger.
_LEGIBLE_AT: Final = 0.55

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

    across = max(1.0, (widest + _CAPTION_MARGIN) / COLUMN)
    down = max(1.0, (tallest + _CAPTION_MARGIN) / ROW)
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

#: The canvas grid: spacing and dot width in screen pixels.
#:
#: A ground for the graph to sit on. Without one the largest region of the
#: window is an unbroken rectangle of one colour, which reads as a surface that
#: failed to draw rather than as a surface with nothing on it yet — the same
#: complaint that made an empty canvas look broken when it was pale.
#:
#: Divide both measurements by the zoom so this remains a background texture
#: at every scale, including when the short IP prompt is fitted to the canvas.
#: The dots remain anchored to the scene origin so they follow panning.
_GRID_PITCH: Final = 20.0
_GRID_DOT: Final = 1.6
_GRID_OPACITY: Final = 0.39

#: How heavy an arrow is drawn while the node it hangs off is being moved.
#: A floor, not a replacement: a weight-1 transition comes out at 1.7 units,
#: which is thin enough that a change of colour alone is easy to miss.
_LIT_WIDTH: Final = 2.0

#: Clear ground kept around the graph, in scene units.
#:
#: Two jobs, both about the graph and neither about the window. `fit` frames
#: the graph plus this, so the outermost captions are not pressed against the
#: frame; and `_grow_scene_for` reaches this far past a node dragged beyond the
#: paper, so it arrives with room around it rather than flush to the edge.
#:
#: Small enough not to matter to either. It used to have to be: while the view
#: hung its scrollbars on this rectangle, ground kept here was ground the
#: reader could be asked to scroll into, and at 80 it bought two bars over a
#: graph that fitted its window with 176 units to spare. The bars are gone now,
#: so this number no longer decides anything the reader sees.
_SCENE_MARGIN: Final = 24.0

#: A session's box. Drawn round the activities of one visit on a trace, so the
#: header's "69 sessions" has something on the canvas to answer to.
#:
#: The padding is what keeps two boxes apart: sessions are laid out two rows
#: apart, and at 20 the closest two boxes on the shopfront excerpt still have
#: 91 units of paper between them (192.0.2.231, 69 sessions; 203.0.113.6, 150).
_SESSION_PAD: Final = 20.0
_SESSION_CORNER: Final = 14.0
#: The outline and the label, both `muted`: 8.4:1 on the box ground, a step
#: below the captions it holds, which is the order they should be read in.
_SESSION_EDGE: Final = THEME.muted
_SESSION_EDGE_WIDTH: Final = 1.4
_SESSION_INK: Final = THEME.muted
#: A heading for the box, a point above the captions inside it.
_SESSION_POINTS: Final = 8.5


def _steps(start: float, stop: float, pitch: float) -> list[float]:
    """Grid lines from `start` up to `stop`, one pitch apart.

    Bounded rather than a bare `while`: the visible rectangle grows without
    limit as the view zooms out, and this is called on every repaint. The cap is
    far past any sane viewport and exists so a stray transform cannot turn a
    background paint into a hang.
    """
    count = min(int((stop - start) / pitch) + 1, 400)
    return [start + index * pitch for index in range(max(count, 0))]


@dataclass(frozen=True, slots=True)
class _EdgeShape:
    """Where one arrow goes, as geometry, before anything is drawn.

    Separated from the drawing because two code paths now need it: the one that
    puts a graph on the canvas, and the one that follows a node being dragged.
    Left to compute their own, they drift — and the drift shows as arrows that
    snap into a different shape the moment the mouse is let go.
    """

    path: QPainterPath
    head: QPolygonF
    anchor: QPointF
    """The point the transition is *about*: the middle of a straight arrow, the
    apex of a bowed one."""

    length: float
    """How far the arrow reaches, rim to rim. What decides whether there is room
    to write a number on it."""

    @property
    def label_at(self) -> QPointF:
        """Where the number sits: clear of the arrow, not on top of it."""
        return QPointF(self.anchor.x(), self.anchor.y() - _ARROW_WIDTH * 2)


def _edge_width(weight: int) -> float:
    """How heavy an arrow is drawn.

    A transition seen many times is drawn heavier, which is the only thing
    separating a habit from a one-off on the behaviour map. Named because the
    pen is also *rebuilt* — after a drag puts the accent on it — and a second
    copy of this expression would let a dragged arrow come back thinner than it
    went in.
    """
    return min(1.0 + math.log1p(weight), 5.0)


def _edge_shape(
    start: QPointF,
    end: QPointF,
    *,
    source_radius: float,
    target_radius: float,
    paired: bool,
) -> _EdgeShape:
    """One arrow between two centres, stopped at the rims.

    Against the circles rather than through them, so the arrowhead lands where
    the eye expects it.
    """
    angle = math.atan2(end.y() - start.y(), end.x() - start.x())
    begin = start + QPointF(math.cos(angle) * source_radius, math.sin(angle) * source_radius)
    finish = end - QPointF(math.cos(angle) * target_radius, math.sin(angle) * target_radius)

    middle = (begin + finish) / 2
    path = QPainterPath(begin)
    arriving = angle
    if paired:
        # Perpendicular to the direction of travel, so A->B leaves one way and
        # B->A the other, symmetrically, without either edge needing to know the
        # other exists. A quadratic control point at twice the bow puts the apex
        # of the curve at the bow itself, which is where the label goes — and is
        # what separates the pair's two numbers.
        away = QPointF(-math.sin(angle), math.cos(angle))
        control = middle + away * (_BOW * 2)
        path.quadTo(control, finish)
        anchor = middle + away * _BOW
        # A quadratic arrives along `finish - control`. Left pointing down the
        # straight line instead, the head is turned about twenty degrees against
        # the curve it caps — and the head is what says which way it ran.
        approach = finish - control
        arriving = math.atan2(approach.y(), approach.x())
    else:
        path.lineTo(finish)
        anchor = middle

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
    return _EdgeShape(
        path=path,
        head=head,
        anchor=anchor,
        length=math.hypot(finish.x() - begin.x(), finish.y() - begin.y()),
    )


class _EdgeArt:
    """One arrow already on the canvas, and what it takes to move it.

    The items are *reshaped*, not replaced, so a node with three arrows on it
    does not create and destroy nine scene items per mouse-move event.

    Measured, on a native Qt platform, for one such event: 0.30 ms against
    0.52 ms rebuilding on a 50-node trace, and 0.34 ms against 0.80 ms on 600.
    About twice as cheap, and worth having — but both sit well inside a 16 ms
    frame, so this is not what would have made a drag stutter. Nothing here
    would have, at the sizes this tool draws.
    """

    __slots__ = (
        "head",
        "label",
        "line",
        "paired",
        "source_id",
        "source_radius",
        "target_id",
        "target_radius",
        "weight",
    )

    def __init__(
        self,
        *,
        source_id: str,
        target_id: str,
        source_radius: float,
        target_radius: float,
        line: QGraphicsPathItem,
        head: QGraphicsPolygonItem,
        label: QGraphicsRectItem | None,
        weight: int,
        paired: bool,
    ) -> None:
        self.source_id = source_id
        self.target_id = target_id
        self.source_radius = source_radius
        self.target_radius = target_radius
        self.line = line
        self.head = head
        self.label = label
        self.weight = weight
        self.paired = paired

    def reshape(self, start: QPointF, end: QPointF) -> None:
        """Redraw this arrow between two centres it has moved to."""
        self.place(
            _edge_shape(
                start,
                end,
                source_radius=self.source_radius,
                target_radius=self.target_radius,
                paired=self.paired,
            )
        )

    def place(self, shape: _EdgeShape) -> None:
        """Put the line, the head and the number where `shape` says.

        Called both when the graph is drawn and when a node is dragged, so a
        graph opened on a saved arrangement is subject to the same rules as one
        the reader has just rearranged.
        """
        self.line.setPath(shape.path)
        self.head.setPolygon(shape.head)
        if self.label is not None:
            self.label.setPos(shape.label_at)
            # The number sits on a patch of ground so an arrow passing behind it
            # cannot cross the text. Two activities dragged close together leave
            # an arrow shorter than that patch is wide, and then the patch hides
            # the whole arrow — the graph stops showing a transition it has.
            #
            # Structure before detail: the transition has to go on reading as an
            # arrow, and the number is what gives way. Compared on width alone,
            # which over-hides slightly on a steep diagonal — where the patch is
            # taller than the arrow is long, and covers it anyway.
            room = shape.length > self.label.rect().width() + _ARROW_LENGTH * 2
            self.label.setVisible(room)


class _SessionBox:
    """One session's box on the canvas: the fill and outline, the label, and
    which activities it holds.

    Reshaped, never rebuilt, when one of its activities moves, for the reason
    `_EdgeArt` is: a drag sends a position change per mouse-move event.
    """

    __slots__ = ("label", "node_ids", "shape")

    def __init__(
        self, *, shape: QGraphicsPathItem, label: QGraphicsRectItem, node_ids: tuple[str, ...]
    ) -> None:
        self.shape = shape
        self.label = label
        self.node_ids = node_ids

    def reshape(self, around: QRectF) -> None:
        """Fit the box to `around`, the activities it holds, in scene units.

        Raised at the top by the label's height so the label sits above the
        first row, and never narrower than the label: a one-activity session's
        label is wider than its activity, and it would otherwise run out over
        the edge of its own box.
        """
        head = self.label.rect().height()
        width = max(around.width(), self.label.rect().width()) + _SESSION_PAD * 2
        box = QRectF(
            around.left() - _SESSION_PAD,
            around.top() - _SESSION_PAD - head,
            width,
            around.height() + _SESSION_PAD * 2 + head,
        )
        path = QPainterPath()
        path.addRoundedRect(box, _SESSION_CORNER, _SESSION_CORNER)
        self.shape.setPath(path)
        self.label.setPos(box.left() + _SESSION_PAD / 2, box.top() + _SESSION_PAD / 2)


class _NodeItem(QGraphicsEllipseItem):
    """One activity. Carries its node id so a click can be traced back.

    Movable. `QGraphicsView.mousePressEvent` offers the press to the scene
    first and only starts hand-scrolling if nothing took it, so a movable item
    and `ScrollHandDrag` do not fight: a press on an activity drags the
    activity, and a press on the ground pans the view.
    """

    def __init__(
        self,
        node: GraphNode,
        radius: float,
        *,
        on_move: Callable[[str], None],
        on_grab: Callable[[str], None],
        on_drop: Callable[[Move], None],
    ) -> None:
        super().__init__(QRectF(-radius, -radius, radius * 2, radius * 2))
        self.node_id = node.node_id
        self._on_move = on_move
        self._on_grab = on_grab
        self._on_drop = on_drop
        self._pressed_at: QPointF | None = None
        self._grabbed = False
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
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setZValue(1)

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value: Any) -> Any:  # noqa: N802 - Qt's naming
        """Tell the canvas, so the arrows and the ring can keep up.

        On `HasChanged` rather than `Change`: the position is already the new
        one, so everything that reads it agrees with what is on screen. On
        `Change` the item has not moved yet and every arrow would be reshaped
        one mouse-move behind the node it is attached to.
        """
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            # On the first movement of a press, not on the press itself. Lit
            # from the press, every click on an activity would flash the arrows
            # around it, and the light would stop meaning *this is what you are
            # moving*.
            if self._pressed_at is not None and not self._grabbed:
                self._grabbed = True
                self._on_grab(self.node_id)
            self._on_move(self.node_id)
        return super().itemChange(change, value)

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent | None) -> None:  # noqa: N802 - Qt's naming
        # Not the closed hand: `ScrollHandDrag` already shows that for panning,
        # so the two gestures would look identical while doing different things.
        self.setCursor(Qt.CursorShape.SizeAllCursor)
        self._pressed_at = QPointF(self.pos())
        self._grabbed = False
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event: QGraphicsSceneMouseEvent | None) -> None:  # noqa: N802 - Qt's naming
        super().mouseReleaseEvent(event)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        started = self._pressed_at if self._pressed_at is not None else self.pos()
        self._pressed_at = None
        self._grabbed = False
        self._on_drop(
            Move(
                node_id=self.node_id,
                before=(started.x(), started.y()),
                after=(self.pos().x(), self.pos().y()),
            )
        )


def _expand_mark(colour: str, *, inward: bool = False) -> QPixmap:
    """Four corner brackets, drawn rather than borrowed from a font.

    The glyph this replaces, `U+26F6`, falls to Segoe UI Emoji on Windows,
    which refuses the pen and paints its own multicoloured mark eight pixels
    across; the Linux runners have no such face and render something else
    again. Drawing it takes the colour the theme was measured with and gets the
    same picture on every machine.

    `inward` turns the brackets around. Outward the joints sit in the corners
    and the arms run toward the middle, which reads as room being taken;
    inward they meet where those arms ended and run back out, which reads as
    room being given up.
    """
    mark = QPixmap(_EXPAND_ICON, _EXPAND_ICON)
    mark.fill(QColor(0, 0, 0, 0))
    painter = QPainter(mark)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor(colour), _EXPAND_PEN, cap=Qt.PenCapStyle.FlatCap))
    near, far = _EXPAND_MARGIN, _EXPAND_ICON - _EXPAND_MARGIN
    for corner_x, towards_x in ((near, 1), (far, -1)):
        for corner_y, towards_y in ((near, 1), (far, -1)):
            reach_x = towards_x * _EXPAND_ARM
            reach_y = towards_y * _EXPAND_ARM
            joint_x = corner_x + reach_x if inward else corner_x
            joint_y = corner_y + reach_y if inward else corner_y
            end_x = corner_x if inward else corner_x + reach_x
            end_y = corner_y if inward else corner_y + reach_y
            painter.drawLine(joint_x, joint_y, end_x, joint_y)
            painter.drawLine(joint_x, joint_y, joint_x, end_y)
    painter.end()
    return mark


class ActivityCanvas(QGraphicsView):
    """Pan, zoom, and click a node to see what it is made of."""

    node_selected = pyqtSignal(str)

    arrangement_changed = pyqtSignal()
    """Something moved, or moved back. `Undo` and `Reset` are menu entries that
    have to grey out when there is nothing left for them to do, and the canvas
    is the only thing that knows."""

    expand_requested = pyqtSignal()
    """The corner button was pressed. What full screen *means* is the window's
    business; the canvas only owns the button, because the canvas is what knows
    when it has been resized and the button has to follow."""

    def __init__(self) -> None:
        super().__init__()
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        # No bars, ever. This is a whiteboard: the paper reaches past the window
        # on every side and the hand pushes it around. A bar reports how much of
        # a document is off screen, and a surface with no edge has no such number
        # to give — every bar the reader saw here was raised by ground they had no
        # reason to visit. `View -> Fit to window` is the way back to the graph.
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(QColor(PAPER)))
        # Framed, so the pinned light ground reads as a document lying on the
        # window rather than as a hole cut through it. Border only: the ground
        # itself stays the background brush above, where a test can see it.
        self.setStyleSheet(f"QGraphicsView {{ border: 1px solid {PAPER_EDGE}; }}")
        self._graph: ActivityGraph | None = None
        self._nodes: dict[str, _NodeItem] = {}
        self._edge_art: list[_EdgeArt] = []
        self._edges_by_node: dict[str, list[_EdgeArt]] = {}
        self._halo: QGraphicsEllipseItem | None = None
        self._selected: str | None = None
        self._lit: str | None = None
        self._history = MoveHistory()
        # Where the layout put each node, before any saved arrangement was
        # applied over it. `Reset` reaches back to here rather than to what the
        # graph was opened with: reaching only that far could not undo the
        # arrangement itself, and there would be no way back to the layout.
        self._base: dict[str, Point] = {}
        self._wrap = True
        # A box round each session of a trace, and the switch for it. On by
        # default; the window hands over the reader's choice before any graph.
        self._sessions = True
        self._boxes: list[_SessionBox] = []
        self._box_of: dict[str, _SessionBox] = {}
        # Every patch a caption or an arrow's number is written on, so turning
        # the boxes on or off can repaint them in the ground they now sit on.
        self._patches: list[QGraphicsRectItem] = []
        self._patch_ground = PAPER
        # Nodes are placed with `setPos` while a graph is being drawn, and every
        # one of those is a position change. Without this the first node placed
        # would ask for arrows that are not on the canvas yet, and the scene
        # rectangle would be stretched by each node in turn before `show_graph`
        # sets the one it wants.
        self._drawing = False
        # Something to read from the moment the window opens. Left to the case
        # being loaded, the largest region of the window spent the whole of
        # startup as blank paper inside dark chrome, which reads as a renderer
        # that failed rather than as a tool waiting to be given something.
        self.show_graph_placeholder(STARTUP_MESSAGE)

        # Floating, at the reader's request, over the objection this project
        # recorded when the arrangement controls were kept out of here. Two of
        # the three reasons are answered rather than accepted: `resizeEvent`
        # below moves it, and being a child widget it takes its own press
        # instead of handing it to `ScrollHandDrag`. The third — that it covers
        # a patch of the graph — is the trade that was chosen.
        self._expand = QToolButton(self)
        self._expand.setCursor(Qt.CursorShape.PointingHandCursor)
        self._expand.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._expand.setFixedSize(_EXPAND_SIDE, _EXPAND_SIDE)
        self._expand.setIconSize(QSize(_EXPAND_ICON, _EXPAND_ICON))
        self._expand.setStyleSheet(
            f"QToolButton {{ background: {_EXPAND_GROUND};"
            f" border: 1px solid {_EXPAND_EDGE}; border-radius: 4px; }}"
            f"QToolButton:hover {{ background: {THEME.edge}; border-color: {THEME.ink}; }}"
        )
        self._expand.clicked.connect(self.expand_requested)
        self.set_expanded(False)
        self._place_expand()

    def set_expanded(self, expanded: bool) -> None:
        """Say which way the button goes.

        One control with two meanings, so it has to name the one it is about to
        do. Offering `Full screen` while already full screen is a control lying
        about itself — and while full screen it is the most visible way back.
        """
        self._expand.setIcon(QIcon(_expand_mark(_EXPAND_INK, inward=expanded)))
        self._expand.setToolTip("Leave full screen  (Esc)" if expanded else "Full screen  (F11)")

    def _place_expand(self) -> None:
        """Keep it in the top right, inside the canvas whatever size it is.

        Held inside with `max`, because the arithmetic goes negative on a canvas
        narrower than the button and a control placed off its own near edge
        cannot be pressed — which, while full screen, is the way out.
        """
        gap = _EXPAND_INSET
        button = self._expand
        button.move(
            max(self.width() - button.width() - gap, 0),
            max(min(gap, self.height() - button.height()), 0),
        )

    def resizeEvent(self, event: QResizeEvent | None) -> None:  # noqa: N802 - Qt's naming
        super().resizeEvent(event)
        self._place_expand()
        # Placeholder text was fitted before the panel received its final size.
        # Refit it after layout so larger UI fonts do not leave the message clipped.
        if not self._nodes:
            self.fit()

    def drawBackground(self, painter: QPainter | None, rect: QRectF) -> None:  # noqa: N802
        """The ground under the graph: the theme's colour, then its grid.

        On the *view* rather than the scene, deliberately. `QGraphicsScene.render`
        — which is what `Export ▸ PNG image` calls — paints the scene's
        background and its items, and never the view's. So an exported graph
        gets the flat fill `_export_png` gives it and none of this, which is the
        right answer: a grid is an on-screen affordance for panning, and printing
        it into a deliverable would put texture behind evidence.
        """
        # Include the whole viewport, even when the scene only holds a prompt.
        # Qt's painter clip still limits updates to the exposed region.
        rect = rect.united(self._on_screen())
        super().drawBackground(painter, rect)
        if painter is None:  # pragma: no cover - Qt always supplies one
            return
        scale = self.transform().m11()
        if scale <= 0:
            return
        pitch = _GRID_PITCH / scale

        dot = QColor(THEME.grid_dot)
        dot.setAlphaF(_GRID_OPACITY)
        pen = QPen(dot)
        # In scene units, so the division cancels the zoom and the dot lands the
        # same size on screen at every magnification.
        pen.setWidthF(_GRID_DOT / scale)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.save()
        painter.setPen(pen)

        first_x = math.floor(rect.left() / pitch) * pitch
        first_y = math.floor(rect.top() / pitch) * pitch
        points = [
            QPointF(x, y)
            for x in _steps(first_x, rect.right(), pitch)
            for y in _steps(first_y, rect.bottom(), pitch)
        ]
        if points:
            painter.drawPoints(*points)
        painter.restore()

    @property
    def graph_scene(self) -> QGraphicsScene:
        """The scene, without the optionality the stubs put on `scene()`."""
        return self._scene

    @property
    def wrap(self) -> bool:
        """Whether a long trace is folded onto further rows."""
        return self._wrap

    @property
    def sessions(self) -> bool:
        """Whether each session of a trace is drawn as a box."""
        return self._sessions

    def set_wrap(self, wrap: bool, positions: Positions | None = None) -> None:
        """Fold long traces onto further rows, or lay each one out on one line.

        Redraws at once, and puts the ring back on whatever was being read — at
        the coordinates the node has moved to. The evidence panel beside the
        canvas goes on showing that episode across the redraw, so a canvas that
        stopped pointing at it, or pointed at where it used to be, would leave
        the two halves of the window describing different activities.

        Safe to call before anything is drawn: the window applies the remembered
        setting while it is still being built, which is long before a case has
        been opened.

        `positions` is the arrangement saved for the wrap being switched *to*,
        handed over with the instruction. A wrapped trace folds onto rows an
        unwrapped one does not have, so each has its own; and redrawing here and
        then again to place the nodes would double the cost of a toggle on the
        graphs where it is already slowest.
        """
        if wrap == self._wrap:
            return
        self._wrap = wrap
        if self._graph is None:
            return
        selected = self._selected
        self.show_graph(self._graph, positions=positions)
        if selected is not None:
            self.highlight(selected)

    # -- moving ------------------------------------------------------------

    def _node_moved(self, node_id: str) -> None:
        """Bring everything attached to an activity along with it.

        Called on every mouse-move event of a drag, and it touches only what
        moved: the arrows filed under this node, and the ring if this is the
        node being read.

        Not for speed. Reshaping every arrow in the graph instead measured the
        same to three decimal places — 0.339 ms against 0.343 ms on a 600-node
        trace — because the cost of one of these events is Qt's, not this
        function's. The index earns its place because `_light_edges` needs the
        same question answered for a reason that is not an optimisation at all:
        *which arrows does this activity carry.*
        """
        if self._drawing:
            return
        item = self._nodes.get(node_id)
        if item is None:  # pragma: no cover - a moved node is always a drawn one
            return

        for art in self._edges_by_node.get(node_id, ()):
            source = self._nodes.get(art.source_id)
            target = self._nodes.get(art.target_id)
            if source is not None and target is not None:
                art.reshape(QPointF(source.pos()), QPointF(target.pos()))

        if self._halo is not None and self._selected == node_id:
            self._halo.setPos(item.pos())

        self._grow_scene_for(item)

    def _node_grabbed(self, node_id: str) -> None:
        """Light the arrows this activity carries, for as long as it is moving.

        On a branching behaviour map it is not obvious which transitions a node
        carries until it is picked up.

        Anything still lit is put out first. A release that never arrives — the
        window losing focus mid-drag will do it — leaves an activity lit with
        nothing holding it, and the next thing picked up is where that gets
        noticed, so it is where it gets cleared.
        """
        if self._lit is not None and self._lit != node_id:
            self._light_edges(self._lit, lit=False)
        self._lit = node_id
        self._light_edges(node_id, lit=True)

    def _light_edges(self, node_id: str, *, lit: bool) -> None:
        """Recolour the arrows filed under one activity.

        The resting pen is rebuilt from the weight rather than remembered.
        Stored, it would be one more thing that can go stale — and what it
        would go stale about is how often a transition happened, which is the
        only thing separating a habit from a one-off on the behaviour map.
        """
        colour = QColor(SELECTION_COLOUR if lit else _EDGE_COLOUR)
        for art in self._edges_by_node.get(node_id, ()):
            width = _edge_width(art.weight)
            pen = QPen(colour)
            pen.setWidthF(max(width, _LIT_WIDTH) if lit else width)
            art.line.setPen(pen)
            art.head.setPen(pen)
            art.head.setBrush(QBrush(colour))

    def _node_dropped(self, move: Move) -> None:
        """Put the light out and settle the scene once the hand lets go.

        `_grow_scene_for` only ever grows, because shrinking under a moving
        hand throws the graph away from the cursor. But grown and never given
        back, the empty ground a node was dragged across stays in the scene for
        the rest of the session — and `Fit to window` frames the emptiness
        along with the graph. Between drags there is no hand to disturb, so
        this is where the room comes back.
        """
        if self._drawing:  # pragma: no cover - nothing is dropped while drawing
            return
        if self._lit is not None:
            self._light_edges(self._lit, lit=False)
            self._lit = None
        self._spread_paper()
        # One entry per drag, not per mouse-move event: `Undo` steps back
        # through the arrangements the reader saw, not through the hundreds of
        # positions their hand passed over on the way.
        if move.is_a_move:
            self._history.record(move)
            self.arrangement_changed.emit()

    def _on_screen(self) -> QRectF:
        """The region of the scene the window is showing, in scene units.

        Empty if there is somehow no viewport, which reads as "nothing is on
        screen" — so the paper falls back to the graph and its margin, which is
        the smallest rectangle that still shows the whole of it.
        """
        viewport = self.viewport()
        if viewport is None:  # pragma: no cover - a scroll area always has one
            return QRectF()
        return self.mapToScene(viewport.rect()).boundingRect()

    def _spread_paper(self) -> None:
        """Lay a screenful of clear paper around the graph, on every side.

        The scene rectangle is not what the reader looks at — `fit` frames the
        graph itself. It is how far they may push the graph before the view
        stops following, and that is all it is now.

        Sized from the window rather than written down, so it scales with both
        the window and the zoom: always somewhere to push to, and never so much
        that a graph can be lost out on empty paper.

        United with what is on screen, so the paper can never be pulled out
        from under the view. Recomputed after a drag that left the graph
        smaller, a rectangle that no longer held the current view would snap
        the graph back under the hand that had just placed it.
        """
        graph = self._scene.itemsBoundingRect()
        seen = self._on_screen()
        paper = graph.adjusted(-seen.width(), -seen.height(), seen.width(), seen.height())
        self._scene.setSceneRect(paper.united(seen))

    def _grow_scene_for(self, item: QGraphicsItem) -> None:
        """Lay more paper under an activity that has landed beyond the edge of it.

        The view clamps panning to the scene rectangle, so a node outside it
        cannot be reached — it is simply gone, with no way to bring it back. A
        drag cannot get one out there any more, since the paper is a screenful
        wide on every side and the hand never leaves the window; an arrangement
        saved from a larger window is read back verbatim, and can.

        Grows and never shrinks. Shrinking as a node comes back would move the
        paper under the hand that is holding it, and the graph would jump away
        from the cursor.
        """
        whole = item.sceneBoundingRect().united(item.mapRectToScene(item.childrenBoundingRect()))
        reach = whole.adjusted(-_SCENE_MARGIN, -_SCENE_MARGIN, _SCENE_MARGIN, _SCENE_MARGIN)
        rect = self._scene.sceneRect()
        if not rect.contains(reach):
            self._scene.setSceneRect(rect.united(reach))

    # -- the arrangement ---------------------------------------------------

    @property
    def can_undo(self) -> bool:
        """Whether there is a drag left to take back."""
        return self._history.can_undo

    @property
    def positions(self) -> Positions:
        """Where every activity sits now, ready to be saved and handed back.

        The same shape `show_graph` takes. If the two ever disagreed, a saved
        arrangement would come back as a different picture from the one that
        was saved.
        """
        return {node_id: (item.pos().x(), item.pos().y()) for node_id, item in self._nodes.items()}

    @property
    def laid_out(self) -> Positions:
        """Where the layout put each activity, before any arrangement went over it.

        The baseline an unsaved arrangement is measured against, in the shape
        `positions` hands back so the two can be compared without either caller
        reshaping the other. `_base` holds `Point`, which is the layout's own
        type: compared against a tuple, every activity on the canvas would read
        as moved.
        """
        return {node_id: (point.x, point.y) for node_id, point in self._base.items()}

    def undo_move(self) -> None:
        """Put the last activity that was dragged back where it came from.

        One drag per press, and nothing to do when the stack is empty — the
        menu entry greys out then, but a keyboard shortcut can still arrive.
        """
        move = self._history.undo()
        if move is None:
            return
        item = self._nodes.get(move.node_id)
        if item is not None:
            # Everything attached follows, because `setPos` is a position change
            # like any other and `_node_moved` does not care who asked for it.
            item.setPos(*move.before)
        self._spread_paper()
        self.arrangement_changed.emit()

    def reset_layout(self) -> None:
        """Put every activity back where the layout put it.

        The history goes with it. Undoing back across a reset would step through
        arrangements the reader has just said they are finished with.
        """
        for node_id, point in self._base.items():
            item = self._nodes.get(node_id)
            if item is not None:
                item.setPos(point.x, point.y)
        self._history.clear()
        self._spread_paper()
        self.arrangement_changed.emit()

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
        # Transparent to the mouse. The ring stands outside the circle it marks,
        # and an unfilled ellipse is still hit along its stroke — so without
        # this, a press that lands on the ring is taken by the ring, which is
        # not movable, and the canvas pans instead of the node moving.
        halo.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
        # Under the node so the outcome border stays the outermost thing read,
        # and above the edges so the ring is not cut by an arrow passing behind.
        halo.setZValue(0.5)
        self._scene.addItem(halo)
        self._halo = halo

    def show_graph(self, graph: ActivityGraph, positions: Positions | None = None) -> None:
        """Replace whatever is on the canvas with `graph`.

        `positions` overrides the layout for the nodes it names, and is how a
        saved arrangement comes back. Applied before anything is drawn rather
        than moved into place afterwards: drawn at the layout and reshaped after
        would look identical at rest and cost a second pass over every arrow on
        every open.

        A node the arrangement does not name keeps its layout position. That is
        not a corner case — a case re-ingested with a different rule pack has
        different activities in it, and an arrangement saved against the old
        ones must not leave the new ones stacked on the origin.
        """
        self._graph = graph
        self._forget_drawing()

        laid_out = _spread(layout_graph(graph, wrap=self._wrap), graph)
        if not laid_out:
            self._show_message("This client has no reconstructed activity.")
            return
        self._base = laid_out

        placed = laid_out
        if positions:
            placed = {
                node_id: Point(*positions[node_id]) if node_id in positions else point
                for node_id, point in laid_out.items()
            }

        self._drawing = True
        try:
            self._draw(graph, placed)
        finally:
            self._drawing = False

    def _draw(self, graph: ActivityGraph, positions: dict[str, Point]) -> None:
        """Put the arrows down, then the activities on top of them, then a box
        round each session.

        Separated from `show_graph` so the guard around it is one statement and
        cannot be left half applied by an early return added later.
        """
        boxed = self._sessions and graph.kind is GraphKind.TRACE
        # Decided before anything is written, because every caption and arrow
        # number is written on a patch of this.
        self._patch_ground = SESSION_GROUND if boxed else PAPER
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
        if boxed:
            self._draw_sessions(graph)

        self.fit()

    def _draw_sessions(self, graph: ActivityGraph) -> None:
        """Box each session of a trace, round its activities where they stand.

        Where they stand, not where the layout put them: a saved arrangement
        has already been applied, and a box drawn at the layout would hold
        nothing.
        """
        groups = sessions_in(graph)
        pen = QPen(QColor(_SESSION_EDGE))
        pen.setWidthF(_SESSION_EDGE_WIDTH)
        for index, nodes in enumerate(groups, start=1):
            shape = QGraphicsPathItem()
            shape.setPen(pen)
            shape.setBrush(QBrush(QColor(SESSION_GROUND)))
            # Under the arrows, which sit at zero, and so under everything.
            shape.setZValue(-1)
            # Takes no button, so a press on the paper inside a box pans the
            # view as it does everywhere else on the paper.
            shape.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
            self._scene.addItem(shape)
            label = self._canvas_text(
                session_caption(index, len(groups), nodes),
                colour=_SESSION_INK,
                point_size=_SESSION_POINTS,
                anchor=QPointF(),
                ground=SESSION_GROUND,
                centred=False,
                bold=True,
            )
            for part in (label, *label.childItems()):
                part.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
            box = _SessionBox(
                shape=shape, label=label, node_ids=tuple(node.node_id for node in nodes)
            )
            self._fit_box(box)
            self._boxes.append(box)
            for node in nodes:
                self._box_of[node.node_id] = box

    def _session_content(self, box: _SessionBox) -> QRectF:
        """What a box has to hold: its activities with their captions, and the
        numbers on the arrows between them."""
        content = QRectF()
        for node_id in box.node_ids:
            item = self._nodes[node_id]
            content = content.united(item.sceneBoundingRect())
            content = content.united(item.mapRectToScene(item.childrenBoundingRect()))
            for art in self._edges_by_node.get(node_id, ()):
                if art.label is not None and art.label.isVisible():
                    content = content.united(art.label.sceneBoundingRect())
        return content

    def _fit_box(self, box: _SessionBox) -> None:
        box.reshape(self._session_content(box))

    def show_graph_placeholder(self, text: str = WAITING_MESSAGE) -> None:
        """Clear the canvas back to its waiting state.

        The wording is a parameter because the two waits are different
        questions: before a case is open there is no client to pick.
        """
        self._graph = None
        self._forget_drawing()
        self._show_message(text)

    def _forget_drawing(self) -> None:
        """Clear the scene and everything that pointed into it.

        `QGraphicsScene.clear` deletes the items the edge art holds. Left
        behind, the next drag would reshape arrows whose C++ side is already
        gone. The history goes too: the nodes it names are gone, and undoing
        onto their replacements would move whichever activity inherited the id.
        """
        self._scene.clear()
        self._nodes.clear()
        self._edge_art.clear()
        self._edges_by_node.clear()
        self._halo = None
        self._boxes.clear()
        self._box_of.clear()
        self._patches.clear()
        self._selected = None
        self._lit = None
        self._history.clear()
        self._base.clear()

    def _show_message(self, text: str) -> None:
        self._message_scale = _IP_PROMPT_SCALE if text == WAITING_MESSAGE else _PLACEHOLDER_SCALE
        item = QGraphicsSimpleTextItem(text)
        item.setBrush(QBrush(QColor(_EDGE_COLOUR)))
        self._scene.addItem(item)
        self._scene.setSceneRect(item.boundingRect().adjusted(-40, -40, 40, 40))
        self.fit()

    def _draw_node(self, node: GraphNode, position: Point) -> None:
        style = style_for(node)
        item = _NodeItem(
            node,
            style.radius,
            on_move=self._node_moved,
            on_grab=self._node_grabbed,
            on_drop=self._node_dropped,
        )
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
        self._patches.append(
            self._canvas_text(
                summarise(node),
                colour=CAPTION_COLOUR,
                point_size=_CAPTION_POINTS,
                anchor=QPointF(0.0, style.radius),
                ground=self._patch_ground,
                gap=_CAPTION_GAP,
                parent=item,
            )
        )

    def _canvas_text(
        self,
        text: str,
        *,
        colour: str,
        point_size: float,
        anchor: QPointF,
        ground: str,
        gap: float = 0.0,
        parent: QGraphicsItem | None = None,
        centred: bool = True,
        bold: bool = False,
    ) -> QGraphicsRectItem:
        """Text on the canvas, scaling with the drawing it belongs to.

        `ground` is what the patch under the words is painted: the paper, or a
        session box's fill when the words sit inside one. `centred` hangs the
        text from the middle of `anchor`, as a caption hangs under its circle;
        off, it starts at `anchor`, as a box's label starts at its corner.

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
        backdrop.setBrush(QBrush(QColor(ground)))
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
        if bold:
            font.setWeight(QFont.Weight.DemiBold)
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
        across = -(bounds.width() + padding * 2) / 2 if centred else 0.0
        backdrop.setTransform(QTransform().translate(across, gap / _LEGIBLE_AT))
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
        source_radius = style_for(source).radius
        target_radius = style_for(target).radius
        shape = _edge_shape(
            QPointF(start.x, start.y),
            QPointF(end.x, end.y),
            source_radius=source_radius,
            target_radius=target_radius,
            paired=paired,
        )

        pen = QPen(QColor(_EDGE_COLOUR))
        pen.setWidthF(_edge_width(weight))
        line = QGraphicsPathItem(shape.path)
        line.setPen(pen)
        line.setZValue(0)
        self._scene.addItem(line)

        arrow = QGraphicsPolygonItem(shape.head)
        arrow.setPen(pen)
        arrow.setBrush(QBrush(QColor(_EDGE_COLOUR)))
        arrow.setZValue(0)
        self._scene.addItem(arrow)

        backdrop = (
            self._canvas_text(
                label,
                colour=_LABEL_COLOUR,
                point_size=_LABEL_SIZE,
                anchor=shape.label_at,
                ground=self._patch_ground,
            )
            if label
            else None
        )
        if backdrop is not None:
            self._patches.append(backdrop)

        art = _EdgeArt(
            source_id=source.node_id,
            target_id=target.node_id,
            source_radius=source_radius,
            target_radius=target_radius,
            line=line,
            head=arrow,
            label=backdrop,
            weight=weight,
            paired=paired,
        )
        art.place(shape)
        self._edge_art.append(art)
        # Under both ends: an arrow belongs to the activity at each of them, and
        # both a drag and the light that goes on during one ask the same
        # question of a node — which arrows are mine.
        self._edges_by_node.setdefault(source.node_id, []).append(art)
        self._edges_by_node.setdefault(target.node_id, []).append(art)

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
        graph = self._scene.itemsBoundingRect()
        # Claimed before framing, not after. The view clamps every scroll to the
        # scene rectangle and `fitInView` scrolls, so a graph lying outside the
        # rectangle the last one left behind cannot be reached: the fit lands
        # short and the graph opens half off the window.
        self._scene.setSceneRect(
            graph.adjusted(-_SCENE_MARGIN, -_SCENE_MARGIN, _SCENE_MARGIN, _SCENE_MARGIN)
        )
        self.fitInView(self._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
        if self.transform().m11() < MIN_FIT_SCALE:
            self.resetTransform()
            self.scale(MIN_FIT_SCALE, MIN_FIT_SCALE)
            # Clamped, so the graph is wider than the window and something has
            # to be off screen. Open on the beginning rather than on whatever
            # the view was centred over: with an unwrapped trace that clamps on
            # every draw, centring hides both ends and starts the reader in the
            # middle of a chronology.
            self.centerOn(graph.topLeft())
        if not self._nodes:
            self.scale(self._message_scale, self._message_scale)
            self.centerOn(graph.center())
        # Last, because it reads the region on screen and the fit has just
        # decided that. The graph keeps its place: the paper only ever grows
        # around what the view is already showing.
        self._spread_paper()


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
