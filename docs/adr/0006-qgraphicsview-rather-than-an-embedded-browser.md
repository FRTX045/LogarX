# ADR-0006: Draw the activity graph on QGraphicsView, not in an embedded browser

- **Status:** Accepted
- **Date:** 2026-08-09

## Context

The activity graph is the product. It needs pan, zoom, hit-testing on nodes, and a click that
opens the evidence behind whatever was clicked.

The obvious shortcut is an embedded browser — `QtWebEngine` hosting D3, Cytoscape or vis.js.
Those libraries are mature, handsome, and would have taken a fraction of the effort. The HTML
report already renders the same graph as inline SVG, so there was even an argument for rendering
it once and showing the same thing in both places.

## Decision

Draw the graph as a Qt scene graph: `QGraphicsView` over `QGraphicsScene`, with one
`QGraphicsEllipseItem` subclass per activity carrying its node id.

`QtWebEngine` is not merely unused — it is named in the PyInstaller `excludes`, so the freezer
cannot pull it in through a transitive import.

## Rationale

**Size.** `QtWebEngine` is a Chromium build. It adds several hundred megabytes to a bundle that
is currently ~250 MB in total, for a tool whose stated point is that an investigator can run it
on a machine with nothing installed. That is the decisive argument; the rest reinforce it.

**The graphs are small.** A session trace is tens of nodes, a behaviour map is under ten. Scene
graphs handle that without a rendering engine. This is not a case where a browser's layout and
compositing earn their keep.

**Attack surface.** The strings drawn on the graph are attacker-controlled — paths, query
strings, user agents. Rendering them in a real browser engine means a forensic tool ships a
JavaScript runtime that evaluates content taken from the evidence. The HTML report already has
to escape carefully for exactly this reason; not having a second, live surface with the same
exposure is worth something.

**One process, one language.** Hit-testing, selection and the evidence panel stay in Python.
An embedded browser would put a JSON bridge between a click and the panel that answers it,
which is more machinery for the same result.

## Consequences

**Positive.** A bundle small enough to hand over. No JavaScript runtime evaluating evidence.
Node appearance is decided in `logarc.gui.style`, which imports no Qt and is unit-tested, so
whether a critical finding *reads* as critical is checkable without a display.

**Negative.** Everything is drawn by hand — edge trimming to circle boundaries, arrowheads,
weight-scaled pens, label placement. A web library would have supplied all of it. Force-directed
animation and slick transitions are not available and are not attempted.

**Revisit if** trace graphs routinely reach thousands of nodes, where a canvas-based renderer
with level-of-detail would start to matter. The layout decision in
[ADR-0004](0004-pure-python-graph-layout.md) has the same threshold, and both should be
reconsidered together.
