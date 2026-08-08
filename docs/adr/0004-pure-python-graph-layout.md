# ADR-0004: Pure-Python graph layout, no Graphviz dependency

- **Status:** Accepted
- **Date:** 2026-08-08

## Context

Activity graphs need coordinates before the Qt renderer can draw them. The design called for
NetworkX with Graphviz layouts (`dot` for the chronological trace, `neato` for the behaviour map).

Graphviz layouts in Python require either `pygraphviz` (which compiles against Graphviz C
headers) or `pydot` (which shells out to a `dot` binary that must be installed separately). Both
are awkward on Windows, and neither bundles cleanly into a PyInstaller distribution — the whole
point of which is that an investigator can run the tool without installing anything.

## Decision

Compute layouts in pure Python:

- **Session trace** — a chronological chain, so layer assignment is just topological depth.
  `networkx.multipartite_layout` over that layering gives a clean left-to-right hierarchy.
- **Behaviour map** — `networkx.spring_layout` with a fixed seed for determinism.

No `pygraphviz`, no `pydot`, no native Graphviz.

Layout lives in `graphbuild/layout.py` and returns coordinates. The Qt renderer only draws them,
keeping layout out of the GUI layer and unit-testable.

## Rationale

Trace graphs are chains or near-chains, which is the case where `dot`'s sophistication buys least.
Behaviour maps hold one node per activity *category* — on the order of 10 nodes — where a spring
layout is entirely adequate.

The seeded `spring_layout` matters beyond aesthetics: a forensic tool that draws the same evidence
differently on each run undermines confidence in it. Deterministic layout makes screenshots in a
report reproducible.

## Consequences

**Positive.** Zero native dependencies, a smaller and more reliable Windows bundle, deterministic
output, and layout that can be tested without a display.

**Negative.** Edge routing is straight-line, so dense behaviour maps may show crossings that `dot`
would have avoided. Acceptable at the node counts involved.

**Revisit if** trace graphs routinely exceed ~100 nodes, at which point a proper Sugiyama
implementation with crossing reduction may be worth writing — still in pure Python.

## Deviation note

This supersedes the "NetworkX/Graphviz" wording in the approved design. The substance of that
decision — layout computed outside the GUI, returning coordinates, independently testable — is
preserved; only the layout backend changed, to remove a native dependency that conflicted with
the packaging requirement.
