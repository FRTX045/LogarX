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

**NetworkX went too, and this note did not say so.** The Decision above still names
`multipartite_layout` and `spring_layout`; `graphbuild/layout.py` calls neither, and imports
nothing but `math`, `dataclasses`, `typing` and one internal module.

In fact `networkx` was never imported at all: `git log -S networkx -- src/` returns nothing.
It was declared in the scaffolding commit on 2026-08-08, ahead of this decision, and the code
never went that way — so every install since has carried a package nothing used, and a reader
checking *why* would have been sent looking for calls that were never written. `mypy` reported
the matching stub override as an unused section on every run, which is the tell that went
unread. Dependency, stubs and override are all removed now.

Each replacement turned out to serve this ADR's own reasoning better than the function it
replaced:

- **The trace needs no layering algorithm at all.** `multipartite_layout` was chosen to lay out
  topological depth, but a trace is already in chronological order and its only edges join
  consecutive episodes of one session — so position follows from order directly. What was added
  instead is serpentine wrapping, which the original design did not consider and which is what
  makes a long session readable.
- **`spring_layout` was chosen for determinism, and a circle is deterministic for a better
  reason.** A seeded iterative solver is reproducible because it is told to be; a circle ordered
  by request volume cannot vary between runs at all. With one node per activity category the
  node count is tiny and every pair may be connected, which is exactly where a force-directed
  layout buys least. `test_layout_is_identical_across_runs` still holds the guarantee this ADR
  asked for.
