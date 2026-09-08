# ADR-0011: A real server's log is the headline corpus, and the generator is removed

- **Status:** Accepted
- **Date:** 2026-09-08

## Context

[ADR-0005](0005-measuring-accuracy-against-generated-ground-truth.md) chose to
generate the primary evaluation corpus, because no labelled dataset existed
with real responses and per-request attack types, and it said to revisit when
one did. Its stated risk was circularity: a generator shares the blind spots of
whoever wrote it. That risk was realised twice. The `+`-as-space defect
survived every generated scenario and was found only by converting someone
else's dataset. And on 2026-09-07 the generator's truth had to be rewritten to
the tool's own definition of an activity, because the episode builder had
changed how it draws ordinary use and the generator had not; after that change
the corpus could no longer disagree with the tool about where an activity ends,
which is half of what this evaluation exists to test.

The BlackHat-Dataset `apache-shopfront` project now exists: a real Apache 2.4
serving a real PHP shop in a container, driven by scripted personas, a real
Chromium for some sessions, five real security tools and six reactive attack
campaigns, with every log line joined through a tagging proxy to the ledger of
the client that made the request. It writes this tool's truth format with the
same fourteen categories, and it carries responses, so outcome can be scored.

## Decision

**The headline evaluation is measured on a pinned build of the dataset**, the
medium tier, with the small tier as a fast check. Builds are identified by
SHA-256 of the log and the truth, recorded in `docs/evaluation.md` and beside
the files. They are not versioned in this repository.

**The generator is removed**, not kept as a regression suite. Regression is
covered by a committed excerpt of the medium build under `tests/data/`. After
the 2026-09-07 regraining the generator measured the tool against the tool's
own model of an activity, which is not a check worth 935 lines.

**The dataset's truth is not adjusted to the tool.** It cuts a shopper's
journey at browsing, searching and using the basket, and it cuts
proxy-labelled traffic on every category change; the tool draws one ordinary-use
episode until an idle gap. On the medium build the truth makes 2,738 cuts
between ordinary requests; 2,586 of them coincide with pauses longer than the
episode gap, which both sides cut anyway, leaving 152 where the grains differ.
The tool draws 38 of those anyway for an unrelated reason: the client changes
its `User-Agent`, which ends a session and so starts an episode. It misses
114, which is 89% of every boundary the headline run misses. The number is
recorded and the score is allowed to be lower for it.

**Reproducibility is by checksum, not by seed.** The dataset reproduces its
plan of requests from a seed but not its bytes, because the campaigns react to
a live server and requests interleave differently on every run. Figures apply
to the checksummed files; a rebuild is expected to score close, and the doc
says so rather than implying an equality it cannot deliver.

## Consequences

**Positive.** CRS enrichment changes the figures on this corpus, which the
generated one could never show. ADR-0008 had to record that its own headline
benefit was invisible on generated traffic. Categories the rules cannot tell
apart on real traffic are visible with support behind them. Every finding
traces to a line a real server actually wrote.

**Negative.** The headline numbers are lower than the generated ones, macro F1
most of all, and anyone comparing the two versions of `docs/evaluation.md` will
read that as a regression. It is not; it is the first honest measurement.
Per-class figures for categories with support in the single digits are
unstable, and the doc names which those are.

**Also negative.** Timestamps in the dataset are rewritten onto a diurnal model
rather than captured, which that project documents and ships the raw capture
beside. Anything measured against the clock, and the idle-timeout sweep above
all, is therefore measuring that model as much as it is measuring this tool.

**Also negative.** The corpus is one application. A different shop, or a
different server, would produce different confusions, and nothing here
separates what is true of the tool from what is true of this one PHP shop.

**Also negative.** Evaluation now depends on files a fresh clone does not have.
The test suite does not: its excerpt is committed and checksum-checked.

**Revisit if** the dataset changes how it cuts episodes, at which point the
numbers should be re-measured on the new build; or if a second project appears
in it, which is what would answer the one-application limitation above.
