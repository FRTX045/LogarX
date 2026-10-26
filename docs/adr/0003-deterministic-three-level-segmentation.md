# ADR-0003: Deterministic three-level segmentation

- **Status:** Accepted; amended 2026-10-27, see *Amendment* at the end
- **Date:** 2026-08-08

## Context

The core research question is: *how do you separate one action from another, and then classify
it?* A single meaningful activity ("SQL injection probing") spans many requests, and a single IP
may interleave several activities across hours.

Approaches considered:

1. **Deterministic rules** — fixed thresholds and declarative signatures.
2. **Change-point / burst detection** — infer boundaries statistically from the request stream.
3. **Unsupervised clustering / sequence mining** — discover activity patterns from data.

## Decision

Segment deterministically, at three nested levels:

| Level | Unit | Boundary condition |
|---|---|---|
| 1 | **Session** | idle gap > 30 min, **or** User-Agent change, **or** duration > 8 h |
| 2 | **Request label** | declarative rule match (signature or windowed behavioural) |
| 3 | **Episode** | label category change, **or** intra-label gap > 5 min |

A post-pass then merges same-category episodes separated by a *short* benign interlude
(< 3 requests and < 60 s), absorbing the interlude.

Every threshold is configuration, and every value used is recorded in the case manifest.

## Rationale

Option 3 was rejected outright: the stated goal is detecting a *known* activity set, not
discovering unknown ones, and an unexplainable cluster boundary is not defensible as evidence.

Option 2 was rejected as the primary mechanism because it trades explainability for adaptivity.
"The episode ended here because the request rate's changepoint statistic exceeded a threshold" is
much harder to defend in a report than "the episode ended here because the next request was 7
minutes later and belonged to a different category."

The **noise-absorption merge** is the one non-obvious rule, and it is load-bearing. Without it a
single `favicon.ico` fetch in the middle of an attack splits one episode into three nodes, and
the graph degrades into unreadable fragments. It is stated explicitly rather than buried so that
its effect on results can be argued about and measured.

## Consequences

**Positive.** O(k) single pass, streaming-compatible, and every boundary traces to a stated rule
and a recorded threshold. Results are reproducible from the manifest alone.

**Negative.** Fixed thresholds cannot adapt to an attacker who deliberately paces requests to
straddle them — a slow scanner at 6-minute intervals fragments into many episodes. This is a
known limitation to be measured in evaluation and reported, not hidden.

**Follow-up.** Default thresholds (30 min / 5 min / 60 s) are literature-derived starting points.
They will be tuned against ground truth during evaluation, and the final values reported as a
finding rather than presented as self-evident.

## Amendment, 2026-10-27: where the thresholds are recorded

**The thresholds are recorded in each analysis export, not in the case manifest.** The decision
above said every value used is recorded in the manifest and that results are reproducible from the
manifest alone. Neither held: `case.json` records the sources, the version that created the case
and the per-case settings, while the session and activity thresholds, the ruleset fingerprint and
the version that ran the analysis are written into every JSON and HTML export. The segmentation is
unchanged and still deterministic; reproducing a result needs the source logs, the manifest and the
export together, as [docs/architecture.md](../architecture.md#forensic-integrity) sets out.
