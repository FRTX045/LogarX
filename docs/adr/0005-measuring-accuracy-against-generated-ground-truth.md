# ADR-0005: Measure accuracy against generated ground truth, and segmentation at the boundary

- **Status:** Accepted
- **Date:** 2026-08-09

## Context

The tool claims to reconstruct what a client did. Nothing in the codebase established whether it
does, and a forensic tool whose accuracy nobody has measured is one nobody should rely on.

Measuring it needs a corpus whose contents are known. Real access logs are exactly the wrong
material: nobody knows what is in them, which is the problem this tool exists to solve. Public
labelled datasets exist, but the standard one for HTTP — CSIC 2010 — is a set of requests with no
responses, no addresses and no per-request attack type, and a substantial share of its attacks
live in POST bodies that a web server access log never records.

There is also a second question, easy to overlook. Classification asks whether each request was
understood. Segmentation asks whether the joins between one activity and the next were put in the
right places. A tool can be good at one and bad at the other, and the second is the harder half of
the research question.

## Decision

**Generate the primary evaluation corpus.** `logarc generate` writes synthetic Apache logs from
scripted client roles, alongside a ground-truth sidecar recording, for every line, which activity
produced it. Clients run concurrently and are merged on time, so they interleave the way a real
server sees them.

**Write ground truth from behaviour, never from rule output.** A burst is labelled enumeration
because the client is sweeping a wordlist, not because the enumeration rule fires on it. Where two
categories sit close together — probing for named artefacts against sweeping a wordlist — the
boundary is stated in the generator and applied consistently.

**Score classification per category**, with precision, recall and F1 per activity, plus a lenient
recall that counts a category which matched but was outranked. Macro-averaging covers only the
categories the log actually contained.

**Score segmentation at the boundary.** For each adjacent pair of one client's requests, the truth
either does or does not put an activity boundary there, and so does the reconstruction. That makes
it a binary classification over boundaries, which distinguishes a merge from a split — comparing
episode counts does not.

**Use CSIC 2010 as a secondary, binary-only check.** Its truth file declares `binary` granularity
and the scorer refuses to produce a per-activity table from it.

## Rationale

Generated traffic is the only source that can answer "was this request enumeration or
reconnaissance", because it is the only source where somebody decided. The risk it carries is
circularity — writing truth to match what the rules do — and the defence is that truth is written
from the client's script, in a module that does not import the detection engine.

Boundary scoring rather than episode counting matters because noise absorption removes boundaries
on purpose: a `favicon.ico` fetched in the middle of an attack must not split it into three
activities. A count comparison reports that as a loss with no way to tell it apart from a failure
to segment at all. Boundary precision and recall separate the two, and `--no-absorb` runs the same
evaluation with the rule switched off, so its cost is measured rather than asserted.

CSIC is kept despite its limits because results on it are comparable with published work, which
results on generated traffic never are. Its limits are recorded in the conversion output rather
than in a footnote: the ceiling that hidden POST bodies place on achievable recall is computed and
printed every time.

## Consequences

**Positive.** Accuracy is a number rather than an intention, and regressions in it are visible.
Building it found seven defects, listed with their numbers in
[docs/evaluation.md](../evaluation.md). Five were in the tool, including one — `+` in a query
string not read as the space it means — that hid every form-encoded payload from every rule and
was found only by converting someone else's dataset.

Two were in the evaluation itself, which is the more uncomfortable half. The threshold sweep
reported identical scores at every setting twice over, first because no generated client ever
paused and then because the pauses landed where the gap rule was never consulted. Both times the
tests passed and the script worked; it surfaced only by reading the output and asking why every
row was the same. A measurement that silently measures nothing is the failure mode this ADR is
most exposed to, and it is not one that testing catches.

**Negative.** The headline figures come from traffic this project wrote, and a generator shares the
blind spots of whoever wrote it. That is not hypothetical: the `+`-as-space defect survived every
generated scenario and was found only when CSIC's own encoding was converted. Generated results
should be read as an upper bound.

**Also negative.** Outcome — the attempt-versus-breach distinction the reconstruction is built
around — cannot be evaluated on CSIC at all, because the traces have no responses.

**Revisit if** a labelled dataset appears with real responses and per-request attack types, at
which point generated traffic should become the regression suite and the real corpus the headline.

## Amendments

**2026-08-10.** The policy "use CSIC 2010 as a secondary, binary-only check" is extended by
[ADR-0007](0007-scoring-detection-against-the-crs-regression-corpus.md), which adds the OWASP CRS
regression corpus as a second external check, scored as a per-family detection rate. It does not
trigger the revisit clause above: CRS carries per-request attack families but no responses at all,
so generated traffic remains the headline.
