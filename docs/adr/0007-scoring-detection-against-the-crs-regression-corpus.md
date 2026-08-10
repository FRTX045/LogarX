# ADR-0007: Score detection against the OWASP CRS regression corpus

- **Status:** Accepted
- **Date:** 2026-08-10

## Context

[ADR-0005](0005-measuring-accuracy-against-generated-ground-truth.md) records the weakness in the
primary evaluation in its own Consequences: the headline figures come from traffic this project
wrote, and a generator shares the blind spots of whoever wrote it. That was not a hypothetical
worry. The `+`-as-space defect — a query-string `+` read literally rather than as the space it
means, which hid every form-encoded payload from every rule — survived every generated scenario
and was found only when CSIC 2010's own encoding was converted.

CSIC is the existing external check and it is a thin one. Its truth file declares `binary`
granularity, it has no responses, no addresses and no per-request attack type, and a substantial
share of its attacks are in POST bodies.

The OWASP Core Rule Set publishes a regression suite alongside its rules: 4,224 cases across the
attack families relevant here, each a concrete payload with an assertion naming which of *their*
rules must fire. It is externally authored, actively maintained against real bypasses, and shaped
by nobody's assumptions but CRS's. It measures a different axis from anything already in place —
breadth of signature coverage against a hostile enumeration of payload syntax — and the first run
of it returned 12.0%, which is a result the generated corpus was structurally unable to produce.

## Decision

**Add `logarc score-crs` as a second external check, scored as a per-family detection rate.** For
each payload the question is binary: did any hostile rule fire? Results are grouped by CRS family
so a family with no coverage cannot hide inside an average.

**Refuse to score category correctness.** CRS families name vulnerability classes; this tool's
categories name observed behaviour. No agreed mapping between the two exists, and none is
constructed. A payload CRS files under SQL injection that a path-traversal rule catches counts as
caught. The categories that fired are reported descriptively and are never compared against an
expected value.

**Define access-log-visible as the combined format.** The request line, plus `Referer` and
`User-Agent`. Every other header is out of reach and excluded. Every exclusion is counted by
reason — body payload, unlogged header, negative assertion, no assertion, pre-encoded request,
malformed — and the accounting is printed on every run.

**Hold CRS's own false-positive tests out of the rate.** Cases asserting `no_expect_ids` are run
separately and reported as an advisory count, never as part of the detection rate.

**Do not vendor the corpus.** `--corpus` takes the path to a clone, as `convert-csic` takes dataset
paths. The clone's git revision is recorded in the report next to the ruleset fingerprint.

## Rationale

Refusing the family-to-category mapping is the decision most likely to be questioned, and it is
load-bearing. Building one would require deciding that CRS's 930 (LFI) family means
`path_traversal` — except that its `restricted-files.data` rule is behaviourally reconnaissance,
so the mapping needs per-rule exceptions, each an opinion. Worse, `episode/builder.py` splits an
episode when the category changes, so a category assignment is a segmentation decision. A metric
built on a contestable mapping would make every future taxonomy change register as an accuracy
regression, and the first run showed exactly why: 932 RCE payloads are caught by reconnaissance
rules 17 times and path-traversal rules 5 times. Under a family mapping those honest detections
would be scored as errors — making the number both worse and less true.

Scoring the combined format rather than the common one is the decision most likely to be revisited,
so the reasoning is recorded. Excluding all header payloads was tried first and it zeroed families
913 and 944 — the two these rules are strongest at, because their payloads ride in `User-Agent`,
which combined logs record and this tool parses and has three rules for. Measuring against a log
format the tool does not ship for is not the conservative choice, only a different inaccuracy.

Not vendoring follows the CSIC precedent and avoids a licensing question: CRS is Apache-2.0 and
this project is MIT, so copying 4,224 case files in would require carrying the Apache notice and
tracking a corpus that moves every release. Recording the revision instead means a rate stays
re-derivable, which matters because both the denominator and the figure drift as CRS gains cases.

## Consequences

**Positive.** The signature layer now has a number that does not come from this project. The
per-family split located the gaps precisely — 933 (PHP) at 0.012 over 173 cases against zero PHP
rules, 932 (RCE) at 0.079 over 406 against one — which the generated corpus could not have shown,
because it writes payloads the rules were written for. `--out` carries all 1,001 uncaught payloads,
which is the actionable half of the result.

**Negative.** The headline is uncomfortable and invites the wrong reading. 12.0% is a coverage
measurement against a corpus that grades payload syntax, not a statement that seven attacks in
eight go unnoticed; the two projects answer different questions. The documentation says so, and
the risk that the number is quoted without that context is real and accepted.

**Also negative.** The rate is measured on 27% of the corpus and is a floor within that, because
status is synthesised as 200 and one bundled rule needs a 4xx. Three qualifications travel with
every quotation of it, which is three more than a figure should need.

**This does not trigger ADR-0005's revisit clause.** That clause fires when a labelled dataset
appears with real responses *and* per-request attack types, at which point generated traffic
becomes the regression suite and the real corpus the headline. CRS has per-request attack families
but no responses at all, so outcome remains unmeasurable on it and it cannot displace generated
traffic. It is a second secondary check, alongside CSIC, measuring a different axis.

**Revisit if** the detection rate is used to justify importing CRS rules. The measurement was built
to inform that decision and deliberately does not make it: the next step is to add the missing
normalisation (HTML entity decode, JS decode, null removal) and re-run, because the split between
what these rules cannot express and what they merely fail to decode is not yet known.
