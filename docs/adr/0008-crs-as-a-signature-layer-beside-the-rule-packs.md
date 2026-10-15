# ADR-0008: Run OWASP CRS beside the rule packs, not instead of them

- **Status:** Accepted; amended 2026-09-15 — see *Amendment* at the end
- **Date:** 2026-08-11

## Context

[ADR-0007](0007-scoring-detection-against-the-crs-regression-corpus.md) measured the bundled rules
at **12.3%** of the access-log-visible payloads in CRS's regression corpus, and its follow-up
established what the remainder is. The misses are not obscured; they arrive in plain text and no
rule expresses their syntax:

| CRS rule | Misses | Payload, decoded |
|---|---|---|
| 932140 | 150 | `for %variable in (set) do command` |
| 934160 | 28 | `while(!false)` |
| 942550 | 27 | `OR '{"b":2}'::jsonb <@ '{"a":1, "b":2}'::jsonb` |

Closing that by hand means writing signatures for Windows batch syntax, JavaScript control flow and
Postgres operators, indefinitely, against a corpus maintained by people who do it full time. That
is not a good use of this project, and it was never the contribution.

## Decision

**Adopt CRS as an additional signature layer, run through Coraza in a Go sidecar.** CRS is SecLang
and cannot execute itself; Coraza is the engine, and using it is what makes this the real CRS
rather than a copy of its patterns. The transformation chains (`t:cmdLine`, `t:normalizePath`,
`t:urlDecodeUni`), per-`ARGS` targeting, rule chaining and libinjection are precisely what a regex
port would lose, and they are most of what makes CRS worth having.

**Keep every native rule.** CRS does one of the four jobs `detect/` performs and cannot do the
other three:

| Job | CRS | Native |
|---|---|---|
| Signature match on one request | yes, far better | 28 rules |
| Behaviour across requests | no — stateless per request | 5 window rules |
| `ActivityCategory` assignment | no — emits rule ids and tags | yes, and it drives segmentation |
| Classifying traffic no rule matched | no — silence | `_classify_benign` |

**A CRS detection may name a request only where the rule packs reached INFO.** Either nothing
matched, or the only match was an observation like `Scripted Client`. Anything LOW or above is a
real claim and wins outright. CRS is recorded as evidence on every request it matched, either way.

**Enrichment is a separate, recorded step.** `logarc enrich` writes `crs.jsonl` into the case and
the configuration into the manifest; `analyze` reads it. Not folded into ingest, which runs at
~30,000 lines/s against the sidecar's ~1,800.

**Absence is announced.** A case without `crs.jsonl` analyses natively and says so on every run.
The failure this prevents is the same log yielding different findings on two machines with nothing
saying why.

## Rationale

The rescue rule is the contestable part, and it is bounded deliberately: a family→category entry
can only replace a non-answer, never a claim a rule made. ADR-0007 refused to build a general
mapping for scoring and that refusal stands — this is a narrower thing, and the bound is what makes
it defensible.

**Paranoia level 2, chosen by measurement after PL1 was chosen by instinct.** A false positive
costs more here than in the tool this sidecar came from — there it added a noisy evidence row, here
it can set a category, and a category change starts a new episode. That reasoning argued for PL1
and it was over-corrected:

| Paranoia | CRS matched | Labelled hostile | Hostile episodes on 365 lines of real traffic |
|---:|---:|---:|---|
| native | — | 0.120 | 5 |
| 1 | 65% | 0.672 | 5 |
| **2** | **91%** | **0.900** | **5** |
| 3 | 93% | 0.920 | 6 — a false positive |
| 4 | 93% | 0.920 | 6 |

PL1 gave up 25 points of recall for a false-positive risk no control could demonstrate. PL2 is also
the ceiling rather than an arbitrary midpoint: at PL3, rule 932237 fires "Unix Shell Code Found in
Request" on a plain `GET /` and manufactures a hostile episode out of a homepage. 20,000 requests
of generated benign traffic produce zero detections at every level, so the real log is the only
control with anything to say here — which is itself a reminder of how thin generated traffic is as
a false-positive test.

## Consequences

**Positive — measured.** On a log of payloads from ADR-0007's miss list, 42 requests that were
reported as a single Info-level `Scripted Client` episode became three activities with the attack
correctly named Critical. That is the whole point: detection improving where the reconstruction
also improves.

**No false positives at the chosen level, on two negative controls.** 20,000 requests of generated
`normal_browsing` produced **zero** CRS detections at every paranoia level. 365 lines of real 2010
WordPress traffic reconstruct to the same five hostile episodes with CRS at PL1 and PL2 as without
it. Above PL2 that stops being true, which is what fixed the level — see the table above.

**No regression, and no gain, on generated traffic.** A 100,000-line `mixed` corpus produced 54,720
CRS detections across 17,439 requests, and scored *byte-identically* — accuracy 0.965, macro F1
0.958, attack-or-not precision 1.000, false alarms 0.000%, 17,983 episodes. Native rules already
fire on everything CRS catches there, so nothing is rescued. This is ADR-0005's blind spot stated
once more: **the generated corpus cannot show the benefit of this change, because the generator
writes the payloads the rules were written for.**

**Negative — the mapping table is an opinion and got it wrong twice before real data corrected it.**
Both errors are recorded in `detect/crs/mapping.py` because both were invisible to reasoning:

- The first draft was written from a grep that truncated at the hyphen, so `attack-injection-php`
  was absent and every PHP payload silently went unrescued while the feature appeared to work.
- `attack-generic` reads like family 934 and belongs to 905 and rule 911100, "Method is not allowed
  by policy". Mapped to `injection`, seven `CONNECT` proxy-abuse requests in the real WordPress log
  were reported as injection attempts. It is now withheld. That proxy abuse is real signal and
  deserves a native rule naming it correctly rather than a borrowed category that does not.

A `KNOWN_FAMILIES` set and a test now require every tag the ruleset carries to be either mapped or
explicitly withheld, so a CRS version bump fails a test instead of quietly narrowing coverage.

**Negative — a build step and two Apache-2.0 dependencies.** Go 1.25, a coreruleset clone, and a
cross-compile when the interpreter and toolchain differ in platform. A `NOTICE` file is now carried.
Distribution of prebuilt binaries is deliberately deferred until the benefit is seen on a real log.

*Since 2026-10-05 the packaged Windows application carries the sidecar.* The condition was met by
the measurements in `docs/evaluation.md`, so `packaging/rebuild.py` now builds it fresh on every
packaging run and bundles it with the request rules, their revision and the licences of everything
linked into it (`packaging/crs_bundle.py`); the bundle grows by about 22 MB. Source installs are
unchanged: they still build it as `crs/README.md` describes.

**This retires `score-crs` for good.** Removed in `2868e78` before this work began, on the reasoning
that rules scored against the corpus their own project maintains grade themselves. ADR-0007 and its
figures are kept as the evidence for this decision.

**Revisit if** the rescue is shown to fire on genuinely benign traffic in the field. The response is
to shrink the mapping table, not to widen it — the same direction taken with `attack-generic`.


## Amendment, 2026-09-15 — `score-crs` returns, pointed the other way

This record retired `score-crs` "for good", and the reasoning was: *rules scored
against the corpus their own project maintains grade themselves.* That still
holds, exactly as written, for the thing that was removed. It scored **CRS's**
rules against **CRS's** corpus.

A command of the same name is back, and it is not that thing. It scores **this
project's** rule packs against that corpus — a question paper written by someone
else, for someone else's tool, years before logarc existed. The objection in the
sentence above is about who wrote the answer key relative to who wrote the
rules, and reversing that reverses the objection with it.

**What made this worth doing now.** The corpus turned out to have been in the
repository the whole time, at `vendor/coreruleset/tests/regression/`, carried in
with the ruleset clone. The blocker was never the data; it was that nothing
could read it. `docs/evaluation.md` had recorded two holes found against that
corpus — family 933 at 0.012 and family 932 at 0.079 — with no way to check
whether anything had since closed them.

**The result, and it is not flattering.** Counting a case as caught when *any*
hostile rule fires, which is generous:

| Family | Cases | Should match | Caught | Recall | Should not | Fired wrongly |
|---|---:|---:|---:|---:|---:|---:|
| 933 PHP | 429 | 184 | 28 | 15% | 38 | 0 |
| 932 RCE | 1,006 | 406 | 33 | 8% | 64 | 0 |
| 941 XSS | 263 | 72 | 13 | 18% | 4 | 0 |
| 942 SQLi | 1,033 | 135 | 31 | 23% | 12 | 0 |

SQLi and XSS have had rules for months and sit beside PHP, whose rules are days
old. That makes this a measurement of the pack rather than of any one
afternoon's work.

**Recall is over what a log can see.** A combined access log holds the request
line, the Referer and the User-Agent. 2,650 cases put their payload in a body or
a header it never writes, and those are counted apart rather than as misses:
scoring them would measure the log format and publish the result as a score for
the rules.

**The corpus asks three questions; two of them are ours.** This decision is
about not letting one project mark its own homework, and reading the answer key
carelessly reintroduces the same fault by another route.

- `expect_ids` — an attack. The recall denominator.
- `no_expect_ids` *described* as a false positive — traffic CRS certifies as
  harmless after a user reported one of its rules firing on it. The false-alarm
  denominator, and the more valuable of the two: a pack reaches any recall it
  likes by matching everything, and only this number stops that scoring well.
- `no_expect_ids` otherwise — **not a question this tool is asked.** The key
  names CRS rule *ids*, not traffic. One case under it is
  `system('echo cd /tmp;wget …;rm -rf')`, marked so that rule 932230 stays out
  of a neighbouring rule's way. logarc has no mapping onto CRS rule numbers —
  by the paragraph below, deliberately — so it can be neither right nor wrong
  there. 469 such cases are counted, named, and scored in neither column.

Across every family, one false alarm in 134 certified-benign cases:
`template_injection` on a bare ERB output tag, which CRS holds is legitimate
unless the tag evaluates something.

**A correction.** The figures first published here — 11%, 8%, 13% and 17% —
were produced by a scorer that read every case as an attack, counting the
quarter of the corpus that must not match as misses. They understated the pack.
The correction is recorded rather than quietly swapped, because an ADR that
edits away its own wrong numbers is worth less than one that keeps them.

**What does not change.** Nothing here revives scoring CRS against itself, and
nothing here treats CRS's rule ids as ground truth for a category — the mapping
table and its withholdings stand exactly as decided above. The third bucket is
that same refusal, applied to the answer key rather than to the findings.

## Amendment, 2026-10-14 — RE2 inside the sidecar

**The sidecar's `@rx` runs on RE2 instead of Go's `regexp`.** Go's `regexp` was
half of a sidecar's time, and RE2 compiled to WebAssembly, run on wazero, takes
CRS replay of the 941,031-line 2026-10-06 large tier from 69.1 s to 49.0 s with
the same detections on all three tiers and on CRS's regression corpus.
`crs/README.md` has the measurements and what they cost.

That adds to the "two Apache-2.0 dependencies" above: wazero (Apache-2.0),
go-re2 (MIT), and the code go-re2 carries compiled in — RE2 and cre2
(BSD-3-Clause), wasi-libc with musl and cloudlibc in it, and LLVM's libc++. None
of their licences is in the Go module, so their texts are kept in
`crs/licenses/go-re2/` and ship beside go-re2's own. The operator itself,
`crs/rx.go`, is adapted from coraza-wasilibs and keeps its Apache-2.0 header.
The sidecar in the packaged application grows from about 22 MB to about 28 MB.

**A detection-changing engine would now fail a test.** The regex engine is the
second component this project does not write, beside Coraza, and either could
change what CRS reports with nothing here changing. So every detection the
sidecar makes on the regression corpus is pinned, by rule and by digest, in
`tests/data/crs-corpus-detections.json`, and CI replays the corpus against it.

## Amendment, 2026-10-15 — RE2 compiled ahead, not at start-up

**The amendment above shipped a sidecar that crashed on newer Intel CPUs.**
go-re2 v1.6.0 ran RE2 on wazero v1.7.2, which compiled the WebAssembly to
machine code when the sidecar started, and that code called Go's `memmove`
counting on it to leave DX alone. From Go 1.24 on, `memmove` writes DX when it
copies 2 KiB or more with `REP MOVSQ`, which it does on Intel CPUs with both
ERMS and FSRM: Ice Lake, 2019, and most Intel CPUs since. On those the sidecar
panicked loading CRS (`wasm error: invalid table access`), and on no other.
wazero fixed it in v1.9.0 (its #2375). It was not seen here because the one
computer that measured the change, and that ran CI while GitHub's runners were
unavailable, has a Comet Lake CPU without FSRM; a teammate's machine found it,
and one of GitHub's runners did on the first run after they came back.

**Decision: go-re2 v1.12.0, which translates RE2 to Go before the build.** Its
default build runs wasm2go over the WebAssembly module and compiles the result
with the rest of the sidecar, so nothing generates machine code at run time and
wazero is not linked in at all. That retires the kind of fault, not only this
one: what runs is ordinary Go, compiled by the Go toolchain that knows its own
calling convention. v1.10.0, which keeps wazero with the fix, was measured
beside it and was slower on every build. Measured 2026-10-15, alternating, six
sidecars, the middle of three runs, identical detections throughout:

| | Go `regexp` | go-re2 v1.6.0 | go-re2 v1.12.0 |
|---|---|---|---|
| start-up | 0.12 s | 1.02 s | 0.32 s |
| small, 63,310 lines | 13.6 s | 11.2 s | 9.4 s |
| medium, 235,732 lines | 31.7 s | 27.0 s | 20.7 s |
| large, 941,031 lines | 90.1 s | 64.1 s | 56.2 s |

The Go `regexp` column was measured in a separate run against v1.12.0, whose
own figures there were 8.1 s, 21.3 s and 53.8 s. Go `regexp`'s three large runs
spread from 80.5 to 105.2 s, the widest of any. The machine was slower than on
2026-10-14 throughout, so none of these compares with the figures in the
amendment above.

The licence folder gains Abseil, which the newer RE2 is built with, and keeps
the rest at the versions wasi-sdk-25 builds from; `crs/licenses/go-re2/README.md`
lists them.

**What keeps it from happening again.** A CPU-dependent fault passes every test
on a machine that does not take the path, so `crs/memmove_test.go` takes it on
purpose: it sets the runtime's own switch for that copy path, loads CRS, and
matches an attack through RE2, then does the same as the CPU copies. CI runs it
on Windows and Linux, and again with `GODEBUG=cpu.all=off`. Against go-re2
v1.6.0 it fails on any amd64 machine with the panic above. And the merge gate
is GitHub's CI again, whose runners are a mix of CPUs, rather than one desk.

**The corpus record was also short.** Defender had removed three CRS corpus
files from the checkout the record was written from, so "the same detections
on CRS's regression corpus" above covered 5,051 of 5,060 requests. The record is
now written from a clean clone, and a checkout missing corpus files is neither
compared nor recorded from.
