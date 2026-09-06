# Evaluation

How the tool is checked, what the numbers say, and what they do not.

Every figure here is reproducible from the commands shown. See
[ADR-0005](adr/0005-measuring-accuracy-against-generated-ground-truth.md) for why it is measured
this way.

## What is being measured

Two questions, scored separately, because a tool can be good at one and bad at the other.

**Classification** — was each request understood? Reported per activity category as precision,
recall and F1. A category the tool is weak at cannot hide inside an overall average.

**Segmentation** — were the joins between one activity and the next put in the right places?
Scored over adjacent pairs of one client's requests: for each pair the truth either does or does
not place a boundary there, and so does the reconstruction. That treats a merge and a split as
different mistakes, which they are; comparing episode counts cannot.

Alongside both, **attack or not** — the question a defender asks first — is reported for every
run, including on sources that cannot support anything finer.

## Where the ground truth comes from

Real access logs cannot be used to measure accuracy, because nobody knows what is in them. That
is the problem the tool exists to solve.

`logarc generate` writes synthetic Apache logs from scripted client roles — shoppers, a search
engine crawler, a content scanner, a password guesser, someone walking out of the document root,
and an attacker who works a site up to a successful injection and returns later to use it.
Clients run concurrently and are merged on time, so they interleave the way a real server sees
them rather than arriving in tidy blocks. Alongside the log it writes a record of which activity
produced every line.

That record is written from the client's script, never from what the rules match. The generator
does not import the detection engine. A burst is labelled enumeration because the client is
sweeping a wordlist, not because the enumeration rule fires on it.

Two categories sit close enough together to need a stated boundary, applied consistently:

- **reconnaissance** — probing for particular known-interesting artefacts: configuration files,
  backups, debug endpoints, a dependency manifest. Few requests, chosen deliberately.
- **enumeration** — sweeping a wordlist to discover what exists at all. Many requests, no prior
  knowledge of any of them.

The truth is written at the grain of what the client is *doing*, not of what each request *is*.
A shopper reading a page, the assets that page pulls in and the cart call it fires are one
activity: the shopper did one thing, and it took three kinds of request. Every request still
carries its exact category — `browsing`, `static_asset`, `api_call` — so classification is
scored per request, while segmentation is scored on the activity. This is the grain the episode
builder draws at, and it has to be: scored against a truth that cuts a page load into three,
the boundary score measures a disagreement about what a page load is rather than the segmenter.
That is not hypothetical; see the ninth row under *What the evaluation found*. Hostile steps keep
an activity of their own however they are made, and an attack between two page loads is never
part of either.

## Reproducing

```bash
logarc generate --scenario mixed --lines 40000 --seed 7 -o mixed.log -t mixed.truth.jsonl
logarc ingest mixed.log --case ./case-mixed
logarc enrich --case ./case-mixed
logarc evaluate --case ./case-mixed --truth mixed.truth.jsonl --out mixed.json
```

The same seed reproduces the same log byte for byte. The `enrich` step is part of the
measurement, not an extra: every headline figure below is of the complete tool, with OWASP CRS
applied at the project's default paranoia level 2. The native-only figures are reported beside
them where they differ, which on generated traffic is nowhere.

## Classification

40,000 requests per scenario, seed 7, default thresholds. Measured 2026-09-07 with ruleset
`e81ace93…` (33 rules) and CRS `d694d465` at paranoia level 2, configuration `f357d142fbcc4441`.
Every figure in this section came out **identical** with and without enrichment, to the last
decimal — CRS fired on 7,592 of `mixed`'s requests and changed no label, because the native rules
already fire on everything CRS catches here. ADR-0008 records why that is expected of generated
traffic, and why it says nothing about CRS's value on real traffic.

| Scenario | Clients | Accuracy | Macro F1 | Weighted F1 | Attack P | Attack R | False alarms |
|---|---:|---:|---:|---:|---:|---:|---:|
| `mixed` | 2,099 | 0.966 | 0.958 | 0.966 | 1.000 | 0.994 | 0 |
| `sqli_campaign` | 1,141 | 0.934 | 0.930 | 0.919 | 1.000 | 1.000 | 0 |
| `wordpress_scan` | 1,757 | 0.946 | 0.971 | 0.944 | 1.000 | 1.000 | 0 |
| `brute_force` | 1,344 | 0.982 | 0.941 | 0.985 | 1.000 | 0.970 | 0 |
| `path_traversal` | 3,012 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 |
| `normal_browsing` | 2,983 | 1.000 | 1.000 | 1.000 | — | — | 0 |

**Not one false positive** in 240,000 requests, including 40,000 lines of purely ordinary
traffic. `normal_browsing` has no attacks in it, so its attack precision and recall are
undefined; the tool reported none, which is the right answer and the reason the cells are empty
rather than zero.

Per category on `mixed`:

| Activity | Support | Precision | Recall | F1 | Recall (any) |
|---|---:|---:|---:|---:|---:|
| enumeration | 9,712 | 0.928 | 1.000 | 0.963 | 1.000 |
| static asset | 5,754 | 1.000 | 1.000 | 1.000 | 1.000 |
| reconnaissance | 5,484 | 1.000 | 0.784 | 0.879 | 1.000 |
| credential attack | 5,369 | 1.000 | 0.970 | 0.985 | 0.970 |
| browsing | 4,361 | 1.000 | 1.000 | 1.000 | 1.000 |
| crawling | 2,764 | 1.000 | 1.000 | 1.000 | 1.000 |
| path traversal | 2,704 | 1.000 | 1.000 | 1.000 | 1.000 |
| access control | 2,680 | 0.862 | 1.000 | 0.926 | 1.000 |
| API call | 562 | 1.000 | 1.000 | 1.000 | 1.000 |
| injection | 316 | 1.000 | 1.000 | 1.000 | 1.000 |
| authentication | 294 | 0.643 | 1.000 | 0.783 | 1.000 |

The two weak rows are both taxonomy overlaps rather than detection failures, and the lenient
recall column is what shows it:

- **reconnaissance, recall 0.784, lenient recall 1.000.** Every one of these requests matched a
  reconnaissance rule. They lost the ranking to a behavioural rule covering the same window: a
  scanner that probes for `/composer.json` in the middle of a wordlist sweep is doing both things
  at once, and the sweep is the stronger signal. 753 went to enumeration, 430 to access control.
- **authentication, precision 0.643.** 163 of the requests it claims are the successful login at
  the end of a password-guessing run. Truth calls those part of the attack; the tool sees a
  request to `/login` that succeeded. Both readings are defensible.

## An external corpus: OWASP CRS regression tests

> **The `score-crs` command that produced this section has been removed.** CRS is being adopted as
> the signature layer, and rules scored against the corpus their own project maintains would be
> grading themselves. The figures below are kept because they are the evidence for that decision;
> they were measured against coreruleset `d694d465` and can be re-derived by reverting the removal.
> See the postscript in [ADR-0007](adr/0007-scoring-detection-against-the-crs-regression-corpus.md).

Every figure above is measured on traffic this project wrote, against rules this project wrote.
That is a real weakness, and the `+`-as-space defect is the proof: it survived every generated
scenario and surfaced only when someone else's dataset was converted. A generator cannot find a
blind spot it shares.

The OWASP Core Rule Set ships a regression suite — 4,224 cases across the nine attack families
relevant here, each a concrete payload with an assertion about which of *their* rules must fire.
It is externally authored, maintained against real bypasses, and owes nothing to this project's
assumptions.

### What can be scored, and what cannot

| | cases |
|---|---:|
| scoreable, payload in the request line | 1,000 |
| scoreable, payload in `User-Agent` or `Referer` | 138 |
| payload in a request body | 2,560 |
| payload in a header a combined log does not write | 181 |
| CRS asserts that no rule should fire | 341 |
| no rule-id assertion either way | 3 |
| pre-encoded request | 1 |
| **total** | **4,224** |

Three in five cases put their payload in a request body, which no access-log tool can ever see.
"Visible" here means the **combined** format — the request line, plus `Referer` and `User-Agent`,
which this tool parses and has rules for. Judging against the common format instead would delete
the two families these rules are strongest at. The 341 negative cases are CRS's own
false-positive regression tests; counting them as payloads to be caught would score correct
restraint as failure, so they are held out of the rate and reported separately.

`score-crs` printed this accounting on every run rather than leaving it to a footnote.

### Reproducing

The command has been removed, so reproducing these figures means restoring it first. It was added
in `cf59dfc` and removed in `2868e78`; reverting the removal restores a working `score-crs`:

```bash
git revert 2868e78
git clone https://github.com/coreruleset/coreruleset vendor/coreruleset
git -C vendor/coreruleset checkout d694d465951ee06347214f1291ae096e40700001
logarc score-crs --corpus vendor/coreruleset --out crs.json
```

The corpus revision matters: both the denominator and the rate drift as CRS gains cases, so a
figure quoted without it is not re-derivable.

### The result

Ruleset `9edf8587…` (33 rules) against coreruleset `d694d465951e`, 200 case files.

| Family | Attack | Scoreable | Detected | Rate | In URI | In header |
|---|---|---:|---:|---:|---:|---:|
| 913 | scanner | 5 | 5 | 1.000 | 0 | 5 |
| 930 | LFI | 58 | 13 | 0.224 | 48 | 10 |
| 931 | RFI | 34 | 5 | 0.147 | 34 | 0 |
| 932 | RCE | 406 | 32 | 0.079 | 318 | 88 |
| 933 | PHP | 173 | 2 | 0.012 | 173 | 0 |
| 934 | generic | 195 | 18 | 0.092 | 195 | 0 |
| 941 | XSS | 83 | 17 | 0.205 | 69 | 14 |
| 942 | SQLi | 169 | 42 | 0.249 | 154 | 15 |
| 944 | Java | 15 | 6 | 0.400 | 9 | 6 |
| **total** | | **1,138** | **140** | **0.123** | **1,000** | **138** |

### Reading it

**12.3%**, and the number should be read for what it measures rather than argued down.

Part of the gap is a difference in what the two projects are for. CRS enumerates payload
*syntax* — hundreds of encodings, obfuscations and dialect variants of the same handful of
techniques — because a WAF has to survive an attacker rewriting a payload until something gets
through. This tool classifies *behaviour* an investigator reconstructs from, plus a set of
well-known artefacts. On a corpus that grades signature breadth, a behavioural ruleset scores
badly, and that is a fact about the two designs rather than an excuse.

The rest is genuinely uncovered ground, and the per-family split says where:

- **933 (PHP), 0.012 over 173 cases.** There is no PHP rule in either pack. The two detections
  are reconnaissance rules catching a path. Payloads like `tidy_parse_string()` and
  `$_SERVER['REQUEST_URI']` pass untouched. This is a hole, not a framing artefact.
- **932 (RCE), 0.079 over 406 cases** — the largest absolute gap, against a single
  `command_injection` rule.
- **934 (generic), 0.092 over 195**, where there is nothing generic to match with.
- **942 (SQLi), 0.249** and **941 (XSS), 0.205** are where six and two rules respectively do
  reach, and the misses are variants — `xor 5-`, `union all` split by comments, `!=` tautologies.
- **913 (scanner), 1.000** — all five, from `scanner_user_agent`.

Two properties of the measurement worth stating. Status is synthesised as 200 because the corpus
has no responses, which disables exactly one bundled rule (`admin_area_probe`, which needs a 4xx),
so the figure is a **floor** rather than an estimate. And the ceiling is 27%: only 1,138 of 4,224
cases are visible to an access-log tool at all.

### What was done about it

CRS itself was adopted, through Coraza in a Go sidecar — see
[ADR-0008](adr/0008-crs-as-a-signature-layer-beside-the-rule-packs.md). Three measurements decided
whether the rescue rule was safe, and they are the numbers that matter more than the 12.3%:

| Corpus | Native only | With CRS |
|---|---|---|
| `normal_browsing`, 20,000 generated requests | 0 hostile episodes | **0 hostile episodes** |
| Real 2010 WordPress traffic, 365 lines | 5 hostile episodes | **5 hostile episodes** |
| `mixed`, 100,000 generated requests | acc 0.965, prec 1.000 | **identical** |

Zero false positives on both negative controls at the shipped paranoia level of 2 — and this is
what fixed that level. The generated corpus produces no CRS detections at any level, so the real
log is the only control with anything to say: PL1 and PL2 leave its five hostile episodes alone,
while PL3 flags a plain `GET /` as "Unix Shell Code Found in Request" and invents a sixth. Against
CRS's own 1,194 regression payloads, PL1 classifies 67% as hostile and PL2 reaches 90%, so the
level is the highest one no control objects to rather than the most cautious available. And no
change
at all on the generated corpus, despite 54,720 CRS detections across 17,439 of its requests —
because the native rules already fire on everything CRS catches there, so nothing is rescued.

**That last row is ADR-0005's blind spot again, and it is worth stating plainly: the generated
corpus cannot demonstrate the benefit of this change.** The generator writes payloads the rules
were written for, so it contains nothing for CRS to rescue. The benefit only appears on payloads
from the miss list — where 42 requests reported as one Info-level `Scripted Client` episode became
three activities with the attack correctly named Critical.

### It is not a decoding problem

The obvious first suspicion about a low rate is that payloads are arriving obfuscated and the
normaliser is not undoing enough of it. That was measured rather than assumed, and it is wrong.

HTML entity decoding, JavaScript escape decoding and null removal were added and the corpus
re-scored: **12.0% to 12.3%**, three cases, all in 944 (Java), where `log4shell_jndi` is one of the
few rules that reads `User-Agent` and `Referer`. Scanning the full scored input of all 1,001 misses
beforehand had already put a ceiling on it — five contain an HTML entity, one a JavaScript escape,
and none a null byte.

What the misses actually are, after the percent-decoding that was already in place:

| CRS rule | Misses | Payload, decoded |
|---|---|---|
| 932140 | 150 | `for %variable in (set) do command` — Windows batch |
| 934160 | 28 | `while(!false)` — JavaScript control flow |
| 942550 | 27 | `OR '{"b":2}'::jsonb <@ '{"a":1, "b":2}'::jsonb` — Postgres JSON operators |

These arrive in plain text. Nothing is hidden; no rule expresses the syntax. The gap is
**expressiveness, not decoding** — which means coverage cannot be bought with normalisation, and
raising the rate means writing signatures for syntax the packs do not cover. See
[ADR-0007](adr/0007-scoring-detection-against-the-crs-regression-corpus.md) for the full follow-up.

### What is not claimed

No mapping from a CRS family to one of this tool's categories exists anywhere in the scorer. CRS
families name vulnerability classes; these categories name observed behaviour. A payload CRS files
under SQL injection that a path-traversal rule catches counts as caught. The categories that fired
are printed descriptively — 932 RCE payloads reaching `reconnaissance` 17 times and `injection` 12
is a shape worth seeing — and are not scored, because scoring them would turn an opinion about
taxonomy into a metric and make every future taxonomy change look like a regression.

The 341 negative cases were run separately: a rule fired on 13 of them, 3.8%. Advisory only —
`no_expect_ids` says one particular CRS rule must not match, not that the request is benign, so
this is not a false-positive rate.

`--out` writes all 1,001 uncaught payloads with their source file, test id and URI. The rate is
the summary; that list is the part that can inform which rules to write next.

## A real server: the BlackHat-Dataset shopfront

Everything above is traffic this project wrote. The companion repository
[BlackHat-Dataset](https://github.com/FRTX045/BlackHat-Dataset) stands up a real Apache serving a
real PHP shop, drives real browsers and real security tools at it — sqlmap, dirb, gobuster,
whatweb, nmap — and writes its truth from the driver's ledger of what each client was told to do.
Its `2026-08-23-small` build, 66,305 lines, scored 2026-09-07 with the same ruleset and CRS
configuration as above:

| | Native | With CRS |
|---|---:|---:|
| Accuracy | 0.972 | 0.972 |
| Macro F1 | 0.631 | 0.638 |
| Attack precision / recall | 0.993 / 0.938 | 0.991 / 0.940 |
| False alarms, share of ordinary traffic | 0.045% | 0.056% |
| Boundary F1, absorption on | 0.824 | 0.823 |
| Boundary F1, absorption off | | 0.751 |

**One build, one sample.** That repository measured the spread between builds of the same seed
at a few hundredths of precision and a few tenths of a point of false-alarm rate, so nothing
narrower than that is a difference. The two numbers worth reading are the ones outside that
spread. Macro F1 is 0.64 against 0.96 on generated traffic, and the confusion table says why:
1,139 requests the dataset calls enumeration were read as reconnaissance. That is a rule finding
on real traffic that the generator cannot produce, and it is recorded here rather than acted on.
And absorption, which changes nothing on generated traffic, lifts boundary precision from 0.625
to 0.731 here: real clients fetch a favicon in the middle of a sweep, and scripted ones do not.

## Segmentation, and what noise absorption costs

Measured 2026-09-07, same runs as the classification tables, CRS applied. `--no-absorb` runs the
same evaluation with noise absorption off:

| Scenario | Truth activities | Episodes | Precision | Recall | Boundary F1 | Boundary F1 (off) |
|---|---:|---:|---:|---:|---:|---:|
| `mixed` | 4,082 | 5,098 | 0.611 | 0.924 | 0.736 | 0.736 |
| `sqli_campaign` | 3,113 | 5,000 | 0.442 | 0.865 | 0.585 | 0.585 |
| `wordpress_scan` | 3,355 | 4,963 | 0.427 | 0.856 | 0.570 | 0.570 |
| `brute_force` | 3,554 | 4,202 | 0.751 | 0.971 | 0.847 | 0.847 |
| `path_traversal` | 6,229 | 6,142 | 1.000 | 0.973 | 0.986 | 0.986 |
| `normal_browsing` | 4,303 | 4,203 | 1.000 | 0.924 | 0.961 | 0.961 |

**Recall is the segmenter's number, and it is 0.86–0.97.** What it misses is one thing: the
pauses the shoppers take, drawn from 120–1,800 s, of which those under the 300 s episode gap
end an activity in the truth and not on the graph. The threshold sweep below is that same fact
seen from the other side.

**Precision is the ranking's number, not the segmenter's.** On the two scenarios with no probing
in them it is 1.000: every boundary the tool drew is one the truth has. On the four with a
scanner it falls to 0.43–0.75, and the extra boundaries are the reconnaissance-versus-enumeration
contest from the classification section: a window rule relabels part of a probing run, and a
label change is a boundary. The lines are all correctly hostile; the graph cuts them one time
more than the truth does.

**Absorption changes nothing on generated traffic, and that is a fact about the generator.**
The episode counts and every score are identical with the rule on and off, on all six scenarios.
Absorption merges two same-category runs split by a benign interlude of at most three requests
inside sixty seconds, and no script here produces one: the scripted attackers do not fetch a
favicon mid-sweep. Real ones do — the section above measured absorption lifting boundary
precision from 0.625 to 0.731 on the shopfront dataset — so the rule's value is established on
real traffic and cannot be established here.

### The measurement before the truth was regrained

The table above is the second measurement of the day, and the first is kept because the
difference is the finding. Until 2026-09-07 the generator wrote a shopper's page view, the assets
it pulled in and its cart call as three activities, while since 2026-08-25 the episode builder
has drawn them as one (`_ORDINARY_USE` in `episode/builder.py`, with its own measured argument).
Nobody re-ran the evaluation across that change, and the previous version of this section went
on publishing 0.98 recall from before it. Scored against the old truth, the current tool came out:

| Scenario | Truth activities | Precision | Recall | Boundary F1 |
|---|---:|---:|---:|---:|
| `mixed` | 8,987 | 0.611 | 0.266 | 0.371 |
| `sqli_campaign` | 5,875 | 0.442 | 0.360 | 0.397 |
| `wordpress_scan` | 5,858 | 0.427 | 0.334 | 0.374 |
| `brute_force` | 11,548 | 0.751 | 0.210 | 0.329 |
| `path_traversal` | 17,305 | 1.000 | 0.219 | 0.359 |
| `normal_browsing` | 18,936 | 1.000 | 0.076 | 0.142 |

Precision is unchanged to the third decimal, which is what says the drop was not the segmenter.
Between 63% and 98% of the expected boundaries lay between two ordinary-use requests, and the
tool declines to draw those on purpose. Regraining the truth restored recall; it could not have
restored the old 0.98, which was a property of the finer grouping the tool no longer produces.

The regraining is a decision, and it is worth stating what keeps it from being the scorer
grading itself. The grain was chosen on 2026-08-25 for the reader's benefit — more than half of
all episodes had become a single request — and without reference to this score, which nobody
had looked at. The truth states the client's intent at that grain rather than copying the
builder's output: a script that merged an attack into a page load would still disagree with the
truth, and the score would still fall. Hostile activities are never merged with anything, so a
missed boundary between an attack and whatever surrounds it counts in full, which is the part of
segmentation a forensic reader cares about.

## Thresholds

The defaults came from web-analytics literature rather than from this problem, so they were swept
against ground truth on `mixed`.

**Episode gap** — the silence that ends an activity:

| Gap | Precision | Recall | Boundary F1 |
|---|---:|---:|---:|
| 60 s | 0.616 | 0.942 | 0.745 |
| 120 s | 0.616 | 0.942 | 0.745 |
| **300 s (default)** | **0.611** | **0.924** | **0.736** |
| 600 s | 0.602 | 0.890 | 0.718 |
| 900 s | 0.594 | 0.860 | 0.703 |

Absorption on and off are identical at every value, for the reason given above. Monotone, and
almost flat: 0.042 of F1 across a fifteen-fold range. Shorter scores marginally
better, and the reason is a caution rather than a result — the generated pauses are drawn from
120–1800 s, so any threshold below 120 s catches all of them and thresholds above it begin to
miss some. **The sweep recovers the generator's own pause distribution, not a fact about real
traffic.** It establishes that the threshold does what it is supposed to do; choosing a value for
a real corpus needs real logs. The default is kept: the difference is not material, and a longer
gap is the more forgiving choice for slow clients.

**Idle timeout** — the silence that ends a session. Classification is *identical* at every value
from 30 seconds to eight hours (macro F1 0.958, accuracy 0.966). Boundary F1 moves only at the
extreme, and downwards: 0.622 at 30 s against 0.736 at 300 s and above, because a session cut
every thirty seconds draws boundaries through activities that were still going on.

This is structural, not a shortcoming of the corpus. Every gap long enough to end a session is
also long enough to end an episode, so the session boundary never decides anything the episode
boundary has not already decided. It would only affect classification if it fell below a
behavioural rule's window span and cut one in half — and even at 30 s it does not, because the
requests those rules match are seconds apart. **On this evidence the idle timeout should be
chosen for how one wants a "session" reported, not tuned for accuracy.**

## Throughput and memory

`logarc benchmark`, Windows 11, Python 3.12, one machine, `mixed` traffic. Each size runs in a
process of its own so peak memory is that run's and not the previous one's.

| Lines | Log | Ingest | Lines/s | MB/s | Peak RSS | Store | Ratio | Clients | Reconstruct |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100,000 | 19.7 MB | 3.8 s | 26,313 | 5.2 | 236 MB | 1.1 MB | 17.3× | 4,899 | 64 ms |
| 1,000,000 | 198 MB | 34.5 s | 29,008 | 5.8 | 626 MB | 8.3 MB | 23.8× | 49,175 | 81 ms |
| 10,000,000 | 1.99 GB | 321 s | 31,159 | 6.2 | 1,186 MB | 75.5 MB | 26.3× | 368,179 | 84 ms |

Those are the rates before the parse path was reworked; see [Taking the marshalling
out](#taking-the-marshalling-out) below, which re-measured 1,000,000 lines at 33,435. The rows are
kept as they were taken rather than restated, because the comparison is the point.

**Reconstruction stays flat while the corpus grows a hundredfold.** 64 ms against 84 ms, over a
store that went from five thousand clients to three hundred and sixty-eight thousand. That is the
two-pass architecture doing what it was chosen to do, and it is the number that matters most:
ingest is paid once, and every question after it is cheap.

Throughput is flat too — slightly *rising* with size, as fixed costs amortise.

Memory is bounded rather than proportional. Measured separately, each size in a fresh process:

| Rows | Peak during ingest | Peak after finalize | Finalize |
|---:|---:|---:|---:|
| 500,000 | 297 MB | 596 MB | 2.4 s |
| 2,000,000 | 296 MB | 1,062 MB | 8.3 s |
| 8,000,000 | 296 MB | 1,186 MB | 28.4 s |
| 12,000,000 | 296 MB | 1,189 MB | 40.2 s |

Ingest is flat at ~296 MB by construction. `finalize` converges on the configured 1 GB engine
ceiling: eight million rows to twelve moved it by 3 MB, where four million used to fail outright.

### Where the time goes

Before trying to make ingest faster, it was worth establishing what it spends its time on. On
`samples/mixed.log`, 50,000 lines:

| Stage | Time | Throughput | Share |
|---|---:|---:|---:|
| Read only — decode, strip, SHA-256 | 0.08 s | 611,000 lines/s | **4%** |
| Read and parse | 1.92 s | 26,000 lines/s | **96%** |

I/O is free; parsing is everything. Inside `parse_line`, by `cProfile` self-time: the regex match
is **25%**, `_parse_timestamp` 17%, and the remaining ~40% is CPython moving fields between
dictionaries — 800,000 `dict.get` calls for 50,000 lines, plus `groupdict` and `_clean`.

That the regex is only a quarter is the useful finding. It rules out a faster pattern engine as the
answer and points at either removing interpreter overhead or spreading the work.

Both were then tried. The share attributed to marshalling here turned out to overstate what
removing it was worth — see [Taking the marshalling out](#taking-the-marshalling-out).

### Parallel ingest

Spreading it. 400,000 lines, 75 MB, ingest only with `finalize` excluded:

| | Ingest | Lines/s | Speedup |
|---|---:|---:|---:|
| Sequential | 14.7 s | 27,265 | 1.00× |
| 2 workers | 8.5 s | 46,964 | 1.72× |
| 4 workers | 6.1 s | 65,864 | 2.42× |
| 8 workers | 5.7 s | **69,655** | **2.55×** |

Every one of those runs stored byte-identical results to the sequential run — same events, same
line numbers, same digest, same quarantine count. That is asserted first and the timings read only
afterwards, because a parallel ingest that loses a line looks exactly like a fast one.

**Ingest throughput still falls short of its target.** The plan asked for 100,000 lines/s; the
measured figure is 69,655 with eight workers, against 27,265 sequential on the same corpus.

The prediction behind this work was 124,000 — four workers times the sequential rate — and it was
wrong because throughput does not scale with the worker count. This machine has **four physical
cores behind eight logical ones**, and hyperthreading adds perhaps a quarter to CPU-bound work
rather than doubling it. 2.55× is close to what the hardware has to give, and adding workers past
four buys almost nothing: 2.42× to 2.55×.

[ADR-0009](adr/0009-parallel-ingest-rather-than-a-native-parser.md) records why the parser was not
rewritten in Go instead, given that the project already builds a Go binary for CRS.

### Taking the marshalling out

The step named above as "the honest next step" was then taken. Two changes to `parse_line`:
positional groups resolved when the format is compiled, in place of `groupdict` and the sixteen
`dict.get` calls a line was read back through; and a timestamp built in UTC and shifted, in place
of one built in the log's zone and converted with `astimezone`.

Parse only, `apache-combined`, best of three runs of 300,000 lines:

| | Lines/s | Gain |
|---|---:|---:|
| Before | 51,268 | — |
| Positional groups | 55,298 | +7.9% |
| ...and the shifted timestamp | **58,508** | **+14.1%** |

End to end, `logarc benchmark -n 1000000`, both runs on this machine minutes apart:

| | Ingest | Lines/s |
|---|---:|---:|
| Before | 34.76 s | 28,772 |
| After | 29.91 s | **33,435** |

**+16.2%, and the 100,000 target is still not met.** The estimate that opened this work was wrong
in the direction that matters: "~40% in field marshalling" implied roughly a third off the parse,
and the measured figure is a seventh. The 40% was self-time in a `cProfile` run, which inflates
what a call-heavy loop costs; the uninstrumented rate is the rate.

What is left is not marshalling. After both changes the profile reads: regex match **30%**,
`parse_line`'s own body 21%, `_parse_timestamp` 18%, constructing the `NormalizedEvent` 10%. The
first and last of those are CPython doing the work it was asked to do, and no rearrangement of
Python reaches 100,000 lines/s from here.

## What the evaluation found

Running it was not a formality. It found nine defects, all fixed, all locked by tests. Six were
in the tool; three were in the evaluation itself, which is the more uncomfortable half.

| Found by | Defect |
|---|---|
| Evaluation run 1 | Enumeration counted refusals as well as "no such thing", so it covered forced browsing's traffic and outranked it. Access control had **0.000 recall over 2,097 requests** while lenient recall was 1.000 — the rule fired every time and lost every time. |
| Evaluation run 1 | Error-based SQL injection matched no rule at all: injection recall 0.885 against precision 1.000, every miss the same technique. |
| Evaluation run 1 | Dependency-manifest probing was uncovered — the whole of the remaining reconnaissance gap. |
| CSIC conversion | `+` in a query string was not read as the space it means. Form encoding writes spaces that way, so `id=1%27+OR+%271%27%3D%271` reached the rules with no whitespace to match and **a payload any browser would send passed every signature**. |
| Benchmark | `finalize` used memory in proportion to the corpus — 238 MB, 1.1 GB, **6.9 GB** at 100k, 1M and 10M lines — against a design that says it follows the batch size. Capping the engine only moved the failure; it took splitting the sort in two. |
| Own test | The first memory fix passed a twenty-row test and failed on real data. Two faults only appear once the engine has actually spilled. |
| Threshold sweep | Every threshold from 60 s to eight hours scored **identically**, twice over. First because no generated client ever paused; then, after adding pauses, because each landed beside a request of a different category, where the category change decides the boundary before the gap is ever consulted. The tuning deliverable had been measuring nothing. |
| CRS follow-up | `distinct_paths` counted raw paths, so `/a/b`, `/a//b` and `/a/./b` counted as three. That metric is a threshold in three window rules, so **how a path happened to be written decided whether a behaviour was detected**. Eight requests across two resources were labelled enumeration. |
| Re-measurement, 2026-09-07 | The truth's grain fell behind the tool's. The episode builder had merged a page load into one activity thirteen days earlier, the generator still wrote it as three, and this document went on publishing a boundary recall of 0.98 that the current tool scored at **0.27** — 0.08 on ordinary browsing — while nothing had regressed. Found only because the tables were re-run for a new ruleset fingerprint. |

The fourth is worth dwelling on. Four scenarios of hand-written attack traffic did not find it,
because the same person wrote the generator and the rules. A dataset written by someone else found
it immediately.

The seventh is worth dwelling on for a different reason. The tests passed and the sweep script
worked; nothing failed. It surfaced only by reading the output and asking why every row was the
same.

The eighth repeats the fourth's lesson exactly. The generated corpus scored **identically** before
and after the fix — accuracy 0.965, 17,983 episodes, every figure unchanged — because the generator
writes clean paths and cannot produce the input that triggers the bug. A generator does not test
what its author did not think to vary.

The ninth is the one this document is most exposed to. A number was published, the code moved
under it for good reasons, and the number stayed on the page for thirteen days looking like a
result. Nothing failed: the tests passed, the tool was better, and the evaluation had quietly
started measuring a policy instead of the segmenter. The only defence is the one that found it —
re-running the tables whenever the ruleset fingerprint changes, and refusing to reprint a figure
the current code has not produced.

## Limits of these numbers

**They come from traffic this project wrote.** A generator shares the blind spots of whoever wrote
it, as the `+` defect demonstrates. Read them as an upper bound, not a prediction of field
performance.

**The corpus is far more hostile than a real site.** About a third of `mixed` is ordinary traffic;
a real log is overwhelmingly ordinary. That is deliberate — attack categories need enough support
to be scored — but it means the false-positive rate measured here is measured on less benign
traffic than a deployment would present.

**Segmentation is scored at the grain the tool draws.** A page load is one activity in the truth
because it is one activity on the graph, and the section above says what keeps that from being
the scorer grading itself. The finer measurement is kept beside it for the record. Absorption
cannot be evaluated on generated traffic at all; the shopfront dataset is where it is measured.

**The CRS rate has a ceiling of 27%.** Only 1,138 of the corpus's 4,224 cases are visible to a
tool reading an access log at all; the rest carry their payload in a body or an unlogged header,
or assert that nothing should match. `score-crs` counted every exclusion by reason and printed the
accounting on every run, so the ceiling travelled with the figure rather than living in this list.
The 12.3% is also a floor within that ceiling: status is synthesised as 200, which disables the one
bundled rule that needs a 4xx.

**Recall on CSIC 2010 has a ceiling below 100%.** A substantial share of its attacks carry their
payload in a POST body, and a web server access log records the request line and nothing after it.
`logarc convert-csic` counts them in the corpus it is given and prints the resulting ceiling, so
the figure quoted alongside a CSIC result is measured on that copy of the dataset rather than
repeated from elsewhere.

**Outcome cannot be evaluated on CSIC at all.** The traces have no responses, so the
attempt-versus-breach distinction the reconstruction is built around has nothing to be scored
against. It is checked only on generated traffic, where the generator decides which injection
succeeded.

**Throughput is a single-machine figure**, reported to show that cost per line does not grow with
the corpus rather than to compete on absolute speed.
