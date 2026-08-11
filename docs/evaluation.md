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

## Reproducing

```bash
logarc generate --scenario mixed --lines 40000 --seed 7 -o mixed.log -t mixed.truth.jsonl
logarc ingest mixed.log --case ./case-mixed
logarc evaluate --case ./case-mixed --truth mixed.truth.jsonl --out mixed.json
```

The same seed reproduces the same log byte for byte.

## Classification

40,000 requests per scenario, seed 7, default thresholds, ruleset `9edf8587…`.

| Scenario | Clients | Accuracy | Macro F1 | Weighted F1 | Attack P | Attack R | False alarms |
|---|---:|---:|---:|---:|---:|---:|---:|
| `mixed` | 2,000 | 0.966 | 0.959 | 0.966 | 1.000 | 0.993 | 0 |
| `sqli_campaign` | 1,141 | 0.934 | 0.930 | 0.919 | 1.000 | 1.000 | 0 |
| `wordpress_scan` | 1,757 | 0.946 | 0.971 | 0.944 | 1.000 | 1.000 | 0 |
| `brute_force` | 1,344 | 0.982 | 0.941 | 0.985 | 1.000 | 0.970 | 0 |
| `path_traversal` | 3,012 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0 |
| `normal_browsing` | 2,355 | 1.000 | 1.000 | 1.000 | — | — | 0 |

**Not one false positive** in 240,000 requests, including 40,000 lines of purely ordinary
traffic. `normal_browsing` has no attacks in it, so its attack precision and recall are
undefined; the tool reported none, which is the right answer and the reason the cells are empty
rather than zero.

Per category on `mixed`:

| Activity | Support | Precision | Recall | F1 | Recall (any) |
|---|---:|---:|---:|---:|---:|
| enumeration | 9,618 | 0.926 | 0.999 | 0.961 | 0.999 |
| static asset | 6,236 | 1.000 | 1.000 | 1.000 | 1.000 |
| credential attack | 5,529 | 1.000 | 0.970 | 0.985 | 0.970 |
| reconnaissance | 5,519 | 1.000 | 0.788 | 0.881 | 1.000 |
| browsing | 3,738 | 0.997 | 1.000 | 0.998 | 1.000 |
| crawling | 2,790 | 1.000 | 1.000 | 1.000 | 1.000 |
| path traversal | 2,680 | 1.000 | 1.000 | 1.000 | 1.000 |
| access control | 2,649 | 0.867 | 1.000 | 0.929 | 1.000 |
| API call | 611 | 1.000 | 1.000 | 1.000 | 1.000 |
| authentication | 324 | 0.663 | 1.000 | 0.797 | 1.000 |
| injection | 306 | 1.000 | 1.000 | 1.000 | 1.000 |

The two weak rows are both taxonomy overlaps rather than detection failures, and the lenient
recall column is what shows it:

- **reconnaissance, recall 0.788, lenient recall 1.000.** Every one of these requests matched a
  reconnaissance rule. They lost the ranking to a behavioural rule covering the same window: a
  scanner that probes for `/composer.json` in the middle of a wordlist sweep is doing both things
  at once, and the sweep is the stronger signal. 764 went to enumeration, 406 to access control.
- **authentication, precision 0.663.** 165 of the requests it claims are the successful login at
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

## Segmentation, and what noise absorption costs

Absorption merges two same-category episodes separated by a brief benign interlude, so that one
`favicon.ico` fetch in the middle of an attack does not split it into three activities. It
therefore removes boundaries the truth records, on purpose. `--no-absorb` runs the same
evaluation with the rule off:

| Scenario | Truth activities | Episodes (on) | Episodes (off) | Boundary F1 (on) | Boundary F1 (off) | Recall (off) |
|---|---:|---:|---:|---:|---:|---:|
| `mixed` | 9,190 | 7,260 | 10,190 | 0.662 | 0.917 | 0.981 |
| `sqli_campaign` | 5,875 | 6,196 | 7,762 | 0.593 | 0.787 | 0.944 |
| `wordpress_scan` | 5,858 | 6,120 | 7,466 | 0.597 | 0.789 | 0.944 |
| `brute_force` | 11,548 | 7,628 | 12,196 | 0.676 | 0.963 | 0.994 |
| `path_traversal` | 17,305 | 11,044 | 17,218 | 0.720 | 0.997 | 0.994 |
| `normal_browsing` | 20,368 | 11,060 | 20,244 | 0.652 | 0.997 | 0.993 |

The important column is the last one. **With absorption off, the segmenter finds 94–99% of the
activity boundaries the log contains** — the three-level scheme works. Absorption then discards
roughly a third to a half of them deliberately, which is what the drop in the on-column is.

That separates two things that could easily have been confused: whether the segmentation is
correct, and how coarse a graph it should produce. The first is measured at 0.99; the second is a
policy, and it has a switch.

## Thresholds

The defaults came from web-analytics literature rather than from this problem, so they were swept
against ground truth on `mixed`.

**Episode gap** — the silence that ends an activity:

| Gap | Boundary F1 (absorption on) | Boundary F1 (off) |
|---|---:|---:|
| 60 s | 0.667 | 0.920 |
| 120 s | 0.667 | — |
| **300 s (default)** | **0.662** | **0.917** |
| 600 s | 0.656 | — |
| 900 s | 0.650 | 0.909 |

Monotone, and almost flat: 0.017 of F1 across a fifteen-fold range. Shorter scores marginally
better, and the reason is a caution rather than a result — the generated pauses are drawn from
120–1800 s, so any threshold below 120 s catches all of them and thresholds above it begin to
miss some. **The sweep recovers the generator's own pause distribution, not a fact about real
traffic.** It establishes that the threshold does what it is supposed to do; choosing a value for
a real corpus needs real logs. The default is kept: the difference is not material, and a longer
gap is the more forgiving choice for slow clients.

**Idle timeout** — the silence that ends a session. Classification is *identical* at every value
from 30 seconds to eight hours (macro F1 0.959, enumeration F1 0.961, credential attack F1
0.985). Boundary F1 moves only at the extreme: 0.766 at 30 s against 0.662 at 300 s and above.

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

What remains is in the parse itself. The profile above puts ~40% of it in field marshalling that
could be removed without leaving Python — positional groups rather than `groupdict`, fewer
`dict.get` calls per line. That is the honest next step, and it is not done.

[ADR-0009](adr/0009-parallel-ingest-rather-than-a-native-parser.md) records why the parser was not
rewritten in Go instead, given that the project already builds a Go binary for CRS.

## What the evaluation found

Running it was not a formality. It found eight defects, all fixed, all locked by tests. Six were
in the tool; two were in the evaluation itself, which is the more uncomfortable half.

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

## Limits of these numbers

**They come from traffic this project wrote.** A generator shares the blind spots of whoever wrote
it, as the `+` defect demonstrates. Read them as an upper bound, not a prediction of field
performance.

**The corpus is far more hostile than a real site.** About a third of `mixed` is ordinary traffic;
a real log is overwhelmingly ordinary. That is deliberate — attack categories need enough support
to be scored — but it means the false-positive rate measured here is measured on less benign
traffic than a deployment would present.

**Segmentation recall is below one on purpose,** and the `--no-absorb` column is the evidence that
this is a policy rather than a failure.

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
