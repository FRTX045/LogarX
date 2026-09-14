# Evaluation

How the tool is checked, what the numbers say, and what they do not.

Every figure here is reproducible from the commands shown, against the builds named below.
See [ADR-0011](adr/0011-a-real-server-log-is-the-headline-corpus.md) for why it is measured on a
real server's log, and [ADR-0005](adr/0005-measuring-accuracy-against-generated-ground-truth.md)
for the scoring method it kept.

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

The corpus is a real server's log. The companion repository
[BlackHat-Dataset](https://github.com/FRTX045/BlackHat-Dataset) stands up Apache 2.4 serving a
PHP shop in a container, drives scripted shoppers, crawlers and a real Chromium at it, runs five
real security tools (whatweb, dirb, gobuster, nmap, sqlmap) alongside six attack campaigns that
read each response and decide what to do next, and ships the log Apache wrote.

What makes it scoreable is how the labels are obtained. Every request passes through a tagging
proxy that gives it an id, and every client writes a ledger of what it was doing. The truth file
is the join of the two, so a label says which client made the request and why, rather than what a
pattern-matcher thought of it afterwards. Nothing in this project produced it, which is the
property the previous generated corpus could not have.

The truth is JSON Lines, one record per log line, in order: the client address, one of fourteen
category names, and an `instance_id` whose consecutive repeats mark one activity.

**Timestamps are computed, not captured.** The driver issues its plan as fast as the sockets
allow, so the captured log covers minutes at an impossible rate; arrival times are then rewritten
onto the diurnal and weekly curves the traffic was planned against, and the raw capture ships
beside the result. Everything else on every line is as Apache wrote it. Anything measured against
the clock, and the threshold sweeps below most of all, is therefore measuring that model as much as
it is measuring this tool.

### The grain of an episode

The dataset and this tool disagree slightly about when one activity ends, and the disagreement is
measured rather than removed.

The dataset cuts a shopper's visit into browsing, searching and using the basket, and for the
traffic it labels through the proxy rather than from a driver ledger it cuts on every change of
category, so a page and the assets it pulls in become separate episodes. The episode builder
draws all ordinary use as one activity until the client goes quiet (`_ORDINARY_USE` in
`episode/builder.py`, chosen 2026-08-25 with its own measured argument).

On the medium build, of 196,746 adjacent pairs of ordinary requests from the same client:

| | pairs |
|---|---:|
| truth keeps them in one activity | 194,008 |
| truth cuts, and the gap is over 300 s so the tool cuts too | 2,586 |
| **truth cuts inside the gap, where the two grains differ** | **152** |

Those 152 are 5.6% of the cuts the truth makes between ordinary requests, and the tool does not
decline all of them: it draws 38 anyway, for a reason that has nothing to do with the grain. In
every one of those 38 the client changes its `User-Agent`, which ends the session
(`split_on_user_agent_change` in `sessionize/segmenter.py`) and so starts a new episode. Both
sides are ordinary use in all 38, and the tool's label agrees with the truth's on both. The
boundary comes from session segmentation, not from classification.

It misses the other **114**, and that is where this policy actually costs recall: 114 of the 128
boundaries the headline run misses in total. The score is allowed to be lower for them. Adjusting
the truth to match the tool is what the previous generated corpus ended up doing, and
[ADR-0011](adr/0011-a-real-server-log-is-the-headline-corpus.md) records why that is not repeated
here. Hostile activities are never merged into anything, so a missed boundary around an attack,
the part a forensic reader cares about, counts in full.

## The builds

Two builds of the same project, both scored below.

| | `2026-09-07-medium` | `2026-08-23-small` |
|---|---|---|
| Role | **the headline** | fast check |
| Lines | 243,908 | 66,305 |
| Span | 7 days, 2026-03-09 to 03-16 | 1 day |
| Sessions | 7,822 | 2,368 |
| Scenario seed | 19 | 7 |
| Dataset commit | `0485a9a6` | `8217bce3` |

The figures belong to these exact bytes, so the digests are recorded here in full. The builds
themselves are not in this repository, and neither are the `SHA256SUMS` files that ship beside
them:

```
# 2026-09-07-medium
a61205732cfcb9ce0369e95326c7daef3be60156b9be2553fcdf07e200e96e8e  access.log
5ad028400eb64cf50b8317a353a1016f6e5c0254aba50f010052daf26483e406  truth.jsonl
94ed6380e17774f7f25fe693badcc50f66e0a783d5e3d288661caef3fd9e1ff0  MANIFEST.json

# 2026-08-23-small
3a48f1ee558b9d58995b7c43d6d1d6f1d05f6f571a5d72c09331a6261910736a  access.log
d1c4599ec127ddb9a5b76bdc943b492a5f56302db032b3749f7e3485bd6621f2  truth.jsonl
da2e65809692e465677a3c0bb814a87a102544f315afafbe32489321722b358a  MANIFEST.json
```

**The figures below belong to those bytes, not to those seeds.** The dataset reproduces its plan
of requests from a seed, and says outright that it does not reproduce its output byte for byte:
six campaigns react to a live, mutating application and requests interleave differently on every
run. A rebuild at the same seed scores close to what is printed here, not identically. Anyone
checking these numbers should verify the checksums first; anyone who rebuilds should expect the
last decimal to move and should say which build they measured.

The builds are not in this repository. They are 22 MB and 80 MB — whole builds,
log plus truth plus manifest, which is why those figures sit above the 52.4 MB
the throughput table gives for the medium build's `access.log` on its own.
[samples/README.md](../samples/README.md) says how to obtain or rebuild one. The test suite does
not need them: it scores a committed 3,825-line excerpt under `tests/data/apache-shopfront/`,
pinned by its own checksums.

## Reproducing

```bash
B=samples/apache-shopfront/2026-09-07-medium
logarc ingest $B/access.log --case ./case-medium
logarc enrich --case ./case-medium
logarc evaluate --case ./case-medium --truth $B/truth.jsonl --out medium.json
logarc evaluate --case ./case-medium --truth $B/truth.jsonl --no-absorb --out medium-noabsorb.json
```

The `enrich` step is part of the measurement, not an extra: every headline figure is of the
complete tool, with OWASP CRS applied at the project's default paranoia level 2. Native-only runs
are reported beside them as labelled comparisons, and on this corpus, unlike on the generated
one, the two differ.

## Classification

Measured 2026-09-08, ruleset `e81ace93…` (33 rules), CRS `d694d465` at paranoia level 2,
configuration `f357d142fbcc4441`. Every line of both builds was scored; none went missing.

| Build | Requests | Clients | | Accuracy | Macro F1 | Weighted F1 | Attack P | Attack R | False alarms |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|
| medium | 243,908 | 2,760 | native | 0.968 | 0.634 | 0.970 | 0.999 | 0.940 | 0.009% |
| medium | 243,908 | 2,760 | **with CRS** | **0.967** | **0.633** | **0.969** | **0.998** | **0.941** | **0.016%** |
| small | 66,305 | 937 | native | 0.972 | 0.631 | 0.974 | 0.993 | 0.938 | 0.045% |
| small | 66,305 | 937 | **with CRS** | **0.972** | **0.638** | **0.974** | **0.991** | **0.940** | **0.056%** |

Per category, medium build with CRS:

| Activity | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| `static_asset` | 168,257 | 0.998 | 1.000 | 0.999 |
| `crawling` | 26,204 | 1.000 | 0.986 | 0.993 |
| `browsing` | 19,716 | 0.944 | 0.998 | 0.970 |
| `enumeration` | 14,242 | 0.999 | 0.542 | 0.703 |
| `api_call` | 11,249 | 0.962 | 1.000 | 0.981 |
| `reconnaissance` | 2,648 | 0.294 | 0.856 | 0.438 |
| `authentication` | 1,007 | 0.998 | 0.872 | 0.931 |
| `unknown` | 442 | 0.000 | 0.000 | 0.000 |
| `injection` | 57 | 0.678 | 0.702 | 0.690 |
| `credential_attack` | 39 | 1.000 | 0.667 | 0.800 |
| `access_control` | 28 | 0.000 | 0.000 | 0.000 |
| `exploitation` | 8 | 0.000 | 0.000 | 0.000 |
| `path_traversal` | 6 | 0.600 | 1.000 | 0.750 |
| `ssrf` | 5 | 0.500 | 0.800 | 0.615 |

The five most frequent category confusions on the medium build with CRS:

| Truth category | Predicted category | Requests |
|---|---|---:|
| `enumeration` | `reconnaissance` | 5,390 |
| `enumeration` | `browsing` | 669 |
| `enumeration` | `access_control` | 455 |
| `unknown` | `api_call` | 438 |
| `crawling` | `browsing` | 339 |

**Macro F1 of 0.633 is the number to be careful with**, and the table says why: it is an unweighted
mean over fourteen categories, three of which score zero and three of which have support in single
digits. Weighted F1 is 0.969 and accuracy 0.967 over the same predictions. Neither is the honest
headline on its own. Macro F1 refuses to let a rare category hide, which is the point of
reporting it. But a reader comparing 0.633 against the 0.958 this document used to print for
generated traffic is comparing two different corpora, not two versions of the tool.

Four groups deserve naming individually.

- **`unknown`, 0.000 over 442 requests, and it cannot be anything else.** These are the dataset's
  deliberately malformed requests. `ActivityCategory.UNKNOWN` exists in this codebase but no rule
  ever assigns it, so there is no prediction that could match. It is a structural zero, not a
  detection failure, and it costs the macro average 0.049 on its own.
- **`enumeration`, recall 0.542, against `reconnaissance`, precision 0.294.** These are one
  finding seen from both ends: requests the dataset calls a wordlist sweep are read as probing for
  known artefacts. The boundary between the two is a judgement (few deliberate requests against
  many blind ones), and on real tool traffic the tool draws it in a different place than the
  dataset's driver does. It is the largest single source of classification error here and it is
  a rule question, recorded rather than acted on.
- **`access_control` and `exploitation`, 0.000 over 28 and 8 requests.** Real ground that is
  genuinely uncovered: forced browsing to admin areas and webshell use, in volumes too small for
  the per-class figure to be stable but large enough to say the rules do not reach them.
- **`static_asset`, `crawling`, `browsing`, `api_call`**, the bulk of any access log, are at
  0.97 to 0.999. Ordinary traffic is read correctly, which is what keeps the false-alarm rate
  where it is.

## An external corpus: OWASP CRS regression tests

> **The `score-crs` command that produced this section has been removed.** CRS is being adopted as
> the signature layer, and rules scored against the corpus their own project maintains would be
> grading themselves. The figures below are kept because they are the evidence for that decision;
> they were measured against coreruleset `d694d465` and can be re-derived by reverting the removal.
> See the postscript in [ADR-0007](adr/0007-scoring-detection-against-the-crs-regression-corpus.md).

The figures above measure this project's rules against traffic somebody else produced, which is
the harder half of the problem. What they still do not do is test those rules against payloads
somebody else chose: the attacks in the corpus come from five tools and six campaigns the
dataset's authors selected, and a payload none of them sends is a payload the rules are never
asked about. The `+`-as-space defect is the proof that this gap is real: it survived every
scenario written here and surfaced only when an outside dataset was converted.

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

**That is not the ruleset shipping today, and the figure still holds.** The
current one fingerprints `e81ace93…`, also 33 rules. Everything that moved
between them is a *window* rule: one confidence raised, a `static_asset_ratio`
condition added to `directory_enumeration`, and `directory_enumeration_low_slow`
added. `owasp.yaml`, where every signature rule lives, is byte-identical to the
commit that produced this table (`cf59dfc`), and `recon.yaml`'s three signature
rules are unchanged.

A window rule cannot affect this measurement: each CRS case file is one request,
and a window rule needs a run of them. So the rate below describes the shipping
ruleset as well as the one it was measured on — which is worth stating, because
two different fingerprints in one document otherwise read as two different tools.

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
[ADR-0008](adr/0008-crs-as-a-signature-layer-beside-the-rule-packs.md). What it does to the
complete tool is measured on both builds, and on a negative control of ordinary traffic only:

| Corpus | Native only | With CRS |
|---|---|---|
| medium, 243,908 real requests | acc 0.968, macro F1 0.634, 21 false alarms | acc 0.967, macro F1 0.633, **37** false alarms |
| small, 66,305 real requests | acc 0.972, macro F1 0.631, 28 false alarms | acc 0.972, **macro F1 0.638**, 35 false alarms |
| ordinary-only clients, 225,881 real requests | | **16 false alarms, 0.0071%** |

**On real traffic CRS is a trade, not a free gain**, and the previous version of this document
could not have shown that: on generated traffic the two columns were identical to the last
decimal, because the native rules already fired on everything CRS caught. Here it raises recall
where the native packs are thin (`ssrf` from 0.600 to 0.800, `injection` from 0.684 to 0.702 on
the medium build), and it costs `injection` precision, 1.000 down to 0.678, which is why medium's
macro F1 moves by −0.001 while small's moves by +0.007. The false-alarm rate roughly doubles from
a very low base, 21 to 37 requests in 243,908.

The negative control is the sharper test. Every client whose truth is entirely ordinary (225,881
requests from 2,358 clients, with all 402 clients carrying any hostile or malformed line removed)
scores **16 false alarms, 0.0071% of ordinary traffic**, with CRS on at paranoia level 2. That is
the number a deployment would feel, and it is measured on real browsing rather than on a corpus
built to be scored.

Paranoia level 2 was fixed by an earlier measurement, on 365 lines of real 2010 WordPress traffic:
PL1 and PL2 leave its five hostile episodes alone, while PL3 flags a plain `GET /` as "Unix Shell
Code Found in Request" and invents a sixth. Against CRS's own 1,194 regression payloads, PL1
classifies 67% as hostile and PL2 reaches 90%, so the level is the highest one no control objects
to rather than the most cautious available.

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

Same runs as the classification tables, with native-only comparisons beside the CRS-enriched
results. `--no-absorb` runs the same evaluation with noise absorption off, so the merge rule
is measured in both configurations. The discussion below uses the CRS-enriched headline run.

| Build | Detection | Absorption | Truth activities | Episodes | Precision | Recall | Boundary F1 |
|---|---|---|---:|---:|---:|---:|---:|
| medium | native | on | 7,822 | 9,590 | 0.722 | 0.975 | 0.830 |
| medium | native | off | 7,822 | 10,676 | 0.624 | 0.975 | 0.761 |
| medium | with CRS | on | 7,822 | 9,619 | 0.719 | 0.975 | **0.828** |
| medium | with CRS | off | 7,822 | 10,709 | 0.621 | 0.975 | 0.759 |
| small | native | on | 2,368 | 2,770 | 0.734 | 0.940 | 0.824 |
| small | native | off | 2,368 | 3,080 | 0.629 | 0.941 | 0.754 |
| small | with CRS | on | 2,368 | 2,776 | 0.731 | 0.940 | **0.823** |
| small | with CRS | off | 2,368 | 3,092 | 0.625 | 0.941 | 0.751 |

**Recall is the segmenter's number, and it is 0.975 on the headline build.** Nearly every join the
truth places, the reconstruction places too: of 5,062 boundaries the truth has, 4,934 are drawn
and 128 are missed. 114 of those 128 are the grain disagreement described above, ordinary-use
cuts the tool declines to draw, which leaves 14 misses from every other cause combined.

**Precision is the ranking's number.** The tool draws 9,619 episodes where the truth has 7,822,
and the extra cuts are mostly the reconnaissance-versus-enumeration contest from the classification
section: a window rule relabels part of a probing run, and a label change is a boundary. Those
lines are all correctly hostile; the graph cuts them one time more than the truth does.

**Noise absorption is worth 0.069 of boundary F1, and this is the first corpus that could show
it.** Turning it off adds 1,090 episodes to the medium build and drops precision from 0.719 to
0.621, with recall unmoved at 0.975. That is exactly the shape the rule was designed for: it removes
boundaries that a brief benign interlude would otherwise create, and removes no others. On
generated traffic every one of these figures was *identical* with the rule on and off, because no
scripted attacker ever fetched a favicon in the middle of a sweep. Real ones do.

## Thresholds

Swept on the medium build, against its ground truth.

**Episode gap**, the silence that ends an activity:

| Gap | Precision | Recall | Boundary F1 | F1 with absorption off |
|---|---:|---:|---:|---:|
| 60 s | 0.706 | 0.992 | 0.824 | 0.757 |
| 120 s | 0.720 | 0.986 | **0.832** | 0.763 |
| **300 s (default)** | **0.719** | **0.975** | **0.828** | 0.759 |
| 600 s | 0.716 | 0.958 | 0.819 | 0.751 |
| 900 s | 0.713 | 0.945 | 0.813 | 0.744 |

Shallow and single-peaked: 0.019 of F1 across a fifteen-fold range, best at 120 s and 0.004 above
the default. Recall falls monotonically as the gap grows, because a longer silence swallows more
of the cuts the truth makes; precision peaks in the middle. **The difference is not material and
the default is kept**. A longer gap is the more forgiving choice for a slow client, and choosing
120 s to gain 0.004 on one build of one application would be tuning to the measurement. Note also
that this sweep runs against modelled arrival times, which is the one caveat that does not apply
to the rest of this document.

**Idle timeout**, the silence that ends a session:

| Idle timeout | Accuracy | Macro F1 | Boundary F1 | Episodes |
|---|---:|---:|---:|---:|
| 30 s | 0.963 | 0.623 | 0.735 | 11,381 |
| 300 s | 0.967 | 0.633 | 0.828 | 9,619 |
| **1,800 s (default)** | **0.967** | **0.633** | **0.828** | **9,619** |
| 28,800 s | 0.967 | 0.633 | 0.827 | 9,626 |

Identical from 300 seconds to eight hours, and worse only at the extreme: a session cut every
thirty seconds draws boundaries through activities that were still going on, costing 0.093 of
boundary F1 and 0.010 of macro F1. This is structural. Every gap long enough to end a session is
also long enough to end an episode, so the session boundary decides nothing the episode boundary
has not already decided. **The idle timeout should be chosen for how one wants a "session"
reported, not tuned for accuracy.**

## Throughput and memory

`logarc benchmark`, Windows 11, Python 3.13, one machine, on the medium build's real log. Each
size runs in a process of its own so peak memory is that run's and not the previous one's.

| Lines | Log | Ingest | Lines/s | MB/s | Peak RSS | Store | Ratio | Clients |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100,000 | 22.0 MB | 4.0 s | 25,170 | 5.5 | 258 MB | 1.0 MB | 22.3× | 1,454 |
| 243,908 | 52.4 MB | 8.5 s | 28,532 | 6.1 | 293 MB | 1.9 MB | 27.4× | 2,760 |

Lines per second is lower than the 26,000–31,000 this document previously reported on generated
logs, and megabytes per second is not: a real combined line here averages 225 bytes against the
generator's 208, so the same work is spread over fewer, longer lines. The store is 22 to 27 times
smaller than the log it came from.

**Reconstruction costs 210 microseconds per request, and that is the architectural claim.** The
benchmark reconstructs the busiest client in the store, and on a real log that client grows with
the corpus, which the generated corpus never showed:

| Lines in store | Busiest client's requests | Reconstruct | Per request |
|---:|---:|---:|---:|
| 100,000 | 6,173 | 1,324 ms | 214.5 µs |
| 243,908 | 16,860 | 3,529 ms | 209.3 µs |

Wall-clock nearly tripled while the corpus grew 2.4×, and the per-request cost held to within 3%.
That is the two-pass design behaving as intended (analysis is O(k) in one client's requests, not
O(n) in the corpus), and it is a stronger demonstration than the old table gave, where every
corpus size had about twenty requests per client and the busiest client barely varied. It also
means the honest way to quote reconstruction latency is per request: three and a half seconds is
what a week of one persistent crawler costs to reconstruct, and an ordinary client of fifty
requests costs about ten milliseconds.

The upper sizes are no longer measured. The million- and ten-million-line rows this section used
to carry came from generated logs that no longer exist; rebuilding them means the dataset's
`large` tier, about a million lines. The memory table below is kept because it was measured
directly against the store rather than against any particular corpus.

Memory is bounded rather than proportional. Measured separately, each size in a fresh process.

**Measured 2026-08-09, on Python 3.12** — a month before the figures above it and
on the previous interpreter, so it does not belong to the Python 3.13 heading
this section opens with. It is kept rather than re-run because it measures the
store directly, in rows pushed into it, and nothing about that path has changed
since. Rows, not log lines: a line becomes one row, but the two are counted at
different ends of the pipeline and the numbers should not be read as throughput.

| Rows | Peak during ingest | Peak after finalize | Finalize |
|---:|---:|---:|---:|
| 500,000 | 297 MB | 596 MB | 2.4 s |
| 2,000,000 | 296 MB | 1,062 MB | 8.3 s |
| 8,000,000 | 296 MB | 1,186 MB | 28.4 s |
| 12,000,000 | 296 MB | 1,189 MB | 40.2 s |

Ingest is flat at ~296 MB by construction. `finalize` converges on the configured 1 GB engine
ceiling: eight million rows to twelve moved it by 3 MB, where four million used to fail outright.

### Where the time goes

Before trying to make ingest faster, it was worth establishing what it spends its time on. These
three subsections were measured in August on a 50,000-line generated log, which no longer ships;
they are kept because the finding is about where CPU time goes inside the parser, which the
corpus does not change. The rates are not comparable with the table above.

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

Running it was not a formality. The first ten findings below concern defects in the tool or
the evaluation. The eleventh records a disagreement between the dataset and the tool about
episode boundaries; it is retained in the score, not treated as a defect to fix.

| Found by | Finding |
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
| Re-measurement, 2026-09-08 | The claim that reconstruction stays flat as the corpus grows was measured where it could not fail. Every generated corpus had about twenty requests per client at every size, so the busiest client, the one the benchmark times, barely varied, and a flat wall-clock said almost nothing. On a real log the busiest client grew from 6,173 requests to 16,860 and the wall-clock nearly tripled; the claim survives, restated per request at 214.5 µs against 209.3 µs, but the old table was not evidence for it. |
| Dataset grain comparison, 2026-09-08 | **Recorded, not fixed.** Of 152 ordinary-use truth boundaries within the episode gap, the tool draws 38 because a `User-Agent` change starts a new session. It misses the other **114**, accounting for 114 of the headline run's 128 missed boundaries. The truth is retained unchanged; see [the grain comparison](#the-grain-of-an-episode). |

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

The tenth is the seventh's lesson in another place: nothing failed, the number was true,
and the measurement behind it could not have come out any other way.

## Limits of these numbers

**One build of one application.** Both builds are the same PHP shop, driven by the same roster of
personas and tools. Nothing here separates what is true of this tool from what is true of that
shop. A second project in the dataset is what would answer it.

**A rebuild is not byte-identical.** The figures belong to the checksummed files in the table
above. The dataset reproduces its plan of requests from a seed but not its output, because the
attack campaigns react to a live application. Expect the last decimal to move.

**Timestamps are modelled.** Arrival times were rewritten onto diurnal and weekly curves; only
the ordering within a session is as captured. The threshold sweeps are the part of this document
most exposed to that, and the episode-gap table should be read as establishing that the parameter
behaves sensibly rather than as choosing a value for a real deployment.

**Three categories score zero, and one of them structurally.** `unknown` cannot be predicted at
all, because no rule assigns it, so it enters the macro average as a guaranteed zero over 442
requests.
`access_control` and `exploitation` are genuine gaps at supports of 28 and 8. Any per-class figure
below about fifty requests of support should be read as an indication, not a measurement; five
categories are below it on each build.

**The truth's grain differs from the tool's, and it costs 114 boundaries.** The truth cuts inside
the episode gap at 152 places between ordinary requests; the tool draws 38 of those for other
reasons and misses 114, which is 89% of every boundary the headline run misses. That is measured
in the grain section rather than corrected for.

**Outcome is not scored here at all.** The attempt-versus-breach distinction the reconstruction is
built around has no ground truth to be scored against: the truth format carries a category and an
episode id and nothing about what a request achieved. It is covered by unit tests over hand-built
events in `tests/episode/test_builder.py`, which is a weaker guarantee than a corpus, and it is
the largest hole in this evaluation. The dataset does record what each campaign achieved, so
closing it is possible.

**The false-alarm rate is measured on a corpus that is mostly ordinary**, which is the right
shape: 225,881 of 243,908 lines come from clients doing nothing hostile. That is a change from
the generated corpus, where a third of traffic was an attack and the rate was measured on less
benign traffic than a deployment would present.

**The CRS regression rate has a ceiling of 27%.** Only 1,138 of that corpus's 4,224 cases are
visible to a tool reading an access log at all; the rest carry their payload in a body or an
unlogged header, or assert that nothing should match. The 12.3% is also a floor within that
ceiling: status is synthesised as 200, which disables the one bundled rule that needs a 4xx.

**Recall on CSIC 2010 has a ceiling below 100%.** A substantial share of its attacks carry their
payload in a POST body, and a web server access log records the request line and nothing after it.
`logarc convert-csic` counts them in the corpus it is given and prints the resulting ceiling, so
the figure quoted alongside a CSIC result is measured on that copy of the dataset rather than
repeated from elsewhere.

**Throughput is a single-machine figure**, reported to show that cost per line does not grow with
the corpus rather than to compete on absolute speed.
