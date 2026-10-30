# Evaluation

How the tool is checked, what the numbers say, and what they do not.

Two kinds of figure appear here, and they are not equally checkable.

- **Reproducible by anyone from this repository:** the figures for the committed
  3,825-request excerpt under `tests/data/apache-shopfront/`, pinned by its own `SHA256SUMS`.
  Its scores, native and with CRS, are committed beside it.
  `tests/evaluation/test_published_scores.py` reruns the native scores on every test run, and
  the CRS scores wherever the sidecar and ruleset are built; CI requires them.
- **Reproducible from published builds:** the headline figures. The three `2026-10-06` builds
  they were measured on are published by the dataset, one release per build, and decompress to
  the digests recorded under [the current baseline](#the-current-baseline--2026-10-06), where
  the commands that scored them are printed.
- **Recorded measurements of builds that are not published:** every earlier baseline. Their
  checksums are recorded, but those bytes can no longer be obtained, so a reader cannot rerun
  them, and a rebuild from the dataset's recipe reproduces its plan of requests, not its bytes.
See [ADR-0011](adr/0011-a-real-server-log-is-the-headline-corpus.md) for why it is measured on a
real server's log, and [ADR-0005](adr/0005-measuring-accuracy-against-generated-ground-truth.md)
for the scoring method it kept.

## In brief

Measured on a real Apache log whose contents are known: the
[LogarX Dataset](https://github.com/FRTX045/LogarX-Dataset) `apache-shopfront`
`2026-10-06-medium` build — 235,732 requests over seven days, a real PHP shop
driven by real security tools, where a tagging proxy joins every line to a record
of which client made the request and why. It includes an administrator doing
ordinary work, which matters more than it sounds: see the false-alarm figure.

Measured 2026-10-09 on a build made at a named commit from a clean tree, whose
checksums were verified before scoring. Native rules only; CRS, which runs
after every scan by default, is the paragraph below the table.

| | |
|---:|---|
| **0.997** | accuracy over 235,732 requests |
| **0.997** | weighted F1 |
| **0.953** | macro F1 — *see below* |
| **1.000 / 0.998** | attack precision / recall |
| **0 requests** | false alarms, in 235,732 |
| **85,908** | lines per second ingesting, with the default four workers |
| **0** | lines quarantined, and 0 truth lines unmatched |

**Both numbers, or neither.** No false alarm in 235,732 requests is one axis and
not a claim that the rules are nearly right. Macro F1 of 0.953 is the other, and
it is an unweighted mean over fourteen categories, so a category with five
requests counts as much as one with 162,801. The weakest are the smallest:
`ssrf` names 4 of 5, `exploitation` 6 of 8 and `unknown` 124 of 201. The
tool's commonest mistake is calling an attack by a neighbouring name, 440 times
`enumeration` read as `reconnaissance`, which costs nothing on the first axis and
something on the second. Both are printed so neither can hide the other.

**With OWASP CRS at paranoia level 2**, the same build scores accuracy 0.997,
macro F1 0.952 and **0 false alarms**, and catches one attack the native rules
miss: 17,108 against 17,107. Across the three `2026-10-06` builds CRS adds 1 to
4 catches per build and no false alarm; until 2026-10-14 it added one on the
small build, a Google Ads click ID read as SQL. Until the same day the Windows
build of CRS also missed file paths such as `/etc/passwd` and `/.git/config`,
which the Linux build always caught; both now find the same. Until 2026-10-06 CRS also called
the shop's own unfilled `?id=${id}` placeholder an injection, 149 times on this
build;
[the rule-pack ledger](rule-pack-ledger.md) has how that was found and
what changed.

**Macro F1 is lower than the figure this project once published, and that is not
a regression.** Until September 2026 accuracy was measured against a corpus this
project generated itself, which scored macro F1 0.958. Moving to a log written by
a real server dropped it to 0.633, and work on the rules — and on defects the
dataset found in itself — has since brought it to 0.953 on the current build:
against real traffic, not against a corpus built to be scored. That first
drop was the first honest measurement, and
[ADR-0011](adr/0011-a-real-server-log-is-the-headline-corpus.md) records why
the generator was deleted rather than kept.

Per-category figures below about fifty requests of support are an indication, not
a measurement, and the sections below name which those are,
along with every caveat these headline numbers carry.

**Provenance note, 2026-09-17.** The bundled OWASP annotations migrated from
Top 10:2021 to Top 10:2025 without changing detection rules or reconstruction.
The committed 3,825-request excerpt was compared before and after, across all
52 clients, both native-only and with CRS enrichment at paranoia level 2.
Classifications, all matching labels apart from their OWASP annotations,
evidence references, sessions, episodes and graph transitions were identical.
CRS used revision `d694d465951ee06347214f1291ae096e40700001`, configuration
fingerprint `f357d142fbcc4441`, and host `localhost` in both runs.

The native-only regression fixture `excerpt.scores.json` was regenerated through
the evaluator. Every numerical result stayed identical; its native ruleset
fingerprint changed from
`5d14fa1f6be3cb8ae8c2d16782ad8a7f733241679224bbd470aed990b4b1d79f` to
`2661e2144bb698535ddf1bbbe48a17953e5c1b4735fed06dff4ff430c1301c57` because
annotations are part of the hashed rule definitions. This fixture is a native
regression check, not a complete-product accuracy measurement. Historical
measurements and their original fingerprints below remain as recorded; this
metadata migration does not remeasure those larger datasets.

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
[LogarX Dataset](https://github.com/FRTX045/LogarX-Dataset) stands up Apache 2.4 serving a
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

## The current baseline — 2026-10-06

**These are the live figures.** The 2026-09-21 baseline below is kept because the analysis written
against it still stands; its numbers are superseded by this table.

All three tiers of one dataset build, taken at one commit with the working tree clean. The dataset
fixed a defect in its own traffic just before it: its scripted browser had taken each request's
Referer from the *previous request*, API calls included, so a page view after a stock check carried
`Referer: http://shop.test/api/stock?id=N`, which no browser does — 8,389 lines of the 2026-09-20
headline build. One line of the same kind, from a second generator, is left in the medium tier
(line 162,137, `GET /c/decorating` from `/api/cart?id=1`). The dataset names it in the commit that
ships these builds. It moves no figure here: neither engine flags the line, and the truth calls it
`browsing`.

| | `2026-10-06-small` | `2026-10-06-medium` | `2026-10-06-large` |
|---|---|---|---|
| Role | fast check | **the headline** | a month |
| Lines / clients | 63,310 / 917 | 235,732 / 2,760 | 941,031 / 7,450 |
| Span | 1 day | 7 days | 30 days |
| Scenario seed | 7 | 19 | 31 |
| Dataset commit | `d2ef291` | `d2ef291` | `d2ef291` |
| Tree clean when built | **yes** | **yes** | **yes** |
| Quarantined on ingest | 0 | 0 | 0 |
| Truth lines unmatched | 0 | 0 | 0 |

`d2ef291` is on that repository's default branch, and the builds' manifests and samples are committed
there at `332b06b`. The logs themselves are published as one release per build, each tagged at that
commit: [`2026-10-06-small`](https://github.com/FRTX045/LogarX-Dataset/releases/tag/2026-10-06-small),
[`2026-10-06-medium`](https://github.com/FRTX045/LogarX-Dataset/releases/tag/2026-10-06-medium) and
[`2026-10-06-large`](https://github.com/FRTX045/LogarX-Dataset/releases/tag/2026-10-06-large). Every file of all three was
verified against the build's own `SHA256SUMS` before scoring, and on 2026-10-28 a fresh download
of each release decompressed to the same digests:

```
# 2026-10-06-small
3b42d1ed0f14a2a18554176e332f7c96b11a6865c596c863f1dd37d4b8e6486b  access.log
19cd892701be7b7512bfe2793037d5aa8134a7099986f5323645d02df5e00d11  truth.jsonl
22d6441492409d22f2646448efe9319bcec0b464c9bae9940b72d4231e32e9b5  MANIFEST.json

# 2026-10-06-medium
d2463e631da14bc0be12281999ebd60e42a57c044043c5118a65cff8ecf29c66  access.log
bf677e9e26ea5327d698e46ff1a63c0f08fe40cea50b413905a53f59f4d8d68c  truth.jsonl
a69632f19c0372c0e0591ccd67196c1b23111c7f38b3ca051a7948200367c621  MANIFEST.json

# 2026-10-06-large
8d1278b8b00d3e83559e8a2c2387cab0e05b99ecacc002ba5332c2bb1ab57a2e  access.log
54b66410effe83b1fddd95a1318db57e551ef78f161d33809a5f993e2662a49c  truth.jsonl
e6ac069ed71ab985a32667a87906173331587a3dfd9cc0be4fedada96801ec9b  MANIFEST.json
```

All six runs are one ruleset, fingerprint `328f237c91a986c6`, recorded in each output and scored
2026-10-14: the rules after PR #33 (`admin_reached_without_signing_in`), the two injection rules
narrowed in `812c4a3` (which moved nothing on these tiers), PR #35
(`injection_reaches_for_secrets`), the naming pass after it (injection tools by User-Agent, a
`file://` fetch as SSRF, `verb_tampering`), `credential_guess_accepted` and
`action_sign_in_wall`, with the episode builder keeping a page's own files with it,
`malformed_software_probe`, and the directory-enumeration windows naming the probes inside their
own sweeps (`outranks`). The same bytes were first scored on 2026-10-06 at `cbb1235` with
fingerprint `5bcfdcff474f63ae`; the [rule-pack ledger](rule-pack-ledger.md) has every step.

Until the last, each moved only requests the truth names `access_control`, `authentication`,
`credential_attack`, `exploitation`, `injection`, `reconnaissance` or `ssrf` — from browsing,
sign-in, an API call, reconnaissance, injection or path traversal — and no category lost a correct
answer. The sweep change did lose some: on medium it moved 287 configuration-file probes from
`reconnaissance` to `enumeration`, 262 of them rightly and 25 a reconnaissance campaign's own probes
sent from inside a sweep (6 of 74 on small, 80 of 1,101 on large). The builder change moved no label
and raised boundary F1 by about two points on every tier, and the sweep change by about three more.
The CRS runs are revision `d694d465`, configuration `f4a1c8296441d261`, paranoia level 2,
and include the `${name}` placeholder fix (PR #30); the native runs are identical with and without
it, field for field. They were re-run on 2026-10-14 after the Windows sidecar was found misreading
file paths, which is why their configuration differs from the excerpt's older figures; see below.

The README's ingest rate is the medium log ingested three times at `e87e8d7` with nothing else
running: 84,623, 85,908 and 87,202 lines/s, median **85,908**, with the default four workers on
four physical cores (Windows 11, Python 3.12). It is a different measurement from the sequential
`zodiarc-dev benchmark` figures under [Throughput and memory](#throughput-and-memory).

| | small native | small + CRS | medium native | medium + CRS | large native | large + CRS |
|---|---:|---:|---:|---:|---:|---:|
| Classification accuracy | 0.9973 | 0.9973 | **0.9975** | 0.9975 | 0.9976 | 0.9976 |
| Weighted F1 | 0.9972 | 0.9972 | 0.9975 | 0.9975 | 0.9976 | 0.9976 |
| Macro F1 | 0.9427 | 0.9434 | **0.9532** | 0.9525 | 0.9646 | 0.9640 |
| Attack-or-not precision | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 1.0000 |
| Attack-or-not recall | 0.9890 | 0.9900 | 0.9976 | 0.9976 | 0.9991 | 0.9992 |
| Caught / missed | 4,039 / 45 | 4,043 / 41 | 17,107 / 42 | 17,108 / 41 | 40,775 / 35 | 40,777 / 33 |
| **False alarms** | **0** | **0** | **0** | **0** | **0** | **0** |
| Boundary F1 | 0.9096 | 0.9099 | 0.9136 | 0.9137 | 0.9184 | 0.9184 |

**No false alarm on any of the three, natively or with CRS, and that is a count, not a rate.**
Until 2026-10-14 CRS added one on small: rule 942100 (libinjection) reading a Google Ads `gclid`
click ID as SQL, which also placed that harmless visitor seventh in the Suspicious queue. A CRS
match on an ad platform's click-ID parameter whose value is an opaque token no longer names the
request; CRS's own regression corpus keeps two such tokens as false positives for 942440. CRS
catches 4, 1 and 2 more attacks than the native rules on the three tiers.

**Until 2026-10-14 the Windows sidecar misread file paths, and the CRS columns were Windows's.**
Coraza tidies a path with Go's `path/filepath`, which on Windows writes `\`, so CRS's lists of
system files and secrets never matched there: on CRS's own regression corpus the Windows sidecar
found 104 fewer things than the Linux one. With that fixed (`crs/paths.go`), small and large each
catch one more attack, a `/.DS_Store` probe the native rules read as browsing among them, and the
three tiers' new CRS evidence otherwise lands on requests the native rules already named. It also showed a
false alarm the Linux sidecar had always raised: rule 930121 finding the path `perl/` inside the
User-Agent `libwww-perl/6.72`, 17, 72 and 151 times on the three tiers. A file-list match inside a
User-Agent made only of `name/version` products no longer names a request, so both systems now
report the zero above.

Before the placeholder fix, CRS scored 45, 149 and 670 false alarms on these tiers, all of them the
shop's unfilled `?id=${id}` requests apart from the click ID on small. The
[rule-pack ledger](rule-pack-ledger.md) has the whole measurement.

**No column is worse than 2026-09-21's, and that comparison is weaker than it looks.** The two baselines are different builds of a dataset that fixed defects in itself in between,
so the change says the pair improved, not how much of it the rules did. What each rule change bought
is measured on fixed bytes in the ledger.

**What is still wrong, on medium, natively.** The commonest mistake is still a neighbouring name:
440 `enumeration` requests read as `reconnaissance`. 433 are lone probes answered 404 for four
files — `/backup.zip`, `/.svn/entries`, `/db.sql` and `/cgi-bin/test.cgi`, one or two from each of
about eighty clients, mostly under a browser's User-Agent — with no sweep around them. A probe for a
named file is reconnaissance by the boundary ADR-0005 draws; the truth calls these enumeration
because of which campaign sent them, the convention the [ledger](rule-pack-ledger.md) left alone on
2026-10-05. It was 702 until 2026-10-14, when the directory-enumeration windows began naming the
probes inside their own sweeps; that put 262 right and 25 wrong, and those 25 are most of the 34
`reconnaissance` now read as `enumeration`. After them come 75 `unknown` read as
`static_asset`, all the shop's own `FettleImporter/1.0` fetching its logo, which is site-specific;
16 `enumeration` read as `browsing`, the pages one wordlist sweep found, each answered as it would be
to anyone; and 10 `reconnaissance` read as `browsing`, mostly a tool's opening `GET /` and `HEAD /`.
That last was 53 until 2026-10-14, when `malformed_software_probe` named one client's 43 hand-built
probes for `/admin.php`, `/phpmyadmin/`, `/shell.php` and `/wp-login.php`, every one answered 400.
Until the same day 67 `authentication` read as `browsing` stood above it too, and this paragraph
explained them wrongly, as an administrator's page views. They were admin pages answering with the
sign-in form, each followed by the sign-in page asking to come back; `action_sign_in_wall` names all
of them.

The commands that produced every column, per tier, starting from the build's release. The
release is 3.5 MB small, 13 MB medium and 53 MB large, compressed; `sha256sum` warns about
the comment lines in `SHA256SUMS` and checks every file it names:

```bash
B=datasets/apache-shopfront/2026-10-06-medium
gh release download 2026-10-06-medium -R FRTX045/LogarX-Dataset -D $B
(cd $B && xz -dk *.xz && sha256sum -c SHA256SUMS --ignore-missing)
zodiarc-dev ingest $B/access.log --case ./case --no-crs
zodiarc-dev enrich --case ./case
zodiarc-dev evaluate -c ./case -t $B/truth.jsonl -o native.json --no-crs
zodiarc-dev evaluate -c ./case -t $B/truth.jsonl -o crs.json
```

Download the build rather than rebuilding it. A rebuild from the recipe will not have these
digests: the dataset reproduces its plan of requests from a seed, not its bytes (see below).
Expect the last decimal to move on a rebuild, and say which build was measured.

Rerun exactly that way on 2026-10-28, from a fresh download of the medium release, at `main`
`d4466ba`: a later ruleset than the table's (`9ede4d8efca57302`), the same CRS configuration. Every
medium figure above came out identical, natively and with CRS: accuracy 0.9975, macro F1 0.9532
and 0.9525, 17,107 and 17,108 caught, 42 and 41 missed, 0 false alarms, boundary F1 0.9136 and
0.9137.

## The same traffic in every log format — 2026-10-27

Every figure above is from an Apache log. Zodiarc reads 21 built-in formats, and a format
can lose a field, or write it differently, in a way no test of a single line would show. So
the small and medium builds were rendered by the dataset into 20 other formats, the same
requests in each. Every rendered file was scored against its own truth and compared with
the Apache original.

The rendering is the dataset's: `render` at
[`1e29c09`](https://github.com/FRTX045/LogarX-Dataset/blob/1e29c09/docs/rendered-formats.md),
from the builds above. Every file is the Apache capture written in another server's
columns, never a capture of that server. A field the capture never measured is a declared
constant. All 41 files of each tier matched its `SHA256SUMS` before scoring
(`MANIFEST.json` `cc2b1e66…` small, `8cde4712…` medium). The code was `main` at `5449f64`
with PRs #88 and #89 merged in. Native rules only.

**Some lines no real server would have written as Apache did,** and the dataset flags them:
37 small and 124 medium that the server would not log at all, and 94 and 294 malformed
request lines that each server writes its own way: as received, or as its own refusal (IIS
would log none of them). They are the same records in every format. The table leaves them
out of every row, the Apache original included, so every row is scored on the same 63,179
(small) or 235,314 (medium) requests.

| Formats | Caught | Missed | False alarms | Recall | Accuracy | Macro F1 |
|---|---|---|---|---|---|---|
| **medium** | | | | | | |
| Apache original | 16,813 | 42 | 0 | 0.9975 | 0.9975 | 0.8980 |
| 15 formats, identical to it ¹ | 16,813 | 42 | 0 | 0.9975 | 0.9975 | 0.8980 |
| No Referer: `envoy`, `istio`, `aws-alb` | 16,813 | 42 | 0 | 0.9975 | 0.9972 | 0.8965 |
| No User-Agent: `apache-common`, `apache-vhost-common`, `haproxy` | 15,696 | 1,159 | 0 | 0.9312 | 0.8920 | 0.7625 |
| **small** | | | | | | |
| Apache original | 3,945 | 45 | 0 | 0.9887 | 0.9972 | 0.8902 |
| 15 formats, identical to it ¹ | 3,945 | 45 | 0 | 0.9887 | 0.9972 | 0.8902 |
| No Referer: `envoy`, `istio`, `aws-alb` | 3,945 | 45 | 0 | 0.9887 | 0.9970 | 0.8890 |
| No User-Agent: `apache-common`, `apache-vhost-common`, `haproxy` | 3,636 | 354 | 0 | 0.9113 | 0.8908 | 0.7552 |

¹ `apache-vhost-combined`, `apache-combined-io`, `nginx-main`, `nginx-combined-forwarded`,
`ingress-nginx`, `traefik-common`, `nginx-json`, `caddy-json`, `traefik-json`,
`cloudflare-json`, `gcp-http-json`, `ecs-http`, `iis-w3c`, `cloudfront`, and `haproxy` read
with its header captures (`haproxy-captures`). Identical means every figure the evaluation
reports, to the last request.

**No format raises a false alarm.** The rows that differ differ because the log has no
field, not because Zodiarc misreads one:

- **Without a User-Agent**, nothing says which client is a crawler, so all 22,680 crawler
  requests in the medium tier read as `browsing`: 0.096 of the 0.106 of accuracy lost. The
  rules that know a tool by its User-Agent cannot fire, either: `enumeration` falls from 13,849
  to 12,751, `authentication` from 1,781 to 759, `reconnaissance` from 2,355 to 2,340 and
  `injection` from 52 to 47. Before #89 these logs did worse. The rule for a missing
  User-Agent could not tell "the client sent none" from "the format has no such column",
  and it called every one of the small tier's 59,226 innocent requests reconnaissance.
- **Without a Referer**, 67 `authentication` requests in the medium tier (16 small) read
  as `browsing`, because a sign-in is known partly by the page it came from.

**With the flagged records left in,** two more differences show, both from those records:
`envoy` reads 235,438 of 235,732 lines (63,216 of 63,310 small). The 294 (94) it
quarantines are exactly the malformed request lines, which Envoy writes as its own refusal
with `-` for the client, its default format having no other client field, so they cannot
be attributed. And on those records `gcp-http-json` and `iis-w3c` lose 0.0005 of accuracy
(0.0006 small), and `aws-alb` 0.0005 (0.0006) more than its missing Referer costs.

The rendering found four defects, all fixed before these runs: Cloudflare's nanosecond
timestamps stopped the import (#86); ECS logs lost their Referer and Cloudflare logs their
protocol (#87); CloudFront's own percent-encoding raised 82 false alarms (#88); and the
missing User-Agent above (#89).

To score one format:

```bash
python3 tools/render.py datasets/apache-shopfront/2026-10-06-medium   # in the dataset's checkout
R=datasets/apache-shopfront/2026-10-06-medium/rendered
(cd $R && sha256sum -c SHA256SUMS)
zodiarc-dev ingest $R/nginx-json.log --case ./case --no-crs
zodiarc-dev evaluate -c ./case -t $R/nginx-json.truth.jsonl -o every-record.json --no-crs
```

For the table, score again with a truth file that leaves out the line numbers listed under
`flagged` in `MANIFEST.json` (offset by the format's `line_no_offset`), and score the Apache
original with the same records left out. `haproxy` with its captures is
`--format haproxy-captures` on `haproxy.log`.

## The previous baseline — 2026-09-21

**Superseded on 2026-10-06 by the current baseline above.** Kept because the corpus defects found against it,
and what was done about them, are still the reasons the rules are shaped as they are. Everything
below *this* section was measured on builds whose bytes can no longer be obtained.

Measured on two builds taken at one commit with the working tree clean, from a dataset that had
just had a defect fixed in it — its forced-browsing attacker never signed in, so the application's
role check was never exercised and no log line it shipped had ever carried a 403. That matters
below.

| | `2026-09-20-medium` | `2026-09-20-small` |
|---|---|---|
| Role | **the headline** | fast check |
| Lines / clients | 237,278 / 2,785 | 64,738 / 920 |
| Scenario seed | 19 | 7 |
| Dataset commit | `e0bbd52` | `e0bbd52` |
| Tree clean when built | **yes** | **yes** |
| Quarantined on ingest | 0 | 0 |
| Truth lines unmatched | 0 | 0 |

`e0bbd52` is the tip of that repository's default branch, so the recipe in its README can be
followed. Both builds ship a `SHA256SUMS` and both were verified here before scoring — every file,
not only the two that matter:

```
# 2026-09-20-medium
f5748a414fc3b774321f8f0661ba3e173d69899bf9920b5b99862a90bb49a8e2  access.log
021f5441edb090c3d037f42faec9cc3fd962430b1fbb35705257b750defc09b5  truth.jsonl
87a1d094cbc317aaa0234ceff36519c26153c97f1009a958e3563eb243c2e119  MANIFEST.json

# 2026-09-20-small
ed59b172aba47f0bafc858b37d8963a2a3d69e5c040d8ce4a3d8edbe933a6504  access.log
44a6146010806dd28500da19394de24dca61b35afb470081d8127005ba830a1e  truth.jsonl
e7f1f8a0d336d3a0447be1f5532ddfe3575927368d347e341692014a0b145b01  MANIFEST.json
```

All four runs are the same ruleset, fingerprint `98c5169f90600aef`, recorded in each output.

| | medium native | medium + CRS | small native | small + CRS |
|---|---:|---:|---:|---:|
| Classification accuracy | **0.975** | 0.975 | **0.977** | 0.977 |
| Weighted F1 | 0.978 | 0.977 | 0.979 | 0.978 |
| Macro F1 | 0.742 | 0.701 | 0.740 | 0.717 |
| Attack-or-not precision | **1.000** | 0.994 | **1.000** | 0.993 |
| Attack-or-not recall | 0.993 | 0.993 | 0.981 | 0.982 |
| Caught / missed | 17,070 / 114 | 17,072 / 112 | 4,029 / 76 | 4,033 / 72 |
| **False alarms** | **1** | 96 | **1** | 29 |
| Boundary F1 | 0.847 | 0.835 | 0.841 | 0.830 |

Against the superseded medium — accuracy 0.968, macro F1 0.634, 21 false alarms native — every
column moved the right way.

**One false alarm in 237,278 requests is not a claim that the rules are nearly perfect.** It is one
axis. Macro F1 of 0.742 is the other, and it says what the per-category tables below say: several
categories are read as neighbouring ones, `enumeration` as `reconnaissance` thousands of times,
which costs nothing on the attack-or-not axis and a great deal on the classification one. A tool
that calls an attack an attack and then names it slightly wrong is a different failure from one that
misses it, and both numbers are printed so neither can hide the other.

### What one rule did to the false-alarm figure

The superseded corpus scored **167** false alarms native, and 166 of them came from a single rule —
`admin_area_redirect`, which claimed `access_control` on any redirect away from an admin path.

Those builds were the first to contain a legitimate administrator doing ordinary work. An
application that protects `/admin` with a login form answers an unauthenticated request with a 302
to that form, so the administrator's first request of every visit looked exactly like the probe the
rule was written for: 179 fires, 13 hostile, 166 not, precision 0.073.

The rule is now `authentication` at `info` severity, which is what the request is and what the
ground truth calls all 165 of the administrator's. **The 13 detections are genuinely lost** — none
was independently claimed by another hostile rule — and losing them is written down rather than
argued away, because at 13 against 166 it is a trade this project will take and say so.

### `access_control`, and why it needed the corpus fixed rather than the rule changed

When the rule above was recategorised, this document recorded that nothing detected `access_control`
at all, and gave the reason as real applications rarely answering with 401 or 403. **That
explanation was wrong.** `admin_area_probe` requires one of those and is correct; the corpus simply
never produced one on an admin path, because its forced-browsing attacker issued bare GETs and the
login check redirected it before the role check could run.

Fixed upstream on 2026-09-20, and the rule works on the first build that exercises it:

| `access_control`, medium | |
|---|---:|
| In the truth | 37 |
| Claimed by `admin_area_probe` | 6 |
| Correct | **6** |
| Precision / recall | **1.000** / 0.162 |

Perfect precision on a small denominator, and recall of 0.162 because the other 31 are the 302
bounces and the successful 200s, neither of which a single request distinguishes from an
administrator's. **Six for six is a count, not a rate** — it is reported that way because
`forced_browsing` runs once per campaign instance, so these do not scale with the log the way 404s
do, and a precision figure over six records would read far more solid than it is.

**The remaining gap is sharper than the one it replaced.** The corpus now contains 21 requests that
are a 200 on an admin path from an address also refused 403 there — forced browsing that *succeeded*
— and the truth calls all 21 hostile. Our rules flag 13 of them, mostly because the attacker was
also injecting something the payload packs reach. **Eight are read as ordinary browsing, six of them
the pure case: a client that simply walked in.** The separating signal is correlation rather than
shape — a legitimate administrator is never refused 403 on a sibling path — and `WindowRule` cannot
currently express it. Eight requests in 237,278 is a small number; that they are the requests where
an attacker *succeeded* is why it is written down.

---

## The builds

Two builds of the same project, both scored below. **Superseded by the section above**; the
analysis that follows is theirs and is kept for that reason.

| | `2026-09-07-medium` | `2026-08-23-small` |
|---|---|---|
| Role | **the headline** | fast check |
| Lines | 243,908 | 66,305 |
| Span | 7 days, 2026-03-09 to 03-16 | 1 day |
| Sessions | 7,822 | 2,368 |
| Scenario seed | 19 | 7 |
| Dataset commit | `0485a9a6` | `8217bce3` |
| Tree clean when built | **not recorded** | **not recorded** |

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

### The headline build's bytes are gone, and this document never recorded enough to rebuild them

**An earlier version of this section, published on 2026-09-18, said `0485a9a6` was "not a valid
object" in the dataset repository and that its history held nothing newer than 2026-08-17. Both
statements were false, and they are retracted here rather than quietly edited away.** They came
from a check run against a clone that had never fetched; the answer described that working copy
and was presented as describing the repository. It was not re-verified here before being published,
which it could have been in one call. A claim about a remote is not a claim a local `git cat-file`
can settle.

What is actually true, verified on 2026-09-18 against the GitHub API rather than any clone:

| | |
|---|---|
| `0485a9a6` | exists, dated 2026-08-24 — and is the **tip** of that repository's default branch |
| `8217bce3` | exists, dated 2026-08-20 |
| `datasets/apache-shopfront/` | holds `2026-08-17-{small,medium,large}` — neither build below |

So the generator state is obtainable: `git checkout 0485a9a6` gets the code that made
`2026-09-07-medium`. What is gone is the output. The build is not in this repository, not on the
machine that produced these figures, and not in the dataset repository, and no `MANIFEST.json` for
it survives anywhere, so the digests above cannot be checked against the manifests they came from.

**The defect that is genuinely ours is narrower, and it stands on its own.** The generator records a
`commit_is_clean` flag in every manifest. This document recorded the commit and never recorded that
flag, so whether the tree was modified when the build was made is unanswerable — and if it was, the
commit does not determine the output and the checkout above reproduces something else. A hash
printed beside a figure reads as a chain of custody; without the flag beside it, this one cannot
carry that. A provenance field earns its place only when something fails when it is wrong, and
nothing ever failed on these.

That the flag matters here is not hypothetical. All three builds that repository does publish —
`2026-08-17-{small,medium,large}` — record `commit_is_clean: false`, checked the same day. Whether
the two below did is exactly what was never written down.

A rebuild at `0485a9a6` with seed 19 is therefore worth attempting and is not a reproduction. The
dataset says outright that a seed reproduces its plan of requests and not its bytes, for the reasons
in the paragraph below. It would produce a *comparable* corpus whose lineage holds, not these bytes.

What remains true is narrow and worth stating plainly. The figures were measured on the bytes whose
digests are printed above, those digests still identify those bytes, and a recovered copy can still
be checked against them. What cannot be answered is which corpus the committed excerpt is an
excerpt *of*.

**One further defect, upstream, with an effect on these figures that is unmeasured.** On 2026-09-17
the dataset project found that its driver shared a single cookie jar across every simulated client,
so one visitor signing in authenticated the others. It is confined to `/account`: on the corpus
this build descends from, 103 of 401 responses there were reached by addresses that had not signed
in. The committed excerpt carries 16 such responses, 3 of them from one address with no sign-in
inside the window — but the window is 3,825 lines of 243,908, and a sign-in just outside it would
look identical, so **the excerpt can neither confirm nor rule it out.** Every rule here that keys
on a status code was checked, and none distinguishes an authenticated request from an
unauthenticated one, so the attack packs are not reading the artefact. The effect on activity
labelling has not been measured.

**The test suite is unaffected by all of this.** It scores a committed 3,825-line excerpt under
`tests/data/apache-shopfront/`, pinned by its own `SHA256SUMS` and enforced by
`tests/evaluation/test_fixture.py`. Every figure measured against those bytes is reproducible by
anyone who clones this repository.

The next baseline will be taken once, and will record the clean flag alongside the commit and the
digests. Two candidates exist and neither is ready yet: a rebuild at `0485a9a6` with seed 19, which
gets a comparable corpus with a lineage that holds but not these bytes, and the dataset project's
newer builds, which carry a full source state and an honest rebuild recipe but were made on a branch
that is not yet reachable from its default branch. Taking a baseline against either one today would
mean pinning a headline figure to something still in motion.

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

**The current baseline can be rerun:** its builds are published, and the commands that scored
them, starting from the download, are under
[the current baseline](#the-current-baseline--2026-10-06).

**The commands below cannot be run today.** They are the commands that produced the figures, kept so
that the method is on the record, but the build they name cannot be obtained — see
[the note above](#the-headline-builds-bytes-are-gone-and-this-document-never-recorded-enough-to-rebuild-them).
Point them at any build you do have and expect different numbers.

```bash
B=samples/apache-shopfront/2026-09-07-medium
zodiarc-dev ingest $B/access.log --case ./case-medium
zodiarc-dev enrich --case ./case-medium
zodiarc-dev evaluate --case ./case-medium --truth $B/truth.jsonl --out medium.json
zodiarc-dev evaluate --case ./case-medium --truth $B/truth.jsonl --no-absorb --out medium-noabsorb.json
```

The `enrich` step is part of the measurement, not an extra: every headline figure is of the
complete tool, with OWASP CRS applied at the project's default paranoia level 2. Native-only runs
are reported beside them as labelled comparisons, and on this corpus, unlike on the generated
one, the two differ.

## Classification

**One corpus here can be re-derived from a fresh clone**, and is checked on every
CI run. `tests/data/apache-shopfront/excerpt.scores.json` holds the complete
evaluation output for the committed 3,825-line excerpt, beside the log and the
truth it was scored against:

```bash
zodiarc-dev ingest tests/data/apache-shopfront/excerpt.log --case /tmp/c --no-crs
zodiarc-dev evaluate -c /tmp/c -t tests/data/apache-shopfront/excerpt.truth.jsonl
```

`tests/evaluation/test_published_scores.py` re-runs exactly that and compares
the whole file, so a rule change that moves a number fails the build instead of
leaving the prose here quietly wrong. That is the gate that was missing when the
episode builder changed on 25 August and a boundary recall of 0.98 stayed
published for weeks against a tool scoring 0.27.

### The same excerpt, scored with CRS on

**Added 2026-09-22, and it closes a gap this document had been carrying.** Every
committed figure in this project was the native rules alone. CRS appeared only
in prose — the tables further down — which nothing re-ran, so a CRS version
bump, a mapping change, or a CRS rule that started firing on ordinary traffic
could move what a reader sees and fail no build.

`excerpt.scores.crs.json` now sits beside the native fixture and is checked the
same way, with the enrichment actually run:

```bash
zodiarc-dev ingest tests/data/apache-shopfront/excerpt.log --case /tmp/c
zodiarc-dev enrich --case /tmp/c
zodiarc-dev evaluate -c /tmp/c -t tests/data/apache-shopfront/excerpt.truth.jsonl
```

| committed excerpt, 3,825 requests | native | with CRS |
|---|---:|---:|
| Caught | 1,186 | **1,188** |
| **False alarms** | **0** | **0** |
| Classification accuracy | 0.9746 | 0.9749 |
| Macro F1 | 0.9508 | **0.9592** |

Figures as of 2026-10-14, after the sequence rule that names forced browsing
nothing refused — `access_control` from 0 of 24 to 15 of 24, every one of them
right, and 15 more attacks caught with no false alarm added — the rule that
names an injection reading secrets, `exploitation` from 4 of 8 to 6 of 8, and
the naming pass after it: injection tools named by their User-Agent
(`injection` 51 → 56 of 57), a `file://` fetch named SSRF (`ssrf` 3 → 4 of 5
natively, 4 → 5 with CRS) and verb tampering (`access_control` 15 → 19 of 24,
4 more attacks caught, no false alarm added), the credential guess that worked
(`credential_attack` 38 → 39 of 39, 1 more caught), and the hand-built probe for
known software answered 400 (`reconnaissance` 578 → 621 of 642, 43 more caught,
no false alarm added). The sweeps naming their own probes broke even here, 17
right for 17 wrong, with accuracy unchanged and boundary F1 0.646 → 0.666. On
2026-10-05 they were 1,123 and 1,125 caught, accuracy 0.9561 and 0.9563, macro
F1 0.8004 and 0.8107; on 2026-09-30, when the commerce action pack was removed,
accuracy 0.9339 and 0.9341. The [rule-pack ledger](rule-pack-ledger.md) has
each step and how to reproduce it.

Both fixtures now carry a `crs_fingerprint`: the CRS one names the ruleset that
produced its detections, and the native one records `null`, which is a claim
rather than an omission. A reader comparing two reports has to be able to see
which of them had a second ruleset behind it.

**The excerpt has too little ordinary traffic to show what CRS costs**, and
until 2026-09-22 that was the end of the story — the larger build measured
**1 false alarm native against 96 with CRS on**. A corpus that cannot see a cost
cannot be used to argue the cost is not there, which is the same lesson the
`admin_area_redirect` pass wrote down from the other direction.

### What the 96 turned out to be

Classified 2026-09-22 against `2026-09-20-medium`, 237,278 requests. Three CRS
rules accounted for 95 of the 96, and the ninety-sixth is native and
pre-existing. **Two of the three were withheld and one was not, and the one that
was not is the more useful story.**

| rule | CRS calls it | named a real attack | accused ordinary traffic | verdict |
|---|---|---:|---:|---|
| 931130 | RFI: Off-Domain Reference/Link | 1 | 73 | withheld until the site is named |
| 931100 | RFI: URL Parameter using IP Address | 1 | 73 | **restored** |
| 932236 | RCE: Unix Command Injection | 0 | 22 | withheld |

The first two fire on the same requests, which is why silencing one alone
changed nothing — 931130 simply took over, and a second measurement was needed
to see it. **Measure the whole set before withholding anything.**

#### The 73 were a defect in the corpus, not a mistake by the rules

All 73 are one line, repeated:

```
GET /admin/import-image?url=http://203.0.113.2/assets/img/logo.png
```

It reads as a shop's administrator importing the shop's own logo, and the truth
labels it benign. But the dataset's benign admin step named its own web
container by a *bridge IP*, while every Referer on the same line calls that
server `shop.test`. That step exists to be the harmless counterpart of the
attackers' metadata-hunting version of the same endpoint, and **a literal IP in
the parameter is the one feature separating those two cases** — so the harmless
example was carrying the hostile marker. Found and fixed upstream at `20a4564`;
the parameter now holds `http://shop.test/assets/img/logo.png`.

That changes the verdict on 931100 and not on 931130:

- **931100 is restored.** Set the 73 aside and it scores 1 for 1 on the same
  corpus, and on the committed excerpt it is strictly better — 1,125 caught
  against 1,124, zero false alarms either way. After a rebuild it cannot fire on
  that request at all, because there is no IP in the parameter any more.
- **931130 stays withheld until the site is named**, for a reason the fix does
  not touch. It compares a URL's host against the request's own `Host`
  header, which Apache does not log — so the sidecar sent `localhost`, and
  every URL, `shop.test` included, read as off-domain. It was an unconfigured
  rule rather than a wrong one, and `site_hosts` is the answer it was missing;
  the next section is what happened when it got it.

  *An earlier version of this paragraph said 931130 compares against
  `TX:ALLOWED_HOSTS`, a list an operator configures. That was written without
  reading the rule and was wrong; the rule is
  `!@endsWith .%{request_headers.host}`.*

**A measurement is evidence about the corpus as much as about the tool.** "This
rule has terrible precision" and "this corpus has a mislabelled request" produce
the same table, and what separated them here was reading the 73 and finding they
were one line.

#### 931130, told the site's name

**Added 2026-09-23.** `zodiarc-dev enrich` now sends CRS the case's own domain as the
Host header, and 931130's verdicts count only when that one domain covers every
domain the reader named. CRS compares by suffix, so `shop.test` covers
`www.shop.test`; a site that also answers to an unrelated domain keeps the rule
withheld, because a Host header holds one name and links to the second domain
would be reported as attacks. Checked against the sidecar directly: told
`shop.test`, the rule is quiet on `shop.test` and `cdn.shop.test` and fires on
`evil.test` and `shop.test.evil.test`.

On the 237,278-request build, named and unnamed:

| | native, unnamed | native, `shop.test` | CRS, unnamed | CRS, `shop.test` |
|---|---:|---:|---:|---:|
| Caught | 17,069 | 17,070 | 17,071 | 17,071 |
| False alarms | **1** | 74 | 74 | 74 |

**Naming the site adds nothing on this build, and that is the honest result.**
931130 fired on 78 requests and was trusted on all 78, and named none of them:
the native rules had already named every one, and CRS only speaks where they
said "ordinary". The 73 false alarms the native rules gain are the same bridge-IP
line described above — `rfi_offsite_url` reads `203.0.113.2` as somewhere other
than `shop.test`, correctly, on a request the corpus mislabels. After the
upstream rebuild that line names `shop.test` and should go quiet under both.

#### The 22 are the product catalogue

```
/search?q=pipe cutter        `pipe` is a shell command
/search?q=wall plugs         `wall` writes to every logged-in user
/api/autocomplete?q=pipe
```

**A plumbing shop cannot search for a pipe cutter.** This one is the rule's
problem in any real deployment, and the corpus is doing its job by exposing it.
Third time this project has met the same error: `attack/windows.yaml` exists
because `find x for y` and `time warner` are ordinary English, and
`http_library_user_agent` was it again in another field. A bare command name is
vocabulary, not intent.

#### Where that leaves CRS

| 237,278 real requests | native | CRS before | CRS after |
|---|---:|---:|---:|
| Caught | 17,069 | 17,071 | **17,071** |
| False alarms | **1** | 96 | 74 |
| — of which the corpus defect above | — | 73 | 73 |
| **Comparable false alarms** | **1** | 23 | **1** |

The 74 is reported rather than quietly netted off, because it is what the tool
scores against the corpus as it stands today and a rebuild has not happened yet.
The comparable row is the one that answers "is CRS worth turning on", and on it
**CRS costs nothing in precision and finds two attacks the native rules do not.**

On the committed excerpt, which has no such defect, the improvement needs no
footnote: 1,125 caught against 1,123, zero false alarms either way, macro F1
0.7860 to 0.7961.

The one misjudgement CRS does make here is worth reading, because it is the
shape of the disagreement rather than a bug in either tool:

```
GET /contact 200    Referer: http://shop.test/search?q="><img src=x onerror=alert(1)>
```

Three CRS XSS rules fire. They are right that an XSS payload is in the request.
The truth calls this `browsing` and is also right: the payload is in the
*Referer*, so this is somebody who followed a poisoned link, not somebody who
wrote one. **CRS judges the payload; Zodiarc judges the actor.** A firewall
should block that request. A tool reconstructing what an address did should say
it browsed to `/contact` and arrived from a poisoned search link.

The tables below are the two pinned dataset builds, which are **not** committed
(22 MB and 80 MB) and whose bytes can no longer be obtained, so they are recorded
measurements rather than figures a reader can rerun.


Measured 2026-09-08, ruleset `e81ace93…` (33 rules), CRS `d694d465` at paranoia level 2,
configuration `f357d142fbcc4441`. Every line of both builds was scored; none went missing.

> **These tables predate eight rule changes and have not been re-run.** On
> 2026-09-14 the pack gained `admin_area_redirect`, `webshell_double_extension`,
> `known_software_probe` and `sqli_column_count`; `sqli_tautology` was broadened
> and `sqli_time_based` gained `randomblob`; `credential_attack` dropped its window
> floor from ten requests to five; `template_injection` grew past the arithmetic
> probe; `admin_area_probe` stopped matching 404; and the classifier stopped calling
> an unreadable request a page view.
> Every one of those moves a figure below.
>
> They were measured on the committed excerpt, 3,825 requests, where the numbers
> went:
>
> | | Before | After |
> |---|---:|---:|
> | Accuracy | 0.900 | **0.931** |
> | Macro F1 | 0.794 | **0.840** |
> | Weighted F1 | 0.907 | **0.934** |
> | Attack-or-not recall | 0.852 | **0.928** |
> | Attacks missed | 179 | **87** |
> | False alarms | 0.765% | 0.765% |
> | `enumeration` recall | 0.629 | **0.843** |
> | `injection` recall | 0.684 | **0.877** |
> | `credential_attack` recall | 0.667 | **0.974** |
> | `browsing` precision | 0.394 | **0.535** |
> | `access_control` precision | 0.146 | **1.000** |
> | `exploitation` recall | 0.000 | **0.500** |
> | **Boundary F1** | **0.642** | **0.620** |
>
> Precision did not pay for any of it: `injection`, `access_control`,
> `exploitation`, `credential_attack` and `authentication` all sit at 1.000,
> `enumeration` rose 0.975 to 0.981, and false alarms are unchanged to three
> decimal places.
>
> The last row is the one cost and it is not an error: labelling 92 more requests
> as hostile cuts more episodes, 567 to 592 against 297 in the truth. Boundary
> recall held at 0.996 throughout — nothing went missing, the cuts are finer than
> the truth's.
>
> The excerpt is 3,825 requests and these tables are 243,908, so all of that is
> an indication of direction and nothing more. The medium build's `enumeration`
> recall is 0.542, lower than the excerpt's 0.629 starting point, so the gain
> there may differ in size.
>
> **Re-run them on the pinned builds before quoting them again.** This document
> has been wrong in exactly this way once already: figures went stale across a
> behaviour change, nobody re-measured, and a boundary recall of 0.98 was
> published for weeks while the tool scored 0.27. The note is here so the same
> gap cannot open quietly a second time.

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
  known artefacts. It is the largest single source of classification error here.

  This document used to call it "a rule question". **Measured on 2026-09-14, it is partly not
  one**, and the part that is not has a floor. The truth labels a request by *which campaign sent
  it*, not by what the request is, and the campaigns' path sets overlap. On the committed excerpt,
  **70 of 444 distinct `(path, status)` pairs carry more than one truth category, covering 1,355
  of 3,615 scored requests — 37.5%**:

  | Request | Truth says | Sent by |
  |---|---|---|
  | `GET /backup.zip` → 404 | `enumeration` ×31 | two clients forging a browser User-Agent |
  | | `reconnaissance` ×11 | one client sending no User-Agent |
  | `GET /admin.php` → 404 | `enumeration` ×30 | three clients with a User-Agent |
  | | `reconnaissance` ×15 | the same no-User-Agent client |
  | `GET /` → 200 | `crawling` ×70, `browsing` ×20, `reconnaissance` ×17 | 42 clients between them |

  The request lines are identical. What separates them is the client, so **no rule reading only
  the request line can be right on both sides** — which is a property of real traffic, not a defect
  in the truth: the same request does mean different things depending on who sends it.

  That is a ceiling on signature rules, not on the tool. Most of this is already resolved by the
  features that *are* observable: `crawling` scores precision 1.000 because the User-Agent settles
  it, and `known_software_probe` reads `/wp-admin/` at 404 as enumeration only when a User-Agent
  is present, which is what keeps the 49 requests from the no-User-Agent client where they belong.

  **What is left is deliberately not chased.** Closing the residual 67 would mean making
  `backup_file_probe` and `config_file_exposure` yield to enumeration whenever a User-Agent is
  present. That is this dataset's convention for telling its two campaigns apart, not a fact about
  security — a scanner forging a User-Agent and asking for `/backup.zip` is doing what one without
  a User-Agent is doing. Writing it into a rule would buy a figure by encoding the answer sheet.

  **2026-10-05: on `2026-09-20-medium` most of it was a different thing, and is fixed.** 4,610 of
  that build's 5,325 were one client, `gobuster/3.5`, named reconnaissance by `scanner_user_agent`
  over the enumeration label its sweep had also earned. That was the rule contradicting the
  boundary above, not the corpus's convention — gobuster exists to sweep a wordlist — so the
  content-discovery tools moved to their own rule, `content_discovery_user_agent`. On the same
  bytes the confusion falls to 715, almost all the file-probe campaign described here, and
  accuracy rises from 0.9751 to 0.9945 with detection unchanged. `docs/rule-pack-ledger.md` has
  the measurement.
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

The command was removed in `2868e78` and a *differently pointed* one of the same
name returned on 2026-09-15 — see ADR-0008's amendment. Reproducing the figures
below means restoring the original, which scored a fixed corpus revision:

```bash
git revert 2868e78
git clone https://github.com/coreruleset/coreruleset vendor/coreruleset
git -C vendor/coreruleset checkout d694d465951ee06347214f1291ae096e40700001
zodiarc-dev score-crs --corpus vendor/coreruleset --out crs.json
```

The corpus revision matters: both the denominator and the rate drift as CRS gains cases, so a
figure quoted without it is not re-derivable.

### The result

Ruleset `9edf8587…` (33 rules) against coreruleset `d694d465951e`, 200 case files.

**This is history, not the ruleset shipping today.** It was true when written and
is kept because the analysis under *Reading it* is what motivated ADR-0008 — but
the rules have since changed substantially and the figures below are stale. The
tree now holds 107 rules across twelve attack packs and one action pack; family
933 alone went from 0.012 to 0.68 on 2026-09-15.

For current figures run `zodiarc-dev score-crs`, which reports both directions —
what was caught, and what fired on traffic CRS certifies as harmless. The
second column did not exist when this table was made.

An earlier version of this passage argued the old figure still described the
shipping ruleset because only *window* rules had moved since. That reasoning was
sound and is no longer true: the signature rules are where nearly all of the
change has been.

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

`zodiarc-dev benchmark`, Windows 11, Python 3.12, one machine, on the medium build's real log. Each
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

**Measured 2026-08-09**, a month before the figures above it, on the same
interpreter. It is kept rather than re-run because it measures the store
directly, in rows pushed into it, and nothing about that path has changed since.
Rows, not log lines: a line becomes one row, but the two are counted at different
ends of the pipeline and the numbers should not be read as throughput. That
difference, and the date, are what separate this table from the one above — not
the interpreter, which is 3.12 for both.

| Rows | Peak during ingest | Peak after finalize | Finalize |
|---:|---:|---:|---:|
| 500,000 | 297 MB | 596 MB | 2.4 s |
| 2,000,000 | 296 MB | 1,062 MB | 8.3 s |
| 8,000,000 | 296 MB | 1,186 MB | 28.4 s |
| 12,000,000 | 296 MB | 1,189 MB | 40.2 s |

Ingest is flat at ~296 MB by construction. `finalize` converges on the configured 1 GB engine
ceiling: eight million rows to twelve moved it by 3 MB, where four million used to fail outright.

One thing this table cannot show, because each row is a fresh process: **the path cache is
module-level and outlives the case that filled it.** `canonical_path` memoises 8,192 entries, and
the cap is on entries rather than bytes, so its size follows how long the paths are. Measured with
`tracemalloc` on 2026-09-14:

| | Entries | Held |
|---|---:|---:|
| The committed 3,825-line excerpt | 372 | 0.05 MB |
| 8,192 distinct paths at Apache's 8 KB request-line limit | 8,192 | 132 MB |

Real traffic is the first row and not close to the second — median path 11 bytes, 90% of lookups
hitting the cache, which is what it is there for. The second row needs a log whose paths are all
distinct and all maximal. It is recorded because it is bounded but not released: nothing calls
`cache_clear`, so a second case opened in the same window inherits whatever the first one left.
Accepted at that size rather than fixed.

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

#### The 100,000 target is retired

Decided 2026-09-14, and recorded here because the measurement is here.

The number is not being met and is not going to be, but that is the smaller half of the reason.
The larger half is that **it was never a target** — it names a rate without naming the hardware
that should reach it, so it cannot be passed or failed, only cited.

It is also in the wrong unit. This document has already caught lines per second moving for a
reason that has nothing to do with the parser: a real combined line averages 225 bytes against
the generator's 208, 8% longer, so the same work spreads over fewer lines and the rate drops
while megabytes per second does not. A goal that moves when the log's lines get longer is
measuring the corpus.

And the one remaining route to it is closed by decision rather than by effort. Parallel ingest
shipped and reached 69,655 lines/s, 2.55× sequential and close to what four physical cores have
to give. Taking the marshalling out bought another 14%. What is left is the regex, the timestamp
and the object construction, none of them dominant, which is the profile of code with no large
win remaining in it. The next real gain needs a parser that is not CPython, and ADR-0009 declined
to write one.

**What is kept instead**, both already measured above:

- **Throughput is reported, with its hardware and in both units** — 28,532 lines/s and 6.1 MB/s
  sequential, 69,655 lines/s with eight workers, on four physical cores. A figure to compare
  against the next measurement, not a bar to clear.
- **Reconstruction cost per request stays flat as the corpus grows** — 214.5 µs against 209.3 µs
  over a 2.4× corpus. *This* is the claim with a pass and a fail in it, because it is the one the
  architecture makes: analysis is O(k) in one client's requests, not O(n) in the corpus. If it
  ever starts climbing with corpus size, the two-pass design has stopped working and the number
  says so.

The gap is worth keeping in proportion. Ingest at 3.5× the hoped-for cost means a week of this
server's traffic — 243,908 lines — takes 8.5 seconds instead of 2.4, once, and never again for
that case. Reconstruction going non-linear would cost the reader the tool.

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

End to end, `zodiarc-dev benchmark -n 1000000`, both runs on this machine minutes apart:

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

**One application.** Every build here is the same PHP shop, driven by the same roster of
personas and tools. Nothing here separates what is true of this tool from what is true of that
shop. A second project in the dataset is what would answer it.

**A rebuild is not byte-identical.** The figures belong to the checksummed files in the table
above. The dataset reproduces its plan of requests from a seed but not its output, because the
attack campaigns react to a live application. Expect the last decimal to move.

**Timestamps are modelled.** Arrival times were rewritten onto diurnal and weekly curves; only
the ordering within a session is as captured. The threshold sweeps are the part of this document
most exposed to that, and the episode-gap table should be read as establishing that the parameter
behaves sensibly rather than as choosing a value for a real deployment.

**The smallest categories decide the macro average.** On the headline build `ssrf` names 4 of 5
and `exploitation` 6 of 8, and they count as much as `static_asset` at 162,801.
`unknown`, which no rule could assign until 2026-10-05, now names 124 of 201. Any per-class figure
below about fifty requests of support should be read as an indication, not a measurement; five
categories are below it on the headline build.

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
shape: 218,583 of the headline build's 235,732 requests are labelled harmless. That is a change from
the generated corpus, where a third of traffic was an attack and the rate was measured on less
benign traffic than a deployment would present.

**The CRS corpus figure has a ceiling.** 2,650 of its cases carry their payload in a body or a
header no access log writes, and no tool reading a log can reach them; `zodiarc-dev score-crs` leaves
them out rather than counting them as misses. Of the 1,099 that remain the native rules catch 960
(87.4%), and they fire on none of the 134 the corpus certifies as harmless. Status is synthesised
as 200 for every case, so a rule that needs a 4xx cannot fire there at all.

**Recall on CSIC 2010 has a ceiling below 100%.** A substantial share of its attacks carry their
payload in a POST body, and a web server access log records the request line and nothing after it.
`zodiarc-dev convert-csic` counts them in the corpus it is given and prints the resulting ceiling, so
the figure quoted alongside a CSIC result is measured on that copy of the dataset rather than
repeated from elsewhere.

**Throughput is a single-machine figure**, reported to show that cost per line does not grow with
the corpus rather than to compete on absolute speed.
