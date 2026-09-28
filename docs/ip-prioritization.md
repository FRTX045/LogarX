# Where to start

Opening a case starts a background scan of every IP in the selected time range.
The **Where to start** tab offers three views:

| View | What determines its order |
| --- | --- |
| Suspicious activity | Supporting requests weighted by bounded severity and supporting-request share; category breadth and hostile paths break score ties |
| Unusual activity | Strongest upper-tail statistical deviations from comparable clients in this case |
| All clients | Request count, including clients outside the original busiest-500 sidebar |

The queues order the entire eligible population before showing pages of 100.
Address search covers that population. The queue and the details below it share
a divider the reader can drag; the details start with half the space. Select a
row and choose **Inspect supporting requests** to reconstruct the client and
select an activity containing its supporting source lines, or click an example
request in the details to open reconstruction on that request. Requested source
lines appear before the ordinary activity sample, within the same display limit.
Counts describe all supporting requests; examples and references are a bounded
sample.

The scan can be cancelled while ordinary reconstruction remains available.
Suspicious findings shown during scanning are provisional and state how many
IPs were examined. **All clients** searches the complete stored population while
scanning, after cancellation or failure, and after completion. It uses paginated
summary queries independent of detection, with 150 ms input debounce. A summary
does not assert that there are no hostile detections: opening it performs ordinary
reconstruction. Only unusualness comparisons need the completed scan.
A changed time range starts a corresponding scan;
results from previous requests cannot replace the current queue.

## Reading the recommendations

Each Suspicious activity recommendation answers three questions, one block per
reason: what was observed, why that deserves attention for this client, and which
requests to inspect. The table's **Key observation** column shows the first
block's observation, for example "40 of 50 requests flagged; strongest high".

1. **Flagged requests** comes first, because it is what the order rests on: how
   many requests carry a hostile detection, their share, and the strongest
   severity. Its why says what kind of flagged request dominates and whether it
   is most (half or more), a substantial part, or a small part (under a tenth) of
   the client's activity. When one rule matches every flagged request, it names
   that rule, because one noisy rule can explain a large count.
2. **Distinct rule matches** counts bundled rules rated at confidence 0.85 or
   above that matched different requests, each rule and each request counted
   once. The rating is the rule author's and describes the rule, not the
   request: a scanner's user-agent string qualifies as readily as an exploit
   pattern.
3. **Probe, then an attack pattern** appears when, within one session, a
   reconnaissance or enumeration request is followed at a strictly later time by
   an injection, traversal, access-control, credential, SSRF or exploitation
   match. Requests logged at the same time are never paired, so with
   second-resolution logs a probe and an attack in the same second do not count. It says nothing
   about whether the probe led to the attempt; a shared IP or a scanner can
   produce the same ordering.
4. **Recurrence across sessions** appears when detections fall in two or more
   sessions. Sessions under an hour apart may be one burst split by a session
   boundary, and the block says so. Session splits and shared IPs do not
   establish one actor.

Examples show the request, its time in UTC and its source reference. A long path
is cut to two lines with **Show full request**. A reference whose source cannot
be read stays visible with the reason and cannot be opened; one read from a
source changed since ingest opens and shows its warning. These reasons are
written when a page is read, so rewording them does not require a rescan.

Blocks 2 to 4 are context for reading a client. They do not affect its rank.

Suspicious activity uses the existing engine's native and CRS label precedence.
Several rule matches on one request still count as one supporting request.
Policy 3 uses
`log2(1 + h) * (1 + s/4) * (0.5 + 0.5*h/n)`, where `h` is deduplicated hostile
requests, `s` is existing severity and `n` is all requests. Ties use category
breadth, distinct hostile paths, hostile requests and IP. The score determines
investigation order, not attack probability. It passed the predeclared held-out
promotion gate in the [validation report](evaluations/ip-prioritization-validation.md).
Category labels are
observations and hypotheses to investigate; response codes and response sizes
do not establish compromise. An IP can represent multiple users or systems.

Unusual activity compares clients within the current case and selected range.
The comparison population is not assumed to be benign or to contain one kind
of application. Mixed workloads therefore need interpretation by the reader.
It measures request count, peak requests in a half-open 60-second window,
distinct-path share, concentration at the most-requested path, 4xx and 5xx
shares, recorded response bytes, and mean recorded response size.

Initial policy defaults require at least 20 requests per client and 30 eligible
clients. Each feature additionally requires enough observed fields: an absent
status or size is not a zero. Only values above the population's median are
offered as deviations. Ties receive the same percentile, and identical clients
do not become unusual simply because a ranking needs a first row. Percentiles
are relative positions, not probabilities that traffic is malicious. A short
client remains eligible for suspicious-activity recommendations.

An empty queue means there are no eligible findings under the current policy.
Missing CRS is stated explicitly; enrichment that ran and found no detections
is distinguished from enrichment that never ran.

## Storage and execution

`logarc.triage` has no Qt dependency. Profiling shares session boundaries and
request labels with reconstruction, without constructing every client's graphs.
A grouped store iterator reads clients chronologically in partition order. A
spawned process owns the scan; the GUI thread handles neither detection nor
database paging.

CRS records use a temporary disk index. DuckDB spill files and incomplete
outputs live under a parent-owned worker directory, so cancellation can stop
an unresponsive worker without touching another reader's scratch files.
Cleanup requires the supervising parent to remain alive and filesystem removal
to succeed. Abrupt termination of that parent, or of a direct evaluation scan,
can leave temporary files. Completed indexes are published separately.
Memory includes the largest client's analysis and compact profiles for all
clients. It is not constant with the number of clients.

Completed SQLite indexes live under the case's `triage/` directory. Their keys
include source records and hashes, native rules, CRS content and configuration,
the exact time range, session settings, and the versioned feature/ranking policy.
Publishing is atomic. Failed or cancelled scans do not replace completed
indexes. Existing cases do not require re-ingestion, and source logs remain
unchanged.

## Optional model experiment

The `evaluation` dependency extra adds scikit-learn for the evaluation harness.
The desktop application uses deterministic statistics and does not import the
model. No new CLI command or public model control is added.

`logarc.evaluation.triage.isolation_order` compares Isolation Forest against
the statistical queue using clients with at least 20 requests and a population
of at least 100. It excludes IP identities, detection labels, and ground truth.
It records feature order, median imputation, missingness indicators, logarithmic
count transforms, library version, seed and model settings. Raw scores order
unusualness; they do not estimate attack probability.

`compare_rankings` evaluates request-count, 4xx-share, suspicious, statistical,
and optional model orderings against explicit per-client judgments at budgets
of 10, 25, 50, 100 and 250, plus full-ranking recall. It reports both operational
populations and a matched cohort with 20 requests and 20 observed statuses;
statistical comparisons and models are refitted in that cohort. Returned counts,
exclusions, recall ceilings, quiet-attack recall and yield per available slot
prevent short queues or eligibility differences from hiding missed clients.
Security and unusualness judgments are separate. Unjudged
clients are rejected rather than silently treated as benign. Recall is
unavailable when there are no positive judgments, and precision is unavailable
when no clients were returned.

The controlled fixture in `tests/evaluation/triage_scenario.py` defines three
legitimate but unusual clients independently of attack labels: a concentrated
burst, large responses, and repeated missing pages. This is a verification
fixture, not evidence of accuracy on real investigations.

## Graded validation (2026-09-24)

The [graded validation](evaluations/suspicious-recommendations-validation.md)
grades clients from truth alone (targeted attack, probe only, benign) and tested
two frozen challengers that add capped bonuses for distinct rule matches, a
probe-then-attack session and recurrence. The chosen challenger, C2, passed the
frozen held-out gate and was not adopted: its gain at the head was one targeted
client in one build, the credential attacker in these builds fell in every
held-out build, its bonuses reached scanners as readily as targeted clients, and
the low-support attackers it was meant to help are not detected at all. Policy 3
remains the ordering; that is a decision about these tradeoffs, not a finding
that policy 3 orders the queue well.

## Current validation (2026-09-21)

The [validation report](evaluations/ip-prioritization-validation.md) covers the
medium corpus, eight small sweep seeds, all-benign broken links and five broader
controlled unusualness workloads, all with CRS at paranoia level 2. Development
and held-out selection, per-case regressions, population exclusions, vector ties
and five model seeds are recorded explicitly.

The promoted suspicious ordering improved mean held-out top-ten yield from
62.5% to 100%, with no mean loss at budgets 25 or 50 or in quiet-attack recall.
All three candidates tied at 100% yield at budgets 10, 25 and 50 in development
and held-out cases. Share was selected only by development quiet recall at 50,
with a 0.453 percentage-point mean advantage over support. The gate establishes
improvement over the baseline, with limited evidence for choosing among candidates.
One held-out case lost two quiet attackers at budget 50; the report preserves
that regression. Broken-links traffic produced no suspicious recommendations.
The statistical unusualness default stays unchanged, and representative
unusualness accuracy remains unvalidated.

## Earlier evaluation (2026-09-20, policy 2)

The numbers below are historical measurements of the severity-first policy.
They used the earlier population accounting; use the current validation above
for exclusions and matched comparisons. In particular, only 57 of the 399
attack-associated clients meet the 20-request threshold, so model eligibility
caps operational attack recall at 14.29% on this case.

The existing Apache shopfront medium corpus contains 243,908 requests, 2,760 IPs,
2,060 statistically eligible clients and 399 clients with at least one hostile
ground-truth request. The source SHA-256 is
`a61205732cfcb9ce0369e95326c7daef3be60156b9be2553fcdf07e200e96e8e`.
CRS enrichment used paranoia level 2, revision
`d694d465951ee06347214f1291ae096e40700001`, configuration fingerprint
`f357d142fbcc4441`. These are complete-product measurements on this corpus,
not a claim of accuracy on arbitrary server logs.

Each cell below is precision / recall, expressed as percentages. Security
judgments are positive when any request from that IP is hostile in the truth
file. Shared IPs are consequently positive even when most traffic is legitimate.

| Ordering | First 10 | First 25 | First 50 |
| --- | ---: | ---: | ---: |
| Request count | 20 / 0.50 | 8 / 0.50 | 10 / 1.25 |
| 4xx share | 100 / 2.51 | 100 / 6.27 | 100 / 12.53 |
| Suspicious activity | 50 / 1.25 | 60 / 3.76 | 80 / 10.03 |
| Statistical unusualness | 40 / 1.00 | 24 / 1.50 | 16 / 2.01 |
| Isolation Forest | 100 / 2.51 | 80 / 5.01 | 76 / 9.52 |

Suspicious activity improves over request count here but underperforms 4xx-share
sorting at all three budgets. The model outperforms the suspicious queue at 10
and 25, but underperforms it at 50. Statistical unusualness has a different
purpose and performs poorly against attack truth. These results do not justify
replacing the GUI default or describing the model as an attack detector.

A cold policy-v2 scan took 102.39 seconds; reopening its completed index took
0.118 seconds. Scan-process peak working set was 308,412,416 bytes (294.1 MiB),
measured before loading truth or fitting the model. This is a single Windows run,
with 16,860 requests in the largest client, not a latency guarantee or a
constant-memory claim.

A separate native Windows GUI event-loop measurement scanned all 2,760 enriched
clients in 115.32 seconds while the repository tests were also running. Across
5,764 observations, a 20 ms timer had a 31.57 ms 95th-percentile gap and 44.87 ms
maximum gap. The hidden prioritization panel stayed responsive to timer events;
this does not measure end-to-end interaction or rendering latency on every screen.

The independently defined unusualness fixture contains 2,700 legitimate
requests from 123 IPs, including three deliberately unusual clients. It also
used CRS paranoia level 2 at the revision above, with configuration fingerprint
`d1c9e04591ad1e66`. Its source SHA-256 is
`60b5558260d2a0ea50ad92f78acdc0247a06e1e03938a6ef806b63e7156c94b4`.

| Ordering | First 10 | First 25 | First 50 |
| --- | ---: | ---: | ---: |
| Request count | 0 / 0 | 0 / 0 | 0 / 0 |
| 4xx share | 10 / 33.33 | 4 / 33.33 | 6 / 100 |
| Statistical unusualness | 30 / 100 | 12 / 100 | 6 / 100 |
| Isolation Forest | 30 / 100 | 12 / 100 | 6 / 100 |

The suspicious queue returned no clients in this legitimate-traffic fixture;
precision is undefined and unusualness recall is zero. Security recall is
undefined because it contains no attacks. The larger corpus has no independent
unusualness judgments, so none were inferred from its attack labels.

Both model runs used scikit-learn 1.9.1, 200 trees, seed 42, contamination `auto`,
one job and maximum samples of 256 (123 for the smaller fixture). Model metadata,
including ordered features and imputation values, is recorded with the raw
results in [the evaluation record](evaluations/ip-prioritization.json).
