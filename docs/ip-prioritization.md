# Triage

Opening a case starts a background scan of every client in the selected time
range. The **Triage** tab offers two queues; hover either tab for what puts a
client on it:

| View | What determines its order |
| --- | --- |
| Suspicious | Clients with exploit evidence first, then all others; within each group, supporting requests weighted by bounded severity and supporting-request share, with category breadth and hostile paths breaking score ties |
| Unusual | Strongest upper-tail statistical deviations from comparable clients in this case |

Finding any one client, busy or quiet, is the client list's job. It shows the
case 500 clients at a time by request count, busiest first, with **Previous**
and **Next** when there is more than one page. Its filter narrows the page at
once and, when the page is not the whole case, then searches every client in
the case and shows up to 500 matches, paged the same way. A complete address
matches only itself. The caption says which slice is on screen, when a page is
sorted by something other than request count, and when the client being read is
not among the rows shown.

The queues order the entire eligible population before showing pages of 100.
Address search covers that population. The queue and the details below it share
a divider the reader can drag; the details start with half the space. Select a
row and press **Open client**, or double-click it, to open the client in
**Activity** with an activity containing its supporting source lines selected.
**Open supporting requests**, under each reason in the details, does the same
for that reason, and an example request in the details opens on that request.
For a client in the first group, Open client opens the request that matched its
exploit rule; for
every other client it opens the sampled flagged requests. Requested source
lines appear before the ordinary activity sample, within the same display limit.
Counts describe all supporting requests; examples and references are a bounded
sample.

The scan can be cancelled while ordinary reconstruction remains available.
Suspicious findings shown during scanning are provisional and state how many
IPs were examined. The client list searches the complete stored population while
scanning, after cancellation or failure, and after completion, because its
searches are paged summary queries independent of detection, started 150 ms after
typing stops. Only unusualness comparisons need the completed scan.
A changed time range starts a corresponding scan;
results from previous requests cannot replace the current queue.

## Reading the recommendations

Each Suspicious recommendation answers three questions, one block per
reason: what was observed, why that deserves attention for this client, and which
requests to inspect. The table's **Finding** column shows the first
block's observation, for example "Exploit evidence: SQL Injection (UNION
SELECT)" or, for a client without exploit evidence, "40 of 50 requests flagged;
strongest high".

1. **Exploit evidence** appears first for a client in the first group (see
   [Exploit evidence first](#exploit-evidence-first)). It names one rule and the
   request it matched, with that request as an example. For a client with native
   evidence that is its earliest request with an eligible native match, named
   after the strongest eligible rule on it (severity, then confidence), even
   when CRS evidence came earlier. Otherwise it is the earliest request with CRS
   paranoia level 1 evidence, named after the strongest qualifying CRS rule
   (severity, then rule id), and the block says the rule is from OWASP CRS. It
   does not show what the request achieved, and the same rule can match harmless
   requests, so the request is the thing to inspect. A client in the second
   group has no such block.
2. **Flagged requests** is what orders clients within a group: how many
   requests carry a hostile detection, their share, and the strongest
   severity. Its why says what kind of flagged request dominates and whether it
   is most (half or more), a substantial part, or a small part (under a tenth) of
   the client's activity. When one rule matches every flagged request, it names
   that rule, because one noisy rule can explain a large count.
3. **Distinct rule matches** counts bundled rules rated at confidence 0.85 or
   above that matched different requests, each rule and each request counted
   once. The rating is the rule author's and describes the rule, not the
   request: a scanner's user-agent string qualifies as readily as an exploit
   pattern.
4. **Probe, then an attack pattern** appears when, within one session, a
   reconnaissance or enumeration request is followed at a strictly later time by
   an injection, traversal, access-control, credential, SSRF or exploitation
   match. Requests logged at the same time are never paired, so with
   second-resolution logs a probe and an attack in the same second do not count. It says nothing
   about whether the probe led to the attempt; a shared IP or a scanner can
   produce the same ordering.
5. **Recurrence across sessions** appears when detections fall in two or more
   sessions. Sessions under an hour apart may be one burst split by a session
   boundary, and the block says so. Session splits and shared IPs do not
   establish one actor.

Examples show the request, its time in UTC and its source reference. A long path
is cut to two lines with **Show full request**. A reference whose source cannot
be read stays visible with the reason and cannot be opened; one read from a
source changed since ingest opens and shows its warning. These reasons are
written when a page is read, so rewording them does not require a rescan.

Blocks 3 to 5 are context for reading a client. They do not affect its rank.

The Suspicious queue uses the existing engine's native and CRS label precedence.
Several rule matches on one request still count as one supporting request.
Policy 5 puts clients with exploit evidence, native or CRS paranoia level 1,
first and orders each group by
`log2(1 + h) * (1 + s/4) * (0.5 + 0.5*h/n)`, where `h` is deduplicated hostile
requests, `s` is existing severity and `n` is all requests. Ties use category
breadth, distinct hostile paths, hostile requests and IP. The order determines
investigation priority, not attack probability. Policy 3 used the same score for
every client with no first group; it passed the predeclared held-out promotion
gate in the [validation report](evaluations/ip-prioritization-validation.md),
which describes policy 3 and does not validate policy 4 (the same first group
with native evidence only) or policy 5. Which clients are in the
queue, and the other views, are unchanged. Category labels are
observations and hypotheses to investigate; response codes and response sizes
do not establish compromise. An IP can represent multiple users or systems.

The Unusual queue compares clients within the current case and selected range.
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

## Exploit evidence first

A client has exploit evidence when any of its requests carries a match by a
native rule that is eligible. Eligible means the rule's category is injection,
path traversal, access control, credential attack, SSRF or exploitation, and its
id is not one of the seven exclusions below. Every match on a request counts, not
only the label the request is reported under, so an eligible match that loses
the label to a scanner's user-agent rule still places the client first.

Labels derived from OWASP CRS never place a client first, wherever they are
stored. A CRS detection can, when all of these hold: it is at paranoia level 1,
the level CRS designs for general deployment with minimal false-positive tuning;
it matched something the request itself carries, not a Referer and not an
unfilled `${name}` template slot; and this project maps the rule to one of the
six categories above, which keeps out scanner identification (913100), the
protocol and generic families, and rules that need a trusted site host when none
was given. Severity is not required. When a client has native evidence too, its
reason names the native rule. CRS evidence at paranoia level 2 or above does not
qualify a client; native evidence on the same client still can. How often
harmless clients enter the first group through CRS on real traffic is not
measured. Custom rules in the six categories take part like bundled ones, and
adding or changing a rule, bundled or custom, can change which clients come
first.

Seven rules are excluded, because none of them is a payload the client sent.
Six record where a client went, which methods it used or what the server
answered, so their evidence also fits ordinary activity. The seventh,
`injection_tool_user_agent`, records what the client says it is. That is not
ordinary activity, but a tool's first requests are harmless baselines, so as the
example that places a client first it would show a search for "oak" instead of
the payload that came later; on every 2026-10-06 build the sqlmap client is in
the first group through its payloads either way. Their matches still put a
client in the queue, appear in its reasons and open in reconstruction; they only
cannot place a client first.

| Rule | What it records | Ordinary activity it also fits |
| --- | --- | --- |
| `admin_area_probe` | a request to an admin path refused with 401 or 403 | a staff member whose session expired, a bookmark to an admin page |
| `forced_browsing` | at least 10 refusals (401/403) across at least 8 paths within 120 s | a single-page app whose token expired refreshing its own API calls |
| `forced_browsing_succeeded` | at least 3 admin-path requests within 300 s, some refused and some served | a staff member signing in after a refusal |
| `admin_reached_without_signing_in` | an admin path redirected, then an admin page served without a sign-in between them | a staff member whose sign-in the access log does not show (single sign-on, a session set elsewhere) |
| `server_errors_provoked` | at least 5 responses of 500 or above within 120 s | any client during an outage or a broken deployment |
| `verb_tampering` | at least 3 methods on admin, API or account paths within 120 s, at most half of them served | an administrator's single-page app whose token expired, sending a GET, a PUT and a DELETE that are all refused |
| `injection_tool_user_agent` | a User-Agent naming sqlmap, havij, commix or ghauri | none, but no payload either: the tool's harmless first requests (`/search?q=oak`) would be the example shown |

`credential_attack` (5 or more responses of 400 or above to sign-in, auth,
session or token paths within 300 s, across at most 3 distinct paths) and
`bulk_account_creation` (5 or more responses of 400 or above to registration
paths within 300 s, across at most 3 distinct paths) also judge by what the
server answered, but they stay eligible: they are the only native view of
password guessing and credential stuffing that an access log gives. So a user
who mistypes a password five times, or a client stuck retrying an expired
token, can enter the first group.

Excluding the seven can leave genuine access-control attacks, attacks that
provoke server errors, and an injection tool none of whose payloads a rule
catches, in the second group. In particular
`admin_reached_without_signing_in` can record a real unauthenticated breach of
an admin area; it is excluded because the access log cannot tell that breach
from a sign-in it does not record.

Within the first group a harmless client with many flagged requests, such as a
retry loop, can outrank a quiet attacker, and a harmless client whose request
matches an eligible rule outranks every client in the second group however low
its score.

Limits of what is known:

- The development builds are one synthetic shop driven by the same campaign
  scripts and contain almost none of the harmless requests that resemble
  attacks. How often harmless clients enter the first group on real traffic is
  unknown.
- Whether a client in the first group can be dismissed quickly is not measured.
- The order among first-group clients is not measured.

## Storage and execution

`logarx.triage` has no Qt dependency. Profiling shares session boundaries and
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

`logarx.evaluation.triage.isolation_order` compares Isolation Forest against
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
| Suspicious queue | 50 / 1.25 | 60 / 3.76 | 80 / 10.03 |
| Statistical unusualness | 40 / 1.00 | 24 / 1.50 | 16 / 2.01 |
| Isolation Forest | 100 / 2.51 | 80 / 5.01 | 76 / 9.52 |

The Suspicious queue improves over request count here but underperforms 4xx-share
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
