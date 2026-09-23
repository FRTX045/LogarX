# Suspicious activity recommendations: content, evaluation and ordering

- **Date:** 2026-09-23
- **Scope:** the Suspicious activity queue of the Where to start tab. The Unusual
  activity and All clients queues are unchanged.

## Purpose

The queue decides which client an investigator opens first. It orders a
worklist; it does not decide guilt. Every recommendation answers three
questions:

1. What did we observe?
2. Why does that deserve attention for this investigation goal?
3. Which requests should the investigator inspect next?

Response codes and sizes are context. A 200 response alone does not establish
that an attack succeeded.

The work has three parts. **A** changes what a recommendation says. **B** is an
evaluation that can distinguish orderings by what an investigator should open
first. **C** proposes two orderings and decides between them and today's with B.
A does not depend on B or C. C is only adopted if it passes B's gate.

## A. Recommendation content

### Layout

The details area shows one block per reason. Each block carries its own
observation, its own why, and example requests for that reason. The table's
"Why look here" column shows a compact observation specific to the client from
its first reason, such as "3 high-confidence rule matches" or "Enumeration then
SQL injection, 1 session". The why sentences stay in the details area, where
they are not repeated row after row.

Example requests are clickable and named by method, path and time, with the
file-and-line reference underneath for traceability. Clicking one opens
reconstruction on that request. The main action is **Inspect supporting
requests**, which works as the existing action does today: it opens
reconstruction on the activity containing the sampled references. It does not
present every supporting request across activities.

Examples are labelled as examples. Counts in the observation cover every
supporting request; the examples are a bounded sample and must not read as the
whole basis for the recommendation.

If a source file or line is unavailable, its reference stays visible with the
reason it cannot open. A recommendation never substitutes another file or
request.

A context line gives response codes with the note that a 200 does not establish
success.

### Reasons

**Distinct high-confidence rule matches.**

- Qualifying detection: a hostile label from a bundled rule pack whose
  author-assigned confidence is at least 0.85, at any severity. CRS labels never
  qualify: neither CRS severity nor the fixed CRS confidence establishes
  specificity. CRS-only clients stay eligible for the queue through their other
  evidence.
- Count: the largest set of (rule, request) pairs from qualifying detections in
  which no rule and no request appears twice. Several rules on one request count
  as one request.
- Observed, for example: "3 rules matched on 3 requests."
- Why: "Distinct high-confidence rule matches provide support beyond repetition
  of one rule."
- Examples: one representative request per counted pair.
- Wording: "high-confidence rule match". Never a confirmed attack, and never an
  attack probability.

**Enumeration, then an attack pattern.**

- Within one session, using the existing session boundaries inside the selected
  time range: a request with a reconnaissance or enumeration label, and a
  different, later request with an injection, path traversal, access control,
  credential attack, SSRF or exploitation label. Later means a strictly later
  timestamp: requests logged at the same time, including ones from different
  source files, are never paired, so a probe and an attack in the same second do
  not count.
- Counted once per session, not once per probe and attack pair.
- Observed, for example: "Enumeration was followed by an SQL-injection match
  against /login in the same session."
- Why: "The ordering makes this session worth reviewing as a whole."
- Examples: the earlier enumeration request and the later attack-pattern match.
- The text never claims that the probing discovered the target or caused the
  later attempt. A shared IP or an automated scanner can produce the same
  ordering.

**Recurrence across sessions.**

- Hostile sessions: sessions inside the selected range with at least one hostile
  request. Each session counts once, however many detections it holds.
- Observed, for example: "Hostile detections occurred in 4 of 6 sessions. The
  first and last matching requests were 3 days apart."
- Examples: requests from different sessions.
- Called "recurrence across sessions", never persistence: session splits and
  shared IPs do not establish one actor.
- Where timestamps were remapped, as in the dataset builds, the span describes
  that timeline, not verified elapsed time.
- A single long session still matters through its supporting requests; it
  contributes one session here.

**Support, share and severity** remain as today: hostile request count, hostile
share, and strongest severity, reported separately from each other.

Reasons appear in the order listed above, and a reason that does not apply to a
client is left out. Support, share and severity apply to every client in the
queue, so a client with none of the three new reasons leads with it. Its why is
drafted in the preview and settled at the preview review.

### Preview before integration

A changes the window, so it is previewed before it is integrated:

1. Capture the current details area as the baseline.
2. Render the proposed reason blocks with the application's own widgets, theme
   and sizing, through an isolated preview that does not change the production
   window.
3. Show several reasons, one reason, long request paths and unavailable source
   evidence. Label illustrative data as illustrative.
4. Demonstrate the interaction: selecting an example and using Inspect
   supporting requests, not only a still image.
5. Review the preview before A is integrated into the window.

## B. Evaluation

### Corpora

The BlackHat-Dataset `apache-shopfront` builds already used for policy 3:

| Role | Builds |
| --- | --- |
| Development | small builds with seeds 13, 19, 23, 31 |
| Held out | small builds with seeds 41, 53, 67, 71 |
| Larger check | the medium build |
| All-benign stress | broken-links |

Every run enriches with CRS at paranoia level 2, using the revision pinned in
CI, and records the CRS revision and configuration fingerprint.

### Grades from truth only

Grades come from the truth files, never from the tool's rules:

| Grade | Client's truth |
| ---: | --- |
| 2 (targeted) | at least one request in injection, path traversal, access control, credential attack, SSRF or exploitation |
| 1 (probe-only) | hostile requests, all reconnaissance or enumeration |
| 0 (benign) | no hostile request |

**Low-support targeted clients:** grade 2 with 5 or fewer hostile truth
requests. The cutoff is frozen. Reports give both the hostile truth request count
and the total request count. This is a cohort observed in these builds, with 2 to
5 hostile truth requests against 18 or more for the other targeted clients, and
not a universal threshold. It is distinct from the existing "quiet" cohort
(fewer than 20 total requests), which keeps its name and meaning.

Existing judgment exclusions (unknown request ground truth) apply unchanged.

### Measures

- **Ranks** are counted within the judged population of a build, after the
  judgment exclusions.
- **Targeted yield at k:** targeted clients among the first k ranks, divided by
  min(k, judged clients in the build). This is yield per investigation slot, as
  the existing evaluation computes it. Higher is better.
- **Targeted recall at k:** targeted clients among the first k ranks, divided by
  targeted clients in the build. A diagnostic, not a selection or gate measure.
- **Mean targeted yield at k:** the arithmetic mean of targeted yield at k over
  the builds concerned.
- **Mean targeted rank:** the mean rank of the targeted clients in a build.
  Lower is better.
- **Benign count at k:** grade 0 clients among the first k ranks.
- **Tier of a client:** within 10, within 25, within 50, or beyond.
- **Unranked targeted clients:** a targeted client absent from the queue, because
  the tool found no hostile detection, is not found at any budget, is in tier
  "beyond", and takes rank (number of judged clients in the build) + 1 for mean
  targeted rank. That value is a penalty for computing the mean, not a queue
  position: reports show such clients as unranked and count them separately.
- **Same ranked set:** today's ordering, C1 and C2 change order, not
  eligibility, so in every build they must rank exactly the same clients. The
  evaluation checks this and stops if they differ.

Graded measures are added alongside the existing binary evaluation, which stays
as it is, including the separate unusualness judgments.

### Always reported

- The rank of every targeted client, by IP, in every build, with low-support
  targeted clients marked, and the number of probe-only and benign clients ranked
  above each.
- Every per-client rank change between today's ordering and each challenger.
- Normalized discounted cumulative gain at 10, 25 and 50 with the grades above,
  and grade 2 recall at 10, 25 and 50, as secondary diagnostics.
- Every benign client in the first 50, with its reasons.
- For every client in the first 50, its base score and the three bonus
  contributions separately.
- A named table of the six benign clients with critical-severity detections in
  the seed 41 record (`false_suspicious_evidence`): today's rank, each
  challenger's rank, supporting requests, and whether each qualifies for the
  high-confidence contribution. Critical severity alone does not establish that
  it does.
- The limits: scripted scenarios from one shop; 7 to 10 targeted clients per
  build and 12 distinct targeted IPs across related builds, which are not
  necessarily 12 independent campaigns; every build, held-out ones included, was
  scored and examined in the policy 3 study, so none is untouched data; the
  seed 41 benign clients are known failure cases.

Results are described as performance on these scripted scenarios, never as
accuracy.

### Audit of the 0.85 confidence filter

For each rule that qualifies under A, across every build:

- matches on benign truth lines and on hostile truth lines;
- which low-support targeted clients have at least one qualifying match.

A rule with benign matches is flagged by name. The 0.85 threshold is an
engineering choice until this audit supports it. An exact exploit-pattern match
may justify the designation; a generic suspicious path or keyword usually needs
more context.

## C. Ordering

### Today's ordering (baseline, policy 3)

```text
base = log2(1 + h) × (1 + s/4) × (0.5 + 0.5 × h/n)
```

`h` is deduplicated hostile requests, `s` is the strongest severity (INFO 0 to
CRITICAL 4), `n` is all requests.

### Bonuses

```text
D = min(3, largest set of distinct (qualifying rule, request) pairs)
Q = 1 if any session in range has enumeration followed by an attack pattern, else 0
R = min(2, 0.5 × max(0, hostile_sessions − 1))
```

`Q` contributes at most one point per client however many sessions qualify.

### Challengers

```text
C1 = log2(1 + h) × (1 + s/4) × (0.5 + 0.5 × h/n) + D + Q + R

C2 = log2(1 + min(h, 31)) × (1 + s/4) × (0.5 + 0.5 × h/n) + D + Q + R
```

In C2 only the logarithmic support term stops growing; the share still uses the
actual `h/n`, and the tie order still sees `h`. Ties in every ordering keep
today's order: category breadth, distinct hostile paths, hostile requests, IP.

The bonuses are correlated priority contributions, not independent increases in
confidence: the same detections can feed the base score and all three bonuses.
Up to six bonus points is substantial for a low-support client, which is why the
evaluation records each part separately.

Weights and caps are fixed here and are not tuned during implementation.

### Development selection

On the development builds, choose one of C1 and C2:

1. higher mean targeted yield at 10 wins;
2. then higher mean targeted yield at 25 wins;
3. then lower mean targeted rank wins;
4. then C1 before C2.

The chosen challenger is frozen before the held-out builds are scored.

### Held-out gate

On the held-out builds, against today's ordering, the chosen challenger is
promoted only if all three hold:

1. Mean targeted yield at 10 and at 25 are each no lower than today's, and at
   least one is higher.
2. No low-support targeted client moves to a worse tier than it has under
   today's ordering, in any held-out build.
3. Benign count at 10, at 25 and at 50 does not increase in any held-out build.

If the gate fails, today's ordering stays, and the criteria are not relaxed
afterwards. A pass is reported with every per-client regression.

## Not in this work

- Sensitive-target tags for potential impact. Impact is judged by rule severity
  for now; the reason format leaves room to add target tags later.
- A view that opens the complete supporting set across activities in
  reconstruction.
- Any use of response codes or sizes in the score.
- Changes to the Unusual activity or All clients queues.
- Showing the score or its parts in the window.
