# Graded validation of the Suspicious activity ordering, 2026-09-24

The frozen challenger, C2, passed the held-out gate, narrowly. It raised mean
targeted yield on the held-out builds by 2.5 percentage points at 10 and 2.0 at 25,
added no benign client at 10, 25 or 50 in any build, and moved no low-support
targeted client out of its tier. It also pushed one targeted client, the credential
attacker `192.0.2.23`, down in every held-out build and in the medium check.

**Decision (2026-09-27): C2 passed the frozen gate and is not adopted.** Policy 3
stays the product ordering. The gate result stands as measured; not adopting C2
is a product decision taken after reviewing the tradeoffs below, not a
retrospective gate failure. The top-10 gain is one extra targeted client in one
held-out build; the credential attacker falls in every held-out build and from 29
to 235 in the medium check; and the low-support safeguard passed without testing
protection of any detected low-support attacker, because none is detected.
Keeping policy 3 does not mean its ordering is satisfactory.

The grades, formulas and gate below were frozen before any build was scored.
Records are in [suspicious-graded](suspicious-graded/): one per
build, `frozen-selection.json` with hashes of the triage and evaluation code, the
study script, and each case's manifest, CRS records, log and truth file, and
`promotion.json` with the gate and every rank change.
The study script's entry in `frozen-selection.json` was renamed to `run_graded.py`
after the run, because the script is not published; its hash is unchanged.

## Method

Fresh cases were built from the BlackHat-Dataset `apache-shopfront` builds and
enriched with today's code: CRS revision `d694d465951ee06347214f1291ae096e40700001`,
paranoia level 2, configuration fingerprint `1c4b66d67838c5e8`, CRS host
`localhost` (no site host named, so rule 931130 stays withheld). The cases used by
the policy 3 study were left untouched.

Grades come from the truth files alone: 2 for a targeted attack category, 1 for
reconnaissance or enumeration only, 0 otherwise. Low-support targeted clients have
at most 5 hostile truth requests. Yield is targeted clients found per available
slot, min(k, judged). An unranked targeted client counts as judged + 1 in mean
targeted rank.

Development builds 13, 19, 23 and 31 chose C2 over C1 on mean targeted yield at 10
(seed 23 was the only build where they differed). The choice was frozen before
builds 41, 53, 67 and 71 were scored. The medium build and broken-links are checks
only.

## Frozen ordering definitions

Policy 3 uses `log2(1 + h) * (1 + s/4) * (0.5 + 0.5 * h/n)`, where `h`
is deduplicated hostile requests, `n` is all requests and `s` is the strongest
severity, from INFO (0) to CRITICAL (4). C1 adds three bonuses to that score:

- `D`: at most 3 distinct rule/request pairs, with no rule or request counted
  twice. Only hostile bundled-rule labels at confidence 0.85 or above qualify;
  CRS labels do not.
- `Q`: 1 if a session contains a reconnaissance or enumeration request followed
  at a strictly later timestamp by a different request in a targeted category,
  otherwise 0.
- `R`: `min(2, 0.5 * max(0, hostile_sessions - 1))`.

C2 uses the same bonuses and formula, but replaces `h` with `min(h, 31)` only
inside the logarithm. The share still uses the actual `h/n`. All methods keep
the same tie-breaks: category breadth, distinct hostile paths, hostile requests,
then IP. These bonuses are correlated contributions, not independent confidence.

Development selection prefers higher mean targeted yield at 10, then at 25,
then lower mean targeted rank, then C1. The gate's review-budget tiers are the
first 10, ranks 11 to 25, ranks 26 to 50, and beyond 50.

## Gate

| Check | Result |
| --- | --- |
| Mean targeted yield at 10 and 25 no lower, one higher | passed: +2.5 points at 10, +2.0 at 25 |
| No low-support targeted client drops a tier | passed, trivially: every one is unranked under all methods |
| Benign clients at 10, 25, 50 do not rise in any build | passed: 0 at every budget, every build, every method |

The gain at 10 is one targeted client in one build (seed 67). The gate establishes
improvement over policy 3 on these builds; it does not establish that C2 is good.

## What moved

- `192.0.2.31` (injection) is rank 1 under C2 in every held-out build and in the
  medium check, from 4 to 12 under policy 3.
- `198.51.100.21` rises from 37 to 103 to between 10 and 17 in the held-out builds,
  and from 286 to 49 in the medium check.
- `198.51.100.23` rises from 58 and 64 to 13 and 9 in the held-out builds where it
  appears (41 and 71), and from 287 to 211 in the medium check.
- `192.0.2.23` (credential attack, 32 to 47 hostile truth requests) falls from 10 to
  19 to between 35 and 67 in every held-out build, and from 29 to 235 in the medium
  check. C1 moves it down too, to 176 in the medium check. The gate does not guard
  it because it is not low-support.

## Why the bonuses barely reach the head

The high-confidence rules that fire most are probe rules. Across all builds,
`directory_enumeration_low_slow`, `directory_enumeration`, `scanner_user_agent`,
`known_software_probe` and `config_file_exposure` matched between 5,145 and 35,483
hostile-truth lines each, all reconnaissance or enumeration. A probe-only scanner
therefore collects the same distinct-match bonus (+3) as a targeted client, and the
first 10 remain mostly probe-only clients: under policy 3 the medium check's first
10 holds no targeted client at all, and under C2 one. This follows from the frozen
definition of specificity (hostile native rules at confidence 0.85 or above, any
severity), which includes reconnaissance rules.

## Low-support targeted clients are not detected

Every low-support targeted client, the access-control clients in `203.0.113.41` to
`.45`, is unranked under every method in every build: the tool raises no hostile
detection on them. No ordering can bring them forward. This is a detection gap on
these builds, not an ordering result, and the gate's second check is satisfied only
because these clients are beyond 50 in both orderings.

## High-confidence rule audit

Two qualifying rules matched benign-truth lines and are flagged: `sqli_tautology`
(5 benign, 112 hostile) and `xss_script_tag` (4 benign, 14 hostile). No
low-support targeted client has a qualifying match. The 0.85 threshold remains
provisional; the audit does not support treating reconnaissance rules as specific
evidence for ordering purposes, since they carry the bonus to scanners.

| Rule | Name | Confidence | Benign-truth lines | Hostile-truth lines | Flagged in |
|---|---|---:|---:|---:|---|
| `sqli_tautology` | SQL Injection (always-true condition) | 0.85 | 5 | 112 | 13, 31, 41, 53, 67 |
| `xss_script_tag` | Cross-Site Scripting (script tag) | 0.9 | 4 | 14 | 13, 23, 31, 67 |
| `command_injection` | OS Command Injection | 0.85 | 0 | 36 | none |
| `config_file_exposure` | Configuration File Probe | 0.9 | 0 | 5145 | none |
| `directory_enumeration` | Directory Enumeration | 0.9 | 0 | 24288 | none |
| `directory_enumeration_low_slow` | Directory Enumeration (Low and Slow) | 0.85 | 0 | 35483 | none |
| `known_software_probe` | Probe for Software the Site Does Not Run | 0.85 | 0 | 11121 | none |
| `path_traversal` | Path Traversal | 0.9 | 0 | 54 | none |
| `scanner_user_agent` | Security Scanner User-Agent | 0.95 | 0 | 12850 | none |
| `sensitive_file_access` | Sensitive System File Access | 0.95 | 0 | 99 | none |
| `sqli_column_count` | SQL Injection (column counting) | 0.85 | 0 | 9 | none |
| `sqli_schema_probe` | SQL Injection (schema enumeration) | 0.9 | 0 | 11 | none |
| `sqli_time_based` | SQL Injection (time-based blind) | 0.9 | 0 | 18 | none |
| `sqli_union_select` | SQL Injection (UNION SELECT) | 0.95 | 0 | 278 | none |
| `ssrf_internal_target` | SSRF (internal address in parameter) | 0.85 | 0 | 27 | none |
| `webshell_double_extension` | Webshell Disguised by a Double Extension | 0.95 | 0 | 15 | none |


## Seed 41 false alarms from the policy 3 study

Five of the six benign clients that policy 3 had placed in its head on seed 41 now
have no hostile detection at all under today's code, so they are unranked by every
method (`seed-41-false-alarms.json`). The sixth, `192.0.2.25` (2 hostile of 18
requests), ranks 133 under every method and qualifies for a distinct-match bonus
of 1. These six were known failure cases before this study.

## Limits

- The frozen fingerprint covers the triage and evaluation code, the study script
  and the case inputs, not the rule packs, sessionizer or event store; the study
  ran in one pass, and the recorded hashes match the committed code.
- Scripted scenarios from one shop. 7 to 10 targeted clients per build, 12
  distinct targeted addresses across related builds, which are not necessarily 12
  independent campaigns.
- Every build, held-out ones included, was scored and examined in the policy 3
  study, so none is untouched data.
- Timestamps in the dataset builds are remapped onto a diurnal model; spans and
  sessions describe that timeline.
- Broken-links has no targeted client; its yields are 0 and its recall, rank and
  nDCG are undefined, as expected. Its benign-head result is vacuous: no client was
  flagged at all, so all three queues were empty (0 of 1,510 clients ranked), and
  CRS returned no detections for its 20,000 requests.

## Every build

| Build | Role | Judged | Targeted | Unranked targeted | Method | Yield 10 | Yield 25 | Yield 50 | Mean targeted rank | Benign 10 / 25 / 50 | nDCG 10 |
|---|---|---:|---:|---:|---|---:|---:|---:|---:|---|---:|
| 13 | development | 928 | 10 | 4 | policy3 | 10.0% | 8.0% | 6.0% | 411.2 | 0 / 0 / 0 | 0.539 |
| 13 | development | 928 | 10 | 4 | c1 | 10.0% | 12.0% | 8.0% | 401.8 | 0 / 0 / 0 | 0.543 |
| 13 | development | 928 | 10 | 4 | c2 | 10.0% | 12.0% | 6.0% | 405.4 | 0 / 0 / 0 | 0.610 |
| 19 | development | 928 | 9 | 3 | policy3 | 10.0% | 8.0% | 4.0% | 359.3 | 0 / 0 / 0 | 0.554 |
| 19 | development | 928 | 9 | 3 | c1 | 10.0% | 8.0% | 4.0% | 347.9 | 0 / 0 / 0 | 0.557 |
| 19 | development | 928 | 9 | 3 | c2 | 10.0% | 8.0% | 4.0% | 348.7 | 0 / 0 / 0 | 0.630 |
| 23 | development | 939 | 8 | 3 | policy3 | 10.0% | 8.0% | 6.0% | 388.0 | 0 / 0 / 0 | 0.585 |
| 23 | development | 939 | 8 | 3 | c1 | 10.0% | 12.0% | 6.0% | 382.6 | 0 / 0 / 0 | 0.585 |
| 23 | development | 939 | 8 | 3 | c2 | 20.0% | 12.0% | 6.0% | 381.5 | 0 / 0 / 0 | 0.686 |
| 31 | development | 936 | 8 | 4 | policy3 | 10.0% | 8.0% | 4.0% | 494.6 | 0 / 0 / 0 | 0.585 |
| 31 | development | 936 | 8 | 4 | c1 | 10.0% | 8.0% | 4.0% | 491.8 | 0 / 0 / 0 | 0.585 |
| 31 | development | 936 | 8 | 4 | c2 | 10.0% | 8.0% | 4.0% | 494.5 | 0 / 0 / 0 | 0.652 |
| 41 | held out | 954 | 7 | 2 | policy3 | 10.0% | 8.0% | 4.0% | 310.9 | 0 / 0 / 0 | 0.594 |
| 41 | held out | 954 | 7 | 2 | c1 | 10.0% | 12.0% | 6.0% | 301.6 | 0 / 0 / 0 | 0.596 |
| 41 | held out | 954 | 7 | 2 | c2 | 10.0% | 12.0% | 6.0% | 299.9 | 0 / 0 / 0 | 0.678 |
| 53 | held out | 970 | 9 | 4 | policy3 | 10.0% | 12.0% | 6.0% | 461.6 | 0 / 0 / 0 | 0.557 |
| 53 | held out | 970 | 9 | 4 | c1 | 10.0% | 16.0% | 8.0% | 450.2 | 0 / 0 / 0 | 0.560 |
| 53 | held out | 970 | 9 | 4 | c2 | 10.0% | 12.0% | 8.0% | 450.4 | 0 / 0 / 0 | 0.630 |
| 67 | held out | 936 | 8 | 4 | policy3 | 10.0% | 8.0% | 6.0% | 491.0 | 0 / 0 / 0 | 0.585 |
| 67 | held out | 936 | 8 | 4 | c1 | 10.0% | 8.0% | 4.0% | 490.5 | 0 / 0 / 0 | 0.585 |
| 67 | held out | 936 | 8 | 4 | c2 | 20.0% | 8.0% | 4.0% | 489.8 | 0 / 0 / 0 | 0.686 |
| 71 | held out | 966 | 8 | 3 | policy3 | 20.0% | 8.0% | 4.0% | 401.4 | 0 / 0 / 0 | 0.611 |
| 71 | held out | 966 | 8 | 3 | c1 | 10.0% | 16.0% | 8.0% | 381.2 | 0 / 0 / 0 | 0.580 |
| 71 | held out | 966 | 8 | 3 | c2 | 20.0% | 12.0% | 8.0% | 382.6 | 0 / 0 / 0 | 0.688 |
| medium | check | 2757 | 9 | 3 | policy3 | 0.0% | 4.0% | 4.0% | 1072.1 | 0 / 0 / 0 | 0.516 |
| medium | check | 2757 | 9 | 3 | c1 | 0.0% | 4.0% | 4.0% | 1038.4 | 0 / 0 / 0 | 0.516 |
| medium | check | 2757 | 9 | 3 | c2 | 10.0% | 4.0% | 4.0% | 1043.6 | 0 / 0 / 0 | 0.630 |
| broken-links | check | 1510 | 0 | 0 | policy3 | 0.0% | 0.0% | 0.0% | n/a | 0 / 0 / 0 | n/a |
| broken-links | check | 1510 | 0 | 0 | c1 | 0.0% | 0.0% | 0.0% | n/a | 0 / 0 / 0 | n/a |
| broken-links | check | 1510 | 0 | 0 | c2 | 0.0% | 0.0% | 0.0% | n/a | 0 / 0 / 0 | n/a |


## Every targeted client

| Build | Client | Hostile truth / total requests | Low-support | policy3 | C1 | C2 | Probe-only above (policy3 / C2) |
|---|---|---|---|---:|---:|---:|---|
| 13 | 192.0.2.22 | 18 / 25 | no | 138 | 126 | 126 | 132 / 120 |
| 13 | 192.0.2.23 | 46 / 51 | no | 14 | 31 | 77 | 12 / 73 |
| 13 | 192.0.2.31 | 46 / 46 | no | 6 | 5 | 1 | 5 / 0 |
| 13 | 198.51.100.21 | 27 / 36 | no | 30 | 15 | 12 | 27 / 10 |
| 13 | 198.51.100.22 | 16 / 19 | no | 137 | 105 | 105 | 132 / 100 |
| 13 | 198.51.100.23 | 31 / 41 | no | 71 | 20 | 17 | 67 / 14 |
| 13 | 203.0.113.41 | 4 / 270 | yes | unranked | unranked | unranked | 136 / 136 |
| 13 | 203.0.113.42 | 2 / 157 | yes | unranked | unranked | unranked | 136 / 136 |
| 13 | 203.0.113.44 | 1 / 97 | yes | unranked | unranked | unranked | 136 / 136 |
| 13 | 203.0.113.45 | 5 / 111 | yes | unranked | unranked | unranked | 136 / 136 |
| 19 | 192.0.2.22 | 18 / 25 | no | 129 | 119 | 119 | 123 / 113 |
| 19 | 192.0.2.23 | 45 / 50 | no | 14 | 57 | 73 | 12 / 69 |
| 19 | 192.0.2.31 | 45 / 45 | no | 7 | 6 | 1 | 6 / 0 |
| 19 | 198.51.100.21 | 21 / 30 | no | 91 | 23 | 20 | 88 / 18 |
| 19 | 198.51.100.22 | 19 / 25 | no | 114 | 75 | 75 | 109 / 70 |
| 19 | 198.51.100.23 | 30 / 38 | no | 92 | 64 | 63 | 88 / 60 |
| 19 | 203.0.113.41 | 4 / 187 | yes | unranked | unranked | unranked | 123 / 123 |
| 19 | 203.0.113.42 | 2 / 149 | yes | unranked | unranked | unranked | 123 / 123 |
| 19 | 203.0.113.45 | 3 / 83 | yes | unranked | unranked | unranked | 123 / 123 |
| 23 | 192.0.2.21 | 44 / 57 | no | 19 | 17 | 14 | 17 / 11 |
| 23 | 192.0.2.23 | 14 / 17 | no | 114 | 119 | 119 | 109 / 114 |
| 23 | 192.0.2.31 | 50 / 50 | no | 4 | 4 | 1 | 3 / 0 |
| 23 | 198.51.100.21 | 27 / 39 | no | 34 | 13 | 10 | 31 / 8 |
| 23 | 198.51.100.22 | 16 / 20 | no | 113 | 88 | 88 | 109 / 84 |
| 23 | 203.0.113.41 | 3 / 202 | yes | unranked | unranked | unranked | 115 / 115 |
| 23 | 203.0.113.42 | 5 / 117 | yes | unranked | unranked | unranked | 115 / 115 |
| 23 | 203.0.113.45 | 4 / 113 | yes | unranked | unranked | unranked | 115 / 115 |
| 31 | 192.0.2.23 | 52 / 57 | no | 12 | 56 | 84 | 10 / 81 |
| 31 | 192.0.2.31 | 47 / 47 | no | 4 | 4 | 1 | 3 / 0 |
| 31 | 198.51.100.21 | 24 / 34 | no | 72 | 17 | 14 | 69 / 12 |
| 31 | 198.51.100.22 | 16 / 21 | no | 121 | 109 | 109 | 117 / 105 |
| 31 | 203.0.113.41 | 2 / 206 | yes | unranked | unranked | unranked | 118 / 118 |
| 31 | 203.0.113.42 | 3 / 142 | yes | unranked | unranked | unranked | 118 / 118 |
| 31 | 203.0.113.43 | 1 / 73 | yes | unranked | unranked | unranked | 118 / 118 |
| 31 | 203.0.113.44 | 2 / 93 | yes | unranked | unranked | unranked | 118 / 118 |
| 41 | 192.0.2.23 | 32 / 39 | no | 15 | 58 | 58 | 13 / 54 |
| 41 | 192.0.2.31 | 45 / 45 | no | 8 | 7 | 1 | 7 / 0 |
| 41 | 198.51.100.21 | 24 / 32 | no | 57 | 15 | 12 | 54 / 10 |
| 41 | 198.51.100.22 | 18 / 22 | no | 128 | 105 | 105 | 123 / 100 |
| 41 | 198.51.100.23 | 31 / 40 | no | 58 | 16 | 13 | 54 / 10 |
| 41 | 203.0.113.41 | 4 / 230 | yes | unranked | unranked | unranked | 127 / 127 |
| 41 | 203.0.113.42 | 3 / 129 | yes | unranked | unranked | unranked | 127 / 127 |
| 53 | 192.0.2.21 | 38 / 51 | no | 23 | 19 | 16 | 20 / 14 |
| 53 | 192.0.2.23 | 42 / 46 | no | 15 | 24 | 36 | 13 / 32 |
| 53 | 192.0.2.31 | 45 / 45 | no | 6 | 5 | 1 | 5 / 0 |
| 53 | 198.51.100.21 | 21 / 31 | no | 100 | 20 | 17 | 96 / 14 |
| 53 | 198.51.100.22 | 16 / 20 | no | 126 | 100 | 100 | 121 / 95 |
| 53 | 203.0.113.41 | 4 / 248 | yes | unranked | unranked | unranked | 123 / 123 |
| 53 | 203.0.113.42 | 2 / 181 | yes | unranked | unranked | unranked | 123 / 123 |
| 53 | 203.0.113.44 | 3 / 81 | yes | unranked | unranked | unranked | 123 / 123 |
| 53 | 203.0.113.45 | 2 / 110 | yes | unranked | unranked | unranked | 123 / 123 |
| 67 | 192.0.2.23 | 35 / 41 | no | 19 | 67 | 67 | 17 / 64 |
| 67 | 192.0.2.31 | 50 / 50 | no | 4 | 4 | 1 | 3 / 0 |
| 67 | 198.51.100.21 | 27 / 37 | no | 37 | 13 | 10 | 34 / 8 |
| 67 | 198.51.100.22 | 19 / 21 | no | 120 | 92 | 92 | 116 / 88 |
| 67 | 203.0.113.41 | 1 / 195 | yes | unranked | unranked | unranked | 120 / 120 |
| 67 | 203.0.113.42 | 1 / 116 | yes | unranked | unranked | unranked | 120 / 120 |
| 67 | 203.0.113.43 | 1 / 63 | yes | unranked | unranked | unranked | 120 / 120 |
| 67 | 203.0.113.45 | 2 / 118 | yes | unranked | unranked | unranked | 120 / 120 |
| 71 | 192.0.2.23 | 47 / 53 | no | 10 | 14 | 35 | 8 / 31 |
| 71 | 192.0.2.31 | 45 / 45 | no | 6 | 5 | 1 | 5 / 0 |
| 71 | 198.51.100.21 | 21 / 32 | no | 103 | 15 | 12 | 99 / 9 |
| 71 | 198.51.100.22 | 18 / 22 | no | 127 | 103 | 103 | 122 / 98 |
| 71 | 198.51.100.23 | 29 / 38 | no | 64 | 12 | 9 | 61 / 7 |
| 71 | 203.0.113.41 | 2 / 216 | yes | unranked | unranked | unranked | 126 / 126 |
| 71 | 203.0.113.44 | 2 / 114 | yes | unranked | unranked | unranked | 126 / 126 |
| 71 | 203.0.113.45 | 2 / 131 | yes | unranked | unranked | unranked | 126 / 126 |
| medium | 192.0.2.22 | 18 / 25 | no | 395 | 386 | 386 | 389 / 380 |
| medium | 192.0.2.23 | 45 / 50 | no | 29 | 176 | 235 | 27 / 231 |
| medium | 192.0.2.31 | 48 / 48 | no | 12 | 12 | 1 | 11 / 0 |
| medium | 198.51.100.21 | 21 / 30 | no | 286 | 50 | 49 | 283 / 47 |
| medium | 198.51.100.22 | 19 / 25 | no | 366 | 236 | 236 | 361 / 231 |
| medium | 198.51.100.23 | 30 / 38 | no | 287 | 212 | 211 | 283 / 208 |
| medium | 203.0.113.41 | 4 / 204 | yes | unranked | unranked | unranked | 389 / 389 |
| medium | 203.0.113.42 | 2 / 140 | yes | unranked | unranked | unranked | 389 / 389 |
| medium | 203.0.113.45 | 3 / 84 | yes | unranked | unranked | unranked | 389 / 389 |

