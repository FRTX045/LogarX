# Rule-pack ledger

Every measured pass over a detection rule pack: what it scored before and after,
what is still getting through, and what was tried and did not work — so the
next pass continues rather than repeats.

Read this before opening a rule file. Numbers are as they came out.

Recall is against the OWASP CRS regression corpus (`logarc score-crs`), over
cases that should match *and* whose payload an access log records. False alarms
are over the cases in the same family that CRS certifies as harmless.

**Since 2026-09-22 a pass that scores a real log scores it twice** — native, and
with the CRS sidecar enriching the same case. `logarc evaluate --no-crs` gets
the native figure out of an enriched case, so both come from one case. Rows
before that date have a native figure only, and saying so is cheaper than
implying the CRS column was ever checked.

| Date | Commit | Focus | Recall before → after | False alarms | Rules added |
|---|---|---|---|---|---|
| 2026-09-15 | a794fc4 | php | 15% → **68%** | 0/38 → 0/38 | 13 |
| 2026-09-15 | 4cbf0c2 | action | n/a — new tree | shopfront accuracy 0.9307 → 0.9310 | 18 |
| 2026-09-15 | 860309f | recon — **false alarms** | 0.928 → **0.943** | **20 → 0** (0.765% → 0%) | 1 |
| 2026-09-15 | 8cb5e18 | session (943) | 8% → **90%** | 0/3 → 0/3 | 1 + an engine field |
| 2026-09-20 | *this pass* | access — **false alarms** | 17,058 → 17,045 caught | **167 → 1** on `2026-09-18-medium` | 0, one recategorised |
| 2026-09-21 | *this pass* | **windows** — new pack | 932 RCE **9% → 45%** | 0/64 → 0/64, and nothing moved on the real log | 3 |
| 2026-09-21 | 080e254 | access — **the success at the end** | 17,070 → **17,073** caught on `2026-09-20-medium` | 1 → **1** | 1 |
| 2026-09-21 | 99facf8 | **ssrf** — the encoded target | 934 generic **17% → 36%**, 931 RFI 45% → 48% | 0/134 → 0/134, and **`ssrf` precision 0.429 → 1.000** on the real log | 2, one rewritten |
| 2026-09-22 | b0b6faf | **ssrf** — the off-site URL, unblocked by asking | 931 RFI **48% → 67%** *when answered*; unchanged when not | 0/134 → 0/134 | 1 |
| 2026-09-22 | 7078f19 | **crs** — the 96 false alarms | unchanged, 17,071 caught | **96 → 74 with CRS**, of which 73 an upstream corpus defect; comparable 23 → **1** | 0, two withheld |
| 2026-09-23 | *this pass* | **934** — perl, nodejs, internal names | 934 **37% → 90%**; overall 45.6% → **55.1%** | 0/134 → 0/134; real log unchanged on both engines | 5, two new packs |
| 2026-09-30 | *this pass* | **python** — new pack, Django ORM | 934 **90% → 91%** (174 → 176); overall 55.1% → **55.2%** (607/1,099) | 0/8 → 0/8 in 934, 0 in every family; excerpt and medium unchanged on both engines (medium: 1 → 1 native, 74 → 74 CRS) | 2, one new pack |
| 2026-09-30 | *this pass* | **action**: `commerce.yaml` removed, labels site-neutral | detection unchanged on the excerpt, both engines; accuracy 0.9346 → 0.9341 CRS, 0.9344 → 0.9339 native | 0 → 0 on both engines | 0, eight removed |
| 2026-10-05 | *this pass* | **942 SQLi** — dialects, fragments, and the User-Agent | 942 **23% → 79%** (31 → 106); overall 55.2% → **62.1%** (607 → 682 of 1,099) | 0/12 → 0/12 in 942, 0 in every family; excerpt and medium unchanged on both engines (medium: 1 → 1 native, 74 → 74 CRS); **one old false positive removed** (`sqli_tautology`) | 6, two extended |
| 2026-10-05 | *this pass* | **941 XSS** — called sinks, disguised tags, the User-Agent; not the Referer | 941 **36% → 81%** (26 → 58); overall 62.1% → **65.0%** (682 → 714 of 1,099) | 0/4 → 0/4 in 941, 0 in every family; excerpt and medium unchanged on both engines | 3, one extended |
| 2026-10-05 | *this pass* | **932 RCE** — globs, braces, disguised names, Windows' own tools, mail commands | 932 **45% → 70%** (183 → 285); overall 65.0% → **74.5%** (714 → 819 of 1,099) | 0/64 → 0/64 in 932, 0 in every family; excerpt and medium unchanged on both engines (medium: 1 → 1 native, 74 → 74 CRS) | 7, two extended |
| 2026-10-05 | *this pass* | **930 LFI** — traversal at a value's start, more file names, the User-Agent | 930 **23% → 97%** (7 → 29); overall 74.5% → **76.9%** (819 → 845 of 1,099) | 0/5 → 0/5 in 930, 0 in every family; excerpt unchanged on both engines after one fix; medium 17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS | 0, three extended |
| 2026-10-05 | *this pass* | **933 PHP** — the call without writing `system(` | 933 **68% → 97%** (126 → 179); overall 76.9% → **81.7%** (845 → 898 of 1,099) | 0/38 → 0/38 in 933, 0 in every family; excerpt unchanged on both engines; medium 17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS | 2, two extended |
| 2026-10-05 | *this pass* | **932 RCE**, second pass — the User-Agent that is a command line | 932 **71% → 85%** (289 → 344); overall 81.7% → **86.7%** (898 → 953 of 1,099) | 0/64 → 0/64 in 932, 0 in every family; excerpt unchanged on both engines; medium 17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS | 1 |
| 2026-10-05 | *this pass* | **the finish** — 934 and 943's last catchable shapes; every family closed out | 934 **91% → 95%** (176 → 183), 943 **90% → 92%** (36 → 37); overall 86.7% → **87.4%** (953 → 961 of 1,099) | 0 in every family; excerpt unchanged on both engines; medium 17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS | 2, three extended |

The 2026-09-20 pass is the first measured against a corpus containing a
legitimate administrator, and it went the same way round as the recon pass: it
started from what the rules got *wrong*. `admin_area_redirect` was
`access_control` at medium severity and fired on 179 requests — 13 hostile, 166
not, precision 0.073. **Those 166 were 166 of the 167 false alarms the entire
ruleset produced over 236,505 requests.** Recategorised to `authentication` at
`info`.

| medium, native only | before | after |
|---|---:|---:|
| Attack-or-not precision | 0.990 | **1.000** |
| Attack-or-not recall | 0.994 | 0.994 |
| False alarms | 167 (0.076%) | **1 (0.000%)** |
| Caught | 17,058 | 17,045 |
| Classification accuracy | 0.974 | **0.975** |
| Macro F1 | 0.728 | 0.722 |

The 13 are genuinely lost — none was independently claimed by another *hostile*
rule, only by INFO ones. Macro F1 barely moves because `access_control` loses
exactly what `authentication` gains.

**On the committed excerpt the same change scores worse**, and that is the point
worth keeping: macro F1 0.845 → 0.767, `access_control` F1 0.703 → 0.000, 13
fewer caught, because that corpus contains no legitimate administrator and so
cannot see the cost the rule was imposing. Precision there still rose to 1.000.
A pack cannot be judged on a corpus that lacks the case it gets wrong.

**Re-measured 2026-09-21 on `2026-09-20-medium`**, the rebuilt corpus whose
forced-browsing attacker now signs in, so the application's role check is
exercised and 403s exist for the first time. It held: 17,070 caught, 114 missed,
**1 false alarm in 237,278**, accuracy 0.975, macro F1 0.742. And
`admin_area_probe` — the rule an earlier note wrote off as unreachable — scores
**6 for 6, precision 1.000** on `access_control`. The rule was always right; the
data had never exercised it, which is a different defect with a different owner.

The CRS column on the same build is 1 → **96** false alarms and macro F1 0.742 →
0.701. An earlier draft of the scan dialog quoted 81, measured on the corpus this
one replaced, in the same sentence as the current 1. Two builds in one sentence,
and the sentence reads as though it came from one. Quote both sides from the same
build or quote neither.

The third pass went the other way round — it started from what the rules got
*wrong* rather than what they missed, and ended up raising both. On the labelled
real log:

| | before | after |
|---|---:|---:|
| Attack-or-not precision | 0.982 | **1.000** |
| Attack-or-not recall | 0.928 | **0.943** |
| False alarms | 20 (0.765%) | **0** |
| Classification accuracy | 0.9310 | **0.9378** |
| Reconnaissance F1 | 0.859 | **0.895** |
| Static asset false positives | 31 | **7** |

Two things paid for it, and both are worth reading before the next pass:
`http_library_user_agent` was recategorised from `reconnaissance` to `crawling`
(a User-Agent supports "automated", not "hostile"), and the sixteen catches that
cost were recovered — with eighteen more — by `project_metadata_probe`, which
names the behaviour those requests actually shared. Residual cost, stated: the
`crawling` category picks up 25 false positives it did not have, and
`authentication` one.

Collateral from the PHP pass, since the packs all load together:

| Family | Before | After |
|---|---|---|
| 931 RFI | 21% | 45% |
| 941 XSS | 18% | 35% |
| 934 generic | 15% | 17% |
| 932 RCE | 8% | 9% |
| 943 session | 5% | 8% |
| 930 LFI | 23% | 23% |
| 942 SQLi | 23% | 23% |

---

### 2026-09-21 — `attack/windows.yaml`, the pack that did not exist

The largest single gap in the tree, named by ADR-0007 a year before it was
closed. 932 RCE sat at **9%** — 368 of 406 in-reach cases missed, more than
every other family combined.

    caught      38 → 183 of 406        recall 9% → 45%
    wrongly      0 → 0 of 64
    real log    nothing moved: accuracy 0.9344, precision 1.000, 0 false alarms

Three rules. `windows_batch_for` took it to 23%, `windows_batch_if` to 44%, and
`windows_shell_invocation` added 3 — most `cmd.exe` payloads were already caught
by the first two, because they arrive inside compound FOR/IF one-liners.

**The harmless half wrote these patterns, not the attacks.** Three of the 64
certified-harmless requests decided every decision in the pack:

    /get?x=find x for y        `for` is an English word
    /get?foo=time warner       `time` is a Windows command and a company
    /get?cmd=go to store.      `cmd` is the commonest parameter name there is

So no rule matches a bare keyword. `for` needs a switch or a `%var in (` header,
`if` needs a batch operator, `cmd` needs `.exe` or a `/c`-style switch. That is
also what the pinned test proves: widening `for\s*/[dlrf]` to `for`
fails immediately on `find x for y`, by name.

Cost is linear — per-unit time flat across an 8× growth in line length (26.4 →
25.3 ms/unit), which is what the bounded `[^\s=]{1,40}` quantifiers buy.

The name was the whole reason this waited a year on a decision rather than on
work. It is **not** support for Windows log formats; `iis-w3c` has been read for
a while. Every case is an ordinary HTTP request to a web application carrying
batch syntax in a parameter — the same axis as `attack/php.yaml`.

---

### 2026-09-21 — `forced_browsing_succeeded`, and a note that was wrong

The `access` pack already read the refusals (`admin_area_probe`) and the bounce
to a login form (`admin_area_redirect`). It did not read the request in the
middle of that sequence that came back **200** — the one where somebody who
should not be there got through.

    caught      17,070 → 17,073 of 237,278
    false alarms     1 → 1
    macro F1     0.742 → 0.751
    accuracy     0.975 → 0.975
    excerpt      unchanged: 1,127 caught, 0 false alarms, macro F1 0.767

**A comment in `access.yaml` said `WindowRule` could not express this. It was
wrong, and it had been written without reading `WINDOW_METRICS`.** The rule is
an ordinary window rule: members are requests to admin paths, and the window
wants `client_error_ratio > 0` **and** `success_ratio > 0` over three of them
inside five minutes.

`client_error_ratio` is the entire discrimination, and it works for a reason
worth keeping: **a 302 is not a 4xx.** A legitimate administrator's admin
traffic is a bounce to the login form and then successes — 302, 200, 200 — so
the ratio is zero and the rule never sees them. Forced browsing is 403 on the
routes that check a role and 200 on the ones that do not. The second test in
this pass is that administrator, and it asserts nothing fires.

**Three of the eight, not eight.** The sizing entry in the project's work list counted 21
requests that are a 200 on an admin path from an address also refused there,
with 13 already flagged by the payload packs and 8 read as ordinary. This rule
moved 3 of those 8. Where the other 5 went is **not measured** — the likely
reason is that they sit below `min_requests: 3` or outside the 300-second span,
but that was not checked, and loosening either threshold was not tried. The next
`access` pass should start there, and should expect the looser window to cost
the administrator control its clean zero.

The prize is small on purpose and the argument for it is consequence, not count:
these are the requests where an attacker *succeeded*, and a forensic tool that
reads a successful privilege escalation as ordinary browsing is making a
different kind of mistake from misnaming an enumeration.


---

### 2026-09-21 — `attack/global/ssrf.yaml`, and an allow-list that was the problem

934 generic was the lowest family in the tree at **17%**, and the only one
nothing had ever been written for. Its largest single shape is SSRF whose
target has been *encoded* — the same address the plain rule already knew,
written so a search for it will not find it.

    934 generic    33 → 69 of 193        17% → 36%
    931 RFI        15 → 16 of 33         45% → 48%
    overall       462 → 499 of 1,099     42.0% → 45.4%
    wrongly         0 → 0 of 134

**The pass that raised recall started, again, by deleting something.**
`ssrf_internal_target` required the parameter to be named `url|uri|target|…`
before it would look at the address. Every corpus case uses `ssrf=`, so the
allow-list reached none of them — and a real attacker uses whatever the
application calls its parameter. The name was never the evidence.

What replaced it is a **URL scheme**, and the harmless half chose that:

    /get?x=ping 127.0.0.1        certified harmless — a diagnostic command
    /get/test?url=example.com/   a host in a parameter, no scheme, ordinary
    /get?page=12345678           a number, not an address
    /get?order=0251              a number with a leading zero, not octal

A loopback address alone cannot be the signal. `http://127.0.0.1` can.

**On the real log the allow-list turns out to have been costing precision,
not buying it.**

| excerpt | before | after |
|---|---:|---:|
| `ssrf` precision | 0.429 | **1.000** |
| `ssrf` recall | 0.600 | 0.600 |
| Macro F1 | 0.767 | **0.786** |
| False alarms | 0 | 0 |
| Caught | 1,127 | 1,123 |

The four it gave up are all `/admin/ping?host=127.0.0.1`, and **one is the
legitimate administrator at 192.0.2.22**, arriving from a browser with a
referer from `/admin/orders`. `/admin/ping` is a diagnostic tool and
`127.0.0.1` is what you point one at. The truth calls those four
`access_control` and `reconnaissance` — none of them is SSRF, so they were
hostile catches wearing the wrong name, which is exactly why giving them up
*raises* macro F1. Same shape as the `http_library_user_agent` pass.
`ssrf` recall did not move: everything the truth calls SSRF is still caught.

**Two shapes needed no rule at all**, which is worth knowing before the next
pass writes one. The normaliser folds Unicode compatibility forms, so
`acap://①②⑦.⓪.⓪.①` reaches the engine as `acap://127.0.0.1` and
`irc://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ` as `irc://localhost`. **U+3002, the ideographic full
stop, is the exception** — NFKC has no ASCII form to fold it to, so
`169。254。169。254` survives intact and needs its own pattern. Its halfwidth
sibling U+FF61 folds to U+3002, so one pattern covers both.

Cost is linear: per-unit time flat across an 8× growth in line length on all
three worst-case shapes (8.7 → 7.7, 17.4 → 16.6, 6.1 → 5.6 ms/unit).


---

### 2026-09-22 — `rfi_offsite_url`, and the entry that stopped being blocked

This one had been in *Tried and did not work* since 2026-09-21, retired with a
number: comparing a URL in a parameter against the request's own Host header
gains attacks and costs two of the 134 the corpus certifies as harmless. That
finding stands. **What changed is who answers the question.**

    unanswered   501/1,099  45.6%   wrongly 0/134   (exactly today's main)
    answered     510/1,099  46.4%   wrongly 0/134
    931 RFI       48% → 67%
    934 generic   37% → 38%
    real log     nothing moved; the fixture diff is the fingerprint alone

| how the site's own name is decided | catches | wrongly |
|---|---:|---:|
| never known — every case before this | 0 | 0 |
| guessed from the log's Host header | 11 | **2** |
| **named by the reader** | **11** | **0** |

The middle row is the whole reason this is a setting and not a rule. Behind a
reverse proxy the Host header says `localhost`, so the guess calls an ad
server's `loc=` and a plain `?url=https://example.com` attacks. Being told costs
nothing and finds the same eleven — including `Host: example.com` fetching
`https://example.com.evil.com/`, a domain bought to be misread as the site's
own, which nothing else in the tree reaches.

**Nine, not eleven, by the time it shipped.** Two of the eleven were the
backslash-escaped hosts, and the `ssrf_host_evasion` fix earlier the same day
started catching those on its own. Both numbers are right; they are from
different builds, which is the trap this ledger already has a paragraph about.

**The new field says nothing when unanswered, and does not fall back.** That is
the whole design: `query_url_offsite` reads 0 with no `site_hosts`, so a tool
nobody has configured scores exactly as it did before. The cost of never
answering is findings, never false ones.

Two notes for whoever writes the next rule that needs a per-case answer:

- **It is not in `ruleset_fingerprint`.** That digest answers "which ruleset
  produced this", and folding a per-case answer into it would make the same
  rules fingerprint differently for every case. `AnalysisResult.site_hosts`
  carries it instead, beside `crs_fingerprint`.
- **`Case.rule_engine()` is now the only place an engine is built for a case.**
  Before this there were two, and a rule that depends on case state would have
  been detected by one front end and not the other — the same failure
  `crs_evidence` was written to end.


---

### 2026-09-22 — the CRS column, measured for the first time

The user asked whether we should be tuning against CRS-on, since that is what
people will run. We were not: every committed figure was the native rules alone
and CRS lived in a prose table nothing re-ran. Scored properly, it cost **96
false alarms against the native rules' 1**, for two extra catches.

Three CRS rules were 95 of the 96, and the pass is worth reading for how the
three were told apart rather than for the total.

| rule | named a real attack | accused ordinary traffic | verdict |
|---|---:|---:|---|
| 931130 RFI: Off-Domain Reference/Link | 1 | 73 | withheld |
| 931100 RFI: URL Parameter using IP Address | 1 | 73 | **restored** |
| 932236 RCE: Unix Command Injection | 0 | 22 | withheld |

**Two traps, both new to this ledger.**

*Whack-a-mole.* 931100 and 931130 fire on the same requests. Withholding 931100
alone moved the total by zero, because 931130 took the same 73. One measurement
of the whole set would have shown that; one rule at a time did not.

*A precision figure is evidence about the corpus too.* All 73 were one line —
`/admin/import-image?url=http://203.0.113.2/assets/img/logo.png` — and the
dataset's benign admin step had named its own web container by a bridge IP. That
step exists to be the harmless twin of the attackers' metadata-hunting version,
and a literal IP in the parameter is the one feature separating them, so the
harmless example was carrying the hostile marker. **CRS was right all 73 times.**
Fixed upstream at `20a4564`. 931100 was withheld for a day on that evidence and
is restored; set the 73 aside and it scores 1 for 1.

931130 stays withheld for a reason the fix does not touch: it compares a URL's
host against the request's Host header, which Apache does not log, so the
sidecar sent `localhost` and read `shop.test` as off-domain as readily as the
IP. An unconfigured rule, not a wrong one — and `site_hosts` is the answer it
is missing. *(Corrected 2026-09-23: this said `TX:ALLOWED_HOSTS`, unread.)*

The 22 are the only ones that are plainly the rule's fault: `pipe cutter`,
`wall plugs`, `pipe`. **A plumbing shop cannot search for a pipe cutter.** Third
time this ledger has recorded that shape, after `attack/windows.yaml` and
`http_library_user_agent`.

| committed excerpt, 3,825 requests | native | with CRS |
|---|---:|---:|
| Caught | 1,123 | **1,125** |
| False alarms | 0 | 0 |
| Macro F1 | 0.7860 | **0.7961** |

On a corpus with no such defect the improvement needs no footnote.


---

### 2026-09-23 — family 934, and a classification that was wrong twice

    934 generic    71 → 174 of 193     37% → 90%
    overall       501 → 605 of 1,099   45.6% → 55.1%
    wrongly         0 → 0 of 134
    real log      unchanged on both engines, 237,278 requests — native 17,069
                  caught and 1 false alarm, CRS 17,071 and 74, before and after
    demo log      83 of 83 rules, 22 of 22 attackers, 0 of 12 ordinary accused

| rule | pack | closed |
|---|---|---:|
| `perl_array_interpolation` | `attack/perl.yaml` — new | 35 |
| `nodejs_endless_loop` | `attack/nodejs.yaml` — new | 25 |
| `nodejs_global_access` | `attack/nodejs.yaml` | 21 |
| `nodejs_prototype_pollution` | `attack/nodejs.yaml` | 9 |
| `ssrf_internal_name` | `attack/global/ssrf.yaml` | 14 |

**The classification this pass started from was wrong, and so was the one
before it.** The work list said 934's remainder was "two shapes, Node.js and
prototype pollution". A grouping pass found those two were 29 of 122, and the
largest single shape was **Perl** — `@{[system 'id']}`, 35 cases, more than both
together. Third time this ledger has recorded it: **classify by shape before
writing anything, and expect the first classifier to be wrong.**

**The harmless half wrote every Node rule.** Eight certified-harmless requests,
and four sit one character from an attack:

    foo=process.            vs  foo=process.env         a member must be named
    eval=while(!true);      vs  eval=while(true);       !true never runs
    x=#{name}               vs  x=#{process.binding()}  the braces are never it

So no Node rule matches a template delimiter, `nodejs_global_access` wants an
identifier after the dot, and `nodejs_endless_loop` is an enumeration of the
always-truthy literals rather than a pattern — JavaScript has six falsy values,
and the line between an attack and a no-op was a single `!`.

**Prototype pollution lives left of the `=`.** Eight of its nine cases carry the
payload in the parameter *name*. Every earlier rule in this tree matches a
value; a pattern written out of habit would anchor on one and miss all of them.

### Three things this pass got wrong, found by its own tests

**`ssrf_internal_name` ate a search.** Anchored at the front of a parameter
value, it matched `q=localhost tutorial` — a developer-tools shop receives that
all day. It now requires the value to *end* at the host, a port or a path. The
benign case was written first and caught it.

**An attack was pinned as benign.** `{% if True %}49{% endif %}` went onto
`NODEJS_BENIGN` under a comment claiming the corpus certifies it harmless. The
corpus says the opposite — it is an SSTI probe, with two siblings. It passed,
because nothing catches it yet, which is exactly the danger: **a benign list is
a list of things a rule must never match, so an attack on it does not merely go
unnoticed — it blocks the rule that would one day catch it.** Removed, and every
remaining entry re-checked against the corpus.

**`php_superglobal` calls every `${` an attack, and nothing has ever tested
that.** Found by trying to add `${name}` as a benign case. Zero `${` in
237,278 real requests, zero in the excerpt, zero in the harmless 134 — the rule
cannot be wrong on any corpus this project holds, which is the
`admin_area_redirect` shape again. **Not changed**, because the only evidence
was invented. Recorded in the work list as needing a corpus with an un-substituted
template placeholder in ordinary traffic.

### The demo log's CRS demonstration changed underneath it

`window_shopper` searches for `wall bracket` so that CRS 932236 calls a hardware
customer a command injection — it was written as *the* demonstration of why CRS
is enrichment rather than a verdict, and the README quoted "1 false alarm with
CRS" for it. Withholding 932236 on 2026-09-22 made that 0. CRS still detects
it and the detection still travels with the request as evidence; logarc just
labels the search a search. Re-measured rather than assumed, and the prose now
says what is true: both halves at once, what CRS says and what this tool
concluded.

### 934 still getting through — 19 of 193

| shape | count | why it is still here |
|---|---:|---|
| Django ORM lookups — `username__startswith=p` | 8 | a mass-assignment shape; needs a rule reading `__` lookups in parameter names |
| base64-wrapped payloads | 5 | `d2hpbGUodHJ1ZSk7` is `while(true);` — unreachable without decoding |
| URL credential confusion — `google.com:80 &@127.88.23.245:22/` | 3 | a parser-differential trick; needs the authority parsed two ways |
| Jinja statement tags — `{% if True %}49{% endif %}` | 1 | an SSTI probe with no arithmetic for `template_injection` to see |
| `function() {`, a Next.js `resolved_model` payload | 2 | one-offs |

The Django eight are the obvious next rule and the only shape left that is both
cheap and unambiguous. The base64 five are a normaliser question, not a rule
one.


## Still getting through

**933 PHP — 58 of 184.** Mostly separators the normaliser does not reach and
function names outside the curated list. Diminishing returns: the next ten rules
here will buy less than the first thirteen did.

**934 generic — 19 of 193, down from 124.** Closed to 90% on 2026-09-23; see
that pass above for what is left. What follows is the note from the SSRF pass
before it, kept for the history. The encoded-SSRF half is closed
(2026-09-21). What is left is two other shapes entirely, counted on the misses:
**Node.js reached through a template or a prototype** — `process.env`,
`require.main.constructor._load('child_process')`, `new Function(`, `#{…}`
interpolation — and **prototype pollution** in the parameter *name* rather than
its value: `__proto__[test]=`, `constructor[prototype][test]=`. Neither is SSRF
and neither belongs in this pack. The harmless half already names the trap for
the first: `/get?foo=process.` and `/get?foo=console.` are certified harmless,
so a bare prefix is not enough and the member access has to be required.

**932 RCE — 223 of 406, down from 368.** The Windows half is closed:
`attack/windows.yaml` landed 2026-09-21 and took the family from 9% to 45%.

What is left is **not Windows and does not belong in that pack**, measured by
shape on the remaining misses:

| shape | count | where it belongs |
|---|---:|---|
| glob and bracket evasion — `/etc/pas[s]wd`, `/[e///]tc` | 13 | `shell.yaml` or `global/files.yaml` |
| bash arithmetic and substitution — `$(($() 42))`, `>(tee log)`, `$[]` | 9 | `shell.yaml` |
| Unix built-ins reached without a metacharacter | 21 | `shell.yaml` |
| unclassified | 162 | needs the same grouping pass doing again |

The 162 unclassified is where the next pass should start, and the lesson from
this one applies to it: **classify by shape before writing anything, and expect
the first classifier to be wrong.** The first grouping here put 211 misses in
"unclassified" because its `if` pattern only knew `exist|defined|errorlevel` and
its `for` pattern only allowed a single-character variable — 58 batch
comparisons and 16 `%variable` loops were sitting in that pile unseen.

**942 SQLi — 29 of 135** (104 before 2026-10-05). Left on purpose: a quoted word on
its own (`?'bla'`), bare numbers (`4294967296`, `2.2250738585072011e-308`), `like null`,
`something like '`, and function names that are not calls (`select pg_sleep`,
`sql_table=pg_catalog`) — each is ordinary text more often than an attack. Also left:
MySQL JSON-path comparisons (`'{...}' < '$.c[2].f' = 7`, 2), `9999 or {if length((` (3),
`div(23,-2)` (2), squashed `xunionselectfrom`, and three User-Agent payloads with no
cast (`json_search(json_array(password),...)`, `starts_with(password) and 'true`).

**930 LFI — 23 of 30.** Windows path separators (`..\`), and `..;` semicolon
traversal. Small family; low value.

**943 session — 4 of 40, down from 37. Unblocked 2026-09-15 by an engine
change, not a pattern.** The reason first recorded here was wrong twice over: it
said these were cookie shapes an access log cannot see, and they are session
identifiers in the *query string*, which it records in full.

What actually blocked them was that no rule could compare two fields. The corpus
puts it plainly — these two are character-for-character identical:

| URL | Referer | verdict |
|---|---|---|
| `/login?sessionid=abc123` | `https://myapp.com/previous-page` | benign |
| `/login?sessionid=abc123` | `https://attacker.example.com/` | attack |

`RequestView.referer_offsite` now answers it, and `session_fixation` reads it.

**Its reach is narrower than the number suggests, and this matters more than the
90%.** It needs the Host header, and `apache-combined`, `apache-common` and
`nginx-combined-forwarded` do not record one — so on the most common web log
format in the world the field has no answer, reads 0, and the rule never fires.
It works on the vhost Apache formats, every JSON format (Caddy, Cloudflare,
nginx, ECS, GCP, Traefik) and `iis-w3c`. The shopfront excerpt is
`apache-combined`, which is why this pass moved nothing at all on the real log:
the fixture diff is one line, and that line is the fingerprint.

**931 RFI — 22 of 33 when the case names its own domains, 16 when it does
not.** The cap that stood at 45% for a week was never a pattern problem: it
needed a fact no access log records. `rfi_offsite_url` shipped 2026-09-22 and
asks for it. The remaining 11 are bare scheme names (`/get?x=http?`), a port
that differs on the same host, and userinfo tricks that a strict host parse
reads correctly — none of them reachable by naming domains.

---

## Tried and did not work

**Comparing the request's host against a URL in a query parameter.**
*Superseded 2026-09-22 — the comparison shipped, against domains the reader
names rather than against the Host header. The finding below is why it is not
the header.* Built as a probe on 2026-09-21 and measured across all nine
families: it **gains 38 attacks nothing catches today and costs 2 of the 134 the
corpus certifies as harmless**.
The two are `/page?url=https://example.com` and an ad server's
`loc=https://www.example.com/...` — genuinely off-domain URLs in a parameter,
and no host comparison can tell them from `/get?x=https://foo.bar`. CRS
separates them against the request's own Host header, which Apache does not
log, so logarc had no true value to give it. *(Corrected 2026-09-23: this said
`TX:ALLOWED_HOSTS`, unread.)*

**31 of those 38 did not need it.** They were 934's encoded SSRF targets, which
shipped the same day at zero cost because an internal address is never a public
one. What the comparison uniquely buys is the 7 in 931 — and 2 false alarms is
too much for 7. The entry in the work list stays blocked, but it is blocked with a
number now instead of an argument.

**A bare off-domain URL as remote file inclusion.** `=\s*(https?|ftps?)://` took
931 RFI from 21% to 64%, and fired on `/page?url=https://example.com` and on an
ad server's `loc=` parameter — two of the 64 harmless RCE cases. Passing a URL in
a query string is one of the most ordinary things on the web. CRS tells the two
apart by comparing the URL's host against the site's own; **the rule engine
cannot compare two fields**, so this is not a pattern problem and no amount of
rewriting the regex will fix it. Settled at 45% with a second signal required.
Revisit only if the engine grows field-to-field comparison.

**`?>` as a PHP close tag.** Every XML declaration ends in one. Five of the 38
harmless PHP cases are XML documents passed as a parameter, which is a real thing
APIs do. Caught nothing the open-tag rule missed.

**A "Product View" action rule.** 767 of 814 requests to `/p/…` in the shopfront
excerpt are one crawler working through the catalogue, and the rule took every
one of them away from the crawler branch. Product and category pages are
browsing; the fallback ladder already says so.

**New `ActivityCategory` members for actions** (`transaction`, `search`).
`excerpt.truth.jsonl` comes from an external dataset that is not in this
repository, so its taxonomy cannot be regenerated and every request carrying a
new category scores as wrong. Few categories, many names.

## 2026-09-23 — `site_hosts` reaches CRS; 931130 conditional

Not a rule-pack pass, but it moves what 931130 may do, so it is recorded here.

- `enrich` sends the case's primary domain as the Host header; the engine
  trusts 931130 only when that domain covers every named one (`host_speaks_for`).
- Medium build, unanswered: identical on both engines (native 17,069 / 1,
  CRS 17,071 / 74).
- Medium build, `shop.test` named: CRS 17,071 / 74 unchanged; native
  17,069 / 1 → 17,070 / 74. The 73 are the bridge-IP line (`20a4564`), which
  `rfi_offsite_url` now reads as off-site — correctly, on a mislabelled request.
- 931130 fired on 78 requests there, trusted on all 78, **named none**: the
  native rules name every one first and CRS only rescues INFO. The gain has to
  be looked for on the rebuilt tiers, not claimed from this one.

**Tried and wrong:** the mechanism. `TX:ALLOWED_HOSTS` was asserted in four
places and relayed to the dataset project without anyone opening the rule. It
did not change the conclusion, but it did hide how small the fix was — the
sidecar already had `--host`.

### 2026-09-30 — `attack/python.yaml`, the Django ORM

    934 generic    174 → 176 of 193     90% → 91%
    overall        605 → 607 of 1,099   55.1% → 55.2%
    wrongly        0/8 in 934, 0 in every family
    excerpt        only ruleset_fingerprint moved, native and CRS
    medium         17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS

Two rules, and **six of the eight Django misses left uncaught on purpose.** A
lookup is how Django filters: django-filter emits `?price__gte=100` and the admin
writes `?is_staff__exact=1` into its own user list. CRS draws the same line —
single-level lookups (934210) fire only at paranoia level 3. So the evidence has
to be what a lookup is *aimed at*:

- `django_orm_secret_probe` — a pattern or range lookup on a password, token,
  secret or key field (`user__password__startswith=`). Nothing filters a page
  by a password prefix; it is how a hash is read out one character at a time.
- `django_orm_privilege_key_probe` — `has_key`/`has_keys`/`has_any_keys` naming
  a privilege flag (`data__has_key=is_admin`).

Pinned both ways in `tests/detect/test_rulepacks.py`: `PYTHON_ORM_PROBES` (7)
and `PYTHON_ORM_BENIGN` (10), the benign list including the single-level corpus
shapes, so a later "improvement" that catches them has to say so. Cost checked:
linear on four worst-case shapes up to 8,000 units.

**Still getting through in 934 — 17 of 193.** Six single-level Django lookups
(deliberate, above); base64-wrapped payloads (5, a normaliser question); URL
credential confusion (3, needs the authority parsed two ways); one Jinja
`{% if %}` probe; two one-offs.








### 2026-10-05 — the finish: what is left in every family, and why

    overall        953 → 961 of 1,099   86.7% → 87.4%
    wrongly        0 in every family
    excerpt        only ruleset_fingerprint moved, native and CRS
    medium         17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS

**This is the last recall pass against the CRS corpus.** Decided with the user
the same day: CRS is to become the default, the native rules already catch
~99.5% of attacks on the final 2026-10-04 dataset tiers with no false alarm,
and the corpus passes (55.2% → 87.4%) moved none of those tiers. Native work
continues on *activity* understanding, which CRS cannot do. What follows is
the record that closes the attack side: every miss is either caught or listed
here with the reason it stays.

Caught by this pass: node-serialize's `_$$ND_FUNC$$_` marker and its base64
form (`nodejs_serialized_function`), a React Server Components reference
reaching a prototype (`"$7:module:prototype"`, the React2Shell shape, in
`nodejs_prototype_pollution`), a Jinja/Twig block that opens and closes in one
value (`template_injection`), URL-parser confusion with an internal host after
`&@` or `# @` (`ssrf_host_evasion`), and a cookie planted by injected script,
`document.cookie='sid=...;expires=...'` (`session_cookie_injection`). Three of
my own probes broke first drafts and are pinned in `FINISH_BENIGN`: "jinja
{% if %} syntax", "contact me @ 10.0.0.1", "$5:off:prototype".

| family | caught | what is left, and why it stays |
|---|---:|---|
| 930 LFI | 29 / 30 | `>/tmp/curl` — the corpus certifies `>/tmp` as harmless, so a redirect alone is not evidence |
| 931 RFI | 16 / 33 | bare off-site URLs and look-alike hosts (`example.com.evil.com`) — indistinguishable from a redirect or share link until the case names the site's own domain, which `rfi_offsite_url` then reads (2026-09-22 entry). The `url/@evil.com` trick is everyday on `medium.com/@user` links |
| 932 RCE | 344 / 406 | 22 in the Referer (the next click after an attack page — see the 941 entry), 3 in the User-Agent, bodies no log records, bash history (`!!`, `!-1`), bare mail verbs, `alias`, `pip install`, and five the corpus files as attacks that read as English |
| 933 PHP | 179 / 184 | unclosed calls (`base64_decode(`), `crypt(abc)`, `file ()`, `$_s erver` — the truncated shape the pack declines on purpose |
| 934 generic | 183 / 193 | six single-level Django lookups (how Django filters), base64 payloads whose case normalisation destroys (`d2hpbguo...`), URL credential confusion, `function() {` |
| 941 XSS | 61 / 72 | 8 in the Referer (kept out, measured), a request body, handlers in a parameter name led by a space that normalisation trims |
| 942 SQLi | 106 / 135 | a quoted word alone, bare numbers, `like null`, names that are not calls (`select pg_sleep`), JSON-path comparisons |
| 943 session | 37 / 40 | session ids that only a cookie or an off-site Referer on a Host-less log format would reveal |
| 944 Java | 6 / 6 | — |

### 2026-10-05 — 932 again: the User-Agent that is a command line

    932 RCE        289 → 344 of 406      71% → 85%
    overall        898 → 953 of 1,099   81.7% → 86.7%
    wrongly        0/64 in 932, 0 in every family
    excerpt        only ruleset_fingerprint moved, native and CRS
    medium         17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS

After the first 932 pass, 85 misses carried the payload outside the URL: 22 in
the Referer (left out on purpose, as for XSS) and 58 in the User-Agent — and in
those the User-Agent *is* the command: `ansible all -m ping`, `env --version`,
`set -o history`, `chef-shell`, `;chmod`, `a=nc&&$a`. One rule,
`shell_command_as_user_agent`, reading only that field, took 55 of the 58.

Clients name themselves `name/version` (`curl/8.6.0`, `Wget/1.21`,
`python-requests/2.32`), so a command followed by a slash is a client. Two
drafts broke on real-world agents before it was written: "ID Scanner 2.0" (so
short words — `id`, `set`, `cat`, `sh` — count only before a flag, a path or a
variable) and bare `curl` and `Ruby` (so only admin tools no client is named
after — `visudo`, `chef-shell`, `ansible-*` — count as a whole User-Agent).
Pinned in `test_ordinary_user_agents_are_not_command_lines`; the 70 distinct
benign agents from both medium tiers still fire nothing.

**Still in the User-Agent — 3:** `id` alone, `time ifconfig`, and a PHP
`system('...')` call, which the PHP rules do not read the User-Agent for
(`Operating System (Linux)`-style agents would make `system(` there costly).

### 2026-10-05 — family 933, the call without writing it

    933 PHP        126 → 179 of 184      68% → 97%
    overall        845 → 898 of 1,099   76.9% → 81.7%
    wrongly        0/38 in 933, 0 in every family, after every rule
    excerpt        only ruleset_fingerprint moved, native and CRS
    medium         17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS

The first PHP pass required the call to be written and closed — `exec (` is a
truncated string, `system('id')` an attack — and that is still right. What it
left were calls that never write the name next to its parenthesis:

| change | 933 caught after | shape |
|---|---:|---|
| `php_short_tag` and `php_stream_wrapper`, extended (measured together) | 138 | `<?xml :echo 1;` — the `(?!xml)` exclusion was the disguise; a real declaration has `version=`, a stylesheet is `<?xml-stylesheet`, both certified harmless — and `ssh2.exec://`, `ssh2.shell://`, the other SSH2 wrappers |
| `php_indirect_call` | 169 | `(system)(ls)`, `[system][0](ls)`, `(['system'])[0]('id')`, `'sys'.'tem'`, `sy.(st).em`, `foogzinflate()` |
| `php_variable_function` | 179 | `$a()`, `$f(101).$f(120)`, `$__[_](24)`, `@$b374k("foo")` |

The corpus's 38 harmless cases decided the guards, as they did the first time:
`(foo)bar or foo(bar) or [foo]bar or foo[bar]` is why a bracketed name counts
only when indexed and a parenthesised one only when called at once — and a
probe of my own, `[system] (docs)`, broke the first draft of exactly that.
`cheval($foo)` and `filemtime($foo)` are why a variable call must open on a
number, a quote or close at once; `$10 (sale)` is why the name must start with
a letter. All pinned in `PHP_INDIRECT_BENIGN`.

**Still getting through — 5 of 184.** An unclosed `base64_decode(` (twice),
`crypt(abc)`, `file ()` and `$_s erver[...]`: the first three are the
truncated-call shape the pack declines on purpose (the corpus certifies
`exec (` as harmless), and the last is a superglobal broken by a space.

### 2026-10-05 — family 930, and the 31 scanners that were reconnaissance

    930 LFI        7 → 29 of 30          23% → 97%
    overall        819 → 845 of 1,099   74.5% → 76.9%
    wrongly        0/5 in 930, 0 in every family
    excerpt        only ruleset_fingerprint moved, native and CRS — after one fix, below
    medium         17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS

No new rule ids; three existing rules extended.

- `path_traversal`: a traversal that starts a parameter value
  (`?arg=..\pineapple`, `?code=../.history`) and Tomcat's `..;`.
- `sensitive_file_access`: more of what a file read asks for — `/etc/subuid`,
  `/proc/net/tcp`, `/sys/class`, anything under `/root/.`, `.ssh/id_rsa`,
  `.aws/credentials`, a Docker secret, a package manifest under
  `node_modules`, and Vite's `/@id/__x00__` — and it reads the User-Agent,
  where ten corpus cases put `cat /root/.ssh/id_rsa` and the like. A browser's
  User-Agent never names a file on the server.
- `backup_file_probe`: a dump named in a parameter by its double extension
  (`?code=backup.sql.zip`), so a plain `report.sql` download stays out.

**The excerpt caught the first draft.** With the new file names matched
anywhere in the target, accuracy fell 0.9339 → 0.9258 and macro F1
0.7855 → 0.7419 with detection unchanged: 31 requests the truth calls
reconnaissance had become path traversal. All 31 were `GET /.aws/credentials`
— scanners asking for a file left in the web root, which is
`config_file_exposure`'s question, not a read through the application. The
names now count in a parameter or the User-Agent, and only Vite's
`/@id/__x00__` matches the path, because there the path is the read. Recall
did not move. `test_asking_for_a_secret_file_by_path_is_still_reconnaissance`
pins it, and fails if the path match is put back (checked).

**Still getting through — 1 of 30:** `?code=>/tmp/curl`, a redirection into
`/tmp`. The corpus certifies `?code=>/tmp` itself as harmless, so the redirect
alone cannot be the evidence; left.

### 2026-10-05 — family 932, the forms written to get past a word filter

    932 RCE        183 → 285 of 406      45% → 70%
    overall        714 → 819 of 1,099   65.0% → 74.5%
    wrongly        0/64 in 932, 0 in every family, after every rule
    excerpt        only ruleset_fingerprint moved, native and CRS
    medium         17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS

What the earlier passes left in 932 was mostly not new commands but old ones
dressed to slip past a filter that knows their names. Each shape was tried
against the 64 requests the corpus certifies as harmless, and against searches
written to break it, before it went into a pack; five of those searches did
break a first draft and are now pinned in `RCE_BENIGN`.

| rule | 932 caught after | shape, and what kept it honest |
|---|---:|---|
| `shell_glob_path` | 204 | `/etc/pa[s]swd`, `/[e//]tc`, `/???/??t`, `/usr/[a-z]in/bash` — only inside an absolute path, so the corpus's `?page=page[1]` and `field_metatags[0][advanced]` stay out |
| `shell_brace_expansion` | 214 | `{,ifconfig}`, `c{a,oun}t`, `{l,-lh}s` — JSON never opens with `{,`; set notation `a{b,c}` broke the first draft |
| `shell_disguised_command` | 229 | `'wh'oami`, `""p""y""t""h""o""n`, `ti''me sh -c whoami` — three empty quote pairs, because one is how SQL escapes `o''brien`; `time` only where a command starts, because the corpus certifies `time warner` and "what time who wins" broke the first draft |
| `shell_syntax_in_value` | 241 | `pi$()ng`, `ping```, `>(tee log)`, the fork bomb, `$d/tcp/` |
| `shell_invocation` | 261 | `bash -c "..."`, `$shell -c`, `;ps`, `;who`, `ll /var/www/`, SQLite `.shell`/`.system` — `-c` must be followed by a quote, `$` or a command, because "bash -c example" broke the first draft |
| `mail_command_injection` | 268 | `mail from:<`, `rcpt to:<`, `ehlo host.tld`, IMAP `a001 examine`; and, written for the demo log, the real arrival after an encoded line break (`%0d%0arcpt to:<`), which normalisation turns into a space — that form caught one more corpus case |
| `windows_batch_for` / `_if`, extended; `windows_living_off_the_land` | 285 | `for %- in (`, `if/i`, `if "a a" == "a a"`; `certutil -urlcache`, `mshta http:`, `regedit /e`, `bcdboot`, `; at 2:00` |

The new shell rules read the User-Agent by alias. Every distinct User-Agent on
the benign lines of both medium tiers, plus a handful chosen to be awkward (a
Sharp phone's `SH-04F`, `Wget/1.21` inside a compatible string, a quoted word),
was run through the whole rule set: none fired — 70 agents, which is a
small sample, so `command_injection` itself is left reading the target only.

**Still getting through — 121 of 406.** 85 carry the payload outside the URL
(38 bare `/get`, 45 `/post`, 2 `/`): headers this pass did not open to the
older rules, and bodies no log records. Of the 36 in the query: bare mail verbs
(`quit`, `list 3`, `help postmaster` — words, left on purpose), bash history
(`!!`, `!-1`), `~-`, `$[]`, `alias a=b`, `pip install`, `python3.10 cmd`,
`bin/ansible`-style paths, `'i'p a`; and five the corpus files as attacks that
read as English (`o'keefe's`, `that's two "o"s in goose`, `size: 8"x11"`,
`''that's the joke''.jpeg`, `go to store. at the store, shop.`), which no
pattern here should ever take.

Found on the way, for its own change: six injection rules carry `A03:2025`,
which in the 2025 list is *Software Supply Chain Failures*; injection is
`A05:2025`. They read like the 2021 numbering, where A03 was injection.

### 2026-10-05 — family 941, and why the Referer stays unread

    941 XSS        26 → 58 of 72         36% → 81%
    overall        682 → 714 of 1,099   62.1% → 65.0%
    wrongly        0/4 in 941, 0 in every family, after every rule
    excerpt        only ruleset_fingerprint moved, native and CRS
    medium         17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS

**The headers, measured before they were read.** Both XSS rules' patterns were
run over the Referer and User-Agent of every line the truth calls benign, on
`2026-09-20-medium` and the final `2026-10-04-medium` (about 237,000 lines
each). The User-Agent matched nothing. The Referer matched one benign line on
each tier, and it was the same shape both times: `GET /contact` arriving from
`/search?q="><img src=x onerror=alert(1)>` — the visitor's *next* click,
still carrying the payload the previous line was already caught for. So the
XSS rules read the User-Agent and not the Referer, and
`test_a_referer_carrying_the_last_page_s_payload_is_not_an_attack` fails if
anyone changes that (checked by adding the Referer and watching it fail).

| change | 941 caught after | what it reads |
|---|---:|---|
| User-Agent on the two existing XSS rules | 30 | the field |
| `xss_sink_call` | 38 | `alert()`, `prompt()`, `settimeout(` as the whole value or after a breaking quote, `;` or `(`; `.call``` |
| `xss_event_handler`, extended | 42 | any `on…=` after a closing quote or inside a tag, `formaction=` — not after `/`, which is the corpus's harmless base64 `…/onafe=` |
| `xss_obfuscated_tag` | 51 | `<f o r m`, `<d i a l o g` (tag names that run script, spaced), `< x: script`, `%u00abscript%u00bb` |
| `xss_style_and_markup` | 58 | `url(javascript`, `-moz-binding:`, `<object … data`, `<base`/`<link … href` |

The spaced-tag pattern caught `a <b c d e` in its first draft, and was cut to
tag names before it was written; the ordinary searches it was tried on are in
`XSS_BENIGN`.

**Still getting through — 14 of 72.** Eight carry the payload only in the
Referer (kept out, above); one is a request body; three put the handler in the
parameter *name* led by a space (`? onabcdefgh= =vardata`), and normalisation
trims the space that told it apart from `?online=1`; two one-offs
(`<importimplementation=`, `"in valueof=`).

**Also seen while re-scoring the final tiers, for a later pass:** on
`2026-10-04-small` one of CRS's two false alarms is the same Referer shape —
942200 on `GET /c/safety` arriving from a page whose URL held a UNION SELECT.
CRS reads the Referer and the engine trusts what it finds there. Whether to
withhold CRS matches whose only matched variable is the Referer is a mapping
decision, to be measured on all three tiers rather than argued.

### 2026-10-05 — family 942, and a field no attack rule was reading

    942 SQLi       31 → 106 of 135      23% → 79%
    overall        607 → 682 of 1,099   55.2% → 62.1%
    wrongly        0/12 in 942, 0 in every family, after every rule
    excerpt        only ruleset_fingerprint moved, native and CRS
    medium         17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS

**The User-Agent first.** 14 of the 15 bare-`/get` misses carried their payload
in the User-Agent, which the combined format records in full and no attack rule
read. Across all families the count was **127 misses: 94 in the User-Agent, 33
in the Referer**, unreachable by any target-only rule. The SQL rules now read
`user_agent_decoded` too, each pattern written once as a YAML anchor on the
target condition and repeated by alias, so the two cannot drift. Not the
Referer: it can innocently carry another site's URL, search query included,
and nothing in this pass measured that cost.

Then one rule per shape, measured after each:

| rule | 942 caught after | what it reads |
|---|---:|---|
| User-Agent on the seven existing SQL rules | 33 | the field, not a pattern |
| `sqli_postgres_cast` | 54 | `::int`, `::jsonb`, `::double precision` — type names only, so `std::vector`, `u32::max` and `fe80::1` stay out |
| `sqli_postgres_functions` | 56 | `lo_get(`/`lo_import(`, `pg_read_file(`, `overlay(... placing` |
| `sqli_boolean_fragment` | 75 | `' or xyz-`, `xor 99>` — `or` pinned after a quote or at the start of a value, then one operand and a comparison |
| `sqli_stacked_query`, extended | 80 | `;droptable`, `;truncate[`, `';print'`, a whole value of `drop t;--` |
| `sqli_statement_fragment` | 95 | `in ( select`, `having count(`, `case when` after `=`/`(`/`,`, `xp_cmdshell`, `execute immediate`, `if(1=` |
| `sqli_sqlite_glob` | 99 | `glob 1`, `glob password` |
| `nosql_injection`, extended | 100 | `[$lte]` and the operators it lacked, bracketed |
| `sqli_numeric_tautology` | 106 | a whole value of `1=1`, `b,1=1`, `42<=>42` |

**Every pattern was tried on ordinary text before it was written** — searches
a person types about SQL and spreadsheets (`how to create table in excel`,
`select a size from the list`, `everything except values`), English with `or`
in it (`tea or coffee > milk`, `l'or bleu - prix`), arithmetic (`2 2=4`,
`1+1=2`). One was caught that way: `case when` read `in case when it rains
then` until it was pinned to where SQL puts it. All of them are in
`SQLI_BENIGN`, beside the corpus's twelve.

**And an old false positive came out.** Pinning those searches against the
whole pack showed `sqli_tautology` calling `a xor b = c` an attack: its
`(or|and)` had no left boundary, so `xor`, `minor version = 2`, `brand new =
yes` and `for i = 1` all ended in one. No letter may now precede it; a digit
still may, so the glued evasion `1and 1=1` stays caught. Recall did not move.

Confidence is set against triage's 0.85: the casts and fragments that a search
for SQL itself could produce sit below it (0.65–0.8); the PostgreSQL server
functions, an exact exploit shape, at 0.9. Cost checked: linear on eleven
worst-case shapes up to 16,000 units. The demo log gained `192.0.2.123`, a tool
fingerprinting the database dialect by dialect, so it still reaches every rule
(83 of 83).

### 2026-09-30: `action/commerce.yaml` removed, and the labels presume no kind of site

Eight rules gone: View Cart, Modify Cart, Checkout, Payment, Order History,
Wishlist, Stock Check and Order Tracking. "Checkout" or "Payment" asserts what a
person did, and on a site that sells nothing it is false: the pack named
`/transactions` "Payment" at 0.95 and `/invoices` "Order History" at 0.85
for any client not calling itself a bot. The requests now get what any site's would: "Page
View", "API Call", "Form Submission" or "Account Area".

    source         tests/data/apache-shopfront/excerpt.log, 3,825 lines
                   sha256 b4912a92181e0d6a3144ae31c79091dbd15886885d64787dd4d99bc690eaa6ce
    truth          tests/data/apache-shopfront/excerpt.truth.jsonl
                   sha256 2da65d2a847d5ae9780067350db98284f14038148a9abc1fc7fb6d957df3f7b9
    base           4e930fe
    ruleset        85 rules, 23ab54d9e0693a816ba77a178a23aed0c46895db36ed7d2e6b97449770643aed
                →  77 rules, 699bdd54762b02c2d8e76a2d87eee0147c54833d0ab26310f285a2dad5e85040
    CRS            d694d465951e, configuration 1c4b66d67838c5e8, paranoia level 2
    policy         evaluate defaults: episode gap 300 s, idle timeout 1,800 s,
                   noise absorption on (3 requests, 60 s), evidence sample 20

| committed excerpt, 3,825 requests | native before | native after | CRS before | CRS after |
|---|---:|---:|---:|---:|
| Caught | 1,123 | 1,123 | 1,125 | 1,125 |
| False alarms | 0 | 0 | 0 | 0 |
| Attack-or-not precision | 1.000 | 1.000 | 1.000 | 1.000 |
| Attack-or-not recall | 0.9289 | 0.9289 | 0.9305 | 0.9305 |
| Classification accuracy | 0.9344 | 0.9339 | 0.9346 | 0.9341 |
| Macro F1 | 0.7860 | 0.7855 | 0.7961 | 0.7956 |
| Weighted F1 | 0.9350 | 0.9345 | 0.9353 | 0.9348 |
| `browsing` recall | 0.899 | 0.886 | 0.899 | 0.886 |
| Episodes | 584 | 583 | 582 | 581 |
| Boundary F1 | 0.6281 | 0.6289 | 0.6297 | 0.6305 |

Before and after are the same enriched case evaluated twice, native with
`--no-crs`, so the source lines and `crs.jsonl` are identical and only the
ruleset differs. Both "before" outputs are identical to the fixtures committed
at 4e930fe, and both "after" outputs are identical to
`excerpt.scores.json` and `excerpt.scores.crs.json` regenerated from fresh
cases. To reproduce the before side, check out 4e930fe; for the after side, the
commit that removes the pack. Then run the two recipes in
`tests/evaluation/test_published_scores.py`.

**Detection did not move; category agreement lost two requests.** Both are
`GET /cart` from `python-requests/2.32.3`, which the truth calls `browsing`.
"View Cart" (0.85) used to name them. Now the only rule that matches is
`http_library_user_agent` ("Scripted Client", `crawling`, 0.4), and a rule
match keeps the fallback's "Page View" from being consulted, so they land in
`crawling`. Each engine also found one episode fewer, with boundary precision
up slightly; which boundary moved was not traced.

**Still getting through: scripted traffic is not necessarily crawling.** A
script on a page no action rule describes is filed as `crawling`, whatever it
asked for. Two requests on the excerpt; left alone here because it is a
question about `http_library_user_agent` and the fallback, not about what the
action pack presumes.
