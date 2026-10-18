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
| 2026-10-05 | *this pass* | **engine** — Apache talking to itself is not a client | detection unchanged everywhere; **`2026-09-20-medium` macro F1 0.8103 → 0.8656 native, 0.7628 → 0.8180 CRS**; `2026-10-04-medium` 0.8146 → 0.8716 native | 1 → 1 native, 74 → 74 CRS on medium; 0 → 0 on `2026-10-04-medium`; excerpt unchanged (none in it) | 0, one ladder branch |
| 2026-10-05 | *this pass* | **engine** — a script is described by what it asked for | detection unchanged everywhere; excerpt accuracy 0.9514 → **0.9561** native, 0.9516 → **0.9563** CRS; `2026-10-04-medium` 0.9950 → 0.9953 | 0 → 0 excerpt; medium 1 → 1 native, 74 → 74 CRS; `2026-10-04-medium` 0 → 0 both | 0, one engine function |
| 2026-10-05 | *this pass* | **action** — crawlers that never say `bot` | detection unchanged everywhere; **excerpt accuracy 0.9339 → 0.9514 native, 0.9341 → 0.9516 CRS**; `2026-10-04-medium` 0.9929 → 0.9950 native | 0 → 0 excerpt; medium 1 → 1 native, 74 → 74 CRS; `2026-10-04-medium` 0 → 0 both | 0, the crawler list extended in two places |
| 2026-10-05 | *this pass* | **php** — a `${name}` placeholder is not PHP | 933 **179 → 178**, 941 61 → 61 after one recovered; overall 961 → **960** of 1,099 | 0 in every family; excerpt unchanged on both engines; the dataset's 41 / 129 / 659 placeholder requests no longer injection | 0, one narrowed, one widened |
| 2026-10-05 | *this pass* | **recon** — content-discovery tools are enumeration | corpus unchanged, 961 of 1,099; medium caught 17,069 → 17,069 native, 17,071 → 17,071 CRS; **medium accuracy 0.9751 → 0.9945 native, 0.9747 → 0.9941 CRS** | 0 in every family; excerpt unchanged on both engines; medium 1 → 1 native, 74 → 74 CRS | 1, one narrowed |
| 2026-10-05 | *this pass* | **the finish** — 934 and 943's last catchable shapes; every family closed out | 934 **91% → 95%** (176 → 183), 943 **90% → 92%** (36 → 37); overall 86.7% → **87.4%** (953 → 961 of 1,099) | 0 in every family; excerpt unchanged on both engines; medium 17,069 / 1 → 17,069 / 1 native; 17,071 / 74 → 17,071 / 74 CRS | 2, three extended |
| 2026-10-06 | *this pass* | **injection** — an injection that reaches for secrets is `exploitation` | corpus unchanged, 960 of 1,099; caught unchanged everywhere; **`exploitation` 4/8 → 6/8 excerpt and medium, 4/9 → 7/9 small, 0/2 → 2/2 large**, precision 1.000 | 0 → 0 everywhere native; CRS unchanged | 1 |
| 2026-10-06 | *this pass* | **access** — forced browsing with nothing refused; the first `sequence` rule | corpus unchanged, 960 of 1,099; **caught +15 on the excerpt, small and medium, +10 on large** (medium 17,044 → 17,059 native); **`access_control` 0/24 → 15/24 excerpt, 9/31 → 24/31 medium**, precision 1.000 | native 0 → 0 everywhere; with CRS unchanged (small 1 → 1, the click ID) | 1, and a new rule kind |
| 2026-10-06 | *this pass* | **crs** — the `${name}` placeholder, from the other engine | corpus unchanged (native only); caught unchanged on all three `2026-10-06` tiers, both engines (small 4,016, medium 17,045, large 40,613); **CRS macro F1 0.8412 → 0.8600 small, 0.8286 → 0.8687 medium, 0.7703 → 0.8293 large** | **CRS 45 → 1 small, 149 → 0 medium, 670 → 0 large**; native 0 → 0 on all three; excerpt and demo contain no `${name}` | 0, one engine condition |
| 2026-10-06 | `52fd2c2` → `a37bc2b` | **command injection and 942 union select**: after `&` a command word is not an injection when a parameter `=` follows it, so `?sort=price&cat=shoes` and `&cat[]=` no longer match; `sqli_union_select` needs `union` not preceded by a letter and `select` as a whole word, so `reunion select` and `credit union selection` no longer match while number-adjacent evasions such as `1e0union select` and `union(select 1)` still do | corpus unchanged, 960 of 1,099 (942 106 of 135, 79%; 932 344 of 406, 85%); `score-crs` output byte-identical on `52fd2c2` and `a37bc2b`, CRS corpus at `d694d465951e` | 0 in every family (942 0/12, 932 0/64); excerpt unchanged on both engines, only `ruleset_fingerprint` moved; medium and other real-log columns not measured | 0, two narrowed |
| 2026-10-09 | *this pass* | **recon** — sqlmap, havij, commix and ghauri are injection tools | corpus unchanged, 960 of 1,099; caught unchanged everywhere; **`injection` 51/57 → 56/57 excerpt, 52/59 → 57/59 small, 47/53 → 52/53 medium, 46/51 → 51/51 large**, both engines; `reconnaissance` predicted 5 fewer a tier, every one right | 0 → 0 everywhere native; CRS unchanged (small 1, the click ID) | 1, one narrowed |
| 2026-10-09 | *this pass* | **ssrf** — a `file://` fetch of a system file is SSRF, not path traversal | corpus unchanged, 960 of 1,099; caught unchanged everywhere; **`ssrf` 3/5 → 4/5 on the excerpt and every tier** (excerpt 4/5 → 5/5 with CRS); `path_traversal` loses its one wrong answer on each | 0 → 0 everywhere, both engines | 1 |
| 2026-10-09 | *this pass* | **access** — verb tampering, on a new `distinct_methods` window metric | corpus unchanged, 960 of 1,099 (a window rule cannot fire on one request); **caught +4 on the excerpt and medium** (medium 17,059 → 17,063 native, 17,060 → 17,064 CRS); **`access_control` 15/24 → 19/24 excerpt, 24/31 → 28/31 medium**; small and large hold no such episode | 0 → 0 everywhere, both engines | 1, and a window metric |
| 2026-10-14 | *this pass* | **credential** — the guess that worked, on a counted sequence (`first_at_least`) | corpus unchanged, 960 of 1,099 (a sequence cannot fire on one request); **caught +1 on the excerpt and every tier**; **`credential_attack` 38/39 → 39/39 excerpt, 28/29 → 29/29 small, 38/39 → 39/39 medium, 44/45 → 45/45 large** | 0 → 0 everywhere, both engines | 1, and a sequence count |
| 2026-10-14 | *this pass* | **action** — the admin page that asked for a sign-in, on a sequence that closes only the latest (`closes: last`) | corpus unchanged, 960 of 1,099; caught unchanged everywhere; **`authentication` 542/558 → 558/558 small, 1,714/1,781 → 1,781/1,781 medium, 6,902/7,204 → 7,204/7,204 large**, both engines; excerpt unchanged (no such page in it) | 0 → 0 everywhere, both engines | 1, and a sequence option |
| 2026-10-14 | *this pass* | **episode** — a page keeps the files it loaded, whatever kind of page | labels unchanged on every tier and the excerpt; **boundary F1 0.8520 → 0.8711 small, 0.8524 → 0.8726 medium, 0.8641 → 0.8816 large** native (CRS 0.8711 / 0.8718 / 0.8814); excerpt byte-identical | 0 → 0 everywhere, both engines | 0, one builder rule |
| 2026-10-14 | *this pass* | **recon** — a hand-built probe for known software, refused 400 | corpus unchanged, 960 of 1,099; **caught +43 on the excerpt and medium, +10 small, +152 large** (medium 17,064 → 17,107 native, 17,065 → 17,108 CRS); **`reconnaissance` 578/642 → 621/642 excerpt, 701/729 → 711/729 small, 2,631/2,695 → 2,674/2,695 medium, 10,240/10,438 → 10,392/10,438 large**, every new answer right | 0 → 0 everywhere native; CRS unchanged (small 1, the click ID) | 1 |
| 2026-10-14 | *this pass* | **recon** — a sweep keeps the named files it probed, on a new window option (`outranks`) | corpus byte-identical, 960 of 1,099; caught unchanged everywhere; **`enumeration` +68 / +262 / +1,021 on small / medium / large, `reconnaissance` −6 / −25 / −80**; accuracy 0.9963 → 0.9973, 0.9965 → 0.9975, 0.9966 → 0.9976; **boundary F1 0.8769 → 0.9096, 0.8791 → 0.9136, 0.8879 → 0.9184**; excerpt 17 right for 17 wrong | 0 → 0 everywhere native; CRS unchanged (small 1, the click ID) | 0, a window option on two rules |
| 2026-10-14 | *this pass* | **crs** — an ad platform's click ID is not a payload | corpus unchanged (native only); caught unchanged on every tier and both engines; small with CRS macro F1 0.9428 → 0.9434; medium and large carry no CRS match on a click ID at any level, so cannot move | **CRS 1 → 0 on small**, the last CRS false alarm on the `2026-10-06` tiers; native 0 → 0 | 0, one engine condition |
| 2026-10-14 | *this pass* | **crs** — the Windows sidecar reads paths like the Linux one; a client's `name/version` is not a file path | corpus unchanged (native only); CRS corpus 4,232 → 4,336 detections on Windows, equal to Linux rule by rule; with CRS caught **+1 on small and large**, medium unchanged; small recall 0.9897 → 0.9900, large macro F1 0.9639 → 0.9640 | CRS 0 → 0 on every tier (the path fix alone: **0 → 17 / 72 / 151**, all 930121 on `libwww-perl/6.72`); native 0 → 0 | 0; one engine condition, one sidecar file |

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








### 2026-10-05 — engine: Apache talking to itself is not a client

`unknown` read as `api_call` was 131 lines on `2026-10-04-medium` and 127 on
`2026-09-20-medium`, every one of them `127.0.0.1 "OPTIONS * HTTP/1.0"` with
the agent `Apache/2.4.68 (Debian) PHP/8.3.33 (internal dummy connection)`.
That is Apache waking its own worker processes by connecting to itself — the
server, not a visitor — and the fallback called it `Non-idempotent Request`,
which was wrong twice: it is not a client's activity, and `OPTIONS` is
idempotent.

The ladder now names it `Apache Internal Connection`, category `unknown`, the
taxonomy's none-of-the-above, which is also what the truth calls it. The
conditions are CRS 905110's, which exempts exactly this traffic: a loopback
client (`127.0.0.1`, `::1`), an agent ending in `(internal dummy connection)`,
and one of the two request lines Apache sends (`GET /`, `OPTIONS *`). All
three, because the marker is only a header; dropping any one of them fails the
test that pins its case.

| | before | after |
|---|---:|---:|
| `2026-10-04-medium` macro F1, native / CRS | 0.8146 / 0.8138 | **0.8716 / 0.8708** |
| `2026-10-04-medium` accuracy, native / CRS | 0.9953 / 0.9952 | **0.9958 / 0.9958** |
| `2026-09-20-medium` macro F1, native / CRS | 0.8103 / 0.7628 | **0.8656 / 0.8180** |
| `2026-09-20-medium` accuracy, native / CRS | 0.9953 / 0.9950 | **0.9959 / 0.9955** |
| `unknown` F1 on either tier | 0.000 | **0.792 / 0.767** |

Small in requests, large in macro F1, because `unknown` was a whole category
at zero. Detection and boundaries are unchanged; the excerpt holds no such
line and did not move; the ruleset fingerprint is unchanged, since the ladder
is engine code.

**Left alone deliberately — `unknown` read as `static_asset`, 67 and 74.**
Every one is the shop application fetching its own logo with the agent
`FettleImporter/1.0`: its image-import feature, run by the server against
itself. Only the site knows its importer's name, so a rule here would encode
this dataset's application rather than a fact about HTTP. If it comes back, the
honest route is the reader naming the site's own addresses, as `site_hosts`
does for its domains.

### 2026-10-05 — engine: a script is described by what it asked for

The other half of the scripted-traffic question the previous entries left
open. `Scripted Client` (`http_library_user_agent`, confidence 0.4) is an
observation about *who* sent a request. The fallback ladder (0.5) says *what*
was asked for. But the ladder only ran when no rule matched, so the observation
displaced it outright, and every page a script fetched was `crawling`. **The
labelled tiers call no library-agent request `crawling` at all**: on
`2026-10-04-medium` they are 615 API calls, 75 page views, and attacks, and 73
of the page views were read as `crawling`.

Now the primary label is the most significant match unless every match is a
benign observation below the ladder's rung, and then the ladder describes the
request. The observation stays in `all_labels`. One function, `_primary`,
decides it in both places it is decided. A fix in `_label_one` alone was
undone by window settling, which re-chose from the matches; reverting that one
line fails every new test. Only `http_library_user_agent` sits below the rung,
and a CRS rescue (0.6) is above it, so a rescue can never be displaced.

| | before | after |
|---|---:|---:|
| excerpt accuracy, native / CRS | 0.9514 / 0.9516 | **0.9561 / 0.9563** |
| excerpt macro F1, native / CRS | 0.7970 / 0.8070 | **0.8004 / 0.8107** |
| excerpt boundary F1 | 0.6289 | 0.6297 |
| `2026-10-04-medium` accuracy, native / CRS | 0.9950 / 0.9949 | **0.9953 / 0.9952** |
| `2026-09-20-medium` accuracy, native / CRS | 0.9952 / 0.9949 | **0.9953 / 0.9950** |

Detection is unchanged on every input, and boundary F1 is unchanged or up.
Expected, and checked: a script's requests no longer share one category,
which could have split episodes. It did not. On the excerpt,
`reconnaissance` read as `browsing` rose 47 → 53. Those six were wrong before
as well, as `crawling`; a scripted reconnaissance request with no rule naming
it is only renamed from one wrong benign label to another.

### 2026-10-05 — action: crawlers that never say `bot`

The fallback ladder recognised a crawler by four words — `bot`, `crawler`,
`spider`, `slurp` — and the action pack's crawler guard repeated the same four,
seven times. **`facebookexternalhit` says none of them**, and on
`2026-10-04-medium` it was 459 requests the truth calls `crawling` and the
fallback called `browsing`; on the committed excerpt, 67.

The new names come from the vendors' own lists, fetched 2026-10-05, not from
the dataset: Meta's web crawlers (`facebookexternalhit`, `meta-webindexer`,
`meta-externalads`, `meta-externalagent`, `meta-externalfetcher`) and the
Google crawlers and fetchers whose names lack `bot` (`GoogleOther`,
`Google-InspectionTool`, `APIs-Google`, `Google-Safety`,
`Mediapartners-Google`). The pack's seven copies of the guard became one YAML
anchor, and a test now fails if the engine's list and the pack's stop naming the
same crawlers — checked by adding a name to one side only.

| | before | after |
|---|---:|---:|
| excerpt accuracy, native / CRS | 0.9339 / 0.9341 | **0.9514 / 0.9516** |
| excerpt macro F1, native / CRS | 0.7855 / 0.7956 | **0.7970 / 0.8070** |
| excerpt `crawling` / `browsing` F1 | 0.963 / 0.676 | **0.989 / 0.798** |
| `2026-10-04-medium` accuracy, native / CRS | 0.9929 / 0.9928 | **0.9950 / 0.9949** |
| `2026-09-20-medium` accuracy, native / CRS | 0.9945 / 0.9941 | **0.9952 / 0.9949** |

Detection and segmentation are byte-identical on every one of them: the
excerpt fixtures' `binary` and `segmentation` blocks did not change, and the
tiers kept 17,058 / 0, 17,069 / 1 and 17,071 / 74. The CRS corpus did not move.

**Still getting through on `2026-10-04-medium`:** 73 `browsing` read as
`crawling` — scripts (python-requests, curl, okhttp…) fetching category
pages, named by `http_library_user_agent`, which suppresses the ladder's
`Page View` whatever the request was; and 131 `unknown` read as `api_call` —
Apache's own internal dummy connection. Both are the next two passes.

### 2026-10-05 — php: a `${name}` placeholder is not PHP

A false alarm suspected since 2026-09-22, now with evidence.
`php_superglobal` matched a bare `\$\s*\{`, and no corpus this project held
contained a single `${`, so it could not be shown wrong. The dataset's rebuilt
tiers now carry a real shop front end sending its placeholder unfilled, from a
real browser — `GET /api/stock?id=${id}&watch=1`, 41 / 129 / 659 requests by
the dataset side's count — and every one was injection at high severity. On a
build where the native false-alarm count had been zero, that would have been
the whole of it.

A bare `${name}` is what every template language writes. What still makes `${`
PHP is what a template never writes, each kept as its own branch:

| branch | the corpus case it keeps |
|---|---|
| `$` then a space, then `{` | `$ {'fdf'}`, `$ { constant }` |
| `${` not followed by a plain name and `}` | `${'a'}`, `${$a}`, `${@$b}`, `${jndi:` |
| `${...}` called as a function | `${_.__}(30)` — nothing else catches it |
| `${name}` then a command flag | `${shell} -c "echo hi"` — nothing else catches it |

Each was dropped in turn and the case it keeps failed.

**The cost, stated rather than chased: `/get?foo=${a}`**, a CRS 933 attack case,
is the same characters as the placeholder. No rule reading a request line is
right on both, and the placeholder is real traffic. 933 goes 179 → 178.

**One loss recovered properly.** `[ 1234 ]. map . call`${eval}…`` (941) had
been caught only by the bare `${`. `xss_sink_call` already catches the
unspaced form; its `\.call\s*`` became `\.\s*call\s*``, so a space after
the dot no longer hides it. 941 stays at 61. Overall 961 → **960** of 1,099,
0 fired wrongly in every family; the excerpt and `2026-09-20-medium` contain no
`${` and did not move; whole-engine cost on long `${`, `$ {` and `. call`
inputs is flat per character.

### 2026-10-06 — crs: the same placeholder, from the other engine

**The pass above was only ever measured natively, and with CRS on it had not
held.** The ledger row says "the dataset's 41 / 129 / 659 placeholder requests
no longer injection"; that was true of the native rules, and the tiers it
counted were held unscored, so nothing ran them through CRS. The first clean
tiers after it (`2026-10-06`, built from `d2ef291`) did, and CRS named every
placeholder request an injection again:

| `2026-10-06`, CRS on | small | medium | large |
|---|---:|---:|---:|
| `${id}` requests, all `api_call` in the truth | 44 | 149 | 670 |
| false alarms, before | 45 | 149 | 670 |
| — of which `${id}` | 44 | 149 | 670 |

Two CRS rules match `${id}`, both critical at paranoia level 1: 933135, PHP
variable access (`\$\s*\{\s*\S[^\{\}]*\}`), and 932130, Unix shell expression.
On small, 933135 won the label on all 44. **Withholding it by id would have
changed nothing** — 932130 sits on the same value and would have taken over, the
whack-a-mole the 931100/931130 pair taught. So the condition is on the shape,
not the rule: a detection whose matched value is *entirely* `${name}` is kept
on the request as evidence and may not name it (`_TEMPLATE_SLOT` in
`detect/engine.py`, beside the Referer rule that works the same way). It is
the line `php_superglobal` already draws — a plain name and nothing else — and
a test pins the other side: `${'ff'}`, `${$a}`, `${id}(30)`, `$ {id}` and
`x;${id}` still name the request, and checking for `${name}` anywhere in the
value instead of the whole value fails that test on `${id}(30)`.

| CRS on | before | after |
|---|---:|---:|
| small: caught / false alarms | 4,016 / 45 | 4,016 / **1** |
| small: accuracy / macro F1 | 0.9948 / 0.8412 | 0.9955 / **0.8600** |
| medium: caught / false alarms | 17,045 / 149 | 17,045 / **0** |
| medium: accuracy / macro F1 | 0.9952 / 0.8286 | 0.9958 / **0.8687** |
| large: caught / false alarms | 40,613 / 670 | 40,613 / **0** |
| large: accuracy / macro F1 | 0.9954 / 0.7703 | 0.9961 / **0.8293** |

Native is identical before and after on all three, field for field. The one
false alarm left on small is CRS 942100 (libinjection) reading a Google Ads
`gclid` token as SQL — a random token, and nothing to do with the placeholder.

The cost is the same as the native rule's: CRS's own `/get?foo=${a}` case is
no longer an injection when CRS alone saw it. The CRS corpus figure is native
only and does not move.

### 2026-10-06 — access: forced browsing with nothing refused, and a third kind of rule

The last gap with security weight on the `2026-10-06` tiers, and the first one
the rule model itself could not express. `access_control` named 9 of 31 on
medium. Of the 22 missed, 13 were `/admin/*` bounces (302 to the login form),
2 were `/account/` bounces, and **6 were the attack working**: one client was
bounced from `/admin/`, `/admin/users` and `/admin/orders` and then answered 200
on `/admin/ping` and `/admin/template` with no sign-in at all — the protected
pages check, the tools behind them do not. `forced_browsing_succeeded` needs a
4xx in its window and there was none.

An administrator is bounced too and let in a moment later. What separates them
is the sign-in between, which is **order, not quantity**, and is not an admin
page — a window rule computes its metrics over its members only, so no window
over admin pages could see it. Status ratios would have separated them on this
build only because the dataset redraws timestamps and puts an administrator's
post-login pages hours after the bounce; a real one signs in seconds later. So
the engine gained a third kind of rule (`sequence`: `first`, then `then` within
`within_seconds`, unless `unless_between`), labelling both ends and nothing
else, and `admin_reached_without_signing_in` is the first rule written in it.

**The false alarms it could have raised are the design.** Real deployments put
the login page, or what it loads, under the admin path. `then` is a GET,
anchored at the path's start, and never a login, logout or auth page, a static
file or WordPress's `load-styles.php`; `unless_between` takes any redirect from
a sign-in, single-sign-on or callback path, so a failed login (401, or the form
again) does not silence it and a successful one does. Each was dropped in turn
and its case failed:

| guard dropped | flow that then accused an administrator |
|---|---|
| `then` excludes login pages and assets | Django (`/admin/login/`, `/static/admin/…`), WordPress (`/wp-admin/load-styles.php`) |
| `then` is a GET | a console whose login form posts to itself, one failed attempt |
| `unless_between` | every administrator, Django, WordPress and a single-sign-on callback |

**What it cannot see:** a sign-in on another host whose log is not in the case.
From one vhost's log that administrator looks exactly like this, which is why
the confidence is 0.8, below the 0.85 triage reads as an exact shape.

| native | caught | false alarms | `access_control` | macro F1 |
|---|---:|---:|---:|---:|
| excerpt | 1,123 → **1,138** | 0 → 0 | 0/24 → **15/24** | 0.8004 → **0.8751** |
| `2026-10-06-small` | 4,013 → **4,028** | 0 → 0 | 9/34 → **24/34** | 0.8598 → **0.8896** |
| `2026-10-06-medium` | 17,044 → **17,059** | 0 → 0 | 9/31 → **24/31** | 0.8696 → **0.8999** |
| `2026-10-06-large` | 40,612 → **40,622** | 0 → 0 | 6/16 → **16/16** | 0.8301 → **0.8626** |

Every `access_control` it names is right (precision 1.000 on all four), and
with CRS the rows move the same way (excerpt 1,125 → 1,140, medium 17,045 →
17,060, false alarms unchanged). The CRS corpus does not move — 960 of 1,099,
0 fired wrongly — since a sequence cannot fire on one request. Whole-engine
cost on 16,000-character admin paths built from the lookahead's own words is
flat per character. In the demo log it fires on the forced-browsing scene's
attacker and nowhere else.

**Still missed on medium, all 7 listed:** one client trying other methods on a
protected page — `POST`, `HEAD` and `OPTIONS /admin/users`, each bounced 302,
and a `DELETE /api/cart` — to see whether the check is method-specific; two
`/account/` bounces; and one `/admin/` bounce. None has a success after it,
which is this rule's shape, and one request at a time each is what an
administrator's bounce looks like. Verb tampering is its own signal and its
own pass.

### 2026-10-06 — injection: the payoff is not a probe

`exploitation` named 4 of 8 on medium. Of the 4 missed, 2 were an avatar
upload (refused 415, accepted 200) whose shell is used two days and a session
later — knowable only from that later use, which is already `exploitation`, so
left alone — and **2 were the attacker taking something**: `;cat /etc/passwd`
through the ping tool and `{{file_get_contents('/etc/passwd')}}` through the
template, read as path traversal by `sensitive_file_access`. The same client's
`;id`, `;whoami` and `{{7*7}}` before them are `injection` in the truth and
here. A probe asks whether the hole is there; these take from it.

`injection_reaches_for_secrets` (`exploitation`, critical, 0.97) has three
exact shapes: a separator and a reader before an account file (`;cat`,
`|head`, `$(tail`…), a reading call around one (`file_get_contents(`,
`readfile(`, `include(`…), and a UNION that selects a credential column FROM a
users table. 0.97 because it has to outrank `sensitive_file_access` (critical,
0.95) on the same request, and every shape is specific enough to earn it.

**The SQL shape was first written too wide, and the truth drew the line.** As
"UNION SELECT … FROM users" it fired on `2026-10-06-small`'s
`UNION SELECT 1,2,3,username,5,6,7,8 FROM users` — the same client lining the
columns up a moment before the payoff, `injection` in the truth — and took
`injection` from 52/53 to 51/51. Requiring a credential column (`password`,
`password_hash`, `passwd`, `secret`, `api_key`…) is what separates them: the
`…,password_hash,…` after it is `exploitation`. Pinned both ways.

Each guard was dropped in turn and its case failed: no separator (a search for
"how to cat /etc/passwd", and a scanner's polyglot naming `../etc/passwd`
inside `xp_cmdshell`); no FROM-a-users-table (asking `information_schema`
whether `users` exists); no credential column (the column-lining query above);
and each positive branch on its own payoff.

| native | caught | false alarms | `exploitation` | `path_traversal` predicted | macro F1 |
|---|---:|---:|---:|---:|---:|
| excerpt | 1,138 → 1,138 | 0 → 0 | 4/8 → **6/8** | 9 → 7 (6 right) | 0.8751 → **0.8992** |
| `2026-10-06-small` | 4,028 → 4,028 | 0 → 0 | 4/9 → **7/9** | 9 → 7 | 0.8896 → **0.9176** |
| `2026-10-06-medium` | 17,059 → 17,059 | 0 → 0 | 4/8 → **6/8** | 9 → 7 | 0.8999 → **0.9223** |
| `2026-10-06-large` | 40,622 → 40,622 | 0 → 0 | 0/2 → **2/2** | 12 → 10 | 0.8626 → **0.9404** |

Every `exploitation` it names is right, detection does not move (these were
already caught, as path traversal or injection), and nothing else loses a
correct answer. With CRS the same: macro F1 0.8855 → 0.9096 excerpt, 0.9215
medium, 0.9397 large, false alarms unchanged. **Large's jump is one small
category, not a broad gain:** `exploitation` has 2 requests there, and going
from 0 to 2 of 2 moves one fourteenth of the macro average from 0 to 1.
Small's boundary F1 moved 0.8515 → 0.8512, the payoff now starting an episode
of its own. CRS corpus unchanged, 960 of 1,099, 0 fired wrongly; cost flat per
character on 16,000-character runs of each shape's own words. In the demo log
it fires on three attacker scenes (sqlmap's UNION, PHP's `file_get_contents`,
the command-injection client's `;cat /etc/passwd`) and nowhere else.

**Rebased 2026-10-09 onto `459debc`**, after the command-injection and UNION
narrowing (`812c4a3`, the row above this pass's in the table) and exploit
evidence first. Every tier was scored again on both sides of this change, both
engines, and the figures above are what came out at fingerprint
`d7d94ead3cd178a0`. The same runs measured the narrowing on real traffic for
the first time: on all three `2026-10-06` tiers it moved nothing, both
engines, every headline figure and every category identical; only the
fingerprint changed.

### 2026-10-09 — naming pass: three shapes read as their neighbour

Not missed attacks: requests already caught, or already read as something, under
the wrong name. Each was found in the medium confusion table and confirmed
request by request against the truth before a rule was written.

**sqlmap, havij, commix and ghauri are injection tools.** `scanner_user_agent`
called their User-Agent reconnaissance, which is right for Nikto or Nuclei
(they map what is there) and wrong for these (they exist to inject). Five
requests a tier are sqlmap's opening moves — on medium the baseline
`/search?q=oak` (twice), a random-value check `q=9401`, and its two heuristic
probes, `oak,,((,').)"` and a quote-and-angle-bracket marker — which carry no
payload a signature can name, and the truth calls every one injection. The
other 39 to 41 sqlmap requests a tier were already named by what they carry.
`injection_tool_user_agent` (injection, medium, 0.95) takes the four names out
of the scanner list. A User-Agent is the cheapest field to forge, which is why
severity stays medium; but a client that names an injection tool and is then
caught injecting is not a mapping exercise.

**It was made exploit evidence by accident, and measured out of it.** As an
injection label it counted as exploit evidence in the Suspicious queue. The
first-group check on all three tiers (below) found the same clients first, but
the sqlmap client's exploit example changed from a sensitive-file read to
sqlmap's baseline `/search?q=oak` — the earliest request the User-Agent marks.
An investigator opening it would see a search for "oak". A User-Agent is what
a client says it is, not a payload it sent, so it joined `NOT_EXPLOIT_EVIDENCE`
in its own commit, and the example went back to the payload.

**A `file://` fetch of a system file is SSRF.** `?url=file:///etc/passwd`
matched `sensitive_file_access` (path traversal, critical, 0.95) and
`ssrf_alternate_scheme` (SSRF, high, 0.8), so the first named it. The truth
calls it SSRF on every tier: the server was asked to fetch a URL, and the file
it named is what makes that critical. `ssrf_file_scheme_reads_system_file`
(SSRF, critical, 0.96) says both and leads. It names directories (`/etc/`,
`/proc/`, `/sys/`, `/root/`, a credential dot-directory, a Windows system
ini) rather than repeating `files.yaml`'s file names, which live in another
pack where a YAML alias cannot reach them and would drift.

**Verb tampering.** One medium client sent POST and HEAD to `/admin/users`
and OPTIONS to `/admin/orders`, each redirected to sign in, then a DELETE the
cart API answered: four methods in thirty seconds, all `access_control` in the
truth, read as sign-in redirects and an API call. CRS's 911100 sees the DELETE
under `attack-generic`, which ADR-0008 leaves unmapped. A window rule needed a
new metric, `distinct_methods`, so it was measured before it was written: no
client on any tier or the excerpt uses more than two methods inside five
minutes except this one and an HTTP fingerprinter sending five, invented ones
included, to `/` (reconnaissance in the truth). `verb_tampering` asks for three
methods on admin, API or account paths within 120 s, at most half served.

**One guard was not guarding.** Mutating the member path to `^/` failed no
test: the fingerprinter case was written as the shopfront logged it, every
method answered 200, so the success ratio kept it out and the path was never
exercised. The case now carries what a server that refuses an unknown method
answers (501, and 405 for TRACE), and the path mutation fails it. The other
four mutations (no success ratio, two methods, five methods, a 1,000 s window)
each failed a named case, including a form submitted after its session expired
— two methods, every one redirected — which is the reason for three.

It records which methods a client used and what the server answered, not a
payload, so it joins `NOT_EXPLOIT_EVIDENCE` with the teammate's per-exclusion
test. **What it can still catch wrongly:** an admin single-page app whose token
expired, sending a GET, a PUT and a DELETE that are all refused. Not in any
corpus here, so not measured.

**In the Suspicious queue** (the first-group check referred to above), measured
2026-10-13 on the new base — `cd06bf7`, with PR #36's CRS level-1 evidence —
against this pass's head: the first group holds the same clients on all three
tiers (7, 6 and 4), the queue the same members (127, 426 and 1,218), the
sqlmap client's exploit example is its sensitive-file read, and the one change
of order is on medium, where the verb-tampering client moves up one place with
four more flagged requests. One harmless client sits in small's first group on
both sides, `203.0.113.233`, placed by CRS 942100 reading a Google Ads click ID
as SQL; that comes from PR #36, not from this pass, and is still open.

**Where activity naming stops on medium**, after this pass. The large
confusions are the campaign-level ones already recorded — `enumeration` read
as `reconnaissance` 702 times, `reconnaissance` as `browsing` 53 (malformed
requests answered 400), `enumeration` as `browsing` 16 (wordlist hits that
exist). What is left in the small attack categories, where one request moves
the macro average, by kind:

- `credential_attack` 38 of 39: **the guess that worked.** Six refusals
  (401, 429) in a minute, then `POST /login` answered 302 — read as an
  ordinary sign-in. One on every tier (28 of 29 small, 44 of 45 large). It is
  the most valuable request in that client's history and the next thing to
  name; it needs a rule that can count the refusals before a redirect, which
  neither a sequence rule nor `success_ratio` (2xx only) can. Not yet written.
- `access_control` 28 of 31: 3 bounces from `/account/` and `/admin/` with
  nothing succeeding. A signed-out visitor does exactly this; only the
  campaign around it says otherwise.
- `exploitation` 6 of 8: an avatar upload, refused 415 then accepted 200,
  whose shell is used two days later. Knowable only from that use.
- `injection` 52 of 53: a `POST /contact` whose payload is in the body, which
  an access log does not have.
- `ssrf` 4 of 5: an import of the site's own stylesheet by URL — the probe
  before the internal ones, indistinguishable from the feature working.

### 2026-10-14 — credential: the guess that worked

The last miss in `credential_attack` on every tier was the same request. On
medium, `192.0.2.23` sent six `POST /login` refused inside a minute (five 401,
one 429), then a seventh answered 302 — read as `action_sign_in`. The truth
calls it credential attack, and to an investigator it is the one request in
that client's history that matters: the account was taken.

**Neither existing kind of rule could say it.** A window counts but has no
order, so "accepted, then refused five times" would match too. A sequence has
order but pairs one `first` with one `then`, so it could not ask for five
refusals. `first_at_least` makes the sequence's first step a count: the rule
fires when at least that many `first` requests are held inside the window as
`then` arrives. One condition in `_ends_of_sequences`, mutation-tested three
ways (ignore the count, accept zero, count before dropping stale requests).

**Measured on the raw logs before it was written:** exactly one client on
every tier and the excerpt is accepted after five or more refusals inside
five minutes, the attacker. Ordinary sign-ins follow one refusal (47, 149 and
631 times on small, medium and large) or two (1, 0 and 4), never three or
more. Five is `credential_attack`'s own floor, and the data leaves room under
it, so the threshold is set by what is defensible rather than by this log.

`credential_guess_accepted` (credential attack, high, 0.75) shares
`credential_attack`'s sign-in path list through one YAML anchor. A sequence
labels every request it held, so the refusals carry this label too; 0.75 sits
under `credential_attack`'s 0.8, so they keep their own name and only the
accepted sign-in is named this. Mutations each failed a named case: a count of
two (two typos, then in), confidence above 0.8 (the refusals renamed), a
`then` that accepts a refusal (never let in), a 1,000 s window (in, ten
minutes later).

**What it cannot tell apart:** somebody who mistyped five times and then got
it right. The refusals already make that client a credential attack, so the
report says nothing new about them that it did not already say.

| native | caught | false alarms | `credential_attack` | macro F1 |
|---|---:|---:|---:|---:|
| excerpt | 1,142 → 1,143 | 0 → 0 | 38/39 → **39/39** | 0.9359 → **0.9395** |
| `2026-10-06-small` | 4,028 → 4,029 | 0 → 0 | 28/29 → **29/29** | 0.9364 → **0.9378** |
| `2026-10-06-medium` | 17,063 → 17,064 | 0 → 0 | 38/39 → **39/39** | 0.9469 → **0.9479** |
| `2026-10-06-large` | 40,622 → 40,623 | 0 → 0 | 44/45 → **45/45** | 0.9578 → **0.9586** |

With CRS the same: one more caught on each, false alarms unchanged (small's one, the click ID),
macro F1 0.9441 → 0.9477 excerpt, 0.9461 → 0.9470 medium. Each tier's `authentication` loses one
wrong answer, every one of them the accepted guess, and nothing else moves. CRS corpus unchanged,
960 of 1,099, 0 fired wrongly. The demo's password guesser now gets in on its thirteenth try, and
the rule fires there and nowhere else.

### 2026-10-14 — action: the admin page that asked for a sign-in

The first pass aimed at activity rather than attacks. Re-measured first: the
TODO's `browsing` read as `crawling` was already gone (fixed 2026-10-05), and
the largest benign confusion left was `authentication` read as `browsing`, 16 /
67 / 302 on small / medium / large. `docs/evaluation.md` had explained those
as administrators' page views, "a page behind a login is still a page view".
**That was wrong, and the raw lines said so.** On medium, `GET /admin/` answered
200 with 2,359 bytes, the size of the 2,351-byte sign-in form, not of an admin
page; 25 seconds later the same client asked for `/login?next=%2Fadmin%2F`
with `/admin/` as its Referer. The page was the sign-in form, served in place.

**Measured on the raw logs before the rule was written.** Every page followed
within a minute by a sign-in that names it as the place to return to, with it
as the Referer, is `authentication` in the truth: 16, 67 and 302, exactly the
confusion, and nothing else. But the truth also has 615 / 2,497 admin page
views that are `browsing` (medium / large), so the path is not the evidence;
the sign-in that follows is.

**Only the admin area.** On a public page a visitor who chooses to sign in
sends the same `next=` back to it, and that page was no wall. The dataset has
no such case, which is why the rule may not lean on its absence: an admin page
is the one place where being asked to sign in to come back means the page did
not let them in.

**Every held page, or only the last.** A sequence labels every `first` it holds
when `then` arrives, and an administrator whose session ran out had been
reading real admin pages a moment before. Measured with the engine, labelling
every held page named 39 real admin pages wrongly on large at a 60-second
window and 185 at 300 (7 and 45 on medium). `closes: last` labels only the
latest: 16 / 67 / 302 and nothing wrong, flat from 60 to 300 seconds; only at
1,800 does a sign-in pair with a page from an earlier visit. It is a general
option, documented in `docs/writing-rules.md`, mutation-tested three ways.

`action_sign_in_wall` (authentication, info, 0.85): a GET of an admin page
answered 2xx, not a sign-in path or a file, by a non-crawler; then a GET of a
sign-in page whose return parameter names the admin area, reached from it;
unless a sign-in worked between. 0.85 sits under `action_sign_in`'s 0.9, so the
sign-in request it also closes keeps that name. Pinned against nine
neighbouring shapes (public page; public page then an admin redirect; returns
elsewhere; no Referer; reached from another page; refused; signed in between;
much later; crawler), and each of eight mutations fails one of them.

**It cost segmentation, and the cost was a builder defect.** Alone, the rule
moved boundary F1 0.8520 → 0.8489 on small and 0.8524 → 0.8489 on medium. The
wall page, now `authentication`, stopped sharing a class with the eleven files
it had loaded, which count as ordinary use; eleven is too many to absorb, so
the page became an episode of its own. Not the rule's fault: every sign-in
page's own files were being cut away from it the same way, and the wall only
made it visible. The builder now keeps a static file with the benign page
before it when its Referer names that page, and compares what follows with the
page rather than its last image. Ordinary pages are unchanged (they share a
class with their files already), and so is anything after a hostile request or
without a Referer naming the page. Labels do not move.

| native | `authentication` | macro F1 | boundary F1, builder alone | boundary F1, both |
|---|---:|---:|---:|---:|
| `2026-10-06-small` | 542 → **558 of 558** | 0.9378 → **0.9389** | 0.8520 → 0.8711 | 0.8520 → **0.8761** |
| `2026-10-06-medium` | 1,714 → **1,781 of 1,781** | 0.9479 → **0.9494** | 0.8524 → 0.8726 | 0.8524 → **0.8784** |
| `2026-10-06-large` | 6,902 → **7,204 of 7,204** | 0.9586 → **0.9603** | 0.8641 → 0.8816 | 0.8641 → **0.8874** |

With CRS the same: macro F1 0.9378 → 0.9390, 0.9470 → 0.9485, 0.9579 → 0.9595,
boundary F1 → 0.8761, 0.8776, 0.8873. Caught and false alarms are unchanged on
every tier and both engines; the excerpt is byte-identical apart from the
ruleset fingerprint (it holds no such page); the CRS corpus is unchanged, 960
of 1,099, 0 fired wrongly. In the demo, the signed-in administrator's session
has run out on the third day, and the rule fires on that `/admin` and nowhere
else (106 of 106 rules, 25 of 25 attackers, 0 false alarms).

**Still getting through, on medium:** 702 `enumeration` read as
`reconnaissance` (the shape: 68 of small's 156 carry an enumeration
window label, which by ADR-0005 is a different argument from the
User-Agent convention left alone on 2026-10-05), 75 `unknown` read as
`static_asset` (the shop's importer, left alone), and 53 `reconnaissance` read
as `browsing`, 43 of them one client's `/admin.php`, `/phpmyadmin/`,
`/shell.php` and `/wp-login.php` probes, every one answered 400.

### 2026-10-14 — recon: the probe the server refused to read

The 43 above were one client, `203.0.113.6`, sending `GET /admin.php HTTP/1.1`
and its three neighbours under the User-Agent `Mozilla/5.0 (compatible)`, every
one answered 400 with the same 352 bytes. The same client sent the same paths as
request lines no client sends, `GET /shell.php x` with no User-Agent at all, and
`absent_user_agent` already named those: 55 of medium's 98.

**Measured on the raw logs before the rule was written.** Every request on
`known_software_probe`'s paths answered 400 is `reconnaissance` in the truth:
22 / 98 / 310 on small / medium / large and 98 on the excerpt, one client on
each. Answered 404, the same paths are mostly `enumeration` (941 / 3,638 /
15,034 against 20 / 49 / 149), which is why `known_software_probe` asks for a
404: the site saying the software is not there is finding out what is
installed. A 400 says nothing about the software. It says the request was not
one a browser sends, and a request built by hand for known attack surface is a
tool probing it.

`malformed_software_probe` (reconnaissance, low, 0.7) shares
`known_software_probe`'s path list through one YAML anchor and asks for 400.
It does not ask for a User-Agent; a request without one is still named by
`absent_user_agent`, which outranks it. Never a 400 on an ordinary page: a stale
form or a bad cookie earns one too, and only the path makes it a probe, pinned
by `/p/12`, `/search?q=oak` and `/cart` at 400. Three mutations each fail a
test: any path, 404 instead of 400, `enumeration` instead of `reconnaissance`.

| native | caught | false alarms | `reconnaissance` | accuracy | macro F1 |
|---|---:|---:|---:|---:|---:|
| excerpt | 1,143 → 1,186 | 0 → 0 | 578/642 → **621/642** | 0.9634 → **0.9746** | 0.9395 → **0.9507** |
| `2026-10-06-small` | 4,029 → 4,039 | 0 → 0 | 701/729 → **711/729** | 0.9961 → 0.9963 | 0.9389 → **0.9395** |
| `2026-10-06-medium` | 17,064 → 17,107 | 0 → 0 | 2,631/2,695 → **2,674/2,695** | 0.9963 → 0.9965 | 0.9494 → **0.9500** |
| `2026-10-06-large` | 40,623 → 40,775 | 0 → 0 | 10,240/10,438 → **10,392/10,438** | 0.9965 → 0.9966 | 0.9603 → **0.9609** |

With CRS the same: 43, 10, 43 and 152 more caught on the excerpt, small, medium
and large, false alarms unchanged (small's one, the click ID), macro F1 0.9477 →
0.9590, 0.9390 → 0.9395, 0.9485 → 0.9492 and 0.9595 → 0.9601. Boundary F1 rises a
little on both engines: natively 0.6379 → 0.6464 on the excerpt, 0.8761 → 0.8769,
0.8784 → 0.8791 and 0.8874 → 0.8879 on the tiers. `browsing` loses only wrong
answers, and every 400 on those paths is now `reconnaissance` on all three tiers
(22, 98 and 310; the rest were already named by `absent_user_agent`). CRS corpus
unchanged, 960 of 1,099, 0 fired wrongly. The demo gains a hand-built prober
answered 400 on the four paths: 107 of 107 rules fire, 26 of 26 attackers are
found, 0 false alarms.

**Still getting through, on medium:** 702 `enumeration` read as
`reconnaissance` and 75 `unknown` read as `static_asset`, both as above. Then 16
`enumeration` read as `browsing`, every one from one wordlist sweep
(`198.51.100.31`, an Internet Explorer 6 User-Agent): the pages it found,
`/about`, `/cart`, `/admin` answered 301 and so on, each answered as it would be
to anyone, so nothing in the request is the evidence, only the sweep around it.
And 10 `reconnaissance` read as `browsing`: eight are a tool's opening `GET /`
and `HEAD /`, two a script's first `/admin/ping` and `/admin/template` before it
tried an injection on them.

### 2026-10-14 — recon: a sweep keeps the named files it probed

The largest confusion left was `enumeration` read as `reconnaissance`: 156 / 702 /
2,795 on small / medium / large. Before anything was written, the requests a
reconnaissance rule named were split by whether the client's own behaviour had
also earned them an enumeration window label:

| medium, `config_file_exposure` leading, answered 404 | truth `enumeration` | truth `reconnaissance` |
|---|---:|---:|
| inside a sweep | **262** | 25 |
| no sweep around it | 113 | **1,272** |

The probe's own label is right when it stands alone and wrong when the client was
sweeping, and inside the sweep it won only on severity: `config_file_exposure` is
high, both sweeps medium. `backup_file_probe` (medium, 0.75) already lost to the
sweep on confidence, which is why only configuration files showed it. A status
rule ("a configuration probe answered 404 is enumeration") would have put 1,272
wrong for 113 right; the evidence is the sweep, not the answer.

**What the 25 are.** `/.env`, `/.git/config`, `/.aws/credentials` and
`/config.json`, from the same four clients whose sweep surrounds them; 258 of the
262 are `/.svn/entries`. The truth files them under different activity instances
of one client running at once: on `192.0.2.233` every reconnaissance probe is in an
odd-numbered instance (`#1`, `#3`, …) and every `/.svn/entries` in an even-numbered
one (`#2`, `#8`, …). By behaviour they cannot be told apart (`/.svn/entries` and `/.git/config` are the same kind of file), so a
rule that got the 25 right would be reading the dataset's wordlist. The reading
taken is ADR-0005's: a sweep that includes `/.env` is a wordlist with `/.env` in it.
The same split holds on the other tiers: 68 and 1,021 right (every one
`/.svn/entries`, `/.git/HEAD` or `/web.config`) for 6 and 80 wrong, the same four paths.

**`outranks`**, a window-rule option: the categories the window's label leads
over on the requests that window labelled, whatever their severity. They are set
aside when the primary label is chosen, not removed, so the probe stays among the
matches that triage reads for severity and high-confidence reasons. Both
directory-enumeration windows outrank `reconnaissance`. Their members are 404–410,
so a file the server handed over is never the sweep's, and only the categories
named yield: an injection inside a sweep still leads. A window that names its own
category is refused. Four engine mutations (ignore it; apply it to every request
rather than the window's own; set aside every other label; drop the own-category
guard) and removing either rule's line each fail a named test.

| native | `enumeration` | `reconnaissance` | accuracy | macro F1 | boundary F1 |
|---|---:|---:|---:|---:|---:|
| `2026-10-06-small` | 3,040 → **3,108** of 3,213 | 711 → 705 of 729 | 0.9963 → **0.9973** | 0.9395 → **0.9427** | 0.8769 → **0.9096** |
| `2026-10-06-medium` | 13,587 → **13,849** of 14,312 | 2,674 → 2,649 of 2,695 | 0.9965 → **0.9975** | 0.9500 → **0.9532** | 0.8791 → **0.9136** |
| `2026-10-06-large` | 27,425 → **28,446** of 30,244 | 10,392 → 10,312 of 10,438 | 0.9966 → **0.9976** | 0.9609 → **0.9646** | 0.8879 → **0.9184** |

**Boundary F1 rose three points or more on every tier.** Each probe had been an
episode of its own cut out of the sweep. On medium the change removed 481
boundaries (episodes 9,581 → 9,100), and only 6 of them were boundaries the truth
has: boundary precision 0.798 → 0.858.

With CRS the same: `enumeration` +68 / +276 / +1,035 (the CRS runs began with 14
more of these wrong on medium and large), `reconnaissance` −6 / −25 / −80, macro F1
0.9395 → 0.9428, 0.9492 → 0.9525, 0.9601 → 0.9639, boundary F1 0.8769 → 0.9096,
0.8783 → 0.9137, 0.8877 → 0.9184. Caught and false alarms are unchanged on every
tier and both engines (small's one with CRS, the click ID). The committed excerpt
breaks even: 17 `/.svn/entries` right for 17 wrong, `/.git/config`, `/.env`,
`/config.json` and `/.aws/credentials` from one client, `192.0.2.231`. Accuracy is
unchanged at 0.9746 (0.9749 with CRS), macro F1 0.9507 → 0.9508 (0.9590 → 0.9592),
boundary F1 0.6464 → 0.6657 (0.6481 → 0.6676). CRS corpus byte-identical, 960 of
1,099; the demo still exercises 107 of 107 rules.

**Still getting through, on medium:** 440 `enumeration` read as `reconnaissance`.
433 are lone probes answered 404 for four files, `/backup.zip` (113),
`/.svn/entries` (113), `/db.sql` (107) and `/cgi-bin/test.cgi` (100), one or two
from each of about eighty clients, mostly under a browser's User-Agent, with no
sweep around them. No sweep caught them because there was none to catch, and a
named-file probe on its own is reconnaissance by ADR-0005. It is the campaign convention the 2026-10-05 entry left alone. Then 34
`reconnaissance` read as `enumeration`, the 25 above and nine lower-severity
probes (`/actuator/health`, `/.well-known/security.txt`) that already yielded to
the sweep before this pass.

### 2026-10-14 — crs: the Windows sidecar reads paths; a client's name is not a path

Found by the corpus record added with RE2 (PR #46): replayed on Linux, CRS's
regression corpus gave 104 more detections than on Windows, all in six rules
that look for file paths from a word list — 930120, 930121, 930130, 930140,
932160 and 932161. Coraza v3.7.0's `t:normalizePath` and `t:normalizePathWin`
call `path/filepath.Clean`, which on Windows turns `/` into `\`, while the
lists are written with `/`. So on Windows `/etc/passwd` was compared as
`\etc\passwd`, and `/.git/config`, `/bin/bash` in a parameter and file paths in
the User-Agent passed as harmless. `crs/paths.go` registers the two
transformations again on `path`; the Windows corpus then matches Linux rule by
rule (4,336, digest `9ca1a14a…`). Five contract payloads pin it, and dropping
either half of the fix fails the ones that half covers.

**Every CRS figure published for the tiers until now was Windows's.** The
path fix alone, re-enriching the three `2026-10-06` cases: caught +1 on small
and large, and false alarms **0 → 17, 72 and 151**. Every one was 930121
finding `perl/` inside the User-Agent `libwww-perl/6.72` (434 detections on
large); the Linux sidecar had always raised them. 930121's other new matches
are Referer copies of real traversal and probes, and 930130's are the `/.git/config`,
`/.env` and `/.aws/credentials` probes the native rules already call
reconnaissance; it maps there too, so it gives triage no exploit evidence.

A 930121 or 932161 match in a User-Agent made only of `name/version` products,
each version starting with a digit, no longer names the request
(`_FILE_LIST_RULES`, `_PRODUCTS`); it stays attached. Every User-Agent attack
in CRS's corpus for these rules is a path or a command and none fits; a path
beside a product, or a product whose version is not a number, still names.
Three mutations each fail a test (any rule excused, a prefix match, any
version).

Both together, with CRS: small caught 4,042 → 4,043 (`GET /.DS_Store` 404,
browsing → reconnaissance), recall 0.9897 → 0.9900; medium identical in every
field; large 40,776 → 40,777, macro F1 0.9639 → 0.9640; false alarms 0 on all
three. The Suspicious queue is unchanged on all three (126 / 426 / 1,218 ranked, same
first group, nobody moved). The sidecar binary now has a revision in the CRS
fingerprint (`SIDECAR_REVISION = 2`), so the excerpt's CRS fixture moves only
in that field, and the triage index layout is 10.

### 2026-10-14 — crs: an ad platform's click ID is not a payload

The last CRS false alarm on the `2026-10-06` tiers, found on 2026-10-13: on
small, `203.0.113.233`'s landing request
`GET /?gclid=-1--dq671umzg6z…` was named an injection by 942100 (libinjection),
which read the token's `-1--` as a number and a comment. It also placed that
harmless visitor seventh of 127 in the Suspicious queue, in the first group,
through PR #36's CRS level-1 evidence.

**Measured first:** across the 1,262 requests carrying an ad click ID on the
three tiers (57 / 243 / 962), CRS matched exactly one, at any paranoia level,
and it was this one. CRS's own regression corpus keeps two click IDs as false
positives for the neighbouring rule 942440 (`942440.yaml`, tests 19 and 20).

`names_activity`, which already keeps a `${id}` placeholder and a Referer from
naming a request, now does the same for a match on an ad platform's click-ID
parameter (`gclid`, `gbraid`, `wbraid`, `dclid`, `fbclid`, `msclkid`, `ttclid`,
`twclid`, `yclid`, `li_fat_id`) whose value is a token: letters, digits, `-`,
`_` and `.` only. The detection stays attached. A quote, a space, a bracket or
a semicolon still names, because a site that stores the click ID can be
injected through it; the same token in any other parameter still names. Three
mutations each fail a test (any value in a click ID; a token in any parameter;
one name dropped). Triage reads the same check, so the visitor leaves the
Suspicious queue altogether: 127 ranked → 126, first group 7 → 6.

**A saved queue would have hidden it.** A triage index is reused while its
identity matches, and the identity holds the rules' fingerprint, not the
engine's code, so a case scanned before this change kept the visitor first. The
index layout is now 9; an index written in layout 8 is rebuilt, pinned the way
layouts 2, 5, 6 and 7 already are.

Small with CRS: false alarms **1 → 0**, caught 4,042 unchanged, macro F1 0.9428
→ 0.9434, boundary F1 0.9096 → 0.9099, the request now a page view. Native is
unchanged everywhere; the excerpt fixtures are byte-identical.

### 2026-10-05 — recon: the tools that sweep a wordlist are enumeration

The first pass aimed at *naming* rather than catching, and the largest single
error on `2026-09-20-medium` turned out to be one rule's category, not a missing
rule. `enumeration` read as `reconnaissance` was 5,325 requests, and **4,610 of
them were one client, `gobuster/3.5`**: `scanner_user_agent` names it
reconnaissance at confidence 0.95, and outranked the `directory_enumeration`
label (0.9) that 4,586 of those requests had also earned.

ADR-0005 states the boundary this project measures by — probing for named
artefacts is reconnaissance, sweeping a wordlist is enumeration — and
gobuster, dirb, dirbuster, dirsearch, ffuf, feroxbuster and wfuzz exist to
sweep. So the scanner list was contradicting the taxonomy, which is a
different thing from the dataset's convention. They moved to
`content_discovery_user_agent`, `enumeration`, same severity and confidence.
The dataset agrees tool by tool, which is a check rather than the reason:
gobuster 4,615 enumeration; nmap 8 and whatweb 6 reconnaissance; sqlmap 43
injection.

**ffuf was never matched at all.** Its default User-Agent is
`Fuzz Faster U Fool v2.1.0-dev`, which does not contain `ffuf`. The demo log's
`scanner_parade` has sent exactly that string all along as its fourth
"tool that announces itself", and nothing announced. Matched by name now.

| `2026-09-20-medium` | native before | native after | CRS before | CRS after |
|---|---:|---:|---:|---:|
| accuracy | 0.9751 | **0.9945** | 0.9747 | **0.9941** |
| macro F1 | 0.7683 | **0.8097** | 0.7209 | **0.7622** |
| `enumeration` F1 | 0.771 | **0.973** | 0.770 | **0.973** |
| `reconnaissance` F1 | 0.493 | **0.869** | 0.492 | **0.867** |
| caught / false alarms | 17,069 / 1 | 17,069 / 1 | 17,071 / 74 | 17,071 / 74 |
| boundary F1 | 0.8472 | 0.8466 | 0.8372 | 0.8367 |

**Boundary F1 fell by 0.0006**, 9,844 episodes to 9,852. The few gobuster
requests that hit a more severe file-exposure rule are still
`reconnaissance`, now inside an `enumeration` run rather than a
`reconnaissance` one, so each splits it. Small, and reported rather than
chased in the same pass. The excerpt carries no content-discovery agent and did
not move; the CRS corpus did not move; none of the 70 distinct benign agents
across the tiers fires a hostile rule; whole-engine cost on 7–56 KB agents
built from the new pattern's own prefixes is flat per character.

**Still getting through — 715 `enumeration` read as `reconnaissance`.** Almost
all are the browser-agent campaign probing `/.svn/entries`, `/backup.zip`,
`/db.sql`, `/cgi-bin/test.cgi`, which `docs/evaluation.md` already decided not
to chase: the same request line is labelled by *which campaign sent it*, and
yielding to enumeration whenever a User-Agent is present would encode that
convention, not a fact. The other handful is the gobuster file-exposure hits
above. Making a *declared* content-discovery tool's file probes enumeration is
defensible by the same ADR — they are wordlist entries — and is the next thing
to measure, separately.

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
