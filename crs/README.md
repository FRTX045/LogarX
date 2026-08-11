# CRS evidence sidecar

Replays parsed access-log records through the [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)
via [Coraza](https://github.com/corazawaf/coraza) and emits matched rules as JSONL.

It contains **no attack knowledge of its own.** CRS supplies every detection; this is transport
plus configuration. CRS is SecLang source and cannot execute itself — Coraza is the engine that
runs it, and it is what brings the per-rule transformation chains (`t:cmdLine`, `t:normalizePath`,
`t:urlDecodeUni`), per-`ARGS` targeting, rule chaining, libinjection and `@pmFromFile`. Those are
exactly the parts that would be lost by copying CRS's regexes into a rule pack instead.

## Build

Requires Go 1.25 or newer. With `GOTOOLCHAIN=auto` (the default) an older Go will fetch it.

```bash
git clone https://github.com/coreruleset/coreruleset.git ../vendor/coreruleset
git -C ../vendor/coreruleset checkout d694d465951ee06347214f1291ae096e40700001

go build -o crs-sidecar .                                # native
GOOS=windows GOARCH=amd64 go build -o crs-sidecar.exe .  # cross-compile
```

Cross-compilation is clean because Coraza's dependency tree is pure Go, and it is **required** when
the Python interpreter running `logarc` targets a different OS than the toolchain — a Windows venv
cannot spawn an ELF binary. `logarc` looks for `crs-sidecar.exe` on Windows and `crs-sidecar`
elsewhere; `LOGARC_CRS_BINARY` overrides both.

Neither binary nor the ruleset clone is committed. Pinned versions — reproducing a measurement
requires all three:

| | |
|---|---|
| CRS | `4.29.0-dev`, commit `d694d465` |
| Coraza | `v3.7.0` |
| libinjection-go | `v0.3.2` |

## Interface

Input is **pre-parsed JSON**, not raw log lines, so `logarc`'s parsers stay the single source of
truth for reading a log.

```bash
./crs-sidecar --rules ../vendor/coreruleset --conf . < records.jsonl > evidence.jsonl
```

stdin, one object per line: `line_no`, `client_ip`, `method`, `raw_target`, `protocol`, `status`,
`referer`, `user_agent`. A null `method` (Apache writes `-` for aborted connections and 408s) is
skipped, not an error.

stdout, one object per **matched datum** — a rule matching in two parameters emits two lines
sharing a `rule_id`, because collapsing them would discard the anchor for `transformed_value`.

## `transformed_value`

CRS's **post-transformation** value: Coraza populates `MatchData.Value` from the transformed
argument, so it reflects `t:urlDecodeUni`, `t:replaceComments`, `t:compressWhitespace` and the rest
of each rule's chain.

```
raw target        /search?q=%27+ORDER+BY+8--+-
transformed_value ' ORDER BY 8-- -
```

## Configuration decisions

These are deliberate, not defaults.

| Setting | Rationale |
|---|---|
| `SecRuleEngine DetectionOnly` | Interruption would truncate the evidence set at the first blocking decision. We want every rule that matched, not a verdict. |
| `SecRequestBodyAccess Off` | Access logs carry no bodies. |
| No `RESPONSE-*.conf` loaded | Every response-phase rule is dead when the only evidence is an access log. |
| **Paranoia level 2** | Measured, not guessed. A false positive costs more here than in the tool this came from — a detection can set a request's `ActivityCategory`, and a category change starts a new episode. That argued for PL1, and the numbers did not support it: across CRS's own 1,194 access-log-visible regression payloads, PL1 reached 67% and PL2 reached 90%. PL2 is also the ceiling: on 365 lines of real 2010 WordPress traffic, PL1 and PL2 leave the hostile-episode count unchanged, while **PL3 flags a plain `GET /` as "Unix Shell Code Found in Request"** and invents an episode. |
| Anomaly score ignored | `tx.anomaly_score` and rule 949110 are a blocking heuristic for a decision this tool does not make. Per-rule severity is kept; the aggregate is discarded. |

### Removed rules

Twelve rules are removed by ID. Each is a `&REQUEST_HEADERS:X` presence test on a header Apache
never logs, so "absent from the log" is indistinguishable from "absent from the request" — constant
signal, not weak signal:

```
920171 920180 920181 920300 920340 920490
920510 920620 920640 920660 921230 920280
```

`920280` (Host) is included because the sidecar synthesizes a `Host` header. `920320` (Missing
User Agent) is **not** removed: the combined format does log that field, so a `-` there is a real
absence rather than an unrecorded one.

### The evidence filter

Most raw matches in a replay are machinery, not findings — paranoia-level gates (`9xx017`/`9xx018`),
performance shortcuts such as `941010`, and counting rules such as `921170` that only `setvar` for
a later reporting rule.

The filter is CRS's own `nolog` convention: **rules meant to be reported carry a `msg`, machinery
does not.** Filtering on the message rather than on ID patterns means future CRS versions cannot
silently reintroduce noise. Rule-ID ranges `900/901/949/980` are excluded separately, because
`949110` and `980170` do carry messages.
