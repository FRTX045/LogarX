# CRS evidence sidecar

Replays parsed access-log records through the [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)
via [Coraza](https://github.com/corazawaf/coraza) and emits matched rules as JSONL.

It contains **no attack knowledge of its own.** CRS supplies every detection; this is transport
plus configuration. CRS is SecLang source and cannot execute itself — Coraza is the engine that
runs it, and it is what brings the per-rule transformation chains (`t:cmdLine`, `t:normalizePath`,
`t:urlDecodeUni`), per-`ARGS` targeting, rule chaining, libinjection and `@pmFromFile`. Those are
exactly the parts that would be lost by copying CRS's regexes into a rule pack instead.

## Build

From a source checkout, one command does all of it and then checks that it works:

```bash
logarx-dev setup-crs
```

It fetches the ruleset at the pinned revision below, builds the sidecar if it is missing or older
than its source, and replays a known SQL injection to prove the two work together. It needs git,
Go and a network connection, once, and leaves alone whatever is already in place. By hand:

Requires Go 1.25 or newer. With `GOTOOLCHAIN=auto` (the default) an older Go will fetch it.

```bash
git clone https://github.com/coreruleset/coreruleset.git ../vendor/coreruleset
git -C ../vendor/coreruleset checkout d694d465951ee06347214f1291ae096e40700001

go build -o crs-sidecar .                                # native
GOOS=windows GOARCH=amd64 go build -o crs-sidecar.exe .  # cross-compile
```

Cross-compilation is clean because Coraza's dependency tree is pure Go. RE2 is no exception: go-re2
builds it to WebAssembly and translates that to Go, so no C toolchain is involved. Cross-compiling
is **required** when
the Python interpreter running `logarx` targets a different OS than the toolchain — a Windows venv
cannot spawn an ELF binary. `logarx` looks for `crs-sidecar.exe` on Windows and `crs-sidecar`
elsewhere; `LOGARX_CRS_BINARY` overrides both.

Neither binary nor the ruleset clone is committed. The packaged Windows build carries both:
`packaging/rebuild.py` builds the sidecar fresh with `-trimpath`, and `packaging/crs_bundle.py`
bundles it with the request rules, their data files, the ruleset's revision (as a `REVISION` file,
since the bundle has no `.git`) and the licence of every Go module linked into it, with the notices
for the code compiled into go-re2 from `licenses/go-re2/`. Pinned versions — reproducing a
measurement requires all of them:

| | |
|---|---|
| CRS | `4.29.0-dev`, commit `d694d465` |
| Coraza | `v3.8.1` |
| libinjection-go | `v0.3.3` |
| go-re2 | `v1.12.0`: RE2 `2025-11-05`, translated to Go |

## Tests

```bash
go test -ldflags=-checklinkname=0 ./...
GODEBUG=cpu.all=off go test -ldflags=-checklinkname=0 ./...
```

The sidecar has to work on whatever CPU a user has, and some of what Go runs depends on it.
`memmove_test.go` loads CRS and matches two attacks twice: once with Go's memory copy on the path
Intel CPUs from Ice Lake on take, where the go-re2 v1.6.0 build crashed, and once as this CPU
copies. The second command makes that "as this CPU" a CPU with no optional features at all. The
linker flag lets the test reach the runtime's switch for that path; the sidecar itself is built
without it. CI runs both, on Windows and Linux. The Python tests (`tests/detect/crs/`) cover the
rest, through the built binary.

## Interface

Input is **pre-parsed JSON**, not raw log lines, so `logarx`'s parsers stay the single source of
truth for reading a log.

```bash
./crs-sidecar --rules ../vendor/coreruleset --conf . < records.jsonl > evidence.jsonl
```

stdin, one object per line: `line_no`, `client_ip`, `method`, `raw_target`, `protocol`, `status`,
`referer`, `user_agent`. A null `method` (Apache writes `-` for aborted connections and 408s) is
skipped, not an error.

A line `{"flush": N}` is answered with `{"flushed": N}` once everything before it has been, and
stdout is flushed. `logarx` keeps each sidecar running for a whole replay and sends it one share
of requests after another, each followed by a marker, so it knows where one share's answers end
without closing the pipe. It passes `--protocol 2` too: a binary built before
flush markers rejects the unknown flag at once, and `logarx` says to rebuild it, where it would
otherwise read every marker as a record and never answer.

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

## Regular expressions: RE2

CRS's `@rx` runs on RE2 rather than Go's `regexp` (`rx.go`, adapted from coraza-wasilibs). Go's
`regexp` was half of a sidecar's time. go-re2 builds RE2 to WebAssembly and translates that to Go,
so it is compiled into the sidecar like the rest of it. Measured 2026-10-15 on the three
`2026-10-06` tiers, six sidecars each, the two builds alternating, the middle of three runs, the
same detections on every one (`tools/measure/`; `tools/README.md` says how):

| | Go `regexp` | RE2 |
|---|---|---|
| small, 63,310 lines | 13.6 s | 8.1 s |
| medium, 235,732 lines | 31.7 s | 21.3 s |
| large, 941,031 lines | 90.1 s | 53.8 s |

Go `regexp`'s three large runs spread from 80.5 to 105.2 s; RE2's from 50.2 to 57.9 s. What it
costs: a sidecar starts in 0.32 s instead of 0.12 s, so the sidecars live for a whole run instead
of one per share of requests, and the binary grows from 21.7 MB to 28.7 MB. It holds less, not
more: six replaying the large tier peaked at 278 MB together, 46 to 49 MB each, against 339 MB
with Go's `regexp`. A 20 ms timer in a Qt window meanwhile fired at worst 14.7, 29.3 and 29.0 ms
late over three runs, and 99% of the time within 7 ms, as it does with Go's `regexp`. Four and six
sidecars are within noise of each other on the medium tier, 18.8 and 20.1 s against 19.0 and
19.1 s, and eight is slower, 20.3 s twice, so six stays. Only `@rx` moved. coraza-wasilibs would
also swap `@pm`, `@detectSQLi` and `@detectXSS` for WebAssembly builds, and importing it for `@rx`
alone started two WebAssembly modules nobody called, which cost 0.3 s of every start.

Until 2026-10-15 the sidecar used go-re2 v1.6.0, which ran RE2 on wazero, compiling it to machine
code as the sidecar started. That crashed on most Intel CPUs from Ice Lake on, where Go copies
memory with a register wazero counted on keeping. ADR-0008's amendment of 2026-10-15 has the story
and the figures for both; `memmove_test.go` keeps it from coming back.

A regex engine that reads one pattern differently would change detections quietly, so
`tests/detect/crs/test_corpus_detections.py` replays CRS's whole regression corpus and compares
every detection, by rule and by digest, with a committed record. CI builds the sidecar and runs it.

## Configuration decisions

These are deliberate, not defaults.

| Setting | Rationale |
|---|---|
| `SecRuleEngine DetectionOnly` | Interruption would truncate the evidence set at the first blocking decision. We want every rule that matched, not a verdict. |
| `SecRequestBodyAccess Off` | Access logs carry no bodies. |
| No `RESPONSE-*.conf` loaded | Every response-phase rule is dead when the only evidence is an access log. |
| **Paranoia level 2** | Measured, not guessed. A false positive costs more here than in the tool this came from — a detection can set a request's `ActivityCategory`, and a category change starts a new episode. That argued for PL1, and the numbers did not support it: across CRS's own 1,194 access-log-visible regression payloads, PL1 reached 67% and PL2 reached 90%. PL2 is also the ceiling: on 365 lines of real 2010 WordPress traffic, PL1 and PL2 leave the hostile-episode count unchanged, while **PL3 flags a plain `GET /` as "Unix Shell Code Found in Request"** and invents an episode. |
| Anomaly score ignored | `tx.anomaly_score` and rule 949110 are a blocking heuristic for a decision this tool does not make. Per-rule severity is kept; the aggregate is discarded. |

### Paths are cleaned the same way on every system

CRS's file lists (`lfi-os-files.data`, `restricted-files.data`, `unix-shell.data`) are written
with forward slashes, and the rules that read them first clean the path with `t:normalizePath` or
`t:normalizePathWin`. Coraza (v3.7.0, and still v3.8.1) implements both with Go's
`path/filepath`, whose `Clean` on Windows turns every `/` into `\`. So the Windows sidecar compared
`/etc/passwd` as `\etc\passwd` and found nothing: on CRS's regression corpus it made 104 fewer detections than the Linux one, all
in 930120, 930121, 930130, 930140, 932160 and 932161, and `/.git/config` passed as harmless.
`paths.go` registers both transformations again on Go's `path`, which is what `path/filepath`
already is on Linux, so the Linux sidecar reports what it did and the Windows one now matches it.

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
