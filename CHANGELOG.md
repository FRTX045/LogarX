# Changelog

Notable changes to logarc. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- **`logarc score-crs`**, added earlier in this same unreleased cycle, is removed along with
  `evaluation/crs.py` and its tests. CRS is being adopted as the signature layer, at which point
  scoring against CRS's own regression corpus grades the rules with the suite their project
  maintains — a number that cannot mean anything and would still be quoted. The measurement it
  produced is kept in `docs/evaluation.md` and ADR-0007, because it is the evidence for the
  adoption decision. The code is recoverable from git history; ADR-0007's postscript names the
  commits.

### Evaluation

- `logarc score-crs` scores the bundled rules against the **OWASP CRS regression corpus** — 4,224
  cases written by the Core Rule Set project, each a payload with an assertion naming which of
  their rules must fire. The first external check of the signature layer; the existing figures all
  come from traffic this project wrote, graded against rules this project wrote. The corpus is not
  vendored: `--corpus` takes a clone path, and its git revision is recorded next to the ruleset
  fingerprint so a rate stays re-derivable as CRS gains cases.
- **The measured result is 12.3%** — 140 of the 1,138 payloads an access log can carry. Reported
  here because a changelog that quotes only favourable numbers is worse than none. Part of the gap
  is that CRS grades payload syntax while these rules classify behaviour, and part is genuinely
  uncovered ground: 933 (PHP) scores 0.012 over 173 cases against no PHP rule at all, and 932 (RCE)
  scores 0.079 over 406 against one. Three qualifications travel with the figure and the command
  prints all three: the ceiling is 27%, because three cases in five put their payload in a request
  body no access log records; it is a floor within that, because status is synthesised as 200 and
  one bundled rule needs a 4xx; and CRS's own 341 false-positive tests are held out of the rate and
  reported separately (a rule fired on 13, 3.8%).
- No mapping between CRS families and this tool's activity categories is asserted. The categories
  that fired are printed descriptively and never scored — see
  [ADR-0007](docs/adr/0007-scoring-detection-against-the-crs-regression-corpus.md).
- `--out` writes every uncaught payload with its source file, test id and URI. The rate is the
  summary; that list is what can inform which rules to write next.
- **The CRS gap is expressiveness, not decoding**, and that is now measured rather than assumed.
  Adding HTML entity decoding, JavaScript escape decoding and null removal moved the rate from
  12.0% to 12.3% — three cases, all Log4Shell in a `User-Agent`. Of the 1,001 missed payloads, five
  contain an HTML entity, one a JavaScript escape and none a null byte; the rest arrive in plain
  text and no rule expresses their syntax (`for %variable in (set) do`, `while(!false)`,
  Postgres `::jsonb` operators). See the follow-up in
  [ADR-0007](docs/adr/0007-scoring-detection-against-the-crs-regression-corpus.md).

### Detection

- **HTML entity, JavaScript escape and null-byte normalisation.** `&#60;script&#62;`,
  `<script>` and `/etc/passwd%00.jpg` now reach the rules in the form the server acts on.
  The three decoders run in one loop with percent-decoding rather than in sequence, because they
  nest in both directions — `%26lt%3B` is percent-then-entity and `&#x25;3C` is entity-then-percent.
  Entity decoding is deliberately stricter than `html.unescape`, which resolves unterminated named
  entities and would invent payloads in ordinary query strings.
- A null byte is now stripped from the matched text but recorded on the result as `had_null`, and
  exposed as a `had_null` match field. This reverses an earlier decision to keep the null in the
  text: the reasoning behind it — that sending one is never accidental — was right, but keeping it
  in the text meant `sensitive_file_access` never saw the path the server actually opens. Both are
  satisfiable at once.

### Fixed

- **`distinct_paths` counted `/a/b`, `/a//b` and `/a/./b` as three paths.** That metric is a
  threshold in three of the five bundled window rules, so how a path happened to be written decided
  whether a behaviour was detected — eight requests across two resources were labelled directory
  enumeration. Paths are now counted canonically while `top_targets` still reports what was
  actually requested. Note this changes window-rule firing, not only accuracy: episodes whose
  detection depended on the inflated count will no longer be labelled.

## [0.1.0] — 2026-08-09

First release. Reconstructs what an IP did on a web server, from its access logs,
and draws it as an activity graph.

### Parsing

- Canonical `NormalizedEvent` schema, so a new log format changes nothing past ingest.
- Apache `LogFormat` directives are **compiled**, not hardcoded, so a site's own directive
  string is supported without code. Presets for `common`, `combined` and `vhost_combined`.
- Format auto-detection by scoring a sample; ambiguity is reported rather than guessed at,
  because silently choosing the wrong parser quarantines an entire log and looks like an
  empty result.
- Open parser registry: `register_format` / `register_logformat` make a format written
  elsewhere available to `--format`, to auto-detection and to `logarc formats`.

### Ingest and storage

- Streaming ingest with memory bounded by batch size rather than file size. `.gz` and `.bz2`
  read transparently.
- Parquet partitioned by `hash(client_ip) % 64` and sorted within partition, queried through
  embedded DuckDB. Two-pass finalize — stream into buckets, then sort each — so memory follows
  the bucket count, not the corpus.
- `ip_index` summary table, so choosing a client is instant and needs no rescan.
- Malformed lines are quarantined with a reason, never dropped silently.
- Long ingests can be cancelled. A stopped run leaves the case un-finalised, and the store
  refuses to be read until it is, so a truncated log cannot be analysed as a complete one.

### Detection and segmentation

- Three-level deterministic segmentation: sessionize on idle gap, user-agent change and maximum
  duration; label each request; merge labelled runs into episodes, absorbing short benign
  interludes so one `favicon.ico` does not split an attack into three.
- Declarative YAML rule engine — signature rules for a single request, window rules for what only
  several requests reveal. Extra packs load with `--rules` and add to the bundled ones.
- Evasion-aware normalisation before matching: bounded recursive percent-decoding, NFKC,
  case folding, SQL comment stripping. Raw and decoded forms are both exposed to rules.
- OWASP mapping as an attribute rather than as the structure, with coverage stated honestly:
  six of ten categories are observable from an access log.
- `outcome` derived from status histogram and response size, so *attempted* and *succeeded* are
  different findings on the graph.

### Output

- Session trace and behaviour map, built from the same episodes, with layout computed in pure
  Python outside the GUI.
- Self-contained HTML report, JSON graph, and PNG export. Attacker-controlled strings are escaped:
  opening the report of an attack must not run the attacker's script.
- `EvidenceRef(source_file_id, line_no)` on every event, episode and node, and `logarc evidence`
  to read the original lines back.

### Desktop application

- PyQt6 window: client table, activity canvas, evidence panel, trace ⇄ behaviour toggle, export.
- All engine work on a `QThreadPool` worker; the window never calls a blocking engine function.
- Presentation rules — colour is severity, border is outcome, size is volume — kept Qt-free in
  `logarc.gui.style` and tested without a display.
- PyInstaller one-folder Windows bundle (~250 MB), carrying the rule packs and package metadata
  that a freezer otherwise drops silently.

### Evaluation

- Synthetic generator with ground truth written from behaviour, never from rule output.
- `logarc evaluate` for per-category precision/recall/F1 and boundary-level segmentation scoring;
  `logarc benchmark` for throughput, peak RSS and reconstruction latency; CSIC 2010 adapter.
- Measured results, and what they do and do not establish, in [docs/evaluation.md](docs/evaluation.md).

### Known limitations

- **Ingest throughput is ~31,000 lines/s against a 100,000 target.** Cost per line does not grow
  with the corpus, but the constant misses the goal. Parallel ingest over byte-range splits is
  the named remedy and is not implemented.
- No plugin discovery for parsers — registering one means importing a module that calls
  `register_format`.
- Four OWASP categories are not observable from an access log and are not claimed.
- Recall on CSIC 2010 is capped below 100%, because a substantial share of its attacks carry the
  payload in a POST body and an access log records the request line only.
