# Changelog

Notable changes to logarc. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
