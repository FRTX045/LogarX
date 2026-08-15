# Changelog

Notable changes to logarc. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Interface

- **Type an address to find one client among tens of thousands.** A filter box above the client
  list, always visible rather than behind a keystroke — a control nobody can find is a control that
  is not there. A complete address matches exactly, because substring matching answered
  `203.0.3.9` with eleven rows: `203.0.3.90` through `.99` all contain it, and an investigator
  copying an address out of a ticket could open the wrong one. Anything shorter stays a search, so
  `203.0.3.` isolates a /24 and `113.66` finds a remembered tail. Every filtered caption names the
  total — a narrowed list reading `9 clients` describes a case with nine clients in it — and an
  empty result says which filter emptied it rather than leaving a blank table.
- **A case you have opened before is one click away.** Opening the window puts
  the list in front of you — **View → Reopen the last case on start** skips it
  and goes straight to the case you were in — and **Case → Recently opened…**
  (Ctrl+Shift+O) brings it back at any time.
  Right-click a row to **pin** it, **rename it in this list**, show its folder,
  or drop just that one. A pinned case holds the top and is exempt from the
  ten-entry cap, so a busy week cannot push it off the end. A rename is a name
  for *this list*: `case.json` is untouched, because the case id is printed in
  the provenance table of every exported report and renaming the case itself
  would leave a report written yesterday and one written today disagreeing about
  what the same case is called. The folder column still shows what it really is.
  Reopening a case keeps whatever pin and name the list already held for it —
  the snapshot read off disk knows about neither. Reopening yesterday's work
  meant navigating a folder dialog to a path you had to remember. The last case
  now reopens with the window — **View → Reopen the last case on start** turns
  that off — and **Case → Recently opened…** (Ctrl+Shift+O) offers the rest as a
  table: when each was opened, how many events it holds, which log it was built
  from, and which folder it is. A submenu was drawn first and rejected against
  it: two cases named `case-001` and `case-002` are not told apart by a name.
  A case whose folder has moved stays listed, says so, and cannot be chosen —
  offering it would send the reader into a failure the list already knew about.
  A case is recorded only once it has opened, so the list never fills with
  entries that lead nowhere.
  **This is the first thing logarc stores that records what was investigated**
  rather than how the window looked doing it: the folders, and when they were
  opened, under `HKCU\Software\logarc`. The chooser carries **Forget these**,
  and the README says what is kept.
- **A long trace wraps instead of running off the canvas.** Laid out on one row
  it was as wide as it was long and barely taller than a node, so fitting it
  shrank the scene to 0.64 on seven episodes and 0.15 on thirty — correct, and
  no longer legible. Rows now wrap and alternate direction; seven episodes fit
  at 1.16 and thirty at 0.75. Short traces keep their straight line.
  See [ADR-0009](docs/adr/0009-parallel-ingest-rather-than-a-native-parser.md)'s
  neighbour, and the numbers in the commit.
- **The side panels could not be resized at all.** The key added below the
  canvas was one unbroken row and reported a minimum width of **1,729px** —
  wider than the window it sat in. A minimum is a demand, so the centre column
  inherited it and both side panels were pinned at their own minimums to pay for
  it; with no slack anywhere, a splitter handle had nothing to give. Measured on
  the client panel: **one** reachable width, or zero if collapsed. Dragging it
  therefore did nothing until it jumped the whole way.
  The key now wraps onto as many rows as it needs (107px minimum, 23 reachable
  widths on the same panel), extra width goes to the graph rather than being
  shared out, and panels no longer collapse to an invisible handle against the
  window edge. The 430px floor put on the client table to stop its columns
  hiding is gone — it was the wrong tool, and it was half of what wedged this.
- **The evidence is a sortable table.** One row per request — source, time,
  the request, status, size — with the selected row shown in full beneath it.
  Twenty-five pieces of evidence were 175 rows of wrapped text readable only in
  the order they arrived; they are twenty-five rows now, and can be **sorted by
  size to find the request that got data out** or by status to find what was
  served rather than refused. Those are the two questions a blue team asks of an
  episode and neither could be answered before without reading every line.
  The detail pane carries the whole payload, the agent at full length, and the
  source line **exactly as the log holds it** — so nothing is summarised away,
  only moved to where there is room for it. `View → Show raw log lines` is
  retired: the pane shows the original for the selected row always, which is
  strictly more than a global on-or-off could give.
- **Both tables were showing raw numbers in place of their formatted values.**
  Qt keeps `DisplayRole` and `EditRole` in one slot on a table item, so a sort
  key written to `EditRole` replaces the text. The client list has shown
  `0.8888888888888888` where it formats `89%` since it was written — in the
  column an investigator sorts by when looking for something worth opening. The
  key now lives in a role of its own, in one shared item both tables use.
- **The evidence panel showed everything except the evidence.** It printed the
  raw source line and nothing else. A Combined line is 293 characters, of which
  **53% is the user agent** and 15% is the client address and timestamp already
  printed in the heading above — leaving **15% carrying the whole finding**, and
  that 15% written as `%27+OR+%271%27%3D%271`. Unwrapped in a ~330px panel every
  line ended at `"GET` with the payload off the right-hand edge; six pieces of
  proof on screen and not one of them showed any.
  Each piece of evidence is now laid out as the request it was — target, status,
  size, referer, agent — **parsed by the same parser that ingested the file**,
  so what is shown is what the detection actually ran against rather than a
  second reading that could disagree with it. nginx, IIS and JSON cases get this
  for nothing. A line the parser cannot read falls back to its raw text, because
  a request that will not parse is itself worth seeing.
  Targets are URL-decoded, so `' OR '1'='1` reads as the tautology it is.
  **Every decoded string is neutralised first**: an attacker controls the URL,
  and `%0A` would otherwise let them compose what looks like a second log entry
  inside the panel, while `%E2%80%AE` would let them reverse how a hostile path
  is drawn. Control and format characters are printed as `<U+000A>` instead.
  Decoding is one pass, so a doubly-encoded payload keeps the percent signs that
  give the evasion away.
  Response sizes read as sizes (`1.3 MB`), a served status stands out while a
  refused one recedes — a 2xx on an injection is the alarm, not the reassurance
  — and an agent identical to the one above is stated once, which turns a field
  that filled twelve of twenty-six rows into a signal that a client changed tool
  mid-episode. Measured on six requests: **489 characters in place of 1,170**.
  Two menu items, both remembered: **View → Decode URL escapes** for when the
  encoding itself is the finding, and **View → Show raw log lines** (Ctrl+R),
  which prints the whole source line verbatim beneath each entry. The
  `file:line` reference is printed whatever either is set to.
- **The evidence panel said "1 requests"** while the node caption beside it said
  "1 request", because each formatted the count itself. One shared helper now.
- **The wrap can be turned off** — **View → Wrap long traces**, Alt+Z, as an
  editor spells it, because it is the same choice about the same trade: fold the
  long line and read it, or keep it straight and scroll. Folding stays the
  default. An unwrapped trace no longer opens half way along itself: once the
  fit clamps at the legibility floor the view starts at the first activity,
  which is the only place to begin reading a chronology. The setting is
  remembered between launches, which means the desktop application now writes
  one key to `HKCU\Software\logarc`; nothing else about it leaves the machine.
  It is greyed out on the behaviour map, where a circle has no rows to fold.
- **A key to the drawing**, under the canvas and in the HTML report. Colour is
  severity, the outline is outcome, size is volume — none of which was written
  anywhere a reader could see it. Built from the tables the renderers draw from,
  so it cannot describe a colour no longer in use.
- **The activity being read is ringed on the canvas.** Clicking a node filled
  the evidence panel and left nothing saying which node it belonged to.
- **The behaviour map says how often a transition was seen** (`x3`), rather than
  carrying it in line thickness alone — which cannot be read as a number or
  compared between two clients' maps, and which is the finding on that view.
- **All six client-table columns fit.** Three of them sat behind a scrollbar,
  including the 4xx ratio the table is sorted by when looking for something
  worth opening.

### Performance

- **Ingest can parse a log across worker processes** — `logarc ingest --workers N`. Measured on
  400,000 lines, ingest only: 27,265 lines/s sequential against **69,655 at eight workers, 2.55×**.
  Profiling drove the choice: parsing is 96% of ingest and the regex is only a quarter of *that*,
  so a faster pattern engine had little to give while the work parallelises cleanly.
  See [ADR-0009](docs/adr/0009-parallel-ingest-rather-than-a-native-parser.md).
- **The parse path reads fields by group index rather than through a dictionary.** `parse_line`
  called `groupdict()` and read the result back through sixteen `dict.get` calls per line; the
  indices are fixed once a format is compiled, so they are resolved there. The timestamp is built
  in UTC and shifted rather than built in the log's zone and converted, which drops an `astimezone`
  and two allocations a line. Measured, best of three runs of 300,000 lines: **51,268 → 58,508
  lines/s parsing, +14.1%**, and **28,772 → 33,435 lines/s ingesting a million lines end to end,
  +16.2%** — both versions run on one machine minutes apart rather than compared against a figure
  from another day.
- **The 100,000 lines/s target is still not met**, and the estimate that was going to close it was
  wrong. The remedy named in 0.1.0 — parallel ingest — closes about two thirds of the gap; the
  prediction of 124,000 assumed throughput scales with the worker count, and it does not, because
  the test machine has four physical cores behind eight logical ones. The remaining "40% of parse
  time in field marshalling" recorded here was `cProfile` self-time, which inflates exactly the
  per-call overhead that removing it takes away: the real rate moved by a seventh, not a third.
  What is left is the regex at 30% of the parse and constructing the event at 10%, and no
  rearrangement of Python reaches the target from there.
- Parallel ingest is opt-in and defaults to off, because **each worker holds its own batch and
  memory rises roughly in step with the count.** Bounded memory is one of the design's stronger
  claims and is not spent without being asked. Compressed logs (no random access) and logs under
  32 MB (spawning costs more than parsing saves) fall back to sequential rather than failing.
  Cancellation is not offered on the parallel path — a stop that only sometimes reaches every
  process is worse than none — so the sequential path, which the desktop application uses, keeps it.
- `logarc enrich` no longer reads the whole case into memory. `EventStore.all_events()` streams, and
  both of its consumers were undoing that: the CLI wrapped it in `list()` and the sidecar collected
  it again into a dict of lists. On a twelve-million-line case that was several gigabytes, against a
  design whose central claim is that memory follows the batch size.

### Fixed

- **Every command that reads a case crashed on one whose ingest never finished** —
  `list-ips`, `analyze`, `evidence`, `export`, `enrich`, all with an unhandled
  exception and no message at all. That state is not a corner case: cancelling an
  ingest leaves one deliberately so the part already read is not thrown away, and
  the window says as much. Someone told a case "cannot be analysed" and then
  trying a command against the folder got a stack trace. It now says which case
  was never finalised.
- **Paths printed to the terminal could not be copied.** Rich wraps to the console
  width and a path offers no spaces to break at, so a long one was cut mid-word —
  and the case folder, which every later command takes as `--case`, was in a table
  title, where it arrived as three centred fragments padded with spaces. It now
  sits under the table as `Case: <path>`, on one line. The same applied to the
  error naming a file that could not be parsed, which was breaking that filename
  across five lines.
- **The behaviour map drew one arrow where there were two.** A map folds a trace by activity type,
  so a client alternating between two of them produces an edge each way between the same circles —
  and drawn straight, both are the same line. Measured, the two midpoints were `0.0` apart, so the
  second label was written exactly over the first and which transition survived was the order the
  edges happened to be listed in. Only a reciprocal pair now bows, so the curve means *there are
  two arrows here* and the map stays straight everywhere else. The HTML report had the identical
  fault — its cubic is symmetric under reversal — and is separated the same way.
- **An arrow and the report disagreed about the same gap.** `report/html.py` had grown its own
  duration formatter beside `gui.style`'s, and the two had drifted: nine of eleven sample gaps
  differed. One transition read `1h 0m` in the window and `60m` in the report, `5h 33m` against
  `5.6h`, and half a second was reported as `0s` — a gap presented as no gap. The report now uses
  the window's own label, which is what the severity colours already do.
- **Captions collided when the graph was zoomed out.** Text was pinned to screen size so `fit()`
  could not shrink it into a smudge, which meant the geometry shrank while the words did not: on a
  52-activity trace, overlapping caption pairs went from 7 at full zoom to **117 at 0.35** and 228
  at 0.25. The whole drawing scales together again — so two captions that clear each other at one
  zoom clear each other at every zoom — and the smudge is answered by sizing captions against the
  fit floor instead, where they come out at the size they always were. Layout spacing widened to
  suit, and is stretched further at draw time when the platform's font is wider than it assumes.
- **The numbers on an arrow were three times dimmer than the captions beside them** — 5.5:1 against
  a caption's 16.5:1, at half a point smaller. Legal by the 4.5:1 floor and unreadable in practice,
  because the eye is calibrated by the brighter text next to it.

- **The desktop application ignored CRS entirely.** `analyse_ip` has taken a detection index since
  CRS was added and the CLI passed one, but the window never did — so the same enriched case
  reported different findings depending on which front end asked. `CrsEvidence` and
  `Case.crs_evidence()` are now the one way to obtain it, so the two cannot disagree again.
- **Staged Parquet files were numbered per store instance.** Harmless with one writer and silent
  data loss with several: every worker would have written `part-000000.parquet` and all but the
  last would have been replaced.
- **CI never built the CRS sidecar**, so the four tests covering the Python/Go boundary skipped
  themselves on every run — the newest and least-proven component was the one nothing verified. CI
  now builds it on both runners and sets `LOGARC_REQUIRE_CRS=1`, which turns the skip into a
  failure so a broken build cannot go back to being quiet.

### Detection

- **OWASP CRS runs beside the bundled rules**, through Coraza in a Go sidecar. `logarc enrich`
  replays a case's requests past CRS once and stores the result; `analyze`, `evidence`, `export`
  and `evaluate` read it. This is the real CRS, not a copy of its patterns: the transformation
  chains, per-`ARGS` targeting, rule chaining and libinjection are what a regex port would lose.
  Optional, and a case without it analyses natively and says so on every run. See
  [ADR-0008](docs/adr/0008-crs-as-a-signature-layer-beside-the-rule-packs.md); build instructions
  are in `crs/README.md`.
- **Every native rule is kept.** CRS does one of the four jobs the detection layer performs — the
  signature matching — and cannot do the others: it is stateless per request, so it expresses none
  of the five window rules; it emits rule ids and tags rather than an `ActivityCategory`; and it
  says nothing at all about the traffic no rule matched.
- A CRS detection names a request **only where the rule packs reached INFO** — nothing matched, or
  the only match was an observation like `Scripted Client`. Anything LOW or above is a real claim
  and keeps precedence. CRS is attached as evidence either way, with `crs:942100`-style rule ids.
- **Paranoia level 2 by default**, chosen by measurement. Across CRS's own 1,194 access-log-visible
  regression payloads, PL1 classifies 67% as hostile and PL2 reaches 90%. PL2 is also the ceiling:
  20,000 requests of generated benign traffic yield zero detections at every level, and on 365
  lines of real 2010 WordPress traffic PL1 and PL2 leave the hostile-episode count untouched while
  PL3 flags a plain `GET /` as "Unix Shell Code Found in Request".
- The CRS revision, configuration fingerprint and paranoia level are written into the case
  manifest, and reported beside the ruleset fingerprint.
- **HTML entity, JavaScript escape and null-byte normalisation.** `&#60;script&#62;` and
  `/etc/passwd%00.jpg` now reach the rules in the form the server acts on. The three decoders run
  in one loop with percent-decoding rather than in sequence, because they nest in both directions —
  `%26lt%3B` is percent-then-entity and `&#x25;3C` is entity-then-percent. Entity decoding is
  deliberately stricter than `html.unescape`, which resolves unterminated named entities and would
  invent payloads in ordinary query strings.
- A null byte is now stripped from the matched text but recorded on the result as `had_null`, and
  exposed as a `had_null` match field. This reverses an earlier decision to keep the null in the
  text: the reasoning behind it — that sending one is never accidental — was right, but keeping it
  in the text meant `sensitive_file_access` never saw the path the server actually opens. Both are
  satisfiable at once.

### Added

- `EventStore.all_events()`, a streamed whole-case read. Enrichment needs one pass over everything
  rather than a lookup per client.

### Fixed

- **`distinct_paths` counted `/a/b`, `/a//b` and `/a/./b` as three paths.** That metric is a
  threshold in three of the five bundled window rules, so how a path happened to be written decided
  whether a behaviour was detected — eight requests across two resources were labelled directory
  enumeration. Paths are now counted canonically while `top_targets` still reports what was
  actually requested. Note this changes window-rule firing, not only accuracy: episodes whose
  detection depended on the inflated count will no longer be labelled.

### Evaluation

- **The bundled rules were measured against the OWASP CRS regression corpus at 12.3%** — 140 of the
  1,138 payloads an access log can carry, against a ceiling of 27% because three cases in five ride
  in a request body. Reported because a changelog quoting only favourable numbers is worse than
  none, and because it is the evidence for adopting CRS rather than writing more signatures.
- **That gap is expressiveness, not decoding**, and it was measured rather than assumed. Adding the
  three transforms above moved the rate by three cases. Of the 1,001 missed payloads, five carry an
  HTML entity, one a JavaScript escape and none a null byte; the rest arrive in plain text with no
  rule expressing them — `for %variable in (set) do`, `while(!false)`, Postgres `::jsonb`
  operators. See [ADR-0007](docs/adr/0007-scoring-detection-against-the-crs-regression-corpus.md).
- The `logarc score-crs` command that produced those figures was added and then removed within this
  same unreleased cycle, so it never shipped: once CRS supplies detection, scoring against CRS's own
  corpus grades the rules with the suite their project maintains. ADR-0007's postscript names the
  commits, and reverting the removal restores it.

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
