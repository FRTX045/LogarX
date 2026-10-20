# Architecture

## In brief

The research question is: **how do you separate one action from another, and then
classify it** — at log sizes measured in gigabytes, offline?

logarc answers it with deterministic three-level segmentation and a two-pass
ingest architecture. Determinism is a deliberate constraint: a forensic finding
must be explainable and reproducible, so every boundary the tool draws can be
traced to a stated rule and a recorded threshold.

**Two passes.** Ingest is O(n) over the log and happens once per case. Analysis
is O(k) over one client's events and happens many times, interactively. After
ingest, selecting a client reads roughly 1/64 of the store, so everything after
retrieval runs in memory instantly.

**Three levels of segmentation.**

1. **Session** — new session on an idle gap over 30 minutes, a User-Agent change
   (same address, different client: the NAT case), or 8 hours elapsed.
2. **Request label** — signature, window and sequence rules, over normalised text.
3. **Episode** — new episode when the category changes or the gap exceeds 5
   minutes, then one merge pass absorbs short benign interludes between
   same-category episodes. Without that pass a single `favicon.ico` fetch splits
   one attack into three.

Full detail below, and the reasoning behind each choice in [adr/](adr/).

## Layers

Dependencies point inward. `core/` is the centre and imports nothing else.

```
┌─ cli/ ────────────────┐  ┌─ gui/ ────────────────┐   outermost: user interfaces
│  typer commands       │  │  PyQt6 (only place    │   both drive the same engine
│                       │  │  Qt is imported)      │
└───────────┬───────────┘  └───────────┬───────────┘
            └──────────────┬───────────┘
                           ▼
   ingest/ ──▶ storage/          graphbuild/ ──▶ report/
      │                                ▲
      ▼                                │
   parsers/ ──▶ core/ ◀── normalize/ ──┴── detect/ ──▶ sessionize/ ──▶ episode/
```

| Package | Responsibility |
|---|---|
| `core/` | Domain models. No I/O, no third-party logic. |
| `parsers/` | Log format adapters. The extension point for new formats. |
| `normalize/` | Evasion-aware decoding of paths and query strings. |
| `ingest/` | Streaming read → parse → batch → write. Bounded memory. |
| `storage/` | Event store (Parquet + DuckDB), case manifest, integrity hashes. |
| `sessionize/` | Splits an IP's event stream into sessions. |
| `detect/` | Declarative rule engine; labels each request. `detect/crs/` drives the OWASP CRS sidecar, which runs after every scan unless turned off. |
| `episode/` | Merges labelled runs into activity episodes. |
| `graphbuild/` | Builds trace and behaviour graphs; computes layout. |
| `report/` | Self-contained HTML export. |
| `cli/`, `gui/` | Interfaces. Contain no analysis logic. |

## Data flow

```
access.log
    │  ingest/reader.py — streaming, gzip-aware, never loads the whole file
    ▼
parsers/  ──▶  NormalizedEvent          canonical schema; the only type that
    │                                    crosses the parser boundary
    ▼
storage/  ──▶  Parquet (partitioned by hash(ip) % 64, sorted by ip+time)
               ip_index  (per-IP summary; powers instant IP selection)
    │
    │  ◀── investigator picks an IP ───
    ▼
sessionize/  ──▶  Session[]             idle gap · UA change · max duration
    ▼
detect/      ──▶  LabelledEvent[]       signature + windowed behavioural rules
    ▼
episode/     ──▶  Episode[]             category change · gap · noise absorption
    ▼
graphbuild/  ──▶  ActivityGraph         trace (chronological) | behaviour (aggregated)
    ▼
report/ · gui/                          HTML · JSON · on-screen graph
```

## Why two passes

The GUI also offers a case-wide prioritization scan before client selection.
`triage/` shares session labeling with reconstruction, stores compact profiles,
and ranks suspicious and statistically unusual clients with source references.
It runs in a cancellable process and caches completed results separately from
the evidence store. All-client search uses a separate paginated summary query:
the stored IP index for a whole case and window aggregation for selected ranges.
It filters in storage, preserves population positions, and runs off the GUI
thread with immediate stale-response invalidation and 150 ms input debounce.
Selecting a recommendation still uses the per-IP analysis
path below. See [IP prioritization](ip-prioritization.md) for policy and cache
semantics.

Ingest is O(n) over the log and happens **once per case**. Analysis is O(k) over one IP's events
and happens **many times**, interactively.

Separating them is what makes large logs workable: after ingest, selecting an IP reads roughly
1/64 of the store (partition pruning) with row-group statistics eliminating most of the rest.
Since one IP typically has 10²–10⁵ events, everything after retrieval runs in memory instantly.

Ingest memory is bounded by the Arrow batch size (100k rows), not by file size — a 50 GB log
ingests in roughly constant RAM.

Ingest can also be spread across processes (`--workers N`). A sequential byte scan first records
where the file can be cut on line boundaries, what line number each range begins at, and the
SHA-256; workers then parse a range each, writing their own Parquet shard and quarantine file into
the shared case. The line numbers are why the scan exists: `EvidenceRef` carries one, and a worker
opening the file at byte 25,000,000 has no other way to know it is at line 130,457.

It is off by default. Each worker holds a batch of its own, so memory rises roughly in step with
the count, and bounded memory is not spent without being asked. Compressed logs cannot be split at
all — gzip has no random access — and fall back rather than failing. See
[ADR-0009](adr/0009-parallel-ingest-rather-than-a-native-parser.md) for why the work was
parallelised instead of the parser being rewritten in another language.

That holds for the streaming half by construction, but not for `finalize`, which sorts the whole
corpus in one query to give the Parquet row groups the ordering that later makes pruning work.
Left at its defaults the query engine will claim most of the machine before it spills anything;
measured at ten million events that came to 6.9 GB. It is therefore given an explicit memory
ceiling and a scratch directory, which turns that sort into an external one — slower on a corpus
that would not have fitted in memory anyway, and the difference between a tool that runs on a
laptop and one that does not. The scratch directory is removed once finalize completes; a spill
can be gigabytes, and it is not evidence.

Every store, reader or writer, spills into a folder of its own inside that directory. The
engine names its spill files the same in every process, so two readers of one case spilling into
one folder write over and delete each other's files; measured on a 941,031-event case, that
crashed 4 of 10 readers and failed 4 more. Two windows on one case, or two jobs of one window,
are two such readers. The engine makes the folder when it first spills and removes it on close.

## Segmentation

See [ADR-0003](adr/0003-deterministic-three-level-segmentation.md) for the reasoning.

**Level 1 — Session.** New session when idle gap > 30 min, User-Agent changes (same IP, different
client — the NAT/proxy case), or duration exceeds 8 h.

**Level 2 — Request label.** Three rule families, all declarative YAML:
- *Signature* — regex over normalized path / query / user-agent / referer.
- *Behavioural* — windowed metrics such as distinct-path count and 404 ratio, which cannot be
  expressed as a single-request match.
- *Sequence* — one request, then another within a time, unless a third came between: order
  rather than quantity, such as being bounced from an admin page and then let into one without
  signing in.

Matching runs against **normalized** text. Without recursive percent-decoding, `%2553ELECT`
evades every signature. Decoding is bounded to 3 iterations and the depth is recorded, because a
depth greater than 1 is itself an evasion signal. Both raw and decoded forms are exposed as
separate match fields.

**OWASP CRS is a third source of signature matches**, run through Coraza in a Go sidecar after
every scan — by the window and by `logarc ingest`, unless the reader turned it off — and by
`logarc enrich` on demand, then read from the case thereafter. It supplies the signatures the packs
above miss — they catch 961 of the 1,099 access-log-visible cases in CRS's own regression corpus,
87.4% on 2026-10-05, and fire on none of its 134 certified-harmless ones — and nothing else: CRS is
stateless per request, so it expresses no behavioural rule, and it emits rule ids and tags rather than an
`ActivityCategory`. A CRS detection is attached as evidence wherever it matched, and names the
activity only where the packs reached INFO, meaning either nothing matched or the only match was
an observation like `Scripted Client`. Anything LOW or above is a real claim and keeps precedence.
See [ADR-0008](adr/0008-crs-as-a-signature-layer-beside-the-rule-packs.md).

When several rules match, the highest severity becomes the primary label; all matches are kept as
evidence. Unmatched requests fall through to benign classification (static asset, page view, API
call, auth attempt).

**Level 3 — Episode.** New episode when the label category changes or the gap exceeds 5 min. Then
one merge pass absorbs short benign interludes between same-category episodes.

## Extension points

**Adding a log format.** Implement `parsers.base.LogParser`:

```python
class LogParser(Protocol):
    name: str
    def sniff(self, sample: Sequence[str]) -> float: ...          # 0.0–1.0 confidence
    def parse_line(self, line: str, line_no: int) -> NormalizedEvent | None: ...
```

Register it in `parsers/registry.py`. Nothing else changes.

For Apache-style formats there is no new code at all, and no Python either: write the
directive down with `logarc formats add` or in **Case → Log formats…**, and
`parsers/logformat.py` compiles it into a matcher.

A format is a *definition*, not a name — `parsers/spec.py` — because a name only
resolves where the definition is already known, which is untrue in the two places
it matters: an ingest worker started by spawn, and a case read back after the
format was edited. Both are handed the definition itself, so the saved-format
library in `parsers/library.py` is read only by the CLI and the window, never by
the engine. See
[ADR-0010](adr/0010-a-log-format-is-data-that-travels-with-the-work.md).

**Adding a detection.** Write YAML in `detect/rulepacks/`. No Python. Rule packs are versioned and
hashed into the case manifest, so a report states exactly which ruleset produced it — as is the CRS
revision and paranoia level when a case was enriched, and an analysis that ran without CRS says so
on every run rather than quietly reporting less.

**Replacing storage.** Implement `storage.base.EventStore`.

**OWASP annotations.** Bundled rules map to Top 10:2025 through optional `owasp`
strings. These are report metadata, independent of behavioural `category`,
label precedence, episode boundaries and graph structure. Custom rules can
retain annotations from earlier editions, including `:2021`; the loader and
report paths preserve their values. Updating an annotation changes the native
ruleset fingerprint but needs no API, case-schema or rule-pack-schema change.
The CRS integration is independent: external CRS rules are unchanged, and
CRS-only labels retain their existing lack of an OWASP annotation.

## Forensic integrity

- Input files are opened read-only and never modified. SHA-256 is recorded at ingest.
- `case.json` records source files with hashes and sizes, ingest time, tool version, rule-pack
  versions and hashes, and every configuration threshold used.
- Each `Episode` carries `(source_file_id, source_line_no)` references, so every node in the graph
  resolves to exact raw log lines.
- Malformed lines are quarantined and counted, never silently dropped.

Together these mean a finding can be reproduced from the manifest alone.
