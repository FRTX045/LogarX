# Architecture

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
| `detect/` | Declarative rule engine; labels each request. `detect/crs/` drives the optional OWASP CRS sidecar. |
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

## Segmentation

See [ADR-0003](adr/0003-deterministic-three-level-segmentation.md) for the reasoning.

**Level 1 — Session.** New session when idle gap > 30 min, User-Agent changes (same IP, different
client — the NAT/proxy case), or duration exceeds 8 h.

**Level 2 — Request label.** Two rule families, both declarative YAML:
- *Signature* — regex over normalized path / query / user-agent / referer.
- *Behavioural* — windowed metrics such as distinct-path count and 404 ratio, which cannot be
  expressed as a single-request match.

Matching runs against **normalized** text. Without recursive percent-decoding, `%2553ELECT`
evades every signature. Decoding is bounded to 3 iterations and the depth is recorded, because a
depth greater than 1 is itself an evasion signal. Both raw and decoded forms are exposed as
separate match fields.

**OWASP CRS is a third, optional source of signature matches**, run through Coraza in a Go sidecar
by `logarc enrich` and read from the case thereafter. It supplies breadth the packs above do not —
they catch 12.3% of the payload syntax CRS enumerates — and nothing else: CRS is stateless per
request, so it expresses no behavioural rule, and it emits rule ids and tags rather than an
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

For Apache- and nginx-style formats there is usually no new code at all: `parsers/logformat.py`
compiles a `LogFormat` directive string directly into a matcher.

**Adding a detection.** Write YAML in `detect/rulepacks/`. No Python. Rule packs are versioned and
hashed into the case manifest, so a report states exactly which ruleset produced it — as is the CRS
revision and paranoia level when a case was enriched, and an analysis that ran without CRS says so
on every run rather than quietly reporting less.

**Replacing storage.** Implement `storage.base.EventStore`.

## Forensic integrity

- Input files are opened read-only and never modified. SHA-256 is recorded at ingest.
- `case.json` records source files with hashes and sizes, ingest time, tool version, rule-pack
  versions and hashes, and every configuration threshold used.
- Each `Episode` carries `(source_file_id, source_line_no)` references, so every node in the graph
  resolves to exact raw log lines.
- Malformed lines are quarantined and counted, never silently dropped.

Together these mean a finding can be reproduced from the manifest alone.
