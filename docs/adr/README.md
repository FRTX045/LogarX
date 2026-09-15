# Architecture decision records

One record per decision that would be expensive to reverse. Each says what was
chosen, what it cost, and what was rejected — the code already says what
happens.

**A record is never renamed and never deleted.** Its number is its identity, and
several of these files are linked from other records, from `docs/` and from
commit messages. When a decision stops holding, the record stays where it is and
gains a status line and an amendment saying what replaced it. That is why the
table below exists: a filename cannot tell you that 0005's corpus decision no
longer holds, so this is where the state of each record is written down.

## The records

| | Decision | Status |
|---|---|---|
| [0001](0001-layered-architecture-and-canonical-event-schema.md) | Layered architecture around a canonical event schema | Accepted |
| [0002](0002-duckdb-parquet-event-store.md) | DuckDB over partitioned Parquet as the event store | Accepted |
| [0003](0003-deterministic-three-level-segmentation.md) | Deterministic three-level segmentation | Accepted |
| [0004](0004-pure-python-graph-layout.md) | Pure-Python graph layout, no Graphviz dependency | Accepted |
| [0005](0005-measuring-accuracy-against-generated-ground-truth.md) | Measure accuracy against generated ground truth | **Partly superseded by [0011](0011-a-real-server-log-is-the-headline-corpus.md)** — the generator it describes was removed. How to *score* still stands; the corpus does not. |
| [0006](0006-qgraphicsview-rather-than-an-embedded-browser.md) | Draw the activity graph on QGraphicsView, not in an embedded browser | Accepted |
| [0007](0007-scoring-detection-against-the-crs-regression-corpus.md) | Score detection against the OWASP CRS regression corpus | **Accepted, tooling since removed.** The measurement was taken once; `logarc score-crs` went in `2868e78` and is not coming back, so the figure cannot currently be re-derived. |
| [0008](0008-crs-as-a-signature-layer-beside-the-rule-packs.md) | Run OWASP CRS beside the rule packs, not instead of them | **Accepted, amended 2026-09-15** — `score-crs` returns, scoring this project's rules against CRS's corpus rather than CRS's own |
| [0009](0009-parallel-ingest-rather-than-a-native-parser.md) | Parallelise ingest rather than rewrite the parser in another language | Accepted |
| [0010](0010-a-log-format-is-data-that-travels-with-the-work.md) | A log format is data, and it travels with the work | Accepted |
| [0011](0011-a-real-server-log-is-the-headline-corpus.md) | A real server's log is the headline corpus, and the generator is removed | Accepted |

## Which to read first

**[0003](0003-deterministic-three-level-segmentation.md)**, if you only read one.
Session, request label and episode are the whole tool, and every other record
assumes them.

**[0005](0005-measuring-accuracy-against-generated-ground-truth.md)**, if you
want to see the format working. It is the record that turned out to be wrong,
kept intact with its reasoning visible and an amendment explaining what the
project learned. A directory of unanimously "Accepted" decisions is a directory
nobody has been honest in.

## Adding one

Copy the shape of an existing record rather than a template: a title line, a
**Status** and **Date**, then Context, Decision, Consequences, and Alternatives
considered. Number it one past the highest.

Two things make a record worth writing rather than a comment in the code:

- **It is expensive to reverse.** A choice of data store, a process boundary, a
  scoring method. If undoing it is an afternoon, it is not an ADR.
- **A reasonable person would ask why.** The record exists to answer the question
  before it is asked for the third time.

Write the alternatives down even when the choice was obvious at the time.
Obvious-at-the-time is exactly the thing that stops being obvious, and the
rejected option is what the next reader needs in order to disagree usefully.
