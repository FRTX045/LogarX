# Documentation

Start with whichever question you arrived with.

| If you want to know | Read |
|---|---|
| How the whole thing fits together | [architecture.md](architecture.md) |
| How to use the desktop application | [desktop-app.md](desktop-app.md) |
| How to add a detection without writing Python | [writing-rules.md](writing-rules.md) |
| How to support another log format | [adding-a-parser.md](adding-a-parser.md) |
| How well it works, and what the numbers do not establish | [evaluation.md](evaluation.md) |
| What the automated suite cannot check | [manual-test-plan.md](manual-test-plan.md) |
| **Why** it is built this way | [adr/](adr/), and the table below |

---

## Architecture decision records

A record per decision that would be expensive to reverse: what was chosen, what
it cost, and what was rejected. Code says what happens; these say why the other
road was not taken.

The ones that turned out to be wrong are the most useful. They are amended in
place rather than deleted, so the reasoning that led somewhere wrong stays
readable — ADR-0005 is the example worth reading first.

| | Decision |
|---|---|
| [0001](adr/0001-layered-architecture-and-canonical-event-schema.md) | Layered architecture around a canonical event schema |
| [0002](adr/0002-duckdb-parquet-event-store.md) | DuckDB over partitioned Parquet as the event store |
| [0003](adr/0003-deterministic-three-level-segmentation.md) | Deterministic three-level segmentation |
| [0004](adr/0004-pure-python-graph-layout.md) | Pure-Python graph layout, no Graphviz dependency |
| [0005](adr/0005-measuring-accuracy-against-generated-ground-truth.md) | Measure accuracy against generated ground truth — **superseded by 0011** |
| [0006](adr/0006-qgraphicsview-rather-than-an-embedded-browser.md) | Draw the activity graph on QGraphicsView, not in an embedded browser |
| [0007](adr/0007-scoring-detection-against-the-crs-regression-corpus.md) | Score detection against the OWASP CRS regression corpus |
| [0008](adr/0008-crs-as-a-signature-layer-beside-the-rule-packs.md) | Run OWASP CRS beside the rule packs, not instead of them |
| [0009](adr/0009-parallel-ingest-rather-than-a-native-parser.md) | Parallelise ingest rather than rewrite the parser in another language |
| [0010](adr/0010-a-log-format-is-data-that-travels-with-the-work.md) | A log format is data, and it travels with the work |
| [0011](adr/0011-a-real-server-log-is-the-headline-corpus.md) | A real server's log is the headline corpus, and the generator is removed |

---

## Reading order, if you are new

1. [architecture.md](architecture.md) — the layers and the data flow, in one page.
2. [adr/0003](adr/0003-deterministic-three-level-segmentation.md) — the three
   levels of segmentation are the heart of the tool, and the one place a reader
   should not skim.
3. [evaluation.md](evaluation.md) — what it scores, and every condition those
   scores carry. Read the caveats, not only the tables.
4. [adr/0011](adr/0011-a-real-server-log-is-the-headline-corpus.md) — why the
   headline numbers went *down*, and why that was the first honest measurement.
