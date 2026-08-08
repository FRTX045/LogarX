# ADR-0002: DuckDB over partitioned Parquet as the event store

- **Status:** Accepted
- **Date:** 2026-08-08

## Context

Logs may reach tens of gigabytes. The interaction model is:

1. **Ingest once** — a full linear scan, done one time per case.
2. **Analyze many times** — repeatedly pull *one IP's* events and reconstruct its activity.

Step 2 must feel instant, and step 1 must not require holding the log in memory. Re-scanning the
raw log for every IP the investigator clicks is not viable.

Candidates considered: re-parse on demand (no store), SQLite, DuckDB over Parquet.

## Decision

Ingest streams into **Parquet files partitioned by `hash(client_ip) % 64`**, sorted within each
partition by `(client_ip, timestamp)`, and query them with **embedded DuckDB**.

Ingest also builds a small `ip_index` summary table (per-IP request count, first/last seen,
distinct paths, 4xx ratio) so the "choose an IP" screen never triggers a full scan.

Both live behind `storage.base.EventStore`, so the backend is replaceable.

## Rationale

- **Partitioning + sorting** means a single-IP query touches roughly 1/64 of the data, and
  Parquet row-group min/max statistics prune most of what remains.
- **Columnar + zstd** typically compresses 8–15× against raw text.
- **Embedded** — no server to install or run, which matters for a tool investigators run on an
  isolated workstation.
- **Parquet is an open archival format.** A case directory stays readable by pandas, Polars,
  Spark or DuckDB long after this tool stops being maintained. For evidence that may be revisited
  years later, this outweighs convenience.

SQLite was rejected on the last two points more than on speed: its file is only readable by
tooling that speaks SQLite, and row-oriented storage is a poor fit for the wide analytical scans
`ip_index` construction performs.

## Consequences

**Positive.** Constant-memory ingest, millisecond per-IP retrieval, small case directories, and
an archival format independent of this tool.

**Negative.** Two dependencies (`pyarrow` + `duckdb`) instead of the standard library's `sqlite3`,
and a case is a *directory* rather than a single file — slightly more awkward to move around.
Packaging both into a PyInstaller bundle adds roughly 60 MB.

**Deferred.** The partition count (64) is fixed. If it proves wrong for very small or very large
cases, it becomes a function of estimated row count — but not before measurement justifies it.
