"""Event storage: streaming Parquet writes, DuckDB reads.

Ingest appends batches to staging Parquet files, which keeps memory bounded by
batch size rather than log size. `finalize` then hands the staged data to DuckDB
to be rewritten partitioned by a hash of the client IP and sorted within each
partition, and builds the per-IP summary table.

That rewrite costs one extra pass over the data at ingest time and buys the
thing the tool is built around: pulling one client's events out of a very large
case in milliseconds, repeatedly. See ADR-0002.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.core.window import TimeWindow
from logarx.search import is_whole_address
from logarx.storage.base import (
    CaseOverview,
    ClientMatchPage,
    IpSummary,
    IpSummaryPage,
    TimeSlot,
)

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable, Iterator

    from logarx.search import Query

__all__ = ["ParquetEventStore", "StoreStateError"]


class StoreStateError(RuntimeError):
    """Raised when the store is used out of order."""


#: Number of hash buckets the events are partitioned across. A single-IP query
#: touches one of these, so the constant trades write-side file count against
#: read-side selectivity.
BUCKETS: Final = 64

#: Rows pulled from the query engine per fetch when streaming the whole
#: case. Large enough that the round trip is not the cost, small enough that
#: a 12M-line case never has more than this resident.
_STREAM_CHUNK: Final = 50_000

#: How much memory the query engine may use. Deliberately modest: `finalize`
#: sorts the whole corpus, and left to its own devices DuckDB claims most of the
#: machine before it spills anything — ten million events peaked at 6.9 GB.
#: Bounding it makes the sort external, which is slower on a corpus that would
#: not have fitted anyway, and keeps the tool usable on an ordinary laptop while
#: the rest of it is still running.
DEFAULT_MEMORY_LIMIT: Final = "1GB"

#: Rows a worker buffers before flushing a partition during the bucketing pass.
#: The default is half a million per worker, which across eight of them is four
#: million rows resident — memory that grows with the corpus. Flushing this much
#: sooner trades a little write throughput for a peak that is a constant.
PARTITION_FLUSH_ROWS: Final = 65_536

#: Sort keys exposed to callers, mapped to SQL. A whitelist rather than string
#: interpolation of whatever was asked for: this text ends up in a query.
SORT_KEYS: Final[dict[str, str]] = {
    "requests": "request_count DESC",
    "recent": "last_seen DESC",
    "errors": "client_error_ratio DESC, request_count DESC",
    "bytes": "bytes_total DESC",
    "paths": "distinct_paths DESC",
}

#: Timestamps are stored without a zone. The parser normalises everything to UTC
#: before it gets here, so the zone is a constant; recording it per row would be
#: redundant and forces a timezone database dependency at read time.
SCHEMA: Final = pa.schema(
    [
        ("timestamp", pa.timestamp("us")),
        ("client_ip", pa.string()),
        ("method", pa.string()),
        ("path", pa.string()),
        ("query", pa.string()),
        ("protocol", pa.string()),
        ("status", pa.int32()),
        ("bytes_sent", pa.int64()),
        ("referer", pa.string()),
        ("user_agent", pa.string()),
        ("host", pa.string()),
        ("source_file_id", pa.string()),
        ("source_line_no", pa.int64()),
        ("extra", pa.string()),
    ]
)


#: Surrogates outside the `\udc80-\udcff` that `surrogateescape` reads a byte as.
_LONE_SURROGATE: Final = re.compile("[\ud800-\udc7f\udd00-\udfff]")


def _storable(text: str | None) -> str | None:
    """Make a string safe to write to a UTF-8 Parquet column.

    Reading preserves malformed bytes as surrogate escapes so nothing is lost in
    memory, but Parquet strings must be valid UTF-8. Those bytes are rendered as
    ``\\xHH`` — the same way Apache would have written them had it escaped them —
    which keeps them visible as evidence rather than dropping or replacing them.

    Text that is already valid passes through untouched, so this only affects
    input that was malformed to begin with.

    A surrogate no byte could have produced — JSON's ``\\ud800``, which decodes
    to half a character — is written back as that escape. One such field used
    to fail the write of its whole batch, and the ingest with it.
    """
    if text is None:
        return None
    try:
        raw = text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        escaped = _LONE_SURROGATE.sub(lambda found: f"\\u{ord(found[0]):04x}", text)
        raw = escaped.encode("utf-8", "surrogateescape")
    return raw.decode("utf-8", "backslashreplace")


def _fits(value: int | None, bits: int) -> int | None:
    """`value`, or unknown if a column `bits` wide cannot hold it.

    A status or byte count is the server's own number, but the line it is read
    from is the client's. Twenty digits failed the write of the whole batch,
    and the ingest with it. Only the number is lost, not the request: the line
    it came from is still the evidence.
    """
    if value is None or -(2 ** (bits - 1)) <= value < 2 ** (bits - 1):
        return value
    return None


class ParquetEventStore:
    """A case directory on disk, holding ingested events."""

    def __init__(
        self,
        root: Path | str,
        *,
        memory_limit: str = DEFAULT_MEMORY_LIMIT,
        shard: str | None = None,
        scratch: Path | None = None,
    ) -> None:
        """`shard` names this writer apart from any other writing the same case.

        Parallel ingest gives each worker its own store over one case directory,
        and the staged file names are numbered per instance — so without a name
        every worker writes `part-000000.parquet` and all but the last are
        replaced. The case then finalises, the counts look plausible, and the
        lost evidence is the evidence nobody knows to look for.

        `None` for a single writer, which keeps the sequential path writing
        exactly where it always did.
        """
        self.root = Path(root)
        self._shard = shard
        self._staging = self.root / "staging"
        self._events = self.root / "events"
        self._ip_index = self.root / "ip_index.parquet"
        self._finalizing = self.root / ".finalizing"
        self._finalized = self.root / ".finalized"
        self._scratch = scratch if scratch is not None else self.root / "tmp"
        self._memory_limit = memory_limit
        self._writer: pq.ParquetWriter | None = None
        self._batch = 0
        self._connection: duckdb.DuckDBPyConnection | None = None
        self._index_has_bucket: bool | None = None
        #: This store's own folder inside `_scratch`, while it has a connection.
        self._spill: Path | None = None

    # -- ingest ------------------------------------------------------------

    @property
    def is_finalized(self) -> bool:
        if not self._events.is_dir() or not self._ip_index.is_file():
            return False
        if self._finalized.is_file():
            return True
        # Legacy stores have no completion marker. Their final index and the
        # absence of staged data distinguish a finished write from a partial one.
        return not self._finalizing.exists() and not any(self._staging.glob("*.parquet"))

    def write(self, events: Iterable[NormalizedEvent]) -> None:
        batch = list(events)
        if self.is_finalized:
            raise StoreStateError(f"case at {self.root} is already finalised; cannot write more")
        if self._finalizing.exists() or self._events.exists() or self._ip_index.exists():
            raise StoreStateError("cannot append to a store whose finalization has started")
        if not batch:
            return

        self._staging.mkdir(parents=True, exist_ok=True)
        table = pa.Table.from_pydict(
            {
                "timestamp": [e.timestamp.astimezone(UTC).replace(tzinfo=None) for e in batch],
                "client_ip": [_storable(e.client_ip) for e in batch],
                "method": [_storable(e.method) for e in batch],
                "path": [_storable(e.path) for e in batch],
                "query": [_storable(e.query) for e in batch],
                "protocol": [_storable(e.protocol) for e in batch],
                "status": [_fits(e.status, 32) for e in batch],
                "bytes_sent": [_fits(e.bytes_sent, 64) for e in batch],
                "referer": [_storable(e.referer) for e in batch],
                "user_agent": [_storable(e.user_agent) for e in batch],
                "host": [_storable(e.host) for e in batch],
                "source_file_id": [e.evidence.source_file_id for e in batch],
                "source_line_no": [e.evidence.line_no for e in batch],
                "extra": [json.dumps(dict(e.extra)) if e.extra else None for e in batch],
            },
            schema=SCHEMA,
        )
        # `finalize` globs the directory, so any name it can read will do; what
        # matters is only that two writers cannot choose the same one.
        stem = "part" if self._shard is None else f"part-{self._shard}"
        path = self._staging / f"{stem}-{self._batch:06d}.parquet"
        self._batch += 1
        pq.write_table(table, path, compression="zstd")

    def finalize(self) -> None:
        """Publish completion only after every partition and the index are written.

        Until the marker is published, staging is left intact. A retry can
        rebuild this implementation's incomplete outputs from that copy. Legacy
        partial stores cannot prove their staging survived cleanup intact, so
        they are refused rather than guessed complete or rebuilt from a subset.
        """
        if self.is_finalized:
            return
        if (self._events.exists() or self._ip_index.exists()) and not self._finalizing.exists():
            raise StoreStateError(
                f"incomplete store at {self.root}; re-ingest the source logs into a new case"
            )
        self.root.mkdir(parents=True, exist_ok=True)
        self._finalizing.touch()
        if self._events.exists():
            shutil.rmtree(self._events)
        self._ip_index.unlink(missing_ok=True)
        self._index_has_bucket = None
        self._events.mkdir(parents=True, exist_ok=True)
        try:
            if any(self._staging.glob("*.parquet")):
                connection = self._connect()
                staged = self._sql_path(self._staging / "*.parquet")
                self._partition_and_sort(connection, staged)
                self._write_index(connection, staged)
            else:
                # A log may legitimately contain nothing parseable.
                self._write_empty_index()
            self._clear_scratch()
            self._finalized.touch(exist_ok=False)
        except BaseException:
            self.close()
            raise
        # Completion precedes cleanup. A crash or failed removal here must not
        # cause a retry to rebuild the case from partially removed staging.
        with suppress(OSError):
            self._finalizing.unlink()
        shutil.rmtree(self._staging, ignore_errors=True)

    def _write_index(self, connection: duckdb.DuckDBPyConnection, staged: str) -> None:
        connection.execute(f"""
            COPY (
                SELECT
                    client_ip,
                    count(*)                                  AS request_count,
                    min(timestamp)                            AS first_seen,
                    max(timestamp)                            AS last_seen,
                    count(DISTINCT path)                      AS distinct_paths,
                    coalesce(
                        count(*) FILTER (WHERE status BETWEEN 400 AND 499) * 1.0 / count(*),
                        0.0
                    )                                         AS client_error_ratio,
                    coalesce(sum(bytes_sent), 0)              AS bytes_total,
                    hash(client_ip) % {BUCKETS}               AS bucket
                FROM read_parquet({staged})
                GROUP BY client_ip
            ) TO {self._sql_path(self._ip_index)} (FORMAT PARQUET, COMPRESSION zstd)
        """)

    def _partition_and_sort(self, connection: duckdb.DuckDBPyConnection, staged: str) -> None:
        """Lay the events out bucketed and sorted, in two bounded passes.

        Doing it in one — sort the whole corpus, hand the sorted stream to a
        partitioned writer — is the obvious formulation and does not survive a
        memory ceiling. The sorted result has to be held while sixty-four
        partition writers drain it, so the working set follows the corpus. Ten
        million events ran out of memory inside a gigabyte and took 6.9 GB
        without one.

        Split in two, neither pass needs to hold much:

        1. Bucket the events with no ordering at all. A partitioned write with
           nothing to preserve streams straight through.
        2. Sort each bucket into its final file, one at a time. Each sort covers
           a sixty-fourth of the corpus, so the peak follows `BUCKETS` and the
           width of a single bucket rather than the size of the log.

        The cost is one extra write of the events, which is transient and worth
        it: the ordering is what lets a later per-IP query skip almost every row
        group in the bucket it lands in.
        """
        # Named as briefly as the final layout is. Windows still refuses paths
        # past 260 characters by default, and this directory sits at the same
        # depth as `events/bucket=NN/...`, so a longer name here would be the
        # thing that tips a deep case directory over the limit.
        scratch = self.root / "raw"
        shutil.rmtree(scratch, ignore_errors=True)
        connection.execute(f"""
            COPY (
                SELECT *, hash(client_ip) % {BUCKETS} AS bucket
                FROM read_parquet({staged})
            ) TO {self._sql_path(scratch)}
            (FORMAT PARQUET, PARTITION_BY (bucket), COMPRESSION zstd, OVERWRITE_OR_IGNORE)
        """)

        try:
            for part in sorted(scratch.glob("bucket=*")):
                target = self._events / part.name
                target.mkdir(parents=True, exist_ok=True)
                # `bucket` is excluded on the way out: it lives in the directory
                # name, and a copy inside the file would collide with the value
                # hive partitioning reads back off the path.
                connection.execute(f"""
                    COPY (
                        SELECT * EXCLUDE (bucket)
                        FROM read_parquet({self._sql_path(part / "*.parquet")})
                        ORDER BY client_ip, timestamp
                    ) TO {self._sql_path(target / "data.parquet")}
                    (FORMAT PARQUET, COMPRESSION zstd)
                """)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def _clear_scratch(self) -> None:
        """Drop whatever the sort spilled. It can be gigabytes, and it is not evidence.

        The connection is closed first, because DuckDB holds its spill files
        open and Windows will not delete a file that is. It reopens by itself on
        the next query; `finalize` is the last thing the write side does, so
        nothing is paying for the reconnect but the first read.

        Redirecting the temp directory instead does not work: once DuckDB has
        used one it refuses to be moved off it.

        Only this store's own spill goes, and the shared folder only once it is
        empty: another reader of the case may be spilling beside it.
        """
        self.close()
        with suppress(OSError):
            self._scratch.rmdir()

    def _write_empty_index(self) -> None:
        empty = pa.table(
            {
                "client_ip": pa.array([], pa.string()),
                "request_count": pa.array([], pa.int64()),
                "first_seen": pa.array([], pa.timestamp("us")),
                "last_seen": pa.array([], pa.timestamp("us")),
                "distinct_paths": pa.array([], pa.int64()),
                "client_error_ratio": pa.array([], pa.float64()),
                "bytes_total": pa.array([], pa.int64()),
                "bucket": pa.array([], pa.uint64()),
            }
        )
        pq.write_table(empty, self._ip_index, compression="zstd")

    # -- analysis ----------------------------------------------------------

    @property
    def _events_glob(self) -> Path:
        """Every finalised event file, as the pattern the query engine reads."""
        return self._events / "**" / "*.parquet"

    def _has_events(self) -> bool:
        """Whether finalisation wrote any event file at all.

        An empty case is legitimate and has an index but no events, and a glob
        over nothing is a query error rather than an empty result.
        """
        return any(self._events.rglob("*.parquet"))

    def events_for_ip(
        self, client_ip: str, *, window: TimeWindow | None = None
    ) -> list[NormalizedEvent]:
        self._require_finalized()
        if not self._has_events():
            return []

        clause, bounds = _window_sql(window)
        predicate, client_parameters = self._client_predicate(client_ip)
        rows = (
            self._connect()
            .execute(
                f"""
            SELECT timestamp, client_ip, method, path, query, protocol, status,
                   bytes_sent, referer, user_agent, host, source_file_id,
                   source_line_no, extra
            FROM read_parquet({self._sql_path(self._events_glob)}, hive_partitioning = true)
            WHERE {predicate}{clause}
            ORDER BY timestamp, source_line_no
            """,
                [*client_parameters, *bounds],
            )
            .fetchall()
        )
        return [_to_event(row) for row in rows]

    def iter_clients(self, *, window: TimeWindow | None = None) -> Iterator[list[NormalizedEvent]]:
        """Scan in partition/client order for case-wide analysis without graphs.

        DuckDB can spill the ordering under the store's memory ceiling. Python
        retains one client's events, so its peak depends on the largest client.
        """
        self._require_finalized()
        if not self._has_events():
            return
        clause, bounds = _window_sql(window)
        cursor = self._connect().execute(
            f"""
            SELECT timestamp, client_ip, method, path, query, protocol, status,
                   bytes_sent, referer, user_agent, host, source_file_id,
                   source_line_no, extra
            FROM read_parquet({self._sql_path(self._events_glob)}, hive_partitioning = true)
            WHERE true{clause}
            ORDER BY bucket, client_ip, timestamp, source_line_no
            """,
            bounds,
        )
        current: list[NormalizedEvent] = []
        while rows := cursor.fetchmany(_STREAM_CHUNK):
            for row in rows:
                event = _to_event(row)
                if current and current[0].client_ip != event.client_ip:
                    yield current
                    current = []
                current.append(event)
        if current:
            yield current

    def all_events(self) -> Iterator[NormalizedEvent]:
        """Every event in the case, in source order, streamed in chunks.

        Ordered by source file and line rather than by timestamp: the consumer
        is enrichment, which cares only that a detection can be tied back to the
        line it came from, and this ordering lets the sidecar receive one
        source's requests contiguously.
        """
        self._require_finalized()
        if not self._has_events():
            return

        cursor = self._connect().execute(
            f"""
            SELECT timestamp, client_ip, method, path, query, protocol, status,
                   bytes_sent, referer, user_agent, host, source_file_id,
                   source_line_no, extra
            FROM read_parquet({self._sql_path(self._events_glob)}, hive_partitioning = true)
            ORDER BY source_file_id, source_line_no
            """
        )
        while rows := cursor.fetchmany(_STREAM_CHUNK):
            for row in rows:
                yield _to_event(row)

    def ip_summaries(
        self,
        *,
        limit: int | None = None,
        order_by: str = "requests",
        window: TimeWindow | None = None,
    ) -> list[IpSummary]:
        self._require_finalized()
        try:
            ordering = SORT_KEYS[order_by]
        except KeyError:
            raise ValueError(
                f"unknown sort key {order_by!r}; choose one of {', '.join(SORT_KEYS)}"
            ) from None

        cap = f"LIMIT {int(limit)}" if limit is not None else ""
        source, bounds = self._summary_source(window)
        rows = (
            self._connect()
            .execute(
                f"""
            SELECT client_ip, request_count, first_seen, last_seen, distinct_paths,
                   client_error_ratio, bytes_total
            FROM ({source})
            ORDER BY {ordering}, client_ip
            {cap}
        """,
                bounds,
            )
            .fetchall()
        )
        return [_to_summary(row) for row in rows]

    def ip_summary_page(
        self,
        *,
        query: str = "",
        offset: int = 0,
        limit: int = 100,
        window: TimeWindow | None = None,
        exact: bool = False,
    ) -> IpSummaryPage:
        """Page the complete index, or a window aggregate, before returning rows.

        Number before filtering so search results keep their population positions.
        The count row survives an empty page, including offsets beyond the end.
        `exact` matches the whole address rather than any address containing it.
        """
        self._require_finalized()
        if offset < 0 or limit < 1:
            raise ValueError("offset must be nonnegative and limit must be positive")
        source, bounds = self._summary_source(window)
        match = "client_ip = ?" if exact else "contains(client_ip, ?)"
        rows = (
            self._connect()
            .execute(
                f"""
            WITH ranked AS (
                SELECT client_ip, request_count, first_seen, last_seen, distinct_paths,
                       client_error_ratio, bytes_total,
                       row_number() OVER (ORDER BY request_count DESC, client_ip) AS position
                FROM ({source})
            ), matching AS (SELECT * FROM ranked WHERE {match})
            SELECT page.*, totals.total
            FROM (SELECT count(*) AS total FROM matching) totals
            LEFT JOIN (SELECT * FROM matching ORDER BY position LIMIT ? OFFSET ?) page ON true
            ORDER BY page.position
            """,
                [*bounds, query, limit, offset],
            )
            .fetchall()
        )
        return IpSummaryPage(
            tuple(_to_summary(row, position=int(row[7])) for row in rows if row[0] is not None),
            int(rows[0][8]),
            offset,
        )

    def search_clients(
        self,
        query: Query,
        *,
        offset: int = 0,
        limit: int = 100,
        window: TimeWindow | None = None,
        clients: frozenset[str] | None = None,
        also: frozenset[str] = frozenset(),
    ) -> ClientMatchPage:
        self._require_finalized()
        if offset < 0 or limit < 1:
            raise ValueError("offset must be nonnegative and limit must be positive")
        if not self._has_events() or (clients is not None and not clients):
            return ClientMatchPage((), (), 0, 0, offset)
        source, source_bounds = self._summary_source(window)
        clause, bounds = _window_sql(window)
        matches, values = _request_sql(query)
        who, whose = _client_sql(query)
        connection = self._connect()
        # The clients `activity:` chose, joined while the events are read. As a
        # table rather than a bound list: DuckDB took 2.2s to take 4,916
        # addresses as one parameter on the large tier, and 0.002s as a table.
        chosen = ""
        table: str | None = None
        if clients is not None:
            table = f"chosen_{uuid.uuid4().hex}"
            connection.register(
                table, pa.table({"client_ip": pa.array(sorted(clients), pa.string())})
            )
            chosen = f" AND client_ip IN (SELECT client_ip FROM {table})"
        # The clients found by name, joined as `clients` is. Without any, the
        # statement is the one the parity tests hold to the evidence box: an
        # inner join on the hits.
        named = ""
        matching = f"""matching AS (
                SELECT ranked.*, hits.hits
                FROM ranked JOIN hits USING (client_ip)
                WHERE {who}
            )"""
        order, page_order = "hits DESC, client_ip", "page.hits DESC, page.client_ip"
        if also:
            named = f"named_{uuid.uuid4().hex}"
            connection.register(named, pa.table({"client_ip": pa.array(sorted(also), pa.string())}))
            # No column of its own for being named: the page's columns are read
            # by position below. Named clients sort first by the test itself.
            first = f"client_ip IN (SELECT client_ip FROM {named})"
            matching = f"""matching AS (
                SELECT ranked.*, coalesce(hits.hits, 0) AS hits
                FROM ranked LEFT JOIN hits USING (client_ip)
                WHERE (hits.hits IS NOT NULL AND {who}) OR ranked.{first}
            )"""
            order = f"{first} DESC, hits DESC, client_ip"
            page_order = f"page.{first} DESC, page.hits DESC, page.client_ip"
        try:
            rows = connection.execute(
                f"""
            WITH ranked AS (
                SELECT client_ip, request_count, first_seen, last_seen, distinct_paths,
                       client_error_ratio, bytes_total,
                       row_number() OVER (ORDER BY request_count DESC, client_ip) AS position
                FROM ({source})
            ), hits AS (
                SELECT client_ip, count(*) AS hits
                FROM read_parquet({self._sql_path(self._events_glob)}, hive_partitioning = true)
                WHERE TRUE{clause} AND {matches}{chosen}
                GROUP BY client_ip
            ), {matching}
            SELECT page.*, totals.total, totals.requests
            FROM (SELECT count(*) AS total, coalesce(sum(hits), 0) AS requests
                  FROM matching) totals
            LEFT JOIN (SELECT * FROM matching ORDER BY {order}
                       LIMIT ? OFFSET ?) page ON true
            ORDER BY {page_order}
            """,
                [*source_bounds, *bounds, *values, *whose, limit, offset],
            ).fetchall()
        finally:
            if table is not None:
                connection.unregister(table)
            if named:
                connection.unregister(named)
        found = [row for row in rows if row[0] is not None]
        return ClientMatchPage(
            tuple(_to_summary(row, position=int(row[7])) for row in found),
            tuple(int(row[8]) for row in found),
            int(rows[0][9]),
            int(rows[0][10]),
            offset,
        )

    def clients_present(self, clients: Collection[str]) -> frozenset[str]:
        """Which of `clients` the case holds, whole addresses only, in one query.

        Read from the per-client table ingest built, not the events: one small
        file. The addresses go over as a registered table, as `search_clients`
        hands over its own, and are unregistered once answered.
        """
        self._require_finalized()
        if not clients:
            return frozenset()
        connection = self._connect()
        table = f"chosen_{uuid.uuid4().hex}"
        connection.register(
            table, pa.table({"client_ip": pa.array(sorted(set(clients)), pa.string())})
        )
        try:
            rows = connection.execute(
                f"SELECT client_ip FROM read_parquet({self._sql_path(self._ip_index)})"
                f" WHERE client_ip IN (SELECT client_ip FROM {table})"
            ).fetchall()
        finally:
            connection.unregister(table)
        return frozenset(row[0] for row in rows)

    def value_counts(
        self, *, window: TimeWindow | None = None
    ) -> dict[str, list[tuple[str, int, int]]]:
        self._require_finalized()
        counted: dict[str, list[tuple[str, int, int]]] = {"status": [], "method": []}
        if not self._has_events():
            return counted
        clause, bounds = _window_sql(window)
        # One read of the range for all three groupings. Only what the box can
        # make a filter of: a code from 100 to 599, a method of letters a to z.
        rows = (
            self._connect()
            .execute(
                f"""
            WITH seen AS (
                SELECT client_ip, status, method
                FROM read_parquet({self._sql_path(self._events_glob)}, hive_partitioning = true)
                WHERE TRUE{clause}
            )
            SELECT 'code', CAST(status AS VARCHAR), count(DISTINCT client_ip), count(*)
            FROM seen WHERE status BETWEEN 100 AND 599 GROUP BY status
            UNION ALL
            SELECT 'class', CAST(status // 100 AS VARCHAR) || 'xx',
                   count(DISTINCT client_ip), count(*)
            FROM seen WHERE status BETWEEN 100 AND 599 GROUP BY status // 100
            UNION ALL
            SELECT 'method', upper(method), count(DISTINCT client_ip), count(*)
            FROM seen WHERE regexp_full_match(coalesce(method, ''), '[A-Za-z]+')
            GROUP BY upper(method)
            """,
                bounds,
            )
            .fetchall()
        )
        grouped: dict[str, list[tuple[str, int, int]]] = {"code": [], "class": [], "method": []}
        for kind, value, clients, requests in rows:
            grouped[kind].append((value, int(clients), int(requests)))
        ranked = sorted(grouped["code"], key=lambda item: (-item[2], item[0]))
        counted["status"] = ranked + sorted(grouped["class"])
        counted["method"] = sorted(grouped["method"], key=lambda item: (-item[2], item[0]))
        return counted

    # -- plumbing ----------------------------------------------------------

    def _client_predicate(self, client_ip: str) -> tuple[str, list[object]]:
        """Use the partition recorded at ingest, never today's hash function.

        Old indexes have no mapping. Reading their partitions with an IP
        filter is slower but correct, and leaves the case untouched. New ones
        retain partition pruning across DuckDB upgrades without a migration.
        """
        if self._index_has_bucket is None:
            self._index_has_bucket = "bucket" in pq.read_schema(self._ip_index).names
        if not self._index_has_bucket:
            return "client_ip = ?", [client_ip]
        row = (
            self._connect()
            .execute(
                f"SELECT bucket FROM read_parquet({self._sql_path(self._ip_index)}) "
                "WHERE client_ip = ?",
                [client_ip],
            )
            .fetchone()
        )
        if row is None:
            return "FALSE", []
        return "bucket = ? AND client_ip = ?", [int(row[0]), client_ip]

    def activity_over_time(
        self, *, buckets: int = 200, client_ip: str | None = None
    ) -> list[TimeSlot]:
        self._require_finalized()
        if not self._has_events():
            return []

        predicate, who = self._client_predicate(client_ip) if client_ip else ("TRUE", [])
        whose = f" WHERE {predicate}"

        connection = self._connect()
        span = connection.execute(
            f"""
            SELECT min(timestamp), max(timestamp)
            FROM read_parquet({self._sql_path(self._events_glob)}, hive_partitioning = true)
            {whose}
            """,
            who,
        ).fetchone()
        if span is None or span[0] is None:  # pragma: no cover - see above
            # Unreachable while the guard above holds: a case with no event
            # files never gets here. Kept because it is the difference between
            # an empty band and a TypeError on the line below if that ever
            # stops being true.
            return []

        # At least a second. A case whose events share one instant has a span of
        # zero, and the width is that span divided by the bucket count — which
        # is a division by zero, and the band never draws at all.
        seconds = max(int((span[1] - span[0]).total_seconds() // max(buckets, 1)), 1)
        rows = connection.execute(
            f"""
            SELECT time_bucket(INTERVAL '{seconds} seconds', timestamp) AS slot, count(*)
            FROM read_parquet({self._sql_path(self._events_glob)}, hive_partitioning = true)
            {whose}
            GROUP BY slot
            ORDER BY slot
            """,
            who,
        ).fetchall()
        counts = {row[0].replace(tzinfo=UTC): int(row[1]) for row in rows}
        if not counts:  # pragma: no cover - the span query above already found events
            return []
        # Every bucket across the span, the quiet ones as zero. A histogram with
        # holes in it is not a histogram, and the holes cost the band the one
        # thing it cannot work out for itself: how wide a bucket is. It inferred
        # that from the narrowest gap between two buckets that arrived, which on
        # a client with a handful of requests is far wider than the bucket really
        # is — six requests over two minutes drew as six blocks 21px wide, each
        # claiming to have lasted half a minute.
        #
        # Filled here rather than in SQL. `time_bucket` aligns to whole steps
        # from the epoch, so the buckets that came back already sit on those
        # boundaries and stepping from the first lands on every one of them.
        step = timedelta(seconds=seconds)
        slots: list[TimeSlot] = []
        at, last = min(counts), max(counts)
        while at <= last:
            slots.append(TimeSlot(start=at, request_count=counts.get(at, 0)))
            at += step
        return slots

    def overview(self, *, window: TimeWindow | None = None) -> CaseOverview:
        self._require_finalized()
        source, bounds = self._summary_source(window)
        row = (
            self._connect()
            .execute(
                f"SELECT count(*), min(first_seen), max(last_seen) FROM ({source})",
                bounds,
            )
            .fetchone()
        )
        if row is None or not row[0]:  # pragma: no cover - count(*) always returns a row
            return CaseOverview(clients=0, first_seen=None, last_seen=None)
        return CaseOverview(
            clients=int(row[0]),
            first_seen=row[1].replace(tzinfo=UTC),
            last_seen=row[2].replace(tzinfo=UTC),
        )

    def _summary_source(self, window: TimeWindow | None) -> tuple[str, list[datetime]]:
        """Where the per-client figures come from.

        Without a window, the table built during ingest — one small file, and
        the reason choosing a client is instant on a large case.

        With one, that table is useless: it was computed once and knows only the
        whole case. The figures are aggregated from the events instead. Measured
        at 0.221s on three million events against 0.061s for the precomputed
        table, which is the difference between a filter that can be dragged and
        one that cannot.
        """
        if window is None or window.is_open:
            return f"SELECT * FROM read_parquet({self._sql_path(self._ip_index)})", []
        clause, bounds = _window_sql(window)
        return (
            f"""
            SELECT client_ip,
                   count(*) AS request_count,
                   min(timestamp) AS first_seen,
                   max(timestamp) AS last_seen,
                   count(DISTINCT path) AS distinct_paths,
                   avg(CASE WHEN status BETWEEN 400 AND 499 THEN 1.0 ELSE 0.0 END)
                       AS client_error_ratio,
                   coalesce(sum(bytes_sent), 0) AS bytes_total
            FROM read_parquet({self._sql_path(self._events_glob)}, hive_partitioning = true)
            WHERE TRUE{clause}
            GROUP BY client_ip
            """,
            bounds,
        )

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        if self._spill is not None:
            # DuckDB removes a folder it made itself; this is for one it could not.
            shutil.rmtree(self._spill, ignore_errors=True)
            self._spill = None

    def _connect(self) -> duckdb.DuckDBPyConnection:
        """Open the query engine with a memory ceiling and room to spill.

        Left at its defaults DuckDB will take most of the machine before it
        spills anything, and the sort in `finalize` covers the whole corpus.
        Measured on ten million events that came to 6.9 GB of resident memory,
        which is not what "bounded by batch size" means. Capping it and giving
        it somewhere to write turns the sort into an external one: slower on a
        corpus that would not have fitted anyway, and survivable.
        """
        if self._connection is None:
            self._scratch.mkdir(parents=True, exist_ok=True)
            # A folder of its own, because DuckDB names its spill files the same
            # in every process and connection (`duckdb_temp_storage_S64K-0.tmp`):
            # two readers of one case spilling into one folder write over and
            # delete each other's, and crash. DuckDB makes the folder on its
            # first spill and removes it on close, so a reader that never
            # spills leaves nothing behind.
            self._spill = self._scratch / f"spill-{os.getpid()}-{uuid.uuid4().hex[:8]}"
            self._connection = duckdb.connect(":memory:")
            self._connection.execute(f"SET memory_limit = '{self._memory_limit}'")
            self._connection.execute(f"SET temp_directory = {self._sql_path(self._spill)}")
            # Under a ceiling, the partitioned write in `finalize` runs out of
            # memory rather than spilling, because holding insertion order
            # across 64 partitions means buffering them. Every query here that
            # cares about order states it with ORDER BY, so there is nothing to
            # preserve and a great deal to buffer.
            self._connection.execute("SET preserve_insertion_order = false")
            # Each worker buffers this many rows before flushing a partition,
            # and the default half-million across eight of them is four million
            # rows held at once — memory that follows the corpus, which is the
            # thing being avoided. Flushing more often costs a little write
            # throughput and makes the peak a constant.
            self._connection.execute(
                f"SET partitioned_write_flush_threshold = {PARTITION_FLUSH_ROWS}"
            )
            # One open file per bucket, so the writer never has to close and
            # reopen partitions as rows arrive out of order.
            self._connection.execute(f"SET partitioned_write_max_open_files = {BUCKETS + 1}")
        return self._connection

    def _require_finalized(self) -> None:
        if not self.is_finalized:
            raise StoreStateError(f"case at {self.root} has not been finalised; call finalize()")

    @staticmethod
    def _sql_path(path: Path) -> str:
        """Render a path as a SQL string literal.

        Backslashes are the norm on Windows, so they are escaped rather than
        left to be read as escape sequences.
        """
        return "'" + str(path).replace("\\", "/").replace("'", "''") + "'"


def _window_sql(window: TimeWindow | None) -> tuple[str, list[datetime]]:
    """A time predicate and its parameters, or nothing at all.

    Returns an empty clause for an open window rather than one that is always
    true, so the query a case without a filter runs is byte for byte the query
    it has always run — and nothing about its plan can quietly change.

    Both ends are inclusive, matching `TimeWindow.contains`. A store that
    excluded them would drop the very request whose second the reader typed.
    """
    if window is None or window.is_open:
        return "", []
    clauses: list[str] = []
    bounds: list[datetime] = []
    if window.start is not None:
        clauses.append("timestamp >= ?")
        bounds.append(_naive(window.start))
    if window.end is not None:
        clauses.append("timestamp <= ?")
        bounds.append(_naive(window.end))
    return " AND " + " AND ".join(clauses), bounds


def _folded(expression: str) -> str:
    """DuckDB's `lower`, finished as `search.fold` finishes Python's.

    DuckDB already writes a dotted capital I as a plain `i`; what is left is
    the final sigma, `chr(962)`, read as the ordinary one, `chr(963)`.
    """
    return f"replace(lower({expression}), chr(962), chr(963))"


#: The path, and the path as the panel shows it: one pass of decoding, and the
#: path as written when the bytes it decodes to are not UTF-8. DuckDB raises
#: there, as Python's strict `unquote` does, and `try` turns that into the
#: fallback (measured on `%C3%28`).
_PATH: Final = "coalesce(path, '')"
_SHOWN_PATH: Final = f"coalesce(try(url_decode({_PATH})), {_PATH})"
#: A query decodes as `unquote_plus` does: a plus is a space, then escapes.
_SHOWN_QUERY: Final = "coalesce(try(url_decode(replace(query, '+', ' '))), query)"
#: Path and query joined as `NormalizedEvent.target` joins them: nothing at all
#: without a path, and no question mark without a query.
_TARGET: Final = (
    f"CASE WHEN {_PATH} = '' THEN '' WHEN coalesce(query, '') = '' THEN path "
    "ELSE path || '?' || query END"
)
_SHOWN_TARGET: Final = (
    f"CASE WHEN {_PATH} = '' THEN '' WHEN coalesce(query, '') = '' THEN {_SHOWN_PATH} "
    f"ELSE {_SHOWN_PATH} || '?' || {_SHOWN_QUERY} END"
)


def _request_sql(query: Query) -> tuple[str, list[object]]:
    """`query.matches`, as a predicate on one stored request, and its parameters.

    Every typed value is bound; none is written into the statement. The
    parity tests in `tests/storage/test_search_clients.py` hold the two to the
    same answer, request for request.
    """
    clauses: list[str] = ["TRUE"]
    values: list[object] = []
    if query.statuses or query.classes:
        either: list[str] = []
        if query.statuses:
            either.append(f"status IN ({', '.join('?' * len(query.statuses))})")
            values.extend(query.statuses)
        if query.classes:
            either.append(f"status // 100 IN ({', '.join('?' * len(query.classes))})")
            values.extend(query.classes)
        clauses.append(f"(status IS NOT NULL AND ({' OR '.join(either)}))")
    if query.paths:
        clauses.append(
            "("
            + " OR ".join(
                f"contains({_folded(_PATH)}, ?) OR contains({_folded(_SHOWN_PATH)}, ?)"
                for _ in query.paths
            )
            + ")"
        )
        for wanted in query.paths:
            values.extend((wanted, wanted))
    if query.methods:
        # In ASCII only, as `search._method_in` compares: `strlen` counts bytes
        # and `length` characters, so they agree exactly when nothing is wider.
        clauses.append(
            "(method IS NOT NULL AND strlen(method) = length(method)"
            f" AND upper(method) IN ({', '.join('?' * len(query.methods))}))"
        )
        values.extend(query.methods)
    if query.after is not None:
        clauses.append("timestamp >= ?")
        values.append(_naive(query.after))
    if query.before is not None:
        clauses.append("timestamp < ?")
        values.append(_naive(query.before))
    for word in query.words:
        clauses.append(
            f"(contains({_folded(_TARGET)}, ?) OR contains({_folded(_SHOWN_TARGET)}, ?))"
        )
        values.extend((word, word))
    return " AND ".join(clauses), values


def _client_sql(query: Query) -> tuple[str, list[object]]:
    """Which clients a search's addresses name."""
    clauses: list[str] = ["TRUE"]
    values: list[object] = []
    if query.ips:
        clauses.append(
            "("
            + " OR ".join(
                "client_ip = ?" if is_whole_address(ip) else "contains(client_ip, ?)"
                for ip in query.ips
            )
            + ")"
        )
        values.extend(query.ips)
    return " AND ".join(clauses), values


def _naive(when: datetime) -> datetime:
    """UTC with the marker taken off.

    The `timestamp` column holds naive values — reads put the marker back on
    the way out. Compared against an aware bound, DuckDB matched nothing at
    all, silently: the query succeeded and returned an empty window over data
    that was there.
    """
    return when.astimezone(UTC).replace(tzinfo=None)


def _to_summary(row: tuple[Any, ...], *, position: int = 0) -> IpSummary:
    return IpSummary(
        row[0],
        int(row[1]),
        row[2].replace(tzinfo=UTC),
        row[3].replace(tzinfo=UTC),
        int(row[4]),
        float(row[5]),
        int(row[6]),
        position,
    )


def _to_event(row: tuple[Any, ...]) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=row[0].replace(tzinfo=UTC),
        client_ip=row[1],
        evidence=EvidenceRef(source_file_id=row[11], line_no=int(row[12])),
        method=row[2],
        path=row[3],
        query=row[4],
        protocol=row[5],
        status=int(row[6]) if row[6] is not None else None,
        bytes_sent=int(row[7]) if row[7] is not None else None,
        referer=row[8],
        user_agent=row[9],
        host=row[10],
        extra=json.loads(row[13]) if row[13] else {},
    )
