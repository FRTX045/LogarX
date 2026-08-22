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
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.core.window import TimeWindow
from logarc.storage.base import IpSummary, TimeSlot

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

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


def _storable(text: str | None) -> str | None:
    """Make a string safe to write to a UTF-8 Parquet column.

    Reading preserves malformed bytes as surrogate escapes so nothing is lost in
    memory, but Parquet strings must be valid UTF-8. Those bytes are rendered as
    ``\\xHH`` — the same way Apache would have written them had it escaped them —
    which keeps them visible as evidence rather than dropping or replacing them.

    Text that is already valid passes through untouched, so this only affects
    input that was malformed to begin with.
    """
    if text is None:
        return None
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


class ParquetEventStore:
    """A case directory on disk, holding ingested events."""

    def __init__(
        self,
        root: Path | str,
        *,
        memory_limit: str = DEFAULT_MEMORY_LIMIT,
        shard: str | None = None,
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
        self._scratch = self.root / "tmp"
        self._memory_limit = memory_limit
        self._writer: pq.ParquetWriter | None = None
        self._batch = 0
        self._connection: duckdb.DuckDBPyConnection | None = None

    # -- ingest ------------------------------------------------------------

    @property
    def is_finalized(self) -> bool:
        return self._events.exists()

    def write(self, events: Iterable[NormalizedEvent]) -> None:
        batch = list(events)
        if self.is_finalized:
            raise StoreStateError(f"case at {self.root} is already finalised; cannot write more")
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
                "status": [e.status for e in batch],
                "bytes_sent": [e.bytes_sent for e in batch],
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
        """Partition, sort and index the staged events, then drop the staging copy."""
        if self.is_finalized:
            return

        self._events.mkdir(parents=True, exist_ok=True)
        if not any(self._staging.glob("*.parquet")):
            # An empty case is legitimate: a log may contain nothing parseable.
            self._write_empty_index()
            return

        connection = self._connect()
        staged = self._sql_path(self._staging / "*.parquet")
        self._partition_and_sort(connection, staged)
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
                    coalesce(sum(bytes_sent), 0)              AS bytes_total
                FROM read_parquet({staged})
                GROUP BY client_ip
            ) TO {self._sql_path(self._ip_index)} (FORMAT PARQUET, COMPRESSION zstd)
        """)
        shutil.rmtree(self._staging, ignore_errors=True)
        self._clear_scratch()

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
        """
        self.close()
        shutil.rmtree(self._scratch, ignore_errors=True)

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
            }
        )
        pq.write_table(empty, self._ip_index, compression="zstd")

    # -- analysis ----------------------------------------------------------

    def events_for_ip(
        self, client_ip: str, *, window: TimeWindow | None = None
    ) -> list[NormalizedEvent]:
        self._require_finalized()
        pattern = self._events / "**" / "*.parquet"
        if not any(self._events.rglob("*.parquet")):
            return []

        clause, bounds = _window_sql(window)
        # Constraining `bucket` lets DuckDB skip whole partition files rather
        # than opening each one to check its statistics.
        rows = (
            self._connect()
            .execute(
                f"""
            SELECT timestamp, client_ip, method, path, query, protocol, status,
                   bytes_sent, referer, user_agent, host, source_file_id,
                   source_line_no, extra
            FROM read_parquet({self._sql_path(pattern)}, hive_partitioning = true)
            WHERE bucket = hash(?) % {BUCKETS} AND client_ip = ?{clause}
            ORDER BY timestamp, source_line_no
            """,
                [client_ip, client_ip, *bounds],
            )
            .fetchall()
        )
        return [_to_event(row) for row in rows]

    def all_events(self) -> Iterator[NormalizedEvent]:
        """Every event in the case, in source order, streamed in chunks.

        Ordered by source file and line rather than by timestamp: the consumer
        is enrichment, which cares only that a detection can be tied back to the
        line it came from, and this ordering lets the sidecar receive one
        source's requests contiguously.
        """
        self._require_finalized()
        pattern = self._events / "**" / "*.parquet"
        if not any(self._events.rglob("*.parquet")):
            return

        cursor = self._connect().execute(
            f"""
            SELECT timestamp, client_ip, method, path, query, protocol, status,
                   bytes_sent, referer, user_agent, host, source_file_id,
                   source_line_no, extra
            FROM read_parquet({self._sql_path(pattern)}, hive_partitioning = true)
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
        return [
            IpSummary(
                client_ip=row[0],
                request_count=int(row[1]),
                first_seen=row[2].replace(tzinfo=UTC),
                last_seen=row[3].replace(tzinfo=UTC),
                distinct_paths=int(row[4]),
                client_error_ratio=float(row[5]),
                bytes_total=int(row[6]),
            )
            for row in rows
        ]

    # -- plumbing ----------------------------------------------------------

    def activity_over_time(
        self, *, buckets: int = 200, client_ip: str | None = None
    ) -> list[TimeSlot]:
        self._require_finalized()
        pattern = self._events / "**" / "*.parquet"
        if not any(self._events.rglob("*.parquet")):
            return []

        # Constraining `bucket` as well lets DuckDB skip whole partition files,
        # the same way a single client's events are read.
        whose = f" WHERE bucket = hash(?) % {BUCKETS} AND client_ip = ?" if client_ip else ""
        who = [client_ip, client_ip] if client_ip else []

        connection = self._connect()
        span = connection.execute(
            f"""
            SELECT min(timestamp), max(timestamp)
            FROM read_parquet({self._sql_path(pattern)}, hive_partitioning = true)
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
            FROM read_parquet({self._sql_path(pattern)}, hive_partitioning = true)
            {whose}
            GROUP BY slot
            ORDER BY slot
            """,
            who,
        ).fetchall()
        return [
            TimeSlot(start=row[0].replace(tzinfo=UTC), request_count=int(row[1])) for row in rows
        ]

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
        pattern = self._events / "**" / "*.parquet"
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
            FROM read_parquet({self._sql_path(pattern)}, hive_partitioning = true)
            WHERE TRUE{clause}
            GROUP BY client_ip
            """,
            bounds,
        )

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

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
            self._connection = duckdb.connect(":memory:")
            self._connection.execute(f"SET memory_limit = '{self._memory_limit}'")
            self._connection.execute(f"SET temp_directory = {self._sql_path(self._scratch)}")
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


def _naive(when: datetime) -> datetime:
    """UTC with the marker taken off.

    The `timestamp` column holds naive values — reads put the marker back on
    the way out. Compared against an aware bound, DuckDB matched nothing at
    all, silently: the query succeeded and returned an empty window over data
    that was there.
    """
    return when.astimezone(UTC).replace(tzinfo=None)


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
