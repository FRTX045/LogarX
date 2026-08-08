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
from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.storage.base import IpSummary

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["ParquetEventStore", "StoreStateError"]


class StoreStateError(RuntimeError):
    """Raised when the store is used out of order."""


#: Number of hash buckets the events are partitioned across. A single-IP query
#: touches one of these, so the constant trades write-side file count against
#: read-side selectivity.
BUCKETS: Final = 64

#: How much memory the query engine may use. Deliberately modest: `finalize`
#: sorts the whole corpus, and left to its own devices DuckDB claims most of the
#: machine before it spills anything — ten million events peaked at 6.9 GB.
#: Bounding it makes the sort external, which is slower on a corpus that would
#: not have fitted anyway, and keeps the tool usable on an ordinary laptop while
#: the rest of it is still running.
DEFAULT_MEMORY_LIMIT: Final = "1GB"

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

    def __init__(self, root: Path | str, *, memory_limit: str = DEFAULT_MEMORY_LIMIT) -> None:
        self.root = Path(root)
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
        path = self._staging / f"part-{self._batch:06d}.parquet"
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
        connection.execute(f"""
            COPY (
                SELECT *, hash(client_ip) % {BUCKETS} AS bucket
                FROM read_parquet({staged})
                ORDER BY client_ip, timestamp
            ) TO {self._sql_path(self._events)}
            (FORMAT PARQUET, PARTITION_BY (bucket), COMPRESSION zstd, OVERWRITE_OR_IGNORE)
        """)
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

    def _clear_scratch(self) -> None:
        """Drop whatever the sort spilled. It can be gigabytes, and it is not evidence."""
        connection = self._connection
        if connection is not None:
            # DuckDB holds its spill files open; point it elsewhere before
            # removing them, or Windows refuses and the case keeps them.
            connection.execute("SET temp_directory = ''")
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

    def events_for_ip(self, client_ip: str) -> list[NormalizedEvent]:
        self._require_finalized()
        pattern = self._events / "**" / "*.parquet"
        if not any(self._events.rglob("*.parquet")):
            return []

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
            WHERE bucket = hash(?) % {BUCKETS} AND client_ip = ?
            ORDER BY timestamp, source_line_no
            """,
                [client_ip, client_ip],
            )
            .fetchall()
        )
        return [_to_event(row) for row in rows]

    def ip_summaries(
        self, *, limit: int | None = None, order_by: str = "requests"
    ) -> list[IpSummary]:
        self._require_finalized()
        try:
            ordering = SORT_KEYS[order_by]
        except KeyError:
            raise ValueError(
                f"unknown sort key {order_by!r}; choose one of {', '.join(SORT_KEYS)}"
            ) from None

        clause = f"LIMIT {int(limit)}" if limit is not None else ""
        rows = (
            self._connect()
            .execute(f"""
            SELECT client_ip, request_count, first_seen, last_seen, distinct_paths,
                   client_error_ratio, bytes_total
            FROM read_parquet({self._sql_path(self._ip_index)})
            ORDER BY {ordering}, client_ip
            {clause}
        """)
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
