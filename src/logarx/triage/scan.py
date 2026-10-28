"""Build and query atomically published, disposable investigation indexes."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from time import monotonic
from typing import TYPE_CHECKING, Any

from logarx.analysis import label_sessions
from logarx.case import Case
from logarx.core.evidence import EvidenceRef
from logarx.core.window import EVERYTHING, TimeWindow
from logarx.detect.crs.sidecar import CrsDetection
from logarx.detect.crs.store import recorded_coverage
from logarx.detect.ruleset import NO_EXTRA_RULES, RuleSet
from logarx.search import labels_for_activity
from logarx.sessionize.segmenter import SessionPolicy
from logarx.storage.event_store import ParquetEventStore
from logarx.triage.profile import (
    DEFAULT_POLICY,
    ClientProfile,
    PriorityReason,
    QueueName,
    RankedClient,
    RequestExample,
    TriagePolicy,
    profile_client,
    rank_profiles,
)
from logarx.triage.reasons import suspicious_reasons

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    from logarx.core.event import NormalizedEvent
    from logarx.detect.engine import LabelledEvent


class ScanCancelled(Exception):  # noqa: N818 - cancellation is a normal worker outcome
    """The caller stopped a scan before it could publish a completed index."""


@dataclass(frozen=True)
class TriageResult:
    path: Path
    clients: int
    eligible: int
    crs_present: bool
    cached: bool = False
    seconds: float = 0
    crs_partial: bool = False
    """The CRS evidence comes from a run stopped part way. Read from the case on
    every call rather than kept in the index, whose identity already includes
    the config that says it."""


@dataclass(frozen=True)
class TriageProgress:
    processed: int
    total: int
    findings: tuple[RankedClient, ...]


#: The shape of a published index. Part of its identity, so an index written
#: before a table was added is rebuilt rather than read as having nothing in it.
#: Separate from `TriagePolicy.version`, which names the ranking that was
#: validated and promoted; the layout changing is not the ranking changing.
#: Raised too when what counts as evidence changes and the rules fingerprint
#: cannot see it: 9 is an ad click ID no longer counting as level 1 evidence,
#: 10 a file-list match inside a client's `name/version` no longer counting.
#: 11 added the table of labels `activity:` searches by.
_LAYOUT = 11


@dataclass(frozen=True)
class RuleMatch:
    """One client a rule matched, and how much of that client it explains."""

    client_ip: str
    matched: int
    """Requests the rule matched."""
    won: int
    """Of those, the requests it named — what a reconstruction calls them."""
    requests: int
    """Every request the client made in the scanned range."""


@dataclass(frozen=True)
class TriagePage:
    rows: tuple[RankedClient, ...]
    total: int
    offset: int


def _digest(path: Path) -> str | None:
    if not path.exists():
        return None
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _example(data: dict[str, Any]) -> RequestExample:
    return RequestExample(**{**data, "evidence": EvidenceRef(**data["evidence"])})


def _examples(items: list[dict[str, Any]]) -> tuple[RequestExample, ...]:
    return tuple(_example(item) for item in items)


def _reason(data: dict[str, Any]) -> PriorityReason:
    return PriorityReason(
        **{
            **data,
            "evidence": tuple(EvidenceRef(**ref) for ref in data["evidence"]),
            "examples": _examples(data.get("examples", [])),
        }
    )


def _profile(data: dict[str, Any]) -> ClientProfile:
    return ClientProfile(
        **{
            **data,
            "categories": tuple(data["categories"]),
            "reasons": tuple(_reason(reason) for reason in data["reasons"]),
            **{
                name: _examples(data.get(name, []))
                for name in (
                    "distinct_examples",
                    "sequence_examples",
                    "recurrence_examples",
                    "exploit_examples",
                )
            },
            "exploit_rules": tuple(data.get("exploit_rules", ())),
            "rule_labels": tuple(tuple(item) for item in data.get("rule_labels", ())),
            "evidence": {
                key: tuple(EvidenceRef(**ref) for ref in refs)
                for key, refs in data["evidence"].items()
            },
        }
    )


def read_page(
    path: Path,
    queue: QueueName,
    *,
    query: str = "",
    offset: int = 0,
    limit: int = 100,
) -> TriagePage:
    """Search the entire ranking and retrieve only the requested page."""
    if queue not in ("suspicious", "unusual", "all"):
        raise ValueError(f"unknown investigation queue: {queue}")
    if offset < 0 or limit < 1:
        raise ValueError("page offset must be nonnegative and limit positive")
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        where = "queue = ? AND instr(ip, ?) > 0"
        params = (queue, query.strip())
        total = connection.execute(
            f"SELECT count(*) FROM ranking WHERE {where}", params
        ).fetchone()[0]
        rows = connection.execute(
            f"SELECT profile, reasons, position FROM ranking JOIN clients USING(ip) WHERE {where} ORDER BY position LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
    return TriagePage(
        tuple(_ranked(queue, profile, reasons, position) for profile, reasons, position in rows),
        total,
        offset,
    )


def _ranked(queue: QueueName, profile: str, reasons: str, position: int) -> RankedClient:
    """A stored row, with Suspicious activity reasons rebuilt from its profile.

    Those reasons are wording over facts the profile keeps, so they are written
    from the code that reads the index, not the code that wrote it: otherwise a
    case scanned before a rewording would go on showing the old text. Unusual
    activity reasons compare the client with the whole scanned population, which
    only the stored copy knows.
    """
    stored = _profile(json.loads(profile))
    if queue == "suspicious":
        return RankedClient(stored, suspicious_reasons(stored), position)
    return RankedClient(stored, tuple(_reason(r) for r in json.loads(reasons)), position)


def read_rule_matches(path: Path, rule_id: str) -> tuple[RuleMatch, ...]:
    """Every client whose requests this rule matched, most matches first.

    Includes clients the rule matched without naming: see `RuleMatch.won`.
    """
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        rows = connection.execute(
            "SELECT ip, matched, won, requests FROM rules WHERE rule = ? ORDER BY matched DESC, ip",
            (rule_id,),
        ).fetchall()
    return tuple(RuleMatch(ip, matched, won, requests) for ip, matched, won, requests in rows)


def read_labels(path: Path) -> tuple[tuple[str, str, str], ...]:
    """Every `(rule id, name, category)` the scan saw, for `labels_for_activity`."""
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        rows = connection.execute(
            "SELECT rule, name, category FROM labels ORDER BY rule, name, category"
        ).fetchall()
    return tuple((rule, name, category) for rule, name, category in rows)


def read_activity_clients(path: Path, rule_ids: frozenset[str]) -> frozenset[str]:
    """The clients any of `rule_ids` matched, whether or not its label was kept."""
    if not rule_ids:
        return frozenset()
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        rows = connection.execute(
            "SELECT DISTINCT ip FROM rules WHERE rule IN (SELECT value FROM json_each(?))",
            (json.dumps(sorted(rule_ids)),),
        ).fetchall()
    return frozenset(row[0] for row in rows)


def read_activity_counts(path: Path) -> list[tuple[str, int]]:
    """Each activity the scan saw, with how many clients; most clients first.

    Counted as `activity:` finds them, by category and by rule name, so the
    number offered beside a value is the number of clients choosing it lists.
    Counted by category alone, `enumeration` left out an injection rule named
    *schema enumeration* that the search then listed.
    """
    labels = read_labels(path)
    counts = [
        (category, len(read_activity_clients(path, labels_for_activity(labels, category))))
        for category in sorted({category for _rule, _name, category in labels})
    ]
    return sorted(
        ((category, clients) for category, clients in counts if clients),
        key=lambda item: (-item[1], item[0]),
    )


def read_profiles(path: Path) -> tuple[ClientProfile, ...]:
    """Read completed profiles in stable order for evaluation without rescanning logs."""
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
        return tuple(
            _profile(json.loads(row[0]))
            for row in connection.execute("SELECT profile FROM clients ORDER BY ip")
        )


def _load_crs(connection: sqlite3.Connection, path: Path, check: Callable[[], None]) -> bool:
    """Index line-keyed CRS records on disk; memory is bounded by one JSON line."""
    connection.execute("CREATE TABLE crs(source TEXT, line INTEGER, payload TEXT)")
    if path.exists():
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                check()
                if line.strip():
                    data = json.loads(line)
                    connection.execute(
                        "INSERT INTO crs VALUES (?, ?, ?)",
                        (data["source_file_id"], data["line_no"], line),
                    )
    connection.execute("CREATE INDEX crs_evidence ON crs(source, line)")
    connection.commit()
    return connection.execute("SELECT 1 FROM crs LIMIT 1").fetchone() is not None


def _client_crs(
    connection: sqlite3.Connection,
    events: Sequence[NormalizedEvent],
) -> dict[tuple[str, int], list[CrsDetection]]:
    index: dict[tuple[str, int], list[CrsDetection]] = {}
    for event in events:
        key = (event.evidence.source_file_id, event.evidence.line_no)
        rows = connection.execute("SELECT payload FROM crs WHERE source = ? AND line = ?", key)
        matches = [
            CrsDetection.from_json(json.loads(row[0]), source_file_id=key[0]) for row in rows
        ]
        if matches:
            index[key] = matches
    return index


def scan_case(
    root: Path,
    *,
    window: TimeWindow = EVERYTHING,
    policy: TriagePolicy = DEFAULT_POLICY,
    report: Callable[[TriageProgress], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    scratch_root: Path | None = None,
    rules: RuleSet = NO_EXTRA_RULES,
) -> TriageResult:
    """Profile all clients and publish only complete results under their input hash.

    `rules` is what the window reads clients with. The engine's fingerprint is
    part of that hash, so a change of rules gets a scan of its own, and the one
    before stays on disk for switching back.
    """
    started = monotonic()

    def check() -> None:
        if cancelled is not None and cancelled():
            raise ScanCancelled()

    check()
    session_policy = SessionPolicy()
    crs_path = root / "crs.jsonl"
    with Case.open(root) as case:
        # The case's engine rather than a default one. `rfi_offsite_url`
        # reports nothing until a reader has named the site's own domains, so
        # an engine built here would label a client differently from the
        # reconstruction of that same client, and the queue is only useful
        # while the two agree.
        engine = case.rule_engine(rules)
        crs_partial = crs_path.exists() and recorded_coverage(case.manifest.config) is not None
        identity = {
            "sources": [asdict(source) for source in case.manifest.sources],
            "config": case.manifest.config,
            "rules": engine.fingerprint,
            # What each file cannot record changes what the rules find, and is
            # not in their fingerprint: it is the case's, not the rules'.
            "unrecorded": {source: sorted(fields) for source, fields in engine.unrecorded.items()},
            "crs": _digest(crs_path),
            "window": asdict(window),
            "session": session_policy.as_config(),
            "policy": asdict(policy),
            "layout": _LAYOUT,
        }
        key = hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()
        directory = root / "triage"
        directory.mkdir(exist_ok=True)
        destination = directory / f"{key}.sqlite"
        if destination.exists():
            try:
                with closing(
                    sqlite3.connect(f"{destination.resolve().as_uri()}?mode=ro", uri=True)
                ) as cached:
                    data = json.loads(cached.execute("SELECT payload FROM metadata").fetchone()[0])
                    count = cached.execute("SELECT count(*) FROM clients").fetchone()[0]
                    ranked = cached.execute(
                        "SELECT count(*) FROM ranking WHERE queue = 'all'"
                    ).fetchone()[0]
                    # Asked only so a missing table raises: every client
                    # matches some rule, even if only the benign fallback.
                    cached.execute("SELECT count(*) FROM rules").fetchone()
                    cached.execute("SELECT count(*) FROM labels").fetchone()
                    if count != data["clients"] or ranked != count:
                        raise ValueError("incomplete prioritization cache")
                return TriageResult(
                    destination,
                    data["clients"],
                    data["eligible"],
                    data["crs_present"],
                    True,
                    monotonic() - started,
                    crs_partial,
                )
            except (sqlite3.Error, ValueError, KeyError, TypeError):
                pass
        with (
            tempfile.TemporaryDirectory(prefix="scan-", dir=scratch_root or directory) as temporary,
            closing(ParquetEventStore(root, scratch=Path(temporary) / "duckdb")) as store,
        ):
            scratch = Path(temporary)
            total = store.overview(window=window).clients
            profiles = []
            leaders: list[ClientProfile] = []
            last_report = 0.0
            with closing(sqlite3.connect(scratch / "crs.sqlite")) as crs:
                has_detections = _load_crs(crs, crs_path, check)
                for events in store.iter_clients(window=window):
                    check()
                    index = _client_crs(crs, events) if has_detections else None
                    profile = profile_client(
                        events, engine, crs=index, session_policy=session_policy
                    )
                    profiles.append(profile)
                    if profile.hostile_requests:
                        leaders = [
                            row.profile
                            for row in rank_profiles([*leaders, profile], "suspicious")[:20]
                        ]
                    if report is not None and monotonic() - last_report >= 0.25:
                        report(
                            TriageProgress(
                                len(profiles), total, tuple(rank_profiles(leaders, "suspicious"))
                            )
                        )
                        last_report = monotonic()
            eligible = sum(p.requests >= policy.minimum_requests for p in profiles)
            data = {
                "identity": identity,
                "clients": len(profiles),
                "eligible": eligible,
                "crs_present": crs_path.exists(),
            }
            staging = scratch / "result.sqlite"
            with closing(sqlite3.connect(staging)) as output:
                output.executescript(
                    "CREATE TABLE metadata(payload TEXT);"
                    "CREATE TABLE clients(ip TEXT PRIMARY KEY, profile TEXT);"
                    "CREATE TABLE ranking(queue TEXT, position INTEGER, ip TEXT, reasons TEXT, PRIMARY KEY(queue, position));"
                    # Its own table rather than read out of `clients`: asking
                    # who else a rule matched would otherwise parse every
                    # profile in the case to answer for a handful of them.
                    "CREATE TABLE rules(rule TEXT, ip TEXT, matched INTEGER, won INTEGER, requests INTEGER, PRIMARY KEY(rule, ip));"
                    # What each rule id was called, and which activity it named,
                    # as the labels themselves said: `activity:` searches by it.
                    "CREATE TABLE labels(rule TEXT, name TEXT, category TEXT, PRIMARY KEY(rule, name, category));"
                )
                output.execute("INSERT INTO metadata VALUES (?)", (json.dumps(data, default=str),))
                output.executemany(
                    "INSERT INTO clients VALUES (?, ?)",
                    ((p.client_ip, json.dumps(asdict(p))) for p in profiles),
                )
                output.executemany(
                    "INSERT INTO rules VALUES (?, ?, ?, ?, ?)",
                    (
                        (rule, p.client_ip, matched, p.rules_won.get(rule, 0), p.requests)
                        for p in profiles
                        for rule, matched in p.rules_matched.items()
                    ),
                )
                output.executemany(
                    "INSERT OR IGNORE INTO labels VALUES (?, ?, ?)",
                    (label for p in profiles for label in p.rule_labels),
                )
                for queue in ("suspicious", "unusual", "all"):
                    check()
                    for position, row in enumerate(rank_profiles(profiles, queue, policy), 1):
                        check()
                        output.execute(
                            "INSERT INTO ranking VALUES (?, ?, ?, ?)",
                            (
                                queue,
                                position,
                                row.profile.client_ip,
                                json.dumps([asdict(r) for r in row.reasons]),
                            ),
                        )
                output.commit()
            check()
            if _digest(crs_path) != identity["crs"]:
                raise RuntimeError(
                    "CRS evidence changed during prioritization; run the scan again."
                )
            staging.replace(destination)
    return TriageResult(
        destination,
        len(profiles),
        eligible,
        crs_path.exists(),
        False,
        monotonic() - started,
        crs_partial,
    )


def iter_labelled(root: Path, *, window: TimeWindow = EVERYTHING) -> Iterator[LabelledEvent]:
    """Every request in the case as the scan labels it: the case's engine, its CRS
    records and the same session boundaries, one client at a time.

    For evaluation passes that need each request's labels, such as auditing which
    rules count as high-confidence matches; the queue itself reads profiles.
    """
    session_policy = SessionPolicy()
    with Case.open(root) as case:
        # The built-in rules only, never a reader's: an evaluation measures the
        # rules LogarX ships.
        engine = case.rule_engine()
    directory = root / "triage"
    directory.mkdir(exist_ok=True)
    with (
        tempfile.TemporaryDirectory(prefix="labels-", dir=directory) as temporary,
        closing(ParquetEventStore(root, scratch=Path(temporary) / "duckdb")) as store,
        closing(sqlite3.connect(Path(temporary) / "crs.sqlite")) as crs,
    ):
        has_detections = _load_crs(crs, root / "crs.jsonl", lambda: None)
        for events in store.iter_clients(window=window):
            index = _client_crs(crs, events) if has_detections else None
            ordered = sorted(events, key=lambda e: (e.timestamp, e.evidence.line_no))
            for _, labelled in label_sessions(ordered, engine, policy=session_policy, crs=index):
                yield from labelled
