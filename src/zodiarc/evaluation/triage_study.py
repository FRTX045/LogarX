"""Reproducible case evaluation for the fixed prioritization experiment."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

from zodiarc.case import Case
from zodiarc.core.activity import ActivityCategory
from zodiarc.detect.crs.store import COMPLETE_KEY
from zodiarc.evaluation.graded import client_truth, graded_scores, low_support
from zodiarc.evaluation.priorities import (
    assert_same_ranked,
    audit_unusual,
    bonus_parts,
    crs_placed,
    exploit_orderings,
    graded_orderings,
)
from zodiarc.evaluation.triage import compare_rankings
from zodiarc.evaluation.truth import GroundTruth, read_truth
from zodiarc.storage.case import CaseManifest, SourceRecord
from zodiarc.triage.profile import (
    DEFAULT_POLICY,
    NOT_EXPLOIT_EVIDENCE,
    TARGETED,
    ClientProfile,
    high_confidence_match,
    priority_score,
    rank_profiles,
)
from zodiarc.triage.reasons import suspicious_reasons
from zodiarc.triage.scan import iter_labelled, read_profiles, scan_case


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@dataclass(frozen=True)
class _Verified:
    manifest: CaseManifest
    record: SourceRecord
    truth: GroundTruth
    source_hash: str
    judgments: dict[str, bool]
    exclusions: dict[str, str]
    seconds: float


def _verified(root: Path, source: Path, truth_path: Path) -> _Verified:
    """Check the case, its one source and its per-line truth agree, and judge each client.

    A client whose truth is unknown for some request and hostile for none is excluded,
    not assumed benign.
    """
    started = perf_counter()
    manifest = CaseManifest.load(root)
    if len(manifest.sources) != 1:
        raise ValueError("the study requires one verified source per case")
    record = manifest.sources[0]
    source_hash = file_hash(source)
    if source_hash != record.sha256:
        raise ValueError("source hash does not match the ingested case")
    if manifest.config.get("crs_paranoia_level") != 2 or not (root / "crs.jsonl").is_file():
        raise ValueError("complete-product evaluation requires recorded CRS paranoia level 2")
    if not all(manifest.config.get(key) for key in ("crs_revision", "crs_fingerprint")):
        raise ValueError("CRS revision and configuration fingerprint are required")
    if manifest.config.get(COMPLETE_KEY) is False:
        raise ValueError("complete-product evaluation requires a CRS run that finished")
    truth = read_truth(truth_path)
    records = {item.line_no: item for item in truth.records}
    if truth.source_file_id != record.file_id or len(records) != len(truth.records):
        raise ValueError("truth source or line references do not match the case")
    judgments: dict[str, bool] = {}
    exclusions: dict[str, str] = {}
    count = 0
    with Case.open(root) as case:
        for event in case.store.all_events():
            item = records.get(event.evidence.line_no)
            if (
                item is None
                or item.client_ip != event.client_ip
                or event.evidence.source_file_id != truth.source_file_id
            ):
                raise ValueError(f"truth does not judge case line {event.evidence}")
            judgments[item.client_ip] = (
                judgments.get(item.client_ip, False) or item.category.is_hostile
            )
            if item.category is ActivityCategory.UNKNOWN:
                exclusions[item.client_ip] = "unknown request ground truth"
            count += 1
    if count != len(records):
        raise ValueError("truth line coverage differs from the parsed case")
    exclusions = {ip: reason for ip, reason in exclusions.items() if not judgments[ip]}
    return _Verified(
        manifest, record, truth, source_hash, judgments, exclusions, perf_counter() - started
    )


def evaluate_case(
    root: Path,
    source: Path,
    truth_path: Path,
    *,
    include_model: bool = True,
) -> dict[str, Any]:
    """Verify source and per-line truth, then score cached profiles with CRS PL2."""
    verified = _verified(root, source, truth_path)
    manifest, record, truth = verified.manifest, verified.record, verified.truth
    source_hash, exclusions = verified.source_hash, verified.exclusions
    judgments = verified.judgments
    verified_seconds = verified.seconds
    result = scan_case(root)
    profiles = read_profiles(result.path)
    observed_clients = len(profiles)
    profiles = tuple(p for p in profiles if p.client_ip not in exclusions)
    judgments = {ip: value for ip, value in judgments.items() if ip not in exclusions}
    evaluation_started = perf_counter()
    report = compare_rankings(
        profiles,
        suspicious=judgments,
        include_model=include_model,
        provenance={
            "suspicious": f"{truth.scenario}, seed {truth.seed}; positive iff any source request has hostile ground truth"
        },
    )
    head = report.comparisons["operational"]["suspicious"]["suspicious"].false_recommendations
    return {
        "identity": {
            "case": manifest.case_id,
            "scenario": truth.scenario,
            "seed": truth.seed,
            "source_sha256": source_hash,
            "truth_sha256": file_hash(truth_path),
            "crs_sha256": file_hash(root / "crs.jsonl"),
            **manifest.config,
        },
        "timing": {
            "verification_seconds": verified_seconds,
            "scan_seconds": result.seconds,
            "scan_cached": result.cached,
            "evaluation_seconds": perf_counter() - evaluation_started,
        },
        "requests": record.events_parsed,
        "observed_clients": observed_clients,
        "judgment_exclusions": exclusions,
        "largest_client_requests": max((p.requests for p in profiles), default=0),
        "report": asdict(report),
        "unusual_audit": audit_unusual(profiles),
        "false_suspicious_evidence": {
            p.client_ip: {
                "severity": p.severity,
                "requests": p.requests,
                "hostile_requests": p.hostile_requests,
                "reasons": [asdict(reason) for reason in p.reasons],
            }
            for p in profiles
            if p.client_ip in head
        },
        "unusual_judgments": "unavailable; security comparisons are secondary retrieval diagnostics",
    }


def evaluate_graded_case(root: Path, source: Path, truth_path: Path) -> dict[str, Any]:
    """Verify the case, then score today's ordering and both challengers against grades
    taken from the truth file alone, with the high-confidence rule audit beside them.

    Every targeted client is listed by address with its rank under each method; clients
    in any method's first 50 carry their base score and bonus parts; benign ones among
    them carry the reasons the queue would show.
    """
    verified = _verified(root, source, truth_path)
    exclusions = verified.exclusions
    truth = client_truth(verified.truth.records, exclusions)
    result = scan_case(root)
    profiles = {p.client_ip: p for p in read_profiles(result.path) if p.client_ip not in exclusions}
    orders = graded_orderings(tuple(profiles.values()))
    assert_same_ranked(orders)
    scores = {name: graded_scores(order, truth) for name, order in orders.items()}
    quiet = low_support(truth)

    def above(name: str, ip: str) -> dict[str, int]:
        """Probe-only and benign clients ranked ahead of `ip`, or anywhere if it is unranked."""
        rank = scores[name].ranks[ip]
        ahead = orders[name][: rank - 1] if rank else orders[name]
        return {
            "probe_only": sum(truth[other].grade == 1 for other in ahead),
            "benign": sum(truth[other].grade == 0 for other in ahead),
        }

    targeted = [
        {
            "ip": ip,
            "grade": item.grade,
            "hostile": item.hostile,
            "requests": item.requests,
            "low_support": ip in quiet,
            "ranks": {name: scores[name].ranks[ip] for name in orders},
            "above": {name: above(name, ip) for name in orders},
        }
        for ip, item in sorted(truth.items())
        if item.grade == 2
    ]
    head_ips = sorted({ip for order in orders.values() for ip in order[:50]})
    head = {}
    for ip in head_ips:
        profile = profiles[ip]
        distinct, sequence, recurrence = bonus_parts(profile)
        head[ip] = {
            "grade": truth[ip].grade,
            "base": priority_score(profile),
            "D": distinct,
            "Q": sequence,
            "R": recurrence,
            "ranks": {name: scores[name].ranks[ip] for name in orders},
        }
    benign_head = [
        {
            "ip": ip,
            "ranks": head[ip]["ranks"],
            "reasons": [reason.text for reason in suspicious_reasons(profiles[ip])],
        }
        for ip in head_ips
        if truth[ip].grade == 0
    ]
    return {
        "identity": {
            "case": verified.manifest.case_id,
            "scenario": verified.truth.scenario,
            "seed": verified.truth.seed,
            "source_sha256": verified.source_hash,
            "truth_sha256": file_hash(truth_path),
            "crs_sha256": file_hash(root / "crs.jsonl"),
            **verified.manifest.config,
        },
        "judged": len(truth),
        "judgment_exclusions": exclusions,
        "low_support": sorted(quiet),
        "methods": {name: asdict(value) for name, value in scores.items()},
        "targeted": targeted,
        "head": head,
        "benign_head": benign_head,
        "audit": _audit(root, verified.truth, quiet, profiles),
    }


def evaluate_exploit_case(root: Path, source: Path, truth_path: Path) -> dict[str, Any]:
    """Verify the case, then score the exploit-evidence-first order against policy 3 and the
    category-only comparator on grades from the truth file alone.

    `queue` is taken from the scanned profiles before any truth exclusion, so it can be
    compared with another build's queue. `app_equals_exploit_first` compares the application's
    order with the one computed here from `hostile_rules`. `orderings_share_members` only
    checks that the orderings rank the same clients, which they do by construction (one
    profile list). `crs_only_first` lists clients the application puts first that have no
    eligible native rule among their hostile rules: those placed by CRS paranoia level 1
    evidence alone. It is reported, not required to be empty.
    """
    verified = _verified(root, source, truth_path)
    exclusions = verified.exclusions
    truth = client_truth(verified.truth.records, exclusions)
    result = scan_case(root)
    scanned = read_profiles(result.path)
    queue = [row.profile.client_ip for row in rank_profiles(scanned, "suspicious")]
    queue_policy3 = graded_orderings(scanned)["policy3"]
    with Case.open(root) as case:
        engine = case.rule_engine()
    category_rules = frozenset(r.id for r in engine.rules if r.category in TARGETED)
    eligible_rules = category_rules - NOT_EXPLOIT_EVIDENCE
    profiles = {p.client_ip: p for p in scanned if p.client_ip not in exclusions}
    orders = exploit_orderings(
        tuple(profiles.values()), category_rules=category_rules, eligible_rules=eligible_rules
    )
    shared = len({frozenset(order) for order in orders.values()}) == 1
    scores = {
        name: graded_scores(orders[name], truth)
        for name in ("policy3", "exploit_first", "category_only")
    }

    def first(order: list[str], group: frozenset[str], crs: bool = False) -> list[str]:
        return sorted(
            ip
            for ip in order
            if (crs and crs_placed(profiles[ip]))
            or any(r in group for r in profiles[ip].hostile_rules)
        )

    app_first = [
        row.profile.client_ip
        for row in rank_profiles(tuple(profiles.values()), "suspicious")
        if row.profile.exploit_examples
    ]
    targeted = [
        {
            "ip": ip,
            "grade": item.grade,
            "hostile": item.hostile,
            "requests": item.requests,
            "exploit_rules": list(profiles[ip].exploit_rules),
            "ranks": {
                name: order.index(ip) + 1 if ip in order else 0 for name, order in orders.items()
            },
        }
        for ip, item in sorted(truth.items())
        if item.grade == 2
    ]
    return {
        "identity": {
            "case": verified.manifest.case_id,
            "scenario": verified.truth.scenario,
            "seed": verified.truth.seed,
            "source_sha256": verified.source_hash,
            "truth_sha256": file_hash(truth_path),
            "crs_sha256": file_hash(root / "crs.jsonl"),
            "policy_version": DEFAULT_POLICY.version,
            **verified.manifest.config,
        },
        "judged": len(truth),
        "judgment_exclusions": exclusions,
        "methods": {name: asdict(value) for name, value in scores.items()},
        "first_group": {
            "policy3": [],
            "exploit_first": first(orders["exploit_first"], eligible_rules, crs=True),
            "category_only": first(orders["category_only"], category_rules),
            "app": sorted(app_first),
        },
        "app_equals_exploit_first": orders["app"] == orders["exploit_first"],
        "orderings_share_members": shared,
        "queue": {
            "members": sorted(queue),
            "policy3": queue_policy3,
            "app": queue,
        },
        "crs_only_first": sorted(
            ip
            for ip in app_first
            if not any(r in eligible_rules for r in profiles[ip].hostile_rules)
        ),
        "targeted": targeted,
    }


def _audit(
    root: Path,
    truth: GroundTruth,
    quiet: frozenset[str],
    profiles: dict[str, ClientProfile],
) -> dict[str, Any]:
    """Per qualifying rule, how many benign-truth and hostile-truth lines it matched."""
    categories = {record.line_no: record.category for record in truth.records}
    rules: dict[str, dict[str, Any]] = {}
    for item in iter_labelled(root):
        hostile = categories[item.event.evidence.line_no].is_hostile
        for label in {label.rule_id: label for label in item.all_labels}.values():
            if not high_confidence_match(label):
                continue
            row = rules.setdefault(
                label.rule_id,
                {
                    "name": label.name,
                    "confidence": label.confidence,
                    "benign_lines": 0,
                    "hostile_lines": 0,
                },
            )
            row["hostile_lines" if hostile else "benign_lines"] += 1
    for row in rules.values():
        row["flagged"] = row["benign_lines"] > 0
    matched = {ip for ip in quiet if ip in profiles and profiles[ip].distinct_rule_pairs}
    return {
        "rules": dict(sorted(rules.items())),
        "low_support_with_match": sorted(matched),
        "low_support_without_match": sorted(quiet - matched),
    }
