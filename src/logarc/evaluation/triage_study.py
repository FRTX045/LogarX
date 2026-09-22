"""Reproducible case evaluation for the fixed prioritization experiment."""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from pathlib import Path
from time import perf_counter
from typing import Any

from logarc.case import Case
from logarc.core.activity import ActivityCategory
from logarc.evaluation.priorities import audit_unusual
from logarc.evaluation.triage import compare_rankings
from logarc.evaluation.truth import read_truth
from logarc.storage.case import CaseManifest
from logarc.triage.scan import read_profiles, scan_case


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def evaluate_case(
    root: Path,
    source: Path,
    truth_path: Path,
    *,
    include_model: bool = True,
) -> dict[str, Any]:
    """Verify source and per-line truth, then score cached profiles with CRS PL2."""
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
    verified_seconds = perf_counter() - started
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
