"""Bounded, explicit live source verification.

Fetches each configured source file ONCE (the fetcher may retry transient failures,
within its own request budget), parses it with the project's own parsers and reports
health per file: retrieval time, HTTP status, size, SHA-256, parser outcome, record
counts and freshness. It never classifies an address and never caches anything.

The module has no endpoint list of its own: callers pass ProbeTargets built from the
adapters' constants (see scripts/verify_sources.py), so there is nothing to drift.
It does not touch the network by itself; it only uses the Fetcher it is given.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Optional

from .errors import SourceError, SourceErrorKind
from .http_client import Clock, Fetcher, utc_now
from .parsers import CidrSet, parse_cidr_list, parse_ip_list
from .redaction import redact_text, redact_url
from .source_health import (
    SourceHealthRecord,
    SourceHealthState,
    state_for_error,
)

TOOL_VERSION = "live-verify-1"
REPORT_SCHEMA_VERSION = 1
KIND_IP_LIST = "ip_list"
KIND_CIDR_LIST = "cidr_list"


@dataclass(frozen=True)
class ProbeTarget:
    source: str  # registry name
    file: str  # label shown in the report
    url: str
    kind: str  # KIND_IP_LIST or KIND_CIDR_LIST
    min_entries: int = 1
    family: Optional[int] = None  # 4 or 6 for a family-specific CIDR list
    role: str = "evidence"  # "evidence" or "exclusion"
    overlap_key: Optional[str] = None  # "tor", "vpn_cidr_v4", "vpn_cidr_v6", "az0", "apple"


def _last_modified_age(
    headers: dict[str, str], now: datetime
) -> tuple[Optional[str], Optional[float]]:
    raw = headers.get("last-modified")
    if not raw:
        return None, None
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return raw, None
    if when.tzinfo is None:
        return raw, None
    return raw, (now - when).total_seconds()


def _probe(
    target: ProbeTarget,
    fetcher: Fetcher,
    clock: Clock,
    max_source_age_seconds: int,
    monotonic: Callable[[], float],
) -> tuple[SourceHealthRecord, Any]:
    record = SourceHealthRecord(
        source=target.source,
        file=target.file,
        role=target.role,
        url=redact_url(target.url),
        state=SourceHealthState.NOT_CHECKED,
        sanity_floor=target.min_entries,
    )
    started = monotonic()
    parsed: Any = None
    try:
        result = fetcher.fetch(target.url)
    except SourceError as exc:
        record.checked_at = clock()
        record.elapsed_seconds = round(monotonic() - started, 3)
        record.state = state_for_error(exc.kind)
        record.error_kind = exc.kind.value
        record.http_status = exc.status_code
        record.message = redact_text(exc.message)
        record.parser_outcome = "NOT_RUN"
        return record, None

    record.checked_at = result.retrieved_at
    record.elapsed_seconds = round(monotonic() - started, 3)
    record.http_status = result.status_code
    record.attempts = getattr(result, "attempts", 1)
    record.bytes = len(result.body)
    record.sha256 = hashlib.sha256(result.body).hexdigest()
    record.etag = result.headers.get("etag")
    record.last_modified, record.source_age_seconds = _last_modified_age(
        dict(result.headers), result.retrieved_at
    )
    record.freshness_verifiable = record.source_age_seconds is not None
    if not record.freshness_verifiable:
        record.notes.append(
            "no usable Last-Modified header: the source's age cannot be verified "
            "(this is not a failure, but staleness would go unnoticed)"
        )

    try:
        if target.kind == KIND_IP_LIST:
            parsed = parse_ip_list(result.body, source=target.file, min_entries=target.min_entries)
        else:
            parsed = parse_cidr_list(
                result.body,
                source=target.file,
                family=target.family,
                min_entries=target.min_entries,
            )
    except SourceError as exc:
        record.state = state_for_error(exc.kind)
        record.error_kind = exc.kind.value
        record.message = redact_text(exc.message)
        record.parser_outcome = exc.kind.value
        return record, None

    record.parser_outcome = "OK"
    record.records = parsed.count
    record.ipv4_records = parsed.v4_count
    record.ipv6_records = parsed.v6_count
    if record.freshness_verifiable and record.source_age_seconds > max_source_age_seconds:
        record.state = SourceHealthState.STALE
        record.error_kind = SourceErrorKind.STALE_SOURCE.value
        record.message = (
            f"source last modified {record.source_age_seconds:.0f}s ago, "
            f"older than the {max_source_age_seconds}s limit"
        )
        return record, None  # a stale file is never used as evidence
    record.state = SourceHealthState.HEALTHY
    return record, parsed


Group = list[tuple[SourceHealthRecord, Any]]


def _all_healthy(group: Optional[Group]) -> bool:
    return bool(group) and all(rec.state is SourceHealthState.HEALTHY for rec, _ in group)


def _overlap(groups: dict[str, Group]) -> dict[str, Any]:
    """Tor / VPN / Apple overlap from HEALTHY files only. Counts, never a classification."""
    if not _all_healthy(groups.get("tor")):
        return {
            "status": "NOT_ASSESSABLE",
            "reason": "Tor exit list is not HEALTHY; overlap with VPN evidence cannot be measured",
        }
    tor = groups["tor"][0][1]
    vpn_keys = [k for k in ("vpn_cidr_v4", "vpn_cidr_v6", "az0") if k in groups]
    healthy_vpn = [k for k in vpn_keys if _all_healthy(groups[k])]
    unhealthy_vpn = [k for k in vpn_keys if k not in healthy_vpn]
    if not healthy_vpn:
        return {
            "status": "NOT_ASSESSABLE",
            "reason": "no VPN evidence file is HEALTHY; overlap cannot be measured",
            "vpn_files_not_healthy": unhealthy_vpn,
        }

    cidr_sets: list[CidrSet] = [
        groups[k][0][1].cidrs for k in ("vpn_cidr_v4", "vpn_cidr_v6") if k in healthy_vpn
    ]
    az0_entries: Optional[set[str]] = None
    if "az0" in healthy_vpn:
        az0_entries = set()
        for _, parsed in groups["az0"]:
            az0_entries |= set(parsed.entries)
    apple = groups["apple"][0][1].cidrs if _all_healthy(groups.get("apple")) else None

    in_cidr = in_az0 = both = apple_excluded = 0
    by_cidr: dict[str, int] = {}
    for address in tor.entries:
        hits = [net for cidrs in cidr_sets for net in cidrs.match_all(address)]
        listed_az0 = az0_entries is not None and address in az0_entries
        in_cidr += bool(hits)
        in_az0 += listed_az0
        both += bool(hits) and listed_az0
        if hits:
            if apple is not None and apple.match(address) is not None:
                apple_excluded += 1
            by_cidr[str(hits[0])] = by_cidr.get(str(hits[0]), 0) + 1

    complete = not unhealthy_vpn and apple is not None
    return {
        "status": "COMPLETE" if complete else "PARTIAL",
        "tor_exit_addresses": tor.count,
        "tor_in_x4bnet_ranges": in_cidr if cidr_sets else None,
        "tor_in_az0_lists": in_az0 if az0_entries is not None else None,
        "tor_in_both_vpn_sources": both if (cidr_sets and az0_entries is not None) else None,
        "tor_in_x4bnet_ranges_also_apple_excluded": apple_excluded if apple is not None else None,
        "top_matched_x4bnet_ranges": sorted(by_cidr.items(), key=lambda kv: (-kv[1], kv[0]))[:10],
        "vpn_files_not_healthy": unhealthy_vpn,
        "apple_exclusion_healthy": apple is not None,
        "counts_are_lower_bounds": not complete,
        "note": (
            "Counts only. Policy (unchanged, ps010-policy-1): when both a Tor and a VPN record "
            "are established the classifier answers Unknown. If a VPN file or the Apple list is "
            "NOT healthy, a Tor listing alone still yields 'Known Tor exit' because the conflict "
            "cannot be seen (documented edge case A)."
        ),
    }


def run_live_verification(
    targets: list[ProbeTarget],
    fetcher: Fetcher,
    *,
    max_source_age_seconds: int = 86400,
    request_budget: Optional[int] = None,
    group_floors: Optional[dict[str, int]] = None,
    clock: Clock = utc_now,
    monotonic: Optional[Callable[[], float]] = None,
) -> dict[str, Any]:
    """Probe every target once and return a JSON-safe, already-redacted report."""
    monotonic = monotonic or time.monotonic
    started_at = clock()
    records: list[SourceHealthRecord] = []
    groups: dict[str, Group] = {}
    for target in targets:
        made = getattr(fetcher, "requests_made", None)
        if request_budget is not None and made is not None and made >= request_budget:
            rec = SourceHealthRecord(
                source=target.source,
                file=target.file,
                role=target.role,
                url=redact_url(target.url),
                state=SourceHealthState.NOT_CHECKED,
                message="request budget exhausted before this file was checked",
                sanity_floor=target.min_entries,
            )
            parsed = None
        else:
            rec, parsed = _probe(target, fetcher, clock, max_source_age_seconds, monotonic)
        records.append(rec)
        if target.overlap_key:
            groups.setdefault(target.overlap_key, []).append((rec, parsed))

    group_checks = []
    for key, floor in (group_floors or {}).items():
        group = groups.get(key)
        if not group:
            continue
        healthy_total = sum(
            rec.records or 0 for rec, _ in group if rec.state is SourceHealthState.HEALTHY
        )
        ok = _all_healthy(group) and healthy_total >= floor
        group_checks.append(
            {
                "group": key,
                "state": SourceHealthState.HEALTHY.value
                if ok
                else SourceHealthState.INSUFFICIENT_EVIDENCE.value,
                "healthy_records_total": healthy_total,
                "combined_floor": floor,
                "files_not_healthy": [r.file for r, _ in group if r.state is not SourceHealthState.HEALTHY],
            }
        )

    states = [r.state for r in records]
    failing = [r for r in records if r.state is not SourceHealthState.HEALTHY]
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "mode": "LIVE",
        "started_at": started_at.isoformat(),
        "finished_at": clock().isoformat(),
        "requests_made": getattr(fetcher, "requests_made", None),
        "request_budget": request_budget,
        "max_source_age_seconds": max_source_age_seconds,
        "summary": {
            "files_checked": len(records),
            "healthy": states.count(SourceHealthState.HEALTHY),
            "unhealthy": len(failing),
            "by_state": {s.value: states.count(s) for s in SourceHealthState if s in states},
        },
        "files": [r.to_dict() for r in records],
        "group_checks": group_checks,
        "tor_vpn_overlap": _overlap(groups),
        "evidence_rule": (
            "Only a HEALTHY file can support 'confirmed absence'. Any other state means absence "
            "is NOT established and must never be treated as negative evidence."
        ),
    }


def format_markdown(report: dict[str, Any]) -> str:
    """Human-readable version of the (already redacted) report."""
    s = report["summary"]
    lines = [
        "# Live source verification",
        "",
        f"- Started: {report['started_at']}  Finished: {report['finished_at']}",
        f"- Tool: {report['tool_version']}  Requests made: {report['requests_made']} "
        f"(budget {report['request_budget']})",
        f"- Files: {s['files_checked']} checked, {s['healthy']} healthy, {s['unhealthy']} not healthy "
        f"{s['by_state']}",
        "",
        "| Source | File | Role | State | HTTP | Bytes | Records | Parser | Attempts | Detail |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for f in report["files"]:
        detail = f.get("message") or "; ".join(f.get("notes") or []) or ""
        lines.append(
            f"| {f['source']} | {f['file']} | {f['role']} | {f['state']} | {f['http_status']} | "
            f"{f['bytes']} | {f['records']} | {f['parser_outcome']} | {f['attempts']} | "
            f"{detail.replace('|', '/')} |"
        )
    lines += ["", "## SHA-256 and freshness", ""]
    for f in report["files"]:
        lines.append(
            f"- {f['source']}/{f['file']}: sha256={f['sha256']} etag={f['etag']} "
            f"last_modified={f['last_modified']} age_s={f['source_age_seconds']}"
        )
    lines += ["", "## Tor / VPN overlap", "", "```", str(report["tor_vpn_overlap"]), "```", ""]
    lines += [f"_{report['evidence_rule']}_", ""]
    return "\n".join(lines)


MAX_REQUESTS_CEILING = 60
MAX_TIMEOUT_CEILING = 30.0

LIVE_WARNING = (
    "LIVE VERIFICATION: this will contact the real source endpoints (Tor Project, "
    "raw.githubusercontent.com). It makes at most {budget} HTTPS GET requests, caches nothing, "
    "writes only the redacted report files below, and never classifies an address."
)


def cli_main(
    argv: list[str],
    *,
    targets_factory: Callable[[], list[ProbeTarget]],
    fetcher_factory: Callable[[float, int, int], Fetcher],
    group_floors: Optional[dict[str, int]] = None,
    default_timeout: float = 10.0,
    default_max_age: int = 86400,
    clock: Clock = utc_now,
    out: Callable[[str], None] = print,
) -> int:
    """Exit codes: 0 every file healthy, 1 at least one file not healthy, 2 not run."""
    parser = argparse.ArgumentParser(
        prog="verify_sources.py", description="Bounded live check of the PS-010 source files."
    )
    parser.add_argument("--live", action="store_true", help="REQUIRED: allow real network requests")
    parser.add_argument("--output-dir", default="reports/live", help="where reports are written")
    parser.add_argument("--max-requests", type=int, default=30, help="hard cap on HTTP requests")
    parser.add_argument("--timeout", type=float, default=default_timeout, help="seconds per read")
    parser.add_argument("--retries", type=int, default=2, help="retries per file (0-2)")
    parser.add_argument("--max-source-age", type=int, default=default_max_age, help="seconds")
    args = parser.parse_args(argv)

    if not args.live:
        out(
            "Nothing was done: live verification needs the explicit --live flag. "
            "No network request was made."
        )
        return 2
    if not 1 <= args.max_requests <= MAX_REQUESTS_CEILING:
        out(f"--max-requests must be between 1 and {MAX_REQUESTS_CEILING}")
        return 2
    if not 0 < args.timeout <= MAX_TIMEOUT_CEILING:
        out(f"--timeout must be greater than 0 and at most {MAX_TIMEOUT_CEILING:g} seconds")
        return 2
    if not 0 <= args.retries <= 2:
        out("--retries must be between 0 and 2")
        return 2
    if args.max_source_age <= 0:
        out("--max-source-age must be positive")
        return 2

    out(LIVE_WARNING.format(budget=args.max_requests))
    fetcher = fetcher_factory(args.timeout, args.retries, args.max_requests)
    report = run_live_verification(
        targets_factory(),
        fetcher,
        max_source_age_seconds=args.max_source_age,
        request_budget=args.max_requests,
        group_floors=group_floors,
        clock=clock,
    )

    stamp = clock().strftime("%Y%m%dT%H%M%SZ")
    directory = Path(args.output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"live-verification-{stamp}.json"
    md_path = directory / f"live-verification-{stamp}.md"
    with open(json_path, "x", encoding="utf-8") as handle:  # never overwrite earlier evidence
        json.dump(report, handle, indent=2)
    with open(md_path, "x", encoding="utf-8") as handle:
        handle.write(format_markdown(report))

    summary = report["summary"]
    out(
        f"{summary['healthy']}/{summary['files_checked']} files healthy; "
        f"{report['requests_made']} request(s) made."
    )
    for item in report["files"]:
        if item["state"] != "HEALTHY":
            out(f"  NOT HEALTHY: {item['source']}/{item['file']} -> {item['state']}: {item['message']}")
    out(f"Reports written: {json_path} and {md_path}")
    return 0 if summary["unhealthy"] == 0 else 1
