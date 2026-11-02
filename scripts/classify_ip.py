r"""Classify one IP address using live data (cached under data/cache).

Run from the project root:
    python scripts\classify_ip.py 8.8.8.8
    python scripts\classify_ip.py 2606:4700:4700::1111
    python scripts\classify_ip.py 8.8.8.8 --at 2026-10-29T12:00:00+00:00
    python scripts\classify_ip.py 8.8.8.8 --context     # also query RIPEstat (context only)
    python scripts\classify_ip.py 8.8.8.8 --ipinfo      # also query IPinfo (metadata only; needs IPINFO_TOKEN)
    python scripts\classify_ip.py 8.8.8.8 --audit       # also save the result to the SQLite audit history

Audit history is OFF unless NETCLASS_AUDIT_ENABLED is set or --audit is passed (--no-audit wins
over the setting). Without it nothing is written and the output is exactly as before. With it the
JSON gains an "audit" section; exit code 5 means "classified, but the audit record was NOT saved".

The observation time defaults to now (UTC). Only a time close to now can be
supported: all three sources are current-only snapshots.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pydantic import ValidationError  # noqa: E402

from netclass.config import load_settings  # noqa: E402
from netclass.models import Observation  # noqa: E402
from netclass.service import AuditStatus, ClassificationService  # noqa: E402

EXIT_AUDIT_NOT_SAVED = 5


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("ip", help="IPv4 or IPv6 address")
    parser.add_argument("--at", help="observation time, ISO 8601 with UTC offset (default: now)")
    parser.add_argument("--evidence", action="store_true", help="include full evidence records")
    parser.add_argument(
        "--context",
        action="store_true",
        help="also fetch RIPEstat network context (metadata only; never changes the label)",
    )
    parser.add_argument(
        "--ipinfo",
        action="store_true",
        help=(
            "also query IPinfo Lite for supplementary metadata (needs IPINFO_TOKEN; sends the "
            "IP address to IPinfo; never changes the label)"
        ),
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help=(
            "also save this run to the SQLite audit history (path: NETCLASS_DB_PATH; stores the "
            "IP address and result locally; never stores tokens or raw responses)"
        ),
    )
    parser.add_argument(
        "--no-audit",
        action="store_true",
        help="do not write the audit history, even if NETCLASS_AUDIT_ENABLED is set",
    )
    args = parser.parse_args()
    if args.audit and args.no_audit:
        parser.error("--audit and --no-audit cannot be used together")

    try:
        observed_at = (
            datetime.fromisoformat(args.at) if args.at else datetime.now(timezone.utc)
        )
        observation = Observation(ip=args.ip, observed_at=observed_at)
    except (ValueError, ValidationError) as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return 2

    settings = load_settings()
    audit_on = args.audit or (settings.audit_enabled and not args.no_audit)
    if audit_on != settings.audit_enabled:
        settings = dataclasses.replace(settings, audit_enabled=audit_on)

    service = ClassificationService.from_settings(settings)
    audit_outcome = None
    if audit_on:
        audited = service.classify_and_record(
            observation, include_ripestat=args.context, include_ipinfo=args.ipinfo
        )
        outcome, audit_outcome = audited.result, audited.audit
    else:
        outcome = service.classify(
            observation, include_ripestat=args.context, include_ipinfo=args.ipinfo
        )
    output = {"result": outcome.classification.model_dump(mode="json")}
    if outcome.ripestat_context is not None:
        output["ripestat_context"] = outcome.ripestat_context.model_dump(mode="json")
    if outcome.ipinfo_metadata is not None:
        output["ipinfo_metadata"] = outcome.ipinfo_metadata.model_dump(mode="json")
    if args.evidence:
        output["evidence"] = [r.model_dump(mode="json") for r in outcome.evidence]
    if audit_outcome is not None:
        output["audit"] = audit_outcome.model_dump(mode="json")
    print(json.dumps(output, indent=2))
    if audit_outcome is not None and audit_outcome.status is not AuditStatus.SAVED:
        detail = audit_outcome.error or audit_outcome.note or "unknown reason"
        print(
            f"WARNING: the classification above is valid, but the audit record was NOT saved "
            f"({audit_outcome.status.value}): {detail}",
            file=sys.stderr,
        )
        return EXIT_AUDIT_NOT_SAVED
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
