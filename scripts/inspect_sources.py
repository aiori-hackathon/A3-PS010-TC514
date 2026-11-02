r"""Download all three sources and report formats, hashes, counts and overlaps.

Run from the project root:   python scripts\inspect_sources.py
Optional:                    python scripts\inspect_sources.py --json report.json

This is how you verify, on YOUR machine, that the live endpoints are reachable
and still have the format the parsers expect. Nothing is cached.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netclass.config import load_settings  # noqa: E402
from netclass.http_client import RequestsFetcher  # noqa: E402
from netclass.inspection import format_report, inspect_sources  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", metavar="PATH", help="also write the full report as JSON")
    args = parser.parse_args()

    settings = load_settings()
    fetcher = RequestsFetcher(
        timeout_seconds=settings.http_timeout_seconds, max_bytes=settings.max_download_bytes
    )
    report = inspect_sources(fetcher, max_source_age_seconds=settings.max_source_age_seconds)
    print(format_report(report))
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nFull report written to {args.json}")
    return 0 if all(f["status"] == "OK" for f in report["files"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
