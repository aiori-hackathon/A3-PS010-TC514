r"""Inspect and maintain the SQLite audit history (Stage 5). Nothing here runs automatically.

Run from the project root:
    python scripts\audit_history.py info
    python scripts\audit_history.py list [--ip IP] [--label LABEL] [--since T] [--until T] [--limit N]
    python scripts\audit_history.py show RUN_ID
    python scripts\audit_history.py export [--ip IP] [--label LABEL] [--since T] [--until T] [--output FILE]
    python scripts\audit_history.py purge [--days N] [--yes] [--vacuum]
    python scripts\audit_history.py delete-ip IP [--yes] [--vacuum]

Retention: NETCLASS_AUDIT_RETENTION_DAYS (default 90; 0 = keep indefinitely). It is applied ONLY
by `purge`, and `purge` / `delete-ip` are dry runs unless you pass --yes. Times are ISO 8601 with
a UTC offset and filter on when a record was SAVED. `--db PATH` overrides NETCLASS_DB_PATH.

Exit codes: 0 ok, 1 audit database problem, 2 invalid arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netclass.audit import AuditError, AuditStore  # noqa: E402
from netclass.config import load_settings  # noqa: E402


def _when(text: str) -> datetime:
    value = datetime.fromisoformat(text)
    if value.tzinfo is None or value.utcoffset() is None:
        raise argparse.ArgumentTypeError("time must include a UTC offset, e.g. 2026-10-01T00:00:00+00:00")
    return value


def _days(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("--days must be a whole number") from None
    if value < 1:
        raise argparse.ArgumentTypeError("--days must be at least 1 (0 would mean keep everything)")
    return value


def _filters(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--ip")
    sub.add_argument("--label")
    sub.add_argument("--since", type=_when, help="saved at or after this time")
    sub.add_argument("--until", type=_when, help="saved before this time")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", help="audit database path (default: NETCLASS_DB_PATH)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("info", help="database facts and the configured retention")
    lst = commands.add_parser("list", help="list runs, newest first")
    _filters(lst)
    lst.add_argument("--limit", type=int, default=50)
    lst.add_argument("--offset", type=int, default=0)
    show = commands.add_parser("show", help="one run with its evidence and metadata")
    show.add_argument("run_id", type=int)
    export = commands.add_parser("export", help="full records as JSON (never overwrites a file)")
    _filters(export)
    export.add_argument("--output", help="write to this NEW file instead of stdout")
    purge = commands.add_parser("purge", help="delete runs older than the retention period")
    purge.add_argument("--days", type=_days, help="override NETCLASS_AUDIT_RETENTION_DAYS")
    purge.add_argument("--yes", action="store_true", help="actually delete (default: dry run)")
    purge.add_argument("--vacuum", action="store_true", help="compact the file afterwards")
    erase = commands.add_parser("delete-ip", help="erase every run for one address")
    erase.add_argument("ip")
    erase.add_argument("--yes", action="store_true", help="actually delete (default: dry run)")
    erase.add_argument("--vacuum", action="store_true", help="compact the file afterwards")
    return parser


def _emit(doc) -> None:
    print(json.dumps(doc, indent=2, ensure_ascii=False))


def _write_new_file(path: str, doc) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # refuses to overwrite
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def _report(report) -> dict:
    return {
        "action": report.action,
        "dry_run": report.dry_run,
        "cutoff": report.cutoff.isoformat() if report.cutoff else None,
        "matched_runs": report.matched_runs,
        "deleted_runs": report.deleted_runs,
        "note": report.note,
    }


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    settings = load_settings()
    store = AuditStore(args.db or settings.db_path)
    try:
        if args.command == "info":
            info = store.info()
            info["audit_enabled_setting"] = settings.audit_enabled
            info["retention_days_setting"] = settings.audit_retention_days
            info["retention_note"] = (
                "keep indefinitely (0)" if settings.audit_keeps_forever
                else "applied only when you run `purge --yes`"
            )
            _emit(info)
        elif args.command == "list":
            _emit(store.list_runs(
                ip=args.ip, label=args.label, since=args.since, until=args.until,
                limit=args.limit, offset=args.offset,
            ))
        elif args.command == "show":
            run = store.get_run(args.run_id)
            if run is None:
                print(f"No run with id {args.run_id}", file=sys.stderr)
                return 1
            _emit(run)
        elif args.command == "export":
            records = store.export_runs(
                ip=args.ip, label=args.label, since=args.since, until=args.until
            )
            if args.output:
                _write_new_file(args.output, records)
                print(f"Wrote {len(records)} record(s) to {args.output}", file=sys.stderr)
            else:
                _emit(records)
        elif args.command == "purge":
            days = args.days if args.days is not None else settings.audit_retention_days
            report = store.purge(days, dry_run=not args.yes, vacuum=args.vacuum)
            _emit(_report(report))
            if not args.yes and report.matched_runs:
                print("Dry run. Re-run with --yes to delete these runs.", file=sys.stderr)
        elif args.command == "delete-ip":
            report = store.delete_ip(args.ip, dry_run=not args.yes, vacuum=args.vacuum)
            _emit(_report(report))
            if not args.yes and report.matched_runs:
                print("Dry run. Re-run with --yes to delete these runs.", file=sys.stderr)
    except AuditError as exc:
        print(f"Audit database problem: {exc}", file=sys.stderr)
        return 1
    except FileExistsError:
        print(f"Refusing to overwrite existing file: {args.output}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
