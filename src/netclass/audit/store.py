"""The SQLite audit store. Standard library only; no pydantic import.

WHAT IT IS
    An append-only history of classification runs: the authoritative classification
    (label, reason codes, assessments), the evidence records the classifier used, and,
    in a SEPARATE table, any RIPEstat / IPinfo supplementary metadata.

WHAT IT IS NOT
    * Nothing in the classification path reads it. Stored rows can never influence a label.
    * It does not run unless the caller creates an ``AuditStore`` and calls ``record``.
      Constructing a store touches no file. ``ClassificationService.classify`` never writes.

SAFETY RULES (each pinned by tests/test_audit_*.py)
    * The database file is created lazily, on the first ``record``, exclusively
      (``O_EXCL``, mode 0600 where the OS supports it). An existing file is never
      truncated or replaced. A file that is not an audit database is refused untouched.
    * Reads never create or modify anything (read-only connection).
    * Every write is one explicit transaction; a failure rolls everything back and raises
      ``AuditError``. Nothing is half-saved and nothing is silently dropped.
    * All SQL values are bound parameters.
    * Retention is applied ONLY by an explicit ``purge`` call; opening a database never deletes.
    * Tokens, authorization headers and raw bodies are never stored (see ``privacy``).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

from ..address_policy import AddressCategory, assess_address
from . import schema
from .errors import AuditError
from .privacy import safe_error_message, scrub

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]
BUSY_TIMEOUT_SECONDS = 5.0
MAX_LIST_LIMIT = 1000


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    """One fixed text format for every stored timestamp, so text order == time order."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _norm_ts(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return iso_utc(datetime.fromisoformat(value))


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


@dataclass(frozen=True)
class SaveReceipt:
    run_id: int
    recorded_at: datetime


@dataclass(frozen=True)
class PurgeReport:
    """Outcome of ``purge`` / ``delete_ip``. ``deleted_runs`` is 0 for a dry run."""

    action: str
    cutoff: Optional[datetime]
    matched_runs: int
    deleted_runs: int
    dry_run: bool
    note: str


class AuditStore:
    def __init__(
        self,
        path: "str | os.PathLike[str]",
        *,
        clock: Clock = _utc_now,
        secrets: Iterable[Optional[str]] = (),
    ) -> None:
        """No file is touched here."""
        self._path = Path(path)
        self._clock = clock
        self._secrets = tuple(s for s in secrets if isinstance(s, str) and s)
        self._warned_permissions = False

    # ------------------------------------------------------------------ basics
    @property
    def path(self) -> Path:
        return self._path

    def __repr__(self) -> str:  # secrets are deliberately not shown
        return f"AuditStore(path={str(self._path)!r})"

    def safe_error(self, exc: BaseException) -> str:
        """A short redacted description of ``exc`` suitable for results and logs."""
        return safe_error_message(exc, self._secrets)

    # ------------------------------------------------------------------ connection handling
    def _create_file(self) -> None:
        parent = self._path.parent
        parent_existed = parent.exists()
        parent.mkdir(parents=True, exist_ok=True)
        if not parent_existed and os.name == "posix":
            try:
                os.chmod(parent, 0o700)
            except OSError:  # best effort
                pass
        try:
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return  # someone created it first: use it, never replace it
        os.close(fd)

    def _check_permissions(self) -> None:
        if os.name != "posix" or self._warned_permissions:
            return
        try:
            mode = stat.S_IMODE(os.stat(self._path).st_mode)
        except OSError:
            return
        if mode & 0o077:
            self._warned_permissions = True
            logger.warning(
                "audit database %s is accessible to other users (mode %o); "
                "consider restricting it (chmod 600)",
                self._path, mode,
            )

    def _connect(self, *, create: bool, writable: bool) -> sqlite3.Connection:
        if create and not self._path.exists():
            self._create_file()
        if not self._path.exists():
            raise AuditError(f"audit database does not exist: {self._path}")
        if self._path.is_dir():
            raise AuditError(f"audit database path is a directory: {self._path}")
        if writable:
            conn = sqlite3.connect(
                str(self._path), timeout=BUSY_TIMEOUT_SECONDS, isolation_level=None
            )
        else:
            uri = self._path.resolve().as_uri() + "?mode=ro"
            conn = sqlite3.connect(
                uri, uri=True, timeout=BUSY_TIMEOUT_SECONDS, isolation_level=None
            )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            if writable:
                conn.execute("PRAGMA secure_delete = ON")  # purged content is overwritten
            self._check_permissions()
            schema.prepare(conn, create=create, allow_migrate=writable, now=self._clock())
        except BaseException:
            conn.close()
            raise
        return conn

    @contextmanager
    def _session(self, *, create: bool = False, writable: bool = False) -> Iterator[sqlite3.Connection]:
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = self._connect(create=create, writable=writable)
            yield conn
        except AuditError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise AuditError(f"audit database error: {self.safe_error(exc)}") from exc
        finally:
            if conn is not None:
                conn.close()

    @staticmethod
    @contextmanager
    def _transaction(conn: sqlite3.Connection) -> Iterator[None]:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ writing
    def _prepare_record(self, result: Any) -> dict[str, Any]:
        """Turn a ServiceResult into plain, scrubbed rows. Pure; touches no file."""
        classification = result.classification.model_dump(mode="json")
        evidence = [e.model_dump(mode="json") for e in result.evidence]
        ripe = result.ripestat_context.model_dump(mode="json") if result.ripestat_context else None
        info = result.ipinfo_metadata.model_dump(mode="json") if result.ipinfo_metadata else None

        redactions = 0
        classification, n = scrub(classification, self._secrets)
        redactions += n
        clean_evidence = []
        for record in evidence:
            record, n = scrub(record, self._secrets)
            redactions += n
            clean_evidence.append(record)
        contexts = []
        for provider, dump in (("ripestat", ripe), ("ipinfo", info)):
            if dump is not None:
                dump, n = scrub(dump, self._secrets)
                redactions += n
                contexts.append((provider, dump))

        assessments = {
            (a["source_name"], a["kind"]): a for a in classification.get("evidence_assessments", [])
        }
        return {
            "classification": classification,
            "evidence": clean_evidence,
            "assessments": assessments,
            "contexts": contexts,
            "redactions": redactions,
            "service_version": str(result.service_version),
            "ripestat_requested": ripe is not None,
            "ipinfo_requested": info is not None,
        }

    def record(self, result: Any) -> SaveReceipt:
        """Save one ServiceResult. Returns a receipt only after the transaction committed.

        Raises ``AuditError`` on any failure; in that case nothing was saved.
        """
        try:
            prepared = self._prepare_record(result)
        except Exception as exc:
            raise AuditError(f"could not prepare the audit record: {self.safe_error(exc)}") from exc

        recorded_at = self._clock()
        c = prepared["classification"]
        with self._session(create=True, writable=True) as conn:
            with self._transaction(conn):
                cursor = conn.execute(
                    "INSERT INTO classification_runs (recorded_at, observed_at, ip, label, "
                    "reason_code, additional_reason_codes, explanation, caveats, policy_version, "
                    "service_version, ripestat_requested, ipinfo_requested, redaction_count, "
                    "result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        iso_utc(recorded_at),
                        _norm_ts(c["observed_at"]),
                        c["ip"],
                        c["label"],
                        c["reason_code"],
                        _dumps(c.get("additional_reason_codes", [])),
                        c["explanation"],
                        _dumps(c.get("caveats", [])),
                        c["policy_version"],
                        prepared["service_version"],
                        int(prepared["ripestat_requested"]),
                        int(prepared["ipinfo_requested"]),
                        prepared["redactions"],
                        _dumps(c),
                    ),
                )
                run_id = int(cursor.lastrowid)
                for position, e in enumerate(prepared["evidence"]):
                    a = prepared["assessments"].get((e["source_name"], e["kind"]))
                    conn.execute(
                        "INSERT INTO evidence_records (run_id, position, source_name, "
                        "source_endpoint, kind, status, retrieved_at, source_timestamp, "
                        "valid_from, valid_to, snapshot_sha256, error, limitations, "
                        "metadata_json, applicability, assessment_note) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            run_id,
                            position,
                            e["source_name"],
                            e["source_endpoint"],
                            e["kind"],
                            e["status"],
                            _norm_ts(e["retrieved_at"]),
                            _norm_ts(e.get("source_timestamp")),
                            _norm_ts(e.get("valid_from")),
                            _norm_ts(e.get("valid_to")),
                            e.get("snapshot_sha256"),
                            e.get("error"),
                            _dumps(e.get("limitations", [])),
                            _dumps(e.get("metadata", {})),
                            a["applicability"] if a else None,
                            a["note"] if a else None,
                        ),
                    )
                for provider, dump in prepared["contexts"]:
                    conn.execute(
                        "INSERT INTO context_metadata (run_id, provider, status, requested_at, "
                        "payload_json) VALUES (?, ?, ?, ?, ?)",
                        (run_id, provider, str(dump["status"]), _norm_ts(dump["requested_at"]), _dumps(dump)),
                    )
        return SaveReceipt(run_id=run_id, recorded_at=recorded_at)

    # ------------------------------------------------------------------ reading
    @staticmethod
    def _normalise_ip(ip: str) -> str:
        assessment = assess_address(ip)
        if assessment.category is AddressCategory.INVALID or assessment.normalized is None:
            raise ValueError(f"not a valid IP address: {ip!r}")
        return assessment.normalized

    @staticmethod
    def _filters(
        ip: Optional[str], label: Optional[str], since: Optional[datetime], until: Optional[datetime]
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if ip is not None:
            clauses.append("ip = ?")
            params.append(AuditStore._normalise_ip(ip))
        if label is not None:
            if label not in schema.LABELS:
                raise ValueError(f"unknown label {label!r}; expected one of {schema.LABELS}")
            clauses.append("label = ?")
            params.append(label)
        if since is not None:
            clauses.append("recorded_at >= ?")
            params.append(iso_utc(since))
        if until is not None:
            clauses.append("recorded_at < ?")
            params.append(iso_utc(until))
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "run_id": row["run_id"],
            "recorded_at": row["recorded_at"],
            "observed_at": row["observed_at"],
            "ip": row["ip"],
            "label": row["label"],
            "reason_code": row["reason_code"],
            "additional_reason_codes": json.loads(row["additional_reason_codes"]),
            "explanation": row["explanation"],
            "caveats": json.loads(row["caveats"]),
            "policy_version": row["policy_version"],
            "service_version": row["service_version"],
            "ripestat_requested": bool(row["ripestat_requested"]),
            "ipinfo_requested": bool(row["ipinfo_requested"]),
            "redaction_count": row["redaction_count"],
        }

    def _full(self, conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        doc = self._summary(row)
        doc["result"] = json.loads(row["result_json"])
        doc["evidence"] = [
            {
                "position": e["position"],
                "source_name": e["source_name"],
                "source_endpoint": e["source_endpoint"],
                "kind": e["kind"],
                "status": e["status"],
                "retrieved_at": e["retrieved_at"],
                "source_timestamp": e["source_timestamp"],
                "valid_from": e["valid_from"],
                "valid_to": e["valid_to"],
                "snapshot_sha256": e["snapshot_sha256"],
                "error": e["error"],
                "limitations": json.loads(e["limitations"]),
                "metadata": json.loads(e["metadata_json"]),
                "applicability": e["applicability"],
                "assessment_note": e["assessment_note"],
            }
            for e in conn.execute(
                "SELECT * FROM evidence_records WHERE run_id = ? ORDER BY position",
                (row["run_id"],),
            )
        ]
        doc["context_metadata"] = [
            {
                "provider": m["provider"],
                "status": m["status"],
                "requested_at": m["requested_at"],
                "payload": json.loads(m["payload_json"]),
            }
            for m in conn.execute(
                "SELECT * FROM context_metadata WHERE run_id = ? ORDER BY provider",
                (row["run_id"],),
            )
        ]
        return doc

    def list_runs(
        self,
        *,
        ip: Optional[str] = None,
        label: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Newest first. ``since``/``until`` filter on ``recorded_at`` (when it was saved)."""
        if not 1 <= limit <= MAX_LIST_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        if offset < 0:
            raise ValueError("offset must not be negative")
        where, params = self._filters(ip, label, since, until)
        with self._session() as conn:
            rows = conn.execute(
                f"SELECT * FROM classification_runs{where} ORDER BY run_id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
            return [self._summary(r) for r in rows]

    def get_run(self, run_id: int) -> Optional[dict[str, Any]]:
        with self._session() as conn:
            row = conn.execute(
                "SELECT * FROM classification_runs WHERE run_id = ?", (int(run_id),)
            ).fetchone()
            return self._full(conn, row) if row is not None else None

    def export_runs(
        self,
        *,
        ip: Optional[str] = None,
        label: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        """Full records (oldest first) for the filter."""
        where, params = self._filters(ip, label, since, until)
        with self._session() as conn:
            rows = conn.execute(
                f"SELECT * FROM classification_runs{where} ORDER BY run_id ASC", params
            ).fetchall()
            return [self._full(conn, r) for r in rows]

    def info(self) -> dict[str, Any]:
        """Facts about the database. Never creates it."""
        if not self._path.exists():
            return {"path": str(self._path), "exists": False}
        with self._session() as conn:
            count, oldest, newest = conn.execute(
                "SELECT COUNT(*), MIN(recorded_at), MAX(recorded_at) FROM classification_runs"
            ).fetchone()
            return {
                "path": str(self._path),
                "exists": True,
                "schema_version": int(conn.execute("PRAGMA user_version").fetchone()[0]),
                "runs": int(count),
                "oldest_recorded_at": oldest,
                "newest_recorded_at": newest,
            }

    # ------------------------------------------------------------------ deleting (explicit only)
    def _delete_where(
        self, action: str, where: str, params: list[Any], cutoff: Optional[datetime],
        *, dry_run: bool, vacuum: bool, empty_note: str,
    ) -> PurgeReport:
        if not self._path.exists():
            return PurgeReport(action, cutoff, 0, 0, dry_run, "no audit database exists; nothing to do")
        count_sql = f"SELECT COUNT(*) FROM classification_runs{where}"
        deleted = 0
        if dry_run:
            # Read-only connection: a dry run can never modify (or even migrate) the file.
            with self._session() as conn:
                matched = int(conn.execute(count_sql, params).fetchone()[0])
        else:
            with self._session(writable=True) as conn:
                with self._transaction(conn):
                    matched = int(conn.execute(count_sql, params).fetchone()[0])
                    if matched:
                        conn.execute(f"DELETE FROM classification_runs{where}", params)
                        deleted = matched  # evidence/context rows go too (ON DELETE CASCADE)
                if deleted and vacuum:
                    conn.execute("VACUUM")
        if not matched:
            note = empty_note
        elif dry_run:
            note = "dry run: nothing was deleted"
        else:
            note = f"deleted {deleted} run(s) with their evidence and metadata"
        return PurgeReport(action, cutoff, matched, deleted, dry_run, note)

    def purge(
        self,
        retention_days: int,
        *,
        now: Optional[datetime] = None,
        dry_run: bool = False,
        vacuum: bool = False,
    ) -> PurgeReport:
        """Delete runs SAVED more than ``retention_days`` days ago. Only runs when called.

        ``retention_days == 0`` means "keep indefinitely": nothing is deleted.
        """
        if retention_days < 0:
            raise ValueError("retention_days must not be negative")
        if retention_days == 0:
            return PurgeReport(
                "purge", None, 0, 0, dry_run,
                "retention is 0 (keep indefinitely); nothing was deleted",
            )
        cutoff = (now or self._clock()) - timedelta(days=retention_days)
        return self._delete_where(
            "purge", " WHERE recorded_at < ?", [iso_utc(cutoff)], cutoff,
            dry_run=dry_run, vacuum=vacuum,
            empty_note=f"no runs older than {retention_days} day(s)",
        )

    def delete_ip(self, ip: str, *, dry_run: bool = True, vacuum: bool = False) -> PurgeReport:
        """Erase every run for one address (e.g. on request). Dry run unless told otherwise."""
        normalised = self._normalise_ip(ip)
        return self._delete_where(
            "delete-ip", " WHERE ip = ?", [normalised], None,
            dry_run=dry_run, vacuum=vacuum, empty_note="no runs recorded for that address",
        )
