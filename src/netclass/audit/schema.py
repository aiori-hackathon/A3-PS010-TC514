"""SQLite schema and versioned migrations for the audit history (pydantic-free).

VERSIONING
    * ``PRAGMA application_id`` marks a file as a netclass audit database.
    * ``PRAGMA user_version`` and the ``schema_migrations`` table hold the schema version.
    * Migrations are ordered and applied one per transaction. A database NEWER than this
      code, a database of another application, and a file that is not SQLite at all are
      REFUSED and left untouched.

The CHECK lists below are deliberately literal copies of the labels, reason codes
and enum values: a schema version is a frozen record, and a test pins that these literals
equal the live enums, so adding a label later forces a new migration instead of silently
passing or silently failing inserts.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from .errors import AuditError

APPLICATION_ID = 0x4E434155  # "NCAU"

LABELS = ("Known Tor exit", "Known hosted VPN/proxy endpoint", "Unknown")
REASON_CODES = (
    "TOR_EXIT_MATCH",
    "VPN_PROXY_ENDPOINT_MATCH",
    "UNKNOWN_EXCLUDED_ADDRESS",
    "UNKNOWN_CONFLICTING_EVIDENCE",
    "UNKNOWN_SOURCE_UNAVAILABLE",
    "UNKNOWN_STALE_EVIDENCE",
    "UNKNOWN_PROVIDER_NOT_CONFIGURED",
    "UNKNOWN_HOSTING_ONLY",
    "UNKNOWN_NO_QUALIFYING_MATCH",
)
EVIDENCE_KINDS = ("TOR_EXIT", "VPN_PROXY_ENDPOINT")
EVIDENCE_STATUSES = ("MATCH", "NO_MATCH", "SOURCE_UNAVAILABLE", "NOT_CONFIGURED")
APPLICABILITIES = ("APPLICABLE", "STALE", "NOT_EVALUATED")
PROVIDERS = ("ripestat", "ipinfo")

APPEND_ONLY_MESSAGE = "audit records are append-only"
_AUDIT_TABLES = ("classification_runs", "evidence_records", "context_metadata")


def _in(values: tuple[str, ...]) -> str:
    return "(" + ", ".join("'" + v.replace("'", "''") + "'" for v in values) + ")"


@dataclass(frozen=True)
class Migration:
    version: int
    description: str
    statements: tuple[str, ...]


_V1: tuple[str, ...] = (
    """CREATE TABLE schema_migrations (
        version     INTEGER PRIMARY KEY,
        description TEXT NOT NULL,
        applied_at  TEXT NOT NULL
    )""",
    # One row per classification run. The classification columns mirror ClassificationResult.
    f"""CREATE TABLE classification_runs (
        run_id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        recorded_at             TEXT NOT NULL,
        observed_at             TEXT NOT NULL,
        ip                      TEXT NOT NULL,
        label                   TEXT NOT NULL CHECK (label IN {_in(LABELS)}),
        reason_code             TEXT NOT NULL CHECK (reason_code IN {_in(REASON_CODES)}),
        additional_reason_codes TEXT NOT NULL,
        explanation             TEXT NOT NULL,
        caveats                 TEXT NOT NULL,
        policy_version          TEXT NOT NULL,
        service_version         TEXT NOT NULL,
        ripestat_requested      INTEGER NOT NULL CHECK (ripestat_requested IN (0, 1)),
        ipinfo_requested        INTEGER NOT NULL CHECK (ipinfo_requested IN (0, 1)),
        redaction_count         INTEGER NOT NULL DEFAULT 0 CHECK (redaction_count >= 0),
        result_json             TEXT NOT NULL
    )""",
    # Classification EVIDENCE only (the sources the classifier used). No IPinfo/RIPEstat here.
    f"""CREATE TABLE evidence_records (
        evidence_id     INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id          INTEGER NOT NULL REFERENCES classification_runs(run_id) ON DELETE CASCADE,
        position        INTEGER NOT NULL CHECK (position >= 0),
        source_name     TEXT NOT NULL,
        source_endpoint TEXT NOT NULL,
        kind            TEXT NOT NULL CHECK (kind IN {_in(EVIDENCE_KINDS)}),
        status          TEXT NOT NULL CHECK (status IN {_in(EVIDENCE_STATUSES)}),
        retrieved_at    TEXT NOT NULL,
        source_timestamp TEXT,
        valid_from      TEXT,
        valid_to        TEXT,
        snapshot_sha256 TEXT,
        error           TEXT,
        limitations     TEXT NOT NULL,
        metadata_json   TEXT NOT NULL,
        applicability   TEXT CHECK (applicability IS NULL OR applicability IN {_in(APPLICABILITIES)}),
        assessment_note TEXT,
        UNIQUE (run_id, position)
    )""",
    # Supplementary RIPEstat / IPinfo metadata ONLY. Never evidence, never read by the classifier.
    f"""CREATE TABLE context_metadata (
        context_id   INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id       INTEGER NOT NULL REFERENCES classification_runs(run_id) ON DELETE CASCADE,
        provider     TEXT NOT NULL CHECK (provider IN {_in(PROVIDERS)}),
        status       TEXT NOT NULL,
        requested_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        UNIQUE (run_id, provider)
    )""",
    "CREATE INDEX idx_runs_ip_observed ON classification_runs (ip, observed_at)",
    "CREATE INDEX idx_runs_recorded ON classification_runs (recorded_at)",
    "CREATE INDEX idx_runs_label ON classification_runs (label)",
    "CREATE INDEX idx_evidence_run ON evidence_records (run_id)",
    "CREATE INDEX idx_context_run ON context_metadata (run_id)",
    # Audit rows are history: they are inserted and deleted (purge / erase), never edited.
    *(
        f"CREATE TRIGGER {table}_append_only BEFORE UPDATE ON {table} "
        f"BEGIN SELECT RAISE(ABORT, '{APPEND_ONLY_MESSAGE}'); END"
        for table in _AUDIT_TABLES
    ),
)

MIGRATIONS: tuple[Migration, ...] = (Migration(1, "initial audit schema", _V1),)
LATEST_VERSION = MIGRATIONS[-1].version


def read_state(conn: sqlite3.Connection) -> tuple[int, int, int]:
    """(application_id, user_version, number of user tables)."""
    app_id = conn.execute("PRAGMA application_id").fetchone()[0]
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    tables = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchone()[0]
    return int(app_id), int(version), int(tables)


def _iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).isoformat(timespec="microseconds")


def apply_migrations(conn: sqlite3.Connection, now: datetime) -> None:
    """Initialise an empty database or upgrade an older audit database, atomically.

    The state is re-read INSIDE the write lock so two processes cannot both initialise.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        app_id, version, tables = read_state(conn)
        if app_id == 0 and (version != 0 or tables != 0):
            raise AuditError("refusing to modify a SQLite file that is not a netclass audit database")
        if app_id not in (0, APPLICATION_ID):
            raise AuditError("refusing to modify a SQLite file that belongs to another application")
        if version > LATEST_VERSION:
            raise AuditError(
                f"audit database schema version {version} is newer than this program "
                f"supports ({LATEST_VERSION}); refusing to modify it"
            )
        for migration in MIGRATIONS:
            if migration.version <= version:
                continue
            for statement in migration.statements:
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                (migration.version, migration.description, _iso(now)),
            )
            conn.execute(f"PRAGMA user_version = {int(migration.version)}")
        conn.execute(f"PRAGMA application_id = {int(APPLICATION_ID)}")
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def prepare(
    conn: sqlite3.Connection, *, create: bool, allow_migrate: bool, now: datetime
) -> None:
    """Check that ``conn`` is an audit database of a usable version (migrating if allowed)."""
    app_id, version, tables = read_state(conn)
    if app_id == APPLICATION_ID:
        if version > LATEST_VERSION:
            raise AuditError(
                f"audit database schema version {version} is newer than this program "
                f"supports ({LATEST_VERSION}); refusing to use it"
            )
        if version < LATEST_VERSION:
            if not allow_migrate:
                raise AuditError(
                    f"audit database schema version {version} is older than {LATEST_VERSION}; "
                    "it is upgraded the next time a record is written"
                )
            apply_migrations(conn, now)
        return
    if app_id == 0 and version == 0 and tables == 0:
        if not create:
            raise AuditError("the audit database file is empty and has not been initialised")
        apply_migrations(conn, now)
        return
    raise AuditError("the file is not a netclass audit database; refusing to use or modify it")
