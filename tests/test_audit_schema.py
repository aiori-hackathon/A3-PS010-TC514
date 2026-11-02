"""Schema, migrations and the refusal rules. Standard library only (no pydantic)."""
import os
import sqlite3
from datetime import timedelta

import pytest

from audit_support import T0, fake_result
from netclass.audit import AuditError, AuditStore
from netclass.audit import schema


def store_at(tmp_path, name="audit.sqlite3"):
    return AuditStore(tmp_path / name, clock=lambda: T0)


def connect(path):
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def tables(path):
    with connect(path) as conn:
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_constructing_a_store_touches_no_file(tmp_path):
    AuditStore(tmp_path / "sub" / "audit.sqlite3")
    assert list(tmp_path.iterdir()) == []


def test_first_record_creates_the_schema_and_marks_the_file(tmp_path):
    store = store_at(tmp_path)
    store.record(fake_result())
    path = tmp_path / "audit.sqlite3"
    assert {"schema_migrations", "classification_runs", "evidence_records", "context_metadata"} <= tables(path)
    with connect(path) as conn:
        assert conn.execute("PRAGMA application_id").fetchone()[0] == schema.APPLICATION_ID
        assert conn.execute("PRAGMA user_version").fetchone()[0] == schema.LATEST_VERSION == 1
        assert conn.execute("SELECT version, description FROM schema_migrations").fetchall() == [
            (1, "initial audit schema")
        ]


def test_reopening_is_idempotent_and_never_duplicates_migrations(tmp_path):
    store = store_at(tmp_path)
    for _ in range(3):
        store.record(fake_result())
    with connect(tmp_path / "audit.sqlite3") as conn:
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM classification_runs").fetchone()[0] == 3


def test_reading_a_missing_database_never_creates_it(tmp_path):
    store = store_at(tmp_path)
    with pytest.raises(AuditError, match="does not exist"):
        store.list_runs()
    with pytest.raises(AuditError):
        store.get_run(1)
    assert store.info() == {"path": str(tmp_path / "audit.sqlite3"), "exists": False}
    assert list(tmp_path.iterdir()) == []


def test_a_zero_byte_file_is_initialised_in_place_not_replaced(tmp_path):
    path = tmp_path / "audit.sqlite3"
    path.write_bytes(b"")
    store_at(tmp_path).record(fake_result())
    assert "classification_runs" in tables(path)


def test_a_newer_schema_is_refused_and_left_untouched(tmp_path):
    store = store_at(tmp_path)
    store.record(fake_result())
    path = tmp_path / "audit.sqlite3"
    with connect(path) as conn:
        conn.execute(f"PRAGMA user_version = {schema.LATEST_VERSION + 1}")
    before = path.read_bytes()
    with pytest.raises(AuditError, match="newer"):
        store.record(fake_result())
    with pytest.raises(AuditError, match="newer"):
        store.list_runs()
    assert path.read_bytes() == before


def test_a_foreign_sqlite_database_is_refused_and_left_untouched(tmp_path):
    path = tmp_path / "audit.sqlite3"
    with connect(path) as conn:
        conn.execute("CREATE TABLE other_app (x INTEGER)")
        conn.execute("INSERT INTO other_app VALUES (42)")
    before = path.read_bytes()
    store = store_at(tmp_path)
    with pytest.raises(AuditError, match="not a netclass audit database"):
        store.record(fake_result())
    with pytest.raises(AuditError):
        store.list_runs()
    assert path.read_bytes() == before


def test_a_file_that_is_not_sqlite_is_refused_and_left_untouched(tmp_path):
    path = tmp_path / "audit.sqlite3"
    path.write_bytes(b"this is my diary, not a database" * 20)
    before = path.read_bytes()
    with pytest.raises(AuditError):
        store_at(tmp_path).record(fake_result())
    assert path.read_bytes() == before


def test_a_directory_at_the_path_is_an_error_not_a_crash(tmp_path):
    (tmp_path / "audit.sqlite3").mkdir()
    with pytest.raises(AuditError, match="directory"):
        store_at(tmp_path).record(fake_result())


def test_check_constraints_reject_values_outside_the_policy(tmp_path):
    store_at(tmp_path).record(fake_result())
    with connect(tmp_path / "audit.sqlite3") as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO classification_runs (recorded_at, observed_at, ip, label, reason_code,"
                " additional_reason_codes, explanation, caveats, policy_version, service_version,"
                " ripestat_requested, ipinfo_requested, result_json)"
                " VALUES ('t','t','1.1.1.1','Probably a VPN','TOR_EXIT_MATCH','[]','e','[]','p','s',0,0,'{}')"
            )


def test_audit_rows_are_append_only(tmp_path):
    store_at(tmp_path).record(fake_result(ipinfo=True))
    with connect(tmp_path / "audit.sqlite3") as conn:
        for sql in (
            "UPDATE classification_runs SET label = 'Unknown'",
            "UPDATE evidence_records SET status = 'MATCH'",
            "UPDATE context_metadata SET status = 'X'",
        ):
            with pytest.raises(sqlite3.DatabaseError, match="append-only"):
                conn.execute(sql)


def test_deleting_a_run_cascades_to_evidence_and_metadata(tmp_path):
    store_at(tmp_path).record(fake_result(ripestat=True, ipinfo=True))
    with connect(tmp_path / "audit.sqlite3") as conn:
        conn.execute("DELETE FROM classification_runs")
        for table in ("evidence_records", "context_metadata"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_a_failed_migration_rolls_back_completely(tmp_path):
    path = tmp_path / "audit.sqlite3"
    path.write_bytes(b"")
    bad = schema.Migration(1, "broken", ("CREATE TABLE a (x)", "THIS IS NOT SQL"))
    original = schema.MIGRATIONS
    try:
        schema.MIGRATIONS = (bad,)
        with pytest.raises(AuditError):
            store_at(tmp_path).record(fake_result())
    finally:
        schema.MIGRATIONS = original
    assert tables(path) == set()
    with connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert conn.execute("PRAGMA application_id").fetchone()[0] == 0


def test_an_older_database_is_upgraded_by_a_write_but_not_by_a_read(tmp_path):
    store = store_at(tmp_path)
    store.record(fake_result())
    path = tmp_path / "audit.sqlite3"
    extra = schema.Migration(2, "add a note", ("CREATE TABLE note (id INTEGER PRIMARY KEY)",))
    original = schema.MIGRATIONS
    try:
        schema.MIGRATIONS = original + (extra,)
        schema.LATEST_VERSION = 2
        with pytest.raises(AuditError, match="older"):
            store.list_runs()
        assert "note" not in tables(path)
        store.record(fake_result())
        assert "note" in tables(path)
        with connect(path) as conn:
            assert conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall() == [(1,), (2,)]
        assert len(store.list_runs()) == 2  # earlier history survived the upgrade
    finally:
        schema.MIGRATIONS = original
        schema.LATEST_VERSION = original[-1].version


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_new_database_and_new_directory_are_private(tmp_path):
    store = AuditStore(tmp_path / "newdir" / "audit.sqlite3", clock=lambda: T0)
    store.record(fake_result())
    assert (tmp_path / "newdir" / "audit.sqlite3").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "newdir").stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_existing_permissions_are_reported_not_changed(tmp_path, caplog):
    path = tmp_path / "audit.sqlite3"
    path.write_bytes(b"")
    path.chmod(0o644)
    store_at(tmp_path).record(fake_result())
    assert path.stat().st_mode & 0o777 == 0o644
    assert "accessible to other users" in caplog.text
