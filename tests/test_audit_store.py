"""AuditStore behaviour on fake results: round trip, separation, atomicity, retention.

Standard library only; the same store is exercised with the real models in
test_audit_service_integration.py.
"""
import json
import sqlite3
from datetime import timedelta

import pytest

from audit_support import (
    FAKE_TOKEN,
    IPINFO_MARKER,
    RIPESTAT_MARKER,
    T0,
    evidence_dump,
    fake_result,
)
from netclass.audit import AuditError, AuditStore
from netclass.audit import schema


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


def make(tmp_path, **kw):
    clock = Clock()
    return AuditStore(tmp_path / "audit.sqlite3", clock=clock, **kw), clock


def rows(path, sql):
    with sqlite3.connect(str(path)) as conn:
        return conn.execute(sql).fetchall()


# ------------------------------------------------------------------ round trip
def test_record_round_trips_label_reason_and_evidence_exactly(tmp_path):
    store, _ = make(tmp_path)
    fake = fake_result(
        "185.220.101.45", label="Known Tor exit", reason="TOR_EXIT_MATCH",
        evidence=[evidence_dump("TOR_EXIT", "MATCH"), evidence_dump("VPN_PROXY_ENDPOINT", "NO_MATCH")],
    )
    receipt = store.record(fake)
    assert receipt.run_id == 1 and receipt.recorded_at == T0
    run = store.get_run(1)
    c = fake.classification.model_dump()
    assert (run["ip"], run["label"], run["reason_code"]) == ("185.220.101.45", "Known Tor exit", "TOR_EXIT_MATCH")
    assert run["result"] == c
    assert run["policy_version"] == "ps010-policy-1" and run["service_version"] == "ps010-service-1"
    assert run["observed_at"] == "2026-10-28T12:00:00.000000+00:00"
    assert run["recorded_at"] == "2026-10-28T12:00:00.000000+00:00"
    assert [(e["kind"], e["status"], e["applicability"]) for e in run["evidence"]] == [
        ("TOR_EXIT", "MATCH", "APPLICABLE"), ("VPN_PROXY_ENDPOINT", "NO_MATCH", "APPLICABLE"),
    ]
    assert run["evidence"][0]["metadata"] == fake.evidence[0].model_dump()["metadata"]
    assert run["evidence"][0]["assessment_note"]
    assert run["context_metadata"] == [] and run["redaction_count"] == 0


def test_excluded_address_with_no_evidence_is_recorded(tmp_path):
    store, _ = make(tmp_path)
    store.record(fake_result("10.0.0.1", reason="UNKNOWN_EXCLUDED_ADDRESS", evidence=[]))
    run = store.get_run(1)
    assert run["reason_code"] == "UNKNOWN_EXCLUDED_ADDRESS" and run["evidence"] == []


def test_hostile_text_is_stored_verbatim_and_never_executed(tmp_path):
    store, _ = make(tmp_path)
    nasty = "O'Brien'); DROP TABLE classification_runs;--"
    store.record(fake_result(explanation=nasty))
    store.record(fake_result())
    assert store.get_run(1)["explanation"] == nasty
    assert len(store.list_runs()) == 2


# ------------------------------------------------------------------ separation
def test_supplementary_metadata_lives_only_in_its_own_table(tmp_path):
    store, _ = make(tmp_path)
    store.record(fake_result(ripestat=True, ipinfo=True))
    path = tmp_path / "audit.sqlite3"
    run = store.get_run(1)
    assert run["ripestat_requested"] and run["ipinfo_requested"]
    assert {m["provider"] for m in run["context_metadata"]} == {"ripestat", "ipinfo"}
    ipinfo = [m for m in run["context_metadata"] if m["provider"] == "ipinfo"][0]
    assert ipinfo["payload"]["as_name"] == IPINFO_MARKER and ipinfo["status"] == "AVAILABLE"
    # no marker in the evidence table or in the classification columns/result
    evidence_text = json.dumps(rows(path, "SELECT * FROM evidence_records"))
    run_text = json.dumps(rows(path, "SELECT * FROM classification_runs"))
    for marker in (IPINFO_MARKER, RIPESTAT_MARKER):
        assert marker not in evidence_text and marker not in run_text


def test_not_requested_metadata_leaves_no_context_rows(tmp_path):
    store, _ = make(tmp_path)
    store.record(fake_result())
    run = store.get_run(1)
    assert run["context_metadata"] == [] and not run["ripestat_requested"] and not run["ipinfo_requested"]


def test_failed_lookup_status_is_stored_as_status_not_as_evidence(tmp_path):
    store, _ = make(tmp_path)
    store.record(fake_result(ipinfo=True, ipinfo_over={"status": "UNAVAILABLE", "as_name": None}))
    run = store.get_run(1)
    assert run["context_metadata"][0]["status"] == "UNAVAILABLE"
    assert all(e["kind"] in ("TOR_EXIT", "VPN_PROXY_ENDPOINT") for e in run["evidence"])


# ------------------------------------------------------------------ privacy
def test_secrets_and_raw_bodies_never_reach_the_file(tmp_path):
    store, _ = make(tmp_path, secrets=[FAKE_TOKEN])
    leaky_evidence = evidence_dump(
        "TOR_EXIT",
        error=f"HTTP 401 for https://x.invalid/?token={FAKE_TOKEN}",
        metadata={
            "http_headers": {"Authorization": f"Bearer {FAKE_TOKEN}", "Set-Cookie": "sid=SESSIONVALUE"},
            "response_body": "RAW-BODY-CONTENT-1234",
        },
    )
    store.record(
        fake_result(
            evidence=[leaky_evidence], ipinfo=True,
            ipinfo_over={"note": f"debug {FAKE_TOKEN}", "warnings": ["Bearer ANOTHERSECRET"]},
        )
    )
    raw = (tmp_path / "audit.sqlite3").read_bytes()
    for forbidden in (FAKE_TOKEN, "SESSIONVALUE", "RAW-BODY-CONTENT-1234", "ANOTHERSECRET"):
        assert forbidden.encode() not in raw, forbidden
    run = store.get_run(1)
    assert run["redaction_count"] >= 5
    assert "[REDACTED]" in json.dumps(run["evidence"])


def test_repr_and_error_messages_do_not_expose_secrets(tmp_path):
    store, _ = make(tmp_path, secrets=[FAKE_TOKEN])
    assert FAKE_TOKEN not in repr(store)
    message = store.safe_error(RuntimeError(f"failed with {FAKE_TOKEN}"))
    assert FAKE_TOKEN not in message and message.startswith("RuntimeError")


# ------------------------------------------------------------------ atomicity and failure
def test_a_failing_insert_rolls_back_every_table(tmp_path):
    store, _ = make(tmp_path)
    store.record(fake_result())  # a good run first
    bad = fake_result(evidence=[evidence_dump("TOR_EXIT"), evidence_dump("NOT_A_KIND")])
    with pytest.raises(AuditError):
        store.record(bad)
    path = tmp_path / "audit.sqlite3"
    assert rows(path, "SELECT COUNT(*) FROM classification_runs") == [(1,)]
    assert rows(path, "SELECT COUNT(*) FROM evidence_records") == [(2,)]


def test_an_unserialisable_result_raises_and_creates_no_database(tmp_path):
    store, _ = make(tmp_path)

    class Broken:
        classification = object()
        evidence = []
        ripestat_context = None
        ipinfo_metadata = None
        service_version = "x"

    with pytest.raises(AuditError, match="could not prepare"):
        store.record(Broken())
    assert list(tmp_path.iterdir()) == []


def test_unwritable_location_raises_audit_error_not_silence(tmp_path):
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    store = AuditStore(blocker / "audit.sqlite3", clock=Clock())
    with pytest.raises(AuditError):
        store.record(fake_result())


def test_record_never_replaces_an_existing_history(tmp_path):
    store, _ = make(tmp_path)
    store.record(fake_result("8.8.8.8"))
    again = AuditStore(tmp_path / "audit.sqlite3", clock=Clock())  # a fresh process, same file
    again.record(fake_result("1.1.1.1"))
    assert [r["ip"] for r in again.list_runs()] == ["1.1.1.1", "8.8.8.8"]


# ------------------------------------------------------------------ queries
def test_list_filters_order_and_limits(tmp_path):
    store, clock = make(tmp_path)
    store.record(fake_result("8.8.8.8"))
    clock.now = T0 + timedelta(days=1)
    store.record(fake_result("185.220.101.45", label="Known Tor exit", reason="TOR_EXIT_MATCH"))
    clock.now = T0 + timedelta(days=2)
    store.record(fake_result("2001:4860:4860:0:0:0:0:8888"))
    assert [r["run_id"] for r in store.list_runs()] == [3, 2, 1]
    assert [r["run_id"] for r in store.list_runs(ip="185.220.101.45")] == [2]
    assert [r["run_id"] for r in store.list_runs(label="Known Tor exit")] == [2]
    assert [r["run_id"] for r in store.list_runs(since=T0 + timedelta(days=1))] == [3, 2]
    assert [r["run_id"] for r in store.list_runs(until=T0 + timedelta(days=1))] == [1]
    assert [r["run_id"] for r in store.list_runs(limit=1, offset=1)] == [2]
    assert store.get_run(99) is None


def test_ip_filter_normalises_and_rejects_garbage(tmp_path):
    store, _ = make(tmp_path)
    store.record(fake_result("2001:4860:4860::8888"))
    assert len(store.list_runs(ip="2001:4860:4860:0:0:0:0:8888")) == 1
    with pytest.raises(ValueError):
        store.list_runs(ip="'; DROP TABLE classification_runs;--")
    with pytest.raises(ValueError):
        store.list_runs(label="not a label")
    with pytest.raises(ValueError):
        store.list_runs(limit=0)


def test_export_returns_full_records_oldest_first(tmp_path):
    store, _ = make(tmp_path)
    store.record(fake_result("8.8.8.8", ipinfo=True))
    store.record(fake_result("1.1.1.1"))
    exported = store.export_runs()
    assert [r["run_id"] for r in exported] == [1, 2]
    assert exported[0]["context_metadata"][0]["provider"] == "ipinfo" and exported[0]["evidence"]
    json.dumps(exported)  # JSON-serialisable


def test_info_reports_counts_without_modifying(tmp_path):
    store, clock = make(tmp_path)
    store.record(fake_result())
    clock.now = T0 + timedelta(days=3)
    store.record(fake_result())
    info = store.info()
    assert info["exists"] and info["runs"] == 2 and info["schema_version"] == 1
    assert info["oldest_recorded_at"] < info["newest_recorded_at"]


# ------------------------------------------------------------------ retention (explicit only)
def seed_ages(tmp_path, days):
    store, clock = make(tmp_path)
    for age in days:
        clock.now = T0 - timedelta(days=age)
        store.record(fake_result(ripestat=True, ipinfo=True))
    clock.now = T0
    return store


def test_opening_listing_and_recording_never_purge(tmp_path):
    store = seed_ages(tmp_path, [1000, 500, 100])
    store.list_runs()
    store.info()
    store.record(fake_result())
    AuditStore(tmp_path / "audit.sqlite3", clock=Clock()).list_runs()
    assert store.info()["runs"] == 4  # nothing old was removed on its own


def test_purge_dry_run_deletes_nothing_and_does_not_open_for_writing(tmp_path):
    store = seed_ages(tmp_path, [200, 100, 10])
    path = tmp_path / "audit.sqlite3"
    before = path.read_bytes()
    report = store.purge(90, now=T0, dry_run=True)
    assert (report.matched_runs, report.deleted_runs, report.dry_run) == (2, 0, True)
    assert path.read_bytes() == before


def test_purge_deletes_only_older_runs_with_their_children(tmp_path):
    store = seed_ages(tmp_path, [200, 100, 10])
    report = store.purge(90, now=T0)
    assert (report.matched_runs, report.deleted_runs) == (2, 2)
    assert [r["run_id"] for r in store.list_runs()] == [3]
    path = tmp_path / "audit.sqlite3"
    assert rows(path, "SELECT COUNT(DISTINCT run_id) FROM evidence_records") == [(1,)]
    assert rows(path, "SELECT COUNT(DISTINCT run_id) FROM context_metadata") == [(1,)]


def test_purge_cutoff_is_exclusive_and_exact(tmp_path):
    store = seed_ages(tmp_path, [90, 91])
    report = store.purge(90, now=T0)
    assert report.deleted_runs == 1  # 91 days old goes; exactly 90 days old stays
    assert [r["run_id"] for r in store.list_runs()] == [1]


def test_retention_zero_keeps_everything_and_says_so(tmp_path):
    store = seed_ages(tmp_path, [5000, 4000])
    report = store.purge(0, now=T0)
    assert report.deleted_runs == 0 and "indefinitely" in report.note
    assert store.info()["runs"] == 2


def test_purge_on_a_missing_database_does_nothing_and_creates_nothing(tmp_path):
    store, _ = make(tmp_path)
    report = store.purge(90, now=T0)
    assert report.matched_runs == 0 and list(tmp_path.iterdir()) == []


def test_purge_rejects_negative_retention(tmp_path):
    store, _ = make(tmp_path)
    with pytest.raises(ValueError):
        store.purge(-1)


def test_delete_ip_is_a_dry_run_by_default_and_erases_only_that_address(tmp_path):
    store, _ = make(tmp_path)
    store.record(fake_result("8.8.8.8", ipinfo=True))
    store.record(fake_result("8.8.8.8"))
    store.record(fake_result("1.1.1.1"))
    assert store.delete_ip("8.8.8.8").deleted_runs == 0
    assert store.info()["runs"] == 3
    report = store.delete_ip("8.8.8.8", dry_run=False)
    assert report.deleted_runs == 2
    assert [r["ip"] for r in store.list_runs()] == ["1.1.1.1"]
    with pytest.raises(ValueError):
        store.delete_ip("not-an-ip")


def test_vacuum_after_purge_keeps_remaining_history(tmp_path):
    store = seed_ages(tmp_path, [200, 1])
    store.purge(90, now=T0, vacuum=True)
    assert [r["run_id"] for r in store.list_runs()] == [2]


def test_secrets_inside_the_classification_part_are_scrubbed_too(tmp_path):
    store, _ = make(tmp_path, secrets=[FAKE_TOKEN])
    store.record(
        fake_result(
            explanation=f"lookup used {FAKE_TOKEN}",
            extra_classification={"caveats": [f"Authorization: Bearer {FAKE_TOKEN}"]},
        )
    )
    raw = (tmp_path / "audit.sqlite3").read_bytes()
    assert FAKE_TOKEN.encode() not in raw
    run = store.get_run(1)
    assert FAKE_TOKEN not in json.dumps(run) and run["redaction_count"] >= 2


def test_a_dry_run_cannot_even_migrate_the_database(tmp_path):
    store = seed_ages(tmp_path, [200, 1])
    path = tmp_path / "audit.sqlite3"
    extra = schema.Migration(2, "later change", ("CREATE TABLE later (id INTEGER PRIMARY KEY)",))
    original = schema.MIGRATIONS
    try:
        schema.MIGRATIONS = original + (extra,)
        schema.LATEST_VERSION = 2
        before = path.read_bytes()
        with pytest.raises(AuditError, match="older"):
            store.purge(90, now=T0, dry_run=True)
        with pytest.raises(AuditError, match="older"):
            store.delete_ip("8.8.8.8", dry_run=True)
        assert path.read_bytes() == before
    finally:
        schema.MIGRATIONS = original
        schema.LATEST_VERSION = original[-1].version
