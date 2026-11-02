"""Audit history through the real service and models (mocked HTTP only).

classify() never writes; classify_and_record() saves AFTER classifying and reports the outcome
explicitly; a failed save never changes or hides the classification; stored history is never read
by classification.
"""
import json

import pytest

from audit_support import fake_result
from factories import T0, obs
from fakes import FakeFetcher, MutableClock, ip_body
from ipinfo_support import TOKEN, lite, make as make_ipinfo, url_for
from netclass.audit import AuditStore
from netclass.config import Settings
from netclass.models import Label
from netclass.service import (
    AuditedResult,
    AuditOutcome,
    AuditStatus,
    ClassificationService,
    ServiceResult,
)
from ripestat_support import healthy as ripe_healthy
from ripestat_support import make as make_ripestat
from support import (
    AZ0_IP,
    CLEAN_IP,
    TOR_IP,
    TOR_URL,
    TOR_V6,
    VPN_IP,
    all_adapters,
    make_stack,
    standard_routes,
)

EXCLUDED_IP = "10.0.0.1"
CONFLICT_ROUTES = standard_routes(**{TOR_URL: ip_body([VPN_IP, TOR_IP])})
# The Stage 4 scenario set (tests/test_service_layer.py): every label and several reason codes.
SCENARIOS = [
    (TOR_IP, None),
    (VPN_IP, None),
    (AZ0_IP, None),
    (CLEAN_IP, None),
    (EXCLUDED_IP, None),
    (VPN_IP, CONFLICT_ROUTES),
    (TOR_V6, None),
]


def build(
    tmp_path, ip=CLEAN_IP, *, store="default", ipinfo_route=None, with_ripestat=False, name="w",
    routes=None,
):
    """A service over the fake world. ``store``: 'default' (a store in tmp_path),
    None (no audit), or an AuditStore instance."""
    stack = make_stack(tmp_path / name, routes)
    ipinfo, _, _ = make_ipinfo(
        {url_for(ip): ipinfo_route} if ipinfo_route is not None else {}, token=TOKEN
    )
    ripestat = None
    if with_ripestat:
        ripestat, ripe_fetcher, _ = make_ripestat()
        ripe_fetcher.routes.update(ripe_healthy(ripestat, ip=ip, holder="RIPE-HOLDER-NAME"))
    db = tmp_path / name / "audit.sqlite3"
    if store == "default":
        store = AuditStore(db, clock=stack.clock, secrets=[TOKEN])
    service = ClassificationService(
        Settings(), all_adapters(stack), ripestat=ripestat, ipinfo=ipinfo, audit=store, clock=stack.clock
    )
    return service, store, db


# --------------------------------------------------------------------------- classify() is untouched
def test_classify_never_writes_even_when_a_store_is_configured(tmp_path):
    service, store, db = build(tmp_path)
    service.classify(obs(CLEAN_IP))
    service.classify(obs(CLEAN_IP), include_ipinfo=True)
    assert not db.exists() and not list((tmp_path / "w").glob("*.sqlite3"))


def test_classify_returns_a_plain_service_result(tmp_path):
    service, _, _ = build(tmp_path)
    assert type(service.classify(obs(CLEAN_IP))) is ServiceResult


# --------------------------------------------------------------------------- saving
def test_classify_and_record_saves_exactly_what_it_returns(tmp_path):
    service, store, db = build(tmp_path, TOR_IP)
    out = service.classify_and_record(obs(TOR_IP))
    assert isinstance(out, AuditedResult) and out.audit.status is AuditStatus.SAVED
    assert out.audit.run_id == 1 and out.audit.recorded_at is not None and out.audit.error is None
    c = out.result.classification
    run = store.get_run(1)
    assert (run["label"], run["reason_code"]) == (c.label.value, c.reason_code.value) == (
        "Known Tor exit", "TOR_EXIT_MATCH",
    )
    assert run["result"] == c.model_dump(mode="json")
    assert [e["status"] for e in run["evidence"]] == [e.status.value for e in out.result.evidence]
    assert [e["source_name"] for e in run["evidence"]] == [e.source_name for e in out.result.evidence]
    assert run["policy_version"] == c.policy_version == "ps010-policy-1"


@pytest.mark.parametrize("ip,routes", SCENARIOS)
@pytest.mark.parametrize("ipinfo", [False, True])
def test_auditing_never_changes_the_classification(tmp_path, ip, routes, ipinfo):
    route = lite(ip) if ipinfo else None
    audited, _, _ = build(tmp_path, ip, ipinfo_route=route, name="a", routes=routes)
    plain, _, _ = build(tmp_path, ip, store=None, ipinfo_route=route, name="b", routes=routes)
    with_audit = audited.classify_and_record(obs(ip), include_ipinfo=ipinfo)
    without = plain.classify(obs(ip), include_ipinfo=ipinfo)
    assert with_audit.audit.status is AuditStatus.SAVED
    assert with_audit.result.model_dump(mode="json") == without.model_dump(mode="json")
    assert with_audit.result.classification.label is without.classification.label
    assert with_audit.result.classification.reason_code is without.classification.reason_code
    assert with_audit.result.evidence == without.evidence


def test_every_label_reaches_the_database_unchanged(tmp_path):
    seen = set()
    for ip in (TOR_IP, VPN_IP, CLEAN_IP, EXCLUDED_IP):
        service, store, _ = build(tmp_path, ip, name=f"w-{ip}")
        out = service.classify_and_record(obs(ip))
        row = store.get_run(out.audit.run_id)
        assert row["label"] == out.result.classification.label.value
        seen.add(row["label"])
    assert seen == {Label.KNOWN_TOR_EXIT.value, Label.KNOWN_VPN_PROXY.value, Label.UNKNOWN.value}


# --------------------------------------------------------------------------- separation and privacy
def test_ipinfo_and_ripestat_metadata_are_stored_apart_from_evidence(tmp_path):
    service, store, db = build(
        tmp_path, TOR_IP, ipinfo_route=lite(TOR_IP, as_name="IPINFO-ONLY-NET"), with_ripestat=True
    )
    out = service.classify_and_record(obs(TOR_IP), include_ripestat=True, include_ipinfo=True)
    assert out.audit.status is AuditStatus.SAVED
    run = store.get_run(1)
    assert run["ripestat_requested"] and run["ipinfo_requested"]
    by_provider = {m["provider"]: m for m in run["context_metadata"]}
    assert set(by_provider) == {"ripestat", "ipinfo"}
    assert by_provider["ipinfo"]["status"] == "AVAILABLE"
    assert by_provider["ipinfo"]["payload"]["as_name"] == "IPINFO-ONLY-NET"
    # IPinfo text appears nowhere in the classification or its evidence
    assert "IPINFO-ONLY-NET" not in json.dumps(run["result"]) + json.dumps(run["evidence"])
    assert "IPINFO-ONLY-NET" not in run["explanation"]
    assert run["label"] == "Known Tor exit"


def test_not_requested_metadata_is_not_stored(tmp_path):
    service, store, _ = build(tmp_path, TOR_IP, ipinfo_route=lite(TOR_IP), with_ripestat=True)
    service.classify_and_record(obs(TOR_IP))
    run = store.get_run(1)
    assert run["context_metadata"] == [] and not run["ipinfo_requested"] and not run["ripestat_requested"]


def test_the_token_never_reaches_the_database_file(tmp_path):
    service, _, db = build(tmp_path, TOR_IP, ipinfo_route=lite(TOR_IP), with_ripestat=True)
    service.classify_and_record(obs(TOR_IP), include_ripestat=True, include_ipinfo=True)
    assert TOKEN.encode() not in db.read_bytes()


# --------------------------------------------------------------------------- failure is explicit
def test_a_failed_save_keeps_the_classification_and_says_it_failed(tmp_path, caplog):
    blocked = tmp_path / "is-a-directory"
    blocked.mkdir()
    service, _, _ = build(tmp_path, TOR_IP, store=AuditStore(blocked, secrets=[TOKEN]))
    plain, _, _ = build(tmp_path, TOR_IP, store=None, name="p")
    out = service.classify_and_record(obs(TOR_IP))
    assert out.audit.status is AuditStatus.FAILED
    assert out.audit.run_id is None and out.audit.recorded_at is None and out.audit.error
    assert out.result.model_dump(mode="json") == plain.classify(obs(TOR_IP)).model_dump(mode="json")
    assert "NOT saved" in caplog.text


def test_an_unexpected_store_exception_is_contained_and_redacted(tmp_path):
    class Exploding(AuditStore):
        def record(self, result):
            raise RuntimeError(f"disk exploded near {TOKEN}")

    service, _, _ = build(tmp_path, store=Exploding(tmp_path / "x.sqlite3", secrets=[TOKEN]))
    out = service.classify_and_record(obs(CLEAN_IP))
    assert out.audit.status is AuditStatus.FAILED
    assert TOKEN not in out.audit.error and "RuntimeError" in out.audit.error
    assert out.result.classification.label is Label.UNKNOWN


def test_classification_errors_are_not_swallowed_by_the_audit_wrapper(tmp_path):
    service, _, _ = build(tmp_path)
    with pytest.raises(ValueError, match="RIPEstat"):
        service.classify_and_record(obs(CLEAN_IP), include_ripestat=True)  # no RIPEstat service


def test_without_a_store_the_outcome_is_disabled_and_nothing_is_written(tmp_path):
    service, _, _ = build(tmp_path, store=None)
    out = service.classify_and_record(obs(CLEAN_IP))
    assert out.audit.status is AuditStatus.DISABLED and out.audit.run_id is None and out.audit.note
    assert service.audit_enabled is False
    assert list(tmp_path.rglob("*.sqlite3")) == []


def test_audit_outcome_cannot_claim_a_save_it_did_not_make():
    with pytest.raises(Exception):
        AuditOutcome(status=AuditStatus.SAVED)
    with pytest.raises(Exception):
        AuditOutcome(status=AuditStatus.FAILED)
    with pytest.raises(Exception):
        AuditOutcome(status=AuditStatus.DISABLED, run_id=3)
    with pytest.raises(Exception):
        AuditOutcome(status=AuditStatus.SAVED, run_id=1, recorded_at=T0, error="x")
    out = AuditOutcome(status=AuditStatus.FAILED, error="boom")
    with pytest.raises(Exception):  # frozen
        out.status = AuditStatus.SAVED  # type: ignore[misc]


# --------------------------------------------------------------------------- history never influences classification
def test_stored_history_cannot_influence_a_later_classification(tmp_path):
    service, store, db = build(tmp_path, CLEAN_IP)
    # A stored record that CLAIMS this address is a Tor exit:
    store.record(
        fake_result(CLEAN_IP, label="Known Tor exit", reason="TOR_EXIT_MATCH", observed_at="2026-10-28T11:00:00Z")
    )
    out = service.classify_and_record(obs(CLEAN_IP))
    assert out.result.classification.label is Label.UNKNOWN
    assert out.result.classification.reason_code.value != "TOR_EXIT_MATCH"
    assert [r["label"] for r in store.list_runs()] == ["Unknown", "Known Tor exit"]


def test_classification_never_reads_the_store(tmp_path):
    class NoReads(AuditStore):
        def __getattribute__(self, name):
            if name in {"list_runs", "get_run", "export_runs", "info", "purge", "delete_ip"}:
                raise AssertionError(f"the service must not call {name}")
            return super().__getattribute__(name)

    stack = make_stack(tmp_path / "w")
    store = NoReads(tmp_path / "w" / "a.sqlite3", clock=stack.clock)
    service = ClassificationService(Settings(), all_adapters(stack), audit=store, clock=stack.clock)
    for ip in (TOR_IP, CLEAN_IP, EXCLUDED_IP):
        out = service.classify_and_record(obs(ip))
        assert out.audit.status is AuditStatus.SAVED


# --------------------------------------------------------------------------- wiring
def test_from_settings_builds_a_store_only_when_enabled_and_touches_no_file(tmp_path):
    clock = MutableClock(T0)
    kwargs = dict(
        fetcher=make_stack(tmp_path / "e").fetcher,
        ripestat_fetcher=FakeFetcher({}, clock),
        ipinfo_fetcher=FakeFetcher({url_for(CLEAN_IP): lite(CLEAN_IP)}, clock),
        clock=clock,
    )
    db = tmp_path / "data" / "audit.sqlite3"
    off = ClassificationService.from_settings(Settings(cache_dir=tmp_path / "c1", db_path=db), **kwargs)
    on = ClassificationService.from_settings(
        Settings(cache_dir=tmp_path / "c2", db_path=db, audit_enabled=True, ipinfo_token=TOKEN), **kwargs
    )
    assert off.audit_enabled is False and on.audit_enabled is True
    assert not db.exists() and not db.parent.exists()  # constructing anything wrote nothing
    on.classify(obs(CLEAN_IP))
    assert not db.exists()  # classify() still writes nothing
    out_off = off.classify_and_record(obs(CLEAN_IP))
    assert out_off.audit.status is AuditStatus.DISABLED and not db.exists()
    out_on = on.classify_and_record(obs(CLEAN_IP))
    assert out_on.audit.status is AuditStatus.SAVED and db.exists()
    assert out_on.result.classification.label is out_off.result.classification.label


def test_from_settings_hides_secrets_in_the_store_repr(tmp_path):
    on = ClassificationService.from_settings(
        Settings(cache_dir=tmp_path / "c", db_path=tmp_path / "a.sqlite3", audit_enabled=True, ipinfo_token=TOKEN),
        fetcher=make_stack(tmp_path / "e").fetcher,
    )
    assert TOKEN not in repr(on._audit) and TOKEN not in on._audit.safe_error(RuntimeError(TOKEN))
