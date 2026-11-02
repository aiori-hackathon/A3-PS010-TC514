"""Stage 6: dashboard logic (no Streamlit needed). Mocked sources only; no network.

The dashboard is a presentation layer: these tests pin that it validates input first, uses the
existing ClassificationService, skips collection for excluded addresses, keeps context out of
the label, and writes an audit record only after an explicit, confirmed opt-in.
"""
import dataclasses
import hashlib
from pathlib import Path

import pytest

import ipinfo_support as ii
import ripestat_support as rs
from audit_support import fake_result
from factories import T0
from netclass.audit import AuditStore
from netclass.config import Settings
from netclass.dashboard import logic
from netclass.models import Label, ReasonCode
from netclass.service import AuditedResult, AuditStatus, ClassificationService, ServiceResult
from support import CLEAN_IP, TOR_IP, VPN_IP, all_adapters, make_stack

TOKEN = ii.TOKEN
AUDIT_YES = logic.AuditChoice(wants_recording=True, acknowledged_privacy=True)


def now():
    return T0


def run(ip, options=None, *, settings, factory):
    return logic.run_classification(
        ip, options or logic.ClassifyOptions(), settings=settings, service_factory=factory, now=now
    )


def world(tmp_path, **service_kwargs):
    """(settings, factory, stack): the existing service over the fake world, as from_settings wires it."""
    stack = make_stack(tmp_path / "cache")
    settings = Settings(db_path=tmp_path / "data" / "audit.sqlite3", ipinfo_token=TOKEN)
    built = []

    def factory(received):
        store = (
            AuditStore(received.db_path, clock=stack.clock, secrets=(TOKEN,))
            if received.audit_enabled
            else None
        )
        service = ClassificationService(
            received, all_adapters(stack), audit=store, clock=stack.clock, **service_kwargs
        )
        built.append((received, service))
        return service

    factory.built = built
    return settings, factory, stack


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# 1 ---------------------------------------------------------------- import safety
def test_logic_import_starts_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import importlib

    importlib.reload(logic)
    assert list(tmp_path.iterdir()) == []  # no database, cache or data directory was created


def test_streamlit_modules_import_without_launching_the_ui():
    pytest.importorskip("streamlit")
    import importlib.util

    import netclass.dashboard.ui as ui

    assert callable(ui.main)
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("ps010_app", root / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # __name__ != "__main__": must not build the page
    assert callable(module.main)


# 2 / 3 ------------------------------------------------------------ validation
@pytest.mark.parametrize(
    "raw,expected",
    [("8.8.8.8", "8.8.8.8"), ("  8.8.8.8 ", "8.8.8.8"), ("2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888"),
     ("::ffff:8.8.8.8", "8.8.8.8")],
)
def test_valid_ipv4_and_ipv6_are_normalised(raw, expected):
    check = logic.check_ip_input(raw)
    assert check.status is logic.InputStatus.VALID and check.normalized == expected and check.ok_to_collect


@pytest.mark.parametrize(
    "raw", ["", "   ", "abc", "8.8.8.256", "8.8.8.0/24", "fe80::1%eth0", "8.8.8.8:80", "1.2.3", None, 123, "8.8.8.8; rm -rf /"]
)
def test_invalid_input_is_rejected_before_any_collection(tmp_path, raw):
    settings, factory, stack = world(tmp_path)
    out = run(raw, settings=settings, factory=factory)
    assert out.error_kind == "invalid_input" and out.result is None and out.error
    assert factory.built == [] and stack.fetcher.requested == []  # service never even built
    assert not settings.db_path.exists()


# 4 ---------------------------------------------------------------- exclusions
@pytest.mark.parametrize(
    "ip", ["10.0.0.1", "192.168.1.5", "127.0.0.1", "169.254.1.1", "::1", "fe80::1", "fc00::1",
           "224.0.0.1", "100.64.0.1", "0.0.0.0", "192.0.2.1", "240.0.0.1"],
)
def test_excluded_addresses_trigger_no_external_request(tmp_path, ip):
    settings, factory, stack = world(tmp_path)  # no RIPEstat service: asking for it would raise
    options = logic.ClassifyOptions(include_ripestat=True, include_ipinfo=True, audit=AUDIT_YES)
    out = run(ip, options, settings=settings, factory=factory)
    assert out.check.status is logic.InputStatus.EXCLUDED and out.collection_skipped
    assert out.skipped_reason and "No evidence source" in out.skipped_reason
    assert out.result.classification.label is Label.UNKNOWN
    assert out.result.classification.reason_code is ReasonCode.UNKNOWN_EXCLUDED_ADDRESS
    assert out.result.evidence == [] and stack.fetcher.requested == []
    assert out.result.ripestat_context is None and out.result.ipinfo_metadata is None


# 5 ---------------------------------------------------------------- uses the existing service
def test_default_path_goes_through_ClassificationService_from_settings(tmp_path, monkeypatch):
    stack = make_stack(tmp_path / "cache")
    settings = Settings(db_path=tmp_path / "audit.sqlite3")
    seen = []

    def from_settings(cls, received, **kwargs):
        seen.append(received.audit_enabled)
        return ClassificationService(received, all_adapters(stack), clock=stack.clock)

    monkeypatch.setattr(ClassificationService, "from_settings", classmethod(from_settings))
    out = logic.run_classification(TOR_IP, logic.ClassifyOptions(), settings=settings, now=now)
    assert seen == [False]
    assert isinstance(out.result, ServiceResult)
    assert out.result.classification.label is Label.KNOWN_TOR_EXIT


def test_dashboard_has_no_classifier_of_its_own():
    assert not hasattr(logic, "classify") and not hasattr(logic, "classify_with_evidence")
    source = Path(logic.__file__).read_text(encoding="utf-8")
    assert "from ..classifier import classify" not in source and "collect_evidence" not in source


def test_result_is_the_services_own_result_unchanged(tmp_path):
    settings, factory, stack = world(tmp_path)
    shown = run(TOR_IP, settings=settings, factory=factory).result
    direct = ClassificationService(settings, all_adapters(make_stack(tmp_path / "d")), clock=stack.clock).classify(
        __import__("factories").obs(TOR_IP)
    )
    assert shown.classification == direct.classification and shown.evidence == direct.evidence


# 6 ---------------------------------------------------------------- context cannot change the label
@pytest.mark.parametrize("ip", [TOR_IP, VPN_IP, CLEAN_IP])
def test_ripestat_and_ipinfo_context_never_change_the_classification(tmp_path, ip):
    ripe, ripe_fetcher, _ = rs.make()
    ripe_fetcher.routes.update(rs.healthy(ripe, ip=ip, holder="HOSTING-LOOKING-HOLDER"))
    info, _, _ = ii.make({ii.url_for(ip): ii.lite(ip, as_name="Example Cloud Hosting VPN Services")})
    settings, factory, _ = world(tmp_path, ripestat=ripe, ipinfo=info)
    plain = run(ip, settings=settings, factory=factory).result
    both = run(
        ip, logic.ClassifyOptions(include_ripestat=True, include_ipinfo=True),
        settings=settings, factory=factory,
    ).result
    assert both.ripestat_context is not None and both.ipinfo_metadata is not None
    assert both.classification.label == plain.classification.label
    assert both.classification.reason_code == plain.classification.reason_code
    assert both.classification.evidence_assessments == plain.classification.evidence_assessments
    names = {r["Source"] for r in logic.evidence_rows(both)}
    assert not names & {"ripestat", "ipinfo-lite-api", "ripestat-data-api"}  # context is not evidence


def test_context_tables_are_separate_from_evidence_rows(tmp_path):
    ripe, ripe_fetcher, _ = rs.make()
    ripe_fetcher.routes.update(rs.healthy(ripe, ip=CLEAN_IP, holder="MARKER-RIPE-HOLDER"))
    settings, factory, _ = world(tmp_path, ripestat=ripe)
    out = run(CLEAN_IP, logic.ClassifyOptions(include_ripestat=True), settings=settings, factory=factory)
    assert "MARKER-RIPE-HOLDER" in str(logic.ripestat_rows(out.result.ripestat_context))
    assert "MARKER-RIPE-HOLDER" not in str(logic.evidence_rows(out.result))


# 7 / 8 / 9 -------------------------------------------------------------- audit off by default
def test_audit_choice_defaults_to_nothing_recorded():
    assert logic.AuditChoice().confirmed is False
    assert logic.ClassifyOptions().audit.confirmed is False
    assert logic.AuditChoice(wants_recording=True).confirmed is False  # needs the acknowledgement
    assert logic.AuditChoice(acknowledged_privacy=True).confirmed is False


def test_opening_the_dashboard_creates_no_database(tmp_path):
    settings = Settings(db_path=tmp_path / "data" / "audit.sqlite3")
    diag = logic.collect_diagnostics(settings)
    page = logic.read_history(settings)
    assert diag.history.state is logic.HistoryState.NO_DATABASE
    assert page.state is logic.HistoryState.NO_DATABASE and page.rows == []
    assert not settings.db_path.exists() and not settings.db_path.parent.exists()


def test_classification_without_opt_in_writes_nothing(tmp_path):
    settings, factory, _ = world(tmp_path)
    out = run(CLEAN_IP, settings=settings, factory=factory)
    assert out.audit is None and out.result is not None
    assert not settings.db_path.exists() and not settings.db_path.parent.exists()
    assert factory.built[0][0].audit_enabled is False
    assert factory.built[0][1].audit_enabled is False


def test_environment_enabled_flag_does_not_make_the_dashboard_record(tmp_path):
    settings, factory, _ = world(tmp_path)
    settings = dataclasses.replace(settings, audit_enabled=True)  # e.g. NETCLASS_AUDIT_ENABLED=true
    out = run(CLEAN_IP, settings=settings, factory=factory)
    assert out.audit is None and not settings.db_path.exists()


def test_wanting_without_acknowledging_writes_nothing(tmp_path):
    settings, factory, _ = world(tmp_path)
    opts = logic.ClassifyOptions(audit=logic.AuditChoice(wants_recording=True))
    out = run(CLEAN_IP, opts, settings=settings, factory=factory)
    assert out.audit is None and not settings.db_path.exists()


# 10 --------------------------------------------------------------- explicit opt-in
def test_opt_in_records_only_through_classify_and_record(tmp_path, monkeypatch):
    settings, factory, _ = world(tmp_path)
    calls = []
    original = ClassificationService.classify_and_record

    def spy(self, *a, **k):
        calls.append("classify_and_record")
        return original(self, *a, **k)

    monkeypatch.setattr(ClassificationService, "classify_and_record", spy)
    out = run(TOR_IP, logic.ClassifyOptions(audit=AUDIT_YES), settings=settings, factory=factory)
    assert calls == ["classify_and_record"]
    assert out.audit.status is AuditStatus.SAVED and settings.db_path.exists()
    level, text = logic.audit_message(out.audit)
    assert level == "success" and f"#{out.audit.run_id}" in text
    runs = AuditStore(settings.db_path).list_runs()
    assert len(runs) == 1 and runs[0]["ip"] == TOR_IP and runs[0]["label"] == "Known Tor exit"
    assert out.result.classification.label is Label.KNOWN_TOR_EXIT  # recording changed nothing


def test_opt_in_with_audit_does_not_change_the_result(tmp_path):
    settings, factory, _ = world(tmp_path)
    plain = run(VPN_IP, settings=settings, factory=factory).result
    audited = run(VPN_IP, logic.ClassifyOptions(audit=AUDIT_YES), settings=settings, factory=factory).result
    assert plain.classification == audited.classification


# 11 --------------------------------------------------------------- failed audit write
def test_failed_audit_write_keeps_the_result_and_reports_failure(tmp_path):
    stack = make_stack(tmp_path / "cache")
    directory_as_db = tmp_path / "is-a-directory"
    directory_as_db.mkdir()
    settings = Settings(db_path=directory_as_db, ipinfo_token=TOKEN)

    def factory(received):
        store = AuditStore(received.db_path, clock=stack.clock, secrets=(TOKEN,))
        return ClassificationService(received, all_adapters(stack), audit=store, clock=stack.clock)

    out = run(TOR_IP, logic.ClassifyOptions(audit=AUDIT_YES), settings=settings, factory=factory)
    assert out.result.classification.label is Label.KNOWN_TOR_EXIT
    assert out.audit.status is AuditStatus.FAILED and out.audit.run_id is None
    level, text = logic.audit_message(out.audit, settings)
    assert level == "warning" and "NOT saved" in text and "Saved to" not in text
    assert TOKEN not in text and str(directory_as_db) not in text  # no private path in the UI


# 12 / 13 / 14 ----------------------------------------------------------- history
def seed(settings, n=3):
    store = AuditStore(settings.db_path)
    labels = [("Unknown", "UNKNOWN_NO_QUALIFYING_MATCH"), ("Known Tor exit", "TOR_EXIT_MATCH")]
    for i in range(n):
        label, reason = labels[i % 2]
        store.record(fake_result(f"8.8.8.{i + 1}", label=label, reason=reason, ripestat=True, ipinfo=True))
    return store


def test_history_reads_do_not_mutate_the_database(tmp_path):
    settings = Settings(db_path=tmp_path / "audit.sqlite3")
    seed(settings)
    before = sha(settings.db_path)
    mtime = settings.db_path.stat().st_mtime_ns
    page = logic.read_history(settings, label="Unknown", page=1, page_size=10)
    detail = logic.read_run_detail(settings, page.rows[0]["run_id"])
    logic.collect_diagnostics(settings)
    assert page.state is logic.HistoryState.READY and detail is not None
    assert sha(settings.db_path) == before and settings.db_path.stat().st_mtime_ns == mtime
    assert sorted(p.name for p in tmp_path.iterdir()) == ["audit.sqlite3"]  # no journal/wal left behind


def test_history_is_newest_first_filtered_and_paged(tmp_path):
    settings = Settings(db_path=tmp_path / "audit.sqlite3")
    seed(settings, n=5)
    first = logic.read_history(settings, page=1, page_size=10)
    assert [r["run_id"] for r in first.rows] == [5, 4, 3, 2, 1] and first.has_next is False
    only_tor = logic.read_history(settings, label="Known Tor exit")
    assert {r["label"] for r in only_tor.rows} == {"Known Tor exit"}
    by_ip = logic.read_history(settings, ip=" 8.8.8.3 ")
    assert [r["ip"] for r in by_ip.rows] == ["8.8.8.3"]
    empty = logic.read_history(settings, ip="9.9.9.9")
    assert empty.state is logic.HistoryState.READY and empty.rows == []  # a true, readable empty result


def test_history_pagination_is_bounded(tmp_path, monkeypatch):
    settings = Settings(db_path=tmp_path / "audit.sqlite3")
    store = seed(settings, n=3)
    calls = []
    original = AuditStore.list_runs

    def spy(self, **kw):
        calls.append(kw)
        return original(self, **kw)

    monkeypatch.setattr(AuditStore, "list_runs", spy)
    page = logic.read_history(settings, page=1, page_size=25, store=store)
    assert calls[-1]["limit"] == 26 <= 1000 and calls[-1]["offset"] == 0
    logic.read_history(settings, page=2, page_size=999_999, store=store)  # unsupported size -> default
    assert calls[-1]["limit"] == logic.DEFAULT_PAGE_SIZE + 1 and calls[-1]["offset"] == logic.DEFAULT_PAGE_SIZE
    logic.read_history(settings, page=10**9, page_size=100, store=store)
    assert calls[-1]["offset"] == (logic.MAX_PAGE_NUMBER - 1) * 100
    assert page.has_next is False
    two = logic.read_history(settings, page=1, page_size=10)
    assert len(two.rows) == 3


@pytest.mark.parametrize(
    "hostile", ["x' OR '1'='1", "8.8.8.8'; DROP TABLE classification_runs;--", "1 OR 1=1", "%", "' UNION SELECT * FROM sqlite_master--"]
)
def test_history_filters_never_reach_sql_unvalidated(tmp_path, monkeypatch, hostile):
    settings = Settings(db_path=tmp_path / "audit.sqlite3")
    store = seed(settings)
    monkeypatch.setattr(AuditStore, "list_runs", lambda self, **kw: pytest.fail("query must not run"))
    by_ip = logic.read_history(settings, ip=hostile, store=store)
    by_label = logic.read_history(settings, label=hostile, store=store)
    assert by_ip.filter_error and by_label.filter_error and by_ip.rows == by_label.rows == []
    monkeypatch.undo()
    assert len(AuditStore(settings.db_path).list_runs()) == 3  # table intact


def test_history_passes_only_normalised_values_to_the_store(tmp_path, monkeypatch):
    settings = Settings(db_path=tmp_path / "audit.sqlite3")
    store = seed(settings)
    seen = {}
    original = AuditStore.list_runs
    monkeypatch.setattr(
        AuditStore, "list_runs", lambda self, **kw: (seen.update(kw), original(self, **kw))[1]
    )
    logic.read_history(settings, ip="::ffff:8.8.8.1", label="Unknown", store=store)
    assert seen["ip"] == "8.8.8.1" and seen["label"] == "Unknown"


def test_missing_database_is_not_reported_as_an_empty_success(tmp_path):
    settings = Settings(db_path=tmp_path / "missing.sqlite3")
    page = logic.read_history(settings)
    assert page.state is logic.HistoryState.NO_DATABASE and page.message
    assert logic.read_run_detail(settings, 1) is None
    assert not settings.db_path.exists()


def test_unavailable_messages_hide_the_database_path(tmp_path):
    directory = tmp_path / "a-directory"
    directory.mkdir()
    page = logic.read_history(Settings(db_path=directory))
    assert page.state is logic.HistoryState.UNAVAILABLE and str(directory) not in page.message


def test_unreadable_database_is_unavailable_and_left_untouched(tmp_path):
    bad = tmp_path / "not-a-db.sqlite3"
    bad.write_bytes(b"this is not sqlite" * 50)
    before = sha(bad)
    settings = Settings(db_path=bad)
    page = logic.read_history(settings)
    assert page.state is logic.HistoryState.UNAVAILABLE and page.rows == []
    assert logic.collect_diagnostics(settings).history.state is logic.HistoryState.UNAVAILABLE
    assert sha(bad) == before


def test_empty_file_is_unavailable_and_not_initialised(tmp_path):
    empty = tmp_path / "empty.sqlite3"
    empty.write_bytes(b"")
    page = logic.read_history(Settings(db_path=empty))
    assert page.state is logic.HistoryState.UNAVAILABLE and empty.read_bytes() == b""


def test_detail_keeps_evidence_and_context_separate(tmp_path):
    settings = Settings(db_path=tmp_path / "audit.sqlite3")
    seed(settings, n=1)
    detail = logic.read_run_detail(settings, 1)
    ev = logic.detail_evidence_rows(detail)
    ctx = logic.detail_context_rows(detail)
    assert {r["Kind"] for r in ev} == {"TOR_EXIT", "VPN_PROXY_ENDPOINT"}
    assert {r["Provider"] for r in ctx} == {"ripestat", "ipinfo"}
    assert "IPINFO-ONLY-MARKER-NET" not in str(ev) and "RIPESTAT-ONLY-MARKER-HOLDER" not in str(ev)


# 15 --------------------------------------------------------------- secrets and bodies
def test_service_failure_message_does_not_leak_secrets_or_bodies(tmp_path):
    settings = Settings(db_path=tmp_path / "a.sqlite3", ipinfo_token=TOKEN)
    body = "<html>" + "SECRET-RAW-BODY " * 200 + "</html>"

    def factory(received):
        raise RuntimeError(f"boom Authorization: Bearer {TOKEN} token={TOKEN} {body}")

    out = run(CLEAN_IP, settings=settings, factory=factory)
    assert out.error_kind == "classification" and out.result is None
    assert TOKEN not in out.error and "SECRET-RAW-BODY" not in out.error and "Authorization" not in out.error
    assert "RuntimeError" in out.error and len(out.error) < 400 and "Traceback" not in out.error
    assert "No label was produced" in out.error  # an error is never presented as evidence


def test_missing_dependency_is_reported_plainly(tmp_path):
    settings = Settings(db_path=tmp_path / "a.sqlite3")

    def factory(received):
        raise ImportError("no module", name="somepackage")

    out = run(CLEAN_IP, settings=settings, factory=factory)
    assert out.error_kind == "dependency" and "pip install -r requirements.txt" in out.error


def test_config_errors_name_the_setting_but_not_its_value():
    msg = logic.describe_config_error(ValueError("NETCLASS_AUDIT_ENABLED must be one of true/false, got 'hunter2-private'"))
    assert "NETCLASS_AUDIT_ENABLED" in msg and "hunter2-private" not in msg
    settings, problem = logic.load_settings_safely(lambda: (_ for _ in ()).throw(ValueError("NETCLASS_HTTP_TIMEOUT_SECONDS must be a number, got 'zzz-secret'")))
    assert settings is None and "zzz-secret" not in problem and "NETCLASS_HTTP_TIMEOUT_SECONDS" in problem


def test_safe_text_redacts_configured_secrets_and_clips():
    text = logic.safe_text(f"x {TOKEN} y " + "a" * 5000, (TOKEN,))
    assert TOKEN not in text and len(text) < 700


def test_diagnostics_show_no_secret_values_or_full_paths(tmp_path):
    settings = Settings(db_path=tmp_path / "deep" / "private" / "audit.sqlite3", ipinfo_token=TOKEN)
    diag = logic.collect_diagnostics(settings)
    flat = repr(dataclasses.asdict(diag))
    assert TOKEN not in flat and str(tmp_path) not in flat
    assert diag.ipinfo_configured is True and diag.database_file == "audit.sqlite3"
    assert diag.policy_version == "ps010-policy-1" and diag.service_version == "ps010-service-1"
    assert not (tmp_path / "deep").exists()


def test_diagnostics_make_no_network_request(tmp_path):
    # tests/conftest.py blocks sockets for the whole suite; this simply must not raise.
    logic.collect_diagnostics(Settings(db_path=tmp_path / "a.sqlite3", ipinfo_token=TOKEN))


# UI-facing text is never HTML -------------------------------------------------
def test_untrusted_evidence_text_stays_plain_text(tmp_path):
    settings, factory, stack = world(tmp_path)
    out = run(CLEAN_IP, settings=settings, factory=factory)
    rows = logic.evidence_rows(out.result)
    assert rows and all(isinstance(v, str) for r in rows for v in r.values())
    ui_source = (Path(logic.__file__).parent / "ui.py").read_text(encoding="utf-8")
    assert "unsafe_allow_html" not in ui_source and "components.html" not in ui_source
