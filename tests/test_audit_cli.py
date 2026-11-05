"""CLI contracts for audit history.

* Without --audit (and with the setting off) classify_ip.py output, exit codes and side effects
  are exactly those without auditing: no "audit" section, no database file, nothing extra on stderr.
* --audit saves and adds an "audit" section; a failed save exits 5 but still prints the result.
* audit_history.py maintains the history; purge / delete-ip are dry runs without --yes.

Mocked HTTP only; the subprocess tests use an excluded address (no network needed).
"""
import importlib.util
import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from audit_support import T0 as FAKE_T0
from audit_support import fake_result
from netclass.audit import AuditStore
from netclass.config import Settings
from netclass.service import ClassificationService
from support import CLEAN_IP, TOR_IP, all_adapters, make_stack

ROOT = Path(__file__).resolve().parents[1]
AT = "2026-10-28T12:00:00+00:00"  # == T0, the fixture clock


def load_script(name):
    spec = importlib.util.spec_from_file_location(f"script_{name}", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def classify_cli(monkeypatch, capsys, tmp_path):
    """Run classify_ip.py main() over the fake world. Returns (code, stdout, stderr, db_path)."""

    def run(*argv, ip=CLEAN_IP, audit_enabled=False, db_path=None):
        db = db_path or (tmp_path / "audit.sqlite3")
        stack = make_stack(tmp_path / "cli")
        settings = Settings(db_path=db, audit_enabled=audit_enabled)

        def from_settings(cls, received, **kwargs):
            # mirrors the real wiring: a store exists only if the CLI enabled audit in the settings
            store = AuditStore(received.db_path, clock=stack.clock) if received.audit_enabled else None
            return ClassificationService(received, all_adapters(stack), audit=store, clock=stack.clock)

        monkeypatch.setattr(ClassificationService, "from_settings", classmethod(from_settings))
        script = load_script("classify_ip")
        monkeypatch.setattr(script, "load_settings", lambda: settings)
        monkeypatch.setattr(sys, "argv", ["classify_ip.py", *argv])
        code = script.main()
        out = capsys.readouterr()
        return code, out.out, out.err, db

    return run


# ------------------------------------------------------------------ disabled: exactly the unaudited behaviour
def test_without_the_flag_nothing_changes_and_nothing_is_written(classify_cli):
    code, out, err, db = classify_cli(CLEAN_IP, "--at", AT)
    assert code == 0 and err == ""
    assert list(json.loads(out)) == ["result"]
    assert not db.exists()


def test_evidence_flag_without_audit_writes_nothing(classify_cli):
    code, out, err, db = classify_cli(CLEAN_IP, "--at", AT, "--evidence")
    assert code == 0 and err == "" and list(json.loads(out)) == ["result", "evidence"]
    assert not db.exists() and not list(db.parent.glob("*.sqlite3"))


def test_no_audit_flag_overrides_the_enabled_setting(classify_cli):
    code, out, err, db = classify_cli(CLEAN_IP, "--at", AT, "--no-audit", audit_enabled=True)
    assert code == 0 and err == "" and list(json.loads(out)) == ["result"]
    assert not db.exists()


def test_invalid_input_exits_2_and_never_creates_the_database(classify_cli):
    code, out, err, db = classify_cli("not-an-ip", "--audit")
    assert code == 2 and out == "" and err.startswith("Invalid input:")
    assert not db.exists()


def test_audit_and_no_audit_together_exit_2(classify_cli):
    with pytest.raises(SystemExit) as raised:
        classify_cli(CLEAN_IP, "--audit", "--no-audit")
    assert raised.value.code == 2


# ------------------------------------------------------------------ enabled
def test_audit_flag_saves_and_adds_a_section_without_changing_the_result(classify_cli):
    _, plain, _, _ = classify_cli(TOR_IP, "--at", AT, ip=TOR_IP)
    code, out, err, db = classify_cli(TOR_IP, "--at", AT, "--audit", "--evidence", ip=TOR_IP)
    doc = json.loads(out)
    assert code == 0 and err == "" and list(doc) == ["result", "evidence", "audit"]
    assert doc["result"] == json.loads(plain)["result"] and doc["result"]["label"] == "Known Tor exit"
    assert doc["audit"]["status"] == "SAVED" and doc["audit"]["run_id"] == 1
    saved = AuditStore(db).get_run(1)
    assert saved["result"] == doc["result"] and len(saved["evidence"]) == len(doc["evidence"])


def test_the_setting_alone_enables_auditing(classify_cli):
    code, out, _, db = classify_cli(CLEAN_IP, "--at", AT, audit_enabled=True)
    assert code == 0 and json.loads(out)["audit"]["status"] == "SAVED" and db.exists()


def test_excluded_address_is_recorded_without_evidence(classify_cli):
    code, out, _, db = classify_cli("10.0.0.1", "--at", AT, "--audit")
    run = AuditStore(db).get_run(1)
    assert code == 0 and run["reason_code"] == "UNKNOWN_EXCLUDED_ADDRESS" and run["evidence"] == []


def test_a_failed_save_exits_5_but_prints_the_classification_and_a_warning(classify_cli, tmp_path):
    blocked = tmp_path / "a-directory"
    blocked.mkdir()
    code, out, err, _ = classify_cli(TOR_IP, "--at", AT, "--audit", ip=TOR_IP, db_path=blocked)
    doc = json.loads(out)
    assert code == 5
    assert doc["result"]["label"] == "Known Tor exit"
    assert doc["audit"]["status"] == "FAILED" and doc["audit"]["error"] and doc["audit"]["run_id"] is None
    assert err.startswith("WARNING: the classification above is valid, but the audit record was NOT saved")


def test_help_lists_the_new_flags(classify_cli, capsys, monkeypatch):
    script = load_script("classify_ip")
    monkeypatch.setattr(sys, "argv", ["classify_ip.py", "--help"])
    with pytest.raises(SystemExit) as raised:
        script.main()
    text = capsys.readouterr().out
    assert raised.value.code == 0
    for flag in ("--at", "--evidence", "--context", "--ipinfo", "--audit", "--no-audit"):
        assert flag in text


# ------------------------------------------------------------------ real scripts (no network)
def run_script(tmp_path, *argv, db=None, enabled=""):
    env = dict(os.environ)
    env.update(
        {
            "IPINFO_TOKEN": "",
            "NETCLASS_CACHE_DIR": str(tmp_path / "cache"),
            "NETCLASS_DB_PATH": str(db or tmp_path / "real.sqlite3"),
            "NETCLASS_AUDIT_ENABLED": enabled,  # set explicitly so a developer's .env cannot leak in
            "NETCLASS_AUDIT_RETENTION_DAYS": "90",
            "NETCLASS_VPN_PROVIDER": "",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / argv[0]), *argv[1:]],
        capture_output=True, text=True, cwd=tmp_path, env=env, timeout=60,
    )


def test_real_cli_without_audit_writes_no_database(tmp_path):
    done = run_script(tmp_path, "classify_ip.py", "10.0.0.1", "--at", AT)
    assert done.returncode == 0 and "audit" not in json.loads(done.stdout)
    assert not (tmp_path / "real.sqlite3").exists()


def test_real_cli_with_audit_saves_an_excluded_address_and_history_can_read_it(tmp_path):
    done = run_script(tmp_path, "classify_ip.py", "10.0.0.1", "--at", AT, "--audit")
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["audit"]["status"] == "SAVED"
    listed = run_script(tmp_path, "audit_history.py", "list")
    rows = json.loads(listed.stdout)
    assert listed.returncode == 0 and len(rows) == 1 and rows[0]["reason_code"] == "UNKNOWN_EXCLUDED_ADDRESS"


def test_real_history_script_prints_help(tmp_path):
    done = run_script(tmp_path, "audit_history.py", "--help")
    assert done.returncode == 0 and "purge" in done.stdout


# ------------------------------------------------------------------ audit_history.py in-process
@pytest.fixture
def history(monkeypatch, capsys, tmp_path):
    db = tmp_path / "history.sqlite3"
    clock_now = {"t": FAKE_T0}
    store = AuditStore(db, clock=lambda: clock_now["t"])

    def seed(age_days, ip="8.8.8.8", **kwargs):
        clock_now["t"] = FAKE_T0 - timedelta(days=age_days)
        return store.record(fake_result(ip, **kwargs))

    def run(*argv, retention=90):
        script = load_script("audit_history")
        monkeypatch.setattr(
            script, "load_settings", lambda: Settings(db_path=db, audit_retention_days=retention)
        )
        code = script.main(list(argv))
        out = capsys.readouterr()
        return code, out.out, out.err

    return seed, run, db, store


def test_history_commands_on_a_missing_database_do_not_create_it(history):
    _, run, db, _ = history
    code, out, err = run("list")
    assert code == 1 and "does not exist" in err and not db.exists()
    code, out, _ = run("info")
    assert code == 0 and json.loads(out)["exists"] is False and not db.exists()
    code, out, _ = run("purge", "--yes")
    assert code == 0 and json.loads(out)["matched_runs"] == 0 and not db.exists()


def test_list_show_info_and_export(history, tmp_path):
    seed, run, db, _ = history
    seed(1, "8.8.8.8", ipinfo=True)
    seed(0, "1.1.1.1")
    code, out, _ = run("list", "--ip", "8.8.8.8")
    assert code == 0 and [r["ip"] for r in json.loads(out)] == ["8.8.8.8"]
    code, out, _ = run("show", "1")
    shown = json.loads(out)
    assert code == 0 and shown["context_metadata"][0]["provider"] == "ipinfo" and shown["evidence"]
    assert run("show", "99")[0] == 1
    info = json.loads(run("info")[1])
    assert info["runs"] == 2 and info["retention_days_setting"] == 90
    target = tmp_path / "out.json"
    code, _, _ = run("export", "--output", str(target))
    assert code == 0 and len(json.loads(target.read_text())) == 2
    before = target.read_text()
    code, _, err = run("export", "--output", str(target))
    assert code == 1 and "Refusing to overwrite" in err and target.read_text() == before


def test_invalid_filters_exit_2(history):
    seed, run, _, _ = history
    seed(0)
    code, _, err = run("list", "--ip", "nope")
    assert code == 2 and "Invalid input" in err
    with pytest.raises(SystemExit) as raised:
        run("list", "--since", "2026-01-01T00:00:00")  # naive time
    assert raised.value.code == 2


def test_purge_is_a_dry_run_unless_yes_and_respects_the_setting(history):
    seed, run, db, store = history
    for age in (200, 100, 10):
        seed(age)
    code, out, err = run("purge")
    report = json.loads(out)
    assert code == 0 and report["dry_run"] is True and report["matched_runs"] == 2 and report["deleted_runs"] == 0
    assert "Dry run" in err and store.info()["runs"] == 3
    code, out, _ = run("purge", "--yes")
    assert json.loads(out)["deleted_runs"] == 2 and store.info()["runs"] == 1


def test_purge_days_override_and_retention_zero(history):
    seed, run, _, store = history
    for age in (50, 5):
        seed(age)
    code, out, _ = run("purge", "--yes", retention=0)
    assert json.loads(out)["deleted_runs"] == 0 and "indefinitely" in json.loads(out)["note"]
    assert store.info()["runs"] == 2
    code, out, _ = run("purge", "--days", "30", "--yes", retention=0)
    assert json.loads(out)["deleted_runs"] == 1 and store.info()["runs"] == 1
    with pytest.raises(SystemExit) as raised:
        run("purge", "--days", "0")
    assert raised.value.code == 2


def test_listing_and_info_never_purge(history):
    seed, run, _, store = history
    for age in (5000, 4000):
        seed(age)
    run("list"); run("info"); run("show", "1"); run("export")
    assert store.info()["runs"] == 2


def test_delete_ip_is_a_dry_run_unless_yes(history):
    seed, run, _, store = history
    seed(1, "8.8.8.8"); seed(1, "8.8.8.8"); seed(1, "1.1.1.1")
    out = json.loads(run("delete-ip", "8.8.8.8")[1])
    assert out["dry_run"] and out["matched_runs"] == 2 and store.info()["runs"] == 3
    out = json.loads(run("delete-ip", "8.8.8.8", "--yes")[1])
    assert out["deleted_runs"] == 2 and store.info()["runs"] == 1
    assert run("delete-ip", "not-an-ip")[0] == 2
