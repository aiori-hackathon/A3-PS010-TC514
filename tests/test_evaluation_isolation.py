"""Evaluation is isolated and cannot change classification, policy or existing behavior.

* the evaluation package never imports audit, dashboard, network, database or .env code;
* an evaluation run creates no file or directory, makes no network call, writes no audit row;
* the classification an evaluation records is exactly what the existing pipeline returns;
* context-only metadata (RIPEstat holder names, IPinfo AS names) cannot change any label;
* the policy constants and the three labels are the shipped ones.
"""
import ast
import os
from datetime import datetime
from pathlib import Path

import pytest

import ripestat_support
import ipinfo_support
from evaluation_support import DATASET_PATH, ROOT
from netclass import __version__
from netclass.classifier import POLICY_VERSION
from netclass.collector import classify_with_evidence
from netclass.config import Settings
from netclass.evaluation import dataset as ds
from netclass.evaluation.runner import build_replay_service, default_replay_config, run_replay
from netclass.models import Label, Observation, ReasonCode
from netclass.service import SERVICE_VERSION

PACKAGE = ROOT / "src" / "netclass" / "evaluation"
MODULES = sorted(PACKAGE.glob("*.py"))
SCRIPT = ROOT / "scripts" / "evaluate.py"
FORBIDDEN_IMPORTS = ("audit", "dashboard", "requests", "socket", "urllib", "sqlite3",
                     "subprocess", "dotenv", "streamlit", "http.client", "ssl")
FORBIDDEN_TEXT = (".purge(", "delete_ip", "AuditStore", "classify_and_record", "from_settings",
                  "load_settings", "include_ripestat=True", "include_ipinfo=True")


def imported_modules(path: Path) -> list:
    names = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names.append(("." * node.level) + (node.module or ""))
            if not node.module:  # "from .. import audit": the imported name is the module
                names += [("." * node.level) + a.name for a in node.names]
    return names


def test_the_package_has_the_expected_modules():
    assert {m.name for m in MODULES} == {"__init__.py", "dataset.py", "metrics.py", "replay.py", "report.py", "runner.py"}


@pytest.mark.parametrize("path", MODULES + [SCRIPT], ids=lambda p: p.name)
def test_evaluation_code_imports_nothing_that_could_touch_audit_network_or_ui(path):
    for name in imported_modules(path):
        for banned in FORBIDDEN_IMPORTS:
            parts = name.lower().lstrip(".").split(".")
            assert banned not in parts and not name.lower().lstrip(".").startswith(banned), (path.name, name)


@pytest.mark.parametrize("path", MODULES + [SCRIPT], ids=lambda p: p.name)
def test_evaluation_code_contains_no_audit_write_or_purge_calls(path):
    text = path.read_text(encoding="utf-8")
    for fragment in FORBIDDEN_TEXT:
        assert fragment not in text, (path.name, fragment)


def test_pure_modules_need_only_the_standard_library():
    stdlib_or_local = lambda n: n.startswith(".") or n.split(".")[0] in __import__("sys").stdlib_module_names
    for name in ("dataset.py", "metrics.py", "report.py"):
        assert all(stdlib_or_local(m) for m in imported_modules(PACKAGE / name)), name


def test_evaluation_service_is_built_without_audit_history():
    dataset = ds.load_dataset(DATASET_PATH)
    service, _ = build_replay_service(dataset.worlds["healthy"], default_replay_config(dataset))
    assert service.audit_enabled is False
    assert service.ipinfo_enabled is False


def _snapshot(*roots):
    """(path, size, mtime_ns) of every file under the given roots; tolerant of absent roots."""
    seen = {}
    for root in roots:
        if root.exists():
            for path in sorted(root.rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts:
                    stat = path.stat()
                    seen[str(path)] = (stat.st_size, stat.st_mtime_ns)
    return seen


def test_a_run_creates_no_files_and_leaves_any_existing_audit_data_untouched(tmp_path, monkeypatch):
    # A real checkout may legitimately hold data\ with an audit database (opt-in recording from
    # the dashboard). The run must leave all of it exactly as it was.
    monkeypatch.chdir(tmp_path)
    watched = (ROOT / "data", ROOT / "evaluation" / "output", ROOT / "evaluation" / "output-live")
    existing_db = sorted(str(p) for p in ROOT.rglob("*") if p.suffix in (".sqlite3", ".sqlite", ".db"))
    before = _snapshot(*watched)
    run_replay(ds.load_dataset(DATASET_PATH))
    assert list(tmp_path.iterdir()) == []
    assert _snapshot(*watched) == before
    assert sorted(str(p) for p in ROOT.rglob("*") if p.suffix in (".sqlite3", ".sqlite", ".db")) == existing_db


def test_an_audit_enabled_environment_does_not_make_the_run_write_history(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for key in ("AUDIT_ENABLED", "NETCLASS_AUDIT_ENABLED", "PS010_AUDIT_ENABLED"):
        monkeypatch.setenv(key, "true")
    report = run_replay(ds.load_dataset(DATASET_PATH))
    assert report["configuration"]["audit_enabled"] is False
    assert list(tmp_path.rglob("*")) == []


def test_replay_never_touches_the_network_even_when_a_world_has_no_route(monkeypatch):
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("network access attempted during offline evaluation")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    report = run_replay(ds.load_dataset(DATASET_PATH))
    assert report["evaluation"]["network_used"] is False


# ----------------------------------------------------------- classification is unchanged
def test_recorded_classification_equals_the_existing_pipeline_result():
    dataset = ds.load_dataset(DATASET_PATH)
    config = default_replay_config(dataset)
    for case in dataset.cases:
        service_a, _ = build_replay_service(dataset.worlds[case.world], config)
        service_b, _ = build_replay_service(dataset.worlds[case.world], config)
        observation = Observation(ip=case.ip, observed_at=case.observed_at)
        via_service = service_a.classify(observation)
        direct, records = classify_with_evidence(observation, service_b._adapters, service_b._settings)
        assert via_service.classification == direct, case.case_id
        assert via_service.evidence == records, case.case_id


def test_policy_and_label_constants_are_the_shipped_ones():
    assert POLICY_VERSION == "ps010-policy-1"
    assert SERVICE_VERSION == "ps010-service-1"
    assert [l.value for l in Label] == ["Known Tor exit", "Known hosted VPN/proxy endpoint", "Unknown"]
    assert len(ReasonCode) == 9
    assert __version__ == "0.7.0-stage7"


def test_evaluation_adds_no_label_and_does_not_import_the_classifier_internals():
    for name in ("replay.py", "metrics.py", "dataset.py", "report.py"):
        names = imported_modules(PACKAGE / name)
        assert not any(n.endswith("classifier") for n in names), name
    assert "classify(" not in (PACKAGE / "runner.py").read_text(encoding="utf-8").replace("service.classify(", "")


# ----------------------------------------------------------- context-only metadata
HOLDER = "Acme Tor Exit VPN Proxy Hosting Datacenter Ltd"


def test_context_only_metadata_cannot_change_any_classification():
    dataset = ds.load_dataset(DATASET_PATH)
    config = default_replay_config(dataset)
    exercised = 0
    for case in dataset.cases:
        plain, _ = build_replay_service(dataset.worlds[case.world], config)
        observation = Observation(ip=case.ip, observed_at=case.observed_at)
        baseline = plain.classify(observation)

        ripestat, ripe_fetcher, _ = ripestat_support.make()
        ripe_fetcher.routes.update(ripestat_support.healthy(ripestat, ip=case.ip_normalized, holder=HOLDER))
        ipinfo, ipinfo_fetcher, _ = ipinfo_support.make(
            {ipinfo_support.url_for(case.ip_normalized): ipinfo_support.lite(
                case.ip_normalized, as_name=HOLDER, as_domain="vpn-hosting.example")}
        )
        enriched_service, _ = build_replay_service(
            dataset.worlds[case.world], config, ripestat=ripestat, ipinfo=ipinfo)
        enriched = enriched_service.classify(observation, include_ripestat=True, include_ipinfo=True)

        assert enriched.classification == baseline.classification, case.case_id
        assert enriched.evidence == baseline.evidence, case.case_id
        exercised += bool(ripe_fetcher.requested or ipinfo_fetcher.requested)
    assert exercised >= 30  # the metadata path really ran for the non-excluded cases
