"""Stage 6 architectural boundaries, checked on the source (stdlib only: no pydantic, no network).

* The dashboard may import the audit package ONLY for read access (and the error type), and may
  call only the store's read methods; it can never write, purge, delete or export.
* Recording happens only through ClassificationService.classify_and_record.
* The classification path (and the audit package) never import the dashboard.
* The Streamlit UI module touches neither the audit package nor the classification internals.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "netclass"
DASH = SRC / "dashboard"
LOGIC = DASH / "logic.py"
UI = DASH / "ui.py"

# Exactly what dashboard/logic.py may import from the rest of the package.
ALLOWED_PACKAGE_IMPORTS = {
    ("..", "__version__"),
    ("..address_policy", "AddressCategory"),
    ("..address_policy", "assess_address"),
    ("..audit", "AuditError"),  # error type, to report an unreadable history
    ("..audit", "AuditStore"),  # constructed only to read (see the method pin below)
    ("..audit.privacy", "redact_text"),  # pure redaction helper
    ("..audit.schema", "LABELS"),  # the three label strings, to validate the label filter
    ("..classifier", "POLICY_VERSION"),  # a version string for display; not classify()
    ("..config", "load_settings"),
    ("..models", "Observation"),
    ("..service", "AuditedResult"),
    ("..service", "ClassificationService"),
    ("..service", "SERVICE_VERSION"),
}
READ_ONLY_STORE_METHODS = {"info", "list_runs", "get_run", "path"}
FORBIDDEN_STORE_METHODS = {
    "record", "purge", "delete_ip", "export_runs", "_delete_where", "_connect", "_session", "_create_file",
}


def parse(path):
    return ast.parse(path.read_text(encoding="utf-8"))


def package_imports(path):
    found = set()
    for node in ast.walk(parse(path)):
        if isinstance(node, ast.ImportFrom) and node.level > 0:
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                found.add((module, alias.name))
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("netclass"):
            for alias in node.names:
                found.add((node.module, alias.name))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("netclass"):
                    found.add((alias.name, None))
    return found


def test_dashboard_logic_imports_exactly_the_pinned_package_names():
    assert package_imports(LOGIC) == ALLOWED_PACKAGE_IMPORTS


def test_dashboard_logic_never_imports_the_classification_internals():
    forbidden = (
        "collector", "adapters", "snapshots", "cache", "parsers", "http_client", "ripestat", "ipinfo",
        "hashing", "inspection", "sources",
    )
    for module, name in package_imports(LOGIC):
        assert not any(module.endswith(f) or f".{f}" in module for f in forbidden), (module, name)
    # classifier is imported for its version string only, never for classify()
    assert {n for m, n in package_imports(LOGIC) if m == "..classifier"} == {"POLICY_VERSION"}


def test_dashboard_logic_only_calls_read_methods_on_the_store():
    used = set()
    for node in ast.walk(parse(LOGIC)):
        if isinstance(node, ast.Attribute):
            owner = node.value
            if isinstance(owner, ast.Name) and owner.id == "store":
                used.add(node.attr)
            if isinstance(owner, ast.Call) and isinstance(owner.func, ast.Name) and owner.func.id == "open_store":
                used.add(node.attr)
    assert used == READ_ONLY_STORE_METHODS, used


def test_no_write_purge_delete_or_export_name_appears_anywhere_in_the_dashboard():
    for path in DASH.glob("*.py"):
        tree = parse(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in FORBIDDEN_STORE_METHODS, (path.name, node.attr)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lowered = node.name.lower()
                assert not any(w in lowered for w in ("purge", "delete", "erase")), (path.name, node.name)
        text = path.read_text(encoding="utf-8")
        assert ".purge(" not in text and "delete_ip" not in text and "export_runs" not in text, path.name


def test_the_only_write_path_is_the_services_classify_and_record():
    calls = [
        n for n in ast.walk(parse(LOGIC))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr in {"classify", "classify_and_record"}
    ]
    assert {c.func.attr for c in calls} == {"classify", "classify_and_record"}
    # the audit call sits under the confirmed-opt-in branch only
    guarded = [
        n for n in ast.walk(parse(LOGIC))
        if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "audit_on"
    ]
    assert guarded and any(
        isinstance(c.func, ast.Attribute) and c.func.attr == "classify_and_record"
        for g in guarded for stmt in g.body for c in ast.walk(stmt) if isinstance(c, ast.Call)
    )
    assert not any(
        isinstance(c.func, ast.Attribute) and c.func.attr == "classify_and_record"
        for g in guarded for stmt in g.orelse for c in ast.walk(stmt) if isinstance(c, ast.Call)
    )


def test_audit_enabled_is_always_derived_from_the_confirmed_choice():
    src = LOGIC.read_text(encoding="utf-8")
    assert "dataclasses.replace(settings, audit_enabled=audit_on)" in src
    assert "audit_on = options.audit.confirmed" in src


def test_the_ui_module_has_no_audit_or_classification_internals():
    for module, name in package_imports(UI):
        assert module == "." or module.startswith(".logic") or module == ".logic", (module, name)
    tree = parse(UI)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not names & {"AuditStore", "AuditError", "ClassificationService"}
    assert "sqlite3" not in imported
    keywords = {k.arg for n in ast.walk(tree) if isinstance(n, ast.Call) for k in n.keywords}
    assert "unsafe_allow_html" not in keywords  # untrusted text is never rendered as HTML


def test_nothing_in_the_classification_path_or_audit_package_imports_the_dashboard():
    for path in SRC.rglob("*.py"):
        if DASH in path.parents:
            continue
        for module, _ in package_imports(path):
            assert "dashboard" not in module, (path.relative_to(SRC).as_posix(), module)
    for path in (SRC / "audit").glob("*.py"):
        assert "dashboard" not in path.read_text(encoding="utf-8"), path.name


def test_the_streamlit_dependency_is_confined_to_the_ui_module():
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if path == UI:
            continue
        assert "import streamlit" not in text and "from streamlit" not in text, path.name
