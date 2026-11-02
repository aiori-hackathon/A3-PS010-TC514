"""Structural guarantees of Stage 5, checked on the source (no pydantic, no network).

* The classification path cannot read the audit history.
* Nothing purges or deletes except the explicit maintenance calls.
* The store's SQL is parameterised.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "netclass"
AUDIT = SRC / "audit"


def parse(path):
    return ast.parse(path.read_text(encoding="utf-8"))


def imports_of(path):
    """Set of (module, imported name or None) with relative dots kept in the module string."""
    found = set()
    for node in ast.walk(parse(path)):
        if isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                found.add((module, alias.name))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.add((alias.name, None))
    return found


def test_only_config_service_and_the_dashboard_logic_import_the_audit_package():
    """Stage 6 made the dashboard's read-only history view the third, explicit importer.

    The list is closed: any other module (above all the classifier and collector) importing the
    audit package fails this test. What the dashboard may import and call is pinned, name by
    name, in tests/test_dashboard_boundaries.py.
    """
    importers = set()
    for path in SRC.rglob("*.py"):
        if AUDIT in path.parents:
            continue
        if any("audit" in module for module, _ in imports_of(path)):
            importers.add(path.relative_to(SRC).as_posix())
    assert importers == {"config.py", "service.py", "dashboard/logic.py"}


def test_config_imports_only_the_pure_retention_parsers():
    audit_imports = {(m, n) for m, n in imports_of(SRC / "config.py") if "audit" in m}
    assert audit_imports == {
        (".audit.retention", "DEFAULT_RETENTION_DAYS"),
        (".audit.retention", "parse_enabled"),
        (".audit.retention", "parse_retention_days"),
    }


def test_service_imports_only_the_store_class_from_audit():
    audit_imports = {(m, n) for m, n in imports_of(SRC / "service.py") if "audit" in m}
    assert audit_imports == {(".audit", "AuditStore")}


def test_the_classification_path_modules_never_import_the_audit_package():
    for name in (
        "classifier.py", "collector.py", "models.py", "ipinfo.py", "ripestat.py", "snapshots.py",
        "cache.py", "parsers.py", "address_policy.py", "adapters/base.py", "adapters/tor.py",
        "adapters/x4bnet.py", "adapters/az0.py",
    ):
        assert not [m for m, _ in imports_of(SRC / name) if "audit" in m], name


def test_the_service_only_ever_writes_to_the_store():
    """Every attribute used on self._audit is a write/describe call; no read method is."""
    allowed = {"record", "safe_error"}
    used = set()
    for node in ast.walk(parse(SRC / "service.py")):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "_audit"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "self"
        ):
            used.add(node.attr)
    assert used and used <= allowed, used


def test_the_audit_package_imports_nothing_from_the_classification_path():
    allowed_relative = {
        "..address_policy", ".errors", ".privacy", ".retention", ".schema", ".store", ".",
    }
    for path in AUDIT.glob("*.py"):
        for module, _ in imports_of(path):
            if module.startswith("."):
                assert module in allowed_relative, (path.name, module)
            else:
                assert module.split(".")[0] not in {
                    "requests", "socket", "pydantic", "netclass", "urllib", "http",
                }, (path.name, module)


def test_purge_and_erase_are_never_called_outside_the_maintenance_script():
    """Prose may mention purging; only scripts/audit_history.py may call it."""
    for path in SRC.rglob("*.py"):
        if path == AUDIT / "store.py":
            continue
        text = path.read_text(encoding="utf-8")
        assert ".purge(" not in text and "delete_ip" not in text, path
    for script in sorted((ROOT / "scripts").glob("*.py")):
        text = script.read_text(encoding="utf-8")
        if script.name == "audit_history.py":
            continue
        assert ".purge(" not in text and "delete_ip" not in text, script


def test_deletes_happen_only_inside_the_explicit_delete_helper():
    tree = parse(AUDIT / "store.py")
    owners = {}
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(func):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "DELETE FROM" in node.value:
                owners[func.name] = True
    assert set(owners) == {"_delete_where"}
    callers = set()
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for node in ast.walk(func):
            if isinstance(node, ast.Attribute) and node.attr == "_delete_where":
                callers.add(func.name)
    assert callers == {"purge", "delete_ip"}


def test_store_sql_is_constant_text_with_bound_values():
    tree = parse(AUDIT / "store.py")
    allowed_names = {"where", "count_sql"}
    executes = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            executes += 1
            first = node.args[0]
            if isinstance(first, ast.Constant):
                assert isinstance(first.value, str)
            elif isinstance(first, ast.Name):
                assert first.id in allowed_names, first.id
            else:
                assert isinstance(first, ast.JoinedStr), ast.dump(first)
                for part in first.values:
                    if isinstance(part, ast.FormattedValue):
                        assert isinstance(part.value, ast.Name) and part.value.id in allowed_names
    assert executes >= 10


def test_the_where_fragment_is_built_only_from_fixed_clauses():
    tree = parse(AUDIT / "store.py")
    func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_filters"][0]
    appended = [
        n.args[0].value
        for n in ast.walk(func)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "append" and isinstance(n.args[0], ast.Constant)
        and isinstance(n.args[0].value, str) and "?" in n.args[0].value
    ]
    assert sorted(appended) == ["ip = ?", "label = ?", "recorded_at < ?", "recorded_at >= ?"]


def test_local_database_and_secrets_are_git_ignored():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for pattern in ("data/", "*.sqlite3", "*.db", ".env"):
        assert pattern in ignore


def test_env_example_documents_the_audit_settings_and_keeps_them_off():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "NETCLASS_AUDIT_ENABLED=\n" in text
    assert "NETCLASS_AUDIT_RETENTION_DAYS=90\n" in text
    assert "NETCLASS_DB_PATH=data/audit.sqlite3" in text
