# Stage 6: local Streamlit dashboard (`0.6.0-stage6`)

`POLICY_VERSION = "ps010-policy-1"`, `SERVICE_VERSION = "ps010-service-1"`, the three labels, the
nine reason codes, adapters, parsers, cache, classifier, `ripestat.py`, `ipinfo.py`, the audit
package (`store.py`, `schema.py`, `privacy.py`, `retention.py`), `ServiceResult`, `config.py` and
every CLI script are **unchanged**. No existing test file was edited. No store method was added:
the dashboard uses `AuditStore.info`, `list_runs` and `get_run` as they are.

## Added
* `app.py`: Streamlit entry point (`python -m streamlit run app.py`). Importing it starts nothing.
* `src/netclass/dashboard/logic.py`: UI-free logic (input validation, classification through
  `ClassificationService`, audit opt-in handling, read-only history, diagnostics, safe text).
* `src/netclass/dashboard/ui.py`: the Streamlit page (Classify / Audit history / Status tabs).
* `.streamlit/config.toml`: binds to 127.0.0.1, headless, no usage statistics.
* `requirements.txt`: `streamlit>=1.40,<2` (application dependency). `requirements-dev.txt` unchanged.
* Tests: `tests/test_dashboard_logic.py`, `tests/test_dashboard_app_smoke.py` (skipped without Streamlit).
* Docs: README dashboard section, this changelog, `STAGE6_VERIFICATION.md`.

## Changed
* `netclass/__init__.py`: `__version__` `0.5.0-stage5` -> `0.6.0-stage6` (no test pins it).
* `.gitignore`: adds `.streamlit/secrets.toml`.

## Design decisions
* **Audit opt-in is per classification** and needs two ticks (opt in + privacy acknowledgement).
  The dashboard always overrides `audit_enabled` for the call to match that choice, so
  `NETCLASS_AUDIT_ENABLED=true` in the environment cannot make it write silently. Recording goes
  through `ClassificationService.classify_and_record` only.
* **Excluded addresses** (private, loopback, link-local, ...) still go through the existing service,
  which returns the policy's own `Unknown` / `UNKNOWN_EXCLUDED_ADDRESS` without any lookup. The
  dashboard additionally never requests RIPEstat/IPinfo for them, and says why collection was skipped.
* **Pagination** uses a one-row look-ahead (`limit = page_size + 1`) instead of a new COUNT method,
  so the store needed no change. Page sizes are 10/25/50/100; page numbers are capped at 10,000.
* **Error text**: unexpected classification failures show only the exception type name, never its
  message (messages can carry request details). Configuration errors name the setting, not its value.
  The database path is replaced by `<audit database>` in audit-related messages.
* A fresh service is built for every Classify press; nothing is cached across sessions, and the only
  Streamlit session state is the last result shown to that browser session.

## Regression fix after the first Windows run (same version, `0.6.0-stage6`)
Your run of the first Stage 6 package: 1,028 passed, 3 failed, 2 skipped. All three failures were
test-side issues; no product code, label, policy, schema, retention rule or CLI behaviour changed.

1. `test_audit_isolation.py::test_only_config_and_service_import_the_audit_package`. The dashboard's
   read-only history view legitimately imports the audit package. The boundary is now explicit:
   the test is renamed `test_only_config_service_and_the_dashboard_logic_import_the_audit_package`
   and the closed set of importers is `config.py`, `service.py`, `dashboard/logic.py`. Every other
   test in that file (classifier/collector/models/etc. never import audit; the service only writes
   to the store; no purge/delete outside the maintenance script; SQL is parameterised) is untouched.
   New `tests/test_dashboard_boundaries.py` pins, by AST: the exact names `dashboard/logic.py`
   may import; that it calls only `info`, `list_runs`, `get_run` (and `path`) on the store, with no
   record/purge/delete/export name anywhere in the dashboard; that the only write path is
   `classify_and_record` under the confirmed opt-in branch; that `audit_enabled` is always derived
   from the confirmed choice; that the UI module touches no audit or classification internals;
   that nothing in the classification path or the audit package imports the dashboard; and that
   Streamlit is imported only by `ui.py`.
2. 3. `test_dashboard_app_smoke.py` (both tests). Windows asyncio builds a local socket pair by
   connecting over loopback, which the autouse guard blocked. The guard now lives in
   `tests/network_guard.py`; `conftest.py` calls it. Default behaviour is unchanged (everything
   blocked). Tests marked `@pytest.mark.allow_loopback` (registered in `pytest.ini`, used only by the
   smoke tests) may connect to this machine only: loopback IP literals, `localhost`, local paths.
   Any other host, any name needing DNS and `create_connection` to external addresses still raise.
   New `tests/test_network_guard.py` pins both sides. The smoke tests are not skipped.
