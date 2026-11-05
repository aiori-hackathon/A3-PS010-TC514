# Dashboard verification report

Read this before trusting the release. It separates what was run from what was only written, and
who ran it.

## A. Results reported by the project owner (Windows, Python 3.12.10) on the first dashboard package
Not executed by the author of this fix; recorded as reported.
* Manual: dashboard launches and renders; classification and evidence display; audit history;
  Status tab; invalid-IP validation; opt-in audit recording. All passed.
* Automated: **1,028 passed, 3 failed, 2 skipped.** Failures:
  `test_audit_isolation.py::test_only_config_and_service_import_the_audit_package`,
  `test_dashboard_app_smoke.py::test_app_renders_without_a_lookup_or_a_database`,
  `test_dashboard_app_smoke.py::test_invalid_input_is_reported_without_a_lookup`.

## B. Environment of the author of this fix
Linux sandbox, Python 3.12.3. **pydantic, pytest and streamlit are NOT installed and cannot be
installed (no network).** So the three previously failing tests and the full suite could **not**
be run here, in any order or in batches. Nothing in this section claims otherwise.

## C. Executed by the author in this sandbox, with results
| Check | Result |
|-------|--------|
| Every test function in `test_audit_isolation.py` (12), including the corrected one, called directly with Python (no pytest) | 12 / 12 passed |
| Every test function in `test_dashboard_boundaries.py` (9), called directly | 9 / 9 passed |
| `tests/network_guard.py`, exercised with a stand-in for `monkeypatch` on Linux: default blocks loopback connect, `getaddrinfo` and `create_connection`; with loopback allowed: external IPv4/IPv6 connect, DNS names and external `create_connection` still raise `RuntimeError`; `socketpair`, a TCP loopback connect/accept round trip and `getaddrinfo` for loopback/None work; the patch is fully undone | 11 / 11 checks passed |
| `python -m compileall -q src scripts tests app.py` | OK |

Caveats: the direct-call runs are not pytest runs (no fixtures/collection). On Linux `socketpair`
is AF_UNIX, so it does not by itself reproduce the Windows path; the loopback TCP round trip
exercises the same `connect` guard that Windows' emulated socketpair uses. The earlier 40-assertion
ad-hoc check of the dashboard logic was also re-run after the changes (not part of this fix's scope
but still passing).

## D. Written but NOT executed (need pytest/pydantic/streamlit)
* `tests/test_network_guard.py` (5 tests): the pytest-fixture side of the guard (marker handling).
* The two smoke tests in `tests/test_dashboard_app_smoke.py` with the new `allow_loopback` marker:
  whether Streamlit's AppTest then passes on your machine is **unverified**. If it still fails,
  the failure will be a different one from the socket-pair error; report its text.
* `tests/test_dashboard_logic.py` and all earlier tests: unchanged by this fix, not run here
  (your run above is the only evidence for them).

## E. What to run (Windows PowerShell)
```powershell
python -m pytest tests\test_audit_isolation.py tests\test_dashboard_boundaries.py tests\test_network_guard.py tests\test_dashboard_app_smoke.py -v
python -m pytest -v
```
Expected, if the fix is right: the 3 formerly failing tests pass; total = your previous 1,028 + 3
newly passing + the 14 added tests (9 boundary, 5 network-guard) = about 1,045 passed, 2 skipped,
0 failed. That figure is an expectation, not a result.

## F. Known limitations
* Item D's smoke-test outcome is unverified until you run it.
* The loopback allowance is test-only and does not touch application code.
* Everything in `docs/RELEASE_NOTES.md` under "Local dashboard" design decisions still applies.
