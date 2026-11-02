# Stage 5: SQLite audit history (`0.5.0-stage5`)

`POLICY_VERSION = "ps010-policy-1"`, `SERVICE_VERSION = "ps010-service-1"`, the three labels, the nine
reason codes, the evidence adapters, parsers, cache, classifier, `ipinfo.py` and `ripestat.py` are
unchanged. `ServiceResult` has exactly the same fields. No existing test file was edited.

## Added
* `src/netclass/audit/`: `store.py` (`AuditStore`), `schema.py` (versioned migrations),
  `privacy.py` (secret / body scrubbing), `retention.py` (setting parsers), `errors.py`.
  Standard-library `sqlite3` only; no new dependency.
* `service.py`: `ClassificationService.classify_and_record()`, `AuditedResult`, `AuditOutcome`,
  `AuditStatus` (`SAVED` / `FAILED` / `DISABLED`), `audit_enabled` property, optional `audit=`
  constructor / `from_settings` argument.
* `scripts/audit_history.py` (info, list, show, export, purge, delete-ip).
* `classify_ip.py`: `--audit`, `--no-audit`; exit code 5 = classified but not saved.
* Settings: `NETCLASS_AUDIT_ENABLED` (default off), `NETCLASS_AUDIT_RETENTION_DAYS` (default 90;
  0 = keep indefinitely). `NETCLASS_DB_PATH` already existed and is now used.
* Docs: `AUDIT_HISTORY.md`, INTEGRATION_GUIDE section 14, README, `.env.example`.
* Tests: `test_audit_{retention,privacy,schema,store,isolation,config,invariance,
  service_integration,cli}.py`, helper `audit_support.py`.

## Changed (small, additive)
`config.py` (two fields, two parser calls), `service.py` (additions only), `scripts/classify_ip.py`
(the Stage 4 code path is unchanged when auditing is off), `netclass/__init__.py` version.
`http_client.USER_AGENT` was left at `0.4` on purpose (a test pins it and it is not part of this stage).

## Decisions
* Audit is off by default; `classify()` never writes; a database is created only by the first
  successful save.
* Retention runs only through `audit_history.py purge --yes`; never on start-up or open.
* A failed save never hides the classification; it is reported as `FAILED`, logged without record
  contents, and the CLI exits 5. `SAVED` is reported only after the transaction committed.
* Journal mode is SQLite's default (rollback journal), not WAL: one file, no `-wal`/`-shm` side
  files to permission or purge. `secure_delete` is on for writes.
* The Stage 4 `_TtlCache` cleanup was deliberately not done.

## Verification (what was and was NOT run)
Environment: Linux sandbox, Python 3.12.3, SQLite 3.45.1, no network.
* **The Stage 4 suite could not be run.** `pytest` and `pydantic` are not installed in this sandbox
  and could not be installed (no network). The historical "809 passed" is therefore NOT verified here.
* **Run for real** (standard-library code, via a throwaway ad-hoc runner that is not pytest and is
  not shipped): `test_audit_retention`, `test_audit_privacy`, `test_audit_schema`,
  `test_audit_store`, `test_audit_isolation`: **90 passed, 0 failed**. Mutation checks on the audit
  package (inclusive purge cutoff, foreign keys off, append-only trigger removed, scrubbing removed
  for classification / evidence, truncating create with loose permissions, writable dry run,
  accepting a newer schema, default retention 0) each made at least one of these tests fail after two
  gaps were closed with new tests.
* `scripts/audit_history.py` was exercised end to end against the real store with only
  `netclass.config` stubbed (missing database never created, dry-run defaults, retention 0,
  `--days 0` rejected, export refuses to overwrite and writes mode 0600, delete-ip).
* All sources, scripts and tests compile (`compileall`); a crude undefined-name scan of the edited
  files found nothing.
* **Written but NOT executed** (they import pydantic or pytest-only features): `test_audit_config`,
  `test_audit_invariance`, `test_audit_service_integration`, `test_audit_cli`, and every Stage 4
  test. The `service.py` and `classify_ip.py` changes have therefore never been run with the real
  models. Run on your machine: `python -m pytest -q`.
* Not verified: Windows behaviour (permissions are not applied there), any live network request.
