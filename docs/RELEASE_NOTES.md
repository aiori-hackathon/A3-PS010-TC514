# Release notes

The policy labels, the nine reason codes and `POLICY_VERSION = "ps010-policy-1"` are identical in
every release listed here; no release changed a classification rule unless its section says so.
Package versions before 0.7.0 are listed without the build suffix they carried at the time. The
current package version string is defined in `src/netclass/__init__.py`: a test pins it and the
committed evaluation report embeds it, so it changes only together with a regenerated report.

Newest first.

## Source health and live verification

Adds per-source health reporting and a bounded, opt-in live check. See `docs/SOURCE_HEALTH.md`,
`docs/LIVE_VERIFICATION.md`, `docs/EVIDENCE_POLICY.md` and `docs/SOURCE_HEALTH_VERIFICATION.md`.

Added:
* `redaction.py`: shared redaction of URL credentials and queries, bearer tokens, key=value secrets
  and sensitive headers.
* `source_health.py`: health states (`HEALTHY`, `SOURCE_FAILURE`, `STALE`, `PARSE_FAILURE`,
  `INSUFFICIENT_EVIDENCE`, `NOT_CHECKED`), `absence_support`, `SourceHealthRecord`.
* `live_verify.py`, `live_targets.py`, `scripts/verify_sources.py`: explicit, bounded live check
  (`--live`, request budget, hard ceilings); timestamped, redacted JSON and Markdown reports;
  per-file provenance; combined az0 floor check; Tor/VPN/Apple overlap counts.
* Tests: HTTP hardening, redaction, live-verification engine and CLI, target equivalence with the
  adapters, retry configuration and the evidence-policy edge cases.

Changed (labels and reason codes unaffected):
* `http_client.py`: bounded retries (at most 2; timeouts, connection errors, 429, 5xx; `Retry-After`
  honoured within the deadline); manual redirect handling with an HTTPS check on every hop and no
  credential forwarding to other origins; incomplete-download detection via Content-Length; an
  optional hard request budget; redacted errors; User-Agent version `0.4` -> `0.7`. The class
  default is `max_retries=0`.
* `errors.py`: `SourceError` gained optional `retryable` and `retry_after` fields (default off).
* `config.py`, `collector.py`, `.env.example`, `scripts/inspect_sources.py`: new
  `NETCLASS_HTTP_MAX_RETRIES` (default 2, range 0-2) for the three evidence sources only.
* `cache.py`, `snapshots.py`: warning logs print redacted URLs and messages.

Not changed: `classifier.py`, `models.py`, `service.py`, `address_policy.py`, the audit package,
RIPEstat and IPinfo behaviour (context only, still no retries), existing tests, `evaluation/`.

Baseline and rollback: the change set was built on commit `21975513e81f2f68b3164fa6eddb8d1772ec16c7`
(release archive SHA-256 `4183fb74acddd4ea235e288f33a3a96d859cf271653ffb8f6e688add85718bcc`).
It adds files and makes small additive edits only, and it changes no stored data or schema, so it can
be rolled back by reverting its commits (`git revert`); the baseline commit, archive and evaluation
reports are not modified by it. `tests/test_evaluation_isolation.py` pins the package version string.

## Evaluation framework (0.7.0)

Reproducible evaluation of the existing pipeline. See `docs/EVALUATION.md` and
`docs/EVALUATION_VERIFICATION.md`. The classifier, adapters, parsers, cache, `service.py`,
`collector.py`, `ripestat.py`, `ipinfo.py`, the audit package and schema, `config.py`, every CLI
script and the dashboard are unchanged. No existing test file was edited or removed.

Added:
* `src/netclass/evaluation/`: `dataset.py` (strict schema, loader, validator, canonical hash),
  `metrics.py` (denominators, selective classification, warnings), `report.py` (JSON + Markdown),
  `replay.py` (offline fetcher serving fixture worlds), `runner.py` (replay and live modes). The
  first three need only the standard library.
* `scripts/evaluate.py`: the evaluation command.
* `evaluation/datasets/ps010-eval-v1/`: `dataset.json` (42 synthetic cases, 11 fixture worlds, no
  reference cases), `README.md`, `PROVENANCE.md`.
* `evaluation/reports/ps010-eval-v1-replay.{json,md}`: release-evidence reports, checked by a test.
* Tests: `test_evaluation_metrics.py`, `test_evaluation_dataset.py`, `test_evaluation_runner.py`,
  `test_evaluation_isolation.py`, `test_evaluation_cli.py`, helper `evaluation_support.py`.

Changed:
* `netclass/__init__.py`: `__version__` `0.6.0` -> `0.7.0-stage7`; shown on the dashboard Status tab.
* `.gitignore`: ignores `evaluation/output/` and `evaluation/output-live/` (not `evaluation/reports/`).

Design decisions:
* No second classifier: the runner only calls `ClassificationService.classify`; a test compares
  every case with `classify_with_evidence` over the same adapters.
* Synthetic and reference results never share a metric block; synthetic results are labeled policy
  conformance and cannot be presented as accuracy.
* An unlabeled case needs a reason, is listed, and is never scored.
* Isolation by construction and by test: the package imports nothing from the audit, dashboard,
  network, database or `.env` code, and the service is built with `audit=None`.
* The label, reason-code, source-name and tolerance constants duplicated in `dataset.py` (to keep it
  pydantic-free) are pinned to the real ones by a test.
* Fixture sanity floors are lowered to 1 in replay and recorded in every report.

Documented conflicts with the existing architecture (nothing changed):
* `UNKNOWN_HOSTING_ONLY` is unreachable through the service, so it is not evaluated end to end.
* No source has validity intervals, so historical ground truth cannot be source-backed.
* Two conservative-but-surprising behaviours are recorded as observations in `docs/EVALUATION.md`.
* `tests/test_audit_isolation.py` pins the exact set of modules that import the audit package; the
  evaluation package adds none.

## Local dashboard (0.6.0)

Streamlit dashboard over the existing service and audit store. See `docs/DASHBOARD_VERIFICATION.md`.
The classifier, adapters, parsers, cache, `ripestat.py`, `ipinfo.py`, the audit package, `config.py`,
`ServiceResult` and every CLI script are unchanged. No existing test file was edited. No store
method was added: the dashboard uses `AuditStore.info`, `list_runs` and `get_run` as they are.

Added:
* `app.py`: Streamlit entry point (`python -m streamlit run app.py`). Importing it starts nothing.
* `src/netclass/dashboard/logic.py`: UI-free logic (input validation, classification through
  `ClassificationService`, audit opt-in handling, read-only history, diagnostics, safe text).
* `src/netclass/dashboard/ui.py`: the Streamlit page (Classify / Audit history / Status tabs).
* `.streamlit/config.toml`: binds to 127.0.0.1, headless, no usage statistics.
* `requirements.txt`: `streamlit>=1.40,<2` (application dependency). `requirements-dev.txt` unchanged.
* Tests: `tests/test_dashboard_logic.py`, `tests/test_dashboard_app_smoke.py` (skipped without Streamlit).

Changed: `__version__` `0.5.0` -> `0.6.0`; `.gitignore` adds `.streamlit/secrets.toml`.

Design decisions:
* **Audit opt-in is per classification** and needs two ticks (opt in + privacy acknowledgement).
  The dashboard overrides `audit_enabled` for the call to match that choice, so
  `NETCLASS_AUDIT_ENABLED=true` in the environment cannot make it write silently. Recording goes
  through `ClassificationService.classify_and_record` only.
* **Excluded addresses** (private, loopback, link-local, ...) still go through the existing service,
  which returns the policy's own `Unknown` / `UNKNOWN_EXCLUDED_ADDRESS` without any lookup. The
  dashboard additionally never requests RIPEstat or IPinfo for them, and says why collection was
  skipped.
* **Pagination** uses a one-row look-ahead (`limit = page_size + 1`) instead of a new COUNT method,
  so the store needed no change. Page sizes are 10/25/50/100; page numbers are capped at 10,000.
* **Error text**: unexpected classification failures show only the exception type name, never its
  message (messages can carry request details). Configuration errors name the setting, not its
  value. The database path is replaced by `<audit database>` in audit-related messages.
* A fresh service is built for every Classify press; nothing is cached across sessions, and the only
  Streamlit session state is the last result shown to that browser session.

Test-side fixes after the first Windows run (same version): 1,028 passed, 3 failed, 2 skipped. All
three failures were test-side issues; no product code, label, policy, schema, retention rule or CLI
behaviour changed.
1. `test_audit_isolation.py::test_only_config_and_service_import_the_audit_package`: the dashboard's
   read-only history view legitimately imports the audit package. The test is renamed
   `test_only_config_service_and_the_dashboard_logic_import_the_audit_package`
   and the closed set of importers is `config.py`, `service.py`, `dashboard/logic.py`. Every other
   test in that file is untouched. New `tests/test_dashboard_boundaries.py` pins, by AST: the exact
   names `dashboard/logic.py` may import; that it calls only `info`, `list_runs`, `get_run` (and
   `path`) on the store, with no record/purge/delete/export name anywhere in the dashboard; that the
   only write path is `classify_and_record` under the confirmed opt-in branch; that `audit_enabled`
   is always derived from the confirmed choice; that the UI module touches no audit or
   classification internals; that nothing in the classification path or the audit package imports
   the dashboard; and that Streamlit is imported only by `ui.py`.
2. `test_dashboard_app_smoke.py` (both tests): Windows asyncio builds a local socket pair by
   connecting over loopback, which the autouse guard blocked. The guard now lives in
   `tests/network_guard.py`; `conftest.py` calls it. Default behaviour is unchanged (everything
   blocked). Tests marked `@pytest.mark.allow_loopback` (registered in `pytest.ini`, used only by the
   smoke tests) may connect to this machine only: loopback IP literals, `localhost`, local paths.
   Any other host, any name needing DNS and `create_connection` to external addresses still raise.
   New `tests/test_network_guard.py` pins both sides. The smoke tests are not skipped.

## Audit history (0.5.0)

Optional SQLite audit history. See `docs/AUDIT_HISTORY.md`. `SERVICE_VERSION = "ps010-service-1"`,
the three labels, the nine reason codes, the evidence adapters, parsers, cache, classifier,
`ipinfo.py` and `ripestat.py` are unchanged. `ServiceResult` has exactly the same fields. No
existing test file was edited.

Added:
* `src/netclass/audit/`: `store.py` (`AuditStore`), `schema.py` (versioned migrations), `privacy.py`
  (secret / body scrubbing), `retention.py` (setting parsers), `errors.py`. Standard-library
  `sqlite3` only; no new dependency.
* `service.py`: `ClassificationService.classify_and_record()`, `AuditedResult`, `AuditOutcome`,
  `AuditStatus` (`SAVED` / `FAILED` / `DISABLED`), `audit_enabled` property, optional `audit=`
  constructor / `from_settings` argument.
* `scripts/audit_history.py` (info, list, show, export, purge, delete-ip).
* `classify_ip.py`: `--audit`, `--no-audit`; exit code 5 = classified but not saved.
* Settings: `NETCLASS_AUDIT_ENABLED` (default off), `NETCLASS_AUDIT_RETENTION_DAYS` (default 90;
  0 = keep indefinitely). `NETCLASS_DB_PATH` already existed and is now used.
* Tests: `test_audit_{retention,privacy,schema,store,isolation,config,invariance,service_integration,cli}.py`,
  helper `audit_support.py`.

Changed (small, additive): `config.py` (two fields, two parser calls), `service.py` (additions
only), `scripts/classify_ip.py` (the unaudited code path is unchanged when auditing is off),
`netclass/__init__.py` version. `http_client.USER_AGENT` was left unchanged on purpose (a test pins it).

Decisions:
* Audit is off by default; `classify()` never writes; a database is created only by the first
  successful save.
* Retention runs only through `audit_history.py purge --yes`; never on start-up or open.
* A failed save never hides the classification; it is reported as `FAILED`, logged without record
  contents, and the CLI exits 5. `SAVED` is reported only after the transaction committed.
* Journal mode is SQLite's default (rollback journal), not WAL: one file, no `-wal`/`-shm` side
  files to permission or purge. `secure_delete` is on for writes.
* The shared `_TtlCache` cleanup between `ripestat.py` and `ipinfo.py` was deliberately not done.

Verification of this release (Linux sandbox, Python 3.12.3, SQLite 3.45.1, no network):
* The earlier suite could not be run there: `pytest` and `pydantic` were not installable. The
  previously reported 809 passes are therefore not verified by this run.
* Run for real (standard-library code, via a throwaway ad-hoc runner that is not pytest and is not
  shipped): `test_audit_retention`, `test_audit_privacy`, `test_audit_schema`, `test_audit_store`,
  `test_audit_isolation`: 90 passed, 0 failed. Mutation checks on the audit package (inclusive purge
  cutoff, foreign keys off, append-only trigger removed, scrubbing removed for classification /
  evidence, truncating create with loose permissions, writable dry run, accepting a newer schema,
  default retention 0) each made at least one of these tests fail after two gaps were closed with
  new tests.
* `scripts/audit_history.py` was exercised end to end against the real store with only
  `netclass.config` stubbed (missing database never created, dry-run defaults, retention 0,
  `--days 0` rejected, export refuses to overwrite and writes mode 0600, delete-ip).
* All sources, scripts and tests compile (`compileall`); a crude undefined-name scan of the edited
  files found nothing.
* Written but not executed there (they import pydantic or pytest-only features): `test_audit_config`,
  `test_audit_invariance`, `test_audit_service_integration`, `test_audit_cli`, and every IPinfo and
  service-layer test. The `service.py` and `classify_ip.py` changes had therefore not been run with
  the real models in that environment.
* Not verified: Windows behaviour (permissions are not applied there), any live network request.

## Service layer and IPinfo metadata (0.4.0)

Optional IPinfo Lite metadata and a service layer. See `docs/IPINFO_CONTEXT.md`. No classification
rule, adapter, parser, cache or classifier code was modified.

Added:
* `src/netclass/ipinfo.py`: IPinfo Lite metadata service.
* `src/netclass/service.py`: `ClassificationService` / `ServiceResult`
  (`service_version = "ps010-service-1"`).
* `collector.build_ipinfo_service`; `scripts/ipinfo_context.py`; `classify_ip.py --ipinfo`.
* Settings `ipinfo_base_url`, `ipinfo_cache_ttl_seconds`, property `ipinfo_enabled`
  (`IPINFO_TOKEN` and `Settings.ipinfo_token` already existed).
* Tests: `test_ipinfo_service.py`, `test_ipinfo_config.py`, `test_service_layer.py`,
  `test_cli_compat.py`, helper `ipinfo_support.py`.

Changed (small, backward compatible):
* `http_client.RequestsFetcher`: optional `extra_headers` (default none; defaults unchanged).
  `USER_AGENT` version `0.3` -> `0.4`.
* `scripts/classify_ip.py` calls the service layer. Output keys and values without `--ipinfo` are
  unchanged (A/B checked, see below); `ipinfo_metadata` appears only with `--ipinfo`.
* `.env.example`, `README.md`, `docs/INTEGRATION_GUIDE.md`. No existing test file was edited.

Design notes:
* `ipinfo.py` reuses `_TtlCache`, `_clean_text`, `_parse_asn` from `ripestat.py` instead of copying
  them. Moving them to a shared module is a reasonable cleanup.
* There was no retry layer at this release, so none was added; a 429 is reported, not retried.

Verification (Linux, Python 3.12.3, pydantic 2.14.2, requests 2.33.1, pytest 9.2.0; 2026-10-31):
* Baseline on the untouched previous tree: 507 passed. After this release: 809 passed
  (`python -m pytest -q`).
* Mutation spot checks (broken redaction, disabled exclusion guard, cached failures, IPinfo text
  leaking into the classification, removed failure containment) each made tests fail.
* A/B: original and new `classify_ip.py` run against the same fake world, 36 invocations (9 inputs x
  4 flag sets): exit code, stdout and stderr identical.
* Real scripts in a sandbox whose egress allowed GitHub but not Tor Project, RIPEstat or IPinfo:
  X4BNet and az0 loaded live; the blocked hosts gave `SOURCE_UNAVAILABLE` / `UNAVAILABLE` as
  documented; `8.8.8.8` stayed `Unknown` with identical label and reason with IPinfo disabled,
  enabled (fake token, blocked host) and not requested; `10.0.0.1` sent no request; the fake token
  never appeared in output.
* Not verified: any successful live IPinfo, RIPEstat or Tor Project response; behaviour on
  Windows. Run on your machine: `python -m pytest -q`, `python scripts\ipinfo_context.py 8.8.8.8`.

## Integration audit (0.3.0)

Documentation and housekeeping release; no architecture change, no feature added, no test changed.
Details: `docs/INTEGRATION_AUDIT.md`.
* `src/netclass/ripestat.py`: corrected a stale comment (`build_ripestat_service` does not exist;
  the function is `collector.build_context_service`). Comment only.
* `src/netclass/http_client.py`: `USER_AGENT` version `0.2` -> `0.3` (the string is sent to every
  source, including RIPEstat). `tests/test_http_client.py` compares against the constant.
* `README.md`, `docs/INTEGRATION_GUIDE.md`, `docs/WORKSTREAM_A_AUDIT.md`: removed or qualified
  claims not supported by the evidence available (hard-coded test totals, "verified live"
  statements by earlier authors); fixed layout and a stale "Expected: 286 passed".
* `docs/RIPESTAT_CONTEXT.md`: added the documented caveat that `announced=false` also covers
  transit-only ASNs; recorded the documentation re-check.
* `.gitignore`: also ignores `inspection-report.json`, `test-results.txt`, `*.egg-info/`.

## RIPEstat network context (0.3.0)

Details: `docs/RIPESTAT_CONTEXT.md`.
* `src/netclass/ripestat.py`: client and service for the documented `network-info` and `as-overview`
  data calls; typed errors; in-memory TTL cache; provenance with SHA-256 of the raw response.
* `collector.py`: `build_context_service`, `classify_with_context` (new functions only).
* `config.py`: `ripestat_sourceapp`, `ripestat_cache_ttl_seconds`; HTTPS and `sourceapp` validation.
  `.env.example`: `NETCLASS_RIPESTAT_SOURCEAPP`, `NETCLASS_RIPESTAT_CACHE_TTL_SECONDS`.
* `scripts/ripestat_context.py`; `scripts/classify_ip.py --context` (opt-in; default behaviour
  unchanged).
* Tests: `tests/test_ripestat_service.py` (110), `tests/test_ripestat_invariance.py` (97),
  `tests/test_ripestat_config.py` (14), helper `tests/ripestat_support.py`.
* RIPEstat output is metadata only: never an `EvidenceRecord`, never a label or reason code,
  `hosting_indicator` always `False`.
* Not changed (deliberately): `classifier.py`, `models.py`, `errors.py`, `http_client.py`,
  `sources.py`, all adapters, the policy-refinement tests, `POLICY_VERSION`, the three labels and
  reason codes. RIPEstat is not registered in `SOURCES` because it is not an evidence source.
* Known consequence of the design: `UNKNOWN_HOSTING_ONLY` can no longer be reached through RIPEstat,
  because the service never sets a hosting indicator. It stays reachable only by a future explicit,
  non-RIPEstat hosting source.

## Policy refinement and source quality

Details: `docs/WORKSTREAM_A_AUDIT.md`.
* Tor + VPN evidence stays `Unknown` / `UNKNOWN_CONFLICTING_EVIDENCE` (documented, tested).
* `adapters/tor.py`, `adapters/az0.py`: an IPv4 query against a source holding no IPv4 entries is
  `NOT_CONFIGURED` ("IPv4 not covered"), mirroring the existing IPv6 rule. Never a negative.
* `adapters/x4bnet.py`: if the Apple exclusion list holds no IPv6 CIDRs, the IPv6 gap is recorded in
  metadata and limitations.
* `inspection.py`: Tor-in-X4BNet overlap detail, per-CIDR counts, sanity-floor headroom.
* `tests/test_workstream_a_audit.py`: 17 added tests on a baseline of 269 (286 in total at that
  time). No earlier test was edited or removed. `classifier.py` untouched.
