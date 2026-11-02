# Stage 4: optional IPinfo + service layer (`0.4.0-stage4`)

Policy labels, reason codes and `POLICY_VERSION = "ps010-policy-1"` are unchanged.
No classification rule, adapter, parser, cache or classifier code was modified.

## Added
* `src/netclass/ipinfo.py`: IPinfo Lite metadata service (details: `docs/IPINFO_CONTEXT.md`).
* `src/netclass/service.py`: `ClassificationService` / `ServiceResult` (`service_version = "ps010-service-1"`).
* `collector.build_ipinfo_service`; `scripts/ipinfo_context.py`; `classify_ip.py --ipinfo`.
* Settings `ipinfo_base_url`, `ipinfo_cache_ttl_seconds`, property `ipinfo_enabled`
  (`IPINFO_TOKEN` and `Settings.ipinfo_token` already existed).
* Tests: `test_ipinfo_service.py`, `test_ipinfo_config.py`, `test_service_layer.py`,
  `test_cli_compat.py`, helper `ipinfo_support.py`.

## Changed (small, backward compatible)
* `http_client.RequestsFetcher`: optional `extra_headers` (default none; defaults unchanged).
  `USER_AGENT` version `0.3` -> `0.4`; `__version__` -> `0.4.0-stage4`.
* `scripts/classify_ip.py` now calls the service layer. Output keys and values without `--ipinfo`
  are unchanged (A/B checked against the Stage 3C script, see below); `ipinfo_metadata` appears only
  with `--ipinfo`.
* `.env.example`, `README.md`, `docs/INTEGRATION_GUIDE.md`.
* No existing test file was edited.

## Design notes
* `ipinfo.py` reuses `_TtlCache`, `_clean_text`, `_parse_asn` from `ripestat.py` instead of copying
  them. A shared module is a reasonable Stage 5 cleanup.
* There is no retry layer in the project, so none was added; a 429 is reported, not retried.

## Verification (Linux, Python 3.12.3, pydantic 2.14.2, requests 2.33.1, pytest 9.2.0; 2026-10-31)
* Baseline on the untouched Stage 3C tree: **507 passed**.
* After Stage 4: **809 passed** (`python -m pytest -q`).
* Mutation spot checks (broken redaction, disabled exclusion guard, cached failures, IPinfo text
  leaking into the classification, removed failure containment) each made tests fail.
* A/B: original and new `classify_ip.py` run against the same fake world, 36 invocations (9 inputs x
  4 flag sets): exit code, stdout and stderr identical.
* Real scripts in a sandbox whose egress allowed GitHub but not Tor Project, RIPEstat or IPinfo:
  X4BNet and az0 loaded live; the blocked hosts gave `SOURCE_UNAVAILABLE` / `UNAVAILABLE` as
  documented; `8.8.8.8` stayed `Unknown` with identical label and reason with IPinfo disabled, enabled
  (fake token, blocked host) and not requested; `10.0.0.1` sent no request; the fake token never
  appeared in output.
* **Not verified:** any successful live IPinfo, RIPEstat or Tor Project response; behaviour on
  Windows. Run on your machine: `python -m pytest -q`, `python scripts\ipinfo_context.py 8.8.8.8`.

## Remains for Stage 5 and later
SQLite audit history (Stage 5), Streamlit dashboard (Stage 6), live end-to-end verification and
final README (Stage 7). None of these is started.
