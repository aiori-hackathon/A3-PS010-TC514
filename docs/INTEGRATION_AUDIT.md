# Integration audit (release 0.3.0)

## 0. Read this first: what was and was not executed

| Item | Result |
|------|--------|
| Environment of the audit | Ubuntu 24.04.4 LTS (Linux x86_64), Python 3.12.3, pip 24.0. **Not Windows.** |
| Network in the audit sandbox | None for shell commands (pip could not reach any index). |
| `pytest` and `pydantic` | **Not installed and not installable in the audit sandbox.** |
| Full test suite, before changes | **NOT RUN.** No baseline pass/fail count exists from this audit. |
| Full test suite, after changes | **NOT RUN.** |
| Test counts | **None are claimed by this audit.** Counts quoted in `WORKSTREAM_A_AUDIT.md` (269 / 286) and `RELEASE_NOTES.md` (110 / 97 / 14) were reported by earlier authors. A hand count of the parametrisation grids reproduced 14 (config) and 97 (invariance); the others were not re-derived. |
| Live endpoint checks | **None.** No Tor, X4BNet, az0 or RIPEstat request was made by the code. |
| `python -m compileall` (all of `src`, `scripts`, `tests`, warnings as errors) | Passed. Proves syntax only. |
| Ad-hoc checks that need no third-party packages | Passed (see section 3). These are not the project suite and do not replace it. |
| RIPEstat documentation | Read online on 2026-10-31 (section 5). |

The release therefore has **not** been proven by a green test run. The first thing to do on a
networked Windows machine is section 7. If the suite reports any failure, treat the release as
unverified and report the output.

## 1. Requirement-by-requirement audit

| # | Requirement | Evidence | Status |
|---|-------------|----------|--------|
| 1 | Inspect tree, read modules/config/docs/tests | Read in full: every module in `src/netclass` except `inspection.py` (header and imports only) and `adapters/` helpers beyond those listed; all three scripts; README, `.env.example`, RIPESTAT_CONTEXT, RELEASE_NOTES, INTEGRATION_GUIDE; `conftest.py`, `fakes.py`, `support.py` (first 60 lines), `ripestat_support.py`, `test_ripestat_invariance.py`, `test_ripestat_config.py`. Inspected structurally or by search only: the other test files (including `test_ripestat_service.py`), `DATA_SOURCES.md`, `WORKSTREAM_A_AUDIT.md`. No stray files in the archive | Partly (see left) |
| 2 | Baseline test run before changes | Impossible in sandbox (section 0) | **Not done** |
| 3 | Policy-refinement rules and tests still present | `classifier.py` has no RIPEstat reference; `adapters/tor.py`, `adapters/az0.py` IPv4-not-covered rules and `x4bnet.py` IPv6 Apple-gap recording present; `tests/test_workstream_a_audit.py` present | Verified by reading; tests not run |
| 4 | RIPEstat strictly contextual | `ripestat.py` imports no classifier/label/evidence types (static check, also pinned by an AST test); `hosting_indicator=False` appears once and `=True` never; `classify_with_context` passes only `NetworkContext`; `test_ripestat_invariance.py` compares full classifier output with and without context over an 8-scenario x 6-holder grid | Verified by reading + static check; tests not run |
| 5 | Imports, interfaces, config, types, errors, timestamps, cache | Reviewed; see section 2 | Verified by reading |
| 6 | Labels exact | Regex check of `models.Label`: `Known Tor exit`, `Known hosted VPN/proxy endpoint`, `Unknown` | Verified (executed) |
| 7 | Unavailable/stale/missing/malformed/conflicting evidence never negative | Adapters raise `SourceError` -> `SOURCE_UNAVAILABLE`; classifier counts a kind as covered only by an applicable `NO_MATCH`; conflicts -> `Unknown` | Verified by reading |
| 8 | Apple exclusions, IPv4/IPv6 coverage, exact CIDR, provenance, UTC, SHA-256 | `x4bnet.py` subtracts exact apple CIDRs and fails closed if the exclusion list cannot load; `CidrSet` exact matching and SHA-256 helpers executed ad hoc; UTC enforced by `_require_utc`/`_utc` validators | Verified (partly executed) |
| 9 | ASN/hosting/data-centre cannot establish VPN | RIPEstat cannot set a hosting indicator; a hosting indicator can only produce `UNKNOWN_HOSTING_ONLY`; datacenter lists never fetched (`sources.py`) | Verified by reading |
| 10 | Unit tests need no internet | `tests/conftest.py` autouse fixture blocks `socket.connect`, `getaddrinfo`, `create_connection`; fetchers are fakes or a stub `requests` transport; the only `requests.get` in tests is the guard test that expects failure | Verified by reading |
| 11 | No weakened/deleted/skipped tests | No test file was modified in this audit | Verified |
| 12 | Docs match code | Fixed items in section 2 | Done |
| 13 | No secrets/venv/reports/datasets in ZIP | Pattern scan found only variable names and comments; no `.env`, `.venv`, `data/`, `*.sqlite3`, `*.bin`, `__pycache__`, or file over 100 KB | Done |

## 2. Findings

### Fixed (all low risk; no logic change)
1. `ripestat.py` comment pointed to a nonexistent `build_ripestat_service`. Corrected.
2. `http_client.USER_AGENT` still said `0.2` while the project is `0.3.x`. Updated (`test_http_client.py` compares against the constant, not a literal).
3. `__version__` bumped to the 0.3.0 release identifier.
4. Documentation claims not supported by evidence: README "exercised live in the development sandbox" and INTEGRATION_GUIDE section 11 (now attributed to earlier authors and marked not re-checked); stale "Expected: 286 passed"; README layout and roadmap.
5. Missing caveat for RIPEstat `announced` (transit-only ASNs report `false`).

### Observed, deliberately NOT changed (design decisions or no demonstrated defect)
* If one evidence kind's source is down, a positive match of the other kind still stands, with the outage listed in `caveats`. Documented policy, not silent.
* `UNKNOWN_HOSTING_ONLY` is unreachable through RIPEstat by design.
* `NETCLASS_RIPESTAT_CACHE_TTL_SECONDS` is parsed through an integer cast, so `0.5` becomes `0` and disables the cache. This errs on the side of fresher data and is harmless; `0` itself is rejected from the environment.
* The service cache compares the fetcher's `retrieved_at` with the service clock. `build_context_service` gives both the same clock; a custom fetcher with a different clock could mis-age entries.
* `classify_with_context` calls `ripe.to_network_context()` without a guard. No input that makes it raise was found (ASN range and prefix are validated upstream), so no change was made.
* RIPEstat error bodies and `Retry-After` are not read (the shared fetcher raises first). Documented.
* Historical lookups: RIPEstat context describes routing at retrieval time only.

## 3. Executed ad-hoc checks (Linux, Python 3.12.3, stdlib only)

Run with `PYTHONPATH=src`. They are not part of the repository and are not a substitute for the suite:
* Address policy: global v4/v6 allowed; private, loopback, link-local, CGNAT, documentation, multicast, ULA, `::1`, `0.0.0.0` excluded; `::ffff:8.8.8.8` normalised to `8.8.8.8`; empty, CIDR, scoped, port, junk and non-string inputs are INVALID.
* Hashing: SHA-256 of empty input; `verify_sha256` rejects malformed digests; manifest hash independent of order.
* Parsers: exact CIDR boundaries (`104.28.28.63` in `/26`, `.64` not); `has_network` exact-prefix test used for Apple exclusion; HTML, host-bits-set CIDR, `0.0.0.0/0`, empty and NUL-byte bodies all rejected; CIDR rejected in an exact-address list.
* Static: `ripestat.py` import set contains none of the forbidden classification names, `requests` or `socket`.

## 4. Architecture and evidence flow

```
Observation(ip, observed_at UTC)
   |
   +--> address_policy.assess_address  -- non-global/invalid -> Unknown (no lookups at all)
   |
   +--> collector.collect_evidence --> adapters (Tor | X4BNet+Apple exclusion | az0)
   |        SnapshotProvider: cache-first, TTL, parse-before-cache, SHA-256 verified
   |        every failure -> EvidenceRecord(SOURCE_UNAVAILABLE), never NO_MATCH
   |
   +--> (optional) RipeStatContextService.lookup  -- separate fetcher, separate in-memory cache
   |        -> RipeStatContext -> to_network_context() (hosting_indicator=False)
   |
   v
classifier.classify(observation, evidence, context)   pure function
   1 excluded address  2 temporal applicability  3 conflicts  4 single match -> label
   5 otherwise Unknown with prioritised reason
   network_context is copied to the result for display only
```
Only evidence records can produce `Known Tor exit` or `Known hosted VPN/proxy endpoint`.

## 5. Official RIPEstat endpoints and documentation

Base `https://stat.ripe.net/data` (HTTPS enforced, configurable).
* `GET /data/network-info/data.json?resource=<ip>[&sourceapp=<id>]` (v1.1 current; output `asns`, `prefix`; based on RISwhois 8-hourly dumps): https://stat.ripe.net/docs/data-api/api-endpoints/network-info/
* `GET /data/as-overview/data.json?resource=AS<n>[&sourceapp=<id>]` (v1.3 current, 2.1 also listed; output `holder`, `announced`, `resource`): https://stat.ripe.net/docs/data-api/api-endpoints/as-overview/
* About the Data API (envelope `status` ok/error/maintenance, `sourceapp`): https://stat.ripe.net/docs/data-api/ripestat-data-api/
* Legal information: https://stat.ripe.net/docs/legal-information/

## 6. Known limitations and what needs your Windows machine

* The full test suite on Windows and Python 3.12 (before/after counts; none exist from this audit).
* Live RIPEstat behaviour (real response shapes, unrouted address behaviour, HTTP 429 behaviour).
* Live Tor Project endpoint (format, IPv6 content, size) and a fresh live run of the X4BNet and az0 sources.
* Real overlap of Tor exits inside X4BNet ranges (`inspect_sources.py --json`).
* Sanity floors for the Tor list are loose (10) until a live count is known.
* All three evidence sources are current-only; historical observation times are `UNKNOWN_STALE_EVIDENCE`.
* At the time of this audit SQLite audit history and the Streamlit dashboard were not implemented;
  both have since been added (see `docs/RELEASE_NOTES.md`). Models and results are frozen,
  JSON-serialisable and UTC-based, and `db_path` was already in `Settings`.

## 7. Windows PowerShell

```powershell
# 1. Extract (adjust the path to where you saved the ZIP)
Get-FileHash .\viltrumites-ps010.zip -Algorithm SHA256
Expand-Archive -Path .\viltrumites-ps010.zip -DestinationPath . -Force
cd .\viltrumites-ps010

# 2. Python 3.12 virtual environment and dependencies
py -3.12 --version
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
python --version; pip list

# 3. All tests (no internet needed). Keep the output.
python -m pytest -v 2>&1 | Tee-Object test-results.txt
python -m pytest -q

# 4. Live checks (internet needed)
Copy-Item .env.example .env
python scripts\inspect_sources.py --json inspection-report.json
python scripts\classify_ip.py 8.8.8.8 --evidence
python scripts\classify_ip.py 8.8.8.8 --context
python scripts\ripestat_context.py 8.8.8.8
python scripts\ripestat_context.py 2606:4700:4700::1111
python scripts\ripestat_context.py 10.0.0.1    # excluded address: NOT_QUERIED, exit code 3
$LASTEXITCODE
```
`ripestat_context.py` exit codes: 0 usable context, 1 unavailable or invalid input, 3 not queried.
