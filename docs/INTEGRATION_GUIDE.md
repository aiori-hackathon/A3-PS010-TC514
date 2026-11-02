# Integration guide (Stage 2)

How live evidence flows through the project, how to run and verify it on
Windows, and how to extend it.

## 1. Data flow

```
 Observation(ip, observed_at UTC)
        |
        v
 collector.collect_evidence()   <- no lookups at all for private/reserved addresses
        |  one call per enabled adapter
        v
 EvidenceAdapter.lookup(ip)     <- never raises; always returns an EvidenceRecord
        |
        v
 SnapshotProvider.load(url)     <- cache-first, TTL, freshness, parse-before-cache
        |            |
        |            +--> SnapshotStore (data/cache: snapshots/<sha256>.bin, index/*.json)
        v
 RequestsFetcher.fetch(url)     <- timeout, size cap, HTTPS-only redirects, HTTP 200 only
        |
        v
 classifier.classify()          <- Stage 1 rules (unchanged)
```

## 2. How errors become evidence statuses

| Situation | EvidenceStatus | Classifier outcome |
|-----------|----------------|--------------------|
| Source lists the address | MATCH | label for that kind |
| Source loaded fine and does not list it | NO_MATCH | that kind is "covered" |
| Timeout, DNS/TLS failure, HTTP status other than 200 | SOURCE_UNAVAILABLE | Unknown, UNKNOWN_SOURCE_UNAVAILABLE |
| Download larger than the cap | SOURCE_UNAVAILABLE (TOO_LARGE) | same |
| HTML page, junk line, wrong IP family, over-broad CIDR | SOURCE_UNAVAILABLE (MALFORMED) | same |
| No entries, or fewer than the sanity floor | SOURCE_UNAVAILABLE (EMPTY / TOO_SMALL) | same |
| Source's Last-Modified is older than the limit | SOURCE_UNAVAILABLE (STALE_SOURCE) | same |
| Cached copy older than the TTL and refresh failed | SOURCE_UNAVAILABLE (message names the stale copy) | same |
| IPv6 query but the source holds no IPv6 data | NOT_CONFIGURED ("IPv6 not covered") | Unknown, UNKNOWN_PROVIDER_NOT_CONFIGURED |
| Snapshot valid but observation time too far from retrieval | (record is fine) classifier marks it STALE | Unknown, UNKNOWN_STALE_EVIDENCE |

A failed request is never turned into NO_MATCH.

## 3. Conflict and overlap policy (chosen, documented, tested)

* Any applicable Tor match together with any applicable VPN/proxy match
  gives Unknown with UNKNOWN_CONFLICTING_EVIDENCE.
* This holds whether the VPN evidence is range-level (X4BNet) or an exact
  address (az0). Tor never takes precedence, because both are independent
  claims about the same address and neither can be verified here.
* Known cost: X4BNet's inputs include a Tor-exit ASN, so some real Tor exits
  may fall inside its ranges and come out Unknown. Measure this with
  `scripts\inspect_sources.py` before deciding whether to change the policy.
* Known limitation: if one kind's source is down, a positive from the other
  kind still stands, with the outage listed in `caveats`. (Example: Tor list
  unreachable, address inside an X4BNet range: result is Known VPN with a
  caveat naming the Tor list.)
* Tests: `tests/test_collector_overlap.py`, `tests/test_workstream_a_audit.py`.
* Workstream A kept this policy. `inspect_sources.py --json` now breaks the Tor-in-X4BNet overlap down by matched CIDR; see `docs/WORKSTREAM_A_AUDIT.md`.

## 4. Source-specific rules

| Source | Used | Never used |
|--------|------|------------|
| Tor bulk exit list | the list, exact addresses | n/a |
| X4BNet | `output/vpn/ipv4.txt`, `ipv6.txt` (VPN only); `input/vpn/ips/apple.txt` as an exclusion list | `output/datacenter/*`, legacy root lists |
| az0 | `ip/expressvpn.txt`, `hideme.txt`, `hideme_api.txt`, `nordvpn_api.txt`, `pia.txt` | `nordvpn.txt` (DNS resolvers), files that hold only comments |

Apple Private Relay: CIDRs from `apple.txt` are subtracted from the X4BNet
VPN set (they appear verbatim in the merged output). An address matched only
by those ranges is NO_MATCH, with `excluded_by_policy: apple_private_relay`
in the evidence metadata. If `apple.txt` cannot be loaded while an address
matches a VPN range, the result is SOURCE_UNAVAILABLE.

## 5. Setup and commands (Windows PowerShell)

From the project folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

Run the tests (no internet needed; the suite blocks sockets on purpose):

```powershell
python -m pytest -v
```

Verify the live endpoints and measure overlaps (needs internet):

```powershell
python scripts\inspect_sources.py
python scripts\inspect_sources.py --json inspection-report.json
```

Classify an address with live data:

```powershell
python scripts\classify_ip.py 8.8.8.8
python scripts\classify_ip.py 8.8.8.8 --evidence
python scripts\classify_ip.py 2606:4700:4700::1111
```

Exit codes: `inspect_sources.py` returns 0 only if every file loaded;
`classify_ip.py` returns 2 for invalid input.

## 6. Reading the evidence JSON

Every record has: `source_name`, `source_endpoint`, `retrieved_at` (UTC),
`source_timestamp` (null for GitHub files, which send an ETag but no
Last-Modified), `snapshot_sha256`, `status`, `error`, `limitations`, and
`metadata` (granularity, entry counts, matched CIDR/files, per-file URL,
SHA-256, size, ETag, `from_cache`).

For sources made of several files, `snapshot_sha256` is the hash of the sorted
list of (URL, file hash) pairs; the individual file hashes are in
`metadata.files`. To re-check a hash, hash the retained file
`data\cache\snapshots\<sha256>.bin`.

## 7. Cache behaviour

* Reused while younger than `NETCLASS_CACHE_TTL_SECONDS`.
* Re-downloaded afterwards. If that fails, the old copy is NOT used.
* Content-addressed: unchanged lists are stored once; changed lists keep the
  old file so earlier audit hashes stay verifiable. Delete `data\cache` to
  reclaim space at any time.
* A corrupted or tampered cache file fails SHA-256 verification and is
  re-downloaded.
* A download is parsed before it is stored. Bad content is never cached.

## 8. Windows notes

* All paths use `pathlib`; cache file names are plain hex and ASCII.
* Writes are atomic (`os.replace`). If antivirus locks a file, the cache write
  fails with a logged warning and the lookup still succeeds (not retained).
* Behind a proxy, `requests` honours the standard `HTTPS_PROXY` environment
  variable. Corporate TLS inspection can cause CONNECTION errors that mention
  certificates.
* PowerShell may block `Activate.ps1`: run
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

## 9. Adding a source

1. Add a `SourceSpec` in `sources.py` (endpoints, licence, attribution,
   limitations, exclusions).
2. Write a strict parser in `parsers.py` if the format is new.
3. Subclass `EvidenceAdapter`: implement `_lookup()` returning MATCH, NO_MATCH
   or NOT_CONFIGURED, and raise `SourceError` for anything that is not a
   trustworthy answer.
4. Register it in `collector.build_adapters`.
5. Add mocked-HTTP tests, including timeout, HTTP error, malformed, empty,
   stale and overlap cases.

## 10. Licences and bundling

This project ships no data from any source. Downloads go to `data\cache`
(ignored by Git). az0/vpn_ip is GPL-3.0-or-later: do not commit or
redistribute its files with this project. Credit the sources in any report or
UI footer: Tor Project; X4BNet/lists_vpn (MIT, Copyright (c) 2024 X4B, Mathew
Heard); az0/vpn_ip (GPL-3.0-or-later, Copyright (C) 2023-2024 Andrew Ziem).
Not legal advice.

## 11. What is and is not verified

* Covered by mocked tests (no internet): adapters, parsers, cache, freshness, error mapping,
  overlap and conflict policy. The authoritative test count is whatever `python -m pytest` reports
  on your machine; earlier stage documents quote counts that Stage 3C could not re-run (see
  `docs/STAGE3C_AUDIT.md`).
* Reported by the Stage 2 author, not re-checked in Stage 3C: a live run on 2026-10-30 in which the
  X4BNet and az0 GitHub endpoints downloaded and parsed.
* NOT verified live: the Tor Project endpoint (reported unreachable from the earlier sandbox) and the
  RIPEstat endpoints. Format and size are assumed from documentation until you run
  `scripts\inspect_sources.py` and `scripts\ripestat_context.py` on your own machine.

## 12. RIPEstat network context (Stage 3B)

Optional and separate from evidence: `collector.classify_with_context(...)` fetches RIPEstat
ASN/prefix/holder context and passes it to the classifier only as display metadata
(`hosting_indicator` is always False). Labels and reason codes are identical with or without it.
A RIPEstat failure yields an explicit `UNAVAILABLE` context and never affects the label.
Details, schema, errors, cache and freshness: `docs/RIPESTAT_CONTEXT.md`.

## 13. Service layer and IPinfo metadata (Stage 4)

```
 Observation
     |
     v
 ClassificationService.classify(observation, include_ripestat=False, include_ipinfo=False)
     |  1. collector.classify_with_evidence / classify_with_context   (unchanged pipeline)
     |  2. only afterwards, only if asked: IpInfoService.lookup(ip)   (never fed back)
     v
 ServiceResult(classification, evidence, ripestat_context, ipinfo_metadata, service_version)
```

* **Classification first and alone.** `classification` and `evidence` are produced by the existing
  pipeline before IPinfo is consulted. IPinfo output is not an input to anything. Enabling,
  disabling or failing IPinfo cannot change them (pinned by an invariance grid in
  `tests/test_service_layer.py`: 7 scenarios x 14 IPinfo behaviours, whole-object equality).
* **Errors.** An invalid observation or a bug in the classification path raises. Only the optional
  lookups are contained: a failure is an explicit status in `ipinfo_metadata` / `ripestat_context`.
* **Opt-in.** Nothing is sent to IPinfo unless `include_ipinfo=True` and a usable token exists;
  excluded addresses are never sent. Without a token the status is `DISABLED`.
* **CLI.** `classify_ip.py` uses the service. Without `--ipinfo` its output is identical to Stage 3C
  (checked by running both versions on the same fake world). `--ipinfo` adds one key,
  `ipinfo_metadata`, and never changes the exit code (0 even if IPinfo fails).
* **Evidence vs metadata:** `docs/IPINFO_CONTEXT.md` section 1. A VPN-sounding AS name, an ASN or a
  hosting-looking domain from IPinfo still yields the same label as without it.

### Verification status (Stage 4)
Mocked tests cover the adapter and the service. Not verified: any successful live IPinfo response
(no token was available), and Windows. Run `python -m pytest -q`, then, with your token,
`python scripts\ipinfo_context.py 8.8.8.8` and `python scripts\classify_ip.py 8.8.8.8 --ipinfo`.

### Left for Stage 5
SQLite audit history (store `ServiceResult`, which is frozen and JSON-serialisable, with the
`ipinfo_metadata` section kept separate from evidence; decide whether queried addresses and
IPinfo answers may be persisted, since the in-memory caches deliberately write nothing to disk).

## 14. SQLite audit history (Stage 5)

Opt-in and off by default; full description in `docs/AUDIT_HISTORY.md`.

* `service.classify()` is unchanged and never writes. `service.classify_and_record()` classifies
  first, then saves, and returns `AuditedResult(result, audit)` where `audit.status` is `SAVED`,
  `FAILED` (classification still returned) or `DISABLED`. `ServiceResult` is unchanged.
* The audit store lives in `netclass/audit/` and is imported only by `service.py` (the store
  class) and `config.py` (two pure settings parsers). The classifier, collector, adapters and the
  IPinfo / RIPEstat services do not import it; history is never read during classification.
* Evidence goes to `evidence_records`; RIPEstat / IPinfo metadata goes to `context_metadata`.
* Settings: `NETCLASS_AUDIT_ENABLED` (default off), `NETCLASS_AUDIT_RETENTION_DAYS` (default 90,
  0 = keep indefinitely), `NETCLASS_DB_PATH`. Retention is applied only by `audit_history.py purge --yes`.
* CLI: `classify_ip.py --audit / --no-audit` (exit 5 = classified but not saved);
  `audit_history.py` for info, list, show, export, purge and delete-ip.
