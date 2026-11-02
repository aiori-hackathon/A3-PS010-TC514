# Release changelog: Stage 3A + 3B + 3C (`0.3.0-stage3c`)

Policy labels, reason codes and `POLICY_VERSION = "ps010-policy-1"` are unchanged across 3A to 3C.

## Stage 3A (policy refinement and source quality; "Workstream A")
Details: `docs/WORKSTREAM_A_AUDIT.md`.
* Tor + VPN evidence stays `Unknown` / `UNKNOWN_CONFLICTING_EVIDENCE` (documented, tested).
* `adapters/tor.py`, `adapters/az0.py`: an IPv4 query against a source holding no IPv4 entries is
  `NOT_CONFIGURED` ("IPv4 not covered"), mirroring the existing IPv6 rule. Never a negative.
* `adapters/x4bnet.py`: if the Apple exclusion list holds no IPv6 CIDRs, the IPv6 gap is recorded
  in metadata and limitations.
* `inspection.py`: Tor-in-X4BNet overlap detail, per-CIDR counts, sanity-floor headroom.
* `tests/test_workstream_a_audit.py`: 17 added tests. No earlier test was edited or removed.

## Stage 3B (RIPEstat network context)
Details: `docs/RIPESTAT_CONTEXT.md`, `docs/STAGE3B_CHANGELOG.md`.
* `src/netclass/ripestat.py`: context service for the documented `network-info` and `as-overview`
  data calls; typed errors; in-memory TTL cache; provenance with SHA-256 of the raw response.
* `collector.py`: `build_context_service`, `classify_with_context` (new functions only).
* `config.py`: `ripestat_sourceapp`, `ripestat_cache_ttl_seconds`, HTTPS and `sourceapp` validation.
* `scripts/ripestat_context.py`; `scripts/classify_ip.py --context` (opt-in).
* Tests: `test_ripestat_service.py`, `test_ripestat_invariance.py`, `test_ripestat_config.py`,
  helper `ripestat_support.py`.
* RIPEstat output is metadata only: never an `EvidenceRecord`, never a label or reason code,
  `hosting_indicator` always `False`.

## Stage 3C (integration audit; this release)
Details: `docs/STAGE3C_AUDIT.md`. No architecture change, no feature added, no test changed.
* `src/netclass/ripestat.py`: corrected a stale comment (`build_ripestat_service` does not exist;
  the function is `collector.build_context_service`). Comment only.
* `src/netclass/http_client.py`: `USER_AGENT` version `0.2` -> `0.3` (the string is sent to every
  source, including RIPEstat). `tests/test_http_client.py` compares against the constant.
* `src/netclass/__init__.py`: `__version__` `0.3.0-stage3b` -> `0.3.0-stage3c`.
* `README.md`, `docs/INTEGRATION_GUIDE.md`, `docs/WORKSTREAM_A_AUDIT.md`: removed or qualified claims
  not supported by evidence available to this stage (hard-coded test totals, "verified live" statements
  by earlier authors); fixed layout, roadmap and stale "Expected: 286 passed".
* `docs/RIPESTAT_CONTEXT.md`: added the documented caveat that `announced=false` also covers
  transit-only ASNs; recorded the Stage 3C documentation re-check.
* `.gitignore`: also ignores `inspection-report.json`, `test-results.txt`, `*.egg-info/`.
* Added `docs/STAGE3C_AUDIT.md` and this file.
