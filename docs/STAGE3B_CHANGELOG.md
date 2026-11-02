# Changelog: Stage 3A vs Stage 3B

## Stage 3A (inherited unchanged; "Workstream A", see `docs/WORKSTREAM_A_AUDIT.md`)

* Policy kept: Tor evidence plus VPN evidence is `Unknown` / `UNKNOWN_CONFLICTING_EVIDENCE`.
* `adapters/tor.py`, `adapters/az0.py`: IPv4 query against a list with no IPv4 entries is
  `NOT_CONFIGURED` ("IPv4 not covered").
* `adapters/x4bnet.py`: IPv6 Apple-exclusion gap recorded as metadata/limitation.
* `inspection.py`: Tor-in-X4BNet overlap detail, per-CIDR counts, floor headroom.
* `tests/test_workstream_a_audit.py`: 17 regression tests. Baseline 269 + 17 = 286 tests.
* `classifier.py` untouched; `POLICY_VERSION = "ps010-policy-1"`.

## Stage 3B (this change)

Added:

* `src/netclass/ripestat.py`: RIPEstat client/service, models, parsers, in-memory TTL cache.
* `collector.py`: `build_context_service`, `classify_with_context` (new functions only).
* `config.py`: `ripestat_sourceapp`, `ripestat_cache_ttl_seconds`; HTTPS and `sourceapp`
  validation. `.env.example`: `NETCLASS_RIPESTAT_SOURCEAPP`, `NETCLASS_RIPESTAT_CACHE_TTL_SECONDS`.
* `scripts/ripestat_context.py`; `scripts/classify_ip.py --context` (opt-in; default behaviour
  unchanged).
* Tests: `tests/test_ripestat_service.py` (110), `tests/test_ripestat_invariance.py` (97),
  `tests/test_ripestat_config.py` (14), helper `tests/ripestat_support.py`.
* Docs: `docs/RIPESTAT_CONTEXT.md`, this file; README and INTEGRATION_GUIDE updated.
* `__version__` -> `0.3.0-stage3b`.

Not changed (deliberately): `classifier.py`, `models.py`, `errors.py`, `http_client.py`,
`sources.py`, all adapters, all Stage 3A tests, `POLICY_VERSION`, the three labels, reason codes.
No compatibility fix to Stage 3A was needed. RIPEstat is not registered in `SOURCES` because it is
not an evidence source. No SQLite, no Streamlit.

Known consequence of the design: `UNKNOWN_HOSTING_ONLY` (Stage 3A) can no longer be reached
through RIPEstat, because the service never sets a hosting indicator. It stays reachable only by a
future explicit, non-RIPEstat hosting source.
