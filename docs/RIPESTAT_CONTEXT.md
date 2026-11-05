# RIPEstat network-context service

Module: `src/netclass/ripestat.py`. Wiring: `collector.build_context_service`,
`collector.classify_with_context`. CLI: `scripts\ripestat_context.py`,
`scripts\classify_ip.py --context`.

## 1. The rule

RIPEstat output is **contextual metadata only**. It is never an `EvidenceRecord`, never
produces a label or reason code, and never sets `NetworkContext.hosting_indicator`.
An ASN, a holder name that sounds like hosting/cloud/VPN, or a data-centre prefix does not
show VPN/proxy or Tor use. The three primary labels are unchanged and come from the
evidence sources only. This is enforced by tests, including an AST check that
`ripestat.py` does not import or name the classifier, `Label`, `ReasonCode` or the evidence types.

## 2. Official documentation and exact endpoints

Documentation (read 2026-10-31):

* About the Data API (URL scheme, envelope, usage rules): https://stat.ripe.net/docs/data-api/ripestat-data-api/
* Network Info: https://stat.ripe.net/docs/data-api/api-endpoints/network-info/
* AS Overview: https://stat.ripe.net/docs/data-api/api-endpoints/as-overview/
* Service terms referenced by the docs: https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions

Endpoints used (base `https://stat.ripe.net/data`, configurable, HTTPS enforced):

| Call | Request | Documented output used |
|------|---------|------------------------|
| network-info (v1.1 current) | `GET /data/network-info/data.json?resource=<ip>` | `asns`, `prefix` |
| as-overview (v1.3 current) | `GET /data/as-overview/data.json?resource=AS<n>` | `holder`, `announced`, `resource` |

Optional parameter: `sourceapp=<id>` (documented: letters, digits, `-`, `_`). RIPEstat asks
regular users (>1000 requests/day) to register an identifier by mail to stat@ripe.net.

Common envelope fields the service reads (documented): `status` (`ok`/`error`/`maintenance`),
`data_call_name`, `data_call_status`, `version`, `cached`, `data`. `message` is read on `error`.

Documentation gaps (handled defensively, not assumed):

* The pages do not show a sample JSON body, so the element type of `asns` (integer or string) is
  not documented. The parser accepts integers, numeric strings and `AS`-prefixed strings.
* The pages do not name an HTTP status for rate limiting. They state a limit of 8 concurrent
  requests per source IP. HTTP 429 is mapped to `RATE_LIMITED` (the standard status); any other
  non-200 is `HTTP_ERROR`.
* `network-info` is documented as "the prefix the resource matches *if routed*", so an unrouted
  address is expected to return empty values. This is reported as `EMPTY`, not as an error.
* The 429 mapping, the unrouted behaviour and every response shape are verified against **mocked**
  bodies only. No live RIPEstat request has been verified by the author (see the changelog).

## 3. API

```python
from netclass.collector import build_context_service
from netclass.config import load_settings

service = build_context_service(load_settings())
ctx = service.lookup("8.8.8.8")        # never raises
ctx.status                              # AVAILABLE | PARTIAL | UNAVAILABLE | NOT_QUERIED
ctx.routing.asns, ctx.routing.prefix    # network-info
ctx.holders[0].holder                   # as-overview, per origin ASN
ctx.to_network_context()                # NetworkContext for display, or None
```

Classification with context:
`classify_with_context(observation, adapters, settings, service) -> (result, records, ripe_context)`.
`classify_with_evidence` is unchanged and does not touch RIPEstat.

### Response schema (`RipeStatContext`, frozen Pydantic model)

| Field | Meaning |
|-------|---------|
| `ip` | normalised address |
| `status` | `AVAILABLE` all attempted lookups succeeded; `PARTIAL` routing ok, a holder lookup failed; `UNAVAILABLE` nothing usable; `NOT_QUERIED` excluded address, no request made |
| `requested_at` | UTC time the lookup started |
| `routing` | `RoutingSection`: `status` (`OK`/`EMPTY`/`UNAVAILABLE`), `asns` (sorted ints), `prefix`, `provenance`, `error`, `warnings` |
| `holders` | one `HolderSection` per looked-up ASN (max 3, lowest numbers first): `asn`, `holder`, `announced`, `status`, `provenance`, `error`, `warnings` |
| `error` | only for `INVALID_INPUT`/`INTERNAL` at top level |
| `note` | reason when `NOT_QUERIED` |
| `limitations` | fixed caveats plus case-specific ones (multi-origin, holder cap, unrouted) |

`Provenance`: `source_name` (`ripestat-data-api`), `data_call`, exact `endpoint` URL,
`retrieved_at` (UTC; original time on a cache hit), `from_cache`, `response_sha256` (of the raw
body), `api_version`, `data_call_status`, `api_reported_cached` (RIPEstat's own `cached` flag).

Invariants (model-enforced): an `UNAVAILABLE` section has an error and no provenance; a
successful section has provenance and no error.

### Errors (`ContextError.kind`)

`TIMEOUT`, `CONNECTION` (DNS/TLS/refused/non-HTTPS redirect), `HTTP_ERROR` (non-200, not 429),
`RATE_LIMITED` (429), `TOO_LARGE` (response over 1 MB), `INVALID_JSON`, `UNEXPECTED_STRUCTURE`
(wrong envelope, wrong data call, wrong types, neither `asns` nor `prefix`, returned prefix not
containing the queried address, ASN mismatch), `API_ERROR`, `API_MAINTENANCE`, `INVALID_INPUT`,
`INTERNAL`. Each carries the endpoint, HTTP status when known and a UTC time.

Tolerated (valid response, `warnings` recorded): missing `asns` or `prefix` (but not both),
unparseable individual ASN values (skipped), an invalid prefix string (dropped), missing/non-text
`holder`, non-boolean `announced`, holder text with control characters (cleaned) or over 256
characters (truncated), `data_call_status` of deprecated/development.

### Mapping to the existing `NetworkContext`

`to_network_context()` returns `None` when nothing usable exists. `asn`/`as_name` are filled only
when exactly one origin ASN is reported (multi-origin is not collapsed to a guess; the full list
stays on `RipeStatContext`). `hosting_indicator` is always `False`. `retrieved_at` is the oldest
retrieval time among the sections used. `country_code` is never set (not requested).

## 4. Caching and freshness

* In-memory only; nothing is written to disk, so queried addresses are not persisted.
  (Deliberately not the evidence `SnapshotStore`: that stores per-URL files, which would create one
  file per queried IP.)
* Key: (data call, resource). Only responses that parsed successfully are stored. Errors and
  malformed bodies are never cached. Valid empty answers (unrouted address) are cached.
* TTL: `NETCLASS_RIPESTAT_CACHE_TTL_SECONDS`, default 3600 (network-info is built from 8-hourly
  dumps, so a one-hour reuse adds little staleness). `0` disables caching in code.
* An entry is served while `0 <= age <= TTL`. Older entries, or entries whose age is negative
  (clock moved backwards), are dropped and never served, even if the refresh then fails; the
  result is then `UNAVAILABLE`, mirroring the evidence-source rule that stale data is not used as evidence.
* A cache hit keeps the original `retrieved_at` and sets `from_cache=True`.
* Bounded to 2048 entries (oldest inserted evicted first). Holder answers are shared across
  addresses of the same ASN.
* No automatic retry or back-off. After a 429 the next call simply tries again; a caller that
  loops over many addresses should pace itself (the service itself is sequential, so it stays
  under the documented 8-concurrent-request limit).

## 5. Limitations

* **Not live-verified.** Tests use mocked bodies. Run `python scripts\ripestat_context.py 8.8.8.8`
  on a networked machine and keep the output.
* Describes routing at retrieval time. For a historical observation time the context may not
  match; compare `retrieved_at` to `observed_at`. Historical endpoints were not used.
* `network-info` reflects RIPE RIS visibility, not registry data; an unrouted-looking result is
  not proof the address is unallocated.
* The holder is the ASN holder's registered free-text name, not the address's user.
* `HolderSection.announced` is RIPEstat's own flag: true only if the ASN originates prefixes visible to at least 10 RIS full-feed peers. RIPEstat's page states that a transit-only ASN is reported as `false` and that the field name may change in a future version. Do not read `announced=False` as "not routed".
* Documentation re-checked on 2026-10-31 (see `docs/INTEGRATION_AUDIT.md`): network-info 1.1 (current); as-overview 1.3 (current, 2.1 also listed). The service sends no `version` parameter, so it receives the default version; the envelope `version` is stored in `Provenance.api_version`.
* Retry-After is not available (the shared fetcher drops it); the RIPEstat error body on non-200
  responses is not read (the shared fetcher raises before returning the body).
* Terms of service apply; add `NETCLASS_RIPESTAT_SOURCEAPP` for regular use.
