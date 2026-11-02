# ps010-eval-v1 (version 1.0.0)

**Synthetic only.** This dataset contains 42 synthetic fixture cases and **no** independently sourced,
timestamped reference cases. It supports policy-conformance checks of the PS-010 pipeline. It does
**not** support any claim about real-world accuracy, precision or recall.

## What a case is

* `tier: "synthetic"`: the evidence is a fixture "world" defined in `dataset.json`; the pipeline's
  real adapters parse it and the real `ClassificationService` classifies the observation. The
  expected label follows from the documented policy by construction. Expected values were written
  from the policy before the first run, then compared with the pipeline's output.
* `tier: "reference"`: an independently sourced, timestamped label with full provenance. Version 1
  has none. The schema, loader and validator exist so cases can be added without changing code.
* `expected_label: null` is an **unlabeled** case. It must carry an `unlabeled_reason`, is reported,
  and is never scored as correct or incorrect.

## Addresses

Every IP address is an arbitrary global address chosen so it passes the exclusion policy, or a
deliberately excluded address (private, loopback, link-local, multicast, documentation, ULA,
shared address space). **None is a claim about a real Tor exit, VPN endpoint or host.** No
personal data, credentials or tokens are embedded.

## Worlds

| world | what it models |
|---|---|
| `healthy` | all sources up; IPv4-only Tor list and az0 files; X4BNet-style IPv4+IPv6 ranges; Apple Private Relay exclusion list; some excluded addresses deliberately listed |
| `tor-unavailable`, `tor-timeout`, `tor-malformed`, `tor-empty` | the Tor source fails four different ways |
| `tor-stale-source` | the Tor source's own `Last-Modified` is older than the configured maximum age |
| `vpn-unavailable` | both VPN-kind sources fail |
| `all-unavailable` | every source fails |
| `apple-list-unavailable` | X4BNet loads but the Apple exclusion list does not |
| `tor-only` | only the Tor source is enabled (no VPN/proxy provider configured) |
| `ipv6-covered` | as `healthy` but the Tor list has IPv6 entries |

## Coverage of the required situations

Known Tor exit (`syn-tor-*`), known hosted VPN/proxy (`syn-vpn-*`), Unknown (`syn-nomatch-*`,
`syn-apple-*`), conflicting Tor/VPN evidence (`syn-conflict-*`), missing or unavailable sources
(`syn-unavail-*`, `syn-notconf-*`), stale and historical observations (`syn-historical-*`,
`syn-unavail-008`), excluded ranges (`syn-excluded-*`) and IPv6 coverage limits (`syn-ipv6-*`,
`syn-vpn-004-ipv6`).

## Known limitations of this dataset

* All three evaluated sources are **current-only** snapshots. No source-backed historical ground
  truth exists, so historical cases can only expect `Unknown` / `UNKNOWN_STALE_EVIDENCE`.
* `UNKNOWN_HOSTING_ONLY` cannot occur through the service (RIPEstat context never sets a hosting
  indicator); it is covered by classifier-level tests, not here.
* Fixture sanity floors are lowered to 1 entry so tiny lists load; the real floors are covered by
  the adapter tests.
* Two cases document existing behavior that is conservative but worth knowing about, and are marked
  as observations in their `rationale`: `syn-unavail-004-conflict-masked` (a Tor+VPN conflict cannot
  be seen when the Tor list is down) and `syn-unavail-012-apple-list-down` (the label is Unknown but
  the reason code is the broad "no qualifying match").

## Hash

The dataset hash in every report is the SHA-256 of the file's **canonical JSON** (sorted keys,
no whitespace), so line endings and key order do not change it. Reordering the `cases` list does.
