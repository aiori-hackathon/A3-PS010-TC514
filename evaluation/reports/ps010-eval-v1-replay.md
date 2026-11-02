# PS-010 evaluation report: ps010-eval-v1 1.0.0

> **SYNTHETIC REPLAY.** Every case below runs the real classification service over fixture evidence with no network access. The results show policy conformance only. They are not real-world accuracy.

## Run

| field | value |
|---|---|
| mode | replay |
| evidence basis | synthetic-fixture-replay |
| evaluation time (UTC) | 2026-10-28T12:00:00+00:00 |
| deterministic output | True |
| network used | False |
| audit history enabled | False |
| package version | 0.7.0-stage7 |
| policy version | ps010-policy-1 |
| service version | ps010-service-1 |
| evaluation runner | ps010-eval-runner-1 |
| report schema | ps010-eval-report-1 |

## Dataset

| field | value |
|---|---|
| id / version | ps010-eval-v1 / 1.0.0 |
| schema | ps010-eval-dataset-1 |
| SHA-256 (canonical JSON) | 736acbddd488c0791ade2cc1ede9352f4f76c4b4ed850ddc03ded5f5768a8218 |
| cases | 42 |
| synthetic cases | 42 |
| reference cases | 0 |

Version 1 evaluation dataset for the PS-010 IP classification pipeline. It is SYNTHETIC ONLY: every case runs the real classification service over fixture evidence described in this file, and every expected label follows from the documented policy. It contains no independently sourced reference cases, so it supports policy-conformance checks and nothing else.

## Configuration

| setting | value |
|---|---|
| audit_enabled | False |
| cache_ttl_seconds | 1800 |
| current_evidence_tolerance_seconds | 3600 |
| disk_cache | none (in-memory only) |
| evaluation_time | 2026-10-28T12:00:00+00:00 |
| include_ipinfo | False |
| include_ripestat | False |
| max_source_age_seconds | 86400 |
| mode | replay |
| sanity_floor_entries | 1 |

## Provenance

| evaluated source | kind | granularity | temporal support | licence |
|---|---|---|---|---|
| az0-vpn-ip | VPN_PROXY_ENDPOINT | exact-address | current-only | GNU GPL v3 or later, Copyright (C) 2023-2024 Andrew Ziem. Do not bundle the data in this project; download at runtime and credit the author. |
| tor-project-bulk-exit-list | TOR_EXIT | exact-address | current-only | No licence statement found at the endpoint. Treat as publicly published operational data; cite the Tor Project. |
| x4bnet-lists-vpn | VPN_PROXY_ENDPOINT | cidr-range | current-only | MIT, Copyright (c) 2024 X4B (Mathew Heard). README states the licence covers the list itself. |

Fixture worlds (SHA-256 of each world's canonical JSON):

| world | sha256 | description |
|---|---|---|
| all-unavailable | df95f23a4d3dae478dc0e36f0a7cba8cbfe6556bd3b5e0a655c7fc16e2ec288c | Every source answers HTTP 503. |
| apple-list-unavailable | 5355cc482f5242da4d8bf08735e8aaf7bbf6a98c699a183944c222baca53fe80 | X4BNet ranges load but the Apple Private Relay exclusion list answers HTTP 503. |
| healthy | ff01c74042ae3b45a960960825f175cf0ffc2d097b9084ca744a9a99bcaee198 | All three sources healthy. Tor list and az0 files hold IPv4 only (no IPv6 coverage); the X4BNet-style list has IPv4 and IPv6 ranges and a separate Apple Private Relay exclusion list. Some excluded-by-policy addresses are deliberately listed in the fixtures. |
| ipv6-covered | 18eb406af89a8de7590c69441732de803d649ec7cbe5192060af9d4767e2ef1c | As 'healthy' but the Tor list also contains IPv6 exit addresses. |
| tor-empty | c42abe5fe2d3320bf88dfd73b9d9e07eab72a5f9e8bd8c470792259c06b97159 | Tor endpoint returns a file with comments only; VPN sources healthy. |
| tor-malformed | fe83786b2440ba110380e5ea0c2f279615cb8bdcf6aefdd48a2db8b5491ccff2 | Tor endpoint returns an HTML page instead of a list; VPN sources healthy. |
| tor-only | f464eea3b9be4a5d9fc160e1f7ec906821e66c0a6c2cfc6c47ac57038cf6892b | Only the Tor source is enabled; no VPN/proxy provider is configured. |
| tor-stale-source | f725325ae525fa1be7f24145e2a8533014e94fa875a73605368e67f2d221d367 | Tor endpoint reports Last-Modified three days before retrieval (limit: 86400 s); VPN sources healthy. |
| tor-timeout | c224279db66430b3b74746bc0cb7b0cecb90c8133feffd4c829d9169879aabc0 | Tor list times out; VPN sources healthy. |
| tor-unavailable | b120cec00dfd270086da128d97b0ffa4223bceb8195cd558ed8929c193fa7503 | Tor list answers HTTP 503; VPN sources healthy. |
| vpn-unavailable | cc1e3915bbc40f58b3e7046e2daba6e66315d8c6908e4effd9bc3075a4ff94de | Both VPN sources answer HTTP 503; Tor list healthy. |

## Synthetic policy conformance

Policy-conformance results on synthetic fixtures. The expected labels follow from the documented policy by construction, so agreement here shows only that the pipeline implements that policy on those fixtures. It is NOT real-world accuracy, precision or recall and must not be cited as such.

Cases evaluated: 42. Labeled (scored): 41. Unlabeled (listed, never scored): 1.

**Confusion matrix** (rows = expected, columns = predicted; labeled cases only)

| expected \ predicted | Tor | VPN/proxy | Unknown |
|---|---|---|---|
| Known Tor exit | 6 | 0 | 0 |
| Known hosted VPN/proxy endpoint | 0 | 6 | 0 |
| Unknown | 0 | 0 | 29 |

**Per class** (denominators in the definitions below)

| class | support | predicted | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|---|---|
| Known Tor exit | 6 | 6 | 6 | 0 | 0 | 6/6 = 1.0 | 6/6 = 1.0 |
| Known hosted VPN/proxy endpoint | 6 | 6 | 6 | 0 | 0 | 6/6 = 1.0 | 6/6 = 1.0 |
| Unknown | 29 | 29 | 29 | 0 | 0 | 29/29 = 1.0 | 29/29 = 1.0 |

**Coverage and selective classification** (reported separately on purpose)

| measure | value |
|---|---|
| overall agreement | 41/41 = 1.0 |
| coverage (definitive predictions) | 12/42 = 0.2857 |
| abstention rate (Unknown predictions) | 30/42 = 0.7143 |
| labeled coverage | 12/41 = 0.2927 |
| selective precision | 12/12 = 1.0 |
| definitive recall | 12/12 = 1.0 |
| primary reason-code agreement | 41/41 = 1.0 |

**Errors:** 0 label mismatch(es): 0 definitive where Unknown expected, 0 wrong definitive label, 0 missed by abstention.

**Sample-size warnings**

- Class 'Known Tor exit' has only 6 labeled case(s) (< 30): its precision and recall are anecdotal.
- Class 'Known hosted VPN/proxy endpoint' has only 6 labeled case(s) (< 30): its precision and recall are anecdotal.
- Class 'Unknown' has only 29 labeled case(s) (< 30): its precision and recall are anecdotal.

**Denominators**

- `abstention_rate`: evaluated cases predicted Unknown / evaluated cases (= 1 - coverage)
- `coverage`: evaluated cases with a definitive (non-Unknown) prediction / evaluated cases (includes unlabeled cases: coverage needs no reference label)
- `definitive_recall`: labeled cases with a definitive expected label that were predicted correctly / labeled cases with a definitive expected label
- `false_negatives[class]`: labeled cases expected as the class but predicted as another class
- `false_positives[class]`: labeled cases predicted as the class but expected as another class
- `labeled_coverage`: labeled cases with a definitive prediction / labeled cases
- `overall_agreement`: labeled cases where predicted == expected / labeled cases
- `precision[class]`: labeled cases predicted as the class and expected as the class / labeled cases predicted as the class
- `recall[class]`: labeled cases predicted as the class and expected as the class / labeled cases expected as the class (class support)
- `selective_precision`: labeled cases with a definitive prediction that equals the expected label / labeled cases with a definitive prediction

## Reference-case accuracy

Not evaluated: the dataset contains no reference-tier cases: no accuracy, precision or recall against independent ground truth can be reported.

## Invariant checks

Checked: excluded_address_zero_fetches, label_is_one_of_three, repeat_run_identical. Result: **PASSED**.

## Per-case errors

None: no labeled case disagreed with its expectation.

## All cases

| case | tier | category | ip | observed (UTC) | expected | predicted | reason | fetches | status |
|---|---|---|---|---|---|---|---|---|---|
| syn-apple-001-relay-range | synthetic | apple_private_relay | 15.50.60.10 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_NO_QUALIFYING_MATCH | 8 | match |
| syn-conflict-001-tor-x4bnet | synthetic | conflicting_evidence | 12.20.30.99 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_CONFLICTING_EVIDENCE | 8 | match |
| syn-conflict-002-tor-az0 | synthetic | conflicting_evidence | 11.10.10.5 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_CONFLICTING_EVIDENCE | 7 | match |
| syn-excluded-001-private-listed | synthetic | excluded_address | 10.1.2.3 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_EXCLUDED_ADDRESS | 0 | match |
| syn-excluded-002-cgnat-listed | synthetic | excluded_address | 100.64.1.1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_EXCLUDED_ADDRESS | 0 | match |
| syn-excluded-003-loopback | synthetic | excluded_address | 127.0.0.1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_EXCLUDED_ADDRESS | 0 | match |
| syn-excluded-004-link-local | synthetic | excluded_address | 169.254.1.1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_EXCLUDED_ADDRESS | 0 | match |
| syn-excluded-005-multicast | synthetic | excluded_address | 224.0.0.1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_EXCLUDED_ADDRESS | 0 | match |
| syn-excluded-006-documentation | synthetic | excluded_address | 192.0.2.10 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_EXCLUDED_ADDRESS | 0 | match |
| syn-excluded-007-ula-v6 | synthetic | excluded_address | fc00::1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_EXCLUDED_ADDRESS | 0 | match |
| syn-excluded-008-mapped-private | synthetic | excluded_address | ::ffff:10.0.0.1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_EXCLUDED_ADDRESS | 0 | match |
| syn-historical-001-tor-listed | synthetic | stale_or_historical | 11.10.10.1 | 2026-10-27T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_STALE_EVIDENCE | 7 | match |
| syn-historical-002-vpn-listed | synthetic | stale_or_historical | 12.20.30.10 | 2026-10-27T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_STALE_EVIDENCE | 8 | match |
| syn-historical-003-unlisted | synthetic | stale_or_historical | 14.40.50.60 | 2026-10-27T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_STALE_EVIDENCE | 7 | match |
| syn-historical-004-future | synthetic | stale_or_historical | 14.40.50.60 | 2026-10-28T14:00:00+00:00 | Unknown | Unknown | UNKNOWN_STALE_EVIDENCE | 7 | match |
| syn-historical-005-boundary-beyond | synthetic | stale_or_historical | 11.10.10.1 | 2026-10-28T10:59:59+00:00 | Unknown | Unknown | UNKNOWN_STALE_EVIDENCE | 7 | match |
| syn-ipv6-001-uncovered | synthetic | ipv6_coverage | 2a0e:2000::1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_PROVIDER_NOT_CONFIGURED | 7 | match |
| syn-ipv6-002-tor-v6-exit | synthetic | ipv6_coverage | 2a0e:3000::1 | 2026-10-28T12:00:00+00:00 | Known Tor exit | Known Tor exit | TOR_EXIT_MATCH | 7 | match |
| syn-ipv6-003-covered-unlisted | synthetic | ipv6_coverage | 2a0e:2000::1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_NO_QUALIFYING_MATCH | 7 | match |
| syn-nomatch-001 | synthetic | no_match | 14.40.50.60 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_NO_QUALIFYING_MATCH | 7 | match |
| syn-notconf-001-no-vpn-provider | synthetic | source_not_configured | 14.40.50.60 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_PROVIDER_NOT_CONFIGURED | 1 | match |
| syn-notconf-002-tor-listed-no-vpn-provider | synthetic | source_not_configured | 11.10.10.1 | 2026-10-28T12:00:00+00:00 | Known Tor exit | Known Tor exit | TOR_EXIT_MATCH | 1 | match |
| syn-tor-001 | synthetic | known_tor_exit | 11.10.10.1 | 2026-10-28T12:00:00+00:00 | Known Tor exit | Known Tor exit | TOR_EXIT_MATCH | 7 | match |
| syn-tor-002-ipv4-mapped | synthetic | known_tor_exit | ::ffff:11.10.10.1 | 2026-10-28T12:00:00+00:00 | Known Tor exit | Known Tor exit | TOR_EXIT_MATCH | 7 | match |
| syn-tor-003-boundary-within | synthetic | known_tor_exit | 11.10.10.1 | 2026-10-28T11:00:00+00:00 | Known Tor exit | Known Tor exit | TOR_EXIT_MATCH | 7 | match |
| syn-unavail-001-tor-down-unlisted | synthetic | source_unavailable | 14.40.50.60 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_SOURCE_UNAVAILABLE | 7 | match |
| syn-unavail-002-tor-down-listed | synthetic | source_unavailable | 11.10.10.1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_SOURCE_UNAVAILABLE | 7 | match |
| syn-unavail-003-tor-down-vpn-listed | synthetic | source_unavailable | 13.30.40.50 | 2026-10-28T12:00:00+00:00 | Known hosted VPN/proxy endpoint | Known hosted VPN/proxy endpoint | VPN_PROXY_ENDPOINT_MATCH | 7 | match |
| syn-unavail-004-conflict-masked | synthetic | source_unavailable | 11.10.10.5 | 2026-10-28T12:00:00+00:00 | Known hosted VPN/proxy endpoint | Known hosted VPN/proxy endpoint | VPN_PROXY_ENDPOINT_MATCH | 7 | match |
| syn-unavail-005-tor-timeout | synthetic | source_unavailable | 14.40.50.60 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_SOURCE_UNAVAILABLE | 7 | match |
| syn-unavail-006-tor-malformed | synthetic | source_unavailable | 14.40.50.60 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_SOURCE_UNAVAILABLE | 7 | match |
| syn-unavail-007-tor-empty | synthetic | source_unavailable | 14.40.50.60 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_SOURCE_UNAVAILABLE | 7 | match |
| syn-unavail-008-tor-stale-source | synthetic | stale_or_historical | 14.40.50.60 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_SOURCE_UNAVAILABLE | 7 | match |
| syn-unavail-009-vpn-down-unlisted | synthetic | source_unavailable | 14.40.50.60 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_SOURCE_UNAVAILABLE | 7 | match |
| syn-unavail-010-vpn-down-tor-listed | synthetic | source_unavailable | 11.10.10.1 | 2026-10-28T12:00:00+00:00 | Known Tor exit | Known Tor exit | TOR_EXIT_MATCH | 7 | match |
| syn-unavail-011-all-down | synthetic | source_unavailable | 11.10.10.1 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_SOURCE_UNAVAILABLE | 7 | match |
| syn-unavail-012-apple-list-down | synthetic | source_unavailable | 12.20.30.10 | 2026-10-28T12:00:00+00:00 | Unknown | Unknown | UNKNOWN_NO_QUALIFYING_MATCH | 8 | match |
| syn-unlabeled-001 | synthetic | unlabeled | 14.40.50.61 | 2026-10-28T12:00:00+00:00 | - | Unknown | UNKNOWN_NO_QUALIFYING_MATCH | 7 | unlabeled |
| syn-vpn-001-x4bnet | synthetic | known_vpn_proxy | 12.20.30.10 | 2026-10-28T12:00:00+00:00 | Known hosted VPN/proxy endpoint | Known hosted VPN/proxy endpoint | VPN_PROXY_ENDPOINT_MATCH | 8 | match |
| syn-vpn-002-az0 | synthetic | known_vpn_proxy | 13.30.40.50 | 2026-10-28T12:00:00+00:00 | Known hosted VPN/proxy endpoint | Known hosted VPN/proxy endpoint | VPN_PROXY_ENDPOINT_MATCH | 7 | match |
| syn-vpn-003-both-vpn-sources | synthetic | known_vpn_proxy | 12.20.30.20 | 2026-10-28T12:00:00+00:00 | Known hosted VPN/proxy endpoint | Known hosted VPN/proxy endpoint | VPN_PROXY_ENDPOINT_MATCH | 8 | match |
| syn-vpn-004-ipv6 | synthetic | ipv6_coverage | 2a0e:1000::1234 | 2026-10-28T12:00:00+00:00 | Known hosted VPN/proxy endpoint | Known hosted VPN/proxy endpoint | VPN_PROXY_ENDPOINT_MATCH | 8 | match |

## Limitations and warnings

- Synthetic only: no independently sourced, timestamped reference cases are included; no real-world accuracy, precision or recall can be derived from this dataset.
- All IP addresses are arbitrary global (or deliberately excluded) addresses chosen for fixtures. None is a claim about a real Tor exit, VPN endpoint or any real host.
- All three evaluated sources are current-only snapshots, so no source-backed historical ground truth exists; historical cases can only expect Unknown (stale evidence).
- Fixture sanity floors are lowered to 1 entry so small lists load; the real floors are covered by the adapter tests.
- UNKNOWN_HOSTING_ONLY is not reachable through the service (RIPEstat context never sets a hosting indicator) and is therefore not exercised here.
- Policy-conformance results on synthetic fixtures. The expected labels follow from the documented policy by construction, so agreement here shows only that the pipeline implements that policy on those fixtures. It is NOT real-world accuracy, precision or recall and must not be cited as such.
- Reference accuracy: the dataset contains no reference-tier cases: no accuracy, precision or recall against independent ground truth can be reported.
