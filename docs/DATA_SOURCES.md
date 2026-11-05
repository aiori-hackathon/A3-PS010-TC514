# Data sources: inspection notes

Update (2026-10-30): the GitHub sources were also downloaded and parsed
live by the adapter code; see section 4 for the policies and section 5 for the
latest observed numbers.

Inspected on 2026-10-28. The X4BNet and az0 repositories were cloned and their
files parsed. The Tor list could not be downloaded in that session (the
sandbox had no route to check.torproject.org), so its entry below rests on Tor
Project documentation and MUST be verified against a real download.

Not legal advice: licence notes are a reading of the published terms.

## 1. Tor Project bulk exit list (Tor evidence)

- Endpoint: https://check.torproject.org/torbulkexitlist
- Format (per Tor documentation, to verify): plain text, one IP per line.
- What it is: addresses the Tor Project has observed being used by exit
  relays through active measurement.
- Update process: Tor documentation says it updates at most about every 40
  minutes and that hourly fetching is reasonable.
- Licence: no licence statement found. Cite the Tor Project.
- Limitations: current snapshot only; no history. A relay operator reported
  addresses staying listed for roughly a month after a relay stopped exiting
  (unverified). Per-entry timestamps are not known to exist.
- Possible historical source (not yet evaluated): Tor Project CollecTor
  archives of exit lists, which carry timestamps per entry. Evaluate before
  claiming any historical support.

## 2. X4BNet/lists_vpn (VPN/proxy evidence)

- Repository: https://github.com/X4BNet/lists_vpn (branch main)
- Files to use: `output/vpn/ipv4.txt` and `output/vpn/ipv6.txt`.
- Files that MUST NOT be used as VPN evidence: `output/datacenter/*` and the
  legacy root `ipv4.txt`/`ipv6.txt`. These are datacenter lists ("anything
  that is not an eyeball network"), so a datacenter match is not VPN evidence.
- Format: plain text, one CIDR per line. Observed: 10,942 IPv4 CIDRs (about
  3.18 million addresses) and 498 IPv6 CIDRs; all parse with Python
  `ipaddress`; no comments, no blank lines.
- Update process: GitHub Actions rebuild on a daily schedule and on input
  changes. Latest commit seen: 2026-10-28T16:24:06Z. The output is built from
  provider ASNs plus per-provider netblock files in `input/vpn/`.
- Licence: MIT, Copyright (c) 2024 X4B (Mathew Heard). The README says the
  licence covers the scripts, automation and the list itself. Keep the
  copyright and licence notice with any copy of the data. There is no separate
  LICENSE file in the repository root; the terms are in the README.
- Limitations:
  - Range-level evidence: a match means "inside a listed VPN netblock", not
    "confirmed active VPN endpoint".
  - Partly ASN-derived, so ranges can include non-VPN hosts.
  - The VPN ASN input includes AS60729, commented "Tor Servers (Tor exit
    nodes)", and `input/vpn/ips/apple.txt` has about 3,490 Apple Private
    Relay ranges. The merged output cannot tell them apart, so overlap with
    Tor evidence is possible and the list is not strictly classic VPNs.
  - 4,289 of the 10,942 VPN CIDRs also appear literally in the datacenter
    list; this is the "small overlap" the README warns about.
  - Current snapshot only; no per-entry timestamps (Git history exists).

## 3. az0/vpn_ip (VPN/proxy evidence)

- Repository: https://github.com/az0/vpn_ip (branch main), directory
  `data/input/ip/`.
- Format: plain text, one IPv4 address per line, optional trailing
  `# comment`, `#` header lines. 11 files; 6 contain addresses and 5 contain
  only headers today.
- Observed: 11,479 unique IPv4 addresses (nordvpn_api 6,126; pia 5,293;
  expressvpn 52; hideme 2 and hideme_api 4; nordvpn 2). No IPv6, no invalid
  lines, no non-global addresses.
- Overlap with X4BNet: 7,349 of the 11,479 (64%) fall inside X4BNet VPN
  ranges; 2,145 are in neither X4BNet list. So the sources are complementary:
  az0 adds addresses X4BNet does not cover. Per file: pia 5,292 of 5,293
  inside X4BNet; nordvpn_api 2,054 of 6,126; expressvpn 0 of 52.
- Update process: scheduled GitHub Action twice daily (01:00 and 13:00 UTC).
  Latest commit seen: 2026-10-28T18:34:18Z. `data/input/ip` is raw input; the
  curated `ip.txt` is published at an off-GitHub URL (http, not https).
- Licence: GNU GPL v3 or later, Copyright (C) 2023-2024 Andrew Ziem. This is
  a copyleft licence. Do not bundle or commit the data into this project;
  download at runtime, credit the author, and keep this project's use as a
  separate program reading the file. If the team wants to redistribute data,
  take advice first.
- Limitations: raw inputs, partial provider coverage; `nordvpn.txt` contains
  provider DNS resolver addresses (not tunnel endpoints); current snapshot
  only; no per-entry timestamps.

## Time handling for all three sources

All three are current-only snapshots. The classifier therefore accepts them
only when the observation time is within the tolerance of the retrieval time.
Source-provided timestamps (Git commit time for the GitHub files, a
Last-Modified header for Tor if present) are recorded as provenance but do not
extend validity.

## Open decisions (to settle with real data)

1. Tor/VPN overlap. Today any Tor match plus any VPN match gives Unknown
   (conflict). Because X4BNet's inputs include a Tor-exit ASN, real Tor exits
   may land in both sources and become Unknown. Measure the overlap on real
   downloads first, then choose: keep the conservative rule, or let exact-
   address Tor evidence outrank range-level VPN evidence (a policy change that
   needs a documented reason and tests).
2. Range-only VPN matches. Decide whether a CIDR match alone supports the
   label "Known hosted VPN/proxy endpoint". Recommendation: yes for
   `output/vpn` (it is VPN-only by design) but always state the granularity
   in the explanation.
3. Apple Private Relay. It is a privacy relay rather than a classic VPN.
   Optional refinement: build ranges from `input/vpn/ips/*` per provider,
   excluding apple.txt, which also gives per-provider provenance.
4. Historical support. Git history of both repositories could provide
   commit-pinned snapshots for past dates. Treat as a stretch goal; do not
   claim historical support until it is implemented and tested.

## 4. Adapter policy decisions

| Question | Decision | Where enforced / tested |
|----------|----------|-------------------------|
| Datacenter-only evidence | Never fetched, never VPN evidence | `sources.py` guard test; `test_adapters_x4bnet.py` requested-URL test |
| Apple Private Relay | Its CIDRs (`input/vpn/ips/apple.txt`) are subtracted from the X4BNet VPN set; Apple-only matches are NO_MATCH with the exclusion recorded | `adapters/x4bnet.py`; tests in `test_adapters_x4bnet.py`, `test_collector_overlap.py` |
| DNS resolver addresses | az0 `nordvpn.txt` is never fetched | `sources.py`; `test_adapters_az0.py` |
| Tor + any VPN match | Unknown (conflicting evidence); no Tor precedence | `classifier.py` rule 3; `test_collector_overlap.py` |
| Range-level VPN match | Counts as VPN evidence; granularity "cidr-range" is recorded on every record | `adapters/x4bnet.py` |
| IPv6 vs sources with no IPv6 data | Not covered (NOT_CONFIGURED), never a negative | `adapters/tor.py`, `adapters/az0.py` |
| Partial az0 failure | A match in loaded files stands; absence is unavailable | `adapters/az0.py` |
| Stale cache | Never used; refresh failure is SOURCE_UNAVAILABLE | `snapshots.py` |
| Malformed or empty download | SOURCE_UNAVAILABLE, never cached | `parsers.py`, `snapshots.py` |
| Over-broad CIDR (shorter than /8 or /16) | Whole snapshot rejected as malformed | `parsers.py` |

Sanity floors (minimum entry counts, to catch truncated files). They are
safety checks, not accuracy claims:
Tor 10; X4BNet IPv4 1,000, IPv6 50, Apple 100; az0 1,000 in total.
Reviewed in Workstream A, unchanged; rationale and limits in `docs/WORKSTREAM_A_AUDIT.md` section 3.
A Tor or az0 list holding no IPv4 entries is reported as IPv4 not covered, mirroring the IPv6 rule.

## 5. Latest live observations (2026-10-30, development sandbox)

These lists change daily; treat the numbers as a snapshot, not a constant.

* X4BNet `output/vpn/ipv4.txt`: 11,011 CIDRs, prefixes /17 to /32.
  `ipv6.txt`: 647 CIDRs, prefixes /29 to /48. `apple.txt`: 3,490 IPv4 CIDRs.
* az0: expressvpn 52, hideme 2, hideme_api 4, nordvpn_api 6,126, pia 5,286
  addresses (11,470 unique IPv4 in total).
* 7,341 of the az0 addresses lie inside genuine (non-Apple) X4BNet VPN ranges;
  4,129 do not. Zero az0 addresses fall in Apple ranges.
* `raw.githubusercontent.com` returns an ETag but no Last-Modified header, so
  `source_timestamp` is null for the GitHub sources; only the retrieval time
  and the ETag are recorded as provenance. Fetching the GitHub commit time is
  not implemented.
* The Tor endpoint could not be reached from the sandbox (DNS failure), so
  its real format, size, IPv6 content and headers are NOT verified. Run
  `python scripts\inspect_sources.py` locally to check them.
