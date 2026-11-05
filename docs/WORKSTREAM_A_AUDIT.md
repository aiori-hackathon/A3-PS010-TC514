# Workstream A: policy refinement and source-quality audit

Scope: classification policy, evidence-quality audit, regression tests.
Not in scope (not implemented): RIPEstat, SQLite audit history, dashboard.

## 0. What was and was not verified

| Item | Status |
|------|--------|
| Existing suite (269 tests) | 269 pass on the maintainer's Windows 11 / Python 3.12.10 baseline (reported by the maintainer, not re-run by the author of this change). |
| Changed project (269 + 17 = 286 tests) | **Not yet run on real pytest/pydantic or on Windows.** The author's sandbox had no network, pytest or pydantic. Run the PowerShell commands in section 8. |
| Author's smoke check | A throw-away stand-in for pytest/pydantic (not shipped, not authoritative) ran the unmodified project to 269/269 and the changed project to 286/286. It shows the logic is consistent, nothing more. |
| Live sources | **No live source was reached by the author in this workstream** (no network). The numbers below marked "reported" come from `docs/DATA_SOURCES.md` (2026-10-28 and 2026-10-30 inspections). The 269 Tor-in-X4BNet figure is the maintainer's; it was not re-measured. |

## 1. Change log

Policy outcomes are unchanged: no label, reason code, threshold or `POLICY_VERSION` changed. `classifier.py` is untouched.

| File | Change | Why |
|------|--------|-----|
| `adapters/tor.py` | IPv4 query against a list with zero IPv4 entries -> `NOT_CONFIGURED` ("IPv4 not covered"). | Coverage must be derived from content, symmetric with the existing IPv6 rule. |
| `adapters/az0.py` | Same rule for az0 (no IPv4 addresses loaded). | Same. |
| `adapters/x4bnet.py` | IPv6 match records `apple_exclusion_ipv6_entries` and, when the Apple list has no IPv6 CIDRs, a limitation saying the Apple exclusion could not be checked for IPv6. Status stays MATCH. | Makes the IPv6 Apple-exclusion gap explicit and auditable without changing outcomes. |
| `inspection.py` | Tor-in-X4BNet overlap now lists every address, counts per matched CIDR, and shows which are also in az0; each file reports its sanity floor and headroom; reports Apple IPv6 CIDR count. Text report abbreviates; `--json` keeps everything. | Needed to investigate the 269 and to review floors against real data. |
| `tests/test_workstream_a_audit.py` | 17 new tests (section 5). | Regression pins. |
| docs | This file; README, DATA_SOURCES, INTEGRATION_GUIDE updated. | |

## 2. Tor / X4BNet overlap (the 269 entries)

Decision: **keep the conservative rule.** Tor evidence plus any applicable VPN evidence is `Unknown` / `UNKNOWN_CONFLICTING_EVIDENCE`. Neither source is preferred.

Rationale:
- The documented mechanism is that X4BNet's VPN input includes an ASN commented "Tor Servers (Tor exit nodes)" (DATA_SOURCES.md section 2). If that is the cause, the VPN list is partly derived from Tor infrastructure, so the two sources are not independent and "VPN" evidence there is weak for those ranges. That argues against letting the VPN side win.
- Letting exact-address Tor evidence win would be a defensible alternative, but it would mean trusting one source over another on a mechanism that is documented, not measured. Not done.
- The mechanism is **unverified**: the author could not see the 269 addresses. Run `python scripts\inspect_sources.py --json inspection-report.json` and read `overlap.tor_inside_x4bnet_vpn_ranges`: `by_matched_cidr` shows whether the 269 cluster in a few CIDRs (supports the ASN explanation), `also_in_az0` shows addresses independently listed as VPN by az0, and `all_addresses` can be diffed between runs.
- What would justify changing the policy: per-CIDR provenance for X4BNet output (not published; the merged file cannot be split by origin) or ASN data per address (RIPEstat, out of scope). Until then, Unknown is the honest answer.

Known cost: such addresses never reach "Known Tor exit".
Known gap (pre-existing, tested, unchanged): if the VPN sources are unavailable, a Tor match stands with caveats, so a conflict cannot be detected during an outage.

## 3. Sanity floors reviewed (no thresholds changed)

Floors catch gross truncation or a wrong file. They are not accuracy claims, and they cannot detect partial truncation.

| Floor | Value | Observed (reported) | Headroom | Decision / rationale |
|-------|-------|---------------------|----------|----------------------|
| Tor entries | 10 | **No observed count in the project docs.** | unknown | Unchanged. Cannot be justified or tightened without the live count. Action: read `sanity_floor`/`floor_headroom_ratio` for the Tor file from your next inspection, then propose a floor. 10 is very loose. |
| X4BNet IPv4 CIDRs | 1,000 | 10,942 (28 Oct), 11,011 (30 Oct) | ~11x | Unchanged. Stable, large margin. |
| X4BNet IPv6 CIDRs | 50 | 498 (28 Oct), 647 (30 Oct) | ~13x | Unchanged. Note the list grew about 30% in two days, so a ratio-based floor would be fragile. |
| Apple exclusion CIDRs | 100 | 3,490 on both dates | ~35x | Unchanged, but the loosest relative to risk: a truncated list that still passes could leave Apple ranges un-subtracted and produce a false VPN label. The failure direction is a false positive, so a higher floor (for example 1,000) is worth considering. Not applied: two identical observations are thin evidence, and a legitimate shrink would turn into SOURCE_UNAVAILABLE. Revisit after more inspections. |
| az0 total unique | 1,000 | 11,479 (28 Oct), 11,470 (30 Oct) | ~11x | Unchanged. |
| az0 per file | 1 | smallest observed files hold 2, 4, 52 addresses | n/a | Unchanged: small files are legitimate, so a uniform per-file floor is not possible. Limitation: a large file (`pia.txt` ~5,286, `nordvpn_api.txt` ~6,126) truncated to a few lines passes while the union stays above 1,000. A per-file floor for those two files is a possible later refinement. |

Boundary behaviour (exactly at the floor accepted, one below rejected) is now pinned by tests. Any future change to a floor must change those tests, which forces a recorded reason.

## 4. Rules audited

| Rule | Result |
|------|--------|
| Unavailable / malformed / stale / missing evidence is never negative | Holds. A kind is "covered" only by an applicable NO_MATCH. Confirmed by existing tests. |
| Current evidence is not proof of past status | Holds. Current-only snapshots apply within a symmetric tolerance (default 3,600 s) of retrieval. Limitation: the window also accepts observations up to one hour *before* retrieval. It is a configurable policy choice, left as is. |
| Unsupported IPv4/IPv6 coverage stays uncovered | Gap found and fixed: IPv4 symmetry for Tor and az0. IPv6 Apple-exclusion coverage now explicit. |
| Apple Private Relay exclusions | Preserved. Open gap documented: if `apple.txt` contains no IPv6 CIDRs, IPv6 relay ranges present in X4BNet `ipv6.txt` (if any) cannot be subtracted. Whether X4BNet's IPv6 output contains Apple ranges is unverified (observed IPv6 prefixes were /29 to /48). |
| Provenance, UTC-aware timestamps, snapshot SHA-256, determinism | Preserved; unchanged code paths. |
| Hosting-only evidence never gives a VPN label | Preserved; classifier untouched. |

## 5. Tests added (`tests/test_workstream_a_audit.py`, 17 cases)

- Floor constants pinned; inclusive boundary for Tor, X4BNet IPv4, IPv6, Apple (including that a short Apple list blocks a match rather than allowing it), and az0 total.
- IPv4 uncovered for Tor-only-IPv6 and az0-only-IPv6 data, and the resulting `UNKNOWN_PROVIDER_NOT_CONFIGURED`.
- X4BNet IPv6 Apple gap recorded; not added for IPv4; IPv6 Apple ranges excluded when listed.
- Conflict stays Unknown regardless of adapter order, carries `matched_cidr`, hashes and UTC time, and is not hidden by an unrelated az0 outage.
- Inspection: per-CIDR attribution, `also_in_az0`, floor headroom, Apple IPv6 note, text/JSON difference.

No existing test was edited or removed. Verified against the original code, 7 of the 17 fail (the new behaviours) and 10 pass (pins of existing behaviour).

## 6. Unresolved concerns

1. The 269 overlap is unexplained until you inspect `by_matched_cidr` on a live run.
2. Tor floor of 10 has no observed basis in the repository.
3. GitHub sources send no Last-Modified, so "current" means "retrieved now", not "built recently". A stalled X4BNet or az0 pipeline would not be detected. Commit timestamps are not implemented.
4. Partial truncation passes every floor; a truncated VPN list can hide a conflict (leaving "Known Tor exit") or a truncated Apple list can cause a false VPN label.
5. Tor match stands while VPN sources are down (conflict undetectable), by existing documented design.
6. Apple IPv6 exclusion coverage depends on data not yet inspected.
7. Tolerance window is symmetric around retrieval time.
8. Tor Project endpoint: reachable on your machine per your baseline, but its entry count and IPv6 content are not recorded in these docs.

## 7. Live inspection record

Author, this workstream: no live source reached. Maintainer baseline: live inspection succeeded on 30 October 2026 (per maintainer; sources reached are not itemised in the project files, so please record them from your `inspect_sources.py` output).

## 8. Windows PowerShell verification

```powershell
cd path\to\viltrumites-ps010
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
python --version
python -m pytest -v 2>&1 | Tee-Object test-results.txt
python -m pytest tests\test_workstream_a_audit.py -v
python scripts\inspect_sources.py --json inspection-report.json   # live, needs internet
```

Expected at the time of this audit: 286 passed (269 + 17). Superseded: the full integrated suite now also
contains the RIPEstat tests; use the count your own run reports (see `docs/INTEGRATION_AUDIT.md`).
