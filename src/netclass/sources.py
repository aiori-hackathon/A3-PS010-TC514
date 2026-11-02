"""Registry of the hackathon-provided evidence sources.

This module is DATA ONLY: it records what was found when the sources were
inspected (formats, licences, update processes, limitations) so adapters,
the dashboard and the audit log can all cite the same facts. It performs no
network access.

Facts here were checked on 2026-10-28 by inspecting the repositories. The Tor
entry could not be downloaded in that session and is based on Tor Project
documentation; Stage 2 must verify it against a real download.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import EvidenceKind


@dataclass(frozen=True)
class SourceSpec:
    name: str  # stable id; used as EvidenceRecord.source_name
    kind: EvidenceKind
    description: str
    endpoints: tuple[str, ...]  # exact files the adapter may fetch
    data_format: str
    granularity: str  # "exact-address" or "cidr-range"
    temporal_support: str  # "current-only" for all three sources today
    update_process: str
    license: str
    attribution: str
    limitations: tuple[str, ...]
    # Extra files fetched to REFINE the evidence (never used as evidence themselves).
    auxiliary_endpoints: tuple[str, ...] = ()
    # Explicit policy exclusions: material deliberately NOT treated as VPN/proxy evidence.
    exclusions: tuple[str, ...] = ()


TOR_SOURCE = SourceSpec(
    name="tor-project-bulk-exit-list",
    kind=EvidenceKind.TOR_EXIT,
    description="Tor Project list of IP addresses observed as exit relays.",
    endpoints=("https://check.torproject.org/torbulkexitlist",),
    data_format="Plain text, one IP address per line (per Tor Project documentation; "
    "to be verified against a real download in Stage 2).",
    granularity="exact-address",
    temporal_support="current-only",
    update_process="Maintained by the Tor Project from active measurements. Tor "
    "documentation says it is updated at most every ~40 minutes and that fetching "
    "it hourly is reasonable.",
    license="No licence statement found at the endpoint. Treat as publicly "
    "published operational data; cite the Tor Project.",
    attribution="Tor Project, https://check.torproject.org/torbulkexitlist",
    limitations=(
        "Current snapshot only: it cannot support claims about past observation times.",
        "Lists exit relay addresses; it does not identify any person or session.",
        "An address may stay listed for some time after a relay stops exiting "
        "(reported by a relay operator; unverified).",
        "Per-entry timestamps are not known to be present; validity interval is unknown.",
        "IPv6 coverage is unverified: if a downloaded snapshot contains no IPv6 entries, "
        "IPv6 queries are reported as not covered rather than as a negative match.",
    ),
)

X4BNET_VPN_SOURCE = SourceSpec(
    name="x4bnet-lists-vpn",
    kind=EvidenceKind.VPN_PROXY_ENDPOINT,
    description="X4BNet 'strictly VPN' netblock list (output/vpn only).",
    endpoints=(
        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt",
    ),
    data_format="Plain text, one CIDR per line (IPv4 and IPv6 in separate files); "
    "no comments or blank lines observed.",
    granularity="cidr-range",
    temporal_support="current-only",
    update_process="Rebuilt by GitHub Actions on a daily schedule and on input changes "
    "(inputs: provider ASNs plus per-provider netblock files).",
    license="MIT, Copyright (c) 2024 X4B (Mathew Heard). README states the licence "
    "covers the list itself.",
    attribution="X4BNet/lists_vpn, MIT License, Copyright (c) 2024 X4B (Mathew Heard), "
    "https://github.com/X4BNet/lists_vpn",
    limitations=(
        "Range-level evidence: a match means the address lies inside a listed VPN "
        "netblock, not that it is a confirmed active VPN endpoint.",
        "Partly derived from provider ASNs, so ranges can include non-VPN hosts.",
        "The ASN input includes an entry labelled as Tor exit servers and Apple "
        "Private Relay ranges, so the list is not strictly classic VPNs and can "
        "overlap with Tor evidence.",
        "output/datacenter/ and the legacy root ipv4.txt are DATACENTER lists and "
        "must never be used as VPN evidence.",
        "Current snapshot only; no per-entry timestamps (git history exists).",
    ),
    auxiliary_endpoints=(
        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ips/apple.txt",
    ),
    exclusions=(
        "Datacenter lists (output/datacenter/*, legacy root ipv4.txt) are never fetched: "
        "datacenter membership is not VPN evidence.",
        "Apple Private Relay: every CIDR in input/vpn/ips/apple.txt is removed from the "
        "VPN set. An address matched only by those ranges is reported as NO_MATCH with "
        "the exclusion recorded. Apple's relay is a privacy relay, not a conventional "
        "hosted VPN, so it is not labelled as one.",
    ),
)

AZ0_VPN_SOURCE = SourceSpec(
    name="az0-vpn-ip",
    kind=EvidenceKind.VPN_PROXY_ENDPOINT,
    description="az0/vpn_ip per-provider VPN server addresses (data/input/ip).",
    endpoints=(
        "https://raw.githubusercontent.com/az0/vpn_ip/main/data/input/ip/expressvpn.txt",
        "https://raw.githubusercontent.com/az0/vpn_ip/main/data/input/ip/hideme.txt",
        "https://raw.githubusercontent.com/az0/vpn_ip/main/data/input/ip/hideme_api.txt",
        "https://raw.githubusercontent.com/az0/vpn_ip/main/data/input/ip/nordvpn_api.txt",
        "https://raw.githubusercontent.com/az0/vpn_ip/main/data/input/ip/pia.txt",
    ),
    data_format="Plain text, one IPv4 address per line, optional trailing '# comment', "
    "and '#' header lines. Some files contain only headers.",
    granularity="exact-address",
    temporal_support="current-only",
    update_process="Repository updated by a scheduled GitHub Action twice a day. The "
    "curated ip.txt output is hosted off-GitHub; data/input/ip holds raw inputs.",
    license="GNU GPL v3 or later, Copyright (C) 2023-2024 Andrew Ziem. Do not bundle "
    "the data in this project; download at runtime and credit the author.",
    attribution="az0/vpn_ip, GPL-3.0-or-later, Copyright (C) 2023-2024 Andrew Ziem, "
    "https://github.com/az0/vpn_ip",
    limitations=(
        "Raw input files, not the curated final list; coverage is limited to the "
        "providers collected (observed files cover a handful of providers).",
        "Exact addresses only; IPv6 not observed.",
        "Files that contain only header comments today (for example hoxx_api.txt, "
        "protonvpn_api.txt, windscribe_api.txt) are not fetched; they add no data.",
        "Current snapshot only; no per-entry timestamps.",
    ),
    exclusions=(
        "nordvpn.txt (provider DNS resolver addresses, not tunnel endpoints) is never "
        "fetched or counted as VPN evidence.",
    ),
)

SOURCES: dict[str, SourceSpec] = {
    s.name: s for s in (TOR_SOURCE, X4BNET_VPN_SOURCE, AZ0_VPN_SOURCE)
}
