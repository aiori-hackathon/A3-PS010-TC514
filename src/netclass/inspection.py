"""Measure the real data sources and the overlaps between them.

Used by scripts/inspect_sources.py to verify live endpoints from the user's own
machine and to produce the numbers needed for the open policy decisions (for
example, how many Tor exits also fall inside X4BNet VPN ranges). Nothing here
is cached: every run downloads fresh copies.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Optional

from .adapters.tor import TOR_MIN_ENTRIES
from .adapters.x4bnet import X4B_MIN_APPLE, X4B_MIN_V4, X4B_MIN_V6
from .errors import SourceError
from .http_client import Clock, Fetcher, utc_now
from .parsers import CidrSet, parse_cidr_list, parse_ip_list
from .snapshots import SnapshotProvider
from .sources import AZ0_VPN_SOURCE, TOR_SOURCE, X4BNET_VPN_SOURCE

SAMPLE = 5


@dataclass(frozen=True)
class Floors:
    """Minimum plausible entry counts (sanity floors) used while inspecting."""

    tor: int = TOR_MIN_ENTRIES
    x4_v4: int = X4B_MIN_V4
    x4_v6: int = X4B_MIN_V6
    apple: int = X4B_MIN_APPLE
    az0_file: int = 1


def _load(
    provider: SnapshotProvider, source: str, url: str, parser, floor: Optional[int] = None
) -> tuple[dict[str, Any], Any]:
    entry: dict[str, Any] = {"source": source, "url": url}
    try:
        loaded = provider.load(source, url, parser)
    except SourceError as exc:
        entry.update(status="UNAVAILABLE", error_kind=exc.kind.value, error=str(exc))
        return entry, None
    snap, parsed = loaded.snapshot, loaded.parsed
    entry.update(
        status="OK",
        sha256=snap.sha256,
        bytes=snap.size,
        retrieved_at=snap.retrieved_at.isoformat(),
        last_modified=snap.source_timestamp.isoformat() if snap.source_timestamp else None,
        etag=snap.headers.get("etag"),
        entries=parsed.count,
        ipv4_entries=parsed.v4_count,
        ipv6_entries=parsed.v6_count,
        comment_lines=parsed.comment_lines,
    )
    if floor:
        # Workstream A: how far above its sanity floor the observed file is.
        entry["sanity_floor"] = floor
        entry["floor_headroom_ratio"] = round(parsed.count / floor, 2)
    if hasattr(parsed, "cidrs"):
        entry["prefix_range_v4"] = parsed.cidrs.prefix_range(4)
        entry["prefix_range_v6"] = parsed.cidrs.prefix_range(6)
    return entry, parsed


def _group_by_cidr(addresses, vpn_set_for, apple) -> dict[str, int]:
    """Count addresses per most specific genuine (non-Apple) X4BNet CIDR, largest first."""
    counts: dict[str, int] = {}
    for ip in addresses:
        cidrs = vpn_set_for(ipaddress.ip_address(ip).version)
        if cidrs is None:
            continue
        nets = [n for n in cidrs.match_all(ip) if not (apple and apple.cidrs.has_network(n))]
        if nets:
            key = str(nets[0])
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def inspect_sources(
    fetcher: Fetcher,
    *,
    clock: Clock = utc_now,
    max_source_age_seconds: Optional[int] = None,
    floors: Optional[Floors] = None,
) -> dict[str, Any]:
    floors = floors or Floors()
    provider = SnapshotProvider(
        fetcher, None, ttl_seconds=0, clock=clock, max_source_age_seconds=max_source_age_seconds
    )
    files: list[dict[str, Any]] = []

    tor_entry, tor = _load(
        provider,
        TOR_SOURCE.name,
        TOR_SOURCE.endpoints[0],
        lambda b: parse_ip_list(b, source=TOR_SOURCE.name, min_entries=floors.tor),
        floors.tor,
    )
    files.append(tor_entry)

    x4_v4_entry, x4_v4 = _load(
        provider,
        X4BNET_VPN_SOURCE.name,
        X4BNET_VPN_SOURCE.endpoints[0],
        lambda b: parse_cidr_list(b, source="x4bnet:ipv4", family=4, min_entries=floors.x4_v4),
        floors.x4_v4,
    )
    x4_v6_entry, x4_v6 = _load(
        provider,
        X4BNET_VPN_SOURCE.name,
        X4BNET_VPN_SOURCE.endpoints[1],
        lambda b: parse_cidr_list(b, source="x4bnet:ipv6", family=6, min_entries=floors.x4_v6),
        floors.x4_v6,
    )
    apple_entry, apple = _load(
        provider,
        X4BNET_VPN_SOURCE.name,
        X4BNET_VPN_SOURCE.auxiliary_endpoints[0],
        lambda b: parse_cidr_list(b, source="x4bnet:apple", min_entries=floors.apple),
        floors.apple,
    )
    files += [x4_v4_entry, x4_v6_entry, apple_entry]

    az0_sets = {}
    for url in AZ0_VPN_SOURCE.endpoints:
        name = url.rsplit("/", 1)[-1]
        entry, parsed = _load(
            provider,
            AZ0_VPN_SOURCE.name,
            url,
            lambda b, name=name: parse_ip_list(b, source=f"az0:{name}", min_entries=floors.az0_file),
        )
        files.append(entry)
        if parsed is not None:
            az0_sets[name] = parsed

    report: dict[str, Any] = {
        "generated_at": clock().isoformat(),
        "files": files,
        "overlap": {},
        "notes": [],
    }

    # ---- overlaps (only for the data that actually loaded) ----------------
    az0_all: set[str] = set().union(*(p.entries for p in az0_sets.values())) if az0_sets else set()
    if az0_sets:
        report["az0_total_unique_addresses"] = len(az0_all)

    def genuine(cidrs: Optional[CidrSet], ip: str) -> bool:
        """In an X4BNet VPN range that is NOT an Apple Private Relay range."""
        if cidrs is None:
            return False
        matches = cidrs.match_all(ip)
        return any(not (apple and apple.cidrs.has_network(n)) for n in matches)

    def vpn_set_for(version: int) -> Optional[CidrSet]:
        parsed = x4_v4 if version == 4 else x4_v6
        return parsed.cidrs if parsed is not None else None

    overlap = report["overlap"]
    if tor is not None and az0_sets:
        both = sorted(tor.entries & az0_all)
        overlap["tor_and_az0_exact"] = {"count": len(both), "sample": both[:SAMPLE]}
    if tor is not None and (x4_v4 is not None or x4_v6 is not None):
        in_range = [
            ip
            for ip in sorted(tor.entries)
            if genuine(vpn_set_for(ipaddress.ip_address(ip).version), ip)
        ]
        overlap["tor_inside_x4bnet_vpn_ranges"] = {
            "count": len(in_range),
            "of_tor_entries": tor.count,
            "sample": in_range[:SAMPLE],
            "note": "each of these would classify as Unknown (conflicting evidence)",
            # Workstream A: attribution detail for investigating the overlap. Every
            # address is listed so the set can be diffed between runs; policy is unchanged.
            "all_addresses": in_range,
            "by_matched_cidr": _group_by_cidr(in_range, vpn_set_for, apple),
            "also_in_az0": sorted(set(in_range) & az0_all),
        }
        if apple is not None:
            in_apple = [ip for ip in sorted(tor.entries) if apple.cidrs.match(ip) is not None]
            overlap["tor_inside_apple_private_relay_ranges"] = {
                "count": len(in_apple),
                "sample": in_apple[:SAMPLE],
            }
    if az0_sets and x4_v4 is not None:
        v4 = [ip for ip in sorted(az0_all) if ":" not in ip]
        inside = [ip for ip in v4 if genuine(x4_v4.cidrs, ip)]
        overlap["az0_inside_x4bnet_vpn_ranges"] = {
            "count": len(inside),
            "of_az0_ipv4": len(v4),
            "not_in_x4bnet": len(v4) - len(inside),
        }
    if az0_sets and apple is not None:
        in_apple = [ip for ip in sorted(az0_all) if apple.cidrs.match(ip) is not None]
        overlap["az0_inside_apple_private_relay_ranges"] = {"count": len(in_apple)}
    if apple is not None:
        report["apple_cidrs_total"] = apple.count
        report["apple_cidrs_ipv6"] = apple.v6_count
        if apple.v6_count == 0:
            report["notes"].append(
                "apple.txt holds no IPv6 CIDRs: Apple Private Relay exclusion cannot be "
                "applied to IPv6 matches from X4BNet ipv6.txt."
            )

    failed = [f for f in files if f["status"] != "OK"]
    if failed:
        report["notes"].append(
            f"{len(failed)} file(s) could not be loaded; overlaps involving them are omitted."
        )
    return report


def format_report(report: dict[str, Any]) -> str:
    lines = [f"Source inspection report ({report['generated_at']})", ""]
    for f in report["files"]:
        name = f["url"].rsplit("/", 1)[-1] or f["url"]
        if f["status"] == "OK":
            extra = ""
            if f.get("prefix_range_v4") or f.get("prefix_range_v6"):
                extra = f" prefixes v4={f.get('prefix_range_v4')} v6={f.get('prefix_range_v6')}"
            lines.append(
                f"[OK]          {f['source']} / {name}: {f['entries']} entries "
                f"(v4 {f['ipv4_entries']}, v6 {f['ipv6_entries']}), {f['bytes']} bytes, "
                f"sha256 {f['sha256'][:16]}...{extra}"
                + (
                    f" floor {f['sanity_floor']} (x{f['floor_headroom_ratio']})"
                    if f.get("sanity_floor")
                    else ""
                )
            )
            if f.get("last_modified"):
                lines.append(f"              Last-Modified: {f['last_modified']}")
        else:
            lines.append(f"[UNAVAILABLE] {f['source']} / {name}: {f['error']}")
    lines.append("")
    if report["overlap"]:
        lines.append("Overlaps (genuine X4BNet VPN ranges exclude Apple Private Relay):")
        for key, value in report["overlap"].items():
            if isinstance(value, dict) and "all_addresses" in value:
                value = {k: v for k, v in value.items() if k != "all_addresses"}
                value["by_matched_cidr"] = dict(list(value["by_matched_cidr"].items())[:10])
                lines.append("  (top 10 CIDRs shown; full address list is in the --json report)")
            lines.append(f"  {key}: {value}")
    else:
        lines.append("No overlaps could be computed (required files were unavailable).")
    for note in report["notes"]:
        lines.append(f"NOTE: {note}")
    return "\n".join(lines)
