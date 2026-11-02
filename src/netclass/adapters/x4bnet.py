"""X4BNet lists_vpn adapter (evidence kind: VPN_PROXY_ENDPOINT, range-level).

Only the VPN-only output files are used (output/vpn/ipv4.txt, ipv6.txt). The
datacenter lists are never fetched.

Apple Private Relay policy: input/vpn/ips/apple.txt lists the Apple Private
Relay CIDRs, and each of them also appears verbatim in the merged VPN output.
They are subtracted exactly: a CIDR listed in apple.txt is not VPN evidence.
An address matched ONLY by such CIDRs is reported as NO_MATCH, with the
exclusion recorded in the metadata and limitations. If the exclusion list
cannot be loaded while an address matches a VPN range, the result is
SOURCE_UNAVAILABLE (we cannot rule out that the match is Apple's).
"""
from __future__ import annotations

from typing import Optional

from ..errors import SourceError
from ..http_client import Clock, utc_now
from ..models import EvidenceRecord, EvidenceStatus
from ..parsers import IPAddress, ParsedCidrList, parse_cidr_list
from ..snapshots import SnapshotProvider
from ..sources import X4BNET_VPN_SOURCE
from .base import EvidenceAdapter, file_metadata

# Sanity floors (observed 2026-10-28: 10,942 IPv4 / 498 IPv6 / 3,490 Apple CIDRs).
X4B_MIN_V4 = 1000
X4B_MIN_V6 = 50
X4B_MIN_APPLE = 100


class X4BNetVpnAdapter(EvidenceAdapter):
    spec = X4BNET_VPN_SOURCE

    def __init__(
        self,
        provider: SnapshotProvider,
        *,
        ipv4_url: Optional[str] = None,
        ipv6_url: Optional[str] = None,
        apple_url: Optional[str] = None,
        min_v4: int = X4B_MIN_V4,
        min_v6: int = X4B_MIN_V6,
        min_apple: int = X4B_MIN_APPLE,
        clock: Clock = utc_now,
    ) -> None:
        super().__init__(provider, clock=clock)
        self._v4_url = ipv4_url or self.spec.endpoints[0]
        self._v6_url = ipv6_url or self.spec.endpoints[1]
        self._apple_url = apple_url or self.spec.auxiliary_endpoints[0]
        self._min = {4: min_v4, 6: min_v6}
        self._min_apple = min_apple

    def _parser_for(self, version: int, label: str):
        def parse(body: bytes) -> ParsedCidrList:
            return parse_cidr_list(
                body, source=f"{self.name}:{label}", family=version, min_entries=self._min[version]
            )

        return parse

    def _parse_apple(self, body: bytes) -> ParsedCidrList:
        return parse_cidr_list(
            body, source=f"{self.name}:apple.txt", family=None, min_entries=self._min_apple
        )

    def _lookup(self, ip: IPAddress) -> EvidenceRecord:
        url = self._v4_url if ip.version == 4 else self._v6_url
        label = "ipv4.txt" if ip.version == 4 else "ipv6.txt"
        vpn = self._provider.load(self.name, url, self._parser_for(ip.version, label))
        snapshots = [vpn.snapshot]
        metadata = {
            "granularity": "cidr-range",
            "address_family": f"IPv{ip.version}",
            "list_entries": vpn.parsed.count,
            "files": [file_metadata(vpn.snapshot)],
        }

        matches = vpn.parsed.cidrs.match_all(ip)
        if not matches:
            return self._build_record(
                status=EvidenceStatus.NO_MATCH, endpoint=url, snapshots=snapshots, metadata=metadata
            )

        # The address lies in at least one listed range: check the Apple exclusion list.
        try:
            apple = self._provider.load(self.name, self._apple_url, self._parse_apple)
        except SourceError as exc:
            raise exc.with_context(
                f"address matched VPN range {matches[0]} but the Apple Private Relay "
                "exclusion list could not be loaded, so the match cannot be verified"
            ) from exc

        snapshots.append(apple.snapshot)
        metadata["files"].append(file_metadata(apple.snapshot))
        metadata["apple_exclusion_entries"] = apple.parsed.count

        # Audit note: the Apple exclusion list is only as wide as its content. If it holds
        # no IPv6 CIDRs, an IPv6 match cannot have been checked against Apple IPv6 ranges.
        v6_gap: list[str] = []
        if ip.version == 6:
            metadata["apple_exclusion_ipv6_entries"] = apple.parsed.v6_count
            if apple.parsed.v6_count == 0:
                v6_gap.append(
                    "Apple Private Relay exclusion list holds no IPv6 CIDRs, so this IPv6 "
                    "match could not be checked against Apple IPv6 relay ranges."
                )

        genuine = [net for net in matches if not apple.parsed.cidrs.has_network(net)]
        excluded = [str(net) for net in matches if apple.parsed.cidrs.has_network(net)]
        if genuine:
            metadata["matched_cidr"] = str(genuine[0])  # most specific non-Apple range
            metadata["all_matching_cidrs"] = [str(n) for n in genuine]
            if excluded:
                metadata["also_matched_apple_cidrs_ignored"] = excluded
            return self._build_record(
                status=EvidenceStatus.MATCH,
                endpoint=url,
                snapshots=snapshots,
                metadata=metadata,
                extra_limitations=v6_gap,
            )

        metadata["excluded_by_policy"] = "apple_private_relay"
        metadata["excluded_cidrs"] = excluded
        return self._build_record(
            status=EvidenceStatus.NO_MATCH,
            endpoint=url,
            snapshots=snapshots,
            metadata=metadata,
            extra_limitations=[
                "Address lies only in Apple Private Relay ranges. Policy: Apple Private Relay "
                "is not treated as a conventional hosted VPN, so these ranges give no VPN evidence."
            ],
        )
