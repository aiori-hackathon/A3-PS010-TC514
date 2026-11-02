"""az0/vpn_ip adapter (evidence kind: VPN_PROXY_ENDPOINT, exact-address).

Reads the per-provider raw input files in data/input/ip. Policy:
  * nordvpn.txt (DNS resolver addresses) is never fetched or counted.
  * A MATCH in any loaded file stands, even if other files failed (the address
    really is listed); the failures are recorded in the metadata.
  * NO_MATCH is only reported when EVERY configured file loaded. If any file
    failed, absence cannot be established and the result is SOURCE_UNAVAILABLE.
  * The union of loaded files must reach a sanity floor, else UNAVAILABLE.
  * If the loaded data holds no IPv6 entries, an IPv6 query is "not covered".
"""
from __future__ import annotations

from typing import Optional, Sequence

from ..errors import SourceError, SourceErrorKind
from ..http_client import Clock, utc_now
from ..models import EvidenceRecord, EvidenceStatus
from ..parsers import IPAddress, ParsedIpList, parse_ip_list
from ..snapshots import SnapshotProvider
from ..sources import AZ0_VPN_SOURCE
from .base import EvidenceAdapter, file_metadata

# Sanity floor on the union of all files (observed 2026-10-28: 11,479 addresses).
AZ0_MIN_TOTAL = 1000


class Az0VpnIpAdapter(EvidenceAdapter):
    spec = AZ0_VPN_SOURCE

    def __init__(
        self,
        provider: SnapshotProvider,
        *,
        urls: Optional[Sequence[str]] = None,
        min_total_entries: int = AZ0_MIN_TOTAL,
        clock: Clock = utc_now,
    ) -> None:
        super().__init__(provider, clock=clock)
        self._urls = tuple(sorted(urls if urls is not None else self.spec.endpoints))
        if not self._urls:
            raise ValueError("at least one az0 file URL is required")
        self._min_total = min_total_entries

    @property
    def primary_endpoint(self) -> str:
        return self._urls[0].rsplit("/", 1)[0] + "/"

    def _parser_for(self, url: str):
        label = url.rsplit("/", 1)[-1]

        def parse(body: bytes) -> ParsedIpList:
            return parse_ip_list(body, source=f"{self.name}:{label}", min_entries=1)

        return parse

    def _lookup(self, ip: IPAddress) -> EvidenceRecord:
        loaded = []
        failures: list[dict] = []
        for url in self._urls:
            try:
                loaded.append(self._provider.load(self.name, url, self._parser_for(url)))
            except SourceError as exc:
                failures.append({"url": url, "error_kind": exc.kind.value, "error": str(exc)})

        endpoint = self.primary_endpoint
        if not loaded:
            raise SourceError(
                SourceErrorKind.CONNECTION,
                f"none of the {len(self._urls)} az0 files could be loaded: "
                + " | ".join(f["error"] for f in failures),
                url=endpoint,
            )

        total = len(set().union(*(item.parsed.entries for item in loaded)))
        total_v6 = sum(item.parsed.v6_count for item in loaded)
        total_v4 = sum(item.parsed.v4_count for item in loaded)
        if total < self._min_total:
            raise SourceError(
                SourceErrorKind.TOO_SMALL,
                f"loaded az0 files hold only {total} addresses, below the sanity floor of "
                f"{self._min_total}"
                + (f" ({len(failures)} file(s) failed)" if failures else ""),
                url=endpoint,
            )

        snapshots = [item.snapshot for item in loaded]
        address = str(ip)
        matched_files = [
            item.snapshot.url.rsplit("/", 1)[-1] for item in loaded if address in item.parsed
        ]
        metadata = {
            "granularity": "exact-address",
            "files_loaded": len(loaded),
            "files_failed": failures,
            "list_entries_total": total,
            "ipv6_entries_total": total_v6,
            "files": [file_metadata(item.snapshot) for item in loaded],
        }
        extra = (
            [f"{len(failures)} az0 file(s) failed to load; coverage was partial for this lookup."]
            if failures
            else []
        )

        if matched_files:
            metadata["matched_files"] = sorted(matched_files)
            metadata["matched_entry"] = address
            return self._build_record(
                status=EvidenceStatus.MATCH,
                endpoint=endpoint,
                snapshots=snapshots,
                metadata=metadata,
                extra_limitations=extra,
            )

        if failures:
            raise SourceError(
                SourceErrorKind.CONNECTION,
                f"address not found in the {len(loaded)} loaded az0 file(s), but "
                f"{len(failures)} file(s) failed so absence cannot be established: "
                + " | ".join(f["error"] for f in failures),
                url=endpoint,
            )

        if ip.version == 4 and total_v4 == 0:
            return self._build_record(
                status=EvidenceStatus.NOT_CONFIGURED,
                endpoint=endpoint,
                snapshots=snapshots,
                metadata=metadata,
                error=(
                    "IPv4 not covered: the retrieved az0 files contain no IPv4 addresses, "
                    "so absence of this IPv4 address cannot be treated as a negative"
                ),
            )
        if ip.version == 6 and total_v6 == 0:
            return self._build_record(
                status=EvidenceStatus.NOT_CONFIGURED,
                endpoint=endpoint,
                snapshots=snapshots,
                metadata=metadata,
                error=(
                    "IPv6 not covered: the retrieved az0 files contain no IPv6 addresses, "
                    "so absence of this IPv6 address cannot be treated as a negative"
                ),
            )
        return self._build_record(
            status=EvidenceStatus.NO_MATCH,
            endpoint=endpoint,
            snapshots=snapshots,
            metadata=metadata,
        )
