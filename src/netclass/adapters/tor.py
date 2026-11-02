"""Tor Project bulk exit list adapter (evidence kind: TOR_EXIT).

The list is a current-only snapshot of exit addresses. Use it only for
observations close to the retrieval time; the classifier enforces that.
"""
from __future__ import annotations

from typing import Optional

from ..http_client import Clock, utc_now
from ..models import EvidenceRecord, EvidenceStatus
from ..parsers import IPAddress, ParsedIpList, parse_ip_list
from ..snapshots import SnapshotProvider
from ..sources import TOR_SOURCE
from .base import EvidenceAdapter, file_metadata

# Sanity floor, not a claim about the real list size: far fewer entries than any
# realistic exit list suggests a truncated or wrong file.
TOR_MIN_ENTRIES = 10


class TorExitListAdapter(EvidenceAdapter):
    spec = TOR_SOURCE

    def __init__(
        self,
        provider: SnapshotProvider,
        *,
        url: Optional[str] = None,
        min_entries: int = TOR_MIN_ENTRIES,
        clock: Clock = utc_now,
    ) -> None:
        super().__init__(provider, clock=clock)
        self._url = url or TOR_SOURCE.endpoints[0]
        self._min_entries = min_entries

    @property
    def primary_endpoint(self) -> str:
        return self._url

    def _parse(self, body: bytes) -> ParsedIpList:
        return parse_ip_list(body, source=self.name, min_entries=self._min_entries)

    def _lookup(self, ip: IPAddress) -> EvidenceRecord:
        loaded = self._provider.load(self.name, self._url, self._parse)
        snapshot, parsed = loaded.snapshot, loaded.parsed
        metadata = {
            "granularity": "exact-address",
            "list_entries": parsed.count,
            "ipv4_entries": parsed.v4_count,
            "ipv6_entries": parsed.v6_count,
            "snapshot": file_metadata(snapshot),
        }
        common = dict(endpoint=self._url, snapshots=[snapshot], metadata=metadata)
        address = str(ip)

        if address in parsed:
            metadata["matched_entry"] = address
            return self._build_record(status=EvidenceStatus.MATCH, **common)

        if ip.version == 4 and parsed.v4_count == 0:
            # Mirror of the IPv6 rule: a list with no IPv4 exits at all says nothing
            # about an IPv4 address (Workstream A audit).
            return self._build_record(
                status=EvidenceStatus.NOT_CONFIGURED,
                error=(
                    "IPv4 not covered: the retrieved Tor exit list contains no IPv4 entries, "
                    "so absence of this IPv4 address cannot be treated as a negative"
                ),
                **common,
            )
        if ip.version == 6 and parsed.v6_count == 0:
            # The list shows no IPv6 exit addresses at all, so we cannot claim this
            # IPv6 address is "not an exit": its absence proves nothing.
            return self._build_record(
                status=EvidenceStatus.NOT_CONFIGURED,
                error=(
                    "IPv6 not covered: the retrieved Tor exit list contains no IPv6 entries, "
                    "so absence of this IPv6 address cannot be treated as a negative"
                ),
                **common,
            )
        return self._build_record(status=EvidenceStatus.NO_MATCH, **common)
