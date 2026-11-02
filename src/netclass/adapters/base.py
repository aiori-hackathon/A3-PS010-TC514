"""Shared behaviour for evidence adapters.

Contract: `lookup(ip)` ALWAYS returns an EvidenceRecord and never raises. Any
SourceError (or unexpected exception) becomes a SOURCE_UNAVAILABLE record, so a
failed download can never be mistaken for a negative result.
"""
from __future__ import annotations

import ipaddress
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Iterable, Optional

from ..cache import Snapshot
from ..errors import SourceError, SourceErrorKind
from ..hashing import manifest_sha256
from ..http_client import Clock, utc_now
from ..models import EvidenceRecord, EvidenceStatus
from ..parsers import IPAddress, normalise_ip
from ..snapshots import SnapshotProvider
from ..sources import SourceSpec

logger = logging.getLogger(__name__)


def file_metadata(snapshot: Snapshot) -> dict[str, Any]:
    """JSON-safe provenance for one retained file."""
    return {
        "url": snapshot.url,
        "sha256": snapshot.sha256,
        "bytes": snapshot.size,
        "retrieved_at": snapshot.retrieved_at.isoformat(),
        "source_timestamp": snapshot.source_timestamp.isoformat()
        if snapshot.source_timestamp
        else None,
        "from_cache": snapshot.from_cache,
        "http_headers": dict(snapshot.headers),
        "notes": list(snapshot.notes),
    }


class EvidenceAdapter(ABC):
    spec: SourceSpec

    def __init__(self, provider: SnapshotProvider, *, clock: Clock = utc_now) -> None:
        self._provider = provider
        self._clock = clock

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def primary_endpoint(self) -> str:
        return self.spec.endpoints[0]

    # ------------------------------------------------------------------
    def lookup(self, ip: str) -> EvidenceRecord:
        try:
            address = normalise_ip(ipaddress.ip_address(ip))
            return self._lookup(address)
        except SourceError as exc:
            return self._failure_record(exc)
        except Exception as exc:  # fail safe: an internal bug is "unavailable", never "no match"
            logger.exception("Unexpected error in adapter %s", self.name)
            return self._failure_record(
                SourceError(SourceErrorKind.INTERNAL, f"unexpected {type(exc).__name__}: {exc}")
            )

    @abstractmethod
    def _lookup(self, ip: IPAddress) -> EvidenceRecord:
        """Return MATCH / NO_MATCH / NOT_CONFIGURED, or raise SourceError."""

    # ------------------------------------------------------------------
    def _build_record(
        self,
        *,
        status: EvidenceStatus,
        endpoint: str,
        snapshots: Iterable[Snapshot],
        metadata: dict[str, Any],
        error: Optional[str] = None,
        extra_limitations: Iterable[str] = (),
    ) -> EvidenceRecord:
        snaps = list(snapshots)
        source_timestamp: Optional[datetime] = None
        sha: Optional[str] = None
        if snaps:
            retrieved_at = min(s.retrieved_at for s in snaps)  # oldest file governs freshness
            sha = (
                snaps[0].sha256
                if len(snaps) == 1
                else manifest_sha256((s.url, s.sha256) for s in snaps)
            )
            stamps = [s.source_timestamp for s in snaps if s.source_timestamp is not None]
            source_timestamp = min(stamps) if stamps else None
        else:
            retrieved_at = self._clock()
        return EvidenceRecord(
            source_name=self.spec.name,
            source_endpoint=endpoint,
            kind=self.spec.kind,
            status=status,
            retrieved_at=retrieved_at,
            source_timestamp=source_timestamp,
            snapshot_sha256=sha,
            metadata=metadata,
            error=error,
            limitations=[*self.spec.limitations, *extra_limitations],
        )

    def _failure_record(self, exc: SourceError) -> EvidenceRecord:
        return self._build_record(
            status=EvidenceStatus.SOURCE_UNAVAILABLE,
            endpoint=exc.url or self.primary_endpoint,
            snapshots=[],
            metadata={"error_kind": exc.kind.value, "http_status": exc.status_code},
            error=str(exc),
        )
