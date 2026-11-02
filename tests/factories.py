"""Test helpers. Fixture IP addresses are arbitrary public addresses; they are
NOT claims about any real Tor exit or VPN endpoint."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from netclass.hashing import sha256_hex
from netclass.models import (
    EvidenceKind,
    EvidenceRecord,
    EvidenceStatus,
    NetworkContext,
    Observation,
)

T0 = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
PUBLIC_IP = "185.220.101.45"
OTHER_PUBLIC_IP = "8.8.8.8"

S = EvidenceStatus
K = EvidenceKind


def obs(ip: str = PUBLIC_IP, at: datetime = T0) -> Observation:
    return Observation(ip=ip, observed_at=at)


def record(
    kind: EvidenceKind,
    status: EvidenceStatus,
    *,
    source: Optional[str] = None,
    retrieved_at: datetime = T0,
    valid_from: Optional[datetime] = None,
    valid_to: Optional[datetime] = None,
    error: Optional[str] = None,
) -> EvidenceRecord:
    if status in (S.SOURCE_UNAVAILABLE, S.NOT_CONFIGURED) and error is None:
        error = "simulated condition for tests"
    name = source or f"fixture-{kind.value.lower()}"
    return EvidenceRecord(
        source_name=name,
        source_endpoint=f"https://fixture.invalid/{kind.value.lower()}",
        kind=kind,
        status=status,
        retrieved_at=retrieved_at,
        valid_from=valid_from,
        valid_to=valid_to,
        snapshot_sha256=sha256_hex(b"fixture-snapshot"),
        error=error,
    )


def tor(status: EvidenceStatus, **kwargs) -> EvidenceRecord:
    return record(K.TOR_EXIT, status, **kwargs)


def vpn(status: EvidenceStatus, **kwargs) -> EvidenceRecord:
    return record(K.VPN_PROXY_ENDPOINT, status, **kwargs)


def hosting_context() -> NetworkContext:
    return NetworkContext(
        asn=64496,
        as_name="FIXTURE-HOSTING",
        hosting_indicator=True,
        hosting_indicator_basis="fixture ASN list used in tests",
    )


def hours(n: float) -> timedelta:
    return timedelta(hours=n)
