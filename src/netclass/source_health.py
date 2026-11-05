"""Source-health vocabulary and records. Pure data: no network, no classification.

This module answers one question per source file: "could we establish what the source
says?" It is deliberately separate from the classifier. It never produces a label and
never duplicates classification rules; it only states how much weight
a source's silence can carry.

Key distinction (existing policy, unchanged): only a HEALTHY source can support
"confirmed absence of matching evidence". Every other state means "not established".
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Optional

from .errors import SourceErrorKind


class SourceHealthState(StrEnum):
    HEALTHY = "HEALTHY"  # fetched in full and parsed; counts plausible
    SOURCE_FAILURE = "SOURCE_FAILURE"  # could not retrieve it (timeout, network, HTTP, size)
    STALE = "STALE"  # retrieved, but the source's own timestamp says it is too old
    PARSE_FAILURE = "PARSE_FAILURE"  # retrieved, but not in the documented format
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"  # empty or below the sanity floor
    NOT_CHECKED = "NOT_CHECKED"  # skipped (for example the request budget ran out)


class AbsenceSupport(StrEnum):
    """What a source's 'no match' may be taken to mean."""

    CONFIRMED_ABSENCE = "CONFIRMED_ABSENCE"  # healthy source, address not listed
    NOT_ESTABLISHED = "NOT_ESTABLISHED"  # source unhealthy: silence proves nothing


_STATE_FOR_ERROR = {
    SourceErrorKind.TIMEOUT: SourceHealthState.SOURCE_FAILURE,
    SourceErrorKind.CONNECTION: SourceHealthState.SOURCE_FAILURE,
    SourceErrorKind.HTTP_STATUS: SourceHealthState.SOURCE_FAILURE,
    SourceErrorKind.TOO_LARGE: SourceHealthState.SOURCE_FAILURE,
    SourceErrorKind.INTERNAL: SourceHealthState.SOURCE_FAILURE,
    SourceErrorKind.MALFORMED: SourceHealthState.PARSE_FAILURE,
    SourceErrorKind.EMPTY: SourceHealthState.INSUFFICIENT_EVIDENCE,
    SourceErrorKind.TOO_SMALL: SourceHealthState.INSUFFICIENT_EVIDENCE,
    SourceErrorKind.STALE_SOURCE: SourceHealthState.STALE,
}


def state_for_error(kind: SourceErrorKind) -> SourceHealthState:
    return _STATE_FOR_ERROR[kind]


def absence_support(state: SourceHealthState) -> AbsenceSupport:
    """Only a HEALTHY source can turn 'not listed' into 'confirmed absence'."""
    if state is SourceHealthState.HEALTHY:
        return AbsenceSupport.CONFIRMED_ABSENCE
    return AbsenceSupport.NOT_ESTABLISHED


@dataclass
class SourceHealthRecord:
    """Everything known about one fetched file. Free-text fields are already redacted."""

    source: str  # registry name, e.g. "tor_exit_list"
    file: str  # human label of the file, e.g. "ipv4.txt"
    role: str  # "evidence" or "exclusion"
    url: str  # redacted
    state: SourceHealthState
    checked_at: Optional[datetime] = None
    error_kind: Optional[str] = None
    message: Optional[str] = None
    http_status: Optional[int] = None
    attempts: int = 0
    elapsed_seconds: Optional[float] = None
    bytes: Optional[int] = None
    sha256: Optional[str] = None
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    source_age_seconds: Optional[float] = None
    freshness_verifiable: bool = False
    parser_outcome: Optional[str] = None  # "OK" or the SourceErrorKind that stopped the parser
    records: Optional[int] = None
    ipv4_records: Optional[int] = None
    ipv6_records: Optional[int] = None
    sanity_floor: Optional[int] = None
    notes: list[str] = field(default_factory=list)

    @property
    def absence(self) -> AbsenceSupport:
        return absence_support(self.state)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        data["checked_at"] = self.checked_at.isoformat() if self.checked_at else None
        data["absence_support"] = self.absence.value
        return data
