"""Validated data models shared by every layer of the prototype.

All datetimes must be timezone-aware and are normalised to UTC. Naive
datetimes are rejected on purpose: ambiguity about time zones is exactly the
kind of error an evidence-based system must not make silently.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .address_policy import AddressCategory, assess_address

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
class Label(StrEnum):
    """The only three primary labels the system may return."""

    KNOWN_TOR_EXIT = "Known Tor exit"
    KNOWN_VPN_PROXY = "Known hosted VPN/proxy endpoint"
    UNKNOWN = "Unknown"


class ReasonCode(StrEnum):
    # Declaration order is the deterministic order used for secondary codes.
    TOR_EXIT_MATCH = "TOR_EXIT_MATCH"
    VPN_PROXY_ENDPOINT_MATCH = "VPN_PROXY_ENDPOINT_MATCH"
    UNKNOWN_EXCLUDED_ADDRESS = "UNKNOWN_EXCLUDED_ADDRESS"
    UNKNOWN_CONFLICTING_EVIDENCE = "UNKNOWN_CONFLICTING_EVIDENCE"
    UNKNOWN_SOURCE_UNAVAILABLE = "UNKNOWN_SOURCE_UNAVAILABLE"
    UNKNOWN_STALE_EVIDENCE = "UNKNOWN_STALE_EVIDENCE"
    UNKNOWN_PROVIDER_NOT_CONFIGURED = "UNKNOWN_PROVIDER_NOT_CONFIGURED"
    UNKNOWN_HOSTING_ONLY = "UNKNOWN_HOSTING_ONLY"
    UNKNOWN_NO_QUALIFYING_MATCH = "UNKNOWN_NO_QUALIFYING_MATCH"


class EvidenceKind(StrEnum):
    TOR_EXIT = "TOR_EXIT"
    VPN_PROXY_ENDPOINT = "VPN_PROXY_ENDPOINT"


class EvidenceStatus(StrEnum):
    MATCH = "MATCH"  # source was queried and lists the address
    NO_MATCH = "NO_MATCH"  # source was queried successfully and does not list it
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"  # timeout / HTTP error / malformed data
    NOT_CONFIGURED = "NOT_CONFIGURED"  # no provider set up for this kind


class Applicability(StrEnum):
    APPLICABLE = "APPLICABLE"  # evidence covers the observation time
    STALE = "STALE"  # evidence does NOT cover the observation time
    NOT_EVALUATED = "NOT_EVALUATED"  # unavailable / not configured: nothing to evaluate


def _require_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware (UTC); naive datetimes are rejected")
    return value.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# Input
# --------------------------------------------------------------------------
class Observation(BaseModel):
    """One thing to classify: an IP address seen at a specific UTC time."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ip: str
    observed_at: datetime

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, value: str) -> str:
        assessment = assess_address(value)
        if assessment.category is AddressCategory.INVALID:
            raise ValueError(assessment.message)
        assert assessment.normalized is not None
        return assessment.normalized

    @field_validator("observed_at")
    @classmethod
    def _validate_observed_at(cls, value: datetime) -> datetime:
        result = _require_utc(value)
        assert result is not None
        return result


# --------------------------------------------------------------------------
# Evidence (what a source says about an address) and provenance
# --------------------------------------------------------------------------
class EvidenceRecord(BaseModel):
    """One source's answer for one address, with full provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_name: str = Field(min_length=1)
    source_endpoint: str = Field(min_length=1)
    kind: EvidenceKind
    status: EvidenceStatus
    retrieved_at: datetime  # UTC retrieval time
    source_timestamp: Optional[datetime] = None  # timestamp provided by the source
    valid_from: Optional[datetime] = None  # evidence validity interval, if known
    valid_to: Optional[datetime] = None
    snapshot_sha256: Optional[str] = None  # hash of the retained raw snapshot
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None  # required for SOURCE_UNAVAILABLE / NOT_CONFIGURED
    limitations: list[str] = Field(default_factory=list)

    @field_validator("retrieved_at", "source_timestamp", "valid_from", "valid_to")
    @classmethod
    def _utc(cls, value: Optional[datetime]) -> Optional[datetime]:
        return _require_utc(value)

    @field_validator("snapshot_sha256")
    @classmethod
    def _sha(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        lowered = value.strip().lower()
        if not _SHA256_RE.match(lowered):
            raise ValueError("snapshot_sha256 must be 64 lowercase hex characters")
        return lowered

    @model_validator(mode="after")
    def _consistency(self) -> "EvidenceRecord":
        if self.valid_from and self.valid_to and self.valid_from > self.valid_to:
            raise ValueError("valid_from must not be after valid_to")
        if self.status in (EvidenceStatus.SOURCE_UNAVAILABLE, EvidenceStatus.NOT_CONFIGURED):
            if not self.error:
                raise ValueError(f"error text is required when status is {self.status.value}")
        return self

    @property
    def has_validity_interval(self) -> bool:
        return self.valid_from is not None or self.valid_to is not None


# --------------------------------------------------------------------------
# Network context (NOT evidence: never decides a label on its own)
# --------------------------------------------------------------------------
class NetworkContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    asn: Optional[int] = Field(default=None, ge=0)
    as_name: Optional[str] = None
    prefix: Optional[str] = None
    country_code: Optional[str] = None
    source_name: Optional[str] = None
    retrieved_at: Optional[datetime] = None
    # A hosting indicator is context only. It can explain an Unknown result
    # (UNKNOWN_HOSTING_ONLY) but can never produce a VPN/proxy label.
    hosting_indicator: bool = False
    hosting_indicator_basis: Optional[str] = None

    @field_validator("retrieved_at")
    @classmethod
    def _utc(cls, value: Optional[datetime]) -> Optional[datetime]:
        return _require_utc(value)

    @model_validator(mode="after")
    def _basis_required(self) -> "NetworkContext":
        if self.hosting_indicator and not self.hosting_indicator_basis:
            raise ValueError("hosting_indicator_basis is required when hosting_indicator is True")
        return self


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
class EvidenceAssessment(BaseModel):
    """How the classifier treated one evidence record (feeds the dashboard table)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_name: str
    kind: EvidenceKind
    status: EvidenceStatus
    applicability: Applicability
    note: str


class ClassificationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ip: str
    observed_at: datetime
    label: Label
    reason_code: ReasonCode
    additional_reason_codes: list[ReasonCode] = Field(default_factory=list)
    explanation: str
    evidence_assessments: list[EvidenceAssessment] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
    network_context: Optional[NetworkContext] = None  # shown separately from evidence
    policy_version: str
