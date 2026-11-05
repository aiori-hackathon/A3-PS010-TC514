"""Service layer: one stable entry point for callers.

    from netclass.service import ClassificationService
    service = ClassificationService.from_settings(load_settings())
    outcome = service.classify(observation)                       # classification only
    outcome = service.classify(observation, include_ipinfo=True)  # + optional metadata

WHAT IT DOES
    1. Classifies with the existing evidence pipeline (``collector`` +
       ``classifier``). No classification rule lives in this module.
    2. Optionally attaches RIPEstat network context.
    3. Optionally attaches IPinfo supplementary metadata.

GUARANTEES (pinned by tests/test_service_layer.py)
    * ``outcome.classification`` is computed BEFORE, and without any input from,
      IPinfo. Enabling, disabling, or failing IPinfo cannot change the label, the
      reason codes, the evidence assessments or any other field of it.
    * Classification errors are never hidden: an invalid observation or a bug in the
      classification path raises. Only OPTIONAL lookups are contained: their failure
      becomes an explicit status inside ``ipinfo_metadata``.
    * Nothing is sent to IPinfo unless the caller passes ``include_ipinfo=True`` AND a
      usable token is configured. Excluded addresses are never sent.

AUDIT HISTORY (opt-in)
    * ``classify()`` is unchanged and NEVER writes anything, whether or not an audit store
      is configured. ``ServiceResult`` is unchanged.
    * ``classify_and_record()`` classifies exactly as ``classify()`` does, then tries to save
      the result and returns it together with an explicit ``AuditOutcome``: SAVED (only after
      the database transaction committed), FAILED (the classification is still returned) or
      DISABLED (no store configured; nothing was written).
    * The audit store is never read here, so stored history cannot influence a label.
"""
from __future__ import annotations

import logging
from datetime import datetime
from enum import StrEnum
from typing import Iterable, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .adapters import EvidenceAdapter
from .audit import AuditStore
from .collector import (
    build_adapters,
    build_context_service,
    build_ipinfo_service,
    classify_with_context,
    classify_with_evidence,
)
from .config import Settings
from .http_client import Clock, Fetcher, utc_now
from .ipinfo import IpInfoErrorKind, IpInfoMetadata, IpInfoService, failed_metadata
from .models import ClassificationResult, EvidenceRecord, Observation
from .ripestat import RipeStatContext, RipeStatContextService

SERVICE_VERSION = "ps010-service-1"

logger = logging.getLogger(__name__)


class ServiceResult(BaseModel):
    """Everything one call returns. Each part is clearly separated.

    * ``classification`` and ``evidence``: the authoritative result and its sources.
    * ``ripestat_context`` / ``ipinfo_metadata``: supplementary, ``None`` when not requested.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    service_version: str = SERVICE_VERSION
    classification: ClassificationResult
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    ripestat_context: Optional[RipeStatContext] = None
    ipinfo_metadata: Optional[IpInfoMetadata] = None


class AuditStatus(StrEnum):
    SAVED = "SAVED"  # the record was committed to the audit database
    FAILED = "FAILED"  # saving failed; nothing was saved; the classification is still valid
    DISABLED = "DISABLED"  # no audit store configured; nothing was written


class AuditOutcome(BaseModel):
    """What happened to the audit record of one ``classify_and_record`` call."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: AuditStatus
    run_id: Optional[int] = None
    recorded_at: Optional[datetime] = None
    error: Optional[str] = None  # redacted, clipped description; set for FAILED only
    note: Optional[str] = None

    @model_validator(mode="after")
    def _consistent(self) -> "AuditOutcome":
        if self.status is AuditStatus.SAVED:
            if self.run_id is None or self.recorded_at is None or self.error is not None:
                raise ValueError("SAVED needs run_id and recorded_at and no error")
        elif self.run_id is not None or self.recorded_at is not None:
            raise ValueError(f"{self.status.value} must not carry a run_id or recorded_at")
        if self.status is AuditStatus.FAILED and not self.error:
            raise ValueError("FAILED needs an error description")
        return self


class AuditedResult(BaseModel):
    """A ``ServiceResult`` plus the explicit outcome of saving it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    result: ServiceResult
    audit: AuditOutcome


class ClassificationService:
    def __init__(
        self,
        settings: Settings,
        adapters: Iterable[EvidenceAdapter],
        *,
        ripestat: Optional[RipeStatContextService] = None,
        ipinfo: Optional[IpInfoService] = None,
        audit: Optional[AuditStore] = None,
        clock: Clock = utc_now,
    ) -> None:
        self._settings = settings
        self._adapters = list(adapters)
        self._ripestat = ripestat
        # Without an IPinfo service the integration is simply disabled.
        self._ipinfo = ipinfo or IpInfoService(None, token=None, clock=clock)
        self._audit = audit
        self._clock = clock

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        fetcher: Optional[Fetcher] = None,
        ripestat_fetcher: Optional[Fetcher] = None,
        ipinfo_fetcher: Optional[Fetcher] = None,
        audit: Optional[AuditStore] = None,
        clock: Clock = utc_now,
    ) -> "ClassificationService":
        """Build the evidence adapters and both optional services from settings.

        Nothing here touches the network or the disk; requests happen only inside
        ``classify`` and the audit database is only touched by ``classify_and_record``.
        An audit store is created only when ``settings.audit_enabled`` (or one is passed in).
        """
        if audit is None and settings.audit_enabled:
            audit = AuditStore(
                settings.db_path,
                clock=clock,
                secrets=(settings.ipinfo_token, settings.vpn_provider_api_key),
            )
        return cls(
            settings,
            build_adapters(settings, fetcher=fetcher, clock=clock),
            ripestat=build_context_service(settings, fetcher=ripestat_fetcher, clock=clock),
            ipinfo=build_ipinfo_service(settings, fetcher=ipinfo_fetcher, clock=clock),
            audit=audit,
            clock=clock,
        )

    @property
    def ipinfo_enabled(self) -> bool:
        return self._ipinfo.enabled

    @property
    def audit_enabled(self) -> bool:
        return self._audit is not None

    def classify(
        self,
        observation: Observation,
        *,
        include_ripestat: bool = False,
        include_ipinfo: bool = False,
    ) -> ServiceResult:
        """Classify one observation and optionally attach supplementary context.

        Raises only for classification problems or programming errors (for example
        asking for RIPEstat context from a service built without one). A failing
        optional lookup never raises: see ``ipinfo_metadata.status`` and ``.error``.
        """
        ripe: Optional[RipeStatContext] = None
        if include_ripestat:
            if self._ripestat is None:
                raise ValueError("RIPEstat context was requested but no RIPEstat service is set")
            result, records, ripe = classify_with_context(
                observation, self._adapters, self._settings, self._ripestat
            )
        else:
            result, records = classify_with_evidence(observation, self._adapters, self._settings)

        metadata = self._ipinfo_metadata(observation.ip) if include_ipinfo else None
        return ServiceResult(
            classification=result,
            evidence=records,
            ripestat_context=ripe,
            ipinfo_metadata=metadata,
        )

    def classify_and_record(
        self,
        observation: Observation,
        *,
        include_ripestat: bool = False,
        include_ipinfo: bool = False,
    ) -> AuditedResult:
        """``classify`` plus an attempt to save the result to the audit history.

        The classification is computed first, by ``classify``, with no knowledge of the audit
        store. A failure to save never changes or hides it; it is reported in ``audit``.
        Classification errors still raise, exactly as in ``classify``.
        """
        result = self.classify(
            observation, include_ripestat=include_ripestat, include_ipinfo=include_ipinfo
        )
        return AuditedResult(result=result, audit=self._record_audit(result))

    def _record_audit(self, result: ServiceResult) -> AuditOutcome:
        if self._audit is None:
            return AuditOutcome(
                status=AuditStatus.DISABLED,
                note="audit history is not enabled; nothing was written",
            )
        try:
            receipt = self._audit.record(result)
        except Exception as exc:  # a failed save must never hide a successful classification
            message = self._audit.safe_error(exc)
            logger.warning("audit record was NOT saved: %s", message)  # no record contents
            return AuditOutcome(status=AuditStatus.FAILED, error=message)
        return AuditOutcome(
            status=AuditStatus.SAVED, run_id=receipt.run_id, recorded_at=receipt.recorded_at
        )

    def _ipinfo_metadata(self, ip: str) -> IpInfoMetadata:
        try:
            return self._ipinfo.lookup(ip)
        except Exception as exc:  # IpInfoService.lookup never raises; this guards a replacement
            return failed_metadata(
                ip,
                self._clock(),
                IpInfoErrorKind.INTERNAL,
                f"unexpected metadata failure ({type(exc).__name__})",
            )
