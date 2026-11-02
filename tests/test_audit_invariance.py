"""Stage 5 must not change the classification policy: labels, reason codes, enum values."""
from netclass.audit import schema
from netclass.classifier import POLICY_VERSION
from netclass.models import (
    Applicability,
    EvidenceKind,
    EvidenceStatus,
    Label,
    ReasonCode,
)
from netclass.service import SERVICE_VERSION, AuditedResult, AuditOutcome, ServiceResult


def values(enum):
    return tuple(member.value for member in enum)


def test_schema_literals_equal_the_live_enums():
    """If a label/reason/kind/status is ever added, a new migration is required."""
    assert schema.LABELS == values(Label)
    assert schema.REASON_CODES == values(ReasonCode)
    assert schema.EVIDENCE_KINDS == values(EvidenceKind)
    assert schema.EVIDENCE_STATUSES == values(EvidenceStatus)
    assert schema.APPLICABILITIES == values(Applicability)


def test_policy_and_service_versions_are_unchanged():
    assert POLICY_VERSION == "ps010-policy-1"
    assert SERVICE_VERSION == "ps010-service-1"


def test_service_result_shape_is_unchanged_and_audit_lives_in_a_wrapper():
    assert tuple(ServiceResult.model_fields) == (
        "service_version", "classification", "evidence", "ripestat_context", "ipinfo_metadata",
    )
    assert tuple(AuditedResult.model_fields) == ("result", "audit")
    assert tuple(AuditOutcome.model_fields) == ("status", "run_id", "recorded_at", "error", "note")
