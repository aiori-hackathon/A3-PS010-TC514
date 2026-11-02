"""Deterministic classification rules. Pure function: no I/O, no clock.

Rule order (see the project README for the full policy):
  1. Excluded address            -> Unknown / UNKNOWN_EXCLUDED_ADDRESS
  2. Temporal applicability of every evidence record
  3. Conflict                    -> Unknown / UNKNOWN_CONFLICTING_EVIDENCE
  4. Exactly one kind matched    -> that label
  5. Otherwise Unknown, reason chosen by fixed priority:
       SOURCE_UNAVAILABLE > STALE_EVIDENCE > PROVIDER_NOT_CONFIGURED
       > HOSTING_ONLY > NO_QUALIFYING_MATCH

A kind (Tor / VPN-proxy) is "covered" only if at least one APPLICABLE source
returned NO_MATCH for it. A failed request is never treated as a negative.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable, Optional

from .address_policy import assess_address
from .models import (
    Applicability,
    ClassificationResult,
    EvidenceAssessment,
    EvidenceKind,
    EvidenceRecord,
    EvidenceStatus,
    Label,
    NetworkContext,
    Observation,
    ReasonCode,
)

POLICY_VERSION = "ps010-policy-1"

# A current-only snapshot (no validity interval) supports an observation only
# if the observation time is within this distance of the retrieval time.
DEFAULT_CURRENT_TOLERANCE = timedelta(hours=1)

_KIND_LABEL = {
    EvidenceKind.TOR_EXIT: Label.KNOWN_TOR_EXIT,
    EvidenceKind.VPN_PROXY_ENDPOINT: Label.KNOWN_VPN_PROXY,
}
_KIND_MATCH_REASON = {
    EvidenceKind.TOR_EXIT: ReasonCode.TOR_EXIT_MATCH,
    EvidenceKind.VPN_PROXY_ENDPOINT: ReasonCode.VPN_PROXY_ENDPOINT_MATCH,
}
_KIND_NAME = {
    EvidenceKind.TOR_EXIT: "Tor exit",
    EvidenceKind.VPN_PROXY_ENDPOINT: "hosted VPN/proxy endpoint",
}

# Priority when evidence is incomplete (highest first).
_INCOMPLETE_PRIORITY = (
    ReasonCode.UNKNOWN_SOURCE_UNAVAILABLE,
    ReasonCode.UNKNOWN_STALE_EVIDENCE,
    ReasonCode.UNKNOWN_PROVIDER_NOT_CONFIGURED,
)
_REASON_ORDER = list(ReasonCode)

_BASE_EXPLANATION = {
    ReasonCode.UNKNOWN_SOURCE_UNAVAILABLE: (
        "At least one required evidence source could not be queried, so the "
        "absence of a match cannot be established."
    ),
    ReasonCode.UNKNOWN_STALE_EVIDENCE: (
        "Available evidence does not cover the observation time, so it cannot "
        "support or rule out a label."
    ),
    ReasonCode.UNKNOWN_PROVIDER_NOT_CONFIGURED: (
        "No evidence source was configured or supplied for a required evidence "
        "kind, so the system cannot check it."
    ),
    ReasonCode.UNKNOWN_HOSTING_ONLY: (
        "No qualifying Tor or VPN/proxy evidence was found. The address only "
        "carries a hosting-network indicator, which is not sufficient for a "
        "VPN/proxy label."
    ),
    ReasonCode.UNKNOWN_NO_QUALIFYING_MATCH: (
        "All required evidence kinds were checked with evidence that applies to "
        "the observation time, and no source lists this address."
    ),
}

_HOSTING_NOTE = (
    " A hosting-network indicator is present in the network context; it is not "
    "evidence of VPN/proxy use and did not influence the label."
)


def temporal_applicability(
    record: EvidenceRecord, observed_at, tolerance: timedelta
) -> Applicability:
    """Does this record's evidence cover the observation time?"""
    if record.status in (EvidenceStatus.SOURCE_UNAVAILABLE, EvidenceStatus.NOT_CONFIGURED):
        return Applicability.NOT_EVALUATED

    if record.has_validity_interval:
        if record.valid_from is not None and observed_at < record.valid_from:
            return Applicability.STALE
        if record.valid_to is not None and observed_at > record.valid_to:
            return Applicability.STALE
        return Applicability.APPLICABLE

    # Current-only snapshot: only meaningful near its retrieval time.
    if abs(observed_at - record.retrieved_at) <= tolerance:
        return Applicability.APPLICABLE
    return Applicability.STALE


def _note(record: EvidenceRecord, applicability: Applicability, tolerance: timedelta) -> str:
    if applicability is Applicability.NOT_EVALUATED:
        return record.error or record.status.value
    if record.has_validity_interval:
        window = (
            f"{record.valid_from.isoformat() if record.valid_from else '...'} to "
            f"{record.valid_to.isoformat() if record.valid_to else '...'}"
        )
        if applicability is Applicability.APPLICABLE:
            return f"observation time is inside validity interval {window}"
        return f"observation time is outside validity interval {window}"
    seconds = int(tolerance.total_seconds())
    if applicability is Applicability.APPLICABLE:
        return (
            f"current-only snapshot retrieved {record.retrieved_at.isoformat()} is within "
            f"{seconds}s of the observation time"
        )
    return (
        f"current-only snapshot retrieved {record.retrieved_at.isoformat()} is more than "
        f"{seconds}s from the observation time and cannot support a claim about it"
    )


def _sort_key(record: EvidenceRecord):
    # Total ordering so results never depend on the order evidence was supplied.
    return (
        record.kind.value,
        record.source_name,
        record.retrieved_at,
        record.status.value,
        record.model_dump_json(),
    )


def _ordered(codes: Iterable[ReasonCode]) -> list[ReasonCode]:
    return sorted(set(codes), key=_REASON_ORDER.index)


def classify(
    observation: Observation,
    evidence: Iterable[EvidenceRecord],
    context: Optional[NetworkContext] = None,
    *,
    current_tolerance: timedelta = DEFAULT_CURRENT_TOLERANCE,
) -> ClassificationResult:
    """Classify one observation. Same inputs always give the same output."""

    def build(label, reason, explanation, extras=(), assessments=(), caveats=()):
        return ClassificationResult(
            ip=observation.ip,
            observed_at=observation.observed_at,
            label=label,
            reason_code=reason,
            additional_reason_codes=_ordered(extras),
            explanation=explanation,
            evidence_assessments=list(assessments),
            caveats=list(caveats),
            network_context=context,
            policy_version=POLICY_VERSION,
        )

    # ---- Rule 1: excluded addresses ----------------------------------
    address = assess_address(observation.ip)
    if not address.allowed:
        return build(Label.UNKNOWN, ReasonCode.UNKNOWN_EXCLUDED_ADDRESS, address.message)

    # ---- Rule 2: temporal applicability -------------------------------
    records = sorted(evidence, key=_sort_key)
    pairs: list[tuple[EvidenceRecord, EvidenceAssessment]] = []
    for record in records:
        applicability = temporal_applicability(record, observation.observed_at, current_tolerance)
        pairs.append(
            (
                record,
                EvidenceAssessment(
                    source_name=record.source_name,
                    kind=record.kind,
                    status=record.status,
                    applicability=applicability,
                    note=_note(record, applicability, current_tolerance),
                ),
            )
        )
    assessments = [a for _, a in pairs]

    caveats = [
        f"{r.source_name} ({_KIND_NAME[r.kind]}): {a.note}"
        for r, a in pairs
        if a.applicability is not Applicability.APPLICABLE
    ]

    applicable = [(r, a) for r, a in pairs if a.applicability is Applicability.APPLICABLE]

    # ---- Rule 3: conflicts -------------------------------------------
    matched_sources: dict[EvidenceKind, list[str]] = {k: [] for k in EvidenceKind}
    statuses_by_source: dict[tuple[str, EvidenceKind], set[EvidenceStatus]] = defaultdict(set)
    for r, _ in applicable:
        statuses_by_source[(r.source_name, r.kind)].add(r.status)
        if r.status is EvidenceStatus.MATCH:
            matched_sources[r.kind].append(r.source_name)

    conflicts: list[str] = []
    if matched_sources[EvidenceKind.TOR_EXIT] and matched_sources[EvidenceKind.VPN_PROXY_ENDPOINT]:
        conflicts.append(
            "applicable evidence lists this address as both a Tor exit "
            f"({', '.join(sorted(set(matched_sources[EvidenceKind.TOR_EXIT])))}) and a hosted "
            f"VPN/proxy endpoint ({', '.join(sorted(set(matched_sources[EvidenceKind.VPN_PROXY_ENDPOINT])))})"
        )
    for (source, kind), seen in sorted(
        statuses_by_source.items(), key=lambda item: (item[0][0], item[0][1].value)
    ):
        if EvidenceStatus.MATCH in seen and EvidenceStatus.NO_MATCH in seen:
            conflicts.append(
                f"source {source!r} returned both MATCH and NO_MATCH for {_KIND_NAME[kind]}"
            )
    if conflicts:
        return build(
            Label.UNKNOWN,
            ReasonCode.UNKNOWN_CONFLICTING_EVIDENCE,
            "Conflicting evidence: " + "; ".join(conflicts) + ". "
            "Policy returns Unknown instead of choosing between conflicting claims.",
            assessments=assessments,
            caveats=caveats,
        )

    # ---- Rule 4: a single, unambiguous positive match -----------------
    matched_kinds = [k for k in EvidenceKind if matched_sources[k]]
    if len(matched_kinds) == 1:
        kind = matched_kinds[0]
        sources = ", ".join(sorted(set(matched_sources[kind])))
        return build(
            _KIND_LABEL[kind],
            _KIND_MATCH_REASON[kind],
            f"Applicable evidence from {sources} lists this address as a {_KIND_NAME[kind]} "
            "at the observation time. This classifies network evidence only; it does not "
            "identify a person or device.",
            assessments=assessments,
            caveats=caveats,
        )

    # ---- Rule 5: Unknown; decide which Unknown ------------------------
    uncovered: dict[EvidenceKind, ReasonCode] = {}
    for kind in EvidenceKind:
        kind_pairs = [(r, a) for r, a in pairs if r.kind is kind]
        covered = any(
            a.applicability is Applicability.APPLICABLE and r.status is EvidenceStatus.NO_MATCH
            for r, a in kind_pairs
        )
        if covered:
            continue
        if any(r.status is EvidenceStatus.SOURCE_UNAVAILABLE for r, _ in kind_pairs):
            uncovered[kind] = ReasonCode.UNKNOWN_SOURCE_UNAVAILABLE
        elif any(a.applicability is Applicability.STALE for _, a in kind_pairs):
            uncovered[kind] = ReasonCode.UNKNOWN_STALE_EVIDENCE
        else:
            # NOT_CONFIGURED records, or no record of this kind supplied at all.
            uncovered[kind] = ReasonCode.UNKNOWN_PROVIDER_NOT_CONFIGURED

    hosting = context is not None and context.hosting_indicator
    incomplete_reasons = set(uncovered.values())

    if incomplete_reasons:
        primary = next(code for code in _INCOMPLETE_PRIORITY if code in incomplete_reasons)
        extras = incomplete_reasons - {primary}
        if hosting:
            extras.add(ReasonCode.UNKNOWN_HOSTING_ONLY)
    elif hosting:
        primary = ReasonCode.UNKNOWN_HOSTING_ONLY
        extras = set()
    else:
        primary = ReasonCode.UNKNOWN_NO_QUALIFYING_MATCH
        extras = set()

    explanation = _BASE_EXPLANATION[primary]
    if uncovered:
        details = "; ".join(
            f"{_KIND_NAME[kind]}: {code.value}"
            for kind, code in sorted(uncovered.items(), key=lambda item: item[0].value)
        )
        explanation += f" Incomplete evidence kinds: {details}."
    if hosting and primary is not ReasonCode.UNKNOWN_HOSTING_ONLY:
        explanation += _HOSTING_NOTE

    return build(
        Label.UNKNOWN,
        primary,
        explanation,
        extras=extras,
        assessments=assessments,
        caveats=caveats,
    )
