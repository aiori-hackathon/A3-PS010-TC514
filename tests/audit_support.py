"""Audit test helpers that need no pydantic.

``fake_result`` builds an object shaped like ``netclass.service.ServiceResult``: it exposes
``classification``, ``evidence``, ``ripestat_context``, ``ipinfo_metadata`` and
``service_version``, and each part has ``model_dump(mode="json")`` returning the same JSON
shape the real models produce. The store only relies on that interface, so the SQLite layer
can be tested independently of the models. (End-to-end tests with the real models are in
test_audit_service_integration.py and test_audit_cli.py.)

Addresses and markers are fixtures, not claims about real networks.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Optional

T0 = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
SHA = "a" * 64
IPINFO_MARKER = "IPINFO-ONLY-MARKER-NET"
RIPESTAT_MARKER = "RIPESTAT-ONLY-MARKER-HOLDER"
FAKE_TOKEN = "tok_FIXTURE_0123456789abcdef"


class Dumpable:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def model_dump(self, mode: str = "json") -> dict[str, Any]:
        return copy.deepcopy(self.data)


class FakeServiceResult:
    def __init__(
        self,
        classification: Dumpable,
        evidence: list[Dumpable],
        ripestat_context: Optional[Dumpable] = None,
        ipinfo_metadata: Optional[Dumpable] = None,
        service_version: str = "ps010-service-1",
    ) -> None:
        self.classification = classification
        self.evidence = evidence
        self.ripestat_context = ripestat_context
        self.ipinfo_metadata = ipinfo_metadata
        self.service_version = service_version


def evidence_dump(kind: str = "TOR_EXIT", status: str = "NO_MATCH", **over: Any) -> dict[str, Any]:
    doc = {
        "source_name": f"fixture-{kind.lower()}",
        "source_endpoint": f"https://fixture.invalid/{kind.lower()}",
        "kind": kind,
        "status": status,
        "retrieved_at": "2026-10-28T12:00:00Z",
        "source_timestamp": None,
        "valid_from": None,
        "valid_to": None,
        "snapshot_sha256": SHA,
        "metadata": {"files": [{"url": "https://fixture.invalid/x", "sha256": SHA, "bytes": 10}]},
        "error": None,
        "limitations": ["current-only snapshot"],
    }
    doc.update(over)
    return doc


def fake_result(
    ip: str = "8.8.8.8",
    *,
    label: str = "Unknown",
    reason: str = "UNKNOWN_NO_QUALIFYING_MATCH",
    observed_at: str = "2026-10-28T12:00:00Z",
    explanation: str = "No qualifying evidence.",
    evidence: Optional[list[dict[str, Any]]] = None,
    ripestat: bool = False,
    ipinfo: bool = False,
    ipinfo_over: Optional[dict[str, Any]] = None,
    extra_classification: Optional[dict[str, Any]] = None,
) -> FakeServiceResult:
    if evidence is None:
        evidence = [evidence_dump("TOR_EXIT"), evidence_dump("VPN_PROXY_ENDPOINT")]
    assessments = [
        {
            "source_name": e["source_name"],
            "kind": e["kind"],
            "status": e["status"],
            "applicability": "APPLICABLE",
            "note": f"{e['source_name']} covers the observation time",
        }
        for e in evidence
    ]
    classification = {
        "ip": ip,
        "observed_at": observed_at,
        "label": label,
        "reason_code": reason,
        "additional_reason_codes": [],
        "explanation": explanation,
        "evidence_assessments": assessments,
        "caveats": ["Classifies network evidence only."],
        "network_context": None,
        "policy_version": "ps010-policy-1",
    }
    classification.update(extra_classification or {})
    ripe = None
    if ripestat:
        ripe = Dumpable(
            {
                "ip": ip,
                "status": "AVAILABLE",
                "requested_at": "2026-10-28T12:00:00Z",
                "routing": {"prefix": "8.8.8.0/24", "asns": [15169], "status": "OK"},
                "holders": [{"asn": 15169, "holder": RIPESTAT_MARKER, "status": "OK"}],
                "error": None,
                "note": None,
                "limitations": ["context only"],
            }
        )
    info = None
    if ipinfo:
        payload = {
            "ip": ip,
            "status": "AVAILABLE",
            "requested_at": "2026-10-28T12:00:00Z",
            "asn": 64496,
            "as_name": IPINFO_MARKER,
            "as_domain": "example.net",
            "country_code": "US",
            "country": "United States",
            "continent_code": "NA",
            "continent": "North America",
            "provenance": {
                "source_name": "ipinfo-lite-api",
                "endpoint": f"https://api.ipinfo.io/lite/{ip}",
                "retrieved_at": "2026-10-28T12:00:00Z",
                "from_cache": False,
                "response_sha256": SHA,
            },
            "error": None,
            "note": None,
            "warnings": [],
            "limitations": ["supplementary metadata only"],
        }
        payload.update(ipinfo_over or {})
        info = Dumpable(payload)
    return FakeServiceResult(
        Dumpable(classification), [Dumpable(e) for e in evidence], ripe, info
    )
