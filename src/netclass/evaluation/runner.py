"""Runs the evaluation through the EXISTING classification service. No rule lives here.

Two modes, always labeled in the report:

* ``replay`` (default, offline, deterministic): every synthetic case is classified by a real
  ``ClassificationService`` built from the real adapters, but their downloads are answered by a
  ``ReplayFetcher`` from the fixture "world" the case names. Nothing leaves the process.
* ``live`` (explicit opt-in, uses the network, NOT deterministic): reference-tier cases are
  classified with the real sources. The snapshot cache lives in a temporary directory that is
  deleted afterwards.

Isolation (pinned by tests/test_evaluation_isolation.py):
* the service is always built with ``audit=None`` and ``audit_enabled=False``; this package never
  imports the audit package, reads ``.env`` or writes to ``data/``;
* excluded addresses must trigger zero evidence fetches; the run records the fetch count of
  every case and reports any violation;
* no RIPEstat or IPinfo lookup is ever requested, so no context-only metadata is involved.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from .. import __version__
from ..adapters import Az0VpnIpAdapter, TorExitListAdapter, X4BNetVpnAdapter
from ..address_policy import assess_address
from ..classifier import POLICY_VERSION
from ..config import Settings
from ..http_client import utc_now
from ..models import Label, Observation, ReasonCode
from ..service import SERVICE_VERSION, ClassificationService
from ..snapshots import SnapshotProvider
from ..sources import AZ0_VPN_SOURCE, SOURCES, TOR_SOURCE, X4BNET_VPN_SOURCE
from .dataset import Case, Dataset, sha256_of_object
from .replay import CountingFetcher, ReplayFetcher, routes_for_world
from .report import REPORT_SCHEMA_VERSION, build_report

RUNNER_VERSION = "ps010-eval-runner-1"
REPLAY_SANITY_FLOOR = 1  # fixtures are tiny; the real floors are covered by the adapter tests
BASIS_REPLAY = "synthetic-fixture-replay"
BASIS_LIVE = "live-source-backed"

INVARIANTS_CHECKED = (
    "excluded_address_zero_fetches",
    "label_is_one_of_three",
    "repeat_run_identical",
)


class EvaluationError(Exception):
    """The evaluation cannot be run (not a dataset problem and not a classification result)."""


@dataclass(frozen=True)
class EvaluationConfig:
    mode: str
    evaluation_time: datetime
    current_evidence_tolerance_seconds: int
    cache_ttl_seconds: int
    max_source_age_seconds: int
    sanity_floor_entries: Optional[int]  # None = the adapters' real defaults
    disk_cache: str
    audit_enabled: bool
    include_ripestat: bool = False
    include_ipinfo: bool = False

    def as_dict(self) -> dict:
        return {
            "mode": self.mode,
            "evaluation_time": self.evaluation_time.isoformat(),
            "current_evidence_tolerance_seconds": self.current_evidence_tolerance_seconds,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "max_source_age_seconds": self.max_source_age_seconds,
            "sanity_floor_entries": self.sanity_floor_entries,
            "disk_cache": self.disk_cache,
            "audit_enabled": self.audit_enabled,
            "include_ripestat": self.include_ripestat,
            "include_ipinfo": self.include_ipinfo,
        }


def versions() -> dict:
    return {
        "package": __version__,
        "policy": POLICY_VERSION,
        "service": SERVICE_VERSION,
        "evaluation_runner": RUNNER_VERSION,
        "report_schema": REPORT_SCHEMA_VERSION,
    }


def source_provenance() -> list:
    out = []
    for name in sorted(SOURCES):
        spec = SOURCES[name]
        out.append({
            "name": spec.name,
            "kind": spec.kind.value,
            "granularity": spec.granularity,
            "temporal_support": spec.temporal_support,
            "license": spec.license,
            "attribution": spec.attribution,
            "endpoints": sorted([*spec.endpoints, *spec.auxiliary_endpoints]),
        })
    return out


def _base_settings(enabled: tuple, **changes) -> Settings:
    return replace(Settings(), enabled_sources=enabled, audit_enabled=False, **changes)


# --------------------------------------------------------------------------
# outcomes and invariants
# --------------------------------------------------------------------------
def _outcome(case: Case, service_result, fetch_calls: int) -> dict:
    result = service_result.classification
    return {
        "case_id": case.case_id,
        "tier": case.tier,
        "category": case.category,
        "world": case.world,
        "ip": case.ip,
        "ip_normalized": case.ip_normalized,
        "observed_at": case.observed_at.isoformat(),
        "expected_label": case.expected_label,
        "expected_reason_code": case.expected_reason_code,
        "predicted_label": result.label.value,
        "predicted_reason_code": result.reason_code.value,
        "additional_reason_codes": [code.value for code in result.additional_reason_codes],
        "explanation": result.explanation,
        "evidence": [
            {
                "source": a.source_name,
                "kind": a.kind.value,
                "status": a.status.value,
                "applicability": a.applicability.value,
            }
            for a in result.evidence_assessments
        ],
        "fetch_calls": fetch_calls,
        "address_excluded": not assess_address(case.ip).allowed,
        "reference": case.reference,
        "unlabeled_reason": case.unlabeled_reason,
    }


def check_outcome(outcome: dict, *, repeat_identical: Optional[bool]) -> list[dict]:
    """Invariants that must hold for every case, whatever its expected label."""
    found: list[dict] = []
    case_id = outcome["case_id"]
    if outcome["address_excluded"]:
        if outcome["fetch_calls"] != 0:
            found.append({"case_id": case_id, "invariant": "excluded_address_zero_fetches",
                          "detail": f"{outcome['fetch_calls']} evidence fetch(es) for an excluded address"})
        if outcome["predicted_reason_code"] != ReasonCode.UNKNOWN_EXCLUDED_ADDRESS.value or outcome["evidence"]:
            found.append({"case_id": case_id, "invariant": "excluded_address_zero_fetches",
                          "detail": "excluded address did not short-circuit to UNKNOWN_EXCLUDED_ADDRESS"})
    if outcome["predicted_label"] not in {label.value for label in Label}:
        found.append({"case_id": case_id, "invariant": "label_is_one_of_three",
                      "detail": f"unexpected label {outcome['predicted_label']!r}"})
    if repeat_identical is False:
        found.append({"case_id": case_id, "invariant": "repeat_run_identical",
                      "detail": "two classifications of the same observation differed"})
    return found


# --------------------------------------------------------------------------
# replay mode
# --------------------------------------------------------------------------
def default_replay_config(dataset: Dataset) -> EvaluationConfig:
    defaults = Settings()
    return EvaluationConfig(
        mode="replay",
        evaluation_time=dataset.evaluation_time,
        current_evidence_tolerance_seconds=defaults.current_evidence_tolerance_seconds,
        cache_ttl_seconds=defaults.cache_ttl_seconds,
        max_source_age_seconds=defaults.max_source_age_seconds,
        sanity_floor_entries=REPLAY_SANITY_FLOOR,
        disk_cache="none (in-memory only)",
        audit_enabled=False,
    )


def build_replay_service(world: dict, config: EvaluationConfig, *, ripestat=None, ipinfo=None):
    """A real ClassificationService over fixture evidence. Returns (service, fetcher).

    ``ripestat``/``ipinfo`` exist only so tests can prove context-only metadata cannot change a
    classification; the evaluation itself never passes them.
    """
    enabled_names = world.get("enabled_sources") or list(SOURCES)
    enabled = tuple(name for name in SOURCES if name in enabled_names)
    settings = _base_settings(
        enabled,
        current_evidence_tolerance_seconds=config.current_evidence_tolerance_seconds,
        cache_ttl_seconds=config.cache_ttl_seconds,
        max_source_age_seconds=config.max_source_age_seconds,
    )
    when = config.evaluation_time

    def clock() -> datetime:
        return when

    fetcher = ReplayFetcher(routes_for_world(world), clock)
    provider = SnapshotProvider(
        fetcher, None, ttl_seconds=settings.cache_ttl_seconds, clock=clock,
        max_source_age_seconds=settings.max_source_age_seconds,
    )
    floor = config.sanity_floor_entries
    makers = {
        TOR_SOURCE.name: lambda: TorExitListAdapter(provider, min_entries=floor, clock=clock),
        X4BNET_VPN_SOURCE.name: lambda: X4BNetVpnAdapter(
            provider, min_v4=floor, min_v6=floor, min_apple=floor, clock=clock),
        AZ0_VPN_SOURCE.name: lambda: Az0VpnIpAdapter(provider, min_total_entries=floor, clock=clock),
    }
    adapters = [makers[name]() for name in settings.enabled_sources]
    service = ClassificationService(settings, adapters, ripestat=ripestat, ipinfo=ipinfo, clock=clock)
    return service, fetcher


def _replay_case(case: Case, dataset: Dataset, config: EvaluationConfig):
    service, fetcher = build_replay_service(dataset.worlds[case.world], config)
    observation = Observation(ip=case.ip, observed_at=case.observed_at)
    return service, service.classify(observation), fetcher.request_count


def run_replay(dataset: Dataset, config: Optional[EvaluationConfig] = None) -> dict:
    """Evaluate every synthetic case offline. Returns the finished report dict."""
    config = config or default_replay_config(dataset)
    outcomes: list[dict] = []
    violations: list[dict] = []
    for case in dataset.cases_of_tier("synthetic"):
        service, first, calls = _replay_case(case, dataset, config)
        if service.audit_enabled:  # never true here; fail loudly rather than record silently
            raise EvaluationError("evaluation service unexpectedly has audit history enabled")
        _, second, _ = _replay_case(case, dataset, config)
        identical = first.classification == second.classification and first.evidence == second.evidence
        outcome = _outcome(case, first, calls)
        outcomes.append(outcome)
        violations.extend(check_outcome(outcome, repeat_identical=identical))
    skipped = [
        {"case_id": c.case_id,
         "reason": "reference cases need independent live evidence and are not replayable offline"}
        for c in dataset.cases_of_tier("reference")
    ]
    worlds = {
        name: {"sha256": sha256_of_object(world), "description": world["description"]}
        for name, world in dataset.worlds.items()
    }
    return build_report(
        dataset=dataset, config=config.as_dict(), versions=versions(),
        source_provenance=source_provenance(), world_fingerprints=worlds,
        outcomes=outcomes, skipped=skipped, violations=violations,
        invariants_checked=list(INVARIANTS_CHECKED), evidence_basis=BASIS_REPLAY,
        network_used=False, deterministic=True,
    )


# --------------------------------------------------------------------------
# live mode (explicit opt-in)
# --------------------------------------------------------------------------
LiveFactory = Callable[[Path, Callable[[], datetime]], tuple]


def default_live_factory(cache_dir: Path, clock: Callable[[], datetime]):
    """Real sources over HTTPS, cached only in ``cache_dir`` (a temporary directory)."""
    from ..collector import build_adapters
    from ..http_client import RequestsFetcher

    settings = _base_settings(tuple(SOURCES), cache_dir=cache_dir)
    fetcher = CountingFetcher(RequestsFetcher(
        timeout_seconds=settings.http_timeout_seconds,
        max_bytes=settings.max_download_bytes,
        clock=clock,
    ))
    adapters = build_adapters(settings, fetcher=fetcher, clock=clock)
    return ClassificationService(settings, adapters, clock=clock), fetcher, settings


def run_live(
    dataset: Dataset,
    *,
    factory: Optional[LiveFactory] = None,
    clock: Callable[[], datetime] = utc_now,
    basis: str = BASIS_LIVE,
    network_used: bool = True,
) -> dict:
    """Classify the reference-tier cases with the real sources (needs the network).

    ``factory``/``basis``/``network_used`` exist so tests can drive this exact code path with a
    replay fetcher; such a run is then labeled as mocked in its report, never as live.
    """
    cases = dataset.cases_of_tier("reference")
    if not cases:
        raise EvaluationError(
            "the dataset has no reference-tier cases, so there is nothing to evaluate against "
            "live sources; live mode never invents ground truth"
        )
    started = clock()
    with tempfile.TemporaryDirectory(prefix="ps010-eval-") as tmp:
        service, fetcher, settings = (factory or default_live_factory)(Path(tmp), clock)
        if service.audit_enabled:
            raise EvaluationError("evaluation service unexpectedly has audit history enabled")
        outcomes: list[dict] = []
        violations: list[dict] = []
        for case in cases:
            before = fetcher.request_count
            result = service.classify(Observation(ip=case.ip, observed_at=case.observed_at))
            outcome = _outcome(case, result, fetcher.request_count - before)
            outcomes.append(outcome)
            violations.extend(check_outcome(outcome, repeat_identical=None))
    config = EvaluationConfig(
        mode="live",
        evaluation_time=started,
        current_evidence_tolerance_seconds=settings.current_evidence_tolerance_seconds,
        cache_ttl_seconds=settings.cache_ttl_seconds,
        max_source_age_seconds=settings.max_source_age_seconds,
        sanity_floor_entries=None,
        disk_cache="temporary directory, deleted after the run",
        audit_enabled=service.audit_enabled,
    )
    skipped = [
        {"case_id": c.case_id, "reason": "synthetic fixture cases are replay-only"}
        for c in dataset.cases_of_tier("synthetic")
    ]
    return build_report(
        dataset=dataset, config=config.as_dict(), versions=versions(),
        source_provenance=source_provenance(), world_fingerprints={},
        outcomes=outcomes, skipped=skipped, violations=violations,
        invariants_checked=[n for n in INVARIANTS_CHECKED if n != "repeat_run_identical"],
        evidence_basis=basis, network_used=network_used, deterministic=False,
    )
