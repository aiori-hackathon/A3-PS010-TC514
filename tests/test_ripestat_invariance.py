"""RIPEstat context is metadata only: it can never change a primary classification.

These tests pin the Stage 3B rule that ASN ownership, a hosting/VPN-sounding
holder name or a data-centre prefix is not evidence. They use only mocked data.
"""
import ast
import ipaddress
from pathlib import Path

import pytest

import netclass.ripestat as ripestat_module
from factories import K, S, T0, hours, obs, tor, vpn
from fakes import FakeFetcher, MutableClock
from netclass.classifier import classify
from netclass.collector import build_context_service, classify_with_context, classify_with_evidence
from netclass.config import Settings
from netclass.errors import SourceError, SourceErrorKind
from netclass.models import Label, NetworkContext, ReasonCode
from netclass.ripestat import (
    AS_OVERVIEW_CALL,
    NETWORK_INFO_CALL,
    ContextStatus,
    RipeStatContextService,
)
from support import (
    AZ0_IP,
    CLEAN_IP,
    TOR_IP,
    VPN_IP,
    all_adapters,
    make_stack,
)
from ripestat_support import IP, ao, ni

# ---------------------------------------------------------------- scenario grids
EVIDENCE_SCENARIOS = {
    "tor-match": lambda: [tor(S.MATCH), vpn(S.NO_MATCH)],
    "vpn-match": lambda: [tor(S.NO_MATCH), vpn(S.MATCH)],
    "conflict": lambda: [tor(S.MATCH), vpn(S.MATCH)],
    "all-no-match": lambda: [tor(S.NO_MATCH), vpn(S.NO_MATCH)],
    "source-unavailable": lambda: [tor(S.SOURCE_UNAVAILABLE), vpn(S.NO_MATCH)],
    "stale": lambda: [tor(S.NO_MATCH, retrieved_at=T0 - hours(5)), vpn(S.NO_MATCH)],
    "vpn-not-configured": lambda: [tor(S.NO_MATCH), vpn(S.NOT_CONFIGURED)],
    "no-evidence": lambda: [],
}

SUSPICIOUS_HOLDERS = [
    "Hetzner Online GmbH",
    "DigitalOcean, LLC",
    "Example VPN Services Ltd",
    "The Tor Project",
    "Datacenter Colocation Hosting Cloud",
    None,
]


def context_for(holder, *, asns=("64496",), prefix="8.8.8.0/24") -> NetworkContext:
    clock = MutableClock(T0)
    service = RipeStatContextService(FakeFetcher({}, clock), clock=clock)
    routes = service._fetcher.routes
    routes[service.build_url(NETWORK_INFO_CALL, IP)] = ni(asns, prefix)
    for asn in asns:
        routes[service.build_url(AS_OVERVIEW_CALL, f"AS{asn}")] = ao(int(asn), holder)
    display = service.lookup(IP).to_network_context()
    assert display is not None
    return display


def without_context(result):
    data = result.model_dump(mode="json")
    data.pop("network_context")
    return data


# ---------------------------------------------------------------- the core rule
@pytest.mark.parametrize("scenario", sorted(EVIDENCE_SCENARIOS))
@pytest.mark.parametrize("holder", SUSPICIOUS_HOLDERS)
def test_context_never_changes_any_part_of_the_classification(scenario, holder):
    evidence = EVIDENCE_SCENARIOS[scenario]()
    baseline = classify(obs(), evidence, None)
    with_context = classify(obs(), evidence, context_for(holder))
    assert with_context.network_context is not None  # shown, but separate
    assert without_context(with_context) == without_context(baseline)
    assert with_context.label is baseline.label
    assert with_context.reason_code is baseline.reason_code


@pytest.mark.parametrize("holder", SUSPICIOUS_HOLDERS)
def test_context_alone_cannot_create_a_known_label(holder):
    # No evidence at all, and evidence that checked everything and found nothing.
    for evidence in ([], [tor(S.NO_MATCH), vpn(S.NO_MATCH)]):
        result = classify(obs(), evidence, context_for(holder))
        assert result.label is Label.UNKNOWN
        assert result.label not in (Label.KNOWN_TOR_EXIT, Label.KNOWN_VPN_PROXY)
        assert ReasonCode.UNKNOWN_HOSTING_ONLY not in [result.reason_code, *result.additional_reason_codes]


def test_fully_checked_clean_address_stays_no_qualifying_match_with_hosting_style_context():
    result = classify(obs(), [tor(S.NO_MATCH), vpn(S.NO_MATCH)], context_for("Cloud Hosting VPN Ltd"))
    assert result.reason_code is ReasonCode.UNKNOWN_NO_QUALIFYING_MATCH


def test_context_does_not_remove_a_known_label_either():
    result = classify(obs(), [tor(S.MATCH), vpn(S.NO_MATCH)], context_for("Totally Ordinary ISP"))
    assert result.label is Label.KNOWN_TOR_EXIT
    result = classify(obs(), [tor(S.NO_MATCH), vpn(S.MATCH)], context_for("Totally Ordinary ISP"))
    assert result.label is Label.KNOWN_VPN_PROXY


@pytest.mark.parametrize("holder", SUSPICIOUS_HOLDERS)
@pytest.mark.parametrize("asns", [("64496",), ("64496", "64497"), ("1",)])
def test_service_projection_has_no_hosting_indicator_so_stage_3a_hosting_rule_is_unreachable(holder, asns):
    display = context_for(holder, asns=asns)
    assert display.hosting_indicator is False
    assert display.hosting_indicator_basis is None


def test_stage_3a_hosting_policy_is_unchanged_for_a_manually_built_indicator():
    # The Stage 3A rule still exists: a hosting indicator explains an Unknown but
    # never produces a VPN label. Only an explicit, non-RIPEstat source may set it.
    manual = NetworkContext(asn=64496, hosting_indicator=True, hosting_indicator_basis="test fixture")
    result = classify(obs(), [tor(S.NO_MATCH), vpn(S.NO_MATCH)], manual)
    assert result.label is Label.UNKNOWN
    assert result.reason_code is ReasonCode.UNKNOWN_HOSTING_ONLY


# ---------------------------------------------------------------- architectural guards
def test_ripestat_module_does_not_import_or_reference_classification_types():
    source = Path(ripestat_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    forbidden = {
        "classifier", ".classifier", "Label", "ReasonCode", "EvidenceRecord", "EvidenceKind",
        "EvidenceStatus", "classify", "Applicability", "ClassificationResult", "adapters",
    }
    assert not (imported & forbidden), imported & forbidden
    names_used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not (names_used & {"Label", "ReasonCode", "EvidenceRecord", "EvidenceKind", "EvidenceStatus"})


def test_ripestat_module_only_ever_builds_network_context_with_hosting_indicator_false():
    source = Path(ripestat_module.__file__).read_text(encoding="utf-8")
    assert "hosting_indicator=True" not in source
    assert source.count("hosting_indicator=False") == 1


# ---------------------------------------------------------------- collector integration
def ripe_service(routes):
    clock = MutableClock(T0)
    fetcher = FakeFetcher(routes, clock)
    return RipeStatContextService(fetcher, clock=clock), fetcher


def full_ripe_routes(ip, holder):
    base = RipeStatContextService(FakeFetcher({}, MutableClock(T0)))
    return {
        base.build_url(NETWORK_INFO_CALL, ip): ni(["64496"], _covering(ip)),
        base.build_url(AS_OVERVIEW_CALL, "AS64496"): ao(64496, holder),
    }


def _covering(ip):
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


@pytest.mark.parametrize("ip", [TOR_IP, VPN_IP, AZ0_IP, CLEAN_IP])
@pytest.mark.parametrize("holder", ["Hosting Cloud VPN Provider", "Tor Project", None])
def test_collector_labels_are_identical_with_and_without_ripestat(tmp_path, ip, holder):
    stack = make_stack(tmp_path)
    adapters = all_adapters(stack)
    observation = obs(ip, T0)
    plain, _ = classify_with_evidence(observation, adapters, Settings())
    service, _ = ripe_service(full_ripe_routes(ip, holder))
    enriched, records, ripe = classify_with_context(observation, adapters, Settings(), service)

    assert ripe.status is ContextStatus.AVAILABLE
    assert enriched.network_context is not None and enriched.network_context.asn == 64496
    assert without_context(enriched) == without_context(plain)
    assert enriched.label is plain.label and enriched.reason_code is plain.reason_code
    assert enriched.label in set(Label)  # exactly the three primary labels


def test_known_labels_in_the_collector_come_from_evidence_only(tmp_path):
    stack = make_stack(tmp_path)
    adapters = all_adapters(stack)
    service, _ = ripe_service(full_ripe_routes(TOR_IP, "Plain ISP"))
    tor_result, _, _ = classify_with_context(obs(TOR_IP), adapters, Settings(), service)
    assert tor_result.label is Label.KNOWN_TOR_EXIT
    clean_service, _ = ripe_service(full_ripe_routes(CLEAN_IP, "Hosting VPN Cloud Datacenter"))
    clean_result, _, _ = classify_with_context(obs(CLEAN_IP), adapters, Settings(), clean_service)
    assert clean_result.label is Label.UNKNOWN


@pytest.mark.parametrize(
    "error_route", [RuntimeError("boom"), SourceError(SourceErrorKind.TIMEOUT, "slow")]
)
def test_ripestat_outage_does_not_affect_the_label_and_is_reported_as_unavailable(tmp_path, error_route):
    stack = make_stack(tmp_path)
    adapters = all_adapters(stack)
    base = RipeStatContextService(FakeFetcher({}, MutableClock(T0)))
    service, _ = ripe_service({base.build_url(NETWORK_INFO_CALL, TOR_IP): error_route})
    plain, _ = classify_with_evidence(obs(TOR_IP), adapters, Settings())
    enriched, _, ripe = classify_with_context(obs(TOR_IP), adapters, Settings(), service)
    assert ripe.status is ContextStatus.UNAVAILABLE
    assert enriched.network_context is None  # nothing fabricated
    assert without_context(enriched) == without_context(plain)


def test_excluded_address_triggers_no_ripestat_and_no_evidence_requests(tmp_path):
    stack = make_stack(tmp_path)
    service, ripe_fetcher = ripe_service({})
    result, records, ripe = classify_with_context(obs("10.1.2.3"), all_adapters(stack), Settings(), service)
    assert result.reason_code is ReasonCode.UNKNOWN_EXCLUDED_ADDRESS
    assert ripe.status is ContextStatus.NOT_QUERIED
    assert ripe_fetcher.requested == [] and stack.fetcher.requested == [] and records == []


def test_ripestat_requests_are_separate_from_evidence_sources(tmp_path):
    stack = make_stack(tmp_path)
    service, ripe_fetcher = ripe_service(full_ripe_routes(CLEAN_IP, "X"))
    classify_with_context(obs(CLEAN_IP), all_adapters(stack), Settings(), service)
    assert all("stat.ripe.net" in url for url in ripe_fetcher.requested)
    assert not any("stat.ripe.net" in url for url in stack.fetcher.requested)


def test_ripestat_cannot_reach_the_evidence_registry():
    from netclass.sources import SOURCES

    assert not any("ripe" in name for name in SOURCES)


def test_build_context_service_uses_settings_and_injected_fetcher():
    settings = Settings(
        ripestat_base_url="https://stat.ripe.net/data",
        ripestat_sourceapp="viltrumites-test",
        ripestat_cache_ttl_seconds=42,
    )
    clock = MutableClock(T0)
    fetcher = FakeFetcher({}, clock)
    service = build_context_service(settings, fetcher=fetcher, clock=clock)
    assert service.build_url(NETWORK_INFO_CALL, IP).endswith("resource=8.8.8.8&sourceapp=viltrumites-test")
    ctx = service.lookup(IP)  # fetcher has no routes -> 404 -> unavailable, no network used
    assert ctx.status is ContextStatus.UNAVAILABLE and fetcher.requested


def test_default_build_creates_real_fetcher_without_touching_the_network():
    service = build_context_service(Settings())
    assert isinstance(service, RipeStatContextService)  # constructing must not do I/O
