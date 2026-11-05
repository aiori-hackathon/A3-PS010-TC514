"""Service layer: classification stays authoritative and independent of IPinfo.

Mocked HTTP only. The evidence stack is the same fake world the adapter and collector tests use.
"""
import ast
import json
from pathlib import Path

import pytest

import netclass.service as service_module
from factories import T0, obs
from fakes import FakeFetcher, MutableClock, ip_body
from ipinfo_support import DROP, TOKEN, http_error, lite, make as make_ipinfo, url_for
from netclass.classifier import POLICY_VERSION
from netclass.collector import classify_with_context, classify_with_evidence
from netclass.config import Settings
from netclass.errors import SourceError, SourceErrorKind
from netclass.ipinfo import IpInfoErrorKind, IpInfoStatus
from netclass.models import Label, Observation, ReasonCode
from netclass.service import SERVICE_VERSION, ClassificationService, ServiceResult
from ripestat_support import healthy as ripe_healthy
from ripestat_support import make as make_ripestat
from support import (
    AZ0_IP,
    CLEAN_IP,
    TOR_IP,
    TOR_URL,
    TOR_V6,
    VPN_IP,
    all_adapters,
    make_stack,
    standard_routes,
)

S = IpInfoStatus
IP6 = "2001:4860:4860::8888"

# --------------------------------------------------------------------------- scenarios
# (ip, evidence routes, expected label, expected reason)
CONFLICT_ROUTES = standard_routes(**{TOR_URL: ip_body([VPN_IP, TOR_IP])})
SCENARIOS = {
    "tor-exit": (TOR_IP, None, Label.KNOWN_TOR_EXIT, ReasonCode.TOR_EXIT_MATCH),
    "vpn-range": (VPN_IP, None, Label.KNOWN_VPN_PROXY, ReasonCode.VPN_PROXY_ENDPOINT_MATCH),
    "vpn-exact": (AZ0_IP, None, Label.KNOWN_VPN_PROXY, ReasonCode.VPN_PROXY_ENDPOINT_MATCH),
    "clean-8.8.8.8": (CLEAN_IP, None, Label.UNKNOWN, ReasonCode.UNKNOWN_NO_QUALIFYING_MATCH),
    "conflict": (VPN_IP, CONFLICT_ROUTES, Label.UNKNOWN, ReasonCode.UNKNOWN_CONFLICTING_EVIDENCE),
    "ipv6-not-covered": (TOR_V6, None, Label.UNKNOWN, ReasonCode.UNKNOWN_PROVIDER_NOT_CONFIGURED),
    "excluded": ("10.0.0.1", None, Label.UNKNOWN, ReasonCode.UNKNOWN_EXCLUDED_ADDRESS),
}


def _timeout(ip):
    return SourceError(SourceErrorKind.TIMEOUT, "no response", url=url_for(ip))


def _conn(ip):
    return SourceError(SourceErrorKind.CONNECTION, f"failed with {TOKEN}", url=url_for(ip))


def _raises(ip):
    def boom():
        raise RuntimeError(f"unexpected {TOKEN}")

    return boom


# name -> (token, body-or-error factory taking ip)
IPINFO_BEHAVIOURS = {
    "disabled-no-token": (None, lambda ip: lite(ip)),
    "healthy": (TOKEN, lambda ip: lite(ip)),
    "vpn-sounding-org": (TOKEN, lambda ip: lite(ip, as_name="Example VPN Proxy Hosting Ltd", as_domain="vpn.example")),
    "tor-sounding-org": (TOKEN, lambda ip: lite(ip, as_name="The Tor Project", asn="AS4224")),
    "other-asn": (TOKEN, lambda ip: lite(ip, asn="AS64511", country_code="DE", country="Germany")),
    "only-ip": (TOKEN, lambda ip: json.dumps({"ip": ip}).encode()),
    "missing-fields": (TOKEN, lambda ip: lite(ip, as_name=DROP, asn=DROP)),
    "http-401": (TOKEN, lambda ip: http_error(url_for(ip), 401)),
    "http-429": (TOKEN, lambda ip: http_error(url_for(ip), 429)),
    "http-503": (TOKEN, lambda ip: http_error(url_for(ip), 503)),
    "timeout": (TOKEN, _timeout),
    "connection-with-token-in-message": (TOKEN, _conn),
    "invalid-json": (TOKEN, lambda ip: b"<html>oops</html>"),
    "fetcher-raises": (TOKEN, _raises),
}


# --------------------------------------------------------------------------- helpers
def build(tmp_path, ip, routes=None, *, token=TOKEN, ipinfo_route=None, with_ripestat=False, tag="a"):
    stack = make_stack(tmp_path / tag, routes)
    ipinfo_routes = {url_for(ip): ipinfo_route} if ipinfo_route is not None else {}
    ipinfo, ipinfo_fetcher, _ = make_ipinfo(ipinfo_routes, token=token)
    ripestat = ripe_fetcher = None
    if with_ripestat:
        ripestat, ripe_fetcher, _ = make_ripestat()
        ripe_fetcher.routes.update(ripe_healthy(ripestat, ip=ip, holder="RIPE-HOLDER-NAME"))
    service = ClassificationService(
        Settings(), all_adapters(stack), ripestat=ripestat, ipinfo=ipinfo, clock=stack.clock
    )
    return service, stack, ipinfo_fetcher, ripe_fetcher


def baseline(tmp_path, ip, routes=None):
    """What the evidence pipeline alone (without the service layer) returns for the same world."""
    stack = make_stack(tmp_path / "baseline", routes)
    return classify_with_evidence(obs(ip), all_adapters(stack), Settings())


# --------------------------------------------------------------------------- required behaviours
@pytest.mark.parametrize("name", list(SCENARIOS))
def test_scenarios_have_the_documented_labels_and_reasons(tmp_path, name):
    ip, routes, label, reason = SCENARIOS[name]
    result, _ = baseline(tmp_path, ip, routes)
    assert (result.label, result.reason_code) == (label, reason)


@pytest.mark.parametrize("ip", [TOR_IP, VPN_IP, AZ0_IP, CLEAN_IP, IP6])
def test_classification_works_with_ipinfo_disabled(tmp_path, ip):
    service, _, ipinfo_fetcher, _ = build(tmp_path, ip, token=None)
    assert service.ipinfo_enabled is False
    outcome = service.classify(obs(ip), include_ipinfo=True)
    expected, expected_records = baseline(tmp_path, ip)
    assert outcome.classification == expected and outcome.evidence == expected_records
    assert outcome.ipinfo_metadata.status is S.DISABLED
    assert ipinfo_fetcher.requested == []


@pytest.mark.parametrize("ip", [TOR_IP, VPN_IP, CLEAN_IP, IP6])
def test_classification_works_when_ipinfo_succeeds(tmp_path, ip):
    service, _, ipinfo_fetcher, _ = build(tmp_path, ip, ipinfo_route=lite(ip))
    outcome = service.classify(obs(ip), include_ipinfo=True)
    expected, expected_records = baseline(tmp_path, ip)
    assert outcome.classification == expected and outcome.evidence == expected_records
    assert outcome.ipinfo_metadata.status is S.AVAILABLE and outcome.ipinfo_metadata.asn == 64496
    assert ipinfo_fetcher.requested == [url_for(ip)]


@pytest.mark.parametrize("behaviour", list(IPINFO_BEHAVIOURS))
@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_classification_is_identical_whatever_ipinfo_says_or_does(tmp_path, scenario, behaviour):
    ip, routes, label, reason = SCENARIOS[scenario]
    token, route = IPINFO_BEHAVIOURS[behaviour]
    service, _, _, _ = build(tmp_path, ip, routes, token=token, ipinfo_route=route(ip))
    outcome = service.classify(obs(ip), include_ipinfo=True)  # never raises

    expected, expected_records = baseline(tmp_path, ip, routes)
    assert outcome.classification == expected  # every field: label, codes, assessments, caveats ...
    assert outcome.evidence == expected_records
    assert (outcome.classification.label, outcome.classification.reason_code) == (label, reason)
    assert outcome.ipinfo_metadata is not None  # requested, so a structured answer is present
    # IPinfo text never leaks into the classification part.
    assert "Proxy Hosting" not in outcome.classification.model_dump_json()
    assert "The Tor Project" not in outcome.classification.model_dump_json()


def test_8_8_8_8_stays_unknown_with_and_without_ipinfo(tmp_path):
    plain, _, _, _ = build(tmp_path, CLEAN_IP, token=None, tag="p")
    rich, _, _, _ = build(tmp_path, CLEAN_IP, ipinfo_route=lite(CLEAN_IP, as_name="Example VPN Co"), tag="r")
    a = plain.classify(obs(CLEAN_IP))
    b = rich.classify(obs(CLEAN_IP), include_ipinfo=True)
    assert a.classification.label is b.classification.label is Label.UNKNOWN
    assert a.classification.reason_code is b.classification.reason_code
    assert b.classification.reason_code is ReasonCode.UNKNOWN_NO_QUALIFYING_MATCH


def test_vpn_sounding_metadata_cannot_create_a_vpn_label(tmp_path):
    body = lite(CLEAN_IP, as_name="Super VPN Proxy Hosting", as_domain="vpn.example")
    service, _, _, _ = build(tmp_path, CLEAN_IP, ipinfo_route=body)
    outcome = service.classify(obs(CLEAN_IP), include_ipinfo=True)
    assert outcome.classification.label is Label.UNKNOWN
    assert outcome.ipinfo_metadata.as_name == "Super VPN Proxy Hosting"  # shown, not used


def test_ipinfo_cannot_override_conflicting_evidence(tmp_path):
    ip, routes, _, _ = SCENARIOS["conflict"]
    for name in ("healthy", "vpn-sounding-org", "tor-sounding-org"):
        token, route = IPINFO_BEHAVIOURS[name]
        service, _, _, _ = build(tmp_path, ip, routes, token=token, ipinfo_route=route(ip), tag=name)
        outcome = service.classify(obs(ip), include_ipinfo=True)
        assert outcome.classification.label is Label.UNKNOWN
        assert outcome.classification.reason_code is ReasonCode.UNKNOWN_CONFLICTING_EVIDENCE


# --------------------------------------------------------------------------- optional-lookup failures
def test_metadata_failure_is_contained_and_reported(tmp_path):
    service, _, _, _ = build(tmp_path, TOR_IP, ipinfo_route=http_error(url_for(TOR_IP), 401))
    outcome = service.classify(obs(TOR_IP), include_ipinfo=True)
    assert outcome.classification.label is Label.KNOWN_TOR_EXIT  # no false negative
    assert outcome.ipinfo_metadata.status is S.UNAVAILABLE
    assert outcome.ipinfo_metadata.error.kind is IpInfoErrorKind.AUTH_FAILED


def test_metadata_failure_does_not_create_a_false_positive(tmp_path):
    service, _, _, _ = build(tmp_path, CLEAN_IP, ipinfo_route=http_error(url_for(CLEAN_IP), 500))
    outcome = service.classify(obs(CLEAN_IP), include_ipinfo=True)
    assert outcome.classification.label is Label.UNKNOWN
    assert outcome.classification.reason_code is ReasonCode.UNKNOWN_NO_QUALIFYING_MATCH


def test_a_replacement_ipinfo_service_that_raises_is_contained(tmp_path):
    class Exploding:
        enabled = True

        def lookup(self, ip):
            raise RuntimeError(f"bug with {TOKEN}")

    stack = make_stack(tmp_path / "x")
    service = ClassificationService(Settings(), all_adapters(stack), ipinfo=Exploding(), clock=stack.clock)  # type: ignore[arg-type]
    outcome = service.classify(obs(TOR_IP), include_ipinfo=True)
    assert outcome.classification.label is Label.KNOWN_TOR_EXIT
    assert outcome.ipinfo_metadata.error.kind is IpInfoErrorKind.INTERNAL
    assert TOKEN not in outcome.model_dump_json()


def test_classification_errors_are_not_hidden(tmp_path):
    class BrokenAdapter:
        def lookup(self, ip):
            raise RuntimeError("classification path is broken")

    ipinfo, ipinfo_fetcher, _ = make_ipinfo({url_for(TOR_IP): lite(TOR_IP)})
    service = ClassificationService(Settings(), [BrokenAdapter()], ipinfo=ipinfo)  # type: ignore[list-item]
    with pytest.raises(RuntimeError, match="classification path is broken"):
        service.classify(obs(TOR_IP), include_ipinfo=True)
    assert ipinfo_fetcher.requested == []  # classification failed first; no metadata was sent


def test_invalid_observation_is_rejected_before_the_service_is_reached():
    with pytest.raises(ValueError):
        Observation(ip="not-an-ip", observed_at=T0)


# --------------------------------------------------------------------------- privacy / opt-in / exclusion
def test_nothing_is_sent_to_ipinfo_unless_requested(tmp_path):
    service, _, ipinfo_fetcher, _ = build(tmp_path, CLEAN_IP, ipinfo_route=lite(CLEAN_IP))
    assert service.ipinfo_enabled is True  # a token exists ...
    outcome = service.classify(obs(CLEAN_IP))
    assert outcome.ipinfo_metadata is None and outcome.ripestat_context is None  # ... but not asked
    assert ipinfo_fetcher.requested == []


@pytest.mark.parametrize("excluded", ["10.0.0.1", "127.0.0.1", "169.254.1.1", "::1", "fe80::1", "100.64.0.1"])
def test_excluded_addresses_are_never_sent_anywhere(tmp_path, excluded):
    service, stack, ipinfo_fetcher, ripe_fetcher = build(
        tmp_path, excluded, ipinfo_route=lite(excluded), with_ripestat=True
    )
    outcome = service.classify(obs(excluded), include_ipinfo=True, include_ripestat=True)
    assert outcome.classification.label is Label.UNKNOWN
    assert outcome.classification.reason_code is ReasonCode.UNKNOWN_EXCLUDED_ADDRESS
    assert outcome.ipinfo_metadata.status is S.NOT_QUERIED
    assert outcome.ripestat_context.status.value == "NOT_QUERIED"
    assert ipinfo_fetcher.requested == [] and ripe_fetcher.requested == [] and stack.fetcher.requested == []


# --------------------------------------------------------------------------- RIPEstat unchanged
def test_ripestat_behaviour_is_identical_to_the_direct_context_pipeline(tmp_path):
    ip = CLEAN_IP
    service, _, _, _ = build(tmp_path, ip, with_ripestat=True)
    outcome = service.classify(obs(ip), include_ripestat=True)

    stack = make_stack(tmp_path / "direct")
    ripestat, ripe_fetcher, _ = make_ripestat()
    ripe_fetcher.routes.update(ripe_healthy(ripestat, ip=ip, holder="RIPE-HOLDER-NAME"))
    result, records, ripe = classify_with_context(obs(ip), all_adapters(stack), Settings(), ripestat)

    assert outcome.classification == result
    assert outcome.evidence == records
    assert outcome.ripestat_context == ripe
    assert outcome.classification.network_context.as_name == "RIPE-HOLDER-NAME"
    assert outcome.classification.network_context.hosting_indicator is False


def test_enabling_ipinfo_leaves_the_ripestat_result_untouched(tmp_path):
    ip = CLEAN_IP
    without, _, _, _ = build(tmp_path, ip, with_ripestat=True, token=None, tag="w")
    with_meta, _, _, _ = build(
        tmp_path, ip, with_ripestat=True, ipinfo_route=lite(ip, as_name="IPINFO-NAME"), tag="m"
    )
    a = without.classify(obs(ip), include_ripestat=True)
    b = with_meta.classify(obs(ip), include_ripestat=True, include_ipinfo=True)
    assert a.classification == b.classification  # incl. network_context from RIPEstat only
    assert a.ripestat_context == b.ripestat_context
    assert b.classification.network_context.as_name == "RIPE-HOLDER-NAME"
    assert "IPINFO-NAME" not in b.classification.model_dump_json()
    assert b.ipinfo_metadata.as_name == "IPINFO-NAME"  # kept in its own section


def test_ripestat_and_ipinfo_fail_independently(tmp_path):
    service, _, _, ripe_fetcher = build(
        tmp_path, TOR_IP, ipinfo_route=lite(TOR_IP), with_ripestat=True
    )
    ripe_fetcher.routes.clear()  # RIPEstat now answers 404 for everything
    outcome = service.classify(obs(TOR_IP), include_ripestat=True, include_ipinfo=True)
    assert outcome.classification.label is Label.KNOWN_TOR_EXIT
    assert outcome.ripestat_context.usable is False
    assert outcome.ipinfo_metadata.status is S.AVAILABLE


def test_requesting_ripestat_without_a_ripestat_service_is_a_clear_error(tmp_path):
    service, _, _, _ = build(tmp_path, TOR_IP)
    with pytest.raises(ValueError, match="RIPEstat"):
        service.classify(obs(TOR_IP), include_ripestat=True)


# --------------------------------------------------------------------------- structure and contract
def test_result_shape_is_stable_and_serialisable(tmp_path):
    service, _, _, _ = build(tmp_path, TOR_IP, ipinfo_route=lite(TOR_IP), with_ripestat=True)
    outcome = service.classify(obs(TOR_IP), include_ripestat=True, include_ipinfo=True)
    assert tuple(ServiceResult.model_fields) == (
        "service_version", "classification", "evidence", "ripestat_context", "ipinfo_metadata",
    )
    dumped = outcome.model_dump(mode="json")
    assert dumped["service_version"] == SERVICE_VERSION == "ps010-service-1"
    assert dumped["classification"]["policy_version"] == POLICY_VERSION == "ps010-policy-1"
    assert json.loads(outcome.model_dump_json()) == dumped
    assert dumped["ipinfo_metadata"]["provenance"]["source_name"] == "ipinfo-lite-api"
    assert "ipinfo" not in json.dumps(dumped["classification"]).lower()
    with pytest.raises(Exception):  # frozen
        outcome.classification = None  # type: ignore[misc]


def test_the_three_labels_and_reason_codes_are_unchanged():
    assert [m.value for m in Label] == [
        "Known Tor exit", "Known hosted VPN/proxy endpoint", "Unknown",
    ]
    assert [m.value for m in ReasonCode] == [
        "TOR_EXIT_MATCH", "VPN_PROXY_ENDPOINT_MATCH", "UNKNOWN_EXCLUDED_ADDRESS",
        "UNKNOWN_CONFLICTING_EVIDENCE", "UNKNOWN_SOURCE_UNAVAILABLE", "UNKNOWN_STALE_EVIDENCE",
        "UNKNOWN_PROVIDER_NOT_CONFIGURED", "UNKNOWN_HOSTING_ONLY", "UNKNOWN_NO_QUALIFYING_MATCH",
    ]


def test_token_never_reaches_the_serialised_result(tmp_path):
    ip = TOR_IP
    service, _, _, _ = build(tmp_path, ip, ipinfo_route=_conn(ip))
    outcome = service.classify(obs(ip), include_ipinfo=True)
    assert outcome.ipinfo_metadata.status is S.UNAVAILABLE
    assert TOKEN not in outcome.model_dump_json() + repr(outcome) + repr(service)


def test_from_settings_wires_everything_without_touching_the_network(tmp_path):
    clock = MutableClock(T0)
    ipinfo_fetcher = FakeFetcher({url_for(CLEAN_IP): lite(CLEAN_IP)}, clock)
    ripe_fetcher = FakeFetcher({}, clock)
    evidence_fetcher = make_stack(tmp_path / "e").fetcher
    kwargs = dict(
        fetcher=evidence_fetcher, ripestat_fetcher=ripe_fetcher, ipinfo_fetcher=ipinfo_fetcher, clock=clock
    )
    enabled = ClassificationService.from_settings(
        Settings(cache_dir=tmp_path / "c1", ipinfo_token=TOKEN), **kwargs
    )
    disabled = ClassificationService.from_settings(Settings(cache_dir=tmp_path / "c2"), **kwargs)
    assert enabled.ipinfo_enabled is True and disabled.ipinfo_enabled is False
    on = enabled.classify(obs(CLEAN_IP), include_ipinfo=True)
    off = disabled.classify(obs(CLEAN_IP), include_ipinfo=True)
    assert on.ipinfo_metadata.status is S.AVAILABLE and off.ipinfo_metadata.status is S.DISABLED
    assert on.classification.label is off.classification.label
    assert on.classification.reason_code is off.classification.reason_code
    assert ipinfo_fetcher.requested == [url_for(CLEAN_IP)]


def test_service_module_contains_no_classification_logic():
    source = Path(service_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    forbidden = {
        "classifier", ".classifier", "classify", "Label", "ReasonCode", "EvidenceStatus",
        "EvidenceKind", "Applicability", "NetworkContext", "requests", "socket",
    }
    assert not (imported & forbidden), imported & forbidden
    names_used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not (names_used & {"Label", "ReasonCode", "EvidenceStatus", "EvidenceKind"})
