"""RIPEstat context service: every response here is a canned, mocked body.

No test contacts RIPEstat. Bodies follow the envelope and fields documented at
https://stat.ripe.net/docs/data-api/ (network-info, as-overview); the values are
arbitrary fixtures, not claims about real networks.
"""
import json
from datetime import timedelta

import pytest
import requests

from factories import T0
from fakes import FakeFetcher, MutableClock, StubResponse, StubTransport
from netclass.errors import SourceError, SourceErrorKind
from netclass.hashing import sha256_hex
from netclass.http_client import RequestsFetcher
from ripestat_support import IP, IP6, ao, envelope, healthy, http_error, make, ni
from netclass.ripestat import (
    AS_OVERVIEW_CALL,
    NETWORK_INFO_CALL,
    RIPESTAT_SOURCE_NAME,
    ContextErrorKind,
    ContextStatus,
    HolderSection,
    RipeStatContextService,
    RoutingSection,
    SectionStatus,
)

E = ContextErrorKind


def service_with_routing_body(body):
    service, fetcher, clock = make()
    fetcher.routes[service.build_url(NETWORK_INFO_CALL, IP)] = body
    return service


# ---------------------------------------------------------------- success
def test_success_returns_asn_prefix_holder_with_provenance():
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    ctx = service.lookup(IP)

    assert ctx.status is ContextStatus.AVAILABLE and ctx.usable
    assert ctx.ip == IP and ctx.requested_at == T0
    assert ctx.routing.status is SectionStatus.OK
    assert ctx.routing.asns == (15169,)
    assert ctx.routing.prefix == "8.8.8.0/24"
    (holder,) = ctx.holders
    assert holder.status is SectionStatus.OK
    assert holder.asn == 15169 and holder.holder == "EXAMPLE-HOLDER" and holder.announced is True

    prov = ctx.routing.provenance
    assert prov.source_name == RIPESTAT_SOURCE_NAME
    assert prov.data_call == "network-info"
    assert prov.endpoint == service.build_url(NETWORK_INFO_CALL, IP)
    assert prov.retrieved_at == T0 and prov.from_cache is False
    assert prov.response_sha256 == sha256_hex(ni())
    assert prov.api_version == "1.1" and prov.data_call_status == "supported"
    assert prov.api_reported_cached is False
    assert holder.provenance.data_call == "as-overview"


def test_only_documented_endpoints_and_parameters_are_requested():
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    service.lookup(IP)
    assert fetcher.requested == [
        "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8",
        "https://stat.ripe.net/data/as-overview/data.json?resource=AS15169",
    ]


def test_ipv6_resource_is_normalised_and_colons_are_kept_literal():
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service, ip=IP6, prefix="2001:4860::/32"))
    ctx = service.lookup("2001:4860:4860:0:0:0:0:8888")
    assert ctx.ip == IP6 and ctx.status is ContextStatus.AVAILABLE
    assert fetcher.requested[0] == (
        "https://stat.ripe.net/data/network-info/data.json?resource=2001:4860:4860::8888"
    )


def test_sourceapp_is_sent_when_configured_and_validated():
    service, fetcher, _ = make(sourceapp="my_app-1")
    assert service.build_url("network-info", IP).endswith("?resource=8.8.8.8&sourceapp=my_app-1")
    for bad in ("has space", "semi;colon", "", "x" * 65, "ünï"):
        with pytest.raises(ValueError):
            make(sourceapp=bad)


@pytest.mark.parametrize("base", ["http://stat.ripe.net/data", "ftp://x", "stat.ripe.net/data"])
def test_non_https_base_url_is_rejected(base):
    with pytest.raises(ValueError):
        RipeStatContextService(FakeFetcher({}, MutableClock(T0)), base_url=base)


def test_trailing_slash_in_base_url_is_tolerated():
    service = RipeStatContextService(
        FakeFetcher({}, MutableClock(T0)), base_url="https://stat.ripe.net/data/"
    )
    assert service.build_url("network-info", IP).startswith("https://stat.ripe.net/data/network-info/")


def test_asns_accepted_as_integers_or_as_prefixed_strings_and_deduplicated():
    service, fetcher, _ = make()
    fetcher.routes[service.build_url(NETWORK_INFO_CALL, IP)] = ni([15169, "AS15169", "as64496"])
    fetcher.routes[service.build_url(AS_OVERVIEW_CALL, "AS15169")] = ao(15169)
    fetcher.routes[service.build_url(AS_OVERVIEW_CALL, "AS64496")] = ao(64496, "OTHER")
    ctx = service.lookup(IP)
    assert ctx.routing.asns == (15169, 64496)
    assert [h.asn for h in ctx.holders] == [15169, 64496]


def test_multi_origin_prefix_is_not_collapsed_to_one_asn():
    service, fetcher, _ = make()
    fetcher.routes[service.build_url(NETWORK_INFO_CALL, IP)] = ni(["64497", "64496"])
    for asn in (64496, 64497):
        fetcher.routes[service.build_url(AS_OVERVIEW_CALL, f"AS{asn}")] = ao(asn, f"HOLDER-{asn}")
    ctx = service.lookup(IP)
    assert ctx.routing.asns == (64496, 64497)
    assert any("multi-origin" in text for text in ctx.limitations)
    display = ctx.to_network_context()
    assert display.asn is None and display.as_name is None  # no arbitrary pick
    assert display.prefix == "8.8.8.0/24"


def test_holder_lookups_are_capped_and_the_cap_is_disclosed():
    service, fetcher, _ = make(max_holder_lookups=2)
    fetcher.routes[service.build_url(NETWORK_INFO_CALL, IP)] = ni(["5", "4", "3"])
    for asn in (3, 4, 5):
        fetcher.routes[service.build_url(AS_OVERVIEW_CALL, f"AS{asn}")] = ao(asn, "H")
    ctx = service.lookup(IP)
    assert [h.asn for h in ctx.holders] == [3, 4]
    assert any("first 2" in text for text in ctx.limitations)
    assert fetcher.count(service.build_url(AS_OVERVIEW_CALL, "AS5")) == 0


# ---------------------------------------------------------------- missing / optional fields
def test_missing_prefix_is_tolerated_with_a_warning():
    service = service_with_routing_body(ni(prefix=None))
    service._fetcher.routes[service.build_url(AS_OVERVIEW_CALL, "AS15169")] = ao()
    ctx = service.lookup(IP)
    assert ctx.routing.status is SectionStatus.OK
    assert ctx.routing.prefix is None and ctx.routing.asns == (15169,)
    assert any('no "prefix"' in w for w in ctx.routing.warnings)


def test_missing_asns_is_tolerated_with_a_warning_and_no_holder_lookup():
    service = service_with_routing_body(ni(asns=None))
    ctx = service.lookup(IP)
    assert ctx.routing.status is SectionStatus.OK and ctx.routing.asns == ()
    assert ctx.routing.prefix == "8.8.8.0/24"
    assert ctx.holders == []
    assert any('no "asns"' in w for w in ctx.routing.warnings)
    assert service._fetcher.requested == [service.build_url(NETWORK_INFO_CALL, IP)]


def test_unrouted_address_is_an_explicit_empty_result_not_an_error():
    service = service_with_routing_body(ni(asns=[], prefix=""))
    ctx = service.lookup(IP)
    assert ctx.status is ContextStatus.AVAILABLE
    assert ctx.routing.status is SectionStatus.EMPTY
    assert ctx.routing.asns == () and ctx.routing.prefix is None
    assert ctx.routing.provenance is not None and ctx.routing.error is None
    assert any("no announced prefix" in text for text in ctx.limitations)
    assert ctx.to_network_context() is None  # nothing is invented for display
    assert len(service._fetcher.requested) == 1  # no ASN, so no holder lookup


def test_null_holder_is_an_empty_section():
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    fetcher.routes[service.build_url(AS_OVERVIEW_CALL, "AS15169")] = ao(holder=None)
    ctx = service.lookup(IP)
    assert ctx.status is ContextStatus.AVAILABLE
    assert ctx.holders[0].status is SectionStatus.EMPTY and ctx.holders[0].holder is None
    display = ctx.to_network_context()
    assert display.asn == 15169 and display.as_name is None


def test_holder_field_missing_or_wrong_type_is_tolerated():
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    key = service.build_url(AS_OVERVIEW_CALL, "AS15169")
    fetcher.routes[key] = envelope(AS_OVERVIEW_CALL, {"resource": "15169"})
    h = service.lookup(IP).holders[0]
    assert h.holder is None and h.announced is None and any('no "holder"' in w for w in h.warnings)

    service2, fetcher2, _ = make()
    fetcher2.routes.update(healthy(service2))
    fetcher2.routes[service2.build_url(AS_OVERVIEW_CALL, "AS15169")] = envelope(
        AS_OVERVIEW_CALL, {"resource": "15169", "holder": 12345, "announced": "yes"}
    )
    h2 = service2.lookup(IP).holders[0]
    assert h2.holder is None and h2.announced is None
    assert len(h2.warnings) == 2


def test_holder_text_is_cleaned_and_bounded():
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    key = service.build_url(AS_OVERVIEW_CALL, "AS15169")
    fetcher.routes[key] = ao(holder="  Example\n\tHolder \x00 Inc  ")
    assert service.lookup(IP).holders[0].holder == "Example Holder Inc"
    service2, fetcher2, _ = make()
    fetcher2.routes.update(healthy(service2))
    fetcher2.routes[service2.build_url(AS_OVERVIEW_CALL, "AS15169")] = ao(holder="A" * 1000)
    h = service2.lookup(IP).holders[0]
    assert len(h.holder) == 256 and any("truncated" in w for w in h.warnings)


def test_unparseable_asn_values_are_skipped_but_reported():
    service = service_with_routing_body(ni(["15169", "bogus", None, True, -1, 2**40]))
    service._fetcher.routes[service.build_url(AS_OVERVIEW_CALL, "AS15169")] = ao()
    ctx = service.lookup(IP)
    assert ctx.routing.asns == (15169,)
    assert any("ignored 5" in w for w in ctx.routing.warnings)


def test_invalid_prefix_string_is_dropped_with_warning():
    service = service_with_routing_body(ni(prefix="not-a-prefix"))
    service._fetcher.routes[service.build_url(AS_OVERVIEW_CALL, "AS15169")] = ao()
    ctx = service.lookup(IP)
    assert ctx.routing.prefix is None
    assert any("not a valid CIDR" in w for w in ctx.routing.warnings)


def test_deprecated_data_call_status_is_surfaced():
    service = service_with_routing_body(ni(data_call_status="deprecated (expires 2027-01-01)"))
    service._fetcher.routes[service.build_url(AS_OVERVIEW_CALL, "AS15169")] = ao()
    ctx = service.lookup(IP)
    assert any("deprecated" in w for w in ctx.routing.warnings)
    assert ctx.routing.provenance.data_call_status.startswith("deprecated")


# ---------------------------------------------------------------- malformed responses
MALFORMED = [
    (b"<html>maintenance page</html>", E.INVALID_JSON),
    (b"", E.INVALID_JSON),
    (b"\xff\xfe\x00not utf8", E.INVALID_JSON),
    (b"[1, 2, 3]", E.UNEXPECTED_STRUCTURE),
    (b'"just a string"', E.UNEXPECTED_STRUCTURE),
    (b"{}", E.UNEXPECTED_STRUCTURE),
    (json.dumps({"data": {"asns": ["1"], "prefix": "8.8.8.0/24"}}).encode(), E.UNEXPECTED_STRUCTURE),
    (ni(status="weird"), E.UNEXPECTED_STRUCTURE),
    (ni(status="error", message="invalid resource"), E.API_ERROR),
    (ni(status="maintenance"), E.API_MAINTENANCE),
    (ni(data_call_name="as-overview"), E.UNEXPECTED_STRUCTURE),
    (envelope(NETWORK_INFO_CALL, None), E.UNEXPECTED_STRUCTURE),
    (envelope(NETWORK_INFO_CALL, ["asns"]), E.UNEXPECTED_STRUCTURE),
    (envelope(NETWORK_INFO_CALL, {"unrelated": 1}), E.UNEXPECTED_STRUCTURE),
    (envelope(NETWORK_INFO_CALL, {"asns": "15169", "prefix": "8.8.8.0/24"}), E.UNEXPECTED_STRUCTURE),
    (envelope(NETWORK_INFO_CALL, {"asns": ["x", "y"], "prefix": "8.8.8.0/24"}), E.UNEXPECTED_STRUCTURE),
    (envelope(NETWORK_INFO_CALL, {"asns": ["15169"], "prefix": 12}), E.UNEXPECTED_STRUCTURE),
    (ni(["15169"], "9.9.9.0/24"), E.UNEXPECTED_STRUCTURE),  # prefix does not contain the queried IP
]


@pytest.mark.parametrize("body,kind", MALFORMED)
def test_malformed_routing_response_is_unavailable_never_empty_success(body, kind):
    service = service_with_routing_body(body)
    ctx = service.lookup(IP)
    assert ctx.status is ContextStatus.UNAVAILABLE and not ctx.usable
    assert ctx.routing.status is SectionStatus.UNAVAILABLE
    assert ctx.routing.error.kind is kind
    assert ctx.routing.error.endpoint == service.build_url(NETWORK_INFO_CALL, IP)
    assert ctx.routing.asns == () and ctx.routing.prefix is None  # nothing fabricated
    assert ctx.routing.provenance is None
    assert ctx.to_network_context() is None
    assert len(service._fetcher.requested) == 1  # no follow-up lookups on bad data


def test_api_error_message_is_kept_for_diagnosis():
    service = service_with_routing_body(ni(status="error", message="resource not valid"))
    assert "resource not valid" in service.lookup(IP).routing.error.message


@pytest.mark.parametrize(
    "body",
    [
        envelope(AS_OVERVIEW_CALL, {"resource": "99999", "holder": "WRONG"}),  # different ASN
        envelope(AS_OVERVIEW_CALL, None),
        ao(status="error", message="boom"),
        b"not json",
    ],
)
def test_malformed_holder_response_gives_partial_not_fabricated_name(body):
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    fetcher.routes[service.build_url(AS_OVERVIEW_CALL, "AS15169")] = body
    ctx = service.lookup(IP)
    assert ctx.status is ContextStatus.PARTIAL and ctx.usable
    assert ctx.routing.status is SectionStatus.OK
    assert ctx.holders[0].status is SectionStatus.UNAVAILABLE and ctx.holders[0].holder is None
    display = ctx.to_network_context()
    assert display.asn == 15169 and display.as_name is None


# ---------------------------------------------------------------- transport errors
FETCH_ERRORS = [
    (SourceError(SourceErrorKind.TIMEOUT, "no response within 10s"), E.TIMEOUT, None),
    (SourceError(SourceErrorKind.CONNECTION, "request failed (ConnectionError)"), E.CONNECTION, None),
    (SourceError(SourceErrorKind.TOO_LARGE, "body exceeds limit"), E.TOO_LARGE, None),
    (http_error("u", 429), E.RATE_LIMITED, 429),
    (http_error("u", 500), E.HTTP_ERROR, 500),
    (http_error("u", 503), E.HTTP_ERROR, 503),
    (http_error("u", 404), E.HTTP_ERROR, 404),
    (http_error("u", 400), E.HTTP_ERROR, 400),
    (SourceError(SourceErrorKind.MALFORMED, "odd"), E.INTERNAL, None),
]


@pytest.mark.parametrize("error,kind,status", FETCH_ERRORS)
def test_routing_fetch_errors_map_to_typed_unavailable_context(error, kind, status):
    service, fetcher, _ = make()
    fetcher.routes[service.build_url(NETWORK_INFO_CALL, IP)] = error
    ctx = service.lookup(IP)
    assert ctx.status is ContextStatus.UNAVAILABLE
    assert ctx.routing.status is SectionStatus.UNAVAILABLE
    assert ctx.routing.error.kind is kind
    assert ctx.routing.error.http_status == status
    assert ctx.routing.asns == () and ctx.routing.prefix is None
    assert ctx.to_network_context() is None
    assert ctx.holders == [] and len(fetcher.requested) == 1


def test_rate_limit_message_is_explicit_and_there_is_no_automatic_retry():
    service, fetcher, _ = make()
    fetcher.routes[service.build_url(NETWORK_INFO_CALL, IP)] = http_error("u", 429)
    ctx = service.lookup(IP)
    assert "rate limited" in ctx.routing.error.message
    assert fetcher.count(service.build_url(NETWORK_INFO_CALL, IP)) == 1


@pytest.mark.parametrize("error,kind,status", FETCH_ERRORS[:7])
def test_holder_fetch_errors_degrade_to_partial(error, kind, status):
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    fetcher.routes[service.build_url(AS_OVERVIEW_CALL, "AS15169")] = error
    ctx = service.lookup(IP)
    assert ctx.status is ContextStatus.PARTIAL
    assert ctx.routing.status is SectionStatus.OK and ctx.routing.asns == (15169,)
    assert ctx.holders[0].error.kind is kind
    display = ctx.to_network_context()
    assert display is not None and display.as_name is None and display.asn == 15169


def test_unexpected_fetcher_exception_is_contained():
    service, fetcher, _ = make()
    fetcher.routes[service.build_url(NETWORK_INFO_CALL, IP)] = RuntimeError("bug")
    ctx = service.lookup(IP)
    assert ctx.status is ContextStatus.UNAVAILABLE
    assert ctx.routing.error.kind is E.INTERNAL
    assert "bug" not in ctx.routing.error.message  # only the exception type is exposed


def test_lookup_never_raises_even_if_internals_fail(monkeypatch):
    service, _, _ = make()

    def explode(*args, **kwargs):
        raise ZeroDivisionError("x")

    monkeypatch.setattr(service, "_routing", explode)
    ctx = service.lookup(IP)
    assert ctx.status is ContextStatus.UNAVAILABLE and ctx.error.kind is E.INTERNAL


# ---------------------------------------------------------------- input handling
@pytest.mark.parametrize("bad", ["", "not-an-ip", "8.8.8.0/24", "fe80::1%eth0", "8.8.8.8:80", None, 5])
def test_invalid_input_makes_no_request(bad):
    service, fetcher, _ = make()
    ctx = service.lookup(bad)
    assert ctx.status is ContextStatus.UNAVAILABLE and ctx.error.kind is E.INVALID_INPUT
    assert ctx.routing is None and fetcher.requested == []
    assert ctx.to_network_context() is None


@pytest.mark.parametrize(
    "ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "192.0.2.1", "::1", "fd00::1", "224.0.0.1"]
)
def test_excluded_addresses_are_not_queried(ip):
    service, fetcher, _ = make()
    ctx = service.lookup(ip)
    assert ctx.status is ContextStatus.NOT_QUERIED and not ctx.usable
    assert "No RIPEstat request was made" in ctx.note
    assert fetcher.requested == [] and ctx.routing is None
    assert ctx.to_network_context() is None


def test_ipv4_mapped_ipv6_is_normalised_before_querying():
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    ctx = service.lookup("::ffff:8.8.8.8")
    assert ctx.ip == "8.8.8.8" and ctx.status is ContextStatus.AVAILABLE


# ---------------------------------------------------------------- caching and freshness
def test_second_lookup_within_ttl_is_served_from_cache_with_original_timestamp():
    service, fetcher, clock = make(ttl=600)
    fetcher.routes.update(healthy(service))
    first = service.lookup(IP)
    clock.advance(seconds=599)
    second = service.lookup(IP)
    assert len(fetcher.requested) == 2  # one network-info + one as-overview, total
    assert second.routing.provenance.from_cache is True
    assert second.holders[0].provenance.from_cache is True
    assert second.routing.provenance.retrieved_at == T0  # NOT the cache-hit time
    assert second.requested_at == T0 + timedelta(seconds=599)
    assert first.routing.provenance.from_cache is False
    assert second.routing.provenance.response_sha256 == first.routing.provenance.response_sha256
    assert second.routing.asns == first.routing.asns


def test_entry_exactly_at_ttl_is_served_and_one_second_later_is_refetched():
    service, fetcher, clock = make(ttl=600)
    fetcher.routes.update(healthy(service))
    service.lookup(IP)
    clock.advance(seconds=600)
    assert service.lookup(IP).routing.provenance.from_cache is True
    assert len(fetcher.requested) == 2
    clock.advance(seconds=1)
    refreshed = service.lookup(IP)
    assert refreshed.routing.provenance.from_cache is False
    assert refreshed.routing.provenance.retrieved_at == T0 + timedelta(seconds=601)
    assert len(fetcher.requested) == 4


def test_expired_entry_is_never_served_when_refresh_fails():
    service, fetcher, clock = make(ttl=600)
    fetcher.routes.update(healthy(service))
    service.lookup(IP)
    clock.advance(seconds=601)
    fetcher.routes[service.build_url(NETWORK_INFO_CALL, IP)] = SourceError(
        SourceErrorKind.TIMEOUT, "no response"
    )
    ctx = service.lookup(IP)
    assert ctx.status is ContextStatus.UNAVAILABLE
    assert ctx.routing.error.kind is E.TIMEOUT
    assert ctx.routing.asns == ()  # the stale answer was not reused


def test_errors_are_never_cached():
    service, fetcher, _ = make()
    url = service.build_url(NETWORK_INFO_CALL, IP)
    fetcher.routes[url] = http_error(url, 503)
    assert service.lookup(IP).status is ContextStatus.UNAVAILABLE
    assert service.cache_size == 0
    fetcher.routes.update(healthy(service))
    assert service.lookup(IP).status is ContextStatus.AVAILABLE
    assert fetcher.count(url) == 2


def test_malformed_body_is_not_cached():
    service = service_with_routing_body(b"garbage")
    url = service.build_url(NETWORK_INFO_CALL, IP)
    service.lookup(IP)
    assert service.cache_size == 0
    service._fetcher.routes[url] = ni(asns=[], prefix=None)
    assert service.lookup(IP).routing.status is SectionStatus.EMPTY
    assert service._fetcher.count(url) == 2


def test_valid_empty_answers_are_cacheable():
    service = service_with_routing_body(ni(asns=[], prefix=None))
    service.lookup(IP)
    service.lookup(IP)
    assert service._fetcher.count(service.build_url(NETWORK_INFO_CALL, IP)) == 1


def test_ttl_zero_disables_caching():
    service, fetcher, _ = make(ttl=0)
    fetcher.routes.update(healthy(service))
    service.lookup(IP)
    service.lookup(IP)
    assert len(fetcher.requested) == 4 and service.cache_size == 0


def test_holder_answers_are_shared_between_addresses_of_the_same_asn():
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    fetcher.routes.update(healthy(service, ip="8.8.4.4", prefix="8.8.4.0/24"))
    service.lookup(IP)
    other = service.lookup("8.8.4.4")
    assert fetcher.count(service.build_url(AS_OVERVIEW_CALL, "AS15169")) == 1
    assert other.holders[0].provenance.from_cache is True
    assert other.routing.provenance.from_cache is False


def test_cache_is_bounded_and_evicts_oldest():
    service, fetcher, _ = make(max_cache_entries=2, max_holder_lookups=0)
    for ip, prefix in (("8.8.8.8", "8.8.8.0/24"), ("8.8.4.4", "8.8.4.0/24"), ("1.1.1.1", "1.1.1.0/24")):
        fetcher.routes[service.build_url(NETWORK_INFO_CALL, ip)] = ni(["1"], prefix)
        service.lookup(ip)
    assert service.cache_size == 2
    service.lookup("8.8.8.8")  # was evicted: fetched again
    assert fetcher.count(service.build_url(NETWORK_INFO_CALL, "8.8.8.8")) == 2


def test_clock_moving_backwards_does_not_serve_the_entry():
    service, fetcher, clock = make()
    fetcher.routes.update(healthy(service))
    service.lookup(IP)
    clock.advance(seconds=-5)
    assert service.lookup(IP).routing.provenance.from_cache is False


def test_negative_cache_settings_are_rejected():
    fetcher = FakeFetcher({}, MutableClock(T0))
    with pytest.raises(ValueError):
        RipeStatContextService(fetcher, cache_ttl_seconds=-1)
    with pytest.raises(ValueError):
        RipeStatContextService(fetcher, max_holder_lookups=-1)


# ---------------------------------------------------------------- through the real RequestsFetcher
def real_stack(responses, **kwargs):
    """RIPEstat service + the real RequestsFetcher over a stub transport (no sockets)."""
    clock = MutableClock(T0)
    service = RipeStatContextService(
        FakeFetcher({}, clock), cache_ttl_seconds=600, clock=clock, **kwargs
    )  # temporary, only to build URLs
    transport = StubTransport({service.build_url(c, r): v for (c, r), v in responses.items()})
    session = requests.Session()
    session.mount("https://", transport)
    session.mount("http://", transport)
    fetcher = RequestsFetcher(session=session, clock=clock, timeout_seconds=4, max_bytes=1_000_000)
    real = RipeStatContextService(fetcher, cache_ttl_seconds=600, clock=clock, **kwargs)
    return real, transport


def test_end_to_end_success_through_requests_fetcher():
    real, transport = real_stack(
        {
            (NETWORK_INFO_CALL, IP): StubResponse(body=ni()),
            (AS_OVERVIEW_CALL, "AS15169"): StubResponse(body=ao()),
        }
    )
    ctx = real.lookup(IP)
    assert ctx.status is ContextStatus.AVAILABLE
    assert transport.calls[0]["timeout"] == (4, 4)


@pytest.mark.parametrize(
    "response,kind,status",
    [
        (StubResponse(status=429, body=b"slow down"), E.RATE_LIMITED, 429),
        (StubResponse(status=500, body=b"oops"), E.HTTP_ERROR, 500),
        (StubResponse(status=404, body=b"{}"), E.HTTP_ERROR, 404),
        (StubResponse(body=b"<html>not json</html>"), E.INVALID_JSON, None),
        (StubResponse(body=ni(status="maintenance")), E.API_MAINTENANCE, None),
        (requests.exceptions.ConnectTimeout("c"), E.TIMEOUT, None),
        (requests.exceptions.ReadTimeout("r"), E.TIMEOUT, None),
        (requests.exceptions.ConnectionError("refused"), E.CONNECTION, None),
        (requests.exceptions.SSLError("bad cert"), E.CONNECTION, None),
        (StubResponse(body=b"x" * 2_000_000), E.TOO_LARGE, None),
        (StubResponse(body=ni(), final_url="http://stat.ripe.net/redirected"), E.CONNECTION, None),
    ],
)
def test_end_to_end_failures_through_requests_fetcher(response, kind, status):
    real, _ = real_stack({(NETWORK_INFO_CALL, IP): response})
    ctx = real.lookup(IP)
    assert ctx.status is ContextStatus.UNAVAILABLE
    assert ctx.routing.error.kind is kind
    assert ctx.routing.error.http_status == status
    assert ctx.routing.asns == ()


# ---------------------------------------------------------------- display projection and models
@pytest.mark.parametrize(
    "holder",
    [
        "Hetzner Online GmbH",
        "DigitalOcean, LLC - cloud hosting",
        "Example VPN Services Ltd",
        "The Tor Project (relay hosting)",
        "DATACENTER-NET Colocation",
    ],
)
def test_projection_never_sets_a_hosting_indicator(holder):
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service, holder=holder))
    display = service.lookup(IP).to_network_context()
    assert display.as_name == holder
    assert display.hosting_indicator is False and display.hosting_indicator_basis is None
    assert display.source_name == RIPESTAT_SOURCE_NAME
    assert display.country_code is None


def test_projection_reports_the_oldest_retrieval_time():
    service, fetcher, clock = make(ttl=3600)
    fetcher.routes.update(healthy(service))
    service.lookup(IP)  # both sections retrieved at T0
    clock.advance(minutes=50)
    fetcher.routes[service.build_url(NETWORK_INFO_CALL, "8.8.4.4")] = ni(["15169"], "8.8.4.0/24")
    ctx = service.lookup("8.8.4.4")  # routing fresh now, holder from cache (T0)
    assert ctx.routing.provenance.retrieved_at == T0 + timedelta(minutes=50)
    assert ctx.holders[0].provenance.retrieved_at == T0
    assert ctx.to_network_context().retrieved_at == T0


def test_context_round_trips_to_json_and_is_frozen():
    service, fetcher, _ = make()
    fetcher.routes.update(healthy(service))
    ctx = service.lookup(IP)
    dumped = json.loads(ctx.model_dump_json())
    assert dumped["status"] == "AVAILABLE"
    assert dumped["routing"]["provenance"]["endpoint"].startswith("https://stat.ripe.net/data/")
    assert dumped["limitations"] and "never changes" in dumped["limitations"][0]
    with pytest.raises(Exception):
        ctx.status = ContextStatus.UNAVAILABLE


def test_section_invariants_are_enforced_by_the_models():
    with pytest.raises(ValueError):
        RoutingSection(status=SectionStatus.UNAVAILABLE)  # needs an error
    with pytest.raises(ValueError):
        RoutingSection(status=SectionStatus.OK)  # needs provenance
    with pytest.raises(ValueError):
        HolderSection(asn=-1, status=SectionStatus.UNAVAILABLE)
