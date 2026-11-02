"""IPinfo adapter (Stage 4): mocked HTTP only, no token or network needed."""
import ast
import logging
from pathlib import Path

import pytest

import netclass.ipinfo as ipinfo_module
from factories import T0
from fakes import MutableClock
from ipinfo_support import DROP, IP, IP6, TOKEN, http_error, lite, make, url_for
from netclass.errors import SourceError, SourceErrorKind
from netclass.hashing import sha256_hex
from netclass.ipinfo import (
    IpInfoError,
    IpInfoErrorKind,
    IpInfoMetadata,
    IpInfoService,
    IpInfoStatus,
    parse_lite_response,
    valid_token_format,
)

E = IpInfoErrorKind
S = IpInfoStatus


# ------------------------------------------------------------------ successful lookups
def test_successful_ipv4_lookup():
    service, fetcher, _ = make({url_for(IP): lite(IP)})
    meta = service.lookup(IP)
    assert meta.status is S.AVAILABLE and meta.usable
    assert meta.ip == IP
    assert meta.asn == 64496  # "AS64496" text parsed to an integer
    assert meta.as_name == "EXAMPLE-NET Example Networks"
    assert meta.as_domain == "example.net"
    assert (meta.country_code, meta.country) == ("US", "United States")
    assert (meta.continent_code, meta.continent) == ("NA", "North America")
    assert meta.error is None and meta.note is None
    assert meta.provenance.source_name == "ipinfo-lite-api"
    assert meta.provenance.endpoint == "https://api.ipinfo.io/lite/8.8.8.8"
    assert meta.provenance.from_cache is False
    assert meta.provenance.response_sha256 == sha256_hex(lite(IP))
    assert meta.provenance.retrieved_at == T0
    assert fetcher.requested == [url_for(IP)]


def test_successful_ipv6_lookup():
    service, fetcher, _ = make({url_for(IP6): lite(IP6, asn="AS64497")})
    meta = service.lookup(IP6)
    assert meta.status is S.AVAILABLE
    assert meta.ip == IP6 and meta.asn == 64497
    assert fetcher.requested == ["https://api.ipinfo.io/lite/2001:4860:4860::8888"]


def test_ipv6_response_may_use_a_different_textual_form():
    service, _, _ = make({url_for(IP6): lite("2001:4860:4860:0:0:0:0:8888")})
    assert service.lookup(IP6).status is S.AVAILABLE


def test_ipv4_mapped_ipv6_input_is_normalised_to_ipv4():
    service, fetcher, _ = make({url_for(IP): lite(IP)})
    meta = service.lookup("::ffff:8.8.8.8")
    assert meta.ip == IP and meta.status is S.AVAILABLE
    assert fetcher.requested == [url_for(IP)]


def test_custom_base_url_is_used_and_must_be_https():
    base = "https://ipinfo-proxy.example.invalid"
    service, fetcher, _ = make({url_for(IP, base): lite(IP)}, base_url=base + "/")
    assert service.lookup(IP).status is S.AVAILABLE
    assert fetcher.requested == [url_for(IP, base)]
    with pytest.raises(ValueError):
        IpInfoService(None, token=TOKEN, base_url="http://api.ipinfo.io")


# ------------------------------------------------------------------ missing / odd fields
def test_missing_optional_fields_are_left_empty_not_invented():
    body = lite(IP, as_name=DROP, as_domain=DROP, country=DROP, continent=DROP, continent_code=DROP)
    service, _, _ = make({url_for(IP): body})
    meta = service.lookup(IP)
    assert meta.status is S.AVAILABLE
    assert meta.asn == 64496 and meta.country_code == "US"
    assert meta.as_name is None and meta.as_domain is None
    assert meta.country is None and meta.continent is None and meta.continent_code is None
    assert any("fields absent from the response" in w for w in meta.warnings)
    assert "as_name" in " ".join(meta.warnings)


def test_response_with_only_ip_is_empty_not_available():
    service, _, _ = make({url_for(IP): b'{"ip": "8.8.8.8"}'})
    meta = service.lookup(IP)
    assert meta.status is S.EMPTY and not meta.usable
    assert meta.provenance is not None and meta.error is None
    assert meta.asn is None and meta.as_name is None


def test_null_and_blank_values_count_as_not_provided():
    body = lite(IP, as_name=None, as_domain="   ", country=None, asn=None)
    meta = make({url_for(IP): body})[0].lookup(IP)
    assert meta.as_name is None and meta.as_domain is None and meta.asn is None
    assert meta.country_code == "US"


@pytest.mark.parametrize(
    "overrides, ignored",
    [
        ({"asn": "banana"}, "asn"),
        ({"asn": True}, "asn"),
        ({"asn": 99999999999}, "asn"),
        ({"as_name": 123}, "as_name"),
        ({"as_domain": "not a domain"}, "as_domain"),
        ({"country_code": "usa"}, "country_code"),
        ({"country_code": "u"}, "country_code"),
        ({"continent_code": 5}, "continent_code"),
        ({"country": ["US"]}, "country"),
    ],
)
def test_wrongly_typed_or_malformed_fields_are_ignored_with_a_warning(overrides, ignored):
    meta = make({url_for(IP): lite(IP, **overrides)})[0].lookup(IP)
    assert meta.status is S.AVAILABLE  # the other fields are still fine
    assert getattr(meta, ignored) is None
    assert any(ignored in w for w in meta.warnings)


def test_text_is_cleaned_and_long_values_are_truncated_with_a_warning():
    long_name = "N" * 400
    body = lite(IP, as_name=long_name, country="United\x00 \tStates\n")
    meta = make({url_for(IP): body})[0].lookup(IP)
    assert meta.as_name == "N" * 256
    assert any("as_name" in w and "truncated" in w for w in meta.warnings)
    assert meta.country == "United States"


def test_undocumented_fields_are_ignored_and_never_surface():
    body = lite(
        IP,
        is_vpn=True,
        privacy={"vpn": True, "proxy": True, "tor": True, "hosting": True},
        hosting=True,
        org="AS1 Some VPN Hosting Ltd",
        bogon=False,
    )
    meta = make({url_for(IP): body})[0].lookup(IP)
    assert meta.status is S.AVAILABLE
    dumped = meta.model_dump(mode="json")
    for name in ("is_vpn", "privacy", "hosting", "org", "bogon"):
        assert name not in dumped
    assert "VPN Hosting" not in meta.model_dump_json()


def test_result_carries_limitations_that_say_it_is_not_evidence():
    meta = make({url_for(IP): lite(IP)})[0].lookup(IP)
    text = " ".join(meta.limitations)
    assert "not evidence" in text and "never changes" in text


# ------------------------------------------------------------------ invalid / excluded input
@pytest.mark.parametrize(
    "bad", ["", "   ", "not-an-ip", "8.8.8.8/24", "8.8.8.8:80", "fe80::1%eth0", "8.8.8", 12345, None]
)
def test_invalid_ip_input_is_rejected_without_a_request(bad):
    service, fetcher, _ = make({})
    meta = service.lookup(bad)
    assert meta.status is S.UNAVAILABLE
    assert meta.error.kind is E.INVALID_INPUT
    assert fetcher.requested == []


@pytest.mark.parametrize(
    "excluded",
    [
        "10.0.0.1",  # RFC 1918
        "172.16.5.4",
        "192.168.1.1",
        "127.0.0.1",  # loopback
        "169.254.10.10",  # link-local
        "100.64.0.1",  # shared address space
        "192.0.2.1",  # documentation
        "224.0.0.1",  # multicast
        "240.0.0.1",  # reserved
        "0.0.0.0",  # unspecified
        "::1",
        "fe80::1",
        "fc00::1",  # unique local
        "ff02::1",
        "::",
        "2001:db8::1",  # documentation
    ],
)
def test_private_reserved_addresses_are_never_sent_to_ipinfo(excluded):
    service, fetcher, _ = make({})
    meta = service.lookup(excluded)
    assert meta.status is S.NOT_QUERIED
    assert "No IPinfo request was made" in meta.note
    assert meta.error is None and meta.provenance is None and meta.asn is None
    assert fetcher.requested == []


# ------------------------------------------------------------------ disabled integration
@pytest.mark.parametrize("token", [None, "", "   "])
def test_missing_token_disables_the_integration_safely(token):
    service, fetcher, _ = make({url_for(IP): lite(IP)}, token=token)
    assert service.enabled is False
    meta = service.lookup(IP)
    assert meta.status is S.DISABLED and not meta.usable
    assert "IPINFO_TOKEN" in meta.note and "No request was made" in meta.note
    assert meta.error is None and meta.provenance is None
    assert fetcher.requested == []


@pytest.mark.parametrize("token", ["has space", "line\nbreak", "tab\there", "ünïcode", "x" * 513])
def test_unusable_token_format_disables_the_integration_without_echoing_it(token):
    service, fetcher, _ = make({url_for(IP): lite(IP)}, token=token)
    meta = service.lookup(IP)
    assert service.enabled is False
    assert meta.status is S.DISABLED
    assert token.strip() not in meta.note and token.strip() not in repr(service)
    assert fetcher.requested == []


def test_no_fetcher_means_disabled_even_with_a_token():
    service = IpInfoService(None, token=TOKEN)
    assert service.enabled is False
    assert service.lookup(IP).status is S.DISABLED


def test_valid_token_format_helper():
    assert valid_token_format("abc123")
    assert not valid_token_format("")
    assert not valid_token_format(None)
    assert not valid_token_format("a b")
    assert not valid_token_format("a\r\nb")


# ------------------------------------------------------------------ transport failures
def test_timeout_is_unavailable_not_empty():
    err = SourceError(SourceErrorKind.TIMEOUT, "no response within 10s", url=url_for(IP))
    meta = make({url_for(IP): err})[0].lookup(IP)
    assert meta.status is S.UNAVAILABLE and meta.error.kind is E.TIMEOUT
    assert meta.asn is None and meta.provenance is None


def test_connection_failure_is_unavailable():
    err = SourceError(SourceErrorKind.CONNECTION, "request failed (ConnectionError)", url=url_for(IP))
    meta = make({url_for(IP): err})[0].lookup(IP)
    assert meta.status is S.UNAVAILABLE and meta.error.kind is E.CONNECTION


def test_oversized_response_is_unavailable():
    err = SourceError(SourceErrorKind.TOO_LARGE, "body exceeds limit", url=url_for(IP))
    meta = make({url_for(IP): err})[0].lookup(IP)
    assert meta.error.kind is E.TOO_LARGE


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failures(status):
    meta = make({url_for(IP): http_error(url_for(IP), status)})[0].lookup(IP)
    assert meta.status is S.UNAVAILABLE
    assert meta.error.kind is E.AUTH_FAILED and meta.error.http_status == status
    assert "IPINFO_TOKEN" in meta.error.message


def test_rate_limit_http_429():
    meta = make({url_for(IP): http_error(url_for(IP), 429)})[0].lookup(IP)
    assert meta.status is S.UNAVAILABLE
    assert meta.error.kind is E.RATE_LIMITED and meta.error.http_status == 429
    assert "does not retry" in meta.error.message


@pytest.mark.parametrize("status", [500, 502, 503, 504, 599])
def test_server_errors(status):
    meta = make({url_for(IP): http_error(url_for(IP), status)})[0].lookup(IP)
    assert meta.status is S.UNAVAILABLE
    assert meta.error.kind is E.SERVER_ERROR and meta.error.http_status == status


@pytest.mark.parametrize("status", [400, 404, 418])
def test_other_http_statuses_are_generic_http_errors(status):
    meta = make({url_for(IP): http_error(url_for(IP), status)})[0].lookup(IP)
    assert meta.error.kind is E.HTTP_ERROR and meta.error.http_status == status


def test_an_unrouted_url_is_reported_as_a_failure_not_an_empty_success():
    # FakeFetcher answers HTTP 404 for any URL without a route.
    meta = make({})[0].lookup(IP)
    assert meta.status is S.UNAVAILABLE and meta.error.kind is E.HTTP_ERROR


# ------------------------------------------------------------------ malformed responses
@pytest.mark.parametrize("body", [b"", b"<html>Service Unavailable</html>", b"{not json", b"\xff\xfe\x00"])
def test_invalid_json(body):
    meta = make({url_for(IP): body})[0].lookup(IP)
    assert meta.status is S.UNAVAILABLE and meta.error.kind is E.INVALID_JSON


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'"8.8.8.8"',
        b"123",
        b"null",
        b"{}",  # no "ip"
        b'{"asn": "AS64496"}',  # no "ip"
        b'{"ip": null, "asn": "AS64496"}',
        b'{"ip": 5}',
        b'{"ip": "not-an-ip"}',
        b'{"ip": "1.1.1.1", "asn": "AS64496"}',  # answer for a different address
        b'{"ip": "2606:4700:4700::1111"}',
    ],
)
def test_structurally_wrong_responses_are_rejected(body):
    meta = make({url_for(IP): body})[0].lookup(IP)
    assert meta.status is S.UNAVAILABLE and meta.error.kind is E.UNEXPECTED_STRUCTURE
    assert meta.asn is None


def test_parse_function_is_pure_and_reports_warnings():
    fields, warnings = parse_lite_response(lite(IP, country=DROP), IP)
    assert fields["asn"] == 64496 and "country" not in fields
    assert any("country" in w for w in warnings)


# ------------------------------------------------------------------ cache
def test_second_lookup_is_served_from_cache_with_the_original_retrieval_time():
    service, fetcher, clock = make({url_for(IP): lite(IP)})
    first = service.lookup(IP)
    clock.advance(minutes=10)
    second = service.lookup(IP)
    assert fetcher.count(url_for(IP)) == 1
    assert first.provenance.from_cache is False and second.provenance.from_cache is True
    assert second.provenance.retrieved_at == T0 == first.provenance.retrieved_at
    assert second.asn == first.asn and second.provenance.response_sha256 == first.provenance.response_sha256
    assert service.cache_size == 1


def test_cache_entries_expire_and_are_refetched():
    service, fetcher, clock = make({url_for(IP): lite(IP)}, ttl=600)
    service.lookup(IP)
    clock.advance(seconds=601)
    again = service.lookup(IP)
    assert fetcher.count(url_for(IP)) == 2
    assert again.provenance.from_cache is False
    assert again.provenance.retrieved_at == clock.now


def test_an_expired_entry_is_never_served_when_the_refresh_fails():
    service, fetcher, clock = make({url_for(IP): lite(IP)}, ttl=600)
    service.lookup(IP)
    clock.advance(seconds=601)
    fetcher.routes[url_for(IP)] = SourceError(SourceErrorKind.TIMEOUT, "slow", url=url_for(IP))
    meta = service.lookup(IP)
    assert meta.status is S.UNAVAILABLE and meta.error.kind is E.TIMEOUT
    assert meta.asn is None


def test_failures_are_never_cached():
    service, fetcher, _ = make({url_for(IP): http_error(url_for(IP), 503)})
    assert service.lookup(IP).status is S.UNAVAILABLE
    fetcher.routes[url_for(IP)] = lite(IP)
    assert service.lookup(IP).status is S.AVAILABLE  # recovered immediately
    assert fetcher.count(url_for(IP)) == 2


def test_unparseable_bodies_are_never_cached():
    service, fetcher, _ = make({url_for(IP): b"<html>"})
    service.lookup(IP)
    service.lookup(IP)
    assert fetcher.count(url_for(IP)) == 2 and service.cache_size == 0


def test_cache_can_be_disabled_and_is_per_address():
    service, fetcher, _ = make({url_for(IP): lite(IP), url_for(IP6): lite(IP6)}, ttl=0)
    service.lookup(IP)
    service.lookup(IP)
    assert fetcher.count(url_for(IP)) == 2 and service.cache_size == 0
    cached, f2, _ = make({url_for(IP): lite(IP), url_for(IP6): lite(IP6)})
    cached.lookup(IP)
    cached.lookup(IP6)
    assert f2.requested == [url_for(IP), url_for(IP6)] and cached.cache_size == 2


def test_negative_cache_settings_are_rejected():
    with pytest.raises(ValueError):
        IpInfoService(None, token=TOKEN, cache_ttl_seconds=-1)
    with pytest.raises(ValueError):
        IpInfoService(None, token=TOKEN, max_cache_entries=-1)


# ------------------------------------------------------------------ secrets
def _everything(meta: IpInfoMetadata, service: IpInfoService) -> str:
    return meta.model_dump_json() + repr(meta) + repr(service) + str(meta.error)


@pytest.mark.parametrize(
    "message",
    [
        f"request failed (ConnectionError): bad {TOKEN} here",
        f"GET https://api.ipinfo.io/lite/8.8.8.8?token={TOKEN} failed",
        f"sent header Authorization: Bearer {TOKEN}",
        "Authorization: Bearer some-other-looking-secret",
        "https://api.ipinfo.io/lite/8.8.8.8?token=another-secret&x=1",
    ],
)
def test_token_is_redacted_from_errors_coming_from_the_fetcher(message, caplog):
    leaky = SourceError(
        SourceErrorKind.CONNECTION, message, url=f"https://api.ipinfo.io/lite/8.8.8.8?token={TOKEN}"
    )
    service, _, _ = make({url_for(IP): leaky})
    with caplog.at_level(logging.DEBUG):
        meta = service.lookup(IP)
    blob = _everything(meta, service) + caplog.text
    for secret in (TOKEN, "some-other-looking-secret", "another-secret"):
        assert secret not in blob
    assert "[REDACTED]" in meta.error.message or "[REDACTED]" in (meta.error.endpoint or "")


def test_token_is_redacted_when_the_fetcher_raises_something_unexpected(caplog):
    def boom():
        raise RuntimeError(f"internal failure with {TOKEN} inside")

    service, _, _ = make({url_for(IP): boom})
    with caplog.at_level(logging.DEBUG):
        meta = service.lookup(IP)
    assert meta.status is S.UNAVAILABLE and meta.error.kind is E.INTERNAL
    assert TOKEN not in _everything(meta, service) + caplog.text
    assert "RuntimeError" in meta.error.message  # the type is reported, the text is not


def test_token_never_appears_in_urls_provenance_or_successful_results(caplog):
    service, fetcher, _ = make({url_for(IP): lite(IP)})
    with caplog.at_level(logging.DEBUG):
        meta = service.lookup(IP)
    assert all(TOKEN not in url for url in fetcher.requested)
    assert TOKEN not in _everything(meta, service) + caplog.text
    assert "token=" not in meta.provenance.endpoint


def test_service_repr_hides_the_token():
    service, _, _ = make({})
    assert TOKEN not in repr(service) and TOKEN not in str(service)
    assert "enabled=True" in repr(service)


# ------------------------------------------------------------------ robustness
def test_lookup_never_raises_even_if_the_clock_or_cache_misbehave():
    class BadFetcher:
        def fetch(self, url):
            raise KeyError("surprise")

    service = IpInfoService(BadFetcher(), token=TOKEN, clock=MutableClock(T0))
    meta = service.lookup(IP)
    assert meta.status is S.UNAVAILABLE and meta.error.kind is E.INTERNAL


def test_result_models_reject_inconsistent_states():
    with pytest.raises(ValueError):  # UNAVAILABLE needs an error
        IpInfoMetadata(ip=IP, status=S.UNAVAILABLE, requested_at=T0)
    with pytest.raises(ValueError):  # AVAILABLE needs provenance
        IpInfoMetadata(ip=IP, status=S.AVAILABLE, requested_at=T0, asn=1)
    with pytest.raises(ValueError):  # DISABLED needs a note
        IpInfoMetadata(ip=IP, status=S.DISABLED, requested_at=T0)
    with pytest.raises(ValueError):  # naive datetimes are rejected like everywhere else
        IpInfoError(kind=E.TIMEOUT, message="x", occurred_at=T0.replace(tzinfo=None))


# ------------------------------------------------------------------ architectural guards
def test_ipinfo_module_does_not_import_or_reference_classification_types():
    source = Path(ipinfo_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    forbidden = {
        "classifier", ".classifier", "models", ".models", "adapters", ".adapters", "collector",
        ".collector", "service", ".service", "Label", "ReasonCode", "EvidenceRecord",
        "EvidenceKind", "EvidenceStatus", "classify", "Applicability", "ClassificationResult",
        "NetworkContext", "requests", "socket",
    }
    assert not (imported & forbidden), imported & forbidden
    names_used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not (names_used & {"Label", "ReasonCode", "EvidenceRecord", "EvidenceKind", "EvidenceStatus"})
