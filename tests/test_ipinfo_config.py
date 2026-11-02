"""Stage 4 configuration and transport: token handling, defaults, header-only credentials."""
import logging
from pathlib import Path

import pytest
import requests

import netclass.collector as collector_module
from factories import T0
from fakes import MutableClock, StubResponse, StubTransport
from ipinfo_support import IP, TOKEN, lite
from netclass.collector import build_ipinfo_service
from netclass.config import Settings, load_settings
from netclass.http_client import RequestsFetcher
from netclass.ipinfo import IpInfoErrorKind, IpInfoService, IpInfoStatus

URL = f"https://api.ipinfo.io/lite/{IP}"


# ------------------------------------------------------------------ configuration
def test_ipinfo_is_disabled_by_default():
    s = load_settings(env={})
    assert s.ipinfo_token is None and s.ipinfo_enabled is False
    assert s.ipinfo_base_url == "https://api.ipinfo.io"
    assert s.ipinfo_cache_ttl_seconds == 3600


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_token_means_disabled(value):
    s = load_settings(env={"IPINFO_TOKEN": value})
    assert s.ipinfo_token is None and s.ipinfo_enabled is False


def test_existing_variable_name_is_still_the_one_that_enables_it():
    s = load_settings(env={"IPINFO_TOKEN": f"  {TOKEN} "})
    assert s.ipinfo_token == TOKEN and s.ipinfo_enabled is True


def test_overrides():
    s = load_settings(
        env={
            "NETCLASS_IPINFO_BASE_URL": "https://ipinfo.example.invalid",
            "NETCLASS_IPINFO_CACHE_TTL_SECONDS": "120",
        }
    )
    assert s.ipinfo_base_url == "https://ipinfo.example.invalid" and s.ipinfo_cache_ttl_seconds == 120


@pytest.mark.parametrize(
    "env",
    [
        {"NETCLASS_IPINFO_BASE_URL": "http://api.ipinfo.io"},
        {"NETCLASS_IPINFO_CACHE_TTL_SECONDS": "0"},
        {"NETCLASS_IPINFO_CACHE_TTL_SECONDS": "-5"},
        {"NETCLASS_IPINFO_CACHE_TTL_SECONDS": "abc"},
    ],
)
def test_invalid_ipinfo_settings_are_rejected(env):
    with pytest.raises(ValueError):
        load_settings(env=env)


def test_token_is_not_in_settings_repr_or_in_a_config_error():
    assert TOKEN not in repr(load_settings(env={"IPINFO_TOKEN": TOKEN}))
    with pytest.raises(ValueError) as caught:
        load_settings(env={"IPINFO_TOKEN": TOKEN, "NETCLASS_IPINFO_BASE_URL": "http://x"})
    assert TOKEN not in str(caught.value)


def test_a_token_in_the_environment_does_not_change_other_defaults():
    plain, with_token = load_settings(env={}), load_settings(env={"IPINFO_TOKEN": TOKEN})
    assert plain.enabled_sources == with_token.enabled_sources
    assert plain.cache_ttl_seconds == with_token.cache_ttl_seconds
    assert Settings().ipinfo_token is None


def test_the_shipped_env_template_keeps_ipinfo_disabled_and_changes_no_defaults():
    from dotenv import dotenv_values

    template = dotenv_values(Path(__file__).resolve().parents[1] / ".env.example")
    assert "IPINFO_TOKEN" in template  # the existing variable name is unchanged
    assert not template["IPINFO_TOKEN"]  # and the template ships it blank
    from_template = load_settings(env={k: v or "" for k, v in template.items()})
    assert from_template.ipinfo_enabled is False
    defaults = load_settings(env={})
    assert from_template.ipinfo_base_url == defaults.ipinfo_base_url == "https://api.ipinfo.io"
    assert from_template.ipinfo_cache_ttl_seconds == defaults.ipinfo_cache_ttl_seconds == 3600


# ------------------------------------------------------------------ builder
def test_builder_without_token_is_disabled_and_builds_no_fetcher(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("no fetcher may be built without a token")

    monkeypatch.setattr(collector_module, "RequestsFetcher", forbidden)
    service = build_ipinfo_service(load_settings(env={}))
    assert service.enabled is False
    assert service.lookup(IP).status is IpInfoStatus.DISABLED


def test_builder_with_unusable_token_is_disabled(monkeypatch):
    monkeypatch.setattr(collector_module, "RequestsFetcher", lambda **kw: pytest.fail("built"))
    service = build_ipinfo_service(Settings(ipinfo_token="bad token"))
    assert service.enabled is False


def test_builder_sends_the_token_only_as_a_bearer_header(monkeypatch):
    captured = {}

    class Recorder:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(collector_module, "RequestsFetcher", Recorder)
    service = build_ipinfo_service(Settings(ipinfo_token=TOKEN, http_timeout_seconds=4.0))
    assert service.enabled is True
    assert captured["extra_headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert captured["extra_headers"]["Accept"] == "application/json"
    assert captured["timeout_seconds"] == 4.0
    assert captured["max_bytes"] <= 1_000_000  # small cap, not the 20 MB evidence cap
    assert TOKEN not in repr(service)


def test_builder_accepts_an_injected_fetcher():
    marker = object()
    service = build_ipinfo_service(Settings(ipinfo_token=TOKEN), fetcher=marker)  # type: ignore[arg-type]
    assert service.enabled is True


# ------------------------------------------------------------------ real RequestsFetcher + stub transport
def stubbed_fetcher(routes, **kwargs):
    transport = StubTransport(routes)
    session = requests.Session()
    session.mount("https://", transport)
    return RequestsFetcher(session=session, clock=MutableClock(T0), **kwargs), transport


def test_default_fetcher_sends_no_credentials_header():
    fetcher, transport = stubbed_fetcher({URL: StubResponse(body=b"x")})
    fetcher.fetch(URL)
    assert "Authorization" not in transport.calls[0]["headers"]
    assert transport.calls[0]["headers"]["Accept"] == "text/plain, */*"


def test_extra_headers_are_sent_and_may_override_accept():
    fetcher, transport = stubbed_fetcher(
        {URL: StubResponse(body=b"{}")},
        extra_headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"},
    )
    fetcher.fetch(URL)
    headers = transport.calls[0]["headers"]
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert headers["Accept"] == "application/json"
    assert "viltrumites-ps010" in headers["User-Agent"]
    assert TOKEN not in transport.calls[0]["url"]


def end_to_end(routes):
    fetcher, transport = stubbed_fetcher(
        routes, extra_headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"}
    )
    service = IpInfoService(fetcher, token=TOKEN, clock=MutableClock(T0))
    return service, transport


def test_end_to_end_success_uses_header_auth_and_a_token_free_url():
    service, transport = end_to_end({URL: StubResponse(body=lite(IP))})
    meta = service.lookup(IP)
    assert meta.status is IpInfoStatus.AVAILABLE and meta.asn == 64496
    call = transport.calls[0]
    assert call["url"] == URL and call["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert call["timeout"] == (10.0, 10.0)


@pytest.mark.parametrize(
    "response, kind",
    [
        (StubResponse(status=401), IpInfoErrorKind.AUTH_FAILED),
        (StubResponse(status=403), IpInfoErrorKind.AUTH_FAILED),
        (StubResponse(status=429), IpInfoErrorKind.RATE_LIMITED),
        (StubResponse(status=500), IpInfoErrorKind.SERVER_ERROR),
        (StubResponse(status=503), IpInfoErrorKind.SERVER_ERROR),
        (requests.exceptions.ConnectTimeout("slow"), IpInfoErrorKind.TIMEOUT),
        (requests.exceptions.ReadTimeout("slow"), IpInfoErrorKind.TIMEOUT),
        (requests.exceptions.ConnectionError("refused"), IpInfoErrorKind.CONNECTION),
        (requests.exceptions.SSLError("bad cert"), IpInfoErrorKind.CONNECTION),
        (StubResponse(body=b"<html>"), IpInfoErrorKind.INVALID_JSON),
        (StubResponse(body=b"[1, 2]"), IpInfoErrorKind.UNEXPECTED_STRUCTURE),
        (StubResponse(body=b"x" * 200_000, headers={"Content-Length": "200000"}), None),
    ],
)
def test_end_to_end_failures_map_to_typed_errors(response, kind):
    fetcher, _ = stubbed_fetcher({URL: response}, max_bytes=100_000,
                                 extra_headers={"Authorization": f"Bearer {TOKEN}"})
    service = IpInfoService(fetcher, token=TOKEN, clock=MutableClock(T0))
    meta = service.lookup(IP)
    assert meta.status is IpInfoStatus.UNAVAILABLE
    assert meta.error.kind is (kind or IpInfoErrorKind.TOO_LARGE)


def test_end_to_end_errors_and_logs_never_contain_the_token(caplog):
    leaky = requests.exceptions.ConnectionError(f"proxy said: Authorization Bearer {TOKEN} refused")
    service, _ = end_to_end({URL: leaky})
    with caplog.at_level(logging.DEBUG):
        meta = service.lookup(IP)
    assert meta.error.kind is IpInfoErrorKind.CONNECTION
    assert TOKEN not in meta.model_dump_json() + caplog.text + repr(meta)
