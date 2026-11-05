import pytest

from netclass.config import Settings, load_settings


def test_defaults_when_env_is_empty():
    s = load_settings(env={})
    assert s.tor_exit_list_url == "https://check.torproject.org/torbulkexitlist"
    assert s.vpn_provider_configured is False
    assert s.ipinfo_token is None
    assert s.cache_ttl_seconds <= s.current_evidence_tolerance_seconds


def test_overrides_and_blank_values():
    s = load_settings(
        env={
            "NETCLASS_VPN_PROVIDER": "  example-provider ",
            "NETCLASS_VPN_API_KEY": "",
            "IPINFO_TOKEN": "tok",
            "NETCLASS_HTTP_TIMEOUT_SECONDS": "3.5",
        }
    )
    assert s.vpn_provider_name == "example-provider"
    assert s.vpn_provider_configured is True
    assert s.vpn_provider_api_key is None  # blank means not configured
    assert s.ipinfo_token == "tok"
    assert s.http_timeout_seconds == 3.5


def test_secrets_are_not_in_repr():
    s = load_settings(env={"IPINFO_TOKEN": "super-secret", "NETCLASS_VPN_API_KEY": "key-123"})
    text = repr(s)
    assert "super-secret" not in text
    assert "key-123" not in text


@pytest.mark.parametrize("value", ["abc", "0", "-5"])
def test_invalid_numbers_are_rejected(value):
    with pytest.raises(ValueError):
        load_settings(env={"NETCLASS_HTTP_TIMEOUT_SECONDS": value})


def test_cache_ttl_must_not_exceed_tolerance():
    with pytest.raises(ValueError):
        load_settings(env={"NETCLASS_CACHE_TTL_SECONDS": "7200"})


def test_settings_is_immutable():
    with pytest.raises(Exception):
        Settings().cache_ttl_seconds = 1  # type: ignore[misc]


# ------------------------------------------------------------- adapter and download settings
def test_adapter_and_download_defaults():
    s = load_settings(env={})
    assert s.max_source_age_seconds == 86400
    assert s.max_download_bytes == 20_000_000
    assert s.enabled_sources == (
        "tor-project-bulk-exit-list",
        "x4bnet-lists-vpn",
        "az0-vpn-ip",
    )


def test_enabled_sources_are_validated_ordered_and_deduplicated():
    s = load_settings(env={"NETCLASS_ENABLED_SOURCES": " az0-vpn-ip , tor-project-bulk-exit-list,az0-vpn-ip"})
    assert s.enabled_sources == ("tor-project-bulk-exit-list", "az0-vpn-ip")


@pytest.mark.parametrize("value", ["nonsense", "tor-project-bulk-exit-list,bogus", ",,"])
def test_unknown_or_empty_source_lists_are_rejected(value):
    with pytest.raises(ValueError):
        load_settings(env={"NETCLASS_ENABLED_SOURCES": value})


def test_adapter_and_download_numeric_overrides():
    s = load_settings(
        env={"NETCLASS_MAX_SOURCE_AGE_SECONDS": "7200", "NETCLASS_MAX_DOWNLOAD_BYTES": "1000000"}
    )
    assert s.max_source_age_seconds == 7200 and s.max_download_bytes == 1_000_000
    with pytest.raises(ValueError):
        load_settings(env={"NETCLASS_MAX_DOWNLOAD_BYTES": "-1"})
