import pytest

from netclass.config import Settings, load_settings


def test_ripestat_defaults():
    s = load_settings(env={})
    assert s.ripestat_base_url == "https://stat.ripe.net/data"
    assert s.ripestat_sourceapp is None
    assert s.ripestat_cache_ttl_seconds == 3600


def test_ripestat_overrides():
    s = load_settings(
        env={
            "NETCLASS_RIPESTAT_SOURCEAPP": " viltrumites_ps010 ",
            "NETCLASS_RIPESTAT_CACHE_TTL_SECONDS": "120",
            "NETCLASS_RIPESTAT_BASE_URL": "https://stat.example.invalid/data",
        }
    )
    assert s.ripestat_sourceapp == "viltrumites_ps010"
    assert s.ripestat_cache_ttl_seconds == 120
    assert s.ripestat_base_url == "https://stat.example.invalid/data"


def test_blank_sourceapp_means_not_set():
    assert load_settings(env={"NETCLASS_RIPESTAT_SOURCEAPP": "  "}).ripestat_sourceapp is None


@pytest.mark.parametrize("value", ["has space", "semi;colon", "a/b", "x" * 65])
def test_invalid_sourceapp_is_rejected(value):
    with pytest.raises(ValueError):
        load_settings(env={"NETCLASS_RIPESTAT_SOURCEAPP": value})


@pytest.mark.parametrize("value", ["http://stat.ripe.net/data", "ftp://x", "stat.ripe.net/data"])
def test_non_https_base_url_is_rejected(value):
    with pytest.raises(ValueError):
        load_settings(env={"NETCLASS_RIPESTAT_BASE_URL": value})


@pytest.mark.parametrize("value", ["abc", "0", "-1"])
def test_invalid_ripestat_ttl_is_rejected(value):
    with pytest.raises(ValueError):
        load_settings(env={"NETCLASS_RIPESTAT_CACHE_TTL_SECONDS": value})


def test_cache_and_download_settings_are_unchanged():
    s = Settings()
    assert s.cache_ttl_seconds == 1800 and s.current_evidence_tolerance_seconds == 3600
    assert s.max_source_age_seconds == 86400 and s.max_download_bytes == 20_000_000
