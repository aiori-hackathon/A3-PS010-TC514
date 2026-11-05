"""Audit settings: audit is off by default, retention defaults to 90 days, 0 only when explicit."""
from pathlib import Path

import pytest

from netclass.config import Settings, load_settings


def test_defaults_keep_auditing_off():
    s = Settings()
    assert s.audit_enabled is False
    assert s.audit_retention_days == 90 and s.audit_keeps_forever is False
    assert s.db_path == Path("data/audit.sqlite3")


def test_empty_environment_leaves_audit_disabled_with_90_days():
    s = load_settings(env={})
    assert s.audit_enabled is False and s.audit_retention_days == 90


def test_blank_values_mean_defaults():
    s = load_settings(env={"NETCLASS_AUDIT_ENABLED": "", "NETCLASS_AUDIT_RETENTION_DAYS": "  "})
    assert s.audit_enabled is False and s.audit_retention_days == 90


@pytest.mark.parametrize("raw,expected", [("true", True), ("1", True), ("off", False), ("no", False)])
def test_enabled_is_parsed(raw, expected):
    assert load_settings(env={"NETCLASS_AUDIT_ENABLED": raw}).audit_enabled is expected


def test_retention_is_parsed_and_zero_means_keep_forever():
    assert load_settings(env={"NETCLASS_AUDIT_RETENTION_DAYS": "30"}).audit_retention_days == 30
    zero = load_settings(env={"NETCLASS_AUDIT_RETENTION_DAYS": "0"})
    assert zero.audit_retention_days == 0 and zero.audit_keeps_forever is True


@pytest.mark.parametrize(
    "key,raw",
    [
        ("NETCLASS_AUDIT_ENABLED", "perhaps"),
        ("NETCLASS_AUDIT_RETENTION_DAYS", "-5"),
        ("NETCLASS_AUDIT_RETENTION_DAYS", "ninety"),
        ("NETCLASS_AUDIT_RETENTION_DAYS", "1.5"),
    ],
)
def test_bad_values_are_rejected_with_the_key_name(key, raw):
    with pytest.raises(ValueError, match=key):
        load_settings(env={key: raw})


def test_db_path_setting_is_used():
    s = load_settings(env={"NETCLASS_DB_PATH": "somewhere/else.sqlite3"})
    assert s.db_path == Path("somewhere/else.sqlite3")


def test_ipinfo_and_cache_settings_are_unaffected():
    s = load_settings(env={"NETCLASS_AUDIT_ENABLED": "true", "IPINFO_TOKEN": "tok"})
    assert s.ipinfo_enabled is True and s.cache_ttl_seconds == 1800
    assert "tok" not in repr(s)
