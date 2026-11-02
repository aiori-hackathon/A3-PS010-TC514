"""Parsing of the audit settings: disabled by default, 90-day default, 0 only when explicit."""
import pytest

from netclass.audit.retention import (
    DEFAULT_RETENTION_DAYS,
    MAX_RETENTION_DAYS,
    parse_enabled,
    parse_retention_days,
)


def test_defaults_are_disabled_and_ninety_days():
    assert parse_enabled(None) is False
    assert parse_enabled("") is False
    assert parse_enabled("   ") is False
    assert DEFAULT_RETENTION_DAYS == 90
    assert parse_retention_days(None) == 90
    assert parse_retention_days("") == 90


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", " yes ", "On"])
def test_enabled_true_values(raw):
    assert parse_enabled(raw) is True


@pytest.mark.parametrize("raw", ["0", "false", "No", "off"])
def test_enabled_false_values(raw):
    assert parse_enabled(raw) is False


@pytest.mark.parametrize("raw", ["maybe", "2", "enabled", "y"])
def test_enabled_rejects_anything_unclear(raw):
    with pytest.raises(ValueError, match="NETCLASS_AUDIT_ENABLED"):
        parse_enabled(raw)


@pytest.mark.parametrize("raw,expected", [("1", 1), ("30", 30), (" 365 ", 365), ("0", 0)])
def test_retention_accepts_whole_days_and_explicit_zero(raw, expected):
    assert parse_retention_days(raw) == expected


@pytest.mark.parametrize("raw", ["-1", "1.5", "ninety", "9 0", "1e3", str(MAX_RETENTION_DAYS + 1), "9999999"])
def test_retention_rejects_bad_values(raw):
    with pytest.raises(ValueError, match="NETCLASS_AUDIT_RETENTION_DAYS"):
        parse_retention_days(raw)
