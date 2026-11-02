"""Parsing of the audit settings (pure; no database access, no pydantic).

NETCLASS_AUDIT_ENABLED         off unless explicitly set to a true value
NETCLASS_AUDIT_RETENTION_DAYS  default 90; 0 = keep records indefinitely (must be set explicitly)

Retention is applied ONLY when the operator runs ``scripts/audit_history.py purge``.
Nothing in this package purges automatically, on start-up or when a database is opened.
"""
from __future__ import annotations

import re
from typing import Optional

DEFAULT_RETENTION_DAYS = 90
MAX_RETENTION_DAYS = 36_500  # 100 years: a typo guard, not a policy

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_DIGITS = re.compile(r"^[0-9]{1,6}$")


def parse_enabled(raw: Optional[str], key: str = "NETCLASS_AUDIT_ENABLED") -> bool:
    """Blank or missing means disabled. Anything that is not clearly true/false is an error."""
    if raw is None or raw.strip() == "":
        return False
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(f"{key} must be one of true/false/yes/no/on/off/1/0, got {raw!r}")


def parse_retention_days(raw: Optional[str], key: str = "NETCLASS_AUDIT_RETENTION_DAYS") -> int:
    """Blank or missing means the 90-day default. 0 means keep indefinitely."""
    if raw is None or raw.strip() == "":
        return DEFAULT_RETENTION_DAYS
    text = raw.strip()
    if not _DIGITS.match(text):
        raise ValueError(f"{key} must be a whole number of days (0 = keep indefinitely), got {raw!r}")
    days = int(text)
    if days > MAX_RETENTION_DAYS:
        raise ValueError(f"{key} must not exceed {MAX_RETENTION_DAYS} days, got {raw!r}")
    return days
