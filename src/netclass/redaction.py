"""Redaction of secrets and sensitive request details for logs and reports.

Pure functions, no I/O. Everything that is written to a log, an error message or a
live-verification report goes through here, so a token, a URL credential or a query
string cannot leak by accident. Redaction is deliberately over-eager: it is better to
hide a harmless value than to print a secret.
"""
from __future__ import annotations

import re
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit

REDACTED = "<redacted>"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
    }
)

_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{6,}")
_KEY_VALUE_RE = re.compile(
    r"(?i)\b(token|access[_-]?token|api[_-]?key|apikey|secret|password|passwd|authorization)"
    r"\s*([=:])\s*[^\s&;,\"']+"
)


def redact_url(url: str) -> str:
    """Drop credentials (user:pass@), the query string and the fragment from a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED
    if not parts.scheme or not parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[-1]
    query = f"{REDACTED}" if parts.query else ""
    return urlunsplit((parts.scheme, host, parts.path, query, ""))


def redact_text(text: str) -> str:
    """Remove secrets from free text (exception messages, log lines)."""
    if not text:
        return text
    out = _URL_RE.sub(lambda m: redact_url(m.group(0)), text)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", out)
    out = _KEY_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", out)
    return out


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Copy of `headers` with the value of every sensitive header replaced."""
    return {
        name: (REDACTED if name.lower() in SENSITIVE_HEADERS else value)
        for name, value in headers.items()
    }
