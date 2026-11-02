"""What may be written to the audit database (pure; no database access, no pydantic).

NEVER STORED
    * API tokens, passwords, authorization headers, cookies: values under such keys are
      replaced, and token-shaped text is redacted wherever it occurs in a string.
    * The exact secret values the application is configured with (``secrets``).
    * Raw HTTP response bodies: values under body-like keys are dropped. The models
      already carry only parsed fields and SHA-256 digests; this is a second line of defence.

Every change is counted so the audit row can say how many values were redacted. Nothing is
changed silently: a redacted value is replaced by a visible marker.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

REDACTED = "[REDACTED]"
OMITTED_BODY = "[OMITTED: raw response bodies are never stored]"
OMITTED_DEPTH = "[OMITTED: nested too deeply]"
TRUNCATED = "...[truncated]"
MAX_TEXT_LENGTH = 4096
MAX_DEPTH = 24
MIN_SECRET_LENGTH = 4  # shorter exact values would mangle ordinary text; patterns still apply

_SECRET_KEYS = frozenset(
    {
        "authorization", "proxy-authorization", "token", "access_token", "refresh_token",
        "api_key", "apikey", "api-key", "x-api-key", "password", "passwd", "secret",
        "client_secret", "cookie", "set-cookie",
    }
)
_BODY_KEYS = frozenset(
    {"body", "raw_body", "response_body", "raw_response", "response_text", "raw_content"}
)

_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*[:=]\s*)[^\r\n'\"]+"), r"\1" + REDACTED),
    (re.compile(r"(?i)(bearer\s+)[^\s'\"]+"), r"\1" + REDACTED),
    (re.compile(r"(?i)(token=)[^&\s'\"]+"), r"\1" + REDACTED),
    (
        re.compile(r"(?i)((?:api[_-]?key|access[_-]?token)\s*[=:]\s*)[^\s&'\"]+"),
        r"\1" + REDACTED,
    ),
)


def _exact_secrets(secrets: Iterable[Optional[str]]) -> tuple[str, ...]:
    found = {s for s in secrets if isinstance(s, str) and len(s) >= MIN_SECRET_LENGTH}
    return tuple(sorted(found, key=len, reverse=True))  # longest first


def redact_text(text: str, secrets: Iterable[Optional[str]] = ()) -> tuple[str, int]:
    """Return (clean text, number of redactions)."""
    count = 0
    for secret in _exact_secrets(secrets):
        if secret in text:
            count += text.count(secret)
            text = text.replace(secret, REDACTED)
    for pattern, replacement in _PATTERNS:
        text, n = pattern.subn(replacement, text)
        count += n
    return text, count


def scrub(value: Any, secrets: Iterable[Optional[str]] = ()) -> tuple[Any, int]:
    """Return (a cleaned deep copy of a JSON-like value, number of changes). Input is not modified."""
    exact = _exact_secrets(secrets)
    changes = 0

    def walk(item: Any, depth: int) -> Any:
        nonlocal changes
        if depth > MAX_DEPTH:
            changes += 1
            return OMITTED_DEPTH
        if isinstance(item, dict):
            clean: dict[str, Any] = {}
            for key, inner in item.items():
                name = str(key)
                lowered = name.lower()
                if lowered in _SECRET_KEYS and inner not in (None, ""):
                    changes += 1
                    clean[name] = REDACTED
                elif lowered in _BODY_KEYS and inner not in (None, ""):
                    changes += 1
                    clean[name] = OMITTED_BODY
                else:
                    clean[name] = walk(inner, depth + 1)
            return clean
        if isinstance(item, (list, tuple)):
            return [walk(inner, depth + 1) for inner in item]
        if isinstance(item, str):
            text, n = redact_text(item, exact)
            changes += n
            if len(text) > MAX_TEXT_LENGTH:
                text = text[:MAX_TEXT_LENGTH] + TRUNCATED
                changes += 1
            return text
        return item

    return walk(value, 0), changes


def safe_error_message(exc: BaseException, secrets: Iterable[Optional[str]] = (), limit: int = 300) -> str:
    """A short, redacted description of an error: type name plus clipped message."""
    text, _ = redact_text(str(exc), secrets)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit] + TRUNCATED
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__
