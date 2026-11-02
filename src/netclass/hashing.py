"""SHA-256 helpers for evidence snapshot integrity."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Iterable

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of `data`."""
    return hashlib.sha256(data).hexdigest()


def verify_sha256(data: bytes, expected_hex: str) -> bool:
    """True only if `expected_hex` is a well-formed digest matching `data`."""
    if not isinstance(expected_hex, str):
        return False
    expected = expected_hex.strip().lower()
    if not _SHA256_RE.match(expected):
        return False
    return hmac.compare_digest(sha256_hex(data), expected)


def canonical_json_bytes(obj: Any) -> bytes:
    """Stable JSON encoding (sorted keys, no whitespace) so equal data hashes equally."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def manifest_sha256(items: Iterable[tuple[str, str]]) -> str:
    """Hash of a set of (url, sha256) pairs, independent of the order given.

    Used as the single `snapshot_sha256` of a source made of several files.
    The per-file hashes are kept separately in the evidence metadata.
    """
    pairs = sorted([url, digest] for url, digest in items)
    return sha256_hex(canonical_json_bytes(pairs))
