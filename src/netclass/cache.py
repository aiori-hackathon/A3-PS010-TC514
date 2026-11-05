"""On-disk snapshot store.

Layout under the cache directory:
    snapshots/<sha256>.bin      raw downloaded bytes, named by their own hash
    index/<source>-<urlhash>.json   pointer to the most recent snapshot of a URL

Snapshots are content-addressed, so an unchanged list is stored once and every
audit record's SHA-256 can be re-checked against the retained file. The cache
directory is safe to delete at any time. Writes are atomic (temp file then
os.replace) and all file names are plain hex/ASCII, so this works on Windows.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional

from .redaction import redact_text, redact_url
from .hashing import sha256_hex, verify_sha256

logger = logging.getLogger(__name__)
_INDEX_VERSION = 1


@dataclass(frozen=True)
class Snapshot:
    """One retained download of one URL."""

    source_name: str
    url: str
    body: bytes = field(repr=False)
    sha256: str
    retrieved_at: datetime  # UTC
    source_timestamp: Optional[datetime]  # from the server's Last-Modified, if present
    from_cache: bool
    headers: Mapping[str, str] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    @property
    def size(self) -> int:
        return len(self.body)


@dataclass(frozen=True)
class CacheLookup:
    snapshot: Optional[Snapshot]
    problem: Optional[str] = None  # why an existing entry was rejected, if it was


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:60]


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("naive datetime in cache index")
    return parsed.astimezone(timezone.utc)


class SnapshotStore:
    def __init__(self, cache_dir: Path) -> None:
        self._root = Path(cache_dir)

    def _body_path(self, digest: str) -> Path:
        return self._root / "snapshots" / f"{digest}.bin"

    def _index_path(self, source_name: str, url: str) -> Path:
        return self._root / "index" / f"{_safe(source_name)}-{sha256_hex(url.encode())[:16]}.json"

    def save(self, snapshot: Snapshot) -> None:
        body_path = self._body_path(snapshot.sha256)
        if not verify_sha256(snapshot.body, snapshot.sha256):
            raise ValueError("snapshot body does not match its SHA-256")
        if not body_path.exists():
            _atomic_write(body_path, snapshot.body)
        else:
            try:
                existing_body = body_path.read_bytes()
            except OSError:
                existing_body = None

            if existing_body is None or not verify_sha256(
                existing_body, snapshot.sha256
            ):
                _atomic_write(body_path, snapshot.body)

        # Verify the stored body before updating the cache index.
        stored_body = body_path.read_bytes()
        if not verify_sha256(stored_body, snapshot.sha256):
            raise OSError(
                "snapshot body failed SHA-256 verification after write"
            )
        index = {
            "version": _INDEX_VERSION,
            "source_name": snapshot.source_name,
            "url": snapshot.url,
            "sha256": snapshot.sha256,
            "size": snapshot.size,
            "retrieved_at": snapshot.retrieved_at.isoformat(),
            "source_timestamp": (
                snapshot.source_timestamp.isoformat() if snapshot.source_timestamp else None
            ),
            "headers": dict(snapshot.headers),
        }
        _atomic_write(
            self._index_path(snapshot.source_name, snapshot.url),
            json.dumps(index, indent=2, sort_keys=True).encode("utf-8"),
        )

    def load(self, source_name: str, url: str) -> CacheLookup:
        """Return the cached snapshot, or None plus the reason it was rejected."""
        index_path = self._index_path(source_name, url)
        if not index_path.exists():
            return CacheLookup(None)
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
            if index.get("version") != _INDEX_VERSION or index.get("url") != url:
                return CacheLookup(None, "cache index has an unexpected version or URL")
            digest = str(index["sha256"])
            body = self._body_path(digest).read_bytes()
            if not verify_sha256(body, digest):
                return CacheLookup(None, "cached snapshot failed SHA-256 verification; discarded")
            return CacheLookup(
                Snapshot(
                    source_name=source_name,
                    url=url,
                    body=body,
                    sha256=digest,
                    retrieved_at=_parse_dt(index["retrieved_at"]),  # type: ignore[arg-type]
                    source_timestamp=_parse_dt(index.get("source_timestamp")),
                    from_cache=True,
                    headers=dict(index.get("headers") or {}),
                )
            )
        except FileNotFoundError:
            return CacheLookup(None, "cache index points at a missing snapshot file")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            logger.warning(
                "Unreadable cache entry for %s: %s", redact_url(url), redact_text(str(exc))
            )
            return CacheLookup(None, f"cache entry unreadable ({type(exc).__name__})")
