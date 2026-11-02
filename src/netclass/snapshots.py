"""Cache-first retrieval of a source file, with freshness and validation rules.

Rules (all enforced here so every adapter behaves identically):
  * A cached snapshot is used only while younger than the TTL.
  * An older snapshot is NEVER used as evidence, even if the refresh fails; the
    failure is reported as an error that mentions the stale copy.
  * Downloaded bytes are parsed BEFORE they are cached; malformed or empty
    content is never stored and never read as "no match".
  * If the server reports a Last-Modified time older than the configured limit,
    the data is rejected as STALE_SOURCE.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Generic, Optional, TypeVar

from .cache import Snapshot, SnapshotStore
from .errors import SourceError, SourceErrorKind
from .hashing import sha256_hex
from .http_client import Clock, Fetcher, utc_now

logger = logging.getLogger(__name__)
T = TypeVar("T")


@dataclass(frozen=True)
class LoadedSnapshot(Generic[T]):
    snapshot: Snapshot
    parsed: T


def parse_http_date(value: Optional[str]) -> Optional[datetime]:
    """Parse an HTTP date header into an aware UTC datetime; None if absent/invalid."""
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class SnapshotProvider:
    def __init__(
        self,
        fetcher: Fetcher,
        store: Optional[SnapshotStore] = None,
        *,
        ttl_seconds: int,
        clock: Clock = utc_now,
        max_source_age_seconds: Optional[int] = None,
    ) -> None:
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must not be negative")
        self._fetcher = fetcher
        self._store = store
        self._ttl = ttl_seconds
        self._clock = clock
        self._max_source_age = max_source_age_seconds
        self._memo: dict[tuple[str, str], tuple[str, Any]] = {}  # (source, url) -> (sha, parsed)

    # ------------------------------------------------------------------
    def _parse(
        self, source_name: str, url: str, digest: str, body: bytes, parser: Callable[[bytes], T]
    ) -> T:
        memo = self._memo.get((source_name, url))
        if memo is not None and memo[0] == digest:
            return memo[1]
        try:
            parsed = parser(body)
        except SourceError as exc:
            if exc.url is None:
                exc.url = url
            raise
        self._memo[(source_name, url)] = (digest, parsed)
        return parsed

    def _check_source_age(self, snapshot: Snapshot, now: datetime) -> None:
        if self._max_source_age is None or snapshot.source_timestamp is None:
            return
        age = (now - snapshot.source_timestamp).total_seconds()
        if age > self._max_source_age:
            raise SourceError(
                SourceErrorKind.STALE_SOURCE,
                f"source reports Last-Modified {snapshot.source_timestamp.isoformat()} "
                f"({int(age)}s ago), older than the {self._max_source_age}s limit",
                url=snapshot.url,
            )

    # ------------------------------------------------------------------
    def load(
        self,
        source_name: str,
        url: str,
        parser: Callable[[bytes], T],
        *,
        force_refresh: bool = False,
    ) -> LoadedSnapshot[T]:
        now = self._clock()
        notes: list[str] = []
        stale_note: Optional[str] = None

        if self._store is not None and not force_refresh:
            lookup = self._store.load(source_name, url)
            if lookup.problem:
                notes.append(f"cache: {lookup.problem}")
            cached = lookup.snapshot
            if cached is not None:
                age = (now - cached.retrieved_at).total_seconds()
                if 0 <= age <= self._ttl:
                    try:
                        parsed = self._parse(source_name, url, cached.sha256, cached.body, parser)
                        self._check_source_age(cached, now)
                        return LoadedSnapshot(replace(cached, notes=tuple(notes)), parsed)
                    except SourceError as exc:
                        notes.append(f"cached snapshot unusable ({exc.kind.value}); refetching")
                else:
                    stale_note = (
                        f"a cached snapshot retrieved {cached.retrieved_at.isoformat()} is "
                        f"{int(age)}s old (freshness limit {self._ttl}s) and was not used as evidence"
                    )

        try:
            result = self._fetcher.fetch(url)
        except SourceError as exc:
            context = "; ".join([*([stale_note] if stale_note else []), *notes])
            raise (exc.with_context(context) if context else exc) from exc

        digest = sha256_hex(result.body)
        parsed = self._parse(source_name, url, digest, result.body, parser)  # raises, uncached
        snapshot = Snapshot(
            source_name=source_name,
            url=url,
            body=result.body,
            sha256=digest,
            retrieved_at=result.retrieved_at,
            source_timestamp=parse_http_date(result.headers.get("last-modified")),
            from_cache=False,
            headers=dict(result.headers),
        )
        self._check_source_age(snapshot, now)

        if self._store is not None:
            try:
                self._store.save(snapshot)
            except OSError as exc:  # a cache write problem must not break evidence retrieval
                logger.warning("Could not write cache for %s: %s", url, exc)
                notes.append(f"cache write failed ({type(exc).__name__}); result not retained")
        return LoadedSnapshot(replace(snapshot, notes=tuple(notes)), parsed)
