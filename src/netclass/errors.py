"""Error type shared by every layer that touches an external source.

A SourceError always means "evidence could not be established". Adapters turn
it into an EvidenceRecord with status SOURCE_UNAVAILABLE, never into a negative
(NO_MATCH) result.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Optional


class SourceErrorKind(StrEnum):
    TIMEOUT = "TIMEOUT"  # connect/read timeout or overall download deadline
    CONNECTION = "CONNECTION"  # DNS, TLS, refused, interrupted, bad redirect
    HTTP_STATUS = "HTTP_STATUS"  # any HTTP status other than 200
    TOO_LARGE = "TOO_LARGE"  # body exceeds the configured download cap
    MALFORMED = "MALFORMED"  # content is not the documented format
    EMPTY = "EMPTY"  # parsed fine but contains no entries
    TOO_SMALL = "TOO_SMALL"  # fewer entries than the sanity floor (possible truncation)
    STALE_SOURCE = "STALE_SOURCE"  # source's own timestamp says the data is too old
    INTERNAL = "INTERNAL"  # unexpected error inside this program


class SourceError(Exception):
    def __init__(
        self,
        kind: SourceErrorKind,
        message: str,
        *,
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        retryable: bool = False,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(f"{kind.value}: {message}")
        self.kind = kind
        self.message = message
        self.url = url
        self.status_code = status_code
        # Set only by the HTTP client, which alone decides what is worth retrying.
        self.retryable = retryable
        self.retry_after = retry_after

    def with_context(self, extra: str) -> "SourceError":
        """Same error with extra explanation appended (e.g. about a stale cache)."""
        return SourceError(
            self.kind,
            f"{self.message}; {extra}",
            url=self.url,
            status_code=self.status_code,
            retryable=self.retryable,
            retry_after=self.retry_after,
        )
