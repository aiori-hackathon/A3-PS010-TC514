"""HTTP retrieval with explicit timeouts, a size cap and clear error mapping.

Only HTTP 200 is accepted. Every failure is raised as SourceError so callers
can never mistake a failed download for an empty or negative result.
"""
from __future__ import annotations

import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional, Protocol

import requests

from .errors import SourceError, SourceErrorKind

USER_AGENT = "viltrumites-ps010/0.4 (AIORI-3 PS-010 research prototype)"
_KEPT_HEADERS = ("etag", "last-modified", "content-type", "content-length", "date")

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class FetchResult:
    url: str
    status_code: int
    body: bytes = field(repr=False)
    headers: Mapping[str, str]  # lower-cased subset of response headers
    retrieved_at: datetime  # UTC time the download completed


class Fetcher(Protocol):
    def fetch(self, url: str) -> FetchResult:  # pragma: no cover - protocol
        ...


class RequestsFetcher:
    """Downloads a URL with the `requests` library.

    timeout_seconds applies to connecting and to each socket read. Because a
    slow trickle could still run forever, total_deadline_seconds also caps the
    whole download (default: 6x the timeout).
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        max_bytes: int = 20_000_000,
        total_deadline_seconds: Optional[float] = None,
        session: Optional[requests.Session] = None,
        user_agent: str = USER_AGENT,
        extra_headers: Optional[Mapping[str, str]] = None,
        clock: Clock = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if timeout_seconds <= 0 or max_bytes <= 0:
            raise ValueError("timeout_seconds and max_bytes must be positive")
        self._timeout = timeout_seconds
        self._max_bytes = max_bytes
        self._deadline = total_deadline_seconds or timeout_seconds * 6
        self._session = session or requests.Session()
        self._user_agent = user_agent
        # Sent on every request, after the defaults (so "Accept" can be overridden).
        # Used for credentials: a token in a header never appears in the URL, so it
        # cannot leak through error messages, logs or provenance records.
        self._extra_headers = dict(extra_headers or {})
        self._clock = clock
        self._monotonic = monotonic

    def fetch(self, url: str) -> FetchResult:
        started = self._monotonic()
        try:
            response = self._session.get(
                url,
                headers={
                    "User-Agent": self._user_agent,
                    "Accept": "text/plain, */*",
                    **self._extra_headers,
                },
                timeout=(self._timeout, self._timeout),
                stream=True,
                allow_redirects=True,
            )
        except requests.exceptions.Timeout as exc:
            raise SourceError(
                SourceErrorKind.TIMEOUT,
                f"no response within {self._timeout:g}s ({type(exc).__name__})",
                url=url,
            ) from exc
        except requests.exceptions.SSLError as exc:
            raise SourceError(
                SourceErrorKind.CONNECTION, f"TLS/certificate error: {exc}", url=url
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise SourceError(
                SourceErrorKind.CONNECTION, f"request failed ({type(exc).__name__}): {exc}", url=url
            ) from exc

        with closing(response):
            if response.status_code != 200:
                raise SourceError(
                    SourceErrorKind.HTTP_STATUS,
                    f"HTTP {response.status_code} (expected 200)",
                    url=url,
                    status_code=response.status_code,
                )
            if not str(response.url).lower().startswith("https://"):
                raise SourceError(
                    SourceErrorKind.CONNECTION,
                    f"redirected to a non-HTTPS URL ({response.url}); refusing it",
                    url=url,
                )
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > self._max_bytes:
                raise SourceError(
                    SourceErrorKind.TOO_LARGE,
                    f"declared size {declared} bytes exceeds limit {self._max_bytes}",
                    url=url,
                )

            chunks: list[bytes] = []
            total = 0
            try:
                for chunk in response.iter_content(chunk_size=65536):
                    if self._monotonic() - started > self._deadline:
                        raise SourceError(
                            SourceErrorKind.TIMEOUT,
                            f"download exceeded the {self._deadline:g}s overall deadline",
                            url=url,
                        )
                    total += len(chunk)
                    if total > self._max_bytes:
                        raise SourceError(
                            SourceErrorKind.TOO_LARGE,
                            f"body exceeds limit of {self._max_bytes} bytes",
                            url=url,
                        )
                    chunks.append(chunk)
            except requests.exceptions.Timeout as exc:
                raise SourceError(
                    SourceErrorKind.TIMEOUT, f"read timed out ({type(exc).__name__})", url=url
                ) from exc
            except requests.exceptions.RequestException as exc:
                raise SourceError(
                    SourceErrorKind.CONNECTION,
                    f"download interrupted ({type(exc).__name__}): {exc}",
                    url=url,
                ) from exc

            headers = {
                name: response.headers[name] for name in _KEPT_HEADERS if name in response.headers
            }
            return FetchResult(
                url=url,
                status_code=response.status_code,
                body=b"".join(chunks),
                headers=headers,
                retrieved_at=self._clock(),
            )
