"""HTTP retrieval with explicit timeouts, a size cap and clear error mapping.

Only HTTP 200 is accepted. Every failure is raised as SourceError so callers
can never mistake a failed download for an empty or negative result.

Behaviour beyond a plain GET:

* bounded retries (``max_retries``, at most 2) for timeouts, connection errors,
  HTTP 429 and HTTP 5xx only, honouring ``Retry-After`` inside the overall deadline;
* every redirect hop is followed manually and must be HTTPS; credentials in
  ``extra_headers`` are never sent to a different origin;
* a body whose length differs from the declared Content-Length is an incomplete
  download (an error), never a short "successful" list;
* an optional hard cap on the total number of HTTP requests (``max_total_requests``);
* secrets and URL query strings are redacted from every error message.
"""
from __future__ import annotations

import time
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Callable, Mapping, Optional, Protocol
from urllib.parse import urljoin, urlsplit

import requests

from .errors import SourceError, SourceErrorKind
from .redaction import redact_text, redact_url

USER_AGENT = "viltrumites-ps010/0.7 (AIORI-3 PS-010 research prototype)"
_KEPT_HEADERS = ("etag", "last-modified", "content-type", "content-length", "date")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_RETRIES_LIMIT = 2  # upper bound on retries after the first attempt

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
    attempts: int = 1  # HTTP attempts used (1 = no retry was needed)


class Fetcher(Protocol):
    def fetch(self, url: str) -> FetchResult:  # pragma: no cover - protocol
        ...


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, (parts.hostname or "").lower(), port


def parse_retry_after(value: Optional[str], now: datetime) -> Optional[float]:
    """Seconds from a Retry-After header (delta-seconds or HTTP-date); None if unusable."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(int(value))
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - now).total_seconds())


class RequestsFetcher:
    """Downloads a URL with the `requests` library.

    timeout_seconds applies to connecting and to each socket read. Because a
    slow trickle could still run forever, total_deadline_seconds also caps the
    whole download, retries and redirects included (default: 6x the timeout).
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
        max_retries: int = 0,
        retry_backoff_seconds: float = 0.5,
        max_retry_after_seconds: float = 30.0,
        max_redirects: int = 5,
        max_total_requests: Optional[int] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if timeout_seconds <= 0 or max_bytes <= 0:
            raise ValueError("timeout_seconds and max_bytes must be positive")
        if not 0 <= max_retries <= MAX_RETRIES_LIMIT:
            raise ValueError(f"max_retries must be between 0 and {MAX_RETRIES_LIMIT}")
        if retry_backoff_seconds < 0 or max_retry_after_seconds < 0 or max_redirects < 0:
            raise ValueError("backoff, Retry-After cap and redirect limit cannot be negative")
        if max_total_requests is not None and max_total_requests < 1:
            raise ValueError("max_total_requests must be at least 1")
        self._timeout = timeout_seconds
        self._max_bytes = max_bytes
        self._deadline = total_deadline_seconds or timeout_seconds * 6
        self._session = session or requests.Session()
        self._user_agent = user_agent
        # Sent only to the original origin (after the defaults, so "Accept" can be overridden).
        # Intended for credentials: a token stays out of the URL and is never forwarded to
        # another host by a redirect.
        self._extra_headers = dict(extra_headers or {})
        self._clock = clock
        self._monotonic = monotonic
        self._max_retries = max_retries
        self._backoff = retry_backoff_seconds
        self._max_retry_after = max_retry_after_seconds
        self._max_redirects = max_redirects
        self._max_total_requests = max_total_requests
        self._sleep = sleep
        self.requests_made = 0  # HTTP requests issued so far (every attempt and redirect hop)

    def fetch(self, url: str) -> FetchResult:
        started = self._monotonic()
        attempt = 0
        while True:
            attempt += 1
            try:
                result = self._attempt(url, started)
                return FetchResult(
                    url=result.url,
                    status_code=result.status_code,
                    body=result.body,
                    headers=result.headers,
                    retrieved_at=result.retrieved_at,
                    attempts=attempt,
                )
            except SourceError as err:
                delay = self._retry_delay(err, attempt, started)
                if delay is None:
                    raise (err.with_context(f"gave up after {attempt} attempts") if attempt > 1 else err)
                if delay > 0:
                    self._sleep(delay)

    def _retry_delay(self, err: SourceError, attempt: int, started: float) -> Optional[float]:
        """Seconds to wait before the next attempt, or None when we must not retry."""
        if not err.retryable or attempt > self._max_retries:
            return None
        delay = self._backoff * (2 ** (attempt - 1))
        if err.retry_after is not None:
            if err.retry_after > self._max_retry_after:
                return None  # the server asks for more patience than we allow
            delay = max(delay, err.retry_after)
        if (self._monotonic() - started) + delay >= self._deadline:
            return None  # waiting would blow the overall deadline
        return delay

    def _headers_for(self, hop_url: str, first_url: str) -> dict[str, str]:
        headers = {"User-Agent": self._user_agent, "Accept": "text/plain, */*"}
        if _origin(hop_url) == _origin(first_url):
            headers.update(self._extra_headers)
        return headers

    def _get(self, hop_url: str, first_url: str) -> requests.Response:
        if self._max_total_requests is not None and self.requests_made >= self._max_total_requests:
            raise SourceError(
                SourceErrorKind.CONNECTION,
                f"request budget of {self._max_total_requests} exhausted; not contacting the source",
                url=redact_url(first_url),
            )
        self.requests_made += 1
        return self._session.get(
            hop_url,
            headers=self._headers_for(hop_url, first_url),
            timeout=(self._timeout, self._timeout),
            stream=True,
            allow_redirects=False,
        )

    def _attempt(self, url: str, started: float) -> FetchResult:
        shown = redact_url(url)
        hop_url = url
        hops = 0
        while True:
            try:
                response = self._get(hop_url, url)
            except SourceError:
                raise
            except requests.exceptions.Timeout as exc:
                raise SourceError(
                    SourceErrorKind.TIMEOUT,
                    f"no response within {self._timeout:g}s ({type(exc).__name__})",
                    url=shown,
                    retryable=True,
                ) from exc
            except requests.exceptions.SSLError as exc:
                # A certificate failure will not resolve itself on retry.
                raise SourceError(
                    SourceErrorKind.CONNECTION,
                    f"TLS/certificate error: {redact_text(str(exc))}",
                    url=shown,
                ) from exc
            except requests.exceptions.RequestException as exc:
                raise SourceError(
                    SourceErrorKind.CONNECTION,
                    f"request failed ({type(exc).__name__}): {redact_text(str(exc))}",
                    url=shown,
                    retryable=True,
                ) from exc

            with closing(response):
                if response.status_code in _REDIRECT_STATUSES:
                    hops += 1
                    location = response.headers.get("Location")
                    if hops > self._max_redirects or not location:
                        raise SourceError(
                            SourceErrorKind.CONNECTION,
                            "too many redirects" if location else "redirect without a Location",
                            url=shown,
                        )
                    target = urljoin(hop_url, location)
                    if not target.lower().startswith("https://"):
                        raise SourceError(
                            SourceErrorKind.CONNECTION,
                            f"redirected to a non-HTTPS URL ({redact_url(target)}); refusing it",
                            url=shown,
                        )
                    hop_url = target
                    continue
                return self._read(response, url, shown, started)

    def _read(
        self, response: requests.Response, url: str, shown: str, started: float
    ) -> FetchResult:
        status = response.status_code
        if status != 200:
            raise SourceError(
                SourceErrorKind.HTTP_STATUS,
                f"HTTP {status} (expected 200)",
                url=shown,
                status_code=status,
                retryable=(status == 429 or 500 <= status <= 599),
                retry_after=parse_retry_after(response.headers.get("Retry-After"), self._clock()),
            )
        if not str(response.url).lower().startswith("https://"):
            raise SourceError(
                SourceErrorKind.CONNECTION,
                f"redirected to a non-HTTPS URL ({redact_url(str(response.url))}); refusing it",
                url=shown,
            )
        declared = response.headers.get("Content-Length")
        declared_size = int(declared) if declared and declared.isdigit() else None
        if declared_size is not None and declared_size > self._max_bytes:
            raise SourceError(
                SourceErrorKind.TOO_LARGE,
                f"declared size {declared} bytes exceeds limit {self._max_bytes}",
                url=shown,
            )

        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=65536):
                if self._monotonic() - started > self._deadline:
                    raise SourceError(
                        SourceErrorKind.TIMEOUT,
                        f"download exceeded the {self._deadline:g}s overall deadline",
                        url=shown,
                    )
                total += len(chunk)
                if total > self._max_bytes:
                    raise SourceError(
                        SourceErrorKind.TOO_LARGE,
                        f"body exceeds limit of {self._max_bytes} bytes",
                        url=shown,
                    )
                chunks.append(chunk)
        except requests.exceptions.Timeout as exc:
            raise SourceError(
                SourceErrorKind.TIMEOUT,
                f"read timed out ({type(exc).__name__})",
                url=shown,
                retryable=True,
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise SourceError(
                SourceErrorKind.CONNECTION,
                f"download interrupted ({type(exc).__name__}): {redact_text(str(exc))}",
                url=shown,
                retryable=True,
            ) from exc

        # Content-Length counts the bytes on the wire, so it only equals the decoded body
        # size when no Content-Encoding (gzip, ...) was applied.
        if (
            declared_size is not None
            and not response.headers.get("Content-Encoding")
            and total != declared_size
        ):
            raise SourceError(
                SourceErrorKind.CONNECTION,
                f"incomplete download: received {total} of {declared_size} declared bytes",
                url=shown,
                retryable=True,
            )

        headers = {
            name: response.headers[name] for name in _KEPT_HEADERS if name in response.headers
        }
        return FetchResult(
            url=url,
            status_code=status,
            body=b"".join(chunks),
            headers=headers,
            retrieved_at=self._clock(),
        )
