"""Offline replay of fixture "worlds": a Fetcher that never touches the network.

``routes_for_world`` turns the description of a world (see dataset.py) into canned responses
for the exact endpoints the real adapters request. ``ReplayFetcher`` serves them and records
every URL requested, so a test (and the evaluation report) can prove how many evidence
fetches a case triggered. A URL the world does not define answers HTTP 404, like a missing file.

Everything here is fixture data. None of it is a claim about a real Tor exit or VPN endpoint.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import format_datetime
from typing import Callable, Mapping, Optional, Union

from ..errors import SourceError, SourceErrorKind
from ..http_client import FetchResult
from ..sources import AZ0_VPN_SOURCE, TOR_SOURCE, X4BNET_VPN_SOURCE

_MALFORMED_BODY = b"<html><body>Service temporarily unavailable</body></html>\n"
_EMPTY_BODY = b"# header only: no entries\n"


@dataclass(frozen=True)
class ReplayFailure:
    """A request that fails the way a real download can."""

    kind: SourceErrorKind
    message: str
    status_code: Optional[int] = None


Route = Union[bytes, tuple, ReplayFailure]


class ReplayFetcher:
    def __init__(self, routes: Mapping[str, Route], clock: Callable[[], datetime]) -> None:
        self.routes = dict(routes)
        self._clock = clock
        self.requested: list[str] = []

    @property
    def request_count(self) -> int:
        return len(self.requested)

    def fetch(self, url: str) -> FetchResult:
        self.requested.append(url)
        route = self.routes.get(url)
        if route is None:
            raise SourceError(
                SourceErrorKind.HTTP_STATUS, "HTTP 404 (expected 200)", url=url, status_code=404
            )
        if isinstance(route, ReplayFailure):
            raise SourceError(route.kind, route.message, url=url, status_code=route.status_code)
        body, headers = route if isinstance(route, tuple) else (route, {})
        return FetchResult(
            url=url,
            status_code=200,
            body=body,
            headers={k.lower(): v for k, v in headers.items()},
            retrieved_at=self._clock(),
        )


class CountingFetcher:
    """Wraps any Fetcher and counts requests (used for live runs and for tests)."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.requested: list[str] = []

    @property
    def request_count(self) -> int:
        return len(self.requested)

    def fetch(self, url: str) -> FetchResult:
        self.requested.append(url)
        return self._inner.fetch(url)


def _lines(items: list[str]) -> bytes:
    return ("# fixture list (synthetic; not real data)\n" + "\n".join(items) + "\n").encode("utf-8")


def _failure(state: str) -> Optional[Route]:
    """The route for a non-ok state (None for 'ok')."""
    if state == "http_error":
        return ReplayFailure(SourceErrorKind.HTTP_STATUS, "HTTP 503 (expected 200)", 503)
    if state == "timeout":
        return ReplayFailure(SourceErrorKind.TIMEOUT, "simulated read timeout")
    if state == "malformed":
        return _MALFORMED_BODY
    if state == "empty":
        return _EMPTY_BODY
    return None


def routes_for_world(world: Mapping) -> dict[str, Route]:
    """Canned responses for every endpoint of every source the world enables."""
    routes: dict[str, Route] = {}

    tor = world.get("tor")
    if tor is not None:
        failure = _failure(tor["state"])
        body: Route = failure if failure is not None else _lines(tor["entries"])
        if tor.get("last_modified") and isinstance(body, bytes):
            stamp = datetime.fromisoformat(tor["last_modified"]).astimezone(timezone.utc)
            body = (body, {"Last-Modified": format_datetime(stamp, usegmt=True)})
        routes[TOR_SOURCE.endpoints[0]] = body

    x4 = world.get("x4bnet")
    if x4 is not None:
        v4_url, v6_url = X4BNET_VPN_SOURCE.endpoints
        apple_url = X4BNET_VPN_SOURCE.auxiliary_endpoints[0]
        failure = _failure(x4["state"])
        routes[v4_url] = failure if failure is not None else _lines(x4["ipv4"])
        routes[v6_url] = failure if failure is not None else _lines(x4["ipv6"])
        apple_failure = _failure(x4["apple_state"])
        routes[apple_url] = apple_failure if apple_failure is not None else _lines(x4["apple"])

    az0 = world.get("az0")
    if az0 is not None:
        failure = _failure(az0["state"])
        for url in AZ0_VPN_SOURCE.endpoints:
            name = url.rsplit("/", 1)[-1]
            routes[url] = failure if failure is not None else _lines(az0["files"][name])
    return routes
