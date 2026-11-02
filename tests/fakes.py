"""Fakes for network-free tests: a fake Fetcher and a stub requests transport."""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional, Union

import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

from netclass.errors import SourceError, SourceErrorKind
from netclass.http_client import FetchResult


class MutableClock:
    """A controllable UTC clock."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        self.now += timedelta(**kwargs)


Route = Union[bytes, tuple, Exception, Callable[[], object]]


class FakeFetcher:
    """Serves canned responses by URL and records every request made."""

    def __init__(self, routes: dict[str, Route], clock: Callable[[], datetime]) -> None:
        self.routes = dict(routes)
        self.clock = clock
        self.requested: list[str] = []

    def fetch(self, url: str) -> FetchResult:
        self.requested.append(url)
        route = self.routes.get(url)
        if route is None:
            raise SourceError(
                SourceErrorKind.HTTP_STATUS, "HTTP 404 (expected 200)", url=url, status_code=404
            )
        if callable(route) and not isinstance(route, (bytes, tuple, Exception)):
            route = route()
        if isinstance(route, Exception):
            raise route
        body, headers = route if isinstance(route, tuple) else (route, {})
        return FetchResult(
            url=url,
            status_code=200,
            body=body,
            headers={k.lower(): v for k, v in headers.items()},
            retrieved_at=self.clock(),
        )

    def count(self, url: str) -> int:
        return self.requested.count(url)


def ip_body(ips, header: str = "# fixture list\n", eol: str = "\n") -> bytes:
    return (header + eol.join(ips) + eol).encode("utf-8")


def cidr_body(cidrs, eol: str = "\n") -> bytes:
    return (eol.join(cidrs) + eol).encode("utf-8")


# ---------------------------------------------------------------------------
# requests-level stub (exercises RequestsFetcher itself, no sockets)
# ---------------------------------------------------------------------------
class _ExplodingRaw(io.BytesIO):
    def __init__(self, error: Exception) -> None:
        super().__init__(b"")
        self._error = error

    def read(self, *args, **kwargs):
        raise self._error


@dataclass
class StubResponse:
    status: int = 200
    body: bytes = b""
    headers: dict = field(default_factory=dict)
    final_url: Optional[str] = None
    read_error: Optional[Exception] = None


class StubTransport(HTTPAdapter):
    """Answers requests from a dict of URL -> StubResponse | Exception."""

    def __init__(self, routes: dict[str, Union[StubResponse, Exception]]) -> None:
        super().__init__()
        self.routes = routes
        self.calls: list[dict] = []

    def send(self, request, **kwargs):
        self.calls.append(
            {"url": request.url, "headers": dict(request.headers), "timeout": kwargs.get("timeout")}
        )
        route = self.routes[request.url]
        if isinstance(route, Exception):
            raise route
        response = requests.Response()
        response.status_code = route.status
        response.url = route.final_url or request.url
        response.headers = CaseInsensitiveDict(route.headers)
        response.raw = _ExplodingRaw(route.read_error) if route.read_error else io.BytesIO(route.body)
        response.request = request
        response.reason = "STUB"
        return response


class StepClock:
    """monotonic() replacement that returns the given values in order, then repeats the last."""

    def __init__(self, *values: float) -> None:
        self._values = list(values)

    def __call__(self) -> float:
        return self._values.pop(0) if len(self._values) > 1 else self._values[0]
