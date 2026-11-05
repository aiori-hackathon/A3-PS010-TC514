"""Retries, redirect handling, truncation, request budget and redaction of HTTP errors.

Everything here runs against an in-memory transport: no sockets, no sleeping.
"""
import io

import pytest
import requests
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

from factories import T0
from fakes import MutableClock, StepClock
from netclass.errors import SourceError, SourceErrorKind
from netclass.http_client import RequestsFetcher, parse_retry_after

URL = "https://example.invalid/list.txt"
K = SourceErrorKind


class Reply:
    def __init__(self, status=200, body=b"1.2.3.4\n", headers=None):
        self.status, self.body, self.headers = status, body, headers or {}


class SequenceTransport(HTTPAdapter):
    """Answers each URL from a list of replies (or exceptions), in order; the last repeats."""

    def __init__(self, routes):
        super().__init__()
        self.routes = {url: list(items) for url, items in routes.items()}
        self.calls = []

    def send(self, request, **kwargs):
        self.calls.append({"url": request.url, "headers": dict(request.headers)})
        queue = self.routes[request.url]
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        response = requests.Response()
        response.status_code = item.status
        response.url = request.url
        response.headers = CaseInsensitiveDict(item.headers)
        response.raw = io.BytesIO(item.body)
        response.request = request
        return response


def make(routes, **kwargs):
    transport = SequenceTransport(routes)
    session = requests.Session()
    session.mount("https://", transport)
    session.mount("http://", transport)
    sleeps = []
    kwargs.setdefault("sleep", sleeps.append)
    fetcher = RequestsFetcher(session=session, clock=MutableClock(T0), **kwargs)
    return fetcher, transport, sleeps


# ------------------------------------------------------------------ retries
def test_default_is_no_retry_so_existing_callers_behave_as_before():
    fetcher, transport, sleeps = make({URL: [Reply(503)]})
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.HTTP_STATUS and len(transport.calls) == 1 and sleeps == []


def test_timeout_then_success_is_retried_once():
    fetcher, transport, sleeps = make(
        {URL: [requests.exceptions.ReadTimeout("slow"), Reply()]}, max_retries=2
    )
    result = fetcher.fetch(URL)
    assert result.body == b"1.2.3.4\n" and result.attempts == 2
    assert len(transport.calls) == 2 and sleeps == [0.5]


def test_never_more_than_two_retries_after_the_first_attempt():
    fetcher, transport, sleeps = make({URL: [Reply(503)]}, max_retries=2)
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.HTTP_STATUS and info.value.status_code == 503
    assert "gave up after 3 attempts" in info.value.message
    assert len(transport.calls) == 3 and sleeps == [0.5, 1.0]


def test_retry_limit_above_two_is_rejected():
    with pytest.raises(ValueError):
        RequestsFetcher(max_retries=3)
    with pytest.raises(ValueError):
        RequestsFetcher(max_retries=-1)


@pytest.mark.parametrize("status", [429, 500, 502, 503, 599])
def test_retryable_statuses(status):
    fetcher, transport, _ = make({URL: [Reply(status), Reply()]}, max_retries=1)
    assert fetcher.fetch(URL).attempts == 2


@pytest.mark.parametrize("status", [204, 400, 401, 403, 404, 410])
def test_other_statuses_are_not_retried(status):
    fetcher, transport, sleeps = make({URL: [Reply(status), Reply()]}, max_retries=2)
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.HTTP_STATUS and len(transport.calls) == 1 and sleeps == []


def test_connection_error_is_retried_but_tls_error_is_not():
    fetcher, transport, _ = make(
        {URL: [requests.exceptions.ConnectionError("refused"), Reply()]}, max_retries=1
    )
    assert fetcher.fetch(URL).attempts == 2

    fetcher, transport, sleeps = make(
        {URL: [requests.exceptions.SSLError("bad cert"), Reply()]}, max_retries=2
    )
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert "TLS" in info.value.message and len(transport.calls) == 1 and sleeps == []


def test_too_large_is_never_retried():
    fetcher, transport, _ = make(
        {URL: [Reply(body=b"x" * 50, headers={"Content-Length": "50"}), Reply()]},
        max_bytes=10,
        max_retries=2,
    )
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.TOO_LARGE and len(transport.calls) == 1


def test_retry_after_seconds_is_honoured_when_longer_than_backoff():
    fetcher, _, sleeps = make(
        {URL: [Reply(429, headers={"Retry-After": "3"}), Reply()]}, max_retries=1
    )
    fetcher.fetch(URL)
    assert sleeps == [3.0]


def test_retry_after_beyond_the_cap_means_no_retry():
    fetcher, transport, sleeps = make(
        {URL: [Reply(503, headers={"Retry-After": "600"}), Reply()]},
        max_retries=2,
        max_retry_after_seconds=30,
    )
    with pytest.raises(SourceError):
        fetcher.fetch(URL)
    assert len(transport.calls) == 1 and sleeps == []


def test_retry_that_would_exceed_the_overall_deadline_is_not_attempted():
    fetcher, transport, sleeps = make(
        {URL: [Reply(429, headers={"Retry-After": "20"}), Reply()]},
        max_retries=2,
        timeout_seconds=1,
        total_deadline_seconds=10,
        max_retry_after_seconds=60,
    )
    with pytest.raises(SourceError):
        fetcher.fetch(URL)
    assert len(transport.calls) == 1 and sleeps == []


def test_overall_deadline_timeout_is_not_retried():
    fetcher, transport, _ = make(
        {URL: [Reply(body=b"x" * 10), Reply()]},
        timeout_seconds=1,
        total_deadline_seconds=5,
        monotonic=StepClock(0.0, 100.0),
        max_retries=2,
    )
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.TIMEOUT and len(transport.calls) == 1


def test_parse_retry_after_forms():
    assert parse_retry_after("7", T0) == 7.0
    assert parse_retry_after("Wed, 28 Oct 2026 12:00:30 GMT", T0) == 30.0
    assert parse_retry_after("Wed, 28 Oct 2026 11:00:00 GMT", T0) == 0.0  # in the past
    assert parse_retry_after("soon", T0) is None
    assert parse_retry_after(None, T0) is None


# ---------------------------------------------------------------- redirects
def test_https_redirect_to_same_origin_keeps_credentials_and_is_followed():
    final = "https://example.invalid/moved.txt"
    fetcher, transport, _ = make(
        {URL: [Reply(302, headers={"Location": "/moved.txt"})], final: [Reply()]},
        extra_headers={"Authorization": "Bearer SECRET-TOKEN-1"},
    )
    assert fetcher.fetch(URL).body == b"1.2.3.4\n"
    assert transport.calls[1]["headers"]["Authorization"] == "Bearer SECRET-TOKEN-1"


def test_cross_origin_redirect_never_forwards_credentials():
    other = "https://other.invalid/data.txt"
    fetcher, transport, _ = make(
        {URL: [Reply(301, headers={"Location": other})], other: [Reply()]},
        extra_headers={"Authorization": "Bearer SECRET-TOKEN-1"},
    )
    fetcher.fetch(URL)
    assert "Authorization" in transport.calls[0]["headers"]
    assert "Authorization" not in transport.calls[1]["headers"]
    assert transport.calls[1]["headers"]["User-Agent"]


def test_redirect_to_plain_http_is_refused_before_any_request_is_made():
    fetcher, transport, _ = make(
        {URL: [Reply(302, headers={"Location": "http://evil.invalid/x"})]}
    )
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.CONNECTION and "non-HTTPS" in info.value.message
    assert [c["url"] for c in transport.calls] == [URL]


def test_https_to_http_to_https_chain_is_still_refused():
    fetcher, transport, _ = make(
        {URL: [Reply(302, headers={"Location": "http://hop.invalid/x"})]}
    )
    with pytest.raises(SourceError):
        fetcher.fetch(URL)
    assert len(transport.calls) == 1


def test_redirect_loop_is_cut_off():
    fetcher, transport, _ = make({URL: [Reply(302, headers={"Location": URL})]}, max_redirects=3)
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.CONNECTION and "too many redirects" in info.value.message
    assert len(transport.calls) == 4  # the original request plus 3 followed hops


def test_redirect_without_location_is_an_error():
    fetcher, _, _ = make({URL: [Reply(302)]})
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.CONNECTION and "Location" in info.value.message


# --------------------------------------------------------------- truncation
def test_body_shorter_than_declared_is_an_incomplete_download_not_a_short_list():
    fetcher, _, _ = make({URL: [Reply(body=b"1.2.3.4\n", headers={"Content-Length": "100"})]})
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.CONNECTION
    assert "incomplete download" in info.value.message and "8 of 100" in info.value.message


def test_truncated_download_is_retried_and_can_recover():
    good = Reply(body=b"1.2.3.4\n", headers={"Content-Length": "8"})
    bad = Reply(body=b"1.2.", headers={"Content-Length": "8"})
    fetcher, _, _ = make({URL: [bad, good]}, max_retries=1)
    result = fetcher.fetch(URL)
    assert result.body == b"1.2.3.4\n" and result.attempts == 2


def test_content_length_is_not_compared_when_the_body_was_content_encoded():
    reply = Reply(body=b"decoded body", headers={"Content-Length": "5", "Content-Encoding": "gzip"})
    fetcher, _, _ = make({URL: [reply]})
    assert fetcher.fetch(URL).body == b"decoded body"


def test_matching_content_length_is_accepted():
    fetcher, _, _ = make({URL: [Reply(body=b"abc\n", headers={"Content-Length": "4"})]})
    assert fetcher.fetch(URL).body == b"abc\n"


# ------------------------------------------------------------------- budget
def test_request_budget_is_a_hard_cap_across_fetches():
    fetcher, transport, _ = make({URL: [Reply()]}, max_total_requests=2)
    fetcher.fetch(URL)
    fetcher.fetch(URL)
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert "budget" in info.value.message and len(transport.calls) == 2
    assert fetcher.requests_made == 2


def test_budget_counts_retries_and_redirect_hops():
    fetcher, transport, _ = make({URL: [Reply(503)]}, max_retries=2, max_total_requests=2)
    with pytest.raises(SourceError):
        fetcher.fetch(URL)
    assert len(transport.calls) == 2  # the third attempt was blocked by the budget


def test_invalid_budget():
    with pytest.raises(ValueError):
        RequestsFetcher(max_total_requests=0)


# ---------------------------------------------------------------- redaction
def test_error_messages_and_urls_never_contain_secrets():
    secret_url = "https://user:hunter2@example.invalid/list.txt?token=SECRETVALUE"
    exc = requests.exceptions.ConnectionError(f"failed to reach {secret_url} api_key=SECRETVALUE")
    fetcher, _, _ = make({secret_url: [exc]})
    with pytest.raises(SourceError) as info:
        fetcher.fetch(secret_url)
    text = f"{info.value} {info.value.url} {info.value.message}"
    assert "SECRETVALUE" not in text and "hunter2" not in text
    assert info.value.url == "https://example.invalid/list.txt?<redacted>"
