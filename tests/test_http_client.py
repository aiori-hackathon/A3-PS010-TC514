import pytest
import requests

from factories import T0
from fakes import MutableClock, StepClock, StubResponse, StubTransport
from netclass.errors import SourceError, SourceErrorKind
from netclass.http_client import USER_AGENT, RequestsFetcher

URL = "https://example.invalid/list.txt"
K = SourceErrorKind


def make(routes, **kwargs):
    transport = StubTransport(routes)
    session = requests.Session()
    session.mount("https://", transport)
    session.mount("http://", transport)
    fetcher = RequestsFetcher(session=session, clock=MutableClock(T0), **kwargs)
    return fetcher, transport


def test_successful_download_returns_body_headers_and_utc_timestamp():
    fetcher, transport = make(
        {
            URL: StubResponse(
                body=b"1.2.3.4\n",
                headers={"ETag": '"abc"', "Last-Modified": "Thu, 29 Oct 2026 10:00:00 GMT", "X-Other": "x"},
            )
        },
        timeout_seconds=5,
    )
    result = fetcher.fetch(URL)
    assert result.body == b"1.2.3.4\n"
    assert result.status_code == 200
    assert result.retrieved_at == T0 and result.retrieved_at.utcoffset().total_seconds() == 0
    assert result.headers == {"etag": '"abc"', "last-modified": "Thu, 29 Oct 2026 10:00:00 GMT"}


def test_request_carries_user_agent_and_configured_timeouts():
    fetcher, transport = make({URL: StubResponse(body=b"x")}, timeout_seconds=7)
    fetcher.fetch(URL)
    call = transport.calls[0]
    assert call["headers"]["User-Agent"] == USER_AGENT
    assert call["timeout"] == (7, 7)


@pytest.mark.parametrize(
    "error", [requests.exceptions.ConnectTimeout("c"), requests.exceptions.ReadTimeout("r")]
)
def test_timeouts_are_reported_as_timeout(error):
    fetcher, _ = make({URL: error}, timeout_seconds=3)
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.TIMEOUT
    assert info.value.url == URL


def test_connection_and_tls_errors():
    fetcher, _ = make({URL: requests.exceptions.ConnectionError("refused")})
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.CONNECTION

    fetcher, _ = make({URL: requests.exceptions.SSLError("bad cert")})
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.CONNECTION and "TLS" in info.value.message


@pytest.mark.parametrize("status", [204, 403, 404, 429, 500, 503])
def test_non_200_statuses_are_errors_not_empty_results(status):
    fetcher, _ = make({URL: StubResponse(status=status, body=b"1.2.3.4\n")})
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.HTTP_STATUS
    assert info.value.status_code == status


def test_declared_size_over_limit_is_rejected_before_reading():
    fetcher, _ = make(
        {URL: StubResponse(body=b"x", headers={"Content-Length": "5000"})}, max_bytes=1000
    )
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.TOO_LARGE


def test_streamed_size_over_limit_is_rejected():
    fetcher, _ = make({URL: StubResponse(body=b"x" * 3000)}, max_bytes=1000)
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.TOO_LARGE


def test_overall_deadline_applies_even_if_each_read_is_fast():
    fetcher, _ = make(
        {URL: StubResponse(body=b"x" * 10)},
        timeout_seconds=1,
        total_deadline_seconds=5,
        monotonic=StepClock(0.0, 100.0),
    )
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.TIMEOUT and "deadline" in info.value.message


def test_errors_while_streaming_are_mapped():
    fetcher, _ = make({URL: StubResponse(read_error=requests.exceptions.ReadTimeout("slow"))})
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.TIMEOUT

    fetcher, _ = make(
        {URL: StubResponse(read_error=requests.exceptions.ChunkedEncodingError("cut"))}
    )
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.CONNECTION


def test_redirect_to_plain_http_is_refused():
    fetcher, _ = make({URL: StubResponse(body=b"1.2.3.4\n", final_url="http://evil.invalid/x")})
    with pytest.raises(SourceError) as info:
        fetcher.fetch(URL)
    assert info.value.kind is K.CONNECTION and "non-HTTPS" in info.value.message


def test_empty_200_body_is_returned_unjudged():
    # The fetcher only moves bytes; deciding that "empty" is an error is the parser's job.
    fetcher, _ = make({URL: StubResponse(body=b"")})
    assert fetcher.fetch(URL).body == b""


def test_invalid_constructor_arguments():
    with pytest.raises(ValueError):
        RequestsFetcher(timeout_seconds=0)
    with pytest.raises(ValueError):
        RequestsFetcher(max_bytes=0)


def test_the_suite_really_blocks_real_network_access():
    # Guard against the tests silently depending on the internet (see conftest.py).
    with pytest.raises(Exception):
        requests.get("https://check.torproject.org/torbulkexitlist", timeout=2)
