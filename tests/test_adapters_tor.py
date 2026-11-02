from datetime import timedelta

from factories import T0
from fakes import ip_body
from netclass.errors import SourceError, SourceErrorKind
from netclass.hashing import sha256_hex
from netclass.models import EvidenceKind, EvidenceStatus
from netclass.adapters import TorExitListAdapter
from netclass.sources import TOR_SOURCE
from support import CLEAN_IP, TOR_IP, TOR_URL, TOR_V6, make_stack, standard_routes, tor_adapter

S = EvidenceStatus
K = SourceErrorKind


def test_match_record_carries_full_provenance(tmp_path):
    stack = make_stack(tmp_path)
    record = tor_adapter(stack).lookup(TOR_IP)
    assert record.status is S.MATCH and record.kind is EvidenceKind.TOR_EXIT
    assert record.source_name == "tor-project-bulk-exit-list"
    assert record.source_endpoint == TOR_URL
    assert record.retrieved_at == T0 and record.retrieved_at.utcoffset().total_seconds() == 0
    assert record.snapshot_sha256 == sha256_hex(stack.fetcher.routes[TOR_URL])
    assert record.valid_from is None and record.valid_to is None  # current-only snapshot
    assert record.limitations == list(TOR_SOURCE.limitations)
    assert record.metadata["matched_entry"] == TOR_IP
    assert record.metadata["list_entries"] == 2
    assert record.metadata["granularity"] == "exact-address"
    record.model_dump_json()  # must be JSON-serialisable for the audit log


def test_address_not_on_the_list_is_no_match(tmp_path):
    record = tor_adapter(make_stack(tmp_path)).lookup(CLEAN_IP)
    assert record.status is S.NO_MATCH
    assert record.metadata["list_entries"] == 2  # coverage is recorded, not implied


def test_ipv4_mapped_ipv6_query_matches_the_ipv4_entry(tmp_path):
    record = tor_adapter(make_stack(tmp_path)).lookup("::ffff:" + TOR_IP)
    assert record.status is S.MATCH


def test_ipv6_query_is_not_covered_when_the_list_has_no_ipv6(tmp_path):
    record = tor_adapter(make_stack(tmp_path)).lookup(TOR_V6)
    assert record.status is S.NOT_CONFIGURED  # absence proves nothing
    assert "IPv6 not covered" in record.error
    assert record.metadata["ipv6_entries"] == 0


def test_ipv6_query_works_when_the_list_has_ipv6(tmp_path):
    routes = standard_routes(**{})
    routes[TOR_URL] = ip_body([TOR_IP, TOR_V6])
    adapter = tor_adapter(make_stack(tmp_path, routes))
    assert adapter.lookup(TOR_V6).status is S.MATCH
    assert adapter.lookup("2001:67c:e60::2").status is S.NO_MATCH


def _unavailable(tmp_path, route, **stack_kwargs):
    routes = standard_routes()
    routes[TOR_URL] = route
    return tor_adapter(make_stack(tmp_path, routes, **stack_kwargs)).lookup(CLEAN_IP)


def test_timeout_is_unavailable_never_a_negative(tmp_path):
    record = _unavailable(tmp_path, SourceError(K.TIMEOUT, "no response within 10s", url=TOR_URL))
    assert record.status is S.SOURCE_UNAVAILABLE
    assert record.error.startswith("TIMEOUT")
    assert record.metadata["error_kind"] == "TIMEOUT"
    assert record.snapshot_sha256 is None


def test_http_errors_are_unavailable_with_the_status_code(tmp_path):
    record = _unavailable(
        tmp_path, SourceError(K.HTTP_STATUS, "HTTP 503", url=TOR_URL, status_code=503)
    )
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["http_status"] == 503


def test_missing_route_is_http_404_unavailable(tmp_path):
    routes = standard_routes()
    del routes[TOR_URL]
    record = tor_adapter(make_stack(tmp_path, routes)).lookup(CLEAN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["http_status"] == 404


def test_html_error_page_is_unavailable_malformed(tmp_path):
    record = _unavailable(tmp_path, b"<html><body>Bad gateway</body></html>")
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "MALFORMED"


def test_empty_list_is_unavailable_not_everything_is_clean(tmp_path):
    record = _unavailable(tmp_path, b"# no entries\n")
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "EMPTY"


def test_truncated_list_below_the_default_floor_is_unavailable(tmp_path):
    stack = make_stack(tmp_path)  # fixture list has 2 entries; the default floor is 10
    record = TorExitListAdapter(stack.provider, clock=stack.clock).lookup(CLEAN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "TOO_SMALL"


def test_source_that_reports_old_data_is_unavailable(tmp_path):
    record = _unavailable(
        tmp_path,
        (ip_body([TOR_IP]), {"Last-Modified": "Sun, 25 Oct 2026 12:00:00 GMT"}),
        max_source_age=86400,
    )
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "STALE_SOURCE"


def test_expired_cache_plus_failed_refresh_is_unavailable(tmp_path):
    stack = make_stack(tmp_path, ttl=1800)
    adapter = tor_adapter(stack)
    assert adapter.lookup(TOR_IP).status is S.MATCH
    stack.fetcher.routes[TOR_URL] = SourceError(K.TIMEOUT, "no response", url=TOR_URL)
    stack.clock.advance(minutes=45)
    record = adapter.lookup(TOR_IP)
    assert record.status is S.SOURCE_UNAVAILABLE
    assert "not used as evidence" in record.error


def test_second_lookup_reuses_the_cached_snapshot(tmp_path):
    stack = make_stack(tmp_path)
    adapter = tor_adapter(stack)
    adapter.lookup(TOR_IP)
    stack.clock.advance(minutes=5)
    record = adapter.lookup(CLEAN_IP)
    assert stack.fetcher.count(TOR_URL) == 1
    assert record.metadata["snapshot"]["from_cache"] is True
    assert record.retrieved_at == T0  # retrieval time of the snapshot, not of the lookup


def test_unexpected_internal_error_is_unavailable_not_raised(tmp_path):
    stack = make_stack(tmp_path)
    adapter = tor_adapter(stack)

    def boom(*args, **kwargs):
        raise RuntimeError("bug")

    stack.provider.load = boom  # type: ignore[method-assign]
    record = adapter.lookup(TOR_IP)
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "INTERNAL"


def test_custom_url_is_honoured(tmp_path):
    custom = "https://mirror.example.invalid/tor.txt"
    routes = {custom: ip_body([TOR_IP])}
    stack = make_stack(tmp_path, routes)
    record = tor_adapter(stack, url=custom).lookup(TOR_IP)
    assert record.status is S.MATCH and record.source_endpoint == custom
    assert stack.fetcher.requested == [custom]
