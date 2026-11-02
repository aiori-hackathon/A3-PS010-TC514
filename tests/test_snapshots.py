from datetime import timedelta

import pytest

from factories import T0
from fakes import FakeFetcher, MutableClock, ip_body
from netclass.cache import Snapshot, SnapshotStore
from netclass.errors import SourceError, SourceErrorKind
from netclass.hashing import sha256_hex
from netclass.parsers import parse_ip_list
from netclass.snapshots import SnapshotProvider, parse_http_date

URL = "https://example.invalid/list.txt"
K = SourceErrorKind
BODY = ip_body(["1.2.3.4", "5.6.7.8"])
FRESH_STAMP = "Wed, 28 Oct 2026 11:00:00 GMT"  # 1 hour before T0
OLD_STAMP = "Sun, 25 Oct 2026 12:00:00 GMT"  # 3 days before T0


def parse(body):
    return parse_ip_list(body, source="t")


def setup(tmp_path, routes, *, ttl=1800, max_source_age=None, store=True):
    clock = MutableClock(T0)
    fetcher = FakeFetcher(routes, clock)
    cache = SnapshotStore(tmp_path / "cache") if store else None
    provider = SnapshotProvider(
        fetcher, cache, ttl_seconds=ttl, clock=clock, max_source_age_seconds=max_source_age
    )
    return clock, fetcher, cache, provider


def test_first_load_fetches_and_records_hash_and_utc_time(tmp_path):
    clock, fetcher, store, provider = setup(tmp_path, {URL: BODY})
    loaded = provider.load("src", URL, parse)
    snap = loaded.snapshot
    assert fetcher.count(URL) == 1
    assert snap.from_cache is False
    assert snap.sha256 == sha256_hex(BODY)
    assert snap.retrieved_at == T0 and snap.retrieved_at.utcoffset().total_seconds() == 0
    assert loaded.parsed.count == 2
    assert store.load("src", URL).snapshot is not None  # retained


def test_fresh_cache_is_used_without_a_download(tmp_path):
    clock, fetcher, _, provider = setup(tmp_path, {URL: BODY})
    first = provider.load("src", URL, parse).snapshot
    clock.advance(minutes=10)
    second = provider.load("src", URL, parse).snapshot
    assert fetcher.count(URL) == 1
    assert second.from_cache is True
    assert second.sha256 == first.sha256 and second.retrieved_at == first.retrieved_at


def test_expired_cache_is_refreshed_and_changed_content_gets_a_new_hash(tmp_path):
    clock, fetcher, _, provider = setup(tmp_path, {URL: BODY}, ttl=1800)
    first = provider.load("src", URL, parse).snapshot
    fetcher.routes[URL] = ip_body(["1.2.3.4", "9.9.9.9"])
    clock.advance(minutes=31)
    second = provider.load("src", URL, parse).snapshot
    assert fetcher.count(URL) == 2
    assert second.from_cache is False and second.sha256 != first.sha256
    assert second.retrieved_at == T0 + timedelta(minutes=31)


def test_stale_cache_is_never_used_when_refresh_fails(tmp_path):
    clock, fetcher, _, provider = setup(tmp_path, {URL: BODY}, ttl=1800)
    provider.load("src", URL, parse)
    fetcher.routes[URL] = SourceError(K.TIMEOUT, "no response within 10s", url=URL)
    clock.advance(minutes=45)
    with pytest.raises(SourceError) as info:
        provider.load("src", URL, parse)
    error = info.value
    assert error.kind is K.TIMEOUT
    assert "not used as evidence" in error.message
    assert T0.isoformat() in error.message


def test_failure_without_any_cache_is_reported_plainly(tmp_path):
    _, _, _, provider = setup(tmp_path, {URL: SourceError(K.HTTP_STATUS, "HTTP 503", url=URL, status_code=503)})
    with pytest.raises(SourceError) as info:
        provider.load("src", URL, parse)
    assert info.value.kind is K.HTTP_STATUS and info.value.status_code == 503


def test_malformed_download_is_not_cached_and_does_not_poison_later_loads(tmp_path):
    clock, fetcher, store, provider = setup(tmp_path, {URL: b"<html>503 Service Unavailable</html>"})
    with pytest.raises(SourceError) as info:
        provider.load("src", URL, parse)
    assert info.value.kind is K.MALFORMED and info.value.url == URL
    assert store.load("src", URL).snapshot is None
    fetcher.routes[URL] = BODY
    assert provider.load("src", URL, parse).parsed.count == 2


def test_empty_download_is_an_error_and_not_cached(tmp_path):
    _, _, store, provider = setup(tmp_path, {URL: b"# nothing here\n"})
    with pytest.raises(SourceError) as info:
        provider.load("src", URL, parse)
    assert info.value.kind is K.EMPTY
    assert store.load("src", URL).snapshot is None


def test_cached_content_that_no_longer_parses_triggers_a_refetch(tmp_path):
    clock, fetcher, store, provider = setup(tmp_path, {URL: BODY})
    bad = b"<html>old error page</html>"
    store.save(
        Snapshot("src", URL, bad, sha256_hex(bad), T0, None, False, {})
    )
    loaded = provider.load("src", URL, parse)
    assert fetcher.count(URL) == 1 and loaded.parsed.count == 2
    assert any("unusable" in note for note in loaded.snapshot.notes)


def test_tampered_cache_is_discarded_and_refetched(tmp_path):
    clock, fetcher, store, provider = setup(tmp_path, {URL: BODY})
    snap = provider.load("src", URL, parse).snapshot
    (tmp_path / "cache" / "snapshots" / f"{snap.sha256}.bin").write_bytes(ip_body(["6.6.6.6"]))
    loaded = provider.load("src", URL, parse)
    assert fetcher.count(URL) == 2
    assert loaded.snapshot.sha256 == sha256_hex(BODY)
    assert any("SHA-256" in note for note in loaded.snapshot.notes)


def test_cache_entry_from_the_future_is_not_trusted(tmp_path):
    clock, fetcher, store, provider = setup(tmp_path, {URL: BODY})
    store.save(Snapshot("src", URL, BODY, sha256_hex(BODY), T0 + timedelta(minutes=5), None, False, {}))
    loaded = provider.load("src", URL, parse)
    assert fetcher.count(URL) == 1 and loaded.snapshot.from_cache is False


def test_force_refresh_bypasses_a_fresh_cache(tmp_path):
    _, fetcher, _, provider = setup(tmp_path, {URL: BODY})
    provider.load("src", URL, parse)
    provider.load("src", URL, parse, force_refresh=True)
    assert fetcher.count(URL) == 2


def test_works_without_a_store(tmp_path):
    _, fetcher, _, provider = setup(tmp_path, {URL: BODY}, store=False)
    provider.load("src", URL, parse)
    provider.load("src", URL, parse)
    assert fetcher.count(URL) == 2


def test_parse_is_memoised_per_snapshot_hash(tmp_path):
    clock, fetcher, _, provider = setup(tmp_path, {URL: BODY})
    calls = []

    def counting(body):
        calls.append(1)
        return parse(body)

    provider.load("src", URL, counting)
    provider.load("src", URL, counting)
    assert len(calls) == 1


def test_cache_write_failure_does_not_break_retrieval(tmp_path):
    class BrokenStore:
        def load(self, *_):
            from netclass.cache import CacheLookup

            return CacheLookup(None)

        def save(self, _):
            raise PermissionError("disk is read-only")

    clock = MutableClock(T0)
    provider = SnapshotProvider(FakeFetcher({URL: BODY}, clock), BrokenStore(), ttl_seconds=60, clock=clock)
    loaded = provider.load("src", URL, parse)
    assert loaded.parsed.count == 2
    assert any("cache write failed" in note for note in loaded.snapshot.notes)


# ------------------------------------------------------------ source freshness
def test_last_modified_header_becomes_the_source_timestamp(tmp_path):
    _, _, _, provider = setup(tmp_path, {URL: (BODY, {"Last-Modified": FRESH_STAMP})}, max_source_age=86400)
    snap = provider.load("src", URL, parse).snapshot
    assert snap.source_timestamp == T0 - timedelta(hours=1)


def test_unparseable_last_modified_is_ignored(tmp_path):
    _, _, _, provider = setup(tmp_path, {URL: (BODY, {"Last-Modified": "yesterday-ish"})}, max_source_age=60)
    assert provider.load("src", URL, parse).snapshot.source_timestamp is None


def test_source_reporting_old_data_is_rejected_and_not_cached(tmp_path):
    _, _, store, provider = setup(tmp_path, {URL: (BODY, {"Last-Modified": OLD_STAMP})}, max_source_age=86400)
    with pytest.raises(SourceError) as info:
        provider.load("src", URL, parse)
    assert info.value.kind is K.STALE_SOURCE
    assert store.load("src", URL).snapshot is None


def test_cached_snapshot_whose_source_timestamp_has_aged_out_is_refetched(tmp_path):
    clock, fetcher, _, provider = setup(
        tmp_path, {URL: (BODY, {"Last-Modified": FRESH_STAMP})}, ttl=3600 * 30, max_source_age=3600 * 2
    )
    provider.load("src", URL, parse)  # source is 1h old: accepted
    clock.advance(hours=2)  # cached copy is still inside the TTL, but the source data is now 3h old
    with pytest.raises(SourceError) as info:
        provider.load("src", URL, parse)
    assert info.value.kind is K.STALE_SOURCE
    assert fetcher.count(URL) == 2


def test_parse_http_date_variants():
    assert parse_http_date("Wed, 28 Oct 2026 11:00:00 GMT") == T0 - timedelta(hours=1)
    assert parse_http_date(None) is None and parse_http_date("") is None
    assert parse_http_date("not a date") is None
