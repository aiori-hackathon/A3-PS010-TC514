from fakes import ip_body
from netclass.adapters import Az0VpnIpAdapter
from netclass.errors import SourceError, SourceErrorKind
from netclass.hashing import manifest_sha256, sha256_hex
from netclass.models import EvidenceKind, EvidenceStatus
from netclass.sources import AZ0_VPN_SOURCE
from support import (
    AZ0,
    AZ0_IP,
    AZ0_URLS,
    CLEAN_IP,
    DNS_RESOLVER_IP,
    make_stack,
    standard_routes,
    az0_adapter,
)

S = EvidenceStatus
K = SourceErrorKind
BASE = AZ0_URLS[0].rsplit("/", 1)[0] + "/"


def test_exact_address_match_with_per_file_provenance(tmp_path):
    stack = make_stack(tmp_path)
    record = az0_adapter(stack).lookup(AZ0_IP)
    assert record.status is S.MATCH and record.kind is EvidenceKind.VPN_PROXY_ENDPOINT
    assert record.metadata["granularity"] == "exact-address"
    assert record.metadata["matched_files"] == ["pia.txt"]
    assert record.metadata["files_loaded"] == 5 and record.metadata["files_failed"] == []
    assert record.source_endpoint == BASE
    expected = manifest_sha256((u, sha256_hex(stack.fetcher.routes[u])) for u in AZ0_URLS)
    assert record.snapshot_sha256 == expected
    assert {f["url"] for f in record.metadata["files"]} == set(AZ0_URLS)
    record.model_dump_json()


def test_inline_comments_in_the_source_file_do_not_break_matching(tmp_path):
    # the fixture pia.txt line is "91.207.175.10  # CA Montreal"
    assert az0_adapter(make_stack(tmp_path)).lookup(AZ0_IP).status is S.MATCH


def test_address_in_no_file_is_no_match(tmp_path):
    record = az0_adapter(make_stack(tmp_path)).lookup(CLEAN_IP)
    assert record.status is S.NO_MATCH and record.metadata["list_entries_total"] == 6


def test_dns_resolver_file_is_never_fetched_or_counted(tmp_path):
    stack = make_stack(tmp_path)  # routes DO contain nordvpn.txt with DNS resolver addresses
    record = az0_adapter(stack).lookup(DNS_RESOLVER_IP)
    assert record.status is S.NO_MATCH
    assert not any(url.endswith("/nordvpn.txt") for url in stack.fetcher.requested)
    assert set(stack.fetcher.requested) == set(AZ0_URLS)


def test_url_order_does_not_change_the_result_or_hash(tmp_path):
    a = az0_adapter(make_stack(tmp_path / "a")).lookup(AZ0_IP)
    b = az0_adapter(make_stack(tmp_path / "b"), urls=list(reversed(AZ0_URLS))).lookup(AZ0_IP)
    assert a.snapshot_sha256 == b.snapshot_sha256 and a.metadata["matched_files"] == b.metadata["matched_files"]


# --------------------------------------------------------- partial failures
def failing(url, kind=K.HTTP_STATUS):
    return SourceError(kind, "HTTP 500", url=url, status_code=500)


def test_match_in_a_loaded_file_stands_even_if_another_file_failed(tmp_path):
    routes = standard_routes()
    routes[AZ0["expressvpn.txt"]] = failing(AZ0["expressvpn.txt"])
    record = az0_adapter(make_stack(tmp_path, routes)).lookup(AZ0_IP)
    assert record.status is S.MATCH
    assert record.metadata["files_loaded"] == 4
    assert len(record.metadata["files_failed"]) == 1
    assert any("failed to load" in text for text in record.limitations)


def test_no_match_with_a_failed_file_is_unavailable_not_negative(tmp_path):
    routes = standard_routes()
    routes[AZ0["expressvpn.txt"]] = failing(AZ0["expressvpn.txt"])
    record = az0_adapter(make_stack(tmp_path, routes)).lookup(CLEAN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE
    assert "absence cannot be established" in record.error


def test_malformed_and_empty_files_count_as_failures(tmp_path):
    routes = standard_routes()
    routes[AZ0["hideme.txt"]] = b"<html>blocked</html>"
    routes[AZ0["hideme_api.txt"]] = b"# header only\n"
    adapter = az0_adapter(make_stack(tmp_path, routes))
    assert adapter.lookup(AZ0_IP).metadata["files_loaded"] == 3  # match still stands
    record = adapter.lookup(CLEAN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE
    assert "MALFORMED" in record.error and "EMPTY" in record.error


def test_all_files_down_is_unavailable(tmp_path):
    routes = standard_routes()
    for url in AZ0_URLS:
        routes[url] = SourceError(K.TIMEOUT, "no response", url=url)
    record = az0_adapter(make_stack(tmp_path, routes)).lookup(AZ0_IP)
    assert record.status is S.SOURCE_UNAVAILABLE
    assert "none of the 5 az0 files could be loaded" in record.error


def test_union_below_the_default_floor_is_unavailable(tmp_path):
    stack = make_stack(tmp_path)  # fixtures hold 6 addresses; default floor is 1000
    record = Az0VpnIpAdapter(stack.provider, clock=stack.clock).lookup(AZ0_IP)
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "TOO_SMALL"


# -------------------------------------------------------------------- IPv6
def test_ipv6_query_not_covered_when_no_ipv6_entries_loaded(tmp_path):
    record = az0_adapter(make_stack(tmp_path)).lookup("2a0d:5600::1")
    assert record.status is S.NOT_CONFIGURED and "IPv6 not covered" in record.error


def test_ipv6_entries_are_supported_when_present(tmp_path):
    routes = standard_routes()
    routes[AZ0["pia.txt"]] = ip_body([AZ0_IP, "2a0d:5600::1"])
    adapter = az0_adapter(make_stack(tmp_path, routes))
    assert adapter.lookup("2a0d:5600::1").status is S.MATCH
    assert adapter.lookup("2a0d:5600::2").status is S.NO_MATCH


def test_registry_urls_exclude_the_dns_file():
    assert not any(url.endswith("/nordvpn.txt") for url in AZ0_VPN_SOURCE.endpoints)
