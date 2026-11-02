from fakes import cidr_body
from netclass.adapters import X4BNetVpnAdapter
from netclass.errors import SourceError, SourceErrorKind
from netclass.hashing import manifest_sha256, sha256_hex
from netclass.models import EvidenceKind, EvidenceStatus
from support import (
    APPLE_IP,
    APPLE_URL,
    CLEAN_IP,
    VPN_IP,
    VPN_V6_IP,
    X4_V4,
    X4_V6,
    make_stack,
    standard_routes,
    x4_adapter,
)

S = EvidenceStatus
K = SourceErrorKind


def test_ipv4_range_match_records_cidr_granularity_and_both_file_hashes(tmp_path):
    stack = make_stack(tmp_path)
    record = x4_adapter(stack).lookup(VPN_IP)
    assert record.status is S.MATCH and record.kind is EvidenceKind.VPN_PROXY_ENDPOINT
    assert record.metadata["granularity"] == "cidr-range"
    assert record.metadata["matched_cidr"] == "45.83.64.0/24"
    assert record.source_endpoint == X4_V4
    # Two files were used (VPN list + Apple exclusion list): the hash is their manifest.
    expected = manifest_sha256(
        [
            (X4_V4, sha256_hex(stack.fetcher.routes[X4_V4])),
            (APPLE_URL, sha256_hex(stack.fetcher.routes[APPLE_URL])),
        ]
    )
    assert record.snapshot_sha256 == expected
    assert len(record.metadata["files"]) == 2
    record.model_dump_json()


def test_ipv4_no_match_needs_only_the_vpn_file(tmp_path):
    stack = make_stack(tmp_path)
    record = x4_adapter(stack).lookup(CLEAN_IP)
    assert record.status is S.NO_MATCH
    assert stack.fetcher.requested == [X4_V4]  # the Apple list is not fetched unnecessarily
    assert record.snapshot_sha256 == sha256_hex(stack.fetcher.routes[X4_V4])
    assert record.metadata["list_entries"] == 2


def test_ipv6_uses_the_ipv6_file(tmp_path):
    stack = make_stack(tmp_path)
    adapter = x4_adapter(stack)
    match = adapter.lookup(VPN_V6_IP)
    assert match.status is S.MATCH and match.metadata["matched_cidr"] == "2a0d:5600::/32"
    assert match.source_endpoint == X4_V6
    assert adapter.lookup("2a0e::1").status is S.NO_MATCH
    assert X4_V4 not in stack.fetcher.requested


def test_datacenter_and_other_files_are_never_requested(tmp_path):
    stack = make_stack(tmp_path)
    adapter = x4_adapter(stack)
    for ip in (VPN_IP, CLEAN_IP, APPLE_IP, VPN_V6_IP):
        adapter.lookup(ip)
    assert set(stack.fetcher.requested) <= {X4_V4, X4_V6, APPLE_URL}
    assert not any("datacenter" in url for url in stack.fetcher.requested)


# ------------------------------------------------------- Apple Private Relay
def test_address_only_in_apple_private_relay_ranges_is_not_vpn_evidence(tmp_path):
    record = x4_adapter(make_stack(tmp_path)).lookup(APPLE_IP)
    assert record.status is S.NO_MATCH
    assert record.metadata["excluded_by_policy"] == "apple_private_relay"
    assert record.metadata["excluded_cidrs"] == ["104.28.28.0/26"]
    assert any("Apple Private Relay" in text for text in record.limitations)
    assert "matched_cidr" not in record.metadata


def test_apple_range_nested_inside_a_genuine_vpn_range_still_matches_the_genuine_one(tmp_path):
    routes = standard_routes()
    routes[X4_V4] = cidr_body(["104.28.0.0/16", "104.28.28.0/26"])
    record = x4_adapter(make_stack(tmp_path, routes)).lookup(APPLE_IP)
    assert record.status is S.MATCH
    assert record.metadata["matched_cidr"] == "104.28.0.0/16"
    assert record.metadata["also_matched_apple_cidrs_ignored"] == ["104.28.28.0/26"]


def test_match_cannot_be_verified_when_the_apple_list_is_unavailable(tmp_path):
    routes = standard_routes()
    routes[APPLE_URL] = SourceError(K.TIMEOUT, "no response", url=APPLE_URL)
    record = x4_adapter(make_stack(tmp_path, routes)).lookup(VPN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE
    assert "Apple Private Relay exclusion list could not be loaded" in record.error
    assert record.metadata["error_kind"] == "TIMEOUT"


def test_no_match_does_not_depend_on_the_apple_list(tmp_path):
    routes = standard_routes()
    del routes[APPLE_URL]
    assert x4_adapter(make_stack(tmp_path, routes)).lookup(CLEAN_IP).status is S.NO_MATCH


# -------------------------------------------------------------- failures
def test_files_fail_independently_by_address_family(tmp_path):
    routes = standard_routes()
    routes[X4_V4] = SourceError(K.HTTP_STATUS, "HTTP 500", url=X4_V4, status_code=500)
    adapter = x4_adapter(make_stack(tmp_path, routes))
    assert adapter.lookup(CLEAN_IP).status is S.SOURCE_UNAVAILABLE
    assert adapter.lookup(VPN_V6_IP).status is S.MATCH  # IPv6 file is fine


def test_malformed_file_is_unavailable_not_negative(tmp_path):
    routes = standard_routes()
    routes[X4_V4] = b"<html>rate limited</html>"
    record = x4_adapter(make_stack(tmp_path, routes)).lookup(CLEAN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "MALFORMED"


def test_wrong_family_content_is_malformed(tmp_path):
    routes = standard_routes()
    routes[X4_V4] = cidr_body(["2a0d:5600::/32"])  # IPv6 CIDR in the IPv4 file
    record = x4_adapter(make_stack(tmp_path, routes)).lookup(CLEAN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "MALFORMED"


def test_empty_file_and_overbroad_range_are_unavailable(tmp_path):
    routes = standard_routes()
    routes[X4_V4] = b"# nothing\n"
    assert x4_adapter(make_stack(tmp_path, routes)).lookup(CLEAN_IP).metadata["error_kind"] == "EMPTY"

    routes[X4_V4] = cidr_body(["0.0.0.0/0"])
    assert x4_adapter(make_stack(tmp_path / "b", routes)).lookup(CLEAN_IP).status is S.SOURCE_UNAVAILABLE


def test_file_below_the_default_floor_is_unavailable(tmp_path):
    stack = make_stack(tmp_path)  # fixture has 2 CIDRs; default floor is 1000
    record = X4BNetVpnAdapter(stack.provider, clock=stack.clock).lookup(CLEAN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "TOO_SMALL"


def test_timeout_is_unavailable(tmp_path):
    routes = standard_routes()
    routes[X4_V4] = SourceError(K.TIMEOUT, "no response within 10s", url=X4_V4)
    record = x4_adapter(make_stack(tmp_path, routes)).lookup(VPN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE and record.error.startswith("TIMEOUT")
