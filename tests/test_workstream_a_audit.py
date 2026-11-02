"""Workstream A regression tests: sanity-floor boundaries, IPv4/IPv6 coverage symmetry,
Apple Private Relay IPv6 coverage, conflict provenance and overlap diagnostics.

No network. Fixture addresses are arbitrary and are NOT claims about real hosts.
"""
from __future__ import annotations

from factories import T0
from fakes import FakeFetcher, MutableClock, cidr_body, ip_body
from netclass.adapters import Az0VpnIpAdapter, TorExitListAdapter, X4BNetVpnAdapter
from netclass.adapters.az0 import AZ0_MIN_TOTAL
from netclass.adapters.tor import TOR_MIN_ENTRIES
from netclass.adapters.x4bnet import X4B_MIN_APPLE, X4B_MIN_V4, X4B_MIN_V6
from netclass.collector import classify_with_evidence
from netclass.config import Settings
from netclass.inspection import Floors, format_report, inspect_sources
from netclass.models import EvidenceStatus, Label, Observation, ReasonCode
from support import (
    APPLE_IP,
    APPLE_URL,
    AZ0,
    CLEAN_IP,
    TOR_IP,
    TOR_URL,
    VPN_IP,
    VPN_V6_IP,
    X4_V4,
    X4_V6,
    all_adapters,
    az0_adapter,
    make_stack,
    standard_routes,
    tor_adapter,
    x4_adapter,
)

S = EvidenceStatus
R = ReasonCode


def _ips(n: int, prefix: str = "185.220.101") -> list[str]:
    return [f"{prefix}.{i // 250}.{i % 250 + 1}" if n > 250 else f"{prefix}.{i + 1}" for i in range(n)]


def _v4_cidrs(n: int) -> list[str]:
    return [f"45.{64 + i // 256}.{i % 256}.0/24" for i in range(n)]


def _v6_cidrs(n: int) -> list[str]:
    return [f"2a0d:{i + 1:x}::/32" for i in range(n)]


# ------------------------------------------------ sanity floors: values and edges
def test_default_sanity_floors_are_pinned():
    # Changing a floor needs a documented reason (docs/WORKSTREAM_A_AUDIT.md section 3).
    assert (TOR_MIN_ENTRIES, X4B_MIN_V4, X4B_MIN_V6, X4B_MIN_APPLE, AZ0_MIN_TOTAL) == (
        10,
        1000,
        50,
        100,
        1000,
    )
    defaults = Floors()
    assert (defaults.tor, defaults.x4_v4, defaults.x4_v6, defaults.apple, defaults.az0_file) == (
        10,
        1000,
        50,
        100,
        1,
    )


def test_tor_floor_is_inclusive_at_exactly_the_floor(tmp_path):
    ok = make_stack(tmp_path / "ok", {TOR_URL: ip_body(_ips(TOR_MIN_ENTRIES))})
    assert TorExitListAdapter(ok.provider, clock=ok.clock).lookup(CLEAN_IP).status is S.NO_MATCH
    short = make_stack(tmp_path / "short", {TOR_URL: ip_body(_ips(TOR_MIN_ENTRIES - 1))})
    record = TorExitListAdapter(short.provider, clock=short.clock).lookup(CLEAN_IP)
    assert record.status is S.SOURCE_UNAVAILABLE and record.metadata["error_kind"] == "TOO_SMALL"


def test_x4bnet_ipv4_floor_is_inclusive_at_exactly_the_floor(tmp_path):
    def lookup(n, sub):
        stack = make_stack(tmp_path / sub, {X4_V4: cidr_body(_v4_cidrs(n))})
        return X4BNetVpnAdapter(stack.provider, clock=stack.clock).lookup(CLEAN_IP)

    assert lookup(X4B_MIN_V4, "ok").status is S.NO_MATCH
    short = lookup(X4B_MIN_V4 - 1, "short")
    assert short.status is S.SOURCE_UNAVAILABLE and short.metadata["error_kind"] == "TOO_SMALL"


def test_x4bnet_ipv6_floor_is_inclusive_at_exactly_the_floor(tmp_path):
    def lookup(n, sub):
        stack = make_stack(tmp_path / sub, {X4_V6: cidr_body(_v6_cidrs(n))})
        return X4BNetVpnAdapter(stack.provider, clock=stack.clock).lookup("2a0e::1")

    assert lookup(X4B_MIN_V6, "ok").status is S.NO_MATCH
    short = lookup(X4B_MIN_V6 - 1, "short")
    assert short.status is S.SOURCE_UNAVAILABLE and short.metadata["error_kind"] == "TOO_SMALL"


def test_apple_exclusion_floor_is_inclusive_and_a_short_list_blocks_the_match(tmp_path):
    def lookup(n, sub):
        apple = ["104.28.28.0/26"] + [f"17.{i // 256}.{i % 256}.0/24" for i in range(n - 1)]
        stack = make_stack(tmp_path / sub, standard_routes(**{APPLE_URL: cidr_body(apple)}))
        return x4_adapter(stack, min_apple=X4B_MIN_APPLE).lookup(APPLE_IP)

    ok = lookup(X4B_MIN_APPLE, "ok")
    assert ok.status is S.NO_MATCH and ok.metadata["excluded_by_policy"] == "apple_private_relay"
    short = lookup(X4B_MIN_APPLE - 1, "short")
    # A truncated exclusion list must never let an Apple-only address become a VPN match.
    assert short.status is S.SOURCE_UNAVAILABLE and short.metadata["error_kind"] == "TOO_SMALL"


def test_az0_total_floor_counts_unique_addresses_across_files_inclusively(tmp_path):
    def lookup(total, sub):
        routes = standard_routes()
        routes[AZ0["pia.txt"]] = ip_body(_ips(total - 4, "91.208"))  # + 4 single-entry files
        stack = make_stack(tmp_path / sub, routes)
        return Az0VpnIpAdapter(stack.provider, clock=stack.clock).lookup(CLEAN_IP)

    assert lookup(AZ0_MIN_TOTAL, "ok").status is S.NO_MATCH
    # (the 4 other fixture files are fixed, so total = pia + 4)
    short = lookup(AZ0_MIN_TOTAL - 1, "short")
    assert short.status is S.SOURCE_UNAVAILABLE and short.metadata["error_kind"] == "TOO_SMALL"


# --------------------------------------- IPv4 / IPv6 coverage is never assumed
def test_tor_list_without_ipv4_entries_does_not_clear_an_ipv4_address(tmp_path):
    stack = make_stack(tmp_path, {TOR_URL: ip_body(["2001:67c:e60::1"])})
    adapter = tor_adapter(stack)
    v4 = adapter.lookup(CLEAN_IP)
    assert v4.status is S.NOT_CONFIGURED and "IPv4 not covered" in v4.error
    assert adapter.lookup("2001:67c:e60::1").status is S.MATCH
    assert adapter.lookup("2001:67c:e60::2").status is S.NO_MATCH  # IPv6 is covered here


def test_az0_files_without_ipv4_addresses_do_not_clear_an_ipv4_address(tmp_path):
    routes = {url: ip_body(["2001:db8::1"]) for url in AZ0.values()}
    stack = make_stack(tmp_path, routes)
    record = az0_adapter(stack).lookup(CLEAN_IP)
    assert record.status is S.NOT_CONFIGURED and "IPv4 not covered" in record.error


def test_uncovered_ipv4_kind_gives_unknown_not_a_clean_result(tmp_path):
    routes = standard_routes()
    routes[TOR_URL] = ip_body(["2001:67c:e60::1"])
    stack = make_stack(tmp_path, routes)
    result, records = classify_with_evidence(
        Observation(ip=CLEAN_IP, observed_at=T0), all_adapters(stack), Settings()
    )
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_PROVIDER_NOT_CONFIGURED
    assert next(r for r in records if r.kind.value == "TOR_EXIT").status is S.NOT_CONFIGURED


# ------------------------------------- Apple Private Relay: IPv6 exclusion coverage
def test_ipv6_vpn_match_records_that_the_apple_list_has_no_ipv6_coverage(tmp_path):
    record = x4_adapter(make_stack(tmp_path)).lookup(VPN_V6_IP)
    assert record.status is S.MATCH  # behaviour unchanged: the match still stands
    assert record.metadata["apple_exclusion_ipv6_entries"] == 0
    assert any("no IPv6 CIDRs" in text for text in record.limitations)


def test_ipv4_match_does_not_carry_the_ipv6_apple_gap_note(tmp_path):
    record = x4_adapter(make_stack(tmp_path)).lookup(VPN_IP)
    assert "apple_exclusion_ipv6_entries" not in record.metadata
    assert not any("no IPv6 CIDRs" in text for text in record.limitations)


def test_apple_ipv6_ranges_are_excluded_when_the_apple_list_has_them(tmp_path):
    routes = standard_routes(**{APPLE_URL: cidr_body(["104.28.28.0/26", "2a0d:5600::/32"])})
    record = x4_adapter(make_stack(tmp_path, routes)).lookup(VPN_V6_IP)
    assert record.status is S.NO_MATCH
    assert record.metadata["excluded_by_policy"] == "apple_private_relay"


# --------------------------------------------- Tor/VPN conflict: policy and provenance
def _overlap_routes():
    routes = standard_routes()
    routes[X4_V4] = cidr_body(["185.220.101.0/24"])
    return routes


def test_conflict_is_unknown_whatever_the_adapter_order_and_keeps_provenance(tmp_path):
    forward = make_stack(tmp_path / "f", _overlap_routes())
    reverse = make_stack(tmp_path / "r", _overlap_routes())
    obs = Observation(ip=TOR_IP, observed_at=T0)
    a, records = classify_with_evidence(obs, all_adapters(forward), Settings())
    b, _ = classify_with_evidence(obs, list(reversed(all_adapters(reverse))), Settings())
    assert a.label is Label.UNKNOWN and a.reason_code is R.UNKNOWN_CONFLICTING_EVIDENCE
    assert a.model_dump_json() == b.model_dump_json()
    x4 = next(r for r in records if r.source_name == "x4bnet-lists-vpn")
    tor = next(r for r in records if r.kind.value == "TOR_EXIT")
    assert x4.metadata["matched_cidr"] == "185.220.101.0/24"  # which range caused it
    assert x4.snapshot_sha256 and tor.snapshot_sha256
    assert x4.retrieved_at.utcoffset().total_seconds() == 0


def test_conflict_is_not_hidden_by_a_vpn_source_that_was_merely_unavailable_elsewhere(tmp_path):
    # az0 is down, X4BNet still lists the Tor exit's range: the conflict must stand.
    routes = _overlap_routes()
    routes[AZ0["pia.txt"]] = b"<html>error</html>"
    stack = make_stack(tmp_path, routes)
    result, _ = classify_with_evidence(
        Observation(ip=TOR_IP, observed_at=T0), all_adapters(stack), Settings()
    )
    assert result.reason_code is R.UNKNOWN_CONFLICTING_EVIDENCE


# --------------------------------------------------- inspection: overlap diagnostics
LOW = Floors(tor=1, x4_v4=1, x4_v6=1, apple=1, az0_file=1)


def _report(routes):
    clock = MutableClock(T0)
    return inspect_sources(FakeFetcher(routes, clock), clock=clock, floors=LOW)


def test_overlap_report_attributes_tor_addresses_to_the_matching_cidr():
    routes = standard_routes()
    routes[X4_V4] = cidr_body(["185.220.101.0/24", "185.220.101.46/31", "104.28.28.0/26"])
    routes[AZ0["pia.txt"]] = ip_body([TOR_IP])
    overlap = _report(routes)["overlap"]["tor_inside_x4bnet_vpn_ranges"]
    assert overlap["count"] == 2
    assert overlap["all_addresses"] == ["185.220.101.45", "185.220.101.46"]
    # .46 sits in the more specific /31; Apple's /26 is never counted as a genuine range.
    assert overlap["by_matched_cidr"] == {"185.220.101.0/24": 1, "185.220.101.46/31": 1}
    assert overlap["also_in_az0"] == [TOR_IP]


def test_report_shows_floor_headroom_and_flags_missing_apple_ipv6():
    report = _report(standard_routes())
    tor = next(f for f in report["files"] if f["url"] == TOR_URL)
    assert tor["sanity_floor"] == 1 and tor["floor_headroom_ratio"] == 2.0
    assert report["apple_cidrs_ipv6"] == 0
    assert any("no IPv6 CIDRs" in note for note in report["notes"])


def test_text_report_omits_the_full_address_list_but_json_keeps_it():
    routes = standard_routes()
    routes[X4_V4] = cidr_body(["185.220.101.0/24"])
    report = _report(routes)
    text = format_report(report)
    assert "all_addresses" not in text and "by_matched_cidr" in text
    assert "all_addresses" in report["overlap"]["tor_inside_x4bnet_vpn_ranges"]
