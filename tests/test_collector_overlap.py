"""End-to-end: mocked HTTP -> adapters -> evidence records -> classifier.

These tests pin down the documented overlap/conflict policy:
  * Any applicable Tor match together with any applicable VPN match is a conflict.
    It resolves to Unknown. There is NO Tor precedence, whether the VPN evidence is
    range-level (X4BNet) or exact-address (az0).
  * A failed/stale source is never a negative.
"""
import pytest

from factories import T0, hours
from fakes import FakeFetcher, MutableClock, cidr_body, ip_body
from netclass.collector import build_adapters, classify_with_evidence, collect_evidence
from netclass.config import Settings
from netclass.errors import SourceError, SourceErrorKind
from netclass.models import EvidenceStatus, Label, Observation, ReasonCode
from support import (
    ALL_SOURCE_URLS,
    APPLE_IP,
    APPLE_URL,
    AZ0,
    AZ0_IP,
    CLEAN_IP,
    TOR_IP,
    TOR_URL,
    VPN_IP,
    X4_V4,
    all_adapters,
    make_stack,
    standard_routes,
)

R = ReasonCode
S = EvidenceStatus
TOR_NAME = "tor-project-bulk-exit-list"


def run(tmp_path, ip, routes=None, *, at=T0, stack=None):
    stack = stack or make_stack(tmp_path, routes)
    observation = Observation(ip=ip, observed_at=at)
    result, records = classify_with_evidence(observation, all_adapters(stack), Settings())
    return result, records, stack


def timeout(url):
    return SourceError(SourceErrorKind.TIMEOUT, "no response within 10s", url=url)


# ------------------------------------------------------------ single sources
def test_tor_only_is_known_tor_exit(tmp_path):
    result, _, _ = run(tmp_path, TOR_IP)
    assert result.label is Label.KNOWN_TOR_EXIT and result.reason_code is R.TOR_EXIT_MATCH


def test_x4bnet_range_only_is_known_vpn_with_range_granularity_on_record(tmp_path):
    result, records, _ = run(tmp_path, VPN_IP)
    assert result.label is Label.KNOWN_VPN_PROXY
    x4 = next(r for r in records if r.source_name == "x4bnet-lists-vpn")
    assert x4.metadata["granularity"] == "cidr-range"


def test_az0_exact_address_only_is_known_vpn(tmp_path):
    result, _, _ = run(tmp_path, AZ0_IP)
    assert result.label is Label.KNOWN_VPN_PROXY
    assert result.reason_code is R.VPN_PROXY_ENDPOINT_MATCH


def test_two_independent_vpn_sources_agreeing_is_one_vpn_label(tmp_path):
    routes = standard_routes()
    routes[AZ0["pia.txt"]] = ip_body([VPN_IP])
    result, records, _ = run(tmp_path, VPN_IP, routes)
    assert result.label is Label.KNOWN_VPN_PROXY
    assert sum(r.status is S.MATCH for r in records) == 2


def test_clean_address_is_unknown_no_qualifying_match(tmp_path):
    result, records, _ = run(tmp_path, CLEAN_IP)
    assert result.label is Label.UNKNOWN and result.reason_code is R.UNKNOWN_NO_QUALIFYING_MATCH
    assert all(r.status is S.NO_MATCH for r in records)


# -------------------------------------------------- Tor / VPN overlap policy
def test_tor_exit_inside_a_range_level_vpn_list_is_a_conflict_not_tor(tmp_path):
    routes = standard_routes()
    routes[X4_V4] = cidr_body(["185.220.101.0/24"])  # X4BNet range covering the Tor exit
    result, _, _ = run(tmp_path, TOR_IP, routes)
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_CONFLICTING_EVIDENCE


def test_tor_exit_also_listed_exactly_by_az0_is_a_conflict_with_no_tor_precedence(tmp_path):
    routes = standard_routes()
    routes[AZ0["pia.txt"]] = ip_body([TOR_IP])  # independent exact-address VPN evidence
    result, records, _ = run(tmp_path, TOR_IP, routes)
    assert result.label is Label.UNKNOWN  # explicitly NOT "Known Tor exit"
    assert result.reason_code is R.UNKNOWN_CONFLICTING_EVIDENCE
    assert "both a Tor exit" in result.explanation
    assert {r.source_name for r in records if r.status is S.MATCH} == {TOR_NAME, "az0-vpn-ip"}


def test_conflict_with_both_vpn_sources(tmp_path):
    routes = standard_routes()
    routes[X4_V4] = cidr_body(["185.220.101.0/24"])
    routes[AZ0["pia.txt"]] = ip_body([TOR_IP])
    result, _, _ = run(tmp_path, TOR_IP, routes)
    assert result.reason_code is R.UNKNOWN_CONFLICTING_EVIDENCE


def test_tor_exit_confirmed_negative_by_all_vpn_sources_stays_tor(tmp_path):
    result, records, _ = run(tmp_path, TOR_IP)
    assert result.label is Label.KNOWN_TOR_EXIT
    assert [r.status for r in records if r.source_name != TOR_NAME] == [S.NO_MATCH, S.NO_MATCH]


def test_apple_private_relay_never_becomes_vpn_and_never_conflicts_with_tor(tmp_path):
    clean, _, _ = run(tmp_path / "a", APPLE_IP)
    assert clean.label is Label.UNKNOWN and clean.reason_code is R.UNKNOWN_NO_QUALIFYING_MATCH

    routes = standard_routes()
    routes[TOR_URL] = ip_body([TOR_IP, APPLE_IP])  # a Tor exit inside an Apple relay range
    tor_exit, _, _ = run(tmp_path / "b", APPLE_IP, routes)
    assert tor_exit.label is Label.KNOWN_TOR_EXIT  # the Apple range is not VPN evidence


# ------------------------------------------------------------- failures
def test_tor_source_down_never_yields_a_negative(tmp_path):
    routes = standard_routes()
    routes[TOR_URL] = timeout(TOR_URL)
    result, records, _ = run(tmp_path, CLEAN_IP, routes)
    assert result.label is Label.UNKNOWN and result.reason_code is R.UNKNOWN_SOURCE_UNAVAILABLE
    assert next(r for r in records if r.source_name == TOR_NAME).status is S.SOURCE_UNAVAILABLE


def test_vpn_match_with_tor_source_down_stands_but_carries_a_caveat(tmp_path):
    # Documented limitation of the classification policy: a positive from one kind is not
    # withdrawn because the other kind's source is down; the gap is reported as a caveat.
    routes = standard_routes()
    routes[TOR_URL] = timeout(TOR_URL)
    result, _, _ = run(tmp_path, VPN_IP, routes)
    assert result.label is Label.KNOWN_VPN_PROXY
    assert any(TOR_NAME in caveat for caveat in result.caveats)


def test_tor_match_with_vpn_sources_down_stands_with_caveats(tmp_path):
    routes = standard_routes()
    routes[X4_V4] = timeout(X4_V4)
    for url in (AZ0["pia.txt"],):
        routes[url] = timeout(url)
    result, _, _ = run(tmp_path, TOR_IP, routes)
    assert result.label is Label.KNOWN_TOR_EXIT and len(result.caveats) == 2


def test_every_source_down_is_unknown_source_unavailable(tmp_path):
    routes = {url: timeout(url) for url in ALL_SOURCE_URLS}
    result, records, _ = run(tmp_path, TOR_IP, routes)
    assert result.label is Label.UNKNOWN and result.reason_code is R.UNKNOWN_SOURCE_UNAVAILABLE
    assert all(r.status is S.SOURCE_UNAVAILABLE for r in records)


def test_cache_older_than_ttl_is_not_used_when_refresh_fails(tmp_path):
    stack = make_stack(tmp_path, ttl=1800)
    first, _, _ = run(tmp_path, TOR_IP, stack=stack)
    assert first.label is Label.KNOWN_TOR_EXIT
    for url in ALL_SOURCE_URLS:
        stack.fetcher.routes[url] = timeout(url)
    stack.clock.advance(minutes=45)  # older than the TTL, still inside the 1h tolerance
    result, _, _ = run(
        tmp_path, TOR_IP, stack=stack, at=stack.clock()
    )
    assert result.label is Label.UNKNOWN and result.reason_code is R.UNKNOWN_SOURCE_UNAVAILABLE


# ------------------------------------------------------------- time handling
def test_current_lists_cannot_support_a_historical_observation(tmp_path):
    result, _, _ = run(tmp_path, TOR_IP, at=T0 - hours(24 * 30))
    assert result.label is Label.UNKNOWN and result.reason_code is R.UNKNOWN_STALE_EVIDENCE


def test_future_observation_beyond_tolerance_is_stale(tmp_path):
    result, _, _ = run(tmp_path, TOR_IP, at=T0 + hours(3))
    assert result.reason_code is R.UNKNOWN_STALE_EVIDENCE


# ------------------------------------------------------------------ misc
def test_excluded_addresses_trigger_no_downloads_at_all(tmp_path):
    result, records, stack = run(tmp_path, "10.0.0.1")
    assert result.reason_code is R.UNKNOWN_EXCLUDED_ADDRESS
    assert records == [] and stack.fetcher.requested == []


def test_global_ipv6_without_ipv6_tor_coverage_is_unknown_not_clean(tmp_path):
    result, records, _ = run(tmp_path, "2606:4700:4700::1111")
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_PROVIDER_NOT_CONFIGURED
    assert next(r for r in records if r.source_name == TOR_NAME).status is S.NOT_CONFIGURED


def _without_cache_flag(record):
    """Record as a dict with the (legitimately varying) from_cache provenance flag removed."""
    data = record.model_dump(mode="json")
    snapshots = [data["metadata"].get("snapshot")] + list(data["metadata"].get("files", []))
    for snapshot in snapshots:
        if snapshot:
            snapshot.pop("from_cache")
    return data


def test_results_are_deterministic_across_repeated_runs(tmp_path):
    stack = make_stack(tmp_path)
    first, records1, _ = run(tmp_path, TOR_IP, stack=stack)
    second, records2, _ = run(tmp_path, TOR_IP, stack=stack)
    assert first.model_dump_json() == second.model_dump_json()
    assert [_without_cache_flag(r) for r in records1] == [_without_cache_flag(r) for r in records2]
    # The only difference is honest provenance: the second run was served from the cache.
    assert records1[0].metadata["snapshot"]["from_cache"] is False
    assert records2[0].metadata["snapshot"]["from_cache"] is True


def test_each_source_is_downloaded_once_across_many_lookups(tmp_path):
    stack = make_stack(tmp_path)
    for ip in (TOR_IP, VPN_IP, AZ0_IP, CLEAN_IP):
        run(tmp_path, ip, stack=stack)
    for url in (TOR_URL, X4_V4, APPLE_URL, *AZ0.values()):
        assert stack.fetcher.count(url) <= 1, url


# -------------------------------------------------- build_adapters / settings
def test_build_adapters_uses_all_three_sources_in_registry_order(tmp_path):
    clock = MutableClock(T0)
    adapters = build_adapters(
        Settings(cache_dir=tmp_path / "c"), fetcher=FakeFetcher({}, clock), clock=clock
    )
    assert [a.name for a in adapters] == [
        TOR_NAME,
        "x4bnet-lists-vpn",
        "az0-vpn-ip",
    ]


def test_disabled_sources_are_not_consulted_and_leave_that_kind_uncovered(tmp_path):
    clock = MutableClock(T0)
    fetcher = FakeFetcher({TOR_URL: ip_body([f"185.220.101.{i}" for i in range(1, 13)])}, clock)
    settings = Settings(cache_dir=tmp_path / "c", enabled_sources=(TOR_NAME,))
    adapters = build_adapters(settings, fetcher=fetcher, clock=clock)
    assert [a.name for a in adapters] == [TOR_NAME]
    result, records = classify_with_evidence(
        Observation(ip=CLEAN_IP, observed_at=T0), adapters, settings
    )
    assert len(records) == 1 and fetcher.requested == [TOR_URL]  # default floor of 10 satisfied
    assert result.label is Label.UNKNOWN and result.reason_code is R.UNKNOWN_PROVIDER_NOT_CONFIGURED


def test_collect_evidence_skips_excluded_addresses():
    class Exploding:
        def lookup(self, ip):  # pragma: no cover - must never be called
            raise AssertionError("adapter consulted for an excluded address")

    assert collect_evidence(Observation(ip="127.0.0.1", observed_at=T0), [Exploding()]) == []
