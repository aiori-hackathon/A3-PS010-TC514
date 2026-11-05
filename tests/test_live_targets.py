"""The live verifier probes exactly the files the adapters download. Offline."""
from netclass.adapters.az0 import AZ0_MIN_TOTAL
from netclass.adapters.tor import TOR_MIN_ENTRIES
from netclass.adapters.x4bnet import X4B_MIN_APPLE, X4B_MIN_V4, X4B_MIN_V6
from netclass.live_targets import GROUP_FLOORS, default_targets
from netclass.live_verify import KIND_CIDR_LIST, KIND_IP_LIST
from netclass.sources import AZ0_VPN_SOURCE, SOURCES, TOR_SOURCE, X4BNET_VPN_SOURCE


def test_every_target_url_comes_from_the_source_registry_and_nothing_else():
    registry = set()
    for spec in SOURCES.values():
        registry |= set(spec.endpoints) | set(spec.auxiliary_endpoints)
    urls = [t.url for t in default_targets()]
    assert set(urls) == registry and len(urls) == len(set(urls))


def test_targets_cover_every_file_with_the_adapter_floors_and_families():
    by_file = {(t.source, t.file): t for t in default_targets()}
    assert len(by_file) == 9  # tor + x4bnet v4/v6/apple + 5 az0 files
    tor = by_file[(TOR_SOURCE.name, "torbulkexitlist")]
    assert (tor.kind, tor.min_entries) == (KIND_IP_LIST, TOR_MIN_ENTRIES)
    v4 = by_file[(X4BNET_VPN_SOURCE.name, "ipv4.txt")]
    v6 = by_file[(X4BNET_VPN_SOURCE.name, "ipv6.txt")]
    apple = by_file[(X4BNET_VPN_SOURCE.name, "apple.txt")]
    assert (v4.kind, v4.family, v4.min_entries) == (KIND_CIDR_LIST, 4, X4B_MIN_V4)
    assert (v6.kind, v6.family, v6.min_entries) == (KIND_CIDR_LIST, 6, X4B_MIN_V6)
    assert (apple.role, apple.family, apple.min_entries) == ("exclusion", None, X4B_MIN_APPLE)
    assert GROUP_FLOORS == {"az0": AZ0_MIN_TOTAL}
    assert {t.file for t in default_targets() if t.source == AZ0_VPN_SOURCE.name} == {
        url.rsplit("/", 1)[-1] for url in AZ0_VPN_SOURCE.endpoints
    }


def test_only_the_apple_file_has_the_exclusion_role():
    roles = {t.file: t.role for t in default_targets()}
    assert [f for f, r in roles.items() if r == "exclusion"] == ["apple.txt"]


def test_the_datacenter_and_dns_resolver_lists_are_never_probed():
    assert not any(t.file == "nordvpn.txt" for t in default_targets())
    assert not any("datacenter" in t.url for t in default_targets())


def test_a_configured_tor_url_replaces_only_the_tor_target():
    custom = "https://mirror.invalid/torbulkexitlist"
    urls = {t.file: t.url for t in default_targets(custom)}
    assert urls["torbulkexitlist"] == custom
    assert urls["ipv4.txt"] == X4BNET_VPN_SOURCE.endpoints[0]
