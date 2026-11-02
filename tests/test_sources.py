"""Guards for the source registry (no network access)."""
import pytest

from netclass.models import EvidenceKind
from netclass.sources import AZ0_VPN_SOURCE, SOURCES, TOR_SOURCE, X4BNET_VPN_SOURCE


def test_registry_has_the_three_provided_sources_with_unique_names():
    assert set(SOURCES) == {
        "tor-project-bulk-exit-list",
        "x4bnet-lists-vpn",
        "az0-vpn-ip",
    }
    assert all(spec.name == key for key, spec in SOURCES.items())


def test_kinds_are_assigned_correctly():
    assert TOR_SOURCE.kind is EvidenceKind.TOR_EXIT
    assert X4BNET_VPN_SOURCE.kind is EvidenceKind.VPN_PROXY_ENDPOINT
    assert AZ0_VPN_SOURCE.kind is EvidenceKind.VPN_PROXY_ENDPOINT


def test_tor_source_uses_the_official_endpoint():
    assert TOR_SOURCE.endpoints == ("https://check.torproject.org/torbulkexitlist",)


def test_x4bnet_vpn_evidence_never_points_at_datacenter_lists():
    # Datacenter membership must never count as VPN evidence.
    for url in X4BNET_VPN_SOURCE.endpoints:
        assert "/output/vpn/" in url
        assert "datacenter" not in url.lower()
    assert not any(url.endswith("/main/ipv4.txt") for url in X4BNET_VPN_SOURCE.endpoints)


def test_az0_endpoints_are_the_requested_input_ip_directory():
    assert all("/data/input/ip/" in url for url in AZ0_VPN_SOURCE.endpoints)


@pytest.mark.parametrize("spec", list(SOURCES.values()), ids=lambda s: s.name)
def test_every_source_documents_licence_attribution_and_limits(spec):
    assert spec.license.strip()
    assert spec.attribution.strip()
    assert spec.limitations
    assert spec.temporal_support == "current-only"
    assert all(url.startswith("https://") for url in spec.endpoints)


def test_copyleft_source_is_flagged_not_for_bundling():
    assert "GPL" in AZ0_VPN_SOURCE.license
    assert "Do not bundle" in AZ0_VPN_SOURCE.license


# ------------------------------------------------------------- Stage 2 policies
def test_az0_dns_resolver_file_is_excluded_by_policy():
    assert len(AZ0_VPN_SOURCE.endpoints) == 5
    assert not any(url.endswith("/nordvpn.txt") for url in AZ0_VPN_SOURCE.endpoints)
    assert any("nordvpn.txt" in text and "DNS" in text for text in AZ0_VPN_SOURCE.exclusions)


def test_x4bnet_apple_exclusion_list_is_auxiliary_not_evidence():
    assert X4BNET_VPN_SOURCE.auxiliary_endpoints == (
        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ips/apple.txt",
    )
    assert not set(X4BNET_VPN_SOURCE.auxiliary_endpoints) & set(X4BNET_VPN_SOURCE.endpoints)
    assert any("Apple Private Relay" in text for text in X4BNET_VPN_SOURCE.exclusions)
    assert any("Datacenter" in text for text in X4BNET_VPN_SOURCE.exclusions)
