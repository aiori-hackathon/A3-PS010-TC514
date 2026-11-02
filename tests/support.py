"""Shared fixtures for adapter and end-to-end tests (no network)."""
from __future__ import annotations

from dataclasses import dataclass

from factories import T0
from fakes import FakeFetcher, MutableClock, cidr_body, ip_body
from netclass.adapters import Az0VpnIpAdapter, TorExitListAdapter, X4BNetVpnAdapter
from netclass.cache import SnapshotStore
from netclass.snapshots import SnapshotProvider
from netclass.sources import AZ0_VPN_SOURCE, TOR_SOURCE, X4BNET_VPN_SOURCE

TOR_URL = TOR_SOURCE.endpoints[0]
X4_V4, X4_V6 = X4BNET_VPN_SOURCE.endpoints
APPLE_URL = X4BNET_VPN_SOURCE.auxiliary_endpoints[0]
AZ0_URLS = AZ0_VPN_SOURCE.endpoints
AZ0 = {url.rsplit("/", 1)[-1]: url for url in AZ0_URLS}

# Arbitrary global addresses used as fixtures; NOT claims about real Tor/VPN hosts.
TOR_IP = "185.220.101.45"
TOR_V6 = "2001:67c:e60::1"
VPN_IP = "45.83.64.10"  # inside the fixture X4BNet range 45.83.64.0/24
VPN_V6_IP = "2a0d:5600::1234"
AZ0_IP = "91.207.175.10"  # listed in the fixture pia.txt
CLEAN_IP = "8.8.8.8"
APPLE_IP = "104.28.28.10"  # inside a fixture Apple Private Relay CIDR
DNS_RESOLVER_IP = "103.86.99.99"  # the kind of address nordvpn.txt holds

ALL_SOURCE_URLS = {TOR_URL, X4_V4, X4_V6, APPLE_URL, *AZ0_URLS}


def standard_routes(**overrides) -> dict:
    """A healthy world. Override any URL by passing routes={url: ...} via `extra`."""
    routes = {
        TOR_URL: ip_body([TOR_IP, "185.220.101.46"]),
        X4_V4: cidr_body(["45.83.64.0/24", "104.28.28.0/26"]),
        X4_V6: cidr_body(["2a0d:5600::/32"]),
        APPLE_URL: cidr_body(["104.28.28.0/26"]),
        AZ0["pia.txt"]: ip_body([AZ0_IP + "  # CA Montreal", "91.207.175.11"]),
        AZ0["expressvpn.txt"]: ip_body(["91.207.176.1"]),
        AZ0["nordvpn_api.txt"]: ip_body(["91.207.177.1"]),
        AZ0["hideme.txt"]: ip_body(["91.207.178.1"]),
        AZ0["hideme_api.txt"]: ip_body(["91.207.179.1"]),
        # Present upstream but deliberately never fetched by the adapters:
        "https://raw.githubusercontent.com/az0/vpn_ip/main/data/input/ip/nordvpn.txt": ip_body(
            [DNS_RESOLVER_IP, "103.86.96.96"], header="# NordVPN DNS\n"
        ),
    }
    routes.update(overrides)
    return routes


@dataclass
class Stack:
    clock: MutableClock
    fetcher: FakeFetcher
    provider: SnapshotProvider
    store: SnapshotStore


def make_stack(tmp_path, routes=None, *, ttl=1800, max_source_age=None) -> Stack:
    clock = MutableClock(T0)
    fetcher = FakeFetcher(standard_routes() if routes is None else routes, clock)
    store = SnapshotStore(tmp_path / "cache")
    provider = SnapshotProvider(
        fetcher, store, ttl_seconds=ttl, clock=clock, max_source_age_seconds=max_source_age
    )
    return Stack(clock, fetcher, provider, store)


# Adapters with floors lowered to 1 so small fixtures are accepted. Floor
# behaviour itself is tested separately with the real defaults.
def tor_adapter(stack: Stack, **kwargs) -> TorExitListAdapter:
    kwargs.setdefault("min_entries", 1)
    return TorExitListAdapter(stack.provider, clock=stack.clock, **kwargs)


def x4_adapter(stack: Stack, **kwargs) -> X4BNetVpnAdapter:
    for key in ("min_v4", "min_v6", "min_apple"):
        kwargs.setdefault(key, 1)
    return X4BNetVpnAdapter(stack.provider, clock=stack.clock, **kwargs)


def az0_adapter(stack: Stack, **kwargs) -> Az0VpnIpAdapter:
    kwargs.setdefault("min_total_entries", 1)
    return Az0VpnIpAdapter(stack.provider, clock=stack.clock, **kwargs)


def all_adapters(stack: Stack):
    return [tor_adapter(stack), x4_adapter(stack), az0_adapter(stack)]
