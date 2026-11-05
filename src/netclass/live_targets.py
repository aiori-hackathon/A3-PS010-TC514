"""The default list of files that live verification probes.

Built ONLY from the endpoints and sanity floors that the adapters already use, so the
verifier can never check a different URL than the classifier would download. No
endpoint is invented here; tests/test_live_targets.py pins that equivalence.
"""
from __future__ import annotations

from typing import Optional

from .adapters.az0 import AZ0_MIN_TOTAL
from .adapters.tor import TOR_MIN_ENTRIES
from .adapters.x4bnet import X4B_MIN_APPLE, X4B_MIN_V4, X4B_MIN_V6
from .live_verify import KIND_CIDR_LIST, KIND_IP_LIST, ProbeTarget
from .sources import AZ0_VPN_SOURCE, TOR_SOURCE, X4BNET_VPN_SOURCE

# Floors that apply to the sum over a group of files (az0 spans several files).
GROUP_FLOORS = {"az0": AZ0_MIN_TOTAL}


def default_targets(tor_url: Optional[str] = None) -> list[ProbeTarget]:
    v4_url, v6_url = X4BNET_VPN_SOURCE.endpoints
    targets = [
        ProbeTarget(
            TOR_SOURCE.name,
            "torbulkexitlist",
            tor_url or TOR_SOURCE.endpoints[0],
            KIND_IP_LIST,
            TOR_MIN_ENTRIES,
            overlap_key="tor",
        ),
        ProbeTarget(
            X4BNET_VPN_SOURCE.name, "ipv4.txt", v4_url, KIND_CIDR_LIST, X4B_MIN_V4,
            family=4, overlap_key="vpn_cidr_v4",
        ),
        ProbeTarget(
            X4BNET_VPN_SOURCE.name, "ipv6.txt", v6_url, KIND_CIDR_LIST, X4B_MIN_V6,
            family=6, overlap_key="vpn_cidr_v6",
        ),
        ProbeTarget(
            X4BNET_VPN_SOURCE.name, "apple.txt", X4BNET_VPN_SOURCE.auxiliary_endpoints[0],
            KIND_CIDR_LIST, X4B_MIN_APPLE, role="exclusion", overlap_key="apple",
        ),
    ]
    for url in sorted(AZ0_VPN_SOURCE.endpoints):
        targets.append(
            ProbeTarget(
                AZ0_VPN_SOURCE.name, url.rsplit("/", 1)[-1], url, KIND_IP_LIST, 1,
                overlap_key="az0",
            )
        )
    return targets
