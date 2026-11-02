"""Builds the adapters from settings and gathers evidence for one observation."""
from __future__ import annotations

from typing import Iterable, Optional

from .adapters import Az0VpnIpAdapter, EvidenceAdapter, TorExitListAdapter, X4BNetVpnAdapter
from .address_policy import assess_address
from .cache import SnapshotStore
from .classifier import classify
from .config import Settings
from .http_client import Clock, Fetcher, RequestsFetcher, utc_now
from .ipinfo import MAX_RESPONSE_BYTES as IPINFO_MAX_RESPONSE_BYTES
from .ipinfo import IpInfoService, valid_token_format
from .models import ClassificationResult, EvidenceRecord, NetworkContext, Observation
from .ripestat import MAX_RESPONSE_BYTES, RipeStatContext, RipeStatContextService
from .snapshots import SnapshotProvider
from .sources import AZ0_VPN_SOURCE, TOR_SOURCE, X4BNET_VPN_SOURCE


def build_adapters(
    settings: Settings,
    *,
    fetcher: Optional[Fetcher] = None,
    clock: Clock = utc_now,
) -> list[EvidenceAdapter]:
    """Create the enabled adapters sharing one fetcher, cache and freshness policy."""
    fetcher = fetcher or RequestsFetcher(
        timeout_seconds=settings.http_timeout_seconds,
        max_bytes=settings.max_download_bytes,
        clock=clock,
    )
    provider = SnapshotProvider(
        fetcher,
        SnapshotStore(settings.cache_dir),
        ttl_seconds=settings.cache_ttl_seconds,
        clock=clock,
        max_source_age_seconds=settings.max_source_age_seconds,
    )
    makers = {
        TOR_SOURCE.name: lambda: TorExitListAdapter(
            provider, url=settings.tor_exit_list_url, clock=clock
        ),
        X4BNET_VPN_SOURCE.name: lambda: X4BNetVpnAdapter(provider, clock=clock),
        AZ0_VPN_SOURCE.name: lambda: Az0VpnIpAdapter(provider, clock=clock),
    }
    return [makers[name]() for name in settings.enabled_sources]


def collect_evidence(
    observation: Observation, adapters: Iterable[EvidenceAdapter]
) -> list[EvidenceRecord]:
    """One evidence record per adapter. Excluded addresses trigger no lookups at all."""
    if not assess_address(observation.ip).allowed:
        return []
    return [adapter.lookup(observation.ip) for adapter in adapters]


def classify_with_evidence(
    observation: Observation,
    adapters: Iterable[EvidenceAdapter],
    settings: Settings,
    *,
    context: Optional[NetworkContext] = None,
) -> tuple[ClassificationResult, list[EvidenceRecord]]:
    records = collect_evidence(observation, adapters)
    result = classify(
        observation, records, context, current_tolerance=settings.current_evidence_tolerance
    )
    return result, records


# --------------------------------------------------------------------------
# Stage 3B: optional RIPEstat network context (never evidence)
# --------------------------------------------------------------------------
def build_context_service(
    settings: Settings,
    *,
    fetcher: Optional[Fetcher] = None,
    clock: Clock = utc_now,
) -> RipeStatContextService:
    """Create the RIPEstat context service from settings.

    It gets its own small-response fetcher (the evidence fetcher allows 20 MB
    downloads, far more than a RIPEstat JSON answer needs).
    """
    fetcher = fetcher or RequestsFetcher(
        timeout_seconds=settings.http_timeout_seconds,
        max_bytes=MAX_RESPONSE_BYTES,
        clock=clock,
    )
    return RipeStatContextService(
        fetcher,
        base_url=settings.ripestat_base_url,
        sourceapp=settings.ripestat_sourceapp,
        cache_ttl_seconds=settings.ripestat_cache_ttl_seconds,
        clock=clock,
    )


def classify_with_context(
    observation: Observation,
    adapters: Iterable[EvidenceAdapter],
    settings: Settings,
    context_service: RipeStatContextService,
) -> tuple[ClassificationResult, list[EvidenceRecord], RipeStatContext]:
    """Collect evidence, fetch RIPEstat context, classify.

    The context is passed to the classifier only as display metadata
    (``NetworkContext`` with ``hosting_indicator`` always False). The label and
    reason code are therefore exactly what ``classify_with_evidence`` would
    return; this is pinned by tests/test_ripestat_invariance.py.
    """
    records = collect_evidence(observation, adapters)
    ripe = context_service.lookup(observation.ip)
    result = classify(
        observation,
        records,
        ripe.to_network_context(),
        current_tolerance=settings.current_evidence_tolerance,
    )
    return result, records, ripe


# --------------------------------------------------------------------------
# Stage 4: optional IPinfo supplementary metadata (never evidence)
# --------------------------------------------------------------------------
def build_ipinfo_service(
    settings: Settings,
    *,
    fetcher: Optional[Fetcher] = None,
    clock: Clock = utc_now,
) -> IpInfoService:
    """Create the IPinfo metadata service from settings.

    Without ``IPINFO_TOKEN`` (or with a token in an unusable format) the returned
    service is DISABLED: it makes no request and reports that explicitly. The
    token is sent only in an ``Authorization`` header of the service's own fetcher,
    never in a URL.
    """
    token = settings.ipinfo_token
    if fetcher is None and valid_token_format(token):
        fetcher = RequestsFetcher(
            timeout_seconds=settings.http_timeout_seconds,
            max_bytes=IPINFO_MAX_RESPONSE_BYTES,
            extra_headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            clock=clock,
        )
    return IpInfoService(
        fetcher,
        token=token,
        base_url=settings.ipinfo_base_url,
        cache_ttl_seconds=settings.ipinfo_cache_ttl_seconds,
        clock=clock,
    )
