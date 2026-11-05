"""Mocked RIPEstat response builders shared by the RIPEstat tests.

Bodies follow the envelope documented at https://stat.ripe.net/docs/data-api/
(status, status_code, data_call_name, data_call_status, version, cached,
process_time, data). Values are arbitrary fixtures, not claims about real networks.
"""
import json

from fakes import MutableClock, FakeFetcher
from factories import T0
from netclass.errors import SourceError, SourceErrorKind
from netclass.ripestat import AS_OVERVIEW_CALL, NETWORK_INFO_CALL, RipeStatContextService

IP = "8.8.8.8"
IP6 = "2001:4860:4860::8888"


def envelope(call, data, **overrides):
    doc = {
        "status": "ok",
        "status_code": 200,
        "data_call_name": call,
        "data_call_status": "supported",
        "version": "1.1",
        "cached": False,
        "process_time": "12",
        "data": data,
    }
    doc.update(overrides)
    return json.dumps(doc).encode()


def ni(asns=("15169",), prefix="8.8.8.0/24", **overrides):
    data = {}
    if asns is not None:
        data["asns"] = list(asns)
    if prefix is not None:
        data["prefix"] = prefix
    return envelope(NETWORK_INFO_CALL, data, **overrides)


def ao(asn=15169, holder="EXAMPLE-HOLDER - Example Holder Inc.", announced=True, **overrides):
    data = {"resource": str(asn), "type": "as", "announced": announced, "holder": holder}
    return envelope(AS_OVERVIEW_CALL, data, **overrides)


def make(routes=None, *, ttl=3600, **kwargs):
    clock = MutableClock(T0)
    fetcher = FakeFetcher(routes or {}, clock)
    service = RipeStatContextService(fetcher, cache_ttl_seconds=ttl, clock=clock, **kwargs)
    return service, fetcher, clock


def healthy(service, ip=IP, asn=15169, prefix="8.8.8.0/24", holder="EXAMPLE-HOLDER"):
    return {
        service.build_url(NETWORK_INFO_CALL, ip): ni([str(asn)], prefix),
        service.build_url(AS_OVERVIEW_CALL, f"AS{asn}"): ao(asn, holder),
    }


def http_error(url, status):
    return SourceError(
        SourceErrorKind.HTTP_STATUS, f"HTTP {status} (expected 200)", url=url, status_code=status
    )
