"""Mocked IPinfo Lite response builders shared by the Stage 4 tests.

Bodies follow the Lite response documented at https://ipinfo.io/developers/lite-api
(ip, asn, as_name, as_domain, country_code, country, continent_code, continent).
Values are arbitrary fixtures (documentation ASNs and example domains), not claims
about real networks. TOKEN is a made-up fixture, never a real credential.
"""
import json

from factories import T0
from fakes import FakeFetcher, MutableClock
from netclass.errors import SourceError, SourceErrorKind
from netclass.ipinfo import IpInfoService

IP = "8.8.8.8"
IP6 = "2001:4860:4860::8888"
TOKEN = "tok_FIXTURE_0123456789abcdef"


def lite(ip=IP, **overrides) -> bytes:
    doc = {
        "ip": ip,
        "asn": "AS64496",
        "as_name": "EXAMPLE-NET Example Networks",
        "as_domain": "example.net",
        "country_code": "US",
        "country": "United States",
        "continent_code": "NA",
        "continent": "North America",
    }
    doc.update(overrides)
    for key in [k for k, v in doc.items() if v is _DROP]:
        del doc[key]
    return json.dumps(doc).encode()


_DROP = object()
DROP = _DROP  # pass DROP as a value to remove a field from the document


def make(routes=None, *, token=TOKEN, ttl=3600, **kwargs):
    """A service wired to a FakeFetcher. Routes are keyed by the (token-free) URL."""
    clock = MutableClock(T0)
    fetcher = FakeFetcher(routes or {}, clock)
    service = IpInfoService(fetcher, token=token, cache_ttl_seconds=ttl, clock=clock, **kwargs)
    return service, fetcher, clock


def url_for(ip=IP, base="https://api.ipinfo.io"):
    return f"{base}/lite/{ip}"


def http_error(url, status):
    return SourceError(
        SourceErrorKind.HTTP_STATUS, f"HTTP {status} (expected 200)", url=url, status_code=status
    )
