"""RIPEstat network-context service (Stage 3B).

PURPOSE
    Provide registration and routing CONTEXT for an IP address: the ASN(s) that
    announce it, the covering announced prefix and the registered ASN holder
    name. This is metadata for a human reader or a dashboard.

WHAT THIS MODULE MUST NEVER DO
    * It never produces a classification label, a reason code or an
      EvidenceRecord. It does not import the classifier or the Label enum.
    * It never sets ``NetworkContext.hosting_indicator``. An ASN, a holder name
      containing "hosting"/"cloud"/"VPN", or a prefix owned by a data centre is
      NOT evidence of VPN/proxy use or Tor use.

DOCUMENTED ENDPOINTS USED (https://stat.ripe.net/docs/data-api/)
    GET {base}/network-info/data.json?resource=<ip>
        documented output: ``asns`` (ASNs the prefix is announced from) and
        ``prefix`` (matching prefix, if routed). Based on RISwhois 8-hourly dumps.
    GET {base}/as-overview/data.json?resource=AS<n>
        documented output used here: ``holder`` (descriptive name of the ASN
        holder, null if not registered by an RIR) and ``announced``.
    Common envelope fields (documented): status, status_code, data_call_status,
    data_call_name, version, cached, message, process_time, data.

FAILURE POLICY
    ``lookup`` never raises. Anything that prevents trustworthy data (timeout,
    connection failure, HTTP error, HTTP 429, invalid JSON, API ``status`` other
    than "ok", an unexpected structure) becomes an explicit UNAVAILABLE section
    with a typed error. Errors are never cached and never turned into an
    empty-but-successful result.

FRESHNESS
    Successful responses are held in a small in-memory cache for
    ``cache_ttl_seconds``. An entry older than the TTL is never served, even if
    the refresh fails. Cache hits keep the ORIGINAL retrieval time and are
    flagged ``from_cache``. Nothing is written to disk (queried IP addresses are
    not persisted by this service).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Callable, Optional
from urllib.parse import quote, urlencode

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .address_policy import AddressCategory, assess_address
from .errors import SourceError, SourceErrorKind
from .hashing import sha256_hex
from .http_client import Clock, Fetcher, utc_now
from .models import NetworkContext

logger = logging.getLogger(__name__)

RIPESTAT_SOURCE_NAME = "ripestat-data-api"
DEFAULT_BASE_URL = "https://stat.ripe.net/data"
NETWORK_INFO_CALL = "network-info"
AS_OVERVIEW_CALL = "as-overview"

# Responses from these two calls are a few hundred bytes. A small cap makes a
# wrong/hostile response fail fast (used by collector.build_context_service).
MAX_RESPONSE_BYTES = 1_000_000

_SOURCEAPP_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # documented: alphanumerics, - and _
_ASN_TEXT_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
_MAX_ASN = 4_294_967_295
_MAX_HOLDER_LENGTH = 256
_MISSING = object()

LIMITATIONS: tuple[str, ...] = (
    "Contextual metadata only: it is not evidence and never changes the Tor / VPN-proxy label.",
    "An ASN, an ASN holder name or an announced prefix does not show that an address is "
    "used for VPN, proxy or Tor.",
    "network-info is derived from RIPE RIS (RISwhois, 8-hourly dumps); it describes routing "
    "at retrieval time, not necessarily at the observation time.",
    "The holder name is the free-text name registered for the ASN, not for the individual address.",
)


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
class ContextStatus(StrEnum):
    AVAILABLE = "AVAILABLE"  # every attempted lookup succeeded
    PARTIAL = "PARTIAL"  # routing succeeded but at least one holder lookup failed
    UNAVAILABLE = "UNAVAILABLE"  # no usable context could be retrieved (see `error`/sections)
    NOT_QUERIED = "NOT_QUERIED"  # address excluded by policy; no request was made


class SectionStatus(StrEnum):
    OK = "OK"  # response valid and contains data
    EMPTY = "EMPTY"  # response valid; RIPEstat reports nothing (e.g. address not routed)
    UNAVAILABLE = "UNAVAILABLE"  # could not be retrieved / parsed; see `error`


class ContextErrorKind(StrEnum):
    TIMEOUT = "TIMEOUT"
    CONNECTION = "CONNECTION"
    HTTP_ERROR = "HTTP_ERROR"  # any HTTP status other than 200 and 429
    RATE_LIMITED = "RATE_LIMITED"  # HTTP 429
    TOO_LARGE = "TOO_LARGE"
    INVALID_JSON = "INVALID_JSON"
    UNEXPECTED_STRUCTURE = "UNEXPECTED_STRUCTURE"
    API_ERROR = "API_ERROR"  # envelope status "error"
    API_MAINTENANCE = "API_MAINTENANCE"  # envelope status "maintenance"
    INVALID_INPUT = "INVALID_INPUT"
    INTERNAL = "INTERNAL"


# --------------------------------------------------------------------------
# Result models (all frozen, all datetimes timezone-aware UTC)
# --------------------------------------------------------------------------
def _utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware (UTC); naive datetimes are rejected")
    return value.astimezone(timezone.utc)


class ContextError(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ContextErrorKind
    message: str = Field(min_length=1)
    endpoint: Optional[str] = None
    http_status: Optional[int] = None
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def _tz(cls, value: datetime) -> datetime:
        result = _utc(value)
        assert result is not None
        return result


class Provenance(BaseModel):
    """Where a section's data came from and when."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_name: str = RIPESTAT_SOURCE_NAME
    data_call: str
    endpoint: str  # the exact URL requested
    retrieved_at: datetime  # when the response was received (original time on a cache hit)
    from_cache: bool = False
    response_sha256: str  # SHA-256 of the raw response body
    api_version: Optional[str] = None  # envelope `version`, if present
    data_call_status: Optional[str] = None  # envelope `data_call_status`, if present
    api_reported_cached: Optional[bool] = None  # envelope `cached`, if present

    @field_validator("retrieved_at")
    @classmethod
    def _tz(cls, value: datetime) -> datetime:
        result = _utc(value)
        assert result is not None
        return result


class _Section(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: SectionStatus
    provenance: Optional[Provenance] = None
    error: Optional[ContextError] = None
    warnings: list[str] = Field(default_factory=list)  # tolerated oddities in a valid response

    @model_validator(mode="after")
    def _consistent(self):
        if self.status is SectionStatus.UNAVAILABLE:
            if self.error is None:
                raise ValueError("an UNAVAILABLE section must carry an error")
            if self.provenance is not None:
                raise ValueError("an UNAVAILABLE section must not carry data provenance")
        else:
            if self.provenance is None:
                raise ValueError("a successful section must carry provenance")
            if self.error is not None:
                raise ValueError("a successful section must not carry an error")
        return self


class RoutingSection(_Section):
    """network-info: announcing ASN(s) and covering prefix."""

    asns: tuple[int, ...] = ()
    prefix: Optional[str] = None


class HolderSection(_Section):
    """as-overview: registered holder of one ASN."""

    asn: int = Field(ge=0)
    holder: Optional[str] = None
    announced: Optional[bool] = None  # RIPEstat definition: originates prefixes seen by >=10 RIS peers


class RipeStatContext(BaseModel):
    """Everything the service learned about one address. Context, not evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ip: str
    status: ContextStatus
    requested_at: datetime
    routing: Optional[RoutingSection] = None
    holders: list[HolderSection] = Field(default_factory=list)
    error: Optional[ContextError] = None  # set for INVALID_INPUT only
    note: Optional[str] = None  # set when NOT_QUERIED
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))

    @field_validator("requested_at")
    @classmethod
    def _tz(cls, value: datetime) -> datetime:
        result = _utc(value)
        assert result is not None
        return result

    # ------------------------------------------------------------------
    @property
    def usable(self) -> bool:
        return self.status in (ContextStatus.AVAILABLE, ContextStatus.PARTIAL)

    def to_network_context(self) -> Optional[NetworkContext]:
        """Project onto the existing display model, or None if there is nothing to show.

        * Returns None when the context is unavailable / not queried, or when
          RIPEstat reported no ASN and no prefix. Nothing is invented.
        * ``asn``/``as_name`` are filled only when exactly one origin ASN is
          reported; with several origins the choice would be arbitrary, so they
          stay empty (the full list remains on this object).
        * ``hosting_indicator`` is ALWAYS False. This service has no basis for it.
        * ``retrieved_at`` is the OLDEST retrieval time among the sections used.
        """
        if not self.usable or self.routing is None:
            return None
        routing = self.routing
        if routing.status is SectionStatus.UNAVAILABLE or routing.provenance is None:
            return None
        asn = routing.asns[0] if len(routing.asns) == 1 else None
        if asn is None and routing.prefix is None:
            return None
        as_name: Optional[str] = None
        times = [routing.provenance.retrieved_at]
        if asn is not None:
            for holder in self.holders:
                if holder.asn == asn and holder.status is SectionStatus.OK and holder.provenance:
                    as_name = holder.holder
                    times.append(holder.provenance.retrieved_at)
        return NetworkContext(
            asn=asn,
            as_name=as_name,
            prefix=routing.prefix,
            source_name=RIPESTAT_SOURCE_NAME,
            retrieved_at=min(times),
            hosting_indicator=False,
            hosting_indicator_basis=None,
        )


# --------------------------------------------------------------------------
# Response parsing (pure functions; raise _ParseError)
# --------------------------------------------------------------------------
class _ParseError(Exception):
    def __init__(self, kind: ContextErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


class _Envelope:
    def __init__(self, data: dict, meta: dict, warnings: list[str]) -> None:
        self.data = data
        self.meta = meta  # api_version, data_call_status, api_reported_cached
        self.warnings = warnings


def _decode_envelope(body: bytes, expected_call: str) -> _Envelope:
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _ParseError(
            ContextErrorKind.INVALID_JSON, f"response is not valid UTF-8 JSON ({type(exc).__name__})"
        ) from exc
    if not isinstance(document, dict):
        raise _ParseError(
            ContextErrorKind.UNEXPECTED_STRUCTURE,
            f"top-level JSON value is {type(document).__name__}, expected an object",
        )

    status = document.get("status", _MISSING)
    if status == "error":
        text = document.get("message")
        detail = f": {text}" if isinstance(text, str) and text.strip() else ""
        raise _ParseError(ContextErrorKind.API_ERROR, f'RIPEstat reported status "error"{detail}')
    if status == "maintenance":
        raise _ParseError(
            ContextErrorKind.API_MAINTENANCE, 'RIPEstat reported status "maintenance" for this data call'
        )
    if status is _MISSING:
        raise _ParseError(ContextErrorKind.UNEXPECTED_STRUCTURE, 'envelope has no "status" field')
    if status != "ok":
        raise _ParseError(
            ContextErrorKind.UNEXPECTED_STRUCTURE, f"envelope status is {status!r}, expected \"ok\""
        )

    name = document.get("data_call_name")
    if name is not None and name != expected_call:
        raise _ParseError(
            ContextErrorKind.UNEXPECTED_STRUCTURE,
            f"response is for data call {name!r}, expected {expected_call!r}",
        )
    data = document.get("data", _MISSING)
    if not isinstance(data, dict):
        raise _ParseError(
            ContextErrorKind.UNEXPECTED_STRUCTURE,
            'envelope "data" is missing or not an object',
        )

    warnings: list[str] = []
    meta: dict[str, Any] = {"api_version": None, "data_call_status": None, "api_reported_cached": None}
    version = document.get("version")
    if isinstance(version, str) and version:
        meta["api_version"] = version
    dcs = document.get("data_call_status")
    if isinstance(dcs, str) and dcs:
        meta["data_call_status"] = dcs
        if dcs.lower().startswith("deprecated"):
            warnings.append(f"RIPEstat marks the {expected_call} data call as deprecated ({dcs})")
        elif dcs.lower() == "development":
            warnings.append(f"RIPEstat marks the {expected_call} data call as in development")
    cached = document.get("cached")
    if isinstance(cached, bool):
        meta["api_reported_cached"] = cached
    return _Envelope(data, meta, warnings)


def _parse_asn(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        match = _ASN_TEXT_RE.match(value.strip())
        if not match:
            return None
        number = int(match.group(1))
    else:
        return None
    return number if 0 <= number <= _MAX_ASN else None


def _clean_text(value: Any, limit: int = _MAX_HOLDER_LENGTH) -> Optional[str]:
    """Printable single-line text, or None. Long values are truncated."""
    if not isinstance(value, str):
        return None
    text = "".join(ch if ch.isprintable() else " " for ch in value)
    text = " ".join(text.split())
    if not text:
        return None
    return text[:limit]


def parse_network_info(body: bytes, ip: str) -> tuple[tuple[int, ...], Optional[str], _Envelope, list[str]]:
    envelope = _decode_envelope(body, NETWORK_INFO_CALL)
    data = envelope.data
    warnings = list(envelope.warnings)

    asns_raw = data.get("asns", _MISSING)
    prefix_raw = data.get("prefix", _MISSING)
    if asns_raw is _MISSING and prefix_raw is _MISSING:
        raise _ParseError(
            ContextErrorKind.UNEXPECTED_STRUCTURE, 'network-info data has neither "asns" nor "prefix"'
        )

    asns: list[int] = []
    if asns_raw is _MISSING:
        warnings.append('network-info response has no "asns" field')
    elif asns_raw is None:
        pass
    elif not isinstance(asns_raw, list):
        raise _ParseError(
            ContextErrorKind.UNEXPECTED_STRUCTURE,
            f'"asns" is {type(asns_raw).__name__}, expected a list',
        )
    else:
        rejected = 0
        for item in asns_raw:
            parsed = _parse_asn(item)
            if parsed is None:
                rejected += 1
            else:
                asns.append(parsed)
        if asns_raw and not asns:
            raise _ParseError(
                ContextErrorKind.UNEXPECTED_STRUCTURE, '"asns" contains no valid ASN values'
            )
        if rejected:
            warnings.append(f'ignored {rejected} unparseable value(s) in "asns"')

    prefix: Optional[str] = None
    if prefix_raw is _MISSING:
        warnings.append('network-info response has no "prefix" field')
    elif prefix_raw is None or (isinstance(prefix_raw, str) and not prefix_raw.strip()):
        pass
    elif not isinstance(prefix_raw, str):
        raise _ParseError(
            ContextErrorKind.UNEXPECTED_STRUCTURE,
            f'"prefix" is {type(prefix_raw).__name__}, expected a string',
        )
    else:
        try:
            network = ipaddress.ip_network(prefix_raw.strip(), strict=True)
        except ValueError:
            warnings.append("ignored a prefix that is not a valid CIDR network")
        else:
            if ipaddress.ip_address(ip) not in network:
                # The documented meaning is "prefix that the queried resource matches".
                raise _ParseError(
                    ContextErrorKind.UNEXPECTED_STRUCTURE,
                    f"returned prefix {network} does not contain the queried address {ip}",
                )
            prefix = str(network)

    return tuple(sorted(set(asns))), prefix, envelope, warnings


def parse_as_overview(
    body: bytes, asn: int
) -> tuple[Optional[str], Optional[bool], _Envelope, list[str]]:
    envelope = _decode_envelope(body, AS_OVERVIEW_CALL)
    data = envelope.data
    warnings = list(envelope.warnings)

    resource = data.get("resource", _MISSING)
    if resource is not _MISSING:
        if _parse_asn(resource) != asn:
            raise _ParseError(
                ContextErrorKind.UNEXPECTED_STRUCTURE,
                f"response is for resource {resource!r}, expected AS{asn}",
            )

    holder_raw = data.get("holder", _MISSING)
    holder: Optional[str] = None
    if holder_raw is _MISSING:
        warnings.append('as-overview response has no "holder" field')
    elif holder_raw is not None:
        if not isinstance(holder_raw, str):
            warnings.append('ignored a "holder" value that is not text')
        else:
            holder = _clean_text(holder_raw)  # blank text -> None (nothing registered)
            if holder is not None and len(" ".join(holder_raw.split())) > _MAX_HOLDER_LENGTH:
                warnings.append(f"holder name truncated to {_MAX_HOLDER_LENGTH} characters")

    announced_raw = data.get("announced", _MISSING)
    announced: Optional[bool] = None
    if isinstance(announced_raw, bool):
        announced = announced_raw
    elif announced_raw is not _MISSING and announced_raw is not None:
        warnings.append('ignored an "announced" value that is not a boolean')
    return holder, announced, envelope, warnings


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------
class _TtlCache:
    """Small in-memory cache of raw successful response bodies."""

    def __init__(self, ttl: timedelta, max_entries: int) -> None:
        self._ttl = ttl
        self._max = max_entries
        self._items: "OrderedDict[tuple[str, str], tuple[bytes, datetime, str]]" = OrderedDict()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._ttl > timedelta(0) and self._max > 0

    def get(self, key: tuple[str, str], now: datetime) -> Optional[tuple[bytes, datetime, str]]:
        if not self.enabled:
            return None
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            age = now - entry[1]
            if timedelta(0) <= age <= self._ttl:
                return entry
            del self._items[key]  # expired (or clock moved backwards): never served
            return None

    def put(self, key: tuple[str, str], body: bytes, retrieved_at: datetime, url: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._items[key] = (body, retrieved_at, url)
            self._items.move_to_end(key)
            while len(self._items) > self._max:
                self._items.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------
class RipeStatContextService:
    def __init__(
        self,
        fetcher: Fetcher,
        *,
        base_url: str = DEFAULT_BASE_URL,
        sourceapp: Optional[str] = None,
        cache_ttl_seconds: int = 3600,
        max_cache_entries: int = 2048,
        max_holder_lookups: int = 3,
        clock: Clock = utc_now,
    ) -> None:
        base = base_url.strip().rstrip("/")
        if not base.lower().startswith("https://"):
            raise ValueError("RIPEstat base URL must use https")
        if sourceapp is not None and not _SOURCEAPP_RE.match(sourceapp):
            raise ValueError("sourceapp may only contain letters, digits, '-' and '_' (max 64)")
        if cache_ttl_seconds < 0 or max_cache_entries < 0:
            raise ValueError("cache settings must not be negative")
        if max_holder_lookups < 0:
            raise ValueError("max_holder_lookups must not be negative")
        self._fetcher = fetcher
        self._base = base
        self._sourceapp = sourceapp
        self._cache = _TtlCache(timedelta(seconds=cache_ttl_seconds), max_cache_entries)
        self._max_holders = max_holder_lookups
        self._clock = clock

    # ------------------------------------------------------------------
    def build_url(self, data_call: str, resource: str) -> str:
        params = {"resource": resource}
        if self._sourceapp:
            params["sourceapp"] = self._sourceapp
        return f"{self._base}/{data_call}/data.json?{urlencode(params, quote_via=quote, safe=':')}"

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    # ------------------------------------------------------------------
    def lookup(self, ip: str) -> RipeStatContext:
        """Retrieve context for one address. Never raises."""
        requested_at = self._clock()
        try:
            return self._lookup(ip, requested_at)
        except Exception as exc:  # defensive: a context failure must never break a caller
            logger.exception("Unexpected error in RIPEstat context service")
            return RipeStatContext(
                ip=ip if isinstance(ip, str) else repr(ip),
                status=ContextStatus.UNAVAILABLE,
                requested_at=requested_at,
                error=ContextError(
                    kind=ContextErrorKind.INTERNAL,
                    message=f"unexpected internal error ({type(exc).__name__})",
                    occurred_at=self._clock(),
                ),
            )

    def _lookup(self, ip: str, requested_at: datetime) -> RipeStatContext:
        assessment = assess_address(ip)
        if assessment.category is AddressCategory.INVALID or assessment.normalized is None:
            return RipeStatContext(
                ip=ip if isinstance(ip, str) else repr(ip),
                status=ContextStatus.UNAVAILABLE,
                requested_at=requested_at,
                error=ContextError(
                    kind=ContextErrorKind.INVALID_INPUT,
                    message=assessment.message,
                    occurred_at=requested_at,
                ),
            )
        address = assessment.normalized
        if not assessment.allowed:
            return RipeStatContext(
                ip=address,
                status=ContextStatus.NOT_QUERIED,
                requested_at=requested_at,
                note=f"No RIPEstat request was made: {assessment.message}",
            )

        routing = self._routing(address)
        if routing.status is SectionStatus.UNAVAILABLE:
            return RipeStatContext(
                ip=address,
                status=ContextStatus.UNAVAILABLE,
                requested_at=requested_at,
                routing=routing,
            )

        holders: list[HolderSection] = []
        limitations = list(LIMITATIONS)
        asns = routing.asns
        for asn in asns[: self._max_holders]:
            holders.append(self._holder(asn))
        if len(asns) > self._max_holders:
            limitations.append(
                f"{len(asns)} origin ASNs were reported; holder names were looked up for the "
                f"first {self._max_holders} (lowest numbers) only."
            )
        if len(asns) > 1:
            limitations.append(
                "Several origin ASNs announce this prefix (multi-origin); none is singled out."
            )
        if routing.status is SectionStatus.EMPTY:
            limitations.append(
                "RIPEstat reported no announced prefix/ASN for this address. That reflects RIS "
                "routing visibility only; it does not say anything about Tor or VPN use."
            )

        degraded = any(h.status is SectionStatus.UNAVAILABLE for h in holders)
        return RipeStatContext(
            ip=address,
            status=ContextStatus.PARTIAL if degraded else ContextStatus.AVAILABLE,
            requested_at=requested_at,
            routing=routing,
            holders=holders,
            limitations=limitations,
        )

    # ------------------------------------------------------------------
    def _routing(self, address: str) -> RoutingSection:
        url = self.build_url(NETWORK_INFO_CALL, address)
        outcome = self._retrieve(NETWORK_INFO_CALL, address, url, lambda b: parse_network_info(b, address))
        if isinstance(outcome, ContextError):
            return RoutingSection(status=SectionStatus.UNAVAILABLE, error=outcome)
        (asns, prefix, envelope, warnings), provenance = outcome
        status = SectionStatus.OK if (asns or prefix) else SectionStatus.EMPTY
        return RoutingSection(
            status=status, provenance=provenance, asns=asns, prefix=prefix, warnings=warnings
        )

    def _holder(self, asn: int) -> HolderSection:
        resource = f"AS{asn}"
        url = self.build_url(AS_OVERVIEW_CALL, resource)
        outcome = self._retrieve(AS_OVERVIEW_CALL, resource, url, lambda b: parse_as_overview(b, asn))
        if isinstance(outcome, ContextError):
            return HolderSection(asn=asn, status=SectionStatus.UNAVAILABLE, error=outcome)
        (holder, announced, envelope, warnings), provenance = outcome
        return HolderSection(
            asn=asn,
            status=SectionStatus.OK if holder else SectionStatus.EMPTY,
            provenance=provenance,
            holder=holder,
            announced=announced,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    def _retrieve(
        self, call: str, resource: str, url: str, parse: Callable[[bytes], tuple]
    ):
        """Cache-first retrieval. Returns ((parsed...), Provenance) or a ContextError."""
        key = (call, resource)
        now = self._clock()
        entry = self._cache.get(key, now)
        from_cache = entry is not None
        if entry is not None:
            body, retrieved_at, _cached_url = entry
        else:
            try:
                result = self._fetcher.fetch(url)
            except SourceError as exc:
                return self._map_source_error(exc, url)
            except Exception as exc:  # a misbehaving fetcher must not escape
                logger.exception("Unexpected fetcher failure")
                return ContextError(
                    kind=ContextErrorKind.INTERNAL,
                    message=f"unexpected fetch failure ({type(exc).__name__})",
                    endpoint=url,
                    occurred_at=self._clock(),
                )
            body, retrieved_at = result.body, result.retrieved_at

        try:
            parsed = parse(body)
        except _ParseError as exc:
            return ContextError(
                kind=exc.kind, message=exc.message, endpoint=url, occurred_at=self._clock()
            )
        except Exception as exc:  # parser bug: report, never fabricate
            logger.exception("Unexpected parser failure")
            return ContextError(
                kind=ContextErrorKind.INTERNAL,
                message=f"unexpected parse failure ({type(exc).__name__})",
                endpoint=url,
                occurred_at=self._clock(),
            )

        if not from_cache:
            self._cache.put(key, body, retrieved_at, url)  # only parsed, successful bodies

        envelope: _Envelope = parsed[2]
        provenance = Provenance(
            data_call=call,
            endpoint=url,
            retrieved_at=retrieved_at,
            from_cache=from_cache,
            response_sha256=sha256_hex(body),
            **envelope.meta,
        )
        return parsed, provenance

    def _map_source_error(self, exc: SourceError, url: str) -> ContextError:
        kind_map = {
            SourceErrorKind.TIMEOUT: ContextErrorKind.TIMEOUT,
            SourceErrorKind.CONNECTION: ContextErrorKind.CONNECTION,
            SourceErrorKind.TOO_LARGE: ContextErrorKind.TOO_LARGE,
        }
        if exc.kind is SourceErrorKind.HTTP_STATUS:
            kind = (
                ContextErrorKind.RATE_LIMITED
                if exc.status_code == 429
                else ContextErrorKind.HTTP_ERROR
            )
        else:
            kind = kind_map.get(exc.kind, ContextErrorKind.INTERNAL)
        message = exc.message
        if kind is ContextErrorKind.RATE_LIMITED:
            message += (
                " (rate limited; RIPEstat allows 8 concurrent requests per IP address; "
                "this service does not retry automatically)"
            )
        return ContextError(
            kind=kind,
            message=message,
            endpoint=url,
            http_status=exc.status_code,
            occurred_at=self._clock(),
        )
