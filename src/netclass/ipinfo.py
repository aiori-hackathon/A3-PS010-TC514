"""Optional IPinfo Lite supplementary-metadata service.

PURPOSE
    Provide ASN, network-operator name/domain and country/continent METADATA for a
    public IP address, for a human reader or a dashboard. It is supplementary
    information only.

WHAT THIS MODULE MUST NEVER DO
    * It never produces a classification label, a reason code or an
      EvidenceRecord. It does not import the classifier, ``Label``,
      ``ReasonCode``, ``EvidenceRecord`` or ``NetworkContext`` (pinned by an AST
      test). Its output is never passed to the classifier.
    * It never treats an ASN, an AS name or domain, or a country as evidence that
      an address is a Tor exit or a VPN/proxy endpoint.
    * It never invents a value: a field the API omits stays ``None``.

DOCUMENTED ENDPOINT USED (https://ipinfo.io/developers/lite-api)
    GET {base}/lite/{ip}        base default: https://api.ipinfo.io
        Authentication: ``Authorization: Bearer <token>`` (the documentation also
        lists Basic auth and a ``token`` query parameter; this service uses the
        header so the token never appears in a URL, a log line or an error message).
        Documented response fields (all read here): ``ip``, ``asn`` ("AS15169"),
        ``as_name``, ``as_domain``, ``country_code``, ``country``,
        ``continent_code``, ``continent``. Every other field is ignored.
    The Core/Plus ``lookup`` endpoint and any privacy, hosting or proxy fields are
    deliberately NOT used.

FAILURE POLICY
    ``lookup`` never raises. Disabled integration, excluded addresses, timeouts,
    connection failures, HTTP 401/403, HTTP 429, other HTTP errors, invalid JSON
    and unexpected structures all become an explicit status with a typed error.
    Errors are never cached and never turned into an empty-but-successful result.
    No automatic retry is made (consistent with the other services in this project).

SECRETS
    The token is read from configuration (``IPINFO_TOKEN``), is never part of a
    URL, repr, result model, log line or error message, and is redacted from any
    text that comes from a lower layer.

PRIVACY
    A real lookup sends the queried IP address to IPinfo. Excluded (private,
    reserved, loopback, link-local ...) addresses are never sent. Nothing is
    written to disk by this service (in-memory cache only).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Optional
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .address_policy import AddressCategory, assess_address
from .errors import SourceError, SourceErrorKind
from .hashing import sha256_hex
from .http_client import Clock, Fetcher, utc_now

# Shared small helpers of the context services (kept in one place on purpose).
from .ripestat import _TtlCache, _clean_text, _parse_asn

logger = logging.getLogger(__name__)

IPINFO_SOURCE_NAME = "ipinfo-lite-api"
DEFAULT_BASE_URL = "https://api.ipinfo.io"
LITE_PATH = "lite"

# A Lite answer is a few hundred bytes. A small cap makes a wrong response fail fast.
MAX_RESPONSE_BYTES = 100_000

_TOKEN_RE = re.compile(r"^[\x21-\x7e]{1,512}$")  # printable ASCII, no whitespace
_COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")
_MAX_NAME_LENGTH = 256
_MAX_DOMAIN_LENGTH = 253
_REDACTED = "[REDACTED]"
_TOKEN_PARAM_RE = re.compile(r"(?i)(token=)[^&\s'\"]+")
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[^\s'\"]+")
_MISSING = object()

# Fields read from the documented Lite response, in output order.
_TEXT_FIELDS = (
    ("as_name", _MAX_NAME_LENGTH),
    ("as_domain", _MAX_DOMAIN_LENGTH),
    ("country", _MAX_NAME_LENGTH),
    ("continent", _MAX_NAME_LENGTH),
)
_CODE_FIELDS = ("country_code", "continent_code")

LIMITATIONS: tuple[str, ...] = (
    "Supplementary metadata only: it is not evidence and never changes the Tor / VPN-proxy label.",
    "An ASN, an AS name or domain, or a country does not show that an address is used for "
    "VPN, proxy or Tor.",
    "The values describe what IPinfo associates with the address at retrieval time; they say "
    "nothing about the address's status at any other time.",
    "Only the documented IPinfo Lite fields are read. Any other field in a response is ignored "
    "and never interpreted.",
)


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
class IpInfoStatus(StrEnum):
    AVAILABLE = "AVAILABLE"  # valid response with at least one usable metadata field
    EMPTY = "EMPTY"  # valid response, but none of the metadata fields is present/usable
    UNAVAILABLE = "UNAVAILABLE"  # could not be retrieved / parsed (see `error`)
    NOT_QUERIED = "NOT_QUERIED"  # address excluded by policy; no request was made
    DISABLED = "DISABLED"  # no usable token configured; no request was made


class IpInfoErrorKind(StrEnum):
    TIMEOUT = "TIMEOUT"
    CONNECTION = "CONNECTION"
    AUTH_FAILED = "AUTH_FAILED"  # HTTP 401 / 403
    RATE_LIMITED = "RATE_LIMITED"  # HTTP 429
    SERVER_ERROR = "SERVER_ERROR"  # HTTP 5xx
    HTTP_ERROR = "HTTP_ERROR"  # any other status except 200
    TOO_LARGE = "TOO_LARGE"
    INVALID_JSON = "INVALID_JSON"
    UNEXPECTED_STRUCTURE = "UNEXPECTED_STRUCTURE"
    INVALID_INPUT = "INVALID_INPUT"
    INTERNAL = "INTERNAL"


# --------------------------------------------------------------------------
# Result models (frozen; datetimes timezone-aware UTC)
# --------------------------------------------------------------------------
def _utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware (UTC); naive datetimes are rejected")
    return value.astimezone(timezone.utc)


class IpInfoError(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: IpInfoErrorKind
    message: str = Field(min_length=1)
    endpoint: Optional[str] = None  # token-free URL
    http_status: Optional[int] = None
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def _tz(cls, value: datetime) -> datetime:
        result = _utc(value)
        assert result is not None
        return result


class IpInfoProvenance(BaseModel):
    """Where the metadata came from and when."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_name: str = IPINFO_SOURCE_NAME
    endpoint: str  # the exact URL requested (never contains the token)
    retrieved_at: datetime  # original retrieval time, also on a cache hit
    from_cache: bool = False
    response_sha256: str  # SHA-256 of the raw response body

    @field_validator("retrieved_at")
    @classmethod
    def _tz(cls, value: datetime) -> datetime:
        result = _utc(value)
        assert result is not None
        return result


class IpInfoMetadata(BaseModel):
    """Everything the service learned about one address. Metadata, not evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ip: str
    status: IpInfoStatus
    requested_at: datetime
    asn: Optional[int] = Field(default=None, ge=0)
    as_name: Optional[str] = None
    as_domain: Optional[str] = None
    country_code: Optional[str] = None
    country: Optional[str] = None
    continent_code: Optional[str] = None
    continent: Optional[str] = None
    provenance: Optional[IpInfoProvenance] = None
    error: Optional[IpInfoError] = None  # set for UNAVAILABLE only
    note: Optional[str] = None  # set for NOT_QUERIED / DISABLED
    warnings: list[str] = Field(default_factory=list)  # tolerated oddities in a valid response
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))

    @field_validator("requested_at")
    @classmethod
    def _tz(cls, value: datetime) -> datetime:
        result = _utc(value)
        assert result is not None
        return result

    @model_validator(mode="after")
    def _consistent(self) -> "IpInfoMetadata":
        has_data = any(
            value is not None
            for value in (
                self.asn,
                self.as_name,
                self.as_domain,
                self.country_code,
                self.country,
                self.continent_code,
                self.continent,
            )
        )
        if self.status in (IpInfoStatus.AVAILABLE, IpInfoStatus.EMPTY):
            if self.provenance is None:
                raise ValueError("a successful lookup must carry provenance")
            if self.error is not None:
                raise ValueError("a successful lookup must not carry an error")
            if (self.status is IpInfoStatus.AVAILABLE) != has_data:
                raise ValueError("AVAILABLE requires metadata fields; EMPTY requires none")
        else:
            if has_data or self.provenance is not None:
                raise ValueError(f"a {self.status.value} result must not carry metadata")
            if self.status is IpInfoStatus.UNAVAILABLE:
                if self.error is None:
                    raise ValueError("an UNAVAILABLE result must carry an error")
            elif not self.note or self.error is not None:
                raise ValueError(f"a {self.status.value} result needs a note and no error")
        return self

    @property
    def usable(self) -> bool:
        return self.status is IpInfoStatus.AVAILABLE


def failed_metadata(
    ip: object, requested_at: datetime, kind: IpInfoErrorKind, message: str
) -> IpInfoMetadata:
    """An explicit UNAVAILABLE result (used for internal failures and by the service layer)."""
    return IpInfoMetadata(
        ip=ip if isinstance(ip, str) else repr(ip),
        status=IpInfoStatus.UNAVAILABLE,
        requested_at=requested_at,
        error=IpInfoError(kind=kind, message=message, occurred_at=requested_at),
    )


# --------------------------------------------------------------------------
# Token handling
# --------------------------------------------------------------------------
def valid_token_format(token: Optional[str]) -> bool:
    """True for 1-512 printable ASCII characters without whitespace (safe for a header)."""
    return isinstance(token, str) and _TOKEN_RE.match(token) is not None


# --------------------------------------------------------------------------
# Response parsing (pure function; raises _ParseError)
# --------------------------------------------------------------------------
class _ParseError(Exception):
    def __init__(self, kind: IpInfoErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


def _normalise_ip(text: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def parse_lite_response(body: bytes, ip: str) -> tuple[dict[str, Any], list[str]]:
    """Parse a documented IPinfo Lite answer for ``ip``.

    Returns (fields, warnings). ``fields`` holds only values that were present and
    valid; omitted or unusable fields are simply absent (never invented).
    """
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _ParseError(
            IpInfoErrorKind.INVALID_JSON, f"response is not valid UTF-8 JSON ({type(exc).__name__})"
        ) from exc
    if not isinstance(document, dict):
        raise _ParseError(
            IpInfoErrorKind.UNEXPECTED_STRUCTURE,
            f"top-level JSON value is {type(document).__name__}, expected an object",
        )

    # The documented schema marks "ip" as required. It is also the only way to tie
    # the answer to the address that was asked about.
    echoed = document.get("ip", _MISSING)
    if echoed is _MISSING or echoed is None:
        raise _ParseError(IpInfoErrorKind.UNEXPECTED_STRUCTURE, 'response has no "ip" field')
    if not isinstance(echoed, str) or _normalise_ip(echoed) is None:
        raise _ParseError(
            IpInfoErrorKind.UNEXPECTED_STRUCTURE, 'response "ip" is not a valid IP address'
        )
    if _normalise_ip(echoed) != _normalise_ip(ip):
        raise _ParseError(
            IpInfoErrorKind.UNEXPECTED_STRUCTURE,
            "response describes a different address than the one queried",
        )

    fields: dict[str, Any] = {}
    warnings: list[str] = []
    absent: list[str] = []

    def raw(name: str) -> Any:
        value = document.get(name, _MISSING)
        if value is _MISSING or value is None:
            absent.append(name)
            return _MISSING
        return value

    value = raw("asn")
    if value is not _MISSING:
        parsed = _parse_asn(value)
        if parsed is None:
            warnings.append('ignored an "asn" value that is not a valid AS number')
        else:
            fields["asn"] = parsed

    for name, limit in _TEXT_FIELDS:
        value = raw(name)
        if value is _MISSING:
            continue
        if not isinstance(value, str):
            warnings.append(f'ignored a "{name}" value that is not text')
            continue
        text = _clean_text(value, limit)
        if text is None:
            continue  # blank text counts as "nothing provided"
        if name == "as_domain" and " " in text:
            warnings.append('ignored an "as_domain" value that is not a domain name')
            continue
        if len(" ".join(value.split())) > limit:
            warnings.append(f'"{name}" truncated to {limit} characters')
        fields[name] = text

    for name in _CODE_FIELDS:
        value = raw(name)
        if value is _MISSING:
            continue
        if not isinstance(value, str) or not _COUNTRY_CODE_RE.match(value.strip()):
            warnings.append(f'ignored a "{name}" value that is not a two-letter upper-case code')
            continue
        fields[name] = value.strip()

    if absent:
        warnings.append("fields absent from the response: " + ", ".join(sorted(absent)))
    return fields, warnings


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------
class IpInfoService:
    """Looks up IPinfo Lite metadata. Disabled (and silent) without a usable token."""

    def __init__(
        self,
        fetcher: Optional[Fetcher],
        *,
        token: Optional[str],
        base_url: str = DEFAULT_BASE_URL,
        cache_ttl_seconds: int = 3600,
        max_cache_entries: int = 2048,
        clock: Clock = utc_now,
    ) -> None:
        base = base_url.strip().rstrip("/")
        if not base.lower().startswith("https://"):
            raise ValueError("IPinfo base URL must use https")
        if cache_ttl_seconds < 0 or max_cache_entries < 0:
            raise ValueError("cache settings must not be negative")
        secret = token.strip() if isinstance(token, str) else ""
        self._secrets = tuple(s for s in {secret, token if isinstance(token, str) else ""} if s)
        self._disabled_reason: Optional[str] = None
        if not secret:
            self._disabled_reason = (
                "IPinfo is disabled: no IPINFO_TOKEN is configured. No request was made."
            )
        elif not valid_token_format(secret):
            self._disabled_reason = (
                "IPinfo is disabled: IPINFO_TOKEN has an unsupported format (expected printable "
                "ASCII without spaces, at most 512 characters). No request was made."
            )
        elif fetcher is None:
            self._disabled_reason = "IPinfo is disabled: no HTTP fetcher is available."
        self._fetcher = fetcher
        self._base = base
        self._cache = _TtlCache(timedelta(seconds=cache_ttl_seconds), max_cache_entries)
        self._clock = clock

    def __repr__(self) -> str:  # never show the token
        return f"IpInfoService(enabled={self.enabled}, base_url={self._base!r})"

    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self._disabled_reason is None

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def build_url(self, ip: str) -> str:
        """The request URL. It never contains the token."""
        return f"{self._base}/{LITE_PATH}/{quote(ip, safe=':')}"

    def redact(self, text: str) -> str:
        """Remove the token (and token-looking fragments) from text of unknown origin."""
        for secret in self._secrets:
            text = text.replace(secret, _REDACTED)
        text = _TOKEN_PARAM_RE.sub(rf"\1{_REDACTED}", text)
        return _BEARER_RE.sub(rf"\1{_REDACTED}", text)

    # ------------------------------------------------------------------
    def lookup(self, ip: str) -> IpInfoMetadata:
        """Retrieve supplementary metadata for one address. Never raises."""
        requested_at = self._clock()
        try:
            return self._lookup(ip, requested_at)
        except Exception as exc:  # defensive: a metadata failure must never break a caller
            # Type name only: an exception message could contain request details.
            logger.error("Unexpected error in IPinfo service (%s)", type(exc).__name__)
            return failed_metadata(
                ip,
                requested_at,
                IpInfoErrorKind.INTERNAL,
                f"unexpected internal error ({type(exc).__name__})",
            )

    def _lookup(self, ip: str, requested_at: datetime) -> IpInfoMetadata:
        assessment = assess_address(ip)
        if assessment.category is AddressCategory.INVALID or assessment.normalized is None:
            return failed_metadata(
                ip, requested_at, IpInfoErrorKind.INVALID_INPUT, assessment.message
            )
        address = assessment.normalized
        if not assessment.allowed:
            return IpInfoMetadata(
                ip=address,
                status=IpInfoStatus.NOT_QUERIED,
                requested_at=requested_at,
                note=f"No IPinfo request was made: {assessment.message}",
            )
        if self._disabled_reason is not None:
            return IpInfoMetadata(
                ip=address,
                status=IpInfoStatus.DISABLED,
                requested_at=requested_at,
                note=self._disabled_reason,
            )
        assert self._fetcher is not None

        url = self.build_url(address)
        key = (LITE_PATH, address)
        entry = self._cache.get(key, self._clock())
        from_cache = entry is not None
        if entry is not None:
            body, retrieved_at, _cached_url = entry
        else:
            try:
                result = self._fetcher.fetch(url)
            except SourceError as exc:
                return self._failure(address, requested_at, self._map_source_error(exc, url))
            except Exception as exc:  # a misbehaving fetcher must not escape
                logger.error("Unexpected IPinfo fetcher failure (%s)", type(exc).__name__)
                return self._failure(
                    address,
                    requested_at,
                    IpInfoError(
                        kind=IpInfoErrorKind.INTERNAL,
                        message=f"unexpected fetch failure ({type(exc).__name__})",
                        endpoint=url,
                        occurred_at=self._clock(),
                    ),
                )
            body, retrieved_at = result.body, result.retrieved_at

        try:
            fields, warnings = parse_lite_response(body, address)
        except _ParseError as exc:
            return self._failure(
                address,
                requested_at,
                IpInfoError(
                    kind=exc.kind,
                    message=self.redact(exc.message),
                    endpoint=url,
                    occurred_at=self._clock(),
                ),
            )

        if not from_cache:
            self._cache.put(key, body, retrieved_at, url)  # only parsed, successful bodies

        return IpInfoMetadata(
            ip=address,
            status=IpInfoStatus.AVAILABLE if fields else IpInfoStatus.EMPTY,
            requested_at=requested_at,
            provenance=IpInfoProvenance(
                endpoint=url,
                retrieved_at=retrieved_at,
                from_cache=from_cache,
                response_sha256=sha256_hex(body),
            ),
            warnings=warnings,
            **fields,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _failure(address: str, requested_at: datetime, error: IpInfoError) -> IpInfoMetadata:
        return IpInfoMetadata(
            ip=address, status=IpInfoStatus.UNAVAILABLE, requested_at=requested_at, error=error
        )

    def _map_source_error(self, exc: SourceError, url: str) -> IpInfoError:
        status = exc.status_code
        if exc.kind is SourceErrorKind.HTTP_STATUS:
            if status in (401, 403):
                kind = IpInfoErrorKind.AUTH_FAILED
                message = f"IPinfo rejected the request (HTTP {status}); check IPINFO_TOKEN"
            elif status == 429:
                kind = IpInfoErrorKind.RATE_LIMITED
                message = (
                    "IPinfo rate limit or plan quota reached (HTTP 429); this service does not "
                    "retry automatically; see IPinfo's documentation for the limits of your plan"
                )
            elif status is not None and 500 <= status <= 599:
                kind = IpInfoErrorKind.SERVER_ERROR
                message = f"IPinfo server error (HTTP {status})"
            else:
                kind = IpInfoErrorKind.HTTP_ERROR
                message = f"unexpected HTTP status {status} from IPinfo (expected 200)"
        else:
            kind = {
                SourceErrorKind.TIMEOUT: IpInfoErrorKind.TIMEOUT,
                SourceErrorKind.CONNECTION: IpInfoErrorKind.CONNECTION,
                SourceErrorKind.TOO_LARGE: IpInfoErrorKind.TOO_LARGE,
            }.get(exc.kind, IpInfoErrorKind.INTERNAL)
            message = exc.message
        return IpInfoError(
            kind=kind,
            message=self.redact(message),
            endpoint=self.redact(url),
            http_status=status,
            occurred_at=self._clock(),
        )
