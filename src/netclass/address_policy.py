"""IP address validation and the explicit exclusion policy.

Policy:
  * Malformed input (empty, CIDR, scoped IPv6, ports, junk) is INVALID.
  * IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are normalised to IPv4.
  * Only globally routable unicast addresses are classified (category GLOBAL).
    Everything else is excluded: no external evidence is consulted for it.

Category order matters: e.g. 127.0.0.1 is also "private" in Python's
ipaddress module, so more specific categories are checked first.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 (CGNAT)


class AddressCategory(StrEnum):
    INVALID = "INVALID"
    GLOBAL = "GLOBAL"
    UNSPECIFIED = "UNSPECIFIED"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    MULTICAST = "MULTICAST"
    RESERVED = "RESERVED"
    SHARED_ADDRESS_SPACE = "SHARED_ADDRESS_SPACE"
    # Private and special-purpose ranges as defined by Python's ipaddress
    # module (includes RFC 1918, ULA and the documentation ranges).
    PRIVATE = "PRIVATE"
    OTHER_NON_GLOBAL = "OTHER_NON_GLOBAL"


@dataclass(frozen=True)
class AddressAssessment:
    raw: str
    normalized: Optional[str]
    version: Optional[int]
    category: AddressCategory
    allowed: bool  # True only for GLOBAL addresses
    message: str


def _categorise(ip: IPAddress) -> AddressCategory:
    if ip.is_unspecified:
        return AddressCategory.UNSPECIFIED
    if ip.is_loopback:
        return AddressCategory.LOOPBACK
    if ip.is_link_local:
        return AddressCategory.LINK_LOCAL
    if ip.is_multicast:
        return AddressCategory.MULTICAST
    if ip.is_reserved:
        return AddressCategory.RESERVED
    if isinstance(ip, ipaddress.IPv4Address) and ip in _SHARED_ADDRESS_SPACE:
        return AddressCategory.SHARED_ADDRESS_SPACE
    if ip.is_private:
        return AddressCategory.PRIVATE
    if ip.is_global:
        return AddressCategory.GLOBAL
    return AddressCategory.OTHER_NON_GLOBAL


def _invalid(raw: object, message: str) -> AddressAssessment:
    return AddressAssessment(
        raw=raw if isinstance(raw, str) else repr(raw),
        normalized=None,
        version=None,
        category=AddressCategory.INVALID,
        allowed=False,
        message=message,
    )


def assess_address(raw: str) -> AddressAssessment:
    """Validate `raw` and apply the exclusion policy. Never raises."""
    if not isinstance(raw, str):
        return _invalid(raw, "IP address must be a string.")
    text = raw.strip()
    if not text:
        return _invalid(raw, "IP address is empty.")
    if "/" in text:
        return _invalid(raw, "CIDR ranges are not accepted; provide a single IP address.")
    if "%" in text:
        return _invalid(raw, "IPv6 zone/scope identifiers are not accepted.")

    try:
        ip: IPAddress = ipaddress.ip_address(text)
    except ValueError:
        return _invalid(raw, f"{text!r} is not a valid IPv4 or IPv6 address.")

    note = ""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
        note = " (IPv4-mapped IPv6 address normalised to IPv4)"

    category = _categorise(ip)
    if category is AddressCategory.GLOBAL:
        message = f"Address {ip} is globally routable and eligible for classification{note}."
        allowed = True
    else:
        message = (
            f"Address {ip} is in category {category.value} and is excluded from "
            f"classification by policy; no evidence was consulted{note}."
        )
        allowed = False

    return AddressAssessment(
        raw=raw,
        normalized=str(ip),
        version=ip.version,
        category=category,
        allowed=allowed,
        message=message,
    )
