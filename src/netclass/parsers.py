"""Strict parsers for the source file formats, plus fast CIDR matching.

Parsers are pure functions of the downloaded bytes. They are deliberately
strict: one unparseable line makes the whole snapshot MALFORMED, because an
HTML error page or a truncated file must never be read as "the list is empty".
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, Optional, Union

from .errors import SourceError, SourceErrorKind

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Sanity limits against corrupt/poisoned entries such as 0.0.0.0/0. Observed
# X4BNet ranges are /17../32 (IPv4) and /29../48 (IPv6), so these leave headroom.
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 16


def normalise_ip(ip: IPAddress) -> IPAddress:
    """Same normalisation as Observation: IPv4-mapped IPv6 becomes IPv4."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _short(text: str, limit: int = 60) -> str:
    return repr(text if len(text) <= limit else text[:limit] + "...")


def _content_lines(body: bytes, source: str) -> tuple[list[tuple[int, str]], int, int]:
    """Decode and strip comments. Returns (numbered content lines, comment lines, blank lines)."""
    try:
        text = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SourceError(
            SourceErrorKind.MALFORMED,
            f"{source}: not valid UTF-8 text ({exc.reason} at byte {exc.start})",
        ) from exc
    if "\x00" in text:
        raise SourceError(SourceErrorKind.MALFORMED, f"{source}: contains NUL bytes (binary data)")

    content: list[tuple[int, str]] = []
    comments = blanks = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            blanks += 1
        elif stripped.startswith("#"):
            comments += 1
        else:
            value = stripped.split("#", 1)[0].strip()  # trailing "# comment"
            content.append((number, value))
    return content, comments, blanks


def _check_count(count: int, min_entries: int, source: str) -> None:
    if count == 0:
        raise SourceError(SourceErrorKind.EMPTY, f"{source}: contains no entries")
    if count < min_entries:
        raise SourceError(
            SourceErrorKind.TOO_SMALL,
            f"{source}: only {count} entries, below the sanity floor of {min_entries} "
            "(possible truncated or wrong file)",
        )


# --------------------------------------------------------------------------
# Exact-address lists (Tor exit list, az0 files)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ParsedIpList:
    entries: frozenset[str]
    v4_count: int
    v6_count: int
    comment_lines: int
    blank_lines: int

    @property
    def count(self) -> int:
        return len(self.entries)

    def __contains__(self, ip: str) -> bool:
        return ip in self.entries


def parse_ip_list(body: bytes, *, source: str, min_entries: int = 1) -> ParsedIpList:
    """One IP address per line; '#' comments and blank lines allowed."""
    lines, comments, blanks = _content_lines(body, source)
    entries: set[str] = set()
    v4 = v6 = 0
    for number, value in lines:
        if "/" in value:
            raise SourceError(
                SourceErrorKind.MALFORMED,
                f"{source}: line {number} {_short(value)} is a CIDR range in an exact-address list",
            )
        try:
            ip = normalise_ip(ipaddress.ip_address(value))
        except ValueError:
            hint = " (looks like HTML, not a list)" if value.startswith("<") else ""
            raise SourceError(
                SourceErrorKind.MALFORMED,
                f"{source}: line {number} {_short(value)} is not an IP address{hint}",
            ) from None
        text = str(ip)
        if text not in entries:
            entries.add(text)
            if ip.version == 4:
                v4 += 1
            else:
                v6 += 1
    _check_count(len(entries), min_entries, source)
    return ParsedIpList(frozenset(entries), v4, v6, comments, blanks)


# --------------------------------------------------------------------------
# CIDR lists (X4BNet)
# --------------------------------------------------------------------------
class CidrSet:
    """Set of networks with exact longest-prefix lookup.

    For each prefix length that occurs in the data, the network addresses are
    kept in a set. A lookup masks the address once per distinct length, so it
    costs a few dozen dictionary probes regardless of list size.
    """

    def __init__(self, networks: Iterable[IPNetwork]) -> None:
        self._tables: dict[int, dict[int, set[int]]] = {4: {}, 6: {}}
        self._count = {4: 0, 6: 0}
        for net in networks:
            table = self._tables[net.version].setdefault(net.prefixlen, set())
            value = int(net.network_address)
            if value not in table:
                table.add(value)
                self._count[net.version] += 1

    def __len__(self) -> int:
        return self._count[4] + self._count[6]

    def count(self, version: int) -> int:
        return self._count[version]

    def prefix_range(self, version: int) -> Optional[tuple[int, int]]:
        lengths = self._tables[version]
        return (min(lengths), max(lengths)) if lengths else None

    def match_all(self, ip: Union[str, IPAddress]) -> list[IPNetwork]:
        """Every listed network containing `ip`, most specific first."""
        address = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
        bits = address.max_prefixlen
        value = int(address)
        table = self._tables[address.version]
        found: list[IPNetwork] = []
        for plen in sorted(table, reverse=True):
            shift = bits - plen
            key = (value >> shift) << shift
            if key in table[plen]:
                network_address = type(address)(key)
                found.append(ipaddress.ip_network((network_address, plen)))
        return found

    def match(self, ip: Union[str, IPAddress]) -> Optional[IPNetwork]:
        found = self.match_all(ip)
        return found[0] if found else None

    def has_network(self, network: IPNetwork) -> bool:
        """Is this exact network (same address and prefix length) listed?"""
        return int(network.network_address) in self._tables[network.version].get(
            network.prefixlen, ()
        )


@dataclass(frozen=True)
class ParsedCidrList:
    cidrs: CidrSet
    v4_count: int
    v6_count: int
    comment_lines: int
    blank_lines: int

    @property
    def count(self) -> int:
        return len(self.cidrs)


def parse_cidr_list(
    body: bytes,
    *,
    source: str,
    family: Optional[int] = None,
    min_entries: int = 1,
) -> ParsedCidrList:
    """One CIDR per line. `family` (4 or 6) rejects entries of the other family."""
    lines, comments, blanks = _content_lines(body, source)
    networks: list[IPNetwork] = []
    for number, value in lines:
        try:
            net = ipaddress.ip_network(value, strict=True)
        except ValueError:
            hint = " (looks like HTML, not a list)" if value.startswith("<") else ""
            raise SourceError(
                SourceErrorKind.MALFORMED,
                f"{source}: line {number} {_short(value)} is not a valid CIDR "
                f"(host bits set or not a network){hint}",
            ) from None
        if family is not None and net.version != family:
            raise SourceError(
                SourceErrorKind.MALFORMED,
                f"{source}: line {number} {_short(value)} is IPv{net.version} in an IPv{family} list",
            )
        floor = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
        if net.prefixlen < floor:
            raise SourceError(
                SourceErrorKind.MALFORMED,
                f"{source}: line {number} {_short(value)} is implausibly broad "
                f"(shorter than /{floor}); refusing the whole snapshot",
            )
        networks.append(net)
    cidrs = CidrSet(networks)
    _check_count(len(cidrs), min_entries, source)
    return ParsedCidrList(cidrs, cidrs.count(4), cidrs.count(6), comments, blanks)
