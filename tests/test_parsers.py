import pytest

from netclass.errors import SourceError, SourceErrorKind
from netclass.parsers import CidrSet, parse_cidr_list, parse_ip_list

K = SourceErrorKind


def err(fn, *args, **kwargs) -> SourceError:
    with pytest.raises(SourceError) as info:
        fn(*args, **kwargs)
    return info.value


# ------------------------------------------------------------- IP lists
def test_ip_list_handles_ipv4_ipv6_comments_blanks_crlf_and_normalisation():
    body = (
        b"# header comment\r\n185.220.101.45\r\n2001:67C:E60:0:0:0:0:1 # trailing\r\n\r\n"
        b"::ffff:8.8.8.8\r\n185.220.101.45\r\n"
    )
    parsed = parse_ip_list(body, source="t")
    assert parsed.entries == {"185.220.101.45", "2001:67c:e60::1", "8.8.8.8"}
    assert (parsed.v4_count, parsed.v6_count) == (2, 1)
    assert parsed.comment_lines == 1 and parsed.blank_lines == 1
    assert "8.8.8.8" in parsed and "9.9.9.9" not in parsed


def test_ip_list_accepts_utf8_bom():
    assert parse_ip_list(b"\xef\xbb\xbf1.2.3.4\n", source="t").count == 1


@pytest.mark.parametrize(
    "body, fragment",
    [
        (b"<!DOCTYPE html>\n<html><body>Service Unavailable</body></html>", "HTML"),
        (b"1.2.3.4\nnot-an-ip\n", "line 2"),
        (b"1.2.3.4:80\n", "line 1"),
        (b"1.2.3.4/24\n", "CIDR"),
        (b"999.1.1.1\n", "line 1"),
        (b"\xff\xfe\x00garbage", "UTF-8"),
        (b"1.2.3.4\x00\n", "NUL"),
    ],
)
def test_ip_list_malformed_content_is_rejected(body, fragment):
    error = err(parse_ip_list, body, source="t")
    assert error.kind is K.MALFORMED
    assert fragment in error.message


@pytest.mark.parametrize("body", [b"", b"\n\n", b"# only a comment\n   \n"])
def test_ip_list_with_no_entries_is_empty_error(body):
    assert err(parse_ip_list, body, source="t").kind is K.EMPTY


def test_ip_list_below_sanity_floor_is_too_small():
    error = err(parse_ip_list, b"1.2.3.4\n5.6.7.8\n", source="t", min_entries=5)
    assert error.kind is K.TOO_SMALL


# ------------------------------------------------------------- CIDR lists
NETS = b"45.0.0.0/8\n45.83.0.0/16\n45.83.64.0/24\n45.83.64.0/22\n8.8.8.8/32\n"


def test_cidr_matching_boundaries_and_most_specific_first():
    cidrs = parse_cidr_list(b"45.83.64.0/22\n", source="t", family=4).cidrs
    assert str(cidrs.match("45.83.64.0")) == "45.83.64.0/22"
    assert str(cidrs.match("45.83.67.255")) == "45.83.64.0/22"
    assert cidrs.match("45.83.68.0") is None
    assert cidrs.match("45.83.63.255") is None


def test_nested_networks_are_all_reported_most_specific_first():
    cidrs = parse_cidr_list(NETS, source="t", family=4).cidrs
    assert [str(n) for n in cidrs.match_all("45.83.64.9")] == [
        "45.83.64.0/24",
        "45.83.64.0/22",
        "45.83.0.0/16",
        "45.0.0.0/8",
    ]
    assert str(cidrs.match("45.83.64.9")) == "45.83.64.0/24"
    assert [str(n) for n in cidrs.match_all("45.9.9.9")] == ["45.0.0.0/8"]


def test_single_address_entries_and_bare_ips():
    cidrs = parse_cidr_list(b"8.8.8.8/32\n9.9.9.9\n", source="t", family=4).cidrs
    assert cidrs.match("8.8.8.8") is not None and cidrs.match("8.8.8.9") is None
    assert str(cidrs.match("9.9.9.9")) == "9.9.9.9/32"


def test_ipv6_matching_and_no_cross_family_matches():
    v6 = parse_cidr_list(b"2a0d:5600::/32\n", source="t", family=6).cidrs
    assert v6.match("2a0d:5600::1234") is not None
    assert v6.match("2a0d:5601::1") is None
    assert v6.match("45.83.64.9") is None  # an IPv4 address never matches an IPv6 set
    mixed = CidrSet([])
    assert mixed.match("1.2.3.4") is None and len(mixed) == 0


def test_prefix_range_counts_and_exact_network_lookup():
    parsed = parse_cidr_list(NETS, source="t", family=4)
    assert parsed.count == 5 and parsed.v4_count == 5 and parsed.v6_count == 0
    assert parsed.cidrs.prefix_range(4) == (8, 32)
    assert parsed.cidrs.prefix_range(6) is None
    import ipaddress

    assert parsed.cidrs.has_network(ipaddress.ip_network("45.83.0.0/16"))
    assert not parsed.cidrs.has_network(ipaddress.ip_network("45.83.0.0/17"))


def test_duplicate_cidrs_count_once():
    assert parse_cidr_list(b"45.0.0.0/8\n45.0.0.0/8\n", source="t").count == 1


@pytest.mark.parametrize(
    "body, fragment",
    [
        (b"45.83.64.1/22\n", "host bits"),  # not a network address
        (b"0.0.0.0/0\n", "implausibly broad"),
        (b"2a0d:5600::/32\n", "IPv6 in an IPv4 list"),
        (b"<html>error</html>\n", "HTML"),
        (b"45.83.64.0/22\ngarbage\n", "line 2"),
    ],
)
def test_cidr_list_malformed_content_is_rejected(body, fragment):
    error = err(parse_cidr_list, body, source="t", family=4)
    assert error.kind is K.MALFORMED
    assert fragment in error.message


def test_cidr_list_empty_and_too_small():
    assert err(parse_cidr_list, b"# nothing\n", source="t").kind is K.EMPTY
    assert err(parse_cidr_list, b"45.0.0.0/8\n", source="t", min_entries=3).kind is K.TOO_SMALL


def test_overly_broad_ipv6_range_is_rejected_in_an_ipv6_list():
    error = err(parse_cidr_list, b"::/0\n", source="t", family=6)
    assert error.kind is K.MALFORMED and "implausibly broad" in error.message
