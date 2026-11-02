import pytest

from netclass.address_policy import AddressCategory, assess_address


@pytest.mark.parametrize("raw", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_global_addresses_are_allowed(raw):
    result = assess_address(raw)
    assert result.category is AddressCategory.GLOBAL
    assert result.allowed is True


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not-an-ip",
        "999.1.1.1",
        "1.2.3",
        "8.8.8.8:53",
        "8.8.8.8/24",
        "fe80::1%eth0",
        "8.8.8.8 8.8.4.4",
        "12345",
    ],
)
def test_malformed_input_is_invalid(raw):
    result = assess_address(raw)
    assert result.category is AddressCategory.INVALID
    assert result.allowed is False
    assert result.normalized is None


def test_non_string_input_is_invalid():
    assert assess_address(None).category is AddressCategory.INVALID  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "raw, category",
    [
        ("10.0.0.5", AddressCategory.PRIVATE),
        ("192.168.1.1", AddressCategory.PRIVATE),
        ("172.16.0.1", AddressCategory.PRIVATE),
        ("127.0.0.1", AddressCategory.LOOPBACK),
        ("169.254.1.1", AddressCategory.LINK_LOCAL),
        ("224.0.0.1", AddressCategory.MULTICAST),
        ("0.0.0.0", AddressCategory.UNSPECIFIED),
        ("240.0.0.1", AddressCategory.RESERVED),
        ("100.64.0.1", AddressCategory.SHARED_ADDRESS_SPACE),
        ("::1", AddressCategory.LOOPBACK),
        ("::", AddressCategory.UNSPECIFIED),
        ("fe80::1", AddressCategory.LINK_LOCAL),
        ("ff02::1", AddressCategory.MULTICAST),
        ("fc00::1", AddressCategory.PRIVATE),
    ],
)
def test_excluded_categories(raw, category):
    result = assess_address(raw)
    assert result.category is category
    assert result.allowed is False


@pytest.mark.parametrize("raw", ["192.0.2.1", "198.51.100.7", "203.0.113.9", "2001:db8::1"])
def test_documentation_ranges_are_excluded(raw):
    assert assess_address(raw).allowed is False


def test_whitespace_is_stripped_and_ipv6_normalised():
    assert assess_address(" 8.8.8.8 ").normalized == "8.8.8.8"
    assert assess_address("2606:4700:4700:0:0:0:0:1111").normalized == "2606:4700:4700::1111"


def test_ipv4_mapped_ipv6_is_normalised_then_policy_applied():
    mapped_public = assess_address("::ffff:8.8.8.8")
    assert mapped_public.normalized == "8.8.8.8"
    assert mapped_public.version == 4
    assert mapped_public.allowed is True

    mapped_private = assess_address("::ffff:10.0.0.1")
    assert mapped_private.normalized == "10.0.0.1"
    assert mapped_private.allowed is False
