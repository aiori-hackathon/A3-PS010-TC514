from itertools import permutations

import pytest

from factories import (
    OTHER_PUBLIC_IP,
    PUBLIC_IP,
    S,
    T0,
    hosting_context,
    hours,
    obs,
    tor,
    vpn,
)
from netclass.classifier import DEFAULT_CURRENT_TOLERANCE, POLICY_VERSION, classify
from netclass.models import Applicability, Label, ReasonCode

R = ReasonCode


# ---------------------------------------------------------------- positives
def test_known_tor_exit():
    result = classify(obs(), [tor(S.MATCH), vpn(S.NO_MATCH)])
    assert result.label is Label.KNOWN_TOR_EXIT
    assert result.reason_code is R.TOR_EXIT_MATCH
    assert result.policy_version == POLICY_VERSION


def test_known_vpn_proxy_endpoint():
    result = classify(obs(), [tor(S.NO_MATCH), vpn(S.MATCH)])
    assert result.label is Label.KNOWN_VPN_PROXY
    assert result.reason_code is R.VPN_PROXY_ENDPOINT_MATCH


def test_positive_match_stands_when_other_source_unavailable_but_caveat_is_kept():
    result = classify(obs(), [tor(S.MATCH), vpn(S.SOURCE_UNAVAILABLE, source="vpn-provider-x")])
    assert result.label is Label.KNOWN_TOR_EXIT
    assert any("vpn-provider-x" in caveat for caveat in result.caveats)


def test_two_vpn_sources_agreeing_is_still_one_vpn_label():
    result = classify(
        obs(),
        [
            tor(S.NO_MATCH),
            vpn(S.MATCH, source="x4bnet-lists-vpn"),
            vpn(S.MATCH, source="az0-vpn-ip"),
        ],
    )
    assert result.label is Label.KNOWN_VPN_PROXY


def test_one_vpn_source_matching_while_another_says_no_match_is_not_a_conflict():
    result = classify(
        obs(),
        [
            tor(S.NO_MATCH),
            vpn(S.MATCH, source="x4bnet-lists-vpn"),
            vpn(S.NO_MATCH, source="az0-vpn-ip"),
        ],
    )
    assert result.label is Label.KNOWN_VPN_PROXY


# ------------------------------------------------------------------ unknown
def test_no_qualifying_match():
    result = classify(obs(), [tor(S.NO_MATCH), vpn(S.NO_MATCH)])
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_NO_QUALIFYING_MATCH
    assert result.additional_reason_codes == []


def test_hosting_only_returns_unknown_never_vpn():
    result = classify(obs(), [tor(S.NO_MATCH), vpn(S.NO_MATCH)], hosting_context())
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_HOSTING_ONLY
    assert result.network_context is not None  # shown, but separate from evidence


def test_hosting_indicator_is_secondary_when_evidence_is_incomplete():
    result = classify(obs(), [tor(S.NO_MATCH), vpn(S.NOT_CONFIGURED)], hosting_context())
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_PROVIDER_NOT_CONFIGURED
    assert R.UNKNOWN_HOSTING_ONLY in result.additional_reason_codes


def test_missing_provider_configuration_explicit_record():
    result = classify(obs(), [tor(S.NO_MATCH), vpn(S.NOT_CONFIGURED)])
    assert result.reason_code is R.UNKNOWN_PROVIDER_NOT_CONFIGURED
    assert result.label is Label.UNKNOWN


def test_missing_provider_configuration_no_record_supplied():
    result = classify(obs(), [tor(S.NO_MATCH)])
    assert result.reason_code is R.UNKNOWN_PROVIDER_NOT_CONFIGURED


def test_no_evidence_at_all_is_unknown_not_negative():
    result = classify(obs(), [])
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_PROVIDER_NOT_CONFIGURED


# ---------------------------------------------------------- source failures
@pytest.mark.parametrize("error", ["timeout", "HTTP 503", "malformed response body"])
def test_unavailable_source_is_never_a_negative(error):
    result = classify(obs(), [tor(S.SOURCE_UNAVAILABLE, error=error), vpn(S.NO_MATCH)])
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_SOURCE_UNAVAILABLE
    assert result.reason_code is not R.UNKNOWN_NO_QUALIFYING_MATCH
    assert any(error in caveat for caveat in result.caveats)


def test_source_unavailable_outranks_stale_and_not_configured():
    stale_vpn = vpn(S.NO_MATCH, retrieved_at=T0 - hours(5))
    result = classify(obs(), [tor(S.SOURCE_UNAVAILABLE), stale_vpn])
    assert result.reason_code is R.UNKNOWN_SOURCE_UNAVAILABLE
    assert R.UNKNOWN_STALE_EVIDENCE in result.additional_reason_codes


# ------------------------------------------------------------------- stale
def test_stale_current_only_evidence_returns_unknown():
    old = T0 - hours(3)
    result = classify(obs(), [tor(S.MATCH, retrieved_at=old), vpn(S.NO_MATCH, retrieved_at=old)])
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_STALE_EVIDENCE
    assert all(a.applicability is Applicability.STALE for a in result.evidence_assessments)


def test_current_list_cannot_assert_historical_tor_status():
    thirty_days_ago = T0 - hours(24 * 30)
    result = classify(
        obs(at=thirty_days_ago),
        [tor(S.MATCH, retrieved_at=T0), vpn(S.NO_MATCH, retrieved_at=T0)],
    )
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_STALE_EVIDENCE


def test_tolerance_boundary_is_inclusive():
    edge = DEFAULT_CURRENT_TOLERANCE
    inside = classify(obs(at=T0 + edge), [tor(S.MATCH), vpn(S.NO_MATCH)])
    assert inside.label is Label.KNOWN_TOR_EXIT
    outside = classify(
        obs(at=T0 + edge + hours(1) / 3600),  # one second beyond the tolerance
        [tor(S.MATCH), vpn(S.NO_MATCH)],
    )
    assert outside.reason_code is R.UNKNOWN_STALE_EVIDENCE


def test_validity_interval_supports_historical_observation():
    # Evidence retrieved long after the observation, but its validity interval covers it.
    obs_time = T0 - hours(36)
    record = tor(S.MATCH, valid_from=T0 - hours(48), valid_to=T0 - hours(24), retrieved_at=T0)
    result = classify(obs(at=obs_time), [record])
    assert result.label is Label.KNOWN_TOR_EXIT


def test_validity_interval_overrides_retrieval_time():
    record = tor(S.MATCH, valid_from=T0 - hours(48), valid_to=T0 - hours(24), retrieved_at=T0)
    result = classify(obs(at=T0), [record])  # retrieved "now" but interval ended yesterday
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_STALE_EVIDENCE


# --------------------------------------------------------------- conflicts
def test_conflict_between_tor_and_vpn_evidence():
    result = classify(obs(), [tor(S.MATCH), vpn(S.MATCH)])
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_CONFLICTING_EVIDENCE


def test_conflict_within_a_single_source():
    result = classify(
        obs(),
        [tor(S.MATCH, source="same-source"), tor(S.NO_MATCH, source="same-source"), vpn(S.NO_MATCH)],
    )
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_CONFLICTING_EVIDENCE


def test_stale_conflicting_record_does_not_create_a_conflict():
    stale_vpn_match = vpn(S.MATCH, retrieved_at=T0 - hours(10))
    result = classify(obs(), [tor(S.MATCH), stale_vpn_match])
    assert result.label is Label.KNOWN_TOR_EXIT


# ---------------------------------------------------------------- excluded
@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1",
        "224.0.0.1", "0.0.0.0", "240.0.0.1", "100.64.0.1", "::1", "fe80::1",
        "fc00::1", "ff02::1", "::", "2001:db8::1", "192.0.2.1",
    ],
)
def test_excluded_addresses_return_unknown_even_with_matching_evidence(ip):
    result = classify(obs(ip=ip), [tor(S.MATCH), vpn(S.MATCH)])
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_EXCLUDED_ADDRESS
    assert result.evidence_assessments == []


# ------------------------------------------------------------- determinism
def test_repeated_calls_are_identical():
    evidence = [tor(S.NO_MATCH), vpn(S.NOT_CONFIGURED)]
    first = classify(obs(), evidence, hosting_context())
    second = classify(obs(), evidence, hosting_context())
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_result_does_not_depend_on_evidence_order():
    evidence = [
        tor(S.NO_MATCH, source="tor-a"),
        vpn(S.SOURCE_UNAVAILABLE, source="vpn-a"),
        vpn(S.NO_MATCH, source="vpn-b", retrieved_at=T0 - hours(5)),
    ]
    outputs = {classify(obs(), list(p)).model_dump_json() for p in permutations(evidence)}
    assert len(outputs) == 1


def test_different_public_ip_uses_same_rules():
    result = classify(obs(ip=OTHER_PUBLIC_IP), [tor(S.NO_MATCH), vpn(S.NO_MATCH)])
    assert result.ip == OTHER_PUBLIC_IP
    assert result.reason_code is R.UNKNOWN_NO_QUALIFYING_MATCH
    assert PUBLIC_IP != OTHER_PUBLIC_IP
