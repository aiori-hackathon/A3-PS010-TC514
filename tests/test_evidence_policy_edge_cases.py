"""Written decisions for the known policy edge cases A-D (docs/EVIDENCE_POLICY.md).

Characterization tests: they pin the existing behaviour (policy ps010-policy-1). If one
fails, behaviour changed, which needs a separate approved proposal.
"""
import pytest

from factories import T0, hours
from fakes import ip_body
from netclass.collector import classify_with_evidence
from netclass.config import Settings
from netclass.errors import SourceError, SourceErrorKind
from netclass.models import EvidenceStatus, Label, Observation, ReasonCode
from support import APPLE_URL, TOR_URL, TOR_IP, VPN_IP, X4_V4, all_adapters, make_stack, standard_routes

R = ReasonCode
S = EvidenceStatus
X4_NAME = "x4bnet-lists-vpn"


def timeout(url):
    return SourceError(SourceErrorKind.TIMEOUT, "no response within 10s", url=url)


def classify(tmp_path, ip, routes, *, at=T0):
    stack = make_stack(tmp_path, routes)
    return classify_with_evidence(
        Observation(ip=ip, observed_at=at), all_adapters(stack), Settings()
    )


# ----------------------------------------------- A: Tor/VPN overlap, healthy vs failed sources
def overlap_routes(**overrides):
    """VPN_IP is both in a genuine X4BNet range (45.83.64.0/24) and on the Tor list."""
    return standard_routes(**{TOR_URL: ip_body([VPN_IP]), **overrides})


def test_a_healthy_sources_tor_and_vpn_overlap_is_conflict_unknown(tmp_path):
    result, _ = classify(tmp_path, VPN_IP, overlap_routes())
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_CONFLICTING_EVIDENCE


def test_a_vpn_source_down_hides_the_conflict_so_tor_stands_with_caveats(tmp_path):
    routes = overlap_routes(**{X4_V4: timeout(X4_V4)})
    result, records = classify(tmp_path, VPN_IP, routes)
    assert next(r for r in records if r.source_name == X4_NAME).status is S.SOURCE_UNAVAILABLE
    assert result.label is Label.KNOWN_TOR_EXIT
    assert any(X4_NAME in caveat for caveat in result.caveats)


# ---------------------- B: Apple exclusion list outage, visible only as a caveat (Observation 2)
def test_b_apple_list_down_with_a_vpn_range_hit_is_unknown_and_the_outage_is_a_caveat(tmp_path):
    routes = standard_routes(**{APPLE_URL: timeout(APPLE_URL)})
    result, records = classify(tmp_path, VPN_IP, routes)
    x4 = next(r for r in records if r.source_name == X4_NAME)
    assert x4.status is S.SOURCE_UNAVAILABLE
    assert result.label is Label.UNKNOWN
    assert result.reason_code is R.UNKNOWN_NO_QUALIFYING_MATCH  # broad code; see decision B
    assert any("Apple Private Relay" in caveat for caveat in result.caveats)


def test_b_apple_list_down_never_turns_a_vpn_range_hit_into_a_vpn_label(tmp_path):
    routes = standard_routes(**{APPLE_URL: timeout(APPLE_URL)})
    result, _ = classify(tmp_path, VPN_IP, routes)
    assert result.label is not Label.KNOWN_VPN_PROXY


def test_b_apple_list_down_does_not_matter_when_no_vpn_range_matches(tmp_path):
    routes = standard_routes(**{APPLE_URL: timeout(APPLE_URL)})
    result, records = classify(tmp_path, "8.8.8.8", routes)
    assert all(r.status is S.NO_MATCH for r in records)  # the Apple list is never fetched
    assert result.reason_code is R.UNKNOWN_NO_QUALIFYING_MATCH


def test_b_tor_match_survives_an_apple_outage_with_the_outage_in_the_caveats(tmp_path):
    routes = overlap_routes(**{APPLE_URL: timeout(APPLE_URL)})
    result, _ = classify(tmp_path, VPN_IP, routes)
    assert result.label is Label.KNOWN_TOR_EXIT
    assert any("Apple Private Relay" in caveat for caveat in result.caveats)


# ----------------------------------- C: a Tor exit inside an Apple-excluded range stays Tor
def test_c_tor_exit_inside_apple_excluded_range_is_not_a_conflict(tmp_path):
    routes = standard_routes(**{TOR_URL: ip_body(["104.28.28.10"])})
    result, _ = classify(tmp_path, "104.28.28.10", routes)
    assert result.label is Label.KNOWN_TOR_EXIT and result.reason_code is R.TOR_EXIT_MATCH


# ------------------------- D: the observation window is symmetric around the retrieval time
@pytest.mark.parametrize("offset_hours, label", [(-0.5, Label.KNOWN_TOR_EXIT), (0.5, Label.KNOWN_TOR_EXIT)])
def test_d_observations_within_the_tolerance_on_either_side_use_the_current_snapshot(
    tmp_path, offset_hours, label
):
    result, _ = classify(tmp_path, TOR_IP, standard_routes(), at=T0 + hours(offset_hours))
    assert result.label is label


@pytest.mark.parametrize("offset_hours", [-2, 2])
def test_d_observations_beyond_the_tolerance_on_either_side_cannot_be_supported(tmp_path, offset_hours):
    result, _ = classify(tmp_path, TOR_IP, standard_routes(), at=T0 + hours(offset_hours))
    assert result.label is Label.UNKNOWN
