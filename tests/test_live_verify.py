"""Live-verification engine, exercised only with fakes (no network)."""
import hashlib
import json

import pytest

from factories import T0
from fakes import FakeFetcher, MutableClock, cidr_body, ip_body
from netclass.errors import SourceError, SourceErrorKind
from netclass.live_verify import (
    KIND_CIDR_LIST,
    KIND_IP_LIST,
    ProbeTarget,
    format_markdown,
    run_live_verification,
)
from netclass.source_health import AbsenceSupport, SourceHealthState, absence_support, state_for_error

K = SourceErrorKind
TOR_URL = "https://tor.invalid/exits?key=SUPERSECRET"
X4B_V4 = "https://x4b.invalid/ipv4.txt"
X4B_V6 = "https://x4b.invalid/ipv6.txt"
APPLE = "https://x4b.invalid/apple.txt"
AZ0_A = "https://az0.invalid/a.txt"
AZ0_B = "https://az0.invalid/b.txt"

TARGETS = [
    ProbeTarget("tor_exit_list", "torbulkexitlist", TOR_URL, KIND_IP_LIST, 2, overlap_key="tor"),
    ProbeTarget("x4bnet_vpn", "ipv4.txt", X4B_V4, KIND_CIDR_LIST, 1, family=4, overlap_key="vpn_cidr_v4"),
    ProbeTarget("x4bnet_vpn", "ipv6.txt", X4B_V6, KIND_CIDR_LIST, 1, family=6, overlap_key="vpn_cidr_v6"),
    ProbeTarget("x4bnet_vpn", "apple.txt", APPLE, KIND_CIDR_LIST, 1, family=4, role="exclusion", overlap_key="apple"),
    ProbeTarget("az0_vpn_ip", "a.txt", AZ0_A, KIND_IP_LIST, 1, overlap_key="az0"),
    ProbeTarget("az0_vpn_ip", "b.txt", AZ0_B, KIND_IP_LIST, 1, overlap_key="az0"),
]
LM = {"Last-Modified": "Wed, 28 Oct 2026 06:00:00 GMT"}  # 6 h before T0

TOR_BODY = ip_body([f"203.0.113.{i}" for i in range(1, 6)])
HEALTHY_ROUTES = {
    TOR_URL: (TOR_BODY, {"ETag": '"t1"', **LM}),
    X4B_V4: (cidr_body(["203.0.113.0/29"]), LM),
    X4B_V6: (cidr_body(["2001:db8:aaaa::/48"]), LM),
    APPLE: (cidr_body(["203.0.113.0/30"]), LM),
    AZ0_A: (ip_body(["203.0.113.2", "198.51.100.7"]), LM),
    AZ0_B: (ip_body(["198.51.100.9"]), LM),
}


def run(routes, **kwargs):
    fetcher = FakeFetcher(routes, MutableClock(T0))
    clock = MutableClock(T0)
    report = run_live_verification(TARGETS, fetcher, clock=clock, **kwargs)
    files = {f"{f['source']}/{f['file']}": f for f in report["files"]}
    return report, files, fetcher


def test_all_healthy_report_has_full_provenance():
    report, files, _ = run(HEALTHY_ROUTES)
    assert report["summary"]["healthy"] == 6 and report["summary"]["unhealthy"] == 0
    tor = files["tor_exit_list/torbulkexitlist"]
    assert tor["state"] == "HEALTHY" and tor["http_status"] == 200 and tor["parser_outcome"] == "OK"
    assert tor["bytes"] == len(TOR_BODY) and tor["sha256"] == hashlib.sha256(TOR_BODY).hexdigest()
    assert tor["records"] == 5 and tor["ipv4_records"] == 5 and tor["etag"] == '"t1"'
    assert tor["checked_at"] == T0.isoformat() and tor["freshness_verifiable"] is True
    assert tor["source_age_seconds"] == 6 * 3600 and tor["absence_support"] == "CONFIRMED_ABSENCE"
    assert report["mode"] == "LIVE" and report["started_at"] == T0.isoformat()


def test_overlap_counts_when_every_source_is_healthy():
    report, _, _ = run(HEALTHY_ROUTES)
    overlap = report["tor_vpn_overlap"]
    assert overlap["status"] == "COMPLETE"
    assert overlap["tor_exit_addresses"] == 5
    assert overlap["tor_in_x4bnet_ranges"] == 5
    assert overlap["tor_in_az0_lists"] == 1
    assert overlap["tor_in_both_vpn_sources"] == 1
    assert overlap["tor_in_x4bnet_ranges_also_apple_excluded"] == 3  # 203.0.113.0/30 covers the Tor addresses .1 .2 .3
    assert overlap["top_matched_x4bnet_ranges"] == [("203.0.113.0/29", 5)]


def test_tor_failure_makes_overlap_not_assessable_and_absence_not_established():
    routes = {**HEALTHY_ROUTES, TOR_URL: SourceError(K.TIMEOUT, "no response within 10s", url=TOR_URL)}
    report, files, _ = run(routes)
    tor = files["tor_exit_list/torbulkexitlist"]
    assert tor["state"] == "SOURCE_FAILURE" and tor["error_kind"] == "TIMEOUT"
    assert tor["absence_support"] == "NOT_ESTABLISHED" and tor["parser_outcome"] == "NOT_RUN"
    assert report["tor_vpn_overlap"]["status"] == "NOT_ASSESSABLE"


def test_vpn_source_failure_gives_partial_overlap_and_names_the_failed_file():
    routes = {**HEALTHY_ROUTES, X4B_V4: SourceError(K.HTTP_STATUS, "HTTP 503", url=X4B_V4, status_code=503)}
    report, files, _ = run(routes)
    assert files["x4bnet_vpn/ipv4.txt"]["state"] == "SOURCE_FAILURE"
    assert files["x4bnet_vpn/ipv4.txt"]["http_status"] == 503
    overlap = report["tor_vpn_overlap"]
    assert overlap["status"] == "PARTIAL" and overlap["vpn_files_not_healthy"] == ["vpn_cidr_v4"]
    assert overlap["counts_are_lower_bounds"] is True  # the failed file could hide more overlap
    assert "edge case A" in overlap["note"]


def test_all_vpn_sources_down_is_not_assessable():
    routes = {
        **HEALTHY_ROUTES,
        X4B_V4: SourceError(K.CONNECTION, "refused", url=X4B_V4),
        X4B_V6: SourceError(K.CONNECTION, "refused", url=X4B_V6),
        AZ0_A: SourceError(K.TIMEOUT, "slow", url=AZ0_A),
        AZ0_B: SourceError(K.TIMEOUT, "slow", url=AZ0_B),
    }
    report, _, _ = run(routes)
    assert report["tor_vpn_overlap"]["status"] == "NOT_ASSESSABLE"


def test_apple_exclusion_outage_is_visible_in_health_and_overlap():
    routes = {**HEALTHY_ROUTES, APPLE: SourceError(K.HTTP_STATUS, "HTTP 500", url=APPLE, status_code=500)}
    report, files, _ = run(routes)
    apple = files["x4bnet_vpn/apple.txt"]
    assert apple["state"] == "SOURCE_FAILURE" and apple["role"] == "exclusion"
    assert apple["error_kind"] == "HTTP_STATUS" and apple["absence_support"] == "NOT_ESTABLISHED"
    overlap = report["tor_vpn_overlap"]
    assert overlap["status"] == "PARTIAL" and overlap["apple_exclusion_healthy"] is False
    assert overlap["tor_in_x4bnet_ranges_also_apple_excluded"] is None


@pytest.mark.parametrize(
    "body, state, kind",
    [
        (b"<html><body>502 Bad Gateway</body></html>", "PARSE_FAILURE", "MALFORMED"),
        (b"203.0.113.1/24\n203.0.113.2\n", "PARSE_FAILURE", "MALFORMED"),  # CIDR in exact list
        (b"# only a comment\n", "INSUFFICIENT_EVIDENCE", "EMPTY"),
        (b"", "INSUFFICIENT_EVIDENCE", "EMPTY"),
        (b"203.0.113.1\n", "INSUFFICIENT_EVIDENCE", "TOO_SMALL"),  # floor is 2 for the Tor target
        (b"203.0.113.1\n203.0.113.2\xff\n", "PARSE_FAILURE", "MALFORMED"),  # not UTF-8
    ],
)
def test_bad_tor_payloads_are_classified_and_never_healthy(body, state, kind):
    report, files, _ = run({**HEALTHY_ROUTES, TOR_URL: (body, LM)})
    tor = files["tor_exit_list/torbulkexitlist"]
    assert tor["state"] == state and tor["error_kind"] == kind
    assert tor["parser_outcome"] == kind and tor["absence_support"] == "NOT_ESTABLISHED"
    assert tor["bytes"] == len(body) and tor["http_status"] == 200  # provenance kept even on failure
    assert report["tor_vpn_overlap"]["status"] == "NOT_ASSESSABLE"


def test_schema_drift_ipv6_in_an_ipv4_only_file_is_a_parse_failure():
    routes = {**HEALTHY_ROUTES, X4B_V4: (cidr_body(["2001:db8::/32"]), LM)}
    _, files, _ = run(routes)
    assert files["x4bnet_vpn/ipv4.txt"]["state"] == "PARSE_FAILURE"


def test_stale_source_is_flagged_and_excluded_from_overlap():
    old = {"Last-Modified": "Sun, 25 Oct 2026 12:00:00 GMT"}  # 3 days
    routes = {**HEALTHY_ROUTES, X4B_V4: (cidr_body(["203.0.113.0/29"]), old)}
    report, files, _ = run(routes, max_source_age_seconds=86400)
    v4 = files["x4bnet_vpn/ipv4.txt"]
    assert v4["state"] == "STALE" and v4["error_kind"] == "STALE_SOURCE"
    assert v4["records"] == 1 and v4["absence_support"] == "NOT_ESTABLISHED"
    assert report["tor_vpn_overlap"]["vpn_files_not_healthy"] == ["vpn_cidr_v4"]


def test_missing_last_modified_is_healthy_but_flags_that_freshness_is_unverifiable():
    routes = {**HEALTHY_ROUTES, X4B_V4: (cidr_body(["203.0.113.0/29"]), {})}
    _, files, _ = run(routes)
    v4 = files["x4bnet_vpn/ipv4.txt"]
    assert v4["state"] == "HEALTHY" and v4["freshness_verifiable"] is False
    assert any("cannot be verified" in note for note in v4["notes"])


def test_too_large_and_other_fetch_errors_are_source_failures():
    routes = {**HEALTHY_ROUTES, AZ0_A: SourceError(K.TOO_LARGE, "body exceeds limit", url=AZ0_A)}
    _, files, _ = run(routes)
    assert files["az0_vpn_ip/a.txt"]["state"] == "SOURCE_FAILURE"
    assert files["az0_vpn_ip/a.txt"]["error_kind"] == "TOO_LARGE"


def test_request_budget_stops_further_probes_and_marks_them_not_checked():
    class Counting(FakeFetcher):
        requests_made = 0

        def fetch(self, url):
            self.requests_made += 1
            return super().fetch(url)

    fetcher = Counting(HEALTHY_ROUTES, MutableClock(T0))
    report = run_live_verification(TARGETS, fetcher, clock=MutableClock(T0), request_budget=3)
    states = [f["state"] for f in report["files"]]
    assert states[:3] == ["HEALTHY"] * 3 and states[3:] == ["NOT_CHECKED"] * 3
    assert fetcher.requests_made == 3 and report["requests_made"] == 3
    assert report["files"][4]["message"].startswith("request budget exhausted")


def test_report_is_json_serialisable_and_redacted():
    routes = {
        **HEALTHY_ROUTES,
        AZ0_A: SourceError(K.CONNECTION, f"failed to reach {TOR_URL} token=SUPERSECRET", url=AZ0_A),
    }
    report, _, _ = run(routes)
    text = json.dumps(report) + format_markdown(report)
    assert "SUPERSECRET" not in text
    assert "https://tor.invalid/exits?<redacted>" in text
    assert "# Live source verification" in format_markdown(report)


def test_state_mapping_and_absence_rule():
    assert state_for_error(K.TIMEOUT) is SourceHealthState.SOURCE_FAILURE
    assert state_for_error(K.MALFORMED) is SourceHealthState.PARSE_FAILURE
    assert state_for_error(K.EMPTY) is SourceHealthState.INSUFFICIENT_EVIDENCE
    assert state_for_error(K.TOO_SMALL) is SourceHealthState.INSUFFICIENT_EVIDENCE
    assert state_for_error(K.STALE_SOURCE) is SourceHealthState.STALE
    for kind in K:
        assert state_for_error(kind) is not SourceHealthState.HEALTHY
    assert absence_support(SourceHealthState.HEALTHY) is AbsenceSupport.CONFIRMED_ABSENCE
    for state in SourceHealthState:
        if state is not SourceHealthState.HEALTHY:
            assert absence_support(state) is AbsenceSupport.NOT_ESTABLISHED


# ------------------------------------------------------------------ group floor
def test_az0_combined_floor_is_reported_separately_from_per_file_health():
    fetcher = FakeFetcher(HEALTHY_ROUTES, MutableClock(T0))
    report = run_live_verification(
        TARGETS, fetcher, clock=MutableClock(T0), group_floors={"az0": 1000}
    )
    check = report["group_checks"][0]
    assert check["group"] == "az0" and check["healthy_records_total"] == 3
    assert check["state"] == "INSUFFICIENT_EVIDENCE" and check["combined_floor"] == 1000
    assert report["summary"]["unhealthy"] == 0  # the files themselves parsed fine
