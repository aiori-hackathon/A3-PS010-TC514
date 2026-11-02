from fakes import FakeFetcher, MutableClock, ip_body
from factories import T0
from netclass.errors import SourceError, SourceErrorKind
from netclass.inspection import Floors, format_report, inspect_sources
from support import APPLE_URL, TOR_IP, TOR_URL, X4_V4, X4_V6, AZ0, standard_routes
from fakes import cidr_body

LOW = Floors(tor=1, x4_v4=1, x4_v6=1, apple=1, az0_file=1)


def report_for(routes):
    clock = MutableClock(T0)
    return inspect_sources(FakeFetcher(routes, clock), clock=clock, floors=LOW)


def test_report_lists_every_file_with_hash_and_counts():
    report = report_for(standard_routes())
    assert all(f["status"] == "OK" for f in report["files"])
    assert len(report["files"]) == 9  # tor + 2 x4bnet + apple + 5 az0
    tor = next(f for f in report["files"] if f["url"] == TOR_URL)
    assert tor["entries"] == 2 and len(tor["sha256"]) == 64
    assert report["generated_at"] == T0.isoformat()


def test_overlaps_between_sources_are_measured():
    routes = standard_routes()
    routes[X4_V4] = cidr_body(["185.220.101.0/24", "104.28.28.0/26"])  # covers the Tor exits
    routes[AZ0["pia.txt"]] = ip_body([TOR_IP])
    overlap = report_for(routes)["overlap"]
    assert overlap["tor_and_az0_exact"]["count"] == 1
    assert overlap["tor_inside_x4bnet_vpn_ranges"]["count"] == 2
    assert overlap["tor_inside_apple_private_relay_ranges"]["count"] == 0
    assert overlap["az0_inside_apple_private_relay_ranges"]["count"] == 0


def test_unavailable_sources_are_reported_and_their_overlaps_omitted():
    routes = standard_routes()
    routes[TOR_URL] = SourceError(SourceErrorKind.TIMEOUT, "no response", url=TOR_URL)
    report = report_for(routes)
    tor = next(f for f in report["files"] if f["url"] == TOR_URL)
    assert tor["status"] == "UNAVAILABLE" and tor["error_kind"] == "TIMEOUT"
    assert "tor_and_az0_exact" not in report["overlap"]
    assert "az0_inside_x4bnet_vpn_ranges" in report["overlap"]
    text = format_report(report)
    assert "[UNAVAILABLE]" in text and "could not be loaded" in text


def test_floors_flag_suspiciously_small_files():
    clock = MutableClock(T0)
    report = inspect_sources(FakeFetcher(standard_routes(), clock), clock=clock)  # default floors
    kinds = {f["error_kind"] for f in report["files"] if f["status"] != "OK"}
    assert "TOO_SMALL" in kinds
