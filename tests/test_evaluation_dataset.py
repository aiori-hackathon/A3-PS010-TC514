"""Dataset integrity: strict validation, provenance, timestamps, hashing, unlabeled handling."""
import json
import re
from datetime import timezone

import pytest

import netclass.parsers as parsers
from evaluation_support import (
    DATASET_PATH, T0, case_of, edited, reference_case, shipped_raw, with_cases,
)
from netclass.classifier import DEFAULT_CURRENT_TOLERANCE
from netclass.evaluation import dataset as ds
from netclass.models import Label, ReasonCode
from netclass.sources import AZ0_VPN_SOURCE, SOURCES


def problems_of(raw) -> list:
    with pytest.raises(ds.DatasetError) as caught:
        ds.parse_dataset(raw)
    return caught.value.problems


def assert_rejected(raw, fragment):
    found = problems_of(raw)
    assert any(fragment in p for p in found), found


# ----------------------------------------------------------- the shipped dataset
def test_shipped_dataset_loads_and_is_synthetic_only():
    d = ds.load_dataset(DATASET_PATH)
    assert d.dataset_id == "ps010-eval-v1" and d.dataset_version == "1.0.0"
    assert len(d.cases) == 42
    assert len(d.cases_of_tier("reference")) == 0
    assert len(d.cases_of_tier("synthetic")) == 42
    assert "SYNTHETIC ONLY" in d.description
    assert any("no independently sourced" in text.lower() for text in d.limitations)


def test_shipped_dataset_covers_every_required_situation():
    d = ds.load_dataset(DATASET_PATH)
    categories = {c.category for c in d.cases}
    assert {"known_tor_exit", "known_vpn_proxy", "no_match", "conflicting_evidence",
            "source_unavailable", "source_not_configured", "stale_or_historical",
            "excluded_address", "ipv6_coverage", "apple_private_relay", "unlabeled"} <= categories
    labels = {c.expected_label for c in d.cases}
    assert labels == set(ds.LABELS) | {None}


def test_every_shipped_case_is_documented_and_ids_are_sorted_and_unique():
    d = ds.load_dataset(DATASET_PATH)
    ids = [c.case_id for c in d.cases]
    assert ids == sorted(ids) and len(set(ids)) == len(ids)
    for case in d.cases:
        assert case.tier == "synthetic" and case.rationale and case.world in d.worlds


def test_shipped_dataset_has_no_secrets_or_personal_data():
    text = DATASET_PATH.read_text(encoding="utf-8")
    assert not re.search(r"(?i)(token|secret|password|api[_-]?key|bearer)\s*[:=]", text)
    assert "@" not in text
    assert not re.search(r"(?i)[a-z]:\\\\|/home/|/users/", text)


def test_unlabeled_synthetic_case_is_valid_and_carries_no_label():
    d = ds.load_dataset(DATASET_PATH)
    case = next(c for c in d.cases if c.case_id == "syn-unlabeled-001")
    assert case.expected_label is None and case.expected_reason_code is None and case.unlabeled_reason


# ----------------------------------------------------------- hashing
def test_hash_is_the_sha256_of_canonical_json_and_stable():
    d1, d2 = ds.load_dataset(DATASET_PATH), ds.load_dataset(DATASET_PATH)
    assert d1.sha256 == d2.sha256 == ds.sha256_of_object(shipped_raw())
    assert re.fullmatch(r"[0-9a-f]{64}", d1.sha256)


def test_hash_ignores_line_endings_and_key_order(tmp_path):
    raw = shipped_raw()
    crlf = tmp_path / "crlf.json"
    crlf.write_bytes(json.dumps(raw, indent=4).replace("\n", "\r\n").encode("utf-8"))
    reordered = tmp_path / "reordered.json"
    reordered.write_text(json.dumps(dict(reversed(list(raw.items()))), indent=1), encoding="utf-8")
    base = ds.load_dataset(DATASET_PATH).sha256
    assert ds.load_dataset(crlf).sha256 == base
    assert ds.load_dataset(reordered).sha256 == base


def test_hash_changes_when_any_content_changes():
    base = ds.parse_dataset(shipped_raw()).sha256
    changed = edited(lambda r: case_of(r, "syn-tor-001").update(rationale="different"))
    assert ds.parse_dataset(changed).sha256 != base


def test_utf8_bom_is_tolerated(tmp_path):
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + DATASET_PATH.read_bytes())
    assert ds.load_dataset(path).sha256 == ds.load_dataset(DATASET_PATH).sha256


# ----------------------------------------------------------- pins to the real pipeline
def test_constants_match_the_pipeline_they_describe():
    assert list(ds.LABELS) == [label.value for label in Label]
    assert list(ds.REASON_CODES) == [code.value for code in ReasonCode]
    assert set(ds.CLASSIFIER_SOURCE_NAMES) == set(SOURCES)
    assert set(ds.SOURCE_KEYS.values()) == set(SOURCES)
    assert set(ds.AZ0_FILES) == {url.rsplit("/", 1)[-1] for url in AZ0_VPN_SOURCE.endpoints}
    assert ds.CURRENT_ONLY_TOLERANCE_SECONDS == DEFAULT_CURRENT_TOLERANCE.total_seconds()
    assert (ds.MIN_PREFIX_V4, ds.MIN_PREFIX_V6) == (parsers.MIN_PREFIX_V4, parsers.MIN_PREFIX_V6)


# ----------------------------------------------------------- strict rejection
def test_duplicate_case_ids_are_rejected():
    raw = edited(lambda r: r["cases"].append(dict(case_of(r, "syn-tor-001"))))
    assert_rejected(raw, "duplicate case_id 'syn-tor-001'")


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "dup.json"
    path.write_text('{"schema_version": "a", "schema_version": "b"}', encoding="utf-8")
    with pytest.raises(ds.DatasetError, match="duplicate JSON key"):
        ds.load_dataset(path)


@pytest.mark.parametrize("text", ["{not json", "[]", '{"a": NaN}', ""])
def test_unparseable_or_wrong_shaped_files_are_rejected(tmp_path, text):
    path = tmp_path / "bad.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ds.DatasetError):
        ds.load_dataset(path)


def test_missing_file_is_a_dataset_error_without_leaking_the_path(tmp_path):
    missing = tmp_path / "does-not-exist-9f3.json"
    with pytest.raises(ds.DatasetError) as caught:
        ds.load_dataset(missing)
    assert "does-not-exist-9f3" not in str(caught.value)


def _mut(fn, fragment):
    return pytest.param(fn, fragment, id=fragment[:40])


CASE = "syn-tor-001"
BAD_MUTATIONS = [
    _mut(lambda r: case_of(r, CASE).update(expected_label="Tor exit"), "expected_label"),
    _mut(lambda r: case_of(r, CASE).update(expected_label="unknown"), "expected_label"),
    _mut(lambda r: case_of(r, CASE).update(expected_reason_code="NOT_A_CODE"), "unknown reason code"),
    _mut(lambda r: case_of(r, CASE).update(expected_reason_code="UNKNOWN_STALE_EVIDENCE"), "inconsistent with label"),
    _mut(lambda r: case_of(r, "syn-unlabeled-001").update(expected_reason_code="TOR_EXIT_MATCH"), "needs an expected_label"),
    _mut(lambda r: case_of(r, CASE).update(observed_at="2026-10-28T12:00:00"), "no UTC offset"),
    _mut(lambda r: case_of(r, CASE).update(observed_at="yesterday"), "not an ISO 8601"),
    _mut(lambda r: case_of(r, CASE).update(observed_at=1730116800), "must be a string"),
    _mut(lambda r: case_of(r, CASE).update(observed_at="2026-10-28"), "no UTC offset"),
    _mut(lambda r: r.update(evaluation_time="2026-10-28T12:00:00"), "evaluation_time"),
    _mut(lambda r: case_of(r, CASE).update(ip="not-an-ip"), "not a valid single IP"),
    _mut(lambda r: case_of(r, CASE).update(ip="11.10.10.0/24"), "not a valid single IP"),
    _mut(lambda r: case_of(r, CASE).update(ip="10.0.0.1"), "excluded by policy"),
    _mut(lambda r: case_of(r, "syn-excluded-003-loopback").update(ip="14.40.50.60"), "needs an address the policy excludes"),
    _mut(lambda r: case_of(r, CASE).update(tier="gold"), "tier"),
    _mut(lambda r: case_of(r, CASE).update(category="mystery"), "category"),
    _mut(lambda r: case_of(r, CASE).update(case_id="Bad ID!"), "case_id"),
    _mut(lambda r: case_of(r, CASE).update(bonus="field"), "unknown field 'bonus'"),
    _mut(lambda r: case_of(r, CASE).pop("expected_label"), "missing required field 'expected_label'"),
    _mut(lambda r: case_of(r, CASE).pop("ip"), "missing required field 'ip'"),
    _mut(lambda r: case_of(r, CASE).update(world="nowhere"), "unknown world"),
    _mut(lambda r: case_of(r, CASE).pop("rationale"), "rationale"),
    _mut(lambda r: case_of(r, CASE).update(unlabeled_reason="x"), "unlabeled_reason is only valid"),
    _mut(lambda r: case_of(r, "syn-unlabeled-001").pop("unlabeled_reason"), "unlabeled_reason"),
    _mut(lambda r: r.update(schema_version="v0"), "schema_version"),
    _mut(lambda r: r.update(cases=[]), "non-empty list"),
    _mut(lambda r: r.update(limitations=[]), "limitations"),
    _mut(lambda r: r.update(extra="x"), "unknown field 'extra'"),
    _mut(lambda r: r.pop("worlds"), "missing required field 'worlds'"),
    _mut(lambda r: r["worlds"]["healthy"]["tor"].update(entries=["not-an-ip"]), "not an IP address"),
    _mut(lambda r: r["worlds"]["healthy"]["tor"].pop("entries"), "entries"),
    _mut(lambda r: r["worlds"]["tor-unavailable"]["tor"].update(entries=["11.10.10.1"]), "must be absent"),
    _mut(lambda r: r["worlds"]["healthy"]["tor"].update(state="exploded"), "state"),
    _mut(lambda r: r["worlds"]["healthy"]["x4bnet"]["ipv4"].append("12.20.30.1/24"), "valid CIDR"),
    _mut(lambda r: r["worlds"]["healthy"]["x4bnet"]["ipv4"].append("0.0.0.0/0"), "broader than"),
    _mut(lambda r: r["worlds"]["healthy"]["x4bnet"]["ipv6"].append("12.20.31.0/24"), "not an IPv6 range"),
    _mut(lambda r: r["worlds"]["healthy"]["az0"]["files"].pop("pia.txt"), "exactly"),
    _mut(lambda r: r["worlds"]["healthy"].update(enabled_sources=["made-up-source"]), "unknown source"),
    _mut(lambda r: r["worlds"]["tor-only"].update(az0={"state": "http_error"}), "not enabled"),
    _mut(lambda r: r["worlds"]["healthy"].pop("az0"), "required because source"),
    _mut(lambda r: r["worlds"].update(orphan={"description": "never used", "tor": {"state": "http_error"}, "x4bnet": {"state": "http_error", "apple_state": "http_error"}, "az0": {"state": "http_error"}}), "never used"),
    _mut(lambda r: r["worlds"]["healthy"].update(description=""), "description"),
]


@pytest.mark.parametrize("mutate,fragment", BAD_MUTATIONS)
def test_malformed_datasets_are_rejected(mutate, fragment):
    assert_rejected(edited(mutate), fragment)


def test_all_problems_are_reported_together_not_just_the_first():
    def two_faults(r):
        case_of(r, CASE).update(ip="bogus", observed_at="never")
    found = problems_of(edited(two_faults))
    assert any("ip" in p for p in found) and any("observed_at" in p for p in found)


# ----------------------------------------------------------- reference cases: provenance
def test_a_complete_reference_case_is_accepted():
    d = ds.parse_dataset(with_cases(reference_case()))
    case = next(c for c in d.cases if c.case_id == "ref-fixture-001")
    assert case.tier == "reference" and case.reference["confidence"] == "medium"
    assert case.world is None and case.rationale is None


def test_labeled_reference_case_without_provenance_is_rejected():
    case = reference_case()
    del case["reference"]
    assert_rejected(with_cases(case), "missing its provenance")


@pytest.mark.parametrize("field", [
    "source", "source_type", "retrieved_at", "temporal_support",
    "label_basis", "confidence", "limitations", "independent_of_classifier_sources",
])
def test_every_required_provenance_field_is_enforced(field):
    case = reference_case()
    del case["reference"][field]
    assert_rejected(with_cases(case), f"missing required field '{field}'")


@pytest.mark.parametrize("override,fragment", [
    ({"source_type": "vibes"}, "source_type"),
    ({"confidence": "certain"}, "confidence"),
    ({"limitations": []}, "limitations"),
    ({"label_basis": " "}, "label_basis"),
    ({"retrieved_at": "2026-10-28T12:00:00"}, "no UTC offset"),
    ({"retrieved_at": "last tuesday"}, "not an ISO 8601"),
    ({"temporal_support": "forever"}, "temporal_support"),
    ({"independent_of_classifier_sources": "yes"}, "must be true"),
    ({"independent_of_classifier_sources": False}, "must be true"),
    ({"source": "tor-project-bulk-exit-list"}, "circular"),
    ({"source": "X4BNET-LISTS-VPN"}, "circular"),
    ({"source_url": "https://check.torproject.org/torbulkexitlist"}, "circular"),
    ({"source_url": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"}, "circular"),
    ({"source_url": "http://example.org/plain-http"}, "https"),
])
def test_invalid_provenance_is_rejected(override, fragment):
    assert_rejected(with_cases(reference_case(reference=override)), fragment)


def test_reference_case_may_not_carry_policy_reason_codes_or_a_world():
    assert_rejected(with_cases(reference_case(expected_reason_code="TOR_EXIT_MATCH")), "labels only")
    assert_rejected(with_cases(reference_case(world="healthy")), "must not name a fixture world")


def test_synthetic_case_may_not_carry_reference_provenance():
    raw = edited(lambda r: case_of(r, CASE).update(reference=reference_case()["reference"]))
    assert_rejected(raw, "must not carry reference provenance")


def test_unlabeled_reference_case_needs_a_reason_but_no_provenance():
    ok = reference_case(expected_label=None, unlabeled_reason="Reviewer could not confirm the status.")
    del ok["reference"]
    d = ds.parse_dataset(with_cases(ok))
    assert next(c for c in d.cases if c.case_id == "ref-fixture-001").expected_label is None
    bad = reference_case(expected_label=None)
    del bad["reference"]
    assert_rejected(with_cases(bad), "unlabeled_reason")


# ----------------------------------------------------------- current-only evidence is not history
def test_current_only_evidence_cannot_establish_historical_ground_truth():
    case = reference_case(observed_at="2026-10-20T12:00:00+00:00")  # retrieved 8 days later
    assert_rejected(with_cases(case), "cannot establish ground truth")


@pytest.mark.parametrize("gap_seconds,accepted", [(0, True), (3600, True), (3601, False), (-3600, True), (-3601, False)])
def test_current_only_tolerance_boundary(gap_seconds, accepted):
    from datetime import datetime, timedelta
    observed = datetime.fromisoformat(T0) + timedelta(seconds=gap_seconds)
    case = reference_case(observed_at=observed.isoformat())
    if accepted:
        ds.parse_dataset(with_cases(case))
    else:
        assert_rejected(with_cases(case), "cannot establish ground truth")


def test_current_only_reference_must_not_claim_a_validity_interval():
    case = reference_case(reference={"valid_from": T0, "valid_to": T0})
    assert_rejected(with_cases(case), "must not carry a validity interval")


def test_historical_label_is_only_accepted_with_time_bounded_support_covering_the_observation():
    interval = {"temporal_support": "time-bounded",
                "valid_from": "2026-10-01T00:00:00+00:00", "valid_to": "2026-10-10T00:00:00+00:00"}
    ok = reference_case(observed_at="2026-10-05T12:00:00+00:00", reference=interval)
    ds.parse_dataset(with_cases(ok))
    outside = reference_case(observed_at="2026-10-15T12:00:00+00:00", reference=interval)
    assert_rejected(with_cases(outside), "outside the reference validity interval")
    missing = reference_case(observed_at="2026-10-05T12:00:00+00:00", reference={"temporal_support": "time-bounded"})
    assert_rejected(with_cases(missing), "needs both valid_from and valid_to")
    inverted = reference_case(observed_at="2026-10-05T12:00:00+00:00", reference={
        "temporal_support": "time-bounded",
        "valid_from": "2026-10-10T00:00:00+00:00", "valid_to": "2026-10-01T00:00:00+00:00"})
    assert_rejected(with_cases(inverted), "valid_from is after valid_to")


# ----------------------------------------------------------- timestamps
def test_timestamps_are_normalised_to_utc():
    raw = edited(lambda r: case_of(r, CASE).update(observed_at="2026-10-28T14:00:00+02:00"))
    case = next(c for c in ds.parse_dataset(raw).cases if c.case_id == CASE)
    assert case.observed_at.utcoffset() == timezone.utc.utcoffset(None)
    assert case.observed_at.isoformat() == T0


def test_ipv4_mapped_addresses_are_normalised():
    d = ds.load_dataset(DATASET_PATH)
    case = next(c for c in d.cases if c.case_id == "syn-tor-002-ipv4-mapped")
    assert case.ip == "::ffff:11.10.10.1" and case.ip_normalized == "11.10.10.1"
