"""Runner: policy conformance over fixtures, determinism, unlabeled handling, tiers, live path.

Every classification below is made by the real ClassificationService and adapters over a
ReplayFetcher; nothing touches the network. The live path is driven with a replay factory and
therefore labeled "mocked" in its report, never "live".
"""
import copy
import json
import platform
import re
import sys
from datetime import datetime, timezone
from functools import lru_cache

import pytest

from evaluation_support import (
    DATASET_PATH, ROOT, T0, case_of, edited, reference_case, shipped_raw, with_cases,
)
from netclass import __version__
from netclass.classifier import POLICY_VERSION
from netclass.config import Settings
from netclass.evaluation import dataset as ds
from netclass.evaluation.report import render_json, render_markdown
from netclass.evaluation.runner import (
    BASIS_REPLAY, EvaluationError, build_replay_service, check_outcome,
    default_replay_config, run_live, run_replay,
)
from netclass.service import SERVICE_VERSION


@lru_cache(maxsize=1)
def shipped():
    dataset = ds.load_dataset(DATASET_PATH)
    return dataset, run_replay(dataset)


def rows():
    return {row["case_id"]: row for row in shipped()[1]["cases"]}


# ----------------------------------------------------------- conformance
def test_every_labeled_synthetic_case_conforms_to_the_documented_policy():
    report = shipped()[1]
    block = report["synthetic_policy_conformance"]
    assert block["mismatches"] == []
    assert block["metrics"]["errors"]["total_mismatches"] == 0
    assert block["metrics"]["overall_agreement"]["numerator"] == 41
    assert block["metrics"]["overall_agreement"]["denominator"] == 41
    assert block["reason_code_agreement"]["numerator"] == block["reason_code_agreement"]["denominator"] == 41
    assert report["invariants"]["passed"] and report["invariants"]["violations"] == []


@pytest.mark.parametrize("case_id,label,reason", [
    ("syn-tor-001", "Known Tor exit", "TOR_EXIT_MATCH"),
    ("syn-vpn-001-x4bnet", "Known hosted VPN/proxy endpoint", "VPN_PROXY_ENDPOINT_MATCH"),
    ("syn-vpn-002-az0", "Known hosted VPN/proxy endpoint", "VPN_PROXY_ENDPOINT_MATCH"),
    ("syn-conflict-001-tor-x4bnet", "Unknown", "UNKNOWN_CONFLICTING_EVIDENCE"),
    ("syn-apple-001-relay-range", "Unknown", "UNKNOWN_NO_QUALIFYING_MATCH"),
    ("syn-historical-001-tor-listed", "Unknown", "UNKNOWN_STALE_EVIDENCE"),
    ("syn-historical-005-boundary-beyond", "Unknown", "UNKNOWN_STALE_EVIDENCE"),
    ("syn-unavail-002-tor-down-listed", "Unknown", "UNKNOWN_SOURCE_UNAVAILABLE"),
    ("syn-unavail-008-tor-stale-source", "Unknown", "UNKNOWN_SOURCE_UNAVAILABLE"),
    ("syn-ipv6-001-uncovered", "Unknown", "UNKNOWN_PROVIDER_NOT_CONFIGURED"),
    ("syn-notconf-001-no-vpn-provider", "Unknown", "UNKNOWN_PROVIDER_NOT_CONFIGURED"),
    ("syn-excluded-001-private-listed", "Unknown", "UNKNOWN_EXCLUDED_ADDRESS"),
])
def test_key_outcomes_are_pinned_to_the_existing_policy(case_id, label, reason):
    row = rows()[case_id]
    assert (row["predicted_label"], row["predicted_reason_code"]) == (label, reason)


def test_current_only_evidence_never_establishes_historical_status():
    for case_id in ("syn-historical-001-tor-listed", "syn-historical-002-vpn-listed"):
        assert rows()[case_id]["predicted_label"] == "Unknown"
        assert all(e["applicability"] != "APPLICABLE" for e in rows()[case_id]["evidence"])
    assert rows()["syn-tor-003-boundary-within"]["predicted_label"] == "Known Tor exit"


def test_the_only_label_a_run_can_produce_is_one_of_three():
    assert {r["predicted_label"] for r in shipped()[1]["cases"]} <= set(ds.LABELS)


# ----------------------------------------------------------- the metric sensitivity (not vacuous)
def test_a_wrong_expectation_is_reported_as_a_mismatch_with_its_reason():
    def wrong(raw):
        case_of(raw, "syn-tor-001").update(expected_label="Unknown", expected_reason_code="UNKNOWN_NO_QUALIFYING_MATCH")
    report = run_replay(ds.parse_dataset(edited(wrong)))
    block = report["synthetic_policy_conformance"]
    assert [m["case_id"] for m in block["mismatches"]] == ["syn-tor-001"]
    assert block["mismatches"][0]["kind"] == "definitive_where_unknown_expected"
    assert "'Known Tor exit'" in block["mismatches"][0]["detail"] and "TOR_EXIT_MATCH" in block["mismatches"][0]["detail"]
    assert block["metrics"]["errors"]["definitive_where_unknown_expected"] == 1
    assert block["metrics"]["per_class"]["Known Tor exit"]["false_positives"] == 1
    assert "syn-tor-001" in render_markdown(report).split("## Per-case errors")[1]


def test_a_reason_code_difference_alone_is_flagged_separately_from_a_label_error():
    def wrong_reason(raw):
        case_of(raw, "syn-nomatch-001").update(expected_reason_code="UNKNOWN_STALE_EVIDENCE")
    block = run_replay(ds.parse_dataset(edited(wrong_reason)))["synthetic_policy_conformance"]
    assert block["metrics"]["errors"]["total_mismatches"] == 0
    assert [m["kind"] for m in block["mismatches"]] == ["reason_code_differs"]
    assert block["reason_code_agreement"]["numerator"] == 40


# ----------------------------------------------------------- unlabeled
def test_unlabeled_cases_are_listed_and_never_scored():
    report = shipped()[1]
    row = rows()["syn-unlabeled-001"]
    assert row["status"] == "unlabeled" and row["label_match"] is None
    counts = report["synthetic_policy_conformance"]["metrics"]["counts"]
    assert (counts["evaluated"], counts["labeled"], counts["unlabeled"]) == (42, 41, 1)
    assert counts["unlabeled_case_ids"] == ["syn-unlabeled-001"]
    assert sum(map(sum, report["synthetic_policy_conformance"]["metrics"]["confusion_matrix"]["matrix"])) == 41


# ----------------------------------------------------------- evidence-fetch isolation
def test_excluded_addresses_trigger_zero_evidence_fetches():
    excluded = [r for r in rows().values() if r["address_excluded"]]
    assert len(excluded) == 8
    for row in excluded:
        assert row["fetch_calls"] == 0 and row["evidence"] == [], row["case_id"]
        assert row["predicted_reason_code"] == "UNKNOWN_EXCLUDED_ADDRESS"


def test_non_excluded_addresses_do_fetch_evidence():
    # proves the zero-fetch result above is the exclusion rule, not a replay that never fetches
    fetched = [r for r in rows().values() if not r["address_excluded"]]
    assert len(fetched) == 34 and all(r["fetch_calls"] > 0 for r in fetched)


def test_check_outcome_detects_a_fetch_for_an_excluded_address():
    base = dict(rows()["syn-excluded-003-loopback"])
    assert check_outcome(base, repeat_identical=True) == []
    bad = dict(base, fetch_calls=2)
    found = check_outcome(bad, repeat_identical=True)
    assert [v["invariant"] for v in found] == ["excluded_address_zero_fetches"]
    assert "2 evidence fetch" in found[0]["detail"]
    assert check_outcome(base, repeat_identical=False)[0]["invariant"] == "repeat_run_identical"
    assert check_outcome(dict(base, predicted_label="Maybe"), repeat_identical=True)[0]["invariant"] == "label_is_one_of_three"


# ----------------------------------------------------------- determinism
def test_identical_input_and_clock_give_byte_identical_json_and_markdown():
    dataset = ds.load_dataset(DATASET_PATH)
    first, second = run_replay(dataset), run_replay(dataset)
    assert render_json(first).encode("utf-8") == render_json(second).encode("utf-8")
    assert render_markdown(first).encode("utf-8") == render_markdown(second).encode("utf-8")


def test_output_has_no_machine_specific_content():
    text = render_json(shipped()[1]) + render_markdown(shipped()[1])
    assert "\r" not in text
    assert str(ROOT) not in text and str(ROOT).replace("\\", "/") not in text
    host = platform.node()
    assert len(host) < 6 or host not in text  # short host names would match ordinary words
    assert sys.version.split()[0] not in text
    assert not re.search(r"(?i)[a-z]:\\\\|/home/|/users/|/tmp/", text)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert today not in text or today == "2026-10-28"  # no wall-clock timestamp


def test_case_order_in_the_file_changes_the_dataset_hash_but_not_the_results():
    reordered = edited(lambda raw: raw["cases"].reverse())
    base, other = shipped()[1], run_replay(ds.parse_dataset(reordered))
    assert base["dataset"]["sha256"] != other["dataset"]["sha256"]
    for key in ("cases", "synthetic_policy_conformance", "invariants"):
        assert base[key] == other[key]


def test_reports_are_key_sorted_and_cases_are_sorted_by_id():
    report = shipped()[1]
    ids = [c["case_id"] for c in report["cases"]]
    assert ids == sorted(ids)
    text = render_json(report)
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# ----------------------------------------------------------- recorded provenance
def test_report_records_versions_dataset_hash_configuration_and_provenance():
    dataset, report = shipped()
    assert report["dataset"]["sha256"] == dataset.sha256 == ds.sha256_of_object(shipped_raw())
    assert report["dataset"]["id"] == "ps010-eval-v1" and report["dataset"]["case_count"] == 42
    assert report["versions"] == {
        "package": __version__, "policy": POLICY_VERSION, "service": SERVICE_VERSION,
        "evaluation_runner": "ps010-eval-runner-1", "report_schema": "ps010-eval-report-1",
    }
    defaults = Settings()
    assert report["configuration"] == {
        "mode": "replay",
        "evaluation_time": T0,
        "current_evidence_tolerance_seconds": defaults.current_evidence_tolerance_seconds,
        "cache_ttl_seconds": defaults.cache_ttl_seconds,
        "max_source_age_seconds": defaults.max_source_age_seconds,
        "sanity_floor_entries": 1,
        "disk_cache": "none (in-memory only)",
        "audit_enabled": False,
        "include_ripestat": False,
        "include_ipinfo": False,
    }
    ev = report["evaluation"]
    assert (ev["mode"], ev["evidence_basis"]) == ("replay", BASIS_REPLAY)
    assert (ev["network_used"], ev["deterministic"], ev["audit_enabled"]) == (False, True, False)
    names = {s["name"] for s in report["provenance"]["evaluated_sources"]}
    assert names == set(ds.CLASSIFIER_SOURCE_NAMES)
    assert set(report["provenance"]["worlds"]) == set(shipped()[0].worlds)
    assert all(re.fullmatch(r"[0-9a-f]{64}", w["sha256"]) for w in report["provenance"]["worlds"].values())


def test_synthetic_results_are_never_presented_as_real_world_accuracy():
    report = shipped()[1]
    block = report["synthetic_policy_conformance"]
    assert "NOT real-world accuracy" in block["interpretation"]
    md = render_markdown(report)
    assert md.startswith("# PS-010 evaluation report")
    assert "SYNTHETIC REPLAY" in md and "not real-world accuracy" in md
    assert report["reference_accuracy"]["status"] == "not_evaluated"
    assert "no reference-tier cases" in report["reference_accuracy"]["reason"]
    assert report["reference_accuracy"]["metrics"] is None
    assert any("Synthetic only" in w for w in report["warnings"])


def test_small_samples_are_warned_about():
    warnings = shipped()[1]["synthetic_policy_conformance"]["metrics"]["warnings"]
    assert any("'Known Tor exit' has only 6 labeled case(s)" in w for w in warnings)
    assert any("'Known hosted VPN/proxy endpoint' has only 6 labeled case(s)" in w for w in warnings)


# ----------------------------------------------------------- tiers stay separate
def test_reference_cases_are_skipped_and_listed_in_replay_not_silently_dropped():
    dataset = ds.parse_dataset(with_cases(reference_case()))
    report = run_replay(dataset)
    assert [s["case_id"] for s in report["skipped_cases"]] == ["ref-fixture-001"]
    assert "ref-fixture-001" not in {c["case_id"] for c in report["cases"]}
    assert report["reference_accuracy"]["status"] == "not_evaluated"
    assert "not run in this mode" in report["reference_accuracy"]["reason"]
    assert report["dataset"]["tier_counts"] == {"reference": 1, "synthetic": 42}


def _live_factory(dataset):
    def factory(cache_dir, clock):
        service, fetcher = build_replay_service(dataset.worlds["healthy"], default_replay_config(dataset))
        return service, fetcher, Settings()
    return factory


def _live_report(*cases):
    dataset = ds.parse_dataset(with_cases(*cases))
    fixed = datetime.fromisoformat(T0)
    report = run_live(dataset, factory=_live_factory(dataset), clock=lambda: fixed,
                      basis="mocked-replay", network_used=False)
    return dataset, report


def test_live_path_reports_reference_accuracy_separately_and_labels_a_mocked_run_as_mocked():
    extra = [
        reference_case(case_id="ref-fixture-001", ip="11.10.10.1", expected_label="Known Tor exit"),
        reference_case(case_id="ref-fixture-002", ip="14.40.50.60", category="no_match", expected_label="Unknown"),
        reference_case(case_id="ref-fixture-003", ip="14.40.50.61", category="no_match", expected_label=None,
                       unlabeled_reason="Reviewer could not confirm the status."),
    ]
    for case in extra[2:]:
        del case["reference"]
    _, report = _live_report(*extra)
    assert report["evaluation"]["evidence_basis"] == "mocked-replay"
    assert (report["evaluation"]["mode"], report["evaluation"]["deterministic"]) == ("live", False)
    assert report["synthetic_policy_conformance"]["status"] == "not_evaluated"
    block = report["reference_accuracy"]
    assert block["status"] == "computed" and block["cases_evaluated"] == 3
    counts = block["metrics"]["counts"]
    assert (counts["labeled"], counts["unlabeled"]) == (2, 1)
    assert block["metrics"]["overall_agreement"]["value"] == 1.0
    assert any("anecdotal" in w for w in block["metrics"]["warnings"])
    assert any("composition" in w for w in report["warnings"])
    row = next(c for c in report["cases"] if c["case_id"] == "ref-fixture-001")
    assert row["reference"]["source_type"] == "operator_attestation"
    assert len(report["skipped_cases"]) == 42 and all("replay-only" in s["reason"] for s in report["skipped_cases"])


def test_live_mode_refuses_to_run_without_reference_cases():
    with pytest.raises(EvaluationError, match="no reference-tier cases"):
        run_live(ds.load_dataset(DATASET_PATH), factory=_live_factory(ds.load_dataset(DATASET_PATH)))


def test_reference_mismatch_is_reported_per_case_with_its_reason():
    wrong = reference_case(case_id="ref-fixture-009", ip="14.40.50.60", category="no_match", expected_label="Known Tor exit")
    _, report = _live_report(wrong)
    block = report["reference_accuracy"]
    assert [m["kind"] for m in block["mismatches"]] == ["missed_by_abstention"]
    assert "UNKNOWN_NO_QUALIFYING_MATCH" in block["mismatches"][0]["detail"]


# ----------------------------------------------------------- release evidence stays in sync
def test_committed_release_reports_equal_a_fresh_run():
    """evaluation/reports/ is release evidence: it must be exactly what the code produces now.

    Compared after normalising CRLF (a Windows checkout may convert line endings). Passing on
    Windows with the real pydantic also shows the report does not depend on the implementation
    that generated it.
    """
    report = shipped()[1]
    committed_json = (ROOT / "evaluation" / "reports" / "ps010-eval-v1-replay.json").read_bytes()
    committed_md = (ROOT / "evaluation" / "reports" / "ps010-eval-v1-replay.md").read_bytes()
    assert committed_json.replace(b"\r\n", b"\n") == render_json(report).encode("utf-8")
    assert committed_md.replace(b"\r\n", b"\n") == render_markdown(report).encode("utf-8")
