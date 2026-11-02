"""Metrics: explicit denominators, unlabeled handling, undefined values, small-sample warnings.

Pure functions only (no pydantic, no network). Hand-computed expectations.
"""
import pytest

from netclass.evaluation.metrics import (
    LABELS,
    MIN_SUPPORT,
    ScoredCase,
    compute_metrics,
    mismatch_kind,
    ratio,
    reason_code_agreement,
)

T, V, U = LABELS


def sc(case_id, expected, predicted):
    return ScoredCase(case_id, expected, predicted)


# 10 cases: 8 labeled, 2 unlabeled
MIXED = [
    sc("c01", T, T), sc("c02", T, T), sc("c03", T, U),      # Tor: 2 hit, 1 missed by abstention
    sc("c04", V, V), sc("c05", V, T),                        # VPN: 1 hit, 1 wrong definitive
    sc("c06", U, U), sc("c07", U, U), sc("c08", U, V),      # Unknown: 2 hit, 1 false positive
    sc("c09", None, T), sc("c10", None, U),                  # unlabeled
]


def test_confusion_matrix_rows_are_expected_columns_are_predicted():
    m = compute_metrics(MIXED)
    assert m["confusion_matrix"]["labels"] == list(LABELS)
    assert m["confusion_matrix"]["matrix"] == [[2, 0, 1], [1, 1, 0], [0, 1, 2]]
    assert m["confusion_matrix"]["row_axis"].startswith("expected")


def test_unlabeled_cases_are_counted_listed_and_never_scored():
    m = compute_metrics(MIXED)
    assert m["counts"]["evaluated"] == 10
    assert m["counts"]["labeled"] == 8
    assert m["counts"]["unlabeled"] == 2
    assert m["counts"]["unlabeled_case_ids"] == ["c09", "c10"]
    assert sum(sum(row) for row in m["confusion_matrix"]["matrix"]) == 8  # matrix is labeled-only


def test_per_class_counts_precision_and_recall_with_explicit_denominators():
    pc = compute_metrics(MIXED)["per_class"]
    tor = pc[T]
    assert (tor["support"], tor["predicted_count"], tor["true_positives"]) == (3, 3, 2)
    assert (tor["false_positives"], tor["false_negatives"]) == (1, 1)
    assert (tor["precision"]["numerator"], tor["precision"]["denominator"], tor["precision"]["value"]) == (2, 3, 0.6667)
    assert (tor["recall"]["numerator"], tor["recall"]["denominator"], tor["recall"]["value"]) == (2, 3, 0.6667)
    vpn = pc[V]
    assert (vpn["support"], vpn["predicted_count"], vpn["true_positives"]) == (2, 2, 1)
    assert vpn["precision"]["value"] == 0.5 and vpn["recall"]["value"] == 0.5
    unk = pc[U]
    assert (unk["support"], unk["predicted_count"], unk["true_positives"]) == (3, 3, 2)


def test_overall_agreement_uses_labeled_cases_only():
    m = compute_metrics(MIXED)
    assert (m["overall_agreement"]["numerator"], m["overall_agreement"]["denominator"]) == (5, 8)
    assert m["overall_agreement"]["value"] == 0.625


def test_coverage_counts_all_evaluated_cases_selective_precision_only_labeled_definitive():
    sel = compute_metrics(MIXED)["selective_classification"]
    # coverage: definitive predictions among ALL 10 evaluated cases (c01,c02,c04,c05,c08,c09)
    assert (sel["coverage"]["numerator"], sel["coverage"]["denominator"]) == (6, 10)
    assert (sel["abstention_rate"]["numerator"], sel["abstention_rate"]["denominator"]) == (4, 10)
    # labeled coverage: definitive predictions among the 8 labeled cases
    assert (sel["labeled_coverage"]["numerator"], sel["labeled_coverage"]["denominator"]) == (5, 8)
    # selective precision: correct among labeled definitive predictions (c01,c02,c04 of c01,c02,c04,c05,c08)
    assert (sel["selective_precision"]["numerator"], sel["selective_precision"]["denominator"]) == (3, 5)
    # definitive recall: expected definitive & right, over expected definitive (c01..c05)
    assert (sel["definitive_recall"]["numerator"], sel["definitive_recall"]["denominator"]) == (3, 5)


def test_coverage_is_not_selective_precision():
    # abstaining on most cases lowers coverage but leaves selective precision perfect
    cases = [sc("a1", T, T), sc("a2", T, T)] + [sc(f"u{i}", U, U) for i in range(4)]
    sel = compute_metrics(cases)["selective_classification"]
    assert sel["coverage"]["value"] == 0.3333
    assert sel["selective_precision"]["value"] == 1.0


def test_error_breakdown_names_each_kind_of_mismatch():
    err = compute_metrics(MIXED)["errors"]
    assert err["total_mismatches"] == 3
    assert err["missed_by_abstention"] == 1
    assert err["wrong_definitive_label"] == 1
    assert err["definitive_where_unknown_expected"] == 1


@pytest.mark.parametrize("expected,predicted,kind", [
    (T, T, None), (U, U, None), (None, T, None), (None, U, None),
    (T, U, "missed_by_abstention"),
    (V, U, "missed_by_abstention"),
    (U, T, "definitive_where_unknown_expected"),
    (T, V, "wrong_definitive_label"),
])
def test_mismatch_kind(expected, predicted, kind):
    assert mismatch_kind(expected, predicted) == kind


def test_unknown_is_a_legitimate_output_not_an_error():
    m = compute_metrics([sc("a1", U, U), sc("a2", U, U)])
    assert m["errors"]["total_mismatches"] == 0
    assert m["overall_agreement"]["value"] == 1.0
    assert m["selective_classification"]["coverage"]["value"] == 0.0  # all abstained, none wrong


def test_undefined_ratios_are_null_with_a_reason_never_zero_or_one():
    m = compute_metrics([sc("a1", None, U), sc("a2", None, T)])
    assert m["overall_agreement"]["value"] is None
    assert "no labeled cases" in m["overall_agreement"]["undefined_reason"]
    for label in LABELS:
        assert m["per_class"][label]["precision"]["value"] is None
        assert m["per_class"][label]["recall"]["value"] is None
    assert m["selective_classification"]["selective_precision"]["value"] is None
    assert m["selective_classification"]["coverage"]["value"] == 0.5  # coverage needs no label
    assert any("No labeled cases" in w for w in m["warnings"])


def test_empty_input_is_all_undefined_without_crashing():
    m = compute_metrics([])
    assert m["counts"]["evaluated"] == 0
    assert m["selective_classification"]["coverage"]["value"] is None
    assert m["overall_agreement"]["value"] is None


def test_class_never_predicted_has_undefined_precision_but_defined_recall():
    m = compute_metrics([sc("a1", V, U), sc("a2", V, U)])
    vpn = m["per_class"][V]
    assert vpn["precision"]["value"] is None
    assert "predicted as" in vpn["precision"]["undefined_reason"]
    assert vpn["recall"]["value"] == 0.0 and vpn["recall"]["denominator"] == 2


def test_ratio_helper():
    assert ratio(1, 3, undefined_reason="x")["value"] == 0.3333
    r = ratio(0, 0, undefined_reason="nothing to divide")
    assert r["value"] is None and r["undefined_reason"] == "nothing to divide"


def test_small_samples_warn_overall_and_per_class():
    warnings = compute_metrics(MIXED)["warnings"]
    assert any(f"Only 8 labeled case(s) (< {MIN_SUPPORT})" in w for w in warnings)
    for label in LABELS:
        assert any(repr(label) in w for w in warnings)


def test_class_without_support_is_called_out():
    warnings = compute_metrics([sc("a1", U, U)] * 0 + [sc(f"a{i}", U, U) for i in range(40)])["warnings"]
    assert any("'Known Tor exit' has no labeled case" in w for w in warnings)
    assert not any("Only 40" in w for w in warnings)  # overall n is large enough


def test_no_warning_when_every_class_is_large_enough():
    cases = [sc(f"t{i}", T, T) for i in range(30)] + [sc(f"v{i}", V, V) for i in range(30)] + [sc(f"u{i}", U, U) for i in range(30)]
    assert compute_metrics(cases)["warnings"] == []


def test_input_order_does_not_change_the_result():
    assert compute_metrics(MIXED) == compute_metrics(list(reversed(MIXED)))


def test_every_denominator_is_documented():
    docs = compute_metrics(MIXED)["denominators"]
    for key in ("overall_agreement", "coverage", "abstention_rate", "labeled_coverage",
                "selective_precision", "definitive_recall", "precision[class]", "recall[class]"):
        assert docs[key]


@pytest.mark.parametrize("bad", [
    [sc("x", T, "Maybe")],
    [sc("x", "Tor", T)],
    [sc("x", T, T), sc("x", U, U)],
])
def test_invalid_input_is_rejected(bad):
    with pytest.raises(ValueError):
        compute_metrics(bad)


def test_reason_code_agreement_ignores_cases_without_an_expected_reason():
    r = reason_code_agreement([("A", "A"), ("A", "B"), (None, "C")])
    assert (r["numerator"], r["denominator"]) == (1, 2)
    none = reason_code_agreement([(None, "C")])
    assert none["value"] is None and none["undefined_reason"]
