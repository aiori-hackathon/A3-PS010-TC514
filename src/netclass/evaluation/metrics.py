"""Evaluation metrics (pure functions, standard library only).

Terms used everywhere in the evaluation report:

* ``evaluated``  : every case that was run in this tier.
* ``labeled``    : evaluated cases whose reference label is not null. ONLY labeled cases are
                   scored. An unlabeled case is counted, listed, and never treated as correct
                   or incorrect.
* ``definitive`` : a prediction (or reference label) that is one of the two "Known ..." labels.
* ``Unknown``    : a legitimate output (abstention), not automatically an error.

Every ratio is reported as ``{"numerator", "denominator", "value", "undefined_reason"}``. When
the denominator is 0 the value is ``null`` and ``undefined_reason`` says why; it is never
silently reported as 0 or 1.

These functions know nothing about where cases came from. The report keeps synthetic
policy-conformance and reference-case accuracy in separate blocks; a metric is only meaningful
for the tier it was computed on.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

LABELS = ("Known Tor exit", "Known hosted VPN/proxy endpoint", "Unknown")
UNKNOWN = "Unknown"
DEFINITIVE = tuple(label for label in LABELS if label != UNKNOWN)

# Below this many labeled cases (overall) or labeled cases per class, a ratio is anecdotal.
MIN_SUPPORT = 30
VALUE_DECIMALS = 4

DENOMINATORS = {
    "overall_agreement": "labeled cases where predicted == expected / labeled cases",
    "coverage": "evaluated cases with a definitive (non-Unknown) prediction / evaluated cases "
    "(includes unlabeled cases: coverage needs no reference label)",
    "abstention_rate": "evaluated cases predicted Unknown / evaluated cases (= 1 - coverage)",
    "labeled_coverage": "labeled cases with a definitive prediction / labeled cases",
    "selective_precision": "labeled cases with a definitive prediction that equals the "
    "expected label / labeled cases with a definitive prediction",
    "definitive_recall": "labeled cases with a definitive expected label that were predicted "
    "correctly / labeled cases with a definitive expected label",
    "precision[class]": "labeled cases predicted as the class and expected as the class / "
    "labeled cases predicted as the class",
    "recall[class]": "labeled cases predicted as the class and expected as the class / "
    "labeled cases expected as the class (class support)",
    "false_positives[class]": "labeled cases predicted as the class but expected as another class",
    "false_negatives[class]": "labeled cases expected as the class but predicted as another class",
}


@dataclass(frozen=True)
class ScoredCase:
    case_id: str
    expected: Optional[str]  # None = unlabeled
    predicted: str


def ratio(numerator: int, denominator: int, *, undefined_reason: str) -> dict:
    if denominator == 0:
        return {
            "numerator": numerator,
            "denominator": 0,
            "value": None,
            "undefined_reason": undefined_reason,
        }
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": round(numerator / denominator, VALUE_DECIMALS),
        "undefined_reason": None,
    }


def mismatch_kind(expected: Optional[str], predicted: str) -> Optional[str]:
    """Why a labeled case is wrong; None when it is correct or unlabeled."""
    if expected is None or expected == predicted:
        return None
    if predicted == UNKNOWN:
        return "missed_by_abstention"  # expected a definitive label, system abstained
    if expected == UNKNOWN:
        return "definitive_where_unknown_expected"  # a false positive on an abstention case
    return "wrong_definitive_label"  # two different definitive labels


def _validate(cases: list[ScoredCase]) -> None:
    seen: set[str] = set()
    for case in cases:
        if case.case_id in seen:
            raise ValueError(f"duplicate case_id in metrics input: {case.case_id!r}")
        seen.add(case.case_id)
        if case.predicted not in LABELS:
            raise ValueError(f"{case.case_id}: predicted {case.predicted!r} is not one of the three labels")
        if case.expected is not None and case.expected not in LABELS:
            raise ValueError(f"{case.case_id}: expected {case.expected!r} is not null or one of the three labels")


def compute_metrics(cases: Iterable[ScoredCase], *, min_support: int = MIN_SUPPORT) -> dict:
    items = sorted(cases, key=lambda c: c.case_id)
    _validate(items)
    labeled = [c for c in items if c.expected is not None]
    unlabeled = [c for c in items if c.expected is None]

    index = {label: i for i, label in enumerate(LABELS)}
    matrix = [[0] * len(LABELS) for _ in LABELS]
    for c in labeled:
        matrix[index[c.expected]][index[c.predicted]] += 1

    per_class: dict[str, dict] = {}
    for label in LABELS:
        i = index[label]
        tp = matrix[i][i]
        predicted_total = sum(matrix[r][i] for r in range(len(LABELS)))
        support = sum(matrix[i])
        per_class[label] = {
            "support": support,
            "predicted_count": predicted_total,
            "true_positives": tp,
            "false_positives": predicted_total - tp,
            "false_negatives": support - tp,
            "precision": ratio(
                tp, predicted_total,
                undefined_reason=f"no labeled case was predicted as {label!r}",
            ),
            "recall": ratio(
                tp, support,
                undefined_reason=f"no labeled case has {label!r} as its expected label",
            ),
        }

    correct = sum(matrix[i][i] for i in range(len(LABELS)))
    definitive_pred_labeled = [c for c in labeled if c.predicted != UNKNOWN]
    correct_definitive = [c for c in definitive_pred_labeled if c.predicted == c.expected]
    definitive_expected = [c for c in labeled if c.expected != UNKNOWN]
    definitive_hits = [c for c in definitive_expected if c.predicted == c.expected]
    definitive_pred_all = [c for c in items if c.predicted != UNKNOWN]
    kinds = [mismatch_kind(c.expected, c.predicted) for c in labeled]

    metrics = {
        "counts": {
            "evaluated": len(items),
            "labeled": len(labeled),
            "unlabeled": len(unlabeled),
            "unlabeled_case_ids": [c.case_id for c in unlabeled],
            "unlabeled_handling": "counted and listed; excluded from every scored metric; "
            "never treated as correct or incorrect",
        },
        "confusion_matrix": {
            "row_axis": "expected (reference) label",
            "column_axis": "predicted label",
            "labels": list(LABELS),
            "matrix": matrix,
        },
        "per_class": per_class,
        "overall_agreement": ratio(
            correct, len(labeled), undefined_reason="no labeled cases"
        ),
        "selective_classification": {
            "coverage": ratio(
                len(definitive_pred_all), len(items), undefined_reason="no evaluated cases"
            ),
            "abstention_rate": ratio(
                len(items) - len(definitive_pred_all), len(items),
                undefined_reason="no evaluated cases",
            ),
            "labeled_coverage": ratio(
                len(definitive_pred_labeled), len(labeled), undefined_reason="no labeled cases"
            ),
            "selective_precision": ratio(
                len(correct_definitive), len(definitive_pred_labeled),
                undefined_reason="no labeled case received a definitive prediction",
            ),
            "definitive_recall": ratio(
                len(definitive_hits), len(definitive_expected),
                undefined_reason="no labeled case has a definitive expected label",
            ),
        },
        "errors": {
            "total_mismatches": sum(1 for k in kinds if k is not None),
            "definitive_where_unknown_expected": kinds.count("definitive_where_unknown_expected"),
            "wrong_definitive_label": kinds.count("wrong_definitive_label"),
            "missed_by_abstention": kinds.count("missed_by_abstention"),
            "definitions": {
                "definitive_where_unknown_expected": "predicted a Known label, reference says Unknown",
                "wrong_definitive_label": "predicted one Known label, reference says the other",
                "missed_by_abstention": "reference says a Known label, system answered Unknown",
            },
        },
        "denominators": dict(DENOMINATORS),
        "warnings": sample_warnings(per_class, len(labeled), min_support),
    }
    return metrics


def sample_warnings(per_class: dict, labeled_count: int, min_support: int) -> list[str]:
    warnings: list[str] = []
    if labeled_count == 0:
        warnings.append("No labeled cases: every scored metric is undefined.")
        return warnings
    if labeled_count < min_support:
        warnings.append(
            f"Only {labeled_count} labeled case(s) (< {min_support}): overall ratios are anecdotal, "
            "not estimates."
        )
    for label in LABELS:
        support = per_class[label]["support"]
        if support == 0:
            warnings.append(f"Class {label!r} has no labeled case: its recall is undefined.")
        elif support < min_support:
            warnings.append(
                f"Class {label!r} has only {support} labeled case(s) (< {min_support}): "
                "its precision and recall are anecdotal."
            )
    return warnings


def reason_code_agreement(pairs: Iterable[tuple[Optional[str], str]]) -> dict:
    """Primary-reason-code agreement over cases that state an expected reason code."""
    stated = [(e, p) for e, p in pairs if e is not None]
    hits = sum(1 for e, p in stated if e == p)
    return ratio(hits, len(stated), undefined_reason="no case states an expected reason code")
