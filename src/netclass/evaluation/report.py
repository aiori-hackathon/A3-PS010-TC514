"""Evaluation report: assembly, deterministic JSON and Markdown (standard library only).

Determinism rules (pinned by tests/test_evaluation_runner.py):
* no wall-clock time, host name, user name, absolute path or Python version is recorded;
  the only time in a replay report is the dataset's fixed ``evaluation_time``;
* every list is sorted or in dataset order, every dict is dumped key-sorted;
* text is UTF-8 with LF line endings on every platform.
"""
from __future__ import annotations

import json
from typing import Optional

from .metrics import LABELS, ScoredCase, compute_metrics, mismatch_kind, reason_code_agreement

REPORT_SCHEMA_VERSION = "ps010-eval-report-1"

SYNTHETIC_INTERPRETATION = (
    "Policy-conformance results on synthetic fixtures. The expected labels follow from the "
    "documented policy by construction, so agreement here shows only that the pipeline "
    "implements that policy on those fixtures. It is NOT real-world accuracy, precision or "
    "recall and must not be cited as such."
)
REFERENCE_INTERPRETATION = (
    "Agreement with independently sourced, timestamped reference labels. It is meaningful "
    "only for the conditions, time and population the reference cases cover; read the "
    "per-case provenance and the sample-size warnings first."
)


# --------------------------------------------------------------------------
# scoring one row
# --------------------------------------------------------------------------
def score_row(outcome: dict) -> dict:
    row = dict(outcome)
    expected = outcome["expected_label"]
    predicted = outcome["predicted_label"]
    expected_reason = outcome["expected_reason_code"]
    reason_hit: Optional[bool] = None
    if expected_reason is not None:
        reason_hit = expected_reason == outcome["predicted_reason_code"]
    if expected is None:
        row.update(status="unlabeled", label_match=None, mismatch_kind=None,
                   mismatch_detail="no reference label: not scored")
    elif expected != predicted:
        kind = mismatch_kind(expected, predicted)
        row.update(
            status="label_mismatch", label_match=False, mismatch_kind=kind,
            mismatch_detail=(
                f"expected {expected!r} but the pipeline returned {predicted!r} "
                f"({outcome['predicted_reason_code']}): {outcome['explanation']}"
            ),
        )
    elif reason_hit is False:
        row.update(
            status="reason_mismatch", label_match=True, mismatch_kind="reason_code_differs",
            mismatch_detail=(
                f"label agrees ({predicted!r}) but expected reason {expected_reason} and the "
                f"pipeline returned {outcome['predicted_reason_code']}"
            ),
        )
    else:
        row.update(status="match", label_match=True, mismatch_kind=None, mismatch_detail=None)
    row["reason_match"] = reason_hit
    return row


def _tier_block(rows: list[dict], interpretation: str) -> dict:
    scored = [ScoredCase(r["case_id"], r["expected_label"], r["predicted_label"]) for r in rows]
    return {
        "status": "computed",
        "interpretation": interpretation,
        "cases_evaluated": len(rows),
        "metrics": compute_metrics(scored),
        "reason_code_agreement": reason_code_agreement(
            (r["expected_reason_code"], r["predicted_reason_code"]) for r in rows
        ),
        "mismatches": [
            {"case_id": r["case_id"], "kind": r["mismatch_kind"], "detail": r["mismatch_detail"]}
            for r in rows
            if r["status"] in ("label_mismatch", "reason_mismatch")
        ],
    }


def _not_evaluated(reason: str) -> dict:
    return {"status": "not_evaluated", "reason": reason, "metrics": None}


# --------------------------------------------------------------------------
# assembling the report
# --------------------------------------------------------------------------
def build_report(
    *,
    dataset,
    config: dict,
    versions: dict,
    source_provenance: list,
    world_fingerprints: dict,
    outcomes: list,
    skipped: list,
    violations: list,
    invariants_checked: list,
    evidence_basis: str,
    network_used: bool,
    deterministic: bool,
) -> dict:
    rows = [score_row(o) for o in sorted(outcomes, key=lambda o: o["case_id"])]
    synthetic_rows = [r for r in rows if r["tier"] == "synthetic"]
    reference_rows = [r for r in rows if r["tier"] == "reference"]

    if synthetic_rows:
        synthetic = _tier_block(synthetic_rows, SYNTHETIC_INTERPRETATION)
    else:
        synthetic = _not_evaluated("no synthetic case was run in this mode")
    if reference_rows:
        reference = _tier_block(reference_rows, REFERENCE_INTERPRETATION)
    elif dataset.cases_of_tier("reference"):
        reference = _not_evaluated("reference cases exist but were not run in this mode (use --live)")
    else:
        reference = _not_evaluated(
            "the dataset contains no reference-tier cases: no accuracy, precision or recall "
            "against independent ground truth can be reported"
        )

    warnings = list(dataset.limitations)
    if synthetic_rows:
        warnings.append(SYNTHETIC_INTERPRETATION)
    if reference["status"] != "computed":
        warnings.append("Reference accuracy: " + reference["reason"] + ".")
    if reference["status"] == "computed":
        warnings.extend(reference["metrics"]["warnings"])
        warnings.append(
            "Reference-set composition (class balance, address population, source bias) has "
            "not been validated; do not generalise beyond the listed cases."
        )

    tier_counts = {t: len(dataset.cases_of_tier(t)) for t in ("reference", "synthetic")}
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "evaluation": {
            "mode": config["mode"],
            "evidence_basis": evidence_basis,
            "evaluation_time": config["evaluation_time"],
            "deterministic": deterministic,
            "network_used": network_used,
            "audit_enabled": config["audit_enabled"],
        },
        "versions": dict(versions),
        "dataset": {
            "id": dataset.dataset_id,
            "version": dataset.dataset_version,
            "schema_version": dataset.schema_version,
            "sha256": dataset.sha256,
            "description": dataset.description,
            "case_count": len(dataset.cases),
            "tier_counts": tier_counts,
        },
        "configuration": dict(config),
        "provenance": {
            "evaluated_sources": source_provenance,
            "worlds": world_fingerprints,
        },
        "synthetic_policy_conformance": synthetic,
        "reference_accuracy": reference,
        "invariants": {
            "checked": sorted(invariants_checked),
            "violations": sorted(violations, key=lambda v: (v["case_id"], v["invariant"])),
            "passed": not violations,
        },
        "skipped_cases": sorted(skipped, key=lambda s: s["case_id"]),
        "warnings": warnings,
        "cases": rows,
    }


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------
def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------
def _cell(value) -> str:
    text = "-" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _table(headers: list, rows: list) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(_cell(c) for c in row) + " |" for row in rows)
    return lines


def _fmt(r: dict) -> str:
    if r["value"] is None:
        return f"undefined ({r['undefined_reason']})"
    return f"{r['numerator']}/{r['denominator']} = {r['value']}"


def _metrics_section(block: dict, title: str) -> list[str]:
    out = [f"## {title}", ""]
    if block["status"] != "computed":
        out += [f"Not evaluated: {block['reason']}.", ""]
        return out
    m = block["metrics"]
    counts = m["counts"]
    out += [block["interpretation"], ""]
    out += [
        f"Cases evaluated: {counts['evaluated']}. Labeled (scored): {counts['labeled']}. "
        f"Unlabeled (listed, never scored): {counts['unlabeled']}.",
        "",
        "**Confusion matrix** (rows = expected, columns = predicted; labeled cases only)",
        "",
    ]
    short = ["Tor", "VPN/proxy", "Unknown"]
    out += _table(["expected \\ predicted", *short],
                  [[LABELS[i], *m["confusion_matrix"]["matrix"][i]] for i in range(len(LABELS))])
    out += ["", "**Per class** (denominators in the definitions below)", ""]
    pc = m["per_class"]
    out += _table(
        ["class", "support", "predicted", "TP", "FP", "FN", "precision", "recall"],
        [[label, pc[label]["support"], pc[label]["predicted_count"], pc[label]["true_positives"],
          pc[label]["false_positives"], pc[label]["false_negatives"],
          _fmt(pc[label]["precision"]), _fmt(pc[label]["recall"])] for label in LABELS],
    )
    sel = m["selective_classification"]
    out += ["", "**Coverage and selective classification** (reported separately on purpose)", ""]
    out += _table(
        ["measure", "value"],
        [["overall agreement", _fmt(m["overall_agreement"])],
         ["coverage (definitive predictions)", _fmt(sel["coverage"])],
         ["abstention rate (Unknown predictions)", _fmt(sel["abstention_rate"])],
         ["labeled coverage", _fmt(sel["labeled_coverage"])],
         ["selective precision", _fmt(sel["selective_precision"])],
         ["definitive recall", _fmt(sel["definitive_recall"])],
         ["primary reason-code agreement", _fmt(block["reason_code_agreement"])]],
    )
    err = m["errors"]
    out += ["", f"**Errors:** {err['total_mismatches']} label mismatch(es): "
            f"{err['definitive_where_unknown_expected']} definitive where Unknown expected, "
            f"{err['wrong_definitive_label']} wrong definitive label, "
            f"{err['missed_by_abstention']} missed by abstention.", ""]
    if m["warnings"]:
        out += ["**Sample-size warnings**", ""] + [f"- {w}" for w in m["warnings"]] + [""]
    out += ["**Denominators**", ""]
    out += [f"- `{name}`: {text}" for name, text in sorted(m["denominators"].items())]
    out.append("")
    return out


def render_markdown(report: dict) -> str:
    ev, ds, ver, cfg = report["evaluation"], report["dataset"], report["versions"], report["configuration"]
    lines: list[str] = [f"# PS-010 evaluation report: {ds['id']} {ds['version']}", ""]
    if ev["evidence_basis"] == "synthetic-fixture-replay":
        lines += ["> **SYNTHETIC REPLAY.** Every case below runs the real classification service "
                  "over fixture evidence with no network access. The results show policy "
                  "conformance only. They are not real-world accuracy.", ""]
    else:
        lines += [f"> Evidence basis: **{ev['evidence_basis']}**. See the sections below for what "
                  "this run can and cannot support.", ""]
    lines += ["## Run", ""]
    lines += _table(["field", "value"], [
        ["mode", ev["mode"]], ["evidence basis", ev["evidence_basis"]],
        ["evaluation time (UTC)", ev["evaluation_time"]],
        ["deterministic output", ev["deterministic"]], ["network used", ev["network_used"]],
        ["audit history enabled", ev["audit_enabled"]],
        ["package version", ver["package"]], ["policy version", ver["policy"]],
        ["service version", ver["service"]], ["evaluation runner", ver["evaluation_runner"]],
        ["report schema", ver["report_schema"]],
    ])
    lines += ["", "## Dataset", ""]
    lines += _table(["field", "value"], [
        ["id / version", f"{ds['id']} / {ds['version']}"], ["schema", ds["schema_version"]],
        ["SHA-256 (canonical JSON)", ds["sha256"]], ["cases", ds["case_count"]],
        ["synthetic cases", ds["tier_counts"]["synthetic"]],
        ["reference cases", ds["tier_counts"]["reference"]],
    ])
    lines += ["", ds["description"], "", "## Configuration", ""]
    lines += _table(["setting", "value"], [[k, cfg[k]] for k in sorted(cfg)])
    lines += ["", "## Provenance", ""]
    lines += _table(["evaluated source", "kind", "granularity", "temporal support", "licence"],
                    [[s["name"], s["kind"], s["granularity"], s["temporal_support"], s["license"]]
                     for s in report["provenance"]["evaluated_sources"]])
    if report["provenance"]["worlds"]:
        lines += ["", "Fixture worlds (SHA-256 of each world's canonical JSON):", ""]
        lines += _table(["world", "sha256", "description"],
                        [[n, w["sha256"], w["description"]] for n, w in sorted(report["provenance"]["worlds"].items())])
    lines.append("")
    lines += _metrics_section(report["synthetic_policy_conformance"], "Synthetic policy conformance")
    lines += _metrics_section(report["reference_accuracy"], "Reference-case accuracy")

    inv = report["invariants"]
    lines += ["## Invariant checks", "",
              f"Checked: {', '.join(inv['checked']) or 'none'}. Result: **{'PASSED' if inv['passed'] else 'VIOLATED'}**.", ""]
    lines += [f"- `{v['case_id']}` {v['invariant']}: {v['detail']}" for v in inv["violations"]]
    if inv["violations"]:
        lines.append("")

    bad = [r for r in report["cases"] if r["status"] in ("label_mismatch", "reason_mismatch")]
    lines += ["## Per-case errors", ""]
    if bad:
        for r in bad:
            lines.append(f"- `{r['case_id']}` [{r['mismatch_kind']}]: {r['mismatch_detail']}")
    else:
        lines.append("None: no labeled case disagreed with its expectation.")
    lines.append("")

    lines += ["## All cases", ""]
    lines += _table(
        ["case", "tier", "category", "ip", "observed (UTC)", "expected", "predicted", "reason", "fetches", "status"],
        [[r["case_id"], r["tier"], r["category"], r["ip"], r["observed_at"], r["expected_label"],
          r["predicted_label"], r["predicted_reason_code"], r["fetch_calls"], r["status"]]
         for r in report["cases"]],
    )
    lines.append("")
    if report["skipped_cases"]:
        lines += ["## Skipped cases (not silently dropped)", ""]
        lines += [f"- `{s['case_id']}`: {s['reason']}" for s in report["skipped_cases"]]
        lines.append("")
    lines += ["## Limitations and warnings", ""]
    lines += [f"- {w}" for w in report["warnings"]]
    lines.append("")
    return "\n".join(lines)
