"""Stage 7 evaluation command.

    python scripts\\evaluate.py --check-only
    python scripts\\evaluate.py --out-dir evaluation\\output
    python scripts\\evaluate.py --strict
    python scripts\\evaluate.py --live --out-dir evaluation\\output-live   (network; reference cases)

Default: offline replay of the synthetic fixture cases through the real classification service.
Nothing is written unless --out-dir is given (then exactly two files:
evaluation-report.json and evaluation-report.md). Audit history, ``data/`` and ``.env`` are never
read or modified. Exit codes: 0 ok, 2 invalid input / cannot run, 3 --strict and a mismatch or
invariant violation was found.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

DEFAULT_DATASET = PROJECT_ROOT / "evaluation" / "datasets" / "ps010-eval-v1" / "dataset.json"
JSON_NAME = "evaluation-report.json"
MD_NAME = "evaluation-report.md"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="PS-010 evaluation (Stage 7).")
    p.add_argument("--dataset", type=Path, default=DEFAULT_DATASET, help="dataset JSON file")
    p.add_argument("--out-dir", type=Path, default=None,
                   help="write evaluation-report.json and .md here (default: print JSON to stdout)")
    p.add_argument("--check-only", action="store_true", help="validate the dataset and exit")
    p.add_argument("--strict", action="store_true",
                   help="exit 3 if any labeled case mismatches or an invariant is violated")
    p.add_argument("--live", action="store_true",
                   help="use the REAL sources over the network for reference-tier cases")
    return p


def _problems(report: dict) -> int:
    count = len(report["invariants"]["violations"])
    for block in (report["synthetic_policy_conformance"], report["reference_accuracy"]):
        if block["status"] == "computed":
            count += len(block["mismatches"])
    return count


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    from netclass.evaluation.dataset import DatasetError, load_dataset

    try:
        dataset = load_dataset(args.dataset)
    except DatasetError as exc:
        print("Dataset rejected:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    if args.check_only:
        tiers = {t: len(dataset.cases_of_tier(t)) for t in ("synthetic", "reference")}
        print(f"dataset OK: {dataset.dataset_id} {dataset.dataset_version} "
              f"sha256={dataset.sha256} cases={len(dataset.cases)} "
              f"synthetic={tiers['synthetic']} reference={tiers['reference']}")
        return 0

    from netclass.evaluation.report import render_json, render_markdown
    from netclass.evaluation.runner import EvaluationError, run_live, run_replay

    try:
        report = run_live(dataset) if args.live else run_replay(dataset)
    except EvaluationError as exc:
        print(f"Cannot evaluate: {exc}", file=sys.stderr)
        return 2

    json_text = render_json(report)
    if args.out_dir is None:
        sys.stdout.write(json_text)
    else:
        out_dir: Path = args.out_dir
        if out_dir.exists() and not out_dir.is_dir():
            print(f"--out-dir {out_dir} exists and is not a directory", file=sys.stderr)
            return 2
        out_dir.mkdir(parents=True, exist_ok=True)
        # bytes, not text mode: LF endings and UTF-8 on every platform
        (out_dir / JSON_NAME).write_bytes(json_text.encode("utf-8"))
        (out_dir / MD_NAME).write_bytes(render_markdown(report).encode("utf-8"))
        print(f"wrote {out_dir / JSON_NAME} and {out_dir / MD_NAME}")
        print(f"mode={report['evaluation']['mode']} basis={report['evaluation']['evidence_basis']} "
              f"dataset_sha256={report['dataset']['sha256']} problems={_problems(report)}")

    if args.strict and _problems(report):
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
