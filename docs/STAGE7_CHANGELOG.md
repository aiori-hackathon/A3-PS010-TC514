# Stage 7: evaluation and release readiness (`0.7.0-stage7`)

`POLICY_VERSION = "ps010-policy-1"`, `SERVICE_VERSION = "ps010-service-1"`, the three labels, the
nine reason codes, the classifier, adapters, parsers, cache, `service.py`, `collector.py`,
`ripestat.py`, `ipinfo.py`, the audit package and schema, retention, `config.py`, every existing CLI
script and the dashboard are **unchanged**. No existing test file was edited or removed.

## Added
* `src/netclass/evaluation/`: `dataset.py` (strict schema, loader, validator, canonical hash),
  `metrics.py` (denominators, selective classification, warnings), `report.py` (JSON + Markdown),
  `replay.py` (offline fetcher serving fixture worlds), `runner.py` (replay and live modes). The first
  three need only the standard library.
* `scripts/evaluate.py`: the evaluation command.
* `evaluation/datasets/ps010-eval-v1/`: `dataset.json` (42 synthetic cases, 11 fixture worlds, no
  reference cases), `README.md`, `PROVENANCE.md`.
* `evaluation/reports/ps010-eval-v1-replay.{json,md}`: release-evidence reports, checked by a test.
* Tests: `test_evaluation_metrics.py`, `test_evaluation_dataset.py`, `test_evaluation_runner.py`,
  `test_evaluation_isolation.py`, `test_evaluation_cli.py`, helper `evaluation_support.py`.
* Docs: `EVALUATION.md`, this file, `STAGE7_VERIFICATION.md`; README section.

## Changed
* `netclass/__init__.py`: `__version__` `0.6.0-stage6` -> `0.7.0-stage7`. This string is shown on the
  dashboard Status tab; no test pins it. It is the only user-visible difference.
* `.gitignore`: ignores `evaluation/output/` and `evaluation/output-live/` (not `evaluation/reports/`).
* `README.md`: status, evaluation section, layout, roadmap (Stage 8 not started).

## Design decisions
* **No second classifier.** The runner only calls `ClassificationService.classify`; a test compares
  every case with `classify_with_evidence` over the same adapters.
* **Synthetic and reference never share a metric block**; synthetic results are labeled policy
  conformance and cannot be presented as accuracy.
* **Unlabeled is explicit**: needs a reason, is listed, is never scored.
* **Isolation by construction and by test**: the package imports nothing from the audit, dashboard,
  network, database or `.env` code; the service is built with `audit=None`.
* The label/reason-code/source-name/tolerance constants duplicated in `dataset.py` (to keep it
  pydantic-free) are pinned to the real ones by a test.
* Fixture sanity floors lowered to 1 in replay, recorded in every report.

## Conflicts with the existing architecture (documented, nothing changed)
* `UNKNOWN_HOSTING_ONLY` is unreachable through the service, so it is not evaluated end to end.
* No source has validity intervals, so historical ground truth cannot be source-backed.
* Two conservative-but-surprising behaviors are recorded as observations in `EVALUATION.md`.
* `tests/test_audit_isolation.py` pins the exact set of modules that import the audit package; the
  new package adds none (verified).
