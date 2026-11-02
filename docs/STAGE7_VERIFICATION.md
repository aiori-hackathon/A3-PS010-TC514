# Stage 7 verification report

Date of preparation: 2026-11-01. Version `0.7.0-stage7`. Baseline: `viltrumites-ps010-stage6.zip`,
SHA-256 `7aa64608ec2bf46320bf32ce743152fdb3b6e35090134eef02faa0902202c49b` (re-checked after the work;
unchanged). Baseline you verified on Windows, Python 3.12.10: **1,045 passed, 2 skipped, 0 failed**
(your report; not re-run by the author of Stage 7).

## Read this first: what was and was not executed

**The real pytest suite was NOT run for Stage 7. Do not read this report as "the suite passed".**

The environment that produced this package is Linux, Python 3.12.3, with **no pydantic, requests,
pytest or Streamlit installed and no network access** (`pip` could not download anything). So:

* `pytest` (new tests and the 1,045 existing ones): **not run**.
* Streamlit smoke test and the manual dashboard checks: **not run**.
* Live sources / `--live`: **not run** (no network; no reference cases exist anyway).
* Windows: **not run**. The code was written to be Windows-safe (see below) but only you can confirm it.

What *was* executed, honestly described:

* `python3 -m compileall -q src tests scripts app.py`: OK (Python 3.12.3).
* `python3 scripts/evaluate.py --check-only` (standard library only): `dataset OK: ps010-eval-v1 1.0.0
  sha256=736acbdd...8218 cases=42 synthetic=42 reference=0`.
* **A stand-in harness** (kept outside the package, not shipped): a ~100-line imitation of the parts
  of pydantic, requests and pytest that netclass and these tests use. It executes the **real**
  `netclass` classifier, adapters, parsers, snapshot provider, service and the new evaluation code,
  but with a stand-in model layer and test runner. It is **not** pydantic and **not** pytest, and
  every result below is labeled "stand-in".

| stand-in run | result |
|---|---|
| `test_evaluation_metrics.py` | 29 passed, 0 failed |
| `test_evaluation_dataset.py` | 97 passed, 0 failed |
| `test_evaluation_runner.py` | 33 passed, 0 failed |
| `test_evaluation_isolation.py` | 24 passed, 0 failed |
| `test_evaluation_cli.py` | 13 passed, 0 failed |
| **new tests together** | **196 passed, 0 failed, 0 skipped** |
| `test_audit_isolation.py`, `test_dashboard_boundaries.py` (they scan the new files) | 12 and 9 passed |
| all 30 loadable existing test files, Stage 6 baseline tree vs Stage 7 tree | **identical per-file results** (799 passed / 52 failed / 6 files unloadable on BOTH trees) |

The 52 failures and 6 unloadable files in the existing suite are limits of the stand-in (it has no
`model_fields`, `ValidationError`, `ConnectTimeout`, `importorskip`, real subprocess behavior, ...).
They are identical on the untouched Stage 6 tree, so they show the stand-in's gaps and say nothing
about the real suite. The only conclusion drawn from the comparison is "no difference was
introduced relative to the baseline under the same harness".

Mutation checks (scratch copies, discarded): removing the excluded-address short-circuit made 4
evaluation tests fail; widening `current_evidence_tolerance_seconds` to 30 days made 7 fail. So the
tests are sensitive to the regressions they exist to catch.

The static `diff -rq` against the Stage 6 tree shows exactly: modified `.gitignore`, `README.md`,
`src/netclass/__init__.py` (version string only); everything else added. No existing test file was
touched.

## Commands for you (Windows PowerShell, Python 3.12)

From the folder that contains `README.md`:

```powershell
py -3.12 --version
python -m pip install -r requirements.txt -r requirements-dev.txt

# 1. The new tests first
python -m pytest tests\test_evaluation_*.py -v 2>&1 | Tee-Object evaluation-tests.txt

# 2. The full suite (new + existing)
python -m pytest -v 2>&1 | Tee-Object test-results.txt

# 3. The evaluation itself
python scripts\evaluate.py --check-only
python scripts\evaluate.py --out-dir evaluation\output --strict
echo $LASTEXITCODE                      # expect 0

# 4. Cross-machine determinism: compare with the committed release evidence
Get-FileHash evaluation\output\evaluation-report.json -Algorithm SHA256
Get-FileHash evaluation\output\evaluation-report.md   -Algorithm SHA256
Get-FileHash evaluation\reports\ps010-eval-v1-replay.json -Algorithm SHA256
```

**Expected (not yet verified by anyone on Windows):**

* new tests: **196 passed** (pytest's parametrization should match; a small count difference would
  be worth sending to me);
* full suite: **1,045 + 196 = 1,241 passed, 2 skipped, 0 failed**;
* `--check-only` prints `sha256=736acbddd488c0791ade2cc1ede9352f4f76c4b4ed850ddc03ded5f5768a8218`
  (SHA-256 of the dataset's canonical JSON; the raw file's own SHA-256 is
  `a0fc85e583dd9a5823ab993fc6b6c8f50e9a94a20a3032e5b6e1ee18db723462` and may differ if git changes
  line endings, which does not affect the canonical hash);
* `evaluation-report.json` SHA-256 `3f74e3bb27f31c626bbfe189a0d649af5a2433eff9cda0bf360ef42c7e56dbe4`,
  `evaluation-report.md` SHA-256 `f53e52aa1e2bf289d525ac7f21172ffdb9cc6478d683782f2df03f8c492ef48c`.
  These were produced with the stand-in model layer. If your hashes match, the report is
  independent of the model implementation and the operating system. If they differ, run
  `fc /b` or compare the two files; `test_committed_release_reports_equal_a_fresh_run` will also
  show the difference. Do not edit the committed files by hand.

Also keep the Stage 6 manual checks in mind (`python -m streamlit run app.py`): only the Status tab's
version string changed (`0.7.0-stage7`).

## Inspection against your requirements

| requirement | how it is met | evidence |
|---|---|---|
| 1. Preserve Stage 6 baseline | no existing test, classifier, policy, audit, retention, CLI or dashboard file changed; Stage 6 ZIP untouched | `diff -rq`; ZIP SHA re-checked; `test_policy_and_label_constants_are_the_stage_6_ones` |
| 2. Strict dataset validation | `dataset.py` rejects malformed/duplicate keys, malformed records, duplicate ids, invalid labels/reason codes/IPs/timestamps, missing provenance, circular sources, current-only-as-historical; unlabeled handling explicit (`unlabeled_reason`, listed, never scored) | 97 dataset tests incl. 42 malformed-input cases and the 3600/3601 s boundary |
| 3. Deterministic output | fixed clock, sorted keys/cases, bytes written with LF, no path/host/Python/wall-clock; dataset SHA-256 and exact configuration recorded | `test_identical_input_and_clock_give_byte_identical_json_and_markdown`, `test_output_has_no_machine_specific_content`, CLI two-run byte comparison, committed-report test |
| 4. Isolation | no audit/dashboard/network/db/dotenv import; `audit=None`; no files created; existing `data\` untouched; excluded addresses make 0 fetches; context-only metadata cannot change any of the 42 classifications | `test_evaluation_isolation.py`, `test_excluded_addresses_trigger_zero_evidence_fetches` |
| 5. Unambiguous metrics | synthetic conformance and reference accuracy are separate blocks; every denominator documented in the report; coverage vs selective precision separate; undefined = `null` + reason; small-sample warnings; synthetic never called accuracy | `test_evaluation_metrics.py` (hand-computed), `test_synthetic_results_are_never_presented_as_real_world_accuracy` |
| 6. Verification and packaging | this report; exact commands above; ZIP + SHA-256 supplied separately | |

Conflicts with the existing architecture (documented, nothing changed): `UNKNOWN_HOSTING_ONLY` is
unreachable through the service; no source has validity intervals, so no source-backed historical
ground truth; `tests/test_audit_isolation.py` pins the importer set of the audit package (the new
package adds none; verified). Two surprising-but-conservative behaviors are recorded in
`docs/EVALUATION.md` for your review.

## Known limitations of this release

* The dataset is synthetic only: **there is no real-world accuracy, precision or recall figure**, and
  none should be quoted. 100% agreement on the fixtures is by construction.
* Class supports are 6 / 6 / 29, below the 30-case warning threshold; the reports warn about it.
* Fixture sanity floors are lowered to 1 (recorded); real floors are covered by the adapter tests.
* `--live` and the reference-case path are implemented and tested only with a mocked factory; the real
  HTTPS path has never been run.
* Constants duplicated in `dataset.py` (labels, reason codes, source names, tolerance, prefix floors)
  are pinned to the real ones by `test_constants_match_the_pipeline_they_describe`, which has not been
  run under real pytest.
* The `data\` directory and any real audit database are never touched; a test enforces that on your
  machine even if such a database exists.
