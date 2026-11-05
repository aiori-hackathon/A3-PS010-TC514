# Source health verification record

This record separates what was executed, where, and by whom. Windows results are maintainer-reported.
Sandbox results come from a stand-in runner, not from pytest. Only what was actually run is listed
as run.

The Windows run below was made on an earlier build of this change set. The final files differ from
that build in comments and docstrings, one unused import removed, one import moved to module level,
renamed test files and test functions, and renamed documentation files. **The final files have not
been run on Windows**: re-run the full suite on the files as committed.

## 1. Windows execution (maintainer, VS Code, earlier build): reported by the maintainer
    full suite:  1334 passed, 2 skipped in 187.76s (0:03:07)
    SKIPPED tests\test_audit_schema.py:186  POSIX permissions only
    SKIPPED tests\test_audit_schema.py:194  POSIX permissions only
Not seen by the preparer: the command line, the full pytest output, the per-file counts.

## 2. Sandbox execution (preparer, offline, NOT pytest)
The sandbox had Python 3.12 with `requests` only: no pytest, no pydantic, no network. A throwaway
stand-in runner (not shipped, not pytest) executed the pydantic-free tests:

| Scope | Result |
|---|---|
| 5 existing files (parsers, cache, snapshots, hashing, http_client) on the baseline tree | 80 passed |
| same 5 files on the final tree | 80 passed |
| new: http_client_hardening 36, redaction 9, live_verify 20, live_verify_cli 5 | 70 passed |

`python -m compileall src scripts tests`: clean. **No sandbox run of real pytest exists.**

## 3. Reconciliation of counts
* Previous release (maintainer): 1,241 passed + 2 skipped = **1,243 collected**.
* This change set (maintainer, earlier build): 1,334 passed + 2 skipped = **1,336 collected**.
* Difference: **93**, exactly the number of tests added (70 executed in the sandbox stand-in plus
  23 that need pydantic: test_live_targets 5, test_retry_config 7, test_evidence_policy_edge_cases 11).
  No existing test was added or removed, and the skips are the same two POSIX-permission tests.
* The 23 tests the sandbox could not run are inside the 1,334 passes, but per-file results were not
  seen, so that is inferred from the totals, not observed.
* Correction: an early prediction mixed passed with collected counts (1,241 + 93 = 1,334 is the
  number of **passed** tests; collected is 1,336).

## 4. Unreconciled item
A figure of 1,333 passed, 2 skipped was quoted in review. It does not come from any run recorded
here. If it came from another environment, record that output together with `python --version`,
`pip freeze` and the OS.

## 5. Were the same tests collected everywhere? Not verified
No collection list from Windows has been compared with anything. To check, run on Windows:

    python -m pytest --collect-only -q > collected-windows.txt
    python -m pytest -q -rs -p no:cacheprovider > results-windows.txt

Wording-only edits renamed some existing test functions and two new test files, so test ids in a
fresh collection differ from the earlier build for those tests. The expected new test ids per file
are derivable from the sources (36 + 9 + 20 + 5 + 5 + 7 + 11 = 93 parametrized cases).

## 6. Not run anywhere (as far as this record knows)
* `scripts\verify_sources.py --live` and any other live call: **no live verification has been done**.
* Git tree of the baseline commit vs the baseline archive; evaluation-report hash comparison as a
  separate step (the suite passing is not the same as that comparison).
* Real pytest in the sandbox.

## 7. Known limitations
* GitHub-hosted files send no `Last-Modified`: freshness cannot be verified for them.
* Tor endpoint live behaviour and count remain unverified until the live check is run.
* The Apple list is IPv4-only as observed. Retries apply to the three evidence sources only.
* Overlap output is counts only.

## 8. Final integrity review (preparer, sandbox, offline)
Run on the final files. Executed means a command was run and its output observed here.

| Check | Result |
|---|---|
| `python -W error -m compileall -q src scripts tests app.py` (Python 3.12.3) | clean |
| Stand-in runner (not pytest) on 9 pydantic-free test files: 5 existing (80 tests) + 4 new (70 tests) | 150 passed, 0 failed |
| Reference check: 267 repo-path, document-name and link references across all text files; no reference to a removed or renamed file remains | 0 broken. Four paths are generated or git-ignored by design and absent from the tree (`.streamlit/secrets.toml`, `evaluation/output/evaluation-report.{json,md}`) |
| Repo-local imports in all Python files resolve to defined names; no duplicate test function names | no problems (eight reports for `support.X4_V4` and `support.X4_V6` were false positives: they are defined by tuple assignment) |
| Executable-code comparison against the baseline tree (comments and docstrings ignored) | code differs only in the source-health modules, plus string literals in `scripts/evaluate.py` (argument description), `src/netclass/dashboard/ui.py` (caption text) and `src/netclass/sources.py` (two description strings) |
| `classifier.py`, `models.py`, `address_policy.py`, `parsers.py`, `inspection.py`, the three adapters, the audit package | executable code identical to the baseline |
| `evaluation/` | byte-identical to the baseline |
| 22 existing test files edited | identical to the baseline except docstrings, comments and test function names |
| Case-insensitive search for the retired development-sequence wording in all files, names and hidden files | 9 lines in 7 files, all documented in the reference audit; no file or directory name matches |

Not executed here, and why:
* **The real test suite (pytest).** pytest, pydantic and Streamlit are not installed and cannot be
  installed (no network). 43 of the 48 test files need them and were therefore not run at all in
  this environment, including the 23 new tests in `test_live_targets`, `test_retry_config` and
  `test_evidence_policy_edge_cases`.
* **Anything on Windows**, and `scripts\verify_sources.py` against the real endpoints.
The 1,334 passed / 2 skipped figure in section 1 is the maintainer's result on an earlier build and
is not a result for the final files.

## 9. Acceptance checklist
- [x] Full suite passes offline on Windows (1,334 passed, 2 skipped; maintainer-reported, earlier build)
- [ ] Full suite re-run on the final files
- [ ] Baseline reconciled (commit vs archive, evaluation hashes)
- [ ] Collection lists compared (section 5)
- [ ] Live verification run and report kept
- [ ] Baseline archive (SHA-256 4183fb74acddd4ea235e288f33a3a96d859cf271653ffb8f6e688add85718bcc) and tag unchanged: archive re-hashed in the sandbox; tag not checked
- [ ] Decisions A-D in `docs/EVIDENCE_POLICY.md` reviewed; `__version__` decision made
