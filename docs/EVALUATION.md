# Evaluation framework

Purpose: demonstrate the reliability and the limits of the existing PS-010 pipeline in a
reproducible way. It adds **no classifier, no label and no policy change**. The runner calls
`ClassificationService.classify` and scores the answers.

## What it can and cannot show

| question | answered by | status in v1 |
|---|---|---|
| Does the pipeline implement the documented policy on known situations (conflict, outage, stale, excluded, IPv6 gap, ...)? | synthetic replay | yes: 41 labeled cases, 1 unlabeled |
| How often does it abstain on these fixtures? | coverage / abstention rate | yes, **on fixtures only** |
| How accurate is it on real addresses? | reference cases | **not answerable**: v1 ships none |
| How does it behave on the live sources today? | `--live` with reference cases | not run; needs reference cases |

Synthetic agreement is 100% by construction. It shows the wiring and policy are as documented. It
must never be quoted as real-world accuracy, precision or recall; every report says so.

## Dataset (`evaluation/datasets/ps010-eval-v1/dataset.json`)

Two tiers, never mixed in metrics:

* **synthetic**: evidence is a fixture "world" in the same file; the expected label follows from
  the policy. Fields: `case_id`, `tier`, `category`, `ip`, `observed_at`, `world`,
  `expected_label` (or `null`), optional `expected_reason_code`, `rationale`.
* **reference**: an independently sourced, timestamped label with a `reference` provenance object
  (`source`, `source_type`, `source_url?`, `retrieved_at`, `temporal_support`, `valid_from/to`,
  `label_basis`, `confidence`, `limitations`, `independent_of_classifier_sources`).

`expected_label: null` means **unlabeled**: it needs an `unlabeled_reason`, is listed, and is never
scored as correct or incorrect.

Strict validation rejects (all problems are reported together): malformed JSON or duplicate keys,
unknown or missing fields, duplicate case ids, labels or reason codes outside the pipeline's set,
a reason code inconsistent with its label, invalid IP addresses, naive or malformed timestamps,
a category that contradicts the exclusion policy, unknown or unused fixture worlds, a labeled
reference case without provenance, a reference label taken from one of the evaluated sources
(circular), and **current-only evidence offered as historical ground truth**. A current-only
reference supports an observation only within 3600 s of its retrieval; a historical label needs
`time-bounded` support whose validity interval covers the observation.

The dataset hash is the SHA-256 of the canonical JSON (sorted keys, no whitespace), so line
endings and key order do not change it; case order does.

## Running it

```powershell
python scripts\evaluate.py --check-only
python scripts\evaluate.py --out-dir evaluation\output
python scripts\evaluate.py --strict
python scripts\evaluate.py --dataset path\to\other.json --out-dir evaluation\output
python scripts\evaluate.py --live --out-dir evaluation\output-live
```

Exit codes: `0` ok, `2` invalid dataset or cannot run, `3` `--strict` found a mismatch or an
invariant violation. Without `--out-dir` the JSON report is printed and nothing is written; with it
exactly `evaluation-report.json` and `evaluation-report.md` are written (UTF-8, LF).

**Replay (default).** Each case builds a fresh `ClassificationService` with the real
`TorExitListAdapter`, `X4BNetVpnAdapter` and `Az0VpnIpAdapter`, whose downloads are answered by a
`ReplayFetcher` from the case's world. The clock is fixed to the dataset's `evaluation_time`. No
network, no disk cache, `audit=None`, no RIPEstat or IPinfo, no `.env`, no `data\`. Sanity floors
are lowered to 1 so tiny fixtures load (recorded in the configuration; the real floors are covered
by the adapter tests).

**Live (`--live`).** Explicit opt-in. Classifies only the reference-tier cases with the real sources
over HTTPS, caching in a temporary directory that is deleted afterwards. Not deterministic (the
report says so). Because every source is current-only, an old reference observation will correctly
come back `Unknown` / `UNKNOWN_STALE_EVIDENCE`: that is the policy, not an error. With no
reference cases it exits 2: it never invents ground truth.

## Metrics and denominators

`evaluated` = cases run in the tier; `labeled` = evaluated cases with a label; `definitive` = a
"Known ..." label. Only labeled cases are scored. Each ratio is `{numerator, denominator, value,
undefined_reason}`; a zero denominator gives `value: null` plus the reason, never 0 or 1.

| metric | numerator / denominator |
|---|---|
| overall agreement | labeled cases with predicted = expected / labeled |
| precision[class] | labeled, predicted = class and expected = class / labeled, predicted = class |
| recall[class] | labeled, predicted = class and expected = class / labeled, expected = class |
| false positives[class] | labeled, predicted = class, expected another class |
| false negatives[class] | labeled, expected = class, predicted another class |
| coverage | evaluated with a definitive prediction / evaluated (includes unlabeled) |
| abstention rate | evaluated predicted Unknown / evaluated |
| labeled coverage | labeled with a definitive prediction / labeled |
| selective precision | labeled definitive predictions equal to expected / labeled definitive predictions |
| definitive recall | labeled expected-definitive predicted correctly / labeled expected-definitive |

**Unknown is a legitimate output.** It is its own class in the confusion matrix. A mismatch is one
of: `definitive_where_unknown_expected` (false positive), `wrong_definitive_label`,
`missed_by_abstention`, or `reason_code_differs` (label agrees, reason code does not). Coverage and
selective precision are reported separately on purpose: abstaining more lowers coverage but can
raise selective precision. Warnings fire below 30 labeled cases overall or per class. A reference
"Unknown" label means "the independent reference does not establish Tor/VPN status", not "verified
clean".

## Report contents

JSON (`ps010-eval-report-1`) and Markdown contain: mode and evidence basis (`synthetic-fixture-replay`,
`live-source-backed`), the fixed evaluation time, versions (package, policy, service, runner, report
schema), dataset id/version/SHA-256, the exact configuration, the evaluated sources' licences and
endpoints, a SHA-256 per fixture world, the two metric blocks, invariant checks, skipped cases,
per-case rows (expected vs predicted, reason, evidence statuses and applicability, fetch count) and
per-case mismatch explanations. Nothing machine-specific (paths, host, Python version, wall-clock
time) is recorded, so identical input gives byte-identical output.

## Invariants checked on every case

* an excluded address triggers **zero** evidence fetches and short-circuits to
  `UNKNOWN_EXCLUDED_ADDRESS` with no evidence;
* the label is one of the three;
* classifying the same observation twice gives identical output.

Tests additionally show that context-only metadata (RIPEstat holder names, IPinfo AS names that
sound like Tor/VPN/hosting) cannot change any classification.

## Limitations and observations

* Synthetic only; no real-world accuracy figure exists. Supplying reference cases is the way to get one.
* All sources are current-only, so there is no source-backed historical ground truth.
* `UNKNOWN_HOSTING_ONLY` is unreachable through the service (RIPEstat context never sets a hosting
  indicator). It is covered by classifier-level tests.
* Observation 1 (existing behavior, unchanged): with the Tor list unavailable, an address listed as
  both Tor and VPN is reported as a VPN endpoint, because the conflict cannot be seen
  (`syn-unavail-004-conflict-masked`).
* Observation 2 (existing behavior, unchanged): if X4BNet cannot verify a match because the Apple
  exclusion list is unavailable but az0 returns an applicable negative, the label is `Unknown` with
  the broad reason `UNKNOWN_NO_QUALIFYING_MATCH` and the outage appears only as a caveat
  (`syn-unavail-012-apple-list-down`). The label is conservative; the reason code is less specific
  than it could be. Neither was changed; both are documented for your review.
