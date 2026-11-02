# Provenance of ps010-eval-v1

| item | provenance |
|---|---|
| synthetic cases (42) | Authored for Stage 7 from the documented PS-010 policy (`docs/WORKSTREAM_A_AUDIT.md`, `src/netclass/classifier.py` rules as documented). Expected values were written before the first evaluation run. Fixture addresses are arbitrary. Not real-world observations. |
| fixture worlds (11) | Authored for Stage 7. List contents are invented addresses and ranges. The endpoint URLs the adapters address are the real ones (`src/netclass/sources.py`), but in replay no request leaves the process. |
| reference cases (0) | None. No independently sourced, timestamped reference label was supplied. None was invented. |

## What would make a case a reference case

A labeled reference case must record: the independent `source` and `source_type`, `retrieved_at`,
`temporal_support` (`current-only` or `time-bounded` with `valid_from`/`valid_to`), `label_basis`,
`confidence`, `limitations`, and `independent_of_classifier_sources: true`. The validator rejects:

* a source that is one of the three evaluated sources, or a URL pointing at them (circular);
* **current-only** evidence whose retrieval time is more than 3600 s from the observation time
  (a current list is never historical ground truth);
* a time-bounded reference whose validity interval does not cover the observation.

## Licences

The evaluated real sources keep their own licences (see `docs/DATA_SOURCES.md`; az0/vpn_ip is GPL-3.0
and none of its data is bundled). This dataset contains no data copied from any of them.
