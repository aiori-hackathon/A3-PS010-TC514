# Viltrumites: AIORI-3 PS-010 prototype

Evidence-based IP network-type classifier. For one IP address and one UTC
observation time it returns exactly one primary label:

1. Known Tor exit
2. Known hosted VPN/proxy endpoint
3. Unknown

It classifies network evidence only. It does not identify people or devices.

## Features

Implemented and tested with mocked HTTP (no internet is needed for the tests):

- **Classification core:** configuration, validated models, address policy, deterministic
  classification rules, SHA-256 helpers.
- **Evidence sources:** HTTP client with timeouts, size caps and bounded retries, snapshot cache
  with SHA-256 verification and freshness rules, strict parsers, CIDR matching, adapters for the
  Tor exit list, X4BNet `output/vpn` and az0 `data/input/ip`, evidence collector,
  source-inspection script, classification CLI.
- **Policy refinement ("Workstream A"):** see `docs/WORKSTREAM_A_AUDIT.md` (policy decisions,
  floors review, added tests).
- **RIPEstat network context:** ASN, prefix and holder as metadata only. It never changes the
  label. See `docs/RIPESTAT_CONTEXT.md`.
- **Service layer and IPinfo metadata:** optional IPinfo Lite metadata (disabled unless
  `IPINFO_TOKEN` is set; supplementary only, never evidence) behind a small service layer,
  `netclass.service.ClassificationService`. See `docs/IPINFO_CONTEXT.md`.
- **Audit history:** optional SQLite history (off by default; never changes a label; never read
  during classification). See `docs/AUDIT_HISTORY.md`.
- **Dashboard:** local Streamlit dashboard over the existing service and audit store (`app.py`,
  `src/netclass/dashboard/`). See the dashboard section below and `docs/DASHBOARD_VERIFICATION.md`.
- **Evaluation:** reproducible evaluation framework (`scripts\evaluate.py`,
  `src/netclass/evaluation/`, `evaluation/datasets/ps010-eval-v1/`). It drives the existing
  classification service over documented fixtures and reports policy conformance, coverage and
  selective classification. It adds no classifier, no label and no policy change. The shipped
  dataset is SYNTHETIC ONLY: it contains no independently sourced reference cases, so no real-world
  accuracy figure exists. See the Evaluation section below, `docs/EVALUATION.md` and
  `docs/EVALUATION_VERIFICATION.md`.
- **Source health and live verification:** per-source health states and a bounded, opt-in live
  check (`scripts\verify_sources.py --live`). See `docs/SOURCE_HEALTH.md`,
  `docs/LIVE_VERIFICATION.md` and `docs/SOURCE_HEALTH_VERIFICATION.md`. Release history:
  `docs/RELEASE_NOTES.md`.

Not yet done: evaluation against independent, timestamped reference labels (the schema, loader and
validator exist; supply the cases) and a recorded live verification run of every real source
endpoint.

Verification status: the tests use mocked HTTP only. No live RIPEstat, IPinfo or Tor Project
request has been verified by the authors. An earlier maintainer reported a live run of the X4BNet
and az0 endpoints; the integration audit did not repeat it. Run `python scripts\inspect_sources.py`,
`python scripts\ripestat_context.py 8.8.8.8` and `python scripts\verify_sources.py --live` on your
machine to verify live behaviour. See `docs/INTEGRATION_GUIDE.md`, section 11,
`docs/INTEGRATION_AUDIT.md` and `docs/RELEASE_NOTES.md` for exactly what was run for each
capability, and `docs/DASHBOARD_VERIFICATION.md`, `docs/EVALUATION_VERIFICATION.md` and
`docs/SOURCE_HEALTH_VERIFICATION.md` for the verification records.

## Requirements

- Windows 10/11, PowerShell, Python 3.12 (`py -3.12 --version`)
- Internet access only for the live scripts and the dashboard's lookups, not for the tests
- Streamlit (installed by `requirements.txt`) for the dashboard

## Setup (Windows PowerShell)

Run from the folder that contains this README:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

If PowerShell blocks `Activate.ps1`:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Run the tests

```powershell
python -m pytest -v
```

The suite blocks network access on purpose (`tests\conftest.py`), so it
cannot pass by accident through the internet. Keep the output of your run.

The evaluation tests alone: `python -m pytest tests\test_evaluation_*.py -v`.

## Evaluation

```powershell
python scripts\evaluate.py --check-only                 # validate the dataset, run nothing
python scripts\evaluate.py --out-dir evaluation\output   # offline replay; writes JSON + Markdown
python scripts\evaluate.py --strict                      # exit 3 on a mismatch or invariant violation
```

The default run is an offline, deterministic replay: every case goes through the real
`ClassificationService` and adapters, with downloads answered from fixtures. It never uses the
network, `.env`, `data\` or the audit history. `--live` is an explicit opt-in for
independently sourced reference cases (none ship in v1) and is not deterministic. Reports label
synthetic policy conformance and reference accuracy separately; synthetic results are never
real-world accuracy. Details and every metric denominator: `docs/EVALUATION.md`.

## Try it with live data

```powershell
python scripts\inspect_sources.py          # verify endpoints, formats, overlaps
python scripts\classify_ip.py 8.8.8.8 --evidence
python scripts\classify_ip.py 8.8.8.8 --context   # adds RIPEstat context (metadata only)
python scripts\ripestat_context.py 8.8.8.8        # RIPEstat context alone
python scripts\classify_ip.py 8.8.8.8 --ipinfo    # adds IPinfo metadata (needs IPINFO_TOKEN; metadata only)
python scripts\ipinfo_context.py 8.8.8.8          # IPinfo metadata alone (exit 4 = disabled)
```

IPinfo is off by default. To enable it, put your token in `.env` as `IPINFO_TOKEN`; to disable it,
blank it. A lookup sends the public IP address to IPinfo and is made only when you pass `--ipinfo`.
It never changes the label. Details, limits and privacy notes: `docs/IPINFO_CONTEXT.md`.

Calling it from Python:

```python
from datetime import datetime, timezone
from netclass.config import load_settings
from netclass.models import Observation
from netclass.service import ClassificationService

service = ClassificationService.from_settings(load_settings())
outcome = service.classify(
    Observation(ip="8.8.8.8", observed_at=datetime.now(timezone.utc)),
    include_ripestat=False,   # RIPEstat context, optional
    include_ipinfo=True,      # IPinfo metadata, optional; DISABLED without a token
)
outcome.classification   # authoritative label, reason codes, assessments
outcome.evidence         # source records
outcome.ipinfo_metadata  # supplementary; None unless requested
```

Downloads are cached in `data\cache` (ignored by Git).

### Audit history (optional, off by default)

```powershell
python scripts\classify_ip.py 8.8.8.8 --audit      # also save this run to data\audit.sqlite3
python scripts\audit_history.py list               # read the history
python scripts\audit_history.py purge              # dry run; add --yes to delete runs older than retention
```

Enable it for every run with `NETCLASS_AUDIT_ENABLED=true` (`--no-audit` overrides). The file stores
the IP addresses you classify, never tokens or raw responses. Retention is 90 days by default and is
applied only when you run `purge --yes`; `NETCLASS_AUDIT_RETENTION_DAYS=0` keeps records indefinitely.
From Python use `service.classify_and_record(obs)`; `service.classify(obs)` never writes. A failed save
is reported (`audit.status == "FAILED"`, CLI exit code 5) and never hides the classification.
Details and privacy notes: `docs/AUDIT_HISTORY.md`.

## Source health and live verification

`python scripts\verify_sources.py --live` is an explicit, capped, redacted live check of the real
source files (it contacts the internet; the test suite never does). See `docs/SOURCE_HEALTH.md`,
`docs/LIVE_VERIFICATION.md` and `docs/EVIDENCE_POLICY.md`. Only a healthy source can
support "confirmed absence"; every other state means absence is not established.

## Dashboard (local)

A presentation layer over the existing `ClassificationService`. It contains no classifier of its
own and queries no source by itself: every label, reason code and piece of evidence comes from the
service exactly as the CLI sees it.

### Launch (Windows PowerShell, from the folder that contains this README)

```powershell
.\.venv\Scripts\Activate.ps1
python -m streamlit run app.py
```

Then open <http://localhost:8501>. `.streamlit\config.toml` binds the server to `127.0.0.1`,
disables usage statistics and runs headless (no browser is opened for you). Stop it with Ctrl+C.
The app starts no lookup and creates no file by itself.

### Classify an IP

1. Open the **Classify** tab and type an IPv4 or IPv6 address. It is validated locally with the
   standard-library `ipaddress` module; invalid input is rejected before anything else happens.
2. Optionally tick RIPEstat and/or IPinfo Lite (IPinfo needs `IPINFO_TOKEN` in `.env`; the token is
   never displayed). These send the IP address to a third party and are context only.
3. Press **Classify IP**. Nothing is requested on typing or on a page refresh.

The result shows the label, reason code, the classifier's own explanation and caveats, the
classification evidence table (source, status, applicability, retrieval time, errors) and, in
separate sections titled "Context only - does not determine classification", RIPEstat and IPinfo
data. Private, loopback, link-local, multicast, reserved, shared and documentation addresses are
excluded by the existing policy: the page says collection was skipped and no source or context
service is contacted.

### Record to the audit history (explicit opt-in)

Audit recording is off by default and the dashboard never writes just because it is open. To record
one classification, tick **Save this classification to the local audit history**, read the privacy
notice, tick the acknowledgement, then press **Classify IP**. This calls the existing
`ClassificationService.classify_and_record`, which uses the `AuditStore` and the path in
`NETCLASS_DB_PATH`. The opt-in applies to that one classification only; it is not remembered.
`NETCLASS_AUDIT_ENABLED=true` does not make the dashboard record: the per-classification opt-in is
still required. "Saved" is shown only after the database transaction committed; if the save fails,
the classification is still shown together with a warning.

### View the audit history

The **Audit history** tab is read-only and opens the database in read-only mode. It never creates
it: if the file does not exist (or is not a readable audit database) you see an explanation, not an
empty table. You can filter by label and by exact IP address (both validated, then passed to the
store as bound parameters), choose 10/25/50/100 rows per page and page forward. Select a run to see
its recorded evidence and its context metadata, kept in separate tables. The list is newest first
and re-read on every refresh, not cached.

### Retention, purge and privacy

The history file stores the IP addresses you classify, observation times, labels, reason codes and
the evidence/context fields the audit schema allows. It never stores tokens, authorization headers
or raw HTTP bodies. `NETCLASS_AUDIT_RETENTION_DAYS` (default 90; 0 = keep indefinitely) is shown in
the Status tab but is applied only by `python scripts\audit_history.py purge --yes`. **The dashboard has no
purge or delete button** and never purges automatically. The dashboard adds no analytics, telemetry,
authentication or cloud assumption; it is meant to run on localhost only.

### Limitations

* Results reflect available evidence and source coverage only; they say nothing certain about a
  person's identity or activity. Missing, stale, conflicting or unavailable evidence is never proof
  of absence.
* **Unknown** does not mean safe, malicious, or "definitely not a VPN".
* IPv6 coverage is limited (not every source publishes IPv6 data).
* RIPEstat and IPinfo are context only and never change a label. A hosting provider/ASN alone never
  yields a VPN/proxy label.
* All three evidence sources are current snapshots; they are not proof of historical status. The
  dashboard always classifies "now".
* History filters: label and exact IP only (the audit schema supports date filters too, but the
  dashboard does not expose them). No export, delete or purge in the UI.
* The status section reports configuration and local files only; it makes no live check.
* Browser behaviour was verified manually by the project owner on the first dashboard package; see
  `docs/DASHBOARD_VERIFICATION.md` for exactly what was and was not executed.

## Layout

```
src/netclass/
  config.py          settings from .env (secrets hidden from repr)
  address_policy.py  IP validation and exclusion policy
  hashing.py         SHA-256 and manifest hashing
  models.py          Pydantic models, labels, reason codes
  classifier.py      pure deterministic classification rules
  errors.py          SourceError kinds
  http_client.py     requests-based fetcher (timeouts, size cap, HTTPS only)
  parsers.py         strict IP-list / CIDR-list parsers, CidrSet matching
  cache.py           content-addressed snapshot store
  snapshots.py       cache-first loading with freshness rules
  adapters/          tor.py, x4bnet.py, az0.py, base.py
  collector.py       build adapters, gather evidence, classify (+ optional RIPEstat context)
  ipinfo.py          optional IPinfo Lite metadata service (metadata only)
  dashboard/         logic.py (UI-free, tested) and ui.py (Streamlit page)
  service.py         ClassificationService: classification + optional context; classify_and_record (opt-in audit)
  audit/             SQLite audit history: store, schema/migrations, privacy scrubbing, retention parsing
  ripestat.py        RIPEstat context service (metadata only, in-memory TTL cache)
  evaluation/        dataset.py, metrics.py, report.py (stdlib only); replay.py, runner.py
  redaction.py       redaction of secrets in logs, errors and reports
  source_health.py   source-health states and per-file health records
  live_verify.py     bounded live source verification and report builder
  live_targets.py    the files live verification probes (built from the adapters)
  inspection.py      source measurement and overlap report
  sources.py         source registry: licences, attribution, limits, exclusions
scripts/             inspect_sources.py, classify_ip.py, ripestat_context.py, ipinfo_context.py, audit_history.py,
                     evaluate.py, verify_sources.py (live check; opt-in)
evaluation/          datasets/ps010-eval-v1/ (dataset.json, README.md, PROVENANCE.md); reports/ (release evidence)
app.py              Streamlit entry point: python -m streamlit run app.py
.streamlit/          local-only Streamlit config (127.0.0.1, no usage statistics)
tests/               pytest suite (fakes and stub transport only)
docs/                DATA_SOURCES.md, INTEGRATION_GUIDE.md, INTEGRATION_AUDIT.md, RELEASE_NOTES.md,
                     WORKSTREAM_A_AUDIT.md, EVIDENCE_POLICY.md, RIPESTAT_CONTEXT.md, IPINFO_CONTEXT.md,
                     AUDIT_HISTORY.md, EVALUATION.md, SOURCE_HEALTH.md, LIVE_VERIFICATION.md,
                     DASHBOARD_VERIFICATION.md, EVALUATION_VERIFICATION.md, SOURCE_HEALTH_VERIFICATION.md
```

## Classification policy (summary)

1. Private, loopback, link-local, multicast, reserved, shared and
   documentation addresses are excluded: Unknown, `UNKNOWN_EXCLUDED_ADDRESS`.
   No downloads happen for them.
2. Evidence must cover the observation time. All three sources are
   current-only snapshots, so they apply only within a tolerance (default
   1 hour) of their retrieval time. A current list never supports a
   historical claim.
3. A failed, malformed, empty, truncated or stale source is SOURCE_UNAVAILABLE,
   never a negative match.
4. Tor evidence together with any VPN evidence is a conflict: Unknown,
   `UNKNOWN_CONFLICTING_EVIDENCE`. Tor has no precedence.
5. Datacenter lists, DNS resolver addresses and Apple Private Relay ranges are
   not VPN evidence. A hosting indicator can never produce a VPN label.
6. Otherwise Unknown. Reason priority: source unavailable, stale evidence,
   provider not configured, hosting only, no qualifying match.
7. RIPEstat and IPinfo are supplementary metadata only. They never create, change or
   override a label, and a failed lookup never counts as evidence either way.

Details: `docs/INTEGRATION_GUIDE.md` and `docs/DATA_SOURCES.md`.

## Data sources and licences

| Source | Used for | Licence |
|--------|----------|---------|
| Tor Project bulk exit list | Tor evidence | none stated at the endpoint |
| X4BNet/lists_vpn, `output/vpn/` only | VPN evidence (CIDR ranges) | MIT |
| az0/vpn_ip, `data/input/ip/` | VPN evidence (exact addresses) | GPL-3.0-or-later |

This repository contains no data from these sources. Data is downloaded at
run time into `data\cache`. Because az0/vpn_ip is GPL licensed, do not commit
or redistribute its files with this project. Not legal advice.

Credits: Tor Project; X4BNet/lists_vpn (MIT, Copyright (c) 2024 X4B, Mathew
Heard); az0/vpn_ip (GPL-3.0-or-later, Copyright (C) 2023-2024 Andrew Ziem).

## Open items

- Evaluation against independent, timestamped reference labels (supply the cases; the schema,
  loader and validator exist).
- A recorded live verification run of every real source endpoint, including the Tor Project list
  (`python scripts\verify_sources.py --live`).
- Further tuning of the Tor/VPN overlap policy needs live `inspect_sources` output.
