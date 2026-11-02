# Viltrumites — AIORI-3 PS-010

### Evidence-Based IP Network Type Classification

**Team Name:** Viltrumites
**Team Code:** `A3-PS010-TC514`
**Competition:** AIORI-3 Hackathon
**Problem Statement:** PS-010

---

## 1. Project Overview

IP addresses may be associated with Tor exit relays, VPN services, or proxy infrastructure. However, network intelligence sources can be incomplete, outdated, unavailable, or conflicting. Treating uncertain information as definitive can lead to misleading classifications.

**Viltrumites** is an evidence-based IP network classification prototype that evaluates available network intelligence, applies deterministic decision rules, and provides explainable results.

The system focuses on conservative classification: it requires qualifying evidence, handles uncertainty explicitly, and does not infer VPN usage merely because an IP address belongs to a hosting provider or a particular autonomous system.

### Classification Labels

The system returns exactly one primary label:

| Label | Meaning |
|---|---|
| `Known Tor exit` | Qualifying evidence supports a Tor exit classification. |
| `Known hosted VPN/proxy endpoint` | Qualifying VPN/proxy evidence supports the classification. |
| `Unknown` | Evidence is insufficient, unavailable, stale, or conflicting. |

The classifier evaluates network evidence only. It does not identify individuals or devices. An `Unknown` result does not mean that an IP address is safe or definitely not associated with a VPN.

## 2. Key Features

- **Evidence-based classification:** Uses deterministic rules rather than assumptions based on network ownership.
- **Multiple intelligence sources:** Integrates Tor exit information, X4BNet VPN ranges, and az0 VPN IP data.
- **Conservative decision-making:** Handles stale, malformed, unavailable, and conflicting evidence.
- **Source validation and caching:** Uses strict parsing, SHA-256 verification, and freshness checks.
- **Network context:** Optional RIPEstat metadata, including ASN, prefix, and network holder.
- **Optional IP metadata:** IPinfo Lite integration, disabled unless configured and explicitly requested.
- **Local audit history:** Optional SQLite recording with explicit opt-in and documented retention controls.
- **Interactive dashboard:** Streamlit interface for classification, evidence inspection, context, and audit history.
- **Reproducible evaluation:** A deterministic evaluation framework with synthetic fixtures and JSON/Markdown reports.
- **Automated testing:** A pytest suite designed to run with mocked HTTP interactions rather than relying on external network availability.

## 3. How the System Works

The classification pipeline follows these steps:

1. **Input validation:** Validate the IP address and apply the address-exclusion policy.
2. **Evidence collection:** Gather information from supported intelligence sources through source adapters.
3. **Data-quality checks:** Evaluate source availability, parsing integrity, freshness, and applicability.
4. **Classification:** Apply deterministic rules to qualifying evidence and resolve conflicts conservatively.
5. **Result generation:** Return a primary label, reason codes, evidence records, and relevant caveats.
6. **Optional enrichment:** Retrieve supplementary network metadata when requested.
7. **Optional auditing:** Record a classification locally only when the applicable audit opt-in is enabled.

### Classification Safeguards

- Hosting-provider or ASN information alone never establishes a VPN/proxy classification.
- RIPEstat and IPinfo are supplementary metadata sources; they cannot create or override a label.
- Conflicting Tor and VPN evidence results in `Unknown`.
- Failed, malformed, empty, truncated, or stale source data is not treated as a negative match.
- Current intelligence snapshots do not establish an IP address's historical status.
- Private, loopback, link-local, multicast, reserved, shared, and documentation addresses are excluded according to the project's address policy.
- Apple Private Relay ranges and DNS resolver addresses are not treated as VPN evidence.

## 4. Technical Architecture

| Component | Technology / Responsibility |
|---|---|
| Core classifier | Python; deterministic classification rules |
| Address validation | Python `ipaddress` module |
| Data models | Pydantic |
| HTTP client | `requests`, with timeouts, size limits, and HTTPS restrictions |
| Source adapters | Tor Project, X4BNet, and az0 |
| Snapshot cache | SHA-256 verification, caching, and freshness rules |
| Service layer | `ClassificationService` |
| Network context | Optional RIPEstat integration |
| IP metadata | Optional IPinfo Lite integration |
| Audit history | SQLite with migrations and privacy-conscious record handling |
| Dashboard | Streamlit |
| Evaluation | Python evaluation framework, JSON fixtures, and Markdown/JSON reports |
| Testing | pytest with fixtures and mocked HTTP transport |

### Data Sources

| Source | Purpose | Licence information documented by the project |
|---|---|---|
| Tor Project bulk exit list | Tor exit evidence | No licence stated at the endpoint in the project documentation |
| X4BNet `lists_vpn`, `output/vpn/` | VPN CIDR ranges | MIT |
| az0 `vpn_ip`, `data/input/ip/` | VPN IP evidence | GPL-3.0-or-later |

The project downloads source data at runtime rather than including the datasets in the repository. Do not commit or redistribute downloaded az0 data with this project. Refer to `docs/DATA_SOURCES.md` for further details.

## 5. Repository Structure

```text
.
├── app.py
├── src/
│   └── netclass/
│       ├── adapters/
│       ├── audit/
│       ├── dashboard/
│       ├── evaluation/
│       ├── address_policy.py
│       ├── classifier.py
│       ├── collector.py
│       ├── config.py
│       ├── models.py
│       ├── service.py
│       └── ...
├── scripts/
│   ├── classify_ip.py
│   ├── inspect_sources.py
│   ├── ripestat_context.py
│   ├── ipinfo_context.py
│   ├── audit_history.py
│   └── evaluate.py
├── tests/
├── docs/
├── evaluation/
│   ├── datasets/
│   │   └── ps010-eval-v1/
│   └── reports/
├── .streamlit/
├── .env.example
├── requirements.txt
├── requirements-dev.txt
├── pytest.ini
└── README.md
```

- `src/netclass/` contains the classification engine, source integrations, service layer, dashboard logic, audit functionality, and evaluation modules.
- `scripts/` contains command-line utilities for classification, source inspection, context lookups, audit history, and evaluation.
- `tests/` contains the automated test suite.
- `docs/` contains design decisions, integration instructions, change logs, verification reports, and limitations.
- `evaluation/` contains the versioned evaluation dataset and release-evidence reports.

## 6. Installation and Setup

### Prerequisites

- Windows 10 or Windows 11
- Python 3.12
- Internet access for live source lookups; the automated tests are designed to run offline

### Install Dependencies

Open Windows CMD and navigate to the repository root.

Create and activate a virtual environment:

```cmd
py -3.12 --version
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
```

Install the project dependencies:

```cmd
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

Create your local environment configuration:

```cmd
copy .env.example .env
```

Configure optional credentials only if you need them. Keep `.env` private and never commit API tokens or other secrets to GitHub.

## 7. Running the Project

### A. Classify an IP Address

```cmd
python scripts\classify_ip.py 8.8.8.8 --evidence
```

The command displays the classification and its supporting evidence.

### B. Include RIPEstat Context

```cmd
python scripts\classify_ip.py 8.8.8.8 --context
```

RIPEstat information is supplementary context and does not determine the classification.

### C. Include IPinfo Metadata

```cmd
python scripts\classify_ip.py 8.8.8.8 --ipinfo
```

This requires `IPINFO_TOKEN` to be configured in `.env`. IPinfo is optional, and the lookup sends the queried IP address to the third-party service. Its metadata does not change the label.

### D. Launch the Dashboard

```cmd
python -m streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

The dashboard provides IP classification, evidence inspection, optional context lookups, and access to existing audit history. It is intended for local use.

### E. Use the Audit History

To explicitly save a classification through the CLI:

```cmd
python scripts\classify_ip.py 8.8.8.8 --audit
```

View recorded history:

```cmd
python scripts\audit_history.py list
```

Preview the retention purge:

```cmd
python scripts\audit_history.py purge
```

Deletion requires the documented confirmation option, `--yes`. Review `docs/AUDIT_HISTORY.md` before enabling or managing audit history.

## 8. Testing

Run the complete automated test suite:

```cmd
python -m pytest -v
```

Run the Stage 7 evaluation tests separately:

```cmd
python -m pytest tests\test_evaluation_*.py -v
```

### Recorded Verification Results

The recorded Stage 7 test run on the developer's Windows environment completed with:

| Metric | Result |
|---|---:|
| Tests passed | 1,241 |
| Tests skipped | 2 |
| Total execution time | 189.16 seconds |

The two skipped tests concern POSIX-specific permission behavior.

These are recorded test results, not proof that every integration has been independently verified against live external services or in a production deployment.

## 9. Stage 7 — Evaluation Framework

Stage 7 introduces a reproducible evaluation framework that runs the existing classification service against a documented dataset. It evaluates policy conformance, coverage, and selective classification without introducing a new classifier or changing the three primary labels.

### Validate the Dataset

```cmd
python scripts\evaluate.py --check-only
```

### Run an Offline Evaluation

```cmd
python scripts\evaluate.py --out-dir evaluation\output
```

### Enable Strict Checks

```cmd
python scripts\evaluate.py --strict
```

The default evaluation is an offline, deterministic replay. It uses fixtures rather than making live network requests and does not depend on `.env`, the local data directory, or audit history.

### Dataset and Accuracy Limitations

The included `ps010-eval-v1` dataset contains **42 synthetic cases and zero independently sourced reference cases**.

Therefore:

- Synthetic policy-conformance results are not real-world accuracy measurements.
- The dataset does not establish real-world precision, recall, or effectiveness.
- Evaluation against independently sourced, timestamped reference labels remains outstanding.
- Live end-to-end verification of the real data sources remains outstanding.

Consult `docs/EVALUATION.md` and `docs/STAGE7_VERIFICATION.md` for evaluation methodology, denominators, verification details, and limitations.

## 10. Privacy and Responsible Use

This project classifies network evidence, not people.

- Optional third-party lookups may disclose the queried IP address to the relevant provider.
- IPinfo is disabled unless configured and explicitly requested.
- Audit history is optional and is not written merely because the dashboard is opened.
- Local audit records may contain IP addresses, observation times, labels, reason codes, and permitted evidence/context fields.
- Tokens, authorization headers, and raw HTTP response bodies are not intended to be stored in audit records.
- Audit history is stored locally. The dashboard does not automatically purge or delete it.
- Missing or conflicting evidence should be interpreted conservatively.
- An `Unknown` label is not a guarantee of safety or absence of VPN/proxy usage.

Use this prototype as a network-evidence analysis tool, not as the sole basis for consequential security decisions.

## 11. Documentation

For further details, refer to:

- `docs/DATA_SOURCES.md` — source attribution and data-source information
- `docs/INTEGRATION_GUIDE.md` — integration and live-source instructions
- `docs/RIPESTAT_CONTEXT.md` — RIPEstat context integration
- `docs/IPINFO_CONTEXT.md` — optional IPinfo metadata
- `docs/AUDIT_HISTORY.md` — audit storage, retention, and privacy
- `docs/EVALUATION.md` — evaluation methodology and metrics
- `docs/STAGE6_VERIFICATION.md` — dashboard verification notes
- `docs/STAGE7_VERIFICATION.md` — evaluation and release verification
- `docs/RELEASE_CHANGELOG.md` — release changes

## 12. Project Status and Future Work

The repository contains the staged implementation of the classifier, source adapters, supplementary context integrations, optional audit history, local dashboard, and Stage 7 evaluation framework.

Documented outstanding work includes:

- Evaluation against independent, timestamped reference labels
- Additional live end-to-end verification of the real data sources
- Further assessment of source coverage and overlap behavior using live inspection results

The project's stage-specific change logs and verification reports describe what was implemented and what was actually tested.

## 13. Team and Project Resources

- **Team Name:** Viltrumites
- **Team Code:** `A3-PS010-TC514`
- **Competition:** AIORI-3 Hackathon
- **Problem Statement:** PS-010

See `AIORI3_PS010_Viltrumites.pdf` for the project presentation and `VIDEO_LINK.md` for the demonstration link.

---

*Developed by Team Viltrumites for AIORI-3 PS-010, with an emphasis on evidence-based decisions, explainability, reproducibility, and transparent limitations.*
