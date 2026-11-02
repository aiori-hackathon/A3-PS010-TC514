# IPinfo supplementary metadata (Stage 4)

Optional, disabled by default, and **never evidence**. Code: `src/netclass/ipinfo.py`
(adapter), `src/netclass/service.py` (service layer), `collector.build_ipinfo_service`.

## 1. Evidence versus supplementary metadata

| | Classification evidence | Supplementary metadata |
|---|---|---|
| Sources | Tor exit list, X4BNet `output/vpn`, az0 `data/input/ip` | RIPEstat (Stage 3B), IPinfo Lite (Stage 4) |
| Can set the label | Yes (only these) | **No** |
| Where it appears | `classification`, `evidence` | `ripestat_context`, `ipinfo_metadata` |
| Failure means | `SOURCE_UNAVAILABLE`, never a negative | explicit `UNAVAILABLE`/`DISABLED`, label untouched |

An ASN, AS name, AS domain or country from IPinfo is **not** evidence of Tor or VPN/proxy use.
IPinfo output is never passed to the classifier, never creates an `EvidenceRecord`, and never
touches `ClassificationResult.network_context` (that field belongs to RIPEstat). Pinned by
`tests/test_service_layer.py` (invariance grid) and an AST guard in `tests/test_ipinfo_service.py`.

## 2. Endpoint and fields used

Documentation read on 2026-10-31: <https://ipinfo.io/developers> and
<https://ipinfo.io/developers/lite-api>. **No live request to IPinfo was made by the Stage 4
author** (no token was available); behaviour below is verified with mocked HTTP only.

* `GET {base}/lite/{ip}`, base default `https://api.ipinfo.io`.
* Authentication: the documentation lists a `token` query parameter, HTTP Basic and
  `Authorization: Bearer <token>`. This project uses **Bearer only**, so the token never appears
  in a URL, error message, log line or provenance record.
* Fields read (documented Lite response): `ip`, `asn` (text such as `AS15169`, stored as an
  integer), `as_name`, `as_domain`, `country_code`, `country`, `continent_code`, `continent`.
  Every other field is ignored, never interpreted.
* `ip` is required: a response without it, or for another address, is rejected.
* Not used in Stage 4: the Core/Plus `lookup` endpoint, privacy/hosting/proxy fields, batch API,
  `me`. HTTP statuses other than 429 are mapped generically; their meaning is not taken from IPinfo.

## 3. Configure, enable, disable

| Variable | Default | Meaning |
|---|---|---|
| `IPINFO_TOKEN` | blank (disabled) | Your IPinfo API token. Existing name, unchanged. |
| `NETCLASS_IPINFO_BASE_URL` | `https://api.ipinfo.io` | Must be https. |
| `NETCLASS_IPINFO_CACHE_TTL_SECONDS` | `3600` | In-memory reuse of successful answers. |

* **Enable:** put the token in `.env`, then ask for metadata per call:
  `python scripts\classify_ip.py 8.8.8.8 --ipinfo` or `python scripts\ipinfo_context.py 8.8.8.8`.
* **Disable:** blank `IPINFO_TOKEN`. `--ipinfo` then reports `status: DISABLED` and sends nothing.
* A configured token alone sends nothing: a request needs `--ipinfo` (CLI) or
  `include_ipinfo=True` (API). A token with whitespace/control characters or over 512 characters
  is treated as unusable: disabled, not echoed.

## 4. Statuses and errors (`ipinfo_metadata.status`)

| Status | Meaning |
|---|---|
| `AVAILABLE` | Valid answer with at least one metadata field |
| `EMPTY` | Valid answer, none of the fields present/usable |
| `UNAVAILABLE` | See `error.kind`: `TIMEOUT`, `CONNECTION`, `AUTH_FAILED` (401/403), `RATE_LIMITED` (429), `SERVER_ERROR` (5xx), `HTTP_ERROR`, `TOO_LARGE`, `INVALID_JSON`, `UNEXPECTED_STRUCTURE`, `INVALID_INPUT`, `INTERNAL` |
| `NOT_QUERIED` | Address excluded by policy (private, reserved, loopback, link-local, CGNAT, documentation, multicast ...); no request made |
| `DISABLED` | No usable token; no request made |

Omitted fields stay `null` (listed in `warnings`); nothing is invented. No automatic retry is made
(the project has no retry layer); errors are never cached. Failures never raise out of the service
and never alter the classification.

`scripts\ipinfo_context.py` exit codes: 0 metadata retrieved, 1 unavailable/invalid/empty,
3 not queried, 4 disabled.

## 5. API limits

Per IPinfo's documentation at the time of reading, the Lite API is described as free with no daily
or monthly request limit, and paid plans have monthly limits where exceeding them returns HTTP 429.
These are IPinfo's statements, may change, and are not guaranteed by this project. Check
<https://ipinfo.io/developers> and your own account. A 429 becomes `RATE_LIMITED`.

## 6. Privacy and token precautions

* A real lookup sends the queried **public IP address**, your token and the User-Agent
  (`viltrumites-ps010/0.4 ...`) to IPinfo, a third party. See IPinfo's
  [privacy policy](https://ipinfo.io/privacy-policy) and [terms](https://ipinfo.io/terms-of-service).
  Do not enable it for addresses you must not disclose. Only globally routable addresses are sent.
* The token lives in `.env` (ignored by Git) or the environment. It is hidden from `Settings`
  repr, never put in a URL, and redacted (token, `token=...`, `Bearer ...`) from error text and logs.
* Results are cached in memory only; nothing is written to disk.
* Never commit `.env`, paste the token into an issue or screenshot, or put a real token in a test.
  If a token leaks, revoke it in your IPinfo dashboard.

## 7. Tests

`tests/test_ipinfo_service.py` (adapter), `tests/test_ipinfo_config.py` (settings, header-only
auth through the real `RequestsFetcher` with a stub transport), `tests/test_service_layer.py`,
`tests/test_cli_compat.py`. All mocked; the suite blocks sockets (`tests\conftest.py`).
