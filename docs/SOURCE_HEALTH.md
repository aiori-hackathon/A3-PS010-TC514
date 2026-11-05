# Source health

Source health answers one question per source file: **could we establish what the source says?**
It is separate from classification. Nothing in `source_health.py`, `live_verify.py` or
`live_targets.py` produces a label or reason code, and none of it duplicates classifier rules.

## States

| State | Meaning | Typical cause |
|---|---|---|
| `HEALTHY` | Fetched completely, parsed, plausible size | normal operation |
| `SOURCE_FAILURE` | The file could not be retrieved | timeout, DNS/TLS/connection error, HTTP != 200, over the size cap, incomplete download, request budget |
| `STALE` | Retrieved, but the source's own `Last-Modified` is older than the age limit | upstream stopped updating |
| `PARSE_FAILURE` | Retrieved, but not in the documented format | HTML error page, schema drift, wrong IP family, CIDR in an exact list, invalid UTF-8 |
| `INSUFFICIENT_EVIDENCE` | Parsed, but empty or below the sanity floor | empty file, truncated file |
| `NOT_CHECKED` | Skipped | request budget exhausted |

## Absence of evidence

Only a `HEALTHY` file may support **confirmed absence** ("the address is not listed"). Every other
state yields `NOT_ESTABLISHED`: the silence proves nothing and must never be read as a negative.
This restates the existing rule that missing, stale or failed evidence is never negative; it does not change it. Each report row carries
`absence_support` so a reader cannot confuse the two.

## What is recorded per file

Retrieval time (UTC), HTTP status, attempts used, elapsed seconds, response size, SHA-256 of the
body, ETag, `Last-Modified` and the resulting age, parser outcome, record counts (total, IPv4,
IPv6), the sanity floor, and notes. URLs are redacted (credentials and query strings removed);
free text is redacted by `netclass/redaction.py`. Raw response bodies are never written.

## Freshness limits (important)

GitHub's raw host sends no `Last-Modified`. For X4BNet and az0 files the age therefore cannot be
verified and the report says so in a note (`freshness_verifiable: false`). That is **not** a
failure, but a stalled upstream would go unnoticed. The report states this plainly; it does not
invent a freshness rule. The existing 24 h `NETCLASS_MAX_SOURCE_AGE_SECONDS` check applies only
when the header exists.

## Apple Private Relay exclusion list

Apple data is exclusion data, never VPN evidence. It is not a separate source: it is an
auxiliary X4BNet file (`apple.txt`) that the adapter fetches **only when an address matches an
X4BNet range**. Consequences, all pre-existing and now documented:

* an outage is invisible during lookups that never reach an X4BNet range;
* when it matters, X4BNet reports `SOURCE_UNAVAILABLE` and the outage text appears as a caveat;
* if an applicable az0 negative covers the VPN kind, the reason code stays the broad
  `UNKNOWN_NO_QUALIFYING_MATCH` (decision B in `docs/EVIDENCE_POLICY.md`);
* the live verifier probes `apple.txt` directly (`role: exclusion`) so an outage is visible in
  source health even when no lookup hits it. Its content is IPv4-only as observed.

## Retries and request safety

Evidence fetches may retry **at most twice** after the first attempt, only for timeouts,
connection errors, HTTP 429 and HTTP 5xx. `Retry-After` is honoured if it is within
`max_retry_after_seconds` (30) and the overall deadline; otherwise there is no retry. TLS errors,
other HTTP statuses, oversize bodies and non-HTTPS redirects are never retried. Every redirect hop
must be HTTPS, credentials are never forwarded to another origin, and a body that does not match
its declared `Content-Length` is an incomplete download (an error). RIPEstat and IPinfo
(context-only) keep their previous no-retry behaviour. `NETCLASS_HTTP_MAX_RETRIES=0` disables
retries.
