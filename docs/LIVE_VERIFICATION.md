# Live verification

> **Safety.** `scripts/verify_sources.py --live` contacts the real internet (Tor Project and
> raw.githubusercontent.com). It is capped, writes only redacted reports, never classifies an
> address and never touches the cache. **Never run it from CI or from the test suite.** The test
> suite stays offline and blocks sockets.

## Run it (Windows PowerShell, project root)

    python scripts\verify_sources.py --live

Options: `--max-requests N` (default 30, hard ceiling 60), `--timeout S` (default from settings,
max 30), `--retries 0-2` (default 2), `--max-source-age S`, `--output-dir DIR`
(default `reports\live`). Without `--live` it does nothing (exit code 2).

Exit codes: `0` every file healthy, `1` at least one file not healthy, `2` not run or bad arguments.

## Output

Two files per run, never overwritten: `live-verification-<UTC timestamp>.json` and `.md`. They
contain per-file health (see `SOURCE_HEALTH.md`), the combined az0 floor check, request counts,
and Tor/VPN overlap **counts** (no addresses, only the 10 most common public X4BNet ranges).
Overlap is reported as `COMPLETE`, `PARTIAL` (counts are lower bounds) or `NOT_ASSESSABLE`.

## What this does and does not prove

A successful run shows that, at that moment, from that machine, the endpoints answered, were
HTTPS, stayed inside the size and time limits, and parsed with the project's own parsers. It does
**not** show classification accuracy, historical validity, or that the data is correct.
Mocked or replayed tests never count as live verification. A report is evidence only if you ran
it yourself; keep the JSON with the release evidence.

## Existing tools

`scripts\inspect_sources.py` remains available and uses the same bounded retries.
`verify_sources.py` is the bounded verification tool because it adds per-file health states, a hard
request budget and redacted timestamped reports.
