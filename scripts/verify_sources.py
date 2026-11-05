r"""Bounded LIVE check of the real source files Contacts the internet.

Run from the project root, on a machine where outbound HTTPS is allowed:

    python scripts\verify_sources.py --live

WARNING
  * It sends real HTTPS GET requests to the Tor Project and raw.githubusercontent.com.
  * It is capped (default 30 requests, hard limit 60; at most 2 retries per file).
  * It never classifies an address, never writes the cache, and writes only two
    timestamped, redacted report files under reports\live\ (never overwritten).
  * Without --live it does nothing and makes no request.
  * Do not run it from CI or from the test suite; tests must stay offline.

Exit code: 0 all files healthy, 1 at least one file not healthy, 2 not run / bad arguments.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netclass.config import load_settings  # noqa: E402
from netclass.http_client import RequestsFetcher  # noqa: E402
from netclass.live_targets import GROUP_FLOORS, default_targets  # noqa: E402
from netclass.live_verify import cli_main  # noqa: E402


def main(argv: list[str]) -> int:
    settings = load_settings()

    def make_fetcher(timeout: float, retries: int, budget: int) -> RequestsFetcher:
        return RequestsFetcher(
            timeout_seconds=timeout,
            max_bytes=settings.max_download_bytes,
            max_retries=retries,
            max_total_requests=budget,
        )

    return cli_main(
        argv,
        targets_factory=lambda: default_targets(settings.tor_exit_list_url),
        fetcher_factory=make_fetcher,
        group_floors=GROUP_FLOORS,
        default_timeout=settings.http_timeout_seconds,
        default_max_age=settings.max_source_age_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
