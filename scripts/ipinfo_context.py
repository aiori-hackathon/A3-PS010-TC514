r"""Fetch IPinfo Lite supplementary metadata (ASN, operator, country) for one IP address.

Run from the project root:
    python scripts\ipinfo_context.py 8.8.8.8

SUPPLEMENTARY METADATA ONLY. It makes no Tor/VPN determination. It needs internet access
and an IPinfo token in IPINFO_TOKEN (environment or .env). The IP address is sent to IPinfo.
Excluded (private, reserved ...) addresses are never sent. The token is never printed.

Exit codes: 0 metadata retrieved, 1 unavailable / invalid input / empty answer,
            3 not queried (excluded address), 4 disabled (no usable IPINFO_TOKEN).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netclass.collector import build_ipinfo_service  # noqa: E402
from netclass.config import load_settings  # noqa: E402
from netclass.ipinfo import IpInfoStatus  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("ip", help="IPv4 or IPv6 address")
    args = parser.parse_args()

    metadata = build_ipinfo_service(load_settings()).lookup(args.ip)
    print(json.dumps(metadata.model_dump(mode="json"), indent=2))
    if metadata.status is IpInfoStatus.NOT_QUERIED:
        return 3
    if metadata.status is IpInfoStatus.DISABLED:
        return 4
    return 0 if metadata.usable else 1


if __name__ == "__main__":
    raise SystemExit(main())
