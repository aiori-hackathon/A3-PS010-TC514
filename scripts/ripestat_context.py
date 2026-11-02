r"""Fetch RIPEstat network context (ASN, prefix, holder) for one IP address.

Run from the project root:
    python scripts\ripestat_context.py 8.8.8.8

This is CONTEXT ONLY. It makes no Tor/VPN determination. It needs internet
access and calls the documented RIPEstat endpoints network-info and as-overview.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netclass.collector import build_context_service  # noqa: E402
from netclass.config import load_settings  # noqa: E402
from netclass.ripestat import ContextStatus  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("ip", help="IPv4 or IPv6 address")
    args = parser.parse_args()

    service = build_context_service(load_settings())
    context = service.lookup(args.ip)
    print(json.dumps(context.model_dump(mode="json"), indent=2))
    # Exit codes: 0 usable context, 1 unavailable / invalid input, 3 not queried (excluded address)
    if context.status is ContextStatus.NOT_QUERIED:
        return 3
    return 0 if context.usable else 1


if __name__ == "__main__":
    raise SystemExit(main())
