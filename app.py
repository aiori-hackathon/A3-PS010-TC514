"""Streamlit entry point for the PS-010 dashboard.

Run from the project root:
    python -m streamlit run app.py

Importing this module starts nothing; the page is built only by main().
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def main() -> None:
    from netclass.dashboard.ui import main as run_page

    run_page()


if __name__ == "__main__":  # `streamlit run` executes the script as __main__
    main()
