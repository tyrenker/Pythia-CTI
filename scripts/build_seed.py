"""Seed pipeline entry-point — delegates to pythia.core.seed.

Run directly:
  python scripts/build_seed.py
  python scripts/build_seed.py --sources attck,atlas   # selective refresh
  python scripts/build_seed.py --dry-run               # count only, no writes

Available sources:
  misp-galaxy attck attck-mobile attck-ics atlas kev sigma owasp apt-sheet
  abuse-ch ipsum phishtank malpedia sigma-full yara-rules icewater
  signature-base dedup
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure the package is importable when run directly.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pythia.core.seed import run

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pythia seed pipeline")
    parser.add_argument(
        "--sources",
        nargs="*",
        default=None,
        help=(
            "Sources to load (default: all). "
            "Options: misp-galaxy attck attck-mobile attck-ics atlas kev sigma owasp apt-sheet "
            "abuse-ch ipsum phishtank malpedia sigma-full yara-rules icewater signature-base dedup"
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Count only, no DB writes")
    args = parser.parse_args()
    run(sources=args.sources, dry_run=args.dry_run)
