#!/usr/bin/env python
"""Align EVTX records and shift evidence without relying on timestamps alone."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from Evtx.alignment import EvidenceAligner


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Infer possible temporal orders from record numbers, signed markers, and file order."
    )
    parser.add_argument("paths", nargs="+", help="Evidence JSON/case directories and/or EVTX files")
    parser.add_argument("--handoff", help="Explicit handoff marker ID")
    parser.add_argument("--max-orders", type=int, default=1024, help="Maximum candidate orders to enumerate")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of the text report")
    args = parser.parse_args(argv)

    aligner = EvidenceAligner(handoff=args.handoff, max_orders=args.max_orders)
    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.exists():
            parser.error(f"path does not exist: {raw_path}")
        aligner.add_path(path)

    result = aligner.align()
    if args.json:
        json.dump(result.to_dict(), sys.stdout, ensure_ascii=False, indent=2, default=str)
        sys.stdout.write(chr(10))
    else:
        print(result.report())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
