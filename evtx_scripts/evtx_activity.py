#!/usr/bin/env python
"""Read-only EVTX active-slot/residue audit report."""

from __future__ import absolute_import

import argparse
import json
import sys

from Evtx.activity import inspect_path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit header activity ordinals, physical chunks, record ranges, residue, and truncation."
    )
    parser.add_argument("evtx", type=str, help="Path to the Windows EVTX event log file")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Print the report as JSON")
    args = parser.parse_args(argv)

    report = inspect_path(args.evtx)
    if args.as_json:
        json.dump(report.to_dict(), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(report.format_text())
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
