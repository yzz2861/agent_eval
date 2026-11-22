"""Command line entry point for the offline release gate."""

import argparse
import sys

from .report import render_text_report, write_json_report
from .validator import ReleaseGate


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate outbound STIX conclusions against investigation"
                    " authorizations and independent observations (offline).",
    )
    parser.add_argument("bundle", help="path to a STIX bundle JSON file")
    parser.add_argument("--json-out", help="write the detailed JSON report here")
    parser.add_argument("--text-out", help="write the short text report here")
    args = parser.parse_args(argv)

    gate = ReleaseGate(args.bundle)
    verdicts = gate.run()
    text_report = render_text_report(verdicts)
    if args.json_out:
        write_json_report(verdicts, args.json_out)
    if args.text_out:
        with open(args.text_out, "w", encoding="utf-8") as handle:
            handle.write(text_report)
    print(text_report)
    return 1 if any(not verdict.releasable for verdict in verdicts) else 0


if __name__ == "__main__":
    sys.exit(main())
