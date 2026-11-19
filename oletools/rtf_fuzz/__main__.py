"""Command line entry point: python -m oletools.rtf_fuzz."""

import argparse
import json
import sys

from .campaign import run_campaign


def build_parser():
    parser = argparse.ArgumentParser(
        description="Structure-aware RTF object fuzzer for oletools")
    parser.add_argument("--seed", type=int, default=20261119,
                        help="deterministic RNG seed")
    parser.add_argument("--valid-steps", type=int, default=40,
                        help="parser executions in the valid sample pool")
    parser.add_argument("--invalid-steps", type=int, default=40,
                        help="parser executions in the invalid sample pool")
    parser.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024,
                        help="cumulative byte budget for all parses")
    parser.add_argument("--output-dir", default=None,
                        help="directory for JSON summary and minimal RTFs")
    parser.add_argument("--no-reduce", action="store_true",
                        help="skip syntax-unit reduction of findings")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    campaign = run_campaign(
        seed=args.seed,
        valid_steps=args.valid_steps,
        invalid_steps=args.invalid_steps,
        max_bytes=args.max_bytes,
        output_dir=args.output_dir,
        reduce_findings=not args.no_reduce,
    )
    summary = campaign.summary()
    if args.output_dir is None:
        print(json.dumps({
            "finding_count": summary["finding_count"],
            "budget": summary["budget"],
            "seeds": summary["seeds"],
        }, indent=2, sort_keys=True))
    else:
        print("artifacts written to %s" % args.output_dir)
        print("findings: %d" % summary["finding_count"])
        print("budget: %s" % json.dumps(summary["budget"], sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
