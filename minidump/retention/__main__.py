#!/usr/bin/env python3
#
# Offline retention planner command line entry point.
#
import argparse
import json
import sys

from minidump.retention.planner import RetentionPlanningError, build_plan
from minidump.retention.report import format_diff, format_plan


def run():
	parser = argparse.ArgumentParser(
		prog="python -m minidump.retention",
		description=(
			"Offline planner that classifies crash dump fragments as "
			"retained or cleanable based on the analyses and the local "
			"stream catalog used for recomputation."
		),
	)
	parser.add_argument("dump", help="Path to the local minidump file")
	parser.add_argument(
		"catalog",
		help="Directory containing analysis catalog JSON files (stream directory)",
	)
	parser.add_argument(
		"--analysis",
		action="append",
		dest="analyses",
		help="Analysis id to include (repeatable). Defaults to every catalog entry",
	)
	parser.add_argument(
		"--baseline",
		help=(
			"Optional second analysis selection (comma separated) used as a "
			"baseline to print the additional fragments retained by --analysis"
		),
	)
	parser.add_argument(
		"--json",
		action="store_true",
		dest="as_json",
		help="Emit the plan as JSON instead of plain text",
	)
	args = parser.parse_args()

	try:
		plan = build_plan(args.dump, args.catalog, args.analyses)
	except RetentionPlanningError as exc:
		print("error: %s" % exc, file=sys.stderr)
		return 2

	if args.as_json:
		print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
		return 0

	print(format_plan(plan))
	if args.baseline:
		baseline_ids = [item.strip() for item in args.baseline.split(",") if item.strip()]
		try:
			baseline_plan = build_plan(args.dump, args.catalog, baseline_ids)
		except RetentionPlanningError as exc:
			print("error: %s" % exc, file=sys.stderr)
			return 2
		print("")
		print(format_diff(baseline_plan, plan))
	return 0


if __name__ == "__main__":
	sys.exit(run())
