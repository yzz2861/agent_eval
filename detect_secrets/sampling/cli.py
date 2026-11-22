"""Command line interface for the offline review sampler."""

import argparse
import json
import sys
from typing import List
from typing import Optional

from .planner import build_plan
from .planner import verify_exception
from .stratify import DEFAULT_UNDER_REVIEW_THRESHOLD


def _add_common_sampling_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--queue-map",
        help="JSON file mapping filename prefixes to source queues",
    )
    parser.add_argument(
        "--reviewed",
        help="JSON file (list or object) of human-reviewed finding ids",
    )
    parser.add_argument(
        "--under-review-threshold",
        type=float,
        default=DEFAULT_UNDER_REVIEW_THRESHOLD,
        help=(
            "strata with a sample fraction below this are flagged as "
            "under-reviewed (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--allocation-mode",
        choices=["even", "proportional"],
        default="even",
        help=(
            "how the review budget is distributed across strata "
            "(default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--queue-caps",
        help=(
            "JSON file mapping a source queue to the maximum number of "
            "sample slots it may receive"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detect-secrets-sampling",
        description=(
            "Build a fixed-seed, stratified offline manual-review sample from "
            "a detect-secrets baseline, and verify individual exceptions."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser(
        "plan",
        help="build a reproducible stratified sampling plan",
    )
    plan.add_argument("baseline", help="path to a detect-secrets baseline JSON")
    plan.add_argument(
        "--seed",
        type=int,
        required=True,
        help="non-negative integer seed; the same seed replays the same sample",
    )
    plan.add_argument(
        "--budget",
        type=int,
        required=True,
        help="number of findings the security lead can manually review",
    )
    plan.add_argument(
        "--output",
        help="write the full JSON plan here instead of stdout",
    )
    _add_common_sampling_arguments(plan)

    verify = subparsers.add_parser(
        "verify",
        help="check whether a specific exception was missed by manual review",
    )
    verify.add_argument("baseline", help="path to a detect-secrets baseline JSON")
    verify.add_argument(
        "--finding-id",
        required=True,
        help="finding id to check (filename:line_number:hashed_secret)",
    )
    verify.add_argument("--seed", type=int, required=True)
    verify.add_argument("--budget", type=int, required=True)
    _add_common_sampling_arguments(verify)

    return parser


def _load_queue_caps(path: Optional[str]) -> Optional[dict]:
    if path is None:
        return None
    with open(path, encoding="utf-8") as handle:
        caps = json.load(handle)
    return {str(queue): int(cap) for queue, cap in caps.items()}


def render_text_report(plan_dict: dict) -> str:
    """Render a compact, human-readable coverage summary."""
    report = plan_dict["report"]
    aggregate = report["aggregate"]
    lines = [
        "seed={}  budget={}  mode={}  under-review-threshold={}".format(
            plan_dict["seed"],
            plan_dict["sample_budget"],
            plan_dict["allocation_mode"],
            plan_dict["under_review_threshold"],
        ),
        (
            "aggregate: {total_findings} findings, {total_sampled} sampled "
            "({sample_pct}%), {total_reviewed} human-reviewed "
            "({coverage_pct}%), {total_unreviewed} still unreviewed".format(
                total_findings=aggregate["total_findings"],
                total_sampled=aggregate["total_sampled"],
                sample_pct=round(
                    100 * aggregate["aggregate_sample_fraction"],
                    2,
                ),
                total_reviewed=aggregate["total_reviewed"],
                coverage_pct=round(
                    100 * aggregate["aggregate_human_coverage"],
                    2,
                ),
                total_unreviewed=aggregate["total_unreviewed"],
            )
        ),
        "",
        (
            "{queue:<24} {detector:<24} {pop:>5} {samp:>5} {frac:>7} "
            "{revd:>5} {cov:>7} {left:>5}  flag".format(
                queue="queue",
                detector="detector",
                pop="pop",
                samp="samp",
                frac="samp%",
                revd="revd",
                cov="cov%",
                left="left",
            )
        ),
    ]
    for row in report["strata"]:
        lines.append(
            "{queue:<24} {detector:<24} {pop:>5} {samp:>5} {frac:>6}% "
            "{revd:>5} {cov:>6}% {left:>5}  {flag}".format(
                queue=row["source_queue"][:24],
                detector=row["primary_detector"][:24],
                pop=row["population_size"],
                samp=row["sample_size"],
                frac=round(100 * row["sample_fraction"], 2),
                revd=row["reviewed_findings"],
                cov=round(100 * row["human_coverage"], 2),
                left=row["unreviewed_findings"],
                flag="UNDER-REVIEWED" if row["under_reviewed"] else "ok",
            ),
        )
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    plan = build_plan(
        baseline_path=args.baseline,
        seed=args.seed,
        sample_budget=args.budget,
        queue_map_path=args.queue_map,
        reviewed_path=args.reviewed,
        under_review_threshold=args.under_review_threshold,
        allocation_mode=args.allocation_mode,
        queue_caps=_load_queue_caps(args.queue_caps),
    )

    if args.command == "plan":
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                json.dump(plan.to_dict(), handle, indent=2, sort_keys=True)
                handle.write("\n")
        else:
            print(render_text_report(plan.to_dict()))
        return 0

    result = verify_exception(plan, args.finding_id, args.reviewed)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["missed_by_manual_review"] else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
