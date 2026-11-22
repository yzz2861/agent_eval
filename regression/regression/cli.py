"""Command line entry point for the offline Bandit regression chain."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import run_regression
from .loader import load_gate, load_rules, load_samples, load_scan, load_scopes
from .report import export_json, render_coverage_report, render_gate_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bandit-regression",
        description=(
            "Compare two Bandit JSON scans against a frozen, "
            "human-adjudicated sample set and enforce group gates."
        ),
    )
    parser.add_argument("--frozen-dir", required=True, type=Path)
    parser.add_argument("--old-scan", required=True, type=Path)
    parser.add_argument("--new-scan", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--sample-root",
        type=Path,
        default=None,
        help="Optional root for sha256 drift verification of frozen files.",
    )
    parser.add_argument(
        "--old-disabled", type=Path, default=None,
        help="Optional sidecar JSON listing rules disabled in the old scan.",
    )
    parser.add_argument(
        "--new-disabled", type=Path, default=None,
        help="Optional sidecar JSON listing rules disabled in the new scan.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    frozen = args.frozen_dir
    rules = load_rules(frozen / "rule_catalogue.json")
    samples = load_samples(frozen / "samples.json", args.sample_root)
    scopes = load_scopes(frozen / "applicability.json")
    default_min_recall, group_config = load_gate(frozen / "gate.json")

    freeze_id = "unknown"
    manifest_meta = frozen / "freeze.json"
    if manifest_meta.exists():
        import json

        freeze_id = str(json.loads(manifest_meta.read_text()).get(
            "freeze_id", freeze_id
        ))

    old_scan = load_scan(args.old_scan, "升级前", args.old_disabled)
    new_scan = load_scan(args.new_scan, "升级后", args.new_disabled)

    result = run_regression(
        freeze_id=freeze_id,
        samples=samples,
        rules=rules,
        scopes=scopes,
        old_scan=old_scan,
        new_scan=new_scan,
        default_min_recall=default_min_recall,
        group_config=group_config,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    coverage = args.output_dir / "report_coverage.md"
    gate = args.output_dir / "report_gate.md"
    machine = args.output_dir / "regression_result.json"
    coverage.write_text(render_coverage_report(result), encoding="utf-8")
    gate.write_text(render_gate_report(result), encoding="utf-8")
    export_json(result, machine)

    print(f"wrote {coverage}")
    print(f"wrote {gate}")
    print(f"wrote {machine}")
    print("gate verdict:", "BLOCK" if result.blocked else "PASS")
    return 1 if result.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
