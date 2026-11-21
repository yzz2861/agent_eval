"""Command line interface for the maintenance station offline planner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from maintenance.engine.planner import (
    evaluate_fleet,
    load_inventory,
    load_release_directories,
)
from maintenance.scenario.build_scenario import build_scenario


def _print_report(decisions: list[dict]) -> None:
    for decision in decisions:
        print(f"device_group={decision['device_group']}")
        print(f"  inventory_version={decision['inventory_version']}")
        print(f"  selected_version={decision['selected_version']}")
        print(f"  source_release={decision['source_release']}")
        print(f"  decision_status={decision['decision_status']}")
        print(f"  failure_reason={decision['failure_reason']}")
        print(f"  installed_by={decision['installed_by']}")
        print(f"  conclusion_expires_at={decision['conclusion_expires_at']}")
        for candidate in decision["candidates"]:
            print(
                "  candidate "
                f"{candidate['version']} ({candidate['release']}): "
                f"{candidate['status']}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Plan offline TUF-verified updates for device groups during a "
            "maintenance window."
        )
    )
    parser.add_argument(
        "--scenario-dir",
        type=Path,
        default=Path("maintenance/scenario/generated"),
        help="Directory containing inventory.json and release directories.",
    )
    parser.add_argument(
        "--build-scenario",
        action="store_true",
        help="Regenerate the deterministic scenario data before evaluation.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit machine-readable JSON instead of a text report.",
    )
    args = parser.parse_args()

    if args.build_scenario:
        build_scenario(args.scenario_dir)

    inventory = load_inventory(
        args.scenario_dir / "devices" / "inventory.json"
    )
    releases = load_release_directories(args.scenario_dir)
    trusted_root = args.scenario_dir / "devices" / "root.json"
    decisions = evaluate_fleet(inventory, releases, trusted_root)

    if args.emit_json:
        print(json.dumps(decisions, indent=2, ensure_ascii=False))
    else:
        _print_report(decisions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
