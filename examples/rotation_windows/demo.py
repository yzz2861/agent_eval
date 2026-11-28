#!/usr/bin/env python3
"""Run the offline three-role rotation-window sample."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from tuf.rotation import load_rotation_plan


def main() -> None:
    here = Path(__file__).resolve().parent
    scenario = json.loads((here / "scenario.json").read_text(encoding="utf-8"))
    plan = load_rotation_plan(
        str(here / "old_targets.json"),
        str(here / "new_targets.json"),
        str(here / "approvals.json"),
        str(here / "scenario.json"),
    )

    baseline = plan.evaluate()
    print("BASELINE")
    print(baseline.summary())
    print(json.dumps(baseline.to_dict(), indent=2, sort_keys=True))

    delay = scenario["delay"]
    delayed_plan = plan.with_delayed_slip(
        delay["role"], timedelta(minutes=delay["minutes"])
    )
    delayed = delayed_plan.evaluate()
    print()
    print(f"DELAYED {delay['role']} BY {delay['minutes']} MINUTES")
    print(delayed.summary())
    print(json.dumps(delayed.to_dict(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
