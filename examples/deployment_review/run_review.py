"""
Offline, per-deployment-stage lockfile review.

Reads the build-host and runtime-image PEP 751 lock files, audits them
against the frozen offline advisory snapshot, applies the role-scoped
exemption catalog and emits a JSON report in which each role keeps its
own evidence and runtime warnings are never cancelled by another role.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from pip_audit._deployment import render_json, review_stages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    stages = [
        ("build-host", args.samples_dir / "build-host.pylock.toml"),
        ("runtime-image", args.samples_dir / "runtime-image.pylock.toml"),
    ]
    environments = {
        "build-host": {"sys_platform": "linux"},
        "runtime-image": {"sys_platform": "linux"},
    }
    stage_reviews, _service, _catalog = review_stages(
        stages=stages,
        advisory_snapshot=args.samples_dir / "offline-advisories.json",
        exemption_file=args.samples_dir / "exemptions.toml",
        environments=environments,
    )

    args.output.write_text(render_json(stage_reviews), encoding="utf-8")
    for stage in stage_reviews:
        print(f"{stage.role}: {len(stage.runtime_warnings)} runtime warning(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
