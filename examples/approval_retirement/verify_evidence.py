#!/usr/bin/env python3
"""Re-verify the acceptance evidence using only its published public keys."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from securesystemslib.retirement import (  # noqa: E402
    RetirementService,
    VerificationStatus,
)
from securesystemslib.signer import Key  # noqa: E402

DEFAULT_EVIDENCE = Path(__file__).parent / "evidence"


def load_keys(path: Path) -> list[Key]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Key.from_dict(keyid, dict(key_data)) for keyid, key_data in data.items()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        type=Path,
        default=DEFAULT_EVIDENCE,
        help=f"acceptance evidence root (default: {DEFAULT_EVIDENCE})",
    )
    args = parser.parse_args()
    root = args.evidence.resolve()

    success = root / "success"
    success_keys = load_keys(success / "evidence/public-keys.json")
    success_service = RetirementService(success_keys, success_keys)
    success_report = success_service.verify_retirement(
        success / "index.dsse.json",
        success / "retirement-manifest.dsse.json",
    )

    shared = root / "shared-reference"
    shared_keys = load_keys(shared / "evidence/public-keys.json")
    shared_service = RetirementService(shared_keys, shared_keys)
    shared_report = shared_service.verify_rejection(
        shared / "index.dsse.json",
        json.loads((shared / "evidence/request.json").read_text(encoding="utf-8")),
    )

    result = {
        "successful-retirement": success_report.to_dict(),
        "shared-reference-rejection": shared_report.to_dict(),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return (
        0
        if all(
            report.status is VerificationStatus.VALID
            for report in (success_report, shared_report)
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
