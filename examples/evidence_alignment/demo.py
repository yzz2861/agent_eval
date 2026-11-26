#!/usr/bin/env python
"""Run the small handoff-alignment example from a source checkout."""

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from Evtx.alignment import align_files  # noqa: E402


def main() -> int:
    case_dir = Path(__file__).resolve().parent
    result = align_files(case_dir)
    print(result.report())
    print()
    print("Shift assignments:")
    for evidence_id in result.original_order:
        shifts = sorted(result.shift_assignments.get(evidence_id, set()))
        print(f"  {evidence_id}: {', '.join(shifts) if shifts else '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
