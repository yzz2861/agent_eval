"""Hand-checkable demonstration of the tri-state property campaign.

Run it directly with the in-tree PyYAML on sys.path:

    python tests/tri_state/demo.py [seed] [iterations]

It prints sample generated documents, the strict loader clean bill of health,
and the reduced repro produced when the lenient unknown-means-pass stand-in
swallows a decision.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
for path in (ROOT, TESTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from tri_state.contract import permissive_load, strict_load  # noqa: E402
from tri_state.properties import run_property  # noqa: E402
from tri_state.strategy import documents  # noqa: E402


def main(argv):
    seed = int(argv[1]) if len(argv) > 1 else 20261123
    iterations = int(argv[2]) if len(argv) > 2 else 400

    print(f"=== sample generated documents (seed={seed}) ===")
    for spec in documents(seed, 3):
        print(spec.render())

    print("=== strict loader campaign ===")
    strict_failure = run_property(strict_load, seed=seed, iterations=iterations)
    if strict_failure is None:
        print(f"OK: strict loader honoured the contract for all {iterations} documents")
        print()
    else:
        print(strict_failure.render_report())
        return 1

    print("=== lenient unknown-means-pass stand-in campaign ===")
    lenient_failure = run_property(permissive_load, seed=seed, iterations=iterations)
    if lenient_failure is None:
        print("UNEXPECTED: the lenient loader was not caught")
        return 1
    print(lenient_failure.render_report())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
