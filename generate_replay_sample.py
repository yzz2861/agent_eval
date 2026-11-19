#!/usr/bin/env python3
"""Generate a fixed-seed, sub-4KB replayable defect sample.

The sample deliberately breaks exactly one PE constraint (a resource
directory offset) and still reaches the deep resource parsing path before
pefile emits a diagnostic.  It is written to ``tests/replay_defect.bin`` so
that any regression run can re-parse the exact bytes without regenerating
them.
"""

from pathlib import Path

import pefile

from pefuzz import build_mini_pe, mutators


def main():
    base = build_mini_pe()
    broken, record = mutators.break_resource_depth(base)
    out_path = Path(__file__).resolve().parent / "tests" / "replay_defect.bin"
    out_path.write_bytes(broken)

    pe = pefile.PE(data=broken, fast_load=True)
    pe.parse_data_directories()
    warnings = pe.get_warnings()

    print("sample:", out_path)
    print("size_bytes:", len(broken), "(under 4KB:", len(broken) < 4096, ")")
    print("broken_constraint:", record.broken_constraint)
    print("parser_warnings:", warnings)
    assert len(broken) < 4096
    assert any("resources directory" in warning for warning in warnings)


if __name__ == "__main__":
    main()
