# /// script
# requires-python = ">=3.10"
# dependencies = ["dissect.cstruct"]
# ///
"""Offline read of a device image with two redundant security settings tables.

The image below is built in-memory, but read_settings() accepts a real image
path just as well and always opens it read-only.  Two failure modes are shown:

1. the generation counter wrapped around, so the numerically smaller counter is
   actually the newest committed table;
2. a write was interrupted after the data landed but before the commit marker,
   leaving an intact but uncommitted table that is evidence only.
"""

from __future__ import annotations

import struct
import zlib

from dissect.cstruct import cstruct

from settingsreader import TableLayout, WriteState, field_crc32, read_settings

cs = cstruct()
cs.load(
    """
struct SecuritySettings {
    uint32 generation;
    uint32 committed;
    uint32 checksum;
    char   policy[8];
};
"""
)

rule = field_crc32(("generation", "committed", "policy"), stored_checksum_field="checksum")


def make_record(generation: int, committed: int, policy: bytes) -> bytes:
    policy = policy.ljust(8, b"\x00")[:8]
    covered = struct.pack("<II", generation, committed) + policy
    checksum = zlib.crc32(covered) & 0xFFFFFFFF
    return struct.pack("<II", generation, committed) + struct.pack("<I", checksum) + policy


def main() -> None:
    image = bytearray(b"\xff") * 128
    # Region A: last fully committed table, generation close to the uint32 limit.
    image[0:20] = make_record(0xFFFFFFFE, 1, b"allow")
    # Region B: wrapped to generation 1 but the power died before the commit marker.
    image[64:84] = make_record(1, 0, b"deny")

    layout = TableLayout(
        cs.SecuritySettings,
        (0, 64),
        commit_field="committed",
        generation_field="generation",
        checksum_field="checksum",
        checksum_rule=rule,
    )

    result = read_settings(bytes(image), layout)
    print(result.summary())
    print()
    for region in result.evidence_only:
        print(f"region {region.index} is {region.state.value} evidence only: {region.error}")
    assert result.active is not None
    assert result.active.state is WriteState.COMMITTED
    assert result.active.generation == 0xFFFFFFFE


if __name__ == "__main__":
    main()
