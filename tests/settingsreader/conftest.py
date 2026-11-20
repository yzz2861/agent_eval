"""Shared helpers for the settings reader acceptance tests.

The tests all use one small, caller supplied cstruct layout so that generation
wrap around and interrupted writes can be exercised on tiny in-memory images.
"""

from __future__ import annotations

import struct
import zlib

from dissect.cstruct import cstruct

from settingsreader import TableLayout, field_crc32

REGION_A_OFFSET = 0
REGION_B_OFFSET = 64
IMAGE_SIZE = 128
RECORD_SIZE = 20

DEFINITION = """
struct SecuritySettings {
    uint32 generation;
    uint32 committed;
    uint32 checksum;
    char   policy[8];
};
"""


def make_layout(**overrides):
    cs = cstruct()
    cs.load(DEFINITION)
    rule = field_crc32(("generation", "committed", "policy"), stored_checksum_field="checksum")
    layout = TableLayout(
        cs.SecuritySettings,
        (REGION_A_OFFSET, REGION_B_OFFSET),
        commit_field="committed",
        generation_field="generation",
        checksum_field="checksum",
        checksum_rule=rule,
    )
    for key, value in overrides.items():
        object.__setattr__(layout, key, value)
    return layout


def make_record(generation, committed, policy=b"default!", *, valid_checksum=True, checksum=None):
    policy = bytes(policy).ljust(8, b"\x00")[:8]
    covered = struct.pack("<II", generation, committed) + policy
    stored = zlib.crc32(covered) & 0xFFFFFFFF
    if checksum is not None:
        stored = checksum
    elif not valid_checksum:
        stored ^= 0xDEADBEEF
    return struct.pack("<II", generation, committed) + struct.pack("<I", stored) + policy


def make_image(region_a=None, region_b=None, *, fill=0xFF):
    image = bytearray([fill]) * IMAGE_SIZE
    if region_a is not None:
        image[REGION_A_OFFSET:REGION_A_OFFSET + len(region_a)] = region_a
    if region_b is not None:
        image[REGION_B_OFFSET:REGION_B_OFFSET + len(region_b)] = region_b
    return bytes(image)
