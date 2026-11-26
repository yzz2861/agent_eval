#!/usr/bin/env python
from __future__ import print_function

import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from Registry import Registry
SOURCE_HIVE = os.path.join(ROOT, "tests", "reg_samples", "issue22.hive")
BASELINE_HIVE = os.path.join(ROOT, "tests", "reg_samples", "audit_recipients_baseline.hive")
CURRENT_HIVE = os.path.join(ROOT, "tests", "reg_samples", "audit_recipients_current.hive")


BASELINE_RECIPIENTS = ["alice", "", "bob", "alice", "rob"]
CURRENT_RECIPIENTS = ["alice", "", "bob", "alice", "rob", "bob"]

BASELINE_REORDER = ["alice", "bob", "alice", ""]
CURRENT_REORDER = ["", "alice", "alice", "bob"]

BASELINE_DENIED = ["carol", "dan"]
CURRENT_DENIED = ["carol", "dan", "eve"]


def encode_multisz(values):
    chunks = []
    for value in values:
        chunks.append(value.encode("utf-16-le"))
        chunks.append(b"\x00\x00")
    chunks.append(b"\x00\x00")
    return b"".join(chunks)


def patch_ascii_name(buf, record_offset, name):
    encoded = name.encode("ascii")
    old_length = struct.unpack_from("<H", buf, record_offset + 0x02)[0]
    name_start = record_offset + 0x14
    for index in range(old_length):
        buf[name_start + index] = 0
    struct.pack_into("<H", buf, record_offset + 0x02, len(encoded))
    buf[name_start:name_start + len(encoded)] = encoded


def patch_multisz_value(hive_path, output_path, root_name, patches):
    with open(hive_path, "rb") as handle:
        buf = bytearray(handle.read())

    reg = Registry.Registry(hive_path)
    root = reg.root()
    nk_offset = root._nkrecord.offset()
    root_name_bytes = root_name.encode("ascii")
    old_root_length = struct.unpack_from("<H", buf, nk_offset + 0x48)[0]
    for index in range(old_root_length):
        buf[nk_offset + 0x4C + index] = 0
    struct.pack_into("<H", buf, nk_offset + 0x48, len(root_name_bytes))
    buf[nk_offset + 0x4C:nk_offset + 0x4C + len(root_name_bytes)] = root_name_bytes

    values = {value.name(): value for value in root.values()}
    for old_name, new_name, members in patches:
        registry_value = values[old_name]
        vk = registry_value._vkrecord
        vk_offset = vk.offset()
        data = encode_multisz(members)

        data_cell = vk.data_offset()
        cell_size = abs(struct.unpack_from("<i", buf, data_cell)[0])
        data_capacity = cell_size - 4
        if len(data) > data_capacity:
            raise RuntimeError("Encoded value is too large for existing data cell")

        patch_ascii_name(buf, vk_offset, new_name)
        struct.pack_into("<I", buf, vk_offset + 0x04, len(data))
        struct.pack_into("<I", buf, vk_offset + 0x0C, Registry.RegMultiSZ)
        data_start = data_cell + 4
        buf[data_start:data_start + data_capacity] = b"\x00" * data_capacity
        buf[data_start:data_start + len(data)] = data

    with open(output_path, "wb") as handle:
        handle.write(buf)


def main():
    patch_multisz_value(
        SOURCE_HIVE,
        BASELINE_HIVE,
        "AuditConfig",
        [
            ("TimeZoneKeyName", "AuditRecipients", BASELINE_RECIPIENTS),
            ("StandardName", "ReorderOnly", BASELINE_REORDER),
            ("DaylightName", "DeniedAppend", BASELINE_DENIED),
        ],
    )
    patch_multisz_value(
        SOURCE_HIVE,
        CURRENT_HIVE,
        "AuditConfig",
        [
            ("TimeZoneKeyName", "AuditRecipients", CURRENT_RECIPIENTS),
            ("StandardName", "ReorderOnly", CURRENT_REORDER),
            ("DaylightName", "DeniedAppend", CURRENT_DENIED),
        ],
    )
    print(BASELINE_HIVE)
    print(CURRENT_HIVE)


if __name__ == "__main__":
    main()
