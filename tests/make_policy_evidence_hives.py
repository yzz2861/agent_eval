#!/usr/bin/env python
"""
Build the small policy-evidence hives used by tests/test_value_evidence.py.

The generated files are intentionally tiny (8 KiB each). They contain one
root key and four values:

  AuditLevel             RegDWord or RegBigEndian
  LmCompatibilityLevel   RegDWord
  RestrictAnonymous      RegBigEndian
  IncompletePolicy       RegDWord with a declared length of two bytes

Three snapshots are written:

  baseline.hive
  representation_change.hive  AuditLevel's type marker changes, bytes do not
  value_change.hive           LmCompatibilityLevel's stored bytes change
"""

from __future__ import print_function

import os
import struct
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from Registry import Registry as RegistryModule


CELL_START = 0x20
HBIN_SIZE = 0x1000
REGF_SIZE = 0x1000


class Policy(object):
    def __init__(self, name, data_type, raw_data, declared_length=None):
        self.name = name
        self.data_type = data_type
        self.raw_data = raw_data
        if declared_length is None:
            declared_length = len(raw_data)
        self.declared_length = declared_length


def _align(value, alignment=8):
    return (value + alignment - 1) // alignment * alignment


def _cell_size(payload_length):
    return _align(4 + payload_length)


def _pack_cell(payload):
    total = _cell_size(len(payload))
    return (
        struct.pack("<i", -total)
        + bytes(payload)
        + b"\x00" * (total - 4 - len(payload))
    )


def _nk_payload(name, values_list_offset, values_count):
    name_bytes = name.encode("windows-1252")
    payload = bytearray(0x4C + len(name_bytes))
    payload[0:2] = b"nk"
    struct.pack_into("<H", payload, 0x2, 0x2C)
    struct.pack_into("<Q", payload, 0x4, 0)
    struct.pack_into("<I", payload, 0xC, 0)
    struct.pack_into("<I", payload, 0x10, 0xFFFFFFFF)
    struct.pack_into("<I", payload, 0x14, 0)
    struct.pack_into("<I", payload, 0x18, 0)
    struct.pack_into("<I", payload, 0x1C, 0xFFFFFFFF)
    struct.pack_into("<I", payload, 0x20, 0xFFFFFFFF)
    struct.pack_into("<I", payload, 0x24, values_count)
    struct.pack_into("<I", payload, 0x28, values_list_offset)
    struct.pack_into("<I", payload, 0x2C, 0xFFFFFFFF)
    struct.pack_into("<I", payload, 0x30, 0xFFFFFFFF)
    struct.pack_into("<I", payload, 0x34, 0)
    struct.pack_into("<I", payload, 0x38, 0)
    struct.pack_into("<I", payload, 0x3C, 0)
    struct.pack_into("<I", payload, 0x40, 0)
    struct.pack_into("<I", payload, 0x44, 0)
    struct.pack_into("<H", payload, 0x48, len(name_bytes))
    struct.pack_into("<H", payload, 0x4A, 0)
    payload[0x4C:] = name_bytes
    return payload


def _vk_payload(policy):
    name_bytes = policy.name.encode("windows-1252")
    payload = bytearray(0x14 + len(name_bytes))
    payload[0:2] = b"vk"
    struct.pack_into("<H", payload, 0x2, len(name_bytes))

    if len(policy.raw_data) <= 4:
        struct.pack_into(
            "<I", payload, 0x4, 0x80000000 | policy.declared_length
        )
        payload[0x8:0x8 + len(policy.raw_data)] = policy.raw_data
    else:
        raise ValueError("this fixture builder only emits inline integers")

    struct.pack_into("<I", payload, 0xC, policy.data_type)
    struct.pack_into("<H", payload, 0x10, 1)
    struct.pack_into("<H", payload, 0x12, 0)
    payload[0x14:] = name_bytes
    return payload


def _regf_checksum(buf):
    checksum = 0
    for offset in range(0, 0x1FC, 4):
        checksum ^= struct.unpack_from("<I", buf, offset)[0]
    if checksum == 0:
        return 1
    if checksum == 0xFFFFFFFF:
        return 0xFFFFFFFE
    return checksum


def _regf_header(hive_name):
    header = bytearray(REGF_SIZE)
    header[0:4] = b"regf"
    struct.pack_into("<I", header, 0x4, 1)
    struct.pack_into("<I", header, 0x8, 1)
    struct.pack_into("<Q", header, 0xC, 0)
    struct.pack_into("<I", header, 0x14, 1)
    struct.pack_into("<I", header, 0x18, 3)
    struct.pack_into("<I", header, 0x1C, 0)
    struct.pack_into("<I", header, 0x20, 1)
    struct.pack_into("<I", header, 0x24, CELL_START)
    struct.pack_into("<I", header, 0x28, HBIN_SIZE)
    struct.pack_into("<I", header, 0x2C, 1)

    encoded_name = hive_name.encode("utf-16le")[:62]
    header[0x30:0x30 + len(encoded_name)] = encoded_name
    struct.pack_into("<I", header, 0x1FC, _regf_checksum(header))
    return bytes(header)


def build_hive(path, policies, hive_name="policy_evidence.hive"):
    nk_total = _cell_size(0x4C + len("Policies"))
    values_list_payload_length = 4 * len(policies)
    values_list_total = _cell_size(values_list_payload_length)
    vk_totals = [_cell_size(0x14 + len(p.name)) for p in policies]

    nk_offset = CELL_START
    values_list_offset = nk_offset + nk_total
    vk_offsets = []
    cursor = values_list_offset + values_list_total
    for total in vk_totals:
        vk_offsets.append(cursor)
        cursor += total

    nk_cell = _pack_cell(
        _nk_payload("Policies", values_list_offset, len(policies))
    )
    values_list_payload = b"".join(
        struct.pack("<I", offset) for offset in vk_offsets
    )
    values_list_cell = _pack_cell(values_list_payload)
    vk_cells = [_pack_cell(_vk_payload(policy)) for policy in policies]

    body = nk_cell + values_list_cell + b"".join(vk_cells)
    remaining = HBIN_SIZE - CELL_START - len(body)
    if remaining < 4:
        raise ValueError("fixture cells do not fit in one hbin")
    if remaining:
        body += struct.pack("<i", remaining) + b"\x00" * (remaining - 4)

    hbin = bytearray(HBIN_SIZE)
    hbin[0:4] = b"hbin"
    struct.pack_into("<I", hbin, 0x4, 0)
    struct.pack_into("<I", hbin, 0x8, HBIN_SIZE)
    hbin[CELL_START:CELL_START + len(body)] = body

    with open(path, "wb") as f:
        f.write(_regf_header(hive_name))
        f.write(bytes(hbin))


def _baseline_policies():
    return [
        Policy("AuditLevel", RegistryModule.RegDWord, b"\x01\x00\x00\x00"),
        Policy(
            "LmCompatibilityLevel",
            RegistryModule.RegDWord,
            b"\x03\x00\x00\x00",
        ),
        Policy(
            "RestrictAnonymous",
            RegistryModule.RegBigEndian,
            b"\x00\x00\x00\x01",
        ),
        Policy(
            "IncompletePolicy",
            RegistryModule.RegDWord,
            b"\x05\x00\x00\x00",
            declared_length=2,
        ),
    ]


def write_default_hives(output_dir):
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    baseline = _baseline_policies()
    representation = _baseline_policies()
    representation[0] = Policy(
        "AuditLevel",
        RegistryModule.RegBigEndian,
        b"\x01\x00\x00\x00",
    )
    value_change = _baseline_policies()
    value_change[1] = Policy(
        "LmCompatibilityLevel",
        RegistryModule.RegDWord,
        b"\x04\x00\x00\x00",
    )

    for name, policies in [
        ("baseline.hive", baseline),
        ("representation_change.hive", representation),
        ("value_change.hive", value_change),
    ]:
        build_hive(
            os.path.join(output_dir, name),
            policies,
            hive_name="policy_evidence.hive",
        )


if __name__ == "__main__":
    output_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "reg_samples",
        "policy_evidence",
    )
    write_default_hives(output_dir)
    print("wrote policy evidence hives to {0}".format(output_dir))
