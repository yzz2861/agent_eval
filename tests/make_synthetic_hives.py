#!/usr/bin/env python
"""Build small, deterministic SOFTWARE hives for deletion-evidence tests.

The generated hives intentionally keep the target value record ("Policy") at
the same hive-relative cell offset.  The "after" variants then either free that
cell, reuse it for another value, or never contain the target value at all.

Run from the repository root:

    python tests/make_synthetic_hives.py
"""

from __future__ import print_function

import io
import os
import struct
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from Registry import Registry
from Registry import RegistryParse


OUTPUT_DIR = os.path.join(REPO_ROOT, "tests", "reg_samples", "deletion")

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
BEFORE_TIME = datetime(2026, 11, 20, 8, 0, 0, tzinfo=timezone.utc)
AFTER_TIME = datetime(2026, 11, 20, 9, 0, 0, tzinfo=timezone.utc)
BEFORE_SEQUENCE = 7
AFTER_SEQUENCE = 8


def _align(value, alignment=8):
    return (value + alignment - 1) & ~(alignment - 1)


def _filetime(value):
    delta = value - FILETIME_EPOCH
    return ((delta.days * 86400 + delta.seconds) * 10000000
            + delta.microseconds * 10)


def _pack_into(buf, fmt, offset, *values):
    struct.pack_into(fmt, buf, offset, *values)


def _update_checksum(buf):
    checksum = 0
    for offset in range(0, 0x1FC, 4):
        checksum ^= struct.unpack_from("<I", buf, offset)[0]
    if checksum == 0:
        checksum = 1
    elif checksum == 0xFFFFFFFF:
        checksum = 0xFFFFFFFE
    _pack_into(buf, "<I", 0x1FC, checksum)


def _stamp_header(buf, sequence, timestamp):
    _pack_into(buf, "<I", 0x04, sequence)
    _pack_into(buf, "<I", 0x08, sequence)
    _pack_into(buf, "<Q", 0x0C, _filetime(timestamp))
    _update_checksum(buf)


def _nk_record(name, flags, parent_offset, subkey_count, subkey_list_offset,
               value_count, value_list_offset, timestamp):
    name_bytes = name.encode("windows-1252")
    record = bytearray(0x4C + len(name_bytes))
    record[0:2] = b"nk"
    _pack_into(record, "<H", 0x02, flags)
    _pack_into(record, "<Q", 0x04, _filetime(timestamp))
    _pack_into(record, "<I", 0x10, parent_offset)
    _pack_into(record, "<I", 0x14, subkey_count)
    _pack_into(record, "<I", 0x1C, subkey_list_offset)
    _pack_into(record, "<I", 0x20, 0xFFFFFFFF)
    _pack_into(record, "<I", 0x24, value_count)
    _pack_into(record, "<I", 0x28, value_list_offset)
    _pack_into(record, "<I", 0x2C, 0xFFFFFFFF)
    _pack_into(record, "<I", 0x30, 0xFFFFFFFF)
    _pack_into(record, "<H", 0x48, len(name_bytes))
    _pack_into(record, "<H", 0x4A, 0)
    record[0x4C:0x4C + len(name_bytes)] = name_bytes
    return bytes(record)


def _leaf_subkey_list(child_offsets):
    data = bytearray(4 + 4 * len(child_offsets))
    data[0:2] = b"li"
    _pack_into(data, "<H", 2, len(child_offsets))
    for index, offset in enumerate(child_offsets):
        _pack_into(data, "<I", 4 + 4 * index, offset)
    return bytes(data)


def _value_list(value_offsets):
    data = bytearray(4 * len(value_offsets))
    for index, offset in enumerate(value_offsets):
        _pack_into(data, "<I", 4 * index, offset)
    return bytes(data)


def _vk_record(name, data_type, data_length, data_offset):
    name_bytes = name.encode("utf-16le")
    record = bytearray(0x14 + len(name_bytes))
    record[0:2] = b"vk"
    _pack_into(record, "<H", 0x02, len(name_bytes))
    _pack_into(record, "<I", 0x04, data_length)
    _pack_into(record, "<I", 0x08, data_offset)
    _pack_into(record, "<I", 0x0C, data_type)
    _pack_into(record, "<I", 0x10, 0)
    record[0x14:] = name_bytes
    return bytes(record)


def _build_before_hive_bytes():
    timestamp = BEFORE_TIME
    root_name = b"SOFTWARE"
    contoso_name = b"Contoso"
    agent_name = b"Agent"
    value_name = "Policy"
    value_data = "Enabled".encode("utf-16le") + b"\x00\x00"

    root_size = _align(4 + 0x4C + len(root_name))
    contoso_size = _align(4 + 0x4C + len(contoso_name))
    agent_size = _align(4 + 0x4C + len(agent_name))
    li_size = _align(4 + 4 + 4)
    values_size = _align(4 + 4)
    vk_size = 40
    data_size = _align(4 + len(value_data))

    root_abs = 0x1020
    contoso_abs = root_abs + root_size
    agent_abs = contoso_abs + contoso_size
    root_li_abs = agent_abs + agent_size
    contoso_li_abs = root_li_abs + li_size
    values_abs = contoso_li_abs + li_size
    vk_abs = values_abs + values_size
    data_abs = vk_abs + vk_size
    free_abs = data_abs + data_size

    to_rel = lambda absolute: absolute - 0x1000

    root_nk = _nk_record(
        "SOFTWARE", 0x2C, 0xFFFFFFFF, 1, to_rel(root_li_abs),
        0, 0xFFFFFFFF, timestamp)
    contoso_nk = _nk_record(
        "Contoso", 0x20, to_rel(root_abs), 1, to_rel(contoso_li_abs),
        0, 0xFFFFFFFF, timestamp)
    agent_nk = _nk_record(
        "Agent", 0x20, to_rel(contoso_abs), 0, 0xFFFFFFFF,
        1, to_rel(values_abs), timestamp)

    root_li = _leaf_subkey_list([to_rel(contoso_abs)])
    contoso_li = _leaf_subkey_list([to_rel(agent_abs)])
    values = _value_list([to_rel(vk_abs)])
    vk = _vk_record(value_name, RegistryParse.RegSZ, len(value_data),
                    to_rel(data_abs))

    hive = bytearray(0x2000)
    hive[0:4] = b"regf"
    _pack_into(hive, "<Q", 0x0C, _filetime(timestamp))
    _pack_into(hive, "<I", 0x14, 1)
    _pack_into(hive, "<I", 0x18, 5)
    _pack_into(hive, "<I", 0x1C, 0)
    _pack_into(hive, "<I", 0x20, 1)
    _pack_into(hive, "<I", 0x24, to_rel(root_abs))
    _pack_into(hive, "<I", 0x28, 0x1000)
    _pack_into(hive, "<I", 0x2C, 1)
    hive[0x30:0x30 + 64] = b"SOFTWARE".decode("ascii").encode("utf-16le").ljust(64, b"\x00")
    _stamp_header(hive, BEFORE_SEQUENCE, timestamp)

    hbin = 0x1000
    hive[hbin:hbin + 4] = b"hbin"
    _pack_into(hive, "<I", hbin + 0x04, 0)
    _pack_into(hive, "<I", hbin + 0x08, 0x1000)
    _pack_into(hive, "<I", hbin + 0x0C, 0x1000)

    def put_cell(absolute, data, forced_size=None):
        size = forced_size or _align(4 + len(data))
        _pack_into(hive, "<i", absolute, -size)
        hive[absolute + 4:absolute + 4 + len(data)] = data

    put_cell(root_abs, root_nk)
    put_cell(contoso_abs, contoso_nk)
    put_cell(agent_abs, agent_nk)
    put_cell(root_li_abs, root_li)
    put_cell(contoso_li_abs, contoso_li)
    put_cell(values_abs, values)
    put_cell(vk_abs, vk, vk_size)
    put_cell(data_abs, value_data)
    _pack_into(hive, "<i", free_abs, 0x2000 - free_abs)

    return bytes(hive)


def _target_offsets(hive_bytes, value_name="Policy"):
    registry = Registry.Registry(io.BytesIO(hive_bytes))
    key = registry.open("Contoso\\Agent")
    value = key.value(value_name)
    vk_cell = value._vkrecord.offset() - 4
    vk_size = abs(struct.unpack_from("<i", hive_bytes, vk_cell)[0])
    data_cell = value._vkrecord.data_offset()
    data_size = abs(struct.unpack_from("<i", hive_bytes, data_cell)[0])
    return {
        "key": key,
        "value": value,
        "nk_record": key._nkrecord.offset(),
        "vk_cell": vk_cell,
        "vk_size": vk_size,
        "data_cell": data_cell,
        "data_size": data_size,
    }


def _make_released(hive_bytes):
    hive = bytearray(hive_bytes)
    offsets = _target_offsets(hive)
    _pack_into(hive, "<i", offsets["vk_cell"], offsets["vk_size"])
    _pack_into(hive, "<i", offsets["data_cell"], offsets["data_size"])
    _pack_into(hive, "<I", offsets["nk_record"] + 0x24, 0)
    _stamp_header(hive, AFTER_SEQUENCE, AFTER_TIME)
    return bytes(hive)


def _make_reallocated(hive_bytes):
    hive = bytearray(hive_bytes)
    offsets = _target_offsets(hive)

    vk = bytearray(36)
    vk[0:2] = b"vk"
    _pack_into(vk, "<H", 0x02, len("Rotation".encode("utf-16le")))
    _pack_into(vk, "<I", 0x04, 4)
    _pack_into(vk, "<I", 0x08, 30)
    _pack_into(vk, "<I", 0x0C, RegistryParse.RegDWord)
    _pack_into(vk, "<I", 0x10, 0)
    vk[0x14:] = "Rotation".encode("utf-16le")
    hive[offsets["vk_cell"] + 4:offsets["vk_cell"] + 40] = vk

    _pack_into(hive, "<i", offsets["data_cell"], offsets["data_size"])
    _stamp_header(hive, AFTER_SEQUENCE, AFTER_TIME)
    return bytes(hive)


def _make_not_collected(hive_bytes):
    hive = bytearray(hive_bytes)
    offsets = _target_offsets(hive)
    name = "Other".encode("utf-16le")
    _pack_into(hive, "<H", offsets["vk_cell"] + 4 + 0x02, len(name))
    hive[offsets["vk_cell"] + 4 + 0x14:offsets["vk_cell"] + 4 + 0x14 + len(name)] = name
    _stamp_header(hive, BEFORE_SEQUENCE, BEFORE_TIME)
    return bytes(hive)


def _make_not_collected_after(hive_bytes):
    hive = bytearray(_make_not_collected(hive_bytes))
    _stamp_header(hive, AFTER_SEQUENCE, AFTER_TIME)
    return bytes(hive)


def _make_wrong_hive(hive_bytes):
    hive = bytearray(hive_bytes)
    hive[0x30:0x30 + 64] = b"SYSTEM".decode("ascii").encode("utf-16le").ljust(64, b"\x00")
    _update_checksum(hive)
    return bytes(hive)


def _marvin32_hash(data):
    def rotl(value, count):
        return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF

    def to_uint32_le(four_bytes):
        b1, b2, b3, b4 = bytearray(four_bytes)
        return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24)

    def mix(state, value):
        lo, hi = state
        lo = (lo + value) & 0xFFFFFFFF
        hi ^= lo
        lo = (rotl(lo, 20) + hi) & 0xFFFFFFFF
        hi = rotl(hi, 9) ^ lo
        lo = (rotl(lo, 27) + hi) & 0xFFFFFFFF
        hi = rotl(hi, 19)
        return lo, hi

    seed = 0x82EF4D887A4E55C5
    state = (seed & 0xFFFFFFFF, (seed >> 32) & 0xFFFFFFFF)
    length = len(data)
    position = 0
    while length >= 4:
        state = mix(state, to_uint32_le(data[position:position + 4]))
        position += 4
        length -= 4

    final = 0x80
    if length == 3:
        final = (final << 8) | data[position + 2]
    elif length == 2:
        final = (final << 8) | data[position + 1]
    elif length == 1:
        final = (final << 8) | data[position]

    state = mix(state, final)
    state = mix(state, 0)
    lo, hi = state
    return (hi << 32) | lo


def _build_log(after_bytes, sequence=AFTER_SEQUENCE):
    dirty_page_size = 0x1000
    entry_size = _align(40 + 8 + dirty_page_size, 0x200)
    log = bytearray(0x200 + entry_size)

    log[0:4] = b"regf"
    _pack_into(log, "<Q", 0x0C, _filetime(AFTER_TIME))
    _pack_into(log, "<I", 0x14, 1)
    _pack_into(log, "<I", 0x18, 5)
    _pack_into(log, "<I", 0x1C, RegistryParse.FileType.FILE_TYPE_LOG_NEW.value)
    _pack_into(log, "<I", 0x20, 1)
    _pack_into(log, "<I", 0x24, 0x20)
    _pack_into(log, "<I", 0x28, 0x1000)
    _pack_into(log, "<I", 0x2C, 1)
    log[0x30:0x30 + 64] = "SOFTWARE".encode("utf-16le").ljust(64, b"\x00")
    _stamp_header(log, sequence, AFTER_TIME)

    entry = 0x200
    log[entry:entry + 4] = b"HvLE"
    _pack_into(log, "<I", entry + 0x04, entry_size)
    _pack_into(log, "<I", entry + 0x08, 0)
    _pack_into(log, "<I", entry + 0x0C, sequence)
    _pack_into(log, "<I", entry + 0x10, 0x1000)
    _pack_into(log, "<I", entry + 0x14, 1)
    _pack_into(log, "<I", entry + 0x28, 0)
    _pack_into(log, "<I", entry + 0x2C, dirty_page_size)
    log[entry + 0x30:entry + 0x30 + dirty_page_size] = after_bytes[0x1000:0x2000]

    # Hash-1 covers the payload (including the page references).  Hash-2 then
    # covers the first 32 header bytes, which include Hash-1 but not Hash-2.
    _pack_into(log, "<Q", entry + 0x18, _marvin32_hash(bytes(log[entry + 40:entry + entry_size])))
    _pack_into(log, "<Q", entry + 0x20, _marvin32_hash(bytes(log[entry:entry + 32])))
    return bytes(log)


def main():
    if not os.path.isdir(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    before = _build_before_hive_bytes()
    released = _make_released(before)
    reallocated = _make_reallocated(before)
    not_collected = _make_not_collected(before)
    not_collected_after = _make_not_collected_after(before)
    wrong_hive = _make_wrong_hive(reallocated)
    log = _build_log(reallocated)

    outputs = {
        "software_before.hive": before,
        "software_after_released.hive": released,
        "software_after_reallocated.hive": reallocated,
        "software_after_reallocated.SOFTWARE.LOG1": log,
        "software_before_not_collected.hive": not_collected,
        "software_after_not_collected.hive": not_collected_after,
        "software_after_wrong_hive.hive": wrong_hive,
    }
    for name, data in outputs.items():
        path = os.path.join(OUTPUT_DIR, name)
        with open(path, "wb") as output:
            output.write(data)
        print("%s  (%d bytes)" % (path, len(data)))


if __name__ == "__main__":
    main()
