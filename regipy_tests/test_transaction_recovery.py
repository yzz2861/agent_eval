import lzma
import os
import struct
from tempfile import mktemp

import pytest

from regipy.exceptions import RegistryRecoveryException
from regipy.recovery import _marvin32
from regipy.registry import RegistryHive
from regipy.structs import HVLE_BLOCK_HEADER_SIZE, TRANSACTION_LOG
from regipy.transaction_recovery import recover_hive_with_transaction_logs

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
PAGE = 4096
NK_FMT = "<HQ4s13i4sHH"


def _extract(name):
    path = mktemp()
    with lzma.open(os.path.join(DATA_DIR, name)) as source, open(path, "wb") as target:
        target.write(source.read())
    return path


def _cell(payload, signature=None):
    body = (signature if signature else b"") + payload
    return struct.pack("<i", -(len(body) + 4)) + body


def _nk(name, parent=0, subkey_list=0, subkey_count=0, values_list=0, values_count=0, ts=132000000000000000):
    name_bytes = name.encode("ascii")
    head = struct.pack(
        NK_FMT,
        0x20,
        ts,
        b"\x00" * 4,
        parent,
        subkey_count,
        0,
        subkey_list,
        0,
        values_count,
        values_list,
        -1,
        -1,
        0,
        0,
        0,
        0,
        b"\x00" * 4,
        len(name_bytes),
        0,
    )
    assert struct.calcsize(NK_FMT) == 74
    return head + name_bytes


def _vk(name, data_offset, value, dtype=1):
    name_bytes = name.encode("ascii")
    data = value.encode("utf-16-le")
    body = struct.pack("<H", len(name_bytes))
    body += struct.pack("<I", len(data))
    body += struct.pack("<I", data_offset)
    body += struct.pack("<I", dtype)
    body += struct.pack("<H", 1)
    body += struct.pack("<H", 0)
    body += name_bytes
    return _cell(body, signature=b"vk")


def _lf(elements):
    body = b"lf" + struct.pack("<H", len(elements))
    for offset in elements:
        body += struct.pack("<II", offset, 0)
    return _cell(body)


def _empty_hive(bins_size):
    bins = bytearray(bins_size)
    for rel in range(0, bins_size, PAGE):
        struct.pack_into("<4sIIIIQII", bins, rel, b"hbin", rel, PAGE, 0, 0, 0, 0, 0)
    header = bytearray(PAGE)
    header[0:4] = b"regf"
    struct.pack_into("<ii", header, 4, 100, 100)
    struct.pack_into("<Q", header, 12, 132000000000000000)
    struct.pack_into("<iiii", header, 20, 1, 3, 0, 1)
    struct.pack_into("<i", header, 36, 32)
    struct.pack_into("<i", header, 40, bins_size)
    file_name = "?\\C:\\test\\NTUSER.DAT".encode("utf-16-le")
    header[48 : 48 + len(file_name)] = file_name
    checksum = 0
    for off in range(0, 508, 4):
        checksum ^= struct.unpack_from("<I", header, off)[0]
    struct.pack_into("<I", header, 508, checksum)
    return bytes(header) + bytes(bins), bins


def _build_hive_pair_and_log(tmp_dir):
    """Build a minimal 12 KiB hive, a copy with one subkey deleted, and an
    HvLE transaction log whose dirty pages restore the pre-deletion image.

    Layout (bins-relative offsets):
      hbin0 (rel 0):      root NK cell at rel 32
      hbin1 (rel 4096):   LF subkey-list cell at rel 4128
      hbin2 (rel 8192):   data cell, child NK (RecoveredKey), VK (Secret),
                          and the child values-list cell
    """
    bins_size = PAGE * 3
    hive, bins = _empty_hive(bins_size)

    data_cell = _cell("hello".encode("utf-16-le"))
    data_cell_rel = PAGE * 2 + 32
    child_cell_rel = data_cell_rel + len(data_cell)

    probe_child = _cell(_nk("RecoveredKey"), signature=b"nk")
    vk_cell_rel = child_cell_rel + len(probe_child)
    vlist_cell_rel = vk_cell_rel + len(_vk("Secret", data_cell_rel, "hello"))

    child_nk_cell = _cell(
        _nk("RecoveredKey", parent=36, values_count=1, values_list=vlist_cell_rel),
        signature=b"nk",
    )
    vk_cell = _vk("Secret", data_cell_rel, "hello")
    vlist_cell = _cell(struct.pack("<I", vk_cell_rel))
    lf_cell_rel = PAGE + 32
    lf_cell = _lf([child_cell_rel])
    root_cell_rel = 32
    root_cell = _cell(_nk("CMI", subkey_count=1, subkey_list=lf_cell_rel), signature=b"nk")

    for rel, content in (
        (root_cell_rel, root_cell),
        (lf_cell_rel, lf_cell),
        (data_cell_rel, data_cell),
        (child_cell_rel, child_nk_cell),
        (vk_cell_rel, vk_cell),
        (vlist_cell_rel, vlist_cell),
    ):
        bins[rel : rel + len(content)] = content
    primary_image = bytes(bytearray(hive[:PAGE]) + bins)

    # Deleted primary: root loses its subkey reference and the child cell is
    # marked unallocated (positive cell size), exactly as a live deletion leaves
    # the NK bytes in slack space.
    deleted = bytearray(primary_image)
    root_body = PAGE + root_cell_rel + 4
    struct.pack_into("<i", deleted, root_body + 18, 0)
    struct.pack_into("<i", deleted, root_body + 26, 0)
    needle = b"RecoveredKey"
    search = 0
    while True:
        sig_at = deleted.find(b"nk", search)
        name_at = sig_at + 2 + 74
        if deleted[name_at : name_at + len(needle)] == needle:
            break
        search = sig_at + 1
    size_field = sig_at - 4
    current_size = struct.unpack_from("<i", deleted, size_field)[0]
    struct.pack_into("<i", deleted, size_field, -current_size)
    deleted_image = bytes(deleted)

    # An HvLE entry restoring every page the deletion touched (root NK, the LF
    # subkey list, and the child NK/VK region), with valid Marvin32 hashes.
    dirty_pages = [1, 2, 3]
    references = [{"offset": page * PAGE - PAGE, "size": PAGE} for page in dirty_pages]
    page_data = b"".join(primary_image[page * PAGE : (page + 1) * PAGE] for page in dirty_pages)
    log_size = HVLE_BLOCK_HEADER_SIZE + 8 * len(references) + len(page_data)
    body = (
        TRANSACTION_LOG.build(
            {
                "signature": b"HvLE",
                "log_size": log_size,
                "flags": 0,
                "sequence_number": 100,
                "hive_bin_size": bins_size,
                "dirty_pages_count": len(references),
                "hash_1": 0,
                "hash_2": 0,
                "dirty_pages_references": references,
            }
        )
        + page_data
    )
    hash_1 = _marvin32(body[HVLE_BLOCK_HEADER_SIZE:])
    hash_2 = _marvin32(body[:24] + struct.pack("<Q", hash_1))
    body = body[:24] + struct.pack("<QQ", hash_1, hash_2) + body[40:]
    log_image = b"\x00" * 512 + body

    primary_path = os.path.join(tmp_dir, "primary.dat")
    deleted_path = os.path.join(tmp_dir, "deleted.dat")
    log_path = os.path.join(tmp_dir, "deleted.dat.LOG1")
    with open(primary_path, "wb") as handle:
        handle.write(primary_image)
    with open(deleted_path, "wb") as handle:
        handle.write(deleted_image)
    with open(log_path, "wb") as handle:
        handle.write(log_image)
    return primary_path, deleted_path, log_path


def test_registry_hive_from_bytes_roundtrip(transaction_ntuser):
    with open(transaction_ntuser, "rb") as handle:
        image = handle.read()
    in_memory = RegistryHive.from_bytes(image)
    on_disk = RegistryHive(transaction_ntuser)
    assert in_memory.header.primary_sequence_num == on_disk.header.primary_sequence_num
    assert in_memory.name == on_disk.name
    in_memory_paths = [entry.path for entry in in_memory.recurse_subkeys(fetch_values=False)]
    on_disk_paths = [entry.path for entry in on_disk.recurse_subkeys(fetch_values=False)]
    assert in_memory_paths == on_disk_paths


def test_recovery_restores_key_deleted_from_primary(tmp_path):
    primary_path, deleted_path, log_path = _build_hive_pair_and_log(str(tmp_path))

    deleted_paths = [entry.path for entry in RegistryHive(deleted_path).recurse_subkeys(fetch_values=False)]
    assert deleted_paths == [chr(92)]
    primary_bytes = open(deleted_path, "rb").read()

    result = recover_hive_with_transaction_logs(deleted_path, log_path)

    assert open(deleted_path, "rb").read() == primary_bytes

    recovered_key = result.registry_hive.get_key(chr(92) + "RecoveredKey")
    recovered_values = [(value.name, value.value) for value in recovered_key.iter_values()]
    assert recovered_values == [("Secret", "hello")]

    by_path = {(record.record_type, record.path, record.value_name): record for record in result.recovered_records}
    recovered_nk = by_path[("NK", chr(92) + "RecoveredKey", None)]
    recovered_vk = by_path[("VK", chr(92) + "RecoveredKey", "Secret")]

    assert recovered_nk.deleted_from_primary is True
    assert recovered_vk.deleted_from_primary is True
    assert recovered_nk.source == "transaction_log"
    assert recovered_vk.source == "transaction_log"
    assert recovered_nk.confidence == "medium"
    assert recovered_vk.confidence == "high"
    assert recovered_nk.sequence_number == 100
    assert recovered_vk.sequence_number == 100
    assert result.diagnostics.recovered_dirty_pages == 3
    assert result.diagnostics.recovered_deleted_records >= 2

    assert RegistryHive(primary_path).get_key(chr(92) + "RecoveredKey").name == "RecoveredKey"


def test_recovery_real_fixture_annotates_log_backed_records(transaction_ntuser, transaction_log):
    result = recover_hive_with_transaction_logs(transaction_ntuser, transaction_log)
    assert result.diagnostics.recovered_dirty_pages == 132

    primary_paths = {entry.path for entry in RegistryHive(transaction_ntuser).recurse_subkeys(fetch_values=False)}
    merged_paths = {entry.path for entry in result.registry_hive.recurse_subkeys(fetch_values=False)}
    recovered_only = merged_paths - primary_paths
    assert recovered_only

    deleted_nk = [record for record in result.recovered_records if record.record_type == "NK" and record.deleted_from_primary]
    assert deleted_nk
    assert all(record.source == "transaction_log" for record in deleted_nk)
    assert {record.path for record in deleted_nk} == recovered_only
    assert all(record.source in ("primary_hive", "transaction_log") for record in result.recovered_records)
    assert all(record.confidence in ("high", "medium", "low") for record in result.recovered_records)


def test_recovery_rejects_unknown_log_magic_without_touching_primary(transaction_ntuser, tmp_path):
    bad_log = tmp_path / "bad.log1"
    bad_log.write_bytes(b"\x00" * 512 + b"XXXX" + b"\x00" * 128)
    primary_before = open(transaction_ntuser, "rb").read()

    with pytest.raises(RegistryRecoveryException, match="magic"):
        recover_hive_with_transaction_logs(transaction_ntuser, str(bad_log))

    assert open(transaction_ntuser, "rb").read() == primary_before
    RegistryHive(transaction_ntuser)


def test_recovery_hash_corrupt_log_applies_no_pages_but_still_returns(transaction_ntuser, transaction_log):
    corrupt = bytearray(open(transaction_log, "rb").read())
    (dirty_pages_count,) = struct.unpack_from("<I", corrupt, 512 + 20)
    data_start = 512 + HVLE_BLOCK_HEADER_SIZE + 8 * dirty_pages_count
    corrupt[data_start] ^= 0xFF
    corrupt_path = mktemp()
    with open(corrupt_path, "wb") as handle:
        handle.write(bytes(corrupt))

    result = recover_hive_with_transaction_logs(transaction_ntuser, corrupt_path)
    assert result.diagnostics.recovered_dirty_pages == 0
    assert result.merged_hive_bytes == open(transaction_ntuser, "rb").read()
    # The hash failure is surfaced as a diagnostic, not just a log line.
    assert any("failed hash verification" in warning for warning in result.diagnostics.warnings)


def test_recovery_requires_at_least_one_log(transaction_ntuser):
    with pytest.raises(RegistryRecoveryException, match="At least one transaction log"):
        recover_hive_with_transaction_logs(transaction_ntuser, None)
