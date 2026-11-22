#!/usr/bin/env python
"""Read-only deletion evidence queries for Windows Registry hives.

The analyzer answers a narrow question: given two snapshots of the same hive,
did a value exist in the earlier snapshot, and what happened to the physical
cell that held its VK record in the later snapshot?

It deliberately distinguishes:

* RELEASED: the old VK cell is free (or coalesced into a free cell) later.
* REALLOCATED: the old VK cell start is occupied by another allocated structure.
* NOT_COLLECTED: the value is absent from both snapshots, so no baseline exists.
* UNDETERMINED: the supplied materials disagree, or the physical slot cannot be
  compared safely.

No input file is ever opened for writing.  Transaction logs are parsed for
sequence numbers, dirty-page coverage, and the physical state visible in each
batch; they are never applied to the source hive.
"""

from __future__ import absolute_import, print_function, unicode_literals

import argparse
import bisect
import hashlib
import io
import json
import os
import struct
import sys

from . import Registry as RegistryModule
from . import RegistryParse


SCHEMA = "registry-deletion-evidence/v1"
FIRST_HBIN_OFFSET = 0x1000

VERDICT_LABELS = {
    "RELEASED": {"en": "released", "zh": "后续映像中已释放"},
    "REALLOCATED": {"en": "slot reallocated", "zh": "原槽位已再分配"},
    "NOT_COLLECTED": {"en": "not collected", "zh": "未采集到"},
    "PRESENT": {"en": "present", "zh": "仍存在"},
    "PRESENT_MODIFIED": {"en": "present but modified", "zh": "仍存在但内容已变化"},
    "UNDETERMINED": {"en": "undetermined", "zh": "无法判定"},
}


def _hex(value):
    if value is None:
        return None
    return "0x%x" % value


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _iso_utc(value):
    if value is None:
        return None
    return value.isoformat() + "Z"


def _safe_text(value, limit=160):
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.hex()
    else:
        text = str(value)
    if len(text) > limit:
        text = text[:limit] + "..."
    return text


def _read_source(source):
    if hasattr(source, "read"):
        data = source.read()
        if isinstance(data, str):
            data = data.encode("latin1")
        return data
    with open(source, "rb") as handle:
        return handle.read()


def _source_name(source):
    if hasattr(source, "read"):
        return getattr(source, "name", "<file-like>")
    return os.fspath(source)


def _cell_public(descriptor):
    if descriptor is None:
        return None
    return {
        "cell_offset_relative_to_first_hbin": descriptor["cell_rva"],
        "cell_offset_relative_to_first_hbin_hex": _hex(descriptor["cell_rva"]),
        "cell_offset_absolute": descriptor["cell_abs"],
        "cell_offset_absolute_hex": _hex(descriptor["cell_abs"]),
        "cell_size": descriptor["cell_size"],
        "state": "free" if descriptor["free"] else "allocated",
        "signature": descriptor["signature"],
        "residual_signature": descriptor["residual_signature"],
        "cell_sha256": descriptor["cell_sha256"],
        "record_sha256": descriptor["record_sha256"],
    }


class HiveSnapshot(object):
    """A parsed hive plus a map of every cell in every HBIN."""

    def __init__(self, source):
        self.source = _source_name(source)
        self.data = _read_source(source)
        self.size = len(self.data)
        self.sha256 = _sha256(self.data)
        self.registry = None
        self.regf = None
        self.cells = []
        self.cell_by_offset = {}
        self.cell_starts = []
        self.warnings = []
        self.parse_error = None

        try:
            self.registry = RegistryModule.Registry(io.BytesIO(self.data))
            self.regf = self.registry._regf
            self.hive_name = self.regf.hive_name()
            self.root_path = self.registry.root().path()
            self.file_type = self.regf.file_type().name
            self.major_version = self.regf.major_version()
            self.minor_version = self.regf.minor_version()
            self.cluster_factor = self.regf.clustering_factor()
            self.sequence1 = self.regf.hive_sequence1()
            self.sequence2 = self.regf.hive_sequence2()
            self.hbins_size = self.regf.hbins_size()
            self.last_write = self.regf.modification_timestamp()
            self.checksum_valid = self.regf.validate_checksum()
            self.sequence_consistent = self.regf.validate_sequence_numbers()
            self.recovery_required = self.regf.recovery_required()
            self._index_cells()
        except Exception as exc:
            self.parse_error = "%s: %s" % (type(exc).__name__, exc)
            self.hive_name = None
            self.root_path = None
            self.file_type = None
            self.major_version = None
            self.minor_version = None
            self.cluster_factor = None
            self.sequence1 = None
            self.sequence2 = None
            self.hbins_size = None
            self.last_write = None
            self.checksum_valid = False
            self.sequence_consistent = False
            self.recovery_required = None

    def _index_cells(self):
        end_of_hbins = FIRST_HBIN_OFFSET + self.hbins_size
        try:
            hbins = list(self.regf.hbins())
        except Exception as exc:
            self.warnings.append("HBIN enumeration failed: %s" % exc)
            return

        for hbin in hbins:
            try:
                hbin_size = hbin.unpack_dword(0x0C)
            except Exception as exc:
                self.warnings.append(
                    "HBIN at 0x%x has no readable size: %s" % (hbin.offset(), exc))
                continue
            cursor = hbin.offset() + 0x20
            hbin_end = hbin.offset() + hbin_size
            if hbin_end > len(self.data):
                hbin_end = len(self.data)
            while cursor + 4 <= hbin_end:
                signed_size = struct.unpack_from("<i", self.data, cursor)[0]
                if signed_size == 0:
                    self.warnings.append(
                        "Zero-sized cell at 0x%x; cell walk stopped" % cursor)
                    break
                cell_size = abs(signed_size)
                if cell_size < 8 or cursor + cell_size > hbin_end:
                    self.warnings.append(
                        "Invalid cell size 0x%x at 0x%x; cell walk stopped"
                        % (cell_size, cursor))
                    break
                descriptor = self._make_cell_descriptor(cursor, signed_size)
                self.cells.append(descriptor)
                self.cell_by_offset[cursor] = descriptor
                cursor += cell_size
                if cursor == hbin_end:
                    break

        self.cells.sort(key=lambda item: item["cell_abs"])
        self.cell_starts = [item["cell_abs"] for item in self.cells]
        if self.cells:
            last = self.cells[-1]
            if last["cell_abs"] + last["cell_size"] > end_of_hbins:
                self.warnings.append(
                    "Last cell extends beyond REGF hbins_size (0x%x)"
                    % end_of_hbins)

    def _make_cell_descriptor(self, absolute, signed_size):
        cell_size = abs(signed_size)
        free = signed_size > 0
        raw = self.data[absolute:absolute + cell_size]
        signature = None
        residual_signature = None
        if len(raw) >= 6:
            candidate = raw[4:6].decode("latin1")
            if candidate in ("nk", "vk", "sk", "lf", "lh", "li", "ri", "db"):
                residual_signature = candidate
        if not free:
            signature = residual_signature
        record = raw[4:] if len(raw) > 4 else b""
        return {
            "cell_abs": absolute,
            "cell_rva": absolute - FIRST_HBIN_OFFSET,
            "cell_size": cell_size,
            "free": free,
            "signature": signature,
            "residual_signature": residual_signature,
            "cell_sha256": _sha256(raw),
            "record_sha256": _sha256(record),
        }

    def metadata(self):
        recovery = self.recovery_required
        return {
            "source": self.source,
            "sha256": self.sha256,
            "size": self.size,
            "parse_error": self.parse_error,
            "hive_name": self.hive_name,
            "hive_type": (
                self.registry.hive_type().name if self.registry is not None else None
            ),
            "root_key_path": self.root_path,
            "file_type": self.file_type,
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "cluster_factor": self.cluster_factor,
            "sequence1": self.sequence1,
            "sequence2": self.sequence2,
            "sequence_consistent": self.sequence_consistent,
            "last_write_utc": _iso_utc(self.last_write),
            "hbins_size": self.hbins_size,
            "hbins_size_hex": _hex(self.hbins_size),
            "hbins_end_absolute": (
                FIRST_HBIN_OFFSET + self.hbins_size
                if self.hbins_size is not None else None
            ),
            "checksum_valid": self.checksum_valid,
            "recovery_required": {
                "header": bool(recovery.recover_header) if recovery else None,
                "data": bool(recovery.recover_data) if recovery else None,
            },
            "cells_total": len(self.cells),
            "cells_allocated": sum(1 for cell in self.cells if not cell["free"]),
            "cells_free": sum(1 for cell in self.cells if cell["free"]),
            "batch": {
                "kind": "collected_snapshot",
                "sequence1": self.sequence1,
                "sequence2": self.sequence2,
                "sha256": self.sha256,
            },
            "warnings": list(self.warnings),
        }

    def _candidate_paths(self, key_path):
        raw = str(key_path or "").replace("/", "\\").strip()
        raw = raw.strip("\\")
        parts = [part for part in raw.split("\\") if part]
        prefixes = {
            "hkey_local_machine", "hklm", "hkey_current_user", "hkcu",
            "hkey_users", "hku", "hkey_classes_root", "hkcr",
        }
        while parts and parts[0].lower() in prefixes:
            parts = parts[1:]

        candidates = []
        if not parts:
            candidates.append("")
        else:
            candidates.append("\\".join(parts))
            root_names = {
                value.lower() for value in
                (self.root_path, self.hive_name) if value
            }
            if parts[0].lower() in root_names:
                candidates.append("\\".join(parts[1:]))

        seen = set()
        unique = []
        for candidate in candidates:
            if candidate.lower() not in seen:
                seen.add(candidate.lower())
                unique.append(candidate)
        return unique

    def _first_hbin(self):
        return RegistryParse.HBINBlock(self.data, FIRST_HBIN_OFFSET, self.regf)

    def read_vk_info(self, cell_abs):
        info = {
            "name": None,
            "value_type": None,
            "value_type_str": None,
            "data_length": None,
            "data_storage": None,
            "data_cell_offset": None,
            "data_preview": None,
            "error": None,
        }
        try:
            hbin = self._first_hbin()
            cell = RegistryParse.HBINCell(self.data, cell_abs, hbin)
            vk = RegistryParse.VKRecord(self.data, cell.data_offset(), cell)
            info["name"] = vk.name() if vk.has_name() else "(default)"
            info["value_type"] = vk.data_type()
            info["value_type_str"] = vk.data_type_str()
            info["data_length"] = vk.raw_data_length()
            raw_length = vk.raw_data_length()
            if raw_length < 5 or raw_length >= 0x80000000:
                info["data_storage"] = "inline_in_vk"
                info["data_cell_offset"] = None
            else:
                info["data_storage"] = "external_cell"
                info["data_cell_offset"] = vk.data_offset()
            try:
                info["data_preview"] = _safe_text(vk.data())
            except Exception:
                info["data_preview"] = None
        except Exception as exc:
            info["error"] = "%s: %s" % (type(exc).__name__, exc)
        return info

    def locate_value(self, key_path, value_name):
        result = {
            "key_present": False,
            "value_present": False,
            "resolved_key_path": None,
            "full_value_path": None,
            "value": None,
            "error": None,
        }
        key = None
        errors = []
        for candidate in self._candidate_paths(key_path):
            try:
                key = self.registry.open(candidate)
                break
            except Exception as exc:
                errors.append("%s -> %s" % (candidate, exc))

        if key is None:
            result["error"] = "key not found; " + "; ".join(errors[:3])
            return result

        result["key_present"] = True
        result["resolved_key_path"] = key.path()
        normalized_name = value_name or "(default)"
        if normalized_name == "@":
            normalized_name = "(default)"
        try:
            value = key.value(normalized_name)
        except Exception as exc:
            result["error"] = "value not found: %s" % exc
            return result

        result["value_present"] = True
        result["full_value_path"] = "%s!%s" % (key.path(), value.name())

        nk = key._nkrecord
        vk = value._vkrecord
        vk_cell_abs = vk.offset() - 4
        vk_cell = self.cell_by_offset.get(vk_cell_abs)

        values_list_cell = None
        values_list_index = None
        if nk.values_number() > 0:
            values_list_rva = nk.unpack_dword(0x28)
            values_list_abs = FIRST_HBIN_OFFSET + values_list_rva
            values_list_cell = self.cell_by_offset.get(values_list_abs)
            for index in range(nk.values_number()):
                pointer_offset = values_list_abs + 4 + index * 4
                if pointer_offset + 4 > len(self.data):
                    break
                pointer = struct.unpack_from("<I", self.data, pointer_offset)[0]
                if FIRST_HBIN_OFFSET + pointer == vk_cell_abs:
                    values_list_index = index
                    break

        raw_length = vk.raw_data_length()
        data_cell_abs = None
        data_storage = None
        if raw_length < 5 or raw_length >= 0x80000000:
            data_storage = "inline_in_vk"
        else:
            data_storage = "external_cell"
            data_cell_abs = vk.data_offset()
            if raw_length > 0x3FD8:
                data_storage = "external_db_cell"
        data_cell = (
            self.cell_by_offset.get(data_cell_abs)
            if data_cell_abs is not None else None
        )

        try:
            raw_data = value.raw_data()
            data_sha256 = _sha256(raw_data)
        except Exception:
            data_sha256 = None
        try:
            value_preview = _safe_text(value.value())
        except Exception:
            value_preview = None

        vk_public = _cell_public(vk_cell)
        data_public = _cell_public(data_cell)
        if data_storage.startswith("inline"):
            data_identity = {
                "storage": data_storage,
                "absolute_offset": vk.offset() + 0x8,
                "absolute_offset_hex": _hex(vk.offset() + 0x8),
            }
        else:
            data_identity = {
                "storage": data_storage,
                "cell_offset_absolute": data_cell_abs,
                "cell_offset_absolute_hex": _hex(data_cell_abs),
                "cell_offset_relative_to_first_hbin": (
                    data_cell_abs - FIRST_HBIN_OFFSET
                    if data_cell_abs is not None else None
                ),
                "cell": data_public,
            }

        result["value"] = {
            "name": value.name(),
            "value_type": value.value_type(),
            "value_type_str": value.value_type_str(),
            "data_length": raw_length,
            "data_sha256": data_sha256,
            "value_preview": value_preview,
            "data_storage": data_storage,
            "data_identity": data_identity,
            "key_nk_cell": _cell_public(self.cell_by_offset.get(nk.offset() - 4)),
            "values_list_cell": _cell_public(values_list_cell),
            "values_list_index": values_list_index,
            "vk_cell": vk_public,
            "physical_identity": {
                "comparison_basis": (
                    "cell offsets relative to the first HBIN (0x1000); "
                    "comparable only while the HBIN layout is unchanged"
                ),
                "hive_name": self.hive_name,
                "full_value_path": result["full_value_path"],
                "key_nk_cell_rva": (
                    nk.offset() - 4 - FIRST_HBIN_OFFSET
                ),
                "values_list_index": values_list_index,
                "vk_cell_rva": vk_cell_abs - FIRST_HBIN_OFFSET,
                "vk_cell_size": vk_cell["cell_size"] if vk_cell else None,
                "data_storage": data_storage,
                "data_cell_rva": (
                    data_cell_abs - FIRST_HBIN_OFFSET
                    if data_cell_abs is not None else None
                ),
            },
        }
        return result

    def _containing_cell(self, absolute):
        index = bisect.bisect_right(self.cell_starts, absolute) - 1
        if index < 0:
            return None
        cell = self.cells[index]
        if cell["cell_abs"] <= absolute < cell["cell_abs"] + cell["cell_size"]:
            return cell
        return None

    def inspect_slot(self, cell_abs, before_cell=None):
        result = {
            "cell_offset_absolute": cell_abs,
            "cell_offset_absolute_hex": _hex(cell_abs),
            "cell_offset_relative_to_first_hbin": (
                cell_abs - FIRST_HBIN_OFFSET if cell_abs is not None else None
            ),
            "cell_offset_relative_to_first_hbin_hex": (
                _hex(cell_abs - FIRST_HBIN_OFFSET)
                if cell_abs is not None else None
            ),
            "relation": None,
            "state": None,
            "cell": None,
            "covers_entire_before_cell": False,
            "same_bytes_as_before": False,
            "same_payload_as_before": False,
            "allocated_vk": None,
            "residual_vk": None,
        }
        if cell_abs is None:
            result["state"] = "no_external_cell"
            return result
        if self.hbins_size is None:
            result["state"] = "snapshot_unparseable"
            return result
        if cell_abs < FIRST_HBIN_OFFSET:
            result["state"] = "before_first_hbin"
            return result
        if cell_abs >= FIRST_HBIN_OFFSET + self.hbins_size:
            result["state"] = "beyond_captured_hbins"
            return result

        exact = self.cell_by_offset.get(cell_abs)
        containing = exact or self._containing_cell(cell_abs)
        if exact is not None:
            result["relation"] = "exact"
        elif containing is not None:
            result["relation"] = (
                "inside_free_cell" if containing["free"]
                else "inside_allocated_cell"
            )
        else:
            result["relation"] = "unmapped_gap"
            result["state"] = "unmapped_gap"
            return result

        result["state"] = "free" if containing["free"] else "allocated"
        result["cell"] = _cell_public(containing)

        if before_cell is not None:
            before_abs = before_cell["cell_abs"]
            before_size = before_cell["cell_size"]
            result["covers_entire_before_cell"] = (
                containing["cell_abs"] <= before_abs
                and containing["cell_abs"] + containing["cell_size"]
                >= before_abs + before_size
            )
            before_bytes = before_cell.get("raw_bytes")
            after_bytes = self.data[
                before_abs:before_abs + min(before_size, len(before_cell["raw_bytes"]))
            ]
            result["same_bytes_as_before"] = (
                before_bytes is not None and after_bytes == before_bytes
            )
            if before_bytes is not None and len(before_bytes) >= 4:
                after_payload = self.data[
                    before_abs + 4:
                    before_abs + min(before_size, len(before_bytes))
                ]
                result["same_payload_as_before"] = (
                    after_payload == before_bytes[4:]
                )

        if containing["free"]:
            result["residual_vk"] = self.read_vk_info(cell_abs)
        elif containing["signature"] == "vk" and containing["cell_abs"] == cell_abs:
            result["allocated_vk"] = self.read_vk_info(containing["cell_abs"])
        return result


class TransactionLog(object):
    """Parsed HvLE batches with dirty-page-to-slot correlations."""

    def __init__(self, source, target_vk_cell=None, target_data_cell=None,
                 after_snapshot=None):
        self.source = _source_name(source)
        self.data = _read_source(source)
        self.sha256 = _sha256(self.data)
        self.size = len(self.data)
        self.parse_error = None
        self.header = {}
        self.entries = []
        self.trailing_bytes = 0
        self.valid = False
        self.old_format = False
        try:
            regf = RegistryParse.REGFBlock(self.data, 0, False)
            self.header = {
                "hive_name": regf.hive_name(),
                "file_type": regf.file_type().name,
                "sequence1": regf.hive_sequence1(),
                "sequence2": regf.hive_sequence2(),
                "hbins_size": regf.hbins_size(),
                "checksum_valid": regf.validate_checksum(),
            }
            self.hive_name = regf.hive_name()
            self.file_type = regf.file_type()
            self.old_format = regf.is_old_transaction_log_file()
            self.valid = regf.is_new_transaction_log_file() and regf.validate_checksum()
            if regf.is_new_transaction_log_file():
                self._parse_entries(
                    regf, target_vk_cell, target_data_cell, after_snapshot)
        except Exception as exc:
            self.parse_error = "%s: %s" % (type(exc).__name__, exc)
            self.valid = False
            self.hive_name = None
            self.file_type = None

    def _parse_entries(self, regf, target_vk_cell, target_data_cell,
                       after_snapshot):
        offset = 0x200
        while offset + 40 <= len(self.data):
            if self.data[offset:offset + 4] != b"HvLE":
                self.trailing_bytes = len(self.data) - offset
                break
            try:
                entry = RegistryParse.HvLEBlock(self.data, offset, regf)
                size = entry.size()
            except Exception as exc:
                self.parse_error = "HvLE at 0x%x: %s" % (offset, exc)
                self.valid = False
                break
            if size < 40 or offset + size > len(self.data):
                self.parse_error = "HvLE at 0x%x has invalid size 0x%x" % (
                    offset, size)
                self.valid = False
                break
            entry_valid = entry.validate_log_entry()
            if not entry_valid:
                self.valid = False
            references = []
            page_offset = offset + 40 + 8 * entry.dirty_pages_count()
            for reference in entry.dirty_pages_references():
                reference_offset = reference.offset()
                reference_size = reference.size()
                reference_abs = FIRST_HBIN_OFFSET + reference_offset
                reference = {
                    "offset_relative_to_first_hbin": reference_offset,
                    "offset_relative_to_first_hbin_hex": _hex(reference_offset),
                    "absolute_offset": reference_abs,
                    "absolute_offset_hex": _hex(reference_abs),
                    "size": reference_size,
                    "page_data_offset": page_offset,
                }
                page = self.data[page_offset:page_offset + reference_size]
                reference["page_sha256"] = _sha256(page)
                reference["vk_slot"] = self._inspect_page_slot(
                    page, reference_offset, target_vk_cell, after_snapshot)
                reference["data_slot"] = self._inspect_page_slot(
                    page, reference_offset, target_data_cell, after_snapshot)
                references.append(reference)
                page_offset += reference_size

            self.entries.append({
                "offset": offset,
                "offset_hex": _hex(offset),
                "size": size,
                "sequence": entry.sequence(),
                "hive_flags": entry.hive_flags(),
                "hbins_size": entry.hbins_size(),
                "dirty_pages_count": entry.dirty_pages_count(),
                "valid": entry_valid,
                "dirty_pages": references,
            })
            offset += size

    def _inspect_page_slot(self, page, page_rva, target_cell, after_snapshot):
        result = {
            "covered": False,
            "state": None,
            "signature": None,
            "cell_size": None,
            "value_name": None,
            "value_preview": None,
            "matches_after_cell": False,
            "cell_sha256": None,
        }
        if target_cell is None:
            return result
        target_rva = target_cell["cell_abs"] - FIRST_HBIN_OFFSET
        target_size = target_cell["cell_size"]
        if not (page_rva <= target_rva
                and target_rva + target_size <= page_rva + len(page)):
            return result
        local = target_rva - page_rva
        signed_size = struct.unpack_from("<i", page, local)[0]
        cell_size = abs(signed_size)
        if local + cell_size > len(page):
            return result
        raw = page[local:local + cell_size]
        result.update({
            "covered": True,
            "state": "free" if signed_size > 0 else "allocated",
            "signature": raw[4:6].decode("latin1") if len(raw) >= 6 else None,
            "cell_size": cell_size,
            "cell_sha256": _sha256(raw),
        })
        if signed_size < 0 and result["signature"] == "vk":
            try:
                cell = RegistryParse.HBINCell(
                    page, local,
                    RegistryParse.HBINBlock(
                        page, 0, None))
                vk = RegistryParse.VKRecord(page, cell.data_offset(), cell)
                result["value_name"] = (
                    vk.name() if vk.has_name() else "(default)")
                try:
                    result["value_preview"] = _safe_text(vk.data())
                except Exception:
                    pass
            except Exception:
                pass
        if after_snapshot is not None:
            after_cell = after_snapshot.cell_by_offset.get(
                target_cell["cell_abs"])
            if after_cell is not None:
                after_raw = after_snapshot.data[
                    after_cell["cell_abs"]:
                    after_cell["cell_abs"] + after_cell["cell_size"]
                ]
                result["matches_after_cell"] = raw == after_raw
        return result

    def metadata(self):
        return {
            "source": self.source,
            "sha256": self.sha256,
            "size": self.size,
            "parse_error": self.parse_error,
            "valid": self.valid,
            "old_format": self.old_format,
            "header": self.header,
            "entries": self.entries,
            "trailing_bytes": self.trailing_bytes,
        }


def _material_check(before, after, before_target, after_target):
    reasons = []
    if before.parse_error:
        reasons.append("BEFORE_PARSE_ERROR: %s" % before.parse_error)
    if after.parse_error:
        reasons.append("AFTER_PARSE_ERROR: %s" % after.parse_error)
    if before.file_type != "FILE_TYPE_PRIMARY":
        reasons.append("BEFORE_NOT_PRIMARY_HIVE: %s" % before.file_type)
    if after.file_type != "FILE_TYPE_PRIMARY":
        reasons.append("AFTER_NOT_PRIMARY_HIVE: %s" % after.file_type)
    if before.hive_name and after.hive_name:
        if before.hive_name.lower() != after.hive_name.lower():
            reasons.append(
                "HIVE_NAME_MISMATCH: %s vs %s"
                % (before.hive_name, after.hive_name))
    if (before.major_version is not None and after.major_version is not None
            and (before.major_version, before.minor_version)
            != (after.major_version, after.minor_version)):
        reasons.append(
            "HIVE_FORMAT_VERSION_MISMATCH: %s.%s vs %s.%s"
            % (before.major_version, before.minor_version,
               after.major_version, after.minor_version))
    if (before.cluster_factor is not None and after.cluster_factor is not None
            and before.cluster_factor != after.cluster_factor):
        reasons.append(
            "CLUSTER_FACTOR_MISMATCH: %s vs %s"
            % (before.cluster_factor, after.cluster_factor))

    if before.sha256 == after.sha256:
        same_image = True
    else:
        same_image = False
        if before.last_write and after.last_write:
            if after.last_write < before.last_write:
                reasons.append(
                    "TIMESTAMP_ORDER_CONFLICT: after %s < before %s"
                    % (_iso_utc(after.last_write), _iso_utc(before.last_write)))
        if before.sequence2 is not None and after.sequence2 is not None:
            if before.sequence2 == after.sequence2:
                reasons.append(
                    "SEQUENCE_CONFLICT: different images share sequence2=%s"
                    % before.sequence2)
            else:
                delta = (after.sequence2 - before.sequence2) & 0xFFFFFFFF
                if delta >= 0x80000000:
                    reasons.append(
                        "SEQUENCE_ORDER_CONFLICT: before=%s after=%s"
                        % (before.sequence2, after.sequence2))

    if (before_target.get("value_present") and after_target.get("value_present")
            and before_target.get("resolved_key_path")
            and after_target.get("resolved_key_path")
            and before_target["resolved_key_path"].lower()
            != after_target["resolved_key_path"].lower()):
        reasons.append(
            "RESOLVED_PATH_MISMATCH: %s vs %s"
            % (before_target["resolved_key_path"],
               after_target["resolved_key_path"]))

    return {
        "status": "MATCH" if not reasons else "MISMATCH",
        "same_image": same_image,
        "reasons": reasons,
    }


def _transaction_batches(before, after, logs, old_vk_cell, old_data_cell):
    offline = [log.metadata() for log in logs]
    alignment_reasons = []
    alignment_warnings = []
    if not logs:
        alignment = "NOT_PROVIDED"
    else:
        alignment = "ALIGNED"
        for log in logs:
            if log.parse_error:
                alignment_reasons.append(
                    "%s: %s" % (log.source, log.parse_error))
            if log.old_format:
                alignment_reasons.append(
                    "%s: old transaction log format is unsupported" % log.source)
            if not log.valid:
                alignment_reasons.append(
                    "%s: log header or HvLE validation failed" % log.source)
            if (log.hive_name and before.hive_name
                    and log.hive_name.lower() != before.hive_name.lower()):
                alignment_reasons.append(
                    "%s: hive name %s does not match %s"
                    % (log.source, log.hive_name, before.hive_name))
            if before.sequence2 is not None and after.sequence2 is not None:
                low = before.sequence2
                high = after.sequence2
                for entry in log.entries:
                    sequence = entry["sequence"]
                    if sequence > high:
                        alignment_reasons.append(
                            "%s: sequence %s outside snapshot window; later than after (%s)"
                            % (log.source, sequence, high))
                    elif sequence < low:
                        alignment_warnings.append(
                            "%s: sequence %s predates the before snapshot (%s); "
                            "stale but not contradictory"
                            % (log.source, sequence, low))
            sequences = [entry["sequence"] for entry in log.entries]
            for previous, current in zip(sequences, sequences[1:]):
                if current != previous + 1:
                    alignment_warnings.append(
                        "%s: HvLE sequence gap %s -> %s"
                        % (log.source, previous, current))
            if not log.entries:
                alignment_reasons.append(
                    "%s: no HvLE batches parsed" % log.source)
        if alignment_reasons:
            alignment = "MISMATCH"

    covered_vk = False
    covered_data = False
    matching_after_vk = False
    matching_after_data = False
    slot_history = []
    for log in logs:
        for entry in log.entries:
            for page in entry["dirty_pages"]:
                vk_slot = page["vk_slot"]
                data_slot = page["data_slot"]
                if vk_slot["covered"]:
                    covered_vk = True
                    matching_after_vk = (
                        matching_after_vk or vk_slot["matches_after_cell"])
                if data_slot["covered"]:
                    covered_data = True
                    matching_after_data = (
                        matching_after_data or data_slot["matches_after_cell"])
            slot_history.append({
                "log": log.source,
                "sequence": entry["sequence"],
                "vk_cell": [
                    page["vk_slot"] for page in entry["dirty_pages"]
                    if page["vk_slot"]["covered"]
                ],
                "data_cell": [
                    page["data_slot"] for page in entry["dirty_pages"]
                    if page["data_slot"]["covered"]
                ],
            })

    return {
        "snapshot_sequences": {
            "before": {
                "sequence1": before.sequence1,
                "sequence2": before.sequence2,
                "sha256": before.sha256,
                "batch_id": "snapshot:before:seq2=%s:%s"
                            % (before.sequence2, before.sha256[:12]),
            },
            "after": {
                "sequence1": after.sequence1,
                "sequence2": after.sequence2,
                "sha256": after.sha256,
                "batch_id": "snapshot:after:seq2=%s:%s"
                            % (after.sequence2, after.sha256[:12]),
            },
        },
        "offline_batches": offline,
        "alignment": alignment,
        "alignment_reasons": alignment_reasons,
        "alignment_warnings": alignment_warnings,
        "coverage": {
            "old_vk_cell": covered_vk,
            "old_data_cell": covered_data
            if old_data_cell is not None else "inline_or_absent",
            "dirty_page_matches_after_vk_cell": matching_after_vk,
            "dirty_page_matches_after_data_cell": matching_after_data,
        },
        "slot_state_by_batch": slot_history,
    }


def _same_value(after_value, before_value):
    if not after_value or not before_value:
        return False
    return (
        after_value.get("value_type") == before_value.get("value_type")
        and after_value.get("data_sha256") == before_value.get("data_sha256")
    )


def _classify(before_target, after_target, after, old_vk_cell, old_data_cell):
    vk_slot = after.inspect_slot(
        old_vk_cell["cell_abs"] if old_vk_cell else None,
        old_vk_cell)
    data_slot = after.inspect_slot(
        old_data_cell["cell_abs"] if old_data_cell else None,
        old_data_cell)

    if not before_target.get("value_present"):
        if after_target.get("value_present"):
            return {
                "verdict": "PRESENT",
                "reason_code": "PRESENT_IN_AFTER_BUT_NOT_IN_BASELINE",
                "explanation": (
                    "The value is present in the later snapshot but absent "
                    "from the earlier snapshot, so a deletion claim lacks a "
                    "baseline."),
                "vk_slot": vk_slot,
                "data_slot": data_slot,
            }
        return {
            "verdict": "NOT_COLLECTED",
            "reason_code": "TARGET_NOT_IN_EITHER_SNAPSHOT",
            "explanation": (
                "The queried value is not present in either snapshot.  No "
                "physical cell identity exists to compare, so this is a "
                "collection/coverage gap, not deletion evidence."),
            "vk_slot": vk_slot,
            "data_slot": data_slot,
        }

    if after_target.get("value_present"):
        same = _same_value(
            after_target.get("value"), before_target.get("value"))
        return {
            "verdict": "PRESENT" if same else "PRESENT_MODIFIED",
            "reason_code": (
                "VALUE_STILL_PRESENT" if same
                else "VALUE_PRESENT_WITH_DIFFERENT_DATA"),
            "explanation": (
                "The value is still present at the same full path in the later "
                "snapshot; absence was not observed."),
            "vk_slot": vk_slot,
            "data_slot": data_slot,
        }

    if vk_slot["state"] in (
            "beyond_captured_hbins", "snapshot_unparseable",
            "before_first_hbin", "unmapped_gap"):
        return {
            "verdict": "UNDETERMINED",
            "reason_code": "OLD_VK_SLOT_NOT_COMPARABLE",
            "explanation": (
                "The old VK cell cannot be located in the later snapshot "
                "(state=%s).  This may indicate truncation, reorganization, "
                "or an acquisition gap, not a released cell." % vk_slot["state"]),
            "vk_slot": vk_slot,
            "data_slot": data_slot,
        }

    if vk_slot["state"] == "free":
        if not vk_slot["covers_entire_before_cell"]:
            return {
                "verdict": "UNDETERMINED",
                "reason_code": "OLD_VK_SLOT_ONLY_PARTIALLY_COVERED",
                "explanation": (
                    "The old VK cell start falls inside a free cell, but the "
                    "free extent does not cover the entire prior cell."),
                "vk_slot": vk_slot,
                "data_slot": data_slot,
            }
        return {
            "verdict": "RELEASED",
            "reason_code": "OLD_VK_CELL_IS_FREE",
            "explanation": (
                "The value was present in the baseline, is absent from the "
                "later live tree, and its original VK cell is free (or was "
                "coalesced into a free cell)."),
            "vk_slot": vk_slot,
            "data_slot": data_slot,
        }

    if vk_slot["state"] == "allocated":
        if vk_slot.get("same_bytes_as_before"):
            return {
                "verdict": "UNDETERMINED",
                "reason_code": "OLD_VK_BYTES_REMAIN_ALLOCATED_BUT_UNREACHABLE",
                "explanation": (
                    "The old VK cell bytes are unchanged and still marked "
                    "allocated, yet the value is absent from the live tree.  "
                    "This is not a clean release or reallocation."),
                "vk_slot": vk_slot,
                "data_slot": data_slot,
            }
        allocated_vk = vk_slot.get("allocated_vk") or {}
        return {
            "verdict": "REALLOCATED",
            "reason_code": "OLD_VK_CELL_START_REUSED",
            "explanation": (
                "The value was present in the baseline and is absent from the "
                "later live tree.  The exact VK cell start is allocated in the "
                "later hive to %s." % (
                    "value %r" % allocated_vk.get("name")
                    if allocated_vk.get("name")
                    else "another registry structure")),
            "vk_slot": vk_slot,
            "data_slot": data_slot,
        }

    return {
        "verdict": "UNDETERMINED",
        "reason_code": "UNRECOGNIZED_VK_SLOT_STATE",
        "explanation": "The old VK slot state could not be classified.",
        "vk_slot": vk_slot,
        "data_slot": data_slot,
    }


def _missing_evidence(verdict, transaction):
    missing = []
    if verdict == "REALLOCATED":
        missing.append({
            "code": "INTERMEDIATE_FREE_STATE",
            "description": (
                "A snapshot or transaction batch showing the old VK slot free "
                "before a different item occupies it."),
            "description_zh": (
                "需要一份中间快照或事务批次，显示旧 VK 槽位在另一个配置项占用它之前"
                "确实处于空闲状态。"),
        })
        missing.append({
            "code": "DELETION_TRANSACTION_OR_AUDIT_EVENT",
            "description": (
                "A transaction/audit record tying the disappearance to a "
                "specific operation, time, and actor."),
            "description_zh": (
                "需要能把消失过程绑定到具体操作、时间和操作者的事务记录、审计日志、"
                "EDR 或部署工具日志。"),
        })
    elif verdict == "RELEASED":
        missing.append({
            "code": "DELETION_TRANSACTION_OR_AUDIT_EVENT",
            "description": (
                "A transaction/audit record tying the free cell to a deletion "
                "operation rather than hive maintenance or reorganization."),
            "description_zh": (
                "需要事务/审计记录，把空闲 cell 绑定到删除操作，而不是 hive 维护、"
                "重组或其它正常重写。"),
        })
    elif verdict == "NOT_COLLECTED":
        missing.append({
            "code": "EARLIER_ACQUISITION_WITH_TARGET",
            "description": (
                "An earlier image or acquisition scope showing that the value "
                "ever existed in this hive."),
            "description_zh": (
                "需要一份更早的映像或采集范围证明，说明该值曾经存在于这个 hive 中。"),
        })
        missing.append({
            "code": "PHYSICAL_IDENTITY_OF_TARGET",
            "description": (
                "A target VK cell identity from a snapshot in which the value "
                "was actually captured."),
            "description_zh": (
                "需要一份实际捕获到目标值的快照，并给出其 VK cell 物理身份。"),
        })
    elif verdict == "UNDETERMINED":
        missing.append({
            "code": "RECONCILED_MATERIALS",
            "description": (
                "Hive snapshots and transaction batches from the same lineage, "
                "with an ordered sequence window and matching hive identity."),
            "description_zh": (
                "需要同一 hive 血统的快照和事务批次，且 hive 名称、序号窗口和采集顺序"
                "能够互相吻合。"),
        })

    if transaction["alignment"] == "NOT_PROVIDED":
        missing.append({
            "code": "OFFLINE_TRANSACTION_BATCH",
            "description": (
                "The offline transaction record set was not supplied, so no "
                "batch can corroborate the transition."),
            "description_zh": (
                "未提供离线事务记录，无法用事务批次佐证状态转换。"),
        })
    elif not transaction["coverage"]["old_vk_cell"]:
        missing.append({
            "code": "BATCH_COVERING_OLD_VK_SLOT",
            "description": (
                "The supplied transaction batches do not contain a dirty page "
                "covering the old VK cell."),
            "description_zh": (
                "现有事务批次中没有任何脏页覆盖旧 VK cell，无法证明该批次改写了这个槽位。"),
        })

    missing.append({
        "code": "FULL_DISK_PROVENANCE",
        "description": (
            "Acquisition hashes, device/image identifiers, and a documented "
            "chain of custody for both hive snapshots."),
        "description_zh": (
            "需要两份 hive 快照的采集哈希、设备/镜像标识和完整的证据保管链记录。"),
    })
    return missing


def _findings(verdict, query, before, after, before_target, after_target,
              classification, transaction):
    findings = []
    if before_target.get("value_present"):
        value = before_target["value"]
        identity = value["physical_identity"]
        findings.append({
            "kind": "BASELINE_CAPTURE",
            "text": (
                "The earlier snapshot captured %s with VK cell RVA %s "
                "(absolute %s), data storage %s."
                % (before_target["full_value_path"],
                   _hex(identity["vk_cell_rva"]),
                   _hex(identity["vk_cell_rva"] + FIRST_HBIN_OFFSET),
                   identity["data_storage"])),
            "text_zh": (
                "较早快照确实捕获到 %s；VK cell RVA 为 %s（绝对偏移 %s），"
                "数据存储方式为 %s。"
                % (before_target["full_value_path"],
                   _hex(identity["vk_cell_rva"]),
                   _hex(identity["vk_cell_rva"] + FIRST_HBIN_OFFSET),
                   identity["data_storage"])),
        })
    else:
        findings.append({
            "kind": "BASELINE_MISS",
            "text": (
                "The earlier snapshot does not prove that the queried value "
                "ever existed; no physical identity is available."),
            "text_zh": (
                "较早快照不能证明查询值曾经存在；没有可用的物理身份，"
                "因此不能把后续“查不到”当作删除证据。"),
        })

    if after_target.get("value_present"):
        findings.append({
            "kind": "AFTER_LIVE_TREE",
            "text": (
                "The later live tree still contains %s."
                % after_target["full_value_path"]),
            "text_zh": (
                "后续快照的活动树中仍然存在 %s。"
                % after_target["full_value_path"]),
        })
    else:
        findings.append({
            "kind": "AFTER_LIVE_TREE",
            "text": (
                "The later live tree does not contain %s."
                % query["value_path"]),
            "text_zh": (
                "后续快照的活动树中不存在 %s。"
                % query["value_path"]),
        })

    vk_slot = classification["vk_slot"]
    if vk_slot.get("cell"):
        cell = vk_slot["cell"]
        findings.append({
            "kind": "PHYSICAL_SLOT_STATE",
            "text": (
                "In the later snapshot, the old VK slot at RVA %s is %s "
                "(relation=%s, size=%s, signature=%s)."
                % (_hex(vk_slot["cell_offset_relative_to_first_hbin"]),
                   vk_slot["state"], vk_slot["relation"], cell["cell_size"],
                   cell["signature"])),
            "text_zh": (
                "后续快照中，旧 VK 槽位 RVA %s 的状态为 %s"
                "（关系=%s，大小=%s，签名=%s）。"
                % (_hex(vk_slot["cell_offset_relative_to_first_hbin"]),
                   vk_slot["state"], vk_slot["relation"], cell["cell_size"],
                   cell["signature"])),
        })
        reused = vk_slot.get("allocated_vk")
        if reused and reused.get("name"):
            reused_path = (
                "%s!%s" % (after_target.get("resolved_key_path"),
                             reused.get("name"))
                if after_target.get("resolved_key_path") else None)
            findings.append({
                "kind": "SLOT_REUSE_TARGET",
                "text": (
                    "The reused VK cell now holds value %r%s of type %s with "
                    "data preview %r."
                    % (reused.get("name"),
                       " (%s)" % reused_path if reused_path else "",
                       reused.get("value_type_str"),
                       reused.get("data_preview"))),
                "text_zh": (
                    "复用后的 VK cell 现在保存配置项 %r%s，类型为 %s，"
                    "数据预览为 %r。"
                    % (reused.get("name"),
                       "（%s）" % reused_path if reused_path else "",
                       reused.get("value_type_str"),
                       reused.get("data_preview"))),
            })
    elif vk_slot.get("state"):
        findings.append({
            "kind": "PHYSICAL_SLOT_STATE",
            "text": "The old VK slot state is %s." % vk_slot["state"],
            "text_zh": "旧 VK 槽位状态为 %s。" % vk_slot["state"],
        })

    data_slot = classification.get("data_slot") or {}
    if data_slot.get("cell"):
        findings.append({
            "kind": "DATA_SLOT_STATE",
            "text": (
                "The old external data slot at RVA %s is %s in the later "
                "snapshot."
                % (_hex(data_slot.get("cell_offset_relative_to_first_hbin")),
                   data_slot["state"])),
            "text_zh": (
                "后续快照中，旧外部数据槽位 RVA %s 的状态为 %s。"
                % (_hex(data_slot.get("cell_offset_relative_to_first_hbin")),
                   data_slot["state"])),
        })

    if transaction["alignment"] != "NOT_PROVIDED":
        findings.append({
            "kind": "TRANSACTION_BATCH_COVERAGE",
            "text": (
                "Offline batch alignment=%s; old VK cell covered=%s; dirty "
                "page matches the later slot=%s."
                % (transaction["alignment"],
                   transaction["coverage"]["old_vk_cell"],
                   transaction["coverage"][
                       "dirty_page_matches_after_vk_cell"])),
            "text_zh": (
                "离线事务批次对齐状态=%s；旧 VK cell 是否被脏页覆盖=%s；"
                "脏页内容是否与后续槽位一致=%s。"
                % (transaction["alignment"],
                   transaction["coverage"]["old_vk_cell"],
                   transaction["coverage"][
                       "dirty_page_matches_after_vk_cell"])),
        })
    return findings


def _limitations(verdict):
    items = [{
        "text": (
            "Cell RVAs are comparable only if the later hive was not "
            "reorganized (Windows 8+ hive reorganization can move cells)."),
        "text_zh": (
            "只有当后续 hive 没有被重新组织时，cell RVA 才可直接比较；"
            "Windows 8+ 的 hive 重组会移动 cell。"),
    }, {
        "text": (
            "A free cell proves storage release, not who or what requested the "
            "deletion; free-cell residue may also be stale."),
        "text_zh": (
            "空闲 cell 只能证明存储被释放，不能证明是谁或什么操作发起删除；"
            "空闲 cell 中的残留字节也可能来自更早的内容。"),
    }, {
        "text": (
            "Absence from a parsed hive is not proof that a value never "
            "existed; it may be a collection, scope, or acquisition gap."),
        "text_zh": (
            "解析后的 hive 中不存在某个值，不等于该值从未存在；"
            "也可能是采集范围、快照时点或获取过程造成的缺口。"),
    }, {
        "text": (
            "New-format transaction logs contain dirty page images and "
            "sequence numbers, not semantic operation names or actor "
            "identities."),
        "text_zh": (
            "新格式事务日志保存的是脏页映像和序号，不包含语义化的操作名称、"
            "进程、用户或操作者身份。"),
    }]
    if verdict == "REALLOCATED":
        items.append({
            "text": (
                "Reallocation proves that the old slot start was overwritten "
                "or reused by the later state; it does not prove that a free "
                "state existed between the two snapshots."),
            "text_zh": (
                "槽位再分配只能证明后续状态覆盖或复用了旧槽位起始位置，"
                "不能证明两份快照之间一定出现过可观察的空闲状态。"),
        })
    return items


def _explanation_zh(verdict):
    return {
        "RELEASED": (
            "较早快照确实捕获过该值；后续快照的活动树中没有该值，且原 VK cell "
            "已成为空闲 cell。按本工具定义，这可作为“后续映像中已释放”的物理"
            "证据，但仍不能单凭空闲 cell 认定删除动作、时间或操作者。"),
        "REALLOCATED": (
            "较早快照确实捕获过该值；后续快照的活动树中没有该值，而同一 VK "
            "cell 起始位置已被另一个配置项占用。这证明原槽位发生了再分配，"
            "但不能单独证明两次采集之间曾出现可观察的“先释放、后复用”中间状态，"
            "也不能证明删除动作、时间和操作者。"),
        "NOT_COLLECTED": (
            "两份快照都没有该值，基线中没有可用的物理身份。因此后续“查不到”"
            "只能说明未采集到或采集范围未覆盖，不能解释为删除证据。"),
        "PRESENT": (
            "后续快照的活动树中仍然存在该配置项，不能支持“已删除”的结论。"),
        "PRESENT_MODIFIED": (
            "后续快照的活动树中仍存在同名配置项，但数据已变化；这不是删除，"
            "而是修改或替换。"),
        "UNDETERMINED": (
            "材料之间存在 hive 身份、序号窗口、时间顺序或槽位可比性冲突，"
            "按规则只给出“无法判定”，不输出释放或再分配结论。"),
    }[verdict]


def analyze_deletion(before_source, after_source, key_path, value_name,
                     log_sources=None):
    """Return a JSON-serializable deletion-evidence report.

    Parameters
    ----------
    before_source, after_source:
        Paths or binary file-like objects for the earlier/later hives.
    key_path:
        Key path, with or without the hive root name.
    value_name:
        Value name; ``(default)`` selects the default value.
    log_sources:
        Iterable of new-format transaction log paths/file-like objects.
    """
    log_sources = list(log_sources or [])
    before = HiveSnapshot(before_source)
    after = HiveSnapshot(after_source)
    before_target = before.locate_value(key_path, value_name)
    after_target = after.locate_value(key_path, value_name)
    materials = _material_check(before, after, before_target, after_target)

    old_vk_cell = None
    old_data_cell = None
    if before_target.get("value_present"):
        value = before_target["value"]
        vk_public = value.get("vk_cell") or {}
        old_vk_abs = vk_public.get("cell_offset_absolute")
        old_vk_cell = (
            before.cell_by_offset.get(old_vk_abs)
            if old_vk_abs is not None else None)
        if old_vk_cell is not None:
            old_vk_cell = dict(old_vk_cell)
            old_vk_cell["raw_bytes"] = before.data[
                old_vk_cell["cell_abs"]:
                old_vk_cell["cell_abs"] + old_vk_cell["cell_size"]
            ]
        if value["data_identity"]["storage"].startswith("external"):
            data_abs = value["data_identity"].get("cell_offset_absolute")
            old_data_cell = before.cell_by_offset.get(data_abs)
            if old_data_cell is not None:
                old_data_cell = dict(old_data_cell)
                old_data_cell["raw_bytes"] = before.data[
                    old_data_cell["cell_abs"]:
                    old_data_cell["cell_abs"] + old_data_cell["cell_size"]
                ]

    logs = [
        TransactionLog(
            source,
            target_vk_cell=old_vk_cell,
            target_data_cell=old_data_cell,
            after_snapshot=after)
        for source in log_sources
    ]

    if materials["status"] == "MISMATCH":
        classification = {
            "verdict": "UNDETERMINED",
            "reason_code": "MATERIAL_MISMATCH",
            "explanation": (
                "The supplied hives/transaction records do not form a "
                "consistent lineage, so a release/reallocation verdict is "
                "withheld."),
            "vk_slot": after.inspect_slot(
                old_vk_cell["cell_abs"] if old_vk_cell else None,
                old_vk_cell),
            "data_slot": after.inspect_slot(
                old_data_cell["cell_abs"] if old_data_cell else None,
                old_data_cell),
        }
    else:
        classification = _classify(
            before_target, after_target, after, old_vk_cell, old_data_cell)

    transaction = _transaction_batches(
        before, after, logs, old_vk_cell, old_data_cell)
    if transaction["alignment"] == "MISMATCH":
        classification = {
            "verdict": "UNDETERMINED",
            "reason_code": "TRANSACTION_BATCH_MISMATCH",
            "explanation": (
                "The offline transaction records do not align with the "
                "snapshot sequence window or hive identity, so a physical "
                "release/reallocation verdict is withheld."),
            "vk_slot": classification["vk_slot"],
            "data_slot": classification["data_slot"],
        }

    resolved_key_path = (
        before_target.get("resolved_key_path")
        or after_target.get("resolved_key_path")
        or key_path)
    value_path = (
        before_target.get("full_value_path")
        or after_target.get("full_value_path")
        or "%s!%s" % (resolved_key_path, value_name or "(default)"))

    verdict = classification["verdict"]
    report = {
        "schema": SCHEMA,
        "read_only": True,
        "query": {
            "input_key_path": key_path,
            "value_name": value_name or "(default)",
            "resolved_key_path": resolved_key_path,
            "value_path": value_path,
        },
        "verdict": verdict,
        "verdict_label_en": VERDICT_LABELS[verdict]["en"],
        "verdict_label_zh": VERDICT_LABELS[verdict]["zh"],
        "reason_code": classification["reason_code"],
        "explanation": classification["explanation"],
        "explanation_zh": _explanation_zh(verdict),
        "materials": materials,
        "before": dict(
            {"snapshot": before.metadata(), "target": before_target},
            **{"old_vk_slot": _cell_public(old_vk_cell),
               "old_data_slot": _cell_public(old_data_cell)}
        ),
        "after": dict(
            {"snapshot": after.metadata(), "target": after_target},
            **{"old_vk_slot": classification["vk_slot"],
               "old_data_slot": classification["data_slot"]}
        ),
        "transaction_batches": transaction,
        "findings": _findings(
            verdict, {
                "value_path": value_path,
            },
            before, after, before_target, after_target,
            classification, transaction),
        "limitations": _limitations(verdict),
        "missing_evidence": _missing_evidence(verdict, transaction),
    }
    return report


def _render_markdown(report):
    query = report["query"]
    before = report["before"]["snapshot"]
    after = report["after"]["snapshot"]
    transaction = report["transaction_batches"]
    verdict = report["verdict"]
    lines = []
    lines.append("# SOFTWARE Hive 删除证据查询报告")
    lines.append("")
    lines.append("## 结论")
    lines.append("")
    lines.append("- 判定：`%s`（%s）" % (verdict, report["verdict_label_zh"]))
    lines.append("- 原因代码：`%s`" % report["reason_code"])
    lines.append("- 完整配置项路径：`%s`" % query["value_path"])
    lines.append("- 只读模式：`%s`" % report["read_only"])
    lines.append("")
    lines.append(report.get("explanation_zh") or report["explanation"])
    lines.append("")
    lines.append("## 输入与批次")
    lines.append("")
    lines.append("| 时点 | 文件 | hive SHA-256 | sequence1/2 | 最后写入 (UTC) | HBIN 大小 |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    lines.append("| before | `%s` | `%s` | %s/%s | %s | %s |" % (
        before["source"], before["sha256"], before["sequence1"], before["sequence2"],
        before["last_write_utc"], before["hbins_size_hex"]))
    lines.append("| after | `%s` | `%s` | %s/%s | %s | %s |" % (
        after["source"], after["sha256"], after["sequence1"], after["sequence2"],
        after["last_write_utc"], after["hbins_size_hex"]))
    lines.append("")
    materials = report["materials"]
    lines.append("- 材料一致性：`%s`" % materials["status"])
    for reason in materials["reasons"]:
        lines.append("  - %s" % reason)
    lines.append("- 快照批次：`%s`；`%s`" % (
        transaction["snapshot_sequences"]["before"]["batch_id"],
        transaction["snapshot_sequences"]["after"]["batch_id"]))
    lines.append("- 离线批次对齐：`%s`" % transaction["alignment"])
    if transaction["alignment_reasons"]:
        for reason in transaction["alignment_reasons"]:
            lines.append("  - %s" % reason)
    for warning in transaction.get("alignment_warnings", []):
        lines.append("  - 警告：%s" % warning)
    lines.append("- 旧 VK 槽位被离线脏页覆盖：`%s`" % (
        transaction["coverage"]["old_vk_cell"]))
    lines.append("- 脏页内容匹配 after 槽位：`%s`" % (
        transaction["coverage"]["dirty_page_matches_after_vk_cell"]))
    for log in transaction["offline_batches"]:
        sequences = [entry["sequence"] for entry in log["entries"]]
        lines.append(
            "- 离线日志 `%s` SHA-256 `%s`，HvLE 序号 `%s`，有效 `%s`"
            % (log["source"], log["sha256"], sequences, log["valid"]))
    lines.append("")
    lines.append("## 物理身份")
    lines.append("")
    before_value = report["before"]["target"].get("value")
    if before_value:
        identity = before_value["physical_identity"]
        lines.append("- KV 路径：`%s`" % identity["full_value_path"])
        lines.append("- NK cell RVA：`%s`" % _hex(identity["key_nk_cell_rva"]))
        lines.append("- values list 索引：`%s`" % identity["values_list_index"])
        lines.append("- VK cell RVA / 大小：`%s` / `%s`" % (
            _hex(identity["vk_cell_rva"]), identity["vk_cell_size"]))
        lines.append("- VK cell 绝对偏移：`%s`" % _hex(
            identity["vk_cell_rva"] + FIRST_HBIN_OFFSET))
        lines.append("- VK cell SHA-256：`%s`" % (
            (before_value.get("vk_cell") or {}).get("cell_sha256")))
        lines.append("- 数据存储：`%s`；数据 SHA-256：`%s`" % (
            identity["data_storage"], before_value["data_sha256"]))
        if identity["data_cell_rva"] is not None:
            lines.append("- 数据 cell RVA：`%s`" % _hex(
                identity["data_cell_rva"]))
            lines.append("- 数据 cell SHA-256：`%s`" % (
                (before_value.get("data_identity") or {}).get(
                    "cell", {}).get("cell_sha256")))
    else:
        lines.append("- 基线快照未捕获目标值，因此没有可用的物理身份。")
    lines.append("")
    lines.append("后续映像中的旧槽位状态：")
    lines.append("")
    vk_slot = report["after"]["old_vk_slot"]
    lines.append("- 状态：`%s`；关系：`%s`" % (
        vk_slot.get("state"), vk_slot.get("relation")))
    if vk_slot.get("cell"):
        cell = vk_slot["cell"]
        lines.append("- cell 大小 / 签名：`%s` / `%s`" % (
            cell["cell_size"], cell["signature"]))
        lines.append("- 与旧 cell 完整字节相同：`%s`" % vk_slot.get(
            "same_bytes_as_before"))
        lines.append("- 与旧 cell 负载字节相同（忽略 cell 头）：`%s`" % vk_slot.get(
            "same_payload_as_before"))
    reused = vk_slot.get("allocated_vk")
    if reused:
        lines.append("- 新占用值：`%s`，类型 `%s`，预览 `%s`" % (
            reused.get("name"), reused.get("value_type_str"),
            reused.get("data_preview")))
    data_slot = report["after"]["old_data_slot"]
    if data_slot.get("cell"):
        lines.append("- 旧数据槽位：`%s`；负载字节与旧数据相同：`%s`" % (
            data_slot.get("state"), data_slot.get("same_payload_as_before")))
    lines.append("")
    lines.append("## 这对映像说明了什么")
    lines.append("")
    if verdict == "REALLOCATED":
        lines.append(
            "较早快照确实捕获过该值，因此后续“查不到”不是从未采集。"
            "后续快照在**完全相同的 VK cell 起始位置**保存了另一个配置项，"
            "而旧配置项的外部数据槽位已经空闲；这证明旧 VK 槽位被再分配/覆盖，"
            "足以否定旧值仍然有效，但不能单独证明两次采集之间出现过可观察的释放瞬间。")
    elif verdict == "RELEASED":
        lines.append(
            "较早快照确实捕获过该值，后续活动树中没有该值，且原 VK cell "
            "处于空闲状态。这是后续映像中的存储释放证据；它仍不等于已经证明"
            "删除动作、时间或操作者。")
    elif verdict == "NOT_COLLECTED":
        lines.append(
            "两份快照都没有该值，基线中没有物理身份。因此不能把后续“查不到”"
            "作为删除证据；这是未采集或采集范围不足。")
    elif verdict == "UNDETERMINED":
        lines.append(
            "材料在 hive 身份、序号窗口、时间顺序或槽位可比性上存在冲突，"
            "按规则只给出无法判定，不把任一物理状态升级为删除结论。")
    else:
        lines.append(
            "后续快照仍能解析到该配置项，不能支持“已删除”的结论。")
    lines.append("")
    for finding in report["findings"]:
        lines.append("- %s" % (finding.get("text_zh") or finding["text"]))
    lines.append("")
    lines.append("## 还缺什么证据")
    lines.append("")
    for item in report["missing_evidence"]:
        lines.append("- `%s`：%s" % (
            item["code"], item.get("description_zh") or item["description"]))
    lines.append("")
    lines.append("## 限制")
    lines.append("")
    for item in report["limitations"]:
        if isinstance(item, dict):
            lines.append("- %s" % (item.get("text_zh") or item["text"]))
        else:
            lines.append("- %s" % item)
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Read-only deletion evidence query for two SOFTWARE hive "
            "snapshots and optional offline transaction logs."))
    parser.add_argument("--before", "--hive-before", "--old", required=True,
                        help="Earlier SOFTWARE hive (read-only)")
    parser.add_argument("--after", "--hive-after", "--new", required=True,
                        help="Later SOFTWARE hive (read-only)")
    parser.add_argument("--key", "--path", "--key-path", dest="key_path",
                        required=True,
                        help="Full key path, with or without the hive root")
    parser.add_argument("--value", "--value-name", dest="value", default="",
                        help="Value name; use (default) for the default value")
    parser.add_argument("--log", action="append", default=[],
                        help="New-format transaction log (.LOG1/.LOG2); repeatable")
    parser.add_argument("--log1", dest="log1", help="Convenience alias for --log")
    parser.add_argument("--log2", dest="log2", help="Convenience alias for --log")
    parser.add_argument("--format", choices=("json", "markdown"),
                        default="json", help="Output format")
    parser.add_argument("--output", help="Write the report to this file")
    parser.add_argument("--compact", action="store_true",
                        help="Emit compact JSON")
    args = parser.parse_args(argv)

    logs = list(args.log)
    if args.log1:
        logs.append(args.log1)
    if args.log2:
        logs.append(args.log2)

    if args.output:
        output_real = os.path.realpath(args.output)
        for input_path in [args.before, args.after] + logs:
            if os.path.realpath(input_path) == output_real:
                parser.error(
                    "--output must not overwrite an input evidence file: %s"
                    % input_path)

    report = analyze_deletion(
        args.before, args.after, args.key_path, args.value, logs)
    if args.format == "markdown":
        output = _render_markdown(report)
    else:
        output = json.dumps(
            report,
            indent=None if args.compact else 2,
            ensure_ascii=False,
            sort_keys=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
            if not output.endswith("\n"):
                handle.write("\n")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
