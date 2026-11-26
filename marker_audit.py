#!/usr/bin/env python3
"""Static attribution audit for observable markers in ELF firmware.

The auditor combines three sources:

* marker descriptors carried by ELF notes;
* section/segment address mappings produced by pyelftools; and
* an external attribution manifest.

It intentionally keeps ambiguous, unmapped, and undeclared evidence in separate
collections instead of collapsing markers that merely share a name.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from elftools.elf.elffile import ELFFile


OBS_NOTE_TYPE = 0x4F425301
OBS_NOTE_TYPE_NAMES = {"NT_OBS_MARKER", "NT_OBSERVABILITY_MARKER"}
MARKER_NAME_KEYS = ("name", "marker", "event", "event_name", "marker_name")
PROVIDER_KEYS = (
    "provider",
    "provider_name",
    "approved_provider",
    "owner",
    "owner_id",
    "vendor",
    "source",
)
ADDRESS_KEYS = ("address", "vaddr", "addr", "st_value", "virtual_address")
SIZE_KEYS = ("size", "st_size", "length")
DEFAULT_SYMBOL_PREFIXES = (
    "obs.",
    "event.",
    "evt.",
    "marker.",
    "trace.",
    "__obs_",
    "__marker_",
)
APPROVED_STATUSES = {
    "approved",
    "approved_before_release",
    "pre_release_approved",
    "pre-approved",
    "preapproved",
}
PRE_RELEASE_STATUSES = {
    "approved_before_release",
    "pre_release_approved",
    "pre-approved",
    "preapproved",
}


class ManifestError(ValueError):
    """Raised when an external manifest cannot be read or normalized."""


@dataclass
class MappingInfo:
    """Static virtual-address to file/section mapping."""

    requested_address: int | None = None
    requested_size: int = 0
    mapped: bool = False
    file_mapped: bool = False
    memory_mapped: bool = False
    section: str | None = None
    section_index: int | None = None
    section_type: str | None = None
    section_address: int | None = None
    section_size: int | None = None
    section_file_offset: int | None = None
    file_offset: int | None = None
    segment_index: int | None = None
    segment_file_offset: int | None = None
    nobits: bool = False
    zero_fill_only: bool = False
    reason: str = "missing_address"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MarkerOccurrence:
    marker: str
    artifact: str
    artifact_path: str
    source: str
    provider: str | None = None
    address: int | None = None
    size: int = 0
    note_owner: str | None = None
    note_type: int | str | None = None
    note_offset: int | None = None
    note_size: int | None = None
    note_section: str | None = None
    symbol_section: str | None = None
    symbol_type: str | None = None
    symbol_bind: str | None = None
    mapping: MappingInfo = field(default_factory=MappingInfo)
    details: dict[str, Any] = field(default_factory=dict)
    categories: list[str] = field(default_factory=list)
    manifest_records: list[dict[str, Any]] = field(default_factory=list)
    declaration: dict[str, Any] = field(default_factory=dict)
    approval: dict[str, Any] = field(default_factory=dict)
    occurrence_id: str | None = None

    def coordinate_key(self) -> str:
        mapping = self.mapping
        section = mapping.section or self.symbol_section or "<no-section>"
        if self.address is not None:
            address_text = f"0x{self.address:x}"
        else:
            address_text = "no-address"
        if mapping.file_offset is not None:
            return f"{section}:{address_text}:file-0x{mapping.file_offset:x}"
        if self.address is not None:
            return f"{section}:{address_text}:unbacked"
        note_location = self.note_offset if self.note_offset is not None else "symbol"
        return f"{section}:{address_text}:source-{note_location}"

    def location_key(self) -> str:
        return f"{self.artifact}::{self.coordinate_key()}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["coordinate_key"] = self.coordinate_key()
        data["location_key"] = self.location_key()
        return data


def as_int(value: Any) -> int | None:
    """Parse integers and common hexadecimal manifest strings."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def as_bool(value: Any) -> bool:
    """Interpret JSON and CSV boolean spellings conservatively."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
        "approved",
        "approved_before_release",
        "pre_release_approved",
    }


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(source: str | Path | dict[str, Any] | None) -> dict[str, Any]:
    """Load and normalize JSON/TOML/external attribution data."""
    if source is None:
        return {"records": [], "raw": {}}
    if isinstance(source, dict):
        raw = source
    else:
        path = Path(source)
        text = path.read_text(encoding="utf-8")
        suffix = path.suffix.lower()
        if suffix == ".toml":
            try:
                import tomllib
            except ImportError as exc:  # pragma: no cover - Python >=3.11
                raise ManifestError("tomllib is required for TOML manifests") from exc
            raw = tomllib.loads(text)
        elif suffix in {".json", ""}:
            raw = json.loads(text)
        elif suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-not-found]
            except ImportError as exc:
                raise ManifestError(
                    "PyYAML is not available; use JSON or TOML"
                ) from exc
            raw = yaml.safe_load(text)
        elif suffix == ".csv":
            import csv

            with path.open(newline="", encoding="utf-8") as handle:
                raw = {"markers": list(csv.DictReader(handle))}
        else:
            try:
                raw = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ManifestError(f"unsupported manifest format: {path}") from exc

    records = _normalize_manifest_records(raw)
    return {"records": records, "raw": raw}


def _normalize_manifest_records(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, list):
        containers = [{"markers": raw}]
    elif isinstance(raw, dict):
        containers = [raw]
    else:
        raise ManifestError("manifest must be a JSON object or list")

    records: list[dict[str, Any]] = []
    for container in containers:
        for key in ("markers", "approvals", "attestations", "claims", "entries"):
            value = container.get(key)
            if value is None:
                continue
            if isinstance(value, dict):
                for name, item in value.items():
                    record = (
                        dict(item) if isinstance(item, dict) else {"approved": item}
                    )
                    record.setdefault("name", name)
                    records.append(_normalize_record(record))
            elif isinstance(value, list):
                for item in value:
                    if not isinstance(item, dict):
                        raise ManifestError("manifest entries must be objects")
                    records.append(_normalize_record(item))

        if not records and any(key in raw for key in ("name", "marker")):
            records.append(_normalize_record(dict(raw)))

    return records


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    name = first_present(record, MARKER_NAME_KEYS)
    if name is not None:
        normalized["name"] = str(name)
    provider = first_present(record, PROVIDER_KEYS)
    if provider is not None:
        normalized["provider"] = str(provider)
    if "approved" not in normalized and "approval" not in normalized:
        status = normalized.get("status")
        if isinstance(status, str) and status.lower() in APPROVED_STATUSES:
            normalized["approved"] = True
    for boolean_key in ("approved", "approved_before_release", "revoked"):
        if boolean_key in normalized:
            normalized[boolean_key] = as_bool(normalized[boolean_key])
    for key in ("address", "vaddr", "addr"):
        if key in normalized:
            normalized[key] = as_int(normalized[key])
    for map_key in ("addresses", "expected_addresses"):
        if isinstance(normalized.get(map_key), dict):
            normalized[map_key] = {
                str(name): as_int(value) for name, value in normalized[map_key].items()
            }
    return normalized


def first_present(data: dict[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def get_build_id(elf: ELFFile) -> str | None:
    for section in elf.iter_sections():
        if section["sh_type"] != "SHT_NOTE" or not hasattr(section, "iter_notes"):
            continue
        try:
            notes = section.iter_notes()
        except Exception:
            continue
        for note in notes:
            if note.get("n_type") == "NT_GNU_BUILD_ID":
                desc = note.get("n_desc")
                return (
                    desc if isinstance(desc, str) else note.get("n_descdata", b"").hex()
                )
    return None


def map_vaddr(elf: ELFFile, address: int | None, size: int = 0) -> MappingInfo:
    """Map a virtual address to a section, PT_LOAD segment, and file offset."""
    info = MappingInfo(requested_address=address, requested_size=size)
    if address is None:
        info.reason = "missing_address"
        return info
    if address == 0:
        info.reason = "null_address"
        return info

    try:
        file_size = os.fstat(elf.stream.fileno()).st_size
    except (AttributeError, OSError):
        file_size = None

    sections = list(elf.iter_sections())
    for index, section in enumerate(sections):
        header = section.header
        start = int(header["sh_addr"])
        section_size = int(header["sh_size"])
        if start == 0 or section_size == 0:
            continue
        end = start + section_size
        in_range = start <= address < end
        if size > 0:
            in_range = start <= address and address + size <= end
        if not in_range:
            continue

        delta = address - start
        info.mapped = True
        info.section = section.name
        info.section_index = index
        info.section_type = str(header["sh_type"])
        info.section_address = start
        info.section_size = section_size
        info.nobits = header["sh_type"] == "SHT_NOBITS"
        info.section_file_offset = (
            None if info.nobits else int(header["sh_offset"]) + delta
        )
        info.file_offset = info.section_file_offset
        break

    for index, segment in enumerate(elf.iter_segments()):
        header = segment.header
        if header["p_type"] != "PT_LOAD":
            continue
        vaddr = int(header["p_vaddr"])
        file_end = vaddr + int(header["p_filesz"])
        memory_end = vaddr + int(header["p_memsz"])
        if not (vaddr <= address < memory_end):
            continue

        info.memory_mapped = True
        info.segment_index = index
        delta = address - vaddr
        info.segment_file_offset = int(header["p_offset"]) + delta

        if size > 0 and address + size <= file_end:
            info.file_mapped = True
            info.file_offset = info.segment_file_offset
        elif size == 0 and address < file_end:
            info.file_mapped = True
            info.file_offset = info.segment_file_offset
        elif address < file_end:
            info.reason = "range_crosses_file_backing"
        else:
            info.zero_fill_only = True
            if not info.nobits:
                info.nobits = True
            info.reason = "zero_fill_only"
        break

    if info.file_mapped and file_size is not None and info.file_offset is not None:
        end_offset = info.file_offset + max(size, 1)
        if end_offset > file_size:
            info.file_mapped = False
            info.reason = "file_offset_beyond_file"
        elif info.reason == "missing_address":
            info.reason = "ok"
    elif info.file_mapped and info.reason == "missing_address":
        info.reason = "ok"

    if not info.mapped and not info.memory_mapped:
        info.reason = "address_outside_all_mappings"
    elif not info.file_mapped and info.reason in {"missing_address", "ok"}:
        if info.nobits:
            info.reason = "nobits_without_file_bytes"
        elif info.zero_fill_only:
            info.reason = "zero_fill_only"
        else:
            info.reason = "not_file_backed"
    return info


def parse_descriptor_markers(
    desc: bytes,
    *,
    note_owner: str | None,
    note_type: int | str | None,
) -> list[dict[str, Any]]:
    """Parse JSON, text, or compact OBS1 marker note descriptors."""
    markers: list[dict[str, Any]] = []
    if not desc:
        return markers

    stripped = desc.lstrip()
    if stripped.startswith((b"{", b"[")):
        try:
            data = json.loads(desc.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict) and isinstance(data.get("markers"), list):
            raw_markers = data["markers"]
        elif isinstance(data, list):
            raw_markers = data
        elif isinstance(data, dict):
            raw_markers = [data]
        else:
            raw_markers = []
        for raw in raw_markers:
            if (
                isinstance(raw, dict)
                and first_present(raw, MARKER_NAME_KEYS) is not None
            ):
                marker = dict(raw)
                marker.setdefault("provider", note_owner)
                markers.append(marker)
        if markers:
            return markers

    binary_marker = parse_obs1_descriptor(desc)
    if binary_marker is not None:
        binary_marker.setdefault("provider", note_owner)
        return [binary_marker]

    text = None
    try:
        text = desc.decode("utf-8").strip()
    except UnicodeDecodeError:
        text = None
    if text and ("=" in text or ":" in text):
        values: dict[str, Any] = {}
        for line in text.splitlines():
            for part in line.replace(";", "\n").splitlines():
                if "=" in part:
                    key, value = part.split("=", 1)
                elif ":" in part:
                    key, value = part.split(":", 1)
                else:
                    continue
                values[key.strip()] = value.strip()
        if first_present(values, MARKER_NAME_KEYS) is not None:
            values.setdefault("provider", note_owner)
            return [values]

    is_marker_type = note_type == OBS_NOTE_TYPE or note_type in OBS_NOTE_TYPE_NAMES
    if is_marker_type and note_owner:
        return [{"name": note_owner, "provider": note_owner, "address": None}]
    return markers


def parse_obs1_descriptor(desc: bytes) -> dict[str, Any] | None:
    if len(desc) < 16 or desc[:4] != b"OBS1":
        return None
    try:
        _magic, version, name_len, provider_len, _flags, address = struct.unpack(
            "<4sBBBBQ", desc[:16]
        )
    except struct.error:
        return None
    offset = 16
    if len(desc) < offset + name_len + provider_len:
        return None
    try:
        name = desc[offset : offset + name_len].decode("utf-8")
        offset += name_len
        provider = desc[offset : offset + provider_len].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return {
        "name": name,
        "provider": provider or None,
        "address": address,
        "descriptor_version": version,
    }


def _note_identity(note: Any) -> tuple[int | None, int | str | None, str | None]:
    return note.get("n_offset"), note.get("n_type"), note.get("n_name")


def extract_occurrences(
    path: str | Path,
    *,
    include_symbols: bool = True,
    symbol_prefixes: Sequence[str] = DEFAULT_SYMBOL_PREFIXES,
    manifest_names: set[str] | None = None,
) -> list[MarkerOccurrence]:
    """Extract marker occurrences from notes and optionally named symbols."""
    path = Path(path)
    artifact = path.name
    occurrences: list[MarkerOccurrence] = []
    seen_notes: set[int] = set()

    with path.open("rb") as stream:
        elf = ELFFile(stream)
        build_id = get_build_id(elf)

        for section_name, section in ((s.name, s) for s in elf.iter_sections()):
            if section["sh_type"] != "SHT_NOTE" or not hasattr(section, "iter_notes"):
                continue
            try:
                notes = list(section.iter_notes())
            except Exception:
                continue
            for note in notes:
                note_offset = note.get("n_offset")
                if note_offset is not None and note_offset in seen_notes:
                    continue
                if note_offset is not None:
                    seen_notes.add(int(note_offset))
                note_type = note.get("n_type")
                note_owner = note.get("n_name")
                desc = bytes(note.get("n_descdata") or b"")
                markers = parse_descriptor_markers(
                    desc, note_owner=note_owner, note_type=note_type
                )
                for marker in markers:
                    name = str(first_present(marker, MARKER_NAME_KEYS) or "")
                    if not name:
                        continue
                    address = as_int(first_present(marker, ADDRESS_KEYS))
                    size = as_int(first_present(marker, SIZE_KEYS)) or 0
                    provider = first_present(marker, PROVIDER_KEYS)
                    occurrence = MarkerOccurrence(
                        marker=name,
                        artifact=artifact,
                        artifact_path=str(path),
                        source="elf-note",
                        provider=str(provider) if provider is not None else note_owner,
                        address=address,
                        size=size,
                        note_owner=note_owner,
                        note_type=note_type
                        if isinstance(note_type, (int, str))
                        else str(note_type),
                        note_offset=note_offset,
                        note_size=note.get("n_size"),
                        note_section=section_name,
                        mapping=map_vaddr(elf, address, size),
                        details={
                            key: value
                            for key, value in marker.items()
                            if key
                            not in set(
                                MARKER_NAME_KEYS
                                + PROVIDER_KEYS
                                + ADDRESS_KEYS
                                + SIZE_KEYS
                            )
                        },
                    )
                    occurrence.details["build_id"] = build_id
                    occurrences.append(occurrence)

        if include_symbols:
            occurrences.extend(
                _extract_symbol_occurrences(
                    elf,
                    path,
                    symbol_prefixes=symbol_prefixes,
                    manifest_names=manifest_names or set(),
                )
            )

    for index, occurrence in enumerate(occurrences, start=1):
        occurrence.occurrence_id = f"{occurrence.artifact}:M{index:03d}"
    return occurrences


def _extract_symbol_occurrences(
    elf: ELFFile,
    path: Path,
    *,
    symbol_prefixes: Sequence[str],
    manifest_names: set[str],
) -> list[MarkerOccurrence]:
    result: list[MarkerOccurrence] = []
    for section in elf.iter_sections():
        if section["sh_type"] not in {"SHT_SYMTAB", "SHT_DYNSYM"}:
            continue
        try:
            symbols = list(section.iter_symbols())
        except Exception:
            continue
        for symbol in symbols:
            name = symbol.name
            value = as_int(symbol["st_value"])
            if not name or value is None or value == 0:
                continue
            prefix_match = any(name.startswith(prefix) for prefix in symbol_prefixes)
            if not prefix_match and name not in manifest_names:
                continue
            shndx = symbol["st_shndx"]
            if isinstance(shndx, str) and shndx == "SHN_UNDEF":
                continue
            size = as_int(symbol["st_size"]) or 0
            mapping = map_vaddr(elf, value, size)
            result.append(
                MarkerOccurrence(
                    marker=name,
                    artifact=path.name,
                    artifact_path=str(path),
                    source="elf-symbol",
                    address=value,
                    size=size,
                    symbol_section=mapping.section,
                    symbol_type=str(symbol["st_info"]["type"]),
                    symbol_bind=str(symbol["st_info"]["bind"]),
                    mapping=mapping,
                )
            )
    return result


def record_applies_to_artifact(record: dict[str, Any], artifact: str) -> bool:
    artifacts = record.get("artifacts", record.get("artifact"))
    if artifacts is None:
        return True
    if isinstance(artifacts, str):
        artifacts = [artifacts]
    artifact_names = {str(item) for item in artifacts}
    return artifact in artifact_names or Path(artifact).name in artifact_names


def record_address_matches(
    record: dict[str, Any], artifact: str, address: int | None
) -> bool | None:
    """Return True/False when an address constraint exists, else None."""
    expected: int | None = None
    if isinstance(record.get("address"), int):
        expected = record["address"]
    addresses = record.get("addresses")
    if isinstance(addresses, dict):
        if artifact in addresses:
            expected = as_int(addresses[artifact])
        elif Path(artifact).name in addresses:
            expected = as_int(addresses[Path(artifact).name])
    if expected is None:
        locations = record.get("locations")
        if isinstance(locations, list):
            for location in locations:
                if not isinstance(location, dict):
                    continue
                loc_artifact = location.get("artifact") or location.get("path")
                if loc_artifact and Path(str(loc_artifact)).name != artifact:
                    continue
                candidate = as_int(first_present(location, ADDRESS_KEYS))
                if candidate is not None:
                    expected = candidate
                    break
    if expected is None:
        return None
    return address == expected


def record_section_matches(
    record: dict[str, Any], artifact: str, section: str | None
) -> bool | None:
    expected = record.get("section")
    sections = record.get("sections")
    if isinstance(sections, dict):
        expected = sections.get(artifact, sections.get(Path(artifact).name))
    if isinstance(record.get("locations"), list):
        for location in record["locations"]:
            if not isinstance(location, dict):
                continue
            loc_artifact = location.get("artifact") or location.get("path")
            if loc_artifact and Path(str(loc_artifact)).name != artifact:
                continue
            if location.get("section"):
                expected = location["section"]
    if expected is None:
        return None
    return section == expected


def approval_is_pre_release(
    record: dict[str, Any], manifest_raw: dict[str, Any]
) -> dict[str, Any]:
    approval = (
        record.get("approval") if isinstance(record.get("approval"), dict) else {}
    )
    status = str(
        approval.get("status")
        or record.get("approval_status")
        or record.get("status")
        or ""
    ).lower()
    approved = as_bool(record.get("approved")) or status in APPROVED_STATUSES
    pre_release = status in PRE_RELEASE_STATUSES or bool(
        as_bool(approval.get("approved_before_release"))
        or as_bool(record.get("approved_before_release"))
    )

    approved_at = approval.get("approved_at") or record.get("approved_at")
    released_at = (
        approval.get("release_at")
        or record.get("release_at")
        or manifest_raw.get("release_at")
        or manifest_raw.get("released_at")
    )
    timing_proven = False
    if approved_at and released_at:
        try:
            timing_proven = datetime.fromisoformat(
                str(approved_at).replace("Z", "+00:00")
            ) < datetime.fromisoformat(str(released_at).replace("Z", "+00:00"))
        except ValueError:
            timing_proven = False
        pre_release = pre_release or timing_proven

    return {
        "approved": approved,
        "pre_release": pre_release,
        "timing_proven_by_timestamps": timing_proven,
        "status": status or ("approved" if approved else "unknown"),
        "approved_at": approved_at,
        "released_at": released_at,
    }


def attribute_occurrences(
    occurrences: list[MarkerOccurrence], manifest: dict[str, Any]
) -> list[MarkerOccurrence]:
    records = manifest.get("records", [])
    raw = manifest.get("raw", {})
    for occurrence in occurrences:
        name_records = [r for r in records if r.get("name") == occurrence.marker]
        artifact_records = [
            r
            for r in name_records
            if record_applies_to_artifact(r, occurrence.artifact)
        ]
        occurrence.manifest_records = artifact_records
        occurrence.declaration = {
            "declared": bool(artifact_records),
            "name_only_elsewhere": bool(name_records and not artifact_records),
        }

        exact_records: list[dict[str, Any]] = []
        provider_matches: list[bool] = []
        match_details: list[dict[str, Any]] = []
        for record in artifact_records:
            checks: dict[str, Any] = {}
            if record.get("provider") is not None and occurrence.provider is not None:
                checks["provider"] = str(record["provider"]) == occurrence.provider
            elif record.get("provider") is not None:
                checks["provider"] = False
            address_check = record_address_matches(
                record, occurrence.artifact, occurrence.address
            )
            if address_check is not None:
                checks["address"] = address_check
            section_check = record_section_matches(
                record,
                occurrence.artifact,
                occurrence.mapping.section or occurrence.symbol_section,
            )
            if section_check is not None:
                checks["section"] = section_check
            build_id = record.get("build_id")
            build_ids = record.get("build_ids")
            observed_build_id = occurrence.details.get("build_id")
            if isinstance(build_ids, dict):
                build_id = build_ids.get(
                    occurrence.artifact, build_ids.get(Path(occurrence.artifact).name)
                )
            if build_id is not None:
                checks["build_id"] = observed_build_id == build_id
            if record.get("sha256") is not None:
                checks["sha256"] = record["sha256"] == sha256_file(
                    occurrence.artifact_path
                )

            provider_matches.append(checks.get("provider", True))
            exact_match = all(checks.values())
            if exact_match:
                exact_records.append(record)
            match_details.append(
                {
                    "provider": record.get("provider"),
                    "approved": approval_is_pre_release(record, raw),
                    "checks": checks,
                    "exact_match": exact_match,
                }
            )

        occurrence.declaration["matches"] = match_details

        approval = {"approved": False, "pre_release": False}
        for record in exact_records:
            candidate = approval_is_pre_release(record, raw)
            if candidate["pre_release"] and candidate["approved"]:
                approval = candidate
                break
            if candidate["approved"] and not approval.get("approved"):
                approval = candidate
        occurrence.approval = approval

        categories: list[str] = []
        if not occurrence.declaration["declared"]:
            categories.append("undeclared")
        elif artifact_records and not any(provider_matches):
            categories.append("provider_mismatch")
        if not occurrence.mapping.file_mapped:
            categories.append("address_without_file_mapping")
        if (
            approval.get("approved")
            and approval.get("pre_release")
            and occurrence.mapping.file_mapped
        ):
            categories.append("approved_before_release")
        occurrence.categories = categories
    return occurrences


def group_duplicate_names(
    occurrences: Sequence[MarkerOccurrence],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[MarkerOccurrence]] = {}
    for occurrence in occurrences:
        grouped.setdefault(occurrence.marker, []).append(occurrence)

    duplicates: list[dict[str, Any]] = []
    for name, items in sorted(grouped.items()):
        coordinate_keys = sorted({item.coordinate_key() for item in items})
        location_keys = sorted({item.location_key() for item in items})
        providers = sorted({item.provider for item in items if item.provider})
        artifacts = sorted({item.artifact for item in items})
        within_artifact = any(
            len({item.coordinate_key() for item in items if item.artifact == artifact})
            > 1
            for artifact in artifacts
        )
        if len(coordinate_keys) <= 1:
            continue
        duplicate = {
            "marker": name,
            "occurrence_count": len(items),
            "artifacts": artifacts,
            "providers": providers,
            "location_count": len(coordinate_keys),
            "coordinate_count": len(coordinate_keys),
            "artifact_location_count": len(location_keys),
            "within_artifact_duplicate": within_artifact,
            "locations": [item.to_dict() for item in items],
        }
        duplicates.append(duplicate)
        for item in items:
            if "same_name_different_location" not in item.categories:
                item.categories.append("same_name_different_location")
    return duplicates


def compare_programs(report_or_occurrences: Any) -> dict[str, Any]:
    if isinstance(report_or_occurrences, dict):
        occurrences = [
            _occurrence_from_dict(item)
            for item in report_or_occurrences.get("occurrences", [])
        ]
    else:
        occurrences = list(report_or_occurrences)

    by_name: dict[str, list[MarkerOccurrence]] = {}
    for occurrence in occurrences:
        by_name.setdefault(occurrence.marker, []).append(occurrence)

    markers: dict[str, Any] = {}
    for name, items in sorted(by_name.items()):
        artifacts = sorted({item.artifact for item in items})
        approved = [
            item for item in items if "approved_before_release" in item.categories
        ]
        location_conflict = any(
            "same_name_different_location" in item.categories for item in items
        )
        markers[name] = {
            "occurrences": len(items),
            "artifacts": artifacts,
            "providers": sorted({i.provider for i in items if i.provider}),
            "distinct_artifact_locations": len({i.location_key() for i in items}),
            "distinct_coordinates": len({i.coordinate_key() for i in items}),
            "within_artifact_duplicate": any(
                len({i.coordinate_key() for i in items if i.artifact == artifact}) > 1
                for artifact in artifacts
            ),
            "file_mapped": all(i.mapping.file_mapped for i in items),
            "declared": all(i.declaration.get("declared") for i in items),
            "approved_occurrence_ids": [i.occurrence_id for i in approved],
            "approved_artifacts": sorted({i.artifact for i in approved}),
            "approved_providers": sorted({i.provider for i in approved if i.provider}),
            "static_pre_release_attribution": bool(approved),
            "unambiguous_pre_release_attribution": bool(
                approved and not location_conflict
            ),
        }
    approved_markers = sorted(
        name for name, info in markers.items() if info["static_pre_release_attribution"]
    )
    unambiguous_approved_markers = sorted(
        name
        for name, info in markers.items()
        if info["unambiguous_pre_release_attribution"]
    )
    return {
        "marker_count": len(markers),
        "approved_marker_count": len(approved_markers),
        "approved_markers": approved_markers,
        "unambiguous_approved_markers": unambiguous_approved_markers,
        "markers": markers,
    }


def _occurrence_from_dict(data: dict[str, Any]) -> MarkerOccurrence:
    mapping_data = data.get("mapping") or {}
    mapping = MappingInfo(
        **{
            k: v
            for k, v in mapping_data.items()
            if k in MappingInfo.__dataclass_fields__
        }
    )
    known = {key for key in MarkerOccurrence.__dataclass_fields__ if key != "mapping"}
    occurrence = MarkerOccurrence(
        **{key: value for key, value in data.items() if key in known},
        mapping=mapping,
    )
    return occurrence


def audit_paths(
    paths: Sequence[str | Path],
    manifest_source: str | Path | dict[str, Any] | None = None,
    *,
    include_symbols: bool = True,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_source)
    manifest_names = {str(r["name"]) for r in manifest["records"] if r.get("name")}
    occurrences: list[MarkerOccurrence] = []
    artifact_metadata: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            raise FileNotFoundError(path)
        artifact_occurrences = extract_occurrences(
            path,
            include_symbols=include_symbols,
            manifest_names=manifest_names,
        )
        occurrences.extend(artifact_occurrences)
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            build_id = get_build_id(elf)
            elf_type = elf.header["e_type"]
            machine = elf.header["e_machine"]
            elfclass = elf.elfclass
        artifact_metadata.append(
            {
                "path": str(path),
                "artifact": path.name,
                "sha256": sha256_file(path),
                "build_id": build_id,
                "elfclass": elfclass,
                "e_type": elf_type,
                "machine": machine,
            }
        )

    attribute_occurrences(occurrences, manifest)
    duplicates = group_duplicate_names(occurrences)
    comparison = compare_programs(occurrences)

    occurrence_dicts = [item.to_dict() for item in occurrences]
    approved_attributions = [
        item.to_dict()
        for item in occurrences
        if "approved_before_release" in item.categories
    ]
    unmapped_addresses = [
        item.to_dict()
        for item in occurrences
        if "address_without_file_mapping" in item.categories
    ]
    undeclared_markers = [
        item.to_dict() for item in occurrences if "undeclared" in item.categories
    ]
    provider_mismatches = [
        item.to_dict() for item in occurrences if "provider_mismatch" in item.categories
    ]
    approved_ids = [item["occurrence_id"] for item in approved_attributions]
    categories = {
        "approved_before_release": approved_ids,
        "approved_attributions": approved_attributions,
        "same_name_different_locations": duplicates,
        "duplicate_locations": duplicates,
        "addresses_without_file_mapping": unmapped_addresses,
        "addresses_outside_file_mapping": unmapped_addresses,
        "unmapped_addresses": unmapped_addresses,
        "undeclared_markers": undeclared_markers,
        "undeclared_items": undeclared_markers,
        "unlisted_markers": undeclared_markers,
        "provider_mismatches": provider_mismatches,
    }
    summary = {
        "artifact_count": len(paths),
        "occurrence_count": len(occurrences),
        "marker_name_count": len({item.marker for item in occurrences}),
        "approved_occurrence_count": len(approved_ids),
        "duplicate_name_group_count": len(duplicates),
        "unmapped_occurrence_count": len(unmapped_addresses),
        "undeclared_occurrence_count": len(undeclared_markers),
        "provider_mismatch_count": len(provider_mismatches),
    }
    return {
        "schema": "marker-attribution-report/1",
        "summary": summary,
        "artifacts": artifact_metadata,
        "manifest": {
            "record_count": len(manifest["records"]),
            "path": str(manifest_source)
            if isinstance(manifest_source, (str, Path))
            else None,
        },
        "categories": categories,
        "comparison": comparison,
        "occurrences": occurrence_dicts,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", nargs="+", help="ELF program or firmware image to audit")
    parser.add_argument(
        "--manifest", "-m", help="external JSON/TOML/CSV attribution manifest"
    )
    parser.add_argument(
        "--output", "-o", help="write JSON report here instead of stdout"
    )
    parser.add_argument(
        "--no-symbols", action="store_true", help="only inspect ELF note descriptors"
    )
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = audit_paths(
        args.elf,
        args.manifest,
        include_symbols=not args.no_symbols,
    )
    text_out = json.dumps(
        report,
        ensure_ascii=False,
        indent=None if args.compact else 2,
        sort_keys=False,
        default=str,
    )
    if args.output:
        Path(args.output).write_text(text_out + "\n", encoding="utf-8")
    else:
        print(text_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
