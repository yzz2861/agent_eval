#!/usr/bin/env python
"""Offline structured parsing for Windows self-relative security descriptors.

The parser is intentionally read-only and does not depend on any Windows API.
It records relative and absolute byte offsets so callers can distinguish a
semantic permission change from harmless raw-byte drift.
"""
from __future__ import unicode_literals

import hashlib
import struct


SOURCE_REFERENCES = {
    "MS-DTYP-SD": {
        "title": "[MS-DTYP] Security Descriptor and ACL structures",
        "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/",
    },
    "MS-DTYP-SID": {
        "title": "[MS-DTYP] Security Identifier and Well-Known SID Structures",
        "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/24259e09-ad40-4889-87b8-4b68c399affe",
    },
    "MS-WK-SID": {
        "title": "Well-known security identifiers in Windows operating systems",
        "url": "https://support.microsoft.com/en-us/topic/well-known-security-identifiers-in-windows-operating-systems-1308724e-0a8f-0b7e-6d0c-6a24b9057039",
    },
    "WIN-SERVICE-ACCESS": {
        "title": "Service Access Rights and Access Mask",
        "url": "https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights",
    },
}

# Each alias keeps its own interface/source. Several aliases may therefore
# resolve to one canonical description without losing provenance.
SID_CATALOG = {
    "S-1-0-0": {
        "description": "Null SID",
        "aliases": [
            {"name": "S-1-0-0", "interface": "binary SID", "source": "MS-DTYP-SID"},
        ],
    },
    "S-1-1-0": {
        "description": "Everyone",
        "aliases": [
            {"name": "WD", "interface": "SDDL shorthand", "source": "MS-DTYP-SID"},
            {"name": "World", "interface": "account alias", "source": "MS-WK-SID"},
            {"name": "Everyone", "interface": "display name", "source": "MS-WK-SID"},
        ],
    },
    "S-1-5-11": {
        "description": "Authenticated Users",
        "aliases": [
            {"name": "AU", "interface": "SDDL shorthand", "source": "MS-DTYP-SID"},
            {"name": "NT AUTHORITY\\Authenticated Users", "interface": "account name", "source": "MS-WK-SID"},
        ],
    },
    "S-1-5-18": {
        "description": "Local System",
        "aliases": [
            {"name": "SY", "interface": "SDDL shorthand", "source": "MS-DTYP-SID"},
            {"name": "LocalSystem", "interface": "service account alias", "source": "WIN-SERVICE-ACCESS"},
            {"name": "NT AUTHORITY\\SYSTEM", "interface": "account name", "source": "MS-WK-SID"},
        ],
    },
    "S-1-5-19": {
        "description": "Local Service",
        "aliases": [
            {"name": "LS", "interface": "SDDL shorthand", "source": "MS-DTYP-SID"},
            {"name": "NT AUTHORITY\\LocalService", "interface": "account name", "source": "MS-WK-SID"},
        ],
    },
    "S-1-5-20": {
        "description": "Network Service",
        "aliases": [
            {"name": "NS", "interface": "SDDL shorthand", "source": "MS-DTYP-SID"},
            {"name": "NT AUTHORITY\\NetworkService", "interface": "account name", "source": "MS-WK-SID"},
        ],
    },
    "S-1-5-32-544": {
        "description": "Administrators",
        "aliases": [
            {"name": "BA", "interface": "SDDL shorthand", "source": "MS-DTYP-SID"},
            {"name": "BUILTIN\\Administrators", "interface": "account name", "source": "MS-WK-SID"},
        ],
    },
    "S-1-5-32-545": {
        "description": "Users",
        "aliases": [
            {"name": "BU", "interface": "SDDL shorthand", "source": "MS-DTYP-SID"},
            {"name": "BUILTIN\\Users", "interface": "account name", "source": "MS-WK-SID"},
        ],
    },
}

CONTROL_BITS = {
    0x0001: "owner_defaulted",
    0x0002: "group_defaulted",
    0x0004: "dacl_present",
    0x0008: "dacl_defaulted",
    0x0010: "sacl_present",
    0x0020: "sacl_defaulted",
    0x0100: "dacl_auto_inherit_requested",
    0x0200: "sacl_auto_inherit_requested",
    0x0400: "dacl_auto_inherited",
    0x0800: "sacl_auto_inherited",
    0x1000: "dacl_protected",
    0x2000: "sacl_protected",
    0x4000: "rm_control_valid",
    0x8000: "self_relative",
}

ACE_TYPES = {
    0x00: "access_allowed",
    0x01: "access_denied",
    0x02: "system_audit",
    0x03: "system_alarm",
    0x05: "access_allowed_object",
    0x06: "access_denied_object",
    0x07: "system_audit_object",
    0x08: "system_alarm_object",
}

ACE_FLAGS = {
    0x01: "object_inherit",
    0x02: "container_inherit",
    0x04: "no_propagate_inherit",
    0x08: "inherit_only",
    0x10: "inherited",
    0x40: "successful_access_audit",
    0x80: "failed_access_audit",
}

ACCESS_MASK_BITS = {
    0x00000001: "service_query_config",
    0x00000002: "service_change_config",
    0x00000004: "service_query_status",
    0x00000008: "service_enumerate_dependents",
    0x00000010: "service_start",
    0x00000020: "service_stop",
    0x00000040: "service_pause_continue",
    0x00000080: "service_interrogate",
    0x00000100: "service_user_defined_control",
    0x00010000: "delete",
    0x00020000: "read_control",
    0x00040000: "write_dacl",
    0x00080000: "write_owner",
    0x00100000: "synchronize",
    0x01000000: "access_system_security",
    0x10000000: "generic_all",
    0x20000000: "generic_execute",
    0x40000000: "generic_write",
    0x80000000: "generic_read",
}


class StructuredParseError(ValueError):
    pass


def references(reference_ids):
    return [SOURCE_REFERENCES[item] for item in reference_ids if item in SOURCE_REFERENCES]


def resolve_sid(sid):
    """Return catalog information and provenance for a canonical SID."""
    entry = SID_CATALOG.get(sid)
    if entry is None:
        return {
            "sid": sid,
            "description": None,
            "known": False,
            "aliases": [],
            "references": references(["MS-DTYP-SID"]),
        }
    return {
        "sid": sid,
        "description": entry["description"],
        "known": True,
        "aliases": entry["aliases"],
        "references": references(["MS-DTYP-SID", "MS-DTYP-SD", "MS-WK-SID"]),
    }


def parse_sid(data, offset, base_offset=0):
    if offset + 8 > len(data):
        raise StructuredParseError("SID header extends beyond security descriptor")
    revision = data[offset]
    sub_authority_count = data[offset + 1]
    authority = int.from_bytes(data[offset + 2:offset + 8], "big")
    end = offset + 8 + (4 * sub_authority_count)
    if end > len(data):
        raise StructuredParseError("SID sub-authorities extend beyond security descriptor")
    sub_authorities = list(struct.unpack_from("<%dI" % sub_authority_count, data, offset + 8))
    sid = "S-%d-%d" % (revision, authority)
    sid += "".join("-%d" % item for item in sub_authorities)
    result = resolve_sid(sid)
    result.update({
        "revision": revision,
        "sub_authority_count": sub_authority_count,
        "byte_offset": base_offset + offset,
        "relative_offset": offset,
        "byte_length": end - offset,
        "raw_hex": data[offset:end].hex(),
    })
    return result


def decode_bits(value, table):
    names = []
    remaining = value
    for bit, name in sorted(table.items()):
        if value & bit:
            names.append(name)
            remaining &= ~bit
    return names, remaining


def parse_acl(data, offset, component, base_offset=0):
    if offset == 0:
        return None
    if offset + 8 > len(data):
        raise StructuredParseError("%s header extends beyond security descriptor" % component)
    acl_revision, sbz1, acl_size, ace_count, sbz2 = struct.unpack_from("<BBHHH", data, offset)
    result = {
        "component": component,
        "acl_revision": acl_revision,
        "acl_size": acl_size,
        "ace_count": ace_count,
        "byte_offset": base_offset + offset,
        "relative_offset": offset,
        "byte_length": acl_size,
        "aces": [],
        "offset_fields": [
            {"field": "acl_revision", "byte_offset": base_offset + offset, "byte_length": 1},
            {"field": "sbz1", "byte_offset": base_offset + offset + 1, "byte_length": 1},
            {"field": "acl_size", "byte_offset": base_offset + offset + 2, "byte_length": 2},
            {"field": "ace_count", "byte_offset": base_offset + offset + 4, "byte_length": 2},
        ],
    }
    cursor = offset + 8
    for index in range(ace_count):
        if cursor + 4 > len(data):
            raise StructuredParseError("ACE header extends beyond security descriptor")
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", data, cursor)
        if ace_size < 8 or cursor + ace_size > len(data):
            raise StructuredParseError("ACE size is outside security descriptor")
        mask = struct.unpack_from("<I", data, cursor + 4)[0]
        ace = {
            "index": index,
            "type_id": ace_type,
            "type": ACE_TYPES.get(ace_type, "unknown_ace_type_0x%02x" % ace_type),
            "flags_raw": ace_flags,
            "flags": decode_bits(ace_flags, ACE_FLAGS)[0],
            "size": ace_size,
            "access_mask_raw": mask,
            "access_rights": decode_bits(mask, ACCESS_MASK_BITS)[0],
            "unknown_mask_bits": decode_bits(mask, ACCESS_MASK_BITS)[1],
            "byte_offset": base_offset + cursor,
            "relative_offset": cursor,
            "byte_length": ace_size,
            "raw_hex": data[cursor:cursor + ace_size].hex(),
        }
        # Standard allow/deny/audit/alarm ACEs place the SID at +8. Object
        # ACEs contain a flags/GUID section first; retain their raw bytes rather
        # than presenting a guessed trustee.
        if ace_type in (0, 1, 2, 3):
            ace["trustee"] = parse_sid(data, cursor + 8, base_offset)
        else:
            ace["trustee"] = None
            ace["trustee_note"] = "object ACE parsed as raw bytes; GUID/SID layout is type-specific"
        result["aces"].append(ace)
        cursor += ace_size
    return result


def parse_security_descriptor(raw, base_offset=0, source=None):
    """Parse a self-relative SECURITY_DESCRIPTOR binary blob.

    ``base_offset`` is added to every reported absolute byte offset.  For a
    Registry value it should normally be the file offset of the raw value data.
    """
    data = bytes(raw or b"")
    if len(data) < 20:
        raise StructuredParseError("security descriptor is shorter than its 20-byte header")
    revision, sbz1, control, owner_offset, group_offset, sacl_offset, dacl_offset = \
        struct.unpack_from("<BBHIIII", data, 0)

    unknown_versions = []
    if revision != 1:
        unknown_versions.append({
            "component": "security_descriptor_revision",
            "version": revision,
            "byte_offset": base_offset,
            "source": source,
        })

    field_offsets = [
        {"field": "revision", "byte_offset": base_offset, "relative_offset": 0, "byte_length": 1},
        {"field": "sbz1", "byte_offset": base_offset + 1, "relative_offset": 1, "byte_length": 1},
        {"field": "control", "byte_offset": base_offset + 2, "relative_offset": 2, "byte_length": 2},
        {"field": "owner_offset", "byte_offset": base_offset + 4, "relative_offset": 4, "byte_length": 4},
        {"field": "group_offset", "byte_offset": base_offset + 8, "relative_offset": 8, "byte_length": 4},
        {"field": "sacl_offset", "byte_offset": base_offset + 12, "relative_offset": 12, "byte_length": 4},
        {"field": "dacl_offset", "byte_offset": base_offset + 16, "relative_offset": 16, "byte_length": 4},
    ]

    result = {
        "kind": "self_relative_security_descriptor",
        "schema": "structured-registry-comparison/security-descriptor-v1",
        "raw_length": len(data),
        "raw_sha256": hashlib.sha256(data).hexdigest(),
        "raw_hex": data.hex(),
        "base_byte_offset": base_offset,
        "revision": revision,
        "sbz1": sbz1,
        "known_version": revision == 1,
        "unknown_versions": unknown_versions,
        "control_raw": control,
        "control_flags": decode_bits(control, CONTROL_BITS)[0],
        "unknown_control_bits": decode_bits(control, CONTROL_BITS)[1],
        "owner_offset": owner_offset,
        "group_offset": group_offset,
        "sacl_offset": sacl_offset,
        "dacl_offset": dacl_offset,
        "owner": parse_sid(data, owner_offset, base_offset) if owner_offset else None,
        "group": parse_sid(data, group_offset, base_offset) if group_offset else None,
        "sacl": parse_acl(data, sacl_offset, "sacl", base_offset),
        "dacl": parse_acl(data, dacl_offset, "dacl", base_offset),
        "field_offsets": field_offsets,
        "raw_byte_offsets": field_offsets,
        "byte_offsets": field_offsets,
        "references": references(["MS-DTYP-SD", "MS-DTYP-SID"]),
        "source": source,
    }
    result["semantic_signature"] = security_descriptor_signature(result)
    return result


def security_descriptor_signature(parsed):
    """Return offsets-independent semantic content for comparisons."""
    def sid(item):
        return item["sid"] if item else None

    def acl(acl_item):
        if not acl_item:
            return None
        return [
            (
                ace["type"],
                ace["flags"],
                ace["access_mask_raw"],
                ace["trustee"]["sid"] if ace.get("trustee") else ace["raw_hex"],
            )
            for ace in acl_item["aces"]
        ]

    return {
        "revision": parsed["revision"],
        "control_flags": sorted(parsed["control_flags"]),
        "owner": sid(parsed["owner"]),
        "group": sid(parsed["group"]),
        "sacl": acl(parsed["sacl"]),
        "dacl": acl(parsed["dacl"]),
    }


def compare_security_descriptors(baseline_raw, candidate_raw, baseline_base_offset=0,
                                 candidate_base_offset=0):
    baseline = parse_security_descriptor(baseline_raw, baseline_base_offset)
    candidate = parse_security_descriptor(candidate_raw, candidate_base_offset)
    changes = []
    left = baseline["semantic_signature"]
    right = candidate["semantic_signature"]
    for field in ("revision", "owner", "group"):
        if left[field] != right[field]:
            changes.append({"field": field, "baseline": left[field], "candidate": right[field]})
    for field in ("control_flags",):
        if left[field] != right[field]:
            changes.append({"field": field, "baseline": left[field], "candidate": right[field]})
    for field in ("sacl", "dacl"):
        if left[field] != right[field]:
            changes.append({"field": field, "baseline": left[field], "candidate": right[field]})
    return {
        "kind": "self_relative_security_descriptor",
        "security_change": bool(changes),
        "permission_change": bool(changes),
        "changes": changes,
        "unknown_versions": baseline["unknown_versions"] + candidate["unknown_versions"],
        "baseline": baseline,
        "candidate": candidate,
    }
