#!/usr/bin/env python
r"""Offline structured comparison for selected registry value archetypes.

The first supported archetype is the Windows Firewall ``v2`` rule string found
under ``...\FirewallPolicy\FirewallRules``.  A rule is one ``REG_SZ`` value,
but contains display resources (``Name``/``Desc``) together with security
policy fields (``Action``/``Active``/ports/addresses/``LUAuth``).

The module never turns an arbitrary raw-byte difference into a permission
change.  Approved fields are semantically compared; unreviewed fields are
quarantined as needs-review; unknown schema versions remain parseable and are
reported separately; every parsed token retains its raw byte offset.
"""
from __future__ import unicode_literals

import difflib
import hashlib
import json
import os
import re

from . import SecurityDescriptor


SCHEMA_VERSION = "structured-registry-comparison/firewall-v1"
SNAPSHOT_SCHEMA = "structured-registry-comparison/snapshot-v1"
KIND_FIREWALL = "windows_firewall_rule_v2"
KIND_SECURITY_DESCRIPTOR = "self_relative_security_descriptor"
KIND_SERVICE_RECORD = "windows_service_record_v1"
KIND_REGISTRY_RECORD = "windows_registry_record_v1"
RECORD_SCHEMA = "structured-registry-comparison/service-record-v1"
SECURITY_DESCRIPTOR_VALUE_NAMES = {
    "security",
    "launchpermission",
    "accesspermission",
    "defaultlaunchpermission",
    "defaultaccesspermission",
    "machinelaunchrestriction",
    "machineaccessrestriction",
}

SOURCES = {
    "MS-FASP": {
        "title": "[MS-FASP] Windows Firewall and Advanced Security Protocol",
        "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/",
    },
    "MS-NETSH": {
        "title": "Netsh AdvFirewall firewall syntax",
        "url": "https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-advfirewall-firewall",
    },
    "MS-NETFIREWALLRULE": {
        "title": "New-NetFirewallRule (NetSecurity)",
        "url": "https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule",
    },
    "MS-DTYP": {
        "title": "[MS-DTYP] Windows Data Types",
        "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/",
    },
    "EMPIRICAL-SYSTEM-HIVE": {
        "title": "Observed token in tests/reg_samples SYSTEM hive",
        "url": "testing/reg_samples/new_log_1/SYSTEM",
    },
}


def _refs(*ids):
    return [SOURCES[item] for item in ids if item in SOURCES]


# Canonical descriptions can have several aliases across the registry token,
# netsh and PowerShell.  Every alias retains its interface and source.
FIELD_CATALOG = {
    "schema_version": {
        "label": "Firewall rule serialization version",
        "category": "schema",
        "security_relevant": False,
        "approved": True,
        "aliases": [
            {"name": "v2", "interface": "registry prefix", "source": "MS-FASP"},
            {"name": "schemaVersion", "interface": "canonical name", "source": "MS-FASP"},
        ],
    },
    "display_name": {
        "label": "Localized or human-facing rule name",
        "category": "display",
        "security_relevant": False,
        "approved": True,
        "aliases": [
            {"name": "Name", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "name", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "DisplayName", "interface": "PowerShell property", "source": "MS-NETFIREWALLRULE"},
            {"name": "-DisplayName", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "display_description": {
        "label": "Localized or human-facing rule description",
        "category": "display",
        "security_relevant": False,
        "approved": True,
        "aliases": [
            {"name": "Desc", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "Description", "interface": "PowerShell property", "source": "MS-NETFIREWALLRULE"},
            {"name": "description", "interface": "netsh parameter", "source": "MS-NETSH"},
        ],
    },
    "display_context": {
        "label": "Display resource context string",
        "category": "display",
        "security_relevant": False,
        "approved": True,
        "aliases": [
            {"name": "EmbedCtxt", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "EmbedContext", "interface": "expanded token alias", "source": "EMPIRICAL-SYSTEM-HIVE"},
        ],
    },
    "action": {
        "label": "Action taken when the rule matches",
        "category": "security",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "Action", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "action", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "Action", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "enabled_state": {
        "label": "Whether the rule is active",
        "category": "security",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "Active", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "Enable", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "Enabled", "interface": "PowerShell property", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "direction": {
        "label": "Traffic direction",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "Dir", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "dir", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "Direction", "interface": "PowerShell property", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "profile": {
        "label": "Network profile to which the rule applies",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "repeatable": True,
        "aliases": [
            {"name": "Profile", "interface": "registry/netsh token", "source": "MS-NETSH"},
            {"name": "Profile", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "protocol": {
        "label": "IP protocol number or alias",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "Protocol", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "protocol", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "Protocol", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "local_port": {
        "label": "Local port or port alias",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "LPort", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "localport", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "LocalPort", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "remote_port": {
        "label": "Remote port or port alias",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "RPort", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "remoteport", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "RemotePort", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "local_address": {
        "label": "Local IPv4/IPv6 address scope",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "repeatable": True,
        "aliases": [
            {"name": "LA4", "interface": "registry IPv4 token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "LA6", "interface": "registry IPv6 token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "localip", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "LocalAddress", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "remote_address": {
        "label": "Remote IPv4/IPv6 address scope",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "repeatable": True,
        "aliases": [
            {"name": "RA4", "interface": "registry IPv4 token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "RA6", "interface": "registry IPv6 token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "remoteip", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "RemoteAddress", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "application_path": {
        "label": "Application image path constrained by the rule",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "App", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "program", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "Program", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "service_name": {
        "label": "Windows service constrained by the rule",
        "category": "identity",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "Svc", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "service", "interface": "netsh parameter", "source": "MS-NETSH"},
            {"name": "Service", "interface": "PowerShell parameter", "source": "MS-NETFIREWALLRULE"},
        ],
    },
    "local_user_authorization": {
        "label": "SDDL security descriptor authorizing local users",
        "category": "security_descriptor",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "LUAuth", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "LocalUserAuthorization", "interface": "canonical expanded name", "source": "MS-FASP"},
        ],
    },
    "local_user_owner": {
        "label": "Owner or user SID constraint",
        "category": "identity",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "LUOwn", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "LocalUserOwner", "interface": "canonical expanded name", "source": "MS-FASP"},
        ],
    },
    "app_package_sid": {
        "label": "App package SID constraint",
        "category": "identity",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "AppPkgId", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "PackageSID", "interface": "canonical expanded name", "source": "MS-FASP"},
        ],
    },
    "edge_traversal": {
        "label": "Edge/NAT traversal setting",
        "category": "security",
        "security_relevant": True,
        "approved": True,
        "aliases": [
            {"name": "Edge", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "edge", "interface": "netsh parameter", "source": "MS-NETSH"},
        ],
    },
    "icmp_v4": {
        "label": "ICMPv4 type/code constraint",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "aliases": [{"name": "ICMP4", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"}],
    },
    "icmp_v6": {
        "label": "ICMPv6 type/code constraint",
        "category": "network_scope",
        "security_relevant": True,
        "approved": True,
        "aliases": [{"name": "ICMP6", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"}],
    },
    "platform": {
        "label": "Operating system platform applicability",
        "category": "compatibility",
        "security_relevant": False,
        "approved": True,
        "aliases": [
            {"name": "Platform", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "Platform2", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
        ],
    },
    "tag_keyword": {
        "label": "Version-specific firewall rule keyword/tag",
        "category": "compatibility",
        "security_relevant": False,
        "approved": False,
        "aliases": [
            {"name": "TTK", "interface": "registry token prefix", "source": "EMPIRICAL-SYSTEM-HIVE"},
            {"name": "TTK2_22", "interface": "registry token", "source": "EMPIRICAL-SYSTEM-HIVE"},
        ],
    },
}

# Observed offline versions.  Other 2.x versions are still parsed, but are put
# in unknown_versions so a report can show catalog coverage honestly.
KNOWN_FIREWALL_VERSIONS = {"2.0", "2.22"}
VERSION_RE = re.compile(r"^[vV](\d+)\.(\d+)$")
BOOL_TRUE = {"true", "yes", "1", "allow"}
BOOL_FALSE = {"false", "no", "0", "block"}

_ALIAS_INDEX = {}
for canonical_name, entry in FIELD_CATALOG.items():
    for alias in entry.get("aliases", []):
        _ALIAS_INDEX.setdefault(alias["name"].lower(), []).append({
            "canonical": canonical_name,
            "alias": alias,
            "entry": entry,
        })
    # The canonical name itself is always resolvable.
    _ALIAS_INDEX.setdefault(canonical_name.lower(), []).append({
        "canonical": canonical_name,
        "alias": {"name": canonical_name, "interface": "canonical name", "source": "MS-FASP"},
        "entry": entry,
    })


def resolve_field_alias(name):
    """Resolve a token and return all aliases sharing its description."""
    matches = _ALIAS_INDEX.get(str(name).lower(), [])
    if not matches:
        return {
            "requested": name,
            "canonical": "unreviewed_" + re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_"),
            "label": "Unreviewed registry field",
            "category": "unreviewed",
            "security_relevant": False,
            "approved": False,
            "aliases": [],
            "references": [],
        }
    match = matches[0]
    entry = match["entry"]
    return {
        "requested": name,
        "canonical": match["canonical"],
        "label": entry["label"],
        "category": entry["category"],
        "security_relevant": entry["security_relevant"],
        "approved": entry["approved"],
        "repeatable": entry.get("repeatable", False),
        "matched_alias": match["alias"],
        "aliases": entry.get("aliases", []),
        "references": _refs(*{alias["source"] for alias in entry.get("aliases", [])}),
    }


def _utf16_offset(text, char_index):
    return len(text[:char_index].encode("utf-16-le"))


def _normalize_value(alias_info, value):
    canonical = alias_info["canonical"]
    text_value = value.strip()
    if canonical == "enabled_state":
        lowered = text_value.lower()
        if lowered in BOOL_TRUE:
            return True
        if lowered in BOOL_FALSE:
            return False
    if canonical == "action":
        return text_value.capitalize()
    if alias_info.get("repeatable") or canonical in ("profile", "local_address", "remote_address"):
        return [part.strip() for part in text_value.split(",") if part.strip()]
    return text_value


def parse_firewall_rule(raw, source=None, snapshot_id=None, base_byte_offset=0):
    """Parse raw ``REG_SZ`` bytes or text into offset-bearing fields."""
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-16-le")
    else:
        raw_bytes = bytes(raw or b"")

    text = raw_bytes.decode("utf-16-le", errors="replace")
    nul_index = text.find("\x00")
    parse_text = text if nul_index < 0 else text[:nul_index]

    fields = []
    version_token = None
    version = None
    unknown_versions = []
    occurrence_counts = {}
    pos = 0
    segment_index = 0

    while pos <= len(parse_text):
        separator = parse_text.find("|", pos)
        end = len(parse_text) if separator < 0 else separator
        segment = parse_text[pos:end]
        start = pos

        if segment:
            start_byte = _utf16_offset(text, start)
            end_byte = _utf16_offset(text, end)
            if segment_index == 0:
                version_token = segment
                match = VERSION_RE.match(segment)
                if match:
                    version = "%d.%d" % (int(match.group(1)), int(match.group(2)))
                    version_status = "known" if version in KNOWN_FIREWALL_VERSIONS else "unknown_version"
                    if version_status == "unknown_version":
                        unknown_versions.append({
                            "component": "firewall_rule_schema",
                            "version": version,
                            "token": segment,
                            "byte_offset": start_byte,
                            "absolute_byte_offset": base_byte_offset + start_byte,
                            "byte_length": end_byte - start_byte,
                        })
                else:
                    version_status = "unrecognized_version"
                    unknown_versions.append({
                        "component": "firewall_rule_schema",
                        "version": None,
                        "token": segment,
                        "byte_offset": start_byte,
                        "absolute_byte_offset": base_byte_offset + start_byte,
                        "byte_length": end_byte - start_byte,
                    })
            elif "=" in segment:
                key, value = segment.split("=", 1)
                alias_info = resolve_field_alias(key)
                occurrence = occurrence_counts.get(key.lower(), 0)
                occurrence_counts[key.lower()] = occurrence + 1
                eq_char = start + len(key)
                value_start_char = eq_char + 1
                value_end_char = end
                value_start_byte = _utf16_offset(text, value_start_char)
                value_end_byte = _utf16_offset(text, value_end_char)
                field = {
                    "index": len(fields),
                    "segment_index": segment_index,
                    "occurrence": occurrence,
                    "token": key,
                    "value": value,
                    "semantic_value": _normalize_value(alias_info, value),
                    "byte_offset": start_byte,
                    "byte_length": end_byte - start_byte,
                    "key_byte_offset": start_byte,
                    "key_byte_length": len(key.encode("utf-16-le")),
                    "equals_byte_offset": _utf16_offset(text, eq_char),
                    "value_byte_offset": value_start_byte,
                    "value_byte_length": value_end_byte - value_start_byte,
                    "absolute_byte_offset": base_byte_offset + start_byte,
                    "value_absolute_byte_offset": base_byte_offset + value_start_byte,
                    "raw_hex": raw_bytes[start_byte:end_byte].hex(),
                }
                field.update(alias_info)
                if field["canonical"] == "local_user_authorization" and value:
                    # SDDL is text, not the binary self-relative format. Keep
                    # the string as its semantic signature and expose common
                    # SDDL section presence for reports.
                    field["sddl_sections"] = {
                        "owner": value.split("O:", 1)[1].split(":", 1)[0] if "O:" in value else None,
                        "group": value.split("G:", 1)[1].split(":", 1)[0] if "G:" in value else None,
                        "dacl": "D:" in value,
                        "sacl": "S:" in value,
                    }
                fields.append(field)
            else:
                alias_info = resolve_field_alias(segment)
                unreviewed_field = {
                    "index": len(fields),
                    "segment_index": segment_index,
                    "occurrence": 0,
                    "token": segment,
                    "value": None,
                    "semantic_value": None,
                    "byte_offset": start_byte,
                    "byte_length": end_byte - start_byte,
                    "absolute_byte_offset": base_byte_offset + start_byte,
                    "raw_hex": raw_bytes[start_byte:end_byte].hex(),
                }
                unreviewed_field.update(alias_info)
                fields.append(unreviewed_field)

        if separator < 0:
            break
        pos = separator + 1
        segment_index += 1

    approved_fields = []
    unapproved_fields = []
    raw_byte_offsets = []
    for field in fields:
        raw_byte_offsets.append({
            "token": field["token"],
            "canonical": field["canonical"],
            "byte_offset": field["byte_offset"],
            "absolute_byte_offset": base_byte_offset + field["byte_offset"],
            "byte_length": field["byte_length"],
            "value_byte_offset": field.get("value_byte_offset"),
            "value_absolute_byte_offset": (
                base_byte_offset + field["value_byte_offset"]
                if field.get("value_byte_offset") is not None else None
            ),
            "value_byte_length": field.get("value_byte_length"),
        })
        if field.get("approved"):
            approved_fields.append(field["canonical"])
        else:
            unapproved_fields.append(field["canonical"])

    if version is not None:
        approved_fields.insert(0, "schema_version")

    return {
        "kind": KIND_FIREWALL,
        "schema": SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "source": source,
        "raw_length": len(raw_bytes),
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "raw_hex": raw_bytes.hex(),
        "raw_encoding": "utf-16le",
        "version_token": version_token,
        "version": version,
        "version_status": version_status if version_token else "missing_version",
        "known_version": bool(version in KNOWN_FIREWALL_VERSIONS),
        "unknown_versions": unknown_versions,
        "base_byte_offset": base_byte_offset,
        "approved_fields": sorted(set(approved_fields)),
        "approved_checked_fields": sorted(set(approved_fields)),
        "unapproved_fields": sorted(set(unapproved_fields)),
        "fields": fields,
        "raw_byte_offsets": raw_byte_offsets,
        "byte_offsets": raw_byte_offsets,
        "raw_offsets": raw_byte_offsets,
        "references": _refs("MS-FASP", "MS-NETSH", "MS-NETFIREWALLRULE", "EMPIRICAL-SYSTEM-HIVE"),
    }


def parse_security_descriptor_snapshot(raw, source=None, snapshot_id=None, base_offset=0):
    parsed = SecurityDescriptor.parse_security_descriptor(raw, base_offset=base_offset, source=source)
    parsed["snapshot_id"] = snapshot_id
    return parsed


def load_snapshot(path):
    with open(path, "r", encoding="utf-8") as handle:
        snapshot = json.load(handle)
    return snapshot


def snapshot_from_dict(snapshot):
    kind = snapshot.get("kind", KIND_FIREWALL)
    raw_hex = snapshot.get("raw_hex")
    if raw_hex is None and "raw" in snapshot:
        raw = snapshot["raw"]
        if isinstance(raw, str):
            raw_hex = raw.encode("utf-16-le").hex()
        else:
            raw_hex = bytes(raw).hex()
    raw = bytes.fromhex(raw_hex) if raw_hex else b""
    return {
        "snapshot_id": snapshot.get("snapshot_id"),
        "kind": kind,
        "label": snapshot.get("label"),
        "raw": raw,
        "source": snapshot.get("source"),
        "base_byte_offset": snapshot.get("base_byte_offset", 0),
    }


def make_snapshot(raw, snapshot_id=None, label=None, kind=KIND_FIREWALL, source=None,
                   base_byte_offset=0):
    if isinstance(raw, str):
        if kind == KIND_FIREWALL:
            raw_bytes = raw.encode("utf-16-le")
        else:
            raw_bytes = raw.encode("latin-1")
    else:
        raw_bytes = bytes(raw)
    return {
        "schema": SNAPSHOT_SCHEMA,
        "snapshot_id": snapshot_id,
        "kind": kind,
        "label": label,
        "raw_encoding": "utf-16le" if kind == KIND_FIREWALL else "binary",
        "raw_hex": raw_bytes.hex(),
        "base_byte_offset": base_byte_offset,
        "source": source or {},
    }


def registry_value_raw_data_offset(registry_value):
    """Best-effort absolute file offset of bytes returned by raw_data()."""
    vk_record = registry_value._vkrecord
    raw_length = vk_record.raw_data_length()
    data_offset = vk_record.data_offset()
    if raw_length < 5 or raw_length >= 0x80000000:
        return vk_record.absolute_offset(0x8)
    return data_offset + 4


def snapshot_from_registry_value(registry_value, key_path=None, snapshot_id=None, label=None):
    raw = registry_value.raw_data()
    value_name = registry_value.name()
    offset = registry_value_raw_data_offset(registry_value)
    source = {
        "generator": "python-registry",
        "key_path": key_path,
        "value_name": value_name,
        "value_type": registry_value.value_type_str(),
        "vk_record_byte_offset": registry_value._vkrecord.offset(),
        "raw_data_byte_offset": offset,
    }
    kind = KIND_FIREWALL
    if value_name.lower() in SECURITY_DESCRIPTOR_VALUE_NAMES or (
        registry_value.value_type() == 3 and key_path and "security" in key_path.lower()
    ):
        kind = KIND_SECURITY_DESCRIPTOR
    return make_snapshot(raw, snapshot_id=snapshot_id or value_name, label=label,
                         kind=kind, source=source, base_byte_offset=offset)


def build_registry_snapshot(hive_path, key_path, value_name, snapshot_id=None, label=None):
    from .Registry import Registry

    registry = Registry(hive_path)
    key = registry.open(key_path)
    value = key.value(value_name)
    return snapshot_from_registry_value(value, key_path=key_path,
                                        snapshot_id=snapshot_id, label=label)


SERVICE_DISPLAY_FIELDS = {
    "displayname": "display_name",
    "description": "display_description",
}
SERVICE_IDENTITY_FIELDS = {
    "objectname": "service_account",
}
SERVICE_CONFIG_FIELDS = {
    "imagepath": "image_path",
    "start": "start_type",
    "type": "service_type",
}


def _registry_value_envelope(value):
    raw = value.raw_data()
    envelope = {
        "name": value.name(),
        "value_type": value.value_type_str(),
        "raw_hex": raw.hex(),
        "raw_length": len(raw),
        "raw_data_byte_offset": registry_value_raw_data_offset(value),
        "vk_record_byte_offset": value._vkrecord.offset(),
    }
    if value.value_type_str() in ("RegSZ", "RegExpandSZ", "RegMultiSZ"):
        try:
            envelope["text"] = value.value()
        except Exception:
            envelope["text"] = None
    return envelope


def build_service_snapshot(hive_path, service_path, snapshot_id=None, label=None):
    """Build an offline record snapshot for a Windows service key."""
    from .Registry import Registry

    registry = Registry(hive_path)
    key = registry.open(service_path)
    values = {}
    for value in key.values():
        values[value.name()] = _registry_value_envelope(value)

    security_descriptor = None
    try:
        security_value = key.subkey("Security").value("Security")
        raw = security_value.raw_data()
        offset = registry_value_raw_data_offset(security_value)
        security_descriptor = {
            "kind": KIND_SECURITY_DESCRIPTOR,
            "raw_hex": raw.hex(),
            "base_byte_offset": offset,
            "source": {
                "value_name": "Security",
                "key_path": service_path + chr(92) + "Security",
                "raw_data_byte_offset": offset,
            },
        }
    except Exception:
        security_descriptor = None

    return {
        "schema": RECORD_SCHEMA,
        "snapshot_id": snapshot_id or key.name(),
        "kind": KIND_SERVICE_RECORD,
        "label": label,
        "service_path": service_path,
        "values": values,
        "security_descriptor": security_descriptor,
        "source": {
            "generator": "python-registry",
            "hive_path": hive_path,
            "service_path": service_path,
        },
    }


def _load_snapshot_item(item):
    if isinstance(item, str) and os.path.exists(item):
        return load_snapshot(item)
    return item


def compare_service_snapshots(baseline_item, candidate_item):
    baseline = _load_snapshot_item(baseline_item)
    candidate = _load_snapshot_item(candidate_item)
    changes = []
    display_changes = []
    security_changes = []

    value_names = set(baseline.get("values", {})) | set(candidate.get("values", {}))
    for name in sorted(value_names):
        old = baseline.get("values", {}).get(name)
        new = candidate.get("values", {}).get(name)
        if old is None or new is None:
            change = {
                "field": name,
                "change_type": "added" if old is None else "removed",
                "category": "service_value",
                "security_relevant": name.lower() not in SERVICE_DISPLAY_FIELDS,
            }
        elif old.get("raw_hex") != new.get("raw_hex"):
            lower_name = name.lower()
            if lower_name in SERVICE_DISPLAY_FIELDS:
                category = "display"
                security_relevant = False
                canonical = SERVICE_DISPLAY_FIELDS[lower_name]
            elif lower_name in SERVICE_IDENTITY_FIELDS:
                category = "identity"
                security_relevant = True
                canonical = SERVICE_IDENTITY_FIELDS[lower_name]
            elif lower_name in SERVICE_CONFIG_FIELDS:
                category = "service_config"
                security_relevant = True
                canonical = SERVICE_CONFIG_FIELDS[lower_name]
            else:
                category = "unreviewed_service_value"
                security_relevant = False
                canonical = None
            change = {
                "field": name,
                "canonical": canonical,
                "change_type": "modified",
                "category": category,
                "security_relevant": security_relevant,
                "baseline_text": old.get("text"),
                "candidate_text": new.get("text"),
                "baseline_raw_byte_offset": old.get("raw_data_byte_offset"),
                "candidate_raw_byte_offset": new.get("raw_data_byte_offset"),
            }
        else:
            continue
        changes.append(change)
        if change.get("category") == "display":
            display_changes.append(change)
        if change.get("security_relevant"):
            security_changes.append(change)

    sd_result = None
    unknown_versions = []
    old_sd = baseline.get("security_descriptor")
    new_sd = candidate.get("security_descriptor")
    if old_sd and new_sd:
        sd_result = SecurityDescriptor.compare_security_descriptors(
            bytes.fromhex(old_sd["raw_hex"]),
            bytes.fromhex(new_sd["raw_hex"]),
            old_sd.get("base_byte_offset", 0),
            new_sd.get("base_byte_offset", 0),
        )
        unknown_versions = sd_result.get("unknown_versions", [])
        if sd_result["permission_change"]:
            security_changes.append({
                "field": "Security",
                "canonical": "security_descriptor",
                "category": "security_descriptor",
                "security_relevant": True,
                "sd_changes": sd_result["changes"],
            })
    elif bool(old_sd) != bool(new_sd):
        security_changes.append({
            "field": "Security",
            "canonical": "security_descriptor",
            "category": "security_descriptor",
            "security_relevant": True,
            "change_type": "added" if new_sd else "removed",
        })

    raw_changed = json.dumps(baseline.get("values"), sort_keys=True) != \
        json.dumps(candidate.get("values"), sort_keys=True) or \
        (old_sd or {}).get("raw_hex") != (new_sd or {}).get("raw_hex")
    if security_changes:
        verdict = "security_change"
        permission_change = True
    elif display_changes and len(display_changes) == len(changes):
        verdict = "display_only"
        permission_change = False
    elif changes:
        verdict = "needs_review"
        permission_change = False
    else:
        verdict = "unchanged"
        permission_change = False

    if verdict == "display_only":
        summary = "display-only service field change; no security descriptor or identity value changed"
    elif verdict == "security_change":
        summary = "security descriptor or security-relevant service configuration changed"
    elif verdict == "needs_review":
        summary = "non-approved service value changed; manual review required"
    else:
        summary = "No structured service snapshot difference."

    return {
        "kind": KIND_SERVICE_RECORD,
        "baseline_snapshot_id": baseline.get("snapshot_id"),
        "candidate_snapshot_id": candidate.get("snapshot_id"),
        "verdict": verdict,
        "permission_change": permission_change,
        "security_change": bool(security_changes),
        "display_only": verdict == "display_only",
        "raw_changed": raw_changed,
        "unknown_versions": unknown_versions,
        "changes": changes,
        "display_changes": display_changes,
        "security_changes": security_changes,
        "security_descriptor_comparison": sd_result,
        "summary": summary,
    }


def coerce_parsed(item):
    if isinstance(item, dict) and "fields" in item and "raw_hex" in item:
        return item
    if isinstance(item, dict) and "semantic_signature" in item:
        return item
    if isinstance(item, dict) and "raw_hex" in item:
        snapshot = snapshot_from_dict(item)
        if snapshot["kind"] == KIND_SECURITY_DESCRIPTOR:
            return parse_security_descriptor_snapshot(
                snapshot["raw"], source=snapshot.get("source"),
                snapshot_id=snapshot.get("snapshot_id"),
                base_offset=snapshot.get("base_byte_offset", 0))
        return parse_firewall_rule(snapshot["raw"], source=snapshot.get("source"),
                                   snapshot_id=snapshot.get("snapshot_id"),
                                   base_byte_offset=snapshot.get("base_byte_offset", 0))
    if isinstance(item, (bytes, bytearray)):
        return parse_firewall_rule(bytes(item))
    if isinstance(item, str):
        if os.path.exists(item):
            return coerce_parsed(load_snapshot(item))
        return parse_firewall_rule(item)
    raise TypeError("Unsupported snapshot/rule input: %r" % type(item))


def diff_raw_bytes(baseline_raw, candidate_raw):
    baseline_bytes = bytes.fromhex(baseline_raw["raw_hex"]) if isinstance(baseline_raw, dict) else bytes(baseline_raw)
    candidate_bytes = bytes.fromhex(candidate_raw["raw_hex"]) if isinstance(candidate_raw, dict) else bytes(candidate_raw)
    hunks = []
    if len(baseline_bytes) == len(candidate_bytes):
        start = None
        for index, (left, right) in enumerate(zip(baseline_bytes, candidate_bytes)):
            if left != right and start is None:
                start = index
            elif left == right and start is not None:
                hunks.append(_byte_hunk(start, index, baseline_bytes, candidate_bytes))
                start = None
        if start is not None:
            hunks.append(_byte_hunk(start, len(baseline_bytes), baseline_bytes, candidate_bytes))
    else:
        matcher = difflib.SequenceMatcher(a=baseline_bytes, b=candidate_bytes, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                continue
            hunks.append({
                "operation": tag,
                "baseline_offset": i1,
                "baseline_length": i2 - i1,
                "candidate_offset": j1,
                "candidate_length": j2 - j1,
                "baseline_hex": baseline_bytes[i1:i2].hex(),
                "candidate_hex": candidate_bytes[j1:j2].hex(),
            })
    return hunks


def _byte_hunk(start, end, baseline_bytes, candidate_bytes):
    return {
        "operation": "replace",
        "offset": start,
        "byte_offset": start,
        "length": end - start,
        "baseline_offset": start,
        "candidate_offset": start,
        "baseline_length": end - start,
        "candidate_length": end - start,
        "baseline_hex": baseline_bytes[start:end].hex(),
        "candidate_hex": candidate_bytes[start:end].hex(),
    }


def _annotate_hunk_fields(hunks, baseline, candidate):
    fields_by_side = []
    for parsed in (baseline, candidate):
        ranges = []
        for field in parsed.get("fields", []):
            ranges.append((field["byte_offset"], field["byte_offset"] + field["byte_length"], field))
        fields_by_side.append(ranges)
    for hunk in hunks:
        offset = hunk.get("offset", hunk.get("baseline_offset", 0))
        for side_name, ranges in (("baseline_field", fields_by_side[0]), ("candidate_field", fields_by_side[1])):
            matches = [field["token"] for start, end, field in ranges if start <= offset < end]
            hunk[side_name + "s"] = matches
            if matches:
                hunk[side_name] = matches[0]
    return hunks


def _field_key(field):
    return field["token"].lower(), field.get("occurrence", 0)


def compare_firewall_rules(baseline_item, candidate_item):
    baseline = coerce_parsed(baseline_item)
    candidate = coerce_parsed(candidate_item)
    if baseline.get("kind") != KIND_FIREWALL or candidate.get("kind") != KIND_FIREWALL:
        raise TypeError("compare_firewall_rules requires firewall rule snapshots")

    baseline_fields = {_field_key(field): field for field in baseline["fields"]}
    candidate_fields = {_field_key(field): field for field in candidate["fields"]}
    changes = []

    for key in sorted(set(baseline_fields) | set(candidate_fields)):
        old = baseline_fields.get(key)
        new = candidate_fields.get(key)
        if old is None:
            changes.append(_field_change("added", None, new))
        elif new is None:
            changes.append(_field_change("removed", old, None))
        elif old.get("semantic_value") != new.get("semantic_value"):
            changes.append(_field_change("modified", old, new))
        elif old.get("value") != new.get("value"):
            change = _field_change("raw_equivalent", old, new)
            changes.append(change)

    raw_hunks = diff_raw_bytes(baseline, candidate)
    raw_hunks = _annotate_hunk_fields(raw_hunks, baseline, candidate)
    display_changes = [c for c in changes if c.get("category") == "display"]
    security_changes = [c for c in changes if c.get("security_relevant") and c["change_type"] != "raw_equivalent"]
    review_changes = [c for c in changes if c.get("category") == "unreviewed" and c["change_type"] != "raw_equivalent"]
    equivalent_raw_changes = [c for c in changes if c["change_type"] == "raw_equivalent"]

    raw_changed = baseline["raw_sha256"] != candidate["raw_sha256"]
    unknown_versions = baseline["unknown_versions"] + candidate["unknown_versions"]
    if baseline.get("version") != candidate.get("version"):
        unknown_versions.extend(candidate["unknown_versions"])

    if not raw_changed and not changes:
        verdict = "unchanged"
        permission_change = False
    elif security_changes:
        verdict = "security_change"
        permission_change = True
    elif review_changes or unknown_versions and baseline.get("version_status") == "unrecognized_version":
        verdict = "needs_review"
        permission_change = False
    elif display_changes and len(display_changes) == len([c for c in changes if c["change_type"] != "raw_equivalent"]):
        verdict = "display_only"
        permission_change = False
    elif unknown_versions:
        verdict = "unknown_version_change"
        permission_change = False
    elif equivalent_raw_changes and not any(c["change_type"] != "raw_equivalent" for c in changes):
        verdict = "semantically_equivalent_raw_change"
        permission_change = False
    else:
        verdict = "structured_change"
        permission_change = False

    return {
        "kind": KIND_FIREWALL,
        "baseline_snapshot_id": baseline.get("snapshot_id"),
        "candidate_snapshot_id": candidate.get("snapshot_id"),
        "verdict": verdict,
        "permission_change": permission_change,
        "security_change": bool(security_changes),
        "display_only": verdict == "display_only",
        "raw_changed": raw_changed,
        "unknown_versions": unknown_versions,
        "approved_field_changes": [c for c in changes if c.get("approved")],
        "approved_checked_field_changes": [c for c in changes if c.get("approved")],
        "unapproved_field_changes": [c for c in changes if not c.get("approved")],
        "display_changes": display_changes,
        "security_changes": security_changes,
        "review_changes": review_changes,
        "changes": changes,
        "raw_byte_changes": raw_hunks,
        "byte_offset_changes": raw_hunks,
        "raw_byte_offsets": candidate["raw_byte_offsets"],
        "byte_offsets": candidate["raw_byte_offsets"],
        "baseline": baseline,
        "candidate": candidate,
        "summary": summarize_comparison(verdict, display_changes, security_changes, review_changes, unknown_versions),
    }


def _field_change(change_type, old, new):
    chosen = new or old
    return {
        "change_type": change_type,
        "token": chosen.get("token"),
        "canonical": chosen.get("canonical"),
        "label": chosen.get("label"),
        "category": chosen.get("category"),
        "approved": chosen.get("approved"),
        "security_relevant": chosen.get("security_relevant"),
        "baseline_value": old.get("semantic_value") if old else None,
        "candidate_value": new.get("semantic_value") if new else None,
        "baseline_raw_value": old.get("value") if old else None,
        "candidate_raw_value": new.get("value") if new else None,
        "baseline_byte_offset": old.get("byte_offset") if old else None,
        "candidate_byte_offset": new.get("byte_offset") if new else None,
        "baseline_absolute_byte_offset": old.get("absolute_byte_offset") if old else None,
        "candidate_absolute_byte_offset": new.get("absolute_byte_offset") if new else None,
        "baseline_value_byte_offset": old.get("value_byte_offset") if old else None,
        "candidate_value_byte_offset": new.get("value_byte_offset") if new else None,
        "baseline_value_absolute_byte_offset": old.get("value_absolute_byte_offset") if old else None,
        "candidate_value_absolute_byte_offset": new.get("value_absolute_byte_offset") if new else None,
        "aliases": chosen.get("aliases", []),
        "references": chosen.get("references", []),
    }


def summarize_comparison(verdict, display_changes, security_changes, review_changes, unknown_versions):
    if verdict == "unchanged":
        return "No raw or structured differences."
    parts = []
    if display_changes:
        names = ", ".join(sorted(set(c["canonical"] for c in display_changes)))
        parts.append("display-only field change in %s" % names)
    if security_changes:
        names = ", ".join(sorted(set(c["canonical"] for c in security_changes)))
        parts.append("security-relevant change in %s" % names)
    if review_changes:
        names = ", ".join(sorted(set(c["canonical"] for c in review_changes)))
        parts.append("unreviewed field change in %s; manual review required" % names)
    if unknown_versions:
        versions = ", ".join(sorted(set(v.get("version") or v.get("token") or "?" for v in unknown_versions)))
        parts.append("unknown schema version %s tracked separately" % versions)
    if verdict == "display_only":
        parts.append("raw bytes differ, but no permission/security field changed")
    elif verdict == "security_change":
        parts.append("this is a real security/policy change, not a display-only edit")
    return "; ".join(parts)


def compare_snapshots(baseline, candidate):
    """Dispatch snapshot comparison by declared/parsed kind."""
    baseline = _load_snapshot_item(baseline)
    candidate = _load_snapshot_item(candidate)
    if isinstance(baseline, dict) and baseline.get("kind") == KIND_SERVICE_RECORD:
        return compare_service_snapshots(baseline, candidate)
    baseline_parsed = coerce_parsed(baseline)
    candidate_parsed = coerce_parsed(candidate)
    if baseline_parsed.get("kind") == KIND_SECURITY_DESCRIPTOR:
        return SecurityDescriptor.compare_security_descriptors(
            bytes.fromhex(baseline_parsed["raw_hex"]),
            bytes.fromhex(candidate_parsed["raw_hex"]),
            baseline_parsed.get("base_byte_offset", 0),
            candidate_parsed.get("base_byte_offset", 0),
        )
    return compare_firewall_rules(baseline_parsed, candidate_parsed)


def comparison_to_json(result, path=None):
    text_output = json.dumps(result, indent=2, sort_keys=False, ensure_ascii=False)
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text_output)
            handle.write("\n")
    return text_output


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Structured offline registry snapshot comparison")
    parser.add_argument("baseline", help="baseline snapshot JSON")
    parser.add_argument("candidate", help="candidate snapshot JSON")
    parser.add_argument("--json", action="store_true", help="print full JSON result")
    args = parser.parse_args(argv)

    result = compare_snapshots(args.baseline, args.candidate)
    if args.json:
        print(comparison_to_json(result))
    else:
        print("%s: %s" % (result.get("verdict"), result.get("summary", "")))
        print("permission_change=%s raw_changed=%s" % (
            result.get("permission_change"), result.get("raw_changed")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
