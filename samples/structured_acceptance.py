#!/usr/bin/env python
"""Generate offline snapshots used by the structured-comparison acceptance.

The source hive is read with python-registry.  Variants are same-length edits,
so raw offsets remain stable and the report can focus on semantic classification.
"""
from __future__ import print_function

import json
import os
import sys
import copy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from Registry import Registry
from Registry.StructuredComparison import (
    KIND_FIREWALL,
    SNAPSHOT_SCHEMA,
    build_service_snapshot,
    make_snapshot,
    registry_value_raw_data_offset,
)


HIVE = os.path.join(ROOT, "testing", "reg_samples", "new_log_1", "SYSTEM")
KEY_PATH = r"ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
VALUE_NAME = "WirelessDisplay-In-TCP"
SERVICE_PATH = r"ControlSet001\Services\RasMan"
OUT_DIR = os.path.join(ROOT, "acceptance", "snapshots")


def variant_raw(raw, replacements):
    text = raw.decode("utf-16-le")
    for old, new in replacements:
        if old not in text:
            raise RuntimeError("expected text not found: %r" % old)
        text = text.replace(old, new, 1)
    return text.encode("utf-16-le")


def write_snapshot(filename, snapshot):
    if not os.path.isdir(OUT_DIR):
        os.makedirs(OUT_DIR)
    path = os.path.join(OUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return path


def patch_utf16_hex(raw_hex, old, new):
    raw = bytes.fromhex(raw_hex)
    updated = variant_raw(raw, [(old, new)])
    return updated.hex()


def build_service_fixtures():
    baseline = build_service_snapshot(
        HIVE, SERVICE_PATH, snapshot_id="service-rasman-baseline",
        label="Observed RasMan service key with security descriptor")
    baseline["source"]["hive_path"] = os.path.relpath(HIVE, ROOT)

    display_name = copy.deepcopy(baseline)
    display_name["snapshot_id"] = "service-rasman-display-name-only"
    display_name["label"] = "RasMan DisplayName resource identifier changed"
    display_name["values"]["DisplayName"]["raw_hex"] = patch_utf16_hex(
        display_name["values"]["DisplayName"]["raw_hex"], "-200", "-299")
    display_name["values"]["DisplayName"]["text"] = \
        bytes.fromhex(display_name["values"]["DisplayName"]["raw_hex"]).decode("utf-16-le").rstrip("\x00")

    display_desc = copy.deepcopy(baseline)
    display_desc["snapshot_id"] = "service-rasman-display-description-only"
    display_desc["label"] = "RasMan Description resource identifier changed"
    display_desc["values"]["Description"]["raw_hex"] = patch_utf16_hex(
        display_desc["values"]["Description"]["raw_hex"], "-201", "-298")
    display_desc["values"]["Description"]["text"] = \
        bytes.fromhex(display_desc["values"]["Description"]["raw_hex"]).decode("utf-16-le").rstrip("\x00")

    security = copy.deepcopy(baseline)
    security["snapshot_id"] = "service-rasman-security-dacl-bit"
    security["label"] = "One RasMan DACL access-mask bit changed"
    sd = bytearray.fromhex(security["security_descriptor"]["raw_hex"])
    sd[32] ^= 0x10
    security["security_descriptor"]["raw_hex"] = bytes(sd).hex()

    return [
        ("service-rasman-baseline.json", baseline),
        ("service-rasman-display-name.json", display_name),
        ("service-rasman-display-description.json", display_desc),
        ("service-rasman-security-dacl.json", security),
    ]


def main():
    registry = Registry.Registry(HIVE)
    value = registry.open(KEY_PATH).value(VALUE_NAME)
    raw = value.raw_data()
    raw_offset = registry_value_raw_data_offset(value)
    base_source = {
        "generator": "samples/structured_acceptance.py",
        "hive": os.path.relpath(HIVE, ROOT),
        "key_path": KEY_PATH,
        "value_name": VALUE_NAME,
        "value_type": value.value_type_str(),
        "vk_record_byte_offset": value._vkrecord.offset(),
        "raw_data_byte_offset": raw_offset,
    }

    baseline = make_snapshot(
        raw,
        snapshot_id="firewall-baseline",
        label="Observed Wireless Display firewall rule",
        kind=KIND_FIREWALL,
        source=dict(base_source, provenance="observed in offline hive"),
        base_byte_offset=raw_offset,
    )
    baseline["schema"] = SNAPSHOT_SCHEMA

    display_name_raw = variant_raw(raw, [("@wifidisplay.dll,-10200", "@wifidisplay.dll,-10299")])
    display_name = make_snapshot(
        display_name_raw,
        snapshot_id="firewall-display-name-only",
        label="Display Name resource identifier changed",
        kind=KIND_FIREWALL,
        source=dict(base_source, derived_from="firewall-baseline", edit="Name resource id"),
        base_byte_offset=raw_offset,
    )

    display_desc_raw = variant_raw(raw, [("@wifidisplay.dll,-10201", "@wifidisplay.dll,-10298")])
    display_desc = make_snapshot(
        display_desc_raw,
        snapshot_id="firewall-display-description-only",
        label="Display Description resource identifier changed",
        kind=KIND_FIREWALL,
        source=dict(base_source, derived_from="firewall-baseline", edit="Desc resource id"),
        base_byte_offset=raw_offset,
    )

    security_raw = variant_raw(raw, [("Action=Allow", "Action=Block")])
    security = make_snapshot(
        security_raw,
        snapshot_id="firewall-security-action-block",
        label="Firewall action changed from Allow to Block",
        kind=KIND_FIREWALL,
        source=dict(base_source, derived_from="firewall-baseline", edit="Action Allow -> Block"),
        base_byte_offset=raw_offset,
    )

    for filename, snapshot in [
        ("firewall-rule-baseline.json", baseline),
        ("firewall-rule-display-name.json", display_name),
        ("firewall-rule-display-description.json", display_desc),
        ("firewall-rule-security-action.json", security),
    ]:
        print(write_snapshot(filename, snapshot))

    for filename, snapshot in build_service_fixtures():
        print(write_snapshot(filename, snapshot))


if __name__ == "__main__":
    main()
