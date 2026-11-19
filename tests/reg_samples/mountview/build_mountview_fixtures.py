#!/usr/bin/env python
"""
Build the three miniature registry hives used by the MountView tests.

The hives are intentionally tiny, but structurally valid: every one parses
through the unchanged python-registry Registry API. They contain ordinary
keys, ordinary values and symbolic link keys (a RegLink value) so that the
offline mount view can be exercised against real binary hives rather than
mocked objects.

Run this module to (re)generate the .hive files next to this script:

    python build_mountview_fixtures.py
"""
from __future__ import print_function

import os

from Registry import Registry
from Registry.hivebuild import HiveBuilder


HERE = os.path.dirname(os.path.abspath(__file__))

REG_SZ = 0x1
REG_LINK = 0x6


def _link(target):
    return (REG_LINK, (target + "\x00").encode("utf-16le"))


def build_system_hive():
    """
    Evidence EV-SYSTEM. Holds an ordinary key/value and a legal symbolic
    link that crosses into the SOFTWARE mount.
    """
    builder = HiveBuilder(
        evidence_id="EV-SYSTEM",
        internal_hive_name="\\??\\C:\\config\\SYSTEM",
        root_name="CMI-CreateHive{11111111-1111-1111-1111-111111111111}")

    builder.add_key(
        ["ControlSet001", "Control", "ProductOptions"],
        values=[("ProductType", REG_SZ, "WinNT\x00".encode("utf-16le"))])
    builder.add_key(
        ["ControlSet001", "Control", "NetworkProvider"],
        values=[("SymbolicLink",) + _link(
            "\\HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
            "NetworkProvider")])
    return builder.build()


def build_software_hive():
    """
    Evidence EV-SOFTWARE. Hosts the legal cross-mount target, a link to an
    unmounted target, and two keys that form an intra-hive link cycle.
    """
    builder = HiveBuilder(
        evidence_id="EV-SOFTWARE",
        internal_hive_name="\\??\\C:\\config\\SOFTWARE",
        root_name="CMI-CreateHive{22222222-2222-2222-2222-222222222222}")

    builder.add_key(
        ["Microsoft", "Windows", "CurrentVersion", "NetworkProvider"],
        values=[("ProviderOrder", REG_SZ, "lanmanworkstation\x00".encode(
            "utf-16le"))])

    builder.add_key(
        ["Microsoft", "Windows", "CurrentVersion", "RunOnce"],
        values=[("SymbolicLink",) + _link("\\HKU\\NOT-MOUNTED\\Missing")])

    builder.add_key(
        ["Policies", "CycleA"],
        values=[("SymbolicLink",) + _link("\\HKLM\\SOFTWARE\\Policies\\CycleB")])
    builder.add_key(
        ["Policies", "CycleB"],
        values=[("SymbolicLink",) + _link("\\HKLM\\SOFTWARE\\Policies\\CycleA")])
    return builder.build()


def build_ntuser_hive():
    """
    Evidence EV-NTUSER-ALICE. Demonstrates same-name shadowing (a link key
    named like an ordinary key living in another hive), a second unmounted
    target, and an intra-hive cycle.
    """
    builder = HiveBuilder(
        evidence_id="EV-NTUSER-ALICE",
        internal_hive_name="\\??\\C:\\Users\\alice\\ntuser.dat",
        root_name="CMI-CreateHive{33333333-3333-3333-3333-333333333333}")

    builder.add_key(
        ["Software", "Microsoft", "Windows", "CurrentVersion", "Run"],
        values=[("startup", REG_SZ, "notepad.exe\x00".encode("utf-16le"))])

    # Alice has her own, ordinary NetworkProvider key (local evidence).
    builder.add_key(
        ["Software", "NetworkProvider"],
        values=[("LocalNote", REG_SZ,
                 "alice-local-network-provider\x00".encode("utf-16le"))])

    # A same-name impostor lives one level down: it is a symbolic link that
    # resolves to the identically named, ordinary key inside the SOFTWARE
    # evidence. A direct read stays with Alice; following the link silently
    # crosses onto a different piece of material, so it is NAME_SHADOWED.
    builder.add_key(
        ["Software", "Policy", "NetworkProvider"],
        values=[("SymbolicLink",) + _link(
            "\\HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
            "NetworkProvider")])

    builder.add_key(
        ["Software", "Dangling"],
        values=[("SymbolicLink",) + _link("\\HKU\\.DEFAULT\\Absent")])

    builder.add_key(
        ["Software", "LoopA"],
        values=[("SymbolicLink",) + _link("\\HKU\\alice\\Software\\LoopB")])
    builder.add_key(
        ["Software", "LoopB"],
        values=[("SymbolicLink",) + _link("\\HKU\\alice\\Software\\LoopA")])
    return builder.build()


def main():
    fixtures = (
        ("mini_system.hive", build_system_hive()),
        ("mini_software.hive", build_software_hive()),
        ("mini_ntuser.hive", build_ntuser_hive()),
    )
    for filename, blob in fixtures:
        path = os.path.join(HERE, filename)
        with open(path, "wb") as output:
            output.write(blob)
        # Sanity check: every generated hive parses through the original API.
        Registry.Registry(path).root()
        print("wrote", path, len(blob), "bytes")


if __name__ == "__main__":
    main()
