"""
Read-only audit of Mach-O version load commands against a release
declaration.

The lab use case: a batch of offline macOS artifacts claims a target
platform and minimum system version at release time.  This module
checks every architecture slice of a Mach-O file (fat or thin)
against that external declaration without modifying the file.

Every version-related load command (``LC_VERSION_MIN_*`` and
``LC_BUILD_VERSION``) is reported with its original location: the
index of the load command in the slice and its absolute file offset.

A command is *decodable* when macholib's decoded view (``describe()``)
yields a version.  ``LC_BUILD_VERSION`` currently decodes to an empty
dict, so a slice that only carries ``LC_BUILD_VERSION`` cannot be
judged and is set aside for manual review, as is any slice whose
platform disagrees with the declaration.
"""

from __future__ import print_function

from .mach_o import (
    CPU_TYPE_NAMES,
    LC_BUILD_VERSION,
    LC_NAMES,
    LC_VERSION_MIN_IPHONEOS,
    LC_VERSION_MIN_MACOSX,
    LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
)
from .MachO import MachO
from .ptypes import sizeof

__all__ = [
    "STATUS_BELOW_MINIMUM",
    "STATUS_COVERED",
    "STATUS_NO_VERSION_COMMAND",
    "STATUS_PLATFORM_MISMATCH",
    "STATUS_UNDETERMINABLE",
    "audit_file",
    "audit_macho",
    "normalize_platform",
    "parse_version",
]

STATUS_COVERED = "covered"
STATUS_BELOW_MINIMUM = "below_minimum"
STATUS_PLATFORM_MISMATCH = "platform_mismatch"
STATUS_UNDETERMINABLE = "undeterminable"
STATUS_NO_VERSION_COMMAND = "no_version_command"

# Platforms implied by the legacy LC_VERSION_MIN_* commands.
_VERSION_MIN_PLATFORMS = {
    LC_VERSION_MIN_MACOSX: "macOS",
    LC_VERSION_MIN_IPHONEOS: "iOS",
    LC_VERSION_MIN_TVOS: "tvOS",
    LC_VERSION_MIN_WATCHOS: "watchOS",
}

_VERSION_COMMANDS = frozenset(list(_VERSION_MIN_PLATFORMS) + [LC_BUILD_VERSION])

_PLATFORM_ALIASES = {
    "macos": "macOS",
    "macosx": "macOS",
    "osx": "macOS",
    "ios": "iOS",
    "tvos": "tvOS",
    "watchos": "watchOS",
}


def normalize_platform(platform):
    """
    Return the canonical name for *platform*, raising ValueError for
    names that cannot be matched to a known platform.
    """
    canonical = _PLATFORM_ALIASES.get(str(platform).strip().lower())
    if canonical is None:
        raise ValueError("Unknown platform: %r" % (platform,))
    return canonical


def parse_version(text):
    """
    Parse a dotted version string such as "10.15.3" into a tuple of
    integers, padded to at least three components.
    """
    parts = []
    for component in str(text).split("."):
        component = component.strip()
        if not component.isdigit():
            raise ValueError("Invalid version component: %r" % (text,))
        parts.append(int(component))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _version_command_records(header):
    """
    Collect the version-related load commands of *header* (a
    MachOHeader), keeping each command's original location.
    """
    records = []
    file_offset = header.offset + sizeof(header.mach_header)
    for index, (cmd_load, cmd_cmd, _data) in enumerate(header.commands):
        cmd = cmd_load.cmd
        if cmd in _VERSION_COMMANDS:
            decoded = cmd_cmd.describe()
            record = {
                "command_index": index,
                "file_offset": file_offset,
                "cmd": LC_NAMES.get(cmd, "0x%x" % (cmd,)),
                "decodable": False,
                "platform": None,
                "version": None,
                "sdk": None,
            }
            if cmd in _VERSION_MIN_PLATFORMS and "version" in decoded:
                record.update(
                    decodable=True,
                    platform=_VERSION_MIN_PLATFORMS[cmd],
                    version=decoded["version"],
                    sdk=decoded.get("sdk"),
                )
            records.append(record)
        file_offset += cmd_load.cmdsize
    return records


def _audit_slice(header, declaration):
    cputype = int(header.header.cputype)
    records = _version_command_records(header)
    effective = None
    for record in records:
        if record["decodable"]:
            effective = record
            break

    result = {
        "arch": CPU_TYPE_NAMES.get(cputype, "0x%x" % (cputype,)),
        "offset": header.offset,
        "size": header.size,
        "commands": records,
        "effective": effective,
        "status": None,
        "covered": False,
        "needs_review": False,
    }

    if not records:
        result.update(status=STATUS_NO_VERSION_COMMAND, needs_review=True)
    elif effective is None:
        # Only undeterminable version fields (e.g. a lone
        # LC_BUILD_VERSION) remain: set aside for manual review.
        result.update(status=STATUS_UNDETERMINABLE, needs_review=True)
    elif effective["platform"] != declaration["platform"]:
        result.update(status=STATUS_PLATFORM_MISMATCH, needs_review=True)
    elif parse_version(effective["version"]) >= declaration["min_version"]:
        result.update(status=STATUS_COVERED, covered=True)
    else:
        result.update(status=STATUS_BELOW_MINIMUM)
    return result


def audit_macho(macho, platform, min_version):
    """
    Audit an already-opened :class:`macholib.MachO.MachO` against the
    release declaration (*platform*, *min_version*).

    Returns a report with one entry per architecture slice.  A slice
    is ``covered`` when its effective version command matches the
    declared platform and its version is at least *min_version*.
    Slices with a mismatched platform or only undeterminable version
    fields are flagged with ``needs_review``.
    """
    declaration = {
        "platform": normalize_platform(platform),
        "min_version": parse_version(min_version),
    }
    slices = [_audit_slice(header, declaration) for header in macho.headers]
    return {
        "filename": macho.filename,
        "declaration": {
            "platform": declaration["platform"],
            "min_version": ".".join(str(v) for v in declaration["min_version"]),
        },
        "slices": slices,
        "covered_arches": [s["arch"] for s in slices if s["covered"]],
        "review_arches": [s["arch"] for s in slices if s["needs_review"]],
    }


def audit_file(filename, platform, min_version):
    """
    Open *filename* read-only and audit it against the release
    declaration (*platform*, *min_version*).  See :func:`audit_macho`.
    """
    return audit_macho(MachO(filename), platform, min_version)
