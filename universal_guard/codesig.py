"""Parser for the embedded code signature (CS_* SuperBlob).

The release pipeline performs the actual signature verification.  This
module only explains the contents of a slice so that a caller-supplied
verification result can be bound to a concrete CodeDirectory hash and to
the digest of the concrete slice that was inspected.
"""

import hashlib
import struct

from .models import CodeSignatureInfo

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02

CSSLOT_CODEDIRECTORY = 0
CSSLOT_INFOSLOT = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_RESOURCEDIR = 3
CSSLOT_APPLICATION = 4
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_SIGNATURESLOT = 0x10000

HASHER_NAMES = {
    1: "sha1",
    2: "sha256",
    3: "sha256-truncated",
    4: "sha384",
}

CS_FLAGS = {
    0x1: "CS_VALID",
    0x2: "CS_ADHOC",
    0x4: "CS_GET_TASK_ALLOW",
    0x8: "CS_INSTALLER",
    0x10: "CS_FORCE_HARD",
    0x100: "CS_FORCE_KILL",
    0x200: "CS_FORCE_EXPIRATION",
    0x400: "CS_RESTRICT",
    0x800: "CS_REQUIRE_LV",
    0x1000: "CS_PLATFORM_BINARY",
    0x2000: "CS_SETUID",
    0x4000: "CS_RUNTIME",
    0x8000: "CS_INHERIT",
    0x40000: "CS_EXEC_SET_HARD",
    0x80000: "CS_EXEC_SET_KILL",
    0x100000: "CS_KILL",
    0x200000: "CS_DYLD_PLATFORM",
}


def _u32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]


def _flag_names(flags):
    return tuple(sorted(
        name for bit, name in CS_FLAGS.items() if flags & bit
    ))


def parse_code_signature(blob, dataoff=None, datasize=None):
    if not blob or len(blob) < 8:
        return CodeSignatureInfo(
            present=False, dataoff=dataoff, datasize=datasize
        )
    if _u32(blob, 0) != CSMAGIC_EMBEDDED_SIGNATURE:
        return CodeSignatureInfo(
            present=False, dataoff=dataoff, datasize=datasize
        )

    count = _u32(blob, 8)
    slot_types = []
    codedirectory = None
    for index in range(count):
        entry = 12 + index * 8
        slot_type = _u32(blob, entry)
        offset = _u32(blob, entry + 4)
        slot_types.append(slot_type)
        if slot_type == CSSLOT_CODEDIRECTORY and offset < len(blob):
            codedirectory = _parse_code_directory(blob[offset:])

    has_cms = CSSLOT_SIGNATURESLOT in slot_types
    has_entitlements = any(
        slot in slot_types
        for slot in (CSSLOT_ENTITLEMENTS, CSSLOT_DER_ENTITLEMENTS)
    )
    if codedirectory is None:
        return CodeSignatureInfo(
            present=True,
            dataoff=dataoff,
            datasize=datasize,
            has_cms_signature=has_cms,
            has_entitlements=has_entitlements,
        )

    flags = codedirectory["flags"]
    flag_names = _flag_names(flags)
    return CodeSignatureInfo(
        present=True,
        dataoff=dataoff,
        datasize=datasize,
        has_code_directory=True,
        cdhash_algorithm=codedirectory["hash_algorithm"],
        cdhash=codedirectory["cdhash"],
        flags=flags,
        flag_names=flag_names,
        identifier=codedirectory["identifier"],
        team_id=codedirectory["team_id"] or None,
        has_cms_signature=has_cms,
        has_entitlements=has_entitlements,
        adhoc=bool(flags & 0x2) or not has_cms,
    )


def _parse_code_directory(data):
    if _u32(data, 0) != CSMAGIC_CODEDIRECTORY or len(data) < 44:
        return None
    length = _u32(data, 4)
    version = _u32(data, 8)
    flags = _u32(data, 12)
    ident_offset = _u32(data, 20)
    # CodeDirectory scalar layout changed between versions 0x20200 and
    # 0x20400: the hash fields live at byte 36 in the newer layout and at
    # byte 40 in the older one, and teamOffset moved from 44 to 48.
    if version >= 0x20400:
        hash_size = data[36]
        hash_type = data[37]
        platform = data[38]
        team_offset_field = 48
    else:
        hash_size = data[40]
        hash_type = data[41]
        platform = data[42]
        team_offset_field = 44
    if length > len(data):
        length = len(data)

    algorithm = HASHER_NAMES.get(hash_type, "unknown:%d" % hash_type)
    cdhash = _compute_cdhash(data, length, algorithm, hash_size)
    identifier = _read_cstring(data, ident_offset)
    team_id = ""
    if version >= 0x20200:
        team_offset = struct.unpack_from(">I", data, team_offset_field)[0]
        team_id = _read_cstring(data, team_offset)

    return {
        "flags": flags,
        "cdhash": cdhash,
        "hash_algorithm": algorithm,
        "identifier": identifier,
        "team_id": team_id,
        "version": version,
        "platform": platform,
    }


def _compute_cdhash(data, length, algorithm, hash_size):
    directory = data[:length]
    if algorithm == "sha1":
        return hashlib.sha1(directory).hexdigest()
    if algorithm == "sha256":
        return hashlib.sha256(directory).hexdigest()
    if algorithm == "sha256-truncated":
        truncated = hash_size or 20
        return hashlib.sha256(directory).digest()[:truncated].hex()
    if algorithm == "sha384":
        return hashlib.sha384(directory).hexdigest()
    return ""


def _read_cstring(data, offset):
    if offset <= 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    try:
        return data[offset:end].decode("utf-8")
    except UnicodeDecodeError:
        return data[offset:end].decode("latin-1")
