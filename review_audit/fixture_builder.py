"""Build a tiny ECMA-335 assembly used by the review provenance acceptance.

The generated file is metadata-rich but deliberately dependency-free and does
not require dotnet/csc.  It is sufficient for offline dnfile parsing.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


SECTION_RVA = 0x2000
SECTION_RAW_OFFSET = 0x200
METADATA_OFFSET = 0x80


class StringHeap:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")

    def add(self, value: str) -> int:
        if not value:
            return 0
        offset = len(self.data)
        self.data.extend(value.encode("utf-8"))
        self.data.append(0)
        return offset


class BlobHeap:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")

    def add(self, value: bytes) -> int:
        offset = len(self.data)
        size = len(value)
        if size < 0x80:
            length = bytes([size])
        elif size < 0x4000:
            length = bytes([0x80 | (size >> 8), size & 0xFF])
        else:
            length = bytes(
                [
                    0xC0 | ((size >> 24) & 0x1F),
                    (size >> 16) & 0xFF,
                    (size >> 8) & 0xFF,
                    size & 0xFF,
                ]
            )
        self.data.extend(length)
        self.data.extend(value)
        return offset


TYPE_DEF_OR_REF = {"TypeDef": 0, "TypeRef": 1, "TypeSpec": 2}
MEMBER_REF_PARENT = {
    "TypeDef": 0,
    "TypeRef": 1,
    "ModuleRef": 2,
    "MethodDef": 3,
    "TypeSpec": 4,
}
HAS_CUSTOM_ATTRIBUTE = {
    "MethodDef": 0,
    "Field": 1,
    "TypeRef": 2,
    "TypeDef": 3,
    "Param": 4,
    "InterfaceImpl": 5,
    "MemberRef": 6,
}
CUSTOM_ATTRIBUTE_TYPE = {"MethodDef": 2, "MemberRef": 3}
METHOD_DEF_OR_REF = {"MethodDef": 0, "MemberRef": 1}
RESOLUTION_SCOPE = {"Module": 0, "ModuleRef": 1, "AssemblyRef": 2, "TypeRef": 3}
TYPE_OR_METHOD_DEF = {"TypeDef": 0, "MethodDef": 1}


def coded_index(kind: Dict[str, int], table: str, row_id: int, tag_bits: int) -> int:
    return (row_id << tag_bits) | kind[table]


def method_sig(has_this: bool = True, param_count: int = 0) -> bytes:
    calling_convention = 0x20 if has_this else 0x00
    return bytes([calling_convention, param_count, 0x01])


def attribute_blob(statement: str) -> bytes:
    value = statement.encode("utf-8")
    # CA prolog 0x0001, one SerString fixed arg, zero named args.
    return b"\x01\x00" + bytes([len(value)]) + value + b"\x00\x00"


def generic_instance_blob(type_def_row: int, argument_element_type: int) -> bytes:
    type_def_or_ref = (type_def_row << 2) | TYPE_DEF_OR_REF["TypeDef"]
    return bytes(
        [
            0x15,  # GENERICINST
            0x12,  # CLASS
            type_def_or_ref,
            0x01,  # one generic argument
            argument_element_type,
        ]
    )


def build_metadata() -> bytes:
    strings = StringHeap()
    blobs = BlobHeap()
    rows: Dict[int, List[bytes]] = {}

    def row(table: int, data: bytes) -> None:
        rows.setdefault(table, []).append(data)

    def s(value: str) -> int:
        return strings.add(value)

    def b(value: bytes) -> int:
        return blobs.add(value)

    module_name = s("ReviewSample.dll")
    row(0, struct.pack("<HHHHH", 0, module_name, 1, 0, 0))

    missing_scope = coded_index(RESOLUTION_SCOPE, "AssemblyRef", 1, 2)
    row(
        1,
        struct.pack(
            "<HHH",
            missing_scope,
            s("ISecure"),
            s("Missing.Contracts"),
        ),
    )

    type_defs: Sequence[Tuple[str, str, int, int, int]] = [
        ("<Module>", "", 0, 1, 1),
        ("ConfidentialAttribute", "ReviewAudit", 0, 1, 1),
        ("IConfidential", "ReviewAudit", 0, 2, 2),
        ("Box`1", "ReviewAudit", 0, 3, 3),
        ("IntBox", "ReviewAudit", coded_index(TYPE_DEF_OR_REF, "TypeSpec", 1, 2), 4, 4),
        ("StringBox", "ReviewAudit", coded_index(TYPE_DEF_OR_REF, "TypeSpec", 2, 2), 4, 4),
        ("ExplicitEndpoint", "ReviewAudit", 0, 5, 5),
    ]
    type_flags = [0, 0x100001, 0x000000A1, 0x100001, 0x100001, 0x100101, 0x100001]
    for flags, (name, namespace, extends, field_start, method_start) in zip(
        type_flags, type_defs
    ):
        row(
            2,
            struct.pack(
                "<IHHHHH",
                flags,
                s(name),
                s(namespace),
                extends,
                field_start,
                method_start,
            ),
        )

    void_method_sig = b(method_sig())
    ctor_sig = b(method_sig(param_count=1) + b"\x0e")
    method_rvas = [SECTION_RVA + 80, 0, SECTION_RVA + 84, SECTION_RVA + 88, SECTION_RVA + 92]
    method_flags = [0x1886, 0x05C6, 0x01C6, 0x00C6, 0x00E1]
    method_names = [".ctor", "Confirm", "Read", "Write", "ConfirmExplicit"]
    method_sigs = [ctor_sig, void_method_sig, void_method_sig, void_method_sig, void_method_sig]
    for rva, flags, name, signature in zip(
        method_rvas, method_flags, method_names, method_sigs
    ):
        row(6, struct.pack("<IHHHHH", rva, 0, flags, s(name), signature, 1))

    row(9, struct.pack("<HH", 7, coded_index(TYPE_DEF_OR_REF, "TypeDef", 3, 2)))

    member_refs = [
        ("TypeDef", 5, "Read"),
        ("TypeDef", 6, "Write"),
        ("TypeRef", 1, "Mark"),
        ("TypeSpec", 1, "Read"),
        ("TypeSpec", 2, "Write"),
    ]
    for parent_table, parent_id, name in member_refs:
        parent = coded_index(MEMBER_REF_PARENT, parent_table, parent_id, 3)
        row(10, struct.pack("<HHH", parent, s(name), void_method_sig))

    statement_blob = b(attribute_blob("CONFIDENTIAL-REVIEW-016"))
    attribute_ctor = coded_index(CUSTOM_ATTRIBUTE_TYPE, "MethodDef", 1, 3)
    for owner_id in (3, 4, 2):
        parent = coded_index(HAS_CUSTOM_ATTRIBUTE, "MethodDef", owner_id, 5)
        row(12, struct.pack("<HHH", parent, attribute_ctor, statement_blob))

    body = coded_index(METHOD_DEF_OR_REF, "MethodDef", 5, 1)
    declaration = coded_index(METHOD_DEF_OR_REF, "MethodDef", 2, 1)
    row(25, struct.pack("<HHH", 7, body, declaration))

    int_spec = b(generic_instance_blob(4, 0x08))
    string_spec = b(generic_instance_blob(4, 0x0E))
    row(27, struct.pack("<H", int_spec))
    row(27, struct.pack("<H", string_spec))

    row(
        32,
        struct.pack(
            "<IHHHHIHHH",
            0x8004,
            1,
            0,
            0,
            0,
            0,
            0,
            s("ReviewSample"),
            0,
        ),
    )

    row(
        35,
        struct.pack(
            "<HHHHIHHHH",
            1,
            0,
            0,
            0,
            0,
            0,
            s("Missing.Contracts"),
            0,
            0,
        ),
    )

    owner_type = coded_index(TYPE_OR_METHOD_DEF, "TypeDef", 4, 1)
    row(42, struct.pack("<HHHH", 0, 0, owner_type, s("T")))
    constraint = coded_index(TYPE_DEF_OR_REF, "TypeRef", 1, 2)
    row(44, struct.pack("<HH", 1, constraint))

    return pack_metadata_tables(strings, blobs, rows)


def pack_metadata_tables(
    strings: StringHeap, blobs: BlobHeap, rows: Dict[int, List[bytes]]
) -> bytes:
    table_numbers = sorted(rows)
    valid_mask = 0
    for number in table_numbers:
        valid_mask |= 1 << number

    header = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, 0)
    counts = b"".join(struct.pack("<I", len(rows[number])) for number in table_numbers)
    table_data = b"".join(b"".join(rows[number]) for number in table_numbers)
    tables_stream = header + counts + table_data

    version = b"v4.0.30319\x00\x00"
    root_prefix = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version))
    root_prefix += version
    root_prefix += struct.pack("<HH", 0, 4)

    def stream_header(offset: int, name: str, size: int) -> bytes:
        name_bytes = name.encode("ascii") + b"\x00"
        name_bytes += b"\x00" * ((4 - len(name_bytes) % 4) % 4)
        return struct.pack("<II", offset, size) + name_bytes

    stream_payloads = (
        ("#~", tables_stream),
        ("#Strings", bytes(strings.data)),
        ("#GUID", bytes(16)),
        ("#Blob", bytes(blobs.data)),
    )
    header_length = 0
    for name, payload in stream_payloads:
        header_length += len(stream_header(0, name, len(payload)))
    data_offset = len(root_prefix) + header_length
    current_offset = data_offset
    chunks: List[bytes] = []
    for name, payload in stream_payloads:
        header = stream_header(current_offset, name, len(payload))
        chunks.append(header)
        padding = (-len(payload)) % 4
        current_offset += len(payload) + padding

    root = bytearray(root_prefix + b"".join(chunks))
    if len(root) != data_offset:
        raise AssertionError((len(root), data_offset))
    for _, payload in stream_payloads:
        root.extend(payload)
        root.extend(b"\x00" * ((-len(payload)) % 4))
    return bytes(root)


def build_pe() -> bytes:
    metadata = build_metadata()
    section = bytearray(max(METADATA_OFFSET + len(metadata), 0x200))

    for offset, body in {80: b"\x06\x2a", 84: b"\x06\x2a", 88: b"\x06\x2a", 92: b"\x06\x2a"}.items():
        section[offset : offset + len(body)] = body

    cli_values = [
        72, 2, 5,
        SECTION_RVA + METADATA_OFFSET, len(metadata),
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
    cli_header = struct.pack("<IHH" + "I" * 16, *cli_values)
    section[0 : len(cli_header)] = cli_header
    section[METADATA_OFFSET : METADATA_OFFSET + len(metadata)] = metadata

    raw_size = (len(section) + 0x1FF) & ~0x1FF
    section.extend(b"\x00" * (raw_size - len(section)))

    headers = bytearray(0x200)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x2102)
    headers[0x84 : 0x84 + len(coff)] = coff

    optional = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "HH" + "I" * 6,
        0x10B, 14, 0,
        raw_size, raw_size, 0, 0, SECTION_RVA, SECTION_RVA,
        0x10000000, 0x1000, 0x200,
        6, 0, 1, 0, 6, 0,
        0, 0x3000, 0x200, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16,
    )
    if len(optional) != 96:
        raise AssertionError(len(optional))
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 14 * 8, SECTION_RVA, 72)
    optional += bytes(directories)
    headers[0x98 : 0x98 + len(optional)] = optional

    section_header = b".text\x00\x00\x00"
    section_header += struct.pack(
        "<IIIIIIHHI",
        len(section), SECTION_RVA, raw_size, SECTION_RAW_OFFSET,
        0, 0, 0, 0, 0x60000020,
    )
    section_header_offset = 0x98 + 224
    headers[section_header_offset : section_header_offset + len(section_header)] = section_header

    return bytes(headers) + bytes(section)


def write_fixture(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_pe())
    return path


if __name__ == "__main__":
    output = Path("fixtures/ReviewSample.dll")
    write_fixture(output)
    print(output)
