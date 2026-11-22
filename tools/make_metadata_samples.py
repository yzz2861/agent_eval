#!/usr/bin/env python3
"""
Create two tiny, deterministic .NET PE files that contain metadata only.

The samples are intentionally built without a compiler or CLR host.  Every
table row is written directly so the files can be used to test metadata-only
property/interface contract analysis with dnfile.

Sample layout
-------------
readonly-overloads.dll
    IReadOnlyValue.Value has a getter.
    IValueWriter.Value has a getter and a setter, but ReadOnlyFacade does not
    implement IValueWriter.  ReadOnlyFacade also contains three same-name
    "set_Value" decoys, including one with exactly the interface setter's
    name and parameter types.

write-overloads.dll
    WriteFacade implements IValueWriter implicitly.
    ExplicitWriteFacade implements the setter through a MethodImpl row.
    InheritedWriteFacade inherits the implementation from BaseWriter.
    Each writer also contains an unrelated static set_Value(string) overload.
"""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SECTION_RVA = 0x2000
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
CLI_HEADER_SIZE = 72


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _compressed_uint(value: int) -> bytes:
    if value < 0x80:
        return bytes((value,))
    if value < 0x4000:
        return struct.pack("<H", 0x8000 | value)
    if value < 0x20000000:
        value |= 0xC0000000
        return struct.pack(">I", value)
    raise ValueError("compressed integer is too large")


class StringsHeap:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")
        self._offsets: Dict[str, int] = {"": 0}

    def add(self, value: str) -> int:
        if value in self._offsets:
            return self._offsets[value]
        offset = len(self.data)
        self.data.extend(value.encode("utf-8") + b"\x00")
        self._offsets[value] = offset
        return offset


class BlobHeap:
    def __init__(self) -> None:
        self.data = bytearray(b"\x00")
        self._offsets: Dict[bytes, int] = {b"": 0}

    def add(self, value: bytes) -> int:
        if value in self._offsets:
            return self._offsets[value]
        offset = len(self.data)
        self.data.extend(_compressed_uint(len(value)))
        self.data.extend(value)
        self._offsets[value] = offset
        return offset


@dataclass
class MethodSpec:
    name: str
    flags: int
    signature: bytes
    concrete: bool = True
    rid: int = 0
    body_offset: int = 0


@dataclass
class PropertySpec:
    name: str
    signature: bytes
    getter: Optional[MethodSpec] = None
    setter: Optional[MethodSpec] = None
    rid: int = 0


@dataclass(eq=False)
class TypeSpec:
    namespace: str
    name: str
    flags: int
    extends: Optional["TypeSpec"] = None
    methods: List[MethodSpec] = field(default_factory=list)
    properties: List[PropertySpec] = field(default_factory=list)
    interfaces: List["TypeSpec"] = field(default_factory=list)
    rid: int = 0
    method_start: int = 0
    property_start: int = 0

    @property
    def full_name(self) -> str:
        if not self.namespace:
            return self.name
        return f"{self.namespace}.{self.name}"


@dataclass
class MethodImplSpec:
    owner: TypeSpec
    body: MethodSpec
    declaration_interface: TypeSpec
    declaration_name: str
    declaration_signature: bytes


class SampleAssembly:
    def __init__(self, assembly_name: str) -> None:
        self.assembly_name = assembly_name
        self.strings = StringsHeap()
        self.blobs = BlobHeap()
        self.types: List[TypeSpec] = []
        self.methods: List[MethodSpec] = []
        self.properties: List[PropertySpec] = []
        self.interface_impls: List[Tuple[TypeSpec, TypeSpec]] = []
        self.method_semantics: List[Tuple[int, PropertySpec, MethodSpec]] = []
        self.method_impls: List[MethodImplSpec] = []
        self.member_refs: List[Tuple[TypeSpec, str, bytes]] = []
        self._body_methods: List[MethodSpec] = []

    def add_type(
        self,
        namespace: str,
        name: str,
        flags: int,
        extends: Optional[TypeSpec] = None,
        methods: Optional[List[MethodSpec]] = None,
        properties: Optional[List[PropertySpec]] = None,
        interfaces: Optional[List[TypeSpec]] = None,
    ) -> TypeSpec:
        method_specs = list(methods or [])
        for prop in properties or []:
            for accessor in (prop.getter, prop.setter):
                if accessor is not None and all(accessor is not m for m in method_specs):
                    method_specs.append(accessor)

        spec = TypeSpec(
            namespace=namespace,
            name=name,
            flags=flags,
            extends=extends,
            methods=method_specs,
            properties=list(properties or []),
            interfaces=list(interfaces or []),
        )
        spec.rid = len(self.types) + 1
        spec.method_start = len(self.methods) + 1
        spec.property_start = len(self.properties) + 1

        for method in spec.methods:
            method.rid = len(self.methods) + 1
            self.methods.append(method)
            if method.concrete:
                self._body_methods.append(method)

        for prop in spec.properties:
            prop.rid = len(self.properties) + 1
            self.properties.append(prop)
            if prop.getter is not None:
                self.method_semantics.append((0x0002, prop, prop.getter))
            if prop.setter is not None:
                self.method_semantics.append((0x0001, prop, prop.setter))

        self.types.append(spec)
        for interface in spec.interfaces:
            self.interface_impls.append((spec, interface))
        return spec

    def add_method_impl(
        self,
        owner: TypeSpec,
        body: MethodSpec,
        declaration_interface: TypeSpec,
        declaration_name: str,
        declaration_signature: bytes,
    ) -> None:
        self.method_impls.append(
            MethodImplSpec(
                owner=owner,
                body=body,
                declaration_interface=declaration_interface,
                declaration_name=declaration_name,
                declaration_signature=declaration_signature,
            )
        )
        self.member_refs.append(
            (declaration_interface, declaration_name, declaration_signature)
        )

    def _metadata_bytes(self) -> Tuple[bytes, List[MethodSpec]]:
        # Table numbers used by the tiny samples.  Table 8 (Param) is omitted;
        # every MethodDef.ParamList points at the implicit row 1.
        tables: Dict[int, bytearray] = {
            0: bytearray(),
            1: bytearray(),
            2: bytearray(),
            6: bytearray(),
            9: bytearray(),
            10: bytearray(),
            21: bytearray(),
            23: bytearray(),
            24: bytearray(),
            25: bytearray(),
            32: bytearray(),
            35: bytearray(),
        }

        module_name = self.strings.add(self.assembly_name + ".dll")
        tables[0].extend(struct.pack("<HHHHH", 0, module_name, 1, 0, 0))

        self._add_type_ref(
            tables[1], "System", "Object", resolution_scope=(1 << 2) | 2
        )
        self.strings.add("System.Runtime")
        assembly_ref = struct.pack(
            "<HHHHIHHHH",
            4,
            0,
            0,
            0,
            0,
            0,
            self.strings.add("System.Runtime"),
            0,
            0,
        )
        tables[35].extend(assembly_ref)

        for type_spec in self.types:
            extends = 0
            if type_spec.extends is not None:
                extends = type_spec.extends.rid << 2
            elif not (type_spec.flags & 0x00000020):  # not an interface
                extends = (1 << 2) | 1  # TypeRef System.Object
            tables[2].extend(
                struct.pack(
                    "<IHHHHH",
                    type_spec.flags,
                    self.strings.add(type_spec.name),
                    self.strings.add(type_spec.namespace),
                    extends,
                    1,
                    type_spec.method_start,
                )
            )

        for method in self.methods:
            rva = 0
            tables[6].extend(
                struct.pack(
                    "<IHHHHH",
                    rva,
                    0,  # IL | Managed
                    method.flags,
                    self.strings.add(method.name),
                    self.blobs.add(method.signature),
                    1,
                )
            )

        for owner, interface in self.interface_impls:
            tables[9].extend(struct.pack("<HH", owner.rid, interface.rid << 2))

        member_ref_rids: Dict[Tuple[TypeSpec, str, bytes], int] = {}
        for interface, name, signature in self.member_refs:
            if (interface, name, signature) in member_ref_rids:
                continue
            member_ref_rids[(interface, name, signature)] = len(member_ref_rids) + 1
            tables[10].extend(
                struct.pack(
                    "<HHH",
                    (interface.rid << 3) | 0,
                    self.strings.add(name),
                    self.blobs.add(signature),
                )
            )

        for type_spec in self.types:
            tables[21].extend(
                struct.pack("<HH", type_spec.rid, type_spec.property_start)
            )

        for prop in self.properties:
            tables[23].extend(
                struct.pack(
                    "<HHH",
                    0x0200,
                    self.strings.add(prop.name),
                    self.blobs.add(prop.signature),
                )
            )

        for semantics, prop, method in self.method_semantics:
            tables[24].extend(
                struct.pack("<HHH", semantics, method.rid, (prop.rid << 1) | 1)
            )

        for impl in self.method_impls:
            member_ref_rid = member_ref_rids[
                (
                    impl.declaration_interface,
                    impl.declaration_name,
                    impl.declaration_signature,
                )
            ]
            tables[25].extend(
                struct.pack(
                    "<HHH",
                    impl.owner.rid,
                    impl.body.rid << 1,
                    (member_ref_rid << 1) | 1,
                )
            )

        tables[32].extend(
            struct.pack(
                "<IHHHHIHHH",
                0x8004,
                1,
                0,
                0,
                0,
                0,
                0,
                self.strings.add(self.assembly_name),
                0,
            )
        )

        valid_mask = 0
        row_counts = bytearray()
        row_data = bytearray()
        for table_number in sorted(tables):
            data = tables[table_number]
            if not data:
                continue
            valid_mask |= 1 << table_number
            # Row sizes are fixed for this tiny sample, so derive the row count
            # from the known table row size.
            row_size = {
                0: 10,
                1: 6,
                2: 14,
                6: 14,
                9: 4,
                10: 6,
                21: 4,
                23: 6,
                24: 6,
                25: 6,
                32: 22,
                35: 20,
            }[table_number]
            assert len(data) % row_size == 0, (
                f"table {table_number} has {len(data)} bytes, "
                f"not a multiple of row size {row_size}"
            )
            row_counts.extend(struct.pack("<I", len(data) // row_size))
            row_data.extend(data)

        tables_header = struct.pack(
            "<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, 0
        ) + bytes(row_counts) + bytes(row_data)
        return tables_header, self._body_methods

    def _add_type_ref(
        self, table: bytearray, namespace: str, name: str, resolution_scope: int
    ) -> TypeSpec:
        # TypeRef has no TypeSpec instance in the high-level model; this dummy
        # object is only used as a sentinel for System.Object.
        table.extend(
            struct.pack(
                "<HHH",
                resolution_scope,
                self.strings.add(name),
                self.strings.add(namespace),
            )
        )
        return TypeSpec(namespace=namespace, name=name, flags=0)

    def _metadata_root(self, tables: bytes, method_bodies: List[MethodSpec]) -> bytes:
        # The offsets of the method bodies depend on the metadata size, so the
        # table stream is first built with zero RVAs and then patched below.
        streams = [
            (b"#~", tables),
            (b"#Strings", bytes(self.strings.data)),
            (b"#US", b"\x00"),
            (b"#GUID", b"\x00" * 16),
            (b"#Blob", bytes(self.blobs.data)),
        ]

        version = b"v4.0.30319\x00"
        version = version + b"\x00" * (_align(len(version), 4) - len(version))
        header_size = 16 + len(version) + 4
        stream_headers_size = 0
        for name, _ in streams:
            encoded_name = name + b"\x00"
            stream_headers_size += 8 + _align(len(encoded_name), 4)

        data_offset = _align(header_size + stream_headers_size, 4)
        entries = []
        payload = bytearray()
        for name, data in streams:
            offset = data_offset + len(payload)
            entries.append((name, offset, len(data)))
            payload.extend(data)
            payload.extend(b"\x00" * (_align(len(payload), 4) - len(payload)))

        metadata_size = data_offset + len(payload)
        root = bytearray()
        root.extend(
            struct.pack(
                "<IHHII",
                0x424A5342,
                1,
                1,
                0,
                len(version),
            )
        )
        root.extend(version)
        root.extend(struct.pack("<HH", 0, len(streams)))
        for name, offset, size in entries:
            encoded_name = name + b"\x00"
            root.extend(struct.pack("<II", offset, size))
            root.extend(encoded_name)
            root.extend(b"\x00" * (_align(len(encoded_name), 4) - len(encoded_name)))

        assert len(root) == data_offset
        root.extend(payload)
        assert len(root) == metadata_size
        return bytes(root)

    def build(self) -> bytes:
        tables, body_methods = self._metadata_bytes()
        metadata = self._metadata_root(tables, body_methods)

        # Reserve two bytes for each concrete method: tiny header (0x06) + ret.
        body_base = CLI_HEADER_SIZE + _align(len(metadata), 4)
        for index, method in enumerate(body_methods):
            method.body_offset = body_base + index * 2

        # Rebuild rows now that concrete method RVAs are known.
        tables, _ = self._metadata_bytes()
        # Patch the MethodDef Rva fields.  MethodDef starts after Module (10),
        # TypeRef (6), and TypeDef (14 * n) rows in the #~ stream.  To keep this
        # simple and robust, locate each row by its known ordered position.
        method_row_offset = self._table_data_offset(tables, 6)
        for index, method in enumerate(self.methods):
            if not method.concrete:
                continue
            offset = method_row_offset + index * 14
            rva = SECTION_RVA + method.body_offset
            tables = bytearray(tables)
            struct.pack_into("<I", tables, offset, rva)

        metadata = self._metadata_root(bytes(tables), body_methods)

        content = bytearray(CLI_HEADER_SIZE)
        struct.pack_into(
            "<IHH" + "I" * 16,
            content,
            0,
            CLI_HEADER_SIZE,
            2,
            5,
            SECTION_RVA + CLI_HEADER_SIZE,
            len(metadata),
            0x00000001,  # COMIMAGE_FLAGS_ILONLY
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        content.extend(metadata)
        content.extend(b"\x00" * (_align(len(content), 4) - len(content)))
        for method in body_methods:
            content.extend(b"\x06\x2a")
        content.extend(b"\x00" * (_align(len(content), 4) - len(content)))

        return self._wrap_pe(bytes(content))

    def _table_counts(self, tables: bytes) -> Tuple[Dict[int, int], int]:
        """Return table row counts and the offset of the first table row."""
        valid_mask, = struct.unpack_from("<Q", tables, 8)
        counts: Dict[int, int] = {}
        offset = 24
        for table_number in range(64):
            if valid_mask & (1 << table_number):
                counts[table_number], = struct.unpack_from("<I", tables, offset)
                offset += 4
        return counts, offset

    def _table_data_offset(self, tables: bytes, target: int) -> int:
        counts, offset = self._table_counts(tables)
        row_sizes = {
            0: 10,
            1: 6,
            2: 14,
            6: 14,
            9: 4,
            10: 6,
            21: 4,
            23: 6,
            24: 6,
            25: 6,
            32: 22,
            35: 20,
        }
        for table_number in sorted(counts):
            if table_number == target:
                return offset
            offset += counts[table_number] * row_sizes[table_number]
        raise AssertionError(f"table {target} not found")

    def _wrap_pe(self, section_content: bytes) -> bytes:
        raw_size = _align(len(section_content), FILE_ALIGN)
        virtual_size = len(section_content)
        size_of_image = _align(SECTION_RVA + virtual_size, SECTION_ALIGN)
        headers_size = FILE_ALIGN

        dos = bytearray(0x80)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 0x80)

        coff = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0,
            0,
            0,
            0x00E0,
            0x2102,  # executable image | 32-bit | DLL
        )

        optional = bytearray(0x00E0)
        struct.pack_into("<H", optional, 0, 0x010B)
        struct.pack_into("<BB", optional, 2, 8, 0)
        struct.pack_into("<I", optional, 4, raw_size)
        struct.pack_into("<I", optional, 8, raw_size)
        struct.pack_into("<I", optional, 12, 0)
        struct.pack_into("<I", optional, 16, SECTION_RVA)
        struct.pack_into("<I", optional, 20, SECTION_RVA)
        struct.pack_into("<I", optional, 24, SECTION_RVA)
        struct.pack_into("<I", optional, 28, 0x400000)
        struct.pack_into("<I", optional, 32, SECTION_ALIGN)
        struct.pack_into("<I", optional, 36, FILE_ALIGN)
        struct.pack_into("<HHHHHH", optional, 40, 4, 0, 0, 0, 4, 0)
        struct.pack_into("<I", optional, 52, 0)
        struct.pack_into("<I", optional, 56, size_of_image)
        struct.pack_into("<I", optional, 60, headers_size)
        struct.pack_into("<I", optional, 64, 0)
        struct.pack_into("<H", optional, 68, 3)
        struct.pack_into("<H", optional, 70, 0)
        struct.pack_into("<IIII", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<I", optional, 84, 0)
        struct.pack_into("<I", optional, 88, 16)
        struct.pack_into(
            "<II", optional, 96 + 14 * 8, SECTION_RVA, CLI_HEADER_SIZE
        )

        section = struct.pack(
            "<8sIIIIIIHHI",
            b".text\x00\x00\x00",
            virtual_size,
            SECTION_RVA,
            raw_size,
            FILE_ALIGN,
            0,
            0,
            0,
            0,
            0x60000020,
        )

        headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section
        headers += b"\x00" * (headers_size - len(headers))
        return headers + section_content + b"\x00" * (raw_size - len(section_content))


def _gen_readonly() -> SampleAssembly:
    asm = SampleAssembly("MetadataSamples.ReadOnlyOverloads")

    getter_sig = b"\x20\x00\x08"
    setter_sig = b"\x20\x01\x01\x08"
    static_string_sig = b"\x00\x01\x01\x0e"
    instance_string_sig = b"\x20\x01\x01\x0e"
    instance_two_sig = b"\x20\x02\x01\x08\x0e"
    property_sig = b"\x28\x00\x08"

    def interface_attr() -> int:
        return 0x000000A1  # public | interface | abstract

    def public_accessor() -> int:
        return 0x000009E6  # public hidebysig specialname virtual final newslot

    iread = asm.add_type(
        "MetadataSamples.Contracts",
        "IReadOnlyValue",
        interface_attr(),
        properties=[
            PropertySpec(
                "Value",
                property_sig,
                getter=MethodSpec("get_Value", 0x00000DC6, getter_sig, concrete=False),
            )
        ],
    )
    iwrite = asm.add_type(
        "MetadataSamples.Contracts",
        "IValueWriter",
        interface_attr(),
        properties=[
            PropertySpec(
                "Value",
                property_sig,
                getter=MethodSpec("get_Value", 0x00000DC6, getter_sig, concrete=False),
                setter=MethodSpec("set_Value", 0x00000DC6, setter_sig, concrete=False),
            )
        ],
    )

    asm.add_type(
        "MetadataSamples",
        "ReadOnlyFacade",
        0x00100101,  # public | sealed | beforefieldinit
        extends=None,
        interfaces=[iread],
        properties=[
            PropertySpec(
                "Value",
                property_sig,
                getter=MethodSpec("get_Value", public_accessor(), getter_sig),
            )
        ],
        methods=[
            MethodSpec("set_Value", 0x000009E6, setter_sig),
            MethodSpec("set_Value", 0x00000096, static_string_sig),
            MethodSpec("set_Value", 0x00000081, instance_two_sig),
        ],
    )
    # Keep iwrite in the type list so both samples share the same contract
    # surface, but ReadOnlyFacade deliberately does not implement it.
    assert iwrite.rid != 0
    return asm


def _gen_write() -> SampleAssembly:
    asm = SampleAssembly("MetadataSamples.WriteOverloads")

    getter_sig = b"\x20\x00\x08"
    setter_sig = b"\x20\x01\x01\x08"
    static_string_sig = b"\x00\x01\x01\x0e"
    instance_bool_sig = b"\x20\x02\x01\x08\x02"
    property_sig = b"\x28\x00\x08"

    interface_attr = 0x000000A1
    public_accessor = 0x000009E6
    private_final_virtual = 0x000009E1

    iread = asm.add_type(
        "MetadataSamples.Contracts",
        "IReadOnlyValue",
        interface_attr,
        properties=[
            PropertySpec(
                "Value",
                property_sig,
                getter=MethodSpec("get_Value", 0x00000DC6, getter_sig, concrete=False),
            )
        ],
    )
    iwrite = asm.add_type(
        "MetadataSamples.Contracts",
        "IValueWriter",
        interface_attr,
        properties=[
            PropertySpec(
                "Value",
                property_sig,
                getter=MethodSpec("get_Value", 0x00000DC6, getter_sig, concrete=False),
                setter=MethodSpec("set_Value", 0x00000DC6, setter_sig, concrete=False),
            )
        ],
    )

    base_getter = MethodSpec("get_Value", public_accessor, getter_sig)
    base_setter = MethodSpec("set_Value", public_accessor, setter_sig)
    base_type = asm.add_type(
        "MetadataSamples",
        "BaseWriter",
        0x00100001,  # public | beforefieldinit (inheritable)
        interfaces=[iread, iwrite],
        properties=[
            PropertySpec("Value", property_sig, getter=base_getter, setter=base_setter)
        ],
    )

    asm.add_type(
        "MetadataSamples",
        "InheritedWriteFacade",
        0x00100101,
        extends=base_type,
    )

    write_getter = MethodSpec("get_Value", public_accessor, getter_sig)
    write_setter = MethodSpec("set_Value", public_accessor, setter_sig)
    asm.add_type(
        "MetadataSamples",
        "WriteFacade",
        0x00100101,
        interfaces=[iread, iwrite],
        properties=[
            PropertySpec(
                "Value", property_sig, getter=write_getter, setter=write_setter
            )
        ],
        methods=[
            MethodSpec("set_Value", 0x00000096, static_string_sig),
            MethodSpec("set_Value", 0x00000081, instance_bool_sig),
        ],
    )

    explicit_getter = MethodSpec("get_Value", public_accessor, getter_sig)
    explicit_setter = MethodSpec(
        "set_Value", private_final_virtual, setter_sig
    )
    explicit_type = asm.add_type(
        "MetadataSamples",
        "ExplicitWriteFacade",
        0x00100101,
        interfaces=[iread, iwrite],
        properties=[
            PropertySpec("Value", property_sig, getter=explicit_getter)
        ],
        methods=[
            explicit_setter,
            MethodSpec("set_Value", 0x00000096, static_string_sig),
        ],
    )
    asm.add_method_impl(
        explicit_type,
        explicit_setter,
        iwrite,
        "set_Value",
        setter_sig,
    )
    return asm


def build_samples(output_dir: Path) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for filename, factory in (
        ("readonly-overloads.dll", _gen_readonly),
        ("write-overloads.dll", _gen_write),
    ):
        path = output_dir / filename
        path.write_bytes(factory().build())
        results.append(path)
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "samples",
    )
    args = parser.parse_args()
    for path in build_samples(args.output):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
