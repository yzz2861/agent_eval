#!/usr/bin/env python3
"""Static .NET property/interface contract audit using dnfile metadata only.

This tool never loads a managed assembly, never invokes the CLR, and never
uses reflection.  Every conclusion is expressed as a path through metadata
tables (TypeDef, InterfaceImpl, PropertyMap, Property, MethodSemantics,
MethodDef, MethodImpl, MemberRef) so it can be checked independently.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import dnfile


def _align(value: int, alignment: int = 4) -> int:
    return (value + alignment - 1) // alignment * alignment


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _blob(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    inner = getattr(value, "value", None)
    if isinstance(inner, (bytes, bytearray)):
        return bytes(inner)
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return b""


def _read_compressed(data: bytes, pos: int) -> Tuple[int, int]:
    if pos >= len(data):
        raise ValueError("truncated compressed integer")
    first = data[pos]
    if first & 0x80 == 0:
        return first, pos + 1
    if first & 0xC0 == 0x80:
        if pos + 1 >= len(data):
            raise ValueError("truncated compressed integer")
        return ((first & 0x3F) << 8) | data[pos + 1], pos + 2
    if first & 0xE0 == 0xC0:
        if pos + 3 >= len(data):
            raise ValueError("truncated compressed integer")
        value = (
            ((first & 0x1F) << 24)
            | (data[pos + 1] << 16)
            | (data[pos + 2] << 8)
            | data[pos + 3]
        )
        return value, pos + 4
    raise ValueError("invalid compressed integer")


TABLE_NUMBERS = {
    "Module": 0,
    "TypeRef": 1,
    "TypeDef": 2,
    "Field": 4,
    "MethodDef": 6,
    "Param": 8,
    "InterfaceImpl": 9,
    "MemberRef": 10,
    "PropertyMap": 21,
    "Property": 23,
    "MethodSemantics": 24,
    "MethodImpl": 25,
    "TypeSpec": 27,
    "Assembly": 32,
    "AssemblyRef": 35,
}


@dataclass(eq=False)
class TypeHandle:
    kind: str
    rid: int
    table_name: str
    row: Any
    full_name: str

    @property
    def token(self) -> int:
        return (TABLE_NUMBERS[self.table_name] << 24) | self.rid


@dataclass
class Accessor:
    semantics_row: Any
    method_row: Any
    method_rid: int


@dataclass
class PropertyInfo:
    row: Any
    rid: int
    owner: TypeHandle
    map_row: Any
    signature: str
    getter: Optional[Accessor] = None
    setter: Optional[Accessor] = None


@dataclass
class MethodInfo:
    row: Any
    rid: int
    owner: TypeHandle
    name: str
    signature: str
    flags: int
    rva: int

    @property
    def is_static(self) -> bool:
        return bool(self.flags & 0x0010)

    @property
    def is_public(self) -> bool:
        return (self.flags & 0x0007) == 0x0006

    @property
    def is_private(self) -> bool:
        return (self.flags & 0x0007) == 0x0001

    @property
    def is_virtual(self) -> bool:
        return bool(self.flags & 0x0040)

    @property
    def is_final(self) -> bool:
        return bool(self.flags & 0x0020)

    @property
    def is_newslot(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def is_abstract(self) -> bool:
        return bool(self.flags & 0x0400)

    @property
    def is_special_name(self) -> bool:
        return bool(self.flags & 0x0800)

    def flag_names(self) -> List[str]:
        names = []
        access = {
            0x0000: "privatescope",
            0x0001: "private",
            0x0002: "famandassem",
            0x0003: "assembly",
            0x0004: "family",
            0x0005: "famorassem",
            0x0006: "public",
        }
        names.append(access.get(self.flags & 0x0007, "access?"))
        for bit, label in (
            (0x0010, "static"),
            (0x0020, "final"),
            (0x0040, "virtual"),
            (0x0080, "hidebysig"),
            (0x0100, "newslot"),
            (0x0400, "abstract"),
            (0x0800, "specialname"),
        ):
            if self.flags & bit:
                names.append(label)
        return names


class SignatureParser:
    PRIMITIVES = {
        0x01: "void",
        0x02: "bool",
        0x03: "char",
        0x04: "int8",
        0x05: "uint8",
        0x06: "int16",
        0x07: "uint16",
        0x08: "int32",
        0x09: "uint32",
        0x0A: "int64",
        0x0B: "uint64",
        0x0C: "float32",
        0x0D: "float64",
        0x0E: "string",
        0x16: "typedref",
        0x18: "native int",
        0x19: "native uint",
        0x1C: "object",
    }

    def __init__(self, view: "MetadataView") -> None:
        self.view = view

    def method(self, data: bytes) -> str:
        if not data:
            return "<empty method signature>"
        pos = 1
        callconv = data[0]
        generic = ""
        if callconv & 0x10:
            count, pos = _read_compressed(data, pos)
            generic = f" generic[{count}]"
        param_count, pos = _read_compressed(data, pos)
        ret, pos = self._type(data, pos, 0)
        params = []
        for _ in range(param_count):
            param, pos = self._type(data, pos, 0)
            params.append(param)
        kind = "instance" if callconv & 0x20 else "static"
        return f"{kind}{generic} {ret} ({', '.join(params)})"

    def property(self, data: bytes) -> str:
        if not data:
            return "<empty property signature>"
        pos = 1
        param_count, pos = _read_compressed(data, pos)
        prop_type, pos = self._type(data, pos, 0)
        params = []
        for _ in range(param_count):
            param, pos = self._type(data, pos, 0)
            params.append(param)
        return f"{prop_type} ({', '.join(params)})"

    def field(self, data: bytes) -> str:
        if not data:
            return "<empty field signature>"
        value, _ = self._type(data, 1, 0)
        return value

    def standalone_type(self, data: bytes) -> str:
        if not data:
            return "<empty type signature>"
        value, _ = self._type(data, 0, 0)
        return value

    def _type(self, data: bytes, pos: int, depth: int) -> Tuple[str, int]:
        if depth > 16 or pos >= len(data):
            return "<sig-error>", len(data)
        element = data[pos]
        pos += 1
        if element in self.PRIMITIVES:
            return self.PRIMITIVES[element], pos
        if element == 0x0F:  # PTR
            inner, pos = self._type(data, pos, depth + 1)
            return f"{inner}*", pos
        if element == 0x10:  # BYREF
            inner, pos = self._type(data, pos, depth + 1)
            return f"{inner}&", pos
        if element in (0x11, 0x12):  # VALUETYPE / CLASS
            token, pos = _read_compressed(data, pos)
            return self._typedeforref(token, depth), pos
        if element == 0x13:  # VAR
            index, pos = _read_compressed(data, pos)
            return f"!{index}", pos
        if element == 0x1E:  # MVAR
            index, pos = _read_compressed(data, pos)
            return f"!!{index}", pos
        if element == 0x1D:  # SZARRAY
            inner, pos = self._type(data, pos, depth + 1)
            return f"{inner}[]", pos
        if element == 0x14:  # ARRAY
            inner, pos = self._type(data, pos, depth + 1)
            rank, pos = _read_compressed(data, pos)
            size_count, pos = _read_compressed(data, pos)
            for _ in range(size_count):
                _, pos = _read_compressed(data, pos)
            bound_count, pos = _read_compressed(data, pos)
            for _ in range(bound_count):
                _, pos = _read_compressed(data, pos)
            return f"{inner}[{',' * max(rank - 1, 0)}]", pos
        if element == 0x15:  # GENERICINST
            if pos >= len(data):
                return "<sig-error>", len(data)
            form = "class" if data[pos] == 0x12 else "valuetype"
            pos += 1
            token, pos = _read_compressed(data, pos)
            base = self._typedeforref(token, depth)
            count, pos = _read_compressed(data, pos)
            args = []
            for _ in range(count):
                arg, pos = self._type(data, pos, depth + 1)
                args.append(arg)
            return f"{form} {base}<{', '.join(args)}>", pos
        if element == 0x1B:  # FNPTR
            start = pos
            # Reuse the method parser over the remaining bytes; trailing data is
            # not required for a canonical display in this audit.
            sub = data[start:]
            try:
                text = self.method(sub)
            except ValueError:
                text = "<fnptr-error>"
            return f"method {text}", len(data)
        if element == 0x1F or element == 0x20:  # CMOD_REQD / CMOD_OPT
            token, pos = _read_compressed(data, pos)
            modifier = "modreq" if element == 0x1F else "modopt"
            inner, pos = self._type(data, pos, depth + 1)
            return f"{inner} {modifier}({self._typedeforref(token, depth)})", pos
        if element == 0x41:  # SENTINEL
            return self._type(data, pos, depth + 1)
        if element == 0x45:  # PINNED
            return self._type(data, pos, depth + 1)
        return f"<unknown:0x{element:02X}>", pos

    def _typedeforref(self, token: int, depth: int) -> str:
        tag = token & 0x3
        rid = token >> 2
        if rid == 0:
            return "<nil>"
        if tag == 0:
            handle = self.view.typedef_handle(rid)
        elif tag == 1:
            handle = self.view.typeref_handle(rid)
        elif tag == 2:
            handle = self.view.typespec_handle(rid, depth + 1)
        else:
            return f"<bad-token:0x{token:X}>"
        return handle.full_name if handle else f"<bad-token:0x{token:X}>"


class MetadataView:
    """Indexes metadata rows; it does not execute or load the assembly."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.pe = dnfile.dnPE(str(path), clr_lazy_load=False)
        if self.pe.net is None or self.pe.net.mdtables is None:
            raise ValueError(f"{path} has no CLR metadata")
        self.md = self.pe.net.mdtables
        self.signatures = SignatureParser(self)
        self.row_refs: Dict[int, Tuple[str, int]] = {}
        self._typedefs: Dict[int, Any] = {}
        self._typerefs: Dict[int, Any] = {}
        self._typespecs: Dict[int, Any] = {}
        self._typespec_names: Dict[int, str] = {}
        self._methods: Dict[int, MethodInfo] = {}
        self._properties: Dict[int, PropertyInfo] = {}
        self._accessors: Dict[int, List[Accessor]] = {}
        self._property_maps_by_owner: Dict[int, List[Any]] = {}
        self._methods_by_owner: Dict[int, List[MethodInfo]] = {}
        self._methodimpls_by_class: Dict[int, List[Any]] = {}
        self._interfaces_by_class: Dict[int, List[Any]] = {}
        self._method_semantics_by_method: Dict[int, List[Any]] = {}
        self._index_tables()
        self._index_types_and_properties()
        self._index_methods()
        self._index_semantics()

    # ------------------------------------------------------------------
    # Low-level table helpers
    # ------------------------------------------------------------------
    def table_rows(self, name: str) -> List[Tuple[int, Any]]:
        table = getattr(self.md, name, None)
        if table is None:
            return []
        return [(index + 1, row) for index, row in enumerate(table.rows) if row is not None]

    def _index_tables(self) -> None:
        for table in self.md.tables_list:
            for index, row in enumerate(table.rows, 1):
                if row is None:
                    continue
                self.row_refs[id(row)] = (table.name, index)
                if table.name == "TypeDef":
                    self._typedefs[index] = row
                elif table.name == "TypeRef":
                    self._typerefs[index] = row
                elif table.name == "TypeSpec":
                    self._typespecs[index] = row

    def typedef_handle(self, rid: int) -> Optional[TypeHandle]:
        row = self._typedefs.get(rid)
        if row is None:
            return None
        return TypeHandle("TypeDef", rid, "TypeDef", row, self._type_name(row))

    def typeref_handle(self, rid: int) -> Optional[TypeHandle]:
        row = self._typerefs.get(rid)
        if row is None:
            return None
        return TypeHandle("TypeRef", rid, "TypeRef", row, self._type_name(row))

    def typespec_handle(self, rid: int, depth: int = 0) -> Optional[TypeHandle]:
        row = self._typespecs.get(rid)
        if row is None:
            return None
        if rid not in self._typespec_names:
            try:
                name = self.signatures.standalone_type(_blob(row.Signature))
            except (ValueError, IndexError):
                name = ""
            self._typespec_names[rid] = name or f"<TypeSpec#{rid}>"
        return TypeHandle("TypeSpec", rid, "TypeSpec", row, self._typespec_names[rid])

    def handle_from_coded(self, coded: Any) -> Optional[TypeHandle]:
        if coded is None or getattr(coded, "table", None) is None:
            return None
        rid = getattr(coded, "row_index", 0)
        if not rid:
            return None
        name = coded.table.name
        if name == "TypeDef":
            return self.typedef_handle(rid)
        if name == "TypeRef":
            return self.typeref_handle(rid)
        if name == "TypeSpec":
            return self.typespec_handle(rid)
        return None

    @staticmethod
    def _type_name(row: Any) -> str:
        namespace = _text(getattr(row, "TypeNamespace", ""))
        name = _text(getattr(row, "TypeName", ""))
        if name == "<Module>":
            return name
        return f"{namespace}.{name}" if namespace else name

    def row_ref(self, row: Any) -> Dict[str, Any]:
        if row is None:
            return {}
        table, rid = self.row_refs.get(id(row), (getattr(row, "name", "?"), 0))
        try:
            offset = row.struct.get_file_offset()
        except (AttributeError, TypeError):
            offset = None
        return {
            "table": table,
            "rid": rid,
            "token": f"0x{((TABLE_NUMBERS.get(table, 0) << 24) | rid):08X}",
            "file_offset": f"0x{offset:X}" if offset is not None else None,
            "raw": self._raw_struct(row),
        }

    @staticmethod
    def _raw_struct(row: Any) -> Dict[str, Any]:
        raw: Dict[str, Any] = {}
        keys = getattr(getattr(row, "struct", None), "__keys__", []) or []
        flat: List[str] = []
        for key in keys:
            if isinstance(key, (list, tuple)):
                flat.extend(str(item) for item in key)
            else:
                flat.append(str(key))
        for key in flat:
            if not hasattr(row.struct, key):
                continue
            value = getattr(row.struct, key)
            if isinstance(value, (bytes, bytearray)):
                raw[key] = f"0x{bytes(value).hex()}"
            elif isinstance(value, int):
                raw[key] = f"0x{value:X}"
            else:
                raw[key] = value
        return raw

    # ------------------------------------------------------------------
    # Higher-level indexes
    # ------------------------------------------------------------------
    def _index_types_and_properties(self) -> None:
        for pm_rid, map_row in self.table_rows("PropertyMap"):
            parent_rid = getattr(getattr(map_row, "Parent", None), "row_index", 0)
            self._property_maps_by_owner.setdefault(parent_rid, []).append(map_row)
            owner = self.typedef_handle(parent_rid)
            if owner is None:
                continue
            for item in map_row.PropertyList:
                prop_row = item.row
                if prop_row is None:
                    continue
                signature = self.signatures.property(_blob(prop_row.Type))
                info = PropertyInfo(
                    row=prop_row,
                    rid=item.row_index,
                    owner=owner,
                    map_row=map_row,
                    signature=signature,
                )
                self._properties[item.row_index] = info

        for ms_rid, row in self.table_rows("MethodSemantics"):
            method_index = getattr(row, "Method", None)
            assoc = getattr(row, "Association", None)
            if method_index is None or assoc is None or assoc.table is None:
                continue
            method_rid = getattr(method_index, "row_index", 0)
            if assoc.table.name != "Property" or not assoc.row_index:
                continue
            prop = self._properties.get(assoc.row_index)
            if prop is None:
                continue
            accessor = Accessor(row, method_index.row, method_rid)
            if row.Semantics.msGetter:
                prop.getter = accessor
            if row.Semantics.msSetter:
                prop.setter = accessor
            self._accessors.setdefault(prop.rid, []).append(accessor)

    def _index_methods(self) -> None:
        for type_rid, type_row in self._typedefs.items():
            owner = self.typedef_handle(type_rid)
            if owner is None:
                continue
            for item in type_row.MethodList:
                row = item.row
                if row is None:
                    continue
                info = MethodInfo(
                    row=row,
                    rid=item.row_index,
                    owner=owner,
                    name=_text(row.Name),
                    signature=self.signatures.method(_blob(row.Signature)),
                    flags=int(getattr(row.struct, "Flags", 0) or 0),
                    rva=int(getattr(row.struct, "Rva", 0) or 0),
                )
                self._methods[info.rid] = info
                self._methods_by_owner.setdefault(type_rid, []).append(info)

        for row in self.md.MethodImpl.rows if getattr(self.md, "MethodImpl", None) else []:
            if row is None:
                continue
            class_rid = getattr(getattr(row, "Class", None), "row_index", 0)
            if class_rid:
                self._methodimpls_by_class.setdefault(class_rid, []).append(row)

        for row in self.md.InterfaceImpl.rows if getattr(self.md, "InterfaceImpl", None) else []:
            if row is None:
                continue
            class_rid = getattr(getattr(row, "Class", None), "row_index", 0)
            if class_rid:
                self._interfaces_by_class.setdefault(class_rid, []).append(row)

    def _index_semantics(self) -> None:
        for _, row in self.table_rows("MethodSemantics"):
            method_rid = getattr(getattr(row, "Method", None), "row_index", 0)
            if method_rid:
                self._method_semantics_by_method.setdefault(method_rid, []).append(row)

    def method(self, rid: int) -> Optional[MethodInfo]:
        return self._methods.get(rid)

    def property(self, rid: int) -> Optional[PropertyInfo]:
        return self._properties.get(rid)

    def methods_of_type(self, type_rid: int) -> List[MethodInfo]:
        return list(self._methods_by_owner.get(type_rid, []))

    def properties_of_type(self, type_rid: int) -> List[PropertyInfo]:
        result = []
        for map_row in self._property_maps_by_owner.get(type_rid, []):
            for item in map_row.PropertyList:
                info = self._properties.get(item.row_index)
                if info is not None:
                    result.append(info)
        return result

    def semantics_for_method(self, method_rid: int) -> List[Any]:
        return list(self._method_semantics_by_method.get(method_rid, []))

    def interfaces_of(self, type_rid: int) -> List[Any]:
        return list(self._interfaces_by_class.get(type_rid, []))

    def methodimpls_of(self, type_rid: int) -> List[Any]:
        return list(self._methodimpls_by_class.get(type_rid, []))

    def ancestry(self, start: TypeHandle) -> Tuple[List[TypeHandle], Optional[TypeHandle]]:
        path: List[TypeHandle] = []
        external_base: Optional[TypeHandle] = None
        seen = set()
        current = start
        while current is not None and current.kind == "TypeDef" and current.rid not in seen:
            seen.add(current.rid)
            path.append(current)
            base = self.handle_from_coded(getattr(current.row, "Extends", None))
            if base is None:
                break
            if base.kind != "TypeDef":
                external_base = base
                break
            current = base
        return path, external_base

    def implements_interface(self, start: TypeHandle, interface_name: str) -> List[Dict[str, Any]]:
        """Return InterfaceImpl paths for `start` and its base classes."""
        path, _ = self.ancestry(start)
        matches = []
        for depth, type_handle in enumerate(path):
            for row in self.interfaces_of(type_handle.rid):
                iface = self.handle_from_coded(getattr(row, "Interface", None))
                if iface is not None and iface.full_name == interface_name:
                    matches.append(
                        {
                            "row": row,
                            "class": type_handle,
                            "interface": iface,
                            "depth": depth,
                            "inherited": depth > 0,
                        }
                    )
        return matches

    def find_properties(
        self, start: TypeHandle, name: Optional[str], signature: Optional[str] = None
    ) -> List[Tuple[PropertyInfo, int]]:
        path, _ = self.ancestry(start)
        matches: List[Tuple[PropertyInfo, int]] = []
        for depth, type_handle in enumerate(path):
            for prop in self.properties_of_type(type_handle.rid):
                if name is not None and prop.row.Name != name:
                    continue
                if signature is not None and prop.signature != signature:
                    continue
                matches.append((prop, depth))
        return matches

    def resolve_memberref(self, row: Any) -> Dict[str, Any]:
        parent_handle = self.handle_from_coded(getattr(row, "Class", None))
        return {
            "parent": parent_handle,
            "name": _text(getattr(row, "Name", "")),
            "signature": self.signatures.method(_blob(getattr(row, "Signature", b""))),
        }

    def declaration_matches(
        self,
        declaration: Any,
        interface_handle: TypeHandle,
        interface_setter: MethodInfo,
    ) -> Tuple[bool, Dict[str, Any]]:
        info: Dict[str, Any] = {"kind": None}
        if declaration is None or getattr(declaration, "table", None) is None:
            return False, info
        if declaration.table.name == "MethodDef":
            method = self.method(declaration.row_index)
            if method is None:
                return False, info
            info.update({"kind": "MethodDef", "method": method})
            return method.rid == interface_setter.rid, info
        if declaration.table.name == "MemberRef":
            row = declaration.row
            member = self.resolve_memberref(row)
            info.update({"kind": "MemberRef", "member": member, "row": row})
            parent: Optional[TypeHandle] = member["parent"]
            matched = (
                parent is not None
                and parent.full_name == interface_handle.full_name
                and member["name"] == interface_setter.name
                and member["signature"] == interface_setter.signature
            )
            return matched, info
        info["kind"] = declaration.table.name
        return False, info

    def body_method(self, body: Any) -> Tuple[Optional[MethodInfo], Dict[str, Any]]:
        info: Dict[str, Any] = {"kind": None}
        if body is None or getattr(body, "table", None) is None:
            return None, info
        if body.table.name == "MethodDef":
            method = self.method(body.row_index)
            info["kind"] = "MethodDef"
            return method, info
        if body.table.name == "MemberRef":
            info["kind"] = "MemberRef"
            info["member"] = self.resolve_memberref(body.row)
            return None, info
        info["kind"] = body.table.name
        return None, info

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def audit(
        self,
        type_patterns: Sequence[str],
        interface_patterns: Sequence[str],
        property_names: Sequence[str],
    ) -> List[Dict[str, Any]]:
        selected_types = [
            self.typedef_handle(rid)
            for rid, row in self._typedefs.items()
            if not (int(getattr(row.struct, "Flags", 0) or 0) & 0x00000020)
            and _text(row.TypeName) != "<Module>"
        ]
        selected_types = [h for h in selected_types if h is not None]
        if type_patterns:
            selected_types = [
                h for h in selected_types if _matches_any(h.full_name, type_patterns)
            ]

        findings: List[Dict[str, Any]] = []
        for type_handle in selected_types:
            if interface_patterns:
                interface_names = list(interface_patterns)
            else:
                interface_names = []
                for match in self._all_implemented_interfaces(type_handle):
                    name = match.full_name
                    if name not in interface_names:
                        interface_names.append(name)

            for interface_name in interface_names:
                iface_handle = self._find_interface(interface_name)
                props = self._select_properties(iface_handle, property_names)
                if not props:
                    findings.append(
                        self._make_finding(
                            type_handle,
                            interface_name,
                            iface_handle,
                            None,
                            property_names[0] if property_names else None,
                        )
                    )
                    continue
                for prop_name, prop_sig in props:
                    findings.append(
                        self._audit_one(
                            type_handle,
                            interface_name,
                            iface_handle,
                            prop_name,
                            prop_sig,
                        )
                    )
        return findings

    def _all_implemented_interfaces(self, type_handle: TypeHandle) -> List[TypeHandle]:
        result: List[TypeHandle] = []
        seen = set()
        path, _ = self.ancestry(type_handle)
        for item in path:
            for row in self.interfaces_of(item.rid):
                iface = self.handle_from_coded(getattr(row, "Interface", None))
                if iface is not None and iface.full_name not in seen:
                    seen.add(iface.full_name)
                    result.append(iface)
        return result

    def _find_interface(self, name: str) -> Optional[TypeHandle]:
        for rid in self._typedefs:
            handle = self.typedef_handle(rid)
            if handle and handle.full_name == name:
                return handle
        for rid in self._typerefs:
            handle = self.typeref_handle(rid)
            if handle and handle.full_name == name:
                return handle
        for rid in self._typespecs:
            handle = self.typespec_handle(rid)
            if handle and handle.full_name == name:
                return handle
        return None

    def _select_properties(
        self, interface_handle: Optional[TypeHandle], property_names: Sequence[str]
    ) -> List[Tuple[str, Optional[str]]]:
        props: List[PropertyInfo] = []
        if interface_handle is not None and interface_handle.kind == "TypeDef":
            props = self.properties_of_type(interface_handle.rid)
        if property_names:
            selected = []
            for name in property_names:
                candidates = [p for p in props if p.row.Name == name]
                if candidates:
                    selected.extend((str(p.row.Name), p.signature) for p in candidates)
                else:
                    selected.append((name, None))
            return selected
        return [(str(p.row.Name), p.signature) for p in props]

    def _audit_one(
        self,
        type_handle: TypeHandle,
        interface_name: str,
        iface_handle: Optional[TypeHandle],
        property_name: str,
        interface_prop_signature: Optional[str],
    ) -> Dict[str, Any]:
        finding = self._make_finding(
            type_handle, interface_name, iface_handle, interface_prop_signature, property_name
        )
        if iface_handle is None:
            finding["partial_reasons"].append("interface type is not present in this module")
            return finding
        if iface_handle.kind != "TypeDef":
            finding["partial_reasons"].append(
                "interface is a %s; its property/accessor rows are outside this module"
                % iface_handle.kind
            )
            return finding

        iface_props = [
            p
            for p in self.properties_of_type(iface_handle.rid)
            if p.row.Name == property_name
            and (
                interface_prop_signature is None
                or p.signature == interface_prop_signature
            )
        ]
        if not iface_props:
            finding["partial_reasons"].append(
                "selected property is not associated with the interface"
            )
            return finding
        iface_prop = iface_props[0]
        finding["interface_property"] = self.row_ref(iface_prop.row)
        finding["interface_property_map"] = self.row_ref(iface_prop.map_row)
        finding["interface_property_signature"] = iface_prop.signature
        if iface_prop.getter is not None:
            finding["interface_getter"] = self._accessor_trace(iface_prop.getter)
        if iface_prop.setter is None:
            finding["interface_has_setter"] = False
            finding["conclusion"] = "NO_WRITE_INTERFACE_READ_ONLY"
            finding["external_write_accessor"] = False
            self._attach_same_name_methods(finding, type_handle, None, set(), property_name)
            return finding

        interface_setter = self.method(iface_prop.setter.method_rid)
        if interface_setter is None:
            finding["partial_reasons"].append(
                "interface MethodSemantics points at a missing MethodDef"
            )
            return finding
        finding["interface_has_setter"] = True
        finding["interface_setter"] = self._accessor_trace(iface_prop.setter)
        finding["interface_setter_signature"] = interface_setter.signature

        impl_matches = self.implements_interface(type_handle, iface_handle.full_name)
        if not impl_matches:
            finding["conclusion"] = "NOT_IMPLEMENTED"
            finding["external_write_accessor"] = False
            self._attach_same_name_methods(finding, type_handle, interface_setter, set(), property_name)
            return finding
        finding["interface_impl"] = self.row_ref(impl_matches[0]["row"])
        finding["interface_impl_class"] = impl_matches[0]["class"].full_name
        finding["interface_impl_inherited"] = impl_matches[0]["inherited"]
        if impl_matches[0]["inherited"]:
            path, external_base = self.ancestry(type_handle)
            finding["inheritance_path"] = [h.full_name for h in path]
            finding["external_base"] = external_base.full_name if external_base else None

        body, route, mapping = self._find_write_implementation(
            type_handle, iface_handle, iface_prop, interface_setter
        )
        finding["implementation"] = mapping
        if body is None:
            if mapping.get("methodimpl") is not None:
                finding["conclusion"] = "PARTIAL_EXTERNAL_METHODIMPL_BODY"
                finding["external_write_accessor"] = None
                finding["partial_reasons"].append(
                    "MethodImpl maps the interface setter, but the body is not a "
                    "MethodDef in this module; its implementation cannot be verified here"
                )
            else:
                finding["conclusion"] = "NO_WRITE_UNMAPPED_SAME_NAME_ONLY"
                finding["external_write_accessor"] = False
            self._attach_same_name_methods(
                finding, type_handle, interface_setter, set(), property_name
            )
            return finding

        finding["implementation_method"] = self.row_ref(body.row)
        finding["implementation_method_flags"] = body.flag_names()
        finding["implementation_route"] = route
        finding["external_write_accessor"] = True
        finding["conclusion"] = "WRITE_EXPOSED"
        if mapping.get("property_link", {}).get("linked") is False and route.startswith("implicit"):
            finding["conclusion"] = "PARTIAL_WRITE_METHOD_WITHOUT_PROPERTY_SEMANTICS"
            finding["partial_reasons"].append(
                "interface method has an implementation, but the class method is not "
                "linked back to a Property through MethodSemantics"
            )

        mapped = {body.rid}
        declaration = mapping.get("declaration_method")
        if isinstance(declaration, MethodInfo):
            mapped.add(declaration.rid)
        self._attach_same_name_methods(finding, type_handle, interface_setter, mapped, property_name)
        return finding

    def _make_finding(
        self,
        type_handle: TypeHandle,
        interface_name: str,
        iface_handle: Optional[TypeHandle],
        interface_prop_signature: Optional[str],
        property_name: Optional[str],
    ) -> Dict[str, Any]:
        type_flags = int(getattr(type_handle.row.struct, "Flags", 0) or 0)
        finding: Dict[str, Any] = {
            "target_type": type_handle.full_name,
            "target_type_row": self.row_ref(type_handle.row),
            "target_type_flags": f"0x{type_flags:08X}",
            "target_type_sealed": bool(type_flags & 0x00000100),
            "interface": interface_name,
            "interface_row": self.row_ref(iface_handle.row) if iface_handle else None,
            "interface_kind": iface_handle.kind if iface_handle else "unresolved",
            "property": property_name,
            "interface_property_signature": interface_prop_signature,
            "interface_has_setter": None,
            "interface_setter": None,
            "implementation": None,
            "implementation_method": None,
            "implementation_route": "none",
            "external_write_accessor": None,
            "conclusion": "PARTIAL_UNRESOLVED",
            "partial_reasons": [],
            "same_name_methods": [],
        }
        if iface_handle is None:
            finding["partial_reasons"].append(
                "selected interface is not defined in this module"
            )
        return finding

    def _accessor_trace(self, accessor: Accessor) -> Dict[str, Any]:
        return {
            "method_semantics": self.row_ref(accessor.semantics_row),
            "method": self.row_ref(accessor.method_row),
            "method_name": _text(getattr(accessor.method_row, "Name", "")),
            "method_rid": accessor.method_rid,
            "flags": MethodInfo(
                row=accessor.method_row,
                rid=accessor.method_rid,
                owner=TypeHandle("", 0, "TypeDef", accessor.method_row, ""),
                name=_text(getattr(accessor.method_row, "Name", "")),
                signature="",
                flags=int(getattr(accessor.method_row.struct, "Flags", 0) or 0),
                rva=int(getattr(accessor.method_row.struct, "Rva", 0) or 0),
            ).flag_names(),
        }

    def _find_write_implementation(
        self,
        start: TypeHandle,
        iface_handle: TypeHandle,
        iface_prop: PropertyInfo,
        interface_setter: MethodInfo,
    ) -> Tuple[Optional[MethodInfo], str, Dict[str, Any]]:
        path, _ = self.ancestry(start)

        # 1. Explicit MethodImpl rows on the class or any base class.
        for depth, owner in enumerate(path):
            for row in self.methodimpls_of(owner.rid):
                declaration = getattr(row, "MethodDeclaration", None)
                matched, declaration_info = self.declaration_matches(
                    declaration, iface_handle, interface_setter
                )
                if not matched:
                    continue
                body, body_info = self.body_method(getattr(row, "MethodBody", None))
                mapping: Dict[str, Any] = {
                    "route_kind": "explicit",
                    "inherited": depth > 0,
                    "declaring_type": owner.full_name,
                    "methodimpl": self.row_ref(row),
                    "declaration_kind": declaration_info.get("kind"),
                    "declaration_method": declaration_info.get("method"),
                    "body_kind": body_info.get("kind"),
                    "property_link": {
                        "linked": False,
                        "explicit_methodimpl": True,
                        "reason": (
                            "MethodImpl maps the interface setter directly; a class "
                            "Property/MethodSemantics row is not required for this route"
                        ),
                    },
                }
                if declaration_info.get("kind") == "MemberRef":
                    mapping["declaration_memberref"] = self.row_ref(
                        declaration_info["row"]
                    )
                    member = declaration_info["member"]
                    mapping["declaration_parent"] = (
                        member["parent"].full_name if member["parent"] else None
                    )
                    mapping["declaration_name"] = member["name"]
                    mapping["declaration_signature"] = member["signature"]
                if body is not None:
                    mapping["body_method_owner"] = body.owner.full_name
                    mapping["body_method_flags"] = body.flag_names()
                    if body.is_static:
                        mapping["invalid"] = "MethodImpl body is static"
                        continue
                return body, "explicit" if depth == 0 else "inherited-explicit", mapping

        # 2. Implicit implementation: a public virtual method with matching
        #    name/signature on the class or inherited from a base class.
        for depth, owner in enumerate(path):
            for method in self.methods_of_type(owner.rid):
                if method.name != interface_setter.name:
                    continue
                if method.signature != interface_setter.signature:
                    continue
                if method.is_static:
                    continue
                strong = method.is_public and method.is_virtual and not method.is_abstract
                if not strong:
                    continue

                # Find a class Property row associated with this exact method.
                prop_link: Dict[str, Any] = {"linked": False}
                for prop in self.properties_of_type(owner.rid):
                    if prop.row.Name != iface_prop.row.Name:
                        continue
                    if prop.signature != iface_prop.signature:
                        continue
                    if prop.setter is not None and prop.setter.method_rid == method.rid:
                        prop_link = {
                            "linked": True,
                            "property": self.row_ref(prop.row),
                            "property_map": self.row_ref(prop.map_row),
                            "method_semantics": self.row_ref(
                                prop.setter.semantics_row
                            ),
                        }
                        break
                mapping = {
                    "route_kind": "implicit",
                    "inherited": depth > 0,
                    "declaring_type": owner.full_name,
                    "method": self.row_ref(method.row),
                    "method_flags": method.flag_names(),
                    "property_link": prop_link,
                }
                return (
                    method,
                    "implicit" if depth == 0 else "inherited-implicit",
                    mapping,
                )
        return None, "none", {"route_kind": "none"}

    def _attach_same_name_methods(
        self,
        finding: Dict[str, Any],
        start: TypeHandle,
        interface_setter: Optional[MethodInfo],
        mapped_rids: set,
        property_name: Optional[str] = None,
    ) -> None:
        path, _ = self.ancestry(start)
        property_accessor_rids = set()
        for prop in self._properties.values():
            if prop.getter:
                property_accessor_rids.add(prop.getter.method_rid)
            if prop.setter:
                property_accessor_rids.add(prop.setter.method_rid)

        names = {"set"}
        if interface_setter is not None:
            names.add(interface_setter.name)
        if property_name:
            names.add(f"set_{property_name}")
        rows = []
        for depth, owner in enumerate(path):
            for method in self.methods_of_type(owner.rid):
                if method.name not in names:
                    continue
                if method.rid in mapped_rids:
                    relation = "mapped_implementation"
                elif method.rid in property_accessor_rids:
                    relation = "property_accessor"
                else:
                    relation = "unrelated_same_name"
                same_signature = (
                    None
                    if interface_setter is None
                    else (
                        method.name == interface_setter.name
                        and method.signature == interface_setter.signature
                    )
                )
                rows.append(
                    {
                        "method": self.row_ref(method.row),
                        "declaring_type": owner.full_name,
                        "inherited": depth > 0,
                        "name": method.name,
                        "signature": method.signature,
                        "flags": method.flag_names(),
                        "rva": f"0x{method.rva:X}",
                        "same_name_as_interface_setter": (
                            interface_setter is not None
                            and method.name == interface_setter.name
                        ),
                        "same_signature_as_interface_setter": same_signature,
                        "relation": relation,
                        "reason": self._relation_reason(
                            relation, method, same_signature, property_accessor_rids
                        ),
                    }
                )
        finding["same_name_methods"] = rows

    @staticmethod
    def _relation_reason(
        relation: str,
        method: MethodInfo,
        same_signature: bool,
        property_accessor_rids: set,
    ) -> str:
        if relation == "mapped_implementation":
            return "MethodDef is the concrete body selected for the interface setter"
        if relation == "property_accessor":
            return "MethodDef is linked to a Property row through MethodSemantics"
        if same_signature is True:
            return (
                "same name and signature as the interface setter, but no Property "
                "association and no MethodImpl mapping"
            )
        if same_signature is None:
            return (
                "name/prefix collision; the selected interface property has no setter "
                "to compare against"
            )
        return "same method name/prefix, but a different signature and no interface mapping"


def _matches_any(name: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        if name == pattern or name.endswith("." + pattern) or fnmatch.fnmatch(name, pattern):
            return True
    return False


def _conclusion_label(conclusion: str) -> str:
    return {
        "WRITE_EXPOSED": "YES - external write accessor",
        "NO_WRITE_INTERFACE_READ_ONLY": "NO - interface property has no setter",
        "NO_WRITE_UNMAPPED_SAME_NAME_ONLY": "NO - same-name methods are unmapped",
        "NOT_IMPLEMENTED": "NO - interface is not implemented",
        "PARTIAL_WRITE_METHOD_WITHOUT_PROPERTY_SEMANTICS": (
            "PARTIAL - method mapped, property association absent"
        ),
        "PARTIAL_UNRESOLVED": "PARTIAL - metadata incomplete",
        "PARTIAL_EXTERNAL_METHODIMPL_BODY": (
            "PARTIAL - MethodImpl body is outside this module"
        ),
    }.get(conclusion, conclusion)


def render_markdown(findings: Sequence[Dict[str, Any]], source: Path) -> str:
    lines = [
        "# Metadata-only property/interface contract audit",
        "",
        f"Source: `{source}`",
        "",
        "Method: `dnfile` metadata tables only. No assembly load, no CLR host, "
        "no reflection, no IL execution.",
        "",
        "## Verification table",
        "",
        "| # | Type | Sealed | Interface | Property | Interface setter | Route | Implementation MethodDef | Property link | External write | Conclusion |",
        "|---|------|--------|-----------|----------|------------------|-------|--------------------------|---------------|----------------|------------|",
    ]
    for index, finding in enumerate(findings, 1):
        setter = finding.get("interface_setter") or {}
        impl_method = finding.get("implementation_method") or {}
        impl = finding.get("implementation") or {}
        prop_link = (impl.get("property_link") or {}).get("linked")
        if finding.get("implementation_route") in ("explicit", "inherited-explicit"):
            prop_link = "n/a (MethodImpl)"
        elif prop_link is None:
            prop_link = "n/a"
        elif prop_link:
            prop_link = "yes"
        else:
            prop_link = "no"
        lines.append(
            "| {index} | `{type}` | {sealed} | `{iface}` | `{prop}` | {setter} | {route} | {implmethod} | {link} | {write} | {conclusion} |".format(
                index=index,
                type=finding["target_type"],
                sealed="yes" if finding["target_type_sealed"] else "no",
                iface=finding["interface"],
                prop=finding["property"],
                setter=(
                    f"`MethodSemantics#{setter.get('method_semantics', {}).get('rid')}` -> "
                    f"`MethodDef#{setter.get('method_rid')}`"
                    if setter
                    else "none"
                ),
                route=finding.get("implementation_route") or "none",
                implmethod=(
                    f"`MethodDef#{impl_method.get('rid')}`" if impl_method else "-"
                ),
                link=prop_link,
                write={
                    True: "**YES**",
                    False: "no",
                    None: "?",
                }.get(finding.get("external_write_accessor"), "?"),
                conclusion=_conclusion_label(finding["conclusion"]),
            )
        )

    lines.extend(["", "## Evidence trace", ""])
    for index, finding in enumerate(findings, 1):
        lines.extend(
            [
                f"### Finding {index}: `{finding['target_type']}` / `{finding['interface']}` / `{finding['property']}`",
                "",
                f"- `TypeDef` target: {_ref_text(finding['target_type_row'])}; sealed={finding['target_type_sealed']}.",
            ]
        )
        if finding.get("interface_row"):
            lines.append(
                f"- Interface declaration: {_ref_text(finding['interface_row'])}."
            )
        if finding.get("interface_property_map"):
            lines.append(
                f"- Property association: {_ref_text(finding['interface_property_map'])} -> "
                f"{_ref_text(finding.get('interface_property'))}."
            )
        if finding.get("interface_setter"):
            setter = finding["interface_setter"]
            lines.append(
                f"- Interface setter: {_ref_text(setter.get('method_semantics'))} -> "
                f"{_ref_text(setter.get('method'))}."
            )
        if finding.get("interface_impl"):
            lines.append(
                f"- InterfaceImpl: {_ref_text(finding['interface_impl'])}; "
                f"implemented on `{finding.get('interface_impl_class')}`"
                + (" (inherited)." if finding.get("interface_impl_inherited") else ".")
            )
        if finding.get("inheritance_path"):
            lines.append(
                "- Inheritance path: " + " -> ".join(f"`{n}`" for n in finding["inheritance_path"]) + "."
            )
        impl = finding.get("implementation") or {}
        if impl.get("methodimpl"):
            lines.append(
                f"- Explicit override: {_ref_text(impl['methodimpl'])}."
            )
        if impl.get("declaration_memberref"):
            lines.append(
                f"- MethodImpl declaration: {_ref_text(impl['declaration_memberref'])} "
                f"(`{impl.get('declaration_parent')}::{impl.get('declaration_name')}` "
                f"`{impl.get('declaration_signature')}`)."
            )
        if impl.get("method"):
            lines.append(f"- Implicit matching MethodDef: {_ref_text(impl['method'])}.")
        link = impl.get("property_link") or {}
        if link.get("linked") and link.get("property"):
            lines.append(
                f"- Class property association: {_ref_text(link.get('property_map'))} -> "
                f"{_ref_text(link.get('property'))} -> "
                f"{_ref_text(link.get('method_semantics'))}."
            )
        if impl.get("property_link", {}).get("linked") is False and impl.get("route_kind") == "implicit":
            lines.append("- Class property association: absent (only the method matches).")
        if finding.get("implementation_method"):
            lines.append(
                f"- Concrete setter body: {_ref_text(finding['implementation_method'])}; "
                f"flags={', '.join(finding.get('implementation_method_flags') or [])}."
            )
        if finding.get("same_name_methods"):
            lines.append("- Same-name/overload scan:")
            for item in finding["same_name_methods"]:
                lines.append(
                    f"  - {_ref_text(item['method'])} `{item['declaring_type']}::{item['name']}` "
                    f"`{item['signature']}` flags={', '.join(item['flags'])}; "
                    f"same-signature={item['same_signature_as_interface_setter']}; "
                    f"relation={item['relation']} ({item['reason']})."
                )
        if finding.get("partial_reasons"):
            lines.append("- Partial reasons:")
            for reason in finding["partial_reasons"]:
                lines.append(f"  - {reason}")
        lines.append(
            f"- Conclusion: **{_conclusion_label(finding['conclusion'])}**; "
            f"external_write_accessor={finding.get('external_write_accessor')}."
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _ref_text(ref: Optional[Dict[str, Any]]) -> str:
    if not ref:
        return "`missing`"
    rid = ref.get("rid", "?")
    table = ref.get("table", "?")
    token = ref.get("token", "?")
    offset = ref.get("file_offset") or "?"
    return f"`{table}#{rid}` ({token}, file {offset})"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit property/interface static contracts using dnfile metadata only."
    )
    parser.add_argument("assembly", type=Path)
    parser.add_argument(
        "--type",
        dest="types",
        action="append",
        default=[],
        help="target type full name or glob; repeatable (default: all non-interface types)",
    )
    parser.add_argument(
        "--interface",
        dest="interfaces",
        action="append",
        default=[],
        help="interface full name or glob; repeatable",
    )
    parser.add_argument(
        "--property",
        dest="properties",
        action="append",
        default=[],
        help="property name; repeatable (default: all interface properties)",
    )
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args(argv)

    view = MetadataView(args.assembly)
    findings = view.audit(args.types, args.interfaces, args.properties)
    document = {
        "source": str(args.assembly),
        "mode": "dnfile metadata-only; assembly not loaded",
        "warnings": list(view.pe.get_warnings()),
        "findings": findings,
    }
    text = json.dumps(document, indent=2, sort_keys=True, default=str)
    if args.json_out:
        args.json_out.write_text(text + "\n", encoding="utf-8")
    markdown = render_markdown(findings, args.assembly)
    if args.markdown_out:
        args.markdown_out.write_text(markdown, encoding="utf-8")
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
