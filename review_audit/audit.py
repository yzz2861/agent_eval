"""Offline provenance audit for generic, implementation, and interface entries.

The module only reads ECMA-335 metadata through dnfile.  It never resolves an
missing assembly by network or guesses that an unresolved external attribute
exists.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dnfile
from dnfile.enums import MetadataTables
from dnfile.utils import read_compressed_int


EXPECTED_STATEMENT = "CONFIDENTIAL-REVIEW-016"

KIND_LABELS = {
    "open_generic_definition": "开放泛型定义上的声明",
    "instance_implementation": "闭合/实例实现上的声明",
    "explicit_interface_declaration": "显式接口映射指向的接口声明",
    "external_pending": "外部程序集来源，待证",
    "unresolved": "未解析",
}

ELEMENT_TYPE_NAMES = {
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
    0x18: "native int",
    0x19: "native unsigned int",
    0x1C: "object",
}

TYPE_DEF_OR_REF_TABLES = ("TypeDef", "TypeRef", "TypeSpec")


def metadata_token(table_name: str, row_id: int) -> str:
    table_number = MetadataTables[table_name].value
    return f"0x{(table_number << 24) | row_id:08X}"


def text_value(value: Any) -> str:
    if value is None:
        return ""
    inner = getattr(value, "value", None)
    if isinstance(inner, str):
        return inner
    return str(value)


def blob_value(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    inner = getattr(value, "value", None)
    if isinstance(inner, bytes):
        return inner
    try:
        return value.value_bytes()
    except Exception:
        return b""


class ReviewAuditor:
    def __init__(self, assembly_path: str | Path, search_paths: Optional[List[str | Path]] = None):
        self.path = Path(assembly_path)
        self.pe = dnfile.dnPE(str(self.path))
        if not getattr(self.pe, "net", None) or not getattr(self.pe.net, "mdtables", None):
            raise ValueError(f"not a parseable .NET metadata assembly: {self.path}")
        self.mt = self.pe.net.mdtables
        self.search_dirs = [self.path.parent]
        for item in search_paths or []:
            self.search_dirs.append(Path(item))

        self.assembly_refs = self._read_assembly_refs()
        self.method_owner = self._read_method_owners()
        self.ca_by_owner = self._read_custom_attributes()
        self.security_by_owner = self._read_decl_security()
        self.generic_params, self.constraints_by_owner = self._read_generic_constraints()
        self.method_impls_by_body, self.method_impls_by_class = self._read_method_impls()
        self.interface_impls = self._read_interface_impls()

    def rows(self, table_name: str) -> List[Any]:
        table = getattr(self.mt, table_name, None)
        rows = getattr(table, "rows", None)
        return list(rows or [])

    def row(self, table_name: str, row_id: int) -> Optional[Any]:
        rows = self.rows(table_name)
        if row_id and 1 <= row_id <= len(rows):
            return rows[row_id - 1]
        return None

    def _read_assembly_refs(self) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for row_id, assembly_ref in enumerate(self.rows("AssemblyRef"), 1):
            name = text_value(assembly_ref.Name)
            version = (
                f"{assembly_ref.MajorVersion}.{assembly_ref.MinorVersion}."
                f"{assembly_ref.BuildNumber}.{assembly_ref.RevisionNumber}"
            )
            resolved_path: Optional[Path] = None
            for directory in self.search_dirs:
                for suffix in (".dll", ".exe", ".winmd"):
                    candidate = directory / f"{name}{suffix}"
                    if candidate.exists():
                        resolved_path = candidate.resolve()
                        break
                if resolved_path:
                    break
            result.append(
                {
                    "rid": row_id,
                    "token": metadata_token("AssemblyRef", row_id),
                    "name": name,
                    "version": version,
                    "resolved_path": str(resolved_path) if resolved_path else None,
                    "status": "available" if resolved_path else "pending_external_assembly",
                }
            )
        return result

    def assembly_ref_info(self, row_id: int) -> Dict[str, Any]:
        for item in self.assembly_refs:
            if item["rid"] == row_id:
                return item
        return {
            "rid": row_id,
            "token": metadata_token("AssemblyRef", row_id),
            "name": f"AssemblyRef:{row_id}",
            "status": "pending_external_assembly",
            "resolved_path": None,
        }

    def _read_method_owners(self) -> Dict[int, int]:
        owners: Dict[int, int] = {}
        for type_id, type_def in enumerate(self.rows("TypeDef"), 1):
            for method_index in getattr(type_def, "MethodList", []) or []:
                owners[method_index.row_index] = type_id
        return owners

    def type_full_name(self, type_id: int) -> str:
        type_def = self.row("TypeDef", type_id)
        if type_def is None:
            return f"TypeDef:{type_id}"
        name = text_value(type_def.TypeName)
        namespace = text_value(type_def.TypeNamespace)
        return f"{namespace}.{name}" if namespace else name

    def method_full_name(self, method_id: int) -> str:
        method = self.row("MethodDef", method_id)
        name = text_value(getattr(method, "Name", "")) or f"MethodDef:{method_id}"
        owner = self.method_owner.get(method_id)
        if owner:
            return f"{self.type_full_name(owner)}::{name}"
        return name

    def attribute_type_name(self, type_coded: Any) -> str:
        table_name = getattr(getattr(type_coded, "table", None), "name", "")
        row_id = getattr(type_coded, "row_index", 0)
        row = getattr(type_coded, "row", None)
        if table_name == "MethodDef" and row is not None:
            owner = self.method_owner.get(row_id)
            return self.type_full_name(owner) if owner else text_value(row.Name)
        if table_name == "MemberRef" and row is not None:
            parent = row.Class
            parent_row = getattr(parent, "row", None)
            parent_name = self.describe_type(
                getattr(getattr(parent, "table", None), "name", ""),
                getattr(parent, "row_index", 0),
                parent_row,
            ).get("name", "")
            return f"{parent_name}::{text_value(row.Name)}"
        return f"{table_name}:{row_id}"

    def decode_attribute_statement(self, ca_row: Any) -> Optional[str]:
        raw = blob_value(getattr(ca_row, "Value", None))
        if len(raw) < 3 or raw[0] != 0x01 or raw[1] != 0x00:
            return None
        decoded = read_compressed_int(raw[2:])
        if decoded is None:
            return None
        length, consumed = decoded
        start = 2 + consumed
        try:
            return raw[start : start + length].decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _read_custom_attributes(self) -> Dict[Tuple[str, int], List[Dict[str, Any]]]:
        grouped: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        for ca_id, ca in enumerate(self.rows("CustomAttribute"), 1):
            parent = ca.Parent
            table_name = getattr(getattr(parent, "table", None), "name", "Unknown")
            owner_id = getattr(parent, "row_index", 0)
            info = {
                "rid": ca_id,
                "token": metadata_token("CustomAttribute", ca_id),
                "owner_table": table_name,
                "owner_rid": owner_id,
                "owner_token": metadata_token(table_name, owner_id) if owner_id else None,
                "attribute_type": self.attribute_type_name(ca.Type),
                "statement": self.decode_attribute_statement(ca),
            }
            grouped.setdefault((table_name, owner_id), []).append(info)
        return grouped

    def _read_decl_security(self) -> Dict[Tuple[str, int], List[Dict[str, Any]]]:
        grouped: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        for security_id, security in enumerate(self.rows("DeclSecurity"), 1):
            parent = security.Parent
            table_name = getattr(getattr(parent, "table", None), "name", "Unknown")
            owner_id = getattr(parent, "row_index", 0)
            grouped.setdefault((table_name, owner_id), []).append(
                {
                    "rid": security_id,
                    "token": metadata_token("DeclSecurity", security_id),
                    "owner_table": table_name,
                    "owner_rid": owner_id,
                    "owner_token": metadata_token(table_name, owner_id),
                    "action": int(security.Action),
                    "permission_set_hex": blob_value(security.PermissionSet).hex(),
                }
            )
        return grouped

    def _read_generic_constraints(
        self,
    ) -> Tuple[List[Dict[str, Any]], Dict[Tuple[str, int], List[Dict[str, Any]]]]:
        generic_params: List[Dict[str, Any]] = []
        by_owner: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        constraints = self.rows("GenericParamConstraint")
        for param_id, param in enumerate(self.rows("GenericParam"), 1):
            owner = param.Owner
            owner_table = getattr(getattr(owner, "table", None), "name", "Unknown")
            owner_id = getattr(owner, "row_index", 0)
            param_constraints: List[Dict[str, Any]] = []
            for constraint_row in constraints:
                owner_index = getattr(constraint_row, "Owner", None)
                if getattr(owner_index, "row_index", 0) != param_id:
                    continue
                coded_constraint = constraint_row.Constraint
                param_constraints.append(self.describe_coded_type(coded_constraint))
            item = {
                "rid": param_id,
                "token": metadata_token("GenericParam", param_id),
                "name": text_value(param.Name) or f"T{param.Number}",
                "owner_table": owner_table,
                "owner_rid": owner_id,
                "owner_token": metadata_token(owner_table, owner_id) if owner_id else None,
                "constraints": param_constraints,
            }
            generic_params.append(item)
            by_owner.setdefault((owner_table, owner_id), []).append(item)
        return generic_params, by_owner

    def _read_method_impls(self) -> Tuple[Dict[int, List[Dict[str, Any]]], Dict[int, List[Dict[str, Any]]]]:
        by_body: Dict[int, List[Dict[str, Any]]] = {}
        by_class: Dict[int, List[Dict[str, Any]]] = {}
        for impl_id, impl in enumerate(self.rows("MethodImpl"), 1):
            class_id = impl.Class.row_index
            body = impl.MethodBody
            declaration = impl.MethodDeclaration
            item = {
                "rid": impl_id,
                "token": metadata_token("MethodImpl", impl_id),
                "class_rid": class_id,
                "class_token": metadata_token("TypeDef", class_id),
                "body_table": getattr(body.table, "name", None),
                "body_rid": body.row_index,
                "body_token": self.coded_token(body),
                "declaration_table": getattr(declaration.table, "name", None),
                "declaration_rid": declaration.row_index,
                "declaration_token": self.coded_token(declaration),
                "declaration_description": self.describe_method_def_or_ref(declaration),
            }
            if item["body_table"] == "MethodDef":
                by_body.setdefault(item["body_rid"], []).append(item)
            by_class.setdefault(class_id, []).append(item)
        return by_body, by_class

    def _read_interface_impls(self) -> List[Dict[str, Any]]:
        result = []
        for impl_id, impl in enumerate(self.rows("InterfaceImpl"), 1):
            interface = impl.Interface
            result.append(
                {
                    "rid": impl_id,
                    "token": metadata_token("InterfaceImpl", impl_id),
                    "class_rid": impl.Class.row_index,
                    "interface": self.describe_coded_type(interface),
                }
            )
        return result

    def coded_token(self, coded: Any) -> Optional[str]:
        table_name = getattr(getattr(coded, "table", None), "name", None)
        row_id = getattr(coded, "row_index", 0)
        if table_name and row_id:
            return metadata_token(table_name, row_id)
        return None

    def describe_method_def_or_ref(self, coded: Any) -> Dict[str, Any]:
        table_name = getattr(getattr(coded, "table", None), "name", "")
        row_id = getattr(coded, "row_index", 0)
        if table_name == "MethodDef":
            return {
                "table": table_name,
                "rid": row_id,
                "token": metadata_token(table_name, row_id),
                "name": self.method_full_name(row_id),
                "status": "metadata_verified",
            }
        if table_name == "MemberRef":
            member_ref = coded.row or self.row("MemberRef", row_id)
            parent = getattr(member_ref, "Class", None)
            external = self.coded_type_is_external(parent)
            return {
                "table": table_name,
                "rid": row_id,
                "token": metadata_token(table_name, row_id),
                "name": text_value(getattr(member_ref, "Name", "")),
                "parent": self.describe_coded_type(parent) if parent is not None else None,
                "status": "pending_external_assembly" if external else "metadata_verified",
            }
        return {"table": table_name, "rid": row_id, "status": "unresolved"}

    def coded_type_is_external(self, coded: Any) -> bool:
        description = self.describe_coded_type(coded)
        return description.get("status") == "pending_external_assembly"

    def describe_coded_type(self, coded: Any) -> Dict[str, Any]:
        table_name = getattr(getattr(coded, "table", None), "name", "")
        row_id = getattr(coded, "row_index", 0)
        row = getattr(coded, "row", None)
        return self.describe_type(table_name, row_id, row)

    def describe_type(
        self, table_name: str, row_id: int, row: Any = None
    ) -> Dict[str, Any]:
        if not row_id:
            return {"kind": "null", "table": table_name, "rid": 0, "status": "unresolved"}
        row = row or self.row(table_name, row_id)
        base: Dict[str, Any] = {
            "table": table_name,
            "rid": row_id,
            "token": metadata_token(table_name, row_id),
        }
        if row is None:
            base.update({"kind": "missing_metadata_row", "status": "unresolved"})
            return base

        if table_name == "TypeDef":
            base.update(
                {
                    "kind": "typedef",
                    "name": self.type_full_name(row_id),
                    "status": "metadata_verified",
                }
            )
            return base
        if table_name == "TypeRef":
            scope = row.ResolutionScope
            assembly: Optional[Dict[str, Any]] = None
            if getattr(getattr(scope, "table", None), "name", "") == "AssemblyRef":
                assembly = self.assembly_ref_info(scope.row_index)
            namespace = text_value(row.TypeNamespace)
            name = text_value(row.TypeName)
            base.update(
                {
                    "kind": "typeref",
                    "name": f"{namespace}.{name}" if namespace else name,
                    "assembly": assembly,
                    "status": (
                        "pending_external_assembly"
                        if assembly and assembly["status"] != "available"
                        else "external_available"
                        if assembly
                        else "metadata_verified"
                    ),
                }
            )
            return base
        if table_name == "TypeSpec":
            try:
                signature = self.decode_typespec(row_id)
                base.update(signature)
            except Exception as exc:
                base.update(
                    {
                        "kind": "typespec",
                        "signature_hex": blob_value(row.Signature).hex(),
                        "decode_error": str(exc),
                        "status": "metadata_verified",
                    }
                )
            return base
        base.update({"kind": table_name.lower(), "status": "metadata_verified"})
        return base

    def _read_coded_signature_index(self, data: bytes, position: int) -> Tuple[int, int]:
        decoded = read_compressed_int(data[position:])
        if decoded is None:
            raise ValueError("invalid compressed coded index in signature")
        value, consumed = decoded
        return value, position + consumed

    def describe_signature_coded_type(self, coded_value: int) -> Dict[str, Any]:
        row_id = coded_value >> 2
        table_name = TYPE_DEF_OR_REF_TABLES[coded_value & 0x03]
        return self.describe_type(table_name, row_id)

    def parse_signature_type(self, data: bytes, position: int) -> Tuple[Dict[str, Any], int]:
        if position >= len(data):
            raise ValueError("truncated type signature")
        element = data[position]
        position += 1

        if element == 0x15:
            kind_byte = data[position]
            position += 1
            coded_value, position = self._read_coded_signature_index(data, position)
            open_type = self.describe_signature_coded_type(coded_value)
            arg_count, position = self._read_coded_signature_index(data, position)
            arguments = []
            for _ in range(arg_count):
                argument, position = self.parse_signature_type(data, position)
                arguments.append(argument)
            return (
                {
                    "kind": "generic_instance",
                    "value_kind": "class" if kind_byte == 0x12 else "valuetype",
                    "open_type": open_type,
                    "arguments": arguments,
                    "name": self.format_generic_name(open_type, arguments),
                    "status": "metadata_verified",
                },
                position,
            )

        if element in (0x11, 0x12):
            coded_value, position = self._read_coded_signature_index(data, position)
            description = self.describe_signature_coded_type(coded_value)
            return description, position

        if element == 0x1D:
            element_type, position = self.parse_signature_type(data, position)
            return {"kind": "szarray", "element_type": element_type, "name": f"{element_type.get('name', '?')}[]"}, position

        if element in (0x13, 0x1E):
            number, position = self._read_coded_signature_index(data, position)
            name = ("!" if element == 0x13 else "!!") + str(number)
            return {"kind": "generic_variable", "index": number, "name": name}, position

        name = ELEMENT_TYPE_NAMES.get(element, f"element_0x{element:02x}")
        return {"kind": "element_type", "name": name}, position

    def format_generic_name(self, open_type: Dict[str, Any], arguments: List[Dict[str, Any]]) -> str:
        open_name = str(open_type.get("name", "?")).split("`", 1)[0]
        arg_names = ", ".join(str(arg.get("name", "?")) for arg in arguments)
        return f"{open_name}<{arg_names}>"

    def decode_typespec(self, type_spec_id: int) -> Dict[str, Any]:
        type_spec = self.row("TypeSpec", type_spec_id)
        data = blob_value(type_spec.Signature)
        parsed, _ = self.parse_signature_type(data, 0)
        parsed["signature_hex"] = data.hex()
        return parsed

    def constraints_for_typedef(self, type_id: int) -> List[Dict[str, Any]]:
        return self.constraints_by_owner.get(("TypeDef", type_id), [])

    def is_generic_typedef(self, type_id: int) -> bool:
        return bool(self.constraints_for_typedef(type_id)) or "`" in self.type_full_name(type_id)

    def find_method(self, type_id: int, method_name: str) -> Optional[int]:
        type_def = self.row("TypeDef", type_id)
        if type_def is None:
            return None
        for method_index in getattr(type_def, "MethodList", []) or []:
            method_id = method_index.row_index
            method = self.row("MethodDef", method_id)
            if method is not None and text_value(method.Name) == method_name:
                return method_id
        return None

    def generic_base_context(self, type_id: int) -> Optional[Dict[str, Any]]:
        type_def = self.row("TypeDef", type_id)
        extends = getattr(type_def, "Extends", None)
        if extends is None or not getattr(extends, "row_index", 0):
            return None
        if getattr(extends.table, "name", "") != "TypeSpec":
            return None
        spec = self.decode_typespec(extends.row_index)
        open_type = spec.get("open_type") or {}
        open_id = open_type.get("rid")
        return {
            "type_spec": spec,
            "open_typedef_rid": open_id,
            "open_type_name": self.type_full_name(int(open_id)) if open_id else None,
            "arguments": spec.get("arguments", []),
            "constraints": self.constraints_for_typedef(int(open_id)) if open_id else [],
        }

    def resolve_method_through_hierarchy(
        self, type_id: int, method_name: str
    ) -> Dict[str, Any]:
        trace: List[Dict[str, Any]] = []
        current = type_id
        generic_arguments: List[Dict[str, Any]] = []
        visited = set()

        while current and current not in visited:
            visited.add(current)
            trace.append(
                {
                    "step": "search_typedef",
                    **self.describe_type("TypeDef", current),
                }
            )
            method_id = self.find_method(current, method_name)
            if method_id:
                base_context = self.generic_base_context(current)
                return {
                    "status": "metadata_verified",
                    "method_rid": method_id,
                    "method_token": metadata_token("MethodDef", method_id),
                    "owner_typedef_rid": current,
                    "owner_token": metadata_token("TypeDef", current),
                    "owner_name": self.type_full_name(current),
                    "generic_arguments": generic_arguments,
                    "constraints": self.constraints_for_typedef(current),
                    "generic_base_instance": base_context,
                    "trace": trace,
                }

            type_def = self.row("TypeDef", current)
            extends = getattr(type_def, "Extends", None)
            if extends is None or not getattr(extends, "row_index", 0):
                break
            parent_table = getattr(extends.table, "name", "")
            parent_id = extends.row_index
            parent_description = self.describe_coded_type(extends)
            trace.append({"step": "extends", **parent_description})
            if parent_table == "TypeDef":
                current = parent_id
                continue
            if parent_table == "TypeSpec":
                spec = self.decode_typespec(parent_id)
                open_type = spec.get("open_type") or {}
                if open_type.get("table") != "TypeDef":
                    return {
                        "status": "unresolved_generic_definition",
                        "parent": parent_description,
                        "trace": trace,
                    }
                generic_arguments = spec.get("arguments", [])
                current = int(open_type["rid"])
                continue
            if parent_table == "TypeRef":
                return {
                    "status": "pending_external_assembly",
                    "external_type": parent_description,
                    "trace": trace,
                }
            break

        return {"status": "method_not_found", "trace": trace}

    def confidential_attributes(self, owner_table: str, owner_id: int) -> List[Dict[str, Any]]:
        result = []
        for ca in self.ca_by_owner.get((owner_table, owner_id), []):
            attribute_type = ca.get("attribute_type") or ""
            statement = ca.get("statement")
            if "Confidential" in attribute_type or statement == EXPECTED_STATEMENT:
                result.append(ca)
        return result

    def make_attribute_sources(
        self,
        kind: str,
        owner_table: str,
        owner_id: int,
        reason: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        attributes = self.confidential_attributes(owner_table, owner_id)
        if not attributes:
            return []
        owner_name = ""
        if owner_table == "MethodDef":
            owner_name = self.method_full_name(owner_id)
        elif owner_table == "TypeDef":
            owner_name = self.type_full_name(owner_id)
        source = {
            "kind": kind,
            "label": KIND_LABELS[kind],
            "owner_table": owner_table,
            "owner_rid": owner_id,
            "owner_token": metadata_token(owner_table, owner_id),
            "owner_name": owner_name,
            "reason": reason,
            "custom_attributes": attributes,
            "statements": [item.get("statement") for item in attributes if item.get("statement")],
            "reliability": "metadata_verified",
        }
        if extra:
            source.update(extra)
        return [source]

    def external_pending_source(self, description: Dict[str, Any], reason: str) -> Dict[str, Any]:
        assembly = description.get("assembly") or {}
        return {
            "kind": "external_pending",
            "label": KIND_LABELS["external_pending"],
            "reason": reason,
            "external_type": description,
            "assembly": assembly,
            "reliability": "pending_external_assembly",
        }

    def parse_reference(self, reference: str) -> Tuple[str, int]:
        text = reference.strip()
        if ":" in text and not text.lower().startswith("0x"):
            table_name, raw_id = text.split(":", 1)
            return table_name, int(raw_id)
        token = int(text, 16)
        table_number = (token >> 24) & 0x3F
        row_id = token & 0x00FFFFFF
        table_name = MetadataTables(table_number).name
        return table_name, row_id

    def audit_reference(self, reference: str) -> Dict[str, Any]:
        table_name, row_id = self.parse_reference(reference)
        if table_name == "MemberRef":
            return self.audit_member_ref(row_id, reference)
        if table_name == "MethodDef":
            return self.audit_method_def(row_id, reference)
        return {
            "reference": reference,
            "status": "unsupported_reference",
            "message": f"acceptance auditor handles MemberRef/MethodDef, got {table_name}",
        }

    def audit_member_ref(self, member_ref_id: int, reference: str) -> Dict[str, Any]:
        member_ref = self.row("MemberRef", member_ref_id)
        if member_ref is None:
            return {"reference": reference, "status": "not_found"}
        member_name = text_value(member_ref.Name)
        parent = member_ref.Class
        parent_table = getattr(parent.table, "name", "")
        parent_id = parent.row_index
        result: Dict[str, Any] = {
            "reference": reference,
            "entry_token": metadata_token("MemberRef", member_ref_id),
            "entry_kind": "MemberRef",
            "member_name": member_name,
            "member_ref": {
                "token": metadata_token("MemberRef", member_ref_id),
                "name": member_name,
                "parent": self.describe_coded_type(parent),
            },
            "sources": [],
            "pending": [],
        }

        resolution: Dict[str, Any]
        if parent_table == "TypeDef":
            result["entry_name"] = f"{self.type_full_name(parent_id)}::{member_name}"
            resolution = self.resolve_method_through_hierarchy(parent_id, member_name)
        elif parent_table == "TypeSpec":
            spec = self.decode_typespec(parent_id)
            result["closed_type"] = spec
            open_type = spec.get("open_type") or {}
            result["entry_name"] = f"{spec.get('name', metadata_token('TypeSpec', parent_id))}::{member_name}"
            if open_type.get("table") == "TypeDef":
                open_id = int(open_type["rid"])
                method_id = self.find_method(open_id, member_name)
                resolution = {
                    "status": "metadata_verified" if method_id else "method_not_found",
                    "method_rid": method_id,
                    "method_token": metadata_token("MethodDef", method_id) if method_id else None,
                    "owner_typedef_rid": open_id,
                    "owner_name": self.type_full_name(open_id),
                    "generic_arguments": spec.get("arguments", []),
                    "constraints": self.constraints_for_typedef(open_id),
                    "trace": [{"step": "typespec", **spec}],
                }
            else:
                resolution = {"status": "unresolved_generic_definition"}
        elif parent_table == "TypeRef":
            description = self.describe_coded_type(parent)
            result["entry_name"] = f"{description.get('name')}::{member_name}"
            pending = self.external_pending_source(description, "MemberRef parent is an unresolved TypeRef")
            result["sources"].append(pending)
            result["pending"].append(pending)
            result["status"] = "pending"
            return self.finalize_entry(result)
        else:
            resolution = {"status": f"unsupported_parent_{parent_table}"}

        result["resolution"] = self._json_safe(resolution)
        if resolution.get("status") == "pending_external_assembly":
            pending = self.external_pending_source(
                resolution.get("external_type") or {},
                "base type in inheritance chain belongs to a missing assembly",
            )
            result["sources"].append(pending)
            result["pending"].append(pending)
            result["status"] = "pending"
            return self.finalize_entry(result)

        method_id = resolution.get("method_rid")
        owner_id = resolution.get("owner_typedef_rid")
        if not method_id or not owner_id:
            result["status"] = "no_declaration_found"
            return self.finalize_entry(result)

        kind = (
            "open_generic_definition"
            if self.is_generic_typedef(owner_id)
            else "instance_implementation"
        )
        result["sources"].extend(
            self.make_attribute_sources(
                kind,
                "MethodDef",
                int(method_id),
                "CustomAttribute.Parent directly names the resolved MethodDef",
                {
                    "closed_generic_arguments": (
                        resolution.get("generic_arguments")
                        or (resolution.get("generic_base_instance") or {}).get("arguments", [])
                    ),
                    "generic_base_instance": resolution.get("generic_base_instance"),
                    "generic_constraints": (
                        resolution.get("constraints")
                        or (resolution.get("generic_base_instance") or {}).get("constraints", [])
                    ),
                },
            )
        )

        if not result["sources"]:
            base_resolution = self.resolve_base_method(owner_id, member_name)
            result["base_resolution"] = self._json_safe(base_resolution)
            base_method = base_resolution.get("method_rid")
            base_owner = base_resolution.get("owner_typedef_rid")
            if base_method and base_owner:
                base_kind = (
                    "open_generic_definition"
                    if self.is_generic_typedef(int(base_owner))
                    else "instance_implementation"
                )
                result["sources"].extend(
                    self.make_attribute_sources(
                        base_kind,
                        "MethodDef",
                        int(base_method),
                        "No statement on nearest method; using inherited base MethodDef",
                        {
                            "closed_generic_arguments": base_resolution.get("generic_arguments", []),
                            "generic_constraints": base_resolution.get("constraints", []),
                        },
                    )
                )

        constraints = resolution.get("constraints", [])
        base_context = resolution.get("generic_base_instance") or {}
        if not constraints:
            constraints = base_context.get("constraints", [])
        self.add_constraint_pending(result, constraints)
        return self.finalize_entry(result)

    def resolve_base_method(self, owner_id: int, method_name: str) -> Dict[str, Any]:
        type_def = self.row("TypeDef", owner_id)
        extends = getattr(type_def, "Extends", None)
        if extends is None or not extends.row_index:
            return {"status": "no_base"}
        if extends.table.name == "TypeDef":
            return self.resolve_method_through_hierarchy(extends.row_index, method_name)
        if extends.table.name == "TypeSpec":
            spec = self.decode_typespec(extends.row_index)
            open_type = spec.get("open_type") or {}
            if open_type.get("rid"):
                resolution = self.resolve_method_through_hierarchy(int(open_type["rid"]), method_name)
                resolution["generic_arguments"] = spec.get("arguments", [])
                return resolution
        if extends.table.name == "TypeRef":
            return {"status": "pending_external_assembly", "external_type": self.describe_coded_type(extends)}
        return {"status": "base_not_resolved"}

    def audit_method_def(self, method_id: int, reference: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "reference": reference,
            "entry_token": metadata_token("MethodDef", method_id),
            "entry_kind": "MethodDef",
            "entry_name": self.method_full_name(method_id),
            "sources": [],
            "pending": [],
        }
        owner = self.method_owner.get(method_id)
        result["owner_typedef_token"] = metadata_token("TypeDef", owner) if owner else None

        result["sources"].extend(
            self.make_attribute_sources(
                "instance_implementation",
                "MethodDef",
                method_id,
                "CustomAttribute.Parent names the implementation MethodDef",
            )
        )

        for impl in self.method_impls_by_body.get(method_id, []):
            declaration = impl["declaration_description"]
            result.setdefault("method_impls", []).append(impl)
            if impl["declaration_table"] == "MethodDef":
                interface_method_id = impl["declaration_rid"]
                interface_owner = self.method_owner.get(interface_method_id)
                interface_impl = self.find_interface_impl(impl["class_rid"], interface_owner)
                extra = {
                    "method_impl": impl,
                    "interface_impl": interface_impl,
                }
                result["sources"].extend(
                    self.make_attribute_sources(
                        "explicit_interface_declaration",
                        "MethodDef",
                        interface_method_id,
                        "MethodImpl.MethodDeclaration names the interface MethodDef",
                        extra,
                    )
                )
            elif declaration.get("status") == "pending_external_assembly":
                parent = declaration.get("parent") or {}
                pending = self.external_pending_source(
                    parent,
                    "MethodImpl.MethodDeclaration is a MemberRef to a method in a missing assembly",
                )
                pending["method_impl"] = impl
                result["sources"].append(pending)
                result["pending"].append(pending)

        if owner:
            constraints = self.constraints_for_typedef(owner)
            result["generic_constraints"] = constraints
            self.add_constraint_pending(result, constraints)
        return self.finalize_entry(result)

    def find_interface_impl(self, class_id: int, interface_type_id: Optional[int]) -> Optional[Dict[str, Any]]:
        for item in self.interface_impls:
            if item["class_rid"] != class_id:
                continue
            interface = item.get("interface") or {}
            if interface_type_id and interface.get("rid") == interface_type_id:
                return item
        return next((item for item in self.interface_impls if item["class_rid"] == class_id), None)

    def add_constraint_pending(self, result: Dict[str, Any], constraints: List[Dict[str, Any]]) -> None:
        for param in constraints:
            for constraint in param.get("constraints", []):
                if constraint.get("status") == "pending_external_assembly":
                    pending = self.external_pending_source(
                        constraint,
                        f"Generic parameter {param.get('name')} constraint references a missing assembly",
                    )
                    pending["generic_parameter"] = {k: param[k] for k in ("token", "name") if k in param}
                    result["pending"].append(pending)

    def finalize_entry(self, result: Dict[str, Any]) -> Dict[str, Any]:
        verified = [s for s in result.get("sources", []) if s.get("reliability") == "metadata_verified"]
        pending = result.get("pending", [])
        kinds = [s.get("kind") for s in verified]
        if "explicit_interface_declaration" in kinds:
            primary = "explicit_interface_declaration"
        elif "open_generic_definition" in kinds:
            primary = "open_generic_definition"
        elif "instance_implementation" in kinds:
            primary = "instance_implementation"
        else:
            primary = None
        statements = set()
        for source in verified:
            for statement in source.get("statements", []):
                if statement:
                    statements.add(statement)
        result["primary_kind"] = primary
        result["primary_label"] = KIND_LABELS.get(primary or "unresolved", KIND_LABELS["unresolved"])
        result["statements"] = sorted(statements)
        result["statement_match"] = EXPECTED_STATEMENT in statements
        if verified and result.get("statement_match"):
            result["status"] = "supported_with_pending_external_evidence" if pending else "supported"
        elif pending:
            result["status"] = "pending"
        else:
            result["status"] = result.get("status") or "unsupported"
        result["pending_assembly_names"] = sorted(
            {
                (item.get("assembly") or {}).get("name")
                for item in pending
                if (item.get("assembly") or {}).get("name")
            }
        )
        return result

    def external_member_refs(self) -> List[Dict[str, Any]]:
        result = []
        for ref_id, member_ref in enumerate(self.rows("MemberRef"), 1):
            parent = member_ref.Class
            description = self.describe_coded_type(parent)
            if description.get("status") == "pending_external_assembly":
                result.append(
                    {
                        "token": metadata_token("MemberRef", ref_id),
                        "name": text_value(member_ref.Name),
                        "parent": description,
                        "status": "pending_external_assembly",
                    }
                )
        return result

    def build_report(self, references: List[str]) -> Dict[str, Any]:
        entries = [self.audit_reference(reference) for reference in references]
        return {
            "assembly": str(self.path.resolve()),
            "assembly_name": self.local_assembly_name(),
            "expected_statement": EXPECTED_STATEMENT,
            "assembly_refs": self.assembly_refs,
            "external_member_refs": self.external_member_refs(),
            "generic_parameters": self.generic_params,
            "entries": self._json_safe(entries),
        }

    def local_assembly_name(self) -> str:
        assembly = self.row("Assembly", 1)
        return text_value(getattr(assembly, "Name", "")) if assembly else ""

    def _json_safe(self, value: Any) -> Any:
        return json.loads(json.dumps(value, default=str))


ACCEPTANCE_REFERENCES = [
    "0x0A000001",  # MemberRef ReviewAudit.IntBox::Read
    "0x0A000002",  # MemberRef ReviewAudit.StringBox::Write
    "0x06000005",  # MethodDef ExplicitEndpoint::ConfirmExplicit
]


def render_text(report: Dict[str, Any]) -> str:
    lines = [
        f"程序集: {report['assembly_name']} ({report['assembly']})",
        f"保密声明标识: {report['expected_statement']}",
        "",
    ]
    for index, entry in enumerate(report["entries"], 1):
        lines.append(f"[{index}] {entry.get('entry_name')} ({entry.get('entry_token')})")
        lines.append(f"    状态: {entry.get('status')}")
        lines.append(f"    分类: {entry.get('primary_label')}")
        for source in entry.get("sources", []):
            if source.get("reliability") != "metadata_verified":
                continue
            lines.append(
                f"    可依赖来源: {source.get('label')} -> "
                f"{source.get('owner_name')} {source.get('owner_token')}"
            )
            for ca in source.get("custom_attributes", []):
                lines.append(
                    f"      - {ca.get('token')} {ca.get('attribute_type')} "
                    f"Owner={ca.get('owner_table')}:{ca.get('owner_rid')} "
                    f"statement={ca.get('statement')}"
                )
            if source.get("closed_generic_arguments"):
                args = ", ".join(arg.get("name", "?") for arg in source["closed_generic_arguments"])
                lines.append(f"      闭合实例: {args}")
            if source.get("generic_constraints"):
                for param in source["generic_constraints"]:
                    for constraint in param.get("constraints", []):
                        status = constraint.get("status")
                        lines.append(
                            f"      约束: {param.get('name')} : {constraint.get('name')} [{status}]"
                        )
            if source.get("interface_impl"):
                impl = source["interface_impl"]
                lines.append(f"      接口实现证据: {impl.get('token')}")
            if source.get("method_impl"):
                lines.append(f"      显式映射: {source['method_impl'].get('token')}")
        for pending in entry.get("pending", []):
            assembly = pending.get("assembly") or {}
            lines.append(
                f"    待证: {pending.get('reason')} -> "
                f"{assembly.get('name')} {assembly.get('token')}"
            )
        lines.append("")

    lines.append("外部程序集引用:")
    for assembly in report["assembly_refs"]:
        if assembly["status"] == "available":
            lines.append(f"  - {assembly['name']} {assembly['token']} -> {assembly['resolved_path']}")
        else:
            lines.append(
                f"  - {assembly['name']} {assembly['version']} {assembly['token']} -> 未交接/未找到，保留待证"
            )
    for member_ref in report["external_member_refs"]:
        parent = member_ref.get("parent") or {}
        assembly = parent.get("assembly") or {}
        lines.append(
            f"  - 外部成员 {member_ref['token']} {parent.get('name')}::{member_ref['name']} "
            f"依赖 {assembly.get('name')}，不得据其推断属性"
        )
    return "\n".join(lines)


def render_markdown(report: Dict[str, Any]) -> str:
    def md_text(value: Any) -> str:
        return str(value if value is not None else "").replace("`", "&#96;").replace("|", "\\|")

    lines = [
        "# 泛型保密声明复核结果",
        "",
        f"- 程序集：`{report['assembly_name']}`",
        f"- 声明标识：`{report['expected_statement']}`",
        "",
        "| 入口 | 状态 | 判定位置 | 可依赖来源 | 待证外部引用 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in report["entries"]:
        source_names = []
        for source in entry.get("sources", []):
            if source.get("reliability") == "metadata_verified":
                source_names.append(
                    f"`{source.get('owner_token')}` {md_text(source.get('owner_name'))}（{source.get('label')}）"
                )
        pending = ", ".join(f"`{name}`" for name in entry.get("pending_assembly_names", [])) or "无"
        lines.append(
            f"| `{entry.get('entry_token')}` {md_text(entry.get('entry_name'))} "
            f"| {entry.get('status')} | {entry.get('primary_label')} "
            f"| {'；'.join(source_names) or '无'} | {pending} |"
        )
    lines.extend(["", "## 外部引用", ""])
    for assembly in report["assembly_refs"]:
        verdict = "已找到" if assembly["status"] == "available" else "缺失，保留待证"
        lines.append(f"- `{assembly['token']}` `{md_text(assembly['name'])}` {assembly['version']}：{verdict}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Audit confidentiality declaration ownership with dnfile.")
    parser.add_argument("assembly", type=Path, help="managed assembly to inspect offline")
    parser.add_argument("--entry", action="append", default=[], help="token or Table:rid; repeatable")
    parser.add_argument("--search-dir", action="append", default=[], help="directory for handed-off referenced assemblies")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    args = parser.parse_args(argv)

    auditor = ReviewAuditor(args.assembly, args.search_dir)
    references = args.entry or ACCEPTANCE_REFERENCES
    report = auditor.build_report(references)
    print(render_text(report))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
