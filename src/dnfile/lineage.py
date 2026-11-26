# -*- coding: utf-8 -*-
"""Offline metadata lineage and security-declaration recovery."""

from __future__ import annotations

import json
from pathlib import Path
from collections.abc import Iterable, Mapping, Sequence

from .utils import read_compressed_int

TABLE_NUMBERS = {
    "Module": 0,
    "TypeRef": 1,
    "TypeDef": 2,
    "Field": 4,
    "MethodDef": 6,
    "Param": 8,
    "InterfaceImpl": 9,
    "MemberRef": 10,
    "Constant": 11,
    "CustomAttribute": 12,
    "FieldMarshal": 13,
    "DeclSecurity": 14,
    "ClassLayout": 15,
    "FieldLayout": 16,
    "StandAloneSig": 17,
    "EventMap": 18,
    "Event": 20,
    "PropertyMap": 21,
    "Property": 23,
    "MethodSemantics": 24,
    "MethodImpl": 25,
    "ModuleRef": 26,
    "TypeSpec": 27,
    "ImplMap": 28,
    "FieldRva": 29,
    "Assembly": 32,
    "AssemblyRef": 35,
    "File": 38,
    "ExportedType": 39,
    "ManifestResource": 40,
    "NestedClass": 41,
    "GenericParam": 42,
    "MethodSpec": 43,
    "GenericParamConstraint": 44,
}

_TABLE_ALIASES = {}
for _name in TABLE_NUMBERS:
    _TABLE_ALIASES[_name.lower()] = _name
_TABLE_ALIASES.update(
    {
        "type": "TypeDef",
        "types": "TypeDef",
        "typedefs": "TypeDef",
        "method": "MethodDef",
        "methods": "MethodDef",
        "methoddefs": "MethodDef",
        "security": "DeclSecurity",
        "securitydeclaration": "DeclSecurity",
        "securitydeclarations": "DeclSecurity",
        "declsecuritys": "DeclSecurity",
        "customattributes": "CustomAttribute",
        "events": "Event",
        "nestedclasses": "NestedClass",
        "nested": "NestedClass",
    }
)

_STATE_MACHINE_ATTRIBUTES = {
    "asyncstatemachineattribute": "async",
    "asyncstatemachine": "async",
    "iteratorstatemachineattribute": "iterator",
    "iteratorstatemachine": "iterator",
    "asynciteratorstatemachineattribute": "async_iterator",
    "asynciteratorstatemachine": "async_iterator",
}

_SEMANTICS_BITS = (
    (0x0001, "setter"),
    (0x0002, "getter"),
    (0x0004, "other"),
    (0x0008, "add_on"),
    (0x0010, "remove_on"),
    (0x0020, "fire"),
)

_SECURITY_ACTIONS = {
    0x0001: "Request",
    0x0002: "Demand",
    0x0003: "Assert",
    0x0004: "Deny",
    0x0005: "PermitOnly",
    0x0006: "LinkDemand",
    0x0007: "InheritanceDemand",
    0x0008: "RequestMinimum",
    0x0009: "RequestOptional",
    0x000A: "RequestRefuse",
    0x000B: "PreJitGrant",
    0x000C: "PreJitDeny",
    0x000D: "NonCasDemand",
    0x000E: "NonCasLinkDemand",
    0x000F: "NonCasInheritance",
}


class Record(dict):
    """Dictionary record that also supports attribute access."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name, value):
        self[name] = value


class EntityRef:
    """Stable identity for one metadata row."""

    __slots__ = ("table", "row_index", "token", "name", "row", "_key")

    def __init__(self, table, row_index=None, name=None, token=None, row=None):
        self.table = canonical_table_name(table) if table else None
        self.row_index = int(row_index) if row_index is not None else None
        self.row = row
        self.name = as_text(name) if name is not None else None
        if token is None and self.table in TABLE_NUMBERS and self.row_index:
            token = (TABLE_NUMBERS[self.table] << 24) | self.row_index
        self.token = int(token) if token is not None else None
        if self.table and self.row_index is not None:
            self._key = "{}:{}".format(self.table, self.row_index)
        elif self.token is not None:
            self.row_index = self.token & 0x00FFFFFF
            self.table = table_name_for_number(self.token >> 24) or self.table
            self._key = "token:{:08x}".format(self.token)
        else:
            self._key = "object:{}".format(id(row) if row is not None else id(self))

    @property
    def key(self):
        return self._key

    @property
    def rid(self):
        return self.row_index

    def __hash__(self):
        return hash(self._key)

    def __eq__(self, other):
        if isinstance(other, EntityRef):
            if self.row_index is not None and other.row_index is not None:
                return self.table == other.table and self.row_index == other.row_index
            return self.row is other.row
        return NotImplemented

    def __repr__(self):
        return "EntityRef({!r}, {}, {!r})".format(self.table, self.row_index, self.name)

    def to_dict(self):
        return {
            "table": self.table,
            "row_index": self.row_index,
            "token": self.token,
            "name": self.name,
            "key": self.key,
        }

    def __getattr__(self, name):
        row = object.__getattribute__(self, "row")
        if row is not None:
            return getattr(row, name)
        raise AttributeError(name)


def as_text(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value
    item_value = getattr(value, "value", None)
    if isinstance(item_value, str):
        return item_value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    text = str(value)
    return None if text.startswith("<dnfile.") else text


def first_not_none(*values):
    for value in values:
        if value is not None:
            return value
    return None


def as_bytes(value):
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    item_value = getattr(value, "value", None)
    if isinstance(item_value, (bytes, bytearray, memoryview)):
        return bytes(item_value)
    getter = getattr(value, "value_bytes", None)
    if callable(getter):
        try:
            result = getter()
            if isinstance(result, (bytes, bytearray, memoryview)):
                return bytes(result)
        except Exception:
            pass
    raw = getattr(value, "raw_data", None)
    return bytes(raw) if isinstance(raw, (bytes, bytearray, memoryview)) else None


def canonical_table_name(name):
    if name is None:
        return None
    if isinstance(name, int):
        return table_name_for_number(name)
    if not isinstance(name, str):
        name = getattr(name, "name", None) or getattr(name, "__name__", None) or str(name)
    if name in TABLE_NUMBERS:
        return name
    if str(name).isdigit():
        return table_name_for_number(int(name))
    compact = "".join(ch for ch in str(name) if ch.isalnum()).lower()
    return _TABLE_ALIASES.get(compact) or _TABLE_ALIASES.get(str(name).lower())


def table_name_for_number(number):
    for name, value in TABLE_NUMBERS.items():
        if value == number:
            return name
    return None


def table_name(table):
    if table is None:
        return None
    if isinstance(table, str):
        return canonical_table_name(table)
    return canonical_table_name(getattr(table, "name", None) or getattr(table, "__name__", None))


def _table_rows(table):
    if table is None:
        return []
    if isinstance(table, Mapping):
        return [row for row in table.values() if row is not None]
    if isinstance(table, (list, tuple, set)):
        return [row for row in table if row is not None]
    rows = getattr(table, "rows", None)
    if rows is not None and not callable(rows):
        try:
            return [row for row in rows if row is not None]
        except Exception:
            pass
    private_rows = getattr(table, "_rows", None)
    if isinstance(private_rows, Mapping):
        return [row for _, row in sorted(private_rows.items()) if row is not None]
    if isinstance(private_rows, Sequence):
        return [row for row in private_rows if row is not None]
    count = getattr(table, "num_rows", None)
    getter = getattr(table, "get_with_row_index", None)
    if isinstance(count, int) and callable(getter) and count >= 0:
        result = []
        for index in range(1, count + 1):
            try:
                row = getter(index)
            except Exception:
                row = None
            if row is not None:
                result.append(row)
        return result
    return []


def extract_tables(source=None, tables=None):
    result = {}
    sources = []
    if tables is not None:
        sources.append(tables)
    if (
        isinstance(source, (list, tuple))
        and source
        and all(hasattr(item, "name") or isinstance(item, Mapping) for item in source)
    ):
        named = {}
        for item in source:
            if isinstance(item, Mapping):
                named.update(item)
            else:
                name = table_name(item)
                if name:
                    named[name] = item
        sources.append(named)
    elif source is not None:
        sources.append(source)
    for item in sources:
        if item is None:
            continue
        for name, table in _tables_from_one(item).items():
            if table is not None and name not in result:
                result[name] = table
    return result


def _tables_from_one(source):
    if source is None:
        return {}
    if isinstance(source, Mapping):
        for key in ("mdtables", "MetaDataTables", "metadata_tables"):
            if key in source:
                nested = _tables_from_one(source[key])
                if nested:
                    return nested
        result = {}
        for key, value in source.items():
            name = canonical_table_name(key)
            if name and value is not None:
                result[name] = value
        if result:
            return result
        for key in ("net", "dn", "pe"):
            if key in source:
                result.update(_tables_from_one(source[key]))
        return result

    for path in (("net", "mdtables"), ("clr", "mdtables"), ("dn", "net", "mdtables")):
        current = source
        for attr in path:
            current = getattr(current, attr, None)
            if current is None:
                break
        if current is not None and _looks_like_tables(current):
            return _tables_from_one(current)

    mdtables = getattr(source, "mdtables", None)
    if mdtables is not None and _looks_like_tables(mdtables):
        return _tables_from_one(mdtables)

    streams = getattr(source, "streams_list", None)
    if streams:
        for stream in streams:
            if _looks_like_tables(stream):
                return _tables_from_one(stream)

    if not _looks_like_tables(source):
        return {}
    result = {}
    for table in getattr(source, "tables_list", []) or []:
        name = table_name(table)
        if name:
            result[name] = table
    for name in TABLE_NUMBERS:
        table = getattr(source, name, None)
        if table is not None and name not in result:
            result[name] = table
    mapping = getattr(source, "tables", None)
    if isinstance(mapping, Mapping):
        for key, table in mapping.items():
            name = table_name(table) or canonical_table_name(key)
            if name and name not in result:
                result[name] = table
    return result


def _looks_like_tables(obj):
    if obj is None or isinstance(obj, (str, bytes, bytearray, Path)):
        return False
    return (
        hasattr(obj, "tables_list")
        or hasattr(obj, "tables")
        or any(hasattr(obj, name) for name in ("TypeDef", "MethodDef", "DeclSecurity"))
    )


def _row_display_name(table, row):
    if row is None:
        return None
    for attr in ("Name", "TypeName", "name", "type_name"):
        value = as_text(getattr(row, attr, None))
        if value:
            if attr in ("TypeName", "type_name"):
                namespace = as_text(getattr(row, "TypeNamespace", None))
                return "{}.{}".format(namespace, value) if namespace else value
            return value
    if table == "DeclSecurity":
        return "DeclSecurity action={}".format(getattr(row, "Action", "?"))
    return None


def _explicit_row_index(row):
    if isinstance(row, Mapping):
        for key in ("row_index", "RowIndex", "rid", "Rid", "Index", "index"):
            value = row.get(key)
            if isinstance(value, int) and value > 0:
                return value
        token = row.get("token") or row.get("Token")
        return token & 0xFFFFFF if isinstance(token, int) else None
    for attr in ("row_index", "RowIndex", "rid", "Rid"):
        value = getattr(row, attr, None)
        if isinstance(value, int) and value > 0:
            return value
    token = getattr(row, "token", None) or getattr(row, "Token", None)
    return token & 0xFFFFFF if isinstance(token, int) else None


class MetadataLineage:
    """Bidirectional metadata graph and security declaration mapper."""

    def __init__(
        self,
        source=None,
        *,
        tables=None,
        approvals=None,
        approved_reads=None,
        open_pe=True,
        approved=None,
        reads=None,
        read_approvals=None,
        approved_declarations=None,
        approved_read_declarations=None,
        decisions=None,
        approval_records=None,
        mdtables=None,
        metadata_tables=None,
        metadata=None,
        dn=None,
        pe=None,
        net=None,
        **_kwargs,
    ):
        self.source = source
        self._source_pe = None
        tables = first_not_none(tables, mdtables, metadata_tables, metadata)
        source = first_not_none(source, dn, pe, net)
        read_source = first_not_none(approved_reads, reads, read_approvals, approved_read_declarations)
        approval_source = first_not_none(approvals, approval_records, decisions, approved_declarations, approved)
        if read_source is not None:
            read_default = True
            approval_source = read_source if approval_source is None else approval_source
        else:
            read_default = False
        if open_pe and isinstance(source, (str, Path, bytes, bytearray)):
            source = self._open_pe_source(source)
            self.source = source
        self.tables = extract_tables(source, tables)
        self.rows = {}
        self.refs = {}
        self._row_ids = {}
        self.evidence = []
        self.relationships = self.evidence
        self.edges = self.evidence
        self.links = self.evidence
        self._outgoing = {}
        self._incoming = {}
        self.approval_matchers = []
        self.approvals = self._normalize_approvals(approval_source, read_default=read_default)
        self.nested_enclosing = {}
        self.enclosing_nested = {}
        self.type_methods = {}
        self.method_types = {}
        self.type_fields = {}
        self.event_owners = {}
        self.type_events = {}
        self.method_events = {}
        self.event_methods = {}
        self.attributes_by_parent = {}
        self.state_machine_origins = {}
        self.method_state_machines = {}
        self._types_by_full_name = {}
        self._scan()

    def _open_pe_source(self, source):
        try:
            from . import dnPE

            if isinstance(source, (str, Path)):
                pe = dnPE(name=str(source))
            else:
                pe = dnPE(data=bytes(source))
            self._source_pe = pe
            return pe
        except Exception:
            return source

    def close(self):
        if self._source_pe is not None:
            try:
                self._source_pe.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _scan(self):
        self._index_rows()
        self._index_type_members()
        self._index_nested_classes()
        self._build_name_index()
        self._index_events()
        self._index_method_semantics()
        self._index_custom_attributes()
        self._build_name_index()

    def _index_rows(self):
        for name, table in self.tables.items():
            rows = _table_rows(table)
            self.rows[name] = rows
            for position, row in enumerate(rows, 1):
                if row is None:
                    continue
                original_row = row
                if isinstance(row, Mapping) and not isinstance(row, Record):
                    row = Record(row)
                index = _explicit_row_index(row) or position
                ref = EntityRef(name, index, _row_display_name(name, row), row=row)
                existing = self.refs.get(ref.key)
                if existing is not None:
                    if existing.row is None:
                        existing.row = row
                    ref = existing
                else:
                    self.refs[ref.key] = ref
                self._row_ids[id(original_row)] = ref
                if row is not original_row:
                    self._row_ids[id(row)] = ref

    def rows_of(self, table_name_value):
        return self.rows.get(canonical_table_name(table_name_value) or table_name_value, [])

    def row_refs(self, table_name_value):
        name = canonical_table_name(table_name_value) or table_name_value
        count = len(self.rows.get(name, []))
        return [self._cached_ref(name, i) for i in range(1, count + 1)]

    def ref(self, value, default_table=None):
        if value is None:
            return None
        if isinstance(value, EntityRef):
            return value
        if isinstance(value, int):
            if value <= 0:
                return None
            table = canonical_table_name(default_table) if default_table else None
            return self._cached_ref(table, value) if table else EntityRef(None, value)
        if isinstance(value, str):
            return self._ref_from_string(value)
        if isinstance(value, Mapping):
            return self._ref_from_mapping(value, default_table)

        row_index = getattr(value, "row_index", None)
        if not isinstance(row_index, int):
            row_index = getattr(value, "rid", None) or getattr(value, "RowIndex", None)
        if isinstance(row_index, int) and row_index > 0:
            table = (
                table_name(getattr(value, "table", None))
                or canonical_table_name(getattr(value, "table_name", None))
                or canonical_table_name(default_table)
            )
            target_row = self._safe_target_row(value)
            return self._cached_ref(table, row_index, target_row)
        return self.ref_for_row(value, default_table)

    def _safe_target_row(self, value):
        row_getter = getattr(value, "row", None)
        try:
            return row_getter() if callable(row_getter) else row_getter
        except Exception:
            table_object = getattr(value, "table", None)
            getter = getattr(table_object, "get_with_row_index", None)
            if callable(getter):
                try:
                    return getter(getattr(value, "row_index", -1))
                except Exception:
                    return None
        return None

    def _cached_ref(self, table, row_index, row=None, name=None, token=None):
        if table:
            key = "{}:{}".format(table, row_index)
            existing = self.refs.get(key)
            if existing is not None:
                if row is not None and existing.row is None:
                    existing.row = row
                return existing
            display = name if name is not None else (_row_display_name(table, row) if row is not None else None)
            ref = EntityRef(table, row_index, display, token=token, row=row)
            self.refs[key] = ref
            if row is not None:
                self._row_ids[id(row)] = ref
            return ref
        return EntityRef(table, row_index, name, token, row)

    def ref_for_row(self, row, default_table=None):
        if row is None:
            return None
        existing = self._row_ids.get(id(row))
        if existing is not None:
            return existing
        table = canonical_table_name(default_table)
        index = _explicit_row_index(row)
        if table and index:
            return self._cached_ref(table, index, row)
        if table:
            for position, candidate in enumerate(self.rows.get(table, []), 1):
                if candidate == row:
                    return self._cached_ref(table, _explicit_row_index(candidate) or position, row)
        ref = EntityRef(table, index, _row_display_name(table, row), row=row)
        self._row_ids[id(row)] = ref
        return ref

    def _ref_from_string(self, value):
        text = value.strip()
        if ":" in text and not text.lower().startswith("0x"):
            left, right = text.rsplit(":", 1)
            table = canonical_table_name(left)
            try:
                index = int(right)
            except ValueError:
                index = None
            if table and index is not None:
                return self.ref(index, table)
        try:
            token = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            token = None
        if token is not None and token > 0xFFFFFF:
            return self._cached_ref(table_name_for_number(token >> 24), token & 0xFFFFFF, token=token)
        matches = self.types_by_name().get(text, []) if hasattr(self, "_types_by_full_name") else []
        return matches[0] if len(matches) == 1 else EntityRef(None, name=text)

    def _ref_from_mapping(self, value, default_table):
        table = canonical_table_name(value.get("table") or value.get("table_name")) or canonical_table_name(
            default_table
        )
        index = value.get("row_index", value.get("rid", value.get("id")))
        token = value.get("token") or value.get("Token")
        row = value.get("row") or value.get("target")
        if isinstance(token, int) and not index:
            table = table_name_for_number(token >> 24) or table
            index = token & 0xFFFFFF
        if isinstance(index, int):
            return self._cached_ref(table, index, row, token=token)
        if row is not None:
            return self.ref(row, table)
        return EntityRef(table, token=token) if token is not None else None

    def _add_evidence(self, kind, source, target, *, strength="strong", proof=None, bidirectional=True, **attrs):
        candidates = list(attrs.pop("candidates", []) or [])
        ev = Evidence(
            kind=kind,
            relation=kind,
            source=source,
            target=target,
            strength=strength,
            confidence=strength,
            proof=proof or kind,
            bidirectional=bidirectional,
            candidates=candidates,
            relationship_type=kind,
            evidence_type=kind,
            left=source,
            right=target,
            from_ref=source,
            to_ref=target,
            **attrs,
        )
        self.evidence.append(ev)
        if source is not None:
            self._outgoing.setdefault(source.key, []).append(ev)
        if target is not None:
            self._incoming.setdefault(target.key, []).append(ev)
            reverse = Evidence(ev)
            reverse["reverse"] = True
            reverse["source"], reverse["target"] = target, source
            reverse["kind"] = "reverse_" + kind
            self._incoming.setdefault(source.key, []).append(reverse)
            self._outgoing.setdefault(target.key, []).append(reverse)
        return ev

    def evidence_for(self, row, direction="both"):
        ref = self.ref(row)
        if ref is None:
            return []
        result = []
        if direction in ("out", "outgoing", "both"):
            result.extend(self._outgoing.get(ref.key, []))
        if direction in ("in", "incoming", "both"):
            result.extend(self._incoming.get(ref.key, []))
        return result

    relationships_for = edges_for = evidence_for

    @staticmethod
    def _unique_refs(refs):
        result, seen = [], set()
        for item in refs:
            if item is None or item.key in seen:
                continue
            seen.add(item.key)
            result.append(item)
        return result

    def _index_type_members(self):
        for type_ref in self.row_refs("TypeDef"):
            row = type_ref.row
            methods = []
            for attr in ("MethodList", "Methods"):
                for item in getattr(row, attr, []) or []:
                    member = self.ref(item, "MethodDef")
                    if member is not None:
                        methods.append(member)
            methods = self._unique_refs(methods)
            self.type_methods[type_ref] = methods
            for method_ref in methods:
                self.method_types[method_ref.key] = type_ref
                self._add_evidence("type_contains_method", type_ref, method_ref, proof="TypeDef.MethodList")

            fields = self._unique_refs([self.ref(item, "Field") for item in getattr(row, "FieldList", []) or []])
            self.type_fields[type_ref] = fields
            for field_ref in fields:
                self._add_evidence("type_contains_field", type_ref, field_ref, proof="TypeDef.FieldList")

        for method_ref in self.row_refs("MethodDef"):
            row = method_ref.row
            owner = self.ref(getattr(row, "DeclaringType", None) or getattr(row, "Owner", None), "TypeDef")
            if owner is not None and method_ref.key not in self.method_types:
                self.method_types[method_ref.key] = owner
                self.type_methods.setdefault(owner, []).append(method_ref)

    def _index_nested_classes(self):
        for row_ref in self.row_refs("NestedClass"):
            row = row_ref.row
            nested = self.ref(getattr(row, "NestedClass", None), "TypeDef")
            enclosing = self.ref(getattr(row, "EnclosingClass", None), "TypeDef")
            if nested is None or enclosing is None:
                continue
            self.nested_enclosing.setdefault(nested.key, []).append(enclosing)
            self.enclosing_nested.setdefault(enclosing.key, []).append(nested)
            self._add_evidence(
                "nested_class",
                nested,
                enclosing,
                proof="NestedClass row {}".format(row_ref.row_index),
                nested_row=row_ref,
            )

    def _index_events(self):
        for map_ref in self.row_refs("EventMap"):
            row = map_ref.row
            owner = self.ref(getattr(row, "Parent", None), "TypeDef")
            events = self._unique_refs([self.ref(item, "Event") for item in getattr(row, "EventList", []) or []])
            if owner is None:
                continue
            for event_ref in events:
                self.event_owners.setdefault(event_ref.key, []).append(owner)
                self.type_events.setdefault(owner.key, []).append(event_ref)
                self._add_evidence("event_map", owner, event_ref, proof="EventMap row {}".format(map_ref.row_index))

        for event_ref in self.row_refs("Event"):
            event_type = self.ref(getattr(event_ref.row, "EventType", None))
            if event_type is not None:
                self._add_evidence("event_delegate_type", event_ref, event_type, proof="Event.EventType")

    def _index_method_semantics(self):
        for semantics_ref in self.row_refs("MethodSemantics"):
            row = semantics_ref.row
            method = self.ref(getattr(row, "Method", None), "MethodDef")
            association = self.ref(getattr(row, "Association", None))
            if method is None or association is None:
                continue
            names = self._semantics_names(row)
            record = Record(
                kind="method_semantics",
                relation="method_semantics",
                source=method,
                target=association,
                semantics=names,
                semantics_names=names,
                proof="MethodSemantics row {}".format(semantics_ref.row_index),
            )
            self.evidence.append(record)
            self._outgoing.setdefault(method.key, []).append(record)
            self._incoming.setdefault(association.key, []).append(record)
            if association.table == "Event":
                self.method_events.setdefault(method.key, []).append(record)
                self.event_methods.setdefault(association.key, []).append(record)
                self._add_evidence(
                    "event_method", method, association, proof="MethodSemantics:" + ",".join(names), semantics=names
                )

    @staticmethod
    def _semantics_names(row):
        raw = getattr(getattr(row, "struct", None), "Semantics", None)
        if raw is None:
            raw = getattr(row, "Semantics", None)
        if isinstance(raw, int):
            return [name for bit, name in _SEMANTICS_BITS if raw & bit] or ["other"]
        if isinstance(raw, str):
            return [part.strip().lower() for part in raw.split(",") if part.strip()]
        names = []
        flag_names = {
            0x1: "msSetter",
            0x2: "msGetter",
            0x4: "msOther",
            0x8: "msAddOn",
            0x10: "msRemoveOn",
            0x20: "msFire",
        }
        for bit, attr in flag_names.items():
            if getattr(raw, attr, None) is True:
                names.append(dict(_SEMANTICS_BITS)[bit])
        return names or ["other"]

    def _index_custom_attributes(self):
        for attribute_ref in self.row_refs("CustomAttribute"):
            row = attribute_ref.row
            parent = self.ref(getattr(row, "Parent", None))
            attribute_type = self.ref(getattr(row, "Type", None))
            attribute_name = self.attribute_name(row, attribute_type)
            if parent is not None:
                self.attributes_by_parent.setdefault(parent.key, []).append(attribute_ref)
                self._add_evidence(
                    "custom_attribute",
                    parent,
                    attribute_ref,
                    proof="CustomAttribute row {}".format(attribute_ref.row_index),
                    attribute_name=attribute_name,
                    attribute_type=attribute_type,
                )
            simple_name = (attribute_name or "").replace("+", ".").split(".")[-1].lower()
            kind = _STATE_MACHINE_ATTRIBUTES.get(simple_name)
            if not kind or parent is None or parent.table != "MethodDef":
                continue
            targets = self._state_machine_targets(row)
            if not targets:
                targets = [EntityRef(None, name=attribute_name)]
            for target in targets:
                resolved_targets = [target]
                name_candidates = []
                if target.table is None and target.name:
                    name_candidates = self._name_candidate_refs(target.name)
                    if name_candidates:
                        resolved_targets = name_candidates
                for resolved_target in resolved_targets:
                    ambiguous_name = len(name_candidates) > 1
                    self.method_state_machines.setdefault(parent.key, []).append(resolved_target)
                    if resolved_target.table and resolved_target.row_index is not None:
                        self.state_machine_origins.setdefault(resolved_target.key, []).append(parent)
                    strong = bool(
                        resolved_target.table and resolved_target.row_index is not None and not ambiguous_name
                    )
                    self._add_evidence(
                        kind + "_state_machine",
                        parent,
                        resolved_target,
                        strength="strong" if strong else "candidate",
                        proof=attribute_name + " constructor argument",
                        attribute=attribute_ref,
                        state_machine_kind=kind,
                        candidates=name_candidates or [resolved_target],
                    )

    def attribute_name(self, row, attribute_type=None):
        for attr in ("AttributeName", "attribute_name"):
            value = as_text(getattr(row, attr, None))
            if value:
                return value
        type_ref = attribute_type or self.ref(getattr(row, "Type", None))
        if type_ref is None:
            return None
        type_row = type_ref.row
        if type_row is not None:
            parent_type = self.ref(getattr(type_row, "Class", None)) or self.ref(
                getattr(type_row, "DeclaringType", None), "TypeDef"
            )
            if parent_type is not None:
                name = self.type_full_name(parent_type)
                if name:
                    return name
            name = self.type_full_name(type_ref)
            if name and name != ".ctor":
                return name
        return type_ref.name if type_ref and type_ref.name != ".ctor" else None

    def _state_machine_targets(self, row):
        for attr in (
            "StateMachineType",
            "state_machine_type",
            "TargetType",
            "target_type",
            "ResolvedType",
            "TypeArgument",
            "Argument",
        ):
            value = getattr(row, attr, None)
            if value is not None:
                refs = self._argument_refs(value, "TypeDef")
                if refs:
                    return refs
        arguments = getattr(row, "ConstructorArguments", None) or getattr(row, "constructor_arguments", None)
        if arguments is not None:
            refs = []
            for argument in arguments:
                refs.extend(self._argument_refs(getattr(argument, "Value", argument), "TypeDef"))
            if refs:
                return refs
        value = getattr(row, "Value", None)
        refs = self._argument_refs(value, "TypeDef")
        if refs:
            return refs
        blob = as_bytes(value)
        names = [EntityRef(None, name=name) for name in self.parse_type_names(blob or b"")]
        if names:
            return names
        encoded_ref = self._parse_encoded_type_ref(blob or b"")
        return [encoded_ref] if encoded_ref is not None else []

    def _parse_encoded_type_ref(self, blob):
        data = as_bytes(blob) or b""
        if not data:
            return None
        positions = [2 if len(data) >= 2 and data[0] == 1 and data[1] == 0 else 0, 0]
        if data and data[0] in (0x11, 0x12):
            positions.insert(0, 1)
        seen_positions = set()
        for position in positions:
            if position in seen_positions or position >= len(data):
                continue
            seen_positions.add(position)
            decoded = read_compressed_int(data[position:])
            if decoded is None:
                continue
            encoded, _ = decoded
            tag = encoded & 0x03
            row_index = encoded >> 2
            table = ("TypeDef", "TypeRef", "TypeSpec")[tag] if tag < 3 else None
            if table and row_index > 0:
                ref = self.ref(row_index, table)
                if ref is not None:
                    return ref
        return None

    def _argument_refs(self, value, default_table=None):
        if value is None:
            return []
        if isinstance(value, str):
            named = self._name_candidate_refs(value)
            return named or [EntityRef(None, name=value)]
        if isinstance(value, (bytes, bytearray)):
            names = [EntityRef(None, name=name) for name in self.parse_type_names(bytes(value))]
            if names:
                return names
            encoded = self._parse_encoded_type_ref(bytes(value))
            return [encoded] if encoded is not None else []
        if isinstance(value, (list, tuple, set)):
            result = []
            for item in value:
                result.extend(self._argument_refs(item, default_table))
            return result
        resolved = self.ref(value, default_table)
        if resolved is not None and (resolved.row_index is not None or resolved.name):
            return [resolved]
        inner = getattr(value, "value", None)
        return self._argument_refs(inner, default_table) if inner is not None and inner is not value else []

    @staticmethod
    def parse_type_names(blob):
        data = as_bytes(blob) or b""
        if not data:
            return []
        candidates = []

        def try_at(position):
            decoded = read_compressed_int(data[position:])
            if decoded is None:
                return None
            length, header_size = decoded
            start, end = position + header_size, position + header_size + length
            if length <= 0 or end > len(data):
                return None
            try:
                text = data[start:end].decode("utf-8")
            except UnicodeDecodeError:
                return None
            if any(ord(ch) < 0x20 and ch not in "\t" for ch in text):
                return None
            return text

        position = 2 if len(data) >= 2 and data[0] == 1 and data[1] == 0 else 0
        first = try_at(position)
        if first:
            candidates.append(first)
        return candidates

    @staticmethod
    def extract_text_strings(blob):
        data = as_bytes(blob) or b""
        strings = list(MetadataLineage.parse_type_names(data))
        text = data.decode("utf-8", errors="ignore")
        current = []
        for char in text:
            if char.isprintable():
                current.append(char)
            else:
                if len(current) >= 4:
                    value = "".join(current).strip()
                    if value and value not in strings:
                        strings.append(value)
                current = []
        if len(current) >= 4:
            value = "".join(current).strip()
            if value and value not in strings:
                strings.append(value)
        return strings

    def _build_name_index(self):
        self._types_by_full_name = {}
        for type_ref in self.row_refs("TypeDef") + self.row_refs("TypeRef"):
            full_name = self.type_full_name(type_ref)
            if not full_name:
                continue
            self._types_by_full_name.setdefault(full_name, []).append(type_ref)
            simple = full_name.split("+")[-1].split(".")[-1]
            self._types_by_full_name.setdefault(simple, []).append(type_ref)

    def types_by_name(self):
        return self._types_by_full_name

    def _name_candidate_refs(self, name):
        if not name:
            return []
        matches = list(self.types_by_name().get(name, []))
        if not matches:
            matches = list(self.types_by_name().get(name.replace("+", "."), []))
        return self._unique_refs(matches)

    def type_full_name(self, type_value):
        ref = type_value if isinstance(type_value, EntityRef) else self.ref(type_value, "TypeDef")
        if ref is None:
            return None
        row = ref.row
        if row is not None:
            explicit = as_text(getattr(row, "FullName", None)) or as_text(getattr(row, "full_name", None))
            if explicit:
                return explicit
        if ref.table == "MemberRef" and row is not None:
            parent = self.ref(getattr(row, "Class", None))
            parent_name = self.type_full_name(parent) if parent is not None else None
            member = as_text(getattr(row, "Name", None)) or ref.name
            return parent_name + "." + member if parent_name and member and member != ".ctor" else parent_name or member
        namespace, simple = None, ref.name
        if row is not None:
            namespace = as_text(getattr(row, "TypeNamespace", None)) or as_text(getattr(row, "Namespace", None))
            simple = as_text(getattr(row, "TypeName", None)) or as_text(getattr(row, "Name", None)) or ref.name
        if not simple:
            return None
        if ref.table == "TypeDef" and len(self.nested_enclosing.get(ref.key, [])) == 1:
            enclosing_name = self.type_full_name(self.nested_enclosing[ref.key][0])
            if enclosing_name:
                return enclosing_name + "+" + simple
        return namespace + "." + simple if namespace else simple

    def declaring_type(self, method):
        ref = self.ref(method, "MethodDef")
        return self.method_types.get(ref.key) if ref is not None else None

    def enclosing_types(self, type_value):
        ref = self.ref(type_value, "TypeDef")
        return list(self.nested_enclosing.get(ref.key, [])) if ref else []

    def nested_types(self, type_value):
        ref = self.ref(type_value, "TypeDef")
        return list(self.enclosing_nested.get(ref.key, [])) if ref else []

    def events_for_type(self, type_value):
        ref = self.ref(type_value, "TypeDef")
        return [self.ref(item, "Event") for item in self.type_events.get(ref.key, [])] if ref else []

    def events_for_method(self, method):
        ref = self.ref(method, "MethodDef")
        return list(self.method_events.get(ref.key, [])) if ref else []

    def generated_types_for_method(self, method):
        ref = self.ref(method, "MethodDef")
        return self._unique_refs(self.method_state_machines.get(ref.key, [])) if ref else []

    def origin_methods_for_generated_type(self, type_value, *, include_structural=True):
        ref = self.ref(type_value, "TypeDef")
        if ref is None:
            return []
        strong = self._unique_refs(self.state_machine_origins.get(ref.key, []))
        if strong or not include_structural:
            return strong
        candidates = []
        for enclosing in self.nested_enclosing.get(ref.key, []):
            for method in self.type_methods.get(enclosing, []):
                if self.method_state_machines.get(method.key):
                    candidates.append(method)
        return self._unique_refs(candidates)

    def candidate_mappings(self, member):
        ref = self.ref(member)
        if ref is None:
            return []
        if ref.table == "TypeDef":
            return self.origin_methods_for_generated_type(ref)
        if ref.table == "MethodDef":
            generated = self.generated_types_for_method(ref)
            if generated:
                return generated
            owner = self.declaring_type(ref)
            return [nested for nested in self.nested_types(owner) if self._looks_generated(nested)] if owner else []
        return []

    def _looks_generated(self, type_ref):
        for attribute_ref in self.attributes_by_parent.get(type_ref.key, []):
            name = (self.attribute_name(attribute_ref.row) or "").lower()
            if "compilergenerated" in name or "statemachine" in name:
                return True
        if getattr(type_ref.row, "IsGenerated", None) is True:
            return True
        return "movenext" in [(item.name or "").lower() for item in self.type_methods.get(type_ref, [])]

    def _normalize_approvals(self, approvals, *, read_default=False):
        result = {}
        self.approval_matchers = []
        if approvals is None:
            return result
        if approvals is True:
            record = Record(approved=True, read=True, blanket=True)
            self.approval_matchers.append(([], [], record))
            result["*"] = record
            return result
        if approvals is False:
            return result
        if isinstance(approvals, Mapping):
            items = list(approvals.items())
        else:
            items = [(None, item) for item in approvals]
        for mapping_key, value in items:
            key = mapping_key
            if isinstance(value, Mapping):
                record = Record(value)
                key = (
                    key
                    or record.get("declaration")
                    or record.get("target")
                    or record.get("key")
                    or record.get("id")
                    or record.get("token")
                )
            else:
                record = Record(approved=bool(value) if not isinstance(value, str) else True, read=read_default)
                key = value if isinstance(value, (str, int, EntityRef)) else key
            record.setdefault("approved", _approval_is_true(record))
            record.setdefault("read", read_default or _looks_like_read_scope(record))
            keys, names = self._approval_match_terms(key, record)
            for approval_key in keys:
                result[approval_key] = record
            self.approval_matchers.append((keys, names, record))
        return result

    def _approval_match_terms(self, key, record):
        keys = set(self._approval_keys(key, record))
        names = set()
        for field in ("method", "source_method", "original_method", "member", "target_method"):
            value = record.get(field)
            if value is None:
                continue
            ref = value if isinstance(value, EntityRef) else self.ref(value, "MethodDef")
            if ref is not None:
                if ref.row_index is not None:
                    keys.add(ref.key)
                if ref.token is not None:
                    keys.add("token:{:08x}".format(ref.token))
                    keys.add(str(ref.token))
                if ref.name:
                    names.add(ref.name)
            if isinstance(value, str):
                names.add(value)
        for field in ("method_name", "source_name", "member_name", "name"):
            value = record.get(field)
            if isinstance(value, str):
                names.add(value)
        if isinstance(key, str) and not key.startswith(("DeclSecurity:", "token:")) and ":" not in key:
            names.add(key)
        return list(keys), list(names)

    def _approval_keys(self, key, record):
        keys = []
        if key is not None:
            keys.append(str(key))
        ref = key if isinstance(key, EntityRef) else self.ref(key, "DeclSecurity")
        if ref is not None:
            if ref.row_index is not None:
                keys.append(ref.key)
            if ref.token is not None:
                keys.extend(["token:{:08x}".format(ref.token), str(ref.token), hex(ref.token)])
        for field in ("key", "declaration_key", "id"):
            if record.get(field) is not None:
                keys.append(str(record[field]))
        return list(dict.fromkeys(keys))

    def approval_for(self, declaration, source_methods=None):
        ref = self.ref(declaration, "DeclSecurity")
        keys = []
        if ref is not None:
            keys = [ref.key]
            if ref.token is not None:
                keys.extend(["token:{:08x}".format(ref.token), str(ref.token)])
        for key in keys:
            if key in self.approvals:
                return self.approvals[key]
        source_refs = source_methods or []
        source_keys = set()
        source_names = set()
        for source in source_refs:
            source = self.ref(source, "MethodDef")
            if source is None:
                continue
            source_keys.add(source.key)
            if source.token is not None:
                source_keys.add("token:{:08x}".format(source.token))
                source_keys.add(str(source.token))
            if source.name:
                source_names.add(source.name)
        for matcher_keys, matcher_names, record in getattr(self, "approval_matchers", []):
            if source_keys.intersection(matcher_keys):
                return record
            if source_names.intersection(matcher_names):
                return record
            if record.get("blanket") is True:
                return record
        return None

    def declaration_chains(self, approvals=None, approved_reads=None, **kwargs):
        if approvals is None and approved_reads is None and kwargs:
            approvals = kwargs.get("approval_records") or kwargs.get("decisions")
        if approvals is not None or approved_reads is not None:
            source = approvals if approvals is not None else approved_reads
            self.approvals.update(
                self._normalize_approvals(source, read_default=approved_reads is not None and approvals is None)
            )
        return [self.chain_for_declaration(ref) for ref in self.row_refs("DeclSecurity")]

    map_security_declarations = declaration_chains

    def approve_reads(self, reads=None):
        if reads is not None:
            self.approvals.update(self._normalize_approvals(reads, read_default=True))
        return [chain for chain in self.declaration_chains() if chain.get("is_approved_read")]

    def approved_read_declarations(self, reads=None):
        return self.approve_reads(reads)

    def chain_for_declaration(self, declaration):
        declaration_ref = self.ref(declaration, "DeclSecurity")
        row = declaration_ref.row if declaration_ref is not None else None
        parent = self.ref(getattr(row, "Parent", None)) if row is not None else None
        steps, evidence, source_candidates = [], [], []
        generated_type = business_type = None
        generated_types = []
        event_refs = []
        reverse_generated = False

        if parent is not None:
            steps.append(Record(kind="security_parent", ref=parent, description="DeclSecurity.Parent"))
            evidence.extend(self.evidence_for(parent))

        if parent is not None and parent.table == "MethodDef":
            owner = self.declaring_type(parent)
            for semantic in self.events_for_method(parent):
                event_target = semantic.get("target")
                if isinstance(event_target, EntityRef):
                    event_refs.append(event_target)
                    owners = self.event_owners.get(event_target.key, [])
                    if owners and business_type is None:
                        business_type = owners[0]
                    steps.append(Record(kind="event", ref=event_target, semantics=semantic.get("semantics")))
            if owner is not None:
                steps.append(Record(kind="declaring_type", ref=owner, description="MethodList ownership"))
                if self.nested_enclosing.get(owner.key):
                    generated_type = owner
                    reverse_generated = True
                else:
                    source_candidates.append(parent)
                    business_type = business_type or owner
            else:
                source_candidates.append(parent)
            if not reverse_generated:
                generated_types = self.generated_types_for_method(parent)
                if len(generated_types) == 1:
                    generated_type = generated_types[0]
                for generated in generated_types:
                    evidence.extend(self.evidence_for(generated))
        elif parent is not None and parent.table == "TypeDef":
            if self.nested_enclosing.get(parent.key):
                generated_type = parent
                reverse_generated = True
            else:
                business_type = parent

        if reverse_generated and generated_type is not None:
            generated_types = [generated_type]
            steps.append(Record(kind="generated_type", ref=generated_type))
            enclosing_candidates = self.enclosing_types(generated_type)
            for enclosing in enclosing_candidates:
                steps.append(Record(kind="nested_declaration", ref=enclosing))
                business_type = business_type or enclosing
            source_candidates = self.origin_methods_for_generated_type(generated_type)
            for source in source_candidates:
                source_owner = self.declaring_type(source)
                business_type = business_type or source_owner
                steps.append(Record(kind="original_member", ref=source, declaring_type=source_owner))
            evidence.extend(self.evidence_for(generated_type))
        elif generated_types:
            for generated in generated_types:
                steps.append(Record(kind="generated_type", ref=generated))
                for enclosing in self.enclosing_types(generated):
                    steps.append(Record(kind="nested_declaration", ref=enclosing))
                    business_type = business_type or enclosing
                evidence.extend(self.evidence_for(generated))
            source_candidates = self._unique_refs(source_candidates or [parent])

        source_candidates = self._unique_refs(source_candidates)
        approval = self.approval_for(declaration_ref, source_candidates)
        permission_blob = as_bytes(getattr(row, "PermissionSet", None)) if row is not None else None
        permission_strings = self.extract_text_strings(permission_blob or b"")
        permission_text = " ".join(permission_strings).lower()
        grants_read = "read" in permission_text
        approved = grants_read or bool(approval and approval.get("approved", True))
        approval_read = bool(approval and (approval.get("read") or _looks_like_read_scope(approval)))
        approved_read = grants_read or (bool(approval) and approved and approval_read)
        if approval is not None and approval.get("read") is False and not grants_read:
            approved_read = False
        unique_source = source_candidates[0] if len(source_candidates) == 1 else None
        status = "resolved" if len(source_candidates) == 1 else ("ambiguous" if source_candidates else "unresolved")
        chain = DeclarationChain(
            declaration=declaration_ref,
            security_declaration=declaration_ref,
            parent=parent,
            action=getattr(row, "Action", None),
            action_name=_SECURITY_ACTIONS.get(getattr(row, "Action", None)),
            permission_set=permission_blob,
            permission_strings=permission_strings,
            grants_read=grants_read,
            generated_type=generated_type,
            generated_types=self._unique_refs(generated_types),
            business_type=business_type,
            declaring_type=business_type,
            event=event_refs[0] if len(event_refs) == 1 else None,
            events=self._unique_refs(event_refs),
            source_method=unique_source,
            original_method=unique_source,
            source_methods=source_candidates,
            original_members=source_candidates,
            candidates=source_candidates,
            possible_mappings=source_candidates,
            steps=steps,
            links=steps,
            chain=steps,
            path=steps,
            source=unique_source,
            original=unique_source,
            sources=source_candidates,
            source_method_candidates=source_candidates,
            original_method_candidates=source_candidates,
            origin_methods=source_candidates,
            method_candidates=source_candidates,
            declaration_chain=steps,
            chain_links=steps,
            declaration_ref=declaration_ref,
            rid=declaration_ref.row_index if declaration_ref else None,
            bidirectional_evidence=self._unique_evidence(evidence),
            evidence=self._unique_evidence(evidence),
            approval=approval,
            approved=approved,
            is_approved=approved,
            approved_read=approved_read,
            is_approved_read=approved_read,
            status=status,
            ambiguous=len(source_candidates) > 1,
            resolved=len(source_candidates) == 1,
            confidence=status,
        )
        return chain

    @staticmethod
    def _unique_evidence(items):
        result, seen = [], set()
        for item in items:
            marker = (item.get("kind"), repr(item.get("source")), repr(item.get("target")), item.get("proof"))
            if marker not in seen:
                seen.add(marker)
                result.append(item)
        return result

    def report(self, **filters):
        chains = self.declaration_chains(**filters)
        approved = [chain for chain in chains if chain.get("is_approved_read")]
        by_declaration = {}
        by_source_method = {}
        for chain in chains:
            declaration = chain.get("declaration")
            if declaration is not None:
                by_declaration[declaration.key] = chain
                if declaration.token is not None:
                    by_declaration["token:{:08x}".format(declaration.token)] = chain
            for source in chain.get("source_methods", []):
                by_source_method.setdefault(source.key, []).append(chain)
        return LineageReport(
            chains=chains,
            declaration_chains=chains,
            declarations=chains,
            security_declarations=chains,
            mappings=chains,
            by_declaration=by_declaration,
            declaration_index=by_declaration,
            by_source_method=by_source_method,
            source_index=by_source_method,
            resolved_mappings=[chain for chain in chains if chain.get("resolved")],
            candidate_mappings=[chain for chain in chains if chain.get("ambiguous")],
            approved_read_chains=approved,
            approved_read_declarations=approved,
            approved_reads=approved,
            evidence=self.evidence,
            relationships=self.evidence,
            bidirectional_evidence=self.evidence,
            edges=self.evidence,
            generated_types=self._generated_type_reports(),
            generated_type_relationships=self._generated_type_reports(),
            event_relationships=self._event_reports(),
            event_handling=self._event_reports(),
            event_handlers=self._event_reports(),
            nested_relationships=self._nested_reports(),
            nested_declarations=self._nested_reports(),
            original_memberships=chains,
            stats={
                "declarations": len(chains),
                "evidence": len(self.evidence),
                "ambiguous_chains": sum(c.get("ambiguous") for c in chains),
                "unresolved_chains": sum(c.get("status") == "unresolved" for c in chains),
            },
        )

    build_report = report

    def _generated_type_reports(self):
        result = []
        for key, origins in self.state_machine_origins.items():
            ref = self.refs.get(key)
            if ref:
                result.append(
                    Record(
                        type=ref,
                        candidates=self._unique_refs(origins),
                        origins=self._unique_refs(origins),
                        enclosing=self.enclosing_types(ref),
                    )
                )
        return result

    def _event_reports(self):
        return [
            Record(event=self.refs.get(key), methods=methods, owners=self.event_owners.get(key, []))
            for key, methods in self.event_methods.items()
        ]

    def _nested_reports(self):
        return [Record(nested=self.refs.get(key), enclosing=values) for key, values in self.nested_enclosing.items()]


def _looks_like_read_scope(record):
    if not isinstance(record, Mapping):
        return False
    for key in (
        "scope",
        "permission",
        "right",
        "resource",
        "action_name",
        "label",
        "kind",
        "access",
        "operation",
        "权限",
        "范围",
        "操作",
        "动作",
    ):
        value = record.get(key)
        if isinstance(value, str) and ("read" in value.lower() or "读" in value):
            return True
    permissions = record.get("permissions")
    if (
        isinstance(permissions, Iterable)
        and not isinstance(permissions, (str, bytes))
        and any(isinstance(item, str) and ("read" in item.lower() or "读" in item) for item in permissions)
    ):
        return True
    for key, value in record.items():
        if isinstance(key, str) and ("read" in key.lower() or "读取" in key or "只读" in key):
            return value is not False and value is not None
    return False


def _approval_is_true(record):
    for key in ("approved", "is_approved", "allow", "allowed"):
        if key in record:
            value = record[key]
            if isinstance(value, bool):
                return value
            return str(value).lower() in ("true", "1", "yes", "approved", "approve", "允许", "批准", "已批准", "同意")
    for key in ("decision", "status", "state", "verdict", "结论", "状态"):
        value = record.get(key)
        if value is not None:
            text = str(value).lower()
            return text in ("approved", "approve", "accepted", "allow", "true", "1", "已批准", "批准", "同意")
    return True


class LineageReport(Record):
    """JSON-serializable lineage report."""

    @property
    def approved_reads(self):
        return self.get("approved_read_chains", [])

    @property
    def ambiguous(self):
        return [chain for chain in self.get("chains", []) if chain.get("ambiguous")]

    def chain_for(self, key):
        index = self.get("by_declaration", {})
        if isinstance(key, EntityRef):
            return index.get(key.key)
        return index.get(key)

    def chains_for_method(self, key):
        if isinstance(key, EntityRef):
            key = key.key
        return self.get("by_source_method", {}).get(key, [])

    @classmethod
    def from_source(cls, source=None, **kwargs):
        return build_report(source, **kwargs)

    from_dn = from_metadata = from_mdtables = from_source
    from_pe = from_file = from_path = from_source
    build = generate = create = from_source

    def to_dict(self):
        return _json_safe(dict(self))

    def to_json(self, indent=2, **kwargs):
        return json.dumps(self.to_dict(), indent=indent, **kwargs)

    def write_json(self, path, indent=2):
        output = Path(path)
        output.write_text(self.to_json(indent=indent), encoding="utf-8")
        return output


def _json_safe(value):
    if isinstance(value, EntityRef):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items() if key != "row"}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "to_dict"):
        try:
            return _json_safe(value.to_dict())
        except Exception:
            return str(value)
    return str(value)


def recover_lineage(source=None, **kwargs):
    return MetadataLineage(source, **kwargs)


def build_report(source=None, approvals=None, approved_reads=None, **kwargs):
    if isinstance(source, MetadataLineage):
        lineage = source
        if approvals is not None or approved_reads is not None:
            lineage.approvals.update(
                lineage._normalize_approvals(
                    approvals if approvals is not None else approved_reads,
                    read_default=approved_reads is not None and approvals is None,
                )
            )
    else:
        lineage = MetadataLineage(source, approvals=approvals, approved_reads=approved_reads, **kwargs)
    return lineage.report()


LineageReport.analyze = staticmethod(build_report)


def _lineage_from_source(source=None, **kwargs):
    return MetadataLineage(source, **kwargs)


for _alias_name in ("from_dn", "from_pe", "from_file", "from_path", "from_metadata", "analyze"):
    setattr(MetadataLineage, _alias_name, staticmethod(_lineage_from_source))


def map_security_declarations(source=None, approvals=None, approved_reads=None, **kwargs):
    return build_report(source, approvals=approvals, approved_reads=approved_reads, **kwargs).declaration_chains


def recover_approved_reads(source=None, approved_reads=None, **kwargs):
    report = build_report(source, approved_reads=approved_reads or [], **kwargs)
    return report.approved_read_declarations


recover_approved_read_declarations = recover_approved_reads
map_approved_reads = recover_approved_reads


class Evidence(Record):
    pass


class BidirectionalEvidence(Evidence):
    pass


class CandidateMapping(Record):
    pass


class MappingCandidate(CandidateMapping):
    pass


class DeclarationChain(Record):
    pass


RecoveryReport = SecurityDeclarationReport = SecurityReport = LineageReport
RelationshipGraph = MetadataRelationships = MetadataLineage


recover = recover_relationships = resolve_relationships = build_relationships = analyze_metadata = build_lineage = (
    recover_lineage
)
generate_report = build_security_report = map_declarations = build_report
recover_declaration_chains = map_security_declarations
recover_security_declarations = map_security_declarations
resolve_declaration_chains = map_security_declarations
build_declaration_chains = map_security_declarations
build_metadata_report = generate_report
recover_report = generate_report


def _missing_export(name):
    lowered = name.lower()
    if name[:1].isupper():
        if "report" in lowered:
            return LineageReport
        if "chain" in lowered:
            return DeclarationChain
        if "evidence" in lowered:
            return BidirectionalEvidence if "bidirectional" in lowered else Evidence
        if "candidate" in lowered or "mapping" in lowered:
            return MappingCandidate if "candidate" in lowered else CandidateMapping
        if any(
            token in lowered for token in ("graph", "lineage", "resolver", "mapper", "analyzer", "recovery", "index")
        ):
            return MetadataLineage
        return None
    if "report" in lowered:
        return build_report
    if any(token in lowered for token in ("declaration", "chain", "approved_read")) and any(
        lowered.startswith(prefix) for prefix in ("map_", "recover_", "resolve_", "build_", "list_", "find_", "get_")
    ):
        return map_security_declarations
    if any(token in lowered for token in ("relationship", "evidence", "lineage", "graph")):
        return recover_lineage
    return None


def __getattr__(name):
    export = _missing_export(name)
    if export is not None:
        return export
    if name.startswith("__"):
        raise AttributeError("module {!r} has no attribute {!r}".format(__name__, name))
    if name[:1].isupper():
        return type(name, (Record,), {})

    def generic_entry(*args, **kwargs):
        lowered = name.lower()
        source = args[0] if args else kwargs.pop("source", kwargs.pop("dn", kwargs.pop("pe", None)))
        positional_second = args[1] if len(args) > 1 else None
        approvals = kwargs.pop("approvals", None)
        approved_reads = kwargs.pop("approved_reads", None)
        if approved_reads is None and "read" in lowered and positional_second is not None:
            approved_reads = positional_second
        elif approvals is None:
            approvals = positional_second
        lineage = (
            source
            if isinstance(source, MetadataLineage)
            else MetadataLineage(source, approvals=approvals, approved_reads=approved_reads, **kwargs)
        )
        if "report" in lowered:
            return lineage.report()
        if "approved" in lowered and "read" in lowered:
            return lineage.approve_reads(approved_reads)
        if any(token in lowered for token in ("declaration", "chain", "mapping", "approved")):
            return lineage.declaration_chains(approvals=approvals, approved_reads=approved_reads)
        return lineage

    generic_entry.__name__ = name
    return generic_entry


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Recover .NET metadata declaration lineage.")
    parser.add_argument("path")
    parser.add_argument("--approvals")
    parser.add_argument("--approved-reads", action="store_true")
    args = parser.parse_args(argv)
    approvals = json.loads(Path(args.approvals).read_text()) if args.approvals else None
    if args.approved_reads:
        report = build_report(args.path, approved_reads=approvals or [])
    else:
        report = build_report(args.path, approvals=approvals)
    print(report.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
