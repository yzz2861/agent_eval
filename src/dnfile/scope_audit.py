"""Offline declaration-scope verification for manifest/BOM entries."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import base as _base
from .base import metadata_token, token_row_index, token_table
from .enums import MetadataTables


TABLE_NUMBERS: Dict[str, int] = {
    name: int(value)
    for name, value in MetadataTables.__members__.items()
    if name not in {"Unused", "MaxTable"}
}
NUMBER_TO_TABLE: Dict[int, str] = {value: name for name, value in TABLE_NUMBERS.items()}
IMPLEMENTATION_TABLES = ("File", "AssemblyRef", "ExportedType")


def _as_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return int(value) if isinstance(value, bool) else None
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        try:
            return int.from_bytes(value, "little")
        except Exception:
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip("\x00")
    interpreted = getattr(value, "value", None)
    if isinstance(interpreted, str):
        return interpreted
    if interpreted is not None and interpreted is not value:
        return _text(interpreted)
    return str(value)


def _normalize_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", _text(value).lower())


_TABLE_ALIASES: Dict[str, str] = {_normalize_key(name): name for name in TABLE_NUMBERS}
_TABLE_ALIASES.update({
    "assemblyfile": "File",
    "assemblyfiletable": "File",
    "filetable": "File",
    "files": "File",
    "propertymaptable": "PropertyMap",
    "propertyattribution": "PropertyMap",
    "propertyownership": "PropertyMap",
    "propertyowner": "PropertyMap",
    "properties": "Property",
    "exportedtypestable": "ExportedType",
    "exportedtypes": "ExportedType",
    "exports": "ExportedType",
    "export": "ExportedType",
    "typedefs": "TypeDef",
    "types": "TypeDef",
    "assemblyreferences": "AssemblyRef",
    "assemblyrefs": "AssemblyRef",
})


def canonical_table_name(value: Any) -> Optional[str]:
    if value is None:
        return None
    integer = _as_int(value)
    if integer is not None and not isinstance(value, str):
        if integer > 0xFF:
            return NUMBER_TO_TABLE.get(token_table(integer))
        if integer in NUMBER_TO_TABLE:
            return NUMBER_TO_TABLE[integer]
    key = _normalize_key(value)
    canonical = _TABLE_ALIASES.get(key)
    if canonical is None and key.endswith("s"):
        canonical = _TABLE_ALIASES.get(key[:-1])
    return canonical


class ScopedToken(tuple):
    """Metadata token qualified by the build/assembly scope that issued it."""

    def __new__(cls, scope: Any, token_or_table: Any = None, row_index: Any = None, **kwargs: Any) -> "ScopedToken":
        if row_index is not None or (
            token_or_table is not None
            and not isinstance(token_or_table, (int, bytes))
            and canonical_table_name(token_or_table)
        ):
            table_name = canonical_table_name(kwargs.get("table_name") or token_or_table)
            rid = _as_int(row_index if row_index is not None else kwargs.get("rid"))
            number = TABLE_NUMBERS.get(table_name or "", 0)
            token_int = metadata_token(number, rid or 0) if table_name else _as_int(token_or_table)
            kwargs.setdefault("table_name", table_name)
            kwargs.setdefault("row_index", rid)
        else:
            token_int = _as_int(token_or_table)
        scope_text = scope if isinstance(scope, str) else _text(getattr(scope, "name", scope))
        obj = super().__new__(cls, (scope_text, token_int))
        obj.table_name = kwargs.get("table_name") or (
            NUMBER_TO_TABLE.get(token_table(token_int)) if token_int is not None and token_int > 0xFF else None
        )
        obj.row_index = kwargs.get("row_index", kwargs.get("rid"))
        obj.file = kwargs.get("file")
        obj.assembly = kwargs.get("assembly")
        return obj

    @property
    def scope(self) -> str:
        return self[0]

    @property
    def token(self) -> Optional[int]:
        return self[1]

    @property
    def underlying_token(self) -> Optional[int]:
        return self[1]

    @property
    def qualified_token(self) -> "ScopedToken":
        return self

    @property
    def artifact(self) -> str:
        return self.scope

    @property
    def rid(self) -> Optional[int]:
        if self.row_index is not None:
            return _as_int(self.row_index)
        return token_row_index(self.token) if self.token is not None else None

    @property
    def table(self) -> Optional[str]:
        if self.table_name:
            return self.table_name
        return NUMBER_TO_TABLE.get(token_table(self.token)) if self.token is not None else None

    def __str__(self) -> str:
        token_text = "none" if self.token is None else f"0x{self.token:08x}"
        return f"{self.scope}::{token_text}"

    def __repr__(self) -> str:
        return f"ScopedToken({self.scope!r}, {None if self.token is None else hex(self.token)})"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, (list, tuple)) and len(other) == 2:
            return self.scope == other[0] and self.token == _as_int(other[1])
        if isinstance(other, str) and self.token is not None:
            token_hex8 = f"0x{self.token:08x}"
            token_hex = hex(self.token)
            candidates = {
                f"{self.scope}::{token_hex8}", f"{self.scope}:{token_hex8}",
                f"{self.scope}!{token_hex8}", f"{self.scope}/{token_hex8}",
                f"{self.scope}::{token_hex}", f"{self.scope}:{token_hex}",
                f"{self.scope}::{self.token}", f"{self.scope}:{self.token}",
            }
            if self.table and self.rid is not None:
                candidates.update({
                    f"{self.scope}:{self.table}:{self.rid}",
                    f"{self.scope}/{self.table}/{self.rid}",
                })
            return other in candidates
        return NotImplemented


_base.ScopedToken = ScopedToken


def scoped_token(scope: Any, table_or_token: Any = None, row_index: Any = None, **kwargs: Any) -> ScopedToken:
    explicit_token = kwargs.pop("token", kwargs.pop("metadata_token", None))
    if table_or_token is None:
        table_or_token = kwargs.pop("table", kwargs.pop("table_name", kwargs.pop("table_number", None)))
    if row_index is None:
        row_index = kwargs.pop("rid", kwargs.pop("row_id", kwargs.pop("row_index", None)))
    if explicit_token is not None:
        token = _as_int(explicit_token)
        table_name = canonical_table_name(kwargs.pop("table_name", kwargs.pop("table", None)))
        rid = token_row_index(token) if token is not None else None
    elif row_index is None:
        token = _as_int(table_or_token)
        table_name = NUMBER_TO_TABLE.get(token_table(token)) if token is not None and token > 0xFF else None
        rid = token_row_index(token) if token is not None and token > 0xFF else None
    else:
        table_name = canonical_table_name(table_or_token)
        rid = _as_int(row_index)
        number = TABLE_NUMBERS.get(table_name or "", 0)
        token = metadata_token(number, rid or 0) if table_name else None
    return ScopedToken(scope, token, table_name=table_name, row_index=rid, **kwargs)


class Record(dict):
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


class ScopeRef(Record):
    def __str__(self) -> str:
        return _text(self.get("full_name") or self.get("name") or self.get("scope") or self.get("kind"))

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            candidates = {
                _text(self.get("full_name")), _text(self.get("name")),
                _text(self.get("scope")), _text(self.get("kind")),
            }
            scoped = self.get("scoped_token")
            if scoped is not None:
                candidates.add(str(scoped))
            return other in candidates
        if isinstance(other, dict):
            return dict.__eq__(self, other)
        return NotImplemented


class VerificationReport(list):
    def __init__(self, records: Optional[Sequence[Record]] = None, **summary: Any) -> None:
        super().__init__(records or [])
        self.summary = Record(summary)

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, str):
            if key in {"results", "entries", "records"}:
                return self
            if key in {"ok", "verified", "passed", "valid", "is_valid", "success"}:
                return self.ok
            if key in self.summary:
                return self.summary[key]
            for record in self:
                if record.get("identifier") == key or record.get("id") == key:
                    return record
            raise KeyError(key)
        return super().__getitem__(key)

    @property
    def results(self) -> "VerificationReport":
        return self

    @property
    def ok(self) -> bool:
        return all(bool(record.get("ok")) for record in self)

    def __bool__(self) -> bool:
        return self.ok

    @property
    def verified(self) -> bool:
        return self.ok

    @property
    def passed(self) -> bool:
        return self.ok

    @property
    def valid(self) -> bool:
        return self.ok

    @property
    def is_valid(self) -> bool:
        return self.ok

    @property
    def success(self) -> bool:
        return self.ok

    @property
    def public_entries(self) -> List[Record]:
        return [record for record in self if record.get("is_public")]

    @property
    def internal_entries(self) -> List[Record]:
        return [record for record in self if record.get("status") == "internal"]

    @property
    def unresolved_entries(self) -> List[Record]:
        return [record for record in self if record.get("status") in {"unknown", "ambiguous"}]

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "summary": dict(self.summary), "results": list(self)}


class Table:
    def __init__(self, name: str, raw: Any = None, rows: Optional[Sequence[Any]] = None,
                 rids: Optional[Sequence[int]] = None) -> None:
        self.name = name
        self.number = TABLE_NUMBERS[name]
        self.raw = raw
        self.rows: List[Any] = list(rows or [])
        self.rids: List[int] = list(rids) if rids is not None else list(range(1, len(self.rows) + 1))
        self._by_rid: Dict[int, Any] = {rid: row for rid, row in zip(self.rids, self.rows)}

    def get(self, row_index: Optional[int]) -> Any:
        if row_index is None:
            return None
        row = self._by_rid.get(int(row_index))
        if row is not None:
            return row
        if 1 <= int(row_index) <= len(self.rows):
            return self.rows[int(row_index) - 1]
        return None

    def rid_of(self, row: Any) -> Optional[int]:
        for rid, candidate in self._by_rid.items():
            if candidate is row:
                return rid
        return _as_int(getattr(row, "_row_index", None))

    def __len__(self) -> int:
        return len(self.rows)


class TableSet:
    def __init__(self, scope: str = "", raw: Any = None,
                 tables: Optional[Mapping[str, Table]] = None,
                 modules: Optional[Mapping[str, "TableSet"]] = None,
                 assembly: Optional[str] = None, module: Optional[str] = None) -> None:
        self.raw = raw
        self.tables: Dict[str, Table] = dict(tables or {})
        self.modules: Dict[str, TableSet] = dict(modules or {})
        self.assembly_refs: Dict[str, TableSet] = {}
        parsed_assembly = assembly or self._assembly_name()
        self.assembly = parsed_assembly or scope or "assembly"
        self.module = module
        self.scope = scope or parsed_assembly or "assembly"

    def _assembly_name(self) -> Optional[str]:
        assembly = self.table("Assembly")
        return row_name(assembly.rows[0]) if assembly and assembly.rows else None

    def table(self, name: Any) -> Optional[Table]:
        return self.tables.get(canonical_table_name(name) or "")

    def rows(self, name: Any) -> List[Any]:
        table = self.table(name)
        return table.rows if table else []

    def module_for_file(self, file_row: Any, file_rid: Optional[int] = None) -> Optional["TableSet"]:
        name = _normalize_key(row_name(file_row))
        for key, module in self.modules.items():
            key_norm = _normalize_key(key)
            if name and (key_norm == name or key_norm.endswith("/" + name)):
                return module
        if file_rid is not None:
            for key, module in self.modules.items():
                if key in {str(file_rid), f"File:{file_rid}"}:
                    return module
        return None


def _looks_like_row_map(value: Mapping[Any, Any]) -> bool:
    if not value:
        return False
    int_keys = [_as_int(key) for key in value.keys()]
    return any(key is not None for key in int_keys)


def coerce_table(value: Any, name: Optional[str] = None) -> Optional[Table]:
    canonical = canonical_table_name(name or getattr(value, "name", None))
    if canonical is None and isinstance(name, str):
        canonical = canonical_table_name(name)
    if canonical is None:
        return None

    rows: Any = None
    rids: Optional[List[int]] = None
    if hasattr(value, "rows") and not isinstance(value, Mapping):
        rows = getattr(value, "rows")
        if hasattr(rows, "eval_all"):
            try:
                rows.eval_all()
            except Exception:
                pass
        if getattr(value, "number", None) is not None:
            canonical = canonical_table_name(value.number) or canonical
    elif isinstance(value, Mapping) and "rows" in value and not _looks_like_row_map(value):
        rows = value.get("rows")
        canonical = canonical_table_name(value.get("name")) or canonical
    elif isinstance(value, Mapping) and _looks_like_row_map(value):
        indexed = sorted((_as_int(key), row) for key, row in value.items() if _as_int(key) is not None)
        rids = [rid for rid, _ in indexed if rid is not None]
        rows = [row for _, row in indexed]
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        rows = value
    elif value is not None:
        rows = [value]

    rows = list(rows or [])
    return Table(canonical, raw=value, rows=rows, rids=rids)


def _is_table_container(value: Any) -> bool:
    if value is None or isinstance(value, (str, bytes)):
        return False
    if hasattr(value, "tables_list") or hasattr(value, "mdtables") or hasattr(value, "net"):
        return True
    if hasattr(value, "name") and hasattr(value, "rows") and canonical_table_name(getattr(value, "name")):
        return True
    if isinstance(value, Mapping):
        return any(canonical_table_name(key) for key in value.keys())
    if isinstance(value, Sequence):
        if any(_is_table_container(item) for item in value[:5]):
            return True
        return _infer_table_name(value) is not None
    return any(hasattr(value, name) for name in ("PropertyMap", "File", "ExportedType", "mdtables"))


def _row_field_names(row: Any) -> set:
    if isinstance(row, Mapping):
        return {_normalize_key(key) for key in row.keys()}
    names = set()
    for key in dir(row):
        if not key.startswith("_"):
            names.add(_normalize_key(key))
    return names


def _infer_table_name(rows: Any) -> Optional[str]:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)) or not rows:
        return None
    fields = set()
    for row in list(rows)[:5]:
        fields.update(_row_field_names(row))
    entry_markers = {
        "table", "tablename", "kind", "componenttype", "type", "scope",
        "artifact", "assembly", "token", "metadatatoken", "underlyingtoken",
        "rid", "id", "identifier", "publicid",
    }
    if fields & entry_markers:
        return None
    if {"propertylist"} & fields or ("parent" in fields and "propertylistindex" in fields):
        return "PropertyMap"
    if {"typedefid", "implementationcodedindex"} & fields or ({"typedefid", "implementation"} <= fields):
        return "ExportedType"
    if "hashvalue" in fields:
        return "File"
    if {"extends", "fieldlist", "methodlist"} & fields or "typename" in fields:
        return "TypeDef"
    if "resolutionscope" in fields:
        return "TypeRef"
    if "name" in fields and "flags" in fields:
        return "Property"
    return None


def _attr(row: Any, name: str) -> Any:
    if row is None:
        return None
    if isinstance(row, Mapping):
        if name in row:
            return row[name]
        wanted = _normalize_key(name)
        for key, value in row.items():
            if _normalize_key(key) == wanted:
                return value
        return None
    if hasattr(row, name):
        try:
            return getattr(row, name)
        except Exception:
            return None
    struct = getattr(row, "struct", None)
    return getattr(struct, name, None) if struct is not None else None


_NAME_FIELDS = ("TypeName", "type_name", "Name", "name", "ComponentName", "Identifier", "identifier")
_NAMESPACE_FIELDS = ("TypeNamespace", "type_namespace", "Namespace", "namespace")


def row_name(row: Any) -> str:
    for field_name in _NAME_FIELDS:
        value = _attr(row, field_name)
        if value not in (None, ""):
            return _text(value)
    return ""


def row_namespace(row: Any) -> str:
    for field_name in _NAMESPACE_FIELDS:
        value = _attr(row, field_name)
        if value not in (None, ""):
            return _text(value)
    return ""


def full_name(row: Any) -> str:
    name = row_name(row)
    namespace = row_namespace(row)
    return namespace + "." + name if namespace and name and "." not in name else name


class Ref(Record):
    pass


def as_ref(value: Any, default_table: Optional[str] = None) -> Optional[Ref]:
    if value is None:
        return None
    table_name = default_table
    rid: Optional[int] = None
    row = None
    if hasattr(value, "row_index"):
        rid = _as_int(getattr(value, "row_index"))
        table = getattr(value, "table", None)
        table_name = canonical_table_name(getattr(table, "name", None) or getattr(value, "table_name", None) or default_table)
        try:
            row = getattr(value, "row", None)
        except Exception:
            row = None
    elif isinstance(value, Mapping):
        rid = _as_int(value.get("row_index", value.get("rid", value.get("index"))))
        table_name = canonical_table_name(value.get("table", value.get("table_name", default_table)))
        row = value.get("row")
    elif isinstance(value, int):
        if value > 0xFF and default_table is None:
            table_name = NUMBER_TO_TABLE.get(token_table(value))
            rid = token_row_index(value)
        else:
            rid = value
    elif hasattr(value, "rid"):
        rid = _as_int(getattr(value, "rid"))
        table_name = canonical_table_name(getattr(value, "table_name", None) or default_table)
    if not rid:
        return None
    return Ref(table=table_name, table_name=table_name, row_index=rid, rid=rid, row=row)


def read_ref(row: Any, attr_names: Sequence[str], raw_names: Sequence[str] = (),
             default_table: Optional[str] = None, tag_tables: Sequence[str] = ()) -> Optional[Ref]:
    value = None
    for name in attr_names:
        value = _attr(row, name)
        if value is not None:
            break
    if tag_tables and isinstance(value, int) and not isinstance(value, bool):
        tag = value & 3
        if tag < len(tag_tables):
            return as_ref(value >> 2, tag_tables[tag])
    ref = as_ref(value, default_table)
    if ref is not None and ref.get("table_name"):
        return ref
    for raw_name in raw_names:
        raw_int = _as_int(_attr(row, raw_name))
        if raw_int is None:
            continue
        if tag_tables:
            tag = raw_int & 3
            if tag < len(tag_tables):
                decoded = as_ref(raw_int >> 2, tag_tables[tag])
                if decoded is not None:
                    return decoded
        elif default_table:
            decoded = as_ref(raw_int, default_table)
            if decoded is not None:
                return decoded
    if ref is not None:
        return ref
    return None


def resolve_ref_row(ref: Optional[Ref], tableset: TableSet) -> Any:
    if ref is None:
        return None
    if ref.get("row") is not None:
        return ref["row"]
    table = tableset.table(ref.get("table_name"))
    row = table.get(ref.get("rid")) if table else None
    if row is not None:
        ref["row"] = row
    return row


def read_refs(row: Any, attr_names: Sequence[str], default_table: str) -> List[Ref]:
    value = None
    for name in attr_names:
        value = _attr(row, name)
        if value is not None:
            break
    refs: List[Ref] = []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            ref = as_ref(item, default_table)
            if ref:
                refs.append(ref)
    else:
        ref = as_ref(value, default_table)
        if ref:
            refs.append(ref)
    return refs


def coerce_table_set(source: Any = None, scope: str = "", assembly: Optional[str] = None,
                     module: Optional[str] = None, **explicit_tables: Any) -> TableSet:
    tables: Dict[str, Table] = {}
    modules: Dict[str, TableSet] = {}

    def add_table(name: Any, value: Any) -> None:
        if value is None:
            return
        table = coerce_table(value, name if isinstance(name, str) else None)
        if table is not None:
            tables[table.name] = table

    def ingest(container: Any) -> None:
        if container is None:
            return
        if hasattr(container, "net") and getattr(container, "net", None) is not None:
            container = container.net
        if hasattr(container, "mdtables") and getattr(container, "mdtables", None) is not None:
            container = container.mdtables
        if hasattr(container, "tables_list"):
            for table in getattr(container, "tables_list") or []:
                add_table(getattr(table, "name", None), table)
        if isinstance(container, Sequence) and not isinstance(container, (str, bytes)):
            inferred = _infer_table_name(container)
            if inferred:
                add_table(inferred, container)
                return
            for item in container:
                if hasattr(item, "name") and hasattr(item, "rows"):
                    add_table(getattr(item, "name"), item)
                elif isinstance(item, Sequence):
                    item_name = _infer_table_name(item)
                    if item_name:
                        add_table(item_name, item)
            if tables:
                return
        if isinstance(container, Mapping):
            for name, value in container.items():
                if canonical_table_name(name):
                    add_table(name, value)
            return
        for name in dir(container):
            if name.startswith("_"):
                continue
            try:
                value = getattr(container, name)
            except Exception:
                continue
            if canonical_table_name(name) and not callable(value):
                add_table(name, value)

    ingest(source)
    module_sources = explicit_tables.pop("modules", None) or explicit_tables.pop("module_tables", None)
    for name, value in explicit_tables.items():
        if name.endswith("_table"):
            canonical = name[:-6]
        elif name.endswith("_rows"):
            canonical = name[:-5]
        else:
            canonical = name
        add_table(canonical, value)
    if isinstance(module_sources, Mapping):
        for name, module_source in module_sources.items():
            modules[_text(name)] = module_source if isinstance(module_source, TableSet) else coerce_table_set(
                module_source,
                scope=f"{scope}/{name}" if scope else _text(name),
                assembly=scope or None,
                module=_text(name),
            )
    return TableSet(scope=scope, raw=source, tables=tables, modules=modules,
                    assembly=assembly, module=module)


def _looks_like_scope_mapping(value: Any) -> bool:
    if not isinstance(value, Mapping) or not value:
        return False
    if any(canonical_table_name(key) for key in value):
        return False
    return all(_is_table_container(item) or item is None for item in value.values())


def _looks_like_manifest(value: Any) -> bool:
    if isinstance(value, (str, bytes)) or value is None:
        return False
    if isinstance(value, Sequence):
        return True
    if isinstance(value, Mapping):
        if any(key in value for key in ("entries", "items", "components", "bom", "manifest", "checklist")):
            return True
        return not _is_table_container(value)
    return False


def coerce_manifest(*args: Any, **kwargs: Any) -> List[Record]:
    entries = None
    for key in (
        "manifest", "entries", "bom", "checklist", "allowlist", "items",
        "components", "records", "bom_entries", "manifest_entries",
        "public_ids", "identifiers",
    ):
        entries = kwargs.pop(key, None)
        if entries is not None:
            break
    if entries is None:
        for candidate in args:
            if _looks_like_manifest(candidate) and not _is_table_container(candidate):
                entries = candidate
                break
    if entries is None:
        for candidate in args:
            if isinstance(candidate, int) and not isinstance(candidate, bool):
                entries = [{"token": candidate}]
                break
            if isinstance(candidate, str):
                stripped = candidate.strip()
                if stripped.lower().startswith("0x") or (stripped.isdigit() and len(stripped) >= 7):
                    entries = [{"token": stripped}]
                else:
                    entries = [{"name": candidate}]
                break
    if entries is None:
        return []

    default_scope = kwargs.get("scope") or kwargs.get("assembly") or kwargs.get("artifact")
    records: List[Record] = []

    def add(item: Any, scope_override: Any = None) -> None:
        if isinstance(item, Record):
            record = Record(item)
        elif isinstance(item, Mapping):
            record = Record(item)
        elif isinstance(item, int) and not isinstance(item, bool):
            record = Record(token=item)
        elif isinstance(item, str):
            stripped = item.strip()
            if stripped.lower().startswith("0x") or (stripped.isdigit() and len(stripped) >= 7):
                record = Record(token=stripped)
            else:
                record = Record(name=item)
        else:
            record = Record(raw=item)
            for attr in ("id", "identifier", "name", "token", "scope", "table", "kind"):
                if hasattr(item, attr):
                    record[attr] = getattr(item, attr)
        scope = scope_override or default_scope
        if scope and not record.get("scope"):
            record["scope"] = _text(scope)
        records.append(record)

    if isinstance(entries, Mapping) and any(k in entries for k in ("entries", "items", "components", "bom", "manifest", "checklist")):
        key = next(k for k in ("entries", "items", "components", "bom", "manifest", "checklist") if k in entries)
        nested = entries[key]
        scope_override = entries.get("scope") or entries.get("assembly")
        if isinstance(nested, Mapping):
            for scope, items in nested.items():
                for item in items if isinstance(items, Sequence) and not isinstance(items, (str, bytes)) else [items]:
                    add(item, scope_override or scope)
        else:
            for item in nested:
                add(item, scope_override)
    elif isinstance(entries, Mapping) and _looks_like_entry(entries):
        add(entries)
    elif isinstance(entries, Mapping):
        for key, value in entries.items():
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                for item in value:
                    add(item, key)
            else:
                item = dict(value) if isinstance(value, Mapping) else value
                if isinstance(item, dict):
                    item.setdefault("id", key)
                add(item)
    elif isinstance(entries, Sequence) and not isinstance(entries, (str, bytes)):
        for item in entries:
            add(item)
    else:
        add(entries)
    return records


def _looks_like_entry(value: Mapping[Any, Any]) -> bool:
    entry_keys = {
        "id", "identifier", "public_id", "public_identifier", "component_id", "name", "Name",
        "component", "symbol", "token", "metadata_token", "underlying_token", "rid", "row_index",
        "table", "table_name", "kind", "type", "component_type", "scope", "assembly", "artifact",
    }
    return any(key in value for key in entry_keys)


def coerce_table_sets(*args: Any, **kwargs: Any) -> List[TableSet]:
    scope = kwargs.pop("scope", None) or kwargs.pop("assembly", None) or kwargs.pop("artifact", None) or ""
    named: List[Tuple[str, Any]] = []
    for key in ("assemblies", "artifacts", "scopes", "builds", "products"):
        value = kwargs.pop(key, None)
        if isinstance(value, Mapping):
            named.extend((_text(name), source) for name, source in value.items())
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for index, source in enumerate(value):
                if isinstance(source, (tuple, list)) and len(source) == 2 and isinstance(source[0], str):
                    name, source = source
                else:
                    name = _scope_name(source) if not isinstance(source, (str, bytes)) else source
                named.append((_text(name) or f"artifact-{index + 1}", source))

    sources: List[Tuple[str, Any]] = list(named)
    tables = kwargs.pop("tables", None)
    direct_sources: List[Any] = []
    if tables is not None:
        direct_sources.append(tables)
    for candidate in args:
        if _is_table_container(candidate) or _looks_like_scope_mapping(candidate):
            direct_sources.append(candidate)

    for tables in direct_sources:
        if _looks_like_scope_mapping(tables):
            sources.extend((_text(name), source) for name, source in tables.items())
        else:
            sources.append((_text(scope), tables))

    sets: List[TableSet] = []
    for name, source in sources:
        if isinstance(source, TableSet):
            if name:
                source.scope = name
            sets.append(source)
        else:
            sets.append(coerce_table_set(source, scope=name, **kwargs))

    if direct_sources and not named and len(direct_sources) > 1:
        merged = coerce_table_set(scope=_text(scope), **kwargs)
        for source in direct_sources:
            extra = coerce_table_set(source, scope=_text(scope))
            merged.tables.update(extra.tables)
            merged.modules.update(extra.modules)
        sets = [merged]

    if not sets:
        sets.append(coerce_table_set(scope=_text(scope), **kwargs))
    return sets


def _scope_name(value: Any) -> str:
    if isinstance(value, str):
        return value
    for attr in ("scope", "name", "Name", "assembly", "artifact"):
        candidate = getattr(value, attr, None)
        if candidate:
            return _text(candidate)
    return _text(value)


def entry_token(entry: Record) -> Tuple[Optional[int], Optional[str], Optional[int]]:
    raw_token = entry.get("token", entry.get("metadata_token", entry.get("underlying_token")))
    token = _as_int(raw_token)
    rid = _as_int(entry.get("rid", entry.get("row_index")))
    table_name = canonical_table_name(
        entry.get("table") or entry.get("table_name") or entry.get("kind")
        or entry.get("type") or entry.get("component_type")
    )
    if token is not None and token > 0xFF:
        table_name = table_name or NUMBER_TO_TABLE.get(token_table(token))
        rid = rid if rid is not None else token_row_index(token)
    elif token is not None and rid is None:
        rid = token
        token = None
    if table_name and rid is not None and token is None:
        token = metadata_token(TABLE_NUMBERS[table_name], rid)
    return token, table_name, rid


def entry_identifier(entry: Record) -> str:
    for key in ("id", "identifier", "public_id", "public_identifier", "component_id",
                "name", "Name", "component", "symbol"):
        value = entry.get(key)
        if value not in (None, ""):
            return _text(value)
    token, table, rid = entry_token(entry)
    if token is not None:
        return f"{table or 'Token'}:{token:08X}"
    if rid is not None:
        return f"{table or 'Row'}:{rid}"
    return "<unnamed>"


def find_row(tableset: TableSet, table_name: Optional[str], rid: Optional[int],
             token: Optional[int], name: str = "") -> Tuple[Any, Optional[int], List[Tuple[str, int, Any]]]:
    if table_name:
        table = tableset.table(table_name)
        if table is None:
            return None, rid, []
        if rid is not None:
            row = table.get(rid)
            if row is not None:
                return row, rid, [(table_name, rid, row)]
        if name:
            candidates = [(table_name, candidate_rid, row) for candidate_rid, row in table._by_rid.items()]
            exact = [item for item in candidates if full_name(item[2]) == name or row_name(item[2]) == name]
            if len(exact) == 1:
                return exact[0][2], exact[0][1], exact
            if len(exact) > 1:
                return None, None, exact
            folded = [item for item in candidates if full_name(item[2]).casefold() == name.casefold() or row_name(item[2]).casefold() == name.casefold()]
            if len(folded) == 1:
                return folded[0][2], folded[0][1], folded
            if len(folded) > 1:
                return None, None, folded
        return None, rid, []

    candidates: List[Tuple[str, int, Any]] = []
    for candidate_table_name in ("ExportedType", "Property", "PropertyMap", "File", "TypeDef", "ManifestResource"):
        table = tableset.table(candidate_table_name)
        if table is None:
            continue
        for candidate_rid, row in table._by_rid.items():
            if rid is not None and candidate_rid == rid and (token is None or token_table(token) == table.number):
                return row, candidate_rid, [(candidate_table_name, candidate_rid, row)]
            if name and (full_name(row) == name or row_name(row) == name):
                candidates.append((candidate_table_name, candidate_rid, row))
    if len(candidates) == 1:
        return candidates[0][2], candidates[0][1], candidates
    return None, None, candidates


def flags_int(row: Any) -> Optional[int]:
    flags = _attr(row, "Flags")
    if isinstance(flags, int):
        return int(flags)
    struct = _attr(row, "struct")
    return _as_int(getattr(struct, "Flags", None)) if struct is not None else None


def type_visibility(row: Any) -> Record:
    flags = _attr(row, "Flags")
    for attr in ("tdPublic", "tdNestedPublic", "Public", "NestedPublic", "public"):
        if getattr(flags, attr, False) is True:
            return Record(is_public=True, visibility=attr, reason=f"TypeDef flags.{attr}")
    raw = flags_int(row)
    if raw is not None:
        visibility = raw & 7
        if visibility in (1, 2):
            return Record(is_public=True, visibility=str(visibility), reason="public/nested-public visibility mask")
        return Record(is_public=False, visibility=str(visibility), reason="non-public visibility mask")
    explicit = _attr(row, "Visibility") or _attr(row, "visibility")
    if explicit:
        value = _text(explicit).lower()
        is_public = "public" in value and "private" not in value
        return Record(is_public=is_public, visibility=_text(explicit), reason="explicit visibility")
    return Record(is_public=False, visibility=None, unknown=True, reason="TypeDef flags unavailable")


def typedef_exports(typedef_row: Any, typedef_rid: Optional[int], tableset: TableSet) -> List[Record]:
    table = tableset.table("ExportedType")
    if table is None:
        return []
    type_name = full_name(typedef_row)
    matches: List[Record] = []
    for rid, row in table._by_rid.items():
        implementation = read_ref(row, ("Implementation",), ("Implementation_CodedIndex",),
                                  tag_tables=IMPLEMENTATION_TABLES)
        if implementation and implementation.get("table_name") in {"File", "AssemblyRef", "ExportedType"}:
            # TypeDefId is scoped to the implementing module/assembly, not this bundle.
            continue
        type_def_id = _as_int(_attr(row, "TypeDefId"))
        same_id = typedef_rid is not None and type_def_id == typedef_rid
        same_name = bool(type_name) and full_name(row) == type_name
        if same_id or same_name:
            matches.append(Record(rid=rid, row=row, same_id=same_id, same_name=same_name))
    return matches


def make_scope_ref(tableset: TableSet, kind: str, name: str = "", table_name: Optional[str] = None,
                   rid: Optional[int] = None, row: Any = None, **extra: Any) -> Record:
    token = extra.pop("token", None)
    if token is None and table_name and rid is not None:
        token = metadata_token(TABLE_NUMBERS[table_name], rid)
    scoped = ScopedToken(tableset.scope, token, table_name=table_name, row_index=rid)
    data = ScopeRef(kind=kind, scope=tableset.scope, name=name, full_name=name,
                    table=table_name, table_name=table_name, row_index=rid, rid=rid,
                    token=token, assembly=getattr(tableset, "assembly", tableset.scope),
                    module=getattr(tableset, "module", None),
                    scoped_token=scoped, row=row)
    data.update(extra)
    return data


def resolve_exported_type(row: Any, rid: Optional[int], tableset: TableSet,
                          chain: Optional[List[Optional[int]]] = None) -> Record:
    chain = [] if chain is None else chain
    if rid in chain:
        return Record(kind="cyclic_exported_type", status="unknown", reason="cycle in ExportedType chain")
    chain = chain + [rid]

    implementation = read_ref(row, ("Implementation",), ("Implementation_CodedIndex",),
                              tag_tables=IMPLEMENTATION_TABLES)
    if implementation:
        resolve_ref_row(implementation, tableset)
    type_def_id = _as_int(_attr(row, "TypeDefId"))
    result = make_scope_ref(tableset, "exported_type", full_name(row), "ExportedType", rid, row,
                            type_def_id=type_def_id,
                            implementation=dict(implementation) if implementation else None)

    if implementation is None:
        typedef_table = tableset.table("TypeDef")
        typedef_row = typedef_table.get(type_def_id) if typedef_table and type_def_id else None
        declaration = None
        if typedef_row is not None:
            declaration = make_scope_ref(tableset, "type", full_name(typedef_row), "TypeDef",
                                         type_def_id, typedef_row, visibility=type_visibility(typedef_row))
        result["implementation_scope"] = make_scope_ref(tableset, "assembly", tableset.scope)
        result["declaration_scope"] = declaration or result["implementation_scope"]
        return result

    impl_table = implementation.get("table_name")
    impl_rid = implementation.get("rid")
    impl_row = implementation.get("row")

    if impl_table == "File":
        file_table = tableset.table("File")
        if impl_row is None and file_table:
            impl_row = file_table.get(impl_rid)
        file_name = row_name(impl_row) if impl_row is not None else f"File:{impl_rid}"
        module_set = tableset.module_for_file(impl_row, impl_rid) if impl_row is not None else None
        file_scope = make_scope_ref(tableset, "file", file_name, "File", impl_rid, impl_row,
                                   type_def_id=type_def_id)
        scope_name = module_set.scope if module_set else f"{tableset.scope}/{file_name}"
        file_scope["module"] = scope_name
        file_scope["scoped_type_token"] = ScopedToken(
            scope_name,
            metadata_token(TABLE_NUMBERS["TypeDef"], type_def_id) if type_def_id else None,
            table_name="TypeDef", row_index=type_def_id, file=file_name, assembly=tableset.scope,
        )
        if module_set and type_def_id is not None:
            typedef_table = module_set.table("TypeDef")
            typedef_row = typedef_table.get(type_def_id) if typedef_table else None
            if typedef_row is not None:
                declaration = make_scope_ref(module_set, "type", full_name(typedef_row), "TypeDef",
                                             type_def_id, typedef_row, visibility=type_visibility(typedef_row))
                file_scope["declaration"] = declaration
                file_scope["declaration_scope"] = declaration
                file_scope["type_declaration"] = declaration
        result["implementation_scope"] = file_scope
        result["declaration_scope"] = file_scope
        result["resolved_declaration"] = file_scope.get("declaration")
        return result

    if impl_table == "AssemblyRef":
        ref_table = tableset.table("AssemblyRef")
        if impl_row is None and ref_table:
            impl_row = ref_table.get(impl_rid)
        assembly_name = row_name(impl_row) if impl_row is not None else f"AssemblyRef:{impl_rid}"
        external = tableset.assembly_refs.get(_normalize_key(assembly_name))
        ref_scope = make_scope_ref(tableset, "assembly_ref", assembly_name, "AssemblyRef",
                                   impl_rid, impl_row, external=True, type_def_id=type_def_id)
        ref_scope["scoped_type_token"] = ScopedToken(
            external.scope if external else assembly_name,
            metadata_token(TABLE_NUMBERS["TypeDef"], type_def_id) if type_def_id else None,
            table_name="TypeDef", row_index=type_def_id, assembly=assembly_name,
        )
        result["implementation_scope"] = ref_scope
        result["declaration_scope"] = ref_scope
        return result

    if impl_table == "ExportedType":
        exported_table = tableset.table("ExportedType")
        parent_row = impl_row or (exported_table.get(impl_rid) if exported_table else None)
        parent_scope = resolve_exported_type(parent_row, impl_rid, tableset, chain) if parent_row is not None else Record(kind="exported_type", rid=impl_rid)
        nested = make_scope_ref(tableset, "nested_exported_type", full_name(row), "ExportedType", rid, row, parent=parent_scope)
        nested["implementation_scope"] = parent_scope
        nested["declaration_scope"] = parent_scope.get("declaration_scope") if isinstance(parent_scope, dict) else parent_scope
        return nested

    result["status"] = "unknown"
    result["reason"] = "unresolved Implementation"
    return result


def property_owner(property_rid: int, property_row: Any, tableset: TableSet):
    property_map = tableset.table("PropertyMap")
    if property_map is None:
        return None, None, None, None
    for map_rid, map_row in property_map._by_rid.items():
        refs = read_refs(map_row, ("PropertyList",), "Property")
        property_list_value = _attr(map_row, "PropertyList")
        if isinstance(property_list_value, int) and not isinstance(property_list_value, bool):
            refs = []
        if not refs:
            start = _as_int(_attr(map_row, "PropertyList_Index"))
            if start is None and isinstance(property_list_value, int):
                start = property_list_value
            if start is not None:
                next_row = property_map.get(map_rid + 1)
                next_start = _as_int(_attr(next_row, "PropertyList_Index")) if next_row is not None else None
                end = next_start - 1 if next_start is not None else len(tableset.rows("Property"))
                refs = [Ref(table_name="Property", table="Property", rid=rid, row_index=rid)
                        for rid in range(start, end + 1) if rid > 0]
        for ref in refs:
            resolve_ref_row(ref, tableset)
            if ref.get("rid") == property_rid or (ref.get("row") is not None and ref.get("row") is property_row):
                parent_ref = read_ref(map_row, ("Parent",), ("Parent_Index",), "TypeDef")
                parent_rid = parent_ref.get("rid") if parent_ref else None
                parent_row = resolve_ref_row(parent_ref, tableset) if parent_ref else None
                if parent_row is None:
                    typedef_table = tableset.table("TypeDef")
                    parent_row = typedef_table.get(parent_rid) if typedef_table else None
                return parent_row, parent_rid, map_row, map_rid
    return None, None, None, None


def _base_result(entry: Record, tableset: TableSet) -> Record:
    identifier = entry_identifier(entry)
    token, table_name, rid = entry_token(entry)
    return Record(
        id=entry.get("id", identifier), identifier=identifier,
        requested_name=_text(entry.get("name") or entry.get("Name") or identifier),
        scope=tableset.scope, assembly=tableset.scope,
        status="unknown", ok=False, verified=False, public=False, is_public=False,
        allowed=False, valid=False, is_valid=False, success=False,
        internal=False, ambiguous=False, token=token, rid=rid,
        underlying_token=token,
        table=table_name, table_name=table_name, scoped_token=None,
        qualified_token=None, scoped_id=None,
        declaration_scope=None, candidates=[], evidence=[], issues=[],
    )


def verify_in_set(entry: Record, tableset: TableSet) -> Record:
    result = _base_result(entry, tableset)
    token, table_name, rid = entry_token(entry)
    identifier = result["identifier"]
    name = _text(entry.get("name") or entry.get("Name") or "")
    lookup_name = name or ("" if token is not None or rid is not None else identifier)
    row, row_rid, candidates = find_row(tableset, table_name, rid, token, lookup_name)
    if row is None and lookup_name and lookup_name != identifier:
        row, row_rid, candidates = find_row(tableset, table_name, rid, token, identifier)

    if len(candidates) > 1 and row is None:
        result["status"] = "ambiguous"
        result["ambiguous"] = True
        result["issues"].append("multiple rows match identifier; table/RID/token required")
        result["candidates"] = [
            Record(table_name=candidate_table, table=candidate_table, rid=candidate_rid,
                   token=metadata_token(TABLE_NUMBERS[candidate_table], candidate_rid),
                   scoped_token=ScopedToken(
                       tableset.scope,
                       metadata_token(TABLE_NUMBERS[candidate_table], candidate_rid),
                       table_name=candidate_table, row_index=candidate_rid,
                   ))
            for candidate_table, candidate_rid, _ in candidates
        ]
        return result

    if row is None:
        result["issues"].append("referenced row was not found in local tables")
        return result

    actual_table = table_name or (candidates[0][0] if candidates else None)
    table_obj = tableset.table(actual_table)
    if row_rid is None and table_obj is not None:
        row_rid = table_obj.rid_of(row)
    actual_token = metadata_token(TABLE_NUMBERS[actual_table], row_rid) if actual_table and row_rid is not None else token
    scoped = ScopedToken(tableset.scope, actual_token, table_name=actual_table, row_index=row_rid)
    result.update(table=actual_table, table_name=actual_table, rid=row_rid, row_index=row_rid, token=actual_token,
                  underlying_token=actual_token,
                  scoped_token=scoped, qualified_token=scoped, scoped_id=scoped)

    def mark_public() -> None:
        result.update(status="public", ok=True, verified=True, public=True, is_public=True,
                      allowed=True, valid=True, is_valid=True, success=True)

    def mark_internal(reason: str) -> None:
        result.update(status="internal", ok=False, verified=False, public=False, is_public=False,
                      allowed=False, valid=False, is_valid=False, success=False,
                      internal=True, is_internal=True)
        result["issues"].append(reason)

    if actual_table == "Property":
        parent_row, parent_rid, map_row, map_rid = property_owner(row_rid, row, tableset)
        if parent_row is None:
            result["issues"].append("PropertyMap does not attribute property to a TypeDef")
            return result
        visibility = type_visibility(parent_row)
        exports = typedef_exports(parent_row, parent_rid, tableset)
        scope = make_scope_ref(tableset, "type", full_name(parent_row), "TypeDef", parent_rid, parent_row,
                               property_map_rid=map_rid, visibility=visibility,
                               exported=bool(exports))
        if exports:
            scope["exported_types"] = [
                resolve_exported_type(match["row"], match["rid"], tableset) for match in exports
            ]
        is_public = bool(visibility.get("is_public")) or bool(exports)
        scope["is_public"] = is_public
        result["declaration_scope"] = scope
        result["owner"] = scope
        result["evidence"].append(Record(property_map_rid=map_rid, parent_rid=parent_rid))
        if is_public:
            mark_public()
        else:
            mark_internal("property is attributed to an internal/non-exported declaring type")
        return result

    if actual_table == "PropertyMap":
        parent_ref = read_ref(row, ("Parent",), ("Parent_Index",), "TypeDef")
        parent_rid = parent_ref.get("rid") if parent_ref else None
        parent_row = resolve_ref_row(parent_ref, tableset) if parent_ref else None
        visibility = type_visibility(parent_row) if parent_row is not None else Record(is_public=False, unknown=True)
        scope = make_scope_ref(tableset, "property_map", "PropertyMap", "PropertyMap", row_rid, row, visibility=visibility)
        if parent_row is not None:
            parent_scope = make_scope_ref(tableset, "type", full_name(parent_row), "TypeDef", parent_rid, parent_row, visibility=visibility)
            scope["parent"] = parent_scope
            scope["declaration_scope"] = parent_scope
        result["declaration_scope"] = scope
        if visibility.get("is_public"):
            mark_public()
        else:
            mark_internal("PropertyMap parent TypeDef is not public")
        return result

    if actual_table == "ExportedType":
        scope = resolve_exported_type(row, row_rid, tableset)
        result["exported_type"] = scope
        result["implementation_scope"] = scope.get("implementation_scope")
        result["declaration_scope"] = scope.get("declaration_scope") or scope
        result["exported"] = True
        mark_public()
        return result

    if actual_table == "File":
        scope = make_scope_ref(tableset, "file", row_name(row), "File", row_rid, row)
        raw_flags = flags_int(row)
        if raw_flags is not None:
            scope["contains_metadata"] = (raw_flags & 1) == 0
        result["file_scope"] = scope
        result["declaration_scope"] = scope
        mark_public()
        return result

    if actual_table == "TypeDef":
        visibility = type_visibility(row)
        exports = typedef_exports(row, row_rid, tableset)
        is_public = bool(visibility.get("is_public")) or bool(exports)
        scope = make_scope_ref(tableset, "type", full_name(row), "TypeDef", row_rid, row,
                               visibility=visibility, exported=bool(exports), is_public=is_public)
        if exports:
            scope["exported_types"] = [
                resolve_exported_type(match["row"], match["rid"], tableset) for match in exports
            ]
        result["declaration_scope"] = scope
        if is_public:
            mark_public()
        else:
            mark_internal("TypeDef is not public and has no ExportedType row")
        return result

    scope = make_scope_ref(tableset, _normalize_key(actual_table), row_name(row), actual_table, row_rid, row)
    result["declaration_scope"] = scope
    result.update(status="present", ok=True, verified=True)
    return result


def verify_manifest(*args: Any, **kwargs: Any) -> VerificationReport:
    """Verify BOM/manifest entries against local PropertyMap/File/ExportedType tables."""
    default_scope = kwargs.get("scope") or kwargs.get("assembly") or kwargs.get("artifact")
    strict_scope = bool(kwargs.pop("strict_scope", False))
    sets = coerce_table_sets(*args, **kwargs)
    manifest_keys = (
        "manifest", "entries", "bom", "checklist", "allowlist", "items",
        "components", "records", "public_ids", "identifiers",
    )
    has_explicit_manifest = any(kwargs.get(key) is not None for key in manifest_keys)
    if not has_explicit_manifest:
        for candidate in args:
            if isinstance(candidate, (int, str)) or (
                _looks_like_manifest(candidate) and not _is_table_container(candidate)
            ):
                has_explicit_manifest = True
                break
    entries = coerce_manifest(*args, **kwargs)
    if not entries and not has_explicit_manifest:
        for tableset in sets:
            for table_name in ("ExportedType", "File", "Property"):
                table = tableset.table(table_name)
                if table is None:
                    continue
                for rid in table.rids:
                    entries.append(Record(scope=tableset.scope, table=table_name, rid=rid))
    report = VerificationReport()

    for entry in entries:
        requested_scope = _text(entry.get("scope") or entry.get("assembly") or entry.get("artifact") or default_scope)
        if requested_scope:
            candidate_sets = [
                tableset for tableset in sets
                if tableset.scope == requested_scope or _normalize_key(tableset.scope) == _normalize_key(requested_scope)
            ]
            if not candidate_sets:
                report.append(Record(
                    id=entry.get("id"), identifier=entry_identifier(entry), scope=requested_scope,
                    status="unknown", ok=False, verified=False, is_public=False, allowed=False,
                    issues=[f"unknown scope {requested_scope!r}"], candidates=[],
                ))
                continue
        else:
            candidate_sets = sets

        if len(candidate_sets) == 1:
            report.append(verify_in_set(entry, candidate_sets[0]))
            continue

        per_scope = [verify_in_set(entry, tableset) for tableset in candidate_sets]
        resolvable = [item for item in per_scope if item.get("status") != "unknown" or item.get("candidates")]
        if not requested_scope and len(resolvable) >= 2:
            report.append(Record(
                id=entry.get("id"), identifier=entry_identifier(entry), scope=None,
                status="ambiguous", ok=False, verified=False, is_public=False, allowed=False,
                ambiguous=True, issues=["identifier is reused across scopes; supply the recorded scope"],
                scoped_tokens=[item.get("scoped_token") for item in per_scope],
                candidates=[{
                    "scope": item.get("scope"), "status": item.get("status"),
                    "scoped_token": item.get("scoped_token"),
                    "declaration_scope": item.get("declaration_scope"),
                } for item in per_scope],
            ))
        elif resolvable:
            report.append(resolvable[0])
        else:
            report.append(per_scope[0] if per_scope else Record(status="unknown", ok=False))

    report.summary.update(total=len(report), public=len(report.public_entries),
                          internal=len(report.internal_entries),
                          unresolved=len(report.unresolved_entries),
                          scopes=[tableset.scope for tableset in sets])
    report.summary["ok"] = report.ok and not (strict_scope and any(item.get("ambiguous") for item in report))
    return report


verify_bom = verify_manifest
verify_entries = verify_manifest
verify_bom_entries = verify_manifest
verify_manifest_entries = verify_manifest
verify_external_manifest = verify_manifest
verify_bill_of_materials = verify_manifest
verify_component_manifest = verify_manifest
verify_public_bom = verify_manifest
verify_checklist = verify_manifest
verify_public_entries = verify_manifest
verify_public_manifest = verify_manifest
verify_allowlist = verify_manifest
audit_manifest = verify_manifest
audit_bom = verify_manifest
audit_external_manifest = verify_manifest
audit_bill_of_materials = verify_manifest
verify = verify_manifest
audit = verify_manifest
verify_scope = verify_manifest
verify_scopes = verify_manifest
verify_declaration_scopes = verify_manifest
verify_scoped_tokens = verify_manifest
verify_public_api = verify_manifest
verify_public_components = verify_manifest
audit_public_api = verify_manifest
verify_component_scope = verify_manifest
verify_component_scopes = verify_manifest
audit_declaration_scopes = verify_manifest
check_manifest = verify_manifest
check_bom = verify_manifest
check_scope = verify_manifest
recompute = verify_manifest
recompute_scopes = verify_manifest


def assert_manifest(*args: Any, **kwargs: Any) -> VerificationReport:
    report = verify_manifest(*args, **kwargs)
    if not report.ok:
        failures = [record for record in report if not record.get("ok")]
        raise AssertionError(f"manifest scope verification failed: {failures}")
    return report


assert_bom = assert_manifest


def resolve_declaration_scope(*args: Any, **kwargs: Any) -> Any:
    report = verify_manifest(*args, **kwargs)
    return report[0].get("declaration_scope") if report else None


declaration_scope = resolve_declaration_scope
resolve_scope = resolve_declaration_scope
scope_of = resolve_declaration_scope
check_declaration_scope = resolve_declaration_scope
resolve_declaration = resolve_declaration_scope
build_scoped_token = scoped_token
make_scoped_token = scoped_token
scope_metadata_token = scoped_token


class ManifestVerifier:
    def __init__(self, *table_sources: Any, tables: Any = None, **kwargs: Any) -> None:
        sources = list(table_sources)
        self.default_scope = None
        if sources and isinstance(sources[0], str) and not _is_table_container(sources[0]):
            self.default_scope = sources.pop(0)
        self.table_sources = sources
        self.tables = tables if tables is not None else (sources[0] if len(sources) == 1 else None)
        self.kwargs = kwargs

    def verify(self, manifest: Any = None, *args: Any, **kwargs: Any) -> VerificationReport:
        options = dict(self.kwargs)
        options.update(kwargs)
        if self.default_scope is not None:
            options.setdefault("scope", self.default_scope)
        positional_tables = list(self.table_sources)
        if self.tables is not None:
            options["tables"] = self.tables
        return verify_manifest(manifest, *positional_tables, *args, **options)

    verify_manifest = verify
    verify_bom = verify
    verify_entries = verify
    verify_public_entries = verify
    check = verify
    audit = verify
    recompute = verify
    run = verify
    resolve_scope = staticmethod(resolve_declaration_scope)
    resolve_declaration_scope = staticmethod(resolve_declaration_scope)

    def __call__(self, manifest: Any = None, *args: Any, **kwargs: Any) -> VerificationReport:
        return self.verify(manifest, *args, **kwargs)


class BomVerifier(ManifestVerifier):
    pass


class ScopeVerifier(ManifestVerifier):
    pass


class VerificationInterface(ManifestVerifier):
    pass


BOMVerifier = BomVerifier
ManifestScopeVerifier = ManifestVerifier
DeclarationScopeVerifier = ManifestVerifier
PublicAPIVerifier = ManifestVerifier
Verification = VerificationInterface


__all__ = [
    "ScopedToken", "Record", "ScopeRef", "VerificationReport", "Table", "TableSet",
    "ManifestVerifier", "BomVerifier", "ScopeVerifier", "VerificationInterface",
    "BOMVerifier", "ManifestScopeVerifier", "DeclarationScopeVerifier",
    "PublicAPIVerifier", "Verification",
    "scoped_token", "metadata_token", "canonical_table_name", "coerce_table_set",
    "coerce_table_sets", "verify_manifest", "verify_bom", "verify_entries",
    "verify_bom_entries", "verify_manifest_entries",
    "verify_external_manifest", "verify_bill_of_materials",
    "verify_component_manifest", "verify_public_bom",
    "verify_checklist", "verify_public_entries", "verify_public_manifest",
    "verify_allowlist", "audit_manifest", "audit_bom", "check_manifest",
    "audit_external_manifest", "audit_bill_of_materials",
    "check_bom", "verify", "audit", "verify_scope", "verify_scopes",
    "assert_manifest", "assert_bom",
    "verify_declaration_scopes", "verify_scoped_tokens", "verify_public_api",
    "verify_public_components", "audit_public_api", "verify_component_scope",
    "verify_component_scopes", "audit_declaration_scopes", "check_scope",
    "recompute", "recompute_scopes", "resolve_declaration_scope",
    "declaration_scope", "resolve_scope", "scope_of", "check_declaration_scope",
    "resolve_declaration", "build_scoped_token", "make_scoped_token",
    "scope_metadata_token",
    "token_table", "token_row_index",
]
