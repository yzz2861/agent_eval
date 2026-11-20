"""Structural snapshots of one PDF revision.

A snapshot captures form fields (values and appearance streams), pages
(contents, media/rotation, resources) and inherited page-tree attributes,
reduced to plain str/dict/list values for revision comparison.
"""

from __future__ import annotations

import hashlib
from typing import Any

from pypdf import PdfReader
from pypdf.generic import IndirectObject

from .models import FieldSnapshot, PageSnapshot, Snapshot

INHERITED_PAGE_ATTRS = ("/Resources", "/MediaBox", "/CropBox", "/Rotate")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ref_key(obj: Any) -> str | None:
    if isinstance(obj, IndirectObject):
        return f"{obj.idnum} {obj.generation} R"
    return None


def _stable(value: Any, depth: int = 0) -> Any:
    """JSON-serialisable, order-stable representation of a PDF value."""
    if depth > 32:
        return "<recursion-limit>"
    if value is None:
        return None
    if isinstance(value, IndirectObject):
        return f"indirect:{value.idnum} {value.generation} R"
    if isinstance(value, dict):
        return {str(k): _stable(v, depth + 1) for k, v in
                sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple)):
        return [_stable(item, depth + 1) for item in value]
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, bytes):
        return f"bytes(len={len(value)})"
    return str(value)


def _stream_fingerprint(obj: Any) -> dict[str, Any] | None:
    if not hasattr(obj, "get_data"):
        return None
    try:
        raw = obj.get_data()
    except Exception as exc:
        return {"decodable": False, "error": str(exc)}
    return {
        "decodable": True,
        "length": len(raw),
        "sha256": sha256(raw),
        "preview": raw[:80].decode("latin-1", errors="replace"),
    }


def _field_full_name(field: Any, parts: list[str] | None = None) -> str:
    parts = list(parts or [])
    parent = field.get("/Parent") if isinstance(field, dict) else None
    if parent is not None:
        _field_full_name(parent, parts)
    name = field.get("/T")
    if name is not None:
        parts.append(str(name))
    if parts:
        return ".".join(parts)
    ref = getattr(field, "indirect_reference", None)
    return f"obj:{ref}"


def _widget_page_index(field: Any, page_id_to_index: dict[str, int]) -> int | None:
    key = _ref_key(field.get("/P"))
    if key is not None and key in page_id_to_index:
        return page_id_to_index[key]
    return None


def _appearance_stream_hash(field: Any) -> dict[str, Any] | None:
    appearance = field.get("/AP")
    if not isinstance(appearance, dict):
        return None
    normal = appearance.get("/N")
    if normal is None:
        return {"ap_present": True, "normal": None}
    if isinstance(normal, dict):
        states = {str(k): _stream_fingerprint(v) for k, v in normal.items()}
        return {"ap_present": True, "normal_kind": "dict", "states": states}
    return {"ap_present": True, "normal_kind": "stream",
            "stream": _stream_fingerprint(normal), "ref": _ref_key(normal)}


def _widget_annotation_hash(field: Any) -> dict[str, Any]:
    keys = ("/Rect", "/F", "/Border", "/BS", "/MK", "/Subtype", "/P", "/Parent")
    return {k: _stable(field.get(k)) for k in keys if k in field}


def _signature_value(field: Any) -> dict[str, Any] | None:
    value = field.get("/V")
    if not isinstance(value, dict):
        return None
    byte_range = value.get("/ByteRange")
    content = value.get("/Contents")
    return {
        "filter": str(value.get("/Filter")) if "/Filter" in value else None,
        "sub_filter": str(value.get("/SubFilter")) if "/SubFilter" in value else None,
        "byte_range": list(byte_range) if byte_range is not None else None,
        "contents_length": len(content) if isinstance(content, (bytes, str)) else None,
        "name": str(value.get("/Name")) if "/Name" in value else None,
        "signing_time": str(value.get("/M")) if "/M" in value else None,
        "ref": _ref_key(value),
    }


def _resolve(obj: Any) -> Any:
    if hasattr(obj, 'get_object'):
        try:
            return obj.get_object()
        except Exception:
            return obj
    return obj


def _field_snapshots(root: Any, page_id_to_index: dict[str, int]) -> dict[str, FieldSnapshot]:
    acroform = _resolve(root.get("/AcroForm")) if hasattr(root, "get") else None
    if not isinstance(acroform, dict):
        return {}
    fields = [_resolve(item) for item in acroform.get("/Fields", [])]
    result: dict[str, FieldSnapshot] = {}
    for index, field in enumerate(fields):
        if not isinstance(field, dict):
            continue
        object_key = _ref_key(field) or f"idx:{index}"
        result[object_key] = FieldSnapshot(
            object_key=object_key,
            index=index,
            full_name=_field_full_name(field) or object_key,
            field_type=str(field.get("/FT")) if "/FT" in field else None,
            value=_stable(field.get("/V")),
            default_value=_stable(field.get("/DV")),
            appearance_stream_hash=_appearance_stream_hash(field),
            widget_annotation_hash=_widget_annotation_hash(field),
            page_index=_widget_page_index(field, page_id_to_index),
            is_signature=field.get("/FT") == "/Sig",
            signature_value=_signature_value(field),
            flags=int(field.get("/Ff")) if "/Ff" in field else None,
        )
    return result


def _resolve_inherited(page: Any, attr: str) -> tuple[Any, str | None]:
    node: Any = page
    while isinstance(node, dict):
        if attr in node:
            owner = _ref_key(getattr(node, "indirect_reference", None))
            return node.get(attr), owner
        node = _resolve(node.get("/Parent"))
    return None, None


def _resource_entries(resources: Any) -> list[tuple[str, str, Any]]:
    entries: list[tuple[str, str, Any]] = []
    if not isinstance(resources, dict):
        return entries
    for category in ("/Font", "/XObject", "/ExtGState", "/ColorSpace", "/Pattern", "/Shading"):
        group = resources.get(category)
        if isinstance(group, dict):
            for name, entry in group.items():
                entries.append((category[1:], str(name), entry))
    return entries


def _page_resource_map(page: Any) -> dict[str, list[str]]:
    resources, _ = _resolve_inherited(page, "/Resources")
    mapping: dict[str, list[str]] = {}
    for category, name, entry in _resource_entries(resources):
        key = _ref_key(entry) or f"{category}/{name}:direct"
        mapping.setdefault(key, []).append(f"{category}/{name}")
    return mapping


def _page_snapshot(page: Any, index: int) -> PageSnapshot:
    contents = page.get_contents()
    content_fingerprints: list[dict[str, Any]] = []
    if contents is not None:
        streams = contents if isinstance(contents, list) else [contents]
        for stream in streams:
            content_fingerprints.append({
                "ref": _ref_key(stream),
                "stream": _stream_fingerprint(stream),
            })
    resources_raw, inherited_from = _resolve_inherited(page, "/Resources")
    resources = _resolve(resources_raw)
    inherited = {}
    for attr in INHERITED_PAGE_ATTRS:
        value, owner = _resolve_inherited(page, attr)
        inherited[attr] = {"value": _stable(value), "defined_on": owner}
    annotations = [_stable(ann) for ann in page.get("/Annots", [])]
    return PageSnapshot(
        object_key=_ref_key(page) or f"page:{index}",
        index=index,
        media_box=_stable(page.mediabox),
        rotation=page.rotation,
        contents=content_fingerprints,
        resources_ref=_ref_key(resources_raw) or _ref_key(resources) or "<direct>",
        resources=_stable(resources),
        inherited=inherited,
        inherited_from=inherited_from,
        annotations=annotations,
    )


def _resource_impact_index(pages: list[PageSnapshot]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for page in pages:
        for ref, names in _collect_page_resource_refs(page).items():
            index.setdefault(ref, []).append({"page_index": page.index, "names": names})
    return index


def _collect_page_resource_refs(page_snap: PageSnapshot) -> dict[str, list[str]]:
    refs: dict[str, list[str]] = {}
    resources = page_snap.resources
    if not isinstance(resources, dict):
        return refs
    for category in ("Font", "XObject", "ExtGState", "ColorSpace", "Pattern", "Shading"):
        group = resources.get(f"/{category}")
        if isinstance(group, dict):
            for name, value in group.items():
                clean_name = str(name).lstrip("/")
                key = value if isinstance(value, str) and value.startswith("indirect:") else f"{category}/{clean_name}:direct"
                refs.setdefault(key, []).append(f"{category}/{clean_name}")
    return refs


def build_snapshot(reader: PdfReader) -> Snapshot:
    page_id_to_index = {}
    pages: list[PageSnapshot] = []
    for index, page in enumerate(reader.pages):
        key = _ref_key(page.indirect_reference)
        if key is not None:
            page_id_to_index[key] = index
        pages.append(_page_snapshot(page, index))
    root = reader.trailer["/Root"]
    fields = _field_snapshots(root, page_id_to_index)
    return Snapshot(pages=pages, fields=fields,
                    resource_impact=_resource_impact_index(pages))
