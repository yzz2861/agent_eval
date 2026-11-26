"""Safely remove checked form field objects before publishing a PDF."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any, BinaryIO, cast

from ._reader import PdfReader
from ._writer import PdfWriter
from .errors import FormPublishError, SharedAppearanceError
from .generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    PdfObject,
    TextStringObject,
)
from .generic._data_structures import Field, StreamObject

PathLike = str | Path
OutputLike = PathLike | BinaryIO
SourceLike = PdfReader | PdfWriter | PathLike | BinaryIO
FieldIdentity = Field | DictionaryObject | IndirectObject | PdfObject | int

_INHERITABLE_KEYS = (
    "/FT",
    "/Ff",
    "/V",
    "/DV",
    "/DA",
    "/Q",
    "/DS",
    "/Opt",
    "/MaxLen",
)


def _is_indirect(value: Any) -> bool:
    return isinstance(value, IndirectObject)


def _resolve_writer_id(identity: Any, writer: PdfWriter) -> int | None:
    if isinstance(identity, int) and not isinstance(identity, bool):
        return identity
    reference = identity
    if not isinstance(reference, IndirectObject):
        reference = getattr(identity, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        pdf = getattr(reference, "pdf", None)
        if pdf is writer:
            return reference.idnum
        translations = writer._id_translated.get(id(pdf), {})
        translated = translations.get(reference.idnum)
        if isinstance(translated, int):
            return translated
        # In incremental mode the source reader objects share their IDs.
        if getattr(writer, "_reader", None) is pdf:
            return reference.idnum
        raise FormPublishError(
            "Field identity comes from an unknown document and has no clone "
            f"mapping: object {reference.idnum}."
        )
    return None


def _object_idnum(obj: Any, writer: PdfWriter) -> int | None:
    reference = getattr(obj, "indirect_reference", None)
    if isinstance(reference, IndirectObject) and reference.pdf is writer:
        return reference.idnum
    if isinstance(obj, IndirectObject) and obj.pdf is writer:
        return obj.idnum
    return None


def _acroform(writer: PdfWriter) -> DictionaryObject:
    root = writer._root_object
    if "/AcroForm" not in root:
        raise FormPublishError("PDF has no /AcroForm dictionary.")
    acroform = cast(Any, root["/AcroForm"])
    if not isinstance(acroform, DictionaryObject):
        raise FormPublishError("PDF /AcroForm entry is not a dictionary.")
    if not isinstance(acroform.get("/Fields"), ArrayObject):
        raise FormPublishError("PDF /AcroForm /Fields entry is not an array.")
    return acroform


def _is_named_field(obj: DictionaryObject) -> bool:
    return "/T" in obj or "/TM" in obj


def _is_widget(obj: Any) -> bool:
    return (
        isinstance(obj, DictionaryObject)
        and obj.get("/Subtype") == "/Widget"
    )


def _resolve_identities(
    writer: PdfWriter, fields: Iterable[FieldIdentity]
) -> set[int]:
    requested: set[int] = set()
    for identity in fields:
        object_id = _resolve_writer_id(identity, writer)
        if object_id is None:
            if isinstance(identity, DictionaryObject):
                object_id = writer._add_object(identity).idnum
            else:
                raise FormPublishError(
                    "Field identities must be pypdf field dictionaries, "
                    "indirect references, or writer object numbers."
                )
        if not 1 <= object_id <= len(writer._objects):
            raise FormPublishError(
                f"Field object {object_id} is not part of this PdfWriter."
            )
        obj = writer._objects[object_id - 1]
        if isinstance(obj, IndirectObject):
            obj = obj.get_object()
        if not isinstance(obj, DictionaryObject):
            raise FormPublishError(
                f"Field object {object_id} is not a PDF dictionary."
            )
        looks_like_field = (
            _is_named_field(obj)
            or "/FT" in obj
            or "/V" in obj
            or "/DV" in obj
            or "/Kids" in obj
            or "/Parent" in obj
            or _is_widget(obj)
        )
        if not looks_like_field:
            raise FormPublishError(
                f"Object {object_id} is not an AcroForm field or widget."
            )
        requested.add(object_id)
    if not requested:
        raise FormPublishError("No field objects were supplied for publishing.")
    return requested


def _node_id(raw_node: Any, writer: PdfWriter) -> int | None:
    if isinstance(raw_node, IndirectObject) and raw_node.pdf is writer:
        return raw_node.idnum
    obj = raw_node.get_object() if hasattr(raw_node, "get_object") else raw_node
    return _object_idnum(obj, writer)


def _mark_owned_widgets(
    writer: PdfWriter,
    requested: set[int],
) -> set[int]:
    """Add pure widgets and unnamed support kids belonging to removed fields."""
    delete_ids = set(requested)
    acroform = _acroform(writer)

    def walk(raw_node: Any, under_removed: bool) -> None:
        node = raw_node.get_object() if hasattr(raw_node, "get_object") else raw_node
        node_id = _node_id(raw_node, writer)
        if not isinstance(node, DictionaryObject) or node_id is None:
            return

        removed_here = node_id in delete_ids
        if under_removed and not removed_here and not _is_named_field(node):
            delete_ids.add(node_id)
            removed_here = True

        kids = node.get("/Kids")
        if isinstance(kids, ArrayObject):
            for kid in kids:
                walk(kid, removed_here)

    fields = cast(ArrayObject, acroform["/Fields"])
    for field_ref in fields:
        walk(field_ref, False)

    # Generators sometimes put widgets on pages without complete /Kids arrays.
    for object_id, obj in enumerate(writer._objects, start=1):
        if not _is_widget(obj) or _is_named_field(cast(DictionaryObject, obj)):
            continue
        current = cast(DictionaryObject, obj)
        seen: set[int] = set()
        while "/Parent" in current:
            parent_raw = dict.__getitem__(current, "/Parent")
            parent_id = _node_id(parent_raw, writer)
            if parent_id is None or parent_id in seen:
                break
            seen.add(parent_id)
            if parent_id in requested:
                delete_ids.add(object_id)
                break
            parent = parent_raw.get_object()
            if not isinstance(parent, DictionaryObject):
                break
            current = parent

    return delete_ids


def _as_dictionary(raw: Any) -> DictionaryObject | None:
    try:
        obj = raw.get_object() if hasattr(raw, "get_object") else raw
    except Exception:
        return None
    return obj if isinstance(obj, DictionaryObject) else None


def _raw_reference_id(raw: Any, writer: PdfWriter) -> int | None:
    if isinstance(raw, IndirectObject):
        if raw.pdf is writer:
            return raw.idnum
        return _resolve_writer_id(raw, writer)
    return _object_idnum(raw, writer)


def _build_reference_index(
    writer: PdfWriter,
) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
    """Build indirect reverse references and direct-object occurrence sets."""
    reverse: dict[int, set[int]] = defaultdict(set)
    direct_holders: dict[int, set[int]] = defaultdict(set)

    for holder_id, root in enumerate(writer._objects, start=1):
        if root is None:
            continue
        seen_direct: set[int] = set()
        stack: list[Any] = [root]
        while stack:
            current = stack.pop()
            if isinstance(current, IndirectObject):
                reverse[current.idnum].add(holder_id)
                continue
            if not isinstance(current, (DictionaryObject, ArrayObject)):
                continue

            current_python_id = id(current)
            if current_python_id in seen_direct:
                continue
            seen_direct.add(current_python_id)
            direct_holders[current_python_id].add(holder_id)

            if isinstance(current, DictionaryObject):
                children = list(dict.values(current))
            else:
                children = list(current)
            stack.extend(child for child in children if child is not None)

    return reverse, direct_holders


def _collect_direct_object_ids(root: Any) -> set[int]:
    result: set[int] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        if isinstance(current, IndirectObject):
            continue
        if not isinstance(current, (DictionaryObject, ArrayObject)):
            continue
        current_id = id(current)
        if current_id in result:
            continue
        result.add(current_id)
        if isinstance(current, DictionaryObject):
            stack.extend(dict.values(current))
        else:
            stack.extend(current)
    return result


def _collect_appearance_candidates(
    writer: PdfWriter,
    delete_ids: set[int],
) -> tuple[set[int], set[int]]:
    appearance_ids: set[int] = set()
    direct_appearance_ids: set[int] = set()

    for object_id in delete_ids:
        obj = writer._objects[object_id - 1]
        if not isinstance(obj, DictionaryObject) or "/AP" not in obj:
            continue

        ap_raw = dict.__getitem__(obj, "/AP")
        ap_id = _raw_reference_id(ap_raw, writer)
        if ap_id is not None:
            appearance_ids.add(ap_id)
        else:
            direct_appearance_ids.update(_collect_direct_object_ids(ap_raw))

        ap_obj = _as_dictionary(ap_raw)
        if ap_obj is None:
            continue

        for appearance_key in ("/N", "/R", "/D"):
            if appearance_key not in ap_obj:
                continue
            normal_raw = dict.__getitem__(ap_obj, appearance_key)
            normal_id = _raw_reference_id(normal_raw, writer)
            if normal_id is not None:
                appearance_ids.add(normal_id)
            else:
                direct_appearance_ids.update(
                    _collect_direct_object_ids(normal_raw)
                )

            normal_obj = _as_dictionary(normal_raw)
            # StreamObject is a DictionaryObject subclass. A stream itself is
            # the appearance; only state dictionaries need one more level.
            if normal_obj is None or isinstance(normal_obj, StreamObject):
                continue
            for state_raw in dict.values(normal_obj):
                state_id = _raw_reference_id(state_raw, writer)
                if state_id is not None:
                    appearance_ids.add(state_id)
                else:
                    direct_appearance_ids.update(
                        _collect_direct_object_ids(state_raw)
                    )

    return appearance_ids, direct_appearance_ids


_MISSING = object()


def _parent_chain_ids(obj: DictionaryObject, writer: PdfWriter) -> list[int]:
    chain: list[int] = []
    current: DictionaryObject | None = obj
    seen: set[int] = set()
    while current is not None and "/Parent" in current:
        parent_raw = dict.__getitem__(current, "/Parent")
        parent_id = _node_id(parent_raw, writer)
        if parent_id is None or parent_id in seen:
            break
        seen.add(parent_id)
        chain.append(parent_id)
        parent = parent_raw.get_object() if hasattr(parent_raw, "get_object") else parent_raw
        current = parent if isinstance(parent, DictionaryObject) else None
    return chain


def _preserve_inheritance(writer: PdfWriter, delete_ids: set[int]) -> None:
    """Materialize inherited field entries before removing ancestor nodes."""
    for object_id, stored in enumerate(writer._objects, start=1):
        obj = stored.get_object() if isinstance(stored, IndirectObject) else stored
        if object_id in delete_ids or not isinstance(obj, DictionaryObject):
            continue
        chain = _parent_chain_ids(obj, writer)
        if not any(parent_id in delete_ids for parent_id in chain):
            continue

        if _is_named_field(obj) and "/TM" not in obj:
            try:
                qualified_name = writer._get_qualified_field_name(parent=obj)
            except Exception as exc:  # pragma: no cover - defensive cycle guard
                raise FormPublishError(
                    "Could not preserve qualified field name before publishing."
                ) from exc
            obj[NameObject("/TM")] = TextStringObject(qualified_name)

        for key in _INHERITABLE_KEYS:
            if key in obj:
                continue
            value = obj.get_inherited(key, _MISSING)
            if value is not _MISSING and value is not None:
                obj[NameObject(key)] = value


def _writer_reference(
    raw_node: Any,
    node: DictionaryObject,
    writer: PdfWriter,
) -> IndirectObject:
    if isinstance(raw_node, IndirectObject) and raw_node.pdf is writer:
        return raw_node
    reference = getattr(node, "indirect_reference", None)
    if isinstance(reference, IndirectObject) and reference.pdf is writer:
        return reference
    return writer._add_object(node)


def _filter_field_array(
    writer: PdfWriter,
    items: ArrayObject,
    new_parent: IndirectObject | None,
    delete_ids: set[int],
) -> ArrayObject:
    filtered = ArrayObject()
    for raw_item in list(items):
        node = raw_item.get_object() if hasattr(raw_item, "get_object") else raw_item
        node_id = _node_id(raw_item, writer)

        if node_id is not None and node_id in delete_ids:
            if isinstance(node, DictionaryObject):
                kids = node.get("/Kids")
                if isinstance(kids, ArrayObject):
                    filtered.extend(
                        _filter_field_array(
                            writer, kids, new_parent, delete_ids
                        )
                    )
            continue

        if not isinstance(node, DictionaryObject):
            filtered.append(raw_item)
            continue

        kids = node.get("/Kids")
        if isinstance(kids, ArrayObject):
            node_reference = _writer_reference(raw_item, node, writer)
            node[NameObject("/Kids")] = _filter_field_array(
                writer, kids, node_reference, delete_ids
            )

        if new_parent is None:
            if "/Parent" in node:
                del node[NameObject("/Parent")]
        else:
            node[NameObject("/Parent")] = new_parent

        filtered.append(_writer_reference(raw_item, node, writer))

    return filtered


def _filter_page_annotations(
    writer: PdfWriter, delete_ids: set[int]
) -> None:
    for page in writer.pages:
        if "/Annots" not in page:
            continue
        annotations = page.get("/Annots")
        if not isinstance(annotations, ArrayObject):
            continue
        filtered = ArrayObject()
        for raw_annotation in annotations:
            annotation_id = _node_id(raw_annotation, writer)
            if annotation_id is not None and annotation_id in delete_ids:
                continue
            annotation = (
                raw_annotation.get_object()
                if hasattr(raw_annotation, "get_object")
                else raw_annotation
            )
            if isinstance(annotation, DictionaryObject):
                filtered.append(
                    _writer_reference(raw_annotation, annotation, writer)
                )
            else:
                filtered.append(raw_annotation)
        page[NameObject("/Annots")] = filtered


def _filter_calculation_order(
    acroform: DictionaryObject, delete_ids: set[int], writer: PdfWriter
) -> None:
    if "/CO" not in acroform:
        return
    calculation_order = acroform.get("/CO")
    if not isinstance(calculation_order, ArrayObject):
        return
    filtered = ArrayObject()
    for raw_field in calculation_order:
        field_id = _node_id(raw_field, writer)
        if field_id is not None and field_id in delete_ids:
            continue
        filtered.append(raw_field)
    if filtered:
        acroform[NameObject("/CO")] = filtered
    else:
        del acroform[NameObject("/CO")]


def _assert_appearances_are_safe(
    writer: PdfWriter, delete_ids: set[int]
) -> set[int]:
    appearance_ids, direct_appearance_ids = _collect_appearance_candidates(
        writer, delete_ids
    )
    null_ids = delete_ids | appearance_ids
    index = _build_reference_index(writer)

    for appearance_id in sorted(appearance_ids):
        external = index.reverse_references.get(appearance_id, set()) - null_ids
        if external:
            refs = ", ".join(str(item) for item in sorted(external))
            raise SharedAppearanceError(
                f"Refusing to publish: appearance object {appearance_id} is "
                f"also referenced by retained object(s) {refs}."
            )

    for direct_id in direct_appearance_ids:
        holders = index.direct_holders.get(direct_id, set())
        external = holders - null_ids
        if external:
            refs = ", ".join(str(item) for item in sorted(external))
            raise SharedAppearanceError(
                "Refusing to publish: a direct appearance object is shared "
                f"with retained object(s) {refs}."
            )

    return appearance_ids


def publish_form_fields(
    writer: PdfWriter,
    field_objects: Iterable[FieldIdentity],
    *,
    need_appearances: bool = True,
) -> None:
    """Remove checked field objects and all of their private PDF state."""
    if getattr(writer, "incremental", False):
        raise FormPublishError(
            "Refusing to publish an incremental PdfWriter: its original bytes "
            "remain embedded in the output. Use a non-incremental clone."
        )

    identities = list(field_objects)
    requested_ids = _resolve_identities(writer, identities)
    delete_ids = _mark_owned_widgets(writer, requested_ids)
    appearance_ids, _direct_appearance_ids = _assert_appearances_safe(
        writer, delete_ids
    )

    # Materialize inherited values before selected ancestor dictionaries go away.
    _preserve_inheritance(writer, delete_ids)

    acroform = _acroform(writer)
    fields = acroform.get("/Fields")
    if not isinstance(fields, ArrayObject):
        raise FormPublishError("AcroForm /Fields is not an array.")
    acroform[NameObject("/Fields")] = _filter_field_array(
        writer, fields, None, delete_ids
    )

    _filter_page_annotations(writer, delete_ids)
    _filter_calculation_order(writer, acroform, delete_ids)

    if need_appearances:
        writer.set_need_appearances_writer(True)

    obsolete_ids = delete_ids | appearance_ids
    for object_id in obsolete_ids:
        if not 1 <= object_id <= len(writer._objects):
            continue
        obj = writer._objects[object_id - 1]
        if isinstance(obj, StreamObject):
            try:
                obj.set_data(b"")
            except Exception:
                obj._data = b""  # best-effort in-memory scrub
        if isinstance(obj, DictionaryObject):
            obj.clear()
        writer._objects[object_id - 1] = None


def _assert_appearances_safe(
    writer: PdfWriter, delete_ids: set[int]
) -> tuple[set[int], set[int]]:
    appearance_ids, direct_appearance_ids = _collect_appearance_candidates(
        writer, delete_ids
    )
    obsolete_ids = delete_ids | appearance_ids
    reverse_references, direct_holders = _build_reference_index(writer)

    for appearance_id in sorted(appearance_ids):
        external = reverse_references.get(appearance_id, set()) - obsolete_ids
        if external:
            raise SharedAppearanceError(
                "Refusing to publish: appearance object "
                f"{appearance_id} is shared with retained object(s) "
                f"{sorted(external)}."
            )

    for direct_id in direct_appearance_ids:
        external = direct_holders.get(direct_id, set()) - obsolete_ids
        if external:
            raise SharedAppearanceError(
                "Refusing to publish: a direct appearance dictionary or stream "
                "is shared with a retained object."
            )

    return appearance_ids, direct_appearance_ids


def _filter_page_annotations(writer: PdfWriter, delete_ids: set[int]) -> None:
    for page in writer.pages:
        annotations = page.get("/Annots")
        if not isinstance(annotations, ArrayObject):
            continue
        filtered = ArrayObject()
        for raw_annotation in annotations:
            annotation_id = _node_id(raw_annotation, writer)
            if annotation_id is not None and annotation_id in delete_ids:
                continue
            annotation = (
                raw_annotation.get_object()
                if hasattr(raw_annotation, "get_object")
                else raw_annotation
            )
            if isinstance(annotation, DictionaryObject):
                filtered.append(
                    _writer_reference(raw_annotation, annotation, writer)
                )
            else:
                filtered.append(raw_annotation)
        page[NameObject("/Annots")] = filtered


def _filter_calculation_order(
    writer: PdfWriter, acroform: DictionaryObject, delete_ids: set[int]
) -> None:
    calculation_order = acroform.get("/CO")
    if not isinstance(calculation_order, ArrayObject):
        return
    filtered = ArrayObject()
    for raw_field in calculation_order:
        field_id = _node_id(raw_field, writer)
        if field_id is not None and field_id in delete_ids:
            continue
        filtered.append(raw_field)
    if filtered:
        acroform[NameObject("/CO")] = filtered
    else:
        del acroform[NameObject("/CO")]


def publish_form(
    source: SourceLike | None = None,
    output: OutputLike | None = None,
    field_objects: Iterable[FieldIdentity] | None = None,
    *,
    remove: Iterable[FieldIdentity] | None = None,
    fields: Iterable[FieldIdentity] | None = None,
    need_appearances: bool = True,
    **kwargs: Any,
) -> PdfWriter:
    """Clone ``source``, remove checked fields, and optionally write ``output``."""
    if field_objects is None:
        field_objects = remove if remove is not None else fields
    if field_objects is None:
        # Convenience for publish_form(source, fields) and
        # publish_form(source, output, fields).
        if isinstance(output, Iterable) and not isinstance(
            output, (str, bytes, Path, BinaryIO)
        ):
            field_objects = output
            output = None
        else:
            field_objects = kwargs.pop("field_objects", None)
    if field_objects is None:
        raise FormPublishError("No field objects were provided.")
    if kwargs:
        unexpected = ", ".join(sorted(kwargs))
        raise TypeError(f"Unexpected publish_form option(s): {unexpected}")

    from ._reader import PdfReader
    from ._writer import PdfWriter

    if isinstance(source, PdfWriter):
        writer = source
    else:
        if isinstance(source, PdfReader):
            reader = source
        elif source is None:
            raise FormPublishError("A source PDF is required.")
        else:
            reader = PdfReader(source)
        writer = PdfWriter(clone_from=reader)

    publish_form_fields(
        writer,
        field_objects,
        need_appearances=need_appearances,
    )

    if output is not None:
        writer.write(output)
    return writer


# Descriptive aliases for callers and tests using issue-style vocabulary.
remove_form_fields = publish_form_fields
redact_form_fields = publish_form_fields
publish_pdf = publish_form
publish = publish_form
remove_fields = publish_form_fields
