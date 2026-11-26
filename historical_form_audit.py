#!/usr/bin/env python3
"""Read-only historical attribution for incrementally saved PDF form fields.

The auditor never writes to the inspected PDF.  For every cross-reference
revision it opens the byte prefix ending at that revision's ``%%EOF`` with
pypdf.  Those short-lived readers keep indirect-reference resolution bound to
that revision, so later values cannot contaminate historical evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Any

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    BooleanObject,
    ByteStringObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NumberObject,
    TextStringObject,
)


_STARTXREF_RE = re.compile(rb"startxref\s+(\d+)")
_EOF_RE = re.compile(rb"%%EOF\r?\n?")
_PREV_RE = re.compile(rb"/Prev\s+(\d+)")
_ENDOBJ_RE = re.compile(rb"\bendobj\b")
_REF_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s*R?\s*$")
_OBJ_HEADER_RE = re.compile(rb"^(\d+)\s+(\d+)\s+obj\b")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_object_reference(value: str | list[int] | tuple[int, int] | dict[str, int]) -> tuple[int, int]:
    if isinstance(value, dict):
        return int(value["object_number"]), int(value.get("generation", 0))
    if isinstance(value, (list, tuple)):
        return int(value[0]), int(value[1])
    match = _REF_RE.search(value)
    if not match:
        raise ValueError(f"Invalid indirect object reference: {value!r}")
    return int(match.group(1)), int(match.group(2))


def reference_key(reference: Any) -> tuple[int, int] | None:
    if isinstance(reference, IndirectObject):
        return reference.idnum, reference.generation
    indirect_reference = getattr(reference, "indirect_reference", None)
    if isinstance(indirect_reference, IndirectObject):
        return indirect_reference.idnum, indirect_reference.generation
    return None


def _last_startxref_offset(data: bytes) -> int:
    matches = list(_STARTXREF_RE.finditer(data))
    if not matches:
        raise ValueError("No startxref marker found")
    return int(matches[-1].group(1))


def xref_revision_offsets(data: bytes) -> list[int]:
    """Return cross-reference offsets from the oldest revision to newest."""
    newest = _last_startxref_offset(data)
    offsets: list[int] = []
    seen: set[int] = set()
    current: int | None = newest
    while current is not None:
        if current in seen:
            raise ValueError(f"Circular /Prev cross-reference chain at {current}")
        seen.add(current)
        offsets.append(current)

        next_startxref = data.find(b"startxref", current)
        window_end = next_startxref if next_startxref >= 0 else min(len(data), current + 4_096)
        previous = _PREV_RE.search(data[current:window_end])
        current = int(previous.group(1)) if previous else None

    offsets.reverse()
    return offsets


def describe_revisions(data: bytes) -> list[dict[str, Any]]:
    revisions: list[dict[str, Any]] = []
    segment_start = 0
    for number, xref_offset in enumerate(xref_revision_offsets(data), start=1):
        startxref_marker = re.compile(
            rb"startxref\s+0*" + str(xref_offset).encode("ascii") + rb"\b"
        )
        marker_match = startxref_marker.search(data, xref_offset)
        scan_start = marker_match.end() if marker_match else xref_offset
        eof = _EOF_RE.search(data, scan_start)
        if eof is None:
            raise ValueError(f"No %%EOF found after xref offset {xref_offset}")
        prefix_length = eof.end()
        revisions.append(
            {
                "revision": number,
                "segment_start": segment_start,
                "prefix_length": prefix_length,
                "segment_length": prefix_length - segment_start,
                "xref_offset": xref_offset,
                "prefix_sha256": sha256_hex(data[:prefix_length]),
            }
        )
        segment_start = prefix_length
    return revisions


def open_revision(data: bytes, revision: dict[str, Any]) -> PdfReader:
    return PdfReader(BytesIO(data[: revision["prefix_length"]]), strict=False)


def object_locations(reader: PdfReader, object_number: int) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for generation, xref in sorted(reader.xref.items()):
        if generation == 65535 or not isinstance(xref, dict):
            continue
        if object_number in xref:
            offset = xref[object_number]
            if isinstance(offset, tuple):  # pragma: no cover - defensive for pypdf variants
                offset = offset[0]
            locations.append(
                {
                    "kind": "absolute_offset",
                    "object_number": object_number,
                    "generation": int(generation),
                    "offset": int(offset),
                }
            )

    if object_number in getattr(reader, "xref_objStm", {}):
        container_number, index = reader.xref_objStm[object_number]
        locations.append(
            {
                "kind": "object_stream",
                "object_number": object_number,
                "generation": 0,
                "object_stream_number": int(container_number),
                "index": int(index),
            }
        )
    return locations


def raw_object_evidence(data: bytes, location: dict[str, Any]) -> dict[str, Any]:
    if location.get("kind") != "absolute_offset":
        return {"raw_evidence": location}

    start = int(location["offset"])
    endobj = _ENDOBJ_RE.search(data, start)
    if endobj is None:
        return {"raw_start": start, "raw_error": "endobj not found"}
    end = endobj.end()
    raw = data[start:end]
    header_match = _OBJ_HEADER_RE.match(raw)
    evidence: dict[str, Any] = {
        "raw_start": start,
        "raw_end": end,
        "raw_length": len(raw),
        "sha256": sha256_hex(raw),
    }
    if header_match:
        evidence["header_object_number"] = int(header_match.group(1))
        evidence["header_generation"] = int(header_match.group(2))
        evidence["header_valid"] = (
            evidence["header_object_number"] == location["object_number"]
            and evidence["header_generation"] == location["generation"]
        )
    return evidence


def to_native(value: Any, *, resolve_indirect: bool = True) -> Any:
    if isinstance(value, IndirectObject):
        identity = reference_key(value)
        if not resolve_indirect:
            return f"{identity[0]} {identity[1]} R" if identity else "indirect"
        try:
            return to_native(value.get_object(), resolve_indirect=False)
        except Exception as exc:  # pragma: no cover - defensive for malformed PDFs
            return {"reference": f"{identity[0]} {identity[1]} R" if identity else "indirect", "resolve_error": str(exc)}
    if isinstance(value, TextStringObject):
        return str(value)
    if isinstance(value, ByteStringObject):
        return {"bytes_hex": value.original_bytes.hex()}
    if isinstance(value, (str, bool, int, float)) or value is None:
        return value
    if isinstance(value, ArrayObject):
        return [to_native(item, resolve_indirect=False) for item in value]
    if isinstance(value, DictionaryObject):
        return {str(key): to_native(item, resolve_indirect=False) for key, item in value.items()}
    return str(value)


def _indirect_list(value: Any) -> list[IndirectObject]:
    if isinstance(value, IndirectObject):
        return [value]
    if isinstance(value, ArrayObject):
        return [item for item in value if isinstance(item, IndirectObject)]
    return []


def collect_widget_references(field_object: DictionaryObject, field_reference: tuple[int, int]) -> list[tuple[int, int]]:
    widgets: list[tuple[int, int]] = []
    if field_object.get("/Subtype") == "/Widget":
        widgets.append(field_reference)
    for kid in _indirect_list(field_object.get("/Kids")):
        identity = reference_key(kid)
        if identity is None:
            continue
        try:
            kid_object = kid.get_object()
        except Exception:
            kid_object = None
        if isinstance(kid_object, DictionaryObject) and (
            kid_object.get("/Subtype") == "/Widget" or "/Rect" in kid_object or "/AP" in kid_object
        ):
            widgets.append(identity)
        elif "/T" not in (kid_object or {}):
            # Page /Annots always points at widgets; keep a kid even when a
            # producer omitted an explicit /Subtype in the historical bytes.
            widgets.append(identity)
    return sorted(set(widgets))


def field_qualified_names(reader: PdfReader) -> dict[tuple[int, int], str]:
    root = reader.trailer["/Root"].get_object()
    acro_form = root.get("/AcroForm") if isinstance(root, DictionaryObject) else None
    if acro_form is None:
        return {}
    acro_form = acro_form.get_object()
    if not isinstance(acro_form, DictionaryObject):
        return {}

    names: dict[tuple[int, int], str] = {}
    seen: set[tuple[int, int]] = set()

    def walk(value: Any, parent_name: str) -> None:
        for reference in _indirect_list(value):
            key = reference_key(reference)
            if key is None or key in seen:
                continue
            seen.add(key)
            try:
                obj = reference.get_object()
            except Exception:
                continue
            if not isinstance(obj, DictionaryObject):
                continue
            partial = obj.get("/T")
            partial_name = str(partial) if partial is not None else ""
            if parent_name and partial_name:
                qualified = f"{parent_name}.{partial_name}"
            else:
                qualified = partial_name or parent_name
            if "/T" in obj:
                names[key] = qualified
            walk(obj.get("/Kids"), qualified)

    walk(acro_form.get("/Fields"), "")
    return names


def page_references_for_widgets(
    reader: PdfReader, widget_keys: set[tuple[int, int]]
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for page_index, page in enumerate(reader.pages):
        page_reference = page.indirect_reference
        page_key = reference_key(page_reference)
        annots = page.get("/Annots") or ArrayObject()
        for annotation in _indirect_list(annots):
            annotation_key = reference_key(annotation)
            if annotation_key not in widget_keys:
                continue
            annotation_location = next(
                (item for item in object_locations(reader, annotation_key[0]) if item["generation"] == annotation_key[1]),
                None,
            )
            page_location = None
            if page_key is not None:
                page_location = next(
                    (item for item in object_locations(reader, page_key[0]) if item["generation"] == page_key[1]),
                    None,
                )
            matches.append(
                {
                    "page_index": page_index,
                    "page_reference": f"{page_key[0]} {page_key[1]} R" if page_key else None,
                    "page_location": page_location,
                    "annotation_reference": f"{annotation_key[0]} {annotation_key[1]} R",
                    "annotation_location": annotation_location,
                }
            )
    return matches


def field_evidence_at_revision(
    data: bytes,
    revision: dict[str, Any],
    object_number: int,
) -> list[dict[str, Any]]:
    reader = open_revision(data, revision)
    qualified_names = field_qualified_names(reader)
    evidence_rows: list[dict[str, Any]] = []
    for location in object_locations(reader, object_number):
        generation = location["generation"]
        reference = IndirectObject(object_number, generation, reader)
        row: dict[str, Any] = {
            "revision": revision["revision"],
            "reference": f"{object_number} {generation} R",
            "location": location,
            **raw_object_evidence(data, location),
        }
        try:
            obj = reference.get_object()
        except Exception as exc:
            row["read_error"] = f"{type(exc).__name__}: {exc}"
            obj = None

        if isinstance(obj, DictionaryObject):
            row["field_name"] = to_native(obj.get("/T"))
            row["qualified_name"] = qualified_names.get((object_number, generation))
            row["field_type"] = to_native(obj.get("/FT"))
            row["value"] = to_native(obj.get("/V"))
            row["subtype"] = to_native(obj.get("/Subtype"))
            field_key = (object_number, generation)
            widget_keys = set(collect_widget_references(obj, field_key))
            row["widget_references"] = [f"{number} {gen} R" for number, gen in sorted(widget_keys)]
            row["page_references"] = page_references_for_widgets(reader, widget_keys)
            parent = obj.get("/Parent")
            parent_key = reference_key(parent)
            if parent_key is not None:
                row["parent_reference"] = f"{parent_key[0]} {parent_key[1]} R"
        elif obj is not None:
            row["object_type"] = type(obj).__name__
            row["native_object"] = to_native(obj)
        evidence_rows.append(row)
    return evidence_rows


def attribute_history(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add creation/update labels without merging distinct references."""
    last_by_reference: dict[str, dict[str, Any]] = {}
    seen_object_numbers: set[int] = set()
    for row in rows:
        reference = row["reference"]
        previous = last_by_reference.get(reference)
        if previous is None:
            object_number = int(reference.split(" ", 1)[0])
            generation = int(reference.split()[1])
            if generation > 0 and object_number in seen_object_numbers:
                row["attribution"] = "new_generation_introduced"
            elif row.get("field_name") is not None or row.get("value") is not None:
                row["attribution"] = "field_created"
            else:
                row["attribution"] = "generation_introduced"
            seen_object_numbers.add(object_number)
        elif previous.get("sha256") != row.get("sha256") or previous.get("value") != row.get("value"):
            row["attribution"] = "updated"
        else:
            row["attribution"] = "unchanged"
        row["previous_revision"] = None if previous is None else previous["revision"]
        last_by_reference[reference] = row
    return rows


def build_generation_collision_pdf() -> bytes:
    """Build a tiny PDF where revision two introduces generation one of object 4."""

    def xref_entry(offset: int, generation: int = 0, *, free: bool = False) -> bytes:
        entry_type = "f" if free else "n"
        return f"{offset:010d} {generation:05d} {entry_type} \n".encode()

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[tuple[int, int], int] = {}

    def add_object(number: int, body: bytes, generation: int = 0) -> None:
        offsets[(number, generation)] = len(output)
        output.extend(f"{number} {generation} obj\n".encode())
        output.extend(body)
        output.extend(b"\nendobj\n")

    add_object(1, b"<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>")
    add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 120] /Annots [4 0 R] >>")
    add_object(
        4,
        b"<< /FT /Tx /T (GenField) /V (GEN0_APPROVED) /Subtype /Widget "
        b"/Rect [24 40 180 70] /P 3 0 R /F 4 >>",
    )
    add_object(5, b"<< /Fields [4 0 R] /NeedAppearances true >>")

    first_xref = len(output)
    output.extend(b"xref\n0 6\n")
    output.extend(xref_entry(0, 65535, free=True))
    for number in range(1, 6):
        output.extend(xref_entry(offsets[(number, 0)]))
    output.extend(
        f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{first_xref}\n%%EOF\n".encode()
    )

    add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 120] /Annots [4 1 R] >>")
    add_object(
        4,
        b"<< /FT /Tx /T (GenField) /V (GEN1_LATEST) /Subtype /Widget "
        b"/Rect [24 40 180 70] /P 3 0 R /F 4 >>",
        generation=1,
    )
    add_object(5, b"<< /Fields [4 1 R] /NeedAppearances true >>")

    second_xref = len(output)
    output.extend(b"xref\n3 1\n")
    output.extend(xref_entry(offsets[(3, 0)]))
    output.extend(b"4 1\n")
    output.extend(xref_entry(offsets[(4, 1)], generation=1))
    output.extend(b"5 1\n")
    output.extend(xref_entry(offsets[(5, 0)]))
    output.extend(
        f"trailer\n<< /Size 6 /Root 1 0 R /Prev {first_xref} >>\n"
        f"startxref\n{second_xref}\n%%EOF\n".encode()
    )
    return bytes(output)


def discover_field_targets(
    data: bytes, reader: PdfReader | None = None
) -> list[dict[str, Any]]:
    reader = reader or PdfReader(BytesIO(data), strict=False)
    return [
        {"name": qualified_name, "object_reference": f"{key[0]} {key[1]} R"}
        for key, qualified_name in field_qualified_names(reader).items()
    ]


def audit_pdf(pdf_path: str | Path, receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    path = Path(pdf_path)
    data = path.read_bytes()  # explicit read-only access; this tool never opens with "wb"
    revisions = describe_revisions(data)

    if receipt and receipt.get("fields"):
        targets = receipt["fields"]
    elif receipt and (receipt.get("field_name") or receipt.get("object_reference")):
        targets = [receipt]
    else:
        targets = discover_field_targets(data)

    target_reports = []
    for target in targets:
        object_reference = target.get("object_reference")
        if not object_reference:
            name = target["name"] if isinstance(target, dict) else target
            matching = next((item for item in discover_field_targets(data) if item["name"] == name), None)
            if matching is None:
                raise ValueError(f"Field {name!r} was not found in final AcroForm dictionary")
            object_reference = matching["object_reference"]
        object_number, approved_generation = parse_object_reference(object_reference)
        rows: list[dict[str, Any]] = []
        for revision in revisions:
            rows.extend(field_evidence_at_revision(data, revision, object_number))
        attribute_history(rows)
        final_reader = PdfReader(BytesIO(data), strict=False)
        final_locations = object_locations(final_reader, object_number)
        current_generation = max(
            (int(location["generation"]) for location in final_locations),
            default=approved_generation,
        )
        final_object = final_reader.get_object(
            IndirectObject(object_number, current_generation, final_reader)
        )
        target_reports.append(
            {
                "name": target.get("name"),
                "object_number": object_number,
                "approved_generation": approved_generation,
                "final_visible_reference": f"{object_number} {current_generation} R",
                "final_visible_value": to_native(final_object.get("/V"))
                if isinstance(final_object, DictionaryObject)
                else None,
                "history": rows,
            }
        )

    report: dict[str, Any] = {
        "pdf": str(path),
        "file_size": len(data),
        "file_sha256": sha256_hex(data),
        "revision_count": len(revisions),
        "revisions": revisions,
        "fields": target_reports,
    }
    if receipt is not None:
        report["receipt_verification"] = verify_receipt(receipt, report)
    return report


def verify_receipt(receipt: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    approved_revision = int(receipt["approved_revision"])
    checks: list[dict[str, Any]] = []

    def add_check(name: str, ok: bool, expected: Any, actual: Any) -> None:
        checks.append({"check": name, "ok": bool(ok), "expected": expected, "actual": actual})

    revision = next((item for item in report["revisions"] if item["revision"] == approved_revision), None)
    add_check("approved_revision_exists", revision is not None, approved_revision, [item["revision"] for item in report["revisions"]])
    if revision is None:
        return {"verified": False, "checks": checks}

    if receipt.get("approved_prefix_sha256"):
        add_check(
            "prefix_sha256",
            revision["prefix_sha256"] == receipt["approved_prefix_sha256"],
            receipt["approved_prefix_sha256"],
            revision["prefix_sha256"],
        )
    if receipt.get("approved_prefix_length") is not None:
        add_check(
            "prefix_length",
            revision["prefix_length"] == int(receipt["approved_prefix_length"]),
            receipt["approved_prefix_length"],
            revision["prefix_length"],
        )

    entries = receipt.get("fields") or [receipt]
    approved_values: list[dict[str, Any]] = []
    for entry in entries:
        object_number, generation = parse_object_reference(entry["object_reference"])
        field_report = next((item for item in report["fields"] if item["object_number"] == object_number), None)
        if field_report is None:
            add_check(f"field_report:{object_number}", False, "report", None)
            continue
        evidence = next(
            (
                row
                for row in field_report["history"]
                if row["revision"] == approved_revision
                and row["location"]["generation"] == generation
            ),
            None,
        )
        label = entry.get("name") or f"object {object_number} {generation} R"
        add_check(f"{label}:reference_present_at_revision", evidence is not None, True, False)
        if evidence is None:
            continue
        if entry.get("name"):
            actual_names = {evidence.get("field_name"), evidence.get("qualified_name")}
            add_check(
                f"{label}:name",
                entry["name"] in actual_names,
                entry["name"],
                evidence.get("qualified_name") or evidence.get("field_name"),
            )
        add_check(
            f"{label}:approved_value",
            evidence.get("value") == entry["approved_value"],
            entry["approved_value"],
            evidence.get("value"),
        )
        if entry.get("xref_offset") is not None:
            add_check(
                f"{label}:xref_offset",
                evidence["location"].get("offset") == int(entry["xref_offset"]),
                entry["xref_offset"],
                evidence["location"].get("offset"),
            )
        if entry.get("object_sha256"):
            add_check(
                f"{label}:object_sha256",
                evidence.get("sha256") == entry["object_sha256"],
                entry["object_sha256"],
                evidence.get("sha256"),
            )
        approved_values.append(
            {
                "name": entry.get("name"),
                "revision": approved_revision,
                "reference": evidence["reference"],
                "value": evidence["value"],
                "raw_start": evidence.get("raw_start"),
                "raw_end": evidence.get("raw_end"),
                "sha256": evidence.get("sha256"),
            }
        )

    verified = all(check["ok"] for check in checks)
    result = {"verified": verified, "approved_revision": approved_revision, "approved_values": approved_values, "checks": checks}
    if verified and approved_values:
        values = ", ".join(f"{item['name'] or item['reference']}={item['value']!r}" for item in approved_values)
        result["decision"] = f"Approved historical value(s) from revision {approved_revision}: {values}"
    return result


def build_three_save_fixture(directory: Path) -> tuple[Path, Path]:
    pdf_path = directory / "three-normal-saves.pdf"
    receipt_path = directory / "signoff-receipt.json"

    writer = PdfWriter()
    page = writer.add_blank_page(240, 120)
    field = DictionaryObject(
        {
            NameObject("/FT"): NameObject("/Tx"),
            NameObject("/T"): TextStringObject("DisclosureValue"),
            NameObject("/V"): TextStringObject("R1_CREATED_PUBLIC"),
        }
    )
    field_reference = writer._add_object(field)
    widget = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Widget"),
            NameObject("/Rect"): ArrayObject(
                [NumberObject(24), NumberObject(60), NumberObject(216), NumberObject(92)]
            ),
            NameObject("/Parent"): field_reference,
            NameObject("/F"): NumberObject(4),
        }
    )
    widget_reference = writer._add_object(widget)
    field[NameObject("/Kids")] = ArrayObject([widget_reference])
    page[NameObject("/Annots")] = ArrayObject([widget_reference])
    acro_form = DictionaryObject(
        {
            NameObject("/Fields"): ArrayObject([field_reference]),
            NameObject("/NeedAppearances"): BooleanObject(True),
        }
    )
    writer._root_object[NameObject("/AcroForm")] = writer._add_object(acro_form)

    buffer = BytesIO()
    writer.write(buffer)
    pdf_bytes = buffer.getvalue()

    for value in ("R2_APPROVED_VALUE", "R3_LATER_SECRET"):
        incremental_writer = PdfWriter(BytesIO(pdf_bytes), incremental=True)
        incremental_writer.get_object(field_reference.idnum)[NameObject("/V")] = TextStringObject(value)
        buffer = BytesIO()
        incremental_writer.write(buffer)
        pdf_bytes = buffer.getvalue()

    pdf_path.write_bytes(pdf_bytes)
    provisional = audit_pdf(pdf_path)
    revision_two = provisional["revisions"][1]
    field_history = provisional["fields"][0]["history"]
    approved_evidence = next(
        row
        for row in field_history
        if row["revision"] == 2 and row["reference"] == f"{field_reference.idnum} 0 R"
    )
    receipt = {
        "approved_revision": 2,
        "approved_prefix_length": revision_two["prefix_length"],
        "approved_prefix_sha256": revision_two["prefix_sha256"],
        "fields": [
            {
                "name": "DisclosureValue",
                "object_reference": f"{field_reference.idnum} 0 R",
                "approved_value": "R2_APPROVED_VALUE",
                "xref_offset": approved_evidence["location"]["offset"],
                "object_sha256": approved_evidence["sha256"],
            }
        ],
    }
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return pdf_path, receipt_path


def run_self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="pdf-history-audit-") as temporary_directory:
        directory = Path(temporary_directory)
        pdf_path, receipt_path = build_three_save_fixture(directory)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        report = audit_pdf(pdf_path, receipt)

        assert report["revision_count"] == 3
        history = report["fields"][0]["history"]
        values_by_revision = {row["revision"]: row["value"] for row in history if row["reference"] == "5 0 R"}
        assert values_by_revision == {
            1: "R1_CREATED_PUBLIC",
            2: "R2_APPROVED_VALUE",
            3: "R3_LATER_SECRET",
        }
        attribution = {row["revision"]: row["attribution"] for row in history if row["reference"] == "5 0 R"}
        assert attribution == {1: "field_created", 2: "updated", 3: "updated"}
        offsets = {row["revision"]: row["location"]["offset"] for row in history if row["reference"] == "5 0 R"}
        assert len(set(offsets.values())) == 3
        assert offsets[1] < report["revisions"][0]["prefix_length"]
        assert report["revisions"][0]["segment_start"] <= offsets[1] < report["revisions"][0]["prefix_length"]
        assert report["revisions"][1]["segment_start"] <= offsets[2] < report["revisions"][1]["prefix_length"]
        assert report["revisions"][2]["segment_start"] <= offsets[3] < report["revisions"][2]["prefix_length"]
        for row in history:
            page_refs = row["page_references"]
            assert len(page_refs) == 1
            assert page_refs[0]["page_index"] == 0
            assert page_refs[0]["annotation_reference"] == "6 0 R"
        assert report["fields"][0]["final_visible_value"] == "R3_LATER_SECRET"
        assert report["receipt_verification"]["verified"] is True

        generation_pdf = directory / "generation-collision.pdf"
        generation_pdf.write_bytes(build_generation_collision_pdf())
        generation_report = audit_pdf(generation_pdf)
        generation_history = generation_report["fields"][0]["history"]
        second_revision = [row for row in generation_history if row["revision"] == 2]
        assert {(row["reference"], row["value"]) for row in second_revision} == {
            ("4 0 R", "GEN0_APPROVED"),
            ("4 1 R", "GEN1_LATEST"),
        }
        old_generation = next(row for row in second_revision if row["reference"] == "4 0 R")
        new_generation = next(row for row in second_revision if row["reference"] == "4 1 R")
        assert old_generation["sha256"] != new_generation["sha256"]
        assert old_generation["page_references"] == []
        assert new_generation["page_references"][0]["annotation_reference"] == "4 1 R"

        return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit", help="audit a PDF against an optional signoff receipt")
    audit_parser.add_argument("pdf", type=Path)
    audit_parser.add_argument("--receipt", type=Path)
    audit_parser.add_argument("--json-output", type=Path)

    subparsers.add_parser("self-test", help="create and verify a three-save temporary PDF")
    args = parser.parse_args(argv)

    logging.getLogger("pypdf").setLevel(logging.ERROR)

    if args.command == "self-test":
        report = run_self_test()
        print(json.dumps(report["receipt_verification"], ensure_ascii=False, indent=2))
        print("\nHistorical values:")
        for row in report["fields"][0]["history"]:
            print(
                f"  revision {row['revision']}: {row['reference']} @ byte {row.get('raw_start')} "
                f"({row['attribution']}) value={row['value']!r}"
            )
        print(f"\nFinal viewer value: {report['fields'][0]['final_visible_value']!r}")
        return 0

    receipt = json.loads(args.receipt.read_text(encoding="utf-8")) if args.receipt else None
    report = audit_pdf(args.pdf, receipt)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_output:
        args.json_output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report.get("receipt_verification", {}).get("verified", True) else 2


if __name__ == "__main__":
    raise SystemExit(main())
