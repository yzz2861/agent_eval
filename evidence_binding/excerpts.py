"""Standalone registry excerpt manifests.

An excerpt is a JSON file delivered separately from any live hive.  It may
carry a provenance block (source file hash, sequence numbers and record
offset) or only the record content.  The binding logic in
:mod:`evidence_binding.inspector` treats these two situations very
differently: content alone never proves a common source.
"""

import json

from .models import ProvenanceGrade


PROVENANCE_FIELDS = (
    "source_sha256",
    "source_sequence1",
    "source_sequence2",
    "record_absolute_offset_hex",
    "record_kind",
)


def is_excerpt_manifest(path, buffer_bytes):
    """Return True when the file is a JSON excerpt manifest we understand."""
    if not path.lower().endswith(".json"):
        return False
    try:
        payload = json.loads(buffer_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("manifest_type") == (
        "registry-excerpt/v1"
    )


def load_excerpt(path, buffer_bytes):
    """Parse an excerpt manifest and grade the provenance of each record.

    Returns ``(records, errors)``.  Each record dict carries the fields used
    by the binding logic plus a provenance grade and binding blockers that
    explain why a content-only excerpt cannot be merged automatically.
    """
    payload = json.loads(buffer_bytes.decode("utf-8"))
    records = []
    errors = []
    for index, entry in enumerate(payload.get("records", [])):
        provenance = entry.get("provenance") or {}
        missing = [
            field_name
            for field_name in PROVENANCE_FIELDS
            if provenance.get(field_name) in (None, "")
        ]
        if not missing:
            grade = ProvenanceGrade.FULL
            blockers = []
        elif provenance:
            grade = ProvenanceGrade.CONTENT_ONLY
            blockers = [
                "partial provenance, missing: %s" % ", ".join(missing)
            ]
        else:
            grade = ProvenanceGrade.CONTENT_ONLY
            blockers = [
                "excerpt carries content only, no common-source proof"
            ]

        record = {
            "manifest_index": index,
            "record_kind": entry.get("record_kind", "value"),
            "registry_path": entry.get("registry_path", ""),
            "value_name": entry.get("value_name"),
            "value_type": entry.get("value_type"),
            "timestamp": entry.get("timestamp"),
            "content_fingerprint": entry.get("content_fingerprint", ""),
            "claimed_data_hex": entry.get("data_hex"),
            "provenance_grade": grade,
            "provenance": provenance,
            "binding_blockers": blockers,
        }
        if not record["content_fingerprint"]:
            errors.append(
                "record %d in %s has no content_fingerprint" % (index, path)
            )
        records.append(record)
    return records, errors
