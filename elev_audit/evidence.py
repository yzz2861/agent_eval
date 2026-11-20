"""Read-only pefile evidence extraction and manifest parsing for UAC audits.

No default execution level is ever substituted: when an artifact carries no
declaration, that absence is recorded as evidence rather than guessed.
"""
from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import pefile

RT_MANIFEST = pefile.RESOURCE_TYPE.get("RT_MANIFEST", 24)

FINDING_LANGUAGE_BRANCH = "language_branch"
FINDING_NO_DECLARATION = "no_declaration"
FINDING_EVIDENCE_MISSING = "evidence_missing"
FINDING_PARSE_ERROR = "parse_error"
FINDING_MALFORMED_PE = "malformed_pe"


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


@dataclass
class RequestedLevel:
    """The requestedExecutionLevel declaration, if one exists."""

    level: Optional[str]
    ui_access: Optional[bool]
    present: bool


@dataclass
class ManifestEvidence:
    """A single manifest document and everything it declares."""

    source: str
    language_id: Optional[int]
    sha256: str
    requested_level: RequestedLevel
    auto_elevate: Optional[bool]
    raw_size: int
    parse_error: Optional[str] = None
    findings: List[str] = field(default_factory=list)

    @property
    def has_execution_level_declaration(self) -> bool:
        return self.requested_level.present


@dataclass
class ArtifactEvidence:
    """Evidence collected for one audited artifact."""

    artifact_id: str
    pe_sha256: Optional[str]
    machine: Optional[str]
    machine_id: Optional[int]
    manifests: List[ManifestEvidence] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    detail: Dict[str, object] = field(default_factory=dict)

    @property
    def manifest_present(self) -> bool:
        return bool(self.manifests)


@dataclass
class DeploymentConditions:
    """Caller-supplied deployment conditions governing an audit."""

    conditions: Dict[str, object] = field(default_factory=dict)
    source: str = "caller"

    def get(self, key: str) -> Optional[object]:
        return self.conditions.get(key)


def _to_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in ("true", "1", "yes"):
        return True
    if lowered in ("false", "0", "no"):
        return False
    return None


def parse_manifest(blob: bytes, source: str, language_id: Optional[int] = None) -> ManifestEvidence:
    """Parse a manifest document without substituting any default values.

    A manifest without requestedExecutionLevel is recorded as no declaration,
    never as asInvoker. A document that is not well-formed XML yields a parse
    error finding while retaining the hash of the exhibit.
    """
    digest = hashlib.sha256(blob).hexdigest()
    requested = RequestedLevel(level=None, ui_access=None, present=False)
    auto_elevate: Optional[bool] = None
    parse_error: Optional[str] = None
    findings: List[str] = []
    try:
        root = ET.fromstring(blob)
    except ET.ParseError as exc:
        return ManifestEvidence(
            source=source,
            language_id=language_id,
            sha256=digest,
            requested_level=requested,
            auto_elevate=None,
            raw_size=len(blob),
            parse_error=f"xml parse error: {exc}",
            findings=[FINDING_PARSE_ERROR],
        )
    for elem in root.iter():
        name = _local_name(elem.tag)
        if name == "requestedExecutionLevel":
            requested = RequestedLevel(
                level=elem.attrib.get("level"),
                ui_access=_to_bool(elem.attrib.get("uiAccess")),
                present=True,
            )
        elif name == "autoElevate":
            text = (elem.text or "").strip()
            auto_elevate = _to_bool(text) if text else None
    if not requested.present:
        findings.append(FINDING_NO_DECLARATION)
    return ManifestEvidence(
        source=source,
        language_id=language_id,
        sha256=digest,
        requested_level=requested,
        auto_elevate=auto_elevate,
        raw_size=len(blob),
        parse_error=parse_error,
        findings=findings,
    )


def _machine_name(machine_id: int) -> str:
    for name, value in pefile.MACHINE_TYPE.items():
        if value == machine_id:
            return name
    return "IMAGE_FILE_MACHINE_UNKNOWN"


def _iter_manifest_entries(pe: pefile.PE):
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_id = getattr(resource_type, "id", None)
        if type_id is None:
            type_id = getattr(resource_type.struct, "Id", None)
        if type_id != RT_MANIFEST:
            continue
        type_dir = getattr(resource_type, "directory", None)
        if type_dir is None:
            continue
        for name_entry in type_dir.entries:
            name_dir = getattr(name_entry, "directory", None)
            if name_dir is None:
                continue
            for lang_entry in name_dir.entries:
                data_entry = getattr(lang_entry, "data", None)
                if data_entry is None:
                    continue
                lang_id = getattr(lang_entry, "id", None)
                if lang_id is None:
                    lang_id = getattr(lang_entry.struct, "Id", None)
                yield lang_id, data_entry


def extract_embedded_evidence(pe_bytes: bytes, artifact_id: str) -> ArtifactEvidence:
    """Extract RT_MANIFEST evidence from PE bytes using pefile read-only.

    The PE is opened from in-memory bytes with fast_load and only the resource
    directory is parsed. Nothing on the scanning workstation is consulted for
    a default execution level.
    """
    digest = hashlib.sha256(pe_bytes).hexdigest()
    try:
        pe = pefile.PE(data=pe_bytes, fast_load=True)
    except pefile.PEFormatError as exc:
        evidence = ArtifactEvidence(
            artifact_id=artifact_id,
            pe_sha256=digest,
            machine=None,
            machine_id=None,
            findings=[FINDING_MALFORMED_PE, FINDING_EVIDENCE_MISSING],
            detail={"error": str(exc)},
        )
        return evidence
    machine_id = pe.FILE_HEADER.Machine
    evidence = ArtifactEvidence(
        artifact_id=artifact_id,
        pe_sha256=digest,
        machine=_machine_name(machine_id),
        machine_id=machine_id,
    )
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        entries = list(_iter_manifest_entries(pe))
        if not entries:
            evidence.findings.append(FINDING_EVIDENCE_MISSING)
        seen_languages = set()
        for lang_id, data_entry in entries:
            if lang_id in seen_languages:
                continue
            seen_languages.add(lang_id)
            blob = pe.get_data(
                data_entry.struct.OffsetToData, data_entry.struct.Size
            )
            source = f"pe-resource://{artifact_id}/RT_MANIFEST#lang={lang_id}"
            manifest = parse_manifest(blob, source=source, language_id=lang_id)
            evidence.manifests.append(manifest)
        if len(seen_languages) > 1:
            evidence.findings.append(FINDING_LANGUAGE_BRANCH)
    finally:
        pe.close()
    return evidence


def evidence_from_standalone_manifest(
    manifest_bytes: bytes, artifact_id: str, source: str = "caller-supplied"
) -> ManifestEvidence:
    """Wrap an independent manifest handed in by the caller as evidence."""
    return parse_manifest(blob=manifest_bytes, source=source, language_id=None)


def attach_external_manifest(
    evidence: ArtifactEvidence, manifest_bytes: bytes, source: str = "caller-supplied"
) -> ManifestEvidence:
    """Attach a caller-provided standalone manifest to existing PE evidence."""
    manifest = evidence_from_standalone_manifest(
        manifest_bytes, artifact_id=evidence.artifact_id, source=source
    )
    evidence.manifests.append(manifest)
    if evidence.findings and FINDING_EVIDENCE_MISSING in evidence.findings:
        evidence.findings.remove(FINDING_EVIDENCE_MISSING)
    return manifest


def summarize_declarations(evidence: ArtifactEvidence) -> Dict[str, object]:
    """Return a compact, default-free summary of what the evidence declares."""
    levels = sorted({
        m.requested_level.level
        for m in evidence.manifests
        if m.requested_level.present and m.requested_level.level is not None
    })
    auto = {
        m.auto_elevate for m in evidence.manifests if m.auto_elevate is not None
    }
    return {
        "artifact_id": evidence.artifact_id,
        "machine": evidence.machine,
        "pe_sha256": evidence.pe_sha256,
        "manifest_count": len(evidence.manifests),
        "declared_levels": levels,
        "auto_elevate_values": sorted(auto),
        "findings": list(evidence.findings),
        "per_manifest": [
            {
                "source": m.source,
                "language_id": m.language_id,
                "sha256": m.sha256,
                "level": m.requested_level.level,
                "ui_access": m.requested_level.ui_access,
                "declared": m.requested_level.present,
                "auto_elevate": m.auto_elevate,
                "parse_error": m.parse_error,
                "findings": list(m.findings),
            }
            for m in evidence.manifests
        ],
    }
