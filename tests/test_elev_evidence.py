import hashlib

import pefile
import pytest

from elev_audit import (
    FINDING_EVIDENCE_MISSING,
    FINDING_LANGUAGE_BRANCH,
    FINDING_NO_DECLARATION,
    FINDING_PARSE_ERROR,
    build_empty_pe,
    build_pe_with_manifests,
    extract_embedded_evidence,
    make_manifest,
    parse_manifest,
)

MACHINES = ["i386", "amd64", "arm64"]


@pytest.mark.parametrize("machine", MACHINES)
def test_generated_pe_is_parseable_by_pefile_and_roundtrips_manifest(machine):
    manifest = make_manifest("requireAdministrator")
    data = build_pe_with_manifests({0x409: manifest}, machine=machine)
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )
    entries = list(pe.DIRECTORY_ENTRY_RESOURCE.entries)
    assert entries[0].id == pefile.RESOURCE_TYPE["RT_MANIFEST"]
    lang_entry = entries[0].directory.entries[0].directory.entries[0]
    raw = pe.get_data(lang_entry.data.struct.OffsetToData, lang_entry.data.struct.Size)
    assert raw == manifest
    pe.close()


def test_multi_language_manifests_are_separate_evidence_branches():
    english = make_manifest("requireAdministrator")
    chinese = make_manifest("asInvoker", auto_elevate=True)
    data = build_pe_with_manifests({0x409: english, 0x804: chinese}, machine="amd64")
    evidence = extract_embedded_evidence(data, "multi.exe")
    assert FINDING_LANGUAGE_BRANCH in evidence.findings
    assert len(evidence.manifests) == 2
    by_lang = {m.language_id: m for m in evidence.manifests}
    assert by_lang[0x409].requested_level.level == "requireAdministrator"
    assert by_lang[0x804].requested_level.level == "asInvoker"
    assert by_lang[0x804].auto_elevate is True
    assert by_lang[0x409].auto_elevate is None


def test_no_declaration_is_recorded_not_defaulted():
    manifest = make_manifest(level=None)
    data = build_pe_with_manifests({0x409: manifest}, machine="i386")
    evidence = extract_embedded_evidence(data, "nodecl.exe")
    assert len(evidence.manifests) == 1
    manifest_evidence = evidence.manifests[0]
    assert manifest_evidence.has_execution_level_declaration is False
    assert manifest_evidence.requested_level.level is None
    assert FINDING_NO_DECLARATION in manifest_evidence.findings


def test_missing_manifest_resource_is_evidence_missing():
    data = build_empty_pe("arm64")
    evidence = extract_embedded_evidence(data, "empty.exe")
    assert evidence.manifests == []
    assert evidence.findings == [FINDING_EVIDENCE_MISSING]


def test_malformed_pe_is_flagged_without_raising():
    evidence = extract_embedded_evidence(b"NOT A PE" * 8, "broken.exe")
    assert evidence.machine is None
    assert FINDING_EVIDENCE_MISSING in evidence.findings
    assert evidence.pe_sha256 == hashlib.sha256(b"NOT A PE" * 8).hexdigest()


def test_malformed_manifest_xml_is_parse_error_but_keeps_hash():
    blob = b"<?xml version=\"1.0\"?><assembly><unclosed>"
    manifest = parse_manifest(blob, source="caller:x.manifest")
    assert FINDING_PARSE_ERROR in manifest.findings
    assert manifest.sha256 == hashlib.sha256(blob).hexdigest()
    assert manifest.has_execution_level_declaration is False
