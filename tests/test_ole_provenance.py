"""
Tests for the ole_provenance original-vs-derived comparison.
"""

import json
import os

import pytest

from ole_provenance import (
    build_sidecar,
    drop_source_proof,
    resolve_mapping,
)
from ole_provenance.sample import (
    DERIVED_NAME,
    EXPORT_LOG_NAME,
    ORIGINAL_NAME,
    SHARED_BYTES,
    build_sample,
)


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    outdir = tmp_path_factory.mktemp("exhibits")
    build_sample(outdir)
    with open(os.path.join(str(outdir), EXPORT_LOG_NAME),
              encoding="utf-8") as handle:
        proofs = json.load(handle)["proofs"]
    return {
        "original": os.path.join(str(outdir), ORIGINAL_NAME),
        "derived": os.path.join(str(outdir), DERIVED_NAME),
        "proofs": proofs,
    }


@pytest.fixture(scope="module")
def sidecar(sample):
    return build_sidecar(sample["original"], sample["derived"],
                         proofs=sample["proofs"])


def _resolution(report, derived_path):
    for resolution in report["resolutions"]:
        if resolution["derived_path"] == derived_path:
            return resolution
    raise AssertionError("no resolution for %s" % derived_path)


def test_sample_keeps_two_identical_streams(sample):
    sidecar = build_sidecar(sample["original"], sample["derived"])
    hashes = [e["sha256"] for e in sidecar["original"]["entries"]]
    assert len(hashes) != len(set(hashes)), \
        "the original sample must keep two byte-identical streams"


def test_unique_mapping_with_proof(sidecar):
    report = resolve_mapping(sidecar)
    assert report["warnings"] == []
    renamed = _resolution(report, "Handover/renamed_export")
    assert renamed["status"] == "unique"
    assert renamed["match"]["path"] == "Evidence/streamB_copy"


def test_unique_mapping_by_content_only(sidecar):
    report = resolve_mapping(sidecar)
    table = _resolution(report, "Handover/Table")
    assert table["status"] == "unique"
    assert table["match"]["path"] == "Evidence/Table"


def test_dropping_proof_degrades_to_ambiguity(sidecar, sample):
    drop_source_proof(sidecar, "proof-1")
    report = resolve_mapping(sidecar)
    renamed = _resolution(report, "Handover/renamed_export")
    assert renamed["status"] == "ambiguous"
    candidate_paths = {c["path"] for c in renamed["candidates"]}
    assert candidate_paths == {"Evidence/StreamA", "Evidence/streamB_copy"}
    # the untouched proof still keeps the other stream unique
    assert _resolution(report, "Handover/Table")["status"] == "unique"


def test_byte_ranges_recover_stream_bytes(sidecar, sample):
    report = resolve_mapping(sidecar)
    with open(sample["original"], "rb") as handle:
        original_bytes = handle.read()
    for resolution in report["resolutions"]:
        entries = ([resolution["match"]] if resolution["match"]
                   else resolution["candidates"])
        for entry in entries:
            recovered = b"".join(
                original_bytes[offset:offset + length]
                for offset, length in entry["byte_ranges"]
            )
            assert recovered == SHARED_BYTES or len(recovered) == entry["size"]
            assert len(recovered) == entry["size"]


def test_unmatched_when_content_changes(sidecar, sample, tmp_path):
    tampered = tmp_path / "tampered.ole"
    with open(sample["derived"], "rb") as handle:
        data = bytearray(handle.read())
    # flip one byte inside the Table stream data (first data sector)
    data[512] ^= 0xFF
    with open(str(tampered), "wb") as handle:
        handle.write(data)
    stale = build_sidecar(sample["original"], str(tampered),
                          proofs=sidecar["source_proofs"])
    # sidecar records the tampered hash, so resolution is unmatched
    report = resolve_mapping(stale)
    assert _resolution(report, "Handover/Table")["status"] == "unmatched"


def test_contradicted_proof_is_flagged(sidecar):
    sidecar["source_proofs"].append({
        "id": "proof-bogus",
        "derived_path": "Handover/Table",
        "original_path": "Evidence/StreamA",
    })
    report = resolve_mapping(sidecar)
    table = _resolution(report, "Handover/Table")
    assert table["status"] == "unique"
    assert any("proof-bogus" in warning for warning in table["warnings"])
