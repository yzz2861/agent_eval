from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from dissect.cstruct import (
    EvidenceMismatch,
    LayoutRevision,
    UnknownApproval,
    read_union_evidence,
    recompute_union_evidence,
    replay_union_evidence,
)

if TYPE_CHECKING:
    from dissect.cstruct import cstruct

SAMPLE_CDEF = """
union sample {
    uint32 whole;
    uint16 low;
    char   raw[4];
};

union layout_v1 {
    uint32 magic;
    uint16 version;
    char   blob[4];
};

union layout_v2 {
    char   blob[4];
    uint16 version;
    uint32 magic;
};
"""


def test_same_bytes_support_multiple_members(cs: cstruct, compiled: bool) -> None:
    cs.load(SAMPLE_CDEF, compiled=compiled)
    data = b"\x11\x22\x33\x44"

    evidence = cs.sample.read_evidence(data)

    assert evidence.proven_members == ("whole", "low", "raw")
    assert evidence.witnesses[0].value == 0x44332211
    assert evidence.witnesses[1].value == 0x2211
    assert evidence.witnesses[2].value == b"\x11\x22\x33\x44"

    # Every member is a witness to the same retained bytes, not a copy of them.
    assert evidence.basis == data
    assert evidence.witnesses[0].raw == data
    assert evidence.witnesses[1].byte_range == (0, 2)
    assert evidence.witnesses[2].byte_range == (0, 4)
    assert len(evidence.conflicts) == 3
    assert evidence.has_divergence
    json.dumps(evidence.as_dict())


def test_single_member_approval_retains_only_one_field(cs: cstruct) -> None:
    cs.load(SAMPLE_CDEF)
    data = b"\x11\x22\x33\x44"

    evidence = cs.read_union_evidence("sample", data, ["low"])

    assert evidence.proven_members == ("low",)
    assert cs.sample.read_evidence(data, "low").digest == evidence.digest
    assert evidence.withheld == ("whole", "raw")
    assert evidence.conflicts == ()
    assert evidence.basis == data
    assert [verdict.status for verdict in evidence.verdicts] == ["withheld", "proven", "withheld"]

    parsed = cs.sample(data)
    assert parsed.evidence({"low"}).digest == evidence.digest


def test_revoking_one_approval_changes_proof_list_not_bytes(cs: cstruct) -> None:
    cs.load(SAMPLE_CDEF)
    data = b"\x11\x22\x33\x44"

    before = read_union_evidence(cs.sample, data, {"whole", "low", "raw"})
    after = read_union_evidence(cs.sample, data, {"whole", "low"})

    assert before.basis == after.basis == data
    assert before.basis_digest == after.basis_digest
    assert before.proven_members == ("whole", "low", "raw")
    assert after.proven_members == ("whole", "low")
    assert after.withheld == ("raw",)
    assert before.digest != after.digest

    before_low = next(witness for witness in before.witnesses if witness.member == "low")
    after_low = next(witness for witness in after.witnesses if witness.member == "low")
    assert before_low.raw == after_low.raw
    assert before_low.raw_digest == after_low.raw_digest


def test_layout_revisions_keep_their_own_member_views(cs: cstruct) -> None:
    cs.load(SAMPLE_CDEF)
    data = b"\x11\x22\x33\x44"

    revisions = replay_union_evidence(
        data,
        [
            LayoutRevision(1, cs.layout_v1, {"magic"}),
            {"revision": 2, "union": cs.layout_v2, "approvals": {"blob", "version"}},
        ],
    )

    assert [result.revision for result in revisions] == [1, 2]
    assert [result.layout_name for result in revisions] == ["layout_v1", "layout_v2"]
    assert revisions[0].proven_members == ("magic",)
    assert revisions[1].proven_members == ("blob", "version")
    assert revisions[0].members == ("magic", "version", "blob")
    assert revisions[1].members == ("blob", "version", "magic")
    assert revisions[0].basis_digest == revisions[1].basis_digest
    assert revisions[0].digest != revisions[1].digest


def test_truncated_sample_proves_only_members_with_enough_bytes(cs: cstruct) -> None:
    cs.load(SAMPLE_CDEF)
    data = b"\x11\x22"

    evidence = cs.sample.read_evidence(data, {"whole", "low"})

    assert evidence.truncated
    assert evidence.basis_end == 2
    assert evidence.proven_members == ("low",)
    assert evidence.unavailable_members == ("whole",)
    failure = evidence.failures[0]
    assert failure.reason == "insufficient bytes"
    assert failure.required == 4
    assert failure.available == 2


def test_recompute_is_deterministic_and_detects_tampering(cs: cstruct) -> None:
    cs.load(SAMPLE_CDEF)
    data = b"\x11\x22\x33\x44"
    evidence = cs.sample.read_evidence(data, {"whole", "low"})

    assert recompute_union_evidence(evidence).digest == evidence.digest
    assert evidence.recompute().digest == evidence.digest

    with pytest.raises(EvidenceMismatch):
        recompute_union_evidence(replace(evidence, digest="tampered"))

    with pytest.raises(EvidenceMismatch):
        recompute_union_evidence(replace(evidence, basis=b"\x99\x22\x33\x44"))


def test_unknown_approval_is_reported_or_rejected(cs: cstruct) -> None:
    cs.load(SAMPLE_CDEF)
    data = b"\x11\x22\x33\x44"

    with pytest.raises(UnknownApproval):
        cs.sample.read_evidence(data, {"whole", "missing"})

    evidence = cs.sample.read_evidence(data, {"whole", "missing"}, strict=False)
    assert evidence.proven_members == ("whole",)
    assert evidence.unknown_approvals == ("missing",)
    assert evidence.withheld == ("low", "raw")


def test_approval_mapping_only_uses_truthy_entries(cs: cstruct) -> None:
    cs.load(SAMPLE_CDEF)
    evidence = cs.sample.read_evidence(b"\x01\x02\x03\x04", {"whole": True, "low": False, "raw": True})

    assert evidence.proven_members == ("whole", "raw")
