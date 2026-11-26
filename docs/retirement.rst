Signed approval attachment retirement
=====================================

``securesystemslib.retirement`` joins three artifacts into one auditable
workflow:

* a DSSE-signed **approval index**, which lists attachments, case-file
  references, attachment digests, and approver-signed authorization records;
* a DSSE-signed **retirement manifest**, which records exactly which attachment
  was withdrawn and which digest and authorization record were retained; and
* a **retirement service**, which verifies signatures and reference counts
  before it removes a single file through a storage backend.

The goal is not to retain stale attachment bytes.  The goal is to prove, after
the bytes are gone, that the old attachment had a specific digest and that an
approver signed an authorization for that exact digest.

Documents
---------

An approval index has attachments and case files.  A version 2 index stores a
digest for every attachment and an authorization record for every case::

    {
      "schema_version": 2,
      "attachments": {
        "att-1": {
          "path": "attachments/att-1.txt",
          "digest": {"sha256": "..."}
        }
      },
      "cases": {
        "case-a": {
          "attachments": ["att-1"],
          "authorization": {
            "record_id": "authz-case-a",
            "case_id": "case-a",
            "attachment_ids": ["att-1"],
            "approved_at": "2021-06-01T09:30:00+00:00",
            "approver_keyid": "...",
            "authorized_digests": {"att-1": {"sha256": "..."}},
            "signature": {"keyid": "...", "sig": "..."}
          }
        }
      }
    }

The authorization signature covers the record body.  It therefore binds the
approver, the case, the attachment identifier, and the authorized digest.  The
``approved_at`` timestamp is part of the signed body: verification proves that
authorization existed at the recorded time without asking the current key
status to re-authorize an old act.

The index is wrapped in a DSSE envelope and signed by an archive key.  The
manifest is wrapped and signed in the same way.  Each manifest entry has this
shape::

    {
      "attachment_id": "att-1",
      "case_id": "case-a",
      "withdrawn": {"attachment_id": "att-1", "path": "attachments/att-1.txt"},
      "retained": {
        "digest": {"sha256": "..."},
        "authorization": {...},
        "index_digest": {"sha256": "..."}
      },
      "retired_at": "...",
      "request_id": "..."
    }

Usage
-----

Build and sign an index::

    from securesystemslib.retirement import (
        INDEX_PAYLOAD_TYPE, INDEX_SCHEMA_VERSION, ApprovalAttachment,
        ApprovalCase, ApprovalIndex, AuthorizationRecord, write_signed_document,
    )

    authorization = AuthorizationRecord.create(
        record_id="authz-case-a",
        case_id="case-a",
        attachment_ids=["att-1"],
        approved_at="2021-06-01T09:30:00+00:00",
        authorized_digests={"att-1": {"sha256": "..."}},
        approver=approver_signer,
    )
    index = ApprovalIndex(
        schema_version=INDEX_SCHEMA_VERSION,
        attachments={
            "att-1": ApprovalAttachment(
                attachment_id="att-1",
                path="attachments/att-1.txt",
                digest={"sha256": "..."},
            )
        },
        cases={
            "case-a": ApprovalCase(
                case_id="case-a",
                attachment_ids=("att-1",),
                authorization=authorization,
            )
        },
    )
    write_signed_document(
        "archive/index.dsse.json", index.to_dict(), INDEX_PAYLOAD_TYPE, archivist_signer
    )

Retire one attachment::

    service = RetirementService(
        [archivist_key],
        [approver_key],
        signer=archivist_signer,
    )
    result = service.retire(
        "archive/index.dsse.json",
        {"request_id": "r-1", "case_id": "case-a", "attachment_id": "att-1"},
        manifest_path="archive/retirement-manifest.dsse.json",
        evidence_dir="archive/evidence/r-1",
    )
    assert result.retired

Verify the manifest later, even after the attachment is gone::

    report = service.verify_retirement(
        "archive/index.dsse.json", "archive/retirement-manifest.dsse.json"
    )
    assert report.valid

Invariants
----------

``retire()`` enforces the following order:

1. Verify the index envelope signature and threshold.
2. Require a request naming exactly one attachment.  A list of two targets is
   rejected before any storage operation.
3. Require the attachment and case to exist and the case to reference the
   attachment.
4. Require the attachment to have exactly one referring case.  If any other
   case references it, the result is ``shared-reference`` and the file is not
   removed.
5. Require a complete evidence report: index signature, attachment digest,
   case authorization, authorization signature, and authorized digest.
6. Recompute the attachment digest and compare it to both the index and the
   approver-signed authorization.
7. Append one entry to the manifest, sign it, persist it, and only then remove
   the attachment through ``StorageBackendInterface.remove()``.

Every accepted and rejected attempt writes an evidence directory.  A successful
retirement leaves ``retention-record.json`` with the withdrawn attachment, its
digest, the approver authorization, and the index digest, plus dedicated
``retained-digest.json`` and ``authorization-record.json`` files, the signed
manifest, and ``verification-report.json``.  A shared-reference refusal leaves
``rejection.json`` and ``verification-report.json`` showing the still-present
attachment, its matching digest, and all referring cases.

Legacy status
-------------

``load_index()`` accepts legacy schema version 1 and unsigned plain JSON.  It
does not pretend the result is usable.  The returned ``IndexReadResult`` has an
explicit ``missing-evidence`` status with fields such as::

    index.signature
    index.schema_version>=2
    attachments.att-1.digest
    cases.case-a.authorization

``require_complete()`` raises ``MissingEvidenceError`` carrying that report, and
``retire()`` returns ``reason="missing-evidence"`` without removing the file.

Acceptance demo
---------------

Run::

    python examples/approval_retirement/demo.py

It produces two bundles:

* ``examples/approval_retirement/evidence/success``: the old attachment is
  gone, while ``retention-record.json`` and the signed manifest prove its digest
  and authorization; verification status is ``valid``.
* ``examples/approval_retirement/evidence/shared-reference``: the request is
  rejected as ``shared-reference``, the attachment is still present, and
  ``verification-report.json`` records both referring cases and the matching
  digest; verification status is ``valid``.

Both bundles include the signed index snapshot, the request, public keys, and a
machine-readable report.  ``acceptance-summary.json`` is the entry point.
They can be re-verified from the published public keys alone with::

    python examples/approval_retirement/verify_evidence.py
