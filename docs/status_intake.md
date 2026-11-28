# Correction Intake over OCSP Status Material

`asn1crypto.status_intake` sits immediately after ASN.1 parsing.  It takes the
already-verified result of `asn1crypto.ocsp` and records, per public status
declaration, the externally approved corrections that change the internal
handling responsibility of business orders.  It does not verify signatures and
does not re-parse DER; feed it an `OCSPResponse` that the transport/validation
layer has already accepted.

## Model

 - `StatusDeclaration` - one OCSP `SingleResponse`.  Its `declaration_id` is
   derived from the `CertId` only, so the same certificate keeps one identity
   across batches and revisions.  `this_update` distinguishes revisions.
 - `DispositionOrder` - an internal business handling order.  Any number of
   orders may reference the same declaration; a declaration is not consumed by
   the first order.
 - `SignedMaterial` - a material unit that has already been signed for.  A
   successfully applied correction claims exactly one unit per affected order.
 - `ApprovedCorrection` - the externally authorised change, identified by
   `correction_id`, declaration and a monotonic `version`, with an
   `approval_ref` and the new `responsibility`.
 - `CorrectionNotice` - the transport envelope.  Duplicate notifications are
   detected by `notice_id`; re-delivered corrections are detected by
   `(correction_id, declaration_id, version)` plus a content fingerprint.
 - `CorrectionBinding` - the durable link between a correction revision, the
   declaration revision it was bound against, the order, the order's new
   version and the claimed signed material.

## Usage

```python
from asn1crypto import ocsp
from asn1crypto.status_intake import (
    ApprovedCorrection, CorrectionNotice, StatusIntakeLedger,
)

ledger = StatusIntakeLedger()

# batch-1 and batch-2 are parsed and already verified by the caller
batch_1 = ocsp.OCSPResponse.load(first_der)
batch_2 = ocsp.OCSPResponse.load(second_der)
ledger.ingest_batch('batch-1', batch_1)
ledger.ingest_batch('batch-2', batch_2)

declaration = next(iter(ledger.declarations.values()))
ledger.add_order('order-a', declaration.declaration_id, responsibility='intake')
ledger.add_order('order-b', declaration.declaration_id, responsibility='intake')
ledger.add_material('receipt-a-1', order_id='order-a')
ledger.add_material('receipt-b-1', order_id='order-b')

correction = ApprovedCorrection(
    correction_id='correction-17',
    declaration_id=declaration.declaration_id,
    order_ids=['order-a', 'order-b'],
    version=2,
    responsibility='central-review',
    approval_ref='regulator-approval-42',
)
result = ledger.submit(CorrectionNotice('notice-17', correction))
```

The resulting bindings are available from `result.bindings`,
`ledger.bindings_for_declaration(...)`, `ledger.bindings_for_order(...)` and
`ledger.current_binding(...)`.

## Semantics

 - **Two batches, one declaration set.**  Declarations are de-duplicated by
   their stable identity and `this_update` revision.  Replaying a batch is a
   no-op; a newer `this_update` updates the declaration in place.
 - **Incremental by design.**  Applying a correction touches only the named
   declaration/order bindings.  Other orders, their versions and their signed
   material are left untouched; there is no whole-day recomputation.
 - **Duplicate notifications.**  The same `notice_id` is idempotent.  A new
   notice carrying the same correction revision is reported as
   `duplicate_correction`.  Re-issuing the local `correction_id` while keeping
   the same externally approved content is also treated as a duplicate.  None
   of these outcomes claims a second signed material.
 - **Out of order arrival.**  `version` is authoritative; arrival time is not.
   A revision older than the current binding is reported as `stale` and never
   regresses the order.  A correction that arrives before its declaration,
   order or signed material remains `pending` and is replayed automatically
   when the prerequisite is registered.
 - **One declaration, several orders.**  Corrections may target one order or
   several.  A multi-order correction claims material per order and is
   all-or-nothing: if any order lacks available material the notice stays
   pending and no order is changed.
 - **Version collisions.**  Reusing `(correction_id, declaration_id, version)`
   with different content is a `conflict`; it is not silently applied.  The
   same applies to a reused `notice_id` carrying different content.

## Outcomes

Declaration ingestion returns `added`, `updated`, `duplicate`, `stale` or
`conflict`.  Correction submission returns `applied`, `duplicate_notice`,
`duplicate_correction`, `pending`, `stale`, `conflict` or `rejected`.
`SubmissionResult.consumed_materials` contains only material newly claimed by
that call, so duplicates always report an empty list.
