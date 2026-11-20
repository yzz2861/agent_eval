Offline approval receipt reconciliation
=======================================

Emergency releases are often approved and acknowledged out of band.  An
approval form and the signed receipts that consume it may arrive separately,
and a receipt may be retransmitted or supplied manually later.  The
``securesystemslib.receipts`` module reconciles that evidence without network
access and uses the normal ``Key.verify_signature()`` result from
``securesystemslib`` for every approval and receipt.

The module enforces three kinds of scope:

* an approval is tied to the exact artifact name and digest;
* an approval lists the purposes it allows;
* an approval has an inclusive UTC validity window.

Approvals and seats
-------------------

``Approval`` is the signed approval form.  It may allow several purposes for
one artifact, for example ``deploy`` and ``rollback``.

``SeatRequirement`` describes one independent approval seat.  Each seat has a
``signature_type``, such as ``release_manager`` or ``security``, and may list
the purposes that receipts must cover.  The trusted key sets are configured
per signature type, so a receipt cannot claim a security signature with a
release-manager key.

``Receipt`` is a signed acknowledgement from one seat.  It references one
approval, one artifact, one purpose, and the time it was issued.

An approval may cover multiple purposes at the *same* seat, but once it has
been used by that seat it cannot be counted as consent for another independent
seat.  This is a global rule, not a per-seat check.  The verifier therefore
computes a maximum bipartite matching between seats and approvals instead of
walking seats greedily.

Identity and late evidence
--------------------------

Retransmitted evidence keeps its identity:

* approvals are keyed by ``approval_id``;
* receipts are keyed by ``receipt_id``;
* identical retransmissions are merged, including additional signatures over
  the same canonical payload;
* the same identity submitted with a different signed body is a conflict, and
  that identity is invalidated rather than resolved by arrival order.

``add_manual_receipts()`` records late human-supplied evidence.  It does not
relax signature verification or the approval validity window.  A manual
receipt is accepted only when it is otherwise valid at the requested
``as_of`` time, and re-running ``reconcile()`` after adding it recomputes the
global matching.

Python usage
------------

.. code-block:: python

   from datetime import UTC, datetime
   from securesystemslib.receipts import (
       Artifact,
       OfflineReceiptVerifier,
       SeatRequirement,
   )

   artifact = Artifact("payments-api", "sha256:0123...")
   verifier = OfflineReceiptVerifier(
       [
           SeatRequirement("release", "release_manager", {"deploy"}, artifact),
           SeatRequirement("security", "security", {"deploy"}, artifact),
       ],
       approval_keys={approval_key.keyid: approval_key},
       receipt_keys={
           "release_manager": {release_key.keyid: release_key},
           "security": {security_key.keyid: security_key},
       },
   )
   verifier.add_approvals(approvals)
   verifier.add_receipts(receipts)
   result = verifier.reconcile(as_of=datetime.now(UTC))

   if not result.ok:
       print(result.summary())
       print(result.missing_signature_types)

``ReconciliationResult`` exposes:

* ``matches``: the approval and receipt ids selected for each seat;
* ``missing``: one ``MissingSignature`` per unsatisfied seat, with a reason
  such as ``missing_signature``, ``invalid_receipt``,
  ``approval_already_used``, ``artifact_mismatch``, or
  ``purpose_not_allowed``;
* ``missing_signature_types``: the signature categories the reviewer still
  needs;
* ``rejected_approvals``, ``rejected_receipts``, and ``conflicts`` for
  individual evidence diagnostics;
* ``manual_receipt_ids`` for provenance.

Command line usage
------------------

The module also provides an offline JSON entry point::

   python -m securesystemslib.receipts bundle.json
   python -m securesystemslib.receipts bundle.json --as-of 2026-11-20T12:00:00Z
   python -m securesystemslib.receipts bundle.json --json

The bundle contains ``requirements``, ``approvals``, ``receipts``, optional
``manual_receipts``, and ``trusted_keys``.  Public keys use the serialization
returned by ``Key.to_dict()``::

   {
     "as_of": "2026-11-20T12:00:00Z",
     "requirements": [
       {
         "seat": "security",
         "signature_type": "security",
         "purposes": ["deploy"],
         "artifact": {"name": "payments-api", "digest": "sha256:0123..."}
       }
     ],
     "approvals": [
       {
         "schema": "securesystemslib.approval/v1",
         "approval_id": "A1",
         "issuer": "release-board",
         "artifact": {"name": "payments-api", "digest": "sha256:0123..."},
         "purposes": ["deploy"],
         "not_before": "2026-11-20T11:00:00Z",
         "not_after": "2026-11-20T13:00:00Z",
         "signatures": [{"keyid": "...", "sig": "..."}]
       }
     ],
     "receipts": [
       {
         "schema": "securesystemslib.receipt/v1",
         "receipt_id": "security-a1",
         "approval_id": "A1",
         "seat": "security",
         "signature_type": "security",
         "purpose": "deploy",
         "artifact": {"name": "payments-api", "digest": "sha256:0123..."},
         "issued_at": "2026-11-20T11:30:00Z",
         "signatures": [{"keyid": "...", "sig": "..."}]
       }
     ],
     "trusted_keys": {
       "approval": {"...": {"keytype": "ed25519", "scheme": "ed25519",
                            "keyval": {"public": "..."}}},
       "receipt": {
         "security": {"...": {"keytype": "ed25519", "scheme": "ed25519",
                              "keyval": {"public": "..."}}}
       }
     }
   }

The command exits with ``0`` when all seats match, ``1`` when evidence is
missing or invalid, and ``2`` for malformed input.  A failing result names the
missing signature category so the reviewer knows which seat must still sign.

Runnable acceptance example
---------------------------

``examples/receipt_reconciliation.py`` contains two signed cases:

* a passing case where a greedy matcher would fail but the global matcher
  succeeds by moving one seat to another approval;
* a failing case with no receipt for the ``security`` seat, where the summary
  reports ``missing signature type(s): security``.

Run it from the repository root::

   PYTHONPATH=. python examples/receipt_reconciliation.py
