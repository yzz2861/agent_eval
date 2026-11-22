DSSE migration assessment
=========================

The :mod:`securesystemslib.dsse` module provides a migration auditor next to
the DSSE :class:`~securesystemslib.dsse.Envelope` API. It decides whether
historical review conclusions can be carried over to a new verification
backend without re-running every review.

Inputs
------

:class:`~securesystemslib.dsse.ReviewRecord`
    The original DSSE envelope, the recorded conclusion, the key ids accepted
    as evidence, the signing algorithm parameters, an optional canonical
    envelope digest and an optional prior verification failure classification.

:class:`~securesystemslib.dsse.EnvironmentCapabilities`
    An explicit statement of the algorithms the new backend supports (including
    scheme parameters), the public key material it holds, which historical
    review sources are trusted and whether approved legacy evidence may be
    reused. A signature threshold can be declared as well.

Both inputs can be passed as typed objects or as JSON-compatible mappings.

Outcomes
--------

:attr:`~securesystemslib.dsse.MigrationDecision.REVERIFIED`
    The original envelope was cryptographically verified with the new key
    material and satisfies the declared threshold.

:attr:`~securesystemslib.dsse.MigrationDecision.REUSE_APPROVED_EVIDENCE`
    Re-verification is unavailable (for example, a missing key or unsupported
    algorithm), but the record contains approved evidence from a trusted
    source and legacy reuse is explicitly enabled.

:attr:`~securesystemslib.dsse.MigrationDecision.RECHECK`
    The conclusion has insufficient trusted evidence and must be reviewed
    again. :class:`~securesystemslib.dsse.VerificationFailure` classifies the
    cause, distinguishing environment limitations from tampering or invalid
    signatures. A positive cryptographic failure is never rescued by legacy
    evidence reuse.

Example
-------

.. code-block:: python

    from securesystemslib.dsse import assess_migration

    report = assess_migration(old_records, new_capabilities)

    for assessment in report.reusable:
        print(assessment.record_id, assessment.decision)

    for assessment in report.recheck:
        print(assessment.record_id, assessment.failure)
