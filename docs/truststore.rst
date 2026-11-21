Purpose-scoped truststore planning
==================================

.. py:module:: jks.truststore

An intake keystore can serve several delivery purposes at once.  A minimal
Java truststore for one workstation must contain only the certificates that
were approved for that workstation, not every certificate that happens to be
approved somewhere in the intake library.

The jks.truststore module plans those truststores without modifying the intake
store.  Approval is always scoped to a (purpose, alias) pair.  Certificate
fingerprints are used only to recognise repeated certificate material and to
keep each truststore minimal.

Concepts
--------

* Purpose -- a normalised purpose name.  The two delivery purposes are
  Purpose.ISSUANCE_REVIEW and Purpose.HISTORICAL_VERIFICATION.
* EntryDeclaration -- an approval or denial for one alias and one or more
  purposes.  A declaration may also pin the expected certificate fingerprint,
  destination alias and source name.
* ManifestEntry -- one selected certificate, including its source alias,
  certificate fingerprint, certificate bytes and acceptance reason.
* TruststoreManifest -- the re-verifiable delivery manifest for one purpose.
  It contains a canonical SHA-256 digest over its body.
* ReviewResult -- the per-purpose acceptance and rejection reasons, including
  an explicit explanation when two purposes receive the same certificate.
* DeliveryPlan -- all manifests plus the review result.

Example
-------

.. code-block:: python

    from jks import KeyStore
    from jks.truststore import plan_truststores

    intake = KeyStore.load('intake.jks', 'changeit')
    plan = plan_truststores(intake, [
        {'alias': 'issuance-test', 'purpose': 'issuance_review'},
        {'alias': 'history-test', 'purpose': 'historical_verification'},
    ])

    plan.manifests['issuance_review'].source_aliases
    plan.manifests['historical_verification'].source_aliases
    plan.review.reasons_for('issuance_review')

If issuance-test and history-test hold the same certificate, both manifests
contain it once.  Each manifest points at its own approved source alias, and
each acceptance reason states that the other purpose approval was not
inherited.

Non-leaking approvals
---------------------

Aliases are local names, and one alias may hold the same certificate as another.
The planner therefore never turns an approval for one alias into permission for
a different alias.  If history-test is not approved for
historical_verification, the historical manifest stays empty even when
issuance-test contains the same certificate and is approved for issuance
review.

Within a single purpose, repeated certificate material is selected once.  The
canonical source alias prefers a trusted certificate entry over a certificate
taken from a key chain, then a declaration with an explicit destination alias,
then the lexicographically first alias.  Other approved aliases are recorded in
source_aliases and in review.deduplicated with their own reasons.

Re-verification
---------------

Every manifest records the source alias, source name, certificate fingerprint,
certificate bytes and a canonical digest.  A manifest can be checked again
against the intake store::

    manifest = plan.manifests['issuance_review']
    manifest.verify(intake).ok
    manifest.matches(intake)

Verification recomputes the digest, checks that the embedded certificate hashes
to the declared fingerprint, resolves the source alias again, compares the
current source certificate, and optionally checks that the alias is still
approved for that purpose.

Conflicts
---------

The plan reports errors rather than silently guessing.  Conflict codes include
missing_source_alias, missing_certificate, fingerprint_mismatch,
duplicate_declaration, conflicting_declaration, conflicting_approval,
destination_alias_conflict and source_mismatch.  An explicit denial is not an
error; it simply excludes the alias from that purpose.

The planner is read-only.  It does not save the intake store, change aliases or
decrypt key entries.  Use TruststoreManifest.to_keystore (or plan.truststores)
to obtain a new in-memory minimal JKS truststore.

Command line
------------

tools/plan_truststores.py reads a JSON document containing the intake path,
password, purposes and entry declarations, prints the delivery plan and exits
non-zero when the plan has conflicts or a manifest fails verification.
