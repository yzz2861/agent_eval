"""
Offline legacy-policy review workflow for XML signatures.

This package implements an offline review entry point for archival documents that were signed with XML
signature algorithms that have since been deprecated (for example SHA-1 based methods). It separates three
concerns that are often conflated:

* Cryptographic integrity of the signature, established with SignXML using a *test public key* supplied by
  the caller.
* The *historical* admission decision, evaluated against an :class:`AdmissionPolicyTable` at the point in
  time attested by a trusted :class:`TrustedTimeEvidence` token rather than any self-reported date embedded
  in the document.
* The *current* admission decision, evaluated against the policy in force at review time, which only
  determines whether the document must be re-signed.

The two decisions are reported independently on the :class:`ReviewReport`: a document that was legitimately
signed under an old, now-deprecated policy remains historically accepted even though it fails verification
under the current strict configuration.
"""

from .legacy_review import (
    AdmissionPolicy,
    AdmissionPolicyTable,
    ChecklistItem,
    LegacyDocumentSigner,
    OfflineReviewer,
    ReviewError,
    ReviewOutcome,
    ReviewReport,
    TrustedTimeEvidence,
    UpgradeBundle,
    UpgradeReceipt,
    build_default_policy_table,
    document_fingerprint,
    issue_trusted_time_evidence,
    issue_upgrade,
    load_trusted_time_evidence,
    review_reissued_document,
    verify_upgrade_receipt,
)
