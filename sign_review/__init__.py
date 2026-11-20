"""Post-signature revision review built on top of pypdf.

The package splits a PDF into its incremental revisions, maps each digital
signature ByteRange to the revision it covers, and evaluates every later
revision against an explicit ReviewPolicy.  Cryptographic verification is
injected by the caller via SignatureVerifier; this package never trusts a
signature on its own.
"""

from __future__ import annotations

from .engine import (
    record_to_dict,
    review_pdf,
    review_pdf_bytes,
    review_pdf_file,
)
from .models import (
    ChangeType,
    FieldSnapshot,
    Finding,
    PageSnapshot,
    ReviewDecision,
    ReviewPolicy,
    ReviewRecord,
    SignatureInfo,
    Snapshot,
    VerificationResult,
)
from .revisions import RevisionInfo, RevisionScan, scan_revisions
from .verifiers import ByteRangeDigestVerifier, SignatureVerifier, StructuralStubVerifier

__all__ = [
    "ChangeType", "FieldSnapshot", "Finding", "PageSnapshot", "ReviewDecision",
    "ReviewPolicy", "ReviewRecord", "SignatureInfo", "Snapshot",
    "VerificationResult", "RevisionInfo", "RevisionScan", "scan_revisions",
    "SignatureVerifier", "StructuralStubVerifier", "ByteRangeDigestVerifier",
    "review_pdf", "review_pdf_bytes", "review_pdf_file", "record_to_dict",
]
