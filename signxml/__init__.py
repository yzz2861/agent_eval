"""
Use :class:`signxml.XMLSigner` and :class:`signxml.XMLVerifier` to sign and verify XML Signatures, respectively.
See `SignXML documentation <#synopsis>`_ for examples.
"""

from .algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureConstructionMethod, SignatureMethod
from .exceptions import InvalidCertificate, InvalidDigest, InvalidInput, InvalidSignature
from .external import ExternalSigningKey, SigningRequest
from .processor import XMLSignatureProcessor
from .receipts import (
    AttachmentDeclaration,
    AttachmentKey,
    CombinedVerification,
    CombinedVerificationResult,
    OfflineCombinedVerification,
    ReceiptGroup,
    VerificationSource,
    VerificationResultSet,
    VerificationSet,
    VerifiedAttachment,
    archive_name_from_uri,
    combine,
    combine_results,
    combine_verification_results,
    combine_verified_results,
    combine_verify_results,
    combine_verifications,
    offline_combine,
    offline_combined_verification,
    verify_offline,
    source_id,
    verified_attachments,
)
from .signer import SignatureReference, XMLSigner
from .util import namespaces
from .verifier import SignatureConfiguration, VerifyResult, XMLVerifier

methods = SignatureConstructionMethod
