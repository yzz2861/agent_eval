"""
Use :class:`signxml.XMLSigner` and :class:`signxml.XMLVerifier` to sign and verify XML Signatures, respectively.
See `SignXML documentation <#synopsis>`_ for examples.
"""

from .algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureConstructionMethod, SignatureMethod
from .exceptions import (
    AlgorithmPolicyViolation,
    InvalidCertificate,
    InvalidDigest,
    InvalidInput,
    InvalidSignature,
    UnsupportedAlgorithm,
)
from .external import ExternalSigningKey, SigningRequest
from .policy import (
    ARCHIVE_POLICY,
    ARCHIVE_ALGORITHM_POLICY,
    ARCHIVE_PROFILE,
    ARCHIVAL_POLICY,
    ARCHIVAL_PROFILE,
    DELIVERY_POLICY,
    DELIVERY_ALGORITHM_POLICY,
    DELIVERY_PROFILE,
    Admission,
    AdmissionStatus,
    AlgorithmAdmission,
    AlgorithmPolicy,
    SignatureAlgorithmPolicy,
    SignaturePolicy,
    SignatureProfile,
    SignaturePurpose,
    admission_matrix,
)
from .processor import XMLSignatureProcessor
from .signer import SignatureReference, XMLSigner
from .util import namespaces
from .verifier import SignatureConfiguration, VerifyResult, XMLVerifier

methods = SignatureConstructionMethod
