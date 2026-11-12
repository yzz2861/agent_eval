"""Signing policy objects.

This module exists so policy configuration can be imported and reviewed
independently of the signer implementation. The objects are defined in
``itsdangerous.signer`` to keep the historical module layout functional.
"""

from .exc import AlgorithmDowngradeError as AlgorithmDowngradeError
from .exc import AlgorithmNotAllowed as AlgorithmNotAllowed
from .exc import AlgorithmNotAllowedError as AlgorithmNotAllowedError
from .exc import BadSignature as BadSignature
from .exc import InsecureKeyDerivationError as InsecureKeyDerivationError
from .exc import InsecurePolicyError as InsecurePolicyError
from .exc import KeyTooShortError as KeyTooShortError
from .exc import MessageTampered as MessageTampered
from .exc import PolicyError as PolicyError
from .exc import PolicyFailure as PolicyFailure
from .exc import PolicyRejected as PolicyRejected
from .exc import PolicyRejection as PolicyRejection
from .exc import PolicyViolation as PolicyViolation
from .exc import PolicyViolationError as PolicyViolationError
from .exc import SignaturePolicyError as SignaturePolicyError
from .exc import SignatureTampered as SignatureTampered
from .exc import SignerPolicyError as SignerPolicyError
from .exc import SigningPolicyError as SigningPolicyError
from .exc import SigningPolicyViolation as SigningPolicyViolation
from .exc import TamperedSignature as TamperedSignature
from .exc import UnderivedKeyError as UnderivedKeyError
from .exc import UnsupportedAlgorithm as UnsupportedAlgorithm
from .exc import UnsupportedAlgorithmError as UnsupportedAlgorithmError
from .exc import UnsupportedDigest as UnsupportedDigest
from .exc import UnsupportedDigestError as UnsupportedDigestError
from .exc import VerificationPolicyError as VerificationPolicyError
from .exc import VerificationPolicyViolation as VerificationPolicyViolation
from .exc import WeakAlgorithmError as WeakAlgorithmError
from .exc import WeakDigestError as WeakDigestError
from .exc import WeakKeyError as WeakKeyError
from .signer import SignatureConfig as SignatureConfig
from .signer import SignaturePolicy as SignaturePolicy
from .signer import SignerConfig as SignerConfig
from .signer import SignerPolicy as SignerPolicy
from .signer import SigningConfig as SigningConfig
from .signer import SigningPolicy as SigningPolicy
from .signer import VerificationConfig as VerificationConfig
from .signer import VerificationPolicy as VerificationPolicy
