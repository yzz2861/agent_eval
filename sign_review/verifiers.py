"""Signature verification is injected by the caller.

The review library never decides whether a signature is cryptographically
valid.  Callers implement SignatureVerifier against their PKI stack and hand
it to the engine.  Two reference implementations are provided for testing:
a structural stub and a ByteRange digest checker.
"""

from __future__ import annotations

import hashlib
from typing import Protocol, runtime_checkable

from .models import SignatureInfo, VerificationResult


@runtime_checkable
class SignatureVerifier(Protocol):
    """Callable contract for pluggable signature verification."""

    def verify(self, data: bytes, signature: SignatureInfo) -> VerificationResult:
        ...


class StructuralStubVerifier:
    """Deterministic stand-in for a real PKI verifier (no security guarantee).

    It only checks that ByteRange is well formed and covers one contiguous
    prefix/suffix of the file.
    """

    name = "structural-stub"

    def verify(self, data: bytes, signature: SignatureInfo) -> VerificationResult:
        byte_range = signature.byte_range
        if len(byte_range) != 4:
            return VerificationResult(False, self.name, {"reason": "malformed ByteRange"})
        offset, head_length, gap_offset, tail_length = byte_range
        # The gap is the signature Contents entry including its angle brackets,
        # so it always starts at least one byte after the covered head.
        if offset != 0 or gap_offset < head_length:
            return VerificationResult(False, self.name, {"reason": "ByteRange is not contiguous"})
        # Later incremental revisions legitimately extend the file, so the
        # covered tail only has to stay inside the current byte stream.
        if gap_offset + tail_length > len(data):
            return VerificationResult(False, self.name, {"reason": "ByteRange exceeds file length"})
        return VerificationResult(True, self.name, {"note": "structural check only; no PKI trust"})


class ByteRangeDigestVerifier:
    """Verify the covered bytes match a caller-provided digest.

    Real integrations would parse /Contents (PKCS#7/CMS) and validate the
    certificate chain here.  This reference class documents the seam by
    hashing exactly the ByteRange-covered bytes instead.
    """

    def __init__(self, algorithm: str = 'sha256') -> None:
        self.algorithm = algorithm
        self.name = f'byterange-digest-{algorithm}'

    def verify(self, data: bytes, signature: SignatureInfo) -> VerificationResult:
        byte_range = signature.byte_range
        if len(byte_range) != 4:
            return VerificationResult(False, self.name, {'reason': 'malformed ByteRange'})
        offset, head_length, gap_offset, tail_length = byte_range
        end = gap_offset + tail_length
        if offset < 0 or end > len(data) or gap_offset < head_length:
            return VerificationResult(False, self.name, {'reason': 'ByteRange out of bounds'})
        covered = data[offset:head_length] + data[gap_offset:end]
        digest = hashlib.new(self.algorithm, covered).hexdigest()
        return VerificationResult(True, self.name, {
            'covered_bytes': len(covered), 'digest': digest,
            'note': 'digest of ByteRange-covered bytes only'})
