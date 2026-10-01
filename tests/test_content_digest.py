from __future__ import annotations

import base64
import hashlib

import pytest

from aiohttp.content_digest import (
    ContentDigestError,
    ContentDigestVerification,
    ContentDigestVerifier,
    parse_content_digest,
)


def digest(data: bytes, algorithm: str) -> str:
    return base64.b64encode(hashlib.new(algorithm, data).digest()).decode()


def test_parse_content_digest_multiple_algorithms() -> None:
    result = parse_content_digest(
        [
            f"sha-256=:{digest(b'x', 'sha256')}:, "
            f"sha-512=:{digest(b'x', 'sha-512')}:"
        ]
    )
    assert set(result) == {"sha-256", "sha-512"}


@pytest.mark.parametrize(
    "field",
    [
        "sha-256=x",
        "sha-256=::",
        "sha-256=:x:",
        "sha-256=:AA==:;x",
        "sha-256==:AA==:",
    ],
)
def test_parse_content_digest_rejects_malformed(field: str) -> None:
    with pytest.raises(ContentDigestError):
        parse_content_digest([field])


def test_verifier_supports_unpadded_base64url() -> None:
    raw = hashlib.sha256(b"x").digest()
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    verifier = ContentDigestVerifier(
        [f"sha-256=:{encoded}:"],
        ContentDigestVerification.IF_PRESENT,
    )
    verifier.update(b"x")
    verifier.finalize_output()
    assert verifier.verified


def test_optional_mode_without_digest_is_inactive() -> None:
    verifier = ContentDigestVerifier(
        [],
        ContentDigestVerification.IF_PRESENT,
    )
    verifier.finalize_output()
    assert not verifier.verified
    assert verifier.error is None


def test_required_mode_requires_supported_digest() -> None:
    verifier = ContentDigestVerifier(
        [],
        ContentDigestVerification.REQUIRED,
    )
    with pytest.raises(ContentDigestError):
        verifier.check()


def test_unsupported_algorithm_does_not_verify_optional() -> None:
    sha1 = base64.b64encode(hashlib.sha1(b"x").digest()).decode()
    verifier = ContentDigestVerifier(
        [f"sha-1=:{sha1}:"],
        ContentDigestVerification.IF_PRESENT,
    )
    verifier.update(b"x")
    verifier.finalize_output()
    assert not verifier.verified
    assert verifier.error is None


def test_wrong_digest_length_for_algorithm_is_malformed() -> None:
    verifier = ContentDigestVerifier(
        ["sha-256=:AA==:"],
        ContentDigestVerification.IF_PRESENT,
    )
    with pytest.raises(ContentDigestError):
        verifier.check()


def test_verifier_mismatch() -> None:
    verifier = ContentDigestVerifier(
        [f"sha-256=:{digest(b'other', 'sha256')}:"],
        ContentDigestVerification.IF_PRESENT,
    )
    verifier.update(b"x")
    verifier.finalize_output()
    with pytest.raises(ContentDigestError):
        verifier.check()
