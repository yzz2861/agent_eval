from contextlib import nullcontext

import pytest

from contextlib import AbstractContextManager

from jwt.utils import (
    base64url_decode_strict,
    base64url_encode,
    force_bytes,
    from_base64url_uint,
    is_ssh_key,
    to_base64url_uint,
)


@pytest.mark.parametrize(
    "inputval,expected",
    [
        (0, nullcontext(b"AA")),
        (1, nullcontext(b"AQ")),
        (255, nullcontext(b"_w")),
        (65537, nullcontext(b"AQAB")),
        (123456789, nullcontext(b"B1vNFQ")),
        (-1, pytest.raises(ValueError)),
    ],
)
def test_to_base64url_uint(
    inputval: int, expected: AbstractContextManager[bytes]
) -> None:
    with expected as e:
        actual = to_base64url_uint(inputval)
        assert actual == e


@pytest.mark.parametrize(
    "inputval,expected",
    [
        (b"AA", 0),
        (b"AQ", 1),
        (b"_w", 255),
        (b"AQAB", 65537),
        (b"B1vNFQ", 123456789),
    ],
)
def test_from_base64url_uint(inputval: bytes, expected: int) -> None:
    actual = from_base64url_uint(inputval)
    assert actual == expected


def test_force_bytes_raises_error_on_invalid_object() -> None:
    with pytest.raises(TypeError):
        force_bytes({})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "encoded,decoded",
    [
        (b"", b""),
        (b"Zg", b"f"),
        (b"Zm8", b"fo"),
        (b"Zm9v", b"foo"),
        (b"_w", bytes([255])),
        (b"AQAB", bytes([1, 0, 1])),
    ],
)
def test_base64url_decode_strict_accepts_canonical_unpadded(
    encoded: bytes, decoded: bytes
) -> None:
    assert base64url_decode_strict(encoded) == decoded
    # round-trips through the encoder without gaining padding
    assert base64url_encode(decoded) == encoded


@pytest.mark.parametrize(
    "encoded",
    [
        b"Zg==",  # padding must not appear in base64url
        b"Zm8=",
        b"Zg=",  # malformed padding length
        b"Zg/",  # standard base64 alias for the URL-safe '_'
        b"Z+g",  # standard base64 alias for the URL-safe '-'
        b"a",  # length % 4 == 1 can never be valid
        b"Zh",  # non-canonical: trailing bits are not zero
        b"Zh==",
        b"Z?g",  # character outside the alphabet
        b"Z g",  # whitespace is not part of the alphabet
    ],
)
def test_base64url_decode_strict_rejects_non_canonical(encoded: bytes) -> None:
    with pytest.raises(ValueError):
        base64url_decode_strict(encoded)


def test_base64url_decode_strict_accepts_str_and_force_bytes() -> None:
    assert base64url_decode_strict("Zm9v") == b"foo"


@pytest.mark.parametrize(
    "key_format",
    (
        b"ssh-ed25519",
        b"ssh-rsa",
        b"ssh-dss",
        b"ecdsa-sha2-nistp256",
        b"ecdsa-sha2-nistp384",
        b"ecdsa-sha2-nistp521",
    ),
)
def test_is_ssh_key(key_format: bytes) -> None:
    assert is_ssh_key(key_format + b" any") is True
    assert is_ssh_key(b"not a ssh key") is False
