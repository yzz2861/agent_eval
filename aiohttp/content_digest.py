from __future__ import annotations

import base64
import binascii
import enum
import hashlib
import hmac
import re
from collections.abc import Iterable, Sequence
from typing import Final

from .client_exceptions import ClientPayloadError


__all__ = (
    "ContentDigestError",
    "ContentDigestVerification",
    "ContentDigestVerificationPolicy",
    "ContentDigestVerifier",
    "parse_content_digest",
)


class ContentDigestError(ClientPayloadError):
    """Content-Digest verification failed or the header was invalid."""


class ContentDigestVerification(str, enum.Enum):
    IF_PRESENT = "if_present"
    REQUIRED = "required"
    OPTIONAL = IF_PRESENT


ContentDigestVerificationPolicy = ContentDigestVerification


_HASHES: Final = {
    "sha-256": hashlib.sha256,
    "sha-512": hashlib.sha512,
}
_TOKEN_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_SF_BINARY_RE = re.compile(r"[A-Za-z0-9+/=_-]+")


def _decode_sf_binary(value: str) -> bytes:
    if not _SF_BINARY_RE.fullmatch(value):
        raise ContentDigestError("Invalid Content-Digest digest")
    if "=" in value.rstrip("="):
        raise ContentDigestError("Invalid Content-Digest digest")
    value = value.rstrip("=")
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            value.encode("ascii").replace(b"-", b"+").replace(b"_", b"/"),
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ContentDigestError("Invalid Content-Digest digest") from exc


def _split_top_level(value: str, separator: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quoted = False
    index = 0
    while index < len(value):
        char = value[index]
        if quoted:
            if char == "\\" and index + 1 < len(value):
                index += 2
                continue
            if char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == separator:
            parts.append(value[start:index])
            start = index + 1
        index += 1
    if quoted:
        raise ContentDigestError("Invalid Content-Digest parameter")
    parts.append(value[start:])
    return parts


def _parse_parameters(raw: str) -> dict[str, str]:
    parameters: dict[str, str] = {}
    for item in _split_top_level(raw, ";"):
        item = item.strip(" \t")
        if not item:
            if raw.strip(" \t"):
                raise ContentDigestError("Invalid Content-Digest parameter")
            continue
        name, separator, value = item.partition("=")
        name = name.lower()
        if not _TOKEN_RE.fullmatch(name):
            raise ContentDigestError("Invalid Content-Digest parameter")
        if not separator:
            value = "?1"
            if item != name:
                raise ContentDigestError("Invalid Content-Digest parameter")
        elif value in {"?0", "?1"}:
            pass
        elif len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            if not re.fullmatch(r'"(?:\\.|[^"\\])*"', value):
                raise ContentDigestError("Invalid Content-Digest parameter")
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        elif value.startswith((':', '"')):
            raise ContentDigestError("Invalid Content-Digest parameter")
        elif value.startswith(":") and value.endswith(":"):
            try:
                _decode_sf_binary(value[1:-1])
            except ContentDigestError as exc:
                raise ContentDigestError("Invalid Content-Digest parameter") from exc
        elif _TOKEN_RE.fullmatch(value) and not value.startswith(":"):
            pass
        else:
            raise ContentDigestError("Invalid Content-Digest parameter")
        if name in parameters:
            raise ContentDigestError("Duplicate Content-Digest parameter")
        parameters[name] = value
    return parameters


def parse_content_digest(headers: Iterable[str]) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    for raw_member in _split_top_level(",".join(headers), ","):
        raw_member = raw_member.strip(" \t")
        if not raw_member:
            continue
        algorithm, separator, body = raw_member.partition("=")
        algorithm = algorithm.lower()
        if not separator or not _TOKEN_RE.fullmatch(algorithm):
            raise ContentDigestError("Invalid Content-Digest header")
        body = body.lstrip(" \t")
        if not body.startswith(":"):
            raise ContentDigestError("Invalid Content-Digest digest")
        value_end = body.find(":", 1)
        if value_end < 0:
            raise ContentDigestError("Invalid Content-Digest digest")
        digest_value = body[: value_end + 1]
        position = value_end + 1
        if position < len(body) and body[position] != ";":
            raise ContentDigestError("Invalid Content-Digest header")
        parameter_text = body[position:]
        if not digest_value.startswith(":") or not digest_value.endswith(":"):
            raise ContentDigestError("Invalid Content-Digest digest")
        digest = _decode_sf_binary(digest_value[1:-1])
        if algorithm in _HASHES and (
            len(digest) != _HASHES[algorithm]().digest_size
        ):
            raise ContentDigestError("Invalid Content-Digest digest length")
        _parse_parameters(parameter_text)
        if algorithm in members:
            raise ContentDigestError("Duplicate Content-Digest algorithm")
        members[algorithm] = digest
    return members


def normalize_content_digest_verification(
    value: ContentDigestVerification | str | None,
) -> ContentDigestVerification | None:
    if value is None or isinstance(value, ContentDigestVerification):
        return value
    if isinstance(value, str):
        try:
            return ContentDigestVerification(value)
        except ValueError:
            pass
    raise TypeError(
        "content_digest_verification must be ContentDigestVerification, str, "
        f"or None, got {value!r}"
    )


class ContentDigestVerifier:
    __slots__ = (
        "_hashes",
        "_expected",
        "_required",
        "_verified",
        "_error",
        "_encoded_finalized",
    )

    def __init__(
        self,
        headers: Sequence[str],
        policy: ContentDigestVerification,
    ) -> None:
        self._hashes = {name: factory() for name, factory in _HASHES.items()}
        self._required = policy is ContentDigestVerification.REQUIRED
        self._verified = False
        self._error: ContentDigestError | None = None
        self._encoded_finalized = False

        try:
            members = parse_content_digest(headers)
        except ContentDigestError as exc:
            self._hashes = {}
            self._expected = {}
            self._error = exc
            return

        self._expected = {
            name: value for name, value in members.items() if name in _HASHES
        }
        self._hashes = {
            name: _HASHES[name]() for name in self._expected
        }
        if self._required and not self._expected:
            self._error = ContentDigestError(
                "Content-Digest must contain a supported digest"
            )

    def update(self, chunk: bytes) -> None:
        if chunk and self._error is None:
            for hash_object in self._hashes.values():
                hash_object.update(chunk)

    def finalize_encoded(self) -> None:
        if self._encoded_finalized:
            return
        self._encoded_finalized = True
        if self._error is not None or not self._expected:
            return
        for name, expected in self._expected.items():
            if not hmac.compare_digest(self._hashes[name].digest(), expected):
                self._error = ContentDigestError(
                    f"{name} Content-Digest mismatch"
                )
                return

    def finalize_output(self) -> None:
        self.finalize_encoded()
        if self._error is None and self._expected:
            self._verified = True

    def check(self) -> None:
        if self._error is not None:
            raise self._error

    @property
    def active(self) -> bool:
        return bool(self._expected) or self._error is not None

    @property
    def connection_safe(self) -> bool:
        return not self.active or (
            self._encoded_finalized and self._error is None
        )

    @property
    def verified(self) -> bool:
        return self._verified

    @property
    def error(self) -> ContentDigestError | None:
        return self._error
