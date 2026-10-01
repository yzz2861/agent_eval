import base64
import binascii
import hashlib
from collections.abc import Callable
from enum import Enum
from typing import TYPE_CHECKING, Final

from .client_exceptions import ClientPayloadError, ContentDigestError
from .hdrs import CONTENT_DIGEST

if TYPE_CHECKING:
    from .client_reqrep import HeadersMixin


__all__ = (
    "ContentDigestError",
    "ContentDigestVerification",
    "ContentDigestVerifier",
    "create_content_digest_verifier",
)


class ContentDigestVerification(Enum):
    IF_PRESENT = "if-present"
    REQUIRED = "required"


_DIGEST_ALGORITHMS: Final = {
    "sha-256": (hashlib.sha256, 32),
    "sha-512": (hashlib.sha512, 64),
}


def _split_content_digest(value: str) -> list[str]:
    members: list[str] = []
    start = 0
    quote: str | None = None

    for index, char in enumerate(value):
        if quote is not None:
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == ",":
            members.append(value[start:index].strip())
            start = index + 1

    tail = value[start:].strip()
    if quote is not None:
        raise ContentDigestError("Malformed Content-Digest header")
    if tail:
        members.append(tail)
    if not members:
        raise ContentDigestError("Malformed Content-Digest header")
    return members


def _parse_member(member: str) -> tuple[str, bytes] | None:
    algorithm, separator, rest = member.partition("=")
    algorithm = algorithm.strip().lower()
    if not separator or algorithm not in _DIGEST_ALGORITHMS:
        return None

    digest_value: bytes | None = None
    for index, parameter in enumerate(_split_parameters(rest)):
        if index == 0:
            if (
                len(parameter) < 2
                or parameter[0] != ":"
                or parameter[-1] != ":"
            ):
                raise ContentDigestError("Malformed Content-Digest header")
            encoded = parameter[1:-1]
            try:
                digest_value = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ContentDigestError("Malformed Content-Digest header") from exc
            continue

        key, equals, value = parameter.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if not equals or not key or not value:
            raise ContentDigestError("Malformed Content-Digest header")

    hash_factory, digest_size = _DIGEST_ALGORITHMS[algorithm]
    if digest_value is None or len(digest_value) != digest_size:
        raise ContentDigestError("Malformed Content-Digest header")
    return algorithm, digest_value


def _split_parameters(value: str) -> list[str]:
    parameters: list[str] = []
    start = 0
    quote: str | None = None

    for index, char in enumerate(value):
        if quote is not None:
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == ";":
            parameters.append(value[start:index].strip())
            start = index + 1

    parameters.append(value[start:].strip())
    if quote is not None:
        raise ContentDigestError("Malformed Content-Digest header")
    return parameters


class ContentDigestVerifier:
    __slots__ = (
        "_failure",
        "_force_close",
        "_hashes",
        "_coded_verified",
        "_on_output_verified",
        "_required",
        "active",
        "verified",
    )

    def __init__(
        self,
        headers: "HeadersMixin",
        policy: ContentDigestVerification,
        force_close: Callable[[], None],
    ) -> None:
        self._force_close = force_close
        self._required = policy is ContentDigestVerification.REQUIRED
        self._failure: ContentDigestError | None = None
        self._coded_verified = False
        self._on_output_verified: Callable[[], None] | None = None
        self.verified = False
        self.active = True
        self._hashes: dict[str, tuple[object, bytes]] = {}

        try:
            try:
                values = getattr(headers, "_md", headers).getall(CONTENT_DIGEST)
            except KeyError:
                values = ()
            for value in values:
                for member in _split_content_digest(value):
                    parsed = _parse_member(member)
                    if parsed is None:
                        continue
                    algorithm, expected = parsed
                    if algorithm in self._hashes:
                        self._fail("Duplicate Content-Digest algorithm")
                        return
                    hash_factory, _ = _DIGEST_ALGORITHMS[algorithm]
                    self._hashes[algorithm] = (hash_factory(), expected)
        except ContentDigestError as exc:
            self._fail(str(exc))
            return

        if self._failure is None and not self._hashes and self._required:
            self._fail("Missing supported Content-Digest digest")
        elif self._failure is None and not self._hashes:
            self.active = False

    def _fail(self, message: str) -> None:
        if self._failure is None:
            self._failure = ContentDigestError(message)
            self.verified = False
            self.active = False
            self._force_close()

    def update(self, chunk: bytes) -> None:
        if self._failure is not None:
            raise self._failure
        for digest_hash, _ in self._hashes.values():
            digest_hash.update(chunk)

    def check_coded_eof(self) -> bool:
        if self._failure is not None:
            return False
        for algorithm, (digest_hash, expected) in tuple(self._hashes.items()):
            if digest_hash.digest() != expected:
                self._fail(f"Content-Digest {algorithm} mismatch")
                return False
        if self.active:
            self._coded_verified = True
        return True

    def mark_output_verified(self) -> None:
        if self._failure is not None:
            raise self._failure
        callback = self._on_output_verified
        if callback is not None:
            self._on_output_verified = None
            callback()

    @property
    def requires_output_verification(self) -> bool:
        return self.active or self._failure is not None


def create_content_digest_verifier(
    headers: "HeadersMixin",
    policy: ContentDigestVerification | None,
    force_close: Callable[[], None],
) -> ContentDigestVerifier | None:
    if policy is None or not isinstance(policy, ContentDigestVerification):
        return None
    return ContentDigestVerifier(headers, policy, force_close)
