import re
import typing

try:
    import bcrypt
except ImportError as e:  # pragma: no cover
    from ..exceptions import HasherNotAvailable

    raise HasherNotAvailable("bcrypt") from e

from .. import exceptions
from .base import (
    DEFAULT_MAX_HASH_FIELDS,
    DEFAULT_MIN_HASH_BYTES,
    HasherProtocol,
    ensure_bytes,
    ensure_str,
    has_prefix,
    validate_limit,
    validate_password,
    validate_str_or_bytes,
)
from .base import (
    validate_encoded_hash as validate_encoded_hash_input,
)

_IDENTIFY_REGEX = (
    r"^\$(?P<prefix>2[abxy])\$(?P<rounds>\d{2})"
    r"\$(?P<salt>[A-Za-z0-9+/.]{22})(?P<hash>[A-Za-z0-9+/.]{31})$"
)
_ENCODED_HASH_LENGTH = 60
_SUPPORTED_PREFIXES = ("$2a$", "$2b$", "$2x$", "$2y$")


def _match_regex_hash(hash: str | bytes) -> re.Match[str] | None:
    return re.fullmatch(_IDENTIFY_REGEX, ensure_str(hash))


class BcryptHasher(HasherProtocol):
    def __init__(
        self,
        rounds: int = 12,
        prefix: typing.Literal["2a", "2b"] = "2b",
        *,
        max_password_bytes: int = 72,
        min_password_bytes: int = 0,
        max_hash_bytes: int | None = _ENCODED_HASH_LENGTH,
        min_hash_bytes: int = _ENCODED_HASH_LENGTH,
        max_hash_fields: int = DEFAULT_MAX_HASH_FIELDS,
    ) -> None:
        """
        Args:
            rounds: The number of rounds to use for hashing.
            prefix: The prefix to use for hashing.
            max_password_bytes: Maximum password length in UTF-8 bytes. Bcrypt
                only considers the first 72 bytes, so longer passwords are rejected.
            min_password_bytes: Minimum password length in UTF-8 bytes.
            max_hash_bytes: Maximum encoded hash length.
            min_hash_bytes: Minimum encoded hash length.
            max_hash_fields: Maximum number of fields in an encoded hash.
        """
        validate_limit(max_password_bytes, "max_password_bytes")
        validate_limit(min_password_bytes, "min_password_bytes")
        validate_limit(max_hash_bytes, "max_hash_bytes")
        validate_limit(min_hash_bytes, "min_hash_bytes")
        validate_limit(max_hash_fields, "max_hash_fields")
        self.rounds = rounds
        self.prefix = prefix.encode("utf-8")
        self.max_password_bytes = max_password_bytes
        self.min_password_bytes = min_password_bytes
        self.max_hash_bytes = max_hash_bytes
        self.min_hash_bytes = min_hash_bytes
        self.max_hash_fields = max_hash_fields

    @classmethod
    def identify(cls, hash: str | bytes) -> bool:
        validate_str_or_bytes(hash, "hash")
        if not has_prefix(hash, _SUPPORTED_PREFIXES):
            return False
        if len(hash) != _ENCODED_HASH_LENGTH:
            return False
        try:
            hash_str = validate_encoded_hash_input(
                hash,
                max_bytes=_ENCODED_HASH_LENGTH,
                min_bytes=_ENCODED_HASH_LENGTH,
                max_fields=4,
            )
        except exceptions.HashFormatError:
            return False
        return _match_regex_hash(hash_str) is not None

    @classmethod
    def has_supported_prefix(cls, hash: str | bytes) -> bool:
        return has_prefix(hash, _SUPPORTED_PREFIXES)

    def validate_encoded_hash(self, hash: str | bytes) -> str:
        """
        Validate a Bcrypt encoded hash and return its ASCII representation.

        Raises:
            UnsupportedHashError: If the prefix or structure is unsupported.
            HashTooShortError: If the encoded hash is shorter than 60 bytes.
            HashTooLongError: If the encoded hash exceeds 60 bytes.
        """
        validate_str_or_bytes(hash, "hash")
        if len(hash) < DEFAULT_MIN_HASH_BYTES:
            raise exceptions.HashTooShortError(DEFAULT_MIN_HASH_BYTES)
        if not self.has_supported_prefix(hash):
            raise exceptions.UnsupportedHashError(hash)

        max_bytes = (
            _ENCODED_HASH_LENGTH
            if self.max_hash_bytes is None
            else min(_ENCODED_HASH_LENGTH, self.max_hash_bytes)
        )
        min_bytes = (
            _ENCODED_HASH_LENGTH
            if self.min_hash_bytes is None
            else max(_ENCODED_HASH_LENGTH, self.min_hash_bytes)
        )
        max_fields = min(4, self.max_hash_fields)
        hash_str = validate_encoded_hash_input(
            hash,
            max_bytes=max_bytes,
            min_bytes=min_bytes,
            max_fields=max_fields,
        )
        if _match_regex_hash(hash_str) is None:
            raise exceptions.UnsupportedHashError(hash)
        return hash_str

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        validate_password(
            password,
            max_bytes=self.max_password_bytes,
            min_bytes=self.min_password_bytes,
        )
        if salt is None:
            salt = bcrypt.gensalt(self.rounds, self.prefix)
        return ensure_str(bcrypt.hashpw(ensure_bytes(password), salt))

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        validate_password(
            password,
            max_bytes=self.max_password_bytes,
            min_bytes=self.min_password_bytes,
        )
        hash_str = self.validate_encoded_hash(hash)
        return bcrypt.checkpw(ensure_bytes(password), ensure_bytes(hash_str))

    def check_needs_rehash(self, hash: str | bytes) -> bool:
        validate_str_or_bytes(hash, "hash")
        try:
            hash_str = self.validate_encoded_hash(hash)
        except exceptions.HashFormatError:
            return True

        _hash_match = _match_regex_hash(hash_str)
        assert _hash_match is not None

        return int(_hash_match.group("rounds")) != self.rounds or _hash_match.group(
            "prefix"
        ) != self.prefix.decode("utf-8")
