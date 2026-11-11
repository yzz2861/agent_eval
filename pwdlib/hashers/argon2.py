import re

try:
    import argon2.exceptions
    from argon2 import PasswordHasher
except ImportError as e:  # pragma: no cover
    from ..exceptions import HasherNotAvailable

    raise HasherNotAvailable("argon2") from e

from .. import exceptions
from .base import (
    DEFAULT_MAX_HASH_BYTES,
    DEFAULT_MAX_HASH_FIELDS,
    DEFAULT_MAX_PASSWORD_BYTES,
    DEFAULT_MIN_HASH_BYTES,
    HasherProtocol,
    has_prefix,
    validate_limit,
    validate_password,
    validate_str_or_bytes,
)
from .base import (
    validate_encoded_hash as validate_encoded_hash_input,
)

# Pattern for identifying and validating an Argon2 encoded hash, covering all currently
# supported type variants (i.e., `id`, `i`, `d`). Pattern uses deterministic matching,
# explicit anchors, and a non-greedy terminal quantifier to ensure linear run time
# relative to input hash length and resilience against catastrophic backtracking attacks.
ARGON2_ENCODED_HASH_REGEX: re.Pattern = re.compile(
    r"^\$(?P<variant>argon2(id|i|d))\$(?:v=(?P<version>\d+)\$)?"
    r"m=(?P<memory_cost>\d+),t=(?P<time_cost>\d+),p=(?P<parallelism>\d+)"
    r"\$(?P<salt>[A-Za-z0-9+/]+={0,2})\$(?P<digest>[A-Za-z0-9+/]+={0,2})$"
)
_SUPPORTED_PREFIXES = ("$argon2id$", "$argon2i$", "$argon2d$")


class Argon2Hasher(HasherProtocol):
    def __init__(
        self,
        time_cost: int = argon2.DEFAULT_TIME_COST,
        memory_cost: int = argon2.DEFAULT_MEMORY_COST,
        parallelism: int = argon2.DEFAULT_PARALLELISM,
        hash_len: int = argon2.DEFAULT_HASH_LENGTH,
        salt_len: int = argon2.DEFAULT_RANDOM_SALT_LENGTH,
        type: argon2.Type = argon2.Type.ID,
        *,
        max_password_bytes: int = DEFAULT_MAX_PASSWORD_BYTES,
        min_password_bytes: int = 0,
        max_hash_bytes: int | None = DEFAULT_MAX_HASH_BYTES,
        min_hash_bytes: int = DEFAULT_MIN_HASH_BYTES,
        max_hash_fields: int = DEFAULT_MAX_HASH_FIELDS,
    ) -> None:
        """

        Args:
            time_cost: Defines the amount of computation realized and
                therefore the execution time, given in number of iterations.
            memory_cost: Defines the memory usage, given in kibibytes.
            parallelism: Defines the number of parallel threads (*changes*
                the resulting hash value).
            hash_len: Length of the hash in bytes.
            salt_len: Length of random salt to be generated for each
                password.
            type: Argon2 type to use.  Only change for interoperability
                with legacy systems.
            max_password_bytes: Maximum password length in UTF-8 bytes.
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
        self._hasher = PasswordHasher(
            time_cost, memory_cost, parallelism, hash_len, salt_len, "utf-8", type
        )
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
        if len(hash) < DEFAULT_MIN_HASH_BYTES:
            return False
        try:
            hash_str = validate_encoded_hash_input(hash)
        except exceptions.HashFormatError:
            return False
        return ARGON2_ENCODED_HASH_REGEX.fullmatch(hash_str) is not None

    @classmethod
    def has_supported_prefix(cls, hash: str | bytes) -> bool:
        return has_prefix(hash, _SUPPORTED_PREFIXES)

    def validate_encoded_hash(self, hash: str | bytes) -> str:
        """
        Validate an Argon2 encoded hash and return its ASCII representation.

        Raises:
            UnsupportedHashError: If the prefix, charset, or structure is unsupported.
            HashTooShortError: If the encoded hash is missing required fields.
            HashTooLongError: If the encoded hash exceeds the configured maximum.
        """
        validate_str_or_bytes(hash, "hash")
        if len(hash) < DEFAULT_MIN_HASH_BYTES:
            raise exceptions.HashTooShortError(DEFAULT_MIN_HASH_BYTES)
        if not self.has_supported_prefix(hash):
            raise exceptions.UnsupportedHashError(hash)

        hash_str = validate_encoded_hash_input(
            hash,
            max_bytes=self.max_hash_bytes,
            min_bytes=self.min_hash_bytes,
            max_fields=self.max_hash_fields,
        )

        fields = hash_str.split("$")
        has_version = len(fields) > 2 and fields[2].startswith("v=")
        expected_fields = 6 if has_version else 5
        if len(fields) < expected_fields:
            raise exceptions.HashTooShortError(self.min_hash_bytes)
        if len(fields) > expected_fields:
            raise exceptions.HashFieldCountError(self.max_hash_fields)
        if not fields[-2] or not fields[-1]:
            raise exceptions.HashTooShortError(self.min_hash_bytes)

        if ARGON2_ENCODED_HASH_REGEX.fullmatch(hash_str) is None:
            raise exceptions.UnsupportedHashError(hash)
        return hash_str

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        validate_password(
            password,
            max_bytes=self.max_password_bytes,
            min_bytes=self.min_password_bytes,
        )
        return self._hasher.hash(password, salt=salt)

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        validate_password(
            password,
            max_bytes=self.max_password_bytes,
            min_bytes=self.min_password_bytes,
        )
        hash_str = self.validate_encoded_hash(hash)
        try:
            return self._hasher.verify(hash_str, password)
        except (
            argon2.exceptions.VerificationError,
            argon2.exceptions.InvalidHashError,
        ):
            return False

    def check_needs_rehash(self, hash: str | bytes) -> bool:
        validate_str_or_bytes(hash, "hash")
        try:
            hash_str = self.validate_encoded_hash(hash)
        except exceptions.HashFormatError:
            return True
        return self._hasher.check_needs_rehash(hash_str)
