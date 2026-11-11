import collections.abc
import typing
from typing import TYPE_CHECKING

from . import exceptions
from .hashers import HasherProtocol
from .hashers.base import (
    DEFAULT_MAX_HASH_BYTES,
    DEFAULT_MAX_HASH_FIELDS,
    DEFAULT_MAX_PASSWORD_BYTES,
    DEFAULT_MIN_HASH_BYTES,
    validate_encoded_hash,
    validate_limit,
    validate_password,
)

if TYPE_CHECKING:
    import sys

    if sys.version_info >= (3, 11):
        from typing import Self
    else:
        from typing_extensions import Self


class PasswordHash:
    """
    Represents a password hashing utility.
    """

    def __init__(
        self,
        hashers: collections.abc.Sequence[HasherProtocol],
        *,
        max_password_bytes: int | None = DEFAULT_MAX_PASSWORD_BYTES,
        min_password_bytes: int = 0,
        max_hash_bytes: int | None = DEFAULT_MAX_HASH_BYTES,
        min_hash_bytes: int = DEFAULT_MIN_HASH_BYTES,
        max_hash_fields: int = DEFAULT_MAX_HASH_FIELDS,
    ) -> None:
        """
        Args:
            hashers: A sequence of hashers to be used for password hashing.
            max_password_bytes: Maximum password length in UTF-8 bytes, or
                ``None`` to disable the limit.
            min_password_bytes: Minimum password length in UTF-8 bytes.
            max_hash_bytes: Maximum encoded hash length, or ``None`` to disable
                the limit.
            min_hash_bytes: Minimum encoded hash length.
            max_hash_fields: Maximum number of ``$``-separated hash fields.

        Raises:
            AssertionError: If no hashers are specified.
            ValueError: If a configured limit is invalid.
        """
        assert len(hashers) > 0, "You must specify at least one hasher."
        validate_limit(max_password_bytes, "max_password_bytes")
        validate_limit(min_password_bytes, "min_password_bytes")
        validate_limit(max_hash_bytes, "max_hash_bytes")
        validate_limit(min_hash_bytes, "min_hash_bytes")
        validate_limit(max_hash_fields, "max_hash_fields")
        self.hashers = hashers
        self.current_hasher = hashers[0]
        self.max_password_bytes = max_password_bytes
        self.min_password_bytes = min_password_bytes
        self.max_hash_bytes = max_hash_bytes
        self.min_hash_bytes = min_hash_bytes
        self.max_hash_fields = max_hash_fields

    @classmethod
    def recommended(cls) -> "Self":
        """
        Returns a PasswordHash instance with recommended hashers.

        Currently, the hasher is Argon2 with default parameters.

        Examples:
            >>> password_hash = PasswordHash.recommended()
            >>> hash = password_hash.hash("herminetincture")
            >>> password_hash.verify(hash, "herminetincture")
            True
        """
        from .hashers.argon2 import Argon2Hasher

        return cls((Argon2Hasher(),))

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        """
        Hashes a password using the current hasher.

        Args:
            password: The password to be hashed.
            salt: The salt to be used for hashing. Defaults to None.

        Returns:
            The hashed password.

        Examples:
            >>> hash = password_hash.hash("herminetincture")
        """
        self._validate_password_for_hasher(password, self.current_hasher)
        return self.current_hasher.hash(password, salt=salt)

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        """
        Verifies if a password matches a given hash.

        Args:
            password: The password to be checked.
            hash: The hash to be verified.

        Returns:
            True if the password matches the hash, False otherwise.

        Raises:
            exceptions.UnknownHashError: If the hash is not recognized by any of the hashers.

        Examples:
            >>> password_hash.verify("herminetincture", hash)
            True

            >>> password_hash.verify("INVALID_PASSWORD", hash)
            False
        """
        validate_password(
            password,
            max_bytes=self.max_password_bytes,
            min_bytes=self.min_password_bytes,
        )
        validate_encoded_hash(
            hash,
            max_bytes=self.max_hash_bytes,
            min_bytes=self.min_hash_bytes,
            max_fields=self.max_hash_fields,
        )
        for hasher in self.hashers:
            if self._identify_hash(hasher, hash):
                self._validate_password_for_hasher(password, hasher)
                return hasher.verify(password, hash)
        self._raise_unsupported_hash(hash)

    def verify_and_update(
        self, password: str | bytes, hash: str | bytes
    ) -> tuple[bool, str | None]:
        """
        Verifies if a password matches a given hash and updates the hash if necessary.

        Args:
            password: The password to be checked.
            hash: The hash to be verified.

        Returns:
            A tuple containing a boolean indicating if the password matches the hash,
                and an updated hash if the current hasher or the hash itself needs to be updated.

        Raises:
            exceptions.UnknownHashError: If the hash is not recognized by any of the hashers.

        Examples:
            >>> valid, updated_hash = password_hash.verify_and_update("herminetincture", hash)
        """
        validate_password(
            password,
            max_bytes=self.max_password_bytes,
            min_bytes=self.min_password_bytes,
        )
        validate_encoded_hash(
            hash,
            max_bytes=self.max_hash_bytes,
            min_bytes=self.min_hash_bytes,
            max_fields=self.max_hash_fields,
        )
        for hasher in self.hashers:
            if self._identify_hash(hasher, hash):
                self._validate_password_for_hasher(password, hasher)
                if not hasher.verify(password, hash):
                    return False, None
                else:
                    updated_hash: str | None = None
                    if hasher != self.current_hasher or hasher.check_needs_rehash(hash):
                        updated_hash = self.current_hasher.hash(password)
                    return True, updated_hash
        self._raise_unsupported_hash(hash)

    def _identify_hash(self, hasher: HasherProtocol, hash: str | bytes) -> bool:
        """Identify a hash, including formats allowed by a raised wrapper limit."""
        if hasher.identify(hash):
            return True

        # Built-in identify() methods use the conservative default hash limit.
        # If the wrapper explicitly raises or disables that limit, use the
        # instance-aware validator so configuration is still effective.
        if self.max_hash_bytes is None or self.max_hash_bytes > DEFAULT_MAX_HASH_BYTES:
            hash_validator = getattr(hasher, "validate_encoded_hash", None)
            if hash_validator is not None:
                try:
                    hash_validator(hash)
                except exceptions.HashFormatError:
                    return False
                return True
        return False

    def _validate_password_for_hasher(
        self, password: str | bytes, hasher: HasherProtocol
    ) -> None:
        """Apply both wrapper-level and matching-hasher password limits."""
        hasher_max_bytes = getattr(hasher, "max_password_bytes", None)
        if self.max_password_bytes is None:
            max_bytes = hasher_max_bytes
        elif hasher_max_bytes is None:
            max_bytes = self.max_password_bytes
        else:
            max_bytes = min(self.max_password_bytes, hasher_max_bytes)

        hasher_min_bytes = getattr(hasher, "min_password_bytes", 0)
        if hasher_min_bytes is None:
            min_bytes = self.min_password_bytes
        else:
            min_bytes = max(self.min_password_bytes, hasher_min_bytes)
        validate_password(password, max_bytes=max_bytes, min_bytes=min_bytes)

    def _raise_unsupported_hash(self, hash: str | bytes) -> typing.NoReturn:
        """
        Raise the most precise error for a hash no enabled hasher accepted.

        Built-in hashers expose an optional prefix matcher and validator, which
        lets us distinguish unsupported formats from hashes that are merely too
        short or too long without invoking the hashing backend.
        """
        for hasher in self.hashers:
            prefix_matcher = getattr(hasher, "has_supported_prefix", None)
            if prefix_matcher is None or not prefix_matcher(hash):
                continue
            hash_validator = getattr(hasher, "validate_encoded_hash", None)
            if hash_validator is not None:
                hash_validator(hash)
            raise exceptions.UnsupportedHashError(hash)
        raise exceptions.UnsupportedHashError(hash)
