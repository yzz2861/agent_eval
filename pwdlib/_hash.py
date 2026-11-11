import collections.abc
from typing import TYPE_CHECKING

from . import exceptions
from .hashers import HasherProtocol
from .hashers.base import PepperedHasher, PepperStrategy, validate_str_or_bytes

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
        pepper: PepperStrategy | None = None,
    ) -> None:
        """
        Args:
            hashers: A sequence of hashers to be used for password hashing.
            pepper: An optional, explicitly enabled pepper strategy. When
                provided, new hashes are wrapped with the current pepper key
                while legacy unpeppered hashes remain verifiable and are
                upgraded on successful ``verify_and_update`` calls.

        Raises:
            AssertionError: If no hashers are specified.
        """
        assert len(hashers) > 0, "You must specify at least one hasher."
        if pepper is not None and not isinstance(pepper, PepperStrategy):
            raise TypeError(  # noqa: TRY003
                "pepper must be a PepperStrategy instance or None."
            )
        self.pepper = pepper
        if pepper is None:
            self.hashers = tuple(hashers)
        else:
            self.hashers = tuple(PepperedHasher(hasher, pepper) for hasher in hashers)
        self.current_hasher = self.hashers[0]

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
        validate_str_or_bytes(password, "password")
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
        validate_str_or_bytes(password, "password")
        validate_str_or_bytes(hash, "hash")
        if self.pepper is not None and self.pepper.is_wrapped(hash):
            # Fail fast on a malformed wrapper instead of silently treating it
            # as an unknown algorithm hash.
            self.pepper.parse(hash)
        for hasher in self.hashers:
            if hasher.identify(hash):
                return hasher.verify(password, hash)
        raise exceptions.UnknownHashError(hash)

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
        validate_str_or_bytes(password, "password")
        validate_str_or_bytes(hash, "hash")
        if self.pepper is not None and self.pepper.is_wrapped(hash):
            self.pepper.parse(hash)
        for hasher in self.hashers:
            if hasher.identify(hash):
                if not hasher.verify(password, hash):
                    return False, None
                else:
                    updated_hash: str | None = None
                    if hasher != self.current_hasher or hasher.check_needs_rehash(hash):
                        updated_hash = self.current_hasher.hash(password)
                    return True, updated_hash
        raise exceptions.UnknownHashError(hash)
