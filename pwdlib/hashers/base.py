import hashlib
import hmac
import logging
import re
import typing

from .. import exceptions

logger = logging.getLogger("pwdlib.pepper")


def validate_str_or_bytes(value: typing.Any, param_name: str) -> None:
    """
    Validate that a value is a string or bytes.

    Args:
        value: The value to validate.
        param_name: The name of the parameter being validated.

    Raises:
        TypeError: If the value is not a string or bytes.
    """
    if not isinstance(value, (str, bytes)):
        raise TypeError(f"{param_name} must be str or bytes")  # noqa: TRY003


def ensure_str(v: str | bytes, *, encoding: str = "utf-8") -> str:
    return v.decode(encoding) if isinstance(v, bytes) else v


def ensure_bytes(v: str | bytes, *, encoding: str = "utf-8") -> bytes:
    return v.encode(encoding) if isinstance(v, str) else v


_PEPPER_VERSION = "v1"
_PEPPER_WRAPPER_PREFIX = f"$pwdlib-pepper${_PEPPER_VERSION}$"
_KEY_ID_REGEX = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PEPPER_WRAPPER_REGEX = re.compile(
    r"^\$pwdlib-pepper\$v1\$(?P<key_id>[A-Za-z0-9._-]{1,64})\$(?P<inner_hash>.+)$",
    re.DOTALL,
)


class PepperStrategy:
    """
    Explicitly enabled pepper strategy supporting key rotation windows.

    Passwords are never handed to the underlying hasher directly: they are
    first derived deterministically with HMAC-SHA-256 keyed by the selected
    pepper, and the 32-byte digest is what gets hashed. The stored value only
    carries a non-secret key identifier, never the key material itself.

    A stored peppered hash looks like::

        $pwdlib-pepper$v1$<key_id>$<inner algorithm hash>

    Args:
        current_key_id:
            Identifier of the key used for new hashes and upgrades.
        keys:
            Mapping of non-secret key identifiers to their secret material.
            A ``None`` value marks a registered key whose material has been
            retired: verification then raises
            :class:`~pwdlib.exceptions.MissingPepperKeyError` instead of
            returning a password mismatch.

    Raises:
        ValueError: If the key ids or key material are invalid.
    """

    def __init__(
        self,
        current_key_id: str,
        keys: typing.Mapping[str, str | bytes | None],
    ) -> None:
        if not isinstance(current_key_id, str) or not _KEY_ID_REGEX.fullmatch(
            current_key_id
        ):
            raise ValueError(  # noqa: TRY003
                "current_key_id must be a non-empty string containing only "
                "letters, digits, dots, underscores or dashes (max 64 chars)."
            )
        if not isinstance(keys, typing.Mapping) or not keys:
            raise ValueError(  # noqa: TRY003
                "keys must be a non-empty mapping of key id to secret."
            )
        for key_id, material in keys.items():
            if not isinstance(key_id, str) or not _KEY_ID_REGEX.fullmatch(key_id):
                raise ValueError(  # noqa: TRY003
                    "Pepper key ids must be non-empty strings containing only "
                    "letters, digits, dots, underscores or dashes (max 64 chars)."
                )
            if material is not None and (
                not isinstance(material, (str, bytes)) or len(material) == 0
            ):
                raise ValueError(  # noqa: TRY003
                    f"Pepper key {key_id!r} must be a non-empty str/bytes, or None."
                )
        if current_key_id not in keys:
            raise ValueError(  # noqa: TRY003
                f"current_key_id {current_key_id!r} is missing from the keys mapping."
            )
        if keys[current_key_id] is None:
            raise ValueError(  # noqa: TRY003
                f"current_key_id {current_key_id!r} must have available secret material."
            )
        self.current_key_id = current_key_id
        self._keys: dict[str, bytes | None] = {
            key_id: ensure_bytes(material) if material is not None else None
            for key_id, material in keys.items()
        }

    @staticmethod
    def is_wrapped(hash: str | bytes) -> bool:
        """Return whether *hash* carries a pwdlib pepper wrapper."""
        validate_str_or_bytes(hash, "hash")
        try:
            return ensure_str(hash).startswith(_PEPPER_WRAPPER_PREFIX)
        except UnicodeDecodeError:
            return False

    def parse(self, hash: str | bytes) -> tuple[str, str]:
        """
        Split a peppered hash into its ``(key_id, inner_hash)`` components.

        Raises:
            exceptions.CorruptPepperHashError: If the wrapper is malformed.
        """
        validate_str_or_bytes(hash, "hash")
        try:
            hash_str = ensure_str(hash)
        except UnicodeDecodeError as exc:
            logger.warning("Pepper wrapper rejected: undecodable bytes.")
            raise exceptions.CorruptPepperHashError() from exc
        match = _PEPPER_WRAPPER_REGEX.fullmatch(hash_str)
        if match is None:
            logger.warning("Pepper wrapper rejected: malformed structure.")
            raise exceptions.CorruptPepperHashError()
        return match.group("key_id"), match.group("inner_hash")

    def _resolve_key(self, key_id: str) -> bytes:
        if key_id not in self._keys:
            logger.warning("Pepper verification blocked: unknown key id %r.", key_id)
            raise exceptions.UnknownPepperKeyError(key_id)
        material = self._keys[key_id]
        if material is None:
            logger.warning(
                "Pepper verification blocked: key id %r material missing.",
                key_id,
            )
            raise exceptions.MissingPepperKeyError(key_id)
        return material

    def derive(self, password: str | bytes, key_id: str | None = None) -> bytes:
        """
        Derive the value that must be passed to the underlying hasher.

        The derivation is HMAC-SHA-256 over the UTF-8 encoded password, which
        keeps non-ASCII and ``bytes`` passwords deterministic while preserving
        the existing str/bytes distinction of the underlying hashers.
        """
        validate_str_or_bytes(password, "password")
        selected_key_id = key_id or self.current_key_id
        material = self._resolve_key(selected_key_id)
        return hmac.new(material, ensure_bytes(password), hashlib.sha256).digest()

    def wrap(self, inner_hash: str | bytes) -> str:
        """Wrap an inner algorithm hash with the current key identifier."""
        validate_str_or_bytes(inner_hash, "inner_hash")
        return f"{_PEPPER_WRAPPER_PREFIX}{self.current_key_id}${ensure_str(inner_hash)}"


class PepperedHasher:
    """
    Adapter exposing the :class:`HasherProtocol` on top of an inner hasher
    and a :class:`PepperStrategy`.

    Instances are created internally by :class:`~pwdlib.PasswordHash` when
    pepper is enabled; they are not meant to be instantiated directly.
    """

    def __init__(self, hasher: "HasherProtocol", pepper: PepperStrategy) -> None:
        self.hasher = hasher
        self.pepper = pepper

    def identify(self, hash: str | bytes) -> bool:
        if PepperStrategy.is_wrapped(hash):
            try:
                _, inner_hash = self.pepper.parse(hash)
            except exceptions.CorruptPepperHashError:
                return True
            return self.hasher.identify(inner_hash)
        # Legacy unpeppered hashes stay verifiable so they can be upgraded to
        # the pepper wrapper on the next successful login.
        return self.hasher.identify(hash)

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        derived = self.pepper.derive(password)
        return self.pepper.wrap(self.hasher.hash(derived, salt=salt))

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        if self.pepper.is_wrapped(hash):
            key_id, inner_hash = self.pepper.parse(hash)
            derived = self.pepper.derive(password, key_id)
            return self.hasher.verify(derived, inner_hash)
        # Legacy unpeppered hash: verify against the raw password exactly as
        # the underlying hasher always did.
        return self.hasher.verify(password, hash)

    def check_needs_rehash(self, hash: str | bytes) -> bool:
        if not self.pepper.is_wrapped(hash):
            return True
        key_id, inner_hash = self.pepper.parse(hash)
        if key_id != self.pepper.current_key_id:
            return True
        return self.hasher.check_needs_rehash(inner_hash)


class HasherProtocol(typing.Protocol):
    @classmethod
    def identify(cls, hash: str | bytes) -> bool: ...

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str: ...

    def verify(self, password: str | bytes, hash: str | bytes) -> bool: ...

    def check_needs_rehash(self, hash: str | bytes) -> bool: ...


__all__ = [
    "HasherProtocol",
    "PepperedHasher",
    "PepperStrategy",
    "ensure_bytes",
    "ensure_str",
    "validate_str_or_bytes",
]
