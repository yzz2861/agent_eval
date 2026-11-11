import typing

from .. import exceptions

DEFAULT_MAX_PASSWORD_BYTES = 1024
DEFAULT_MAX_HASH_BYTES = 512
DEFAULT_MIN_HASH_BYTES = 8
DEFAULT_MAX_HASH_FIELDS = 6


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


def validate_limit(value: int | None, param_name: str) -> None:
    """
    Validate that a configured limit is a non-negative integer or ``None``.

    Args:
        value: The limit to validate.
        param_name: The name of the limit being validated.

    Raises:
        ValueError: If the limit is invalid.
    """
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(  # noqa: TRY003
            f"{param_name} must be a non-negative integer or None"
        )


def validate_password(
    password: str | bytes,
    *,
    max_bytes: int | None = DEFAULT_MAX_PASSWORD_BYTES,
    min_bytes: int = 0,
) -> None:
    """
    Validate a password without copying unbounded input.

    The initial length check deliberately happens before encoding or decoding, so
    oversized request bodies are rejected without allocating another copy.

    Args:
        password: The password to validate.
        max_bytes: Maximum UTF-8 byte length, or ``None`` to disable the maximum.
        min_bytes: Minimum UTF-8 byte length.

    Raises:
        TypeError: If the password is not a string or bytes.
        PasswordTooLongError: If the password exceeds ``max_bytes``.
        PasswordTooShortError: If the password is shorter than ``min_bytes``.
        PasswordEncodingError: If the password isn't valid UTF-8.
        PasswordNULByteError: If the password contains a NUL byte.
    """
    validate_str_or_bytes(password, "password")
    validate_limit(max_bytes, "max_password_bytes")
    validate_limit(min_bytes, "min_password_bytes")

    if isinstance(password, str):
        # Every character takes at least one UTF-8 byte, so a character count
        # above the byte limit is enough to reject the value without encoding it.
        if max_bytes is not None and len(password) > max_bytes:
            raise exceptions.PasswordTooLongError(max_bytes)
        if "\x00" in password:
            raise exceptions.PasswordNULByteError()
        try:
            encoded_password = password.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise exceptions.PasswordEncodingError() from exc
    else:
        if max_bytes is not None and len(password) > max_bytes:
            raise exceptions.PasswordTooLongError(max_bytes)
        if b"\x00" in password:
            raise exceptions.PasswordNULByteError()
        try:
            password.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise exceptions.PasswordEncodingError() from exc
        encoded_password = password

    if max_bytes is not None and len(encoded_password) > max_bytes:
        raise exceptions.PasswordTooLongError(max_bytes)
    if len(encoded_password) < min_bytes:
        raise exceptions.PasswordTooShortError(min_bytes)


def validate_encoded_hash(
    hash: str | bytes,
    *,
    max_bytes: int | None = DEFAULT_MAX_HASH_BYTES,
    min_bytes: int = DEFAULT_MIN_HASH_BYTES,
    max_fields: int = DEFAULT_MAX_HASH_FIELDS,
) -> str:
    """
    Validate the outer bounds of an encoded password hash.

    Length and field-count checks happen before decoding bytes, preventing a
    bounded hasher from allocating a full copy of an attacker-controlled value.

    Args:
        hash: The encoded hash to validate.
        max_bytes: Maximum encoded hash length, or ``None`` to disable it.
        min_bytes: Minimum encoded hash length.
        max_fields: Maximum number of ``$``-separated fields.

    Returns:
        The hash as an ASCII string.

    Raises:
        TypeError: If the hash is not a string or bytes.
        HashTooLongError: If the hash exceeds ``max_bytes``.
        HashTooShortError: If the hash is shorter than ``min_bytes``.
        InvalidHashEncodingError: If the hash isn't valid ASCII.
        HashFieldCountError: If the hash has too many fields.
    """
    validate_str_or_bytes(hash, "hash")
    validate_limit(max_bytes, "max_hash_bytes")
    validate_limit(min_bytes, "min_hash_bytes")
    validate_limit(max_fields, "max_hash_fields")

    hash_length = len(hash)
    if max_bytes is not None and hash_length > max_bytes:
        raise exceptions.HashTooLongError(max_bytes)
    if hash_length < min_bytes:
        raise exceptions.HashTooShortError(min_bytes)

    if isinstance(hash, bytes):
        try:
            hash_str = hash.decode("ascii")
        except UnicodeDecodeError as exc:
            raise exceptions.InvalidHashEncodingError(hash) from exc
    else:
        hash_str = hash

    if not hash_str.isascii() or "\x00" in hash_str:
        raise exceptions.InvalidHashEncodingError(hash)
    if hash_str.count("$") + 1 > max_fields:
        raise exceptions.HashFieldCountError(max_fields)

    return hash_str


def has_prefix(value: str | bytes, prefixes: tuple[str, ...]) -> bool:
    """
    Check a hash prefix without decoding or copying attacker-controlled bytes.

    Args:
        value: The encoded hash.
        prefixes: ASCII prefixes to check.

    Returns:
        ``True`` if the value starts with one of the prefixes.
    """
    if isinstance(value, bytes):
        return any(value.startswith(prefix.encode("ascii")) for prefix in prefixes)
    return any(value.startswith(prefix) for prefix in prefixes)


def ensure_str(v: str | bytes, *, encoding: str = "utf-8") -> str:
    return v.decode(encoding) if isinstance(v, bytes) else v


def ensure_bytes(v: str | bytes, *, encoding: str = "utf-8") -> bytes:
    return v.encode(encoding) if isinstance(v, str) else v


class HasherProtocol(typing.Protocol):
    @classmethod
    def identify(cls, hash: str | bytes) -> bool: ...

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str: ...

    def verify(self, password: str | bytes, hash: str | bytes) -> bool: ...

    def check_needs_rehash(self, hash: str | bytes) -> bool: ...


__all__ = [
    "DEFAULT_MAX_HASH_BYTES",
    "DEFAULT_MAX_HASH_FIELDS",
    "DEFAULT_MAX_PASSWORD_BYTES",
    "DEFAULT_MIN_HASH_BYTES",
    "HasherProtocol",
    "ensure_bytes",
    "ensure_str",
    "has_prefix",
    "validate_encoded_hash",
    "validate_limit",
    "validate_password",
    "validate_str_or_bytes",
]
