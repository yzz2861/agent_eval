"""
Field adapter for storing encrypted text while exposing plain Python values.

The application owns the cryptography: it provides an :class:`EncryptionProvider`
(registered through :func:`register_encryption_provider`) and only refers to it
by identifier on the field. Tortoise never invents or implements an encryption
algorithm; it only applies the provider on write and unwraps the versioned
ciphertext envelope on read.

Stored values use a self-describing envelope so that rows written with an old
key keep decrypting after rotation, while new writes always use the current
key::

    enc::v1::<urlsafe-base64(key_id)>::<urlsafe-base64(ciphertext)>

The envelope is a framing format, not a cryptographic construction: it carries
the format version and the id of the key that produced the ciphertext.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from tortoise.exceptions import ConfigurationError, FieldError
from tortoise.fields.data import TextField

if TYPE_CHECKING:  # pragma: nocoverage
    from tortoise.models import Model

__all__ = (
    "CURRENT_ENVELOPE_VERSION",
    "ENVELOPE_PREFIX",
    "EncryptionError",
    "EncryptionProvider",
    "EncryptedTextField",
    "Envelope",
    "get_encryption_provider",
    "pack_envelope",
    "parse_envelope",
    "register_encryption_provider",
    "unregister_encryption_provider",
)

#: Prefix that marks a value produced by this adapter.
ENVELOPE_PREFIX = "enc::"

#: Current envelope framing version. Bumped only if the envelope layout changes.
CURRENT_ENVELOPE_VERSION = 1


def _b64url_encode(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _b64url_decode(encoded: str) -> str:
    padding = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise EncryptionError(f"Malformed envelope segment: {encoded!r}") from exc


class EncryptionError(FieldError):
    """Raised when a stored value cannot be unwrapped/decrypted or no key is available."""


@runtime_checkable
class EncryptionProvider(Protocol):
    """Application-provided cryptography backend.

    Implementations decide which algorithm, library and key storage to use;
    Tortoise only serializes the provider identifier into migrations.

    Attributes:
        provider_id: Stable identifier referenced by fields and recorded in
            migrations. Never a key or key material.
        current_key_id: Id of the key used for every new write.
    """

    provider_id: str
    current_key_id: str

    def encrypt(self, plaintext: str, *, key_id: str | None = None) -> str:
        """Return ciphertext (any string, typically base64) for *plaintext*.

        When *key_id* is omitted the provider encrypts with its current key.
        """

    def decrypt(self, ciphertext: str, *, key_id: str) -> str:
        """Decrypt *ciphertext* produced with the given *key_id*.

        Old keys must remain available for decrypting rows written before a
        rotation; the key id to use travels inside the stored envelope.
        """


#: Registry of application-provided encryption backends, keyed by provider id.
_PROVIDERS: dict[str, EncryptionProvider] = {}


def register_encryption_provider(provider: EncryptionProvider) -> EncryptionProvider:
    """Register *provider* so fields can reference it by its provider id.

    :raises ConfigurationError: If the provider is missing the required
        attributes or its id is already taken by a different provider.
    """
    if not isinstance(provider, EncryptionProvider):
        raise ConfigurationError(
            "Encryption provider must expose 'provider_id', 'current_key_id', "
            "'encrypt()' and 'decrypt()'"
        )
    provider_id = provider.provider_id
    if not isinstance(provider_id, str) or not provider_id:
        raise ConfigurationError("Encryption provider 'provider_id' must be a non-empty string")
    if not isinstance(provider.current_key_id, str) or not provider.current_key_id:
        raise ConfigurationError("Encryption provider 'current_key_id' must be a non-empty string")
    existing = _PROVIDERS.get(provider_id)
    if existing is not None and existing is not provider:
        raise ConfigurationError(
            f"Encryption provider {provider_id!r} is already registered to a different provider"
        )
    _PROVIDERS[provider_id] = provider
    return provider


def unregister_encryption_provider(provider_id: str) -> None:
    """Remove a previously registered provider. Missing ids are ignored."""
    _PROVIDERS.pop(provider_id, None)


def get_encryption_provider(provider_id: str) -> EncryptionProvider:
    """Return the registered provider for *provider_id*.

    :raises ConfigurationError: If no such provider has been registered.
    """
    try:
        return _PROVIDERS[provider_id]
    except KeyError:
        raise ConfigurationError(
            f"Encryption provider {provider_id!r} is not registered; "
            "call register_encryption_provider() during application startup"
        ) from None


class Envelope:
    """Parsed versioned ciphertext envelope.

    :param version: Envelope framing version.
    :param key_id: Id of the key that produced ``ciphertext``.
    :param ciphertext: Provider ciphertext exactly as returned by ``encrypt``.
    """

    __slots__ = ("ciphertext", "key_id", "version")

    def __init__(self, version: int, key_id: str, ciphertext: str) -> None:
        self.version = version
        self.key_id = key_id
        self.ciphertext = ciphertext

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Envelope):
            return NotImplemented
        return (
            self.version == other.version
            and self.key_id == other.key_id
            and self.ciphertext == other.ciphertext
        )

    def __repr__(self) -> str:
        return f"Envelope(version={self.version!r}, key_id={self.key_id!r}, ciphertext=...)"


def pack_envelope(ciphertext: str, key_id: str, *, version: int = CURRENT_ENVELOPE_VERSION) -> str:
    """Serialize provider ciphertext into a versioned, key-tagged envelope."""
    return f"{ENVELOPE_PREFIX}v{version}::{_b64url_encode(key_id)}::{_b64url_encode(ciphertext)}"


def parse_envelope(value: Any) -> Envelope | None:
    """Parse a DB value into an :class:`Envelope`.

    :return: The parsed envelope, or ``None`` for values that are not envelopes
        (plaintext, ``None`` or non-string driver values).
    :raises EncryptionError: For values that carry the envelope prefix but are
        malformed or use an unsupported envelope version.
    """
    if not isinstance(value, str) or not value.startswith(ENVELOPE_PREFIX):
        return None
    parts = value.split("::")
    if len(parts) != 4 or not parts[1].startswith("v") or not parts[2] or not parts[3]:
        raise EncryptionError(f"Malformed encrypted value: {value[:24]!r}")
    try:
        version = int(parts[1][1:])
    except ValueError as exc:
        raise EncryptionError(f"Malformed envelope version: {parts[1]!r}") from exc
    if version != CURRENT_ENVELOPE_VERSION:
        raise EncryptionError(
            f"Unsupported encrypted value version {version}; "
            f"this build supports up to v{CURRENT_ENVELOPE_VERSION}"
        )
    return Envelope(version, _b64url_decode(parts[2]), _b64url_decode(parts[3]))


class EncryptedTextField(TextField):
    """A TEXT column that stores encrypted values but behaves as a plain ``str`` field.

    :param provider: Provider id registered with
        :func:`register_encryption_provider`, or a provider instance (which is
        registered automatically). Only the id is recorded by ``deconstruct``;
        key material never enters migration state.

    Reads unwrap the envelope stored in the column and ask the provider to
    decrypt using the **key id carried by that row**. Values without the
    envelope prefix are returned as-is so legacy plaintext rows keep working.

    Writes always encrypt with the provider's *current* key. A value that is
    already an envelope (a raw database value) is passed through untouched, so
    round-tripped ciphertext is never encrypted a second time.

    Because the ciphertext is randomized, content-based lookups (exact match,
    ``__in``, pattern matching, range comparisons, ordering) are rejected while
    building the query rather than returning misleading empty results. Only
    null checks (``__isnull``) remain available; look rows up by another,
    non-encrypted column.
    """

    supports_plaintext_lookups = False

    def __init__(self, provider: str | EncryptionProvider, **kwargs: Any) -> None:
        if isinstance(provider, str):
            self._provider_id = provider
        else:
            register_encryption_provider(provider)
            self._provider_id = provider.provider_id
        super().__init__(**kwargs)

    @property
    def provider_id(self) -> str:
        """Identifier of the encryption backend used by this field."""
        return self._provider_id

    @property
    def provider(self) -> EncryptionProvider:
        """Registered provider instance backing this field."""
        return get_encryption_provider(self._provider_id)

    def to_db_value(self, value: Any, instance: type[Model] | Model) -> str | None:
        if value is None:
            return None
        # Raw database values (already wrapped envelopes) must not be encrypted again.
        if parse_envelope(value) is not None:
            return value
        if not isinstance(value, str):
            value = str(value)
        self.validate(value)
        provider = self.provider
        ciphertext = provider.encrypt(value)
        return pack_envelope(ciphertext, provider.current_key_id)

    def to_python_value(self, value: Any) -> str | None:
        if value is None:
            return None
        envelope = parse_envelope(value)
        if envelope is None:
            # Legacy non-encrypted row or a driver value Tortoise did not wrap.
            return value if isinstance(value, str) else str(value)
        provider = self.provider
        try:
            return provider.decrypt(envelope.ciphertext, key_id=envelope.key_id)
        except EncryptionError:
            raise
        except Exception as exc:  # pragma: no branch - provider errors are opaque to us
            raise EncryptionError(
                f"Failed to decrypt {self.model_field_name!r} with key {envelope.key_id!r}"
            ) from exc

    def deconstruct(self) -> tuple[str, list[Any], dict[str, Any]]:
        path, _args, kwargs = super().deconstruct()
        # Only the provider identifier is recorded; never the provider/key itself.
        kwargs["provider"] = self._provider_id
        return path, [], kwargs
