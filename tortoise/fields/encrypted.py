from __future__ import annotations

import base64
import binascii
import importlib
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from tortoise.exceptions import ConfigurationError
from tortoise.fields.data import TextField

if TYPE_CHECKING:  # pragma: nocoverage
    from tortoise.models import Model

#: Prefix marking a database value as an encryption envelope.
ENVELOPE_PREFIX = "enc"
#: The only envelope version this module understands.
ENVELOPE_VERSION = 1
_SEPARATOR = ":"
_MAX_KEY_ID_LENGTH = 255


@runtime_checkable
class EncryptionProvider(Protocol):
    """Protocol for application-supplied encryption providers.

    Tortoise never invents or implements any cryptographic algorithm itself.
    The application plugs in a provider object (or a dotted path to one) and
    the framework only takes care of the envelope framing (version + key id)
    and of calling the provider on every read/write path.

    A provider must keep old keys available for decryption after rotation:
    rows written with an old key carry that key id in their envelope and are
    decrypted through :meth:`decrypt` with that very key id. New writes
    always use :attr:`current_key_id`.
    """

    @property
    def current_key_id(self) -> str:
        """Identifier of the key used for new writes."""
        ...  # pragma: nocoverage

    def encrypt(self, plaintext: bytes, key_id: str) -> bytes:
        """Encrypt ``plaintext`` with the key identified by ``key_id``.

        ``key_id`` is always the provider's own ``current_key_id``
        here. Must return raw ciphertext bytes; the framework packs them into
        the versioned envelope.
        """
        ...  # pragma: nocoverage

    def decrypt(self, ciphertext: bytes, key_id: str) -> bytes:
        """Decrypt ``ciphertext`` with the key identified by ``key_id``.

        ``key_id`` comes from the stored envelope, so it may refer to an
        old (rotated) key. Must return the original plaintext bytes.
        """
        ...  # pragma: nocoverage


def _validate_key_id(key_id: str) -> None:
    if (
        not isinstance(key_id, str)
        or not key_id
        or len(key_id) > _MAX_KEY_ID_LENGTH
        or _SEPARATOR in key_id
        or not key_id.isprintable()
    ):
        raise ConfigurationError(
            f"Encryption provider returned an invalid key id {key_id!r}: "
            f"must be a printable string of 1..{_MAX_KEY_ID_LENGTH} chars without "
            f"{_SEPARATOR!r}"
        )


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.b64decode(data + padding, altchars=b"-_", validate=True)


def build_envelope(key_id: str, ciphertext: bytes, version: int = ENVELOPE_VERSION) -> str:
    """Pack ciphertext into the versioned text envelope stored in the database.

    The format is ``enc:v<version>:<key_id>:<base64url(ciphertext)>`` so
    every stored value self-describes which format version and which key it
    needs.
    """
    _validate_key_id(key_id)
    return _SEPARATOR.join((ENVELOPE_PREFIX, f"v{version}", key_id, _b64encode(ciphertext)))


def parse_envelope(value: str) -> tuple[int, str, bytes]:
    """Unpack an envelope string into ``(version, key_id, ciphertext)``.

    :raises ValueError: if the value is not a well-formed envelope.
    """
    parts = value.split(_SEPARATOR, 3)
    if len(parts) != 4 or parts[0] != ENVELOPE_PREFIX:
        raise ValueError("not an encryption envelope")
    version_tag, key_id, payload = parts[1], parts[2], parts[3]
    if len(version_tag) < 2 or version_tag[0] != "v" or not version_tag[1:].isdigit():
        raise ValueError(f"malformed envelope version tag {version_tag!r}")
    if not key_id:
        raise ValueError("envelope carries an empty key id")
    try:
        ciphertext = _b64decode(payload)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("envelope payload is not valid base64") from exc
    return int(version_tag[1:]), key_id, ciphertext


def is_envelope(value: Any) -> bool:
    """Return True if `value` is a well-formed encryption envelope string."""
    if not isinstance(value, str) or not value.startswith(ENVELOPE_PREFIX + _SEPARATOR):
        return False
    try:
        parse_envelope(value)
    except ValueError:
        return False
    return True


def _resolve_provider(reference: str) -> EncryptionProvider:
    module_name, sep, attr_path = reference.partition(":")
    if not sep:
        module_name, sep, attr_path = reference.rpartition(".")
    if not module_name or not attr_path:
        raise ConfigurationError(
            f"Encryption provider reference {reference!r} is not an importable path "
            "(expected 'module:attribute' or 'module.attribute')"
        )
    try:
        provider: Any = importlib.import_module(module_name)
        for attr in attr_path.split("."):
            provider = getattr(provider, attr)
    except (ImportError, AttributeError) as exc:
        raise ConfigurationError(f"Cannot import encryption provider {reference!r}: {exc}") from exc
    return provider


class EncryptedField(TextField):
    """A text field whose database value is transparently encrypted at rest.

    The application reads and writes plain ``str`` values; encryption
    and decryption are delegated to an application-provided
    :class:`EncryptionProvider`. The framework only defines the stored
    envelope (``enc:v<version>:<key_id>:<base64-ciphertext>``) and
    never implements any cryptographic algorithm itself.

    :param provider: Either a dotted path string
        (``"myapp.crypto:provider"`` or
        ``"myapp.crypto.provider"``) that is resolved lazily, or a
        provider instance. An instance must expose a ``provider_id``
        attribute holding its importable identifier, so migrations can record
        the identifier without ever serializing key material.

    Behaviour notes:

    * Instance ``save()``, ``QuerySet.update()``,
      ``bulk_create()`` and the read paths all funnel through the
      same ``to_db_value`` / ``to_python_value``
      protocol, so every write is encrypted exactly once and every read is
      decrypted.
    * A value that already is a well-formed envelope (e.g. a raw database
      value assigned back to a model) is passed through unchanged on write,
      so raw database values are never encrypted twice.
    * New writes always use the provider's ``current_key_id``; old
      rows are decrypted with the key id stored in their own envelope, which
      keeps them readable after key rotation.
    * Ordering, fuzzy matching (``contains``/``startswith``/...)
      and range comparisons are meaningless on randomized ciphertext and are
      rejected with ``FieldError`` when the query is constructed.
      Only exact matches and null checks are available as filters.
    """

    def __init__(self, provider: str | EncryptionProvider, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if isinstance(provider, str):
            self.provider_id = provider
            self._provider: EncryptionProvider | None = None
        else:
            provider_id = getattr(provider, "provider_id", None)
            if not isinstance(provider_id, str) or not provider_id:
                raise ConfigurationError(
                    "EncryptedField provider objects must expose a 'provider_id' "
                    "attribute with their importable identifier "
                    "(e.g. 'myapp.crypto:provider'); alternatively pass the "
                    "identifier string directly"
                )
            self.provider_id = provider_id
            self._provider = provider

    @property
    def provider(self) -> EncryptionProvider:
        """The resolved encryption provider (imported lazily for string references)."""
        if self._provider is None:
            self._provider = _resolve_provider(self.provider_id)
        return self._provider

    def to_db_value(self, value: Any, instance: type[Model] | Model) -> Any:
        if value is None:
            self.validate(value)
            return None
        if is_envelope(value):
            # Already a database envelope (e.g. a raw value copied from the
            # DB): pass through untouched so it is never encrypted twice.
            return value
        if not isinstance(value, str):
            value = str(value)
        self.validate(value)
        key_id = self.provider.current_key_id
        ciphertext = self.provider.encrypt(value.encode("utf-8"), key_id)
        return build_envelope(key_id, ciphertext)

    def to_python_value(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if not isinstance(value, str):
            return value
        if value.startswith(ENVELOPE_PREFIX + _SEPARATOR):
            version, key_id, ciphertext = parse_envelope(value)
            if version != ENVELOPE_VERSION:
                raise ValueError(
                    f"Unsupported encryption envelope version {version} "
                    f"for field {self.model_field_name!r}"
                )
            return self.provider.decrypt(ciphertext, key_id).decode("utf-8")
        # Plain python value (e.g. passed to the model constructor).
        return value

    def deconstruct(self) -> tuple[str, list[Any], dict[str, Any]]:
        path, args, kwargs = super().deconstruct()
        # Record only the provider identifier; key material must never end
        # up in migrations.
        kwargs["provider"] = self.provider_id
        return path, args, kwargs
