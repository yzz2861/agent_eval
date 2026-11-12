from __future__ import annotations

import collections.abc as cabc
import dataclasses
import json
import typing as t

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadPayload
from .exc import BadSignature
from .exc import InvalidScope
from .exc import ScopeMigrationRequired
from .exc import ScopeMismatch
from .signer import _make_keys_list
from .signer import Signer

if t.TYPE_CHECKING:
    import typing_extensions as te

    # This should be either be str or bytes. To avoid having to specify the
    # bound type, it falls back to a union if structural matching fails.
    _TSerialized = te.TypeVar("_TSerialized", bound=str | bytes, default=str | bytes)
else:
    # Still available at runtime on Python < 3.13, but without the default.
    _TSerialized = t.TypeVar("_TSerialized", bound=str | bytes)


class _PDataSerializer(t.Protocol[_TSerialized]):
    def loads(self, payload: _TSerialized, /) -> t.Any: ...
    # A signature with additional arguments is not handled correctly by type
    # checkers right now, so an overload is used below for serializers that
    # don't match this strict protocol.
    def dumps(self, obj: t.Any, /) -> _TSerialized: ...


# Use TypeIs once it's available in typing_extensions or 3.13.
def is_text_serializer(
    serializer: _PDataSerializer[t.Any],
) -> te.TypeGuard[_PDataSerializer[str]]:
    """Checks whether a serializer generates text or binary."""
    return isinstance(serializer.dumps({}), str)


# A NUL byte cannot appear in a regular JSON payload or a URL-safe base64
# payload, so this marker cannot be confused with an unscoped token.
_SCOPE_MAGIC = b"\x00itsdangerous.scope.v1\x00"
_SCOPE_KEYS = frozenset(("action", "tenant", "version"))
_SCOPE_MAX_FIELD_BYTES = 1024 * 1024


def _scope_text(value: t.Any, field: str) -> str:
    """Normalize and validate a textual scope field.

    Scope fields are encoded into the signed message itself. They are
    kept independent of any delimiter so an action or tenant containing
    ``.``, ``:``, newlines, or other punctuation cannot change how the
    header is parsed.
    """
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as e:
            raise InvalidScope(
                f"scope {field} must be valid UTF-8",
            ) from e
    elif not isinstance(value, str):
        raise InvalidScope(f"scope {field} must be a string or bytes")

    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as e:
        raise InvalidScope(f"scope {field} must be valid UTF-8") from e

    if not encoded:
        raise InvalidScope(f"scope {field} must not be empty")

    if len(encoded) > _SCOPE_MAX_FIELD_BYTES:
        raise InvalidScope(
            f"scope {field} exceeds the maximum length of"
            f" {_SCOPE_MAX_FIELD_BYTES} bytes"
        )

    return value


def _scope_version(value: t.Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidScope("scope version must be a non-negative integer")

    if value < 0:
        raise InvalidScope("scope version must be a non-negative integer")

    return value


@dataclasses.dataclass(frozen=True)
class Scope:
    """The authenticated purpose of a token.

    A scope binds the action that may consume the token, the tenant the
    token belongs to, and optionally the object version it was issued for.
    The values are stored inside the signed message.
    """

    action: str
    tenant: str
    version: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _scope_text(self.action, "action"))
        object.__setattr__(self, "tenant", _scope_text(self.tenant, "tenant"))

        if self.version is not None:
            object.__setattr__(self, "version", _scope_version(self.version))


#: Alias used by callers that describe the action as a purpose.
Purpose = Scope
AuthScope = Scope


_SCOPE_EXTRA_ALIASES = {
    "purpose_name": "action",
    "purpose_domain": "action",
    "scope_action": "action",
    "action_name": "action",
    "action_id": "action",
    "operation": "action",
    "tenant_key": "tenant",
    "tenant_name": "tenant",
    "tenant_identifier": "tenant",
    "obj_version": "version",
    "rev": "version",
    "version_id": "version",
    "object_version_id": "version",
    "entity_version": "version",
    "current_version": "version",
    "expected_version": "version",
    "schema_version": "version",
}


def _coerce_scope(scope: t.Any) -> Scope:
    if isinstance(scope, Scope):
        return Scope(scope.action, scope.tenant, scope.version)

    if isinstance(scope, cabc.Mapping):
        if "action" in scope:
            action = scope["action"]
        else:
            action = scope.get("purpose")

        if "tenant" in scope:
            tenant = scope["tenant"]
        elif "tenant_id" in scope:
            tenant = scope["tenant_id"]
        else:
            tenant = scope.get("tenant_identifier")

        if "version" in scope:
            version = scope["version"]
        elif "revision" in scope:
            version = scope["revision"]
        else:
            version = scope.get("object_version", scope.get("obj_version"))

        return Scope(action, tenant, version)

    if isinstance(scope, (tuple, list)):
        if len(scope) == 2:
            return Scope(scope[0], scope[1])

        if len(scope) == 3:
            return Scope(scope[0], scope[1], scope[2])

        raise InvalidScope("scope tuple must contain action, tenant, and version")

    if hasattr(scope, "action") or hasattr(scope, "purpose"):
        action = getattr(scope, "action", getattr(scope, "purpose", None))
        tenant = getattr(scope, "tenant", getattr(scope, "tenant_id", None))
        version = getattr(
            scope,
            "version",
            getattr(scope, "revision", getattr(scope, "object_version", None)),
        )
        return Scope(action, tenant, version)

    raise InvalidScope("scope must be a Scope, mapping, or tuple")


def _one_scope_value(values: list[t.Any], field: str) -> t.Any:
    present = [value for value in values if value is not None]

    if not present:
        return None

    first = present[0]

    if field == "version":
        normalized = _scope_version(first)

        for value in present[1:]:
            if _scope_version(value) != normalized:
                raise InvalidScope(f"conflicting scope {field} values")
    else:
        normalized = _scope_text(first, field)

        for value in present[1:]:
            if _scope_text(value, field) != normalized:
                raise InvalidScope(f"conflicting scope {field} values")

    return normalized


def _make_scope(
    *,
    action: t.Any = None,
    purpose: t.Any = None,
    tenant: t.Any = None,
    tenant_id: t.Any = None,
    version: t.Any = None,
    revision: t.Any = None,
    object_version: t.Any = None,
    scope: t.Any = None,
    extra: cabc.Mapping[str, t.Any] | None = None,
) -> Scope | None:
    """Build a scope from the keyword arguments used by dumps and loads.

    ``None`` means that scope verification was not requested, preserving
    the behavior of the original API.
    """
    extra_values: dict[str, list[t.Any]] = {
        "action": [],
        "tenant": [],
        "version": [],
    }

    if extra:
        for key, value in extra.items():
            canonical = _SCOPE_EXTRA_ALIASES.get(key)

            if canonical is None:
                raise TypeError(f"unexpected keyword argument {key!r}")

            extra_values[canonical].append(value)

    if (
        purpose is not None
        and not isinstance(purpose, (str, bytes))
        and isinstance(purpose, (Scope, cabc.Mapping, tuple, list))
    ):
        if scope is not None:
            raise InvalidScope("scope and purpose cannot both be a composite scope")

        scope = purpose
        purpose = None

    explicit = (action, purpose, tenant, tenant_id, version, revision, object_version)

    full_scope = scope
    scope_action = None

    if isinstance(scope, (str, bytes)):
        # A string scope is an alias for the action. It still requires a
        # separately declared tenant.
        full_scope = None
        scope_action = scope

    if full_scope is not None:
        if any(value is not None for value in explicit) or any(
            value is not None for values in extra_values.values() for value in values
        ):
            raise InvalidScope(
                "scope cannot be combined with action, tenant, or version"
            )

        return _coerce_scope(full_scope)

    action_value = _one_scope_value(
        [action, purpose, scope_action, *extra_values["action"]], "action"
    )
    tenant_value = _one_scope_value(
        [tenant, tenant_id, *extra_values["tenant"]], "tenant"
    )
    version_value = _one_scope_value(
        [version, revision, object_version, *extra_values["version"]],
        "version",
    )

    if action_value is None and tenant_value is None and version_value is None:
        return None

    if action_value is None or tenant_value is None:
        raise InvalidScope(
            "scope verification requires both an action and a tenant"
        )

    return Scope(action_value, tenant_value, version_value)


def _wrap_scoped_payload(payload: bytes, scope: Scope) -> bytes:
    header_data = json.dumps(
        {
            "action": scope.action,
            "tenant": scope.tenant,
            "version": scope.version,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    header = base64_encode(_SCOPE_MAGIC + b"." + header_data)
    return header + b"." + payload


def _extract_scoped_payload(payload: bytes) -> tuple[Scope | None, bytes]:
    """Split a signed payload into its scope and the actual data.

    Only the first segment is considered as the header. It is URL-safe
    base64, whose alphabet does not contain ``.``, so data containing
    dots cannot make the header ambiguous.
    """
    if b"." not in payload:
        return None, payload

    header, _, rest = payload.partition(b".")

    if not header:
        return None, payload

    try:
        decoded = base64_decode(header)
    except Exception:
        return None, payload

    if not decoded.startswith(_SCOPE_MAGIC):
        return None, payload

    body = decoded[len(_SCOPE_MAGIC) :]

    if not body.startswith(b"."):
        raise InvalidScope("malformed authenticated scope header")

    body = body[1:]

    try:
        scope_data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise InvalidScope("malformed authenticated scope header") from e

    if not isinstance(scope_data, dict):
        raise InvalidScope("malformed authenticated scope header")

    if set(scope_data) - _SCOPE_KEYS:
        raise InvalidScope("malformed authenticated scope header")

    if "action" not in scope_data or "tenant" not in scope_data:
        raise InvalidScope("authenticated scope is missing action or tenant")

    return Scope(
        scope_data["action"], scope_data["tenant"], scope_data.get("version")
    ), rest


def _check_scope(token_scope: Scope | None, expected_scope: Scope | None) -> None:
    if expected_scope is None:
        if token_scope is not None:
            raise ScopeMismatch(
                "token was issued with an authenticated scope; declare the"
                " action and tenant to verify it"
            )

        return

    if token_scope is None:
        raise ScopeMigrationRequired(
            "migration required: legacy unscoped token must be migrated"
            " and reissued with an authenticated scope"
        )

    if token_scope.action != expected_scope.action:
        raise ScopeMismatch(
            f"scope action mismatch: token was issued for"
            f" {token_scope.action!r}, not {expected_scope.action!r}"
        )

    if token_scope.tenant != expected_scope.tenant:
        raise ScopeMismatch(
            f"scope tenant mismatch: token was issued for"
            f" {token_scope.tenant!r}, not {expected_scope.tenant!r}"
        )

    token_version = token_scope.version
    expected_version = expected_scope.version

    if expected_version is None and token_version is not None:
        raise ScopeMismatch(
            f"token was issued for object version {token_version}; the"
            " current version must be declared"
        )

    if expected_version is not None and token_version is None:
        raise ScopeMismatch(
            "token was issued without an object version, but the current"
            " version requires one"
        )

    if token_version is not None and expected_version is not None:
        if token_version < expected_version:
            raise ScopeMismatch(
                f"scope version mismatch: stale object version"
                f" {token_version}; replay against version"
                f" {expected_version} rejected"
            )

        if token_version > expected_version:
            raise ScopeMismatch(
                f"scope version mismatch: object version {token_version}"
                f" is newer than the current version {expected_version}"
            )


def _strip_scope_from_exception(err: BadSignature) -> None:
    """Expose the original data on a failed signature, not the scope
    header that was added by this module.
    """
    if err.payload is None:
        return

    try:
        _, payload = _extract_scoped_payload(want_bytes(err.payload))
    except InvalidScope:
        return

    err.payload = payload


class Serializer(t.Generic[_TSerialized]):
    """A serializer wraps a :class:`~itsdangerous.signer.Signer` to
    enable serializing and securely signing data other than bytes. It
    can unsign to verify that the data hasn't been changed.

    The serializer provides :meth:`dumps` and :meth:`loads`, similar to
    :mod:`json`, and by default uses :mod:`json` internally to serialize
    the data to bytes.

    The secret key should be a random string of ``bytes`` and should not
    be saved to code or version control. Different salts should be used
    to distinguish signing in different contexts. See :doc:`/concepts`
    for information about the security of the secret key and salt.

    :param secret_key: The secret key to sign and verify with. Can be a
        list of keys, oldest to newest, to support key rotation.
    :param salt: Extra key to combine with ``secret_key`` to distinguish
        signatures in different contexts.
    :param serializer: An object that provides ``dumps`` and ``loads``
        methods for serializing data to a string. Defaults to
        :attr:`default_serializer`, which defaults to :mod:`json`.
    :param serializer_kwargs: Keyword arguments to pass when calling
        ``serializer.dumps``.
    :param signer: A ``Signer`` class to instantiate when signing data.
        Defaults to :attr:`default_signer`, which defaults to
        :class:`~itsdangerous.signer.Signer`.
    :param signer_kwargs: Keyword arguments to pass when instantiating
        the ``Signer`` class.
    :param fallback_signers: List of signer parameters to try when
        unsigning with the default signer fails. Each item can be a dict
        of ``signer_kwargs``, a ``Signer`` class, or a tuple of
        ``(signer, signer_kwargs)``. Defaults to
        :attr:`default_fallback_signers`.

    .. versionchanged:: 2.0
        Added support for key rotation by passing a list to
        ``secret_key``.

    .. versionchanged:: 2.0
        Removed the default SHA-512 fallback signer from
        ``default_fallback_signers``.

    .. versionchanged:: 1.1
        Added support for ``fallback_signers`` and configured a default
        SHA-512 fallback. This fallback is for users who used the yanked
        1.0.0 release which defaulted to SHA-512.

    .. versionchanged:: 0.14
        The ``signer`` and ``signer_kwargs`` parameters were added to
        the constructor.
    """

    #: The default serialization module to use to serialize data to a
    #: string internally. The default is :mod:`json`, but can be changed
    #: to any object that provides ``dumps`` and ``loads`` methods.
    default_serializer: _PDataSerializer[t.Any] = json

    #: The default ``Signer`` class to instantiate when signing data.
    #: The default is :class:`itsdangerous.signer.Signer`.
    default_signer: type[Signer] = Signer

    #: The default fallback signers to try when unsigning fails.
    default_fallback_signers: list[
        dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
    ] = []

    # Serializer[str] if no data serializer is provided, or if it returns str.
    @t.overload
    def __init__(
        self: Serializer[str],
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None = b"itsdangerous",
        serializer: None | _PDataSerializer[str] = None,
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[Signer] | None = None,
        signer_kwargs: dict[str, t.Any] | None = None,
        fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ]
        | None = None,
    ): ...

    # Serializer[bytes] with a bytes data serializer positional argument.
    @t.overload
    def __init__(
        self: Serializer[bytes],
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None,
        serializer: _PDataSerializer[bytes],
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[Signer] | None = None,
        signer_kwargs: dict[str, t.Any] | None = None,
        fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ]
        | None = None,
    ): ...

    # Serializer[bytes] with a bytes data serializer keyword argument.
    @t.overload
    def __init__(
        self: Serializer[bytes],
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None = b"itsdangerous",
        *,
        serializer: _PDataSerializer[bytes],
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[Signer] | None = None,
        signer_kwargs: dict[str, t.Any] | None = None,
        fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ]
        | None = None,
    ): ...

    # Fall back with a positional argument. If the strict signature of
    # _PDataSerializer doesn't match, fall back to a union, requiring the user
    # to specify the type.
    @t.overload
    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None,
        serializer: t.Any,
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[Signer] | None = None,
        signer_kwargs: dict[str, t.Any] | None = None,
        fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ]
        | None = None,
    ): ...

    # Fall back with a keyword argument.
    @t.overload
    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None = b"itsdangerous",
        *,
        serializer: t.Any,
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[Signer] | None = None,
        signer_kwargs: dict[str, t.Any] | None = None,
        fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ]
        | None = None,
    ): ...

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None = b"itsdangerous",
        serializer: t.Any | None = None,
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[Signer] | None = None,
        signer_kwargs: dict[str, t.Any] | None = None,
        fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ]
        | None = None,
    ):
        #: The list of secret keys to try for verifying signatures, from
        #: oldest to newest. The newest (last) key is used for signing.
        #:
        #: This allows a key rotation system to keep a list of allowed
        #: keys and remove expired ones.
        self.secret_keys: list[bytes] = _make_keys_list(secret_key)

        if salt is not None:
            salt = want_bytes(salt)
            # if salt is None then the signer's default is used

        self.salt = salt

        if serializer is None:
            serializer = self.default_serializer

        self.serializer: _PDataSerializer[_TSerialized] = serializer
        self.is_text_serializer: bool = is_text_serializer(serializer)

        if signer is None:
            signer = self.default_signer

        self.signer: type[Signer] = signer
        self.signer_kwargs: dict[str, t.Any] = signer_kwargs or {}

        if fallback_signers is None:
            fallback_signers = list(self.default_fallback_signers)

        self.fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ] = fallback_signers
        self.serializer_kwargs: dict[str, t.Any] = serializer_kwargs or {}

    @property
    def secret_key(self) -> bytes:
        """The newest (last) entry in the :attr:`secret_keys` list. This
        is for compatibility from before key rotation support was added.
        """
        return self.secret_keys[-1]

    def load_payload(
        self, payload: bytes, serializer: _PDataSerializer[t.Any] | None = None
    ) -> t.Any:
        """Loads the encoded object. This function raises
        :class:`.BadPayload` if the payload is not valid. The
        ``serializer`` parameter can be used to override the serializer
        stored on the class. The encoded ``payload`` should always be
        bytes.
        """
        if serializer is None:
            use_serializer = self.serializer
            is_text = self.is_text_serializer
        else:
            use_serializer = serializer
            is_text = is_text_serializer(serializer)

        try:
            if is_text:
                return use_serializer.loads(payload.decode("utf-8"))  # type: ignore[arg-type]

            return use_serializer.loads(payload)  # type: ignore[arg-type]
        except Exception as e:
            raise BadPayload(
                "Could not load the payload because an exception"
                " occurred on unserializing the data.",
                original_error=e,
            ) from e

    def dump_payload(self, obj: t.Any) -> bytes:
        """Dumps the encoded object. The return value is always bytes.
        If the internal serializer returns text, the value will be
        encoded as UTF-8.
        """
        return want_bytes(self.serializer.dumps(obj, **self.serializer_kwargs))

    def make_signer(self, salt: str | bytes | None = None) -> Signer:
        """Creates a new instance of the signer to be used. The default
        implementation uses the :class:`.Signer` base class.
        """
        if salt is None:
            salt = self.salt

        return self.signer(self.secret_keys, salt=salt, **self.signer_kwargs)

    def iter_unsigners(self, salt: str | bytes | None = None) -> cabc.Iterator[Signer]:
        """Iterates over all signers to be tried for unsigning. Starts
        with the configured signer, then constructs each signer
        specified in ``fallback_signers``.
        """
        if salt is None:
            salt = self.salt

        yield self.make_signer(salt)

        for fallback in self.fallback_signers:
            if isinstance(fallback, dict):
                kwargs = fallback
                fallback = self.signer
            elif isinstance(fallback, tuple):
                fallback, kwargs = fallback
            else:
                kwargs = self.signer_kwargs

            for secret_key in self.secret_keys:
                yield fallback(secret_key, salt=salt, **kwargs)

    def dumps(
        self,
        obj: t.Any,
        salt: str | bytes | None = None,
        *,
        action: str | bytes | None = None,
        purpose: str | bytes | None = None,
        tenant: str | bytes | None = None,
        tenant_id: str | bytes | None = None,
        version: int | None = None,
        revision: int | None = None,
        object_version: int | None = None,
        scope: Scope | cabc.Mapping[str, t.Any] | tuple[t.Any, ...] | None = None,
        **kwargs: t.Any,
    ) -> _TSerialized:
        """Returns a signed string serialized with the internal
        serializer. The return value can be either a byte or unicode
        string depending on the format of the internal serializer.

        If ``action`` and ``tenant`` are given, the token is scoped to
        that action and tenant. The scope is included inside the signed
        payload, so it cannot be changed by editing the token or by
        adding unsigned cookie or URL parameters. ``purpose`` is an alias
        for ``action``. ``tenant_id``, ``revision``, and
        ``object_version`` are aliases for ``tenant`` and ``version``.

        When called without scope arguments, the signed value is
        unchanged from the original behavior.
        """
        parsed_scope = _make_scope(
            action=action,
            purpose=purpose,
            tenant=tenant,
            tenant_id=tenant_id,
            version=version,
            revision=revision,
            object_version=object_version,
            scope=scope,
            extra=kwargs,
        )
        payload = want_bytes(self.dump_payload(obj))

        if parsed_scope is not None:
            payload = _wrap_scoped_payload(payload, parsed_scope)

        rv = self.make_signer(salt).sign(payload)

        if self.is_text_serializer:
            return rv.decode("utf-8")  # type: ignore[return-value]

        return rv  # type: ignore[return-value]

    def dump(
        self,
        obj: t.Any,
        f: t.IO[t.Any],
        salt: str | bytes | None = None,
        **kwargs: t.Any,
    ) -> None:
        """Like :meth:`dumps` but dumps into a file. The file handle has
        to be compatible with what the internal serializer expects.
        """
        f.write(self.dumps(obj, salt=salt, **kwargs))

    def loads(
        self,
        s: str | bytes,
        salt: str | bytes | None = None,
        *,
        action: str | bytes | None = None,
        purpose: str | bytes | None = None,
        tenant: str | bytes | None = None,
        tenant_id: str | bytes | None = None,
        version: int | None = None,
        revision: int | None = None,
        object_version: int | None = None,
        scope: Scope | cabc.Mapping[str, t.Any] | tuple[t.Any, ...] | None = None,
        **kwargs: t.Any,
    ) -> t.Any:
        """Reverse of :meth:`dumps`. Raises :exc:`.BadSignature` if the
        signature validation fails.

        If ``action`` and ``tenant`` are given, the token's authenticated
        scope must match before the payload is deserialized. A scoped
        token loaded without declaring its scope, and an unscoped token
        loaded with a declared scope, are both rejected rather than
        silently downgraded. ``version``, when declared, must exactly
        match the token's version; an older token is a stale replay.
        """
        expected_scope = _make_scope(
            action=action,
            purpose=purpose,
            tenant=tenant,
            tenant_id=tenant_id,
            version=version,
            revision=revision,
            object_version=object_version,
            scope=scope,
            extra=kwargs,
        )
        s = want_bytes(s)
        last_exception = None

        for signer in self.iter_unsigners(salt):
            try:
                payload = signer.unsign(s)
            except BadSignature as err:
                _strip_scope_from_exception(err)
                last_exception = err
                continue

            token_scope, payload = _extract_scoped_payload(payload)
            _check_scope(token_scope, expected_scope)
            return self.load_payload(payload)

        raise t.cast(BadSignature, last_exception)

    def load(
        self, f: t.IO[t.Any], salt: str | bytes | None = None, **kwargs: t.Any
    ) -> t.Any:
        """Like :meth:`loads` but loads from a file."""
        return self.loads(f.read(), salt=salt, **kwargs)

    def loads_unsafe(
        self,
        s: str | bytes,
        salt: str | bytes | None = None,
        **kwargs: t.Any,
    ) -> tuple[bool, t.Any]:
        """Like :meth:`loads` but without verifying the signature. This
        is potentially very dangerous to use depending on how your
        serializer works. The return value is ``(signature_valid,
        payload)`` instead of just the payload. The first item will be a
        boolean that indicates if the signature is valid. This function
        never fails.

        Use it for debugging only and if you know that your serializer
        module is not exploitable (for example, do not use it with a
        pickle serializer).

        .. versionadded:: 0.15
        """
        return self._loads_unsafe_impl(s, salt, load_kwargs=kwargs)

    def _loads_unsafe_impl(
        self,
        s: str | bytes,
        salt: str | bytes | None,
        load_kwargs: dict[str, t.Any] | None = None,
        load_payload_kwargs: dict[str, t.Any] | None = None,
    ) -> tuple[bool, t.Any]:
        """Low level helper function to implement :meth:`loads_unsafe`
        in serializer subclasses.
        """
        if load_kwargs is None:
            load_kwargs = {}

        try:
            return True, self.loads(s, salt=salt, **load_kwargs)
        except InvalidScope:
            return False, None
        except BadSignature as e:
            if e.payload is None:
                return False, None

            if load_payload_kwargs is None:
                load_payload_kwargs = {}

            try:
                _, payload = _extract_scoped_payload(e.payload)
            except InvalidScope:
                return False, None

            try:
                return (
                    False,
                    self.load_payload(payload, **load_payload_kwargs),
                )
            except BadPayload:
                return False, None

    def load_unsafe(
        self, f: t.IO[t.Any], salt: str | bytes | None = None, **kwargs: t.Any
    ) -> tuple[bool, t.Any]:
        """Like :meth:`loads_unsafe` but loads from a file.

        .. versionadded:: 0.15
        """
        return self.loads_unsafe(f.read(), salt=salt, **kwargs)
