"""
Versioned encodings for rate limit storage keys.

The legacy ``v1`` encoding joins all key components with ``/`` which makes
it ambiguous: components are not typed and their boundaries are lost, so
e.g. the identifier pairs ``("a/b", "c")`` and ``("a", "b/c")`` map to the
same key. It remains the default so that existing deployments do not
silently reset all of their active rate limit windows on upgrade.

The ``v2`` encoding is a structured, self describing format that preserves
the number, types and boundaries of all key components:

.. code-block:: text

    v2|<field count>|<field>|<field>|...

where each field is one of:

* ``s<byte length>:<utf-8 text>`` for :class:`str`
  (the length prefix counts utf-8 *bytes*, not characters)
* ``b<byte length>:<hex>`` for :class:`bytes`
* ``i<decimal>`` for :class:`int` (and :class:`bool`)
* ``f<repr>`` for finite :class:`float` values

Values without a stable, deterministic representation (``None``, arbitrary
objects, non finite floats, strings that cannot be utf-8 encoded, ...) are
rejected instead of being silently stringified.
"""

from __future__ import annotations

import math
from collections.abc import Iterable

from limits.typing import Literal, cast

KeyEncoding = Literal["v1", "v2"]
"""
Supported storage key encoding versions.
"""

DEFAULT_KEY_ENCODING: KeyEncoding = "v1"
"""
The encoding used when none is explicitly requested.

This remains ``v1`` for backwards compatibility so that upgrading does not
change the keys of already running rate limit windows.
"""

KEY_ENCODINGS: tuple[KeyEncoding, ...] = ("v1", "v2")

KeyComponent = bytes | str | int | float


def safe_string(value: KeyComponent) -> str:
    """
    normalize a byte/str/int or float to a str
    """

    if isinstance(value, bytes):
        return value.decode()

    return str(value)


def validate_key_encoding(encoding: str) -> KeyEncoding:
    """
    Ensure ``encoding`` names a supported key encoding version.

    :raises ValueError: if the version is not supported
    """

    if encoding not in KEY_ENCODINGS:
        raise ValueError(
            f"Unknown key encoding: {encoding!r}."
            f" Supported encodings: {', '.join(KEY_ENCODINGS)}"
        )

    return cast(KeyEncoding, encoding)


def _encode_key_v1(
    namespace: str,
    identifiers: Iterable[KeyComponent],
    amount: int,
    multiples: int,
    granularity_name: str,
) -> str:
    remainder = "/".join(
        [safe_string(k) for k in identifiers]
        + [
            safe_string(amount),
            safe_string(multiples),
            granularity_name,
        ]
    )

    return f"{namespace}/{remainder}"


def _encode_component_v2(value: KeyComponent) -> str:
    if isinstance(value, str):
        try:
            byte_length = len(value.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise ValueError(
                f"String key component {value!r} cannot be encoded as utf-8"
            ) from error

        return f"s{byte_length}:{value}"
    if isinstance(value, bytes):
        return f"b{len(value)}:{value.hex()}"
    if isinstance(value, bool):
        # bool is a subclass of int and True == 1 / False == 0, so they
        # intentionally share the integer representation.
        return f"i{int(value)}"
    if isinstance(value, int):
        return f"i{value}"
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(
                f"Float key component {value!r} has no stable representation"
            )

        return f"f{value!r}"
    raise TypeError(
        f"Key component {value!r} of type {type(value).__name__} has no stable"
        " representation; only str, bytes, int and float are supported"
    )


def _encode_key_v2(
    namespace: str,
    identifiers: Iterable[KeyComponent],
    amount: int,
    multiples: int,
    granularity_name: str,
) -> str:
    components: list[KeyComponent] = [
        namespace,
        *identifiers,
        amount,
        multiples,
        granularity_name,
    ]
    fields = "|".join(_encode_component_v2(component) for component in components)

    return f"v2|{len(components)}|{fields}"


def encode_key(
    encoding: KeyEncoding,
    namespace: str,
    identifiers: Iterable[KeyComponent],
    amount: int,
    multiples: int,
    granularity_name: str,
) -> str:
    """
    Build a storage key from its structural components using the
    requested encoding version.

    All operations belonging to the same logical limiter must use the same
    encoding version, otherwise they will address different keys.
    """

    if encoding == "v1":
        return _encode_key_v1(
            namespace, identifiers, amount, multiples, granularity_name
        )
    if encoding == "v2":
        return _encode_key_v2(
            namespace, identifiers, amount, multiples, granularity_name
        )

    raise ValueError(
        f"Unknown key encoding: {encoding!r}."
        f" Supported encodings: {', '.join(KEY_ENCODINGS)}"
    )
