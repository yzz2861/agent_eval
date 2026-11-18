"""
Verifiable decoding transforms used by the derivation analysis backend.

A transform only counts as a valid derivation when the *decoded* value can be
canonically re-encoded back into the exact observed string. This strict
round-trip requirement is what prevents similar-looking strings (shared
prefixes, shared suffixes, masks) from being treated as the same secret.

No network access or external verification service is involved: every
transform operates on in-process strings only.
"""
import base64
import binascii
import json
import string
from abc import ABCMeta
from abc import abstractmethod
from typing import Optional
from urllib.parse import quote
from urllib.parse import unquote


class Transform(metaclass=ABCMeta):
    """A single, verifiable decoding step.

    Each transform is deliberately *one-directional* (decode only). Allowing
    both directions on the same set of values would produce trivial cycles
    (decode then re-encode) and would let arbitrarily similar strings forge a
    relationship. A chain therefore only ever moves toward the canonical,
    human-readable form of a secret.
    """

    #: Stable identifier persisted in derivation reports.
    name = ''

    @abstractmethod
    def decode(self, value: str) -> Optional[str]:
        """Return the decoded value, or ``None`` when the relationship cannot
        be verified.

        A return value of ``None`` means "no evidence", never an error: the
        caller simply does not follow this edge.
        """
        raise NotImplementedError

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}()'


class UrlDecodeTransform(Transform):
    """Handles percent-encoding such as ``%2F`` and ``%3D``."""

    name = 'url_decode'

    def decode(self, value: str) -> Optional[str]:
        if '%' not in value:
            return None

        try:
            decoded = unquote(value, errors='strict')
        except UnicodeDecodeError:
            return None

        if decoded == value:
            return None

        # Canonical verification: re-encoding the decoded value with the same
        # quoting policy must reproduce the observed bytes exactly.
        if quote(decoded, safe='') != value:
            return None

        return decoded


class JsonUnescapeTransform(Transform):
    """Handles JSON string escaping such as ``\\u002f`` and ``\\n``."""

    name = 'json_unescape'

    def decode(self, value: str) -> Optional[str]:
        if '\\' not in value:
            return None

        try:
            decoded = json.loads(json.dumps(value))
        except (ValueError, RecursionError):
            return None

        # json.loads needs an actual quoted JSON document; feed the raw
        # observed text through the documented decode path instead.
        try:
            decoded = json.loads(f'"{value}"')
        except (ValueError, RecursionError):
            return None

        if not isinstance(decoded, str) or decoded == value:
            return None

        # Canonical verification: the minimal JSON encoding of the decoded
        # string (without its surrounding quotes) must match the observation.
        if json.dumps(decoded, ensure_ascii=True, separators=(',', ':'))[1:-1] != value:
            if json.dumps(decoded, ensure_ascii=False, separators=(',', ':'))[1:-1] != value:
                return None

        return decoded


class Base64DecodeTransform(Transform):
    """Handles standard Base64 layers, rejecting look-alike collisions."""

    name = 'base64_decode'

    #: Base64 only carries information in groups of four characters.
    _alphabet = set(string.ascii_letters + string.digits + '+/=')
    _printable = set(string.printable)

    def decode(self, value: str) -> Optional[str]:
        if len(value) < 8 or len(value) % 4 != 0:
            return None

        if any(character not in self._alphabet for character in value):
            return None

        try:
            raw = base64.b64decode(value.encode('ascii'), validate=True)
        except (binascii.Error, ValueError):
            return None

        try:
            decoded = raw.decode('utf-8')
        except UnicodeDecodeError:
            return None

        # The decoded payload must be a printable text secret rather than
        # arbitrary bytes that happened to be valid Base64.
        if not decoded or any(character not in self._printable or character in '\r\n\t'
                              for character in decoded):
            return None

        # Canonical verification: re-encoding must reproduce the observation
        # byte for byte, including padding.
        if base64.b64encode(decoded.encode('utf-8')).decode('ascii') != value:
            return None

        return decoded


class HexDecodeTransform(Transform):
    """Handles hexadecimal layers such as ``616263`` -> ``abc``."""

    name = 'hex_decode'

    _printable = set(string.printable)

    def decode(self, value: str) -> Optional[str]:
        if len(value) < 8 or len(value) % 2 != 0:
            return None

        try:
            int(value, 16)
        except ValueError:
            return None

        try:
            decoded = bytes.fromhex(value).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            return None

        if not decoded or any(character not in self._printable or character in '\r\n\t'
                              for character in decoded):
            return None

        if decoded.encode('utf-8').hex().upper() != value.upper():
            return None

        return decoded


#: Ordered registry. The fixed order makes every generated chain deterministic,
#: which is required for stable, repeatable reports.
TRANSFORMS = (
    UrlDecodeTransform(),
    JsonUnescapeTransform(),
    Base64DecodeTransform(),
    HexDecodeTransform(),
)

TRANSFORMS_BY_NAME = {
    transform.name: transform
    for transform in TRANSFORMS
}

#: Maximum number of decoding edges any single derivation chain may contain.
#: Multi-layer encodings are supported, but unbounded search is not: this caps
#: both the work and the surface for accidental cross-secret collisions.
MAX_CHAIN_DEPTH = 3


from dataclasses import dataclass


@dataclass(frozen=True)
class DecodeResult:
    """One verified decoding edge, retained for provenance."""

    transform: str
    decoded: str


def get_transform(name: str) -> Transform:
    try:
        return TRANSFORMS_BY_NAME[name]
    except KeyError:
        raise KeyError(f"unknown transform: {name}")


def decode_once(name: str, value: str) -> Optional[DecodeResult]:
    """Applies one named transform, returning ``None`` when unverifiable."""
    decoded = get_transform(name).decode(value)
    if decoded is None:
        return None
    return DecodeResult(transform=name, decoded=decoded)
