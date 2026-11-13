"""Normalization and conflict handling for SAML entity identifiers.

This module intentionally only depends on the Python standard library so it
can be imported from every layer of the package without introducing import
cycles.
"""

import hashlib
from urllib.parse import parse_qsl
from urllib.parse import quote
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from saml2 import SAMLError


#: Maximum accepted size of a single EntityDescriptor (10 MiB).
DEFAULT_ENTITY_DESCRIPTOR_MAX_SIZE = 10 * 1024 * 1024

_DEFAULT_PORTS = {
    "http": "80",
    "https": "443",
    "ftp": "21",
}

#: Version tag embedded in cache file names so that cache layout changes
#: invalidate entries written by older pysaml2 releases.
ENTITY_CACHE_VERSION = "v2"


class MetadataError(SAMLError):
    """Base class for metadata loading and indexing errors."""


class MissingEntityID(MetadataError):
    """Raised when an EntityDescriptor carries no (usable) entityID."""


class EntityDescriptorTooLarge(MetadataError):
    """Raised when an EntityDescriptor exceeds the configured size limit."""


class DuplicateCertificate(MetadataError):
    """Raised when the same certificate appears more than once for an entity."""


class EntityConflict(MetadataError):
    """Raised when the same normalized entityID maps to different content."""


class ExpiredEntity(MetadataError):
    """Raised (or recorded) for EntityDescriptors past their validUntil."""


def _normalize_percent_encoded(component):
    """Normalize percent-encoding without changing the component semantics.

    Percent-encoded unreserved characters are decoded; every other byte
    sequence, including reserved characters, keeps its encoding.
    """
    unreserved = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    result = []
    index = 0
    while index < len(component):
        char = component[index]
        if char == "%" and index + 2 < len(component):
            hexpart = component[index + 1 : index + 3]
            try:
                byte_value = int(hexpart, 16)
            except ValueError:
                result.append(char)
                index += 1
                continue
            decoded = chr(byte_value)
            if decoded in unreserved:
                result.append(decoded)
            else:
                result.append("%" + hexpart.upper())
            index += 3
        else:
            result.append(char)
            index += 1
    return "".join(result)


def _quote_path(path):
    if not path:
        return ""
    normalized = _normalize_percent_encoded(path)
    # Keep structural slashes and already-valid percent encoding intact.
    return quote(normalized, safe="/%")


def normalize_entity_id(entity_id):
    """Return the canonical comparison form of a SAML entityID.

    URL-like entityIDs get a lower-cased scheme and host, default ports are
    removed, percent-encoding is canonicalized and query parameters are
    sorted. The trailing slash of the path (including the distinction between
    no path and a root path) is preserved so distinct entities never collapse
    into one. Non-URL identifiers such as URNs are returned unchanged.
    """
    if not isinstance(entity_id, str) or not entity_id.strip():
        raise MissingEntityID("entityID must be a non-empty string")

    parts = urlsplit(entity_id)
    if not parts.scheme or not parts.netloc:
        return entity_id

    scheme = parts.scheme.lower()
    hostname = parts.hostname or ""
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise MetadataError(f"Invalid host in entityID '{entity_id}'") from exc
    if ":" in hostname:
        host = f"[{hostname}]"
    else:
        host = hostname

    try:
        port = parts.port
    except ValueError as exc:
        raise MetadataError(f"Invalid port in entityID '{entity_id}'") from exc
    is_default_port = port is not None and str(port) == _DEFAULT_PORTS.get(scheme)
    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo = f"{userinfo}:{parts.password}"
        if port is not None and not is_default_port:
            netloc = f"{userinfo}@{host}:{port}"
        else:
            netloc = f"{userinfo}@{host}"
    elif port is not None and not is_default_port:
        netloc = f"{host}:{port}"
    else:
        netloc = host

    # urlsplit gives "" for an absent path and "/" for the root path; keep
    # that distinction (and any other trailing slash).
    path = _quote_path(parts.path)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    query = urlencode(sorted(query_pairs), doseq=True, quote_via=quote)
    fragment = _normalize_percent_encoded(parts.fragment)

    return urlunsplit((scheme, netloc, path, query, fragment))


def entity_ids_equal(left, right):
    """Compare two entityIDs using the canonical normalization rules."""
    try:
        return normalize_entity_id(left) == normalize_entity_id(right)
    except MissingEntityID:
        return left == right


def entity_id_cache_key(entity_id):
    """Return a filesystem-safe cache key derived from a normalized entityID.

    The raw entityID is never concatenated into a path: only the SHA-256
    digest of its canonical form is used, together with a version prefix that
    allows old cache layouts to be detected and invalidated.
    """
    normalized = normalize_entity_id(entity_id)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"{ENTITY_CACHE_VERSION}-{digest}"
