# vim: set et ai ts=4 sts=4 sw=4:
"""Offline forensics for migrating entries between Java keystores.

The helpers in this module deliberately only inspect public certificate
material.  Private keys are never decrypted and private key bytes are never
included in a :class:`MigrationReport`.

Aliases are treated as labels, not identities.  A certificate identity is the
SHA-256 digest of its DER encoding.  This means that moving one certificate to
a new alias is recognised as a rename, while keeping an alias but replacing the
certificate is recognised as a rotation.

The public entry point is :func:`inspect_migration`::

    report = inspect_migration(sources, usages)

``sources`` may contain paths, byte strings, loaded keystore objects, or
descriptions such as ``{"name": "legacy", "path": "old.jks",
"password": "changeit"}``.  Sources are ordered: earlier sources represent the
older hand-off, later sources the newer one.

``usages`` is the caller supplied purpose inventory.  It can be a mapping of
purposes to aliases and risk levels, a mapping of aliases to purposes, or a
list of records such as::

    [{"purpose": "tls-server",
      "aliases": ["legacy-web", "web"],
      "risk": "high"}]

Damaged or password-unverifiable JKS/JCEKS files are parsed on a best-effort
basis so that certificate hand-offs that are already visible are still
reported.
"""

from __future__ import print_function

import hashlib
import json
import os

from pyasn1.codec.der import decoder
from pyasn1.type import univ
try:
    from pyasn1.type import char
except Exception:
    char = None
from pyasn1_modules import rfc2459

from .jks import (
    KeyStore,
    PrivateKeyEntry,
    TrustedCertEntry,
    MAGIC_NUMBER_JKS,
    MAGIC_NUMBER_JCEKS,
    SIGNATURE_WHITENING,
)
from .bks import BksKeyStore, UberKeyStore
from .util import b2, b4, b8, py23basestring


CHANGE_RENAME = "rename"
CHANGE_ROTATION = "rotation"
KIND_RENAME = CHANGE_RENAME
KIND_ROTATION = CHANGE_ROTATION
RENAME = CHANGE_RENAME
ROTATION = CHANGE_ROTATION

INTEGRITY_VERIFIED = "verified"
INTEGRITY_UNVERIFIED = "unverified"
INTEGRITY_UNKNOWN = "unknown"

_HIGH_RISK_WORDS = frozenset([
    "high", "critical", "severe", "urgent", "elevated", "very_high",
    "very-high", "must", "p0", "p1",
])
_LOW_RISK_WORDS = frozenset([
    "low", "medium", "moderate", "normal", "info", "informational", "none",
    "minor", "p3", "p4",
])
_RISK_KEYS = ("risk", "risk_level", "riskLevel", "severity", "criticality", "level", "impact", "priority", "importance", "sensitivity", "classification")
_HIGH_RISK_KEYS = (
    "high_risk", "high-risk", "highRisk", "is_high_risk", "isHighRisk",
    "critical", "is_critical", "high_risk_usages", "critical_usages",
)
_PURPOSE_KEYS = (
    "purpose", "purposes", "use", "uses", "usage", "usages",
    "intended_use", "intended_usage", "intended_purpose",
)
_ALIAS_KEYS = (
    "aliases", "alias", "key_aliases", "key_alias", "entries", "keys",
)
_SOURCE_KEYS = (
    "sources", "source", "stores", "store", "keystores", "keystore",
)

_SOURCE_META_KEYS = frozenset([
    "name", "label", "id", "path", "filename", "file", "data", "bytes",
    "content", "contents", "raw", "password", "store_password", "storepass",
    "passphrase", "pass", "passwd", "store", "keystore", "store_type", "type",
    "format", "order", "index", "sequence", "position", "optional",
])


class MigrationSource(object):
    """Description of one keystore snapshot.

    :param name: Human readable source name used in the report.
    :param path: Path to a keystore file.
    :param data: Raw keystore bytes (alternative to ``path``).
    :param password: Store password.  It is used only to verify integrity and
      is never copied into the report.
    :param store: An already loaded pyjks keystore object.
    :param order: Optional ordering hint.  Sources without an explicit order
      retain their input order.
    """

    def __init__(self, name=None, path=None, data=None, password=None,
                 store=None, order=None, store_type=None):
        self.name = name
        self.path = path
        self.data = data
        self.password = password
        self.store = store
        self.order = order
        self.store_type = store_type

    @classmethod
    def from_path(cls, path, password=None, name=None, order=None):
        return cls(name=name, path=path, password=password, order=order)

    @classmethod
    def from_bytes(cls, data, password=None, name=None, order=None,
                   store_type=None):
        return cls(name=name, data=data, password=password, order=order,
                   store_type=store_type)

    from_data = from_bytes

    @classmethod
    def from_keystore(cls, store, name=None, order=None):
        return cls(name=name, store=store, order=order)

    def __repr__(self):
        return "MigrationSource(name=%r, path=%r, data=%r)" % (
            self.name, self.path, self.data is not None)


KeystoreSource = MigrationSource


class IdentityMap(dict):
    """Mapping of certificate identities that also accepts SHA-1 lookups.

    Iteration, keys, length and JSON serialization use the canonical SHA-256
    fingerprints.  A caller that computes the older keytool SHA-1 fingerprint
    can still look the same identity up by SHA-1, with or without colons and in
    either case.
    """

    def _find(self, key):
        if not isinstance(key, py23basestring):
            return None
        normalized = str(key).replace(":", "").strip().lower()
        if not normalized:
            return None
        for record in dict.values(self):
            for field in ("sha256", "fingerprint", "sha1"):
                value = record.get(field)
                if value and str(value).replace(":", "").lower() == normalized:
                    return record
        return None

    def __getitem__(self, key):
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            record = self._find(key)
            if record is None:
                raise
            return record

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False


class MigrationReport(dict):
    """Result of :func:`inspect_migration`.

    The object is a normal ``dict`` so it can be serialized directly, and its
    commonly used keys are also available as attributes.
    """

    def __init__(self, sources=None, identities=None, observations=None,
                 handoffs=None, unresolved=None, changes=None, renames=None,
                 rotations=None, warnings=None, errors=None, incomplete=False,
                 usage_bindings=None):
        sources = list(sources or [])
        identities = (identities if isinstance(identities, IdentityMap)
                      else IdentityMap(identities or {}))
        observations = list(observations or [])
        handoffs = list(handoffs or [])
        unresolved = list(unresolved or [])
        changes = list(changes or [])
        renames = list(renames or [])
        rotations = list(rotations or [])
        warnings = list(warnings or [])
        errors = list(errors or [])
        usage_bindings = dict(usage_bindings or {})

        self.sources = sources
        self.identities = identities
        self.observations = observations
        self.handoffs = handoffs
        self.confirmed_handoffs = handoffs
        self.unresolved = unresolved
        self.changes = changes
        self.renames = renames
        self.rotations = rotations
        self.warnings = warnings
        self.errors = errors
        self.incomplete = bool(incomplete)
        self.complete = not bool(incomplete)
        self.usage_bindings = usage_bindings

        dict.__init__(self)
        dict.update(self, {
            "sources": self.sources,
            "identities": self.identities,
            "observations": self.observations,
            "handoffs": self.handoffs,
            "confirmed_handoffs": self.confirmed_handoffs,
            "unresolved": self.unresolved,
            "changes": self.changes,
            "renames": self.renames,
            "rotations": self.rotations,
            "warnings": self.warnings,
            "errors": self.errors,
            "incomplete": self.incomplete,
            "complete": self.complete,
            "usage_bindings": self.usage_bindings,
        })
        dict.__setitem__(self, "summary", self.summary)

    _KEY_ALIASES = {
        "events": "changes",
        "renamed": "renames",
        "rotated": "rotations",
        "rename_changes": "renames",
        "rotation_changes": "rotations",
        "partial": "incomplete",
        "failed_sources": "errors",
        "unresolved_handoffs": "unresolved",
        "by_identity": "identities",
        "certificate_identities": "identities",
        "identities_by_fingerprint": "identities",
        "purpose_bindings": "usage_bindings",
        "usage_map": "usage_bindings",
        "handoff_records": "changes",
        "audit_trail": "changes",
        "handoff": "changes",
    }

    def __getitem__(self, key):
        return dict.__getitem__(self, self._KEY_ALIASES.get(key, key))

    def get(self, key, default=None):
        return dict.get(self, self._KEY_ALIASES.get(key, key), default)

    def __contains__(self, key):
        return dict.__contains__(self, self._KEY_ALIASES.get(key, key))

    @property
    def events(self):
        return self.changes

    @property
    def rename_changes(self):
        return self.renames

    @property
    def renamed(self):
        return self.renames

    @property
    def rotation_changes(self):
        return self.rotations

    @property
    def rotated(self):
        return self.rotations

    @property
    def identity_map(self):
        return self.identities

    @property
    def by_identity(self):
        return self.identities

    @property
    def certificate_identities(self):
        return self.identities

    @property
    def identity_list(self):
        return list(self.identities.values())

    @property
    def identities_list(self):
        return list(self.identities.values())

    @property
    def identities_by_fingerprint(self):
        return self.identities

    @property
    def partial(self):
        return self.incomplete

    @property
    def failed_sources(self):
        return self.errors

    @property
    def issues(self):
        return list(self.warnings) + list(self.errors)

    @property
    def unresolved_handoffs(self):
        return self.unresolved

    @property
    def purpose_bindings(self):
        return self.usage_bindings

    @property
    def by_alias(self):
        result = {}
        for observation in self.observations:
            result.setdefault(observation["alias"], []).append(observation)
        return result

    @property
    def source_map(self):
        return dict((item.get("name"), item) for item in self.sources)

    @property
    def handoff_records(self):
        return self.changes

    @property
    def audit_trail(self):
        return self.changes

    @property
    def handoff(self):
        return self.changes

    @property
    def change_sets(self):
        return {
            CHANGE_RENAME: self.renames,
            CHANGE_ROTATION: self.rotations,
        }

    @property
    def summary(self):
        return {
            "identity_count": len(self.identities),
            "observation_count": len(self.observations),
            "handoff_count": len(self.handoffs),
            "rename_count": len(self.renames),
            "rotation_count": len(self.rotations),
            "change_count": len(self.changes),
            "unresolved_count": len(self.unresolved),
            "warning_count": len(self.warnings),
            "error_count": len(self.errors),
            "incomplete": self.incomplete,
        }

    @property
    def counts(self):
        return self.summary

    def to_dict(self):
        """Return a plain, JSON-serializable dictionary."""
        result = dict(self)
        result["identities"] = dict(self.identities)
        return result

    as_dict = to_dict

    def to_json(self, **kwargs):
        """Return the report as JSON text."""
        return json.dumps(self, **kwargs)

    as_json = to_json
    json = to_json


class _Truncated(Exception):
    """Internal marker used by the best-effort JKS parser."""


def _text(value):
    if isinstance(value, py23basestring):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except Exception:
            return repr(value)
    return str(value)


def _alias_key(alias):
    # Java keystore aliases are case-insensitive.
    return _text(alias).lower()


def _colon_hex(value):
    value = str(value)
    return ":".join(value[index:index + 2]
                     for index in range(0, len(value), 2)).upper()


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _first_key(mapping, keys):
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _looks_like_source_dict(value):
    if not isinstance(value, dict):
        return False
    if not value:
        return False
    keys = set(value.keys())
    if keys.intersection([
        "path", "filepath", "keystore_path", "filename", "file", "data",
        "bytes", "content", "contents", "raw", "store", "keystore",
        "store_password", "storepass", "passphrase", "pass", "passwd",
    ]):
        return True
    return "name" in keys and "password" in keys


def _source_from_dict(value, index, name=None):
    def pick(*keys):
        for key in keys:
            if key in value:
                return value[key]
        return None

    source_name = name or pick("name", "label", "id", "source", "store_name")
    path = pick("path", "filepath", "keystore_path", "filename", "file")
    data = pick("data", "bytes", "content", "contents", "raw")
    password = pick("password", "store_password", "storepass",
                    "passphrase", "pass", "passwd")
    store = pick("store", "keystore", "loaded_store")
    if store is not None and (
            isinstance(store, (bytes, bytearray, py23basestring))
            or hasattr(store, "__fspath__")):
        if path is None:
            path = store
        store = None
    store_type = pick("store_type", "type", "format")
    if isinstance(store_type, py23basestring):
        store_type = store_type.lower()
    order = pick("order", "index", "sequence", "position")
    if source_name is None and path is not None:
        source_name = os.path.basename(_text(path))
    if source_name is None:
        source_name = "source-%d" % (index + 1)
    return MigrationSource(
        name=_text(source_name), path=path, data=data, password=password,
        store=store, order=order, store_type=store_type,
    )


def _looks_like_path(value):
    if not isinstance(value, py23basestring):
        return False
    text = _text(value)
    if os.path.sep in text or (os.path.altsep and os.path.altsep in text):
        return True
    if text.lower().endswith((".jks", ".jceks", ".bks", ".uber")):
        return True
    try:
        return os.path.exists(text)
    except Exception:
        return False


def _source_from_tuple(value, index):
    items = list(value)
    if not items:
        raise ValueError("Empty keystore source description")
    if len(items) == 1:
        return _source_from_value(items[0], index)
    if len(items) == 2:
        first, second = items
        if isinstance(first, py23basestring) and (
                second is None or isinstance(second, py23basestring)):
            if (_looks_like_path(second) and not _looks_like_path(first)):
                return MigrationSource(
                    name=_text(first), path=second, order=index,
                )
            return MigrationSource(
                name=os.path.basename(_text(first)), path=first,
                password=second, order=index,
            )
        return MigrationSource(
            name=_text(first), data=second, order=index,
        )
    if len(items) >= 3:
        first, second, third = items[0], items[1], items[2]
        if isinstance(second, dict):
            source = _source_from_dict(second, index, name=_text(first))
            source.order = third
            return source
        if isinstance(first, py23basestring) and (
                isinstance(second, py23basestring) or second is None):
            return MigrationSource(
                name=_text(first), path=second, password=third, order=index,
            )
        return MigrationSource(
            name=_text(first), data=second, password=third, order=index,
        )
    raise ValueError("Unsupported keystore source description")


def _source_from_value(value, index, name=None, password=None):
    if isinstance(value, MigrationSource):
        if name is not None and value.name is None:
            value.name = name
        if password is not None and value.password is None:
            value.password = password
        return value
    if isinstance(value, (KeyStore, BksKeyStore, UberKeyStore)):
        return MigrationSource(
            name=name or "source-%d" % (index + 1),
            store=value, order=index,
        )
    if isinstance(value, dict):
        source = _source_from_dict(value, index, name=name)
        if password is not None and source.password is None:
            source.password = password
        return source
    if isinstance(value, (tuple, list)):
        return _source_from_tuple(value, index)
    if hasattr(value, "__fspath__"):
        path = os.fspath(value)
        return MigrationSource(
            name=name or os.path.basename(_text(path)), path=path,
            password=password, order=index,
        )
    if isinstance(value, (bytes, bytearray, memoryview)):
        return MigrationSource(
            name=name or "source-%d" % (index + 1),
            data=bytes(value), password=password, order=index,
        )
    if isinstance(value, py23basestring):
        return MigrationSource(
            name=name or os.path.basename(value), path=value,
            password=password, order=index,
        )
    if hasattr(value, "read"):
        return MigrationSource(
            name=name or "source-%d" % (index + 1),
            data=value.read(), password=password, order=index,
        )
    if any(hasattr(value, attribute)
           for attribute in ("path", "data", "store", "password")):
        return MigrationSource(
            name=name or getattr(value, "name", None),
            path=getattr(value, "path", None),
            data=getattr(value, "data", None),
            password=(password if password is not None
                      else getattr(value, "password", None)),
            store=getattr(value, "store", None),
            order=(getattr(value, "order", None)
                   if getattr(value, "order", None) is not None else index),
            store_type=getattr(value, "store_type", None),
        )
    raise ValueError("Unsupported keystore source: %r" % (value,))


def _coerce_sources(sources, passwords=None):
    if sources is None:
        return []
    if isinstance(sources, MigrationSource):
        return [sources]
    if isinstance(sources, dict):
        if _looks_like_source_dict(sources):
            return [_source_from_dict(sources, 0)]
        result = []
        for index, item in enumerate(sources.items()):
            name, spec = item
            password = None
            if passwords is not None:
                password = _password_for(passwords, index, name=name)
            if isinstance(spec, dict):
                source = _source_from_dict(spec, index, name=_text(name))
                if password is not None and source.password is None:
                    source.password = password
                result.append(source)
            else:
                result.append(_source_from_value(
                    spec, index, name=_text(name), password=password))
        return result
    if isinstance(sources, (bytes, bytearray, py23basestring)):
        return [_source_from_value(sources, 0)]
    if hasattr(sources, "read"):
        return [_source_from_value(sources, 0)]
    try:
        ordered = list(sources)
    except TypeError:
        return [_source_from_value(sources, 0)]
    result = []
    for index, item in enumerate(ordered):
        name = None
        if isinstance(item, dict):
            name = (item.get("name") or item.get("label") or item.get("id"))
        elif isinstance(item, MigrationSource):
            name = item.name
        elif isinstance(item, py23basestring):
            name = os.path.basename(_text(item))
        password = (_password_for(passwords, index, name=name)
                    if passwords is not None else None)
        result.append(_source_from_value(item, index, password=password))
    return result


def _password_for(passwords, index, name=None):
    if isinstance(passwords, dict):
        if name is not None and name in passwords:
            return passwords[name]
        if index in passwords:
            return passwords[index]
        if str(index) in passwords:
            return passwords[str(index)]
        return None
    if isinstance(passwords, (list, tuple)):
        if index < len(passwords):
            return passwords[index]
        return None
    return passwords


def _read_bounded_data(data, pos):
    if pos + 4 > len(data):
        raise _Truncated("missing data length")
    size = b4.unpack_from(data, pos)[0]
    pos += 4
    if size < 0 or pos + size > len(data):
        raise _Truncated("entry data extends past end of file")
    return data[pos:pos + size], pos + size


def _read_bounded_utf(data, pos, kind="text"):
    if pos + 2 > len(data):
        raise _Truncated("missing %s length" % kind)
    size = b2.unpack_from(data, pos)[0]
    pos += 2
    if pos + size > len(data):
        raise _Truncated("%s extends past end of file" % kind)
    try:
        return data[pos:pos + size].decode("utf-8"), pos + size
    except UnicodeDecodeError as exc:
        raise _Truncated("invalid UTF-8 in %s: %s" % (kind, exc))


def _read_bounded_private_key(data, pos, store_type):
    encrypted, pos = _read_bounded_data(data, pos)
    if pos + 4 > len(data):
        raise _Truncated("missing certificate chain length")
    chain_len = b4.unpack_from(data, pos)[0]
    pos += 4
    if chain_len > 10000:
        raise _Truncated("implausible certificate chain length")
    chain = []
    for unused in range(chain_len):
        cert_type, pos = _read_bounded_utf(data, pos, "certificate type")
        cert_data, pos = _read_bounded_data(data, pos)
        chain.append((cert_type, cert_data))
    return PrivateKeyEntry(
        cert_chain=chain, encrypted=encrypted, store_type=store_type), pos


def _read_bounded_trusted_cert(data, pos, store_type):
    cert_type, pos = _read_bounded_utf(data, pos, "certificate type")
    cert_data, pos = _read_bounded_data(data, pos)
    return TrustedCertEntry(
        type=cert_type, cert=cert_data, store_type=store_type), pos


def _parse_jks_tolerant(data, password, store_type):
    """Parse as many complete JKS/JCEKS entries as possible.

    The normal pyjks loader is intentionally strict about signatures and
    truncation.  Migration forensics needs a different trade-off: never make a
    claim based on a partial entry, but keep complete entries that were already
    recovered.
    """
    if len(data) < 12:
        raise _Truncated("not enough bytes for a keystore header")
    if b4.unpack_from(data, 8)[0] > 100000:
        raise _Truncated("implausible entry count")

    entry_count = b4.unpack_from(data, 8)[0]
    entries = {}
    alias_keys_seen = set()
    display_keys_seen = set()
    warnings = []
    pos = 12
    recovered = 0
    stopped = None

    for index in range(entry_count):
        start = pos
        try:
            if pos + 4 > len(data):
                raise _Truncated("missing entry tag")
            tag = b4.unpack_from(data, pos)[0]
            pos += 4
            alias, pos = _read_bounded_utf(data, pos, "entry alias")
            if pos + 8 > len(data):
                raise _Truncated("missing entry timestamp")
            timestamp = int(b8.unpack_from(data, pos)[0])
            pos += 8

            if tag == 1:
                entry, pos = _read_bounded_private_key(data, pos, store_type)
            elif tag == 2:
                entry, pos = _read_bounded_trusted_cert(data, pos, store_type)
            elif tag == 3 and store_type == "jceks":
                entry, pos = KeyStore._read_secret_key(data, pos, store_type)
                if pos > len(data):
                    raise _Truncated("secret key entry extends past end of file")
            else:
                raise _Truncated("unknown entry tag %d" % tag)

            entry.alias = alias
            entry.timestamp = timestamp
            entry.store_type = store_type

            key = _alias_key(alias)
            display_key = alias
            if key in alias_keys_seen:
                suffix = 2
                while (_alias_key(display_key) in alias_keys_seen
                       or _alias_key(display_key) in display_keys_seen):
                    display_key = "%s#%d" % (alias, suffix)
                    suffix += 1
                warnings.append({
                    "kind": "duplicate_alias",
                    "alias": alias,
                    "message": "preserved duplicate alias %r as %r" % (
                        alias, display_key),
                })
            alias_keys_seen.add(key)
            display_keys_seen.add(_alias_key(display_key))
            entries[display_key] = entry
            recovered += 1
        except Exception as exc:
            pos = start
            stopped = _text(exc)
            break

    integrity = INTEGRITY_UNKNOWN
    if password is not None:
        hash_size = hashlib.sha1().digest_size
        if pos + hash_size <= len(data):
            expected = hashlib.sha1(
                password.encode("utf-16be") + SIGNATURE_WHITENING + data[:pos]
            ).digest()
            integrity = (INTEGRITY_VERIFIED
                         if expected == data[pos:pos + hash_size]
                         else INTEGRITY_UNVERIFIED)
        else:
            integrity = INTEGRITY_UNVERIFIED

    if stopped is not None or recovered < entry_count:
        warnings.append({
            "kind": "partial_keystore",
            "recovered_entries": recovered,
            "expected_entries": entry_count,
            "message": "recovered %d of %d entries from an incomplete or malformed keystore" % (
                recovered, entry_count),
            "detail": stopped,
        })
    if integrity == INTEGRITY_UNVERIFIED:
        warnings.append({
            "kind": "integrity_unverified",
            "message": "keystore signature could not be verified; only complete parsed entries were used",
        })

    return KeyStore(store_type, entries), integrity, warnings


def _load_store_bytes(data, password, store_type=None, salvage=True):
    if isinstance(store_type, py23basestring):
        store_type = store_type.lower()
    magic = data[:4]
    if store_type is None:
        if magic in (MAGIC_NUMBER_JKS, MAGIC_NUMBER_JCEKS):
            store_type = "jks" if magic == MAGIC_NUMBER_JKS else "jceks"

    if store_type in ("jks", "jceks", None):
        if store_type is not None or magic in (MAGIC_NUMBER_JKS, MAGIC_NUMBER_JCEKS):
            try:
                store = KeyStore.loads(
                    data, password, try_decrypt_keys=False)
                integrity = (INTEGRITY_UNKNOWN if password is None
                             else INTEGRITY_VERIFIED)
                return store, integrity, []
            except Exception:
                if not salvage or magic not in (
                        MAGIC_NUMBER_JKS, MAGIC_NUMBER_JCEKS):
                    raise
                store_type = "jks" if magic == MAGIC_NUMBER_JKS else "jceks"
                store, integrity, warnings = _parse_jks_tolerant(
                    data, password, store_type)
                if not store.entries and warnings:
                    # An empty salvage result is only useful if the file truly
                    # was an empty store.
                    expected = b4.unpack_from(data, 8)[0] if len(data) >= 12 else 0
                    if expected:
                        raise
                return store, integrity, warnings

    errors = []
    loaders = []
    if store_type in (None, "bks"):
        loaders.append(("bks", BksKeyStore))
    if store_type in (None, "uber"):
        loaders.append(("uber", UberKeyStore))
    for label, loader in loaders:
        try:
            store = loader.loads(data, password, try_decrypt_keys=False)
            integrity = (INTEGRITY_UNKNOWN if password is None
                         else INTEGRITY_VERIFIED)
            return store, integrity, []
        except Exception as exc:
            errors.append("%s: %s" % (label, exc))
    raise ValueError("; ".join(errors) or "unsupported keystore format")


def _load_source(source, salvage=True):
    if source.store is not None:
        return source.store, INTEGRITY_UNKNOWN, []
    data = source.data
    if data is None:
        with open(source.path, "rb") as file:
            data = file.read()
    elif hasattr(data, "read"):
        data = data.read()
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    password = source.password
    if isinstance(password, (bytes, bytearray)):
        try:
            password = bytes(password).decode("utf-8")
        except Exception:
            password = bytes(password).decode("latin-1")
    return _load_store_bytes(
        data, password, store_type=source.store_type,
        salvage=salvage)


def _decode_asn1_string(value):
    try:
        raw = value.asOctets()
    except Exception:
        return _text(value)
    if char is not None:
        specs = (
            char.UTF8String(), char.PrintableString(), char.TeletexString(),
            char.IA5String(), char.BMPString(), char.UniversalString(),
        )
    else:
        specs = (
            univ.UTF8String(), univ.PrintableString(), univ.TeletexString(),
            univ.IA5String(), univ.BMPString(), univ.UniversalString(),
        )
    for spec in specs:
        try:
            return _text(decoder.decode(raw, asn1Spec=spec)[0])
        except Exception:
            continue
    try:
        return raw.decode("utf-8")
    except Exception:
        return _text(value)


def _name_to_text(name):
    parts = []
    try:
        rdns = name.getComponent()
    except Exception:
        return None
    for rdn in rdns:
        values = []
        try:
            avas = list(rdn)
        except Exception:
            avas = [rdn]
        for ava in avas:
            try:
                oid = ava["type"]
                label = {
                    "2.5.4.3": "CN",
                    "2.5.4.6": "C",
                    "2.5.4.7": "L",
                    "2.5.4.8": "ST",
                    "2.5.4.10": "O",
                    "2.5.4.11": "OU",
                    "1.2.840.113549.1.9.1": "emailAddress",
                }.get(".".join(str(x) for x in oid.asTuple()), ".".join(
                    str(x) for x in oid.asTuple()))
                values.append("%s=%s" % (label, _decode_asn1_string(ava["value"])))
            except Exception:
                continue
        if values:
            parts.append("+".join(values))
    return ", ".join(parts) if parts else None


def _time_to_text(time_choice):
    try:
        name = time_choice.getName()
        if name in ("utcTime", "generalTime"):
            return str(time_choice.getComponent())
        return str(time_choice)
    except Exception:
        return None


def _certificate_metadata(der):
    metadata = {
        "subject": None,
        "issuer": None,
        "serial_number": None,
        "serial_hex": None,
        "not_before": None,
        "not_after": None,
        "public_key_algorithm": None,
        "public_key_sha256": None,
    }
    try:
        cert = decoder.decode(der, asn1Spec=rfc2459.Certificate())[0]
        tbs = cert["tbsCertificate"]
        try:
            serial = int(tbs["serialNumber"])
            metadata["serial_number"] = serial
            metadata["serial_hex"] = "%x" % serial
        except Exception:
            pass
        metadata["subject"] = _name_to_text(tbs["subject"])
        metadata["issuer"] = _name_to_text(tbs["issuer"])
        validity = tbs["validity"]
        metadata["not_before"] = _time_to_text(validity["notBefore"])
        metadata["not_after"] = _time_to_text(validity["notAfter"])
        spki = tbs["subjectPublicKeyInfo"]
        algorithm = spki["algorithm"]["algorithm"]
        metadata["public_key_algorithm"] = ".".join(
            str(x) for x in algorithm.asTuple())
        try:
            key_bits = spki["subjectPublicKey"].asOctets()
            metadata["public_key_sha256"] = hashlib.sha256(key_bits).hexdigest()
        except Exception:
            pass
    except Exception:
        pass
    return metadata


def _observation_for_certificate(source, source_index, alias, entry,
                                 cert_type, der):
    sha256 = hashlib.sha256(der).hexdigest()
    sha1 = hashlib.sha1(der).hexdigest()
    metadata = _certificate_metadata(der)
    observation = {
        "source": _text(source.name),
        "source_index": source_index,
        "source_order": source.order,
        "alias": _text(alias),
        "entry_type": _entry_type(entry),
        "cert_type": _text(cert_type),
        "identity": sha256,
        "fingerprint": sha256,
        "sha256": sha256,
        "sha1": sha1,
        "fingerprint_sha256": sha256,
        "fingerprint_sha1": sha1,
        "certificate_sha256": sha256,
        "certificate_sha1": sha1,
        "sha256_colon": _colon_hex(sha256),
        "fingerprint_colon": _colon_hex(sha256),
        "purposes": set(),
        "high_risk_usages": set(),
    }
    observation.update(metadata)
    observation["certificate"] = {
        "subject": metadata.get("subject"),
        "issuer": metadata.get("issuer"),
        "serial_number": metadata.get("serial_number"),
        "serial_hex": metadata.get("serial_hex"),
        "not_before": metadata.get("not_before"),
        "not_after": metadata.get("not_after"),
        "public_key_algorithm": metadata.get("public_key_algorithm"),
        "public_key_sha256": metadata.get("public_key_sha256"),
        "sha256": sha256,
        "sha1": sha1,
    }
    return observation


def _entry_type(entry):
    if isinstance(entry, TrustedCertEntry):
        return "trusted_cert"
    if isinstance(entry, PrivateKeyEntry):
        return "private_key"
    name = entry.__class__.__name__
    if name == "SecretKeyEntry":
        return "secret_key"
    if name == "BksKeyEntry":
        return "bks_key"
    if name == "BksSealedKeyEntry":
        return "sealed_key"
    if name == "BksSecretKeyEntry":
        return "secret_key"
    return name


def _certificate_material(item):
    """Return (certificate type, DER bytes) for a chain item.

    JKS/JCEKS store chains as (type, bytes) tuples.  BKS and UBER store them
    as TrustedCertEntry-like objects.
    """
    if isinstance(item, (tuple, list)) and len(item) >= 2:
        return _text(item[0]), item[1]
    cert = getattr(item, "cert", None)
    if cert is not None:
        return _text(getattr(item, "type", None) or "X.509"), cert
    return None, None


def _extract_observations(store, source, source_index):
    observations = []
    unresolved = []
    warnings = []
    for alias in sorted(store.entries):
        entry = store.entries[alias]
        display_alias = getattr(entry, "alias", None) or alias
        # Read the attribute from the instance dictionary rather than through
        # getattr(): encrypted SecretKeyEntry instances deliberately raise
        # NotYetDecryptedException from __getattr__ for unknown attributes.
        # We only want the public certificate chain, never key material.
        chain = entry.__dict__.get("cert_chain") or []
        if chain:
            cert_type, der = _certificate_material(chain[0])
            if der is not None:
                observation = _observation_for_certificate(
                    source, source_index, display_alias, entry, cert_type, der)
                observation["chain"] = []
                for item in chain:
                    item_type, item_der = _certificate_material(item)
                    if item_der is None:
                        continue
                    observation["chain"].append({
                        "type": item_type,
                        "sha256": hashlib.sha256(item_der).hexdigest(),
                        "sha1": hashlib.sha1(item_der).hexdigest(),
                    })
                observations.append(observation)
                continue

        if isinstance(entry, TrustedCertEntry) and entry.cert is not None:
            observation = _observation_for_certificate(
                source, source_index, display_alias, entry,
                entry.type, entry.cert)
            observation["chain"] = [{
                "type": _text(entry.type or "X.509"),
                "sha256": observation["sha256"],
                "sha1": observation["sha1"],
            }]
            observations.append(observation)
            continue

        item = {
            "source": _text(source.name),
            "source_index": source_index,
            "source_order": source.order,
            "alias": _text(display_alias),
            "entry_type": _entry_type(entry),
            "identity": None,
            "fingerprint": None,
            "purposes": [],
            "high_risk_usages": [],
            "reason": "no public certificate material is present",
        }
        unresolved.append(item)
        warnings.append({
            "kind": "missing_certificate",
            "source": source.name,
            "alias": alias,
            "message": "entry %r has no public certificate material" % alias,
        })
    return observations, unresolved, warnings


def _truthy(value):
    if isinstance(value, py23basestring):
        return value.strip().lower() not in (
            "", "false", "no", "n", "0", "none", "off")
    return bool(value)


def _risk_word(value):
    if isinstance(value, py23basestring):
        return value.strip().lower().replace(" ", "_")
    return None


def _risk_info(mapping):
    high_risk = None
    for key in _HIGH_RISK_KEYS:
        if key in mapping:
            high_risk = _truthy(mapping[key])
            break
    if high_risk is None:
        for key in _RISK_KEYS:
            if key in mapping:
                value = mapping[key]
                if isinstance(value, bool):
                    high_risk = value
                    return value, high_risk
                if isinstance(value, (int, float)):
                    high_risk = value >= 4
                    return ("high" if high_risk else "low"), high_risk
                if isinstance(value, py23basestring) and _risk_word(value) not in (
                        _HIGH_RISK_WORDS | _LOW_RISK_WORDS):
                    return _risk_word(value), _truthy(value)
                word = _risk_word(value)
                if word in _HIGH_RISK_WORDS:
                    high_risk = True
                elif word in _LOW_RISK_WORDS:
                    high_risk = False
                return word, high_risk
    risk = None
    for key in _RISK_KEYS:
        if key in mapping:
            risk = _risk_word(mapping[key])
            break
    if risk is None and mapping:
        words = [_risk_word(item) for item in mapping.values()]
        words = [word for word in words if word is not None]
        if words and all(word in _HIGH_RISK_WORDS or word in _LOW_RISK_WORDS
                         for word in words):
            if any(word in _HIGH_RISK_WORDS for word in words):
                risk, high_risk = "high", True
            else:
                risk, high_risk = "low", False
    return risk, high_risk


def _is_alias_risk_map(value):
    if not isinstance(value, dict) or not value:
        return False
    metadata_keys = set(_ALIAS_KEYS + _RISK_KEYS + _HIGH_RISK_KEYS
                        + _PURPOSE_KEYS + _SOURCE_KEYS)
    if any(key in metadata_keys for key in value):
        return False
    risk_items = 0
    for item in value.values():
        if isinstance(item, bool):
            risk_items += 1
            continue
        word = _risk_word(item)
        if word in _HIGH_RISK_WORDS or word in _LOW_RISK_WORDS:
            risk_items += 1
    return risk_items == len(value)


def _record_aliases(value):
    aliases = []
    if value is None:
        return aliases
    if isinstance(value, dict):
        for alias_key in _ALIAS_KEYS:
            if alias_key in value:
                return _record_aliases(value[alias_key])
        if value and all(
                isinstance(item, bool)
                or _risk_word(item) in _HIGH_RISK_WORDS
                or _risk_word(item) in _LOW_RISK_WORDS
                for item in value.values()):
            return [_text(key) for key in value.keys()]
        for key, item in value.items():
            if isinstance(item, dict):
                alias = item.get("alias")
                if alias is not None:
                    aliases.append(_text(alias))
                elif item.get("name") is not None:
                    aliases.append(_text(item["name"]))
                elif isinstance(key, py23basestring):
                    aliases.append(_text(key))
            elif isinstance(item, (list, tuple, set)):
                for sub in item:
                    if isinstance(sub, py23basestring):
                        aliases.append(_text(sub))
            else:
                key_text = _text(key)
                item_text = _text(item)
                key_lower = key_text.lower()
                if key_lower in _RISK_KEYS or key_lower in _HIGH_RISK_KEYS:
                    continue
                if key_lower in (
                        "purpose", "purposes", "use", "uses", "usage",
                        "usages", "source", "sources", "store", "stores",
                        "name", "id", "label"):
                    continue
                if key_lower in (
                        "old", "new", "before", "after", "from", "to",
                        "current", "previous"):
                    aliases.append(item_text)
                else:
                    aliases.append(key_text)
                    if item_text and item_text != key_text:
                        aliases.append(item_text)
        return aliases
    for item in _as_list(value):
        if isinstance(item, dict):
            alias = item.get("alias", item.get("name"))
            if alias is not None:
                aliases.append(_text(alias))
        elif isinstance(item, (tuple, list)) and len(item) >= 2:
            aliases.append(_text(item[-1]))
        else:
            aliases.append(_text(item))
    return aliases


def _record_sources(value):
    if value is None:
        return []
    if isinstance(value, dict):
        for source_key in _SOURCE_KEYS:
            if source_key in value:
                return _record_sources(value[source_key])
        return [_text(item) for item in value.keys()]
    return [_text(item) for item in _as_list(value)]


def _make_usage_record(purpose, aliases=None, sources=None, risk=None,
                       high_risk=None, match_all=False):
    aliases = [a for a in _as_list(aliases) if a is not None]
    sources = [s for s in _as_list(sources) if s is not None]
    if isinstance(risk, bool):
        if high_risk is None:
            high_risk = risk
        risk = "high" if risk else "low"
    if isinstance(high_risk, py23basestring):
        high_risk = _truthy(high_risk)
    risk_explicit = high_risk is not None or risk is not None
    if high_risk is None:
        high_risk = risk in _HIGH_RISK_WORDS if risk else True
    return {
        "purpose": _text(purpose),
        "aliases": aliases,
        "alias_keys": set(_alias_key(a) for a in aliases),
        "sources": set(_text(s) for s in sources),
        "risk": risk,
        "high_risk": bool(high_risk),
        "risk_explicit": bool(risk_explicit),
        "match_all": bool(match_all),
        "matched": 0,
    }


def _usage_records_from_record(mapping):
    purpose_values = []
    for key in _PURPOSE_KEYS:
        if key in mapping:
            value = mapping[key]
            purpose_values = [_text(item) for item in _as_list(value)]
            break
    if not purpose_values:
        return []
    aliases = _record_aliases(_first_key(mapping, _ALIAS_KEYS))
    sources = _record_sources(_first_key(mapping, _SOURCE_KEYS))
    risk, high_risk = _risk_info(mapping)
    return [
        _make_usage_record(
            purpose, aliases=aliases, sources=sources, risk=risk,
            high_risk=high_risk)
        for purpose in purpose_values
    ]


def _is_usage_record(mapping):
    if not isinstance(mapping, dict):
        return False
    if any(key in mapping for key in _ALIAS_KEYS + _SOURCE_KEYS + _RISK_KEYS
           + _HIGH_RISK_KEYS):
        return True
    return any(key in mapping for key in _PURPOSE_KEYS)


def _usage_records_from_mapping(mapping, known_aliases, known_sources):
    # A common shape is {source: {alias: [purposes]}}.
    nested_ok = bool(mapping)
    for value in mapping.values():
        if not isinstance(value, dict) or _is_usage_record(value):
            nested_ok = False
            break
    if nested_ok:
        keys = [_text(key) for key in mapping]
        sourceish = set([
            "old", "new", "before", "after", "previous", "current",
            "source", "store", "legacy", "original",
        ])
        if (not all(key in known_sources for key in keys)
                and not any(key.lower() in sourceish for key in keys)):
            nested_ok = False
    if nested_ok:
            records = []
            for source, alias_map in mapping.items():
                for alias, purposes in alias_map.items():
                    for purpose in _as_list(purposes):
                        risk = None
                        high_risk = None
                        if isinstance(purpose, dict):
                            purpose, risk, high_risk = (
                                _purpose_from_item(purpose))
                        if purpose is None:
                            continue
                        records.append(_make_usage_record(
                            purpose, aliases=[alias], sources=[source],
                            risk=risk, high_risk=high_risk))
            return records

    records = []
    for key, value in mapping.items():
        if isinstance(key, tuple) and len(key) >= 2:
            source, alias = key[-2], key[-1]
            for purpose in _as_list(value):
                records.append(_make_usage_record(
                    purpose, aliases=[alias], sources=[source]))
            continue

        key_text = _text(key)
        key_lower = key_text.lower()
        if key_lower in _RISK_KEYS or key_lower in _HIGH_RISK_KEYS:
            continue
        if ":" in key_text:
            prefix, alias = key_text.split(":", 1)
            values = _as_list(value)
            if prefix in known_sources or (
                    prefix and alias and values and all(
                        isinstance(item, (dict, list, tuple, set))
                        or isinstance(item, py23basestring)
                        for item in values)):
                for purpose in values:
                    if isinstance(purpose, dict):
                        purpose, risk, high_risk = _purpose_from_item(purpose)
                    else:
                        risk, high_risk = None, None
                    if purpose is None:
                        continue
                    records.append(_make_usage_record(
                        purpose, aliases=[alias], sources=[prefix],
                        risk=risk, high_risk=high_risk))
                continue

        key_is_alias = key_lower in known_aliases
        if _is_usage_record(value):
            purpose_values = []
            for purpose_key in _PURPOSE_KEYS:
                if purpose_key in value:
                    purpose_values = _as_list(value[purpose_key])
                    break
            if purpose_values:
                aliases = _record_aliases(
                    _first_key(value, _ALIAS_KEYS))
                sources = _record_sources(
                    _first_key(value, _SOURCE_KEYS))
                risk, high_risk = _risk_info(value)
                if key_is_alias:
                    aliases.append(key_text)
                elif not aliases:
                    pass
                else:
                    # A purpose key with an explicit alias list is the normal
                    # purpose-centric record shape.
                    pass
                if not aliases and not key_is_alias:
                    aliases = []
                for purpose in purpose_values:
                    records.append(_make_usage_record(
                        purpose, aliases=aliases, sources=sources, risk=risk,
                        high_risk=high_risk))
                continue
            # The key is the purpose.  An alias that happens to have the
            # same spelling must not hijack the purpose-centric record.
            aliases = _record_aliases(value)
            risk, high_risk = _risk_info(value)
            records.append(_make_usage_record(
                key_text, aliases=aliases, risk=risk, high_risk=high_risk))
            continue

        if isinstance(value, bool):
            records.append(_make_usage_record(
                key_text, high_risk=value))
            continue

        if isinstance(value, py23basestring):
            word = _risk_word(value)
            if word in _HIGH_RISK_WORDS or word in _LOW_RISK_WORDS:
                records.append(_make_usage_record(
                    key_text, risk=word,
                    high_risk=word in _HIGH_RISK_WORDS))
            elif key_is_alias:
                records.append(_make_usage_record(
                    value, aliases=[key_text]))
            elif word in known_aliases:
                records.append(_make_usage_record(
                    key_text, aliases=[value]))
            else:
                records.append(_make_usage_record(
                    key_text, aliases=[value]))
            continue

        if isinstance(value, dict):
            if _is_alias_risk_map(value):
                for inner, item in value.items():
                    if isinstance(item, bool):
                        risk, high_risk = ("high" if item else "low", item)
                    else:
                        word = _risk_word(item)
                        risk = word
                        high_risk = word in _HIGH_RISK_WORDS
                    if key_is_alias:
                        records.append(_make_usage_record(
                            inner, aliases=[key_text], risk=risk,
                            high_risk=high_risk))
                    else:
                        records.append(_make_usage_record(
                            key_text, aliases=[inner], risk=risk,
                            high_risk=high_risk))
                continue
            aliases = _record_aliases(value)
            risk, high_risk = _risk_info(value)
            records.append(_make_usage_record(
                key_text, aliases=aliases, risk=risk,
                high_risk=high_risk))
            continue

        if isinstance(value, (list, tuple, set)):
            values = list(value)
            if key_is_alias and not all(
                    _text(item) in known_aliases for item in values):
                for purpose in values:
                    risk = None
                    high_risk = None
                    if isinstance(purpose, dict):
                        purpose, risk, high_risk = _purpose_from_item(purpose)
                    if purpose is not None:
                        records.append(_make_usage_record(
                            purpose, aliases=[key_text], risk=risk,
                            high_risk=high_risk))
            else:
                aliases = []
                for item in values:
                    risk = None
                    high_risk = None
                    if isinstance(item, dict):
                        aliases.extend(_record_aliases(
                            item.get("aliases", item.get("alias"))))
                        risk, high_risk = _risk_info(item)
                    else:
                        aliases.append(_text(item))
                records.append(_make_usage_record(
                    key_text, aliases=aliases, risk=risk,
                    high_risk=high_risk))
            continue

        records.append(_make_usage_record(key_text, match_all=True))
    return records


def _purpose_from_item(item):
    if isinstance(item, dict):
        purpose = None
        for key in _PURPOSE_KEYS:
            if key in item:
                purpose = item[key]
                break
        if purpose is None:
            purpose = item.get("name", item.get("id"))
        risk, high_risk = _risk_info(item)
        return (_text(purpose) if purpose is not None else None,
                risk, high_risk)
    return (_text(item), None, None)


def _usage_records_from_item(item, known_aliases, known_sources):
    if isinstance(item, dict):
        if _is_usage_record(item):
            records = _usage_records_from_record(item)
            if records:
                return records
        return _usage_records_from_mapping(item, known_aliases, known_sources)
    if isinstance(item, (tuple, list)):
        values = list(item)
        if (len(values) == 2 and isinstance(values[0], (tuple, list))
                and len(values[0]) == 2):
            source, alias = values[0]
            records = []
            for purpose in _as_list(values[1]):
                records.append(_make_usage_record(
                    purpose, aliases=[alias], sources=[source]))
            return records
        if len(values) >= 3:
            first, second, third = values[0], values[1], values[2]
            risk = _risk_word(third)
            first_is_alias = (
                isinstance(first, py23basestring)
                and _text(first).lower() in known_aliases)
            second_is_alias = (
                isinstance(second, py23basestring)
                and _text(second).lower() in known_aliases)
            if first_is_alias and not second_is_alias:
                return [_make_usage_record(
                    second, aliases=[first], risk=risk,
                    high_risk=risk in _HIGH_RISK_WORDS)]
            purpose = first
            aliases = _record_aliases(second)
            return [_make_usage_record(
                purpose, aliases=aliases, risk=risk,
                high_risk=risk in _HIGH_RISK_WORDS)]
        if len(values) == 2:
            first, second = values
            first_is_alias = (
                isinstance(first, py23basestring)
                and _text(first).lower() in known_aliases)
            second_is_alias = (
                isinstance(second, py23basestring)
                and _text(second).lower() in known_aliases)
            if first_is_alias and not second_is_alias:
                return [_make_usage_record(second, aliases=[first])]
            purpose = first
            aliases = _record_aliases(second)
            return [_make_usage_record(purpose, aliases=aliases)]
    return [_make_usage_record(item, match_all=True)]


def _normalize_usages(usages, observations, high_risk_usages=None):
    known_aliases = set(_alias_key(obs["alias"]) for obs in observations)
    known_sources = set(_text(obs["source"]) for obs in observations)
    records = []

    if isinstance(usages, (bytes, bytearray)):
        try:
            usages = json.loads(bytes(usages).decode("utf-8"))
        except Exception:
            pass
    elif (isinstance(usages, py23basestring)
          and os.path.isfile(_text(usages))):
        try:
            with open(_text(usages), "r") as usage_file:
                usages = json.load(usage_file)
        except Exception:
            pass

    if usages is not None:
        if isinstance(usages, dict):
            if _is_usage_record(usages) and any(
                    key in usages for key in _PURPOSE_KEYS):
                records.extend(_usage_records_from_record(usages))
            else:
                records.extend(_usage_records_from_mapping(
                    usages, known_aliases, known_sources))
        elif isinstance(usages, (list, tuple, set)):
            for item in usages:
                records.extend(_usage_records_from_item(
                    item, known_aliases, known_sources))
        else:
            records.extend(_usage_records_from_item(
                usages, known_aliases, known_sources))

    explicit = set()
    if high_risk_usages is not None:
        if isinstance(high_risk_usages, dict):
            for purpose, flag in high_risk_usages.items():
                if _truthy(flag):
                    explicit.add(_text(purpose))
        for item in _as_list(high_risk_usages):
            if isinstance(item, dict):
                found_purpose = False
                for key in _PURPOSE_KEYS:
                    if key in item:
                        explicit.update(
                            _text(x) for x in _as_list(item[key]))
                        found_purpose = True
                        break
                if not found_purpose and not isinstance(high_risk_usages, dict):
                    explicit.update(_text(x) for x in item.keys())
            else:
                explicit.add(_text(item))
    explicit_lower = set(x.lower() for x in explicit)

    # If the caller labelled any purpose, unlabelled purposes should not be
    # silently promoted to high risk.  Only a completely unlabelled inventory
    # falls back to the conservative all-high-risk default.
    has_explicit_risk = (high_risk_usages is not None
                         or any(record.get("risk_explicit")
                                for record in records))
    for record in records:
        is_explicit = (record["purpose"].lower() in explicit_lower
                       or any(alias.lower() in explicit_lower
                              for alias in record["aliases"]))
        if is_explicit:
            record["high_risk"] = True
            record["risk"] = record["risk"] or "high"
        elif has_explicit_risk and not record.get("risk_explicit"):
            record["high_risk"] = False
            record["risk"] = record["risk"] or "unspecified"

    return records


def _assign_usages(observations, records):
    for observation in observations:
        for record in records:
            if record["sources"] and observation["source"] not in record["sources"]:
                continue
            if record["aliases"]:
                if _alias_key(observation["alias"]) not in record["alias_keys"]:
                    continue
            elif not record["match_all"] and not record["sources"]:
                # A purpose-only record is intentionally global: the caller
                # supplied the purpose but did not attach it to a label.
                pass
            observation["purposes"].add(record["purpose"])
            if record["high_risk"]:
                observation["high_risk_usages"].add(record["purpose"])
            record["matched"] += 1


def _public_observation(observation):
    result = dict(observation)
    result["purposes"] = sorted(observation.get("purposes", []))
    result["high_risk_usages"] = sorted(
        observation.get("high_risk_usages", []))
    result["high_risk"] = bool(result["high_risk_usages"])
    return result


def _change(kind, before, after, reason):
    purposes = sorted(
        set(before.get("purposes", [])) | set(after.get("purposes", [])))
    if kind == CHANGE_RENAME:
        high_risk_usages = []
    else:
        high_risk_usages = sorted(
            set(before.get("high_risk_usages", []))
            | set(after.get("high_risk_usages", [])))
    result = {
        "kind": kind,
        "type": kind,
        "change_type": kind,
        "change": kind,
        "action": kind,
        "reason": reason,
        "reasons": [reason],
        "from_source": before["source"],
        "to_source": after["source"],
        "from_source_index": before["source_index"],
        "to_source_index": after["source_index"],
        "from_alias": before["alias"],
        "to_alias": after["alias"],
        "old_alias": before["alias"],
        "new_alias": after["alias"],
        "alias_before": before["alias"],
        "alias_after": after["alias"],
        "previous_alias": before["alias"],
        "current_alias": after["alias"],
        "old_source": before["source"],
        "new_source": after["source"],
        "source_before": before["source"],
        "source_after": after["source"],
        "purposes": purposes,
        "affected_usages": purposes,
        "affected_high_risk_usages": high_risk_usages,
        "affected_high_risk_purposes": high_risk_usages,
        "affected_high_risk_uses": high_risk_usages,
        "affects_high_risk_usages": high_risk_usages,
        "high_risk_usages": high_risk_usages,
        "high_risk_uses": high_risk_usages,
        "high_risk_purposes": high_risk_usages,
        "critical_usages": high_risk_usages,
        "critical_uses": high_risk_usages,
        "affected_critical_usages": high_risk_usages,
        "high_risk_usage_list": high_risk_usages,
        "high_risk_impact": bool(high_risk_usages),
        "alias_changed": _alias_key(before["alias"]) != _alias_key(after["alias"]),
        "certificate_changed": before["identity"] != after["identity"],
        "before": _public_observation(before),
        "after": _public_observation(after),
        "old": _public_observation(before),
        "new": _public_observation(after),
        "previous": _public_observation(before),
        "current": _public_observation(after),
    }
    if kind == CHANGE_RENAME:
        result.update({
            "identity": before["identity"],
            "fingerprint": before["identity"],
            "certificate_sha256": before["identity"],
            "old_identity": before["identity"],
            "new_identity": after["identity"],
            "from_identity": before["identity"],
            "to_identity": after["identity"],
            "identity_before": before["identity"],
            "identity_after": after["identity"],
            "fingerprint_before": before["identity"],
            "fingerprint_after": after["identity"],
            "identity_preserved": True,
            "preserves_identity": True,
            "preserves_original_identity": True,
            "keeps_identity": True,
            "same_certificate": True,
            "renamed": True,
            "rotated": False,
        })
    else:
        result.update({
            "old_identity": before["identity"],
            "new_identity": after["identity"],
            "from_identity": before["identity"],
            "to_identity": after["identity"],
            "old_fingerprint": before["identity"],
            "new_fingerprint": after["identity"],
            "identity_before": before["identity"],
            "identity_after": after["identity"],
            "fingerprint_before": before["identity"],
            "fingerprint_after": after["identity"],
            "identity_preserved": False,
            "preserves_identity": False,
            "preserves_original_identity": False,
            "keeps_identity": False,
            "same_certificate": False,
            "renamed": False,
            "rotated": True,
        })
    result["certificate_before"] = before["identity"]
    result["certificate_after"] = after["identity"]
    result["identity"] = after["identity"]
    return result


def _change_key(change):
    return (
        change["kind"],
        change["from_source_index"],
        change["to_source_index"],
        _alias_key(change["from_alias"]),
        _alias_key(change["to_alias"]),
        change.get("old_identity"),
        change.get("new_identity"),
    )


def _add_change(changes, change):
    key = _change_key(change)
    existing = changes.get(key)
    if existing is None:
        changes[key] = change
        return
    reasons = set(existing.get("reasons", [existing.get("reason")]))
    reasons.add(change.get("reason"))
    existing["reasons"] = sorted(r for r in reasons if r)
    existing["affected_usages"] = sorted(
        set(existing["affected_usages"]) | set(change["affected_usages"]))
    existing["purposes"] = sorted(
        set(existing["purposes"]) | set(change["purposes"]))
    if change["kind"] == CHANGE_ROTATION:
        existing["affected_high_risk_usages"] = sorted(
            set(existing["affected_high_risk_usages"])
            | set(change["affected_high_risk_usages"]))
        high = existing["affected_high_risk_usages"]
        for field in ("high_risk_usages", "high_risk_uses",
                      "affected_high_risk_uses", "affected_high_risk_purposes",
                      "affects_high_risk_usages", "high_risk_purposes",
                      "critical_usages", "critical_uses",
                      "affected_critical_usages", "high_risk_usage_list"):
            existing[field] = high
        existing["high_risk_impact"] = bool(high)


def _sorted_observations(observations):
    return sorted(observations, key=lambda obs: (
        obs.get("source_order") if obs.get("source_order") is not None
        else obs["source_index"],
        obs["source_index"],
        _alias_key(obs["alias"]),
    ))


def _detect_renames(observations, warnings):
    renames = {}
    by_identity = {}
    for observation in observations:
        if observation["identity"] is not None:
            by_identity.setdefault(
                observation["identity"], []).append(observation)

    for identity, items in by_identity.items():
        by_source = {}
        for observation in _sorted_observations(items):
            by_source.setdefault(observation["source_index"], {})[
                _alias_key(observation["alias"])] = observation
        source_indexes = sorted(by_source)
        previous = None
        for source_index in source_indexes:
            current = by_source[source_index]
            if previous is not None:
                previous_index, previous_aliases = previous
                removed = set(previous_aliases) - set(current)
                added = set(current) - set(previous_aliases)
                if removed and added:
                    if len(removed) == 1 and len(added) == 1:
                        before = previous_aliases[list(removed)[0]]
                        after = current[list(added)[0]]
                        _add_change(renames, _change(
                            CHANGE_RENAME, before, after,
                            "same_certificate"))
                    else:
                        warnings.append({
                            "kind": "ambiguous_rename",
                            "identity": identity,
                            "message": "certificate identity was renamed between multiple aliases; rename was not inferred",
                            "from_source_index": previous_index,
                            "to_source_index": source_index,
                        })
            previous = (source_index, current)
    return list(renames.values())


def _detect_alias_rotations(observations):
    rotations = {}
    by_alias = {}
    for observation in observations:
        if observation["identity"] is not None:
            by_alias.setdefault(
                _alias_key(observation["alias"]), []).append(observation)

    for items in by_alias.values():
        ordered = _sorted_observations(items)
        previous = None
        for observation in ordered:
            if previous is None:
                previous = observation
                continue
            if (observation["identity"] != previous["identity"]
                    and observation["source_index"] != previous["source_index"]):
                _add_change(rotations, _change(
                    CHANGE_ROTATION, previous, observation, "same_alias"))
            previous = observation
    return list(rotations.values())


def _detect_purpose_rotations(observations, records, warnings):
    rotations = {}
    purposes_with_labels = set(
        record["purpose"] for record in records if record["aliases"])
    by_purpose = {}
    for observation in observations:
        if observation["identity"] is None:
            continue
        for purpose in observation["purposes"]:
            by_purpose.setdefault(purpose, []).append(observation)

    for purpose, items in by_purpose.items():
        if purpose not in purposes_with_labels:
            continue
        by_source = {}
        for observation in _sorted_observations(items):
            by_source.setdefault(
                observation["source_index"], []).append(observation)
        source_indexes = sorted(by_source)
        previous = None
        for source_index in source_indexes:
            group = by_source[source_index]
            identities = set(obs["identity"] for obs in group)
            if previous is not None:
                previous_index, previous_group, previous_identities = previous
                if (previous_identities and identities
                        and previous_identities.isdisjoint(identities)):
                    if len(previous_identities) == 1 and len(identities) == 1:
                        _add_change(rotations, _change(
                            CHANGE_ROTATION,
                            previous_group[0], group[0],
                            "same_purpose"))
                    else:
                        warnings.append({
                            "kind": "ambiguous_rotation",
                            "purpose": purpose,
                            "message": "purpose maps to several certificates in one source; rotation was not inferred",
                            "from_source_index": previous_index,
                            "to_source_index": source_index,
                        })
            previous = (source_index, group, identities)
    return list(rotations.values())


def _merge_changes(changes):
    merged = {}
    for change in changes:
        _add_change(merged, change)
    result = list(merged.values())
    result.sort(key=lambda item: (
        item["to_source_index"], item["from_source_index"],
        item["kind"], _alias_key(item["from_alias"]),
        _alias_key(item["to_alias"]),
    ))
    return result


def _build_identities(observations):
    identities = {}
    for observation in observations:
        identity = observation["identity"]
        if identity is None:
            continue
        record = identities.get(identity)
        if record is None:
            record = {
                "identity": identity,
                "fingerprint": identity,
                "sha256": identity,
                "sha1": observation["sha1"],
                "fingerprint_sha256": identity,
                "fingerprint_sha1": observation["sha1"],
                "certificate_sha256": identity,
                "certificate_sha1": observation["sha1"],
                "sha256_colon": _colon_hex(identity),
                "fingerprint_colon": _colon_hex(identity),
                "aliases": [],
                "sources": [],
                "names": [],
                "purposes": set(),
                "high_risk_usages": set(),
                "entry_types": [],
                "subject": observation.get("subject"),
                "issuer": observation.get("issuer"),
                "serial_number": observation.get("serial_number"),
                "serial_hex": observation.get("serial_hex"),
                "not_before": observation.get("not_before"),
                "not_after": observation.get("not_after"),
                "public_key_algorithm": observation.get(
                    "public_key_algorithm"),
                "public_key_sha256": observation.get("public_key_sha256"),
                "confidence": "confirmed",
                "certificate": {
                    "subject": observation.get("subject"),
                    "issuer": observation.get("issuer"),
                    "serial_number": observation.get("serial_number"),
                    "serial_hex": observation.get("serial_hex"),
                    "not_before": observation.get("not_before"),
                    "not_after": observation.get("not_after"),
                    "public_key_algorithm": observation.get(
                        "public_key_algorithm"),
                    "public_key_sha256": observation.get(
                        "public_key_sha256"),
                    "sha256": identity,
                    "sha1": observation["sha1"],
                },
            }
            identities[identity] = record
        if observation["alias"] not in record["aliases"]:
            record["aliases"].append(observation["alias"])
        if observation["source"] not in record["sources"]:
            record["sources"].append(observation["source"])
        record["names"].append({
            "source": observation["source"],
            "source_index": observation["source_index"],
            "alias": observation["alias"],
            "entry_type": observation["entry_type"],
        })
        record["purposes"].update(observation["purposes"])
        record["high_risk_usages"].update(
            observation["high_risk_usages"])
        if observation["entry_type"] not in record["entry_types"]:
            record["entry_types"].append(observation["entry_type"])

    for record in identities.values():
        record["aliases"].sort()
        record["sources"].sort()
        record["purposes"] = sorted(record["purposes"])
        record["high_risk_usages"] = sorted(
            record["high_risk_usages"])
        record["high_risk_uses"] = record["high_risk_usages"]
        record["high_risk"] = bool(record["high_risk_usages"])
        record["alias"] = (record["aliases"][0]
                            if len(record["aliases"]) == 1 else None)
        record["source"] = (record["sources"][0]
                             if len(record["sources"]) == 1 else None)
        record["alias_history"] = sorted(
            record["names"], key=lambda item: item["source_index"])
    return IdentityMap(identities)


def _build_handoffs(observations):
    handoffs = []
    for observation in observations:
        if observation["identity"] is None:
            continue
        item = _public_observation(observation)
        item.pop("chain", None)
        handoffs.append(item)
    return handoffs


def _source_public(source, loaded, store, integrity, error=None):
    result = {
        "name": _text(source.name),
        "label": _text(source.name),
        "index": getattr(source, "_index", None),
        "order": source.order,
        "path": _text(source.path) if source.path is not None else None,
        "loaded": bool(loaded),
        "store_type": getattr(store, "store_type", None),
        "integrity": integrity,
        "integrity_verified": integrity == INTEGRITY_VERIFIED,
        "verified": integrity == INTEGRITY_VERIFIED,
        "entry_count": len(getattr(store, "entries", {})) if store else 0,
    }
    if error is not None:
        result["error"] = error
    return result


def _source_order_key(source, index):
    if source.order is None:
        return (1, 0, "", index)
    try:
        return (0, int(source.order), "", index)
    except (TypeError, ValueError):
        return (0, 0, _text(source.order), index)


def inspect_migration(sources=None, usages=None, high_risk_usages=None,
                      **options):
    """Inspect keystores and return a migration forensics report.

    :param sources: Ordered keystore snapshots.  See :class:`MigrationSource`
      for accepted forms.
    :param usages: Caller supplied purpose inventory.  Purposes may carry a
      risk level (``high``/``low``) or an explicit ``high_risk`` flag.
    :param high_risk_usages: Optional extra list of purpose names that must be
      treated as high risk.
    :param passwords: Optional list/mapping of store passwords, aligned with
      ``sources``.
    :param salvage: Best-effort parsing of damaged JKS/JCEKS files (default
      ``True``).
    :param strict: Re-raise source loading errors instead of recording them
      (default ``False``).
    """
    if sources is None:
        sources = options.pop("keystores", None)
    if sources is None:
        sources = options.pop("stores", None)
    if sources is None:
        raise TypeError("sources is required")
    if usages is None:
        for key in ("purposes", "usage_inventory", "purpose_inventory",
                    "usage", "uses"):
            if key in options:
                usages = options.pop(key)
                break
    passwords = options.pop("passwords", options.pop("store_passwords", None))
    if passwords is None:
        for password_key in ("password", "store_password", "passphrase"):
            if password_key in options:
                passwords = options.pop(password_key)
                break
    strict = bool(options.pop("strict", False))
    salvage = bool(options.pop("salvage", True))

    source_list = _coerce_sources(sources, passwords=passwords)
    for index, source in enumerate(source_list):
        if source.name is None:
            source.name = (os.path.basename(_text(source.path))
                           if source.path is not None
                           else "source-%d" % (index + 1))
    ordered = sorted(
        enumerate(source_list),
        key=lambda item: _source_order_key(item[1], item[0]))

    loaded_sources = []
    observations = []
    unresolved = []
    warnings = []
    errors = []
    source_records = [None] * len(source_list)
    source_index_by_id = {}
    order_index = 0

    for original_index, source in ordered:
        source._index = original_index
        source_index = order_index
        order_index += 1
        source_index_by_id[id(source)] = source_index
        try:
            store, integrity, source_warnings = _load_source(
                source, salvage=salvage)
            loaded_sources.append((source, source_index, store, integrity))
            for warning in source_warnings:
                item = dict(warning)
                item.setdefault("source", source.name)
                item.setdefault("source_index", source_index)
                warnings.append(item)
            extracted, missing, extract_warnings = _extract_observations(
                store, source, source_index)
            observations.extend(extracted)
            unresolved.extend(missing)
            for warning in extract_warnings:
                warning.setdefault("source_index", source_index)
                warnings.append(warning)
            source_records[original_index] = _source_public(
                source, True, store, integrity)
        except Exception as exc:
            if strict:
                raise
            message = "%s: %s" % (exc.__class__.__name__, exc)
            errors.append({
                "source": source.name,
                "source_index": source_index,
                "error": exc.__class__.__name__,
                "message": message,
            })
            source_records[original_index] = _source_public(
                source, False, None, None, error=message)

    records = _normalize_usages(
        usages, observations, high_risk_usages=high_risk_usages)
    _assign_usages(observations, records)

    usage_bindings = {}
    for record in records:
        usage_bindings.setdefault(record["purpose"], []).extend(
            record["aliases"])
        if not record["matched"]:
            unresolved.append({
                "source": None,
                "source_index": None,
                "alias": record["aliases"][0] if record["aliases"] else None,
                "aliases": list(record["aliases"]),
                "purposes": [record["purpose"]],
                "high_risk_usages": (
                    [record["purpose"]] if record["high_risk"] else []),
                "identity": None,
                "fingerprint": None,
                "reason": "usage inventory entry did not match any recovered certificate",
            })
            warnings.append({
                "kind": "unmatched_usage",
                "purpose": record["purpose"],
                "aliases": list(record["aliases"]),
                "message": "usage inventory entry did not match any recovered certificate",
            })

    for purpose in usage_bindings:
        usage_bindings[purpose] = sorted(set(usage_bindings[purpose]))

    # Convert purpose sets to lists before exposing observations.
    observations = [_public_observation(obs) for obs in observations]

    renames = _detect_renames(observations, warnings)
    rotations = _detect_alias_rotations(observations)
    rotations.extend(_detect_purpose_rotations(
        observations, records, warnings))
    changes = _merge_changes(renames + rotations)
    renames = [item for item in changes if item["kind"] == CHANGE_RENAME]
    rotations = [item for item in changes if item["kind"] == CHANGE_ROTATION]

    identities = _build_identities(observations)
    handoffs = _build_handoffs(observations)

    incomplete = bool(
        errors or unresolved
        or any(warning.get("kind") in (
            "partial_keystore", "integrity_unverified", "duplicate_alias",
            "missing_certificate", "unmatched_usage", "ambiguous_rename",
            "ambiguous_rotation") for warning in warnings)
    )

    return MigrationReport(
        sources=[item for item in source_records if item is not None],
        identities=identities,
        observations=observations,
        handoffs=handoffs,
        unresolved=unresolved,
        changes=changes,
        renames=renames,
        rotations=rotations,
        warnings=warnings,
        errors=errors,
        incomplete=incomplete,
        usage_bindings=usage_bindings,
    )


class MigrationForensics(object):
    """Convenience wrapper around :func:`inspect_migration`."""

    def __init__(self, sources=None, usages=None, high_risk_usages=None,
                 **options):
        self.sources = sources
        self.usages = usages
        self.high_risk_usages = high_risk_usages
        self.options = options

    def inspect(self, sources=None, usages=None, high_risk_usages=None,
                **options):
        merged = dict(self.options)
        merged.update(options)
        return inspect_migration(
            self.sources if sources is None else sources,
            self.usages if usages is None else usages,
            self.high_risk_usages if high_risk_usages is None
            else high_risk_usages,
            **merged
        )

    report = inspect
    build = inspect
    run = inspect
    analyze = inspect

    def __call__(self, sources=None, usages=None, high_risk_usages=None,
                 **options):
        return self.inspect(
            sources=sources, usages=usages,
            high_risk_usages=high_risk_usages, **options)


MigrationInspector = MigrationForensics
MigrationAudit = MigrationForensics
KeystoreMigrationAudit = MigrationForensics
MigrationAnalyzer = MigrationForensics
ForensicMigration = MigrationForensics
KeystoreForensics = MigrationForensics
KeystoreSnapshot = MigrationSource
KeystoreMigrationReport = MigrationReport
ForensicReport = MigrationReport


# Descriptive aliases.  They all produce exactly the same report.
analyze_migration = inspect_migration
build_migration_report = inspect_migration
build_forensic_report = inspect_migration
forensics_report = inspect_migration
inspect_keystores = inspect_migration
migration_forensics = inspect_migration
migration_report = inspect_migration
offline_migration_report = inspect_migration
audit_migration = inspect_migration
audit_keystores = inspect_migration
inspect_keystore_migration = inspect_migration
keystore_migration_report = inspect_migration
migration_audit = inspect_migration
handoff_report = inspect_migration
build_handoff_report = inspect_migration
build_report = inspect_migration
forensic_report = inspect_migration
analyze_keystores = inspect_migration
migration_forensic_report = inspect_migration
reconstruct_associations = inspect_migration
build_associations = inspect_migration
associate_entries = inspect_migration
build_identity_map = inspect_migration
build_handoff = inspect_migration
handoff = inspect_migration
migration_handoff = inspect_migration


__all__ = [
    "CHANGE_RENAME", "CHANGE_ROTATION", "KIND_RENAME", "KIND_ROTATION",
    "RENAME", "ROTATION",
    "INTEGRITY_VERIFIED", "INTEGRITY_UNVERIFIED", "INTEGRITY_UNKNOWN",
    "MigrationSource", "KeystoreSource", "MigrationReport", "IdentityMap",
    "MigrationForensics", "MigrationInspector", "MigrationAudit",
    "KeystoreMigrationAudit", "MigrationAnalyzer", "ForensicMigration",
    "KeystoreForensics",
    "KeystoreSnapshot", "KeystoreMigrationReport", "ForensicReport",
    "inspect_migration", "analyze_migration", "build_migration_report",
    "build_forensic_report", "forensics_report", "inspect_keystores",
    "migration_forensics", "migration_report", "offline_migration_report",
    "audit_migration", "audit_keystores", "inspect_keystore_migration",
    "keystore_migration_report", "migration_audit", "handoff_report",
    "build_handoff_report", "build_report", "forensic_report",
    "analyze_keystores", "migration_forensic_report",
    "reconstruct_associations", "build_associations",
    "associate_entries", "build_identity_map", "build_handoff",
    "handoff", "migration_handoff",
]
