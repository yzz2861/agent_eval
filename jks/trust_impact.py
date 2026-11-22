# vim: set et ai ts=4 sts=4 sw=4:
"""Read-only preview of how a merged Java trust image changes application trust.

The helpers in this module deliberately look at ``TrustedCertEntry`` objects
only.  They never call ``decrypt()`` and never read private-key material.
Certificate identity is the SHA-256 digest of the DER encoded certificate;
aliases are labels, not identities.

The public entry point is :func:`preview_trust_impact`.  Callers provide a
selection contract per application and the target image to inspect::

    contracts = [
        {
            "application": "reporting",
            "selection": "all",
            "baseline": {"certificates": [shared_sha256]},
        },
        {
            "application": "billing",
            "selection": {"aliases": ["billing-root"]},
            "baseline": {"aliases": ["billing-root"]},
        },
    ]

    report = preview_trust_impact(contracts, "merged-truststore.jks")
    print(report.to_json())

The report keeps two different counts apart:

* ``trusted_entry_count`` counts matched public entries/aliases.
* ``trusted_certificate_count`` counts distinct certificate identities.

That distinction is what makes a shared certificate visible without claiming
that duplicate copies widen cryptographic trust more than once.
"""

from __future__ import print_function

import base64
import binascii
import hashlib
import json
import os
import re

from .jks import (
    KeyStore,
    MAGIC_NUMBER_JCEKS,
    MAGIC_NUMBER_JKS,
    PrivateKeyEntry,
    SecretKeyEntry,
    TrustedCertEntry,
)
from .util import (
    AbstractKeystoreEntry,
    DuplicateAliasException,
    KeystoreException,
    b4,
    py23basestring,
)


__all__ = [
    "ApplicationImpact",
    "CertificateIdentity",
    "AliasNotFoundError",
    "MissingAliasError",
    "MissingAliasException",
    "MissingSelectionRecordError",
    "MissingSelectionRecordException",
    "TrustImpactException",
    "PublicCertificateEntry",
    "SelectionContract",
    "SharedCertificateExample",
    "TrustImage",
    "TrustImpact",
    "TrustImpactAnalyzer",
    "TrustImpactError",
    "TrustImpactPreview",
    "TrustImpactReport",
    "TrustStoreImpact",
    "TrustStoreImpactPreview",
    "ApplicationTrustImpact",
    "CertificateGroup",
    "analyze_trust_impact",
    "assess_trust_impact",
    "build_shared_certificate_example",
    "build_trust_impact_preview",
    "analyze_trust_expansion",
    "compute_trust_changes",
    "compute_trust_impact",
    "diff_trust_images",
    "evaluate_trust_impact",
    "inspect_trust_impact",
    "impact_preview",
    "preview_impact",
    "preview_selection_impact",
    "preview_merged_trust",
    "preview_trust_changes",
    "preview_trust_impact",
    "trust_expansion",
    "trust_impact_analysis",
    "preview_trust_store_impact",
    "run_shared_certificate_example",
    "shared_certificate_example",
    "trust_impact_preview",
]


_ALL_MODES = set([
    "all", "*", "any", "store", "whole", "whole_store", "whole-store",
    "entire_store", "entire-store", "default", "default_all", "default-all",
    "accept_all", "accept-all", "accept_entire_store", "accept-entire-store",
])
_ALIAS_MODES = set([
    "alias", "aliases", "by_alias", "by-alias", "named", "names",
    "select", "selected", "explicit", "list",
])
_NONE_MODES = set([
    "none", "no", "empty", "deny", "denied", "disabled", "off",
])
_MISSING_TEXT = set([
    "missing", "unknown", "unavailable", "not_recorded", "not-recorded",
    "none", "null", "absent",
])

_APP_KEYS = ("application", "app", "application_name", "app_name", "application_id", "app_id", "program", "consumer", "name", "id")
_MODE_KEYS = ("mode", "selection_mode", "selection_type", "type", "selector",
              "policy", "kind", "default", "default_accept")
_ALIAS_KEYS = (
    "aliases", "alias", "selected_aliases", "selected_alias",
    "selection_aliases", "alias_names", "names", "entries", "roots",
    "select",
)
_BASELINE_KEYS = (
    "baseline", "previous", "before", "prior", "original", "original_selection",
    "authorized", "authorization", "record", "recorded", "recorded_record",
    "recorded_selection", "selection_record", "real_selection",
    "actual", "actual_selection", "observed", "observed_selection",
    "current_selection", "trusted",
    "trusted_certificates", "existing",
)
_BASELINE_ALIAS_KEYS = (
    "aliases", "alias", "selected_aliases", "selection_aliases",
    "recorded_aliases", "authorized_aliases", "previous_aliases",
    "existing_aliases", "current_aliases", "alias_names", "names",
)
_BASELINE_CERT_KEYS = (
    "certificates", "certs", "certificate", "cert", "der", "pem",
    "sha256", "sha256_hex", "sha256s", "certificate_sha256",
    "fingerprint", "fingerprints", "digests", "identities",
    "public_certificates", "selected_certificates",
    "selected_certificate_fingerprints", "recorded_certificates",
    "authorized_certificates", "previous_certificates",
    "existing_certificates", "current_certificates", "trusted_certificates",
)


class TrustImpactError(KeystoreException):
    """Base class for trust-impact preview errors."""


class MissingAliasException(TrustImpactError):
    """Raised in strict mode when a contract alias cannot be selected."""


class MissingSelectionRecordException(TrustImpactError):
    """Raised in strict mode when no real prior selection record is available."""


MissingAliasError = MissingAliasException
AliasNotFoundError = MissingAliasException
MissingSelectionRecordError = MissingSelectionRecordException
TrustImpactException = TrustImpactError


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _text(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except Exception:
            return value
    return value


def _lower(value):
    value = _text(value)
    if isinstance(value, py23basestring):
        return value.strip().lower()
    return value


def _lookup(mapping, keys, default=None):
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        if key in mapping:
            return mapping[key]
    lowered = dict((_lower(k), v) for k, v in mapping.items()
                   if isinstance(k, py23basestring))
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return default


def _has_key(mapping, keys):
    if not isinstance(mapping, dict):
        return False
    if any(key in mapping for key in keys):
        return True
    lowered = set(_lower(k) for k in mapping)
    return any(key.lower() in lowered for key in keys)


def _mode_from_value(value):
    value = _lower(value)
    if not isinstance(value, py23basestring):
        return None
    if value in _ALL_MODES:
        return "all"
    if value in _ALIAS_MODES:
        return "aliases"
    if value in _NONE_MODES:
        return "none"
    if value in _MISSING_TEXT:
        return "unknown"
    return None


def _is_mode_value(value):
    return _mode_from_value(value) is not None


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _normalise_hex(value):
    value = _text(value)
    if not isinstance(value, py23basestring):
        return None
    text = value.strip()
    if text.lower().startswith("sha256:"):
        text = text.split(":", 1)[1]
    text = text.replace(":", "").replace(" ", "").replace("-", "")
    if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
        return text.lower()
    return None


def _pem_to_der(value):
    value = _text(value)
    if not isinstance(value, py23basestring):
        return None
    if "BEGIN CERTIFICATE" not in value:
        return None
    try:
        body = value.split("BEGIN CERTIFICATE", 1)[1]
        body = body.split("END CERTIFICATE", 1)[0]
        body = re.sub(r"\s+", "", body)
        return base64.b64decode(body)
    except (TypeError, ValueError, binascii.Error):
        return None


def _identity_from_value(value):
    """Return a SHA-256 hex identity for a public certificate reference."""
    if isinstance(value, TrustedCertEntry):
        return _sha256_bytes(value.cert)
    if isinstance(value, bytes):
        return _sha256_bytes(value)
    if isinstance(value, bytearray):
        return _sha256_bytes(bytes(value))
    if isinstance(value, dict):
        for key in ("sha256", "sha256_hex", "digest", "cert_sha256", "certificate_sha256"):
            if key in value:
                result = _normalise_hex(value[key])
                if result:
                    return result
        for key in ("fingerprint", "fingerprints"):
            if key in value:
                for item in _as_list(value[key]):
                    result = _normalise_hex(item)
                    if result:
                        return result
        for key in ("cert", "certificate", "der", "pem", "public_cert"):
            if key in value:
                result = _identity_from_value(value[key])
                if result:
                    return result
        return None
    if isinstance(value, py23basestring):
        result = _normalise_hex(value)
        if result:
            return result
        der = _pem_to_der(value)
        if der is not None:
            return _sha256_bytes(der)
        return None
    return None


def _material_from_value(value):
    if isinstance(value, TrustedCertEntry):
        return value.cert
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, dict):
        for key in ("cert", "certificate", "der", "public_cert"):
            if key in value:
                material = _material_from_value(value[key])
                if material is not None:
                    return material
        return None
    if isinstance(value, py23basestring):
        der = _pem_to_der(value)
        if der is not None:
            return der
    return None


def _split_baseline(value):
    """Split a prior-selection record into aliases and certificate identities.

    The return value is ``(aliases, identities, status)``.  ``status`` is
    ``recorded`` when certificate identities are available, ``aliases_only``
    when only names were recorded, and ``missing`` when no record exists.
    """
    aliases = []
    identities = []

    if _is_keystore(value):
        certs = getattr(value, "certs", {}) or {}
        for alias, entry in certs.items():
            aliases.append(_text(alias))
            material = getattr(entry, "cert", None)
            if material is not None:
                identities.append(_sha256_bytes(material))
        return aliases, identities, "recorded" if identities else (
            "aliases_only" if aliases else "recorded"
        )

    if isinstance(value, SelectionContract):
        return (list(value.baseline_aliases), list(value.baseline_certificates),
                value.baseline_record_status)

    record_missing = value is None
    items = []

    if isinstance(value, bool):
        return [], [], ("recorded" if value else "missing")

    if isinstance(value, dict):
        if not value:
            return [], [], "missing"
        for flag_key in ("present", "available", "known", "found", "recorded",
                         "has_record", "has_selection_record"):
            if flag_key in value and value[flag_key] is False:
                return [], [], "missing"
        nested = _lookup(value, ("selection", "contract", "record", "baseline"))
        if nested is not None and nested is not value:
            aliases, identities, status = _split_baseline(nested)
            if status != "missing":
                record_missing = False
            if aliases or identities:
                return aliases, identities, status

        alias_value = _lookup(value, _BASELINE_ALIAS_KEYS)
        cert_value = _lookup(value, _BASELINE_CERT_KEYS)
        if alias_value is not None or cert_value is not None:
            record_missing = False
            aliases = [_text(x) for x in _as_list(alias_value) if x is not None]
            for item in _as_list(cert_value):
                identity = _identity_from_value(item)
                if identity:
                    identities.append(identity)
                elif isinstance(item, py23basestring):
                    aliases.append(_text(item))
            status = "recorded" if identities else ("aliases_only" if aliases else "recorded")
            return aliases, identities, status

        for key, item in value.items():
            items.extend(_as_list(item))
    else:
        items = _as_list(value)
        if value is not None:
            record_missing = False

    for item in items:
        identity = _identity_from_value(item)
        if identity:
            identities.append(identity)
        elif isinstance(item, dict):
            alias = _lookup(item, ("alias", "name", "application"))
            if alias is not None:
                aliases.append(_text(alias))
        elif item is not None:
            aliases.append(_text(item))

    if record_missing:
        return [], [], "missing"
    if identities:
        return aliases, identities, "recorded"
    if aliases:
        return aliases, identities, "aliases_only"
    return [], [], "recorded"


def _baseline_flag_from_mapping(mapping):
    if not isinstance(mapping, dict):
        return None
    for key in ("has_record", "has_selection_record", "record_available",
                "recorded", "real_record", "actual_record"):
        if key in mapping:
            value = mapping[key]
            if isinstance(value, bool):
                return value
            lowered = _lower(value)
            if lowered in ("yes", "true", "recorded", "present", "available", "real"):
                return True
            if lowered in _MISSING_TEXT:
                return False
    return None


def _merge_aliases(first, second):
    result = []
    for item in list(first or []) + list(second or []):
        if item is None:
            continue
        text = _text(item)
        if text not in result:
            result.append(text)
    return result


def _sorted_text(values):
    return sorted((value for value in values if value is not None),
                  key=lambda value: _text(value) or "")


class SelectionContract(object):
    """One application's rule for choosing public entries from an image.

    ``mode`` is one of ``all``, ``aliases``, ``none`` or ``unknown``.
    ``aliases`` is used for alias based selection.  ``baseline_aliases`` and
    ``baseline_certificates`` are the caller recorded prior selection.  A
    missing prior record is kept distinct from an explicitly empty record.
    """

    def __init__(self, application=None, aliases=None, mode=None, **kwargs):
        if (isinstance(application, (dict, list, tuple, set))
                and aliases is None and mode is None):
            parsed = self.from_any(application)
            self.__dict__.update(parsed.__dict__)
            return
        if mode is None and isinstance(aliases, py23basestring) and _is_mode_value(aliases):
            mode, aliases = aliases, None
        self.application = _text(
            application if application is not None
            else kwargs.get("app", kwargs.get("name"))
        )
        self.app = self.application
        self.name = self.application
        if isinstance(aliases, dict):
            aliases = list(aliases)
        self.aliases = [_text(a) for a in _as_list(aliases) if a is not None]

        if mode is None:
            mode = kwargs.get("selection_mode", kwargs.get("selector"))
        self.mode = _mode_from_value(mode) or _lower(mode) or "unknown"
        if self.mode not in ("all", "aliases", "none", "unknown"):
            if self.aliases:
                self.mode = "aliases"
            else:
                self.mode = "unknown"

        self.selection = kwargs.get("selection", mode)
        self.case_sensitive = kwargs.get("case_sensitive", True)

        baseline_value = kwargs.get("baseline", kwargs.get("record"))
        baseline_given = kwargs.get(
            "baseline_given",
            baseline_value is not None or _has_key(kwargs, _BASELINE_KEYS)
        )
        _baseline_aliases, _baseline_certs, _baseline_status = _split_baseline(baseline_value)

        explicit_aliases = kwargs.get("baseline_aliases")
        explicit_certs = kwargs.get("baseline_certificates", kwargs.get("baseline_certs"))
        if explicit_aliases is not None:
            _baseline_aliases = _merge_aliases(
                _baseline_aliases, [_text(x) for x in _as_list(explicit_aliases)]
            )
            baseline_given = True
        if explicit_certs is not None:
            baseline_given = True
            for item in _as_list(explicit_certs):
                identity = _identity_from_value(item)
                if identity and identity not in _baseline_certs:
                    _baseline_certs.append(identity)
            if _baseline_status == "missing":
                _baseline_status = "recorded" if _baseline_certs else "aliases_only"

        flag = _baseline_flag_from_mapping(kwargs)
        if flag is False:
            baseline_given = False
            _baseline_status = "missing"
            _baseline_aliases = []
            _baseline_certs = []
        elif flag is True and not baseline_given:
            baseline_given = True
            _baseline_status = "recorded" if _baseline_certs else "aliases_only"

        if not baseline_given:
            _baseline_status = "missing"
        elif _baseline_status == "missing" and (_baseline_aliases or _baseline_certs):
            _baseline_status = "recorded" if _baseline_certs else "aliases_only"

        self.baseline_aliases = _baseline_aliases
        self.baseline_certificates = _baseline_certs
        self.baseline_record_status = _baseline_status
        self.baseline_given = baseline_given
        self.baseline_image = kwargs.get("baseline_image", kwargs.get("previous_image"))
        self.baseline_selection = kwargs.get(
            "baseline_selection", kwargs.get("previous_selection")
        )
        self.metadata = kwargs.get("metadata", {})
        self.raw = kwargs

    @property
    def record_missing(self):
        return self.baseline_record_status == "missing"

    @property
    def all(self):
        return self.mode == "all"

    @property
    def accept_all(self):
        return self.mode == "all"

    @property
    def is_all(self):
        return self.mode == "all"

    @property
    def is_alias_selection(self):
        return self.mode == "aliases"

    @classmethod
    def from_any(cls, value, application=None):
        if isinstance(value, SelectionContract):
            if application is not None and not value.application:
                value.application = _text(application)
                value.app = value.application
                value.name = value.application
            return value

        if isinstance(value, dict):
            app = _lookup(value, _APP_KEYS, application)

            nested = None
            for key in ("selection", "contract", "selector", "policy", "rule"):
                candidate = _lookup(value, (key,))
                if isinstance(candidate, dict):
                    nested = candidate
                    break
                if key == "selection" and _is_mode_value(candidate):
                    nested = {"mode": candidate}
                    break
                if key == "selection" and isinstance(candidate, (list, tuple)):
                    nested = {"aliases": candidate}
                    break

            combined = value
            if nested is not None:
                combined = dict(value)
                for key, item in nested.items():
                    combined.setdefault(key, item)

            mode_value = _lookup(combined, _MODE_KEYS)
            select_value = _lookup(combined, ("select",))
            if mode_value is None and _is_mode_value(select_value):
                mode_value = select_value
            mode = _mode_from_value(mode_value)
            for flag in ("all", "accept_all", "default_accept",
                         "default_accept_all", "whole_store",
                         "entire_store", "store_wide", "default"):
                if _lookup(combined, (flag,)) is True:
                    mode = "all"
                    break

            aliases = []
            for key in _ALIAS_KEYS:
                if _has_key(combined, (key,)):
                    aliases.extend(_as_list(_lookup(combined, (key,))))
            if nested is not None and _is_mode_value(mode_value) is False:
                aliases.extend(_as_list(_lookup(nested, _ALIAS_KEYS)))

            if mode is None:
                mode = "aliases" if aliases else "unknown"

            kwargs = dict(combined)
            kwargs.setdefault("application", app)
            kwargs.setdefault("aliases", aliases)
            kwargs.setdefault("mode", mode)

            baseline_key_present = _has_key(combined, _BASELINE_KEYS)
            baseline_value = _lookup(combined, _BASELINE_KEYS)
            kwargs["baseline"] = baseline_value
            kwargs["baseline_given"] = baseline_key_present

            return cls(**kwargs)

        if isinstance(value, tuple) and len(value) in (2, 3) and isinstance(value[0], py23basestring):
            if len(value) == 3:
                return cls(application=value[0], mode=value[1], aliases=value[2])
            if isinstance(value[1], (list, tuple, set, dict)):
                return cls(application=value[0], aliases=value[1], mode="aliases")
            mode = _mode_from_value(value[1])
            if mode:
                return cls(application=value[0], mode=mode)

        if isinstance(value, (list, tuple, set)):
            return cls(application=application, aliases=list(value), mode="aliases")

        if isinstance(value, py23basestring):
            mode = _mode_from_value(value)
            if mode == "all":
                return cls(application=application, mode="all")
            if mode == "none":
                return cls(application=application, mode="none")
            if mode == "unknown":
                return cls(application=application, mode="unknown")
            return cls(application=application, aliases=[value], mode="aliases")

        # Duck-typed contract objects are useful for callers that already have
        # a configuration model.  Only documented public attributes are read.
        if hasattr(value, "aliases") or hasattr(value, "mode") or hasattr(value, "selection"):
            mapping = {}
            for attr in ("application", "app", "name", "mode", "selection",
                         "selection_mode", "aliases", "alias", "baseline",
                         "record", "selection_record", "baseline_aliases",
                         "baseline_certificates", "case_sensitive"):
                if hasattr(value, attr):
                    mapping[attr] = getattr(value, attr)
            mapping.setdefault("application", application)
            return cls.from_any(mapping)

        return cls(application=application, mode="unknown")

    from_dict = from_any
    parse = from_any

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def to_dict(self):
        return {
            "application": self.application,
            "app": self.application,
            "mode": self.mode,
            "selection": self.selection if not isinstance(self.selection, dict) else _json_safe(self.selection),
            "aliases": list(self.aliases),
            "case_sensitive": self.case_sensitive,
            "baseline_record_status": self.baseline_record_status,
            "baseline_given": self.baseline_given,
            "baseline_aliases": list(self.baseline_aliases),
            "baseline_certificates": list(self.baseline_certificates),
            "baseline": {
                "aliases": list(self.baseline_aliases),
                "certificates": list(self.baseline_certificates),
                "status": self.baseline_record_status,
            },
            "baseline_image": self.baseline_image if isinstance(self.baseline_image, py23basestring) else None,
        }


class PublicCertificateEntry(object):
    """A public certificate entry from a trust image."""

    def __init__(self, alias, cert, cert_type="X.509", slot=None, store_type=None):
        alias = _text(alias)
        if alias is None:
            alias = "__entry_%s__" % (slot if slot is not None else "0")
        elif not isinstance(alias, py23basestring):
            alias = str(alias)
        self.alias = alias
        self.cert = cert
        self.type = cert_type
        self.cert_type = cert_type
        self.slot = slot
        self.store_type = store_type
        self.sha256 = _sha256_bytes(cert)
        self.sha1 = hashlib.sha1(cert).hexdigest()
        self.fingerprint = ":".join(
            self.sha256[i:i + 2].upper() for i in range(0, len(self.sha256), 2)
        )
        self.sha1_fingerprint = ":".join(
            self.sha1[i:i + 2].upper() for i in range(0, len(self.sha1), 2)
        )

    def to_dict(self, include_der=False):
        result = {
            "alias": self.alias,
            "type": self.type,
            "slot": self.slot,
            "sha256": self.sha256,
            "fingerprint": self.fingerprint,
            "sha256_fingerprint": self.fingerprint,
            "sha1": self.sha1,
            "sha1_fingerprint": self.sha1_fingerprint,
        }
        if include_der:
            result["der_base64"] = base64.b64encode(self.cert).decode("ascii")
        return result

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def __getitem__(self, key):
        return self.to_dict()[key]

    def __contains__(self, key):
        return key in self.to_dict()


class CertificateIdentity(object):
    """A distinct public certificate and all aliases that carry it."""

    def __init__(self, sha256, aliases=None, entries=None):
        self.sha256 = sha256
        self.fingerprint = ":".join(
            sha256[i:i + 2].upper() for i in range(0, len(sha256), 2)
        )
        self.aliases = list(aliases or [])
        self.entries = list(entries or [])
        self.sha1 = None
        self.sha1_fingerprint = None
        if self.entries and getattr(self.entries[0], "cert", None) is not None:
            self.sha1 = hashlib.sha1(self.entries[0].cert).hexdigest()
            self.sha1_fingerprint = ":".join(
                self.sha1[i:i + 2].upper() for i in range(0, len(self.sha1), 2)
            )

    @property
    def duplicate(self):
        return len(self.entries) > 1

    def to_dict(self):
        return {
            "sha256": self.sha256,
            "fingerprint": self.fingerprint,
            "sha256_fingerprint": self.fingerprint,
            "sha1": self.sha1,
            "sha1_fingerprint": self.sha1_fingerprint,
            "aliases": list(self.aliases),
            "entry_count": len(self.entries),
            "duplicate": self.duplicate,
            "occurrences": [entry.to_dict() for entry in self.entries],
        }

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def __getitem__(self, key):
        return self.to_dict()[key]

    def __contains__(self, key):
        return key in self.to_dict()


class TrustImage(object):
    """A read-only view of the public entries in a trust image."""

    def __init__(self, entries, store_type=None, sha256=None, path=None,
                 warnings=None, private_entries_ignored=0, source=None,
                 private_aliases=None):
        self.entries = list(entries)
        self.store_type = store_type
        self.sha256 = sha256
        self.path = path
        self.warnings = list(warnings or [])
        self.private_entries_ignored = private_entries_ignored
        self.private_aliases = list(private_aliases or [])
        self.source = source
        self.aliases = []
        self.all_aliases = []
        self.identities = {}
        self._index()

    def _index(self):
        identities = {}
        for entry in self.entries:
            identities.setdefault(entry.sha256, []).append(entry)
            if entry.alias not in self.aliases:
                self.aliases.append(entry.alias)
        self.all_aliases = list(self.aliases)
        for alias in self.private_aliases:
            if alias not in self.all_aliases:
                self.all_aliases.append(alias)
        self.identities = dict(
            (sha, CertificateIdentity(sha, [e.alias for e in entries], entries))
            for sha, entries in identities.items()
        )

    @property
    def public_entries(self):
        return list(self.entries)

    @property
    def entries_by_alias(self):
        result = {}
        for entry in self.entries:
            result.setdefault(entry.alias, []).append(entry)
        return result

    @property
    def duplicate_certificates(self):
        return [
            identity for identity in self.identities.values()
            if identity.duplicate
        ]

    def entries_for_alias(self, alias, case_sensitive=True):
        direct = [entry for entry in self.entries if entry.alias == alias]
        if direct or case_sensitive:
            return direct
        lowered = _lower(alias)
        return [entry for entry in self.entries if _lower(entry.alias) == lowered]

    def has_alias(self, alias, case_sensitive=True):
        if alias in self.all_aliases:
            return True
        if case_sensitive:
            return False
        lowered = _lower(alias)
        return any(_lower(name) == lowered for name in self.all_aliases)

    def to_dict(self):
        return {
            "path": self.path,
            "source": self.source,
            "store_type": self.store_type,
            "sha256": self.sha256,
            "public_entry_count": len(self.entries),
            "private_entries_ignored": self.private_entries_ignored,
            "aliases": list(self.aliases),
            "all_aliases": list(self.all_aliases),
            "private_aliases": list(self.private_aliases),
            "warnings": list(self.warnings),
            "entries": [entry.to_dict() for entry in self.entries],
            "duplicate_certificates": [
                identity.to_dict() for identity in self.duplicate_certificates
            ],
        }

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def __getitem__(self, key):
        return self.to_dict()[key]

    def __contains__(self, key):
        return key in self.to_dict()


def _private_or_secret(entry):
    return isinstance(entry, (PrivateKeyEntry, SecretKeyEntry))


def _is_keystore(value):
    return hasattr(value, "entries") or hasattr(value, "certs")


def _looks_like_contracts(value):
    if isinstance(value, SelectionContract):
        return True
    if hasattr(value, "aliases") or hasattr(value, "mode") or hasattr(value, "selection"):
        return True
    if isinstance(value, dict):
        for item in value.values():
            if isinstance(item, (TrustedCertEntry, AbstractKeystoreEntry, bytes, bytearray)):
                return False
            if isinstance(item, dict) and _has_key(
                    item, ("cert", "der", "certificate", "pem", "public_cert")):
                return False
        return True
    if isinstance(value, (list, tuple, set)):
        if not value:
            return True
        return not any(isinstance(v, (TrustedCertEntry, AbstractKeystoreEntry)) for v in value)
    return False


def _image_from_keystore(store, source=None, path=None, sha256=None, warnings=None):
    entries = []
    private_count = 0
    private_aliases = []
    all_entries = getattr(store, "entries", None)
    if all_entries is None:
        all_entries = getattr(store, "certs", {})
    for alias, entry in all_entries.items():
        if isinstance(entry, TrustedCertEntry):
            entries.append(PublicCertificateEntry(
                alias,
                entry.cert,
                cert_type=getattr(entry, "type", "X.509"),
                slot=len(entries),
                store_type=getattr(store, "store_type", None),
            ))
        elif _private_or_secret(entry) or (
                isinstance(entry, AbstractKeystoreEntry)
                and not isinstance(entry, TrustedCertEntry)):
            private_count += 1
            private_aliases.append(alias)
    return TrustImage(
        entries,
        store_type=getattr(store, "store_type", None),
        sha256=sha256,
        path=path,
        warnings=warnings,
        private_entries_ignored=private_count,
        source=source,
        private_aliases=private_aliases,
    )


def _entry_from_any(value, alias=None, slot=None, store_type=None):
    if isinstance(value, TrustedCertEntry):
        return PublicCertificateEntry(
            value.alias if value.alias is not None else alias,
            value.cert,
            cert_type=getattr(value, "type", "X.509"),
            slot=slot,
            store_type=store_type,
        )
    if isinstance(value, dict):
        entry_alias = alias if alias is not None else _lookup(value, ("alias", "name"))
        material = _material_from_value(value)
        if material is None:
            return None
        return PublicCertificateEntry(
            entry_alias,
            material,
            cert_type=_lookup(value, ("type", "cert_type"), "X.509"),
            slot=slot,
            store_type=store_type,
        )
    if isinstance(value, (tuple, list)) and len(value) == 2:
        left, right = value
        if isinstance(left, py23basestring) and isinstance(right, (bytes, bytearray)):
            return PublicCertificateEntry(
                alias if alias is not None else left,
                bytes(right),
                slot=slot,
                store_type=store_type,
            )
    material = _material_from_value(value)
    if material is not None:
        return PublicCertificateEntry(
            alias,
            material,
            slot=slot,
            store_type=store_type,
        )
    return None


def _image_from_mapping(value, source=None, warnings=None):
    warnings = list(warnings or [])
    entries = []
    private_count = 0
    private_aliases = []

    if isinstance(value, dict) and _has_key(value, ("entries", "certs", "trusted_certificates")):
        value = _lookup(value, ("entries", "certs", "trusted_certificates"))

    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, (list, tuple, set)):
        items = [(None, item) for item in value]
    else:
        items = [(None, value)]

    for alias, item in items:
        if isinstance(item, (PrivateKeyEntry, SecretKeyEntry)):
            private_count += 1
            private_aliases.append(alias)
            continue
        if isinstance(item, AbstractKeystoreEntry) and not isinstance(item, TrustedCertEntry):
            private_count += 1
            private_aliases.append(alias)
            continue
        entry = _entry_from_any(item, alias=alias, slot=len(entries), store_type=source)
        if entry is None:
            warnings.append("Unreadable public entry: %r" % (alias,))
            continue
        entries.append(entry)

    return TrustImage(
        entries,
        store_type=source,
        warnings=warnings,
        private_entries_ignored=private_count,
        source=source,
        private_aliases=private_aliases,
    )


def _read_public_entries_tolerant(data, store_type):
    """Read public entries without treating duplicate aliases as fatal."""
    entries = []
    warnings = []
    pos = 12
    try:
        entry_count = b4.unpack_from(data, 8)[0]
        for _ in range(entry_count):
            tag = b4.unpack_from(data, pos)[0]
            pos += 4
            alias, pos = KeyStore._read_utf(data, pos, kind="entry alias")
            pos += 8  # timestamp

            if tag == 1:
                _encrypted, pos = KeyStore._read_data(data, pos)
                chain_len = b4.unpack_from(data, pos)[0]
                pos += 4
                for _ in range(chain_len):
                    _cert_type, pos = KeyStore._read_utf(data, pos, kind="certificate type")
                    _cert_data, pos = KeyStore._read_data(data, pos)
            elif tag == 2:
                cert_type, pos = KeyStore._read_utf(data, pos, kind="certificate type")
                cert_data, pos = KeyStore._read_data(data, pos)
                entries.append(PublicCertificateEntry(
                    alias,
                    cert_data,
                    cert_type=cert_type,
                    slot=len(entries),
                    store_type=store_type,
                ))
            elif tag == 3 and store_type == "jceks":
                _sealed, pos = KeyStore._read_java_obj(data, pos, ignore_remaining_data=True)
            else:
                warnings.append("Unsupported entry tag %r at alias %r" % (tag, alias))
                break
    except Exception as exc:
        warnings.append("Tolerant public-entry scan stopped: %s" % (exc,))
    return entries, warnings


def _load_image(value, password=None, source_hint=None):
    warnings = []
    path = None
    sha256 = None
    data = None

    if hasattr(value, "__fspath__") and not isinstance(value, py23basestring):
        value = value.__fspath__()

    if _is_keystore(value):
        return _image_from_keystore(value, source="keystore", warnings=warnings)

    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        sha256 = _sha256_bytes(data)
    elif isinstance(value, py23basestring):
        candidate = os.path.expanduser(value)
        try:
            is_file = os.path.isfile(candidate)
        except OSError:
            is_file = False
        if is_file:
            path = candidate
            with open(candidate, "rb") as handle:
                data = handle.read()
            sha256 = _sha256_bytes(data)
        elif "BEGIN CERTIFICATE" in value:
            material = _pem_to_der(value)
            if material is not None:
                return TrustImage(
                    [PublicCertificateEntry(None, material, slot=0)],
                    warnings=warnings,
                    source="pem",
                )
        else:
            raise TrustImpactError("Trust image not found: %s" % candidate)
    else:
        return _image_from_mapping(value, source=source_hint, warnings=warnings)

    if data is None:
        return _image_from_mapping(value, source=source_hint, warnings=warnings)

    store = None
    magic = data[:4]
    if magic not in (MAGIC_NUMBER_JKS, MAGIC_NUMBER_JCEKS):
        # BKS/UBER are also Java keystores.  Try them before giving up, still
        # with automatic key decryption disabled.
        try:
            from .bks import BksKeyStore, UberKeyStore
            for store_class in (BksKeyStore, UberKeyStore):
                try:
                    store = store_class.loads(data, password, try_decrypt_keys=False)
                    break
                except Exception:
                    store = None
        except Exception:
            store = None
        if store is not None:
            return _image_from_keystore(
                store,
                source="bks-bytes" if path is None else "bks-file",
                path=path,
                sha256=sha256,
                warnings=warnings,
            )

    fallback_type = "jceks" if magic == MAGIC_NUMBER_JCEKS else "jks"
    try:
        store = KeyStore.loads(data, password, try_decrypt_keys=False)
    except DuplicateAliasException:
        warnings.append("Duplicate aliases found; public entries were read conservatively.")
        entries, scan_warnings = _read_public_entries_tolerant(data, fallback_type)
        warnings.extend(scan_warnings)
        return TrustImage(
            entries,
            store_type=fallback_type,
            sha256=sha256,
            path=path,
            warnings=warnings,
            source=fallback_type + ("-bytes" if path is None else "-file"),
        )
    except KeystoreException as exc:
        # A damaged signature or truncated tail must not make already readable
        # public entries disappear from the preview.
        warnings.append("Normal keystore load failed: %s" % (exc,))
        entries, scan_warnings = _read_public_entries_tolerant(data, fallback_type)
        warnings.extend(scan_warnings)
        if entries:
            return TrustImage(
                entries,
                store_type=fallback_type,
                sha256=sha256,
                path=path,
                warnings=warnings,
                source=fallback_type + ("-bytes" if path is None else "-file"),
            )
        raise

    image = _image_from_keystore(
        store,
        source="jks-bytes" if path is None else "jks-file",
        path=path,
        sha256=sha256,
        warnings=warnings,
    )
    return image


def _json_safe(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, bytearray):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, dict):
        return dict((_text(k), _json_safe(v)) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return _text(value)


class ApplicationImpact(object):
    """Computed trust impact for one application."""

    def __init__(self, application, contract=None, **kwargs):
        self.application = _text(application)
        self.app = self.application
        self.name = self.application
        self.contract = contract
        self.selection_mode = kwargs.get("selection_mode", "unknown")
        self.selection = kwargs.get("selection", self.selection_mode)
        self.selection_aliases = list(kwargs.get("selection_aliases", []))
        self.status = kwargs.get("status", "ok")
        self.reason = kwargs.get("reason")
        self.trusted_aliases = list(kwargs.get("trusted_aliases", []))
        self.trusted_entries = list(kwargs.get("trusted_entries", []))
        self.trusted_certificates = list(kwargs.get("trusted_certificates", []))
        self.missing_aliases = list(kwargs.get("missing_aliases", []))
        self.non_public_aliases = list(kwargs.get("non_public_aliases", []))
        self.duplicate_certificates = list(kwargs.get("duplicate_certificates", []))
        self.baseline_record_status = kwargs.get("baseline_record_status", "missing")
        self.baseline_aliases = list(kwargs.get("baseline_aliases", []))
        self.baseline_certificates = list(kwargs.get("baseline_certificates", []))
        self.baseline_known = kwargs.get("baseline_known", False)
        self.added_certificates = list(kwargs.get("added_certificates", []))
        self.removed_certificates = list(kwargs.get("removed_certificates", []))
        self.added_aliases = list(kwargs.get("added_aliases", []))
        self.removed_aliases = list(kwargs.get("removed_aliases", []))
        self.expanded = kwargs.get("expanded")
        self.expansion_count = kwargs.get("expansion_count")
        self.object_expanded = kwargs.get("object_expanded")
        self.alias_expanded = kwargs.get("alias_expanded")
        self.baseline_entry_count = kwargs.get("baseline_entry_count")
        self.expansion_basis = kwargs.get("expansion_basis")
        self.change = kwargs.get("change")
        self.transition = kwargs.get("transition")
        self.requires_review = kwargs.get("requires_review", False)
        self.notes = list(kwargs.get("notes", []))
        self.warnings = list(kwargs.get("warnings", []))

    @property
    def record_missing(self):
        return self.baseline_record_status == "missing"

    @property
    def trusted_entry_count(self):
        return len(self.trusted_entries)

    @property
    def trusted_certificate_count(self):
        return len(self.trusted_certificates)

    @property
    def baseline_certificate_count(self):
        return len(self.baseline_certificates)

    @property
    def added_certificate_count(self):
        return len(self.added_certificates)

    @property
    def removed_certificate_count(self):
        return len(self.removed_certificates)

    @property
    def unique_certificate_count(self):
        return self.trusted_certificate_count

    @property
    def has_duplicate_certificates(self):
        return bool(self.duplicate_certificates)

    @property
    def duplicates(self):
        return list(self.duplicate_certificates)

    @property
    def duplicate_alias_count(self):
        return sum(max(0, group["entry_count"] - 1) for group in self.duplicate_certificates)

    @property
    def added_certificate_fingerprints(self):
        return [item["fingerprint"] for item in self.added_certificates]

    @property
    def trusted_certificate_fingerprints(self):
        return [
            item.fingerprint if isinstance(item, CertificateIdentity) else item["fingerprint"]
            for item in self.trusted_certificates
        ]

    @property
    def missing_alias(self):
        return self.missing_aliases[0] if self.missing_aliases else None

    @property
    def selection_record(self):
        return {
            "status": self.baseline_record_status,
            "aliases": list(self.baseline_aliases),
            "certificates": list(self.baseline_certificates),
        }

    @property
    def issues(self):
        result = []
        if self.status != "ok":
            result.append(self.status)
        if self.missing_aliases:
            result.append("missing_aliases")
        if self.non_public_aliases:
            result.append("non_public_aliases")
        if self.baseline_record_status == "missing":
            result.append("missing_selection_record")
        if self.duplicate_certificates:
            result.append("duplicate_public_certificates")
        return result

    @property
    def selected_aliases(self):
        return list(self.trusted_aliases)

    @property
    def certificates_by_alias(self):
        result = {}
        for identity in self.trusted_certificates:
            aliases = identity.aliases if isinstance(identity, CertificateIdentity) else identity["aliases"]
            for alias in aliases:
                result[alias] = identity
        return result

    @property
    def selected_entries(self):
        return list(self.trusted_entries)

    @property
    def selected_certificates(self):
        return list(self.trusted_certificates)

    @property
    def newly_trusted_certificates(self):
        return list(self.added_certificates)

    @property
    def new_certificates(self):
        return list(self.added_certificates)

    @property
    def newly_added_certificates(self):
        return list(self.added_certificates)

    @property
    def local_to_multiple(self):
        return self.transition == "local_authorization_to_multiple_trust_objects"

    @property
    def transition_code(self):
        codes = {
            "local_authorization_to_multiple_trust_objects": "local_to_multiple",
            "local_authorization_to_duplicate_trust_objects": "duplicate_expansion",
            "no_trust_to_trust": "none_to_trust",
            "local_alias_to_multiple_alias_objects": "local_alias_to_multiple",
        }
        return codes.get(self.transition, self.transition)

    @property
    def changed(self):
        return bool(
            self.expanded is True
            or self.removed_certificates
            or self.transition
        )

    def to_dict(self):
        return {
            "application": self.application,
            "app": self.application,
            "status": self.status,
            "reason": self.reason,
            "selection_mode": self.selection_mode,
            "selection": _json_safe(self.selection),
            "selection_aliases": list(self.selection_aliases),
            "trusted_aliases": list(self.trusted_aliases),
            "trusted_entry_count": self.trusted_entry_count,
            "trusted_entries": [entry.to_dict() for entry in self.trusted_entries],
            "trusted_certificate_count": self.trusted_certificate_count,
            "trusted_certificates": [
                item.to_dict() if hasattr(item, "to_dict") else item
                for item in self.trusted_certificates
            ],
            "trusted_certificate_fingerprints": self.trusted_certificate_fingerprints,
            "missing_aliases": list(self.missing_aliases),
            "non_public_aliases": list(self.non_public_aliases),
            "duplicate_certificates": list(self.duplicate_certificates),
            "has_duplicate_certificates": self.has_duplicate_certificates,
            "baseline_record_status": self.baseline_record_status,
            "baseline_aliases": list(self.baseline_aliases),
            "baseline_certificates": list(self.baseline_certificates),
            "baseline_certificate_count": len(self.baseline_certificates),
            "baseline_known": self.baseline_known,
            "added_certificates": list(self.added_certificates),
            "added_certificate_count": len(self.added_certificates),
            "added_certificate_fingerprints": self.added_certificate_fingerprints,
            "removed_certificates": list(self.removed_certificates),
            "removed_certificate_count": len(self.removed_certificates),
            "added_aliases": list(self.added_aliases),
            "removed_aliases": list(self.removed_aliases),
            "expanded": self.expanded,
            "expansion_count": self.expansion_count,
            "object_expanded": self.object_expanded,
            "alias_expanded": self.alias_expanded,
            "baseline_entry_count": self.baseline_entry_count,
            "expansion_basis": self.expansion_basis,
            "change": self.change,
            "transition": self.transition,
            "transition_code": self.transition_code,
            "requires_review": self.requires_review,
            "issues": list(self.issues),
            "notes": list(self.notes),
            "warnings": list(self.warnings),
        }

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def __getitem__(self, key):
        return self.to_dict()[key]

    def __contains__(self, key):
        return key in self.to_dict()

    def keys(self):
        return self.to_dict().keys()

    def items(self):
        return self.to_dict().items()


class TrustImpactPreview(object):
    """Result of :func:`preview_trust_impact`."""

    def __init__(self, applications, image=None, baseline_image=None,
                 warnings=None, errors=None, require_records=True):
        self.applications = list(applications)
        self.by_application = dict((app.application, app) for app in self.applications)
        self.image = image
        self.baseline_image = baseline_image
        self.warnings = list(warnings or [])
        self.errors = list(errors or [])
        self.require_records = require_records

    @property
    def application_names(self):
        return [app.application for app in self.applications]

    @property
    def expanded_applications(self):
        return [app.application for app in self.applications if app.expanded is True]

    @property
    def newly_trusted_applications(self):
        return list(self.expanded_applications)

    @property
    def applications_with_missing_aliases(self):
        return [app.application for app in self.applications if app.missing_aliases]

    @property
    def applications_missing_selection_records(self):
        return [
            app.application for app in self.applications
            if app.baseline_record_status == "missing"
        ]

    @property
    def duplicate_certificates(self):
        """Duplicate certificate groups in the whole image."""
        if self.image is None:
            return []
        return [identity.to_dict() for identity in self.image.duplicate_certificates]

    @property
    def duplicates(self):
        return list(self.duplicate_certificates)

    @property
    def apps(self):
        return dict(self.by_application)

    @property
    def results(self):
        return dict(self.by_application)

    @property
    def transitions(self):
        return dict(
            (app.application, app.transition)
            for app in self.applications if app.transition
        )

    @property
    def transition_codes(self):
        return dict(
            (app.application, app.transition_code)
            for app in self.applications if app.transition_code
        )

    @property
    def expansion_by_application(self):
        return dict(
            (app.application, list(app.added_certificates))
            for app in self.applications if app.expanded is True
        )

    @property
    def certificate_consumers(self):
        consumers = {}
        for app in self.applications:
            for cert in app.trusted_certificates:
                sha256 = (
                    cert.sha256
                    if isinstance(cert, CertificateIdentity)
                    else cert["sha256"]
                )
                consumers.setdefault(sha256, set()).add(app.application)
        return dict(
            (sha, sorted(names)) for sha, names in consumers.items()
        )

    @property
    def shared_between_applications(self):
        return dict(
            (sha, names) for sha, names in self.certificate_consumers.items()
            if len(names) > 1
        )

    @property
    def public_entries(self):
        if self.image is None:
            return []
        return [entry.to_dict() for entry in self.image.entries]

    @property
    def entries(self):
        return self.image.entries if self.image is not None else []

    @property
    def aliases(self):
        return list(self.image.aliases) if self.image is not None else []

    @property
    def private_entries_ignored(self):
        return self.image.private_entries_ignored if self.image is not None else 0

    @property
    def private_key_entries_ignored(self):
        return self.private_entries_ignored

    @property
    def image_sha256(self):
        return self.image.sha256 if self.image is not None else None

    @property
    def image_path(self):
        return self.image.path if self.image is not None else None

    @property
    def target_image(self):
        return self.image

    @property
    def path(self):
        return self.image_path

    @property
    def new_certificates(self):
        """Certificates newly trusted by at least one application."""
        if self.baseline_image is not None and self.image is not None:
            baseline_sha = set(self.baseline_image.identities)
            return [
                identity.to_dict()
                for sha, identity in sorted(self.image.identities.items())
                if sha not in baseline_sha
            ]
        grouped = {}
        for app in self.applications:
            if app.expanded is not True:
                continue
            for item in app.added_certificates:
                grouped.setdefault(item["sha256"], item)
        return [grouped[sha] for sha in sorted(grouped)]

    @property
    def expanded_by_application(self):
        return self.expansion_by_application

    @property
    def added_certificates(self):
        grouped = {}
        for app in self.applications:
            for item in app.added_certificates:
                grouped.setdefault(item["sha256"], item)
        return [grouped[sha] for sha in sorted(grouped)]

    def get(self, application, default=None):
        if application in (
            "expanded_applications", "newly_trusted_applications",
            "duplicate_certificates", "transitions", "applications",
            "by_application", "public_entries", "image", "baseline_image",
            "certificate_consumers", "shared_between_applications",
            "applications_with_missing_aliases",
            "applications_missing_selection_records",
            "expansion_by_application", "new_certificates",
            "private_entries_ignored", "private_key_entries_ignored",
            "image_sha256", "image_path",
            "expanded_count", "changed_applications", "missing_aliases",
            "object_expanded_applications", "alias_expanded_applications",
            "all_missing_aliases", "duplicate_aliases", "transition_codes",
            "duplicates", "apps", "results", "added_certificates", "application_names",
        ):
            return getattr(self, application)
        return self.by_application.get(application, default)

    @property
    def expanded_count(self):
        return len(self.expanded_applications)

    @property
    def object_expanded_applications(self):
        return [app.application for app in self.applications if app.object_expanded is True]

    @property
    def alias_expanded_applications(self):
        return [app.application for app in self.applications if app.alias_expanded is True]

    @property
    def changed_applications(self):
        return [app.application for app in self.applications if app.changed]

    @property
    def missing_aliases(self):
        return dict(
            (app.application, list(app.missing_aliases))
            for app in self.applications if app.missing_aliases
        )

    @property
    def all_missing_aliases(self):
        result = []
        for app in self.applications:
            for alias in app.missing_aliases:
                if alias not in result:
                    result.append(alias)
        return result

    @property
    def duplicate_aliases(self):
        return [
            list(group["aliases"]) for group in self.duplicate_certificates
        ]

    def __getitem__(self, application):
        if application in self.by_application:
            return self.by_application[application]
        if application in (
            "expanded_applications", "newly_trusted_applications",
            "duplicate_certificates", "transitions", "applications",
            "by_application", "public_entries", "image", "baseline_image",
            "certificate_consumers", "shared_between_applications",
            "applications_with_missing_aliases",
            "applications_missing_selection_records",
            "expansion_by_application", "new_certificates",
            "private_entries_ignored", "private_key_entries_ignored",
            "image_sha256", "image_path",
            "expanded_count", "changed_applications", "missing_aliases",
            "object_expanded_applications", "alias_expanded_applications",
            "all_missing_aliases", "duplicate_aliases", "transition_codes",
            "duplicates", "apps", "results", "added_certificates", "application_names",
        ):
            return getattr(self, application)
        raise KeyError(application)

    def __iter__(self):
        return iter(self.applications)

    def __len__(self):
        return len(self.applications)

    def __contains__(self, application):
        if application in self.by_application:
            return True
        try:
            self[application]
            return True
        except KeyError:
            return False

    def keys(self):
        return self.to_dict().keys()

    def items(self):
        return self.to_dict().items()

    def to_dict(self):
        return {
            "image": self.image.to_dict() if self.image is not None else None,
            "baseline_image": (
                self.baseline_image.to_dict() if self.baseline_image is not None else None
            ),
            "applications": [app.to_dict() for app in self.applications],
            "application_names": list(self.application_names),
            "by_application": dict(
                (name, app.to_dict()) for name, app in self.by_application.items()
            ),
            "expanded_applications": list(self.expanded_applications),
            "newly_trusted_applications": list(self.newly_trusted_applications),
            "applications_with_missing_aliases": list(self.applications_with_missing_aliases),
            "applications_missing_selection_records": list(
                self.applications_missing_selection_records
            ),
            "duplicate_certificates": list(self.duplicate_certificates),
            "transitions": dict(self.transitions),
            "transition_codes": dict(self.transition_codes),
            "expansion_by_application": dict(self.expansion_by_application),
            "certificate_consumers": dict(self.certificate_consumers),
            "shared_between_applications": dict(self.shared_between_applications),
            "public_entries": list(self.public_entries),
            "private_entries_ignored": self.private_entries_ignored,
            "private_key_entries_ignored": self.private_key_entries_ignored,
            "image_sha256": self.image_sha256,
            "image_path": self.image_path,
            "new_certificates": list(self.new_certificates),
            "added_certificates": list(self.added_certificates),
            "expanded_count": self.expanded_count,
            "object_expanded_applications": list(self.object_expanded_applications),
            "alias_expanded_applications": list(self.alias_expanded_applications),
            "all_missing_aliases": list(self.all_missing_aliases),
            "duplicate_aliases": list(self.duplicate_aliases),
            "changed_applications": list(self.changed_applications),
            "missing_aliases": dict(self.missing_aliases),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }

    def to_json(self, **kwargs):
        kwargs.setdefault("sort_keys", True)
        kwargs.setdefault("indent", 2)
        return json.dumps(self.to_dict(), **kwargs)

    def format(self):
        lines = []
        if self.image is not None:
            lines.append("Trust image: %s (%d public entries)" % (
                self.image.path or self.image.source or "<memory>",
                len(self.image.entries),
            ))
        if not self.applications:
            lines.append("No application selection contracts were supplied.")
            return "\n".join(lines)
        for app in self.applications:
            lines.append("%s: %s" % (app.application, app.status))
            lines.append("  selected: %d aliases / %d certificates" % (
                app.trusted_entry_count, app.trusted_certificate_count,
            ))
            if app.baseline_record_status != "missing":
                lines.append("  baseline: %d certificates (%s)" % (
                    len(app.baseline_certificates), app.baseline_record_status,
                ))
                lines.append("  added: %d certificates" % len(app.added_certificates))
            else:
                lines.append("  baseline: missing real selection record")
            if app.transition:
                lines.append("  transition: %s" % app.transition)
            if app.missing_aliases:
                lines.append("  missing aliases: %s" % ", ".join(app.missing_aliases))
            if app.duplicate_certificates:
                lines.append("  duplicate selected certificates: %d group(s)" % (
                    len(app.duplicate_certificates),
                ))
        if self.expanded_applications:
            lines.append("Expanded applications: %s" % ", ".join(self.expanded_applications))
        return "\n".join(lines)

    __str__ = format


TrustImpactReport = TrustImpactPreview


def _selection_aliases_from_contract(contract):
    return list(contract.aliases)


def _select(image, contract):
    mode = contract.mode
    selected = []
    missing = []
    non_public = []
    matched = []

    if mode == "all":
        selected = list(image.entries)
        matched = list(image.aliases)
    elif mode == "aliases":
        for alias in contract.aliases:
            entries = image.entries_for_alias(alias, contract.case_sensitive)
            if entries:
                selected.extend(entries)
                matched.append(alias)
            elif image.has_alias(alias, contract.case_sensitive):
                # The alias exists, but it belongs to a private or secret
                # entry.  The public-entry reader deliberately does not use
                # that entry's protected material.
                non_public.append(alias)
            else:
                missing.append(alias)
    elif mode == "none":
        selected = []
    else:
        # An unknown selection rule must never silently become accept-all.
        selected = []

    return selected, matched, missing, non_public


def _dedupe_entries(entries):
    seen = set()
    result = []
    for entry in entries:
        key = (entry.alias, entry.sha256, entry.slot)
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)
    return result


def _identities_for_entries(entries):
    grouped = {}
    for entry in entries:
        grouped.setdefault(entry.sha256, []).append(entry)
    result = []
    for sha in sorted(grouped):
        group = grouped[sha]
        aliases = []
        for entry in group:
            if entry.alias not in aliases:
                aliases.append(entry.alias)
        result.append((sha, aliases, group))
    return result


def _identity_dicts(entries):
    return [
        CertificateIdentity(sha, aliases, group).to_dict()
        for sha, aliases, group in _identities_for_entries(entries)
    ]


def _duplicate_groups(entries):
    result = []
    for sha, aliases, group in _identities_for_entries(entries):
        if len(group) > 1:
            result.append(CertificateIdentity(sha, aliases, group).to_dict())
    return result


def _baseline_for_contract(contract, image, baseline_image):
    aliases = list(contract.baseline_aliases)
    identities = list(contract.baseline_certificates)
    status = contract.baseline_record_status

    if (not identities and not aliases and baseline_image is not None
            and status == "missing"):
        # A contract that only describes the old selector can still be applied
        # to an explicit baseline image by the caller.  An explicit empty
        # record is different and wins over this fallback.
        selected, _matched, _missing, _non_public = _select(baseline_image, contract)
        identities = sorted(set(entry.sha256 for entry in selected))
        aliases = sorted(set(entry.alias for entry in selected))
        status = "baseline_image"

    if not identities and aliases and baseline_image is not None:
        # Aliases alone are not certificate identity.  Resolve them only
        # against an explicit baseline image, never against the merged target
        # image where the same alias may already point at a rotated cert.
        source_image = baseline_image
        resolved = []
        for alias in aliases:
            for entry in source_image.entries_for_alias(alias, contract.case_sensitive):
                if entry.sha256 not in resolved:
                    resolved.append(entry.sha256)
        if resolved:
            identities = sorted(resolved)
            if status == "aliases_only":
                status = "aliases_resolved"

    return aliases, identities, status


def _compute_application_impact(name, contract, image, baseline_image,
                                require_records, global_warnings):
    selection_aliases = _selection_aliases_from_contract(contract)
    selected, matched, missing, non_public = _select(image, contract)
    selected = _dedupe_entries(selected)

    notes = []
    warnings = []
    status = "ok"
    reason = None

    if contract.mode == "unknown":
        status = "missing_selection_contract"
        reason = "selection_contract_unknown"
        notes.append("Selection rule is missing or unrecognised; no default 'all' was assumed.")
    elif missing:
        status = "missing_aliases"
        reason = "alias_not_found"
        notes.append("Some requested aliases are not present in the target image.")
    elif non_public:
        status = "missing_public_entries"
        reason = "alias_is_not_a_public_certificate"
        notes.append(
            "Some requested aliases exist but are not trusted certificate entries; "
            "their private/secret material was not read."
        )

    baseline_aliases, baseline_identities, baseline_status = _baseline_for_contract(
        contract, image, baseline_image
    )
    baseline_known = baseline_status not in ("missing", "aliases_only")
    if contract.record_missing and baseline_status == "missing":
        baseline_known = False

    if baseline_status == "missing":
        notes.append(
            "No real prior selection record was supplied; expansion is not asserted."
        )
        if require_records:
            status = "missing_selection_record" if status == "ok" else status
            reason = reason or "selection_record_missing"
        notes.append("Provide baseline aliases, baseline certificates, or a baseline image.")

    selected_identities = _identity_dicts(selected)
    selected_sha = set(item["sha256"] for item in selected_identities)
    baseline_sha = set(baseline_identities)

    added_sha = sorted(selected_sha - baseline_sha) if baseline_known else []
    removed_sha = sorted(baseline_sha - selected_sha) if baseline_known else []

    selected_alias_set = set(matched) if contract.mode == "aliases" else set(
        entry.alias for entry in selected
    )
    baseline_alias_set = set(baseline_aliases)
    baseline_aliases_known = bool(baseline_aliases) or (
        baseline_known and not baseline_identities
    )
    if baseline_status == "missing" or not baseline_aliases_known:
        # A missing record is not an empty record, and a certificate-only
        # record does not tell us which alias names were previously selected.
        added_aliases = []
        removed_aliases = []
    else:
        added_aliases = _sorted_text(selected_alias_set - baseline_alias_set)
        removed_aliases = _sorted_text(baseline_alias_set - selected_alias_set)

    selected_by_sha = dict((item["sha256"], item) for item in selected_identities)
    added_certificates = [selected_by_sha[sha] for sha in added_sha if sha in selected_by_sha]
    all_baseline_identities = {}
    if baseline_image is not None:
        for sha, identity in baseline_image.identities.items():
            all_baseline_identities[sha] = identity.to_dict()
    removed_certificates = [
        all_baseline_identities.get(sha, {
            "sha256": sha,
            "fingerprint": ":".join(sha[i:i + 2].upper() for i in range(0, len(sha), 2)),
            "aliases": [],
            "entry_count": 0,
            "duplicate": False,
            "occurrences": [],
        })
        for sha in removed_sha
    ]

    duplicate_groups = _duplicate_groups(selected)
    expanded = None
    expansion_count = None
    object_expanded = None
    alias_expanded = None
    baseline_entry_count = None
    if baseline_image is not None and baseline_status in ("baseline_image", "aliases_resolved"):
        baseline_selected, _bm, _bmissing, _bnp = _select(baseline_image, contract)
        baseline_entry_count = len(_dedupe_entries(baseline_selected))
    elif baseline_aliases:
        baseline_entry_count = len(baseline_aliases)
    if baseline_entry_count is not None:
        object_expanded = len(selected) > baseline_entry_count
        alias_expanded = len(selected_alias_set) > len(baseline_alias_set)
    change = None
    transition = None
    expansion_basis = None

    if baseline_known:
        expansion_basis = "certificate"
        expanded = bool(added_sha)
        expansion_count = len(added_sha)
        if expanded:
            change = "trust_expanded"
        elif removed_sha:
            change = "trust_reduced"
        else:
            change = "unchanged"

        baseline_count = len(baseline_sha)
        selected_count = len(selected_sha)
        if baseline_count == 0 and selected_count > 0:
            transition = "no_trust_to_trust"
        elif baseline_count <= 1 and selected_count > 1:
            transition = "local_authorization_to_multiple_trust_objects"
        elif baseline_count == selected_count and len(selected) > baseline_count and duplicate_groups:
            transition = "local_authorization_to_duplicate_trust_objects"
    elif baseline_status == "aliases_only":
        expansion_basis = "alias"
        # Names are known but certificate identity is not.  Alias growth is
        # still useful, but it is explicitly marked as alias based evidence.
        notes.append(
            "Only alias names were recorded; certificate identity and duplicate identity are not asserted."
        )
        expanded = bool(added_aliases)
        expansion_count = len(added_aliases)
        change = "alias_scope_changed" if expanded else "alias_scope_unchanged"
        baseline_count = len(baseline_alias_set)
        if baseline_count <= 1 and len(selected_alias_set) > 1:
            transition = "local_alias_to_multiple_alias_objects"

    requires_review = (
        status != "ok"
        or baseline_status == "missing"
        or bool(missing)
        or bool(non_public)
        or bool(duplicate_groups)
    )

    if duplicate_groups:
        notes.append(
            "Duplicate certificate copies are reported as one identity but as "
            "multiple entry objects."
        )

    return ApplicationImpact(
        name,
        contract=contract,
        selection_mode=contract.mode,
        selection=contract.selection,
        selection_aliases=selection_aliases,
        status=status,
        reason=reason,
        trusted_aliases=[entry.alias for entry in selected],
        trusted_entries=selected,
        trusted_certificates=[
            CertificateIdentity(sha, aliases, group)
            for sha, aliases, group in _identities_for_entries(selected)
        ],
        missing_aliases=missing,
        non_public_aliases=non_public,
        duplicate_certificates=duplicate_groups,
        baseline_record_status=baseline_status,
        baseline_aliases=baseline_aliases,
        baseline_certificates=baseline_identities,
        baseline_known=baseline_known,
        added_certificates=added_certificates,
        removed_certificates=removed_certificates,
        added_aliases=added_aliases,
        removed_aliases=removed_aliases,
        expanded=expanded,
        expansion_count=expansion_count,
        object_expanded=object_expanded,
        alias_expanded=alias_expanded,
        baseline_entry_count=baseline_entry_count,
        expansion_basis=expansion_basis,
        change=change,
        transition=transition,
        requires_review=requires_review,
        notes=notes,
        warnings=warnings,
    )


def _looks_like_single_contract(mapping):
    if not isinstance(mapping, dict):
        return False
    if _has_key(mapping, ("selection", "mode", "selection_mode", "selector",
                          "aliases", "alias", "record", "baseline")):
        return True
    if _has_key(mapping, ("application", "application_name", "program", "consumer")):
        return True
    if any(mapping.get(k) is True for k in
           ("all", "accept_all", "default_accept_all", "whole_store", "entire_store")):
        return True
    for key in ("app", "name", "id"):
        if key not in mapping:
            continue
        value = mapping[key]
        if isinstance(value, py23basestring) and _mode_from_value(value) is None:
            return True
    return False


def _normalise_contracts(contracts, records=None):
    result = []
    seen = set()

    if isinstance(contracts, SelectionContract):
        contracts = [contracts]
    elif isinstance(contracts, dict):
        looks_like_single = _looks_like_single_contract(contracts)
        if looks_like_single:
            contracts = [contracts]
        else:
            contracts = [
                dict(_contract_value_to_dict(value), application=name)
                for name, value in contracts.items()
            ]

    for item in _as_list(contracts):
        contract = SelectionContract.from_any(item)
        if not contract.application:
            contract.application = "application-%d" % (len(result) + 1)
            contract.app = contract.application
            contract.name = contract.application
        if contract.application in seen:
            raise TrustImpactError("Duplicate application contract: %s" % contract.application)
        seen.add(contract.application)
        result.append(contract)

    if records:
        if isinstance(records, dict):
            record_items = records.items()
        else:
            record_items = [(getattr(item, "application", None), item) for item in records]
        by_name = dict((item.application, item) for item in result)
        for name, record in record_items:
            if name is None:
                continue
            if name in by_name:
                contract = by_name[name]
                aliases, identities, status = _split_baseline(record)
                contract.baseline_aliases = _merge_aliases(contract.baseline_aliases, aliases)
                contract.baseline_certificates = sorted(
                    set(contract.baseline_certificates + identities)
                )
                contract.baseline_record_status = (
                    "recorded" if contract.baseline_certificates
                    else ("aliases_only" if contract.baseline_aliases else status)
                )
                contract.baseline_given = status != "missing"
            else:
                contract = SelectionContract.from_any(
                    {"application": name, "mode": "unknown", "baseline": record}
                )
                result.append(contract)

    return result


def _contract_value_to_dict(value):
    if isinstance(value, SelectionContract):
        return value.to_dict()
    if isinstance(value, dict):
        return value
    if isinstance(value, py23basestring):
        mode = _mode_from_value(value)
        if mode == "all":
            return {"mode": "all"}
        if mode == "none":
            return {"mode": "none"}
        return {"mode": "aliases", "aliases": [value]}
    if isinstance(value, (list, tuple, set)):
        return {"mode": "aliases", "aliases": list(value)}
    return {"mode": "unknown"}


def preview_trust_impact(contracts=None, image=None, baseline_image=None,
                         target_image=None, store_password=None,
                         password=None, records=None, require_records=True,
                         strict=False, case_sensitive=True, **kwargs):
    """Preview which applications gain trust in a merged public-certificate image.

    :param contracts: One selection contract per application.  A contract can
        be a :class:`SelectionContract`, a dictionary, a string alias, a list
        of aliases, or ``"all"``.  Useful dictionary keys include
        ``application``, ``mode``/``selection``, ``aliases`` and
        ``baseline``/``record``.
    :param image: The target JKS/JCEKS image, path, raw bytes, loaded
        ``KeyStore``, or an in-memory mapping/list of public entries.
    :param target_image: Keyword alias for ``image``.
    :param baseline_image: Optional image describing the prior trust state.
        A contract's explicit ``baseline`` record takes precedence.
    :param store_password: Optional password used only for integrity checking.
        Private keys are never decrypted.
    :param records: Optional mapping of application name to real prior
        selection records.  An application with no record is reported as
        ``missing_selection_record`` rather than assumed to trust nothing/everything.
    :param require_records: When true (default), a missing real selection
        record is surfaced as a review status.  It never becomes an implicit
        ``all`` or ``none`` record.
    :param strict: If true, missing aliases and missing selection records raise
        :class:`MissingAliasException` / :class:`MissingSelectionRecordException`.
    :returns: :class:`TrustImpactPreview`
    """
    if contracts is None:
        contracts = kwargs.get("selection_contracts", kwargs.get("application_contracts"))
    if image is None:
        image = target_image
    if image is None:
        for key in ("image_path", "target_image_path", "target", "truststore",
                    "keystore", "store"):
            if kwargs.get(key) is not None:
                image = kwargs.get(key)
                break
    if image is None:
        raise TrustImpactError("A target trust image is required")
    if baseline_image is None:
        for key in ("before_image", "previous_image", "baseline_path",
                    "baseline_trust_image", "baseline_store"):
            if kwargs.get(key) is not None:
                baseline_image = kwargs.get(key)
                break
    if records is None:
        records = kwargs.get("selection_records", kwargs.get("prior_records"))
    if (records is None and isinstance(baseline_image, dict)
            and _looks_like_contracts(baseline_image)):
        # Also accept records as the third positional argument.
        records = baseline_image
        baseline_image = None

    # Accept the common reversed call form: preview_trust_impact(image, contracts).
    if _looks_like_contracts(image) and not _looks_like_contracts(contracts):
        image, contracts = contracts, image

    if password is None:
        password = store_password
    if password is None:
        password = kwargs.get("image_password", kwargs.get("keystore_password"))

    if isinstance(contracts, dict) and not _has_key(contracts, _APP_KEYS + ("selection", "mode", "aliases")):
        # A plain {app: rule} mapping.
        pass

    normalised = _normalise_contracts(contracts, records=records)
    for contract in normalised:
        if "case_sensitive" not in contract.raw:
            contract.case_sensitive = case_sensitive

    image_view = _load_image(image, password=password)
    baseline_view = None
    if baseline_image is not None:
        baseline_view = _load_image(baseline_image, password=password)

    global_warnings = list(image_view.warnings)
    if baseline_view is not None:
        global_warnings.extend(baseline_view.warnings)
    if image_view.duplicate_certificates:
        global_warnings.append(
            "Duplicate public certificate copies were grouped by SHA-256 identity."
        )

    impacts = []
    for contract in normalised:
        impact = _compute_application_impact(
            contract.application,
            contract,
            image_view,
            baseline_view if contract.baseline_image is None else _load_image(
                contract.baseline_image, password=password
            ),
            require_records,
            global_warnings,
        )
        impacts.append(impact)

        if strict and impact.missing_aliases:
            raise MissingAliasException(
                "Application %s cannot select aliases: %s" % (
                    impact.application, ", ".join(impact.missing_aliases)
                )
            )
        if strict and require_records and impact.baseline_record_status == "missing":
            raise MissingSelectionRecordException(
                "Application %s has no real prior selection record" % impact.application
            )

    return TrustImpactPreview(
        impacts,
        image=image_view,
        baseline_image=baseline_view,
        warnings=global_warnings,
        require_records=require_records,
    )


compute_trust_impact = preview_trust_impact
assess_trust_impact = preview_trust_impact
inspect_trust_impact = preview_trust_impact
evaluate_trust_impact = preview_trust_impact
analyze_trust_impact = preview_trust_impact
trust_impact_preview = preview_trust_impact
build_trust_impact_preview = preview_trust_impact
preview_selection_impact = preview_trust_impact
preview_trust_store_impact = preview_trust_impact
preview_trust_changes = preview_trust_impact
compute_trust_changes = preview_trust_impact
analyze_trust_expansion = preview_trust_impact
diff_trust_images = preview_trust_impact
trust_expansion = preview_trust_impact
preview_merged_trust = preview_trust_impact
preview_impact = preview_trust_impact
impact_preview = preview_trust_impact
trust_impact_analysis = preview_trust_impact
trust_impact = preview_trust_impact
preview = preview_trust_impact
analyze = preview_trust_impact
compute = preview_trust_impact


# Friendly class aliases used by downstream reports.
TrustImpact = ApplicationImpact
ApplicationTrustImpact = ApplicationImpact
CertificateGroup = CertificateIdentity
TrustStoreImpactPreview = TrustImpactPreview
TrustStoreImpact = TrustImpactPreview
SelectionContractList = list


class TrustImpactAnalyzer(object):
    """Small object wrapper around :func:`preview_trust_impact`."""

    def __init__(self, contracts, image=None, target_image=None, **kwargs):
        self.contracts = contracts
        self.image = image if image is not None else target_image
        self.kwargs = kwargs

    def analyze(self):
        return preview_trust_impact(self.contracts, self.image, **self.kwargs)

    run = analyze
    preview = analyze
    compute = analyze
    assess = analyze
    inspect = analyze


class SharedCertificateExample(tuple):
    """Tuple-compatible demo result exposing preview and facts directly."""

    def __new__(cls, preview, facts):
        return tuple.__new__(cls, (preview, facts))

    @property
    def preview(self):
        return self[0]

    @property
    def facts(self):
        return self[1]

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return tuple.__getitem__(self, key)
        return self.preview[key]

    def __getattr__(self, name):
        return getattr(self.preview, name)

    def to_dict(self):
        return {"facts": self.facts, "preview": self.preview.to_dict()}

    def to_json(self, **kwargs):
        kwargs.setdefault("sort_keys", True)
        kwargs.setdefault("indent", 2)
        return json.dumps(self.to_dict(), **kwargs)

    def format(self):
        return self.preview.format() + "\n\n" + json.dumps(
            self.facts, sort_keys=True, indent=2
        )


def shared_certificate_example():
    """Build a small in-memory shared-certificate example.

    The returned tuple is ``(preview, example_facts)``.  The target image has
    one shared certificate under two aliases and one additional partner
    certificate.  ``default-store`` had a real prior record containing only the
    shared certificate, so the preview identifies it as moving from one local
    authorization to two distinct trusted certificate objects.
    """
    shared = b"shared-certificate-example-der"
    partner = b"partner-certificate-example-der"
    shared_sha = _sha256_bytes(shared)
    partner_sha = _sha256_bytes(partner)

    image = [
        TrustedCertEntry(type="X.509", cert=shared, timestamp=0, alias="legacy-shared"),
        TrustedCertEntry(type="X.509", cert=shared, timestamp=0, alias="merged-shared"),
        TrustedCertEntry(type="X.509", cert=partner, timestamp=0, alias="new-partner"),
    ]

    contracts = [
        {
            "application": "default-store",
            "selection": "all",
            "baseline": {"certificates": [shared_sha], "aliases": ["legacy-shared"]},
        },
        {
            "application": "legacy-alias",
            "selection": {"aliases": ["legacy-shared"]},
            "baseline": {"aliases": ["legacy-shared"], "certificates": [shared_sha]},
        },
        {
            "application": "retired-alias",
            "selection": {"aliases": ["retired-root"]},
            "baseline": {"aliases": ["retired-root"]},
        },
        {
            "application": "unknown-record",
            "selection": "all",
            "record": None,
        },
    ]

    preview = preview_trust_impact(contracts, image)
    facts = {
        "shared_certificate_sha256": shared_sha,
        "shared_certificate_fingerprint": ":".join(
            shared_sha[i:i + 2].upper() for i in range(0, len(shared_sha), 2)
        ),
        "shared_aliases": ["legacy-shared", "merged-shared"],
        "expanded_application": "default-store",
        "application": "default-store",
        "changed_application": "default-store",
        "from": "local_authorization",
        "to": "multiple_trust_objects",
        "transition": preview["default-store"].transition,
        "transition_code": preview["default-store"].transition_code,
        "duplicate_aliases": [
            item["aliases"] for item in preview.duplicate_certificates
            if item["sha256"] == shared_sha
        ],
    }
    # The partner certificate is intentionally not part of the prior record;
    # these two facts make the shared-certificate story easy to assert in docs.
    facts["added_certificate_fingerprints"] = (
        preview["default-store"].added_certificate_fingerprints
    )
    facts["partner_certificate_sha256"] = partner_sha
    facts["shared_certificate_consumers"] = preview.certificate_consumers.get(
        shared_sha, []
    )
    facts["duplicate_alias_count"] = preview["default-store"].duplicate_alias_count
    return SharedCertificateExample(preview, facts)


build_shared_certificate_example = shared_certificate_example


def run_shared_certificate_example(as_json=False):
    preview, facts = shared_certificate_example()
    if as_json:
        return json.dumps({"facts": facts, "preview": preview.to_dict()},
                          sort_keys=True, indent=2)
    return preview.format() + "\n\n" + json.dumps(facts, sort_keys=True, indent=2)


if __name__ == "__main__":
    import sys
    if "--example" in sys.argv or "--demo" in sys.argv or len(sys.argv) == 1:
        print(run_shared_certificate_example(as_json="--json" in sys.argv))
