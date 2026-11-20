# vim: set et ai ts=4 sts=4 sw=4:
# -*- coding: utf-8 -*-
"""Offline recovery-capability checks for keystores.

The functions in this module only inspect metadata that is public in a
keystore: entry categories, aliases, certificate chains and public
certificate material.  They never call ``decrypt()`` and never read a
private or secret key value.  Consequently a check can be run from a
backup inventory without having any entry password available.
"""

from __future__ import print_function

import base64
import binascii
import hashlib
import os
import re

try:
    from collections.abc import Mapping
except ImportError:  # pragma: no cover - Python 2 compatibility
    from collections import Mapping

from .util import AbstractKeystoreEntry, bitstring_to_bytes, b4


class EntryKind(object):
    """Canonical entry categories used by :func:`check_recovery`."""

    PRIVATE_KEY = "private_key"
    TRUSTED_CERT = "trusted_cert"
    SECRET_KEY = "secret_key"
    PUBLIC_KEY = "public_key"
    SEALED_KEY = "sealed_key"


EntryCategory = EntryKind
EntryType = EntryKind
EntryTypes = EntryKind
EntryCategories = EntryKind


class Capability(object):
    """Capabilities that can be required by a recovery purpose."""

    PRIVATE_KEY = "private_key"
    CERTIFICATE_CHAIN = "certificate_chain"
    TRUSTED_CERTIFICATE = "trusted_certificate"
    SECRET_KEY = "secret_key"
    PUBLIC_KEY = "public_key"
    SEALED_KEY = "sealed_key"
    IDENTITY_MATCH = "identity_match"


class RecoveryPurpose(object):
    """Common purpose names.  Plain strings are accepted as well."""

    def __init__(self, name=None, requires=None):
        self.name = name
        self.requires = requires

    @property
    def value(self):
        return self.name

    def __str__(self):
        return str(self.name)

    TLS_SERVER = "tls_server"
    TLS_CLIENT = "tls_client"
    MUTUAL_TLS = "mutual_tls"
    CODE_SIGNING = "code_signing"
    SIGNING = "signing"
    DECRYPTION = "decryption"
    TRUST_ANCHOR = "trust_anchor"
    CERTIFICATE_VALIDATION = "certificate_validation"
    SECRET_KEY = "secret_key"
    SYMMETRIC_ENCRYPTION = "symmetric_encryption"
    PUBLIC_KEY = "public_key"


Purpose = RecoveryPurpose
Purposes = RecoveryPurpose
Capabilities = Capability

ROLE_RECOVERY = "recovery"
ROLE_SECURITY = "security"

ROLE_ALIASES = {
    "recovery": ROLE_RECOVERY,
    "recovery_owner": ROLE_RECOVERY,
    "recovery_lead": ROLE_RECOVERY,
    "dr": ROLE_RECOVERY,
    "dr_owner": ROLE_RECOVERY,
    "dr_lead": ROLE_RECOVERY,
    "disaster_recovery": ROLE_RECOVERY,
    "operator": ROLE_RECOVERY,
    "recovery_operator": ROLE_RECOVERY,
    "recovery_engineer": ROLE_RECOVERY,
    "recovery_specialist": ROLE_RECOVERY,
    "disaster_recovery_lead": ROLE_RECOVERY,
    "backup_operator": ROLE_RECOVERY,
    "operations": ROLE_RECOVERY,
    "restore": ROLE_RECOVERY,
    "dr_manager": ROLE_RECOVERY,
    "business_continuity": ROLE_RECOVERY,
    "bc": ROLE_RECOVERY,
    "application_owner": ROLE_RECOVERY,
    "service_owner": ROLE_RECOVERY,
    "recovery_team": ROLE_RECOVERY,
    "dr_team": ROLE_RECOVERY,
    "security": ROLE_SECURITY,
    "auditor": ROLE_SECURITY,
    "audit": ROLE_SECURITY,
    "security_auditor": ROLE_SECURITY,
    "security_officer": ROLE_SECURITY,
    "compliance": ROLE_SECURITY,
    "risk": ROLE_SECURITY,
    "custodian": ROLE_SECURITY,
    "key_custodian": ROLE_SECURITY,
    "security_lead": ROLE_SECURITY,
    "infosec": ROLE_SECURITY,
    "risk_officer": ROLE_SECURITY,
    "key_admin": ROLE_SECURITY,
    "key_manager": ROLE_SECURITY,
    "crypto_officer": ROLE_SECURITY,
    "security_team": ROLE_SECURITY,
    "pki_team": ROLE_SECURITY,
    "certificate_team": ROLE_SECURITY,
    "灾备负责人": ROLE_RECOVERY,
    "灾备": ROLE_RECOVERY,
    "运维": ROLE_RECOVERY,
    "应用负责人": ROLE_RECOVERY,
    "安全负责人": ROLE_SECURITY,
    "安全": ROLE_SECURITY,
    "审计": ROLE_SECURITY,
    "合规": ROLE_SECURITY,
    "密钥管理员": ROLE_SECURITY,
}

_CATEGORY_ALIASES = {
    "private": EntryKind.PRIVATE_KEY,
    "privatekey": EntryKind.PRIVATE_KEY,
    "privatekeyentry": EntryKind.PRIVATE_KEY,
    "private_key": EntryKind.PRIVATE_KEY,
    "private_key_entry": EntryKind.PRIVATE_KEY,
    "private_key_entries": EntryKind.PRIVATE_KEY,
    "key": EntryKind.PRIVATE_KEY,
    "key_entry": EntryKind.PRIVATE_KEY,
    "trusted": EntryKind.TRUSTED_CERT,
    "trusted_cert": EntryKind.TRUSTED_CERT,
    "trusted_certificate": EntryKind.TRUSTED_CERT,
    "trusted_cert_entry": EntryKind.TRUSTED_CERT,
    "trustedcertentry": EntryKind.TRUSTED_CERT,
    "trusted_cert_entries": EntryKind.TRUSTED_CERT,
    "trust_anchor": EntryKind.TRUSTED_CERT,
    "cert": EntryKind.TRUSTED_CERT,
    "certs": EntryKind.TRUSTED_CERT,
    "certificate": EntryKind.TRUSTED_CERT,
    "certificates": EntryKind.TRUSTED_CERT,
    "certificate_entry": EntryKind.TRUSTED_CERT,
    "secret": EntryKind.SECRET_KEY,
    "secretkey": EntryKind.SECRET_KEY,
    "secretkeyentry": EntryKind.SECRET_KEY,
    "secret_key": EntryKind.SECRET_KEY,
    "secret_key_entry": EntryKind.SECRET_KEY,
    "symmetric": EntryKind.SECRET_KEY,
    "public": EntryKind.PUBLIC_KEY,
    "publickey": EntryKind.PUBLIC_KEY,
    "publickeyentry": EntryKind.PUBLIC_KEY,
    "public_key": EntryKind.PUBLIC_KEY,
    "public_key_entry": EntryKind.PUBLIC_KEY,
    "sealed": EntryKind.SEALED_KEY,
    "sealed_key": EntryKind.SEALED_KEY,
    "sealed_key_entry": EntryKind.SEALED_KEY,
    "bkssealedkeyentry": EntryKind.SEALED_KEY,
    "bkskeyentry": "*",
    "bkssecretkeyentry": EntryKind.SECRET_KEY,
    "bkstrustedcertentry": EntryKind.TRUSTED_CERT,
}

_CAPABILITY_ALIASES = {
    "private": Capability.PRIVATE_KEY,
    "privkey": Capability.PRIVATE_KEY,
    "privatekey": Capability.PRIVATE_KEY,
    "private_key": Capability.PRIVATE_KEY,
    "chain": Capability.CERTIFICATE_CHAIN,
    "cert_chain": Capability.CERTIFICATE_CHAIN,
    "certificate": Capability.CERTIFICATE_CHAIN,
    "certificate_chain": Capability.CERTIFICATE_CHAIN,
    "trust": Capability.TRUSTED_CERTIFICATE,
    "trust_anchor": Capability.TRUSTED_CERTIFICATE,
    "trusted_cert": Capability.TRUSTED_CERTIFICATE,
    "trusted_certificate": Capability.TRUSTED_CERTIFICATE,
    "secret": Capability.SECRET_KEY,
    "symmetric": Capability.SECRET_KEY,
    "secret_key": Capability.SECRET_KEY,
    "public": Capability.PUBLIC_KEY,
    "public_key": Capability.PUBLIC_KEY,
    "sealed": Capability.SEALED_KEY,
    "sealed_key": Capability.SEALED_KEY,
    "match": Capability.IDENTITY_MATCH,
    "identity": Capability.IDENTITY_MATCH,
    "identity_match": Capability.IDENTITY_MATCH,
}

_PURPOSE_REQUIREMENTS = {
    "tls_server": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "tls_server_auth": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "server_auth": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "server_authentication": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "https_server": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "tls_client": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "tls_client_auth": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "client_auth": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "client_authentication": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "mutual_tls": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "mtls": ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)),
    "code_signing": ((Capability.PRIVATE_KEY,),),
    "document_signing": ((Capability.PRIVATE_KEY,),),
    "signing": ((Capability.PRIVATE_KEY,),),
    "signature": ((Capability.PRIVATE_KEY,),),
    "private_key": ((Capability.PRIVATE_KEY,),),
    "decryption": ((Capability.PRIVATE_KEY,),),
    "key_decryption": ((Capability.PRIVATE_KEY,),),
    "encryption": ((Capability.PRIVATE_KEY, Capability.SECRET_KEY),),
    "trust": ((Capability.TRUSTED_CERTIFICATE,),),
    "trust_anchor": ((Capability.TRUSTED_CERTIFICATE,),),
    "trusted_certificate": ((Capability.TRUSTED_CERTIFICATE,),),
    "ca": ((Capability.TRUSTED_CERTIFICATE,),),
    "certificate_validation": ((Capability.TRUSTED_CERTIFICATE,),),
    "certificate_verification": ((Capability.TRUSTED_CERTIFICATE,),),
    "secret_key": ((Capability.SECRET_KEY,),),
    "symmetric": ((Capability.SECRET_KEY,),),
    "symmetric_encryption": ((Capability.SECRET_KEY,),),
    "hmac": ((Capability.SECRET_KEY,),),
    "mac": ((Capability.SECRET_KEY,),),
    "public_key": ((Capability.PUBLIC_KEY,),),
    "verification": ((Capability.PUBLIC_KEY,),),
    "signature_verification": ((Capability.PUBLIC_KEY,),),
}

_MATERIAL_KEYS = set([
    "alias", "aliases", "name", "id", "label",
    "cert", "certs", "certificate", "certificates", "cert_chain", "chain",
    "fingerprint", "fingerprints", "sha1", "sha256", "md5", "digest",
    "public_key", "public_keys", "spki", "raw_public_key",
    "subject", "issuer", "serial", "serial_number",
    "priority", "required", "match", "purpose",
])

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_PEM_RE = re.compile(
    r"-----BEGIN ([A-Za-z0-9 .#/-]+)-----(.*?)-----END \1-----",
    re.DOTALL,
)


# Convenient module-level names for callers that do not want to use the
# container classes.
PRIVATE_KEY = EntryKind.PRIVATE_KEY
TRUSTED_CERT = EntryKind.TRUSTED_CERT
CERTIFICATE = EntryKind.TRUSTED_CERT
SECRET_KEY = EntryKind.SECRET_KEY
PUBLIC_KEY = EntryKind.PUBLIC_KEY
SEALED_KEY = EntryKind.SEALED_KEY

CAPABILITY_PRIVATE_KEY = Capability.PRIVATE_KEY
CAPABILITY_CERTIFICATE_CHAIN = Capability.CERTIFICATE_CHAIN
CAPABILITY_TRUSTED_CERTIFICATE = Capability.TRUSTED_CERTIFICATE
CAPABILITY_SECRET_KEY = Capability.SECRET_KEY
CAPABILITY_PUBLIC_KEY = Capability.PUBLIC_KEY
CAPABILITY_IDENTITY_MATCH = Capability.IDENTITY_MATCH
CAP_PRIVATE_KEY = Capability.PRIVATE_KEY
CAP_CERTIFICATE_CHAIN = Capability.CERTIFICATE_CHAIN
CAP_TRUSTED_CERTIFICATE = Capability.TRUSTED_CERTIFICATE
CAP_SECRET_KEY = Capability.SECRET_KEY
CAP_PUBLIC_KEY = Capability.PUBLIC_KEY
CAP_IDENTITY_MATCH = Capability.IDENTITY_MATCH

ENTRY_PRIVATE_KEY = EntryKind.PRIVATE_KEY
ENTRY_TRUSTED_CERT = EntryKind.TRUSTED_CERT
ENTRY_SECRET_KEY = EntryKind.SECRET_KEY
ENTRY_PUBLIC_KEY = EntryKind.PUBLIC_KEY
ENTRY_SEALED_KEY = EntryKind.SEALED_KEY


class _AttrDict(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value

    def to_dict(self):
        return _plain(self)

    as_dict = to_dict


class RecoveryMatch(_AttrDict):
    """A candidate entry and the reason it matched the supplied material."""

    def __init__(self, values=None, entry=None):
        super(RecoveryMatch, self).__init__(values or {})
        object.__setattr__(self, "_entry", entry)

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            self[name] = value

    @property
    def entry(self):
        """The entry object, intentionally excluded from ``to_dict()``."""
        return self._entry

    def __getitem__(self, key):
        if key == "entry":
            return self._entry
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        if key == "entry":
            return self._entry
        return dict.get(self, key, default)

    def __contains__(self, key):
        if key == "entry":
            return self._entry is not None
        return dict.__contains__(self, key)

    def to_dict(self):
        return _plain(self)

    as_dict = to_dict


class RoleViews(dict):
    """The two role views, also addressable through role aliases."""

    def __getattr__(self, name):
        try:
            return self[name]
        except (KeyError, TypeError):
            raise AttributeError(name)

    def __getitem__(self, key):
        return dict.__getitem__(self, _role_key(key))

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, TypeError):
            return default

    def __contains__(self, key):
        try:
            return dict.__contains__(self, _role_key(key))
        except (KeyError, TypeError):
            return False


class RecoveryRoleView(_AttrDict):
    """A role-specific view of a :class:`RecoveryReport`."""


class RecoveryReport(_AttrDict):
    """Result of :func:`check_recovery`.

    The object is both a normal dictionary and an attribute container, so
    ``report["missing_capabilities"]`` and
    ``report.missing_capabilities`` are equivalent.  It contains no key
    bytes and no passwords.
    """

    def for_role(self, role):
        """Return the view intended for ``role``.

        Role aliases such as ``operator``, ``dr_lead``, ``auditor`` and
        ``key_custodian`` are accepted in addition to ``recovery`` and
        ``security``.
        """
        key = _role_key(role)
        views = dict.get(self, "roles", {})
        if key not in views:
            raise KeyError("Unknown recovery role: %s" % role)
        return views[key]

    role = for_role
    role_view = for_role
    view = for_role
    for_audience = for_role

    @property
    def audiences(self):
        """The two role views, in recovery/security order."""
        views = dict.get(self, "roles", {})
        return [views[ROLE_RECOVERY], views[ROLE_SECURITY]]

    @property
    def selected_match(self):
        alias = dict.get(self, "selected_alias")
        for match in dict.get(self, "matches", []):
            if match.get("alias") == alias:
                return match
        return None

    @property
    def best_match(self):
        matches = dict.get(self, "matches", [])
        return matches[0] if matches else None

    def to_dict(self, role=None):
        """Return a JSON-serializable plain dictionary."""
        if role is not None:
            return _plain(self.for_role(role))
        return _plain(self)

    as_dict = to_dict

    def to_json(self, role=None, **kwargs):
        """Return the secret-free report as JSON."""
        import json
        return json.dumps(self.to_dict(role=role), **kwargs)

    as_json = to_json
    json = to_json

    def summary(self, role=None):
        """Render a short, secret-free text report for one or both roles."""
        if role is not None:
            view = self.for_role(role)
            return _render_role(view)

        lines = [
            "Recovery check: %s" % ("READY" if self.get("ok") else "BLOCKED"),
            "Purpose: %s" % self.get("purpose"),
        ]
        if self.get("selected_alias"):
            lines.append("Selected entry: %s" % self.get("selected_alias"))
        elif self.get("best_match_alias"):
            lines.append("Best matching entry: %s" % self.get("best_match_alias"))
        if self.get("missing_capabilities"):
            lines.append("Missing capabilities: %s" %
                         ", ".join(self.get("missing_capabilities")))
        lines.append("")
        for view in self.audiences:
            lines.append(_render_role(view))
            lines.append("")
        return "\n".join(lines).rstrip()

    render = summary
    as_text = summary

    def __str__(self):
        return self.summary()

    def __getitem__(self, key):
        if isinstance(key, str) and key.lower() in ROLE_ALIASES:
            return self.for_role(key)
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        if isinstance(key, str) and key.lower() in ROLE_ALIASES:
            return self.for_role(key)
        return dict.get(self, key, default)

    def __contains__(self, key):
        if isinstance(key, str) and key.lower() in ROLE_ALIASES:
            return True
        return dict.__contains__(self, key)

    def __getattr__(self, name):
        if name.lower() in ROLE_ALIASES:
            return self.for_role(name)
        return super(RecoveryReport, self).__getattr__(name)


RecoveryAssessment = RecoveryReport


def _plain(value):
    if isinstance(value, dict):
        return dict((k, _plain(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _role_key(role):
    key = str(getattr(role, "value", role)).strip().lower().replace("-", "_")
    if key not in ROLE_ALIASES:
        raise KeyError("Unknown recovery role: %s" % role)
    return ROLE_ALIASES[key]


def _normalize_token(value):
    return re.sub(r"[^a-z0-9]+", "_", str(getattr(value, "value", value)).strip().lower()).strip("_")


def _category(value):
    if value is None:
        return None
    if isinstance(value, str):
        token = _normalize_token(value)
        if token in ("*", "all", "any"):
            return "*"
        if token in _CATEGORY_ALIASES:
            return _CATEGORY_ALIASES[token]
        if "_" in token:
            tail = token.rsplit("_", 1)[-1]
            if tail in _CATEGORY_ALIASES:
                return _CATEGORY_ALIASES[tail]
        return token

    from .jks import PrivateKeyEntry, TrustedCertEntry, SecretKeyEntry
    try:
        from .bks import (BksKeyEntry, BksSealedKeyEntry, BksSecretKeyEntry,
                          BksTrustedCertEntry)
    except ImportError:  # pragma: no cover
        BksKeyEntry = BksSealedKeyEntry = BksSecretKeyEntry = BksTrustedCertEntry = ()

    if isinstance(value, type):
        try:
            if issubclass(value, (BksTrustedCertEntry, TrustedCertEntry)):
                return EntryKind.TRUSTED_CERT
            if issubclass(value, PrivateKeyEntry):
                return EntryKind.PRIVATE_KEY
            if issubclass(value, (SecretKeyEntry, BksSecretKeyEntry)):
                return EntryKind.SECRET_KEY
            if issubclass(value, BksSealedKeyEntry):
                return EntryKind.SEALED_KEY
            if issubclass(value, BksKeyEntry):
                return "*"
        except TypeError:  # pragma: no cover - defensive for odd class pairs
            pass

    if isinstance(value, BksTrustedCertEntry) or isinstance(value, TrustedCertEntry):
        return EntryKind.TRUSTED_CERT
    if isinstance(value, PrivateKeyEntry):
        return EntryKind.PRIVATE_KEY
    if isinstance(value, SecretKeyEntry) or isinstance(value, BksSecretKeyEntry):
        return EntryKind.SECRET_KEY
    if isinstance(value, BksSealedKeyEntry):
        if value.is_decrypted():
            nested = getattr(value, "_nested", None)
            if nested is not None:
                return _category(nested)
        return EntryKind.SEALED_KEY
    if isinstance(value, BksKeyEntry):
        try:
            from .bks import KEY_TYPE_PRIVATE, KEY_TYPE_PUBLIC, KEY_TYPE_SECRET
            return {
                KEY_TYPE_PRIVATE: EntryKind.PRIVATE_KEY,
                KEY_TYPE_PUBLIC: EntryKind.PUBLIC_KEY,
                KEY_TYPE_SECRET: EntryKind.SECRET_KEY,
            }.get(value.type, EntryKind.PUBLIC_KEY)
        except (ImportError, AttributeError):
            return EntryKind.PUBLIC_KEY

    name = type(value).__name__.lower()
    if "privatekey" in name:
        return EntryKind.PRIVATE_KEY
    if "trustedcert" in name or "certificate" in name:
        return EntryKind.TRUSTED_CERT
    if "secretkey" in name:
        return EntryKind.SECRET_KEY
    if "sealedkey" in name:
        return EntryKind.SEALED_KEY
    if "bkskey" in name:
        return EntryKind.PUBLIC_KEY
    cert = _public_attr(value, "cert")
    if isinstance(cert, bytes):
        return EntryKind.TRUSTED_CERT
    return None


def _normalize_allowed(allowed_entry_types):
    if allowed_entry_types is None:
        return None, {}

    priorities = {}
    if isinstance(allowed_entry_types, Mapping):
        items = list(allowed_entry_types.items())
    elif isinstance(allowed_entry_types, str):
        text = allowed_entry_types
        if "," in text or "|" in text:
            items = [(item.strip(), None)
                     for item in re.split(r"[,|]", text) if item.strip()]
        else:
            items = [(allowed_entry_types, None)]
    elif isinstance(allowed_entry_types, type) or not hasattr(allowed_entry_types, "__iter__"):
        items = [(allowed_entry_types, None)]
    else:
        items = [(item, None) for item in allowed_entry_types]

    allowed = set()
    for item, priority in items:
        if isinstance(priority, bool):
            if not priority:
                continue
            priority = None
        cat = _category(item)
        if cat is None:
            continue
        if cat == "*":
            allowed.update([
                EntryKind.PRIVATE_KEY, EntryKind.TRUSTED_CERT,
                EntryKind.SECRET_KEY, EntryKind.PUBLIC_KEY,
                EntryKind.SEALED_KEY,
            ])
            continue
        allowed.add(cat)
        try:
            if priority is not None:
                priorities[cat] = int(priority)
        except (TypeError, ValueError):
            pass
    return allowed, priorities


def _capability(value):
    return _CAPABILITY_ALIASES.get(_normalize_token(value), _normalize_token(value))


def _normalize_requirement(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return list(value)
    except TypeError:
        return [value]


def _purpose_requirements(purpose):
    """Return ``(name, requirement_groups, warnings, policy)``."""
    warnings = []

    if isinstance(purpose, (list, tuple, set)):
        purpose = {"name": "custom", "requires": list(purpose)}

    if not isinstance(purpose, (Mapping, str)) and getattr(purpose, "requires", None):
        purpose = {"name": getattr(purpose, "name", None),
                   "requires": purpose.requires}

    if isinstance(purpose, Mapping):
        name = purpose.get("name") or purpose.get("purpose") or "custom"
        explicit = (purpose.get("requires") or purpose.get("requirements") or
                    purpose.get("required_capabilities") or
                    purpose.get("capabilities") or purpose.get("required"))
        if isinstance(explicit, str):
            explicit = [explicit]
        elif isinstance(explicit, Mapping):
            explicit = [key for key, wanted in explicit.items() if wanted]
        groups = []
        if explicit:
            for group in explicit:
                if isinstance(group, str):
                    groups.append((_capability(group),))
                else:
                    groups.append(tuple(_capability(g) for g in group))
        flag_map = [
            ("requires_private_key", Capability.PRIVATE_KEY),
            ("requires_certificate_chain", Capability.CERTIFICATE_CHAIN),
            ("requires_cert_chain", Capability.CERTIFICATE_CHAIN),
            ("requires_trusted_certificate", Capability.TRUSTED_CERTIFICATE),
            ("requires_trust_anchor", Capability.TRUSTED_CERTIFICATE),
            ("requires_secret_key", Capability.SECRET_KEY),
            ("requires_public_key", Capability.PUBLIC_KEY),
        ]
        present = set(group[0] for group in groups if len(group) == 1)
        for flag, cap in flag_map:
            if purpose.get(flag) and cap not in present:
                groups.append((cap,))
        if not groups:
            groups = [(Capability.PRIVATE_KEY, Capability.SECRET_KEY,
                       Capability.TRUSTED_CERTIFICATE, Capability.PUBLIC_KEY)]
            warnings.append("custom_purpose_without_requirements")
        return str(name), groups, warnings, purpose

    if not isinstance(purpose, str):
        purpose = str(getattr(purpose, "value", purpose))
    name = str(purpose)
    key = _normalize_token(name)

    if key in _PURPOSE_REQUIREMENTS:
        return name, _PURPOSE_REQUIREMENTS[key], warnings, None

    tokens = set(key.split("_"))
    if (key.startswith("trust") or "trust" in tokens or
            "trustanchor" in key or key.endswith("_ca") or
            "validation" in key or "verification" in key) and \
            "signature" not in tokens:
        return name, ((Capability.TRUSTED_CERTIFICATE,),), warnings, None
    if key in ("certificate", "certificates", "cert", "certs", "ca_cert"):
        return name, ((Capability.TRUSTED_CERTIFICATE,),), warnings, None
    if "secret" in tokens or "symmetric" in tokens or "hmac" in tokens:
        return name, ((Capability.SECRET_KEY,),), warnings, None
    if "verify" in tokens or "verification" in tokens or "public" in tokens:
        return name, ((Capability.PUBLIC_KEY,),), warnings, None

    tls_prefixes = ("tls", "ssl", "server", "client")
    key_prefixes = ("sign", "signing", "decrypt", "private", "auth",
                    "exchange", "agreement", "key")
    has_tls = any(token in tls_prefixes or token.startswith(tls_prefixes)
                  for token in tokens) or \
        any(token.startswith(tls_prefixes) for token in [key])
    has_key = any(token in key_prefixes or token.startswith(key_prefixes)
                  for token in tokens) or key.startswith(key_prefixes)
    if has_key or has_tls:
        if has_tls:
            return name, ((Capability.PRIVATE_KEY,), (Capability.CERTIFICATE_CHAIN,)), warnings, None
        return name, ((Capability.PRIVATE_KEY,),), warnings, None

    warnings.append("unknown_purpose")
    return name, ((Capability.PRIVATE_KEY, Capability.SECRET_KEY,
                   Capability.TRUSTED_CERTIFICATE, Capability.PUBLIC_KEY),), warnings, None


def _missing_for(capabilities, groups):
    missing = []
    for group in groups:
        if not any(cap in capabilities for cap in group):
            for cap in group:
                if cap not in missing:
                    missing.append(cap)
    return missing


def _flatten_groups(groups):
    result = []
    for group in groups:
        for cap in group:
            if cap not in result:
                result.append(cap)
    return result


def _cert_der(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, tuple):
        for item in reversed(value):
            if isinstance(item, bytes):
                return item
        return None
    cert = _public_attr(value, "cert")
    if cert is not None:
        return _cert_der(cert)
    return None


def _public_attr(obj, name, default=None):
    """Read a stored metadata attribute without invoking decryption guards."""
    try:
        return object.__getattribute__(obj, name)
    except (AttributeError, TypeError):
        return default


def _cert_facts(der):
    if not isinstance(der, bytes):
        return None
    result = {
        "der": der,
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
        "md5": hashlib.md5(der).hexdigest(),
        "valid": False,
        "spki": None,
        "public_key": None,
        "subject": None,
        "issuer": None,
        "serial": None,
    }
    try:
        from pyasn1.codec.der import decoder, encoder
        from pyasn1_modules import rfc2459
        cert, rest = decoder.decode(der, asn1Spec=rfc2459.Certificate())
        if rest:
            return result
        tbs = cert["tbsCertificate"]
        spki = encoder.encode(tbs["subjectPublicKeyInfo"])
        public_key = bitstring_to_bytes(tbs["subjectPublicKeyInfo"]["subjectPublicKey"])
        result.update({
            "valid": True,
            "spki": spki,
            "public_key": public_key,
            "subject": _normalize_dn(tbs["subject"].prettyPrint()),
            "issuer": _normalize_dn(tbs["issuer"].prettyPrint()),
            "subject_values": _name_values(tbs["subject"]),
            "issuer_values": _name_values(tbs["issuer"]),
            "serial": int(tbs["serialNumber"]),
            "spki_sha256": hashlib.sha256(spki).hexdigest(),
            "spki_sha1": hashlib.sha1(spki).hexdigest(),
            "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
            "public_key_sha1": hashlib.sha1(public_key).hexdigest(),
        })
    except Exception:
        pass
    return result


def _normalize_dn(value):
    if value is None:
        return None
    return re.sub(r"\s+", " ", str(value)).strip().lower()


_DN_NAMES = {
    "2.5.4.3": "cn",
    "2.5.4.6": "c",
    "2.5.4.7": "l",
    "2.5.4.8": "st",
    "2.5.4.10": "o",
    "2.5.4.11": "ou",
}


def _der_text(value):
    """Decode the simple string types used by X.509 distinguished names."""
    if not isinstance(value, bytes) or len(value) < 2:
        return None
    tag = value[0]
    if tag not in (0x0c, 0x13, 0x14, 0x16, 0x1e):
        return None
    length = value[1]
    offset = 2
    if length & 0x80:
        count = length & 0x7f
        if not count or len(value) < 2 + count:
            return None
        length = int(binascii.hexlify(value[2:2 + count]), 16)
        offset = 2 + count
    payload = value[offset:offset + length]
    encoding = "utf-16-be" if tag == 0x1e else "utf-8"
    try:
        return payload.decode(encoding, "replace")
    except (UnicodeError, LookupError):
        return None


def _name_values(name):
    values = []
    try:
        for rdn in name.getComponent():
            for atv in rdn:
                text = _der_text(atv["value"].asOctets())
                if text:
                    values.append((_DN_NAMES.get(str(atv["type"])),
                                   _normalize_dn(text)))
    except Exception:
        pass
    return values


def _entry_certs(entry, category):
    """Return ``(index, der, is_leaf)`` tuples without touching key bytes."""
    out = []
    seen = set()

    def add(index, der, is_leaf):
        if isinstance(der, bytes) and der not in seen:
            seen.add(der)
            out.append((index, der, is_leaf))

    trusted = category == EntryKind.TRUSTED_CERT
    cert = _public_attr(entry, "cert")
    if isinstance(cert, bytes):
        add(0, cert, True)

    chain = _public_attr(entry, "cert_chain") or []
    start = 1 if trusted else 0
    for offset, item in enumerate(chain):
        der = _cert_der(item)
        if der is None:
            continue
        index = start + offset
        add(index, der, index == 0)
    return out


def _entry_capabilities(entry, category, certs):
    caps = set()
    if category == EntryKind.PRIVATE_KEY:
        caps.add(Capability.PRIVATE_KEY)
    elif category == EntryKind.SECRET_KEY:
        caps.add(Capability.SECRET_KEY)
    elif category == EntryKind.TRUSTED_CERT:
        caps.add(Capability.TRUSTED_CERTIFICATE)
    elif category == EntryKind.PUBLIC_KEY:
        caps.add(Capability.PUBLIC_KEY)
    elif category == EntryKind.SEALED_KEY:
        caps.add(Capability.SEALED_KEY)

    if certs:
        caps.add(Capability.CERTIFICATE_CHAIN)
        caps.add(Capability.PUBLIC_KEY)
    return caps


def _looks_like_material_dict(value):
    return any(str(key).lower() in _MATERIAL_KEYS for key in value.keys())


def _decode_pem(value):
    if isinstance(value, bytes):
        text = value.decode("ascii", "ignore")
    else:
        text = str(value)
    if "-----BEGIN" not in text:
        return None

    certs = []
    public_keys = []
    for label, body in _PEM_RE.findall(text):
        try:
            der = base64.b64decode(re.sub(r"\s+", "", body).encode("ascii"))
        except (TypeError, ValueError, binascii.Error):
            continue
        normalized = label.upper()
        if "CERTIFICATE" in normalized:
            certs.append(der)
        elif normalized in ("PUBLIC KEY", "RSA PUBLIC KEY"):
            public_keys.append(der)
    return certs, public_keys


def _hexlify(value):
    if hasattr(value, "hex"):
        return value.hex()
    return binascii.hexlify(value).decode("ascii")


def _fingerprint_spec(value):
    text = str(value).strip().lower()
    for separator in (":", "="):
        if separator in text:
            algorithm = re.sub(r"[^a-z0-9]", "", text.split(separator, 1)[0])
            if algorithm in ("sha256", "sha1", "md5"):
                digest = re.sub(r"[^0-9a-fA-F]", "", text.split(separator, 1)[1]).lower()
                if digest:
                    return (algorithm, digest)
    raw = re.sub(r"[^0-9a-fA-F]", "", text)
    if not raw or not _HEX_RE.match(raw):
        return None
    size = len(raw) // 2
    if size == 16:
        return ("md5", raw.lower())
    if size == 20:
        return ("sha1", raw.lower())
    if size == 32:
        return ("sha256", raw.lower())
    return None


class _MaterialSpec(object):
    def __init__(self):
        self.label = None
        self.alias = None
        self.certs = []
        self.fingerprints = []
        self.public_keys = []
        self.raw_public_keys = []
        self.subject = None
        self.issuer = None
        self.serial = None
        self.priority = None
        self.order = 0
        self.required = True

    def add_cert(self, value):
        der = _cert_der(value)
        if isinstance(der, bytes) and der not in self.certs:
            self.certs.append(der)
            return True
        return False

    def add_public_key(self, value):
        if isinstance(value, str):
            decoded = _decode_pem(value)
            if decoded:
                for der in decoded[1]:
                    self.add_public_key(der)
                return
        if isinstance(value, bytes):
            if value not in self.public_keys:
                self.public_keys.append(value)
            facts = _cert_facts(value)
            if facts and facts.get("public_key") and facts["public_key"] not in self.raw_public_keys:
                self.raw_public_keys.append(facts["public_key"])

    def add_fingerprint(self, value):
        if isinstance(value, tuple) and len(value) == 2:
            algorithm = str(value[0]).lower()
            digest = re.sub(r"[^0-9a-fA-F]", "", str(value[1])).lower()
            if algorithm in ("md5", "sha1", "sha256") and digest:
                fingerprint = (algorithm, digest)
                if fingerprint not in self.fingerprints:
                    self.fingerprints.append(fingerprint)
                return
        fingerprint = _fingerprint_spec(value)
        if fingerprint and fingerprint not in self.fingerprints:
            self.fingerprints.append(fingerprint)

    def empty(self):
        return not any([self.alias, self.certs, self.fingerprints,
                        self.public_keys, self.raw_public_keys,
                        self.subject, self.issuer, self.serial is not None])


def _spec_from_value(value):
    spec = _MaterialSpec()

    if value is None:
        return spec
    if isinstance(value, bytearray):
        value = bytes(value)

    from .jks import PrivateKeyEntry, TrustedCertEntry
    if isinstance(value, TrustedCertEntry):
        spec.alias = getattr(value, "alias", None)
        spec.add_cert(getattr(value, "cert", None))
        return spec
    if isinstance(value, PrivateKeyEntry):
        spec.alias = getattr(value, "alias", None)
        for item in getattr(value, "cert_chain", []) or []:
            spec.add_cert(item)
        return spec

    if isinstance(value, Mapping):
        return _spec_from_dict(value)

    if (isinstance(value, tuple) and len(value) == 2 and
            isinstance(value[1], (int, float)) and not isinstance(value[1], bool)):
        spec = _spec_from_value(value[0])
        spec.priority = int(value[1])
        return spec

    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        if value[0].upper() in ("X.509", "X509", "CERTIFICATE"):
            return _spec_from_value(value[1])
        spec = _spec_from_value(value[1])
        spec.alias = value[0]
        if spec.label is None:
            spec.label = value[0]
        return spec

    if isinstance(value, bytes):
        pem = _decode_pem(value)
        if pem is not None:
            for der in pem[0]:
                spec.add_cert(der)
            for der in pem[1]:
                spec.add_public_key(der)
            return spec
        facts = _cert_facts(value)
        if facts and facts.get("valid"):
            spec.add_cert(value)
            return spec
        facts = _cert_facts(value)
        if facts and facts.get("spki"):
            spec.add_public_key(value)
            return spec
        if len(value) in (16, 20, 32):
            digest = _hexlify(value)
            spec.fingerprints.append({
                16: ("md5", digest),
                20: ("sha1", digest),
                32: ("sha256", digest),
            }[len(value)])
            return spec
        spec.public_keys.append(value)
        return spec

    if isinstance(value, str):
        pem = _decode_pem(value)
        if pem is not None:
            for der in pem[0]:
                spec.add_cert(der)
            for der in pem[1]:
                spec.add_public_key(der)
            return spec
        fingerprint = _fingerprint_spec(value)
        if fingerprint:
            spec.fingerprints.append(fingerprint)
        else:
            raw = re.sub(r"[^0-9a-fA-F]", "", value)
            if len(raw) >= 64 and len(raw) % 2 == 0 and _HEX_RE.match(raw):
                try:
                    decoded = _spec_from_value(binascii.unhexlify(raw))
                    if decoded.certs:
                        return decoded
                except (TypeError, ValueError, binascii.Error):
                    pass
            compact = re.sub(r"\s+", "", value)
            if len(compact) >= 64:
                try:
                    decoded = _spec_from_value(base64.b64decode(compact))
                    if decoded.certs:
                        return decoded
                except (TypeError, ValueError, binascii.Error):
                    pass
            spec.alias = value
        return spec

    for attr in ("cert", "certificate", "cert_chain"):
        item = _public_attr(value, attr)
        if item is not None:
            if isinstance(item, (list, tuple)):
                for cert in item:
                    spec.add_cert(cert)
            else:
                spec.add_cert(item)
            spec.alias = _public_attr(value, "alias")
            if not spec.empty():
                return spec
    for attr in ("public_key", "public_key_info", "spki"):
        item = _public_attr(value, attr)
        if item is not None:
            spec.add_public_key(item)
            spec.alias = _public_attr(value, "alias")
            if not spec.empty():
                return spec
    return spec


def _spec_from_dict(value):
    spec = _MaterialSpec()
    normalized = dict((str(k).lower(), v) for k, v in value.items())

    spec.alias = (normalized.get("alias") or normalized.get("aliases") or
                  normalized.get("name") or normalized.get("id") or
                  normalized.get("label"))
    spec.label = normalized.get("label") or normalized.get("name") or spec.alias
    spec.subject = normalized.get("subject")
    spec.issuer = normalized.get("issuer")
    spec.serial = normalized.get("serial", normalized.get("serial_number"))
    spec.required = bool(normalized.get("required", True))

    try:
        if normalized.get("priority") is not None:
            spec.priority = int(normalized.get("priority"))
    except (TypeError, ValueError):
        spec.priority = None

    for key in ("cert", "certificate", "certs", "certificates", "cert_chain", "chain"):
        if key not in normalized:
            continue
        item = normalized[key]
        if isinstance(item, (list, tuple)) and not (
                len(item) == 2 and isinstance(item[0], str) and isinstance(item[1], bytes)):
            for cert in item:
                _add_cert_value(spec, cert)
        else:
            _add_cert_value(spec, item)

    for key in ("fingerprint", "fingerprints", "digest"):
        if key in normalized:
            item = normalized[key]
            for fingerprint in (item if isinstance(item, (list, tuple)) else [item]):
                spec.add_fingerprint(fingerprint)

    for algorithm in ("md5", "sha1", "sha256"):
        if algorithm in normalized:
            value = normalized[algorithm]
            for fingerprint in (value if isinstance(value, (list, tuple)) else [value]):
                if isinstance(fingerprint, (bytes, bytearray)):
                    fingerprint = _hexlify(bytes(fingerprint))
                spec.fingerprints.append((algorithm, re.sub(r"[^0-9a-fA-F]", "", str(fingerprint)).lower()))

    for key in ("public_key", "public_keys", "spki", "raw_public_key"):
        if key in normalized:
            item = normalized[key]
            for public_key in (item if isinstance(item, (list, tuple)) else [item]):
                spec.add_public_key(public_key)

    return spec


def _add_cert_value(spec, item):
    if isinstance(item, str) and "-----BEGIN" in item:
        decoded = _decode_pem(item)
        if decoded:
            for der in decoded[0]:
                spec.add_cert(der)
            return
    if spec.add_cert(item):
        return
    if isinstance(item, str):
        parsed = _spec_from_value(item)
        if parsed.certs:
            for der in parsed.certs:
                spec.add_cert(der)
            return
        fingerprint = _fingerprint_spec(item)
        if fingerprint:
            spec.fingerprints.append(fingerprint)


def _ordered_specs(specs):
    result = [spec for spec in specs if not spec.empty()]
    for order, spec in enumerate(result):
        spec.order = order
    return result


def _normalize_material(public_material):
    specs = []
    if public_material is None:
        return specs

    if isinstance(public_material, Mapping):
        if _looks_like_material_dict(public_material):
            specs.append(_spec_from_dict(public_material))
        else:
            for alias, value in public_material.items():
                if isinstance(value, Mapping):
                    spec = _spec_from_dict(value)
                elif (isinstance(value, (int, float)) and
                      not isinstance(value, bool)):
                    spec = _MaterialSpec()
                    spec.priority = int(value)
                else:
                    spec = _spec_from_value(value)
                if not spec.alias:
                    spec.alias = alias
                if not spec.label:
                    spec.label = alias
                specs.append(spec)
        return _ordered_specs(specs)

    if (isinstance(public_material, tuple) and len(public_material) == 2 and
            isinstance(public_material[0], str)):
        spec = _spec_from_value(public_material)
        return _ordered_specs([spec])

    if (isinstance(public_material, tuple) and len(public_material) == 2 and
            isinstance(public_material[1], (int, float)) and
            not isinstance(public_material[1], bool)):
        spec = _spec_from_value(public_material)
        return _ordered_specs([spec])

    if isinstance(public_material, (list, tuple, set)):
        values = public_material
        if isinstance(public_material, set):
            values = sorted(public_material, key=lambda item: repr(item))
        for value in values:
            spec = _spec_from_value(value)
            if not spec.empty():
                specs.append(spec)
        return _ordered_specs(specs)

    spec = _spec_from_value(public_material)
    if not spec.empty():
        specs.append(spec)
    return _ordered_specs(specs)


def _match_spec(spec, certs, alias):
    best = [None]

    def consider(rank, basis):
        if best[0] is None or rank < best[0][0]:
            best[0] = (rank, basis)

    if spec.alias and alias is not None and str(spec.alias).lower() == str(alias).lower():
        consider(50, "alias")

    for index, der, is_leaf in certs:
        facts = _cert_facts(der)
        if not facts:
            continue
        if der in spec.certs:
            consider(10 if is_leaf else 20,
                     "certificate_leaf" if is_leaf else "certificate_chain")
        for algorithm, digest in spec.fingerprints:
            if facts.get(algorithm) == digest:
                rank = {"sha256": 10, "sha1": 12, "md5": 14}.get(algorithm, 16)
                if not is_leaf:
                    rank += 5
                consider(rank, "fingerprint_" + algorithm)
            elif facts.get("spki_" + algorithm) == digest:
                consider(16 if is_leaf else 26, "public_key_fingerprint_" + algorithm)
            elif facts.get("public_key_" + algorithm) == digest:
                consider(17 if is_leaf else 27, "public_key_fingerprint_" + algorithm)
        for public_key in spec.public_keys:
            if public_key == facts.get("spki") or public_key == facts.get("public_key"):
                consider(15 if is_leaf else 25, "public_key")
        for public_key in spec.raw_public_keys:
            if public_key == facts.get("public_key"):
                consider(15 if is_leaf else 25, "public_key")
        if spec.subject and facts.get("subject"):
            wanted = _normalize_dn(spec.subject)
            if wanted in facts["subject"] or facts["subject"] in wanted:
                consider(35, "subject")
            else:
                for name, value in facts.get("subject_values", []):
                    if (wanted == name + "=" + value or
                            (len(value) >= 2 and
                             (wanted == value or value in wanted))):
                        consider(34, "subject")
                        break
        if spec.issuer and facts.get("issuer"):
            wanted = _normalize_dn(spec.issuer)
            if wanted in facts["issuer"] or facts["issuer"] in wanted:
                consider(38, "issuer")
            else:
                for name, value in facts.get("issuer_values", []):
                    if (wanted == name + "=" + value or
                            (len(value) >= 2 and
                             (wanted == value or value in wanted))):
                        consider(37, "issuer")
                        break
        if spec.serial is not None and facts.get("serial") is not None:
            try:
                wanted = int(str(spec.serial), 0)
            except (TypeError, ValueError):
                try:
                    wanted = int(str(spec.serial), 16)
                except (TypeError, ValueError):
                    wanted = None
            if wanted is not None and wanted == facts["serial"]:
                consider(30, "serial")

    return best[0]


def _entry_material_match(entry, certs, specs):
    alias = getattr(entry, "alias", None)
    best = None
    labels = []
    for spec in specs:
        match = _match_spec(spec, certs, alias)
        if match is None:
            continue
        label = spec.label or (str(spec.alias) if spec.alias else "public_material")
        labels.append(label)
        priority = spec.priority if spec.priority is not None else 999999
        value = (priority, spec.order, match[0], match[1])
        if best is None or value < best:
            best = value
    if best is None:
        return None
    return {"priority": best[0], "order": best[1], "rank": best[2],
            "basis": best[3], "labels": labels}


def _kind_order(category, required, allowed_priorities):
    if category in allowed_priorities:
        return allowed_priorities[category]

    requiring = set(required)
    if Capability.PRIVATE_KEY in requiring:
        order = [EntryKind.PRIVATE_KEY, EntryKind.SEALED_KEY,
                 EntryKind.TRUSTED_CERT, EntryKind.PUBLIC_KEY, EntryKind.SECRET_KEY]
    elif Capability.TRUSTED_CERTIFICATE in requiring:
        order = [EntryKind.TRUSTED_CERT, EntryKind.PUBLIC_KEY,
                 EntryKind.PRIVATE_KEY, EntryKind.SEALED_KEY, EntryKind.SECRET_KEY]
    elif Capability.SECRET_KEY in requiring:
        order = [EntryKind.SECRET_KEY, EntryKind.SEALED_KEY,
                 EntryKind.PRIVATE_KEY, EntryKind.TRUSTED_CERT, EntryKind.PUBLIC_KEY]
    elif Capability.PUBLIC_KEY in requiring:
        order = [EntryKind.TRUSTED_CERT, EntryKind.PUBLIC_KEY,
                 EntryKind.PRIVATE_KEY, EntryKind.SEALED_KEY, EntryKind.SECRET_KEY]
    else:
        order = [EntryKind.PRIVATE_KEY, EntryKind.SECRET_KEY,
                 EntryKind.SEALED_KEY, EntryKind.TRUSTED_CERT, EntryKind.PUBLIC_KEY]
    try:
        return order.index(category)
    except ValueError:
        return len(order)


def _store_entries(store, store_password=None):
    if isinstance(store, Mapping):
        return dict(store)
    if isinstance(store, AbstractKeystoreEntry):
        alias = getattr(store, "alias", None) or "<entry>"
        return {alias: store}
    if hasattr(store, "entries"):
        return dict(store.entries)
    if isinstance(store, (list, tuple)):
        return dict((getattr(entry, "alias", None) or str(i), entry)
                    for i, entry in enumerate(store))

    if hasattr(os, "PathLike") and isinstance(store, os.PathLike):
        store = os.fspath(store)
    if isinstance(store, str) and os.path.exists(store):
        with open(store, "rb") as file:
            data = file.read()
    elif isinstance(store, bytes):
        data = store
    elif hasattr(store, "read") and not isinstance(store, Mapping):
        data = store.read()
    else:
        raise TypeError("Expected a keystore, mapping of entries, or keystore bytes")

    from .jks import KeyStore
    from .bks import BksKeyStore, UberKeyStore

    if data[:4] == b"\xFE\xED\xFE\xED" or data[:4] == b"\xCE\xCE\xCE\xCE":
        loaded = KeyStore.loads(data, store_password, try_decrypt_keys=False)
        return dict(loaded.entries)
    if data[:4] in (b"\x00\x00\x00\x01", b"\x00\x00\x00\x02"):
        if store_password is not None:
            loaded = BksKeyStore.loads(data, store_password, try_decrypt_keys=False)
            return dict(loaded.entries)
        # BKS entry metadata can be read without its password.  The HMAC at
        # the end cannot be verified offline, so report that separately
        # rather than asking for a secret.
        try:
            pos = 0
            version = b4.unpack_from(data, pos)[0]; pos += 4
            if version not in (1, 2):
                raise ValueError("Unsupported BKS version")
            salt, pos = BksKeyStore._read_data(data, pos)
            iteration_count = b4.unpack_from(data, pos)[0]; pos += 4
            entries, size = BksKeyStore._load_bks_entries(
                data[pos:], "bks", None, try_decrypt_keys=False)
            return dict(entries)
        except Exception as error:
            raise ValueError("Not a recognized JKS, JCEKS, BKS or UBER keystore: %s" % error)
    raise ValueError("Not a recognized JKS, JCEKS, BKS or UBER keystore")


def _is_decrypted(entry):
    try:
        return bool(entry.is_decrypted())
    except Exception:
        return True


def _entry_metadata(entry):
    category = _category(entry)
    certs = _entry_certs(entry, category)
    capabilities = _entry_capabilities(entry, category, certs)
    return category, certs, capabilities


def _make_match(alias, entry, category, certs, capabilities, required,
                material_match, position):
    missing = _missing_for(capabilities, required)
    decrypted = _is_decrypted(entry)

    fingerprints = []
    for _, der, _ in certs:
        facts = _cert_facts(der)
        if facts:
            fingerprints.append({"sha256": facts.get("sha256"),
                                 "sha1": facts.get("sha1"),
                                 "md5": facts.get("md5")})
    leaf_fingerprint = fingerprints[0].get("sha256") if fingerprints else None

    match = RecoveryMatch({
        "alias": alias,
        "entry_alias": alias,
        "fingerprint": leaf_fingerprint,
        "sha256": leaf_fingerprint,
        "certificate_fingerprints": fingerprints,
        "entry_type": type(entry).__name__,
        "category": category,
        "entry_category": category,
        "kind": category,
        "type": category,
        "capabilities": sorted(capabilities),
        "has_private_key": Capability.PRIVATE_KEY in capabilities,
        "has_certificate_chain": Capability.CERTIFICATE_CHAIN in capabilities,
        "has_trusted_certificate": Capability.TRUSTED_CERTIFICATE in capabilities,
        "has_secret_key": Capability.SECRET_KEY in capabilities,
        "missing_capabilities": missing,
        "satisfies": not missing,
        "priority": position,
        "order": position,
        "rank": material_match["rank"] if material_match else 60,
        "material_order": material_match["order"] if material_match else None,
        "basis_priority": material_match["rank"] if material_match else 60,
        "match_basis": material_match["basis"] if material_match else "allowed_entry",
        "match_type": material_match["basis"] if material_match else "allowed_entry",
        "matched_by": material_match["basis"] if material_match else "allowed_entry",
        "match_reason": material_match["basis"] if material_match else "allowed_entry",
        "alias_match": bool(material_match and material_match["basis"] == "alias"),
        "exact_certificate": bool(material_match and material_match["basis"] in
                                  ("certificate_leaf", "certificate_chain")),
        "chain_match": bool(material_match and "chain" in material_match["basis"]),
        "matched_material": material_match["labels"] if material_match else [],
        "identity_match": bool(material_match),
        "certificate_count": len(certs),
        "chain_length": len(certs),
        "encrypted": not decrypted,
        "is_decrypted": decrypted,
    }, entry=entry)
    return match


def _role_view(role, report):
    missing = list(report.get("missing_capabilities", []))
    focus = {
        ROLE_RECOVERY: [
            Capability.PRIVATE_KEY, Capability.SECRET_KEY,
            Capability.SEALED_KEY, Capability.CERTIFICATE_CHAIN,
            Capability.IDENTITY_MATCH,
        ],
        ROLE_SECURITY: [
            Capability.TRUSTED_CERTIFICATE, Capability.CERTIFICATE_CHAIN,
            Capability.PUBLIC_KEY, Capability.IDENTITY_MATCH,
        ],
    }[role]
    specific = [cap for cap in missing if cap in focus]
    focused = list(missing)

    actions = _actions_for(missing)
    if report.get("ok"):
        message = ("Recovery capability confirmed; no missing capability."
                   if role == ROLE_RECOVERY
                   else "Identity and trust material confirmed; no missing capability.")
    else:
        message = ("Recovery blocked; missing capability: %s." % ", ".join(missing)
                   if role == ROLE_RECOVERY else
                   "Security review blocked; missing capability: %s." % ", ".join(missing))

    return RecoveryRoleView({
        "role": role,
        "name": role,
        "audience": role,
        "status": "ready" if report.get("ok") else "blocked",
        "ok": bool(report.get("ok")),
        "passed": bool(report.get("ok")),
        "result": "pass" if report.get("ok") else "fail",
        "supported": bool(report.get("ok")),
        "message": message,
        "missing_capabilities": missing,
        "missing": missing,
        "gaps": missing,
        "capability_gaps": missing,
        "capabilities": list(report.get("available_capabilities", [])),
        "focus_capabilities": focus,
        "focus_missing_capabilities": focused,
        "role_specific_missing_capabilities": specific,
        "role_missing_capabilities": specific,
        "missing_for_role": specific,
        "role_gaps": specific,
        "all_missing_capabilities": missing,
        "overall_missing_capabilities": missing,
        "required_capabilities": list(report.get("required_capabilities", [])),
        "available_capabilities": list(report.get("available_capabilities", [])),
        "selected_alias": report.get("selected_alias"),
        "best_match_alias": report.get("best_match_alias"),
        "warnings": list(report.get("warnings", [])),
        "actions": actions,
        "next_steps": [item["action"] for item in actions],
    })


def _actions_for(missing):
    actions = []
    messages = {
        Capability.PRIVATE_KEY: "Restore a private-key entry for the matched identity; a certificate chain alone is not sufficient.",
        Capability.CERTIFICATE_CHAIN: "Attach the leaf and issuing certificates to the key entry.",
        Capability.TRUSTED_CERTIFICATE: "Add the expected certificate as a trusted-certificate entry.",
        Capability.SECRET_KEY: "Restore the required secret-key entry.",
        Capability.PUBLIC_KEY: "Provide an entry containing the expected public key or certificate.",
        Capability.SEALED_KEY: "Unlock the sealed key entry with the custodian-held password before recovery.",
        Capability.IDENTITY_MATCH: "Provide certificate, public-key or fingerprint material that matches an allowed entry.",
    }
    for cap in missing:
        actions.append({"capability": cap, "action": messages.get(cap, "Restore capability: %s" % cap)})
    return actions


def _render_role(view):
    lines = ["%s: %s" % (view.get("role"), view.get("status").upper())]
    lines.append("  %s" % view.get("message"))
    if view.get("best_match_alias"):
        lines.append("  Best matching entry: %s" % view.get("best_match_alias"))
    if view.get("focus_missing_capabilities"):
        lines.append("  Missing for this role: %s" %
                     ", ".join(view.get("focus_missing_capabilities")))
    return "\n".join(lines)


def check_recovery(store, purpose, allowed_entry_types=None, public_material=None,
                   store_password=None, **kwargs):
    """Check which recovery purpose a keystore can actually support.

    The check is offline and read-only: it looks at entry categories,
    aliases and public certificate material.  It does not decrypt entries
    and does not return private keys, secret keys or passwords.

    :param store: A loaded keystore, a mapping of aliases to entries, a
      sequence of entries, or raw JKS/JCEKS/BKS bytes.  For file paths,
      pass ``store_password`` if the container needs one for parsing.
    :param str purpose: The recovery purpose, for example ``tls_server``,
      ``code_signing``, ``trust_anchor`` or ``secret_key``.  A mapping
      with a ``requires`` key can be used for custom policies.
    :param allowed_entry_types: Entry categories that may be used, as
      classes or names such as ``private_key``, ``trusted_cert`` and
      ``secret_key``.  A mapping may assign a lower-is-better priority to
      each category.  ``None`` permits all categories.
    :param public_material: Public data used to identify the target:
      DER/PEM certificates, public keys, fingerprints, aliases, or a
      mapping/list of those.  Material may also include an explicit
      ``priority``.
    :param store_password: Only used to parse raw keystore bytes.  It is
      never stored in or exposed by the report.

    :returns: :class:`RecoveryReport`, with ordered alternatives and
      role-specific views for ``recovery`` and ``security``.
    """

    allowed_entry_types = kwargs.pop(
        "entry_types",
        kwargs.pop("allowed_types",
                   kwargs.pop("entry_categories",
                              kwargs.pop("allowed_categories",
                                         kwargs.pop("allowed_entry_categories",
                                                    kwargs.pop("allowed_kinds",
                                                               kwargs.pop("entry_kinds",
                                                                          kwargs.pop("allowed",
                                                                                     allowed_entry_types))))))))
    public_material = kwargs.pop(
        "material",
        kwargs.pop("public_materials",
                   kwargs.pop("matching_material",
                              kwargs.pop("match_material",
                                         kwargs.pop("known_public_material",
                                                    kwargs.pop("public",
                                                               kwargs.pop("materials",
                                                                          public_material)))))))

    name, requirement_groups, warnings, purpose_policy = _purpose_requirements(purpose)
    if purpose_policy:
        if allowed_entry_types is None:
            allowed_entry_types = (purpose_policy.get("allowed_entry_types") or
                                   purpose_policy.get("entry_types") or
                                   purpose_policy.get("allowed_categories"))
        if public_material is None:
            public_material = (purpose_policy.get("public_material") or
                               purpose_policy.get("material") or
                               purpose_policy.get("matching_material"))

    allowed, allowed_priorities = _normalize_allowed(allowed_entry_types)
    specs = _normalize_material(public_material)
    entries = _store_entries(store, store_password)
    required = _flatten_groups(requirement_groups)

    matches = []
    all_capabilities = set()
    unmatched_entries = []

    for alias, entry in entries.items():
        category = _category(entry)
        if category is None:
            continue
        certs = _entry_certs(entry, category)
        capabilities = _entry_capabilities(entry, category, certs)

        if allowed is not None and category not in allowed:
            continue
        all_capabilities.update(capabilities)

        if specs:
            material_match = _entry_material_match(entry, certs, specs)
            if material_match is None:
                unmatched_entries.append(alias)
                continue
        else:
            material_match = None

        missing = _missing_for(capabilities, requirement_groups)
        sort_key = (
            0 if not missing else 1,
            material_match["priority"] if material_match else 999999,
            material_match["order"] if material_match else 999999,
            _kind_order(category, required, allowed_priorities),
            material_match["rank"] if material_match else 60,
            0 if _is_decrypted(entry) else 1,
            -len(certs),
            str(alias).lower(),
        )
        matches.append((sort_key, alias, entry, category, certs,
                        capabilities, material_match))

    matches.sort(key=lambda item: item[0])
    report_matches = []
    for position, item in enumerate(matches, 1):
        _, alias, entry, category, certs, capabilities, material_match = item
        report_matches.append(_make_match(
            alias, entry, category, certs, capabilities,
            requirement_groups, material_match, position))

    satisfying = [match for match in report_matches if match["satisfies"]]
    selected = satisfying[0] if satisfying else None
    best = report_matches[0] if report_matches else None
    ok = selected is not None
    for match in report_matches:
        match["selected"] = match is selected
        match["is_selected"] = match is selected
        match["alternative"] = match is not selected
        match["supported"] = match["satisfies"]

    if ok:
        missing = []
    elif best is not None:
        missing = list(best["missing_capabilities"])
        if specs and not best["identity_match"]:
            missing.insert(0, Capability.IDENTITY_MATCH)
    else:
        missing = _missing_for(all_capabilities, requirement_groups)
        if specs:
            missing.insert(0, Capability.IDENTITY_MATCH)

    if not matches and specs:
        warnings.append("no_entry_matched_public_material")
    if not entries:
        warnings.append("empty_keystore")
    if allowed is not None and not allowed:
        warnings.append("no_allowed_entry_types")
    locked_entries = [match["alias"] for match in report_matches
                      if match.get("encrypted") or
                      match.get("category") == EntryKind.SEALED_KEY]
    if not ok and Capability.PRIVATE_KEY in required:
        for match in report_matches:
            if (match["category"] != EntryKind.PRIVATE_KEY and
                    Capability.CERTIFICATE_CHAIN in match["capabilities"]):
                warnings.append("certificate_chain_without_private_key")
                break

    report = RecoveryReport({
        "ok": ok,
        "passed": ok,
        "supported": ok,
        "satisfied": ok,
        "result": "pass" if ok else "fail",
        "purpose": name,
        "required_capabilities": required,
        "requirements": [list(group) for group in requirement_groups],
        "missing_capabilities": missing,
        "missing": missing,
        "missing_details": _actions_for(missing),
        "actions": _actions_for(missing),
        "next_steps": [item["action"] for item in _actions_for(missing)],
        "available_capabilities": sorted(all_capabilities),
        "has_private_key": any(match["has_private_key"] for match in report_matches),
        "has_certificate_chain": any(match["has_certificate_chain"] for match in report_matches),
        "has_trusted_certificate": any(match["has_trusted_certificate"] for match in report_matches),
        "has_secret_key": any(match["has_secret_key"] for match in report_matches),
        "matches": report_matches,
        "alternatives": report_matches[1:],
        "alternative_aliases": [match["alias"] for match in report_matches[1:]],
        "alternative_names": [match["alias"] for match in report_matches[1:]],
        "selected_match": selected,
        "best_match_detail": best,
        "precedence": [match["alias"] for match in report_matches],
        "match_priority": [match["alias"] for match in report_matches],
        "precedence_details": report_matches,
        "priority_order": report_matches,
        "selected_alias": selected["alias"] if selected else None,
        "selected": selected["alias"] if selected else None,
        "best_match_alias": best["alias"] if best else None,
        "best_match": best["alias"] if best else None,
        "can_recover": ok,
        "status": "ready" if ok else "blocked",
        "message": ("Recovery capability confirmed." if ok else
                    "Missing capability: %s." % ", ".join(missing)),
        "reason": None if ok else ", ".join(missing),
        "gaps": missing,
        "capability_gaps": missing,
        "allowed_entry_types": sorted(allowed) if allowed is not None else None,
        "public_material_supplied": bool(specs),
        "unmatched_entries": unmatched_entries,
        "locked_entries": locked_entries,
        "warnings": sorted(set(warnings)),
        "contains_private_key_material": False,
        "contains_secret_material": False,
        "contains_password": False,
    })

    views = RoleViews()
    views[ROLE_RECOVERY] = _role_view(ROLE_RECOVERY, report)
    views[ROLE_SECURITY] = _role_view(ROLE_SECURITY, report)
    report["roles"] = views
    report["role_views"] = views
    report["views"] = views
    report["role_reports"] = views
    report["audiences"] = [views[ROLE_RECOVERY], views[ROLE_SECURITY]]
    report[ROLE_RECOVERY] = views[ROLE_RECOVERY]
    report[ROLE_SECURITY] = views[ROLE_SECURITY]
    report["for_recovery"] = views[ROLE_RECOVERY]
    report["for_security"] = views[ROLE_SECURITY]
    report["recovery_view"] = views[ROLE_RECOVERY]
    report["security_view"] = views[ROLE_SECURITY]
    report["role_list"] = [views[ROLE_RECOVERY], views[ROLE_SECURITY]]
    report["role_outputs"] = [views[ROLE_RECOVERY], views[ROLE_SECURITY]]
    return report


def check_recovery_capabilities(store, purpose, allowed_entry_types=None,
                                public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def audit_recovery(store, purpose, allowed_entry_types=None,
                   public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def assess_recovery(store, purpose, allowed_entry_types=None,
                    public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def recovery_check(store, purpose, allowed_entry_types=None,
                   public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def check_capabilities(store, purpose, allowed_entry_types=None,
                       public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


class RecoveryChecker(object):
    """Reusable checker bound to one keystore."""

    def __init__(self, store, store_password=None):
        self.store = store
        self.store_password = store_password

    def check(self, purpose, allowed_entry_types=None, public_material=None,
              **kwargs):
        return check_recovery(self.store, purpose, allowed_entry_types,
                              public_material,
                              store_password=self.store_password, **kwargs)

    audit = check
    assess = check
    run = check


RecoveryCapabilityCheck = RecoveryChecker
RecoveryCheck = RecoveryChecker


def verify_recovery(store, purpose, allowed_entry_types=None,
                    public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def validate_recovery(store, purpose, allowed_entry_types=None,
                      public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def analyze_recovery(store, purpose, allowed_entry_types=None,
                     public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def recovery_report(store, purpose, allowed_entry_types=None,
                    public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


RecoveryAudit = RecoveryReport
RecoveryCapabilityReport = RecoveryReport
CapabilityReport = RecoveryReport
RecoveryResult = RecoveryReport
RecoveryCapabilities = RecoveryReport


def check_recovery_capability(store, purpose, allowed_entry_types=None,
                              public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def recovery_capabilities(store, purpose, allowed_entry_types=None,
                          public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def capability_check(store, purpose, allowed_entry_types=None,
                     public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def assess_recovery_capabilities(store, purpose, allowed_entry_types=None,
                                  public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def audit_recovery_capabilities(store, purpose, allowed_entry_types=None,
                                public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def check_keystore_recovery(store, purpose, allowed_entry_types=None,
                            public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def check_keystore_capabilities(store, purpose, allowed_entry_types=None,
                                public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def audit_keystore(store, purpose, allowed_entry_types=None,
                   public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)


def evaluate_recovery(store, purpose, allowed_entry_types=None,
                      public_material=None, **kwargs):
    """Alias for :func:`check_recovery`."""
    return check_recovery(store, purpose, allowed_entry_types,
                          public_material, **kwargs)

__all__ = [
    "EntryKind", "EntryCategory", "EntryType", "EntryTypes",
    "EntryCategories", "Capability", "Capabilities",
    "RecoveryPurpose", "Purpose", "Purposes",
    "PRIVATE_KEY", "TRUSTED_CERT", "CERTIFICATE", "SECRET_KEY",
    "PUBLIC_KEY", "SEALED_KEY",
    "CAPABILITY_PRIVATE_KEY", "CAPABILITY_CERTIFICATE_CHAIN",
    "CAPABILITY_TRUSTED_CERTIFICATE", "CAPABILITY_SECRET_KEY",
    "CAPABILITY_PUBLIC_KEY", "CAPABILITY_IDENTITY_MATCH",
    "CAP_PRIVATE_KEY", "CAP_CERTIFICATE_CHAIN",
    "CAP_TRUSTED_CERTIFICATE", "CAP_SECRET_KEY", "CAP_PUBLIC_KEY",
    "CAP_IDENTITY_MATCH",
    "ENTRY_PRIVATE_KEY", "ENTRY_TRUSTED_CERT", "ENTRY_SECRET_KEY",
    "ENTRY_PUBLIC_KEY", "ENTRY_SEALED_KEY",
    "ROLE_RECOVERY", "ROLE_SECURITY", "ROLE_ALIASES",
    "RecoveryMatch", "RecoveryRoleView", "RoleViews", "RecoveryReport",
    "RecoveryAssessment", "RecoveryAudit", "RecoveryCapabilityReport",
    "CapabilityReport", "RecoveryResult", "RecoveryCapabilities",
    "check_recovery", "check_recovery_capabilities",
    "check_recovery_capability", "audit_recovery",
    "assess_recovery", "audit_recovery_capabilities",
    "assess_recovery_capabilities", "recovery_check", "check_capabilities",
    "recovery_capabilities", "capability_check",
    "check_keystore_recovery", "check_keystore_capabilities",
    "audit_keystore", "evaluate_recovery",
    "verify_recovery", "validate_recovery", "analyze_recovery",
    "recovery_report", "RecoveryChecker", "RecoveryCapabilityCheck",
    "RecoveryCheck",
]
