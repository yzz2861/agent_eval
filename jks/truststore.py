# vim: set et ai ts=4 sts=4 sw=4:
"""Read-only, purpose-scoped planning of minimal Java truststores.

An intake keystore is often a shared library: it may contain certificates for
several independent delivery purposes, private keys, and the same certificate
stored under more than one alias.  Creating a truststore for one workstation
must therefore not mean "copy every certificate that looks approved somewhere".
It means selecting exactly the aliases that were approved for that workstation's
purpose, verifying that each alias still resolves to the expected certificate
material, and recording a manifest that can be checked again later.

The important rule in this module is that approval belongs to a
``(purpose, alias)`` pair.  Certificate fingerprints are used to recognise the
same certificate under several aliases and to keep each derived truststore
minimal, but a fingerprint never carries approval from one purpose to another.
If two purposes end up with the same certificate, each manifest must point at
its own approved source alias and explain that acceptance separately.

Typical usage::

    from jks.truststore import plan_truststores, Purpose

    plan = plan_truststores(store, [
        {"alias": "issuance-test", "purpose": Purpose.ISSUANCE_REVIEW},
        {"alias": "history-test", "purpose": Purpose.HISTORICAL_VERIFICATION},
    ])

    plan.manifests[Purpose.ISSUANCE_REVIEW].entries
    plan.review.to_dict()

The planner never writes to, decrypts, or otherwise modifies the intake store.
"""

from __future__ import absolute_import, print_function

import base64
import hashlib
import json
import os

from .jks import KeyStore, TrustedCertEntry
from .util import KeystoreException


MANIFEST_FORMAT = "pyjks-truststore-manifest-v1"
PLAN_FORMAT = "pyjks-truststore-delivery-plan-v1"


class TruststorePlanException(KeystoreException):
    """Superclass for errors raised while planning truststore delivery."""
    pass


class DeclarationException(TruststorePlanException):
    """Raised when an entry declaration cannot be interpreted."""
    pass


class Purpose(str):
    """A normalised purpose name.

    ``Purpose`` is a string subclass so that existing code can use either
    ``Purpose.ISSUANCE_REVIEW`` or the literal ``"issuance_review"`` without
    worrying about enum comparisons.  The ``value`` property mirrors enum-style
    access.
    """

    def __new__(cls, value):
        return str.__new__(cls, normalize_purpose(value))

    @property
    def value(self):
        return str(self)

    @property
    def name(self):
        return str(self).upper()

    def __repr__(self):
        return "Purpose(%r)" % str(self)


_PURPOSE_ALIASES = {
    "issuance": "issuance_review",
    "issuance_review": "issuance_review",
    "issuance_review_workstation": "issuance_review",
    "issuance_workstation": "issuance_review",
    "issuing": "issuance_review",
    "issuing_review": "issuance_review",
    "issuing_workstation": "issuance_review",
    "signing": "issuance_review",
    "issue_review": "issuance_review",
    "signing_review": "issuance_review",
    "sign_review": "issuance_review",
    "history": "historical_verification",
    "historical": "historical_verification",
    "historical_verification": "historical_verification",
    "historical_verification_workstation": "historical_verification",
    "history_verification": "historical_verification",
    "history_verification_workstation": "historical_verification",
    "legacy_verification": "historical_verification",
    "legacy": "historical_verification",
    "archive_verification": "historical_verification",
    "history_workstation": "historical_verification",
    "historical_workstation": "historical_verification",
}


def normalize_purpose(value):
    """Return the canonical spelling of a purpose name.

    Hyphens and whitespace are treated as underscores.  A small set of common
    workstation-oriented spellings are mapped to the two purposes used by the
    delivery process, while unknown purpose names are preserved so that the
    planner can also be used for additional workstations.
    """
    if isinstance(value, Purpose):
        return str(value)
    if value is None:
        raise DeclarationException("A purpose is required")
    if not isinstance(value, (str, bytes)) and hasattr(value, "value"):
        value = value.value
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    text = str(value).strip().lower()
    text = text.replace("-", "_").replace(" ", "_")
    while "__" in text:
        text = text.replace("__", "_")
    return _PURPOSE_ALIASES.get(text, text)


Purpose.ISSUANCE_REVIEW = Purpose("issuance_review")
Purpose.HISTORICAL_VERIFICATION = Purpose("historical_verification")
Purpose.ALL = (Purpose.ISSUANCE_REVIEW, Purpose.HISTORICAL_VERIFICATION)
Purpose.ISSUANCE = Purpose.ISSUANCE_REVIEW
Purpose.HISTORY = Purpose.HISTORICAL_VERIFICATION
Purpose.SIGNING_REVIEW = Purpose.ISSUANCE_REVIEW
Purpose.LEGACY_VERIFICATION = Purpose.HISTORICAL_VERIFICATION
Purpose.ISSUANCE_REVIEW_WORKSTATION = Purpose.ISSUANCE_REVIEW
Purpose.HISTORICAL_VERIFICATION_WORKSTATION = Purpose.HISTORICAL_VERIFICATION

ISSUANCE_REVIEW = Purpose.ISSUANCE_REVIEW
HISTORICAL_VERIFICATION = Purpose.HISTORICAL_VERIFICATION
ISSUANCE = ISSUANCE_REVIEW
HISTORY = HISTORICAL_VERIFICATION
SIGNING_REVIEW = ISSUANCE_REVIEW
LEGACY_VERIFICATION = HISTORY
DEFAULT_PURPOSES = Purpose.ALL
DEFAULT_APPROVED_PURPOSES = Purpose.ALL


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _unique(seq):
    result = []
    for item in seq:
        if item not in result:
            result.append(item)
    return result


def _fingerprint_algorithm_for(value, default="sha256"):
    if value is None:
        return default
    text = str(value).lower().replace("-", "")
    if text in ("sha1", "sha160"):
        return "sha1"
    if text in ("sha256", "sha2256"):
        return "sha256"
    if text in ("sha384", "sha2384"):
        return "sha384"
    if text in ("sha512", "sha2512"):
        return "sha512"
    return text


def certificate_fingerprint(der_bytes, algorithm="sha256"):
    """Return the lower-case hexadecimal digest of DER certificate bytes."""
    return hashlib.new(_fingerprint_algorithm_for(algorithm), der_bytes).hexdigest().lower()


def _infer_fingerprint_algorithm(fingerprint, default="sha256"):
    if fingerprint is None:
        return default
    length = len(str(fingerprint).replace(":", "").strip())
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    if length == 96:
        return "sha384"
    if length == 128:
        return "sha512"
    return default


def _normalise_fingerprint(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("ascii")
    return str(value).replace(":", "").replace(" ", "").strip().lower()


class CertificateIdentity(object):
    """A format-independent certificate identity based on its digest."""

    def __init__(self, fingerprint, algorithm="sha256"):
        self.algorithm = _fingerprint_algorithm_for(algorithm)
        self.fingerprint = _normalise_fingerprint(fingerprint)

    @classmethod
    def from_der(cls, der_bytes, algorithm="sha256"):
        return cls(certificate_fingerprint(der_bytes, algorithm), algorithm)

    @classmethod
    def from_entry(cls, entry, algorithm="sha256"):
        der = entry_certificate_der(entry)
        if der is None:
            raise DeclarationException(
                "Entry carries no certificate material: %r"
                % getattr(entry, "alias", None))
        return cls.from_der(der, algorithm)

    @property
    def sha256(self):
        return self.fingerprint

    def to_dict(self):
        return {"algorithm": self.algorithm, "fingerprint": self.fingerprint}

    def __eq__(self, other):
        return (isinstance(other, CertificateIdentity) and
                self.algorithm == other.algorithm and
                self.fingerprint == other.fingerprint)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.algorithm, self.fingerprint))

    def __repr__(self):
        return "CertificateIdentity(%s:%s)" % (self.algorithm, self.fingerprint)


def _entry_certificate(entry):
    """Return ``(der, type, origin)`` for an entry, or ``(None, None, None)``.

    Trusted certificate entries expose their DER directly.  Key entries are
    allowed as a source of certificate material: the leaf certificate of their
    chain is used.  The derived truststore still contains only a trusted
    certificate entry, never private or secret key material.
    """
    if isinstance(entry, TrustedCertEntry):
        return entry.cert, getattr(entry, "type", "X.509") or "X.509", "trusted_certificate"

    try:
        wrapped = getattr(entry, "entry", None)
    except Exception:
        wrapped = None
    if wrapped is not None and wrapped is not entry:
        return _entry_certificate(wrapped)

    try:
        chain = getattr(entry, "cert_chain", None)
    except Exception:
        chain = None
    if not chain:
        return None, None, None

    leaf = chain[0]
    if isinstance(leaf, tuple):
        return leaf[1], leaf[0] if leaf[0] else "X.509", "key_chain"
    if hasattr(leaf, "cert"):
        return leaf.cert, getattr(leaf, "type", "X.509") or "X.509", "key_chain"
    return None, None, None


def entry_certificate_der(entry):
    """Return the certificate material carried by ``entry``, or ``None``."""
    return _entry_certificate(entry)[0]


class PlanConflict(object):
    """A problem or note discovered while allocating entries to a purpose."""

    def __init__(self, code, message, purpose=None, alias=None, source_alias=None,
                 fingerprint=None, severity="error", details=None):
        self.code = code
        self.message = message
        self.purpose = normalize_purpose(purpose) if purpose is not None else None
        self.alias = alias
        self.source_alias = source_alias
        self.fingerprint = _normalise_fingerprint(fingerprint)
        self.severity = severity
        self.details = dict(details or {})

    @property
    def is_error(self):
        return self.severity == "error"

    def __str__(self):
        return self.message

    def __repr__(self):
        return "PlanConflict(%r, purpose=%r, alias=%r)" % (
            self.code, self.purpose, self.source_alias or self.alias)

    def to_dict(self):
        result = {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }
        if self.purpose is not None:
            result["purpose"] = str(self.purpose)
        if self.alias is not None:
            result["alias"] = self.alias
        if self.source_alias is not None:
            result["source_alias"] = self.source_alias
        if self.fingerprint is not None:
            result["fingerprint"] = self.fingerprint
        if self.details:
            result["details"] = dict(self.details)
        return result

    @classmethod
    def from_dict(cls, data):
        return cls(
            code=data.get("code", "conflict"),
            message=data.get("message", ""),
            purpose=data.get("purpose"),
            alias=data.get("alias"),
            source_alias=data.get("source_alias"),
            fingerprint=data.get("fingerprint"),
            severity=data.get("severity", "error"),
            details=data.get("details"),
        )


class VerificationResult(object):
    """The outcome of re-checking a manifest or a complete delivery plan."""

    def __init__(self, problems=None, checked=None):
        self.problems = list(problems or [])
        self.checked = dict(checked or {})

    @property
    def ok(self):
        return not self.problems

    @property
    def is_valid(self):
        return self.ok

    @property
    def valid(self):
        return self.ok

    def add(self, message):
        self.problems.append(message)
        return self

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__

    def __eq__(self, other):
        if isinstance(other, bool):
            return self.ok == other
        return object.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "VerificationResult(ok=%r, problems=%r)" % (self.ok, self.problems)

    def to_dict(self):
        return {
            "ok": self.ok,
            "problems": list(self.problems),
            "checked": dict(self.checked),
        }



class EntryDeclaration(object):
    """A declaration that an alias is approved for one or more purposes.

    The declaration is intentionally permissive about its input shape so that
    policy data can be loaded from JSON without a separate adapter.  The
    following are equivalent::

        EntryDeclaration("cert-a", "issuance_review", fingerprint="ab...")
        EntryDeclaration(alias="cert-a", purpose="issuance_review",
                         certificate_sha256="ab...")
        {"alias": "cert-a", "purpose": "issuance_review",
         "fingerprint": "ab..."}

    ``approved=False`` records an explicit denial.  A denial and an approval
    for the same ``(purpose, alias)`` are a conflict rather than an implicit
    override.
    """

    _FINGERPRINT_KEYS = (
        "fingerprint", "sha256", "sha_256", "certificate_sha256",
        "certificate_fingerprint", "certificate_digest", "cert_digest",
        "cert_sha256", "cert_fingerprint", "expected_fingerprint",
    )
    _DESTINATION_KEYS = (
        "destination_alias", "destination", "target_alias", "output_alias",
        "truststore_alias",
    )
    _REFERENCE_KEYS = (
        "reference", "approval_reference", "ticket", "change_request", "approval_id",
    )

    def __init__(self, alias=None, purpose=None, fingerprint=None, approved=True,
                 destination_alias=None, purposes=None, approved_purposes=None,
                 source=None, note=None, reference=None, **kwargs):
        if isinstance(alias, dict):
            data = dict(alias)
            data.update(kwargs)
            if purpose is not None:
                data["purpose"] = purpose
            if fingerprint is not None:
                data["fingerprint"] = fingerprint
            if destination_alias is not None:
                data["destination_alias"] = destination_alias
            if source is not None:
                data["source"] = source
            if note is not None:
                data["note"] = note
            if reference is not None:
                data["reference"] = reference
            if purposes is not None:
                data["purposes"] = purposes
            if approved_purposes is not None:
                data["approved_purposes"] = approved_purposes
            if "approved" in kwargs:
                data["approved"] = kwargs.get("approved")
            self._load_dict(data, approved)
            return

        declared_source_alias = kwargs.get("source_alias")
        if alias is None:
            alias = declared_source_alias
        if alias is None:
            alias = kwargs.pop("name", None)
        if alias is None:
            raise DeclarationException("An entry declaration requires an alias")
        if (declared_source_alias is not None and destination_alias is None and
                str(declared_source_alias) != str(alias)):
            destination_alias = alias
            alias = declared_source_alias
        self.alias = str(alias)

        if fingerprint is None:
            for key in self._FINGERPRINT_KEYS:
                if key in kwargs and kwargs[key] is not None:
                    fingerprint = kwargs[key]
                    break
        self.fingerprint = _normalise_fingerprint(fingerprint)

        if destination_alias is None:
            for key in self._DESTINATION_KEYS:
                if key in kwargs and kwargs[key] is not None:
                    destination_alias = kwargs[key]
                    break
        self.destination_alias = str(destination_alias) if destination_alias is not None else None

        if reference is None:
            for key in self._REFERENCE_KEYS:
                if key in kwargs and kwargs[key] is not None:
                    reference = kwargs[key]
                    break
        self.reference = reference

        self.source = str(source) if source is not None else None
        self.note = note
        self.extra = dict(kwargs)

        specs = []
        if approved_purposes is not None:
            specs.extend(_as_list(approved_purposes))
        if purposes is not None:
            specs.extend(_as_list(purposes))

        approval_map = {}
        approval_spec = kwargs.get("approval")
        if isinstance(approval_spec, dict):
            for key, value in approval_spec.items():
                approved_purpose = normalize_purpose(key)
                approval_map[approved_purpose] = bool(value)
                specs.append(approved_purpose)
        if isinstance(purpose, dict):
            for key, value in purpose.items():
                approval_map[normalize_purpose(key)] = bool(value)
            specs.extend(approval_map.keys())
        elif purpose is not None:
            specs.extend(_as_list(purpose))

        if "purpose" in kwargs and kwargs["purpose"] is not None:
            specs.extend(_as_list(kwargs["purpose"]))
        if "approved_for" in kwargs and kwargs["approved_for"] is not None:
            specs.extend(_as_list(kwargs["approved_for"]))
        if "approvals" in kwargs and kwargs["approvals"] is not None:
            approvals_spec = kwargs["approvals"]
            if isinstance(approvals_spec, dict):
                for key, value in approvals_spec.items():
                    approved_purpose = normalize_purpose(key)
                    approval_map[approved_purpose] = bool(value)
                    specs.append(approved_purpose)
            else:
                specs.extend(_as_list(approvals_spec))

        self.purposes = tuple(_unique(normalize_purpose(item) for item in specs))
        if not self.purposes:
            raise DeclarationException(
                "Entry declaration for alias '%s' has no purpose" % self.alias)

        self._approval = {}
        for item in self.purposes:
            self._approval[item] = bool(approval_map.get(item, approved))
        self.approved = all(self._approval.values())

    def _load_dict(self, data, default_approved):
        alias = data.get("alias", data.get("source_alias", data.get("name")))
        if alias is None:
            raise DeclarationException("An entry declaration requires an alias")
        fingerprint = data.get("fingerprint")
        if fingerprint is None:
            for key in self._FINGERPRINT_KEYS:
                if data.get(key) is not None:
                    fingerprint = data[key]
                    break
        destination_alias = data.get("destination_alias")
        declared_source_alias = data.get("source_alias")
        if (destination_alias is None and declared_source_alias is not None and
                data.get("alias") is not None and
                str(data.get("alias")) != str(declared_source_alias)):
            alias = declared_source_alias
            destination_alias = data.get("alias")
        if destination_alias is None:
            for key in self._DESTINATION_KEYS:
                if data.get(key) is not None:
                    destination_alias = data[key]
                    break
        reference = data.get("reference")
        if reference is None:
            for key in self._REFERENCE_KEYS:
                if data.get(key) is not None:
                    reference = data[key]
                    break

        approved = data.get("approved", default_approved)
        approved_purposes = data.get("approved_purposes")
        purposes = data.get("purposes")
        purpose = data.get("purpose")

        specs = []
        if approved_purposes is not None:
            specs.extend(_as_list(approved_purposes))
        if purposes is not None:
            specs.extend(_as_list(purposes))

        approval_map = {}
        if isinstance(data.get("approval"), dict):
            for key, value in data["approval"].items():
                approved_purpose = normalize_purpose(key)
                approval_map[approved_purpose] = bool(value)
                specs.append(approved_purpose)
        if data.get("approved_for") is not None:
            specs.extend(_as_list(data["approved_for"]))
        if data.get("approvals") is not None:
            approvals_spec = data["approvals"]
            if isinstance(approvals_spec, dict):
                for key, value in approvals_spec.items():
                    approved_purpose = normalize_purpose(key)
                    approval_map[approved_purpose] = bool(value)
                    specs.append(approved_purpose)
            else:
                specs.extend(_as_list(approvals_spec))
        if isinstance(purpose, dict):
            for key, value in purpose.items():
                approval_map[normalize_purpose(key)] = bool(value)
            specs.extend(approval_map.keys())
        elif purpose is not None:
            specs.extend(_as_list(purpose))

        self.alias = str(alias)
        self.fingerprint = _normalise_fingerprint(fingerprint)
        self.destination_alias = str(destination_alias) if destination_alias is not None else None
        self.reference = reference
        self.source = data.get("source")
        self.note = data.get("note")
        self.extra = dict((key, value) for key, value in data.items()
                          if key not in ("alias", "source_alias", "name", "purpose",
                                         "purposes", "approved", "approved_purposes",
                                         "fingerprint", "destination_alias",
                                         "reference", "source", "note"))
        self.purposes = tuple(_unique(normalize_purpose(item) for item in specs))
        if not self.purposes:
            raise DeclarationException(
                "Entry declaration for alias '%s' has no purpose" % self.alias)
        self._approval = {}
        for item in self.purposes:
            self._approval[item] = bool(approval_map.get(item, approved))
        self.approved = all(self._approval.values())

    @property
    def certificate_sha256(self):
        return self.fingerprint

    def approved_for(self, purpose):
        purpose = normalize_purpose(purpose)
        if purpose in self._approval:
            return self._approval[purpose]
        return bool(self.approved)

    def to_dict(self):
        result = {
            "alias": self.alias,
            "purpose": (str(self.purposes[0]) if len(self.purposes) == 1
                        else [str(item) for item in self.purposes]),
            "approved": bool(self.approved),
        }
        if len(self.purposes) > 1 or not self.approved:
            result["purposes"] = [str(item) for item in self.purposes]
            result["approval"] = dict((str(key), value)
                                      for key, value in self._approval.items())
        if self.fingerprint is not None:
            result["fingerprint"] = self.fingerprint
        if self.destination_alias is not None:
            result["destination_alias"] = self.destination_alias
        if self.source is not None:
            result["source"] = self.source
        if self.reference is not None:
            result["reference"] = self.reference
        if self.note is not None:
            result["note"] = self.note
        return result

    def __repr__(self):
        return "EntryDeclaration(alias=%r, purposes=%r, approved=%r)" % (
            self.alias, self.purposes, self.approved)

    @classmethod
    def from_dict(cls, data):
        return cls(data)

    @classmethod
    def from_json(cls, value):
        return cls(json.loads(value))


class Approval(EntryDeclaration):
    """Singular-purpose alias for :class:`EntryDeclaration`."""
    pass


class ApprovalPolicy(object):
    """A small mutable collection of entry declarations.

    The policy is only an input builder.  Planning itself remains read-only
    with respect to the intake keystore.
    """

    def __init__(self, declarations=None):
        self.declarations = normalize_declarations(declarations)

    def declare(self, alias, purpose=None, **kwargs):
        self.declarations.append(EntryDeclaration(alias, purpose, **kwargs))
        return self

    approve = declare

    def deny(self, alias, purpose=None, **kwargs):
        kwargs["approved"] = False
        return self.declare(alias, purpose, **kwargs)

    def approvals_for(self, purpose):
        purpose = normalize_purpose(purpose)
        return [item for item in self.declarations if purpose in item.purposes]

    def to_dict(self):
        return {"declarations": [item.to_dict() for item in self.declarations]}

    def __iter__(self):
        return iter(self.declarations)

    def __len__(self):
        return len(self.declarations)

    def __repr__(self):
        return "ApprovalPolicy(declarations=%d)" % len(self.declarations)


Declaration = EntryDeclaration
AliasApproval = Approval
PurposeApproval = Approval
EntryApproval = Approval
PurposePolicy = ApprovalPolicy
DeclarationPolicy = ApprovalPolicy


def _looks_like_purpose(value):
    try:
        text = normalize_purpose(value)
    except Exception:
        return False
    return text in ("issuance_review", "historical_verification") or \
        text in _PURPOSE_ALIASES.values()


def _declaration_from_item(item, purpose=None):
    if isinstance(item, EntryDeclaration):
        return item
    if isinstance(item, dict):
        data = dict(item)
        if purpose is not None and not any(
                key in data for key in ("purpose", "purposes",
                                        "approved_purposes", "approved_for",
                                        "approval", "approvals")):
            data["purpose"] = purpose
        return EntryDeclaration(data)
    if isinstance(item, (list, tuple)):
        if purpose is not None and len(item) == 1:
            return EntryDeclaration(item[0], purpose)
        return EntryDeclaration(*item)
    if isinstance(item, str):
        if purpose is None:
            raise DeclarationException(
                "Alias-only declaration '%s' needs a purpose context" % item)
        return EntryDeclaration(item, purpose)
    raise DeclarationException("Unsupported entry declaration: %r" % (item,))


def normalize_declarations(declarations):
    """Convert supported declaration shapes into :class:`EntryDeclaration`s."""
    meta_keys = ("purposes", "approved_purposes", "intake", "store",
                 "keystore", "path", "password", "store_name", "name",
                 "type", "source", "format", "valid", "review",
                 "manifests", "conflicts")
    result = []
    if declarations is None:
        return result

    if isinstance(declarations, EntryDeclaration):
        return [declarations]
    if isinstance(declarations, ApprovalPolicy):
        return list(declarations.declarations)

    if isinstance(declarations, dict):
        if "declarations" in declarations:
            return normalize_declarations(declarations["declarations"])
        if "approvals" in declarations:
            return normalize_declarations(declarations["approvals"])
        if "entries" in declarations and not _looks_like_purpose_list(declarations):
            return normalize_declarations(declarations["entries"])

        for key, value in declarations.items():
            if key in meta_keys:
                continue
            if _looks_like_purpose(key):
                if (isinstance(value, dict) and
                        not any(name in value for name in (
                            "purpose", "purposes", "approved_purposes", "approved",
                            "approved_for", "approval", "approvals"))):
                    for alias, spec in value.items():
                        if isinstance(spec, dict):
                            data = dict(spec)
                            data.setdefault("alias", alias)
                            data.setdefault("purpose", key)
                            result.append(EntryDeclaration(data))
                        elif isinstance(spec, bool):
                            result.append(EntryDeclaration(alias, key, approved=spec))
                        elif spec is None:
                            result.append(EntryDeclaration(alias, key))
                        elif isinstance(spec, (list, tuple)):
                            result.append(EntryDeclaration(
                                alias, key,
                                fingerprint=spec[0] if spec else None))
                        else:
                            result.append(EntryDeclaration(
                                alias, key, fingerprint=spec))
                    continue
                for item in _as_list(value):
                    result.append(_declaration_from_item(item, purpose=key))
            elif isinstance(value, EntryDeclaration):
                result.append(value)
            elif isinstance(value, dict) and any(
                    name in value for name in ("purpose", "purposes",
                                               "approved_purposes", "approved",
                                               "approved_for", "approval",
                                               "approvals")):
                data = dict(value)
                data.setdefault("alias", key)
                result.append(EntryDeclaration(data))
            else:
                result.append(EntryDeclaration(key, value))
        return result

    if (isinstance(declarations, tuple) and len(declarations) >= 2 and
            isinstance(declarations[0], str) and
            isinstance(declarations[1], (str, list, tuple, set))):
        return [_declaration_from_item(declarations)]

    if isinstance(declarations, (list, tuple, set)):
        for item in declarations:
            result.append(_declaration_from_item(item))
        return result

    raise DeclarationException("Unsupported declarations value: %r" % (declarations,))


def _looks_like_purpose_list(mapping):
    return any(_looks_like_purpose(key) for key in mapping.keys())


class ManifestEntry(object):
    """One certificate selected for one purpose-specific truststore."""

    def __init__(self, alias, purpose, source_alias=None, certificate=None,
                 fingerprint=None, certificate_type="X.509", reason=None,
                 source_aliases=None, source_entry_type=None, source_name=None,
                 reference=None, fingerprint_algorithm="sha256", cert=None,
                 der=None, certificate_der=None, sha256=None, **kwargs):
        if source_alias is None:
            source_alias = kwargs.get("source") or alias
        if certificate is None:
            certificate = cert if cert is not None else der
        if certificate is None:
            certificate = certificate_der
        if fingerprint is None:
            fingerprint = (sha256 if sha256 is not None else
                           kwargs.get("certificate_sha256"))
        self.alias = str(alias)
        self.purpose = normalize_purpose(purpose)
        self.source_alias = str(source_alias)
        self.certificate = certificate
        self.certificate_type = certificate_type or "X.509"
        self.fingerprint_algorithm = _fingerprint_algorithm_for(fingerprint_algorithm)
        self.fingerprint = _normalise_fingerprint(fingerprint)
        if self.fingerprint is None and certificate is not None:
            self.fingerprint = certificate_fingerprint(
                certificate, self.fingerprint_algorithm)
        self.reason = reason
        self.source_aliases = sorted(set(source_aliases or [self.source_alias]))
        self.source_entry_type = source_entry_type
        self.source_name = source_name
        self.reference = reference

    @property
    def cert(self):
        return self.certificate

    @property
    def der(self):
        return self.certificate

    certificate_der = der

    @property
    def fingerprint_sha256(self):
        return self.fingerprint

    @property
    def digest(self):
        return self.fingerprint

    @property
    def provenance(self):
        return {
            "source_name": self.source_name,
            "source_alias": self.source_alias,
            "source_aliases": list(self.source_aliases),
            "source_entry_type": self.source_entry_type,
            "fingerprint": self.fingerprint,
        }

    @property
    def source(self):
        return self.source_alias

    @property
    def sha256(self):
        return self.fingerprint

    @property
    def certificate_sha256(self):
        return self.fingerprint

    @property
    def certificate_b64(self):
        if self.certificate is None:
            return None
        return base64.b64encode(self.certificate).decode("ascii")

    @property
    def size(self):
        return len(self.certificate) if self.certificate is not None else None

    @property
    def keystore_alias(self):
        return self.alias.lower()

    def to_dict(self, include_certificate=True):
        result = {
            "alias": self.alias,
            "purpose": str(self.purpose),
            "source_alias": self.source_alias,
            "source_aliases": list(self.source_aliases),
            "all_source_aliases": list(self.source_aliases),
            "certificate_type": self.certificate_type,
            "type": self.certificate_type,
            "fingerprint_algorithm": self.fingerprint_algorithm,
            "fingerprint": self.fingerprint,
            "sha256": self.fingerprint,
            "certificate_sha256": self.fingerprint,
            "size": self.size,
            "reason": self.reason,
        }
        if self.source_entry_type is not None:
            result["source_entry_type"] = self.source_entry_type
        if self.source_name is not None:
            result["source_name"] = self.source_name
        if self.reference is not None:
            result["reference"] = self.reference
        if include_certificate and self.certificate is not None:
            result["certificate_b64"] = self.certificate_b64
        return result

    @classmethod
    def from_dict(cls, data):
        certificate = None
        if data.get("certificate_b64") is not None:
            certificate = base64.b64decode(data["certificate_b64"].encode("ascii"))
        fingerprint = (data.get("fingerprint") or
                       data.get("certificate_sha256") or data.get("sha256"))
        return cls(
            alias=data["alias"],
            purpose=data["purpose"],
            source_alias=data.get("source_alias", data["alias"]),
            certificate=certificate,
            fingerprint=fingerprint,
            certificate_type=data.get("certificate_type", data.get("type", "X.509")),
            reason=data.get("reason"),
            source_aliases=(data.get("source_aliases") or
                            data.get("all_source_aliases")),
            source_entry_type=data.get("source_entry_type"),
            source_name=data.get("source_name"),
            reference=data.get("reference"),
            fingerprint_algorithm=data.get(
                "fingerprint_algorithm",
                _infer_fingerprint_algorithm(fingerprint)),
        )

    @classmethod
    def from_json(cls, value):
        return cls.from_dict(json.loads(value))

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def keys(self):
        return list(self.to_dict().keys())

    def items(self):
        return list(self.to_dict().items())

    def __repr__(self):
        return "ManifestEntry(purpose=%r, alias=%r, fingerprint=%r)" % (
            str(self.purpose), self.alias, self.fingerprint)


class EntryCollection(list):
    # A list of manifest entries that also supports lookup by alias.

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return list.__getitem__(self, key)
        key = str(key).lower()
        for entry in self:
            if entry.alias.lower() == key:
                return entry
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):
        return [entry.alias for entry in self]

    def values(self):
        return list(self)

    def items(self):
        return [(entry.alias, entry) for entry in self]

    def __contains__(self, item):
        if isinstance(item, str):
            return any(entry.alias.lower() == item.lower() for entry in self)
        return list.__contains__(self, item)


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical_json(value)).hexdigest()


class TruststoreManifest(object):
    """A re-verifiable description of one minimal purpose-specific truststore."""

    def __init__(self, purpose, entries=None, source_name=None,
                 source_inventory_sha256=None, format=MANIFEST_FORMAT,
                 declared_sha256=None):
        self.purpose = normalize_purpose(purpose)
        if isinstance(entries, dict):
            converted = []
            for alias, value in entries.items():
                if isinstance(value, ManifestEntry):
                    converted.append(value)
                elif isinstance(value, dict):
                    converted.append(ManifestEntry.from_dict(value))
                else:
                    converted.append(ManifestEntry(alias, self.purpose, alias, value))
            entries = converted
        elif isinstance(entries, ManifestEntry):
            entries = [entries]
        self.entries = EntryCollection(sorted(
            list(entries or []),
            key=lambda item: (item.alias.lower(), item.fingerprint)))
        self.source_name = source_name
        self.source_inventory_sha256 = source_inventory_sha256
        self.format = format
        self.declared_sha256 = _normalise_fingerprint(declared_sha256)

    @property
    def aliases(self):
        return [entry.alias for entry in self.entries]

    @property
    def fingerprints(self):
        return [entry.fingerprint for entry in self.entries]

    @property
    def source_aliases(self):
        return [entry.source_alias for entry in self.entries]

    @property
    def sha256(self):
        return _digest(self._body(include_certificate=True))

    @property
    def digest(self):
        return self.sha256

    @property
    def manifest_sha256(self):
        return self.sha256

    @property
    def is_empty(self):
        return not self.entries

    def body(self, include_certificate=True):
        return self._body(include_certificate=include_certificate)

    def _body(self, include_certificate=True):
        return {
            "format": self.format,
            "purpose": str(self.purpose),
            "source_name": self.source_name,
            "source_inventory_sha256": self.source_inventory_sha256,
            "entries": [entry.to_dict(include_certificate=include_certificate)
                        for entry in self.entries],
        }

    def to_dict(self, include_certificate=True):
        result = self._body(include_certificate=include_certificate)
        result["sha256"] = _digest(result)
        return result

    def to_json(self, include_certificate=True, indent=2):
        return json.dumps(self.to_dict(include_certificate=include_certificate),
                          sort_keys=True, indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data):
        entries = [ManifestEntry.from_dict(item) for item in data.get("entries", [])]
        manifest = cls(
            purpose=data["purpose"],
            entries=entries,
            source_name=data.get("source_name"),
            source_inventory_sha256=data.get("source_inventory_sha256"),
            format=data.get("format", MANIFEST_FORMAT),
            declared_sha256=data.get("sha256"),
        )
        return manifest

    @classmethod
    def from_json(cls, value):
        return cls.from_dict(json.loads(value))

    def entry_for(self, alias):
        key = str(alias).lower()
        for entry in self.entries:
            if entry.alias.lower() == key:
                return entry
        return None

    entry = entry_for

    def get(self, alias, default=None):
        entry = self.entry_for(alias)
        return entry if entry is not None else default

    def contains(self, alias):
        return self.entry_for(alias) is not None

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def keys(self):
        return list(self.aliases)

    def values(self):
        return list(self.entries)

    def items(self):
        return list(zip(self.aliases, self.entries))

    def __contains__(self, alias):
        return self.entry_for(alias) is not None

    def __getitem__(self, alias):
        entry = self.entry_for(alias)
        if entry is None:
            raise KeyError(alias)
        return entry

    @property
    def certs(self):
        return dict((entry.alias, entry) for entry in self.entries)

    @property
    def entries_by_alias(self):
        return self.certs

    def __repr__(self):
        return "TruststoreManifest(purpose=%r, entries=%d, sha256=%r)" % (
            str(self.purpose), len(self.entries), self.sha256[:12])

    def to_keystore(self, store_type="jks"):
        """Build a new in-memory minimal keystore; the intake store is untouched."""
        entries = []
        for item in self.entries:
            if item.certificate is None:
                raise TruststorePlanException(
                    "Manifest entry '%s' has no certificate material" % item.alias)
            new_entry = TrustedCertEntry.new(item.keystore_alias,
                                              item.certificate)
            new_entry.type = item.certificate_type or "X.509"
            entries.append(new_entry)
        return KeyStore.new(store_type, entries)

    as_keystore = to_keystore
    build_truststore = to_keystore
    materialize = to_keystore

    def verify(self, store=None, declarations=None, algorithm=None,
               check_source_inventory=False, password=None, store_password=None,
               store_type=None):
        """Re-check the manifest digest, certificate material, and provenance."""
        if (isinstance(store, (str, bytes)) and
                isinstance(declarations, (str, bytes)) and
                password is None and store_password is None):
            password = declarations
            declarations = None
        if isinstance(store, (str, bytes)):
            store, _ = _load_store(store, password=password,
                                   store_password=store_password,
                                   store_type=store_type)
        result = VerificationResult(checked={
            "purpose": str(self.purpose),
            "entries": len(self.entries),
        })

        expected = data_sha256 = _digest(self._body(include_certificate=True))
        if self.entries and any(entry.certificate is None for entry in self.entries):
            data_sha256 = None
        if data_sha256 is not None:
            result.checked["manifest_sha256"] = expected
            if (self.declared_sha256 is not None and
                    self.declared_sha256 != expected):
                result.add(
                    "manifest digest mismatch: declared %s, computed %s"
                    % (self.declared_sha256, expected))

        seen_aliases = {}
        seen_fingerprints = {}
        for entry in self.entries:
            alias_key = entry.alias.lower()
            if alias_key in seen_aliases:
                result.add("duplicate destination alias '%s'" % entry.alias)
            seen_aliases[alias_key] = entry

            if entry.fingerprint in seen_fingerprints:
                result.add("certificate %s appears more than once in purpose '%s'"
                           % (entry.fingerprint, self.purpose))
            seen_fingerprints[entry.fingerprint] = entry

            if entry.certificate is not None:
                actual = certificate_fingerprint(
                    entry.certificate,
                    algorithm or entry.fingerprint_algorithm)
                if actual != entry.fingerprint:
                    result.add(
                        "certificate material for alias '%s' hashes to %s, "
                        "manifest declares %s" % (entry.alias, actual, entry.fingerprint))

        if store is not None:
            if not hasattr(store, "entries"):
                result.add("store does not expose an entries mapping")
            else:
                if check_source_inventory:
                    current = inventory_sha256(store)
                    result.checked["source_inventory_sha256"] = current
                    if (self.source_inventory_sha256 is not None and
                            current != self.source_inventory_sha256):
                        result.add("source inventory changed since planning")
                for entry in self.entries:
                    actual_alias, actual_entry, problem = _resolve_entry(
                        store, entry.source_alias)
                    if problem is not None:
                        result.add("source alias '%s' for destination '%s': %s"
                                   % (entry.source_alias, entry.alias, problem))
                        continue
                    der, cert_type, origin = _entry_certificate(actual_entry)
                    if der is None:
                        result.add("source alias '%s' carries no certificate material"
                                   % actual_alias)
                        continue
                    actual_fp = certificate_fingerprint(
                        der, algorithm or entry.fingerprint_algorithm)
                    if actual_fp != entry.fingerprint:
                        result.add(
                            "source alias '%s' now has certificate %s, expected %s"
                            % (actual_alias, actual_fp, entry.fingerprint))
                    if entry.certificate is not None and der != entry.certificate:
                        result.add("certificate bytes for source alias '%s' changed"
                                   % actual_alias)

        if declarations is not None:
            approvals = _approval_index(normalize_declarations(declarations),
                                        self.purpose)
            for entry in self.entries:
                key = entry.source_alias.lower()
                candidates = approvals.get(key, [])
                approved = [item for item in candidates
                            if item.approved_for(self.purpose)]
                if not approved:
                    result.add(
                        "source alias '%s' is not approved for purpose '%s'"
                        % (entry.source_alias, self.purpose))
                    continue
                matching = [item for item in approved
                            if item.fingerprint is None or
                            _normalise_fingerprint(item.fingerprint) == entry.fingerprint]
                if not matching:
                    result.add(
                        "source alias '%s' is approved for purpose '%s' only "
                        "for different certificate material"
                        % (entry.source_alias, self.purpose))

        return result

    def matches(self, store=None, declarations=None, **kwargs):
        return self.verify(store, declarations, **kwargs).ok

    def is_valid(self, store=None, declarations=None, **kwargs):
        return self.matches(store, declarations, **kwargs)


class ReviewDecision(object):
    """Why one alias/certificate was accepted or rejected for one purpose."""

    def __init__(self, purpose, alias, accepted, reason, source_alias=None,
                 fingerprint=None, selected=True, conflict=None,
                 declaration=None, **kwargs):
        self.purpose = normalize_purpose(purpose)
        self.alias = alias
        self.accepted = bool(accepted)
        self.reason = reason or ""
        self.source_alias = source_alias
        self.fingerprint = _normalise_fingerprint(fingerprint)
        self.selected = bool(selected)
        self.conflict = conflict
        self.declaration = declaration
        self.extra = dict(kwargs)

    @property
    def code(self):
        if self.conflict is not None:
            return self.conflict.code
        return "accepted" if self.accepted else "rejected"

    @property
    def is_accepted(self):
        return self.accepted

    def to_dict(self):
        result = {
            "purpose": str(self.purpose),
            "alias": self.alias,
            "source_alias": self.source_alias,
            "accepted": self.accepted,
            "decision": "accept" if self.accepted else "reject",
            "selected": self.selected,
            "reason": self.reason,
        }
        if self.fingerprint is not None:
            result["fingerprint"] = self.fingerprint
        if self.conflict is not None:
            result["conflict"] = self.conflict.to_dict()
        if self.extra:
            result.update(self.extra)
        return result

    @classmethod
    def from_dict(cls, data):
        return cls(
            purpose=data["purpose"],
            alias=data.get("alias"),
            accepted=data.get("accepted", False),
            reason=data.get("reason"),
            source_alias=data.get("source_alias"),
            fingerprint=data.get("fingerprint"),
            selected=data.get("selected", True),
            conflict=(PlanConflict.from_dict(data["conflict"])
                      if data.get("conflict") else None),
        )

    def __repr__(self):
        state = "accepted" if self.accepted else "rejected"
        return "ReviewDecision(%s, purpose=%r, alias=%r)" % (
            state, str(self.purpose), self.source_alias or self.alias)


class ReviewResult(object):
    """The auditable explanation accompanying a delivery plan."""

    def __init__(self, decisions=None, conflicts=None, deduplicated=None,
                 notes=None, shared_certificates=None):
        self.decisions = list(decisions or [])
        self.conflicts = list(conflicts or [])
        self.deduplicated = list(deduplicated or [])
        self.notes = list(notes or [])
        self.shared_certificates = dict(shared_certificates or {})

    @property
    def accepted(self):
        return [item for item in self.decisions if item.accepted]

    @property
    def rejected(self):
        return [item for item in self.decisions if not item.accepted]

    @property
    def accepted_decisions(self):
        return self.accepted

    @property
    def rejected_decisions(self):
        return self.rejected

    @property
    def decisions_by_purpose(self):
        result = {}
        for item in self.decisions:
            result.setdefault(str(item.purpose), []).append(item)
        return result

    @property
    def accepted_by_purpose(self):
        result = {}
        for item in self.accepted:
            result.setdefault(str(item.purpose), []).append(item)
        return result

    @property
    def rejected_by_purpose(self):
        result = {}
        for item in self.rejected:
            result.setdefault(str(item.purpose), []).append(item)
        return result

    @property
    def errors(self):
        return [item for item in self.conflicts if item.is_error]

    @property
    def is_valid(self):
        return not self.errors

    @property
    def has_conflicts(self):
        return bool(self.errors)

    @property
    def valid(self):
        return self.is_valid

    @property
    def ok(self):
        return self.is_valid

    @property
    def decision(self):
        return "accept" if self.is_valid else "reject"

    @property
    def outcome(self):
        return self.decision.upper()

    @property
    def reason(self):
        if self.is_valid:
            return "all selected entries have a purpose-scoped approval and verified source"
        return "%d conflict(s) require review" % len(self.errors)

    @property
    def reasons(self):
        """Accepted reasons grouped by purpose."""
        result = {}
        for item in self.accepted:
            result.setdefault(str(item.purpose), []).append(item.reason)
        return result

    @property
    def manifest_reasons(self):
        return self.reasons

    @property
    def accepted_reasons(self):
        return self.reasons

    @property
    def reason_list(self):
        return [item.reason for item in self.accepted]

    all_reasons = reason_list

    def reasons_for(self, purpose):
        purpose = normalize_purpose(purpose)
        return [item.reason for item in self.accepted if item.purpose == purpose]

    def why(self, purpose, alias=None, fingerprint=None):
        purpose = normalize_purpose(purpose)
        wanted_alias = str(alias).lower() if alias is not None else None
        wanted_fp = _normalise_fingerprint(fingerprint)
        result = []
        for item in self.accepted + self.deduplicated:
            if item.purpose != purpose or not item.accepted:
                continue
            if wanted_alias is not None:
                names = [str(item.alias or "").lower(),
                         str(item.source_alias or "").lower()]
                if wanted_alias not in names:
                    continue
            if wanted_fp is not None and item.fingerprint != wanted_fp:
                continue
            result.append(item.reason)
        return result

    why_accepted = why
    explain = why

    def to_dict(self):
        return {
            "decision": self.decision,
            "reason": self.reason,
            "valid": self.is_valid,
            "decisions": [item.to_dict() for item in self.decisions],
            "accepted": [item.to_dict() for item in self.accepted],
            "rejected": [item.to_dict() for item in self.rejected],
            "deduplicated": [item.to_dict() for item in self.deduplicated],
            "conflicts": [item.to_dict() for item in self.conflicts],
            "notes": list(self.notes),
            "shared_certificates": dict(self.shared_certificates),
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            decisions=[ReviewDecision.from_dict(item)
                       for item in data.get("decisions", [])],
            conflicts=[PlanConflict.from_dict(item)
                       for item in data.get("conflicts", [])],
            deduplicated=[ReviewDecision.from_dict(item)
                          for item in data.get("deduplicated", [])],
            notes=data.get("notes", []),
            shared_certificates=data.get("shared_certificates", {}),
        )

    def __repr__(self):
        return "ReviewResult(decision=%r, accepted=%d, rejected=%d, conflicts=%d)" % (
            self.decision, len(self.accepted), len(self.rejected), len(self.conflicts))


class DeliveryPlan(object):
    """Two (or more) minimal truststore manifests plus their review evidence."""

    def __init__(self, manifests, review=None, conflicts=None,
                 source_name=None, source_inventory_sha256=None,
                 format=PLAN_FORMAT):
        self.manifests = {}
        for key, value in dict(manifests or {}).items():
            purpose = str(normalize_purpose(key))
            if not isinstance(value, TruststoreManifest):
                value = TruststoreManifest(purpose, value)
            self.manifests[purpose] = value
        self.review = review or ReviewResult()
        self.conflicts = list(conflicts or [])
        self.source_name = source_name
        self.source_inventory_sha256 = source_inventory_sha256
        self.format = format

    @property
    def purposes(self):
        return list(self.manifests.keys())

    def __getitem__(self, purpose):
        return self.manifest_for(purpose)

    def __getattr__(self, name):
        manifests = self.__dict__.get("manifests", {})
        if name in manifests:
            return manifests[name]
        try:
            purpose = normalize_purpose(name)
        except Exception:
            purpose = name
        if purpose in manifests:
            return manifests[purpose]
        raise AttributeError(name)

    def __iter__(self):
        return iter(self.manifests)

    def __len__(self):
        return len(self.manifests)

    def keys(self):
        return list(self.manifests)

    def values(self):
        return list(self.manifests.values())

    def items(self):
        return list(self.manifests.items())

    @property
    def entries(self):
        return dict((purpose, list(manifest.entries))
                    for purpose, manifest in self.manifests.items())

    @property
    def errors(self):
        return [item for item in self.conflicts if item.is_error]

    @property
    def ok(self):
        return not self.errors and self.review.is_valid

    @property
    def is_valid(self):
        return self.ok

    @property
    def has_conflicts(self):
        return bool(self.errors)

    @property
    def valid(self):
        return self.ok

    @property
    def review_result(self):
        return self.review

    @property
    def decision(self):
        return "accept" if self.ok else "reject"

    @property
    def outcome(self):
        return self.decision.upper()

    @property
    def reason(self):
        return self.review.reason

    @property
    def shared_certificates(self):
        return self.review.shared_certificates

    @property
    def common_certificates(self):
        return list(self.review.shared_certificates.keys())

    @property
    def shared_certificate_purposes(self):
        return find_shared_certificates(self.manifests)

    @property
    def truststores(self):
        return dict((purpose, manifest.to_keystore())
                    for purpose, manifest in self.manifests.items())

    def manifest_for(self, purpose):
        return self.manifests[normalize_purpose(purpose)]

    manifest = manifest_for
    get_manifest = manifest_for
    manifest_by_purpose = manifest_for

    def get(self, purpose, default=None):
        try:
            return self.manifest_for(purpose)
        except KeyError:
            return default

    def build_truststore(self, purpose, store_type="jks"):
        return self.manifest_for(purpose).to_keystore(store_type=store_type)

    def accepted_aliases(self, purpose):
        return list(self.manifest_for(purpose).source_aliases)

    def accepted_fingerprints(self, purpose):
        return list(self.manifest_for(purpose).fingerprints)

    def materialize(self, store_type="jks"):
        return dict((purpose, manifest.to_keystore(store_type=store_type))
                    for purpose, manifest in self.manifests.items())

    def truststore(self, purpose, store_type="jks"):
        return self.build_truststore(purpose, store_type=store_type)

    def to_dict(self):
        return {
            "format": self.format,
            "source_name": self.source_name,
            "source_inventory_sha256": self.source_inventory_sha256,
            "purposes": list(self.manifests.keys()),
            "manifests": dict((purpose, manifest.to_dict())
                              for purpose, manifest in self.manifests.items()),
            "review": self.review.to_dict(),
            "conflicts": [item.to_dict() for item in self.conflicts],
            "valid": self.ok,
            "decision": self.decision,
            "reason": self.reason,
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent,
                          ensure_ascii=False)

    @classmethod
    def from_dict(cls, data):
        manifests = {}
        for purpose, item in data.get("manifests", {}).items():
            manifests[purpose] = TruststoreManifest.from_dict(item)
        review = ReviewResult.from_dict(data.get("review", {}))
        return cls(
            manifests=manifests,
            review=review,
            conflicts=[PlanConflict.from_dict(item)
                       for item in data.get("conflicts", [])],
            source_name=data.get("source_name"),
            source_inventory_sha256=data.get("source_inventory_sha256"),
            format=data.get("format", PLAN_FORMAT),
        )

    @classmethod
    def from_json(cls, value):
        return cls.from_dict(json.loads(value))

    def verify(self, store=None, declarations=None, check_source_inventory=False,
               password=None, store_password=None, store_type=None):
        result = VerificationResult(checked={
            "source_name": self.source_name,
            "purposes": list(self.manifests.keys()),
        })
        for problem in self.errors:
            result.add(str(problem))
        for purpose, manifest in self.manifests.items():
            sub = manifest.verify(
                store=store, declarations=declarations,
                check_source_inventory=check_source_inventory,
                password=password, store_password=store_password,
                store_type=store_type)
            for problem in sub.problems:
                result.add("%s: %s" % (purpose, problem))
            result.checked.setdefault("manifests", {})[purpose] = sub.to_dict()
        return result

    def matches(self, store=None, declarations=None, **kwargs):
        return self.verify(store, declarations, **kwargs).ok

    def __repr__(self):
        return "DeliveryPlan(purposes=%r, valid=%r)" % (list(self.manifests), self.ok)


def inventory_sha256(store):
    """Digest of the certificate-bearing inventory of ``store``."""
    rows = []
    for alias, entry in sorted(store.entries.items()):
        der, cert_type, origin = _entry_certificate(entry)
        rows.append([
            alias,
            certificate_fingerprint(der) if der is not None else None,
            type(entry).__name__,
            origin,
        ])
    return _digest(rows)


def _resolve_entry(store, alias):
    if alias is None:
        return None, None, "no source alias was declared"
    if alias in store.entries:
        return alias, store.entries[alias], None
    matches = [name for name in store.entries if name.lower() == str(alias).lower()]
    if len(matches) == 1:
        return matches[0], store.entries[matches[0]], None
    if len(matches) > 1:
        return None, None, "alias is ambiguous by case: %s" % ", ".join(sorted(matches))
    return None, None, "alias is not present in the intake store"


def _approval_index(declarations, purpose):
    result = {}
    for item in declarations:
        if purpose in item.purposes:
            result.setdefault(item.alias.lower(), []).append(item)
    return result


def _load_store(store, password=None, store_password=None, store_type=None,
                name=None):
    password = password if password is not None else store_password
    if isinstance(store, dict):
        if "intake" in store:
            return _load_store(store["intake"], password=store.get("password", password),
                               store_type=store.get("type", store_type),
                               name=store.get("name", name))
        if "keystore" in store:
            return _load_store(store["keystore"], store.get("password", password),
                               store_type=store.get("type", store_type),
                               name=store.get("name", name))
        if "path" in store:
            name = name or store.get("name")
            path = store["path"]
            password = password if password is not None else store.get("password")
            store_type = store_type or store.get("type")
            return _load_store(path, password=password, store_type=store_type,
                               name=name)
        if "entries" in store:
            class _MappingStore(object):
                pass
            result = _MappingStore()
            result.store_type = store.get("store_type", "jks")
            raw_entries = store["entries"]
            if isinstance(raw_entries, (list, tuple)):
                raw_entries = dict((item.alias, item) for item in raw_entries)
            result.entries = dict(
                (alias, TrustedCertEntry(alias=alias, cert=bytes(value),
                                         type="X.509", store_type=result.store_type))
                if isinstance(value, (bytes, bytearray)) else (alias, value)
                for alias, value in dict(raw_entries).items())
            return result, name or store.get("name") or "<mapping>"
        raise DeclarationException("Cannot use store mapping without path or entries")

    if hasattr(store, "entries"):
        return store, name or getattr(store, "name", None) or "<memory>"

    if hasattr(store, "keystore") and hasattr(store.keystore, "entries"):
        return store.keystore, name or getattr(store, "name", "<memory>")

    if isinstance(store, (str, bytes)):
        if not isinstance(store, str):
            store = store.decode("utf-8")
        if store_type in (None, "", "auto"):
            lower = store.lower()
            if lower.endswith(".bks") or ".bksv" in lower:
                store_type = "bks"
            elif lower.endswith(".uber"):
                store_type = "uber"
        if store_type in ("bks", "uber"):
            from . import bks
            if store_type == "bks":
                result = bks.BksKeyStore.load(store, password)
            else:
                result = bks.UberKeyStore.load(store, password)
        else:
            result = KeyStore.load(store, password)
        return result, name or os.path.basename(store)

    raise DeclarationException("Unsupported intake store: %r" % (store,))


class TruststorePlanner(object):
    """Allocate intake aliases to purpose-specific minimal truststores."""

    def __init__(self, store=None, declarations=None, purposes=None, store_name=None,
                 password=None, store_password=None, store_type=None,
                 fingerprint_algorithm="sha256", allow_private_key_certificates=True,
                 **kwargs):
        if store is None:
            store = kwargs.pop("intake", None)
        if store is None:
            store = kwargs.pop("keystore", None)
        if store is None:
            raise DeclarationException("An intake store is required")
        if declarations is None:
            declarations = kwargs.pop("approvals", None)
        if declarations is None:
            declarations = kwargs.pop("entry_declarations", None)
        if purposes is None:
            purposes = kwargs.pop("approved_purposes", None)
        if store_name is None:
            store_name = kwargs.pop("source_name", None)
        if store_name is None:
            store_name = kwargs.pop("source", None)
        self.store, detected_name = _load_store(
            store, password=password, store_password=store_password,
            store_type=store_type, name=store_name)
        self.store_name = store_name or detected_name
        self.source = self.store
        self.keystore = self.store
        self.declarations = normalize_declarations(declarations)
        self.purposes = [normalize_purpose(item) for item in _as_list(purposes)]
        self.fingerprint_algorithm = _fingerprint_algorithm_for(fingerprint_algorithm)
        self.allow_private_key_certificates = bool(allow_private_key_certificates)
        self.kwargs = dict(kwargs)

    @classmethod
    def from_keystore(cls, keystore, declarations=None, purposes=None, **kwargs):
        return cls(keystore, declarations, purposes, **kwargs)

    @classmethod
    def from_path(cls, path, password=None, declarations=None, purposes=None,
                  **kwargs):
        return cls(path, declarations, purposes, password=password, **kwargs)

    def plan(self, declarations=None, purposes=None):
        if declarations is not None:
            self.declarations = normalize_declarations(declarations)
        if purposes is not None:
            self.purposes = [normalize_purpose(item) for item in _as_list(purposes)]
        return self.build()

    allocate = plan
    derive = plan
    plan_truststores = plan
    build_plan = plan

    def build(self):
        before_inventory = inventory_sha256(self.store)

        declarations = list(self.declarations)
        purposes = list(self.purposes)
        if not purposes:
            purposes = list(DEFAULT_PURPOSES)
            for item in declarations:
                for purpose in item.purposes:
                    if purpose not in purposes:
                        purposes.append(purpose)

        conflicts = []
        notes = []
        manifest_entries = {}
        decisions = []
        deduplicated = []

        for purpose in purposes:
            purpose_decls = [item for item in declarations if purpose in item.purposes]
            entries, accepted, rejected, dedup, purpose_conflicts = self._plan_purpose(
                purpose, purpose_decls)
            manifest_entries[purpose] = entries
            decisions.extend(accepted)
            decisions.extend(rejected)
            deduplicated.extend(dedup)
            conflicts.extend(purpose_conflicts)

        self._link_shared_certificates(manifest_entries, decisions)

        shared = {}
        for purpose, entries in manifest_entries.items():
            for entry in entries:
                shared.setdefault(entry.fingerprint, []).append({
                    "purpose": str(purpose),
                    "alias": entry.alias,
                    "source_alias": entry.source_alias,
                    "reason": entry.reason,
                })
        shared = dict((fingerprint, items) for fingerprint, items in shared.items()
                      if len(set(item["purpose"] for item in items)) > 1)

        review = ReviewResult(decisions=decisions, conflicts=conflicts,
                              deduplicated=deduplicated, notes=notes,
                              shared_certificates=shared)

        manifests = {}
        for purpose in purposes:
            manifests[purpose] = TruststoreManifest(
                purpose=purpose,
                entries=manifest_entries[purpose],
                source_name=self.store_name,
                source_inventory_sha256=before_inventory,
            )

        after_inventory = inventory_sha256(self.store)
        if before_inventory != after_inventory:
            conflict = PlanConflict(
                "source_modified",
                "the intake store changed during planning; the plan is read-only "
                "and must be rebuilt from a stable source",
                details={"before": before_inventory, "after": after_inventory})
            conflicts.append(conflict)
            review.conflicts.append(conflict)

        return DeliveryPlan(
            manifests=manifests,
            review=review,
            conflicts=conflicts,
            source_name=self.store_name,
            source_inventory_sha256=before_inventory,
        )

    def _plan_purpose(self, purpose, declarations):
        conflicts = []
        decisions = []
        deduplicated = []
        candidates = []

        by_alias = {}
        for declaration in declarations:
            by_alias.setdefault(declaration.alias.lower(), []).append(declaration)

        for alias_key, group in sorted(by_alias.items(), key=lambda item: item[0]):
            approved = [item for item in group if item.approved_for(purpose)]
            denied = [item for item in group if not item.approved_for(purpose)]
            source_alias = group[0].alias

            if denied and approved:
                conflict = PlanConflict(
                    "conflicting_approval",
                    "alias '%s' is both approved and denied for purpose '%s'"
                    % (source_alias, purpose),
                    purpose=purpose, alias=source_alias,
                    source_alias=source_alias)
                conflicts.append(conflict)
                decisions.append(ReviewDecision(
                    purpose, source_alias, False, conflict.message,
                    source_alias=source_alias, conflict=conflict))
                continue
            if not approved:
                decisions.append(ReviewDecision(
                    purpose, source_alias, False,
                    "source alias '%s' is explicitly not approved for purpose '%s'"
                    % (source_alias, purpose),
                    source_alias=source_alias))
                continue

            if len(approved) > 1:
                declared = set(item.fingerprint for item in approved)
                destinations = set((item.destination_alias or "").lower()
                                   for item in approved)
                if len(declared) > 1 or len(destinations) > 1:
                    conflict = PlanConflict(
                        "conflicting_declaration",
                        "alias '%s' has conflicting declarations for purpose '%s'"
                        % (source_alias, purpose),
                        purpose=purpose, alias=source_alias,
                        source_alias=source_alias,
                        details={"fingerprints": sorted(
                            item for item in declared if item is not None)})
                else:
                    conflict = PlanConflict(
                        "duplicate_declaration",
                        "alias '%s' is declared more than once for purpose '%s'"
                        % (source_alias, purpose),
                        purpose=purpose, alias=source_alias,
                        source_alias=source_alias)
                conflicts.append(conflict)
                decisions.append(ReviewDecision(
                    purpose, source_alias, False, conflict.message,
                    source_alias=source_alias, conflict=conflict))
                continue

            declaration = approved[0]
            declared_source = (str(declaration.source)
                               if declaration.source is not None else None)
            actual_source = (str(self.store_name)
                             if self.store_name is not None else None)
            source_matches = (
                declared_source is None or actual_source in (None, "<memory>") or
                declared_source == actual_source or
                os.path.basename(declared_source) == os.path.basename(actual_source))
            if not source_matches:
                conflict = PlanConflict(
                    "source_mismatch",
                    "alias '%s' declares source '%s', but the intake source is '%s'"
                    % (source_alias, declaration.source, self.store_name),
                    purpose=purpose, alias=source_alias,
                    source_alias=source_alias)
                conflicts.append(conflict)
                decisions.append(ReviewDecision(
                    purpose, source_alias, False, conflict.message,
                    source_alias=source_alias, conflict=conflict,
                    declaration=declaration))
                continue

            actual_alias, entry, problem = _resolve_entry(self.store, declaration.alias)
            if problem is not None:
                conflict = PlanConflict(
                    "missing_source_alias",
                    "alias '%s' cannot be sourced from the intake store: %s"
                    % (declaration.alias, problem),
                    purpose=purpose, alias=declaration.alias,
                    source_alias=declaration.alias)
                conflicts.append(conflict)
                decisions.append(ReviewDecision(
                    purpose, declaration.alias, False, conflict.message,
                    source_alias=declaration.alias, conflict=conflict,
                    declaration=declaration))
                continue

            der, cert_type, origin = _entry_certificate(entry)
            if der is None:
                conflict = PlanConflict(
                    "missing_certificate",
                    "alias '%s' carries no certificate material" % actual_alias,
                    purpose=purpose, alias=actual_alias,
                    source_alias=actual_alias)
                conflicts.append(conflict)
                decisions.append(ReviewDecision(
                    purpose, actual_alias, False, conflict.message,
                    source_alias=actual_alias, conflict=conflict,
                    declaration=declaration))
                continue

            if (not self.allow_private_key_certificates and
                    not isinstance(entry, TrustedCertEntry)):
                conflict = PlanConflict(
                    "unsupported_entry_type",
                    "alias '%s' is a %s, not a trusted certificate entry"
                    % (actual_alias, type(entry).__name__),
                    purpose=purpose, alias=actual_alias,
                    source_alias=actual_alias)
                conflicts.append(conflict)
                decisions.append(ReviewDecision(
                    purpose, actual_alias, False, conflict.message,
                    source_alias=actual_alias, conflict=conflict,
                    declaration=declaration))
                continue

            actual_fp = certificate_fingerprint(der, self.fingerprint_algorithm)
            actual_algorithm = self.fingerprint_algorithm
            declared_fp = declaration.fingerprint
            if declared_fp is not None:
                declared_algorithm = _infer_fingerprint_algorithm(
                    declared_fp, self.fingerprint_algorithm)
                expected_fp = certificate_fingerprint(der, declared_algorithm)
                if declared_fp != expected_fp:
                    conflict = PlanConflict(
                        "fingerprint_mismatch",
                        "alias '%s' has certificate %s, declaration expects %s"
                        % (actual_alias, expected_fp, declared_fp),
                        purpose=purpose, alias=actual_alias,
                        source_alias=actual_alias,
                        fingerprint=expected_fp,
                        details={"declared_fingerprint": declared_fp})
                    conflicts.append(conflict)
                    decisions.append(ReviewDecision(
                        purpose, actual_alias, False, conflict.message,
                        source_alias=actual_alias, fingerprint=expected_fp,
                        conflict=conflict, declaration=declaration))
                    continue
                actual_fp = expected_fp
                actual_algorithm = declared_algorithm

            candidates.append({
                "declaration": declaration,
                "source_alias": actual_alias,
                "entry": entry,
                "certificate": der,
                "certificate_type": cert_type,
                "origin": origin,
                "fingerprint": actual_fp,
                "fingerprint_algorithm": actual_algorithm,
                "destination_alias": declaration.destination_alias or actual_alias,
                "explicit_destination": declaration.destination_alias is not None,
                "trusted": isinstance(entry, TrustedCertEntry),
            })

        destination_owners = {}
        for candidate in candidates:
            key = candidate["destination_alias"].lower()
            destination_owners.setdefault(key, set()).add(candidate["fingerprint"])
        bad_destinations = set(key for key, fingerprints in destination_owners.items()
                               if len(fingerprints) > 1)
        if bad_destinations:
            for candidate in candidates:
                if candidate["destination_alias"].lower() not in bad_destinations:
                    continue
                conflict = PlanConflict(
                    "destination_alias_conflict",
                    "destination alias '%s' would be used for different certificates "
                    "in purpose '%s'" % (candidate["destination_alias"], purpose),
                    purpose=purpose, alias=candidate["destination_alias"],
                    source_alias=candidate["source_alias"],
                    fingerprint=candidate["fingerprint"])
                conflicts.append(conflict)
                decisions.append(ReviewDecision(
                    purpose, candidate["destination_alias"], False,
                    conflict.message, source_alias=candidate["source_alias"],
                    fingerprint=candidate["fingerprint"], conflict=conflict,
                    declaration=candidate["declaration"]))
            candidates = [item for item in candidates
                          if item["destination_alias"].lower() not in bad_destinations]

        by_fingerprint = {}
        for candidate in candidates:
            by_fingerprint.setdefault(candidate["fingerprint"], []).append(candidate)

        entries = []
        for fingerprint in sorted(by_fingerprint):
            group = sorted(
                by_fingerprint[fingerprint],
                key=lambda item: (
                    0 if item["trusted"] else 1,
                    0 if item["explicit_destination"] else 1,
                    item["source_alias"].lower(),
                ))
            canonical = group[0]
            all_aliases = sorted(set(item["source_alias"] for item in group))
            declared_fp = canonical["declaration"].fingerprint
            reason_parts = [
                "source alias '%s' is approved for purpose '%s'"
                % (canonical["source_alias"], purpose)
            ]
            if declared_fp is not None:
                reason_parts.append(
                    "and the certificate matches the declared %s fingerprint %s"
                    % (canonical["declaration"].extra.get("fingerprint_algorithm",
                                                          _infer_fingerprint_algorithm(declared_fp)),
                       fingerprint))
            else:
                reason_parts.append(
                    "and the source certificate fingerprint is %s" % fingerprint)
            if canonical["origin"] == "key_chain":
                reason_parts.append(
                    "certificate material is the leaf of the key entry's chain")
            if len(group) > 1:
                reason_parts.append(
                    "the same certificate is also present under approved alias(es) "
                    "%s for this purpose, so the minimal truststore keeps one copy"
                    % ", ".join("'%s'" % item["source_alias"]
                                for item in group[1:]))

            reason = "; ".join(reason_parts)
            entry = ManifestEntry(
                alias=canonical["destination_alias"],
                purpose=purpose,
                source_alias=canonical["source_alias"],
                certificate=canonical["certificate"],
                fingerprint=fingerprint,
                certificate_type=canonical["certificate_type"],
                reason=reason,
                source_aliases=all_aliases,
                source_entry_type=type(canonical["entry"]).__name__,
                source_name=self.store_name,
                reference=canonical["declaration"].reference,
                fingerprint_algorithm=canonical["fingerprint_algorithm"],
            )
            entries.append(entry)
            decisions.append(ReviewDecision(
                purpose, entry.alias, True, reason,
                source_alias=entry.source_alias,
                fingerprint=fingerprint,
                declaration=canonical["declaration"]))

            for duplicate in group[1:]:
                dedup_reason = (
                    "source alias '%s' is approved for purpose '%s' and matches "
                    "certificate %s, but it is not reused as a second truststore "
                    "entry because alias '%s' already supplies the same certificate "
                    "for this purpose"
                    % (duplicate["source_alias"], purpose, fingerprint,
                       canonical["source_alias"]))
                deduplicated.append(ReviewDecision(
                    purpose, canonical["destination_alias"], True, dedup_reason,
                    source_alias=duplicate["source_alias"],
                    fingerprint=fingerprint, selected=False,
                    declaration=duplicate["declaration"]))

        return entries, decisions, [], deduplicated, conflicts

    def _link_shared_certificates(self, manifest_entries, decisions):
        by_fingerprint = {}
        for purpose, entries in manifest_entries.items():
            for entry in entries:
                by_fingerprint.setdefault(entry.fingerprint, []).append(entry)

        for fingerprint, entries in by_fingerprint.items():
            purposes = _unique(str(item.purpose) for item in entries)
            if len(purposes) < 2:
                continue
            detail = []
            for item in entries:
                detail.append("'%s' for %s" % (item.source_alias, item.purpose))
                other = [other for other in entries if other.purpose != item.purpose]
                if other:
                    other_aliases = ", ".join(
                        "'%s'" % other_item.source_alias for other_item in other)
                    item.reason = (
                        "%s; the same certificate is independently approved for "
                        "%s via alias(es) %s, but %s relies only on its own approved "
                        "alias '%s' and does not inherit the other purpose's approval"
                        % (item.reason, ", ".join(str(other_item.purpose)
                                                  for other_item in other),
                           other_aliases, item.purpose, item.source_alias))
            for decision in decisions:
                if (decision.accepted and decision.fingerprint == fingerprint and
                        decision.selected):
                    matching = [item for item in entries
                                if item.purpose == decision.purpose and
                                item.source_alias == decision.source_alias]
                    if matching:
                        decision.reason = matching[0].reason


def _looks_like_declarations(value):
    if isinstance(value, EntryDeclaration):
        return True
    if isinstance(value, dict):
        return True
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, (EntryDeclaration, dict)):
                return True
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                return True
    return False


def _plan_truststores(store, declarations=None, purposes=None, **kwargs):
    return TruststorePlanner(store, declarations, purposes, **kwargs).build()


def plan_truststores(store=None, declarations=None, purposes=None, **kwargs):
    """Plan minimal truststores by approved purpose.

    ``store`` may be a loaded pyjks keystore, a path to one, or a mapping with
    ``path``/``entries``.  ``declarations`` may be a list of declarations, a
    mapping of purpose to aliases, or a mapping of alias to purpose.
    """
    if store is None:
        store = kwargs.pop("intake", None)
    if store is None:
        store = kwargs.pop("keystore", None)
    if store is None:
        raise DeclarationException("An intake store is required")
    if (isinstance(store, (str, bytes)) and isinstance(declarations, (str, bytes))
            and purposes is not None
            and "password" not in kwargs and "store_password" not in kwargs
            and _looks_like_declarations(purposes)):
        kwargs["password"] = declarations
        declarations = purposes
        purposes = None
    if declarations is None:
        declarations = kwargs.pop("approvals", None)
    if declarations is None:
        declarations = kwargs.pop("entry_declarations", None)
    if purposes is None and isinstance(declarations, dict):
        purposes = (declarations.get("purposes") or
                    declarations.get("approved_purposes"))
    if purposes is None:
        purposes = kwargs.pop("approved_purposes", None)
    return _plan_truststores(store, declarations, purposes, **kwargs)


def build_delivery_plan(store=None, declarations=None, purposes=None, **kwargs):
    """Alias for :func:`plan_truststores`."""
    return plan_truststores(store, declarations, purposes, **kwargs)


def create_delivery_plan(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def build_plan(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def plan_by_purpose(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def derive_truststores(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def allocate_truststores(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def review_delivery(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def truststore_plan(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def derive_purpose_truststores(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def build_purpose_truststores(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def plan_purpose_truststores(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def allocate_by_purpose(store=None, declarations=None, purposes=None, **kwargs):
    return plan_truststores(store, declarations, purposes, **kwargs)


def find_shared_certificates(manifests):
    """Return certificate fingerprints that occur in more than one purpose."""
    if isinstance(manifests, dict):
        items = list(manifests.items())
    else:
        items = [(item.purpose, item) for item in manifests]
    found = {}
    for purpose, manifest in items:
        for entry in manifest.entries:
            found.setdefault(entry.fingerprint, []).append(str(purpose))
    return dict((fingerprint, sorted(set(purposes)))
                for fingerprint, purposes in found.items()
                if len(set(purposes)) > 1)


find_shared_identity = find_shared_certificates


def verify_manifest(manifest, store=None, declarations=None, **kwargs):
    """Re-verify a manifest object, mapping or JSON document."""
    if isinstance(manifest, dict):
        manifest = TruststoreManifest.from_dict(manifest)
    elif isinstance(manifest, (str, bytes)):
        manifest = TruststoreManifest.from_json(manifest)
    return manifest.verify(store=store, declarations=declarations, **kwargs)


def verify_delivery_plan(plan, store=None, declarations=None, **kwargs):
    """Re-verify a complete delivery plan."""
    if isinstance(plan, dict):
        plan = DeliveryPlan.from_dict(plan)
    elif isinstance(plan, (str, bytes)):
        plan = DeliveryPlan.from_json(plan)
    return plan.verify(store=store, declarations=declarations, **kwargs)


PurposePlanner = TruststorePlanner
DeliveryPlanner = TruststorePlanner
PurposeScopedPlanner = TruststorePlanner
TrustStorePlanner = TruststorePlanner
DeliveryManifest = TruststoreManifest
TrustStoreManifest = TruststoreManifest
Manifest = TruststoreManifest
PurposeManifest = TruststoreManifest
TruststorePlan = DeliveryPlan
PurposePlan = DeliveryPlan
Delivery = DeliveryPlan
Review = ReviewResult
PurposeScopedTruststorePlanner = TruststorePlanner
ReadOnlyTruststorePlanner = TruststorePlanner
TruststorePlanBuilder = TruststorePlanner
DeliveryManifestEntry = ManifestEntry
ManifestReview = ReviewResult
PurposeAllocation = DeliveryPlan
AllocationPlan = DeliveryPlan
TruststoreDeliveryPlan = DeliveryPlan
ApprovedPurpose = Purpose
TrustPurpose = Purpose
DeclarationError = DeclarationException
PlanError = DeclarationException


__all__ = [
    "MANIFEST_FORMAT",
    "PLAN_FORMAT",
    "TruststorePlanException",
    "DeclarationException",
    "Purpose",
    "normalize_purpose",
    "ISSUANCE_REVIEW",
    "HISTORICAL_VERIFICATION",
    "ISSUANCE",
    "HISTORY",
    "SIGNING_REVIEW",
    "LEGACY_VERIFICATION",
    "DEFAULT_PURPOSES",
    "DEFAULT_APPROVED_PURPOSES",
    "certificate_fingerprint",
    "CertificateIdentity",
    "entry_certificate_der",
    "PlanConflict",
    "VerificationResult",
    "EntryDeclaration",
    "Approval",
    "ApprovalPolicy",
    "PurposePolicy",
    "DeclarationPolicy",
    "normalize_declarations",
    "ManifestEntry",
    "EntryCollection",
    "TruststoreManifest",
    "DeliveryManifest",
    "TrustStoreManifest",
    "Manifest",
    "PurposeManifest",
    "TruststorePlan",
    "PurposePlan",
    "Delivery",
    "Review",
    "Declaration",
    "AliasApproval",
    "PurposeApproval",
    "EntryApproval",
    "ReviewDecision",
    "ReviewResult",
    "DeliveryPlan",
    "inventory_sha256",
    "TruststorePlanner",
    "PurposePlanner",
    "DeliveryPlanner",
    "PurposeScopedPlanner",
    "TrustStorePlanner",
    "plan_truststores",
    "build_delivery_plan",
    "create_delivery_plan",
    "build_plan",
    "plan_by_purpose",
    "derive_truststores",
    "find_shared_certificates",
    "find_shared_identity",
    "verify_manifest",
    "verify_delivery_plan",
    "allocate_truststores",
    "review_delivery",
    "derive_purpose_truststores",
    "build_purpose_truststores",
    "plan_purpose_truststores",
    "allocate_by_purpose",
    "PurposeAllocation",
    "AllocationPlan",
    "TruststoreDeliveryPlan",
    "PurposeScopedTruststorePlanner",
    "ReadOnlyTruststorePlanner",
    "TruststorePlanBuilder",
    "DeliveryManifestEntry",
    "ManifestReview",
    "ApprovedPurpose",
    "TrustPurpose",
    "DeclarationError",
    "PlanError",
]
