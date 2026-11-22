# vim: set et ai ts=4 sts=4 sw=4:
"""
Preflight checks for de-duplicating public certificate objects.

The module operates on the public certificate records exposed by pyjks:

* :class:`jks.PrivateKeyEntry` stores ``cert_chain`` as an ordered list of
  ``(certificate_type, certificate_data)`` tuples.
* :class:`jks.TrustedCertEntry` stores one ``cert`` value.
* Entries such as :class:`jks.SecretKeyEntry` have no public chain.

A de-duplication plan is checked at two independent levels:

1. certificate object recovery: every distinct object used by a visible
   chain must still exist in the shared certificate store;
2. chain-slot recovery: every entry must keep enough positional evidence to
   reproduce the original chain, including its order and repeated objects.

Keeping a set of certificates is intentionally not enough to establish slot
recovery.  A set can prove that an object exists, but it cannot prove where
that object occurred in a chain or how many times it occurred.

The command-line entry point accepts JSON files and is also available as
``python -m jks.cert_dedup``::

    python -m jks.cert_dedup --chains chains.json --plan plan.json
    python -m jks.cert_dedup --demo
"""

from __future__ import print_function

import argparse
import base64
import binascii
import difflib
import hashlib
import json
import sys
from collections import Counter, OrderedDict

from .util import AbstractKeystore


__all__ = [
    "CertificateMaterial",
    "CertMaterial",
    "CertificateSlot",
    "DedupPlan",
    "PlanChain",
    "SlotEvidence",
    "DuplicateLoss",
    "EntryRecovery",
    "ObjectRecovery",
    "SlotRecovery",
    "PreflightReport",
    "preflight_certificate_dedup",
    "preflight",
    "check_dedup_plan",
    "check_certificate_objects",
    "check_chain_slots",
    "check_dedup",
    "verify_dedup",
    "certificate_preflight",
    "DeduplicationPlan",
    "PreflightResult",
    "CertificateObject",
    "replay_synthetic",
    "synthetic_replay",
]


DEFAULT_CERT_TYPE = "X.509"

_OBJECT_KEYS = (
    "certificates",
    "certificate_objects",
    "cert_objects",
    "certificate_set",
    "cert_set",
    "certificate_pool",
    "shared_certificates",
    "object_table",
    "certificate_store",
    "cert_store",
    "objects",
    "pool",
)

_CHAIN_KEYS = (
    "chains",
    "entry_chains",
    "chain_plan",
    "chain_refs",
    "chain_references",
    "chain_slots",
    "public_chains",
    "slot_table",
    "slot_refs",
    "slots",
    "references",
    "refs",
    "entries",
)

_ORDERED_CHAIN_KEYS = (
    "refs",
    "references",
    "object_ids",
    "certificate_ids",
    "cert_ids",
    "slots",
    "positions",
    "ordered_refs",
    "chain",
    "cert_chain",
    "public_chain",
)

_UNORDERED_CHAIN_KEYS = (
    "set",
    "certificates",
    "objects",
    "unordered",
    "cert_set",
    "certificate_set",
    "object_set",
)

_CERT_DATA_KEYS = ("cert", "certificate", "data", "der", "bytes", "value",
                   "encoded", "cert_base64", "der_base64")


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise TypeError("certificate material must be bytes, not %s" % type(value).__name__)


def _safe_getattr(value, name, default=None):
    """Read pyjks attributes without tripping encrypted-entry property guards."""
    try:
        return getattr(value, name)
    except Exception:
        return default


def _decode_text_data(value, encoding=None):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if not isinstance(value, str):
        raise TypeError("certificate data must be bytes or text, not %s" % type(value).__name__)

    if encoding:
        normalized = encoding.lower()
        if normalized in ("base64", "b64"):
            return base64.b64decode(value.encode("ascii"))
        if normalized in ("hex", "hexadecimal"):
            return binascii.unhexlify(value.encode("ascii"))
        if normalized in ("utf8", "utf-8", "text"):
            return value.encode("utf-8")
        raise ValueError("unsupported certificate encoding %r" % encoding)

    if value.startswith("base64:"):
        return base64.b64decode(value[len("base64:"):].encode("ascii"))
    if value.startswith("hex:"):
        return binascii.unhexlify(value[len("hex:"):].encode("ascii"))
    if value.startswith("utf8:"):
        return value[len("utf8:"):].encode("utf-8")
    return value.encode("utf-8")


def _normalize_cert_type(value):
    if value is None:
        return DEFAULT_CERT_TYPE
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return str(value)


def _base64_text(value):
    return base64.b64encode(value).decode("ascii")


class CertificateMaterial(object):
    """One public certificate object, using pyjks' type + DER record shape."""

    __slots__ = ("type", "cert")

    def __init__(self, cert, type=DEFAULT_CERT_TYPE, cert_type=None):
        if cert_type is not None and type == DEFAULT_CERT_TYPE:
            type = cert_type
        self.type = _normalize_cert_type(type)
        self.cert = _as_bytes(cert)

    @property
    def data(self):
        return self.cert

    @property
    def der(self):
        return self.cert

    @property
    def cert_type(self):
        return self.type

    @property
    def sha256(self):
        digest = hashlib.sha256()
        digest.update(self.type.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(self.cert)
        return digest.hexdigest()

    @property
    def fingerprint(self):
        return "sha256:" + self.sha256

    def as_tuple(self):
        return (self.type, self.cert)

    def as_dict(self):
        return {
            "type": self.type,
            "cert": _base64_text(self.cert),
            "encoding": "base64",
            "fingerprint": self.fingerprint,
            "sha256": self.sha256,
        }

    def __iter__(self):
        return iter(self.as_tuple())

    def __len__(self):
        return 2

    def __getitem__(self, index):
        return self.as_tuple()[index]

    def __eq__(self, other):
        if isinstance(other, CertificateMaterial):
            return self.as_tuple() == other.as_tuple()
        if isinstance(other, (tuple, list)) and len(other) == 2:
            try:
                return self.as_tuple() == (
                    _normalize_cert_type(other[0]), _as_bytes(other[1]))
            except (TypeError, ValueError):
                return False
        return False

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.as_tuple())

    def __repr__(self):
        return "CertificateMaterial(type=%r, sha256=%r)" % (self.type, self.sha256)


CertMaterial = CertificateMaterial
CertificateSlot = CertificateMaterial


class SlotEvidence(object):
    """Evidence for one expected chain position."""

    def __init__(self, entry, position, status, expected=None, actual=None,
                 reference=None, detail=None, ordered=True,
                 actual_position=None):
        self.entry = entry
        self.position = position
        self.status = status
        self.expected = expected
        self.actual = actual
        self.reference = reference
        self.detail = detail
        self.ordered = ordered
        self.actual_position = actual_position

    @property
    def expected_fingerprint(self):
        return self.expected.fingerprint if self.expected is not None else None

    @property
    def actual_fingerprint(self):
        return self.actual.fingerprint if self.actual is not None else None

    @property
    def ok(self):
        return self.status == "match"

    def as_dict(self):
        return {
            "entry": self.entry,
            "position": self.position,
            "actual_position": self.actual_position,
            "status": self.status,
            "ordered": self.ordered,
            "expected": self.expected.as_dict() if self.expected is not None else None,
            "actual": self.actual.as_dict() if self.actual is not None else None,
            "expected_fingerprint": self.expected_fingerprint,
            "actual_fingerprint": self.actual_fingerprint,
            "reference": self.reference,
            "detail": self.detail,
        }


class DuplicateLoss(object):
    """A repeated certificate occurrence that the plan cannot reproduce."""

    def __init__(self, entry, material, expected_count, actual_count,
                 expected_positions, lost_positions, ordered=True):
        self.entry = entry
        self.material = material
        self.expected_count = expected_count
        self.actual_count = actual_count
        self.expected_positions = list(expected_positions)
        self.lost_positions = list(lost_positions)
        self.ordered = ordered

    @property
    def fingerprint(self):
        return self.material.fingerprint

    def as_dict(self):
        return {
            "entry": self.entry,
            "fingerprint": self.fingerprint,
            "expected_count": self.expected_count,
            "actual_count": self.actual_count,
            "expected_positions": self.expected_positions,
            "lost_positions": self.lost_positions,
            "ordered": self.ordered,
        }


class EntryRecovery(object):
    """Recovery result for one keystore entry."""

    def __init__(self, alias, expected=None, readable=True, reason=None,
                 detail=None):
        self.alias = alias
        self.readable = readable
        self.reason = reason
        self.detail = detail
        self.expected = list(expected or [])
        self.actual = None
        self.plan_present = False
        self.ordered = True
        self.evidence = []
        self.object_issues = []
        self.slot_issues = []
        self.lost_positions = []
        self.extra_positions = []
        self.order_mismatch_positions = []
        self.unordered_positions = []
        self.duplicate_losses = []
        self.objects_ok = readable
        self.slots_ok = readable

    @property
    def chain_recoverable(self):
        return self.readable and self.objects_ok and self.slots_ok

    @property
    def chain_length(self):
        return len(self.expected)

    @property
    def certificate_objects_recoverable(self):
        return self.objects_ok

    @property
    def chain_slots_recoverable(self):
        return self.slots_ok

    @property
    def duplicate_lost_positions(self):
        positions = []
        for loss in self.duplicate_losses:
            for position in loss.lost_positions:
                if position is not None and position not in positions:
                    positions.append(position)
        return sorted(positions)

    def _chain_fingerprint(self, materials):
        digest = hashlib.sha256()
        for position, material in enumerate(materials):
            digest.update(str(position).encode("ascii"))
            digest.update(b":")
            if material is None:
                digest.update(b"<unresolved>")
            else:
                digest.update(material.type.encode("utf-8"))
                digest.update(b":")
                digest.update(material.sha256.encode("ascii"))
            digest.update(b"\n")
        return "sha256:" + digest.hexdigest()

    @property
    def expected_chain_fingerprint(self):
        return self._chain_fingerprint(self.expected)

    @property
    def actual_chain_fingerprint(self):
        if self.actual is None:
            return None
        return self._chain_fingerprint(self.actual)

    @property
    def chain_digest(self):
        return self.expected_chain_fingerprint

    @property
    def ok(self):
        return self.chain_recoverable

    def as_dict(self):
        return {
            "alias": self.alias,
            "readable": self.readable,
            "reason": self.reason,
            "detail": self.detail,
            "chain_length": len(self.expected),
            "expected": [c.as_dict() for c in self.expected],
            "actual": ([c.as_dict() if c is not None else None for c in self.actual]
                       if self.actual is not None else None),
            "plan_present": self.plan_present,
            "ordered": self.ordered,
            "objects_ok": self.objects_ok,
            "slots_ok": self.slots_ok,
            "chain_recoverable": self.chain_recoverable,
            "expected_chain_fingerprint": self.expected_chain_fingerprint,
            "actual_chain_fingerprint": self.actual_chain_fingerprint,
            "chain_digest": self.chain_digest,
            "lost_positions": self.lost_positions,
            "duplicate_lost_positions": self.duplicate_lost_positions,
            "extra_positions": self.extra_positions,
            "order_mismatch_positions": self.order_mismatch_positions,
            "unordered_positions": self.unordered_positions,
            "duplicate_losses": [d.as_dict() for d in self.duplicate_losses],
            "object_issues": [i.as_dict() for i in self.object_issues],
            "slot_issues": [i.as_dict() for i in self.slot_issues],
            "evidence": [e.as_dict() for e in self.evidence],
        }


class ObjectRecovery(object):
    """Certificate-object level preflight result."""

    def __init__(self):
        self.required = OrderedDict()
        self.available = OrderedDict()
        self.missing = []
        self.unresolved = []
        self.conflicts = []
        self.entry_results = OrderedDict()

    @property
    def ok(self):
        return not self.missing and not self.conflicts

    @property
    def recoverable(self):
        return self.ok

    def as_dict(self):
        return {
            "ok": self.ok,
            "recoverable": self.recoverable,
            "required": [m.as_dict() for m in self.required.values()],
            "available": [m.as_dict() for m in self.available.values()],
            "missing": list(self.missing),
            "missing_objects": list(self.missing),
            "unresolved": list(self.unresolved),
            "conflicts": list(self.conflicts),
            "entries": dict((a, e.objects_ok)
                            for a, e in self.entry_results.items()),
        }

    to_dict = as_dict

    def __getitem__(self, key):
        return self.as_dict()[key]

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__


class SlotRecovery(object):
    """Chain-position level preflight result."""

    def __init__(self):
        self.entries = OrderedDict()
        self.lost_slots = []
        self.extra_slots = []
        self.duplicate_losses = []

    @property
    def ok(self):
        return all(entry.slots_ok for entry in self.entries.values())

    @property
    def recoverable(self):
        return self.ok

    def as_dict(self):
        return {
            "ok": self.ok,
            "recoverable": self.recoverable,
            "entries": dict((a, e.slots_ok) for a, e in self.entries.items()),
            "lost_slots": list(self.lost_slots),
            "lost": list(self.lost_slots),
            "missing_slots": list(self.lost_slots),
            "unrecoverable_slots": list(self.lost_slots),
            "extra_slots": list(self.extra_slots),
            "duplicate_losses": list(self.duplicate_losses),
        }

    to_dict = as_dict

    def __getitem__(self, key):
        return self.as_dict()[key]

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__


class PreflightReport(object):
    """Combined object-level and slot-level preflight report."""

    def __init__(self, entries, objects, slots, unreadable, plan_issues=None):
        self.entries = entries
        self.objects = objects
        self.slots = slots
        self.unreadable = unreadable
        self.plan_issues = list(plan_issues or [])

    @property
    def ok(self):
        return self.objects.ok and self.slots.ok

    @property
    def certificates(self):
        return self.objects

    @property
    def certificate_objects(self):
        return self.objects

    @property
    def chains(self):
        return self.slots

    @property
    def chain_slots(self):
        return self.slots

    @property
    def objects_ok(self):
        return self.objects.ok

    @property
    def slots_ok(self):
        return self.slots.ok

    @property
    def certificates_ok(self):
        return self.objects.ok

    @property
    def certificate_objects_ok(self):
        return self.objects.ok

    @property
    def certificate_objects_recoverable(self):
        return self.objects.ok

    @property
    def chains_ok(self):
        return self.slots.ok

    @property
    def chain_slots_ok(self):
        return self.slots.ok

    @property
    def chain_slots_recoverable(self):
        return self.slots.ok

    @property
    def missing_objects(self):
        return self.objects.missing

    @property
    def missing_slots(self):
        return self.slots.lost_slots

    @property
    def lost_slots(self):
        return self.slots.lost_slots

    @property
    def duplicate_lost_positions(self):
        positions = []
        for entry in self.entries.values():
            for position in entry.duplicate_lost_positions:
                if position not in positions:
                    positions.append(position)
        return sorted(positions)

    @property
    def duplicate_losses(self):
        return self.slots.duplicate_losses

    @property
    def unreadable_entries(self):
        return self.unreadable

    @property
    def unreadable_aliases(self):
        return [item.get("entry") for item in self.unreadable]

    @property
    def unavailable_entries(self):
        return self.unreadable

    def as_dict(self):
        object_dict = self.objects.as_dict()
        slot_dict = self.slots.as_dict()
        return {
            "ok": self.ok,
            "objects_ok": self.objects_ok,
            "slots_ok": self.slots_ok,
            "certificates_ok": self.certificates_ok,
            "chains_ok": self.chains_ok,
            "objects": object_dict,
            "certificates": object_dict,
            "slots": slot_dict,
            "chains": slot_dict,
            "entries": dict((a, e.as_dict()) for a, e in self.entries.items()),
            "unreadable": list(self.unreadable),
            "unreadable_entries": list(self.unreadable),
            "unreadable_aliases": self.unreadable_aliases,
            "plan_issues": list(self.plan_issues),
            "missing_objects": list(self.objects.missing),
            "lost_slots": list(self.slots.lost_slots),
            "duplicate_lost_positions": self.duplicate_lost_positions,
            "duplicate_losses": self.duplicate_losses,
        }

    to_dict = as_dict

    def to_json(self, **kwargs):
        kwargs.setdefault("indent", 2)
        kwargs.setdefault("sort_keys", True)
        return json.dumps(self.as_dict(), **kwargs)

    def __getitem__(self, key):
        return self.as_dict()[key]

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__


class PlanChain(object):
    """Ordered or unordered references supplied for one entry."""

    def __init__(self, refs=None, ordered=True, present=True, source=None):
        self.refs = list(refs or [])
        self.ordered = bool(ordered)
        self.present = bool(present)
        self.source = source

    def as_dict(self):
        return {
            "present": self.present,
            "ordered": self.ordered,
            "refs": list(self.refs),
            "source": self.source,
        }


class DedupPlan(object):
    """
    A de-duplication plan.

    ``certificates`` (also accepted as ``objects``) is a mapping from object
    ID to a pyjks-shaped certificate record.  ``chains`` (also accepted as
    ``slots``) is a mapping from entry alias to either an ordered list of
    object IDs or an unordered set of object IDs.
    """

    def __init__(self, certificates=None, chains=None, objects=None, slots=None,
                 **kwargs):
        if certificates is None:
            certificates = objects
        if certificates is None:
            certificates = kwargs.get("object_table")
        if certificates is None:
            certificates = kwargs.get("cert_store")

        if chains is None:
            chains = slots
        if chains is None:
            chains = kwargs.get("chain_slots")
        if chains is None:
            chains = kwargs.get("references")

        self.has_certificates = certificates is not None
        self.certificates, self.certificate_issues = \
            _normalize_object_table(certificates)
        self.has_chains = chains is not None
        self.chains, self.chain_issues = _normalize_plan_chains(chains)
        self.issues = list(self.certificate_issues) + list(self.chain_issues)

    @property
    def objects(self):
        return self.certificates

    @property
    def slots(self):
        return self.chains

    @classmethod
    def from_dict(cls, value):
        return _normalize_plan(value)

    def as_dict(self):
        return {
            "has_certificates": self.has_certificates,
            "has_chains": self.has_chains,
            "certificates": [c.as_dict() for c in self.certificates.values()],
            "chains": dict((a, c.as_dict()) for a, c in self.chains.items()),
            "issues": list(self.issues),
        }


def _looks_like_cert_type(value):
    if not isinstance(value, str):
        return False
    normalized = value.upper().replace(".", "").replace("-", "")
    return normalized.startswith("X509") or "CERTIFICATE" in normalized


def _is_cert_record(value):
    if isinstance(value, CertificateMaterial):
        return True
    if isinstance(value, (bytes, bytearray, memoryview)):
        return True
    if isinstance(value, str):
        return True
    if _safe_getattr(value, "cert", None) is not None and \
            _safe_getattr(value, "cert_chain", None) is None:
        return True
    if isinstance(value, (tuple, list)) and len(value) == 2:
        if not isinstance(value[0], str):
            return False
        return isinstance(value[1], (bytes, bytearray, memoryview, str)) and \
            (_looks_like_cert_type(value[0]) or
             isinstance(value[1], (bytes, bytearray, memoryview)))
    if isinstance(value, dict):
        if any(key in value for key in _CERT_DATA_KEYS):
            return not any(key in value for key in ("refs", "references",
                                                    "object_ids", "chain",
                                                    "cert_chain"))
    return False


def _normalize_certificate(value, default_type=DEFAULT_CERT_TYPE):
    if isinstance(value, CertificateMaterial):
        return value

    if isinstance(value, (bytes, bytearray, memoryview)):
        return CertificateMaterial(_as_bytes(value), type=default_type)
    if isinstance(value, str):
        return CertificateMaterial(_decode_text_data(value), type=default_type)

    if isinstance(value, (tuple, list)):
        if len(value) != 2:
            raise ValueError("certificate tuple must contain (type, data)")
        cert_type = value[0] if value[0] is not None else default_type
        data = _decode_text_data(value[1])
        return CertificateMaterial(data, type=cert_type)

    if isinstance(value, dict):
        data = None
        for key in _CERT_DATA_KEYS:
            if key in value:
                data = value[key]
                break
        if data is None:
            raise ValueError("certificate record has no cert/data field")
        data = _decode_text_data(data, value.get("encoding"))
        cert_type = value.get("type", value.get("cert_type", default_type))
        return CertificateMaterial(data, type=cert_type)

    cert = _safe_getattr(value, "cert", None)
    if cert is not None:
        cert_type = _safe_getattr(value, "type", default_type)
        return CertificateMaterial(cert, type=cert_type)

    raise TypeError("unsupported certificate record %r" % (value,))


def _normalize_certificate_sequence(value):
    if value is None:
        raise ValueError("certificate sequence is None")
    if isinstance(value, dict):
        for key in ("cert_chain", "public_chain", "chain", "certificates",
                    "certs"):
            if key in value:
                return _normalize_certificate_sequence(value[key])
    if isinstance(value, (CertificateMaterial, bytes, bytearray, memoryview,
                          str)):
        return [_normalize_certificate(value)]
    if _safe_getattr(value, "cert", None) is not None and \
            _safe_getattr(value, "cert_chain", None) is None:
        return [_normalize_certificate(value)]
    if _is_cert_record(value):
        return [_normalize_certificate(value)]

    result = []
    for item in value:
        result.append(_normalize_certificate(item))
    return result


def _visible_items(chains):
    if isinstance(chains, AbstractKeystore):
        return list(chains.entries.items())
    entries = _safe_getattr(chains, "entries", None)
    if entries is not None and not isinstance(chains, dict):
        return list(entries.items())

    if isinstance(chains, dict):
        lowered = dict((str(k).lower(), v) for k, v in chains.items())
        for container_key in ("entries", "chains", "visible_chains",
                              "public_chains", "entry_chains",
                              "cert_chains", "certificate_chains"):
            if container_key not in lowered:
                continue
            inner = lowered[container_key]
            if isinstance(inner, dict):
                return list(inner.items())
            return _visible_items(list(inner))
        return list(chains.items())

    alias = _safe_getattr(chains, "alias", None)
    if alias is not None and (
            _safe_getattr(chains, "cert_chain", None) is not None or
            _safe_getattr(chains, "cert", None) is not None):
        return [(alias, chains)]

    try:
        items = list(chains)
    except TypeError:
        raise TypeError("visible chains must be a keystore, mapping, or sequence")

    result = []
    for index, item in enumerate(items):
        if isinstance(item, (tuple, list)) and len(item) == 2 and \
                isinstance(item[0], str):
            result.append((item[0], item[1]))
            continue
        if isinstance(item, dict):
            alias = item.get("alias", item.get("entry", item.get("name")))
            if alias is not None:
                result.append((alias, item))
                continue
        alias = _safe_getattr(item, "alias", None)
        if alias is None and isinstance(item, dict):
            alias = item.get("alias", item.get("entry", item.get("name")))
        result.append((alias if alias is not None else str(index), item))
    return result


def _extract_visible_chain(alias, value):
    if value is None:
        return EntryRecovery(alias, readable=False, reason="no_public_chain",
                             detail="entry carries no public certificate chain")

    cert_chain = _safe_getattr(value, "cert_chain", None)
    if cert_chain is not None:
        try:
            certs = _normalize_certificate_sequence(cert_chain)
        except Exception as exc:
            return EntryRecovery(alias, readable=False,
                                 reason="unreadable_chain", detail=str(exc))
        if not certs:
            return EntryRecovery(alias, readable=False, reason="empty_chain",
                                 detail="entry has an empty public chain")
        return EntryRecovery(alias, expected=certs)

    if _safe_getattr(value, "cert", None) is not None:
        try:
            certs = _normalize_certificate_sequence(value)
        except Exception as exc:
            return EntryRecovery(alias, readable=False,
                                 reason="unreadable_chain", detail=str(exc))
        return EntryRecovery(alias, expected=certs)

    if isinstance(value, dict):
        for key in ("cert_chain", "public_chain", "chain", "certificates",
                    "certs"):
            if key in value:
                try:
                    certs = _normalize_certificate_sequence(value[key])
                except Exception as exc:
                    return EntryRecovery(alias, readable=False,
                                         reason="unreadable_chain",
                                         detail=str(exc))
                if not certs:
                    return EntryRecovery(
                        alias, readable=False, reason="empty_chain",
                        detail="entry has an empty public chain")
                return EntryRecovery(alias, expected=certs)
        if any(key in value for key in _CERT_DATA_KEYS):
            try:
                certs = _normalize_certificate_sequence(value)
            except Exception as exc:
                return EntryRecovery(alias, readable=False,
                                     reason="unreadable_chain",
                                     detail=str(exc))
            return EntryRecovery(alias, expected=certs)

    if _is_cert_record(value):
        try:
            certs = _normalize_certificate_sequence(value)
        except Exception as exc:
            return EntryRecovery(alias, readable=False,
                                 reason="unreadable_chain", detail=str(exc))
        return EntryRecovery(alias, expected=certs)

    if isinstance(value, (tuple, list)):
        try:
            certs = _normalize_certificate_sequence(value)
        except Exception as exc:
            return EntryRecovery(alias, readable=False,
                                 reason="unreadable_chain", detail=str(exc))
        if not certs:
            return EntryRecovery(alias, readable=False, reason="empty_chain",
                                 detail="entry has an empty public chain")
        return EntryRecovery(alias, expected=certs)

    return EntryRecovery(alias, readable=False, reason="no_public_chain",
                         detail="entry has no cert_chain or cert attribute")


def _normalize_object_table(raw):
    table = OrderedDict()
    issues = []
    if raw is None:
        return table, issues

    fingerprint_ids = []

    if isinstance(raw, dict):
        entries = list(raw.items())
    elif isinstance(raw, (set, frozenset)):
        entries = []
        for item in raw:
            try:
                material = _normalize_certificate(item)
            except Exception as exc:
                issues.append({"kind": "invalid_certificate",
                               "detail": str(exc)})
                continue
            entries.append((material.fingerprint, item))
    elif isinstance(raw, (CertificateMaterial, bytes, bytearray, memoryview)):
        entries = [(None, raw)]
    else:
        try:
            items = list(raw)
        except TypeError:
            raise TypeError("certificate object table must be a mapping or sequence")
        entries = []
        for index, item in enumerate(items):
            if isinstance(item, dict) and any(
                    key in item for key in ("id", "object_id", "object",
                                            "certificate_id", "cert_id",
                                            "key", "ref", "sha256",
                                            "fingerprint")):
                object_id = item.get("id", item.get("object_id",
                    item.get("object", item.get("certificate_id",
                    item.get("cert_id", item.get("key", item.get("ref",
                    item.get("sha256", item.get("fingerprint")))))))))
                entries.append((object_id, item))
            elif isinstance(item, (tuple, list)) and len(item) == 2 and \
                    not _is_cert_record(item) and _is_cert_record(item[1]):
                entries.append((item[0], item[1]))
            else:
                entries.append((index, item))

    for object_id, value in entries:
        try:
            material = _normalize_certificate(value)
        except Exception as exc:
            issues.append({
                "kind": "invalid_certificate",
                "object_id": object_id,
                "detail": str(exc),
            })
            continue

        if object_id is None:
            object_id = material.fingerprint

        if object_id in table and table[object_id] != material:
            issues.append({
                "kind": "conflicting_object_id",
                "object_id": object_id,
                "first_fingerprint": table[object_id].fingerprint,
                "second_fingerprint": material.fingerprint,
            })
            continue

        table[object_id] = material
        fingerprint_ids.append(object_id)

    return table, issues


def _normalize_ref(value):
    if isinstance(value, CertificateMaterial):
        return value, None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return CertificateMaterial(_as_bytes(value)), None
    if isinstance(value, dict):
        if "ref" in value:
            return value["ref"], None
        if "object_id" in value:
            return value["object_id"], None
        if "certificate_id" in value:
            return value["certificate_id"], None
        if "cert_id" in value:
            return value["cert_id"], None
        if "object" in value:
            return value["object"], None
        if "id" in value:
            return value["id"], None
        if "key" in value and not any(k in value for k in _CERT_DATA_KEYS):
            return value["key"], None
        if "sha256" in value and not any(k in value for k in _CERT_DATA_KEYS):
            return value["sha256"], None
        if "fingerprint" in value and not any(
                k in value for k in _CERT_DATA_KEYS):
            return value["fingerprint"], None
        if any(k in value for k in _CERT_DATA_KEYS):
            return _normalize_certificate(value), None
        raise ValueError("reference object has no ID or certificate data")
    if isinstance(value, (tuple, list)):
        if _is_cert_record(value):
            return _normalize_certificate(value), None
        if len(value) == 2 and _is_cert_record(value[1]):
            return value[0], None
        raise ValueError("ambiguous reference %r" % (value,))
    if isinstance(value, (str, int)):
        return value, None
    raise TypeError("unsupported chain reference %r" % (value,))


def _normalize_plan_chain(value):
    if isinstance(value, PlanChain):
        return value
    if value is None:
        return PlanChain([], ordered=True, present=True, source="null")

    if isinstance(value, (set, frozenset)):
        return PlanChain(list(value), ordered=False, present=True,
                         source="set")

    if isinstance(value, dict):
        for key in _ORDERED_CHAIN_KEYS:
            if key in value:
                refs = value[key]
                if isinstance(refs, (set, frozenset)):
                    return PlanChain(list(refs), ordered=False,
                                     present=True, source=key)
                if refs is None:
                    refs = []
                if isinstance(refs, dict):
                    positions = sorted(refs.keys(),
                                       key=lambda p: (str(type(p)), p))
                    refs = [refs[p] for p in positions]
                if isinstance(refs, (str, int)) or _is_cert_record(refs):
                    refs = [refs]
                return PlanChain(list(refs), ordered=True, present=True,
                                 source=key)
        for key in _UNORDERED_CHAIN_KEYS:
            if key in value:
                refs = value[key]
                if refs is None:
                    refs = []
                if isinstance(refs, (str, int)) or _is_cert_record(refs):
                    refs = [refs]
                return PlanChain(list(refs), ordered=False, present=True,
                                 source=key)
        if _is_cert_record(value):
            return PlanChain([value], ordered=True, present=True,
                             source="certificate")

        try:
            positions = sorted(value.keys(), key=lambda p: (str(type(p)), p))
        except TypeError:
            positions = list(value.keys())
        return PlanChain([value[p] for p in positions], ordered=True,
                         present=True, source="position_mapping")

    if isinstance(value, (str, int)):
        return PlanChain([value], ordered=True, present=True,
                         source="single_reference")

    if _is_cert_record(value):
        return PlanChain([value], ordered=True, present=True,
                         source="certificate")

    try:
        refs = list(value)
    except TypeError:
        raise TypeError("chain plan must be a sequence, set, or mapping")
    return PlanChain(refs, ordered=True, present=True, source="sequence")


def _normalize_plan_chains(raw):
    chains = OrderedDict()
    issues = []
    if raw is None:
        return chains, issues

    if isinstance(raw, dict):
        lowered = dict((str(k).lower(), k) for k in raw.keys())
        if "entries" in lowered and isinstance(raw[lowered["entries"]], dict):
            raw = raw[lowered["entries"]]
        elif "chains" in lowered and isinstance(raw[lowered["chains"]], dict):
            raw = raw[lowered["chains"]]
        items = list(raw.items())
    else:
        try:
            values = list(raw)
        except TypeError:
            raise TypeError("chain plan must be a mapping or sequence")
        items = []
        for index, item in enumerate(values):
            if isinstance(item, dict) and "alias" in item:
                alias = item["alias"]
                chain_value = item
                if not any(key in item for key in _ORDERED_CHAIN_KEYS +
                           _UNORDERED_CHAIN_KEYS):
                    chain_value = item.get("chain", item.get("refs", []))
                items.append((alias, chain_value))
            elif isinstance(item, (tuple, list)) and len(item) == 2 and \
                    isinstance(item[0], str):
                items.append((item[0], item[1]))
            else:
                items.append((str(index), item))

    for alias, value in items:
        try:
            chains[alias] = _normalize_plan_chain(value)
        except Exception as exc:
            issues.append({
                "kind": "invalid_chain_plan",
                "entry": alias,
                "detail": str(exc),
            })
            chains[alias] = PlanChain([], ordered=True, present=True,
                                      source="invalid")
    return chains, issues


def _normalize_plan(plan):
    if isinstance(plan, DedupPlan):
        return plan
    if plan is None:
        return DedupPlan()
    plan_certificates = _safe_getattr(plan, "certificates", None)
    if plan_certificates is None:
        plan_certificates = _safe_getattr(plan, "objects", None)
    if plan_certificates is None:
        plan_certificates = _safe_getattr(plan, "object_table", None)

    plan_chains = _safe_getattr(plan, "chains", None)
    if plan_chains is None:
        plan_chains = _safe_getattr(plan, "slots", None)
    if plan_chains is None:
        plan_chains = _safe_getattr(plan, "chain_slots", None)

    if plan_certificates is not None or plan_chains is not None:
        return DedupPlan(
            certificates=plan_certificates,
            chains=plan_chains,
        )
    if isinstance(plan, (tuple, list)) and len(plan) == 2 and \
            not _is_cert_record(plan):
        return DedupPlan(certificates=plan[0], chains=plan[1])
    if isinstance(plan, dict):
        lowered = dict((str(k).lower(), k) for k in plan.keys())
        object_key = None
        chain_key = None
        for key in _OBJECT_KEYS:
            if key in lowered:
                object_key = lowered[key]
                break
        for key in _CHAIN_KEYS:
            if key in lowered:
                chain_key = lowered[key]
                break

        if object_key is not None or chain_key is not None:
            return DedupPlan(
                certificates=plan.get(object_key) if object_key else None,
                chains=plan.get(chain_key) if chain_key else None,
            )

        values = list(plan.values())
        if values and all(_is_cert_record(v) for v in values):
            return DedupPlan(certificates=plan)
        if values and all(isinstance(v, (list, tuple, set, frozenset, dict))
                          for v in values):
            return DedupPlan(chains=plan)
        if not values:
            return DedupPlan(certificates=plan)
        return DedupPlan(certificates=plan)

    return DedupPlan(certificates=plan)


class _Resolver(object):
    def __init__(self, plan):
        self.plan = plan
        self.table = plan.certificates
        self.by_fingerprint = {}
        self.by_string_id = {}

        for object_id, material in self.table.items():
            self.by_fingerprint.setdefault(material.sha256, []).append(object_id)
            self.by_fingerprint.setdefault(material.fingerprint, []).append(object_id)
            self.by_string_id[str(object_id)] = object_id

    def _resolve_fingerprint_text(self, value):
        if not isinstance(value, str):
            return None
        text = value
        if text.startswith("sha256:"):
            text = text[len("sha256:"):]
        if len(text) != 64:
            return None
        try:
            int(text, 16)
        except ValueError:
            return None
        ids = self.by_fingerprint.get(text) or self.by_fingerprint.get(
            "sha256:" + text)
        if ids:
            return self.table[ids[0]]
        return None

    def resolve(self, reference):
        if isinstance(reference, CertificateMaterial):
            return reference, None
        if isinstance(reference, (bytes, bytearray, memoryview)):
            return CertificateMaterial(_as_bytes(reference)), None

        if not isinstance(reference, (dict, list, tuple)):
            if reference in self.table:
                return self.table[reference], None
            if str(reference) in self.by_string_id:
                return self.table[self.by_string_id[str(reference)]], None

        material = self._resolve_fingerprint_text(reference)
        if material is not None:
            return material, None

        try:
            normalized, error = _normalize_ref(reference)
        except Exception as exc:
            return None, str(exc)
        if error is not None:
            return None, error
        if isinstance(normalized, CertificateMaterial):
            return normalized, None
        if normalized == reference:
            return None, "unresolved reference %r" % (reference,)
        return self.resolve(normalized)


def _material_uses(entries):
    uses = OrderedDict()
    for alias, entry in entries.items():
        if not entry.readable:
            continue
        for position, material in enumerate(entry.expected):
            use = uses.setdefault(material.sha256, {
                "material": material,
                "entries": OrderedDict(),
            })
            use["entries"].setdefault(alias, []).append(position)
    return uses


def _available_materials(plan):
    available = OrderedDict()
    for material in plan.certificates.values():
        available[material.sha256] = material
    for chain in plan.chains.values():
        for reference in chain.refs:
            try:
                normalized, _ = _normalize_ref(reference)
            except Exception:
                continue
            if isinstance(normalized, CertificateMaterial):
                available.setdefault(normalized.sha256, normalized)
    return available


def _find_material_in_table(plan, material):
    for candidate in plan.certificates.values():
        if candidate == material:
            return candidate
    return None


def _check_objects(entries, plan, resolver):
    result = ObjectRecovery()
    uses = _material_uses(entries)
    available = _available_materials(plan)
    result.required = OrderedDict((fp, use["material"]) for fp, use in uses.items())
    result.available = available

    for fp, use in uses.items():
        material = use["material"]
        stored = _find_material_in_table(plan, material)
        if stored is None and fp not in available:
            result.missing.append({
                "kind": "missing_certificate_object",
                "fingerprint": material.fingerprint,
                "sha256": material.sha256,
                "type": material.type,
                "cert": material.as_dict()["cert"],
                "encoding": "base64",
                "entries": dict((alias, list(positions))
                                for alias, positions in use["entries"].items()),
            })

    for alias, entry in entries.items():
        if not entry.readable:
            continue
        entry_objects_ok = True
        for position, material in enumerate(entry.expected):
            if _find_material_in_table(plan, material) is None and \
                    material.sha256 not in available:
                entry_objects_ok = False
                entry.object_issues.append(_make_object_issue(
                    "missing_certificate_object", alias, position,
                    material, None, None))

        chain = plan.chains.get(alias)
        if chain is not None:
            for position, reference in enumerate(chain.refs):
                actual, error = resolver.resolve(reference)
                if actual is None and position < len(entry.expected):
                    issue = _make_object_issue(
                        "unresolved_reference", alias, position,
                        entry.expected[position], None, reference)
                    issue["detail"] = error
                    result.unresolved.append(issue)

        entry.objects_ok = entry_objects_ok
        result.entry_results[alias] = entry

    for issue in plan.certificate_issues:
        if issue.get("kind") == "conflicting_object_id":
            result.conflicts.append(issue)

    return result


def _make_object_issue(kind, alias, position, expected, actual, reference):
    return {
        "kind": kind,
        "entry": alias,
        "position": position,
        "expected_fingerprint": expected.fingerprint if expected is not None else None,
        "actual_fingerprint": actual.fingerprint if actual is not None else None,
        "reference": reference,
    }


def _make_slot_dict(evidence):
    return {
        "entry": evidence.entry,
        "position": evidence.position,
        "actual_position": evidence.actual_position,
        "status": evidence.status,
        "expected_fingerprint": evidence.expected_fingerprint,
        "actual_fingerprint": evidence.actual_fingerprint,
        "reference": evidence.reference,
    }


def _choose_lost_duplicate_positions(expected_positions, actual_positions):
    actual_set = set(actual_positions)
    remaining = list(expected_positions)
    for position in expected_positions:
        if position in actual_set:
            remaining.remove(position)
            actual_set.remove(position)
    if len(remaining) >= 0:
        return remaining
    return expected_positions[-1:]


def _compute_duplicate_losses(alias, expected, actual, ordered=True):
    expected_by_fp = OrderedDict()
    actual_by_fp = OrderedDict()
    for position, material in enumerate(expected):
        expected_by_fp.setdefault(material.sha256, {
            "material": material,
            "positions": [],
        })["positions"].append(position)
    for position, material in enumerate(actual):
        if material is None:
            continue
        actual_by_fp.setdefault(material.sha256, {
            "material": material,
            "positions": [],
        })["positions"].append(position)

    losses = []
    for fp, expected_info in expected_by_fp.items():
        actual_info = actual_by_fp.get(fp)
        actual_count = len(actual_info["positions"]) if actual_info else 0
        expected_positions = expected_info["positions"]
        if len(expected_positions) <= actual_count:
            continue
        actual_positions = actual_info["positions"] if actual_info else []
        lost_positions = _choose_lost_duplicate_positions(
            expected_positions, actual_positions)
        if not ordered:
            lost_positions = expected_positions[actual_count:]
        losses.append(DuplicateLoss(
            alias, expected_info["material"], len(expected_positions),
            actual_count, expected_positions, lost_positions, ordered=ordered))
    return losses


def _compare_ordered(alias, entry, chain, resolver):
    expected = entry.expected
    actual = []
    references = []
    for reference in chain.refs:
        material, error = resolver.resolve(reference)
        actual.append(material)
        references.append(reference)

    entry.actual = actual
    entry.ordered = True
    entry.evidence = []
    entry.lost_positions = []
    entry.extra_positions = []
    entry.order_mismatch_positions = []
    entry.unordered_positions = []
    entry.slot_issues = []

    expected_fps = [m.sha256 for m in expected]
    actual_fps = [m.sha256 if m is not None else None for m in actual]
    expected_counts = Counter(expected_fps)
    actual_counts = Counter(actual_fps)
    same_multiplicity = expected_counts == actual_counts
    aligned = OrderedDict()
    matched_actual = set()

    if same_multiplicity and len(expected) == len(actual):
        for position, (expected_material, actual_material) in enumerate(
                zip(expected, actual)):
            if expected_material == actual_material:
                aligned[position] = position
                matched_actual.add(position)
    else:
        matcher = difflib.SequenceMatcher(
            None, expected_fps, actual_fps, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag != "equal":
                continue
            for offset in range(i2 - i1):
                aligned[i1 + offset] = j1 + offset
                matched_actual.add(j1 + offset)

    for position, expected_material in enumerate(expected):
        fingerprint = expected_material.sha256
        if position in aligned:
            actual_position = aligned[position]
            actual_material = actual[actual_position]
            if actual_position == position:
                detail = "same object at the same chain position"
            else:
                detail = ("object matched in order at actual position %d; "
                          "missing/extra slots explain the offset" %
                          actual_position)
            evidence = SlotEvidence(
                alias, position, "match", expected=expected_material,
                actual=actual_material,
                reference=references[actual_position],
                detail=detail, ordered=True,
                actual_position=actual_position)
            entry.evidence.append(evidence)
            continue

        actual_material = None
        actual_reference = None
        if position < len(actual) and position not in matched_actual:
            actual_material = actual[position]
            actual_reference = references[position]

        if position < len(actual) and actual[position] is None and \
                position not in matched_actual:
            status = "unresolved_reference"
            detail = "chain reference did not resolve to a certificate object"
            entry.lost_positions.append(position)
            evidence = SlotEvidence(
                alias, position, status, expected=expected_material,
                actual=None, reference=references[position], detail=detail,
                ordered=True)
            entry.evidence.append(evidence)
            entry.slot_issues.append(evidence)
            continue

        if actual_material is not None and \
                actual_material.sha256 in expected_counts:
            if same_multiplicity:
                status = "wrong_order"
                detail = ("certificate exists in the chain, but order differs "
                          "at this position")
                entry.order_mismatch_positions.append(position)
            elif expected_counts[fingerprint] > actual_counts[fingerprint]:
                status = "duplicate_occurrence_lost"
                detail = ("this repeated occurrence is not evidenced at the "
                          "expected position")
            else:
                status = "duplicate_or_order_loss"
                detail = ("certificate exists elsewhere; this occurrence "
                          "cannot be restored here")
        elif actual_material is not None:
            status = "mismatch"
            detail = "a different certificate object occupies this position"
        elif expected_counts[fingerprint] > actual_counts[fingerprint]:
            status = ("missing_slot" if expected_counts[fingerprint] == 1
                      else "duplicate_occurrence_lost")
            detail = ("plan has no occurrence for this chain position"
                      if status == "missing_slot" else
                      "the repeated occurrence is missing from the plan")
        else:
            status = "missing_slot"
            detail = "plan has no reference for this chain position"

        entry.lost_positions.append(position)
        evidence = SlotEvidence(
            alias, position, status, expected=expected_material,
            actual=actual_material, reference=actual_reference,
            detail=detail, ordered=True,
            actual_position=(position if actual_material is not None else None))
        entry.evidence.append(evidence)
        entry.slot_issues.append(evidence)

    for actual_position, actual_material in enumerate(actual):
        if actual_position in matched_actual:
            continue
        if actual_position in entry.lost_positions:
            continue
        if actual_material is not None and \
                actual_material.sha256 in expected_counts and \
                actual_position < len(expected):
            continue
        entry.extra_positions.append(actual_position)
        evidence = SlotEvidence(
            alias, actual_position, "extra_slot", expected=None,
            actual=actual_material,
            reference=references[actual_position],
            detail="plan supplies a chain position that did not exist originally",
            ordered=True, actual_position=actual_position)
        entry.evidence.append(evidence)
        entry.slot_issues.append(evidence)

    entry.slots_ok = (len(expected) == len(actual) and
                      all(position in aligned and aligned[position] == position
                          for position in range(len(expected))))

    entry.duplicate_losses = _compute_duplicate_losses(
        alias, expected, actual, ordered=True)
    for loss in entry.duplicate_losses:
        unmatched = [
            position for position, material in enumerate(expected)
            if material.sha256 == loss.material.sha256 and
            position not in aligned
        ]
        if unmatched:
            loss.lost_positions = unmatched
        existing_lost = [
            position for position in entry.lost_positions
            if position < len(expected) and
            expected[position].sha256 == loss.material.sha256
        ]
        missing_occurrences = loss.expected_count - loss.actual_count
        for position in loss.lost_positions:
            if len(existing_lost) >= missing_occurrences:
                break
            if position not in entry.lost_positions:
                entry.lost_positions.append(position)
                existing_lost.append(position)
        if not any(evidence.status == "duplicate_occurrence_lost" and
                   evidence.position == loss.lost_positions[0]
                   for evidence in entry.slot_issues):
            entry.slot_issues.append(SlotEvidence(
                alias, loss.lost_positions[0] if loss.lost_positions else None,
                "duplicate_occurrence_lost",
                expected=loss.material, actual=None,
                detail="expected %d occurrence(s), plan provides %d" %
                       (loss.expected_count, loss.actual_count),
                ordered=True))


def _compare_unordered(alias, entry, chain, resolver, result):
    expected = entry.expected
    actual = []
    references = []
    for reference in chain.refs:
        material, error = resolver.resolve(reference)
        actual.append(material)
        references.append((reference, error))

    entry.actual = actual
    entry.ordered = False
    entry.evidence = []
    entry.lost_positions = list(range(len(expected)))
    entry.unordered_positions = list(range(len(expected)))
    entry.extra_positions = []
    entry.order_mismatch_positions = []
    entry.slots_ok = False

    actual_counts = Counter(m.sha256 for m in actual if m is not None)
    seen = Counter()
    for position, expected_material in enumerate(expected):
        seen[expected_material.sha256] += 1
        if actual_counts[expected_material.sha256] >= seen[expected_material.sha256]:
            status = "unordered_slot"
            detail = "object exists, but a set carries no position evidence"
            actual_material = None
            for candidate in actual:
                if candidate == expected_material:
                    actual_material = candidate
                    break
        else:
            status = "missing_slot"
            detail = "certificate set lacks an occurrence required by this slot"
            actual_material = None

        evidence = SlotEvidence(
            alias, position, status, expected=expected_material,
            actual=actual_material, reference=None, detail=detail,
            ordered=False)
        entry.evidence.append(evidence)
        entry.slot_issues.append(evidence)

    entry.duplicate_losses = _compute_duplicate_losses(
        alias, expected, actual, ordered=False)
    for loss in entry.duplicate_losses:
        entry.slot_issues.append(SlotEvidence(
            alias, loss.lost_positions[0] if loss.lost_positions else None,
            "duplicate_occurrence_lost", expected=loss.material, actual=None,
            detail="set contains %d of %d occurrence(s); lost positions %r" %
                   (loss.actual_count, loss.expected_count, loss.lost_positions),
            ordered=False))


def _check_slots(entries, plan, resolver):
    result = SlotRecovery()
    for alias, entry in entries.items():
        if not entry.readable:
            continue

        result.entries[alias] = entry
        chain = plan.chains.get(alias)

        if chain is None:
            entry.plan_present = False
            entry.actual = None
            entry.ordered = False
            entry.slots_ok = False
            entry.lost_positions = list(range(len(entry.expected)))
            entry.unordered_positions = list(range(len(entry.expected)))
            for position, expected_material in enumerate(entry.expected):
                evidence = SlotEvidence(
                    alias, position, "missing_chain_slots",
                    expected=expected_material, actual=None,
                    detail="de-duplication plan has no chain-slot entry for this alias")
                entry.evidence.append(evidence)
                entry.slot_issues.append(evidence)
                result.lost_slots.append(_make_slot_dict(evidence))
            retained_set = list(_available_materials(plan).values())
            entry.duplicate_losses = _compute_duplicate_losses(
                alias, entry.expected, retained_set, ordered=False)
            for loss in entry.duplicate_losses:
                result.duplicate_losses.append(loss.as_dict())
            continue

        entry.plan_present = True
        if chain.ordered:
            _compare_ordered(alias, entry, chain, resolver)
        else:
            _compare_unordered(alias, entry, chain, resolver, result)

        for evidence in entry.slot_issues:
            if evidence.status in ("extra_slot",):
                result.extra_slots.append(_make_slot_dict(evidence))
            elif evidence.status != "match":
                if evidence.status not in ("duplicate_occurrence_lost",):
                    result.lost_slots.append(_make_slot_dict(evidence))
        for loss in entry.duplicate_losses:
            result.duplicate_losses.append(loss.as_dict())

    return result


def preflight_certificate_dedup(chains=None, plan=None, **kwargs):
    """
    Check a public-certificate de-duplication plan.

    :param chains: A pyjks keystore, mapping of alias to pyjks entry/chain, or
        sequence of pyjks entries.  Each visible chain is read from
        ``cert_chain`` (private/BKS key entries) or ``cert`` (trusted
        certificate entries).
    :param plan: A :class:`DedupPlan`, a mapping with ``certificates`` and
        ``chains`` members, a ``(certificates, chains)`` pair, or a mapping
        from alias to chain references.  Certificate records use pyjks'
        ``(type, data)`` shape; JSON input accepts base64/hex/utf8 data.
    :returns: :class:`PreflightReport`
    """
    if chains is None:
        chains = kwargs.pop("visible_chains", kwargs.pop("visible", None))
    if plan is None:
        plan = kwargs.pop("dedup_plan", kwargs.pop("deduplication_plan", None))
    if kwargs:
        raise TypeError("unexpected keyword argument(s): %s" %
                        ", ".join(sorted(kwargs)))
    if chains is None or plan is None:
        raise TypeError("visible chains and a de-duplication plan are required")

    entries = OrderedDict()
    unreadable = []

    for alias, value in _visible_items(chains):
        entry = _extract_visible_chain(alias, value)
        entries[alias] = entry
        if not entry.readable:
            unreadable.append({
                "entry": alias,
                "reason": entry.reason,
                "detail": entry.detail,
            })

    normalized_plan = _normalize_plan(plan)
    resolver = _Resolver(normalized_plan)
    objects = _check_objects(entries, normalized_plan, resolver)
    slots = _check_slots(entries, normalized_plan, resolver)

    for issue in normalized_plan.chain_issues:
        if issue.get("kind") == "invalid_chain_plan":
            alias = issue.get("entry")
            if alias in entries:
                entries[alias].slots_ok = False

    return PreflightReport(entries, objects, slots, unreadable,
                           plan_issues=normalized_plan.issues)


def preflight(chains=None, plan=None, **kwargs):
    """Alias for :func:`preflight_certificate_dedup`."""
    return preflight_certificate_dedup(chains, plan, **kwargs)


check_dedup_plan = preflight_certificate_dedup
preflight_dedup = preflight_certificate_dedup
check_dedup = preflight_certificate_dedup
verify_dedup = preflight_certificate_dedup
certificate_preflight = preflight_certificate_dedup

DeduplicationPlan = DedupPlan
PreflightResult = PreflightReport
CertificateObject = CertificateMaterial


def check_certificate_objects(chains=None, plan=None, **kwargs):
    """Run only the certificate-object level check."""
    return preflight_certificate_dedup(chains, plan, **kwargs).objects


def check_chain_slots(chains=None, plan=None, **kwargs):
    """Run only the chain-position level check."""
    return preflight_certificate_dedup(chains, plan, **kwargs).slots


def _short_fingerprint(fingerprint):
    if not fingerprint:
        return None
    if fingerprint.startswith("sha256:"):
        fingerprint = fingerprint[len("sha256:"):]
    return fingerprint[:12]


def _replay_material(label):
    return CertificateMaterial(label.encode("utf-8"), type=DEFAULT_CERT_TYPE)


def replay_synthetic():
    """
    Replay two synthetic public-certificate de-duplication cases.

    The first case retains shared objects plus per-entry ordered slot
    references, so both chains (including a repeated certificate) reconstruct
    exactly.  The second case retains only the certificate set; objects remain
    recoverable but all chain positions lose their evidence, and the repeated
    occurrence is reported separately.
    """
    a = _replay_material("synthetic-public-a")
    b = _replay_material("synthetic-public-b")
    c = _replay_material("synthetic-public-c")

    visible_one = OrderedDict([
        ("alpha", [
            (a.type, a.cert),
            (b.type, b.cert),
            (a.type, a.cert),
        ]),
        ("beta", [
            (c.type, c.cert),
            (a.type, a.cert),
        ]),
    ])
    plan_one = DedupPlan(
        certificates=OrderedDict([
            ("pub-a", a.as_tuple()),
            ("pub-b", b.as_tuple()),
            ("pub-c", c.as_tuple()),
        ]),
        chains=OrderedDict([
            ("alpha", ["pub-a", "pub-b", "pub-a"]),
            ("beta", ["pub-c", "pub-a"]),
        ]),
    )
    report_one = preflight_certificate_dedup(visible_one, plan_one)

    visible_two = OrderedDict([
        ("gamma", [
            (a.type, a.cert),
            (b.type, b.cert),
            (a.type, a.cert),
        ]),
    ])
    plan_two = DedupPlan(
        certificates=OrderedDict([
            ("pub-a", a.as_tuple()),
            ("pub-b", b.as_tuple()),
        ]),
    )
    report_two = preflight_certificate_dedup(visible_two, plan_two)

    return OrderedDict([
        ("cases", [
            OrderedDict([
                ("name", "shared_objects_with_ordered_slots"),
                ("chains", visible_one),
                ("plan", plan_one),
                ("report", report_one),
                ("expected_ok", True),
            ]),
            OrderedDict([
                ("name", "certificate_set_only"),
                ("chains", visible_two),
                ("plan", plan_two),
                ("report", report_two),
                ("expected_ok", False),
                ("expected_lost_positions", [0, 1, 2]),
                ("expected_duplicate_lost_positions", [2]),
            ]),
        ]),
    ])


synthetic_replay = replay_synthetic


def _format_report(case_name, report):
    lines = []
    lines.append("%s:" % case_name)
    lines.append("  certificate objects: %s" %
                 ("OK" if report.objects_ok else "FAIL"))
    if report.objects.missing:
        for item in report.objects.missing:
            lines.append("    missing %s used by %s" % (
                _short_fingerprint(item["fingerprint"]),
                ", ".join("%s@%r" % (alias, positions)
                          for alias, positions in item["entries"].items())))
    lines.append("  chain slots: %s" % ("OK" if report.slots_ok else "FAIL"))

    for alias, entry in report.entries.items():
        if not entry.readable:
            lines.append("    %s: no readable public chain (%s)" %
                         (alias, entry.reason))
            continue
        lines.append("    %s: %s" %
                     (alias, "OK" if entry.chain_recoverable else "FAIL"))
        if entry.lost_positions:
            lines.append("      lost chain positions: %r" %
                         (entry.lost_positions,))
        for loss in entry.duplicate_losses:
            lines.append(
                "      repeated %s: expected %d, found %d; lost positions %r" %
                (_short_fingerprint(loss.fingerprint), loss.expected_count,
                 loss.actual_count, loss.lost_positions))
    return "\n".join(lines)


def _print_replay():
    replay = replay_synthetic()
    for index, case in enumerate(replay["cases"], 1):
        print("=" * 68)
        print("Synthetic replay %d: %s" % (index, case["name"]))
        print(_format_report(case["name"], case["report"]))
        print("  expected preflight result: %s" %
              ("OK" if case["expected_ok"] else "FAIL"))
    return 0


def _load_json(path):
    if path == "-":
        return json.load(sys.stdin)
    with open(path, "r") as handle:
        return json.load(handle)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Preflight a pyjks public-certificate de-duplication plan.")
    parser.add_argument("chains_file", nargs="?", metavar="CHAINS",
                        help="JSON file containing visible public chains.")
    parser.add_argument("plan_file", nargs="?", metavar="PLAN",
                        help="JSON file containing certificate objects and chain slots.")
    parser.add_argument("--chains", metavar="FILE",
                        help="Same as the CHAINS positional argument.")
    parser.add_argument("--plan", metavar="FILE",
                        help="Same as the PLAN positional argument.")
    parser.add_argument("--demo", action="store_true",
                        help="Replay the synthetic certificate-material cases.")
    parser.add_argument("--json", action="store_true",
                        help="Emit the preflight report as JSON.")
    parser.add_argument("--output", metavar="FILE",
                        help="Write the report to FILE instead of stdout.")
    args = parser.parse_args(argv)

    if args.demo:
        if args.json:
            output = json.dumps([
                {
                    "name": case["name"],
                    "report": case["report"].as_dict(),
                    "expected_ok": case["expected_ok"],
                }
                for case in replay_synthetic()["cases"]
            ], indent=2, sort_keys=True)
            if args.output:
                with open(args.output, "w") as handle:
                    handle.write(output + "\n")
            else:
                print(output)
            return 0
        return _print_replay()

    chains_path = args.chains or args.chains_file
    plan_path = args.plan or args.plan_file
    if not chains_path or not plan_path:
        parser.error("chains and plan files are required unless --demo is used")

    report = preflight_certificate_dedup(
        _load_json(chains_path), _load_json(plan_path))
    if args.json:
        output = report.to_json()
    else:
        output = _format_report("preflight", report)

    if args.output:
        with open(args.output, "w") as handle:
            handle.write(output + "\n")
    else:
        print(output)
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
