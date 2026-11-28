# coding: utf-8
"""
Correction intake on top of parsed ASN.1 public status material.

The classes in this module consume the parsed result of ``asn1crypto.ocsp``
(``OCSPResponse``, ``ResponseData`` or ``SingleResponse``) and turn each
``SingleResponse`` into a stable :class:`StatusDeclaration`.  Externally
approved corrections can then be bound to a declaration, one or more
:class:`DispositionOrder` objects and a monotonically increasing version.

The ledger is deliberately incremental and idempotent:

 - a declaration is identified by its OCSP ``CertId``, not by the batch it
   arrived in, so re-delivering a batch does not create new declarations;
 - a notification is de-duplicated by ``notice_id`` and a correction by
   ``(correction_id, version)`` plus its content signature;
 - corrections that arrive before their declaration/order are retained as
   pending and replayed once the missing material is registered;
 - an older correction delivered after a newer one is recorded as stale and
   never regresses an order;
 - one declaration may support any number of orders; correcting one order does
   not touch the others;
 - applying a correction claims exactly one :class:`SignedMaterial` per
   affected order.  Re-delivering the same correction claims nothing further.

No signatures are verified here.  Callers are expected to pass status material
that has already been verified by their transport/validation layer; the
``approval_ref`` on a correction records the external approval that authorised
the change.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import json
import binascii
from datetime import datetime

try:
    from collections.abc import Mapping
except ImportError:  # pragma: no cover - Python 2
    from collections import Mapping

from . import ocsp
from .util import OrderedDict, timezone


try:
    string_types = (basestring,)  # noqa: F821 - Python 2
except NameError:
    string_types = (str,)


__all__ = [
    'ADDED',
    'APPLIED',
    'CONFLICT',
    'DUPLICATE',
    'DUPLICATE_CORRECTION',
    'DUPLICATE_NOTICE',
    'PENDING',
    'REJECTED',
    'STALE',
    'UPDATED',
    'ApprovedCorrection',
    'BatchIngestResult',
    'CorrectionBinding',
    'CorrectionNotice',
    'DeclarationIngestResult',
    'DispositionOrder',
    'SignedMaterial',
    'StatusDeclaration',
    'StatusIntakeError',
    'StatusIntakeLedger',
    'SubmissionResult',
    'declarations_from_status_material',
    'declaration_id_for_cert_id',
]


# Ingest outcomes
ADDED = 'added'
UPDATED = 'updated'
DUPLICATE = 'duplicate'
STALE = 'stale'

# Correction submission outcomes
APPLIED = 'applied'
DUPLICATE_NOTICE = 'duplicate_notice'
DUPLICATE_CORRECTION = 'duplicate_correction'
PENDING = 'pending'
CONFLICT = 'conflict'
REJECTED = 'rejected'


class StatusIntakeError(ValueError):
    """
    Raised when status material itself is malformed or is not a successful,
    parsed OCSP status response.
    """


def _bytes_hex(value):
    hex_method = getattr(value, 'hex', None)
    if hex_method is not None:
        return hex_method()
    return binascii.hexlify(value).decode('ascii')


def _canonical(value):
    """
    Converts native asn1crypto values into a deterministic, JSON-friendly
    structure used for identity and content fingerprints.
    """

    if isinstance(value, Mapping):
        return OrderedDict(
            (key, _canonical(value[key])) for key in sorted(value.keys(), key=lambda item: _key_text(item))
        )
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, bytes):
        return 'hex:' + _bytes_hex(value)
    if isinstance(value, datetime):
        return 'datetime:' + _datetime_text(value)
    if isinstance(value, (set, frozenset)):
        items = [_canonical(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def _key_text(value):
    if isinstance(value, bytes):
        return _bytes_hex(value)
    return '%s' % value


def _fingerprint(value):
    encoded = json.dumps(_canonical(value), sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def _datetime_text(value):
    if value.tzinfo is None:
        return value.isoformat() + '+00:00'
    return value.isoformat()


def _parse_datetime(value):
    if value is None:
        return None
    value = _as_native(value)
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, string_types):
        raise StatusIntakeError('unsupported datetime value: %r' % (value,))

    text = value.strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    patterns = [
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%d %H:%M:%S.%f%z',
        '%Y-%m-%d %H:%M:%S%z',
    ]
    for pattern in patterns:
        try:
            parsed = datetime.strptime(text, pattern)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    # Python 3.7+ accepts many more ISO-8601 spellings.
    fromisoformat = getattr(datetime, 'fromisoformat', None)
    if fromisoformat is not None:
        try:
            parsed = fromisoformat(text)
        except ValueError:
            parsed = None
        if parsed is not None:
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    raise StatusIntakeError('unable to parse datetime: %r' % (value,))


def _datetime_micros(value):
    """
    Converts a datetime to an integer with microsecond resolution.  This is
    used as the declaration revision and never relies on floating point
    timestamps.
    """

    value = _parse_datetime(value)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return int(delta.days) * 86400 * 1000000 \
        + int(delta.seconds) * 1000000 \
        + int(delta.microseconds)


def _as_native(value):
    native = getattr(value, 'native', None)
    if native is not None and native is not value:
        return native
    return value


def declaration_id_for_cert_id(cert_id):
    """
    Builds the stable identity of a declaration from the parsed OCSP
    ``CertId``.  It intentionally excludes ``this_update``/``next_update`` so
    that a newer revision of the same certificate status keeps the same
    declaration identity.
    """

    return 'decl-' + _fingerprint(['ocsp-cert-id', _as_native(cert_id)])


class StatusDeclaration(object):
    """
    A verified public status statement extracted from one OCSP
    ``SingleResponse``.
    """

    def __init__(self, declaration_id, cert_id, status, this_update, next_update=None,
                 batch_id=None, source_index=None):
        self.declaration_id = declaration_id
        self.cert_id = _as_native(cert_id)
        self.status = _as_native(status)
        self.this_update = _parse_datetime(this_update)
        self.next_update = _parse_datetime(next_update) if next_update is not None else None
        self.batch_id = batch_id
        self.source_index = source_index
        self.version = _datetime_micros(self.this_update)

    @property
    def hash_algorithm(self):
        hash_algorithm = _as_native(self.cert_id).get('hash_algorithm') or {}
        return _as_native(hash_algorithm).get('algorithm')

    @property
    def serial_number(self):
        return _as_native(self.cert_id).get('serial_number')

    @property
    def issuer_name_hash(self):
        return _as_native(self.cert_id).get('issuer_name_hash')

    @property
    def issuer_key_hash(self):
        return _as_native(self.cert_id).get('issuer_key_hash')

    @property
    def content_signature(self):
        return _fingerprint([self.cert_id, self.status, self.this_update, self.next_update])

    @property
    def status_name(self):
        """
        The status choice name: ``good``, ``revoked`` or ``unknown``.  The
        ``status`` attribute retains the native revocation details for a
        revoked declaration.
        """

        status = _as_native(self.status)
        if isinstance(status, Mapping):
            return 'revoked'
        return status

    @classmethod
    def from_single_response(cls, single_response, batch_id=None, source_index=None):
        native = _as_native(single_response)
        if not isinstance(native, Mapping) or 'cert_id' not in native or 'cert_status' not in native:
            raise StatusIntakeError('expected a parsed OCSP SingleResponse, got %r' % (type(single_response),))
        cert_id = native['cert_id']
        return cls(
            declaration_id_for_cert_id(cert_id),
            cert_id,
            native['cert_status'],
            native['this_update'],
            native.get('next_update'),
            batch_id=batch_id,
            source_index=source_index
        )

    def to_dict(self):
        return OrderedDict([
            ('declaration_id', self.declaration_id),
            ('cert_id', _canonical(self.cert_id)),
            ('status', _canonical(self.status)),
            ('this_update', _datetime_text(self.this_update)),
            ('next_update', _datetime_text(self.next_update) if self.next_update is not None else None),
            ('version', self.version),
            ('batch_id', self.batch_id),
        ])

    def __repr__(self):
        return '<StatusDeclaration %s %s @ %s>' % (
            self.declaration_id[:13], self.status, _datetime_text(self.this_update)
        )


class DispositionOrder(object):
    """
    An internal business handling order.  More than one order may reference the
    same declaration.
    """

    def __init__(self, order_id, declaration_id, responsibility=None, status='open',
                 version=0, metadata=None):
        if not order_id:
            raise StatusIntakeError('order_id is required')
        if not declaration_id:
            raise StatusIntakeError('declaration_id is required')
        self.order_id = order_id
        self.declaration_id = declaration_id
        self.responsibility = responsibility
        self.status = status
        self.version = int(version)
        self.metadata = OrderedDict(metadata or {})
        self.updated_at = None

    def to_dict(self):
        return OrderedDict([
            ('order_id', self.order_id),
            ('declaration_id', self.declaration_id),
            ('responsibility', _canonical(self.responsibility)),
            ('status', self.status),
            ('version', self.version),
            ('metadata', _canonical(self.metadata)),
        ])

    def __repr__(self):
        return '<DispositionOrder %s decl=%s v%s>' % (
            self.order_id, self.declaration_id[:13], self.version
        )


class SignedMaterial(object):
    """
    A material unit that has already been signed for/received.  Applying a
    correction claims one unit per affected order; the claim is recorded on the
    correction so that a repeated delivery cannot claim a second unit.
    """

    def __init__(self, material_id, order_id, signed_at=None, metadata=None):
        if not material_id:
            raise StatusIntakeError('material_id is required')
        if not order_id:
            raise StatusIntakeError('order_id is required')
        self.material_id = material_id
        self.order_id = order_id
        self.signed_at = _parse_datetime(signed_at) if signed_at is not None else None
        self.state = 'available'
        self.claimed_by = None
        self.claimed_at = None
        self.metadata = OrderedDict(metadata or {})

    @property
    def available(self):
        return self.state == 'available'

    def to_dict(self):
        return OrderedDict([
            ('material_id', self.material_id),
            ('order_id', self.order_id),
            ('signed_at', _datetime_text(self.signed_at) if self.signed_at is not None else None),
            ('state', self.state),
            ('claimed_by', _canonical(self.claimed_by)),
        ])

    def __repr__(self):
        return '<SignedMaterial %s order=%s %s>' % (self.material_id, self.order_id, self.state)


class ApprovedCorrection(object):
    """
    An externally approved correction.  ``version`` is the external, monotonic
    revision of the correction for the targeted order(s); it is what protects
    the ledger from out-of-order delivery.
    """

    def __init__(self, correction_id, declaration_id, order_ids, version,
                 responsibility=None, approval_ref=None, effective_at=None,
                 reason=None, metadata=None):
        if not correction_id:
            raise StatusIntakeError('correction_id is required')
        if not declaration_id:
            raise StatusIntakeError('declaration_id is required')
        if isinstance(order_ids, string_types):
            order_ids = [order_ids]
        if order_ids is None:
            order_ids = []
        order_ids = tuple(order_ids)
        if not order_ids:
            raise StatusIntakeError('at least one order_id is required')
        if len(set(order_ids)) != len(order_ids):
            raise StatusIntakeError('order_ids must not contain duplicates')
        self.correction_id = correction_id
        self.declaration_id = declaration_id
        self.order_ids = order_ids
        self.version = int(version)
        if self.version < 0:
            raise StatusIntakeError('version must be zero or greater')
        self.responsibility = responsibility
        self.approval_ref = approval_ref
        self.effective_at = _parse_datetime(effective_at) if effective_at is not None else None
        self.reason = reason
        self.metadata = OrderedDict(metadata or {})

    @property
    def key(self):
        # A correction is scoped to a declaration: an external approval may
        # legitimately cover several declarations with the same local id and
        # version, but the bindings are still separate.
        return (self.correction_id, self.declaration_id, self.version)

    def content_signature(self):
        return _fingerprint([
            self.correction_id,
            self.declaration_id,
            sorted(self.order_ids),
            self.version,
            _as_native(self.responsibility),
            self.approval_ref,
            self.effective_at,
            self.reason,
        ])

    def approval_signature(self):
        """
        Fingerprint of the externally approved change without the local
        ``correction_id``.  This catches a re-delivery that regenerated its
        transport/local id while carrying the same approval content.
        """

        return _fingerprint([
            self.declaration_id,
            sorted(self.order_ids),
            self.version,
            _as_native(self.responsibility),
            self.approval_ref,
            self.effective_at,
            self.reason,
        ])

    def to_dict(self):
        return OrderedDict([
            ('correction_id', self.correction_id),
            ('declaration_id', self.declaration_id),
            ('order_ids', list(self.order_ids)),
            ('version', self.version),
            ('responsibility', _canonical(self.responsibility)),
            ('approval_ref', self.approval_ref),
            ('effective_at', _datetime_text(self.effective_at) if self.effective_at is not None else None),
            ('reason', self.reason),
        ])

    def __repr__(self):
        return '<ApprovedCorrection %s v%s orders=%s>' % (
            self.correction_id, self.version, ','.join(self.order_ids)
        )


class CorrectionNotice(object):
    """
    A transport notification carrying an approved correction.  A notice is
    de-duplicated by ``notice_id``; if no id is supplied one is derived from
    the correction content.
    """

    def __init__(self, notice_id, correction, issued_at=None, received_at=None,
                 source=None, metadata=None):
        if not isinstance(correction, ApprovedCorrection):
            raise StatusIntakeError('correction must be an ApprovedCorrection')
        self.correction = correction
        self.notice_id = notice_id or ('notice-' + _fingerprint(['notice', correction.content_signature()]))
        self.issued_at = _parse_datetime(issued_at) if issued_at is not None else None
        self.received_at = _parse_datetime(received_at) if received_at is not None else None
        self.source = source
        self.metadata = OrderedDict(metadata or {})

    def content_signature(self):
        return _fingerprint(['notice', self.correction.key, self.correction.content_signature()])

    def __repr__(self):
        return '<CorrectionNotice %s %s>' % (self.notice_id, self.correction)


class CorrectionBinding(object):
    """
    The durable result of binding a correction revision to one order.  A
    declaration may have many bindings, and each order may be advanced through
    several correction versions.
    """

    def __init__(self, correction, notice_id, order, material_id, previous_responsibility,
                 applied_at, content_signature, declaration_version=None):
        self.correction_id = correction.correction_id
        self.declaration_id = correction.declaration_id
        self.declaration_version = declaration_version
        self.order_id = order.order_id
        self.version = correction.version
        self.notice_id = notice_id
        self.approval_ref = correction.approval_ref
        self.effective_at = correction.effective_at
        self.responsibility = correction.responsibility
        self.previous_responsibility = previous_responsibility
        self.material_id = material_id
        self.applied_at = applied_at
        self.status = 'applied'
        self.superseded_by = None
        self.content_signature = content_signature

    def supersede(self, correction_id, version):
        self.status = 'superseded'
        self.superseded_by = OrderedDict([
            ('correction_id', correction_id),
            ('version', version),
        ])

    def to_dict(self):
        return OrderedDict([
            ('correction_id', self.correction_id),
            ('declaration_id', self.declaration_id),
            ('declaration_version', self.declaration_version),
            ('order_id', self.order_id),
            ('version', self.version),
            ('notice_id', self.notice_id),
            ('approval_ref', self.approval_ref),
            ('responsibility', _canonical(self.responsibility)),
            ('previous_responsibility', _canonical(self.previous_responsibility)),
            ('material_id', self.material_id),
            ('applied_at', _datetime_text(self.applied_at)),
            ('status', self.status),
            ('superseded_by', _canonical(self.superseded_by)),
        ])

    def __repr__(self):
        return '<CorrectionBinding %s v%s order=%s %s>' % (
            self.correction_id, self.version, self.order_id, self.status
        )


class _ResultBase(object):
    def __init__(self, outcome, reason=None):
        self.outcome = outcome
        self.reason = reason

    @property
    def accepted(self):
        return self.outcome in (ADDED, UPDATED, APPLIED)

    def to_dict(self):
        return OrderedDict([
            ('outcome', self.outcome),
            ('reason', self.reason),
        ])

    def __repr__(self):
        return '<%s %s%s>' % (
            self.__class__.__name__,
            self.outcome,
            ' (%s)' % self.reason if self.reason else ''
        )


class DeclarationIngestResult(_ResultBase):
    def __init__(self, outcome, declaration, previous=None, reason=None):
        _ResultBase.__init__(self, outcome, reason)
        self.declaration = declaration
        self.previous = previous


class BatchIngestResult(_ResultBase):
    def __init__(self, batch_id, declarations, results):
        counts = OrderedDict([
            (ADDED, 0),
            (UPDATED, 0),
            (DUPLICATE, 0),
            (STALE, 0),
            ('conflict', 0),
        ])
        for result in results:
            counts[result.outcome] = counts.get(result.outcome, 0) + 1
        outcome = APPLIED if counts[ADDED] or counts[UPDATED] else DUPLICATE
        _ResultBase.__init__(self, outcome)
        self.batch_id = batch_id
        self.declarations = declarations
        self.results = results
        self.counts = counts

    def to_dict(self):
        return OrderedDict([
            ('batch_id', self.batch_id),
            ('outcome', self.outcome),
            ('counts', self.counts),
            ('declarations', [item.declaration_id for item in self.declarations]),
        ])


class SubmissionResult(_ResultBase):
    def __init__(self, outcome, notice=None, reason=None, bindings=None,
                 applied_orders=None, skipped_orders=None, consumed_materials=None,
                 duplicate=False):
        _ResultBase.__init__(self, outcome, reason)
        self.notice = notice
        self.bindings = list(bindings or [])
        self.applied_orders = list(applied_orders or [])
        self.skipped_orders = OrderedDict(skipped_orders or {})
        self.consumed_materials = list(consumed_materials or [])
        self.duplicate = duplicate

    @property
    def correction_id(self):
        return self.notice.correction.correction_id if self.notice is not None else None

    @property
    def version(self):
        return self.notice.correction.version if self.notice is not None else None

    def to_dict(self):
        return OrderedDict([
            ('outcome', self.outcome),
            ('reason', self.reason),
            ('correction_id', self.correction_id),
            ('version', self.version),
            ('applied_orders', self.applied_orders),
            ('skipped_orders', self.skipped_orders),
            ('consumed_materials', self.consumed_materials),
            ('duplicate', self.duplicate),
            ('bindings', [binding.to_dict() for binding in self.bindings]),
        ])


def _single_responses_from_material(material):
    """
    Yields native ``SingleResponse`` mappings from parsed OCSP objects or from
    a native mapping/list.  Both a full ``OCSPResponse`` and the already
    unwrapped ``ResponseData`` are accepted.
    """

    if material is None:
        raise StatusIntakeError('status material is required')

    if isinstance(material, ocsp.OCSPResponse):
        status = material['response_status'].native
        if status != 'successful':
            raise StatusIntakeError('OCSP response status is %s, not successful' % status)
        responses = material.response_data['responses']
        for item in responses:
            yield _as_native(item)
        return

    if isinstance(material, ocsp.BasicOCSPResponse):
        for item in material['tbs_response_data']['responses']:
            yield _as_native(item)
        return

    if isinstance(material, ocsp.ResponseData):
        for item in material['responses']:
            yield _as_native(item)
        return

    if isinstance(material, ocsp.SingleResponse):
        yield _as_native(material)
        return

    if isinstance(material, (list, tuple)):
        for item in material:
            for response in _single_responses_from_material(item):
                yield response
        return

    native = _as_native(material)
    if isinstance(native, Mapping):
        if 'responses' in native:
            for item in native['responses']:
                for response in _single_responses_from_material(item):
                    yield response
            return
        if 'tbs_response_data' in native:
            for response in _single_responses_from_material(native['tbs_response_data']):
                yield response
            return
        if 'cert_id' in native and 'cert_status' in native:
            yield native
            return
        if 'response_status' in native:
            status = native['response_status']
            if status != 'successful':
                raise StatusIntakeError('OCSP response status is %s, not successful' % status)
            response_bytes = native.get('response_bytes') or {}
            response = response_bytes.get('response')
            if response is None:
                raise StatusIntakeError('OCSP response_bytes does not contain a response')
            for item in _single_responses_from_material(response):
                yield item
            return

    raise StatusIntakeError('unsupported status material: %r' % (type(material),))


def declarations_from_status_material(material, batch_id=None):
    """
    Parses already-verified OCSP status material into a list of
    :class:`StatusDeclaration` objects.  No cryptographic verification is
    performed.

    :param material:
        A parsed ``ocsp.OCSPResponse``, ``ocsp.BasicOCSPResponse``,
        ``ocsp.ResponseData``, a ``SingleResponse``, a list of any of these, or
        an equivalent native mapping.

    :param batch_id:
        An optional identifier recorded on each declaration.

    :return:
        A list of StatusDeclaration objects, in material order.
    """

    declarations = []
    for index, response in enumerate(_single_responses_from_material(material)):
        declarations.append(StatusDeclaration.from_single_response(
            response,
            batch_id=batch_id,
            source_index=index
        ))
    return declarations


class _NoticeRecord(object):
    def __init__(self, notice, result):
        self.notice = notice
        self.result = result


class _CorrectionRecord(object):
    def __init__(self, signature, outcome, notice_id, bindings=None):
        self.signature = signature
        self.outcome = outcome
        self.notice_id = notice_id
        self.bindings = list(bindings or [])


class StatusIntakeLedger(object):
    """
    Incremental ledger that binds approved corrections to declarations, orders
    and versions.  The ledger never rebuilds the whole day's receipts when one
    correction is applied.
    """

    def __init__(self, clock=None):
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.declarations = OrderedDict()
        self.declaration_history = OrderedDict()
        self.orders = OrderedDict()
        self.materials = OrderedDict()
        self.bindings = []
        self.notices = OrderedDict()

        self._current_bindings = {}
        self._correction_records = {}
        self._approval_records = {}
        self._material_claims = {}
        self._pending = []
        self._pending_by_notice = {}
        self._draining = False

    # ------------------------------------------------------------------
    # Declaration / order / material registration
    # ------------------------------------------------------------------

    def add_declaration(self, declaration, batch_id=None):
        if not isinstance(declaration, StatusDeclaration):
            declaration = StatusDeclaration.from_single_response(declaration, batch_id=batch_id)
        elif batch_id is not None and declaration.batch_id is None:
            declaration.batch_id = batch_id

        existing = self.declarations.get(declaration.declaration_id)
        if existing is None:
            self.declarations[declaration.declaration_id] = declaration
            self.declaration_history[declaration.declaration_id] = [declaration]
            result = DeclarationIngestResult(ADDED, declaration)
        elif declaration.version > existing.version:
            self.declarations[declaration.declaration_id] = declaration
            self.declaration_history[declaration.declaration_id].append(declaration)
            result = DeclarationIngestResult(UPDATED, declaration, previous=existing)
        elif declaration.version == existing.version:
            if declaration.content_signature == existing.content_signature:
                result = DeclarationIngestResult(DUPLICATE, existing, previous=existing)
            else:
                result = DeclarationIngestResult(
                    CONFLICT,
                    existing,
                    previous=existing,
                    reason='same declaration revision has different content'
                )
        else:
            result = DeclarationIngestResult(
                STALE,
                existing,
                previous=existing,
                reason='a newer declaration revision is already registered'
            )

        if result.outcome in (ADDED, UPDATED):
            self._drain_pending()
        return result

    def ingest_batch(self, batch_id, material):
        declarations = declarations_from_status_material(material, batch_id=batch_id)
        results = [self.add_declaration(item, batch_id=batch_id) for item in declarations]
        return BatchIngestResult(batch_id, declarations, results)

    def add_order(self, order, declaration_id=None, responsibility=None, status='open', metadata=None):
        if not isinstance(order, DispositionOrder):
            order = DispositionOrder(
                order,
                declaration_id,
                responsibility=responsibility,
                status=status,
                metadata=metadata
            )
        existing = self.orders.get(order.order_id)
        if existing is not None:
            if existing.declaration_id != order.declaration_id:
                raise StatusIntakeError(
                    'order %s is already bound to declaration %s' %
                    (order.order_id, existing.declaration_id)
                )
            return existing
        self.orders[order.order_id] = order
        self._drain_pending()
        return order

    def add_material(self, material, order_id=None, signed_at=None, metadata=None):
        if not isinstance(material, SignedMaterial):
            material = SignedMaterial(material, order_id, signed_at=signed_at, metadata=metadata)
        existing = self.materials.get(material.material_id)
        if existing is not None:
            if existing.order_id != material.order_id:
                raise StatusIntakeError(
                    'material %s is already registered for order %s' %
                    (material.material_id, existing.order_id)
                )
            return existing
        if material.order_id not in self.orders:
            raise StatusIntakeError('material %s references unknown order %s' % (
                material.material_id, material.order_id
            ))
        self.materials[material.material_id] = material
        self._drain_pending()
        return material

    def add_materials(self, order_id, material_ids, signed_at=None):
        return [self.add_material(item, order_id=order_id, signed_at=signed_at) for item in material_ids]

    # ------------------------------------------------------------------
    # Correction submission
    # ------------------------------------------------------------------

    def submit(self, notice):
        """
        Submits one correction notice.  The call is safe to retry: duplicate
        notices and duplicate correction deliveries never claim additional
        signed material.
        """

        if isinstance(notice, ApprovedCorrection):
            notice = CorrectionNotice(None, notice)
        if not isinstance(notice, CorrectionNotice):
            raise StatusIntakeError('expected an ApprovedCorrection or CorrectionNotice')

        processed = self.notices.get(notice.notice_id)
        if processed is not None:
            if processed.notice.content_signature() != notice.content_signature():
                return SubmissionResult(
                    CONFLICT,
                    notice=notice,
                    reason='notice_id %s was reused with different content' % notice.notice_id
                )
            prior = processed.result
            return SubmissionResult(
                DUPLICATE_NOTICE,
                notice=notice,
                reason='notification %s was already processed' % notice.notice_id,
                bindings=prior.bindings,
                applied_orders=prior.applied_orders,
                skipped_orders=prior.skipped_orders,
                duplicate=True
            )

        pending = self._pending_by_notice.get(notice.notice_id)
        if pending is not None:
            if pending.content_signature() != notice.content_signature():
                return SubmissionResult(
                    CONFLICT,
                    notice=notice,
                    reason='pending notice_id %s was reused with different content' % notice.notice_id
                )
            return SubmissionResult(
                PENDING,
                notice=notice,
                reason='notification %s is already pending prerequisite material' % notice.notice_id,
                duplicate=True
            )

        result = self._process(notice)
        if result.outcome == PENDING:
            self._pending.append(notice)
            self._pending_by_notice[notice.notice_id] = notice
        else:
            self.notices[notice.notice_id] = _NoticeRecord(notice, result)
        return result

    submit_correction = submit

    def _process(self, notice):
        correction = notice.correction
        key = correction.key
        signature = correction.content_signature()
        approval_signature = correction.approval_signature()

        previous = self._correction_records.get(key)
        if previous is not None:
            if previous.signature != signature:
                return SubmissionResult(
                    CONFLICT,
                    notice=notice,
                    reason='correction %s for declaration %s version %s was reused with different content' % key
                )
            current_versions = self._current_versions(correction)
            if any(version > correction.version for version in current_versions):
                return SubmissionResult(
                    STALE,
                    notice=notice,
                    reason='a newer version is already applied for at least one order',
                    duplicate=True
                )
            return SubmissionResult(
                DUPLICATE_CORRECTION,
                notice=notice,
                reason='correction revision was already applied',
                bindings=previous.bindings,
                duplicate=True
            )

        already_approved = self._approval_records.get(approval_signature)
        if already_approved is not None:
            current_versions = self._current_versions(correction)
            if any(version > correction.version for version in current_versions):
                outcome = STALE
                reason = 'a newer version is already applied for at least one order'
            else:
                outcome = DUPLICATE_CORRECTION
                reason = 'the same externally approved correction content was already applied'
            self._correction_records[key] = _CorrectionRecord(
                signature, outcome, notice.notice_id, already_approved.bindings
            )
            return SubmissionResult(
                outcome,
                notice=notice,
                reason=reason,
                bindings=already_approved.bindings,
                duplicate=True
            )

        evaluation = self._evaluate(correction)
        if evaluation['outcome'] == PENDING:
            return SubmissionResult(PENDING, notice=notice, reason=evaluation['reason'])
        if evaluation['outcome'] == REJECTED:
            return SubmissionResult(REJECTED, notice=notice, reason=evaluation['reason'])
        if evaluation['outcome'] == CONFLICT:
            return SubmissionResult(CONFLICT, notice=notice, reason=evaluation['reason'])
        if evaluation['outcome'] == STALE:
            record = _CorrectionRecord(signature, STALE, notice.notice_id)
            self._correction_records[key] = record
            self._approval_records[approval_signature] = record
            return SubmissionResult(STALE, notice=notice, reason=evaluation['reason'], duplicate=True)
        if evaluation['outcome'] == DUPLICATE_CORRECTION:
            record = _CorrectionRecord(signature, DUPLICATE_CORRECTION, notice.notice_id)
            self._correction_records[key] = record
            self._approval_records[approval_signature] = record
            return SubmissionResult(
                DUPLICATE_CORRECTION,
                notice=notice,
                reason=evaluation['reason'],
                duplicate=True
            )

        result = self._apply(notice, evaluation['actions'])
        self._correction_records[key] = _CorrectionRecord(
            signature, result.outcome, notice.notice_id, result.bindings
        )
        self._approval_records[approval_signature] = self._correction_records[key]
        return result

    def _current_versions(self, correction):
        versions = []
        for order_id in correction.order_ids:
            binding = self._current_bindings.get((correction.declaration_id, order_id))
            if binding is not None:
                versions.append(binding.version)
        return versions

    def _evaluate(self, correction):
        if correction.declaration_id not in self.declarations:
            return {
                'outcome': PENDING,
                'reason': 'declaration %s is not registered yet' % correction.declaration_id,
            }

        missing_orders = [
            order_id for order_id in correction.order_ids if order_id not in self.orders
        ]
        if missing_orders:
            return {
                'outcome': PENDING,
                'reason': 'orders are not registered yet: %s' % ', '.join(missing_orders),
            }

        mismatched = [
            order_id for order_id in correction.order_ids
            if self.orders[order_id].declaration_id != correction.declaration_id
        ]
        if mismatched:
            return {
                'outcome': REJECTED,
                'reason': 'orders do not belong to declaration %s: %s' % (
                    correction.declaration_id, ', '.join(mismatched)
                ),
            }

        actions = OrderedDict()
        signature = correction.content_signature()
        for order_id in correction.order_ids:
            current = self._current_bindings.get((correction.declaration_id, order_id))
            if current is None:
                actions[order_id] = 'apply'
            elif correction.version > current.version:
                actions[order_id] = 'apply'
            elif correction.version == current.version:
                if signature == current.content_signature:
                    actions[order_id] = 'duplicate'
                else:
                    actions[order_id] = 'conflict'
            else:
                actions[order_id] = 'stale'

        if 'conflict' in actions.values():
            return {
                'outcome': CONFLICT,
                'reason': 'the same correction version already exists with different content',
            }

        apply_orders = [order_id for order_id, action in actions.items() if action == 'apply']
        if not apply_orders:
            if all(action == 'stale' for action in actions.values()):
                return {
                    'outcome': STALE,
                    'reason': 'a newer correction version is already applied',
                }
            return {
                'outcome': DUPLICATE_CORRECTION,
                'reason': 'correction revision is already applied',
            }

        for order_id in apply_orders:
            if not self._has_material_for(correction, order_id):
                return {
                    'outcome': PENDING,
                    'reason': 'no signed material is available for order %s' % order_id,
                }

        return {'outcome': APPLIED, 'actions': actions}

    def _claim_key(self, correction, order_id):
        return (correction.correction_id, correction.version, order_id)

    def _has_material_for(self, correction, order_id):
        if self._claim_key(correction, order_id) in self._material_claims:
            return True
        return any(material.available for material in self.materials.values() if material.order_id == order_id)

    def _claim_material(self, correction, order_id):
        claim_key = self._claim_key(correction, order_id)
        existing = self._material_claims.get(claim_key)
        if existing is not None:
            return existing

        candidates = [
            material for material in self.materials.values()
            if material.order_id == order_id and material.available
        ]
        if not candidates:
            raise StatusIntakeError('no signed material available for order %s' % order_id)
        candidates.sort(key=lambda item: (
            item.signed_at is None,
            item.signed_at or datetime(1970, 1, 1, tzinfo=timezone.utc),
            item.material_id
        ))
        material = candidates[0]
        material.state = 'claimed'
        material.claimed_by = OrderedDict([
            ('correction_id', correction.correction_id),
            ('version', correction.version),
        ])
        material.claimed_at = self._clock()
        self._material_claims[claim_key] = material.material_id
        return material.material_id

    def _apply(self, notice, actions):
        correction = notice.correction
        applied_at = self._clock()
        apply_orders = [order_id for order_id, action in actions.items() if action == 'apply']

        # Claim all material first so a shortfall cannot leave a partially
        # applied correction behind.
        claims = OrderedDict()
        for order_id in apply_orders:
            claims[order_id] = self._claim_material(correction, order_id)

        bindings = []
        signature = correction.content_signature()
        for order_id in apply_orders:
            order = self.orders[order_id]
            previous = self._current_bindings.get((correction.declaration_id, order_id))
            previous_responsibility = order.responsibility

            if previous is not None:
                previous.supersede(correction.correction_id, correction.version)

            if correction.responsibility is not None:
                order.responsibility = correction.responsibility
            order.version = order.version + 1
            order.updated_at = applied_at

            binding = CorrectionBinding(
                correction,
                notice.notice_id,
                order,
                claims[order_id],
                previous_responsibility,
                applied_at,
                signature,
                declaration_version=self.declarations[correction.declaration_id].version,
            )
            self.bindings.append(binding)
            self._current_bindings[(correction.declaration_id, order_id)] = binding
            bindings.append(binding)

        skipped = OrderedDict(
            (order_id, action) for order_id, action in actions.items() if action != 'apply'
        )
        return SubmissionResult(
            APPLIED,
            notice=notice,
            bindings=bindings,
            applied_orders=apply_orders,
            skipped_orders=skipped,
            consumed_materials=[claims[order_id] for order_id in apply_orders]
        )

    def _drain_pending(self):
        if self._draining or not self._pending:
            return
        self._draining = True
        try:
            while self._pending:
                pending = sorted(self._pending, key=self._pending_sort_key)
                self._pending = []
                self._pending_by_notice = {}
                progressed = False
                for notice in pending:
                    result = self._process(notice)
                    if result.outcome == PENDING:
                        self._pending.append(notice)
                        self._pending_by_notice[notice.notice_id] = notice
                    else:
                        self.notices[notice.notice_id] = _NoticeRecord(notice, result)
                        progressed = True
                if not progressed:
                    break
        finally:
            self._draining = False

    def _pending_sort_key(self, notice):
        issued = notice.issued_at or datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (notice.correction.version, issued, notice.notice_id)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def current_binding(self, declaration_id, order_id):
        return self._current_bindings.get((declaration_id, order_id))

    def bindings_for_declaration(self, declaration_id):
        return [binding for binding in self.bindings if binding.declaration_id == declaration_id]

    def bindings_for_order(self, order_id):
        return [binding for binding in self.bindings if binding.order_id == order_id]

    def pending_notices(self):
        return list(self._pending)

    def available_material_count(self, order_id):
        return len([
            material for material in self.materials.values()
            if material.order_id == order_id and material.available
        ])

    def inventory_snapshot(self, order_id):
        items = [material for material in self.materials.values() if material.order_id == order_id]
        return OrderedDict([
            ('order_id', order_id),
            ('total', len(items)),
            ('available', len([item for item in items if item.available])),
            ('claimed', len([item for item in items if item.state == 'claimed'])),
        ])
