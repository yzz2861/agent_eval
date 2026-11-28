# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import date, datetime

from asn1crypto.util import timezone

from ._errors import pretty_message
from ._types import byte_cls, str_cls, type_name
from .path import ValidationPath


# Review states used by FreezeReviewItem
REVIEW = 'review'
DEFERRED = 'deferred'
MISSING_MATERIALS = 'missing_materials'

# Short aliases for callers that prefer the category names
DEFER = DEFERRED
MISSING = MISSING_MATERIALS


__all__ = [
    'REVIEW',
    'DEFERRED',
    'MISSING_MATERIALS',
    'DEFER',
    'MISSING',
    'Evidence',
    'Freeze',
    'AlternativeEvidence',
    'ReviewProject',
    'FreezeReviewItem',
    'FreezeReviewPlan',
    'FreezeReviewError',
    'project_from_validation_path',
    'project_from_validator',
    'review_freeze_impact',
    'review_validators',
    'build_freeze_review_plan',
    'freeze_impact_review',
]


# Sorts projects without a service order after every project that has one
_UNRANKED = 10 ** 9


_MAX_DATETIME = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


class FreezeReviewError(Exception):

    pass


def _coerce_evidence(value):
    """
    :param value:
        A unicode/byte string, or an Evidence object

    :return:
        A unicode string identifying the evidence
    """

    if isinstance(value, Evidence):
        return value.key
    if isinstance(value, byte_cls):
        return value.decode('utf-8')
    if isinstance(value, str_cls):
        return value
    if hasattr(value, 'key'):
        return _coerce_evidence(value.key)
    raise TypeError(pretty_message(
        '''
        evidence must be a unicode string or an Evidence object, not %s
        ''',
        type_name(value)
    ))


def _evidence_collection(value):
    """
    :param value:
        None, a single evidence identifier, or an iterable of them

    :return:
        A list of evidence identifiers
    """

    if value is None:
        return []
    if isinstance(value, Freeze):
        return list(value.evidence)
    if isinstance(value, (str_cls, byte_cls, Evidence)) or hasattr(value, 'key'):
        return [value]
    return list(value)


def _project_collection(value):
    """
    :param value:
        A single project/certificate validator or an iterable of them

    :return:
        A list of project-like values
    """

    if value is None:
        return []
    if isinstance(value, (ReviewProject, dict, ValidationPath)) \
            or hasattr(value, '_validate_path'):
        return [value]
    return list(value)


def _coerce_datetime(value, name='date'):
    """
    :param value:
        None, a date, a datetime, or an ISO-8601-ish string

    :param name:
        The parameter name to use in error messages

    :return:
        None or a timezone-aware datetime.datetime object in UTC
    """

    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime(value.year, value.month, value.day)
    elif isinstance(value, (str_cls, byte_cls)):
        raw = value.decode('utf-8') if isinstance(value, byte_cls) else value
        raw = raw.strip()
        if raw.endswith('Z'):
            raw = raw[:-1] + '+0000'
        formats = [
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%d %H:%M:%S%z',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d',
        ]
        parsed = None
        for format_string in formats:
            try:
                parsed = datetime.strptime(raw, format_string)
                break
            except ValueError:
                continue
        if parsed is None:
            raise FreezeReviewError(pretty_message(
                '''
                %s must be a date, datetime or ISO-8601 string, not %s
                ''',
                name,
                value
            ))
    else:
        raise TypeError(pretty_message(
            '''
            %s must be a date, datetime or ISO-8601 string, not %s
            ''',
            name,
            type_name(value)
        ))

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _datetime_key(value):
    """
    :param value:
        None or a timezone-aware datetime

    :return:
        A datetime usable as a sort key, with None sorting last
    """

    return _MAX_DATETIME if value is None else value


def _format_datetime(value):
    if value is None:
        return None
    return value.isoformat()


def _coerce_int(value, name='service_order'):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise TypeError(pretty_message(
            '''
            %s must be an integer, not %s
            ''',
            name,
            type_name(value)
        ))


class Evidence(object):
    """
    Identifies a piece of issuance evidence that may be frozen, such as an
    issuer certificate, a cross-sign, a CRL or an OCSP response.
    """

    def __init__(self, key, kind=None):
        """
        :param key:
            A unicode string uniquely identifying the evidence

        :param kind:
            None or a unicode string describing the evidence type
        """

        self.key = _coerce_evidence(key)
        self.kind = kind

    def __repr__(self):
        return 'Evidence(%r)' % self.key


class Freeze(object):
    """
    A temporary freeze on an external certificate batch. The batch is
    identified by the issuance evidence it supplied; local certificate
    validation is not affected by the freeze.
    """

    def __init__(self, evidence, batch=None, frozen_until=None, reason=None):
        """
        :param evidence:
            An evidence identifier or iterable of identifiers in the batch

        :param batch:
            None or a unicode string identifying the external batch

        :param frozen_until:
            None, a date, datetime or ISO-8601 string for when the temporary
            freeze is expected to end

        :param reason:
            None or a unicode string recording why the batch is frozen
        """

        self.evidence = tuple(sorted(set(
            _coerce_evidence(item) for item in _evidence_collection(evidence)
        )))
        self.batch = batch
        self.frozen_until = _coerce_datetime(frozen_until, 'frozen_until')
        self.reason = reason

    def __repr__(self):
        return 'Freeze(%r)' % (self.batch or ', '.join(self.evidence))


class AlternativeEvidence(object):
    """
    An alternate path or document set that avoids a frozen item. When it is a
    complete replacement, or explicitly covers every frozen item a project
    uses, the project may be split out of the urgent review queue.
    """

    def __init__(self, key, covers=None, evidence=None, complete=True,
                 valid_from=None, valid_until=None, reason=None):
        """
        :param key:
            A unicode string uniquely identifying the alternative

        :param covers:
            None, or an iterable of frozen evidence keys the alternative
            explicitly replaces. Only needed when complete is False.

        :param evidence:
            None, or an iterable of evidence keys used by the alternative
            path. None of these may be frozen for the alternative to be usable.

        :param complete:
            A bool - if the alternative is a complete path replacement. A
            complete alternative avoids the frozen path entirely, so it does
            not need to enumerate the frozen keys it replaces.

        :param valid_from:
            None, a date, datetime or ISO-8601 string for when the alternative
            starts to belong to the project

        :param valid_until:
            None, a date, datetime or ISO-8601 string for when the alternative
            stops belonging to the project

        :param reason:
            None or a unicode string recording why splitting is permitted
        """

        self.key = _coerce_evidence(key)
        if covers is None:
            self.covers = None
        else:
            self.covers = frozenset(
                _coerce_evidence(item) for item in _evidence_collection(covers)
            )
        if evidence is None:
            self.evidence = frozenset()
        else:
            self.evidence = frozenset(
                _coerce_evidence(item) for item in _evidence_collection(evidence)
            )
        self.complete = bool(complete)
        self.valid_from = _coerce_datetime(valid_from, 'valid_from')
        self.valid_until = _coerce_datetime(valid_until, 'valid_until')
        self.reason = reason

    @classmethod
    def from_dict(cls, value):
        covers = value.get('covers', value.get('covers_evidence', value.get('replaces')))
        evidence = value.get(
            'evidence',
            value.get('path_evidence', value.get('uses'))
        )
        return cls(
            value.get('key', value.get('id', value.get('name'))),
            covers=covers,
            evidence=evidence,
            complete=value.get('complete', True),
            valid_from=value.get(
                'valid_from',
                value.get('not_before', value.get('from', value.get('start')))
            ),
            valid_until=value.get(
                'valid_until',
                value.get('not_after', value.get('until', value.get('end')))
            ),
            reason=value.get('reason', value.get('split_reason'))
        )

    def __repr__(self):
        return 'AlternativeEvidence(%r)' % self.key


class ReviewProject(object):
    """
    A release item whose certificate path is already locally valid, but which
    may depend on issuance evidence from a temporarily frozen external batch.
    """

    def __init__(self, name, service_order=None, valid_from=None, valid_until=None,
                 evidence=None, materials=None, required_materials=None,
                 alternatives=None):
        """
        :param name:
            A unicode string uniquely identifying the project

        :param service_order:
            None or an integer used as the final tie-breaker when two projects
            have the same validity end and shared-evidence priority

        :param valid_from:
            None, a date, datetime or ISO-8601 string for the start of the
            project's certificate validity period

        :param valid_until:
            None, a date, datetime or ISO-8601 string for the end of the
            project's certificate validity period

        :param evidence:
            An iterable of evidence keys used by the project's current path

        :param materials:
            An iterable of material names already available for review

        :param required_materials:
            An iterable of material names required before review can start

        :param alternatives:
            An iterable of AlternativeEvidence objects or dicts
        """

        if not isinstance(name, (str_cls, byte_cls)):
            raise TypeError(pretty_message(
                '''
                name must be a unicode string, not %s
                ''',
                type_name(name)
            ))
        if isinstance(name, byte_cls):
            name = name.decode('utf-8')
        if not name:
            raise FreezeReviewError('name must not be an empty string')

        self.name = name
        self.service_order = _coerce_int(service_order)
        self.valid_from = _coerce_datetime(valid_from, 'valid_from')
        self.valid_until = _coerce_datetime(valid_until, 'valid_until')
        self.evidence = tuple(sorted(set(
            _coerce_evidence(item) for item in _evidence_collection(evidence)
        )))
        self.materials = frozenset(
            _coerce_evidence(item) for item in _evidence_collection(materials)
        )
        self.required_materials = frozenset(
            _coerce_evidence(item) for item in _evidence_collection(required_materials)
        )

        coerced_alternatives = []
        if alternatives is None:
            alternatives = []
        elif isinstance(alternatives, (AlternativeEvidence, dict)):
            alternatives = [alternatives]
        for alternative in alternatives:
            if isinstance(alternative, dict):
                alternative = AlternativeEvidence.from_dict(alternative)
            elif not isinstance(alternative, AlternativeEvidence):
                raise TypeError(pretty_message(
                    '''
                    alternatives must contain AlternativeEvidence objects or
                    dicts, not %s
                    ''',
                    type_name(alternative)
                ))
            coerced_alternatives.append(alternative)
        self.alternatives = tuple(sorted(coerced_alternatives, key=lambda item: item.key))

    @classmethod
    def from_dict(cls, value):
        """
        Builds a ReviewProject from a plain dict, accepting a few common
        aliases so callers can feed release-tracking records directly.
        """

        validity = value.get('validity') or {}
        if not isinstance(validity, dict):
            validity = {}
        return cls(
            value.get(
                'name',
                value.get('id', value.get('project', value.get('project_id')))
            ),
            service_order=value.get(
                'service_order',
                value.get('service', value.get('service_rank', value.get('order')))
            ),
            valid_from=value.get(
                'valid_from',
                value.get('not_before', value.get(
                    'from',
                    validity.get('from', validity.get('not_before'))
                ))
            ),
            valid_until=value.get(
                'valid_until',
                value.get('not_after', value.get(
                    'expires',
                    validity.get('until', validity.get('not_after'))
                ))
            ),
            evidence=value.get(
                'evidence',
                value.get(
                    'issuance_evidence',
                    value.get('shared_evidence', value.get('evidence_keys'))
                )
            ),
            materials=value.get(
                'materials',
                value.get('available_materials', value.get('documents'))
            ),
            required_materials=value.get('required_materials', value.get('required')),
            alternatives=value.get(
                'alternatives',
                value.get('alternative_evidence', value.get('alternates'))
            )
        )

    def missing_materials(self):
        """
        :return:
            A sorted list of required material names that were not provided
        """

        return sorted(self.required_materials - self.materials)

    def __repr__(self):
        return 'ReviewProject(%r)' % self.name


def project_from_validation_path(path, name=None, service_order=None,
                                 materials=None, required_materials=None,
                                 alternatives=None, evidence=None):
    """
    Builds a ReviewProject from an already-validated ValidationPath. Issuer
    certificates in the path become the project's issuance evidence, which is
    how two different leaf certificates can be recognized as sharing a frozen
    intermediate or root.

    :param path:
        A certvalidator.path.ValidationPath object

    :param name:
        None to derive a name from the end-entity certificate subject

    :return:
        A ReviewProject object
    """

    certs = list(path)
    if not certs:
        raise FreezeReviewError('path must contain at least one certificate')

    leaf = certs[-1]
    if name is None:
        subject = leaf.subject.native
        name = subject.get('common_name') or leaf.subject.human_friendly
    if evidence is None:
        evidence = [cert.sha256_fingerprint for cert in certs[:-1]]

    return ReviewProject(
        name,
        service_order=service_order,
        valid_from=leaf.not_valid_before,
        valid_until=leaf.not_valid_after,
        evidence=evidence,
        materials=materials,
        required_materials=required_materials,
        alternatives=alternatives
    )


def project_from_validator(validator, name=None, service_order=None, materials=None,
                           required_materials=None, alternatives=None, evidence=None):
    """
    Validates a CertificateValidator's path locally, then builds a
    ReviewProject from it. The local result is intentionally not changed: a
    frozen batch affects release ordering, not signature/path validity.
    """

    validator._validate_path()
    return project_from_validation_path(
        validator._path,
        name=name,
        service_order=service_order,
        materials=materials,
        required_materials=required_materials,
        alternatives=alternatives,
        evidence=evidence
    )


def _coerce_project(value):
    if isinstance(value, ReviewProject):
        return value
    if isinstance(value, dict):
        return ReviewProject.from_dict(value)
    if isinstance(value, ValidationPath):
        return project_from_validation_path(value)
    if hasattr(value, '_validate_path'):
        return project_from_validator(value)
    raise TypeError(pretty_message(
        '''
        projects must contain ReviewProject objects, dicts or
        CertificateValidator objects, not %s
        ''',
        type_name(value)
    ))


def _service_ranks(projects, service_order):
    """
    :param projects:
        A list of ReviewProject objects

    :param service_order:
        None, a list of project names in service order, or a dict of project
        name to integer rank

    :return:
        A dict of project name to integer rank
    """

    ranks = {}
    if service_order is not None:
        if isinstance(service_order, dict):
            for name, rank in service_order.items():
                rank = _coerce_int(rank)
                ranks[_coerce_evidence(name)] = _UNRANKED if rank is None else rank
        else:
            if isinstance(service_order, (str_cls, byte_cls)):
                service_order = [service_order]
            for index, name in enumerate(service_order):
                ranks[_coerce_evidence(name)] = index

    for project in projects:
        if project.name in ranks:
            continue
        if project.service_order is None:
            ranks[project.name] = _UNRANKED
        else:
            ranks[project.name] = project.service_order
    return ranks


class FreezeReviewItem(object):
    """
    The review disposition for one project affected by frozen evidence.
    """

    def __init__(self, project, status, affected_evidence, shared_evidence,
                 peers, service_rank, alternative=None, missing_materials=None,
                 moment=None):
        self.project = project
        self.status = status
        self.affected_evidence = tuple(sorted(affected_evidence))
        self.shared_evidence = tuple(sorted(shared_evidence))
        self.peers = tuple(sorted(peers))
        self.service_rank = service_rank
        self.alternative = alternative
        self.missing_materials = tuple(sorted(missing_materials or []))
        self.order = None
        self.review_position = None

        self.split_allowed = alternative is not None
        self.split_reason = None
        self.alternative_valid_from = None
        self.alternative_valid_until = None
        self.defer_until = None

        if alternative is not None:
            self.alternative_valid_from = alternative.valid_from
            self.alternative_valid_until = alternative.valid_until
            if alternative.reason:
                self.split_reason = alternative.reason
            elif alternative.complete:
                self.split_reason = (
                    'alternative evidence %s provides a complete path that avoids frozen evidence %s'
                    % (
                        alternative.key,
                        ', '.join(sorted(affected_evidence))
                    )
                )
            else:
                self.split_reason = (
                    'alternative evidence %s explicitly covers frozen evidence %s'
                    % (
                        alternative.key,
                        ', '.join(sorted(affected_evidence))
                    )
                )
            if alternative.valid_from is not None and moment is not None \
                    and alternative.valid_from > moment:
                self.defer_until = alternative.valid_from
            else:
                self.defer_until = alternative.valid_until

    @property
    def name(self):
        return self.project.name

    @property
    def is_review(self):
        return self.status == REVIEW

    @property
    def is_deferred(self):
        return self.status == DEFERRED

    @property
    def is_missing_materials(self):
        return self.status == MISSING_MATERIALS

    def to_dict(self):
        return {
            'name': self.name,
            'status': self.status,
            'order': self.order,
            'review_position': self.review_position,
            'valid_from': _format_datetime(self.project.valid_from),
            'valid_until': _format_datetime(self.project.valid_until),
            'affected_evidence': list(self.affected_evidence),
            'shared_evidence': list(self.shared_evidence),
            'peers': list(self.peers),
            'service_order': self.service_rank,
            'split_allowed': self.split_allowed,
            'split_reason': self.split_reason,
            'alternative': None if self.alternative is None else self.alternative.key,
            'alternative_valid_from': _format_datetime(self.alternative_valid_from),
            'alternative_valid_until': _format_datetime(self.alternative_valid_until),
            'defer_until': _format_datetime(self.defer_until),
            'missing_materials': list(self.missing_materials),
        }

    def __repr__(self):
        return 'FreezeReviewItem(%r, %r)' % (self.name, self.status)


def _alternative_sort_key(alternative, moment):
    if moment is None:
        currently_valid = True
    else:
        after_start = alternative.valid_from is None or alternative.valid_from <= moment
        before_end = alternative.valid_until is None or moment <= alternative.valid_until
        currently_valid = after_start and before_end

    return (
        0 if currently_valid else 1,
        0 if alternative.valid_until is None else -alternative.valid_until.toordinal(),
        alternative.key
    )


def _select_alternative(project, frozen_used, frozen_evidence, moment):
    """
    :return:
        None or the best AlternativeEvidence that covers every frozen item the
        project currently relies on and has not itself expired
    """

    candidates = []
    for alternative in project.alternatives:
        if alternative.key in frozen_evidence:
            continue
        if set(alternative.evidence) & set(frozen_evidence):
            continue
        if alternative.covers is not None:
            eligible = set(frozen_used).issubset(alternative.covers)
        elif alternative.complete:
            eligible = True
        else:
            eligible = False
        if not eligible:
            continue
        if moment is not None and alternative.valid_until is not None \
                and alternative.valid_until < moment:
            continue
        candidates.append(alternative)

    if not candidates:
        return None
    return min(candidates, key=lambda item: _alternative_sort_key(item, moment))


class FreezeReviewPlan(object):
    """
    The deterministic outcome of a freeze-impact review. Local validation is
    unchanged; this object only orders the manual release checks.
    """

    def __init__(self, frozen_evidence, items, unaffected, moment=None, freeze=None):
        self.frozen_evidence = tuple(sorted(frozen_evidence))
        self.items = tuple(items)
        self.unaffected = tuple(sorted(unaffected, key=lambda item: item.name))
        self.moment = moment
        self.freeze = freeze

    @property
    def review_queue(self):
        return tuple(item for item in self.items if item.status == REVIEW)

    @property
    def deferred(self):
        return tuple(item for item in self.items if item.status == DEFERRED)

    @property
    def missing_materials(self):
        return tuple(item for item in self.items if item.status == MISSING_MATERIALS)

    @property
    def first_reviewer(self):
        queue = self.review_queue
        if not queue:
            return None
        return queue[0].name

    @property
    def deferred_names(self):
        return tuple(item.name for item in self.deferred)

    @property
    def missing_materials_names(self):
        return tuple(item.name for item in self.missing_materials)

    @property
    def review_projects(self):
        return self.review_queue

    @property
    def deferred_projects(self):
        return self.deferred

    @property
    def missing_projects(self):
        return self.missing_materials

    @property
    def missing_names(self):
        return self.missing_materials_names

    @property
    def affected(self):
        return self.items

    @property
    def projects(self):
        return self.items

    @property
    def order(self):
        return tuple(item.name for item in self.items)

    @property
    def names(self):
        return self.order

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)

    def get(self, name):
        for item in self.items:
            if item.name == name:
                return item
        return None

    def to_dict(self):
        frozen_until = None
        if self.freeze is not None:
            frozen_until = _format_datetime(self.freeze.frozen_until)
        return {
            'frozen_evidence': list(self.frozen_evidence),
            'batch': None if self.freeze is None else self.freeze.batch,
            'frozen_until': frozen_until,
            'freeze_reason': None if self.freeze is None else self.freeze.reason,
            'moment': _format_datetime(self.moment),
            'affected': [item.to_dict() for item in self.items],
            'review_order': [item.name for item in self.review_queue],
            'deferred': [item.name for item in self.deferred],
            'missing_materials': dict(
                (item.name, list(item.missing_materials))
                for item in self.missing_materials
            ),
            'first_reviewer': self.first_reviewer,
            'can_defer': list(self.deferred_names),
            'missing': dict(
                (item.name, list(item.missing_materials))
                for item in self.missing_materials
            ),
            'unaffected': [item.name for item in self.unaffected],
        }

    def report(self):
        """
        :return:
            A unicode string report that separates projects that must be
            reviewed now, projects that may be deferred to alternative
            evidence, and projects that are missing materials.
        """

        lines = []
        lines.append('Freeze impact review')
        lines.append('Local certificate validation: unchanged (path/signature valid)')
        if self.freeze is not None:
            if self.freeze.batch:
                lines.append('Frozen batch: %s' % self.freeze.batch)
            if self.freeze.frozen_until is not None:
                lines.append('Freeze expected until: %s' % _format_datetime(self.freeze.frozen_until))
            if self.freeze.reason:
                lines.append('Freeze reason: %s' % self.freeze.reason)
        lines.append('Frozen evidence: %s' % (', '.join(self.frozen_evidence) or '(none)'))
        lines.append(
            'Affected projects: %d of %d'
            % (len(self.items), len(self.items) + len(self.unaffected))
        )
        lines.append('First review: %s' % (self.first_reviewer or '(none)'))
        lines.append('May defer: %s' % (', '.join(self.deferred_names) or '(none)'))
        lines.append(
            'Missing materials: %s'
            % (', '.join(self.missing_materials_names) or '(none)')
        )

        lines.append('')
        lines.append('Review queue (first review first):')
        if not self.review_queue:
            lines.append('  (none)')
        for item in self.review_queue:
            details = []
            if item.project.valid_until is not None:
                details.append('valid until %s' % _format_datetime(item.project.valid_until))
            if item.shared_evidence:
                details.append(
                    'shares %s with %s'
                    % (', '.join(item.shared_evidence), ', '.join(item.peers))
                )
            details.append('service order %d' % item.service_rank)
            lines.append('  %d. %s | %s' % (item.review_position, item.name, ' | '.join(details)))

        lines.append('')
        lines.append('Deferred to alternative evidence:')
        if not self.deferred:
            lines.append('  (none)')
        for item in self.deferred:
            window = 'unknown'
            if item.alternative_valid_from is not None or item.alternative_valid_until is not None:
                window = '%s to %s' % (
                    _format_datetime(item.alternative_valid_from) or '(start)',
                    _format_datetime(item.alternative_valid_until) or '(end)'
                )
            lines.append(
                '  - %s | alternative %s | belongs %s | defer until %s'
                % (
                    item.name,
                    item.alternative.key,
                    window,
                    _format_datetime(item.defer_until) or '(no expiry)'
                )
            )
            lines.append('    split reason: %s' % item.split_reason)

        lines.append('')
        lines.append('Missing materials:')
        if not self.missing_materials:
            lines.append('  (none)')
        for item in self.missing_materials:
            lines.append('  - %s | missing: %s' % (item.name, ', '.join(item.missing_materials)))
            if item.alternative is not None:
                lines.append(
                    '    after materials arrive, may defer to %s (%s to %s)'
                    % (
                        item.alternative.key,
                        _format_datetime(item.alternative_valid_from) or '(start)',
                        _format_datetime(item.alternative_valid_until) or '(end)'
                    )
                )

        if self.unaffected:
            lines.append('')
            lines.append('Unaffected: %s' % ', '.join(item.name for item in self.unaffected))

        return '\n'.join(lines)

    def __repr__(self):
        return 'FreezeReviewPlan(%d affected)' % len(self.items)


def review_freeze_impact(projects, frozen_evidence, service_order=None, moment=None):
    """
    Builds a manual review plan for projects whose locally-valid certificate
    paths depend on evidence from a temporarily frozen external batch.

    Projects are ordered by certificate validity end (soonest first), then by
    how much frozen evidence they share with other affected projects, then by
    the supplied service order. A project is deferred when an alternative path
    covers every frozen item it uses; the alternative's validity window and the
    reason the split is permitted are recorded on the plan. A project missing
    required review materials is reported separately instead of being put in
    the review queue.

    The result is independent of the order of the input sequence.

    :param projects:
        An iterable of ReviewProject objects, dicts or CertificateValidator
        objects

    :param frozen_evidence:
        An iterable of evidence keys or Evidence objects that are frozen

    :param service_order:
        None, a list of project names in service order, or a dict of project
        name to integer rank. Used only to break ties after validity end and
        shared-evidence priority.

    :param moment:
        None or a date/datetime/ISO-8601 string used to decide whether an
        alternative evidence window is currently usable

    :return:
        A FreezeReviewPlan object
    """

    freeze_object = frozen_evidence if isinstance(frozen_evidence, Freeze) else None
    frozen = set(
        _coerce_evidence(item) for item in _evidence_collection(frozen_evidence)
    )
    moment_value = _coerce_datetime(moment, 'moment')
    effective_moment = moment_value
    if effective_moment is None:
        effective_moment = datetime.now(timezone.utc)
    project_objects = [
        _coerce_project(item) for item in _project_collection(projects)
    ]

    names = set()
    for project in project_objects:
        if project.name in names:
            raise FreezeReviewError(
                'project names must be unique, duplicate: %s' % project.name
            )
        names.add(project.name)

    ranks = _service_ranks(project_objects, service_order)

    affected = []
    unaffected = []
    for project in project_objects:
        used = set(project.evidence) & frozen
        if used:
            affected.append((project, used))
        else:
            unaffected.append(project)

    holders = {}
    for project, used in affected:
        for evidence_key in used:
            holders.setdefault(evidence_key, set()).add(project.name)

    items = []
    for project, used in affected:
        shared = set(
            evidence_key for evidence_key in used
            if len(holders[evidence_key]) > 1
        )
        peers = set()
        for evidence_key in shared:
            peers.update(holders[evidence_key])
        peers.discard(project.name)

        missing = project.missing_materials()
        alternative = _select_alternative(project, used, frozen, effective_moment)
        if missing:
            status = MISSING_MATERIALS
        elif alternative is not None:
            status = DEFERRED
        else:
            status = REVIEW

        items.append(FreezeReviewItem(
            project,
            status,
            used,
            shared,
            peers,
            ranks[project.name],
            alternative=alternative,
            missing_materials=missing,
            moment=effective_moment
        ))

    def sort_key(item):
        if item.shared_evidence:
            evidence_priority = (
                0,
                item.shared_evidence[0],
                -len(item.peers),
                item.affected_evidence[0] if item.affected_evidence else ''
            )
        else:
            evidence_priority = (
                1,
                '',
                0,
                item.affected_evidence[0] if item.affected_evidence else ''
            )
        return (
            _datetime_key(item.project.valid_until),
            evidence_priority,
            item.service_rank,
            item.name
        )

    items.sort(key=sort_key)

    review_position = 0
    for position, item in enumerate(items):
        item.order = position + 1
        if item.status == REVIEW:
            review_position += 1
            item.review_position = review_position

    return FreezeReviewPlan(
        frozen,
        items,
        unaffected,
        moment=moment_value,
        freeze=freeze_object
    )


def review_validators(validators, frozen_evidence, service_order=None, moment=None,
                      names=None, materials=None, required_materials=None,
                      alternatives=None, evidence=None):
    """
    Convenience wrapper that locally validates a list of CertificateValidator
    objects and then runs review_freeze_impact() over their paths.

    :param validators:
        An iterable of certvalidator.CertificateValidator objects

    :param names:
        None, or an iterable of names parallel to validators

    :param materials:
        None, or a dict of project name to available material names

    :param required_materials:
        None, or a dict of project name to required material names

    :param alternatives:
        None, or a dict of project name to AlternativeEvidence/dict objects

    :return:
        A FreezeReviewPlan object
    """

    if hasattr(validators, '_validate_path'):
        validators = [validators]
    else:
        validators = list(validators)
    if names is None:
        names = [None] * len(validators)
    else:
        if isinstance(names, (str_cls, byte_cls)):
            names = [names]
        names = list(names)
    if len(names) != len(validators):
        raise FreezeReviewError('names must be the same length as validators')

    def per_project(value, name, default):
        if isinstance(value, dict) and name is not None:
            return value.get(name, default)
        return value if value is not None else default

    projects = []
    for index, validator in enumerate(validators):
        validator._validate_path()
        path = validator._path
        project_name = names[index]
        if project_name is None:
            subject = path[-1].subject.native
            project_name = subject.get('common_name') or path[-1].subject.human_friendly
        projects.append(project_from_validation_path(
            path,
            name=project_name,
            materials=per_project(materials, project_name, None),
            required_materials=per_project(required_materials, project_name, None),
            alternatives=per_project(alternatives, project_name, None),
            evidence=per_project(evidence, project_name, None)
        ))

    return review_freeze_impact(
        projects,
        frozen_evidence,
        service_order=service_order,
        moment=moment
    )


# Descriptive aliases for callers that prefer a plan-oriented name
build_freeze_review_plan = review_freeze_impact
freeze_impact_review = review_freeze_impact
