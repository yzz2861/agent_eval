# -*- coding: utf-8 -*-
"""
Offline impact assessment for matcher upgrades.

The module answers a narrow operational question: given the same file prefix
samples and two ordered matcher registries, which samples keep the same
isolation route, which gain a newly recognised format, and which legacy files
fall through to a less capable processing queue?

Routing is intentionally separate from detection. A route maps a detected
type to a queue and an integer ``capability`` where larger values mean more
capable processing. The report therefore keeps three facts apart:

* detection changes (winner or matching precedence),
* route changes (queue and capability), and
* matcher failures (which sample and which registry was affected).

Both routing configurations are embedded in the report so an exception or a
changed isolation decision can be reviewed without reconstructing the
deployment.
"""

from __future__ import absolute_import

import argparse
import binascii
import base64
import hashlib
import importlib
import json
import os
import sys

from .match import matcher_name, ranked_matches
from .types import TYPES, Type


SCHEMA_VERSION = 1

DECISION_UNCHANGED = 'unchanged'
DECISION_NEW_FORMAT = 'new_format'
DECISION_NEW_UNROUTED = 'new_unrouted'
DECISION_DOWNGRADE = 'downgrade'
DECISION_UPGRADE = 'upgrade'
DECISION_LATERAL = 'lateral_reroute'
DECISION_COVERAGE_LOST = 'coverage_lost'

ISOLATION_DECISIONS = (
    DECISION_NEW_FORMAT,
    DECISION_NEW_UNROUTED,
    DECISION_DOWNGRADE,
    DECISION_UPGRADE,
    DECISION_LATERAL,
    DECISION_COVERAGE_LOST,
)


class ImpactError(ValueError):
    """Raised for invalid sample, matcher or routing configurations."""


PREFIX_SIZE = 8192


DEFAULT_ROUTE = {
    'queue': 'quarantine',
    'capability': 0,
    'legal': False,
}


def _canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(',', ':'), ensure_ascii=True
    )


def _digest(value):
    if not isinstance(value, (bytes, bytearray)):
        value = _canonical_json(value).encode('utf-8')
    return hashlib.sha256(bytes(value)).hexdigest()


def _as_text_key(value):
    return str(value).strip().lower()


def _resolve_path(path, base_dir=None):
    path = os.path.expanduser(path)
    if os.path.isabs(path):
        return path
    if base_dir and not os.path.exists(path):
        candidate = os.path.join(base_dir, path)
        if os.path.exists(candidate):
            return candidate
    return path


def _load_json(path, base_dir=None):
    resolved = _resolve_path(path, base_dir)
    try:
        with open(resolved, 'r', encoding='utf-8') as fp:
            return json.load(fp), resolved
    except OSError as error:
        raise ImpactError('cannot read JSON file %s: %s' % (path, error))
    except ValueError as error:
        raise ImpactError('invalid JSON in %s: %s' % (path, error))


class Route(object):
    """Resolved queue for one detected type."""

    def __init__(self, queue, capability=0, legal=True, explicit=True,
                 key=None, raw=None):
        try:
            capability = int(capability)
        except (TypeError, ValueError):
            raise ImpactError(
                'route capability must be an integer, got %r' % (capability,)
            )
        self.queue = str(queue)
        self.capability = capability
        self.legal = bool(legal)
        self.explicit = bool(explicit)
        self.key = key
        self.raw = raw if raw is not None else {}

    def to_dict(self):
        return {
            'queue': self.queue,
            'capability': self.capability,
            'legal': self.legal,
            'explicit': self.explicit,
            'key': self.key,
        }


def _route_from_raw(raw, explicit=True, key=None, capabilities=None):
    capabilities = capabilities or {}
    if raw is None:
        raw = DEFAULT_ROUTE
        explicit = False
    if isinstance(raw, str):
        return Route(
            raw, capability=capabilities.get(raw, 0), legal=True,
            explicit=explicit, key=key, raw={'queue': raw},
        )
    if not isinstance(raw, dict):
        raise ImpactError('route entry must be an object or queue string')

    queue = (
        raw.get('queue') or raw.get('service') or raw.get('target') or
        raw.get('name') or 'unrouted'
    )
    capability = raw.get(
        'capability',
        raw.get(
            'capacity',
            raw.get('strength', capabilities.get(queue, 0)),
        ),
    )
    legal = raw.get(
        'legal', raw.get('accepted', raw.get('allow', explicit))
    )
    return Route(
        queue, capability=capability, legal=legal, explicit=explicit,
        key=key, raw=raw,
    )


class RoutingConfig(object):
    """A route table keyed by MIME type or extension."""

    def __init__(self, config=None, name='routes', source=None):
        if isinstance(config, RoutingConfig):
            self.name = config.name
            self.source = config.source
            self.raw = config.raw
            self.default = config.default
            self.routes = dict(config.routes)
            return

        config = config or {}
        if isinstance(config, list):
            config = {'routes': config}
        if not isinstance(config, dict):
            raise ImpactError('routing config must be an object or list')

        self.name = config.get('name', name)
        self.source = config.get('source', source)
        self.raw = config

        capabilities = (
            config.get('capabilities') or
            config.get('queue_capabilities') or {}
        )
        if not isinstance(capabilities, dict):
            raise ImpactError('routing capabilities must be an object')
        capabilities = dict(capabilities)
        queues_config = config.get('queues')
        if isinstance(queues_config, dict):
            for queue, value in queues_config.items():
                if isinstance(value, dict):
                    value = value.get(
                        'capability', value.get('capacity', 0)
                    )
                capabilities.setdefault(queue, value)

        default_raw = config.get('default')
        if default_raw is None:
            default_raw = DEFAULT_ROUTE
            self.default = _route_from_raw(
                default_raw, explicit=False, capabilities=capabilities,
            )
        else:
            self.default = _route_from_raw(
                default_raw, explicit=True, key='default',
                capabilities=capabilities,
            )

        routes = config.get('routes', config.get('map'))
        if routes is None:
            routes = {
                key: value for key, value in config.items()
                if key not in (
                    'name', 'source', 'default', 'metadata', 'capabilities',
                    'queue_capabilities', 'queues',
                )
            }
        if isinstance(routes, list):
            keyed = {}
            for item in routes:
                if not isinstance(item, dict):
                    raise ImpactError('route rule must be an object')
                keys = (
                    item.get('mime'), item.get('extension'), item.get('ext'),
                    item.get('type'), item.get('match'),
                )
                keys = [key for key in keys if key]
                if not keys:
                    raise ImpactError(
                        'route rule needs mime/extension/type/match'
                    )
                for key in keys:
                    keyed[str(key)] = item
            routes = keyed
        if not isinstance(routes, dict):
            raise ImpactError('routing config routes must be an object or list')

        self.routes = {}
        for key, raw in routes.items():
            self.routes[str(key)] = _route_from_raw(
                raw, explicit=True, key=str(key),
                capabilities=capabilities,
            )

    def lookup(self, kind):
        if kind is None:
            return None

        mime = getattr(kind, 'mime', None)
        extension = getattr(kind, 'extension', None)
        candidates = [mime, extension]
        for value in candidates:
            if not value:
                continue
            if value in self.routes:
                return self.routes[value]
            lowered = _as_text_key(value)
            for key, route in self.routes.items():
                if _as_text_key(key) == lowered:
                    return route
        return self.default

    def to_dict(self, include_config=True):
        data = {
            'name': self.name,
            'source': self.source,
            'sha256': _digest(self.raw),
            'default': self.default.to_dict(),
            'routes': {
                key: route.to_dict()
                for key, route in sorted(self.routes.items())
            },
        }
        if include_config:
            data['config'] = self.raw
        return data


def _normalize_routing_config(value, name, base_dir=None):
    if value is None:
        return RoutingConfig(None, name=name)
    if isinstance(value, RoutingConfig):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith('{') or stripped.startswith('['):
            try:
                config = json.loads(stripped)
            except ValueError as error:
                raise ImpactError('invalid inline routing JSON: %s' % error)
            return RoutingConfig(config, name=name)
        config, source = _load_json(value, base_dir)
        return RoutingConfig(config, name=name, source=source)
    return RoutingConfig(value, name=name)


def _lookup_builtin(token):
    lowered = _as_text_key(token)
    aliases = {
        'builtin': None,
        'builtins': None,
        'default': None,
        'all': None,
    }
    if lowered in aliases:
        return list(TYPES)

    for matcher in TYPES:
        cls = type(matcher)
        names = {
            _as_text_key(matcher.extension),
            _as_text_key(matcher.mime),
            _as_text_key(cls.__name__),
            _as_text_key('%s.%s' % (cls.__module__, cls.__name__)),
            _as_text_key('%s.%s' % (cls.__module__.split('.')[-1],
                                    cls.__name__)),
        }
        if lowered in names:
            return matcher
    return None


def _import_matcher(ref, args=None, kwargs=None):
    if ':' in ref:
        module_name, attr = ref.split(':', 1)
    else:
        module_name, _, attr = ref.rpartition('.')
    if not module_name or not attr:
        raise ImpactError(
            'matcher reference %r must be module:Class or module.Class' % ref
        )
    try:
        module = importlib.import_module(module_name)
    except ImportError as error:
        raise ImpactError('cannot import matcher module %r: %s' % (
            module_name, error
        ))
    try:
        obj = getattr(module, attr)
    except AttributeError:
        raise ImpactError('matcher %r has no attribute %r' % (
            module_name, attr
        ))
    if isinstance(obj, type):
        try:
            return obj(*(args or []), **(kwargs or {}))
        except TypeError as error:
            raise ImpactError('cannot construct matcher %r: %s' % (ref, error))
    return obj


def _resolve_matcher(item):
    if isinstance(item, Type):
        return item
    if isinstance(item, type) and issubclass(item, Type):
        return item()
    if isinstance(item, str):
        builtin = _lookup_builtin(item)
        if builtin is not None:
            return builtin
        return _import_matcher(item)
    if isinstance(item, dict):
        ref = item.get('ref') or item.get('class') or item.get('matcher')
        if not ref:
            raise ImpactError('matcher object needs ref/class/matcher')
        return _import_matcher(
            ref, args=item.get('args'), kwargs=item.get('kwargs')
        )
    raise ImpactError('unsupported matcher entry: %r' % (item,))


def normalize_matchers(spec, base_dir=None):
    """Resolves a matcher registry specification to an ordered list."""
    if spec is None:
        return list(TYPES)
    if isinstance(spec, str):
        stripped = spec.strip()
        if stripped.startswith('[') or stripped.startswith('{'):
            try:
                spec = json.loads(stripped)
            except ValueError as error:
                raise ImpactError('invalid inline matcher JSON: %s' % error)
        else:
            builtin = _lookup_builtin(spec)
            if builtin is not None:
                if isinstance(builtin, list):
                    return list(builtin)
                return [builtin]
            if os.path.exists(_resolve_path(spec, base_dir)):
                spec, _ = _load_json(spec, base_dir)
            else:
                spec = [
                    item.strip() for item in spec.split(',') if item.strip()
                ]
    if isinstance(spec, dict):
        spec = (
            spec.get('matchers') or spec.get('order') or
            spec.get('registry') or spec.get('types')
        )
        if spec is None:
            raise ImpactError('matcher config needs matchers/order/registry')
    if not isinstance(spec, (list, tuple)):
        raise ImpactError('matcher registry must be a list')
    resolved = []
    for item in spec:
        matcher = _resolve_matcher(item)
        if isinstance(matcher, (list, tuple)):
            resolved.extend(matcher)
        else:
            resolved.append(matcher)
    return resolved


def _read_prefix(item, base_dir=None):
    if isinstance(item, (bytes, bytearray)):
        return bytes(item)
    if isinstance(item, memoryview):
        return bytes(item)
    if hasattr(item, 'read'):
        return bytes(item.read())
    if isinstance(item, str):
        path = _resolve_path(item, base_dir)
        if os.path.exists(path):
            with open(path, 'rb') as fp:
                return fp.read(PREFIX_SIZE)
        return item.encode('utf-8')
    if isinstance(item, dict):
        if 'path' in item or 'file' in item:
            path = _resolve_path(item.get('path', item.get('file')), base_dir)
            try:
                with open(path, 'rb') as fp:
                    return fp.read(PREFIX_SIZE)
            except OSError as error:
                raise ImpactError('cannot read sample %s: %s' % (path, error))
        if 'hex' in item:
            value = str(item['hex']).replace(' ', '').replace(':', '')
            try:
                return binascii.unhexlify(value)
            except (binascii.Error, ValueError) as error:
                raise ImpactError('invalid hex sample: %s' % error)
        if 'base64' in item or 'b64' in item:
            value = item.get('base64', item.get('b64'))
            try:
                return base64.b64decode(value)
            except (TypeError, ValueError, binascii.Error) as error:
                raise ImpactError('invalid base64 sample: %s' % error)
        if 'text' in item:
            return str(item['text']).encode('utf-8')
        for key in ('prefix', 'bytes', 'data', 'value'):
            if key in item:
                return _read_prefix(item[key], base_dir)
        raise ImpactError('sample object needs path/hex/base64/text/prefix')
    raise ImpactError('unsupported sample prefix: %r' % (item,))


class Sample(object):
    """One named offline file prefix."""

    def __init__(self, name, prefix, source=None, metadata=None):
        self.name = str(name)
        self.prefix = bytes(prefix[:PREFIX_SIZE])
        self.source = source
        self.metadata = metadata or {}
        self.sha256 = _digest(self.prefix)
        self.size = len(self.prefix)

    def to_dict(self):
        data = {
            'name': self.name,
            'prefix_sha256': self.sha256,
            'prefix_size': self.size,
            'source': self.source,
        }
        if self.metadata:
            data['metadata'] = self.metadata
        return data


def _sample_from_mapping(name, value, base_dir=None):
    source = None
    metadata = None
    if isinstance(value, dict):
        source = (
            value.get('source') or value.get('path') or value.get('file')
        )
        metadata = value.get('metadata')
    prefix = _read_prefix(value, base_dir)
    return Sample(name, prefix, source=source, metadata=metadata)


def normalize_samples(samples, base_dir=None):
    """Accepts mappings, ``(name, prefix)`` pairs, sample objects or JSON."""
    if isinstance(samples, str):
        data, source = _load_json(samples, base_dir)
        base_dir = os.path.dirname(source) or base_dir
        samples = data.get('samples', data) if isinstance(data, dict) else data

    if isinstance(samples, dict):
        if 'samples' in samples:
            samples = samples['samples']
        else:
            return [
                _sample_from_mapping(name, value, base_dir)
                for name, value in samples.items()
            ]

    if isinstance(samples, Sample):
        return [samples]
    if not isinstance(samples, (list, tuple)):
        raise ImpactError('samples must be a mapping or a list')

    normalized = []
    for item in samples:
        if isinstance(item, Sample):
            normalized.append(item)
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            normalized.append(
                _sample_from_mapping(item[0], item[1], base_dir)
            )
        elif isinstance(item, str):
            path = _resolve_path(item, base_dir)
            with open(path, 'rb') as fp:
                normalized.append(
                    Sample(
                        os.path.basename(path), fp.read(PREFIX_SIZE),
                        source=path,
                    )
                )
        elif isinstance(item, dict):
            name = item.get('name')
            if name is None:
                raise ImpactError('sample object needs a name')
            value = item
            if not any(key in item for key in
                       ('path', 'file', 'hex', 'base64', 'b64', 'text',
                        'prefix', 'bytes', 'data', 'value')):
                raise ImpactError('sample %r has no prefix data' % name)
            normalized.append(_sample_from_mapping(name, value, base_dir))
        else:
            raise ImpactError('unsupported sample entry: %r' % (item,))
    return normalized


def _candidate_to_dict(candidate):
    data = candidate.to_dict()
    data['matcher_class'] = type(candidate.matcher).__name__
    data['matcher_module'] = type(candidate.matcher).__module__
    return data


def _detect(sample, matchers, routes, side):
    candidates = ranked_matches(
        sample.prefix, matchers=matchers, on_error='record'
    )
    winner = candidates[0] if candidates else None
    route = routes.lookup(winner.matcher) if winner else None

    errors = []
    for error in candidates.errors:
        item = error.to_dict()
        item.update({
            'side': side,
            'sample': sample.name,
        })
        errors.append(item)

    return {
        'matched': winner is not None,
        'type': (
            {'mime': winner.mime, 'extension': winner.extension}
            if winner else None
        ),
        'matcher': (
            {
                'name': winner.matcher_name,
                'class': type(winner.matcher).__name__,
                'module': type(winner.matcher).__module__,
                'index': winner.index,
                'rank': winner.rank,
            }
            if winner else None
        ),
        'rank': winner.rank if winner else None,
        'route': route.to_dict() if route else None,
        'candidates': [_candidate_to_dict(item) for item in candidates],
        'errors': errors,
    }


def _type_key(side):
    if not side or not side.get('type'):
        return None
    return (side['type']['mime'], side['type']['extension'])


def _matcher_key(side):
    if not side or not side.get('matcher'):
        return None
    return side['matcher']['name']


def _route_key(side):
    route = side.get('route') if side else None
    if not route:
        return None
    return (route['queue'], route['capability'])


def _classify(before, after):
    before_matched = before['matched']
    after_matched = after['matched']
    before_route = before['route']
    after_route = after['route']

    if not before_matched and after_matched:
        route = after_route or {}
        if route.get('explicit') and route.get('legal'):
            decision = DECISION_NEW_FORMAT
        else:
            decision = DECISION_NEW_UNROUTED
    elif before_matched and not after_matched:
        decision = DECISION_COVERAGE_LOST
    elif not before_matched and not after_matched:
        decision = DECISION_UNCHANGED
    else:
        before_capability = before_route['capability']
        after_capability = after_route['capability']
        if after_capability < before_capability:
            decision = DECISION_DOWNGRADE
        elif after_capability > before_capability:
            decision = DECISION_UPGRADE
        elif before_route['queue'] != after_route['queue']:
            decision = DECISION_LATERAL
        else:
            decision = DECISION_UNCHANGED

    detection_changed = (
        before_matched != after_matched or
        _type_key(before) != _type_key(after) or
        _matcher_key(before) != _matcher_key(after)
    )
    isolation_changed = _route_key(before) != _route_key(after)
    return decision, detection_changed, isolation_changed


def _precedence_key(side):
    return [
        (
            item['type']['mime'],
            item['type']['extension'],
            item['matcher'],
        )
        for item in side['candidates']
    ]


def _route_summary(side):
    route = side.get('route') if side else None
    return {
        'type': side.get('type') if side else None,
        'matcher': side.get('matcher') if side else None,
        'queue': route['queue'] if route else None,
        'capability': route['capability'] if route else None,
        'legal': route['legal'] if route else None,
        'explicit': route['explicit'] if route else None,
    }


def _decision_record(sample, before, after, decision):
    return {
        'sample': sample.name,
        'decision': decision,
        'before': _route_summary(before),
        'after': _route_summary(after),
    }


def _unpack_registry(value, routes, side):
    if isinstance(value, RoutingConfig):
        return value, routes
    if isinstance(value, dict) and (
        'matchers' in value or 'order' in value or
        'registry' in value or 'types' in value
    ):
        if routes is None:
            routes = (
                value.get('routes') or value.get('routing') or
                value.get('route')
            )
        value = (
            value.get('matchers') or value.get('order') or
            value.get('registry') or value.get('types')
        )
    if isinstance(value, (list, tuple)) and len(value) == 2:
        first, second = value
        if isinstance(second, (RoutingConfig, dict)):
            if routes is None:
                routes = second
            value = first
    if routes is None and isinstance(value, dict):
        routes = value.get('routes') or value.get('routing')
    return value, routes


def assess(samples, before=None, after=None, before_routes=None,
           after_routes=None, include_configs=True, metadata=None,
           sample_base_dir=None):
    """
    Compares two ordered matcher registries on the same file prefixes.

    Args:
        samples: mapping ``{name: prefix}``, ``(name, prefix)`` pairs, sample
            dictionaries, :class:`Sample` objects or a JSON manifest path.
        before: ordered matcher registry before the upgrade. ``None`` uses
            the built-in ``TYPES`` registry.
        after: ordered matcher registry after the upgrade.
        before_routes / after_routes: routing config mappings or JSON paths.
        include_configs: embed both full routing configs in the report.
        metadata: optional caller metadata copied into the report.
        sample_base_dir: base directory for relative sample paths.

    Returns:
        dict: JSON serialisable impact report.
    """
    before, before_routes = _unpack_registry(before, before_routes, 'before')
    after, after_routes = _unpack_registry(after, after_routes, 'after')

    before_matchers = normalize_matchers(before, sample_base_dir)
    after_matchers = normalize_matchers(after, sample_base_dir)
    before_table = _normalize_routing_config(
        before_routes, 'before', sample_base_dir
    )
    after_table = _normalize_routing_config(
        after_routes, 'after', sample_base_dir
    )
    normalized_samples = normalize_samples(samples, sample_base_dir)
    routes_present = bool(
        before_table.routes or after_table.routes or
        before_table.default.explicit or after_table.default.explicit
    )

    records = []
    summary = {
        'samples_total': len(normalized_samples),
        'unchanged': 0,
        'new_format': 0,
        'new_unrouted': 0,
        'downgrade': 0,
        'upgrade': 0,
        'lateral_reroute': 0,
        'coverage_lost': 0,
        'isolation_changed': 0,
        'detection_changed': 0,
        'precedence_changed': 0,
        'error_affected_samples': 0,
        'unrouted_new_formats': 0,
    }
    changed = []
    precedence_changes = []
    errors = []
    affected = []

    for sample in normalized_samples:
        before_match = _detect(sample, before_matchers, before_table, 'before')
        after_match = _detect(sample, after_matchers, after_table, 'after')
        decision, detection_changed, isolation_changed = _classify(
            before_match, after_match
        )
        if decision == DECISION_NEW_UNROUTED and not routes_present:
            decision = DECISION_NEW_FORMAT
        after_route = after_match.get('route') or {}
        routed = bool(
            after_route.get('explicit') and after_route.get('legal')
        )
        precedence_changed = (
            _precedence_key(before_match) != _precedence_key(after_match)
        )
        sample_errors = before_match['errors'] + after_match['errors']

        record = sample.to_dict()
        record.update({
            'before': before_match,
            'after': after_match,
            'decision': decision,
            'detection_changed': detection_changed,
            'isolation_changed': isolation_changed,
            'precedence_changed': precedence_changed,
            'routed': routed,
            'error_affected': bool(sample_errors),
            'errors': sample_errors,
        })
        records.append(record)

        summary[decision] += 1
        if decision == DECISION_NEW_FORMAT and not routed:
            summary['unrouted_new_formats'] += 1
        if isolation_changed:
            summary['isolation_changed'] += 1
            changed.append(_decision_record(
                sample, before_match, after_match, decision
            ))
        if detection_changed:
            summary['detection_changed'] += 1
        if precedence_changed:
            summary['precedence_changed'] += 1
        if precedence_changed or detection_changed:
            precedence_changes.append({
                'sample': sample.name,
                'before_order': [
                    {
                        'rank': item['rank'],
                        'extension': item['extension'],
                        'mime': item['mime'],
                        'matcher': item['matcher'],
                    }
                    for item in before_match['candidates']
                ],
                'after_order': [
                    {
                        'rank': item['rank'],
                        'extension': item['extension'],
                        'mime': item['mime'],
                        'matcher': item['matcher'],
                    }
                    for item in after_match['candidates']
                ],
            })
        if sample_errors:
            affected.append(sample.name)
            errors.extend(sample_errors)

    summary['error_affected_samples'] = len(affected)
    summary['new_formats'] = summary['new_format']
    summary['downgrades'] = summary['downgrade']
    summary['affected_samples'] = len(affected)
    summary['errors'] = len(errors)

    affected_details = [
        {
            'name': record['name'],
            'prefix_sha256': record['prefix_sha256'],
            'prefix_size': record['prefix_size'],
            'source': record.get('source'),
            'error_count': len(record['errors']),
        }
        for record in records if record['error_affected']
    ]

    by_matcher = {}
    for error in errors:
        key = '%s (%s)' % (error['matcher'], error['side'])
        by_matcher[key] = by_matcher.get(key, 0) + 1

    samples_digest = _digest([
        {'name': record['name'], 'prefix_sha256': record['prefix_sha256']}
        for record in records
    ])

    return {
        'schema_version': SCHEMA_VERSION,
        'metadata': metadata or {},
        'samples_sha256': samples_digest,
        'summary': summary,
        'routing_configs': {
            'before': before_table.to_dict(include_configs),
            'after': after_table.to_dict(include_configs),
        },
        'matcher_registries': {
            'before': {
                'sha256': _digest([matcher_name(item)
                                   for item in before_matchers]),
                'order': [matcher_name(item) for item in before_matchers],
            },
            'after': {
                'sha256': _digest([matcher_name(item)
                                  for item in after_matchers]),
                'order': [matcher_name(item) for item in after_matchers],
            },
        },
        'errors': {
            'total': len(errors),
            'affected_samples': affected,
            'affected_sample_details': affected_details,
            'by_matcher': by_matcher,
            'routing_configs': {
                'before': {
                    'name': before_table.name,
                    'source': before_table.source,
                    'sha256': before_table.to_dict(False)['sha256'],
                },
                'after': {
                    'name': after_table.name,
                    'source': after_table.source,
                    'sha256': after_table.to_dict(False)['sha256'],
                },
            },
            'items': errors,
        },
        'changed_isolation_decisions': changed,
        'precedence_changes': precedence_changes,
        'samples': records,
    }


compare = assess
compare_registries = assess
compare_routing = assess
assess_impact = assess
analyze = assess
analyze_impact = assess
impact_report = assess


def _format_type(type_info):
    if not type_info:
        return '<no match>'
    return '%s (%s)' % (type_info['extension'], type_info['mime'])


def _format_route(summary):
    if not summary.get('queue'):
        return '<no route>'
    return '%s cap=%s' % (summary['queue'], summary.get('capability'))


def render_text(report):
    """Renders a compact human readable report."""
    summary = report['summary']
    lines = []
    lines.append('Matcher impact assessment')
    lines.append('=' * 27)
    lines.append('Samples: %d' % summary['samples_total'])
    lines.append('Samples digest: %s' % report.get('samples_sha256'))
    for side in ('before', 'after'):
        config = report['routing_configs'][side]
        lines.append('Routing %s: %s sha256=%s' % (
            side, config.get('source') or config.get('name'),
            config['sha256'],
        ))
    lines.append('')
    lines.append('Summary')
    lines.append('  unchanged: %d' % summary['unchanged'])
    lines.append('  new_format: %d' % summary['new_format'])
    lines.append('  new_unrouted: %d' % summary['new_unrouted'])
    lines.append('  downgrade: %d' % summary['downgrade'])
    lines.append('  upgrade: %d' % summary['upgrade'])
    lines.append('  lateral_reroute: %d' % summary['lateral_reroute'])
    lines.append('  coverage_lost: %d' % summary['coverage_lost'])
    lines.append('  isolation_changed: %d' % summary['isolation_changed'])
    lines.append('  precedence_changed: %d' % summary['precedence_changed'])
    lines.append('  error_affected_samples: %d' % summary[
        'error_affected_samples'
    ])
    lines.append('  unrouted_new_formats: %d' % summary[
        'unrouted_new_formats'
    ])

    new_formats = [
        item for item in report['samples']
        if item['decision'] == DECISION_NEW_FORMAT
    ]
    if new_formats:
        lines.append('')
        lines.append('New legitimate formats')
        for item in new_formats:
            after = item['after']
            marker = '' if item.get('routed') else ' [unrouted]'
            lines.append('  %s: %s -> %s%s' % (
                item['name'], _format_type(after['type']),
                _format_route(_route_summary(after)), marker,
            ))

    downgrades = [
        item for item in report['samples']
        if item['decision'] == DECISION_DOWNGRADE
    ]
    if downgrades:
        lines.append('')
        lines.append('Legacy files moved to a weaker queue')
        for item in downgrades:
            before = _route_summary(item['before'])
            after = _route_summary(item['after'])
            lines.append('  %s: %s [%s] -> %s [%s]' % (
                item['name'], _format_type(before['type']),
                _format_route(before), _format_type(after['type']),
                _format_route(after),
            ))

    lines.append('')
    lines.append('Changed isolation decisions')
    if not report['changed_isolation_decisions']:
        lines.append('  none')
    for item in report['changed_isolation_decisions']:
        lines.append('  %s: %s [%s] -> %s [%s] (%s)' % (
            item['sample'], _format_type(item['before']['type']),
            _format_route(item['before']), _format_type(item['after']['type']),
            _format_route(item['after']), item['decision'],
        ))

    lines.append('')
    lines.append('Matching precedence changes')
    if not report['precedence_changes']:
        lines.append('  none')
    for item in report['precedence_changes']:
        before_order = ', '.join(
            '%s@%s' % (entry['extension'], entry['rank'])
            for entry in item['before_order']
        ) or '<none>'
        after_order = ', '.join(
            '%s@%s' % (entry['extension'], entry['rank'])
            for entry in item['after_order']
        ) or '<none>'
        lines.append('  %s: %s -> %s' % (
            item['sample'], before_order, after_order
        ))

    lines.append('')
    lines.append('Matcher errors')
    if not report['errors']['items']:
        lines.append('  none')
    else:
        lines.append('  affected samples: %s' % ', '.join(
            report['errors']['affected_samples']
        ))
        for error in report['errors']['items']:
            lines.append('  %s [%s] %s rank %s: %s: %s' % (
                error['sample'], error['side'], error['matcher'],
                error['rank'], error['error'], error['message'],
            ))
        config_refs = report['errors']['routing_configs']
        lines.append('  routing configs: before=%s sha256=%s, '
                     'after=%s sha256=%s' % (
                         config_refs['before']['source'] or
                         config_refs['before']['name'],
                         config_refs['before']['sha256'],
                         config_refs['after']['source'] or
                         config_refs['after']['name'],
                         config_refs['after']['sha256'],
                     ))
    return '\n'.join(lines)


def render_markdown(report):
    """Renders the report as Markdown tables."""
    summary = report['summary']
    lines = ['# Matcher impact assessment', '']
    lines.append('- Samples: `%d` (sha256=`%s`)' % (
        summary['samples_total'], report.get('samples_sha256')
    ))
    for side in ('before', 'after'):
        config = report['routing_configs'][side]
        lines.append('- Routing %s: `%s` sha256=`%s`' % (
            side, config.get('source') or config.get('name'),
            config['sha256'],
        ))
    lines.extend(['', '## Summary', ''])
    for key in (
        'unchanged', 'new_format', 'new_unrouted', 'downgrade', 'upgrade',
        'lateral_reroute', 'coverage_lost', 'isolation_changed',
        'precedence_changed', 'error_affected_samples',
        'unrouted_new_formats',
    ):
        lines.append('- `%s`: %d' % (key, summary[key]))

    def table(title, rows):
        lines.extend(['', '## %s' % title, ''])
        if not rows:
            lines.append('_None._')
            return
        lines.append('| Sample | Decision | Before | After |')
        lines.append('| --- | --- | --- | --- |')
        for item in rows:
            lines.append('| `%s` | `%s` | %s / %s | %s / %s |' % (
                item['sample'], item['decision'],
                _format_type(item['before']['type']),
                _format_route(item['before']),
                _format_type(item['after']['type']),
                _format_route(item['after']),
            ))

    table('Changed isolation decisions', report['changed_isolation_decisions'])

    lines.extend(['', '## New legitimate formats', ''])
    new_formats = [
        item for item in report['samples']
        if item['decision'] == DECISION_NEW_FORMAT
    ]
    if new_formats:
        lines.append('| Sample | Format | Queue |')
        lines.append('| --- | --- | --- |')
        for item in new_formats:
            after = _route_summary(item['after'])
            marker = '' if item.get('routed') else ' [unrouted]'
            lines.append('| `%s` | %s | %s%s |' % (
                item['name'], _format_type(after['type']),
                _format_route(after), marker,
            ))
    else:
        lines.append('_None._')

    lines.extend(['', '## Legacy files moved to a weaker queue', ''])
    downgrades = [
        item for item in report['samples']
        if item['decision'] == DECISION_DOWNGRADE
    ]
    if downgrades:
        lines.append('| Sample | Before | After |')
        lines.append('| --- | --- | --- |')
        for item in downgrades:
            before = _route_summary(item['before'])
            after = _route_summary(item['after'])
            lines.append('| `%s` | %s / %s | %s / %s |' % (
                item['name'], _format_type(before['type']),
                _format_route(before), _format_type(after['type']),
                _format_route(after),
            ))
    else:
        lines.append('_None._')

    lines.extend(['', '## Matcher errors', ''])
    if not report['errors']['items']:
        lines.append('_None._')
    else:
        lines.append('Affected samples: %s' % ', '.join(
            '`%s`' % name for name in report['errors']['affected_samples']
        ))
        lines.append('')
        lines.append('| Sample | Side | Matcher | Rank | Error |')
        lines.append('| --- | --- | --- | --- | --- |')
        for error in report['errors']['items']:
            lines.append('| `%s` | `%s` | `%s` | %s | `%s: %s` |' % (
                error['sample'], error['side'], error['matcher'],
                error['rank'], error['error'], error['message'],
            ))
        lines.append('')
        config_refs = report['errors']['routing_configs']
        lines.append('Routing configs: before `%s` (`%s`), after `%s` (`%s`).' % (
            config_refs['before']['source'] or config_refs['before']['name'],
            config_refs['before']['sha256'],
            config_refs['after']['source'] or config_refs['after']['name'],
            config_refs['after']['sha256'],
        ))
    return '\n'.join(lines)


def _load_matcher_arg(value):
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if value.startswith('[') or value.startswith('{'):
        try:
            return json.loads(value)
        except ValueError as error:
            raise ImpactError('invalid inline matcher JSON: %s' % error)
    return value


def _fail_on(report, categories):
    summary = report['summary']
    hits = []
    for category in categories:
        category = category.strip()
        if not category:
            continue
        if category == 'error':
            if summary['error_affected_samples']:
                hits.append(category)
        elif category in summary and summary[category]:
            hits.append(category)
    return hits


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='filetype-impact',
        description=(
            'Compare matcher precedence and isolation routing before/after '
            'installing a file type recogniser.'
        ),
    )
    parser.add_argument(
        '--samples', required=True,
        help='JSON manifest or mapping of sample name to prefix data',
    )
    parser.add_argument(
        '--before-matchers',
        help='matcher registry JSON or comma separated matcher refs',
    )
    parser.add_argument(
        '--after-matchers',
        help='matcher registry JSON or comma separated matcher refs',
    )
    parser.add_argument('--before-routes', help='before routing config JSON')
    parser.add_argument('--after-routes', help='after routing config JSON')
    parser.add_argument(
        '--new-matcher', action='append', default=[],
        help='third-party matcher ref inserted at rank 1 in --after',
    )
    parser.add_argument(
        '--format', choices=('text', 'json', 'markdown'), default='text',
    )
    parser.add_argument('--output', help='write report to this path')
    parser.add_argument(
        '--no-configs', action='store_true',
        help='omit full routing config bodies from JSON output',
    )
    parser.add_argument(
        '--strict', action='store_true',
        help='propagate matcher exceptions instead of recording them',
    )
    parser.add_argument(
        '--fail-on', default='',
        help='comma separated summary keys that should exit non-zero',
    )
    parser.add_argument(
        '--version', action='version', version='%(prog)s 1',
    )
    args = parser.parse_args(argv)

    base_dir = os.path.dirname(os.path.abspath(args.samples))
    try:
        samples = normalize_samples(args.samples, base_dir=base_dir)
        before_matchers = _load_matcher_arg(args.before_matchers)
        after_matchers = _load_matcher_arg(args.after_matchers)
        if args.new_matcher:
            existing = normalize_matchers(after_matchers, base_dir=base_dir)
            inserted = [
                _resolve_matcher(ref) for ref in args.new_matcher
            ]
            after_matchers = inserted + existing

        if args.strict:
            before_list = normalize_matchers(before_matchers, base_dir)
            after_list = normalize_matchers(after_matchers, base_dir)
            # A preflight pass keeps strict mode from producing a partial
            # report if a matcher raises.
            for sample in samples:
                ranked_matches(sample.prefix, before_list, on_error='raise')
                ranked_matches(sample.prefix, after_list, on_error='raise')

        report = assess(
            samples, before=before_matchers, after=after_matchers,
            before_routes=args.before_routes,
            after_routes=args.after_routes,
            include_configs=not args.no_configs,
            metadata={'samples_source': os.path.abspath(args.samples)},
        )
    except ImpactError as error:
        parser.error(str(error))
        return 2

    if args.format == 'json':
        output = json.dumps(report, indent=2, sort_keys=True)
    elif args.format == 'markdown':
        output = render_markdown(report)
    else:
        output = render_text(report)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fp:
            fp.write(output)
            if not output.endswith('\n'):
                fp.write('\n')
    else:
        print(output)

    hits = _fail_on(report, args.fail_on.split(','))
    if hits:
        sys.stderr.write('fail-on matched: %s\n' % ', '.join(hits))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
