from collections import namedtuple
from datetime import datetime, timedelta

from .x509 import X509Certificate


Constraint = namedtuple('Constraint', ['source', 'name', 'time', 'certificate_alias'])
ServicePlan = namedtuple('ServicePlan', [
    'name', 'start_interval', 'constraints', 'limiting_constraint',
    'keystore_available_at', 'waiting_for_keystore'
])
DeploymentPlan = namedtuple('DeploymentPlan', [
    'start_interval', 'services', 'limiting_certificate_alias',
    'waiting_for_keystore'
])


def plan_service_cutover(services, keystores, approval_window, now=None):
    """
    Calculate valid cutover intervals for services using public certificates.

    Each service is a mapping containing ``name``, ``keystore``, ``certificate``,
    ``duration`` and optional ``start_offset``. Durations and offsets are in
    seconds. Service intervals use each service's actual start time; the top
    level interval uses the overall cutover start time. Keystore mappings
    contain ``name``, ``keystore`` and optional ``available_at``.
    ``approval_window`` is a ``(start, end)`` pair.
    """
    if now is None:
        now = datetime.utcnow()
    now = _as_datetime(now)
    window_start, window_end = [_as_datetime(value) for value in approval_window]
    keystore_by_name = _index_keystores(keystores)
    if not services:
        raise ValueError("At least one service is required")

    service_plans = []
    cumulative_duration = 0
    start_offsets = []
    for service_data in services:
        service = dict(service_data)
        duration = service['duration']
        start_offset = service.get('start_offset', cumulative_duration)
        start_offsets.append(start_offset)
        cumulative_duration += duration

        keystore_data = keystore_by_name[service['keystore']]
        keystore = keystore_data['keystore']
        keystore_available_at = _as_datetime(keystore_data.get('available_at', window_start))
        alias = service['certificate']
        certificate = X509Certificate(_certificate_bytes(keystore, alias))
        start_delay = timedelta(seconds=start_offset)
        duration_delay = timedelta(seconds=duration)

        constraints = [
            Constraint('approval_window', 'approval_window_start', window_start + start_delay, None),
            Constraint('approval_window', 'approval_window_end', window_end - duration_delay, None),
            Constraint('keystore', keystore_data['name'], keystore_available_at, None),
            Constraint('certificate', 'not_before', certificate.not_before, alias),
            Constraint('certificate', 'not_after', certificate.not_after - duration_delay, alias),
        ]
        lower_bound = max(constraint.time for constraint in constraints if not _is_latest_validation_constraint(constraint))
        upper_constraints = [constraint for constraint in constraints if _is_latest_validation_constraint(constraint)]
        upper_bound = min(constraint.time for constraint in upper_constraints)
        limiting_constraint = min(upper_constraints, key=lambda constraint: (constraint.time, constraint.name))
        waiting = keystore_available_at > now

        interval = (lower_bound, upper_bound) if lower_bound <= upper_bound else tuple()
        service_plans.append(ServicePlan(
            service['name'], interval, tuple(sorted(constraints, key=lambda constraint: constraint.time)),
            limiting_constraint, keystore_available_at, waiting
        ))

    if all(len(plan.start_interval) == 2 for plan in service_plans):
        overall_intervals = [
            (plan.start_interval[0] - timedelta(seconds=start_offset),
             plan.start_interval[1] - timedelta(seconds=start_offset))
            for plan, start_offset in zip(service_plans, start_offsets)
        ]
        overall_lower = max(interval[0] for interval in overall_intervals)
        overall_upper = min(interval[1] for interval in overall_intervals)
        overall_interval = (overall_lower, overall_upper) if overall_lower <= overall_upper else tuple()
    else:
        overall_interval = tuple()

    limiting_alias = None
    if len(overall_interval) == 2:
        limiting_constraints = [
            plan.limiting_constraint
            for plan, start_offset in zip(service_plans, start_offsets)
            if plan.start_interval[1] - timedelta(seconds=start_offset) == overall_interval[1]
        ]
        limiting_constraint = min(limiting_constraints, key=lambda constraint:
                                  (constraint.time, constraint.source, constraint.name))
        limiting_alias = limiting_constraint.certificate_alias

    return DeploymentPlan(
        overall_interval,
        tuple(service_plans),
        limiting_alias,
        tuple(plan.name for plan in service_plans if plan.waiting_for_keystore)
    )


def _index_keystores(keystores):
    indexed = {}
    for item in keystores:
        if isinstance(item, dict):
            name = item['name']
            indexed[name] = dict(item)
        else:
            name, keystore, available_at = item
            indexed[name] = {'name': name, 'keystore': keystore, 'available_at': available_at}
    return indexed


def _certificate_bytes(keystore, alias):
    entry = keystore.entries[alias]
    if hasattr(entry, 'cert'):
        return entry.cert
    cert_chain = entry.cert_chain
    first = cert_chain[0]
    return first[1] if isinstance(first, tuple) else first.cert


def _is_latest_validation_constraint(constraint):
    return constraint.name in ('approval_window_end', 'not_after')


def _as_datetime(value):
    if isinstance(value, datetime):
        return value
    return datetime.utcfromtimestamp(value)
