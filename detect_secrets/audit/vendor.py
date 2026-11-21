"""
Offline distribution of audit results to multiple vendors.

The regular audit commands assume that the person looking at the baseline is allowed to
see every result.  That is not true when different vendors review different parts of a
repository.  This module keeps that separation explicit:

* A small manifest assigns paths to vendors.  Assignments may overlap, which is useful for
  jointly-owned directories.
* Every vendor receives a self-contained, redacted export.  It only contains findings for
  paths assigned to that vendor, and never contains raw secrets or source snippets.
* Vendor responses are merged into a master state file.  Reviews are kept per vendor, so the
  primary reviewer can see contradictory conclusions on the same finding.
* An accepted review that has been signed off is immutable.  Late or stale feedback is
  recorded, but it cannot silently replace that accepted version.
"""
import fnmatch
import hashlib
import json
import os
import re
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Tuple

from ..core import baseline
from ..core.potential_secret import PotentialSecret
from ..exceptions import InvalidBaselineError
from ..exceptions import UnableToReadBaselineError
from ..exceptions import VendorDistributionError
from .common import get_baseline_from_file


EXPORT_FORMAT = 'detect-secrets-vendor-export'
STATE_FORMAT = 'detect-secrets-vendor-audit-state'
FORMAT_VERSION = 1

STATUS_TRUE_POSITIVE = 'true_positive'
STATUS_FALSE_POSITIVE = 'false_positive'
STATUS_UNREVIEWED = 'unreviewed'

_TRUE_VALUES = {
    'true',
    'yes',
    'y',
    'real',
    'confirmed',
    'true_positive',
    'truepositive',
    'secret',
}
_FALSE_VALUES = {
    'false',
    'no',
    'n',
    'fake',
    'false_positive',
    'falsepositive',
    'not_secret',
    'notsecret',
}
_UNREVIEWED_VALUES = {
    '',
    'unknown',
    'unreviewed',
    'pending',
    'skip',
    'unlabelled',
    'unlabeled',
}


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def load_vendor_manifest(filename: str) -> Dict[str, List[str]]:
    """
    Load a vendor -> paths manifest.

    Supported shapes (all equivalent):

        {"vendors": [{"id": "vendor-a", "paths": ["src/a/"]}]}
        {"vendors": {"vendor-a": ["src/a/"]}}
        {"vendors": {"vendor-a": {"paths": ["src/a/"]}}}

    ``suppliers`` and ``groups`` are accepted as aliases for ``vendors``.
    """
    try:
        with open(filename) as f:
            data = json.load(f)
    except (IOError, OSError, json.decoder.JSONDecodeError) as e:
        raise VendorDistributionError(f'Unable to read vendor manifest {filename}: {e}')

    return normalize_vendor_manifest(data)


def normalize_vendor_manifest(data: Any) -> Dict[str, List[str]]:
    if not isinstance(data, dict):
        raise VendorDistributionError('Vendor manifest must be a JSON object.')

    raw_vendors: Any = None
    for key in ('vendors', 'suppliers', 'groups'):
        if key in data:
            raw_vendors = data[key]
            break

    if raw_vendors is None:
        # Also accept a bare mapping of vendor id to paths.
        raw_vendors = data

    entries: List[Tuple[str, Any]] = []
    if isinstance(raw_vendors, dict):
        entries = list(raw_vendors.items())
    elif isinstance(raw_vendors, list):
        for entry in raw_vendors:
            if not isinstance(entry, dict):
                raise VendorDistributionError('Each vendor entry must be a JSON object.')
            vendor_id = entry.get('id', entry.get('name'))
            if not vendor_id:
                raise VendorDistributionError('Each vendor entry needs an "id".')
            entries.append((str(vendor_id), entry))
    else:
        raise VendorDistributionError('"vendors" must be a list or an object.')

    vendors: Dict[str, List[str]] = {}
    for raw_id, value in entries:
        vendor_id = str(raw_id).strip()
        _validate_vendor_id(vendor_id)
        if vendor_id in vendors:
            raise VendorDistributionError(f'Duplicate vendor id: {vendor_id}')

        if isinstance(value, dict):
            paths = value.get('paths', [])
        elif isinstance(value, list):
            paths = value
        elif isinstance(value, str):
            paths = [value]
        else:
            raise VendorDistributionError(
                f'Vendor {vendor_id!r} needs a "paths" list.',
            )

        if not isinstance(paths, list) or not paths:
            raise VendorDistributionError(
                f'Vendor {vendor_id!r} must be assigned at least one path.',
            )

        normalized: List[str] = []
        for path in paths:
            if not isinstance(path, str) or not path.strip():
                raise VendorDistributionError(
                    f'Vendor {vendor_id!r} contains an invalid path.',
                )
            normalized.append(_normalize_pattern(path))

        vendors[vendor_id] = sorted(set(normalized))

    if not vendors:
        raise VendorDistributionError('Vendor manifest does not assign any paths.')

    return vendors


def manifest_digest(vendors: Mapping[str, Sequence[str]]) -> str:
    payload = json.dumps(
        {vendor: list(sorted(paths)) for vendor, paths in vendors.items()},
        separators=(',', ':'),
        sort_keys=True,
    )
    return _sha256(payload.encode('utf-8'))


def export_vendor_packages(
    baseline_file: str,
    manifest_file: str,
    output_dir: str,
    exported_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Write one redacted export per vendor, plus the master state file.

    Re-exporting into the same directory preserves prior reviews and increments each
    vendor's export revision.
    """
    vendors = load_vendor_manifest(manifest_file)
    digest = manifest_digest(vendors)
    timestamp = exported_at or utc_timestamp()

    raw_baseline = _load_raw_baseline(baseline_file)
    fingerprint = _baseline_fingerprint(baseline_file)
    secrets = _load_baseline_collection(baseline_file)

    if not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir)
        except OSError as e:
            raise VendorDistributionError(
                f'Unable to create vendor export directory {output_dir}: {e}',
            )

    state_path = os.path.join(output_dir, 'master-state.json')
    state = _load_or_create_state(
        state_path=state_path,
        raw_baseline=raw_baseline,
        fingerprint=fingerprint,
        digest=digest,
        secrets=secrets,
        timestamp=timestamp,
    )

    summary: Dict[str, Any] = {
        'state': state_path,
        'output_dir': output_dir,
        'baseline_fingerprint': fingerprint,
        'vendors': {},
    }

    # Keep this deterministic.  It also makes it obvious that a vendor export never
    # contains another vendor's package.
    for vendor_id in sorted(vendors):
        paths = vendors[vendor_id]
        vendor_state = state['vendors'].setdefault(vendor_id, {})
        vendor_state['paths'] = list(paths)
        vendor_state['revision'] = int(vendor_state.get('revision', 0)) + 1
        vendor_state.setdefault('latest_response_revision', 0)
        vendor_state['last_exported_at'] = timestamp

        package = _build_vendor_package(
            state=state,
            vendor_id=vendor_id,
            paths=paths,
            revision=vendor_state['revision'],
            timestamp=timestamp,
        )
        package_path = os.path.join(output_dir, _vendor_filename(vendor_id))
        _write_json(package_path, package)

        summary['vendors'][vendor_id] = {
            'file': package_path,
            'revision': vendor_state['revision'],
            'findings': len(package['findings']),
            'summary': package['summary'],
        }

    state['updated_at'] = timestamp
    state['exported_at'] = timestamp
    _write_json(state_path, state)

    return summary


def merge_vendor_responses(
    state_file: str,
    response_files: Sequence[str],
    baseline_file: Optional[str] = None,
    merged_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Merge vendor responses into the master state file.

    A response is stale when its revision is older than the last response seen from that
    vendor.  Stale feedback is retained for the primary reviewer, but it cannot become the
    accepted decision.  Signed accepted decisions are never replaced automatically.
    """
    timestamp = merged_at or utc_timestamp()
    state = load_state(state_file)

    if baseline_file is not None:
        expected_fingerprint = state.get('baseline_fingerprint')
        actual_fingerprint = _baseline_fingerprint(baseline_file)
        if expected_fingerprint and expected_fingerprint != actual_fingerprint:
            raise VendorDistributionError(
                'Baseline changed since the vendor packages were exported. '
                'Create a new export instead of merging into the old state.',
            )

    expanded_responses: List[str] = []
    for filename in response_files:
        if os.path.isdir(filename):
            expanded_responses.extend(
                os.path.join(filename, name)
                for name in sorted(os.listdir(filename))
                if name.endswith('.json') and name != 'master-state.json'
            )
        else:
            expanded_responses.append(filename)

    if not expanded_responses:
        raise VendorDistributionError('No vendor responses were supplied.')

    merged: List[Dict[str, Any]] = []
    for response_file in expanded_responses:
        response = _load_vendor_response(response_file)
        merged.append(_merge_single_response(state, response, timestamp))
        _refresh_conflicts(state, timestamp)

    _refresh_conflicts(state, timestamp)
    state['updated_at'] = timestamp
    _write_json(state_file, state)

    conflict_report = _build_conflict_report(state)
    return {
        'state': state_file,
        'merged': merged,
        'conflicts': conflict_report['conflicts'],
        'summary': conflict_report['summary'],
    }


def load_state(filename: str) -> Dict[str, Any]:
    try:
        with open(filename) as f:
            state = json.load(f)
    except (IOError, OSError, json.decoder.JSONDecodeError) as e:
        raise VendorDistributionError(f'Unable to read vendor state {filename}: {e}')

    if not isinstance(state, dict) or state.get('format') != STATE_FORMAT:
        raise VendorDistributionError(f'{filename} is not a vendor audit state file.')
    if state.get('format_version') != FORMAT_VERSION:
        raise VendorDistributionError(
            f'Unsupported vendor state version: {state.get("format_version")}',
        )
    if not isinstance(state.get('findings'), dict):
        raise VendorDistributionError('Vendor state is missing its findings.')
    if not isinstance(state.get('vendors'), dict):
        raise VendorDistributionError('Vendor state is missing its vendor assignments.')

    return state


def report_conflicts(state_file: str) -> Dict[str, Any]:
    return _build_conflict_report(load_state(state_file))


def format_conflict_report(report: Mapping[str, Any]) -> str:
    conflicts = report.get('conflicts', [])
    if not conflicts:
        return 'No vendor review conflicts.'

    lines = ['Vendor review conflicts:']
    for conflict in conflicts:
        lines.append('')
        lines.append(
            'Conflict: {path}:{line} ({secret_type})'.format(
                path=conflict['path'],
                line=conflict['line_number'],
                secret_type=conflict['type'],
            ),
        )
        lines.append(f'  Finding:   {conflict["finding_id"]}')
        for vendor_id, status in sorted(conflict['statuses'].items()):
            lines.append(f'  {vendor_id}: {status}')
        for vendor_id, feedback in sorted(conflict.get('late_feedback', {}).items()):
            for item in feedback:
                lines.append(
                    '  {vendor}: {status} '
                    '(late feedback, revision {revision})'.format(
                        vendor=vendor_id,
                        status=item['status'],
                        revision=item['revision'],
                    ),
                )

        accepted = conflict['accepted']
        signed = ' (signed off)' if accepted.get('signed_off') else ''
        lines.append(
            '  Accepted:  {status} via {source}, revision {revision}{signed}'.format(
                status=accepted['status'],
                source=accepted['source'],
                revision=accepted['revision'],
                signed=signed,
            ),
        )
        lines.append(f'  Reason:    {conflict["reason"]}')

    return '\n'.join(lines)


def sign_off_accepted(state_file: str, signed_at: Optional[str] = None) -> Dict[str, Any]:
    """
    Mark reviewed, accepted decisions as signed off by the primary reviewer.

    This does not resolve conflicts.  It only freezes the currently accepted version, so
    late feedback remains visible but cannot silently replace it.
    """
    timestamp = signed_at or utc_timestamp()
    state = load_state(state_file)

    signed = 0
    skipped = 0
    for finding in state['findings'].values():
        accepted = finding.get('accepted') or {}
        if accepted.get('status') == STATUS_UNREVIEWED:
            skipped += 1
            continue

        accepted['signed_off'] = True
        accepted['signed_at'] = timestamp
        signed += 1

    state['updated_at'] = timestamp
    _refresh_conflicts(state, timestamp)
    _write_json(state_file, state)

    return {
        'state': state_file,
        'signed_off': signed,
        'skipped_unreviewed': skipped,
        'conflicts': _build_conflict_report(state)['conflicts'],
    }


def _load_or_create_state(
    state_path: str,
    raw_baseline: Mapping[str, Any],
    fingerprint: str,
    digest: str,
    secrets: Iterable[Tuple[str, PotentialSecret]],
    timestamp: str,
) -> Dict[str, Any]:
    if os.path.exists(state_path):
        state = load_state(state_path)
        if state.get('baseline_fingerprint') != fingerprint:
            raise VendorDistributionError(
                'Baseline does not match the existing master state. '
                'Use a new output directory for a new baseline.',
            )
        if state.get('manifest_digest') != digest:
            raise VendorDistributionError(
                'Vendor manifest changed. Use a new output directory, or keep the '
                'original assignments for this review round.',
            )
        return state

    findings: Dict[str, Any] = {}
    for filename, secret in secrets:
        record = _new_finding_record(filename, secret, timestamp)
        findings[record['finding_id']] = record

    return {
        'format': STATE_FORMAT,
        'format_version': FORMAT_VERSION,
        'baseline_version': str(raw_baseline.get('version', '')),
        'baseline_fingerprint': fingerprint,
        'manifest_digest': digest,
        'created_at': timestamp,
        'updated_at': timestamp,
        'exported_at': timestamp,
        'vendors': {},
        'findings': findings,
    }


def _new_finding_record(
    filename: str,
    secret: PotentialSecret,
    timestamp: str,
) -> Dict[str, Any]:
    status = status_from_secret(secret)
    return {
        'finding_id': finding_id(filename, secret.type, secret.secret_hash),
        'path': filename,
        'type': secret.type,
        'line_number': secret.line_number,
        'hashed_secret': secret.secret_hash,
        'verified': bool(secret.is_verified),
        'baseline_status': status,
        'accepted': {
            'status': status,
            'source': 'baseline',
            'revision': 0,
            'signed_off': False,
            'updated_at': timestamp,
        },
        'reviews': {},
        'late_feedback': [],
        'conflict': None,
    }


def _build_vendor_package(
    state: Mapping[str, Any],
    vendor_id: str,
    paths: Sequence[str],
    revision: int,
    timestamp: str,
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    summary = {
        STATUS_TRUE_POSITIVE: 0,
        STATUS_FALSE_POSITIVE: 0,
        STATUS_UNREVIEWED: 0,
    }

    for finding in state['findings'].values():
        if not path_is_owned(finding['path'], paths):
            continue

        review = finding['reviews'].get(vendor_id)
        status = review['status'] if review else finding['baseline_status']
        summary[status] += 1

        item: Dict[str, Any] = {
            'finding_id': finding['finding_id'],
            'path': finding['path'],
            'line_number': finding['line_number'],
            'type': finding['type'],
            'verified': finding['verified'],
            'status': status,
            'review_state': _review_state(review),
        }
        if review:
            item['last_review'] = {
                'status': review['status'],
                'revision': review['revision'],
                'reviewer': review.get('reviewer'),
                'note': review.get('note'),
                'signed_off': bool(review.get('signed_off')),
                'received_at': review.get('received_at'),
            }
        findings.append(item)

    findings.sort(
        key=lambda item: (item['path'], item['line_number'], item['type'], item['finding_id']),
    )
    return {
        'format': EXPORT_FORMAT,
        'format_version': FORMAT_VERSION,
        'vendor': vendor_id,
        'revision': revision,
        'exported_at': timestamp,
        'baseline_fingerprint': state['baseline_fingerprint'],
        'baseline_version': state.get('baseline_version', ''),
        'scope': {'paths': list(paths)},
        'summary': {
            'total': len(findings),
            'true_positive': summary[STATUS_TRUE_POSITIVE],
            'false_positive': summary[STATUS_FALSE_POSITIVE],
            'unreviewed': summary[STATUS_UNREVIEWED],
        },
        'findings': findings,
    }


def _review_state(review: Optional[Mapping[str, Any]]) -> str:
    if not review:
        return 'unreviewed'
    if review.get('signed_off'):
        return 'signed_off'
    return 'submitted'


def _load_vendor_response(filename: str) -> Dict[str, Any]:
    try:
        with open(filename) as f:
            response = json.load(f)
    except (IOError, OSError, json.decoder.JSONDecodeError) as e:
        raise VendorDistributionError(f'Unable to read vendor response {filename}: {e}')

    if not isinstance(response, dict) or response.get('format') != EXPORT_FORMAT:
        raise VendorDistributionError(f'{filename} is not a vendor export/response file.')
    if response.get('format_version') != FORMAT_VERSION:
        raise VendorDistributionError(
            f'Unsupported vendor response version: {response.get("format_version")}',
        )
    if not response.get('vendor'):
        raise VendorDistributionError(f'{filename} does not identify a vendor.')
    if not isinstance(response.get('findings'), list):
        raise VendorDistributionError(f'{filename} is missing its findings list.')

    return response


def _merge_single_response(
    state: Dict[str, Any],
    response: Mapping[str, Any],
    timestamp: str,
) -> Dict[str, Any]:
    vendor_id = str(response['vendor'])
    vendor_state = state['vendors'].get(vendor_id)
    if vendor_state is None:
        raise VendorDistributionError(f'Unknown vendor in response: {vendor_id}')

    expected_fingerprint = state.get('baseline_fingerprint')
    response_fingerprint = response.get('baseline_fingerprint')
    if response_fingerprint and expected_fingerprint != response_fingerprint:
        raise VendorDistributionError(
            f'Vendor {vendor_id} responded to a different baseline export.',
        )

    try:
        revision = int(response.get('revision', vendor_state.get('revision', 0)))
    except (TypeError, ValueError):
        raise VendorDistributionError(f'Vendor {vendor_id} response has an invalid revision.')

    allowed_ids = {
        finding['finding_id']
        for finding in state['findings'].values()
        if path_is_owned(finding['path'], vendor_state.get('paths', []))
    }
    last_revision = int(vendor_state.get('latest_response_revision', 0))
    # A second response for the same export revision is duplicate/late feedback.  It is
    # retained for the primary reviewer, but it does not replace what was already received.
    is_stale = revision <= last_revision

    updated = 0
    ignored = 0
    for entry in response['findings']:
        if not isinstance(entry, dict):
            raise VendorDistributionError(f'Vendor {vendor_id} response contains a bad entry.')

        item_id = entry.get('finding_id', entry.get('id'))
        if not item_id:
            raise VendorDistributionError(
                f'Vendor {vendor_id} response contains a finding without an id.',
            )
        item_id = str(item_id)
        if item_id not in allowed_ids:
            raise VendorDistributionError(
                f'Vendor {vendor_id} responded for a finding outside its assigned paths.',
            )

        finding = state['findings'][item_id]
        raw_status = entry.get('status', entry.get('decision', entry.get('is_secret')))
        status = normalize_status(raw_status)
        review = {
            'vendor': vendor_id,
            'status': status,
            'revision': revision,
            'reviewer': entry.get('reviewer'),
            'note': entry.get('note'),
            'signed_off': bool(entry.get('signed_off', False)),
            'exported_at': response.get('exported_at'),
            'received_at': timestamp,
        }

        if is_stale:
            _record_late_feedback(finding, review)
            ignored += 1
            continue

        finding['reviews'][vendor_id] = review
        updated += 1

    vendor_state['latest_response_revision'] = max(last_revision, revision)
    vendor_state['last_response_at'] = timestamp

    return {
        'vendor': vendor_id,
        'revision': revision,
        'updated': updated,
        'ignored_as_stale': ignored,
        'stale': is_stale,
    }


def _record_late_feedback(finding: Dict[str, Any], review: Mapping[str, Any]) -> None:
    late_feedback = finding.setdefault('late_feedback', [])
    late_feedback.append(
        {
            'vendor': review['vendor'],
            'status': review['status'],
            'revision': review['revision'],
            'reviewer': review.get('reviewer'),
            'note': review.get('note'),
            'signed_off': bool(review.get('signed_off')),
            'received_at': review['received_at'],
        },
    )


def _refresh_conflicts(state: Dict[str, Any], timestamp: str) -> None:
    for finding in state['findings'].values():
        _refresh_finding_conflict(finding, timestamp)


def _refresh_finding_conflict(finding: Dict[str, Any], timestamp: str) -> None:
    statuses = {
        vendor_id: review['status']
        for vendor_id, review in finding.get('reviews', {}).items()
        if review.get('status') != STATUS_UNREVIEWED
    }
    late_feedback: Dict[str, List[Dict[str, Any]]] = {}
    for item in finding.get('late_feedback', []):
        if item.get('status') == STATUS_UNREVIEWED:
            continue
        late_feedback.setdefault(item['vendor'], []).append(item)

    all_statuses = set(statuses.values())
    for items in late_feedback.values():
        all_statuses.update(item['status'] for item in items)

    accepted = finding.get('accepted') or {}
    accepted_status = accepted.get('status', STATUS_UNREVIEWED)
    conflicting = (
        STATUS_TRUE_POSITIVE in all_statuses and
        STATUS_FALSE_POSITIVE in all_statuses
    )

    signed_version_challenged = bool(
        accepted.get('signed_off') and
        any(status != accepted_status for status in all_statuses),
    )

    if not conflicting and not signed_version_challenged:
        finding['conflict'] = None
        _accept_latest_review(finding)
        return

    reason = 'opposite_conclusions'
    if not conflicting:
        reason = 'signed_version_challenged'

    finding['conflict'] = {
        'statuses': statuses,
        'late_feedback': late_feedback,
        'accepted': {
            'status': accepted_status,
            'source': accepted.get('source', 'baseline'),
            'revision': accepted.get('revision', 0),
            'signed_off': bool(accepted.get('signed_off')),
        },
        'reason': reason,
        'requires_master_review': True,
        'detected_at': timestamp,
    }


def _accept_latest_review(finding: Dict[str, Any]) -> None:
    accepted = finding.get('accepted') or {}
    if accepted.get('signed_off'):
        # Signed versions are immutable.  Any attempted change would have been caught as
        # a conflict above.
        return

    candidates = [
        (review, vendor_id)
        for vendor_id, review in finding.get('reviews', {}).items()
        if review.get('status') != STATUS_UNREVIEWED
    ]
    if not candidates:
        return

    review, vendor_id = sorted(
        candidates,
        key=lambda item: (
            int(item[0].get('revision', 0)),
            item[0].get('received_at', ''),
            item[1],
        ),
    )[-1]

    if int(review.get('revision', 0)) < int(accepted.get('revision', 0)):
        return

    finding['accepted'] = {
        'status': review['status'],
        'source': vendor_id,
        'revision': int(review.get('revision', 0)),
        'signed_off': bool(review.get('signed_off')),
        'updated_at': review['received_at'],
    }


def _build_conflict_report(state: Mapping[str, Any]) -> Dict[str, Any]:
    conflicts: List[Dict[str, Any]] = []
    for finding in state['findings'].values():
        conflict = finding.get('conflict')
        if not conflict:
            continue

        conflicts.append(
            {
                'finding_id': finding['finding_id'],
                'path': finding['path'],
                'line_number': finding['line_number'],
                'type': finding['type'],
                'statuses': conflict['statuses'],
                'late_feedback': conflict.get('late_feedback', {}),
                'accepted': conflict['accepted'],
                'reason': conflict['reason'],
                'requires_master_review': True,
            },
        )

    conflicts.sort(key=lambda item: (item['path'], item['line_number'], item['finding_id']))
    return {
        'conflicts': conflicts,
        'summary': {
            'findings': len(state['findings']),
            'conflicts': len(conflicts),
        },
    }


def normalize_status(value: Any) -> str:
    if isinstance(value, bool):
        return STATUS_TRUE_POSITIVE if value else STATUS_FALSE_POSITIVE

    normalized = re.sub(r'[\s\-]+', '_', str(value).strip().lower())
    if normalized in _TRUE_VALUES:
        return STATUS_TRUE_POSITIVE
    if normalized in _FALSE_VALUES:
        return STATUS_FALSE_POSITIVE
    if normalized in _UNREVIEWED_VALUES:
        return STATUS_UNREVIEWED

    raise VendorDistributionError(f'Unknown review status: {value!r}')


def status_from_secret(secret: PotentialSecret) -> str:
    if secret.is_secret is True:
        return STATUS_TRUE_POSITIVE
    if secret.is_secret is False:
        return STATUS_FALSE_POSITIVE
    return STATUS_UNREVIEWED


def finding_id(filename: str, secret_type: str, secret_hash: str) -> str:
    """
    Stable, opaque identifier for a baseline entry.

    The vendor never needs the raw hash to respond; this identifier is enough to correlate
    the response with the master state.
    """
    payload = '\0'.join((_normalize_filename(filename), secret_type, secret_hash))
    return _sha256(payload.encode('utf-8'))


def path_is_owned(filename: str, patterns: Sequence[str]) -> bool:
    normalized_filename = _normalize_filename(filename)
    for pattern in patterns:
        if _path_matches(normalized_filename, pattern):
            return True
    return False


def _path_matches(filename: str, pattern: str) -> bool:
    normalized_pattern = _normalize_pattern(pattern)
    if normalized_pattern == '.':
        return True

    candidates = {filename}
    if os.path.isabs(normalized_pattern):
        candidates.add(os.path.abspath(filename).replace('\\', '/'))

    for candidate in candidates:
        if _has_glob(normalized_pattern):
            if fnmatch.fnmatchcase(candidate, normalized_pattern):
                return True
        else:
            normalized_pattern = normalized_pattern.rstrip('/')
            if candidate == normalized_pattern:
                return True
            if candidate.startswith(normalized_pattern + '/'):
                return True

    return False


def _has_glob(pattern: str) -> bool:
    return any(character in pattern for character in ('*', '?', '['))


def _normalize_filename(filename: str) -> str:
    normalized = filename.replace('\\', '/')
    while normalized.startswith('./'):
        normalized = normalized[2:]
    return normalized.rstrip('/')


def _normalize_pattern(pattern: str) -> str:
    normalized = pattern.strip().replace('\\', '/')
    if normalized in ('.', './'):
        return '.'
    while normalized.startswith('./'):
        normalized = normalized[2:]
    if len(normalized) > 1:
        normalized = normalized.rstrip('/')
    return normalized


def _validate_vendor_id(vendor_id: str) -> None:
    if not vendor_id or vendor_id in ('.', '..'):
        raise VendorDistributionError('Vendor id cannot be empty.')
    if '/' in vendor_id or '\\' in vendor_id or '\0' in vendor_id:
        raise VendorDistributionError(f'Invalid vendor id: {vendor_id!r}')


def _vendor_filename(vendor_id: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', vendor_id).strip('._')
    if not safe:
        safe = 'vendor'
    if safe == 'master-state':
        safe = 'master-state-vendor'
    if safe != vendor_id:
        # Keep names distinct if two ids normalize to the same filename.
        safe = f'{safe}-{_sha256(vendor_id.encode("utf-8"))[:8]}'
    return f'{safe}.json'


def _load_raw_baseline(filename: str) -> Dict[str, Any]:
    try:
        return baseline.load_from_file(filename)
    except UnableToReadBaselineError as e:
        raise VendorDistributionError(f'Unable to read baseline {filename}: {e}')


def _load_baseline_collection(filename: str) -> Any:
    try:
        return get_baseline_from_file(filename)
    except InvalidBaselineError as e:
        raise VendorDistributionError(f'Invalid baseline {filename}: {e}')


def _baseline_fingerprint(filename: str) -> str:
    try:
        with open(filename, 'rb') as f:
            return _sha256(f.read())
    except (IOError, OSError) as e:
        raise VendorDistributionError(f'Unable to read baseline {filename}: {e}')


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_json(filename: str, data: Any) -> None:
    with open(filename, 'w') as f:
        f.write(json.dumps(data, indent=2, sort_keys=True) + '\n')
