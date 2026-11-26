import hashlib
import hmac
from typing import Any
from typing import Dict
from typing import Mapping


TRACKING_TTL_SECONDS = 7 * 24 * 60 * 60


def generate_tracking_report(
    findings: list[Dict[str, Any]],
    audience: str,
    ledger: Mapping[str, Any],
) -> Dict[str, Any]:
    audience_ledger = ledger['audiences'][audience]
    epoch = audience_ledger['current_epoch']
    epoch_ledger = audience_ledger['epochs'][epoch]
    epoch_secret = _get_epoch_secret(epoch_ledger)
    audience_tracking = ledger['tracking']

    results = []
    for finding in findings:
        if not _is_processed_finding(finding):
            continue

        tracking_id = finding['tracking_id']
        permissions = audience_tracking.get(tracking_id, {}).get(audience)
        if not permissions or permissions.get('status') != 'active':
            continue

        result = {
            'type': finding['type'],
            'tracking_alias': _build_alias(audience, epoch, epoch_secret, tracking_id),
        }

        previous_epoch = epoch_ledger.get('replaces')
        if previous_epoch:
            previous_ledger = audience_ledger['epochs'][previous_epoch]
            result['previous_tracking_alias'] = _build_alias(
                audience,
                previous_epoch,
                _get_epoch_secret(previous_ledger),
                tracking_id,
            )
            result['previous_epoch'] = previous_epoch

        results.append(result)

    return {
        'audience': audience,
        'epoch': epoch,
        'expires_at': epoch_ledger['expires_at'],
        'ttl_seconds': TRACKING_TTL_SECONDS,
        'results': results,
    }


def _is_processed_finding(finding: Mapping[str, Any]) -> bool:
    return finding.get('is_secret') is True


def _get_epoch_secret(epoch_ledger: Mapping[str, Any]) -> str:
    secret = epoch_ledger['secret']
    if not isinstance(secret, str) or not secret:
        raise ValueError('Audience epoch secret must be a non-empty string.')
    return secret


def _build_alias(
    audience: str,
    epoch: str,
    epoch_secret: str,
    tracking_id: str,
) -> str:
    digest = hmac.new(
        epoch_secret.encode('utf-8'),
        '\0'.join((audience, epoch, tracking_id)).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    return f'{epoch}:{digest}'
