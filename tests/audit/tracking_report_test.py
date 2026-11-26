import pytest

from detect_secrets.audit.tracking_report import generate_tracking_report


def make_ledger():
    return {
        'current_epoch': '2026-w48',
        'audiences': {
            'security-oncall': {
                'current_epoch': '2026-w48',
                'epochs': {
                    '2026-w47': {
                        'secret': 'w47-oncall-secret',
                        'expires_at': '2026-11-29T00:00:00Z',
                    },
                    '2026-w48': {
                        'secret': 'w48-oncall-secret',
                        'expires_at': '2026-12-06T00:00:00Z',
                        'replaces': '2026-w47',
                    },
                },
            },
            'partner-a': {
                'current_epoch': '2026-w48',
                'epochs': {
                    '2026-w48': {
                        'secret': 'w48-partner-secret',
                        'expires_at': '2026-12-06T00:00:00Z',
                    },
                },
            },
        },
        'tracking': {
            'finding-1': {
                'security-oncall': {
                    'status': 'active',
                },
                'partner-a': {
                    'status': 'active',
                },
            },
            'finding-2': {
                'security-oncall': {
                    'status': 'active',
                },
            },
            'retired-finding': {
                'security-oncall': {
                    'status': 'retired',
                },
            },
        },
    }


def test_generates_stable_alias_and_allows_same_audience_renewal():
    findings = [
        {
            'tracking_id': 'finding-1',
            'type': 'AWS Key',
            'filename': 'config/production.py',
            'line_number': 12,
            'hashed_secret': 'stable-cross-domain-hash',
            'secret_value': 'plaintext-secret',
        },
    ]
    ledger = make_ledger()

    first_report = generate_tracking_report(findings, 'security-oncall', ledger)
    second_report = generate_tracking_report(findings, 'security-oncall', ledger)

    assert first_report == second_report
    result = first_report['results'][0]
    assert result['tracking_alias'] != 'finding-1'
    assert result['previous_tracking_alias']
    assert result['previous_epoch'] == '2026-w47'
    assert 'stable-cross-domain-hash' not in str(first_report)
    assert 'plaintext-secret' not in str(first_report)


def test_renewal_links_only_to_alias_visible_to_same_audience():
    findings = [
        {
            'tracking_id': 'finding-1',
            'type': 'AWS Key',
            'filename': 'config/production.py',
            'line_number': 12,
        },
    ]
    ledger = make_ledger()

    oncall_report = generate_tracking_report(findings, 'security-oncall', ledger)
    partner_report = generate_tracking_report(findings, 'partner-a', ledger)

    oncall_result = oncall_report['results'][0]
    partner_result = partner_report['results'][0]
    assert oncall_result['tracking_alias'] != partner_result['tracking_alias']
    assert partner_result['tracking_alias'] != oncall_result['previous_tracking_alias']
    assert 'previous_tracking_alias' not in partner_result
    assert set(oncall_report.keys()) == {'audience', 'epoch', 'expires_at', 'results'}


def test_filters_unauthorized_and_retired_findings():
    findings = [
        {
            'tracking_id': 'finding-1',
            'type': 'AWS Key',
            'filename': 'config/production.py',
            'line_number': 12,
        },
        {
            'tracking_id': 'finding-2',
            'type': 'GitHub Token',
            'filename': 'config/development.py',
            'line_number': 3,
        },
        {
            'tracking_id': 'retired-finding',
            'type': 'Slup Token',
            'filename': 'config/retired.py',
            'line_number': 7,
        },
    ]

    report = generate_tracking_report(findings, 'partner-a', make_ledger())

    assert [result['tracking_id'] for result in report['results']] == []
    assert report['audience'] == 'partner-a'
    assert report['epoch'] == '2026-w48'


def test_rejects_unknown_audience():
    with pytest.raises(KeyError):
        generate_tracking_report([], 'unknown-audience', make_ledger())
