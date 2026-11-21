import pytest

from detect_secrets.audit import receipt as receipt_mod
from detect_secrets.audit.receipt import create_receipt
from detect_secrets.audit.receipt import derive_scope_key
from detect_secrets.audit.receipt import DisclosureScope
from detect_secrets.audit.receipt import publish_summary
from detect_secrets.audit.receipt import reconcile
from detect_secrets.audit.receipt import ReceiptSignatureError
from detect_secrets.audit.receipt import ReceiptWindowError
from detect_secrets.audit.receipt import transfer_filenames
from detect_secrets.audit.receipt import UnknownScopeError
from detect_secrets.audit.receipt import verify_receipt
from detect_secrets.audit.receipt import verify_receipt_with_master_key


MASTER_KEY = b'central-security-group-master-key'

WINDOW_START = 1_700_000_000
WINDOW_END = 1_700_100_000
INSIDE_WINDOW = WINDOW_START + 500
AFTER_WINDOW = WINDOW_END + 1


@pytest.fixture
def fictional_report():
    """A fictional central audit report spanning two departments."""
    return {
        'results': [
            {
                'filename': 'dept_a/app.py',
                'lines': {3: 'token = "a-real-secret"'},
                'types': ['Secret Keyword'],
                'category': 'VERIFIED_TRUE',
                'secrets': 'a-real-secret',
            },
            {
                'filename': 'dept_a/config.py',
                'lines': {7: 'password = "a-false-positive"'},
                'types': ['Secret Keyword'],
                'category': 'VERIFIED_FALSE',
                'secrets': 'a-false-positive',
            },
            {
                'filename': 'dept_b/service.py',
                'lines': {12: 'aws = "AKIAEXAMPLEB"'},
                'types': ['AWS Access Key'],
                'category': 'VERIFIED_TRUE',
                'secrets': 'AKIAEXAMPLEB',
            },
            {
                'filename': 'dept_b/unused.py',
                'lines': {1: 'api_key = "b-unverified"'},
                'types': ['Secret Keyword'],
                'category': 'UNVERIFIED',
                'secrets': 'b-unverified',
            },
        ],
    }


@pytest.fixture
def scope_a():
    return DisclosureScope(
        scope_id='dept-a',
        filenames=('dept_a/app.py', 'dept_a/config.py'),
        epoch='2026-10',
        not_before=WINDOW_START,
        not_after=WINDOW_END,
    )


@pytest.fixture
def scope_b():
    return DisclosureScope(
        scope_id='dept-b',
        filenames=('dept_b/service.py', 'dept_b/unused.py'),
        epoch='2026-10',
        not_before=WINDOW_START,
        not_after=WINDOW_END,
    )


def _key(scope):
    return derive_scope_key(MASTER_KEY, scope.scope_id, scope.epoch)


def _sign_all(report, scope):
    summary = publish_summary(report, scope, _key(scope))
    return create_receipt(
        scope,
        _key(scope),
        [
            {'marker': entry['marker'], 'disposition': entry['category']}
            for entry in summary['results']
            if entry['category'] in receipt_mod.APPROVED_CATEGORIES
        ],
        signed_at=INSIDE_WINDOW,
    )


class TestScopedSummary:
    def test_each_department_only_sees_its_own_files(
        self, fictional_report, scope_a, scope_b,
    ):
        summary_a = publish_summary(fictional_report, scope_a, _key(scope_a))
        summary_b = publish_summary(fictional_report, scope_b, _key(scope_b))

        assert {e['filename'] for e in summary_a['results']} == {
            'dept_a/app.py', 'dept_a/config.py',
        }
        assert {e['filename'] for e in summary_b['results']} == {
            'dept_b/service.py', 'dept_b/unused.py',
        }
        for summary in (summary_a, summary_b):
            for entry in summary['results']:
                assert 'secrets' not in entry

    def test_markers_rotate_across_scopes_and_epochs(self, fictional_report, scope_a):
        other_scope = scope_a._replace(scope_id='dept-b')
        other_epoch = scope_a._replace(epoch='2026-11')

        base = publish_summary(fictional_report, scope_a, _key(scope_a))
        cross_scope = publish_summary(fictional_report, other_scope, _key(other_scope))
        next_epoch = publish_summary(fictional_report, other_epoch, _key(other_epoch))

        base_markers = {e['marker'] for e in base['results']}
        assert base_markers.isdisjoint(e['marker'] for e in cross_scope['results'])
        assert base_markers.isdisjoint(e['marker'] for e in next_epoch['results'])


class TestReceiptVerification:
    def test_valid_receipt_roundtrip(self, fictional_report, scope_a):
        receipt = _sign_all(fictional_report, scope_a)
        assert verify_receipt(receipt, scope_a, _key(scope_a), at_time=INSIDE_WINDOW)

    def test_receipt_rejected_outside_window(self, fictional_report, scope_a):
        receipt = _sign_all(fictional_report, scope_a)
        with pytest.raises(ReceiptWindowError):
            verify_receipt(receipt, scope_a, _key(scope_a), at_time=AFTER_WINDOW)

    def test_receipt_rejected_for_foreign_scope(
        self, fictional_report, scope_a, scope_b,
    ):
        receipt = _sign_all(fictional_report, scope_a)
        with pytest.raises(UnknownScopeError):
            verify_receipt(receipt, scope_b, _key(scope_b), at_time=INSIDE_WINDOW)

    def test_tampered_disposition_rejected(self, fictional_report, scope_a):
        receipt = _sign_all(fictional_report, scope_a)
        receipt['dispositions'][0]['disposition'] = 'VERIFIED_FALSE'
        with pytest.raises(ReceiptSignatureError):
            verify_receipt(receipt, scope_a, _key(scope_a), at_time=INSIDE_WINDOW)

    def test_security_group_reverifies_expired_receipt(
        self, fictional_report, scope_a, scope_b,
    ):
        receipt = _sign_all(fictional_report, scope_a)
        with pytest.raises(ReceiptWindowError):
            verify_receipt(receipt, scope_a, _key(scope_a), at_time=AFTER_WINDOW)

        assert verify_receipt_with_master_key(
            receipt, MASTER_KEY, scopes=[scope_a, scope_b],
        )


class TestReconcile:
    def test_all_approved_dispositions_delivered(
        self, fictional_report, scope_a, scope_b,
    ):
        receipts = [
            _sign_all(fictional_report, scope_a),
            _sign_all(fictional_report, scope_b),
        ]
        result = reconcile(
            fictional_report, [scope_a, scope_b], receipts, MASTER_KEY,
        )
        assert result.ok
        # UNVERIFIED findings do not require sign-off.
        assert len(result.covered) == 3

    def test_missing_disposition_flagged(self, fictional_report, scope_a, scope_b):
        result = reconcile(
            fictional_report, [scope_a, scope_b],
            [_sign_all(fictional_report, scope_a)],
            MASTER_KEY,
        )
        assert not result.ok
        assert len(result.missing) == 1

    def test_foreign_marker_flagged(self, fictional_report, scope_a, scope_b):
        summary_b = publish_summary(fictional_report, scope_b, _key(scope_b))
        foreign_marker = summary_b['results'][0]['marker']
        receipt = create_receipt(
            scope_a,
            _key(scope_a),
            [
                {'marker': e['marker'], 'disposition': 'VERIFIED_TRUE'}
                for e in publish_summary(fictional_report, scope_a, _key(scope_a))['results']
            ] + [{'marker': foreign_marker, 'disposition': 'VERIFIED_TRUE'}],
            signed_at=INSIDE_WINDOW,
        )
        result = reconcile(
            fictional_report, [scope_a, scope_b], [receipt], MASTER_KEY,
        )
        assert result.foreign == [foreign_marker]


class TestTransferOfResponsibility:
    def test_handover_rescopes_visibility(
        self, fictional_report, scope_a, scope_b,
    ):
        moved_scope_a, moved_scope_b = transfer_filenames(
            scope_a, scope_b,
            filenames=['dept_a/config.py'],
            epoch='2026-11',
            not_before=WINDOW_START,
            not_after=WINDOW_END,
        )

        summary_old = publish_summary(fictional_report, moved_scope_a, _key(moved_scope_a))
        summary_new = publish_summary(fictional_report, moved_scope_b, _key(moved_scope_b))

        assert {e['filename'] for e in summary_old['results']} == {'dept_a/app.py'}
        assert {e['filename'] for e in summary_new['results']} == {
            'dept_b/service.py', 'dept_b/unused.py', 'dept_a/config.py',
        }

        # Markers rotated: the old department cannot reuse its previous
        # marker for the transferred finding.
        old_marker = {
            e['marker']
            for e in publish_summary(fictional_report, scope_a, _key(scope_a))['results']
            if e['filename'] == 'dept_a/config.py'
        }
        new_markers = {e['marker'] for e in summary_new['results']}
        assert old_marker.isdisjoint(new_markers)

        # Old receipts no longer verify against the re-issued scopes.
        stale_receipt = _sign_all(fictional_report, scope_a)
        with pytest.raises(UnknownScopeError):
            verify_receipt(
                stale_receipt, moved_scope_a, _key(moved_scope_a),
                at_time=INSIDE_WINDOW,
            )

        # After handover, the new department's sign-off covers the
        # transferred finding and reconciliation passes.
        receipts = [
            _sign_all(fictional_report, moved_scope_a),
            _sign_all(fictional_report, moved_scope_b),
        ]
        result = reconcile(
            fictional_report, [moved_scope_a, moved_scope_b], receipts, MASTER_KEY,
        )
        assert result.ok
        assert len(result.covered) == 3
