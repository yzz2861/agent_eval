import json
from pathlib import Path

import pytest

import sqlparse
from sqlparse.exceptions import PrecheckInputError
from sqlparse.precheck import (
    ApprovedChange,
    InitialObject,
    precheck_migration,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / 'examples' / 'privilege_precheck'


def _initial():
    return [
        InitialObject(
            object_id='public.orders',
            schema='public',
            name='orders',
            kind='table',
            privileges={'analyst': ['SELECT']},
        )
    ]


def _approvals():
    return [
        ApprovedChange(
            object_id='public.orders',
            grantee='analyst',
            privilege='UPDATE',
            action='grant',
        )
    ]


def _example(name):
    return (EXAMPLES / name).read_text(encoding='utf-8')


def _grants(result):
    return [
        record for record in result.statements
        if record['kind'] == 'grant'
    ]


def test_example_savepoint_rollback_is_approved():
    result = precheck_migration(
        _example('migration_allowed.sql'),
        _initial(),
        _approvals(),
    )

    assert result.decision == 'approved'
    assert result.release_ok is True
    assert result.status == 'known'
    assert result.privilege_diff['added'] == [
        {
            'object_id': 'public.orders',
            'schema': 'public',
            'object_name': 'orders_archive',
            'grantee': 'analyst',
            'grantee_key': 'analyst',
            'privilege': 'UPDATE',
            'action': 'grant',
            'approved': True,
        }
    ]
    assert result.privilege_diff['removed'] == []
    assert result.privilege_diff['unapproved'] == []
    assert result.post_commit_objects[0]['name'] == 'orders_archive'

    delete_grant = next(
        record for record in _grants(result)
        if any(effect['privilege'] == 'DELETE'
               for effect in record['effects'])
    )
    assert delete_grant['status'] == 'rolled_back'
    assert 'ROLLBACK TO SAVEPOINT' in delete_grant['reason']

    rename = next(
        record for record in result.statements
        if record['kind'] == 'rename'
    )
    assert 'stable object identity public.orders' in rename['reason']


def test_example_savepoint_after_grant_requires_manual_review():
    result = precheck_migration(
        _example('migration_manual_review.sql'),
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert result.release_ok is False
    assert result.status == 'known'
    unapproved = result.privilege_diff['unapproved']
    assert len(unapproved) == 1
    assert unapproved[0]['privilege'] == 'DELETE'
    assert unapproved[0]['object_id'] == 'public.orders'
    assert unapproved[0]['object_name'] == 'orders_archive'
    assert unapproved[0]['approved'] is False

    delete_grant = next(
        record for record in _grants(result)
        if any(effect['privilege'] == 'DELETE'
               for effect in record['effects'])
    )
    assert delete_grant['status'] == 'committed'
    rollback = next(
        record for record in result.statements
        if record["kind"] == "rollback_to"
    )
    assert "Restored the state" in rollback["reason"]


def test_example_files_have_same_statements_but_different_savepoint_scope():
    allowed = [
        line.strip() for line in
        _example("migration_allowed.sql").splitlines()
        if line.strip() and not line.strip().startswith("--")
    ]
    manual = [
        line.strip() for line in
        _example("migration_manual_review.sql").splitlines()
        if line.strip() and not line.strip().startswith("--")
    ]
    assert sorted(allowed) == sorted(manual)
    savepoint = "SAVEPOINT before_destructive_grant;"
    delete = "GRANT DELETE ON TABLE public.orders_archive TO analyst;"
    assert allowed.index(savepoint) < allowed.index(delete)
    assert manual.index(savepoint) > manual.index(delete)



def test_grant_before_rename_keeps_object_identity():
    result = precheck_migration(
        '''
        BEGIN;
        GRANT UPDATE ON TABLE public.orders TO analyst;
        ALTER TABLE public.orders RENAME TO orders_archive;
        COMMIT;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'approved'
    delta = result.privilege_diff['added'][0]
    assert delta['object_id'] == 'public.orders'
    assert delta['object_name'] == 'orders_archive'
    assert result.post_commit_objects[0]['object_id'] == 'public.orders'
    assert result.post_commit_objects[0]['name'] == 'orders_archive'
    assert result.post_commit_objects[0]['privileges']['analyst'] == [
        'SELECT', 'UPDATE',
    ]


def test_initial_privilege_follows_rename():
    result = precheck_migration(
        '''
        ALTER TABLE public.orders RENAME TO orders_archive;
        GRANT UPDATE ON TABLE public.orders_archive TO analyst;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'approved'
    assert result.privilege_diff['added'][0]['object_name'] == 'orders_archive'
    assert result.post_commit_objects[0]['privileges']['analyst'] == [
        'SELECT', 'UPDATE',
    ]


def test_revoke_after_rename_is_diffed_on_stable_identity():
    initial = [
        InitialObject(
            object_id='public.orders',
            schema='public',
            name='orders',
            kind='table',
            privileges={'analyst': ['SELECT', 'UPDATE']},
        )
    ]
    result = precheck_migration(
        '''
        BEGIN;
        ALTER TABLE public.orders RENAME TO orders_archive;
        REVOKE SELECT ON TABLE public.orders_archive FROM analyst;
        COMMIT;
        ''',
        initial,
        [ApprovedChange(
            object_id='public.orders',
            grantee='analyst',
            privilege='SELECT',
            action='revoke',
        )],
    )

    assert result.decision == 'approved'
    assert result.privilege_diff['removed'] == [
        {
            'object_id': 'public.orders',
            'schema': 'public',
            'object_name': 'orders_archive',
            'grantee': 'analyst',
            'grantee_key': 'analyst',
            'privilege': 'SELECT',
            'action': 'revoke',
            'approved': True,
        }
    ]
    assert result.post_commit_objects[0]['privileges']['analyst'] == ['UPDATE']


def test_unapproved_revoke_requires_review():
    initial = [
        InitialObject(
            name='orders',
            schema='public',
            privileges={'analyst': ['SELECT', 'UPDATE']},
        )
    ]
    result = precheck_migration(
        'REVOKE UPDATE ON TABLE public.orders FROM analyst;',
        initial,
    )

    assert result.decision == 'manual_review'
    assert result.privilege_diff['removed'][0]['privilege'] == 'UPDATE'
    assert result.privilege_diff['unapproved'][0]['action'] == 'revoke'


def test_full_rollback_discards_rename_and_grant():
    result = precheck_migration(
        '''
        BEGIN;
        ALTER TABLE public.orders RENAME TO orders_archive;
        GRANT UPDATE ON TABLE public.orders_archive TO analyst;
        ROLLBACK;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'approved'
    assert result.privilege_diff['added'] == []
    assert result.post_commit_objects[0]['name'] == 'orders'
    assert result.post_commit_objects[0]['privileges']['analyst'] == ['SELECT']
    rename = next(
        record for record in result.statements
        if record['kind'] == 'rename'
    )
    grant = _grants(result)[0]
    assert rename['status'] == 'rolled_back'
    assert grant['status'] == 'rolled_back'
    assert 'Discarded by ROLLBACK' in grant['reason']


def test_transaction_failure_then_commit_rolls_back():
    result = precheck_migration(
        '''
        BEGIN;
        GRANT UPDATE ON TABLE public.orders TO analyst;
        GRANT SELECT ON TABLE public.missing TO analyst;
        COMMIT;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert result.status == 'known'
    assert result.privilege_diff['added'] == []
    assert result.post_commit_objects[0]['privileges']['analyst'] == ['SELECT']
    grant = _grants(result)[0]
    assert grant['status'] == 'rolled_back'
    commit = result.statements[-1]
    assert 'failed transaction rolled back' in commit['reason']
    assert result.uncertainties[0]['code'] == 'transaction_failed'
    assert 'post_commit_privileges' in (
        result.uncertainties[0]['affected_conclusions']
    )


def test_transaction_failure_can_recover_via_savepoint():
    result = precheck_migration(
        '''
        BEGIN;
        SAVEPOINT before_bad_grant;
        GRANT SELECT ON TABLE public.missing TO analyst;
        ROLLBACK TO SAVEPOINT before_bad_grant;
        GRANT UPDATE ON TABLE public.orders TO analyst;
        COMMIT;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert result.status == 'known'
    assert result.privilege_diff['unapproved'] == []
    assert [item['privilege'] for item in result.privilege_diff['added']] == [
        'UPDATE'
    ]
    rejected = next(
        record for record in result.statements
        if record['status'] == 'rejected'
    )
    assert 'public.missing' in rejected['reason']
    recovery = next(
        record for record in result.statements
        if record['kind'] == 'rollback_to'
    )
    assert recovery['status'] == 'applied'
    assert result.uncertainties[0]['code'] == 'transaction_failed'


def test_failure_outside_transaction_halts_but_keeps_earlier_commits():
    result = precheck_migration(
        '''
        GRANT UPDATE ON TABLE public.orders TO analyst;
        GRANT SELECT ON TABLE public.missing TO analyst;
        GRANT INSERT ON TABLE public.orders TO analyst;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert result.status == 'known'
    assert [item['privilege'] for item in result.privilege_diff['added']] == [
        'UPDATE'
    ]
    assert result.statements[1]['status'] == 'rejected'
    assert result.statements[2]['status'] == 'not_executed'


def test_unsupported_syntax_marks_post_commit_unknown():
    result = precheck_migration(
        '''
        BEGIN;
        GRANT UPDATE ON TABLE public.orders TO analyst;
        TRUNCATE TABLE public.orders;
        COMMIT;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert result.status == 'unknown'
    assert result.post_commit_objects is None
    assert result.privilege_diff['status'] == 'unknown'
    uncertainty = result.uncertainties[0]
    assert uncertainty['code'] == 'unsupported_syntax'
    assert 'post_commit_privileges' in uncertainty['affected_conclusions']
    assert 'privilege_diff' in uncertainty['affected_conclusions']
    assert result.statements[2]['status'] == 'unsupported'
    assert result.statements[3]['status'] == 'unknown'


def test_supported_grant_with_unsupported_clause_is_not_guessed():
    result = precheck_migration(
        'GRANT UPDATE ON TABLE public.orders TO analyst WITH GRANT OPTION;',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert result.status == 'unknown'
    assert result.statements[0]['status'] == 'unsupported'
    assert result.uncertainties[0]['code'] == 'unsupported_syntax'


def test_syntax_error_is_reported():
    result = precheck_migration(
        '''
        BEGIN;
        GRANT UPDATE ON TABLE public.orders TO analyst;
        GRANT SELECT ON TABLE TO analyst;
        COMMIT;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert result.statements[2]['status'] == 'rejected'
    assert result.uncertainties[0]['code'] == 'syntax_error'


def test_open_transaction_is_unknown():
    result = precheck_migration(
        '''
        BEGIN;
        GRANT UPDATE ON TABLE public.orders TO analyst;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert result.status == 'unknown'
    assert result.post_commit_objects is None
    assert result.uncertainties[0]['code'] == 'open_transaction'
    assert result.statements[1]['status'] == 'uncommitted'


def test_savepoint_snapshot_restores_object_name():
    result = precheck_migration(
        '''
        BEGIN;
        SAVEPOINT before_rename;
        ALTER TABLE public.orders RENAME TO orders_archive;
        GRANT UPDATE ON TABLE public.orders_archive TO analyst;
        ROLLBACK TO SAVEPOINT before_rename;
        GRANT SELECT ON TABLE public.orders TO analyst;
        COMMIT;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'approved'
    assert result.post_commit_objects[0]['name'] == 'orders'
    assert result.post_commit_objects[0]['privileges']['analyst'] == ['SELECT']
    rename = next(
        record for record in result.statements
        if record['kind'] == 'rename'
    )
    assert rename['status'] == 'rolled_back'


def test_set_schema_keeps_object_identity():
    result = precheck_migration(
        '''
        ALTER TABLE public.orders SET SCHEMA archive;
        GRANT UPDATE ON TABLE archive.orders TO analyst;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'approved'
    delta = result.privilege_diff['added'][0]
    assert delta['object_id'] == 'public.orders'
    assert delta['schema'] == 'archive'
    assert delta['object_name'] == 'orders'
    assert result.post_commit_objects[0]['schema'] == 'archive'


def test_approval_may_use_new_name_alias():
    result = precheck_migration(
        '''
        ALTER TABLE public.orders RENAME TO orders_archive;
        GRANT UPDATE ON TABLE public.orders_archive TO analyst;
        ''',
        _initial(),
        [ApprovedChange(
            object_id='public.orders_archive',
            grantee='analyst',
            privilege='UPDATE',
        )],
    )

    assert result.decision == 'approved'
    assert result.privilege_diff['added'][0]['approved'] is True


def test_all_privileges_expands_and_wildcard_approval_matches():
    result = precheck_migration(
        'GRANT ALL PRIVILEGES ON TABLE public.orders TO analyst;',
        _initial(),
        [ApprovedChange(
            object_id='public.orders',
            grantee='analyst',
            privilege='ALL',
        )],
    )

    assert result.decision == 'approved'
    added = {item['privilege'] for item in result.privilege_diff['added']}
    assert added == {
        'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER',
    }
    assert all(item['approved'] for item in result.privilege_diff['added'])


def test_duplicate_savepoint_name_uses_latest():
    result = precheck_migration(
        '''
        BEGIN;
        GRANT UPDATE ON TABLE public.orders TO analyst;
        SAVEPOINT s;
        GRANT DELETE ON TABLE public.orders TO analyst;
        SAVEPOINT s;
        GRANT TRUNCATE ON TABLE public.orders TO analyst;
        ROLLBACK TO SAVEPOINT s;
        COMMIT;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert {
        item['privilege'] for item in result.privilege_diff['added']
    } == {'UPDATE', 'DELETE'}
    assert result.privilege_diff['unapproved'][0]['privilege'] == 'DELETE'


def test_release_destroys_nested_savepoints():
    result = precheck_migration(
        '''
        BEGIN;
        SAVEPOINT outer_sp;
        SAVEPOINT inner_sp;
        GRANT UPDATE ON TABLE public.orders TO analyst;
        RELEASE SAVEPOINT outer_sp;
        ROLLBACK TO SAVEPOINT inner_sp;
        COMMIT;
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'manual_review'
    assert result.status == 'known'
    assert result.privilege_diff['added'] == []
    rejected = next(
        record for record in result.statements
        if record['status'] == 'rejected'
    )
    assert 'inner_sp' in rejected['reason']


def test_commit_and_rollback_outside_transaction_are_noops():
    result = precheck_migration(
        '''
        COMMIT;
        ROLLBACK;
        ''',
        _initial(),
    )

    assert result.decision == 'approved'
    assert [record['status'] for record in result.statements] == [
        'no_op', 'no_op',
    ]


def test_comments_and_quoted_identifiers_are_supported():
    result = precheck_migration(
        '''
        -- rename first
        ALTER TABLE "public"."orders" RENAME TO "orders_archive";
        GRANT UPDATE ON TABLE "public"."orders_archive" TO "analyst";
        ''',
        _initial(),
        _approvals(),
    )

    assert result.decision == 'approved'
    assert result.post_commit_objects[0]['name'] == 'orders_archive'


def test_approval_for_unknown_object_is_rejected():
    with pytest.raises(PrecheckInputError):
        precheck_migration(
            'GRANT UPDATE ON TABLE public.orders TO analyst;',
            _initial(),
            [ApprovedChange(
                object_id='public.not_in_catalog',
                grantee='analyst',
                privilege='UPDATE',
            )],
        )


def test_duplicate_initial_object_id_is_rejected():
    with pytest.raises(PrecheckInputError):
        precheck_migration(
            '',
            [
                InitialObject(name='a', object_id='same'),
                InitialObject(name='b', object_id='same'),
            ],
        )


def test_cli_emits_json_and_status_codes(capsys):
    from sqlparse.precheck import main

    state = str(EXAMPLES / 'state.json')
    migration = str(EXAMPLES / 'migration_allowed.sql')
    assert main([migration, '--state', state, '--json']) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['decision'] == 'approved'
    assert payload['release_ok'] is True

    migration = str(EXAMPLES / 'migration_manual_review.sql')
    assert main([migration, '--state', state, '--json']) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload['decision'] == 'manual_review'
    assert payload['release_ok'] is False


def test_top_level_api_is_lazy_importable():
    assert sqlparse.precheck_migration is precheck_migration
    assert sqlparse.InitialObject is InitialObject


def test_grant_on_all_tables_in_schema_is_unsupported():
    result = precheck_migration(
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO analyst;",
        _initial(),
    )

    assert result.decision == "manual_review"
    assert result.status == "unknown"
    assert result.statements[0]["status"] == "unsupported"
    assert result.uncertainties[0]["code"] == "unsupported_syntax"


def test_invalid_initial_privilege_is_rejected():
    with pytest.raises(PrecheckInputError):
        precheck_migration(
            "",
            [InitialObject(
                name="orders", kind="table",
                privileges={"analyst": ["NONSENSE"]},
            )],
        )


def test_privilege_not_valid_for_object_kind_is_rejected():
    with pytest.raises(PrecheckInputError):
        precheck_migration(
            "",
            [InitialObject(
                name="orders", kind="table",
                privileges={"analyst": ["CONNECT"]},
            )],
        )


def test_release_savepoint_keeps_effects():
    result = precheck_migration(
        """
        BEGIN;
        SAVEPOINT s;
        GRANT DELETE ON TABLE public.orders TO analyst;
        RELEASE SAVEPOINT s;
        COMMIT;
        """,
        _initial(),
        _approvals(),
    )

    assert result.decision == "manual_review"
    assert result.privilege_diff["unapproved"][0]["privilege"] == "DELETE"
    delete_grant = _grants(result)[0]
    assert delete_grant["status"] == "committed"
