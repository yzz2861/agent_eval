import json

import pytest

import RestrictedPython.Guards
from RestrictedPython import approval_applies
from RestrictedPython import build_compile_artifact
from RestrictedPython import check_approval
from RestrictedPython import compile_restricted
from RestrictedPython import compile_restricted_exec
from RestrictedPython import compile_restricted_with_artifact
from RestrictedPython import create_approval_record
from RestrictedPython import RestrictingNodeTransformer


SOURCE = '''\
def answer(value):
    return value + 1
'''


class PolicyA(RestrictingNodeTransformer):
    pass


class PolicyB(RestrictingNodeTransformer):
    pass


def test_compile_result_keeps_legacy_tuple_shape():
    result = compile_restricted_exec('answer = 42')

    code, errors, warnings, used_names = result

    assert code is result.code
    assert errors == ()
    assert warnings == []
    assert used_names == {}
    assert len(result) == 4
    assert result[4] is result.artifact

    namespace = {}
    exec(result.code, namespace)
    assert namespace['answer'] == 42


def test_compile_restricted_can_return_artifact():
    result = compile_restricted(
        'answer = 42', with_artifact=True)

    assert result.code is not None
    assert result.artifact is not None
    assert result.artifact.source_digest


def test_artifact_is_deterministic_and_text_only():
    marker = 'HOST-OBJECT-VALUE-MUST-NOT-APPEAR'
    source = f'answer = {marker!r}\n'

    first = compile_restricted_exec(source).artifact
    second = compile_restricted_exec(source).artifact

    assert first is not None
    assert second is not None
    assert first.to_json() == second.to_json()
    assert first.source_sha256 != source
    assert marker not in first.to_json()
    assert marker not in create_approval_record(first)
    assert json.loads(first.to_json())['source_sha256'] == first.digest


def test_approval_applies_to_identical_artifact():
    result = compile_restricted_exec(SOURCE)
    record = result.artifact.approval_record()

    decision = check_approval(record, result)

    assert decision.applicable
    assert decision.changed_fields == ()
    assert approval_applies(record, result)


def test_switching_policy_invalidates_same_source():
    old = compile_restricted_exec(SOURCE, policy=PolicyA)
    new = compile_restricted_exec(SOURCE, policy=PolicyB)
    record = create_approval_record(old)

    decision = check_approval(record, new)

    assert old.artifact.source_sha256 == new.artifact.source_sha256
    assert not decision.applicable
    assert decision.changed_fields == ('policy',)
    assert decision.invalidated_by == ('policy',)
    assert 'policy changed from' in decision.reason


def test_switching_guard_version_invalidates_same_source():
    old = compile_restricted_exec(SOURCE, guard_version='guards-v1')
    new = compile_restricted_exec(SOURCE, guard_version='guards-v2')

    decision = check_approval(create_approval_record(old), new)

    assert not decision.applicable
    assert decision.changed_fields == ('guard_version',)
    assert decision.config_changes == ('guard_version',)


def test_switching_language_features_invalidates_same_source():
    old = compile_restricted_exec(
        SOURCE, language_features={'top_level_await': False})
    new = compile_restricted_exec(
        SOURCE, language_features={'top_level_await': True})

    decision = check_approval(create_approval_record(old), new)

    assert not decision.applicable
    assert decision.changed_fields == ('language_features',)
    assert decision.differences['language_features'] == (
        (('top_level_await', False),),
        (('top_level_await', True),),
    )


def test_comparison_does_not_execute_the_source():
    marker = []
    source = 'marker.append("executed")\n'
    result = compile_restricted_exec(source)
    record = create_approval_record(result)

    decision = check_approval(record, result)
    approval_applies(record, result)

    assert decision.applicable
    assert marker == []


def test_host_objects_are_not_written_to_review_material():
    secret = object()

    class SecretPolicy(RestrictingNodeTransformer):
        host_value = secret

    artifact = build_compile_artifact(
        SOURCE,
        policy=SecretPolicy,
        language_features={'safe': True},
    )

    summary = artifact.to_json()

    assert 'SecretPolicy' in summary
    assert 'object at 0x' not in summary
    assert 'host_value' not in summary


def test_same_source_control_reports_environment_change():
    source = SOURCE
    old = compile_restricted_with_artifact(
        source, policy=PolicyA, guard_version='v1')
    new = compile_restricted_with_artifact(
        source, policy=PolicyA, guard_version='v2')

    decision = check_approval(old.artifact, new.artifact)

    assert old.artifact.source_sha256 == new.artifact.source_sha256
    assert decision.changed_fields == ('guard_version',)


def test_default_guard_version_change_invalidates(monkeypatch):
    old = compile_restricted_exec(SOURCE)
    monkeypatch.setattr(
        RestrictedPython.Guards, 'GUARD_VERSION', 'upgraded-guards')
    new = compile_restricted_exec(SOURCE)

    decision = check_approval(old, new)

    assert old.artifact.source_sha256 == new.artifact.source_sha256
    assert decision.changed_fields == ('guard_version',)
    assert decision.cause == 'guard_version'


def test_invalid_approval_text_is_reported_without_echoing_it():
    secret = 'HOST-OBJECT-VALUE-MUST-NOT-APPEAR'
    current = compile_restricted_exec(SOURCE)

    decision = check_approval(secret, current)

    assert not decision.applicable
    assert decision.changed_fields == ('approval_record',)
    assert 'HOST-OBJECT-VALUE-MUST-NOT-APPEAR' not in repr(decision)


@pytest.mark.parametrize('features', [
    ('f_string', 'walrus'),
    {'f_string': True, 'walrus': True},
])
def test_language_feature_inputs_normalize(features):
    first = compile_restricted_exec(
        'x = 1', language_features=features)
    second = compile_restricted_exec(
        'x = 1', language_features={'walrus': True, 'f_string': True})

    assert first.artifact.language_features == (
        ('f_string', True), ('walrus', True))
    assert check_approval(first, second).applicable
