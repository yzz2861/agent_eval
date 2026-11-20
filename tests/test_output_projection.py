import pytest

from RestrictedPython import OutputPolicy
from RestrictedPython import OutputProjectionError
from RestrictedPython import guarded_print_collector
from tests.helper import restricted_exec


SECRET = 'fake-secret-token'


@pytest.fixture
def policy():
    return OutputPolicy()


@pytest.fixture
def protected_token(policy):
    """An in-memory fake protected value marked with its source."""
    return policy.protect(SECRET, origin='ledger.token')


def test_project__approves_plain_summary(policy):
    summary = {
        'total': 3,
        'ok': True,
        'items': [('a', 1.5), ('b', None)],
        'tags': {'x', 'y'},
    }
    assert policy.project(summary) is summary


def test_project__rejects_unapproved_shape(policy):
    class Custom:
        pass

    with pytest.raises(OutputProjectionError) as excinfo:
        policy.project({'obj': Custom()})
    assert excinfo.value.location == "output['obj']"
    assert "'Custom'" in excinfo.value.reason


def test_project__rejects_nested_protected_value(policy, protected_token):
    result = {'stats': [1, {'token': protected_token}]}
    with pytest.raises(OutputProjectionError) as excinfo:
        policy.project(result)
    assert excinfo.value.location == "output['stats'][1]['token']"
    assert 'ledger.token' in str(excinfo.value)
    assert SECRET not in str(excinfo.value)


def test_project__rejects_aliased_protected_value(policy, protected_token):
    alias = protected_token
    with pytest.raises(OutputProjectionError) as excinfo:
        policy.project({'first': 'fine', 'second': [alias]})
    assert excinfo.value.location == "output['second'][0]"
    assert SECRET not in str(excinfo.value)


def test_project__rejects_protected_dict_key(policy, protected_token):
    with pytest.raises(OutputProjectionError) as excinfo:
        policy.project({protected_token: 1})
    assert excinfo.value.location == 'output.keys()'
    assert SECRET not in str(excinfo.value)


def test_project__tolerates_cycles_and_shared_containers(policy):
    shared = [1, 2]
    result = {'a': shared, 'b': shared}
    result['self'] = result
    assert policy.project(result) is result


def test_project__custom_location(policy, protected_token):
    with pytest.raises(OutputProjectionError) as excinfo:
        policy.project([protected_token], location='result')
    assert excinfo.value.location == 'result[0]'


def _print_globals(policy, **extra):
    glb = {
        '_print_': guarded_print_collector(policy),
        '_getattr_': None,
    }
    glb.update(extra)
    return glb


def test_print__keeps_normal_summary_output(policy):
    glb = restricted_exec(
        "print('rows:', 3)\nprint('done')",
        _print_globals(policy),
    )
    assert glb['_print']() == 'rows: 3\ndone\n'


def test_print__rejects_protected_value(policy, protected_token):
    glb = _print_globals(policy, token=protected_token)
    with pytest.raises(OutputProjectionError) as excinfo:
        restricted_exec("print('token:', token)", glb)
    assert excinfo.value.location == 'print argument 1'
    assert SECRET not in str(excinfo.value)
    assert SECRET not in glb['_print']()


def test_print__rejects_protected_value_in_container(policy,
                                                     protected_token):
    glb = _print_globals(policy, data={'token': protected_token})
    with pytest.raises(OutputProjectionError) as excinfo:
        restricted_exec("print(data)", glb)
    assert excinfo.value.location == "print argument 0['token']"
    assert SECRET not in str(excinfo.value)


def test_integration__compare_protected_publish_summary(
        policy, protected_token):
    glb = _print_globals(policy, expected=protected_token, submitted=SECRET)
    restricted_exec(
        "if submitted == expected:\n"
        "    result = {'match': True, 'count': 1}\n"
        "else:\n"
        "    result = {'match': False, 'count': 0}\n"
        "print('compared', len(result))",
        glb,
    )
    assert glb['_print']() == 'compared 2\n'
    assert policy.project(glb['result']) == {'match': True, 'count': 1}
