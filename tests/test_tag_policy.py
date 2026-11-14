import datetime

import pytest

import yaml
from yaml.constructor import (
    ConstructorError,
    TagPolicy, TagSchema, TagBudget,
    TagPolicyError, UnknownTagError, DeniedTagError, TagArityError,
    TagBudgetError, IncludePathError, IncludeCycleError,
)


def load_with_policy(text, policy, Loader=yaml.SafeLoader):
    loader = Loader(text, policy=policy)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


# --- dangerous Python tags -------------------------------------------------

PYTHON_PAYLOADS = [
    '!!python/object/apply:os.system ["touch canary"]',
    '!!python/object/new:os.system ["touch canary"]',
    '!!python/object:__main__.Whatever {}',
    '!!python/module:os',
]


@pytest.mark.parametrize('payload', PYTHON_PAYLOADS)
def test_python_tags_denied_by_default(payload):
    with pytest.raises(DeniedTagError):
        yaml.safe_load(payload)


@pytest.mark.parametrize('payload', PYTHON_PAYLOADS)
def test_python_tags_denied_with_custom_policy(payload):
    policy = TagPolicy()
    policy.register_tag('!anything', lambda loader, node: None)
    with pytest.raises(DeniedTagError):
        load_with_policy(payload, policy)


def test_python_tags_not_executed(tmp_path):
    canary = tmp_path / 'pwned'
    payload = '!!python/object/apply:os.system ["touch %s"]' % canary
    with pytest.raises(DeniedTagError):
        yaml.safe_load(payload)
    assert not canary.exists()


def test_python_tags_cannot_be_registered():
    policy = TagPolicy()
    for tag in ('tag:yaml.org,2002:python/object:',
                'tag:yaml.org,2002:python/object/apply:',
                'tag:yaml.org,2002:python/module:'):
        with pytest.raises(ValueError):
            policy.register_tag(tag, lambda loader, node: None)
        with pytest.raises(ValueError):
            policy.register_prefix(tag, lambda loader, suffix, node: None)


def test_catch_all_multi_constructor_cannot_reopen_python_tags():
    class CatchAllLoader(yaml.SafeLoader):
        pass
    CatchAllLoader.add_multi_constructor(None, lambda loader, suffix, node: None)
    try:
        with pytest.raises(DeniedTagError):
            yaml.load('!!python/object/apply:os.system ["id"]', CatchAllLoader)
    finally:
        CatchAllLoader.yaml_multi_constructors.clear()


def test_denied_error_does_not_echo_content():
    secret = 's3cr3t-canary-value'
    with pytest.raises(DeniedTagError) as excinfo:
        yaml.safe_load('!!python/object/apply:os.system ["%s"]' % secret)
    assert secret not in str(excinfo.value)


# --- unknown tags ----------------------------------------------------------

def test_unknown_tag_rejected():
    with pytest.raises(UnknownTagError):
        yaml.safe_load('!no-such-tag 1')


def test_unknown_tag_error_is_constructor_error():
    # stays compatible with existing error handling
    with pytest.raises(ConstructorError):
        yaml.safe_load('!no-such-tag 1')
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load('!no-such-tag 1')


def test_unknown_tag_error_does_not_echo_content():
    secret = 's3cr3t-canary-value'
    with pytest.raises(UnknownTagError) as excinfo:
        yaml.safe_load('!no-such-tag "%s"' % secret)
    assert secret not in str(excinfo.value)


# --- standard tags keep working --------------------------------------------

def test_standard_tags_still_work():
    data = yaml.safe_load(
        'ts: 2001-12-15 02:59:43\n'
        'date: 2002-12-14\n'
        's: !!set {a, b}\n'
        'o: !!omap [{a: 1}, {b: 2}]\n'
        'b: !!binary aGk=\n'
        'i: 42\n'
        'f: 1.5\n'
        'flag: true\n'
        'nothing: null\n')
    assert data['ts'] == datetime.datetime(2001, 12, 15, 2, 59, 43)
    assert data['date'] == datetime.date(2002, 12, 14)
    assert data['s'] == {'a', 'b'}
    assert data['o'] == [('a', 1), ('b', 2)]
    assert data['b'] == b'hi'
    assert data['i'] == 42
    assert data['f'] == 1.5
    assert data['flag'] is True
    assert data['nothing'] is None


# --- custom tags: schema, budget, call counts ------------------------------

class CountingConstructor:
    def __init__(self, result=None):
        self.calls = []
        self.result = result

    def __call__(self, loader, node):
        self.calls.append(node.tag)
        if self.result is not None:
            return self.result
        return loader.construct_sequence(node)


def make_point_policy(counter):
    policy = TagPolicy()
    policy.register_tag('!point', counter,
            schema=TagSchema(kind='sequence', min_args=2, max_args=2),
            budget=TagBudget(max_args=2))
    return policy


def test_registered_custom_tag_works():
    counter = CountingConstructor()
    policy = make_point_policy(counter)
    assert load_with_policy('!point [1, 2]', policy) == [1, 2]
    assert counter.calls == ['!point']


def test_custom_tag_constructor_called_once_per_node():
    counter = CountingConstructor()
    policy = make_point_policy(counter)
    assert load_with_policy('- !point [1, 2]\n- !point [3, 4]\n', policy) \
            == [[1, 2], [3, 4]]
    assert counter.calls == ['!point', '!point']


@pytest.mark.parametrize('doc', ['!point [1]', '!point [1, 2, 3]', '!point x'])
def test_wrong_parameter_count_rejected(doc):
    counter = CountingConstructor()
    policy = make_point_policy(counter)
    with pytest.raises(TagArityError):
        load_with_policy(doc, policy)
    assert counter.calls == []


def test_parameter_bomb_rejected_by_budget():
    counter = CountingConstructor()
    policy = TagPolicy()
    policy.register_tag('!bomb', counter,
            schema=TagSchema(kind='sequence'),
            budget=TagBudget(max_args=8))
    doc = '!bomb [%s]' % ', '.join(str(i) for i in range(10000))
    with pytest.raises(TagBudgetError):
        load_with_policy(doc, policy)
    assert counter.calls == []


def test_scalar_bomb_rejected_by_budget():
    counter = CountingConstructor()
    policy = TagPolicy()
    policy.register_tag('!blob', counter,
            schema=TagSchema(kind='scalar'),
            budget=TagBudget(max_scalar_length=16))
    with pytest.raises(TagBudgetError):
        load_with_policy('!blob ' + 'x' * 100000, policy)
    assert counter.calls == []


def test_mapping_item_budget():
    counter = CountingConstructor(result={})
    policy = TagPolicy()
    policy.register_tag('!cfg', counter,
            schema=TagSchema(kind='mapping'),
            budget=TagBudget(max_items=2))
    assert load_with_policy('!cfg {a: 1, b: 2}', policy) == {}
    with pytest.raises(TagBudgetError):
        load_with_policy('!cfg {a: 1, b: 2, c: 3}', policy)
    assert counter.calls == ['!cfg']


def test_budget_error_does_not_echo_content():
    secret = 's3cr3t-canary-value'
    policy = TagPolicy()
    policy.register_tag('!blob', lambda loader, node: None,
            schema=TagSchema(kind='scalar'),
            budget=TagBudget(max_scalar_length=4))
    with pytest.raises(TagBudgetError) as excinfo:
        load_with_policy('!blob %s' % (secret * 10), policy)
    assert secret not in str(excinfo.value)


# --- existing explicit registration keeps working --------------------------

def test_explicit_loader_registration_still_works():
    class MyLoader(yaml.SafeLoader):
        pass
    MyLoader.add_constructor('!legacy',
            lambda loader, node: ('legacy', loader.construct_scalar(node)))
    try:
        assert yaml.load('!legacy x', MyLoader) == ('legacy', 'x')
    finally:
        del MyLoader.yaml_constructors['!legacy']


def test_full_loader_python_tags_still_work():
    assert yaml.full_load('!!python/tuple [1, 2]') == (1, 2)
    with pytest.raises(DeniedTagError):
        yaml.full_load('!!python/object/apply:os.system ["id"]')


# --- !include ---------------------------------------------------------------

def test_include_reads_allowed_directory(tmp_path):
    (tmp_path / 'child.yaml').write_text('value: 42\n')
    policy = TagPolicy(include_dirs=[str(tmp_path)])
    assert load_with_policy('!include child.yaml', policy) == {'value': 42}


def test_include_not_enabled_by_default(tmp_path):
    (tmp_path / 'child.yaml').write_text('value: 42\n')
    with pytest.raises(UnknownTagError):
        yaml.safe_load('!include child.yaml')


def test_include_traversal_rejected(tmp_path):
    allowed = tmp_path / 'allowed'
    allowed.mkdir()
    secret = tmp_path / 'secret.yaml'
    secret.write_text('password: s3cr3t-canary-value\n')
    policy = TagPolicy(include_dirs=[str(allowed)])
    for doc in ('!include ../secret.yaml', '!include %s' % secret):
        with pytest.raises(IncludePathError) as excinfo:
            load_with_policy(doc, policy)
        assert 's3cr3t-canary-value' not in str(excinfo.value)


def test_include_missing_file_rejected(tmp_path):
    policy = TagPolicy(include_dirs=[str(tmp_path)])
    with pytest.raises(IncludePathError):
        load_with_policy('!include no-such-file.yaml', policy)


def test_include_cycle_rejected(tmp_path):
    (tmp_path / 'self.yaml').write_text('!include self.yaml\n')
    policy = TagPolicy(include_dirs=[str(tmp_path)])
    with pytest.raises(IncludeCycleError):
        load_with_policy('!include self.yaml', policy)


def test_include_indirect_cycle_rejected(tmp_path):
    (tmp_path / 'a.yaml').write_text('!include b.yaml\n')
    (tmp_path / 'b.yaml').write_text('!include a.yaml\n')
    policy = TagPolicy(include_dirs=[str(tmp_path)])
    with pytest.raises(IncludeCycleError):
        load_with_policy('!include a.yaml', policy)


def test_include_depth_budget(tmp_path):
    for i in range(1, 5):
        (tmp_path / ('f%d.yaml' % i)).write_text('!include f%d.yaml\n' % (i + 1))
    (tmp_path / 'f5.yaml').write_text('done\n')
    policy = TagPolicy(include_dirs=[str(tmp_path)], max_include_depth=2)
    with pytest.raises(TagBudgetError):
        load_with_policy('!include f1.yaml', policy)


def test_include_nested_document_tags_are_policed(tmp_path):
    (tmp_path / 'evil.yaml').write_text(
        '!!python/object/apply:os.system ["s3cr3t-canary-value"]\n')
    policy = TagPolicy(include_dirs=[str(tmp_path)])
    with pytest.raises(DeniedTagError) as excinfo:
        load_with_policy('!include evil.yaml', policy)
    # the included file content must not leak through the error
    assert 's3cr3t-canary-value' not in str(excinfo.value)


def test_include_error_does_not_echo_file_content(tmp_path):
    (tmp_path / 'broken.yaml').write_text('s3cr3t-canary-value: [unclosed\n')
    policy = TagPolicy(include_dirs=[str(tmp_path)])
    with pytest.raises(ConstructorError) as excinfo:
        load_with_policy('!include broken.yaml', policy)
    assert 's3cr3t-canary-value' not in str(excinfo.value)


# --- per-source / per-tenant policies ---------------------------------------

def test_per_tenant_policies(tmp_path):
    dir_a = tmp_path / 'a'
    dir_b = tmp_path / 'b'
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / 'cfg.yaml').write_text('tenant: a\n')
    (dir_b / 'cfg.yaml').write_text('tenant: b\n')
    base = TagPolicy()
    tenant_a = base.derive().enable_include([str(dir_a)])
    tenant_b = base.derive().enable_include([str(dir_b)])
    assert load_with_policy('!include cfg.yaml', tenant_a) == {'tenant': 'a'}
    assert load_with_policy('!include cfg.yaml', tenant_b) == {'tenant': 'b'}
    # tenant A cannot reach tenant B's directory
    with pytest.raises(IncludePathError):
        load_with_policy('!include %s' % (dir_b / 'cfg.yaml'), tenant_a)
    # the base policy remains untouched
    with pytest.raises(UnknownTagError):
        load_with_policy('!include cfg.yaml', base)


def test_derived_policy_cannot_reopen_python_tags(tmp_path):
    policy = TagPolicy(include_dirs=[str(tmp_path)]).derive()
    with pytest.raises(DeniedTagError):
        load_with_policy('!!python/object/apply:os.system ["id"]', policy)


def test_policy_errors_are_yaml_errors():
    for cls in (UnknownTagError, DeniedTagError, TagArityError, TagBudgetError,
            IncludePathError, IncludeCycleError):
        assert issubclass(cls, ConstructorError)
        assert issubclass(cls, yaml.YAMLError)
        assert issubclass(cls, TagPolicyError)
