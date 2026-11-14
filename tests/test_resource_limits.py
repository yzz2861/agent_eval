import io

import pytest

import yaml
from yaml import ResourceLimits, ResourceBudgetExceeded, SafeLoader


NL = chr(10)


def block_sequence(depth):
    lines = ['  ' * level + '-' for level in range(depth)]
    lines.append('  ' * depth + '1')
    return NL.join(lines) + NL


def anchor_bomb(levels):
    lines = ["a: &a ['x']"]
    previous = 'a'
    for level in range(1, levels):
        name = chr(97 + level)
        lines.append('%s: &%s [*%s, *%s]' % (
            name, name, previous, previous))
        previous = name
    lines.append('z: *' + previous)
    return NL.join(lines) + NL


@pytest.mark.parametrize('stream', [
    '- a' + NL + '- b' + NL,
    b'- a' + bytes([10]) + b'- b' + bytes([10]),
    io.StringIO('- a' + NL + '- b' + NL),
])
def test_byte_budget_charges_every_input_kind(stream):
    with pytest.raises(ResourceBudgetExceeded) as info:
        yaml.safe_load(stream, ResourceLimits(max_bytes=3))
    assert info.value.resource == 'input byte'
    assert info.value.limit == 3


def test_scalar_budget_counts_alias_references():
    source = "s: &s '" + 'x' * 100 + "'" + NL + 'a: *s' + NL + 'b: *s' + NL
    with pytest.raises(ResourceBudgetExceeded) as info:
        yaml.safe_load(source, ResourceLimits(max_scalar_length=150))
    assert info.value.resource == 'scalar length'
    # the original scalar plus each alias expansion are charged incrementally
    assert info.value.used >= 200


def test_node_budget():
    with pytest.raises(ResourceBudgetExceeded) as info:
        yaml.safe_load('- 1' + NL + '- 2' + NL + '- 3' + NL,
                       ResourceLimits(max_nodes=2))
    assert info.value.resource == 'node'


def test_alias_expansion_budget():
    source = 'a: &a 1' + NL + NL.join(
            'x%d: *a' % index for index in range(5)) + NL
    with pytest.raises(ResourceBudgetExceeded) as info:
        yaml.safe_load(source, ResourceLimits(max_aliases=2))
    assert info.value.resource == 'alias expansion'


def test_anchor_reference_width_budget():
    source = 'a: &a 1' + NL + NL.join(
            'x%d: *a' % index for index in range(5)) + NL
    with pytest.raises(ResourceBudgetExceeded) as info:
        yaml.safe_load(source, ResourceLimits(max_anchor_refs=3))
    assert 'anchor reference width' in info.value.resource
    assert info.value.used == 4


def test_depth_budget_for_block_collections():
    with pytest.raises(ResourceBudgetExceeded) as info:
        yaml.safe_load(block_sequence(50), ResourceLimits(max_depth=10))
    assert info.value.resource == 'collection depth'


def test_flow_depth_is_rejected_before_native_recursion():
    # Thousands of flow levels must raise the budget exception from the
    # iterative scanner instead of a native RecursionError.
    deep = '[' * 5000 + '1' + ']' * 5000
    with pytest.raises(ResourceBudgetExceeded) as info:
        yaml.safe_load(deep)
    assert info.value.resource == 'collection depth'


def test_anchor_bomb_is_rejected_while_small():
    bomb = anchor_bomb(14)
    assert len(bomb) < 1024
    with pytest.raises(ResourceBudgetExceeded):
        yaml.safe_load(bomb, ResourceLimits(
            max_aliases=50, max_depth=None))


def test_long_scalar_alias_cannot_bypass_budget():
    source = "v: &v '" + 'y' * 5000 + "'" + NL + 'z: *v' + NL
    assert len(source) < 6000
    with pytest.raises(ResourceBudgetExceeded) as info:
        yaml.safe_load(source, ResourceLimits(
            max_bytes=10_000_000, max_scalar_length=4096))
    assert info.value.resource == 'scalar length'


def test_undefined_alias_remains_a_composer_error():
    with pytest.raises(yaml.composer.ComposerError):
        yaml.safe_load('a: *missing' + NL)


def test_duplicate_anchor_remains_a_composer_error():
    with pytest.raises(yaml.composer.ComposerError):
        yaml.safe_load('a: &x 1' + NL + 'b: &x 2' + NL)


def test_circular_alias_builds_recursive_object():
    data = yaml.safe_load('a: &a' + NL + '  b: *a' + NL)
    assert data['a']['b'] is data['a']


def test_merge_chain_order_is_deterministic():
    source = NL.join([
        'base: &base {x: 1, y: 2}',
        'mid: &mid {<<: *base, z: 3}',
        'top: {<<: *mid, w: 4}',
    ])
    data = yaml.safe_load(source)
    assert list(data['top'].keys()) == ['x', 'y', 'z', 'w']


def test_legal_document_keeps_types_and_order():
    data = yaml.safe_load(
            'ints: [1, 2, 3]' + NL
            + 'strs: {b: two, a: one, c: three}' + NL
            + 'none: null' + NL + 'flag: true' + NL)
    assert list(data['strs'].keys()) == ['b', 'a', 'c']
    assert type(data['ints'][0]) is int
    assert type(data['flag']) is bool
    assert data['none'] is None


def test_budget_instance_is_shared_across_components():
    limits = ResourceLimits(max_nodes=3)
    loader = SafeLoader('- 1' + NL + '- 2' + NL + '- 3' + NL, limits)
    try:
        with pytest.raises(ResourceBudgetExceeded):
            loader.get_single_data()
    finally:
        loader.dispose()
    assert loader.resource_limits is limits


def test_unlimited_budget_disables_every_limit():
    limits = ResourceLimits.unlimited()
    assert limits.enabled is False
    assert limits.max_depth is None
    data = yaml.safe_load(block_sequence(450), limits)
    assert data is not None


def test_named_unsafe_entry_point_disables_budgets():
    with pytest.raises(ResourceBudgetExceeded):
        yaml.safe_load(block_sequence(450))
    yaml.unsafe_load_unlimited(block_sequence(450))
    yaml.load(block_sequence(450), yaml.UnsafeUnlimitedSafeLoader)


def test_unsafe_load_all_unlimited_disables_budgets():
    documents = list(yaml.unsafe_load_all_unlimited(
            '---' + NL + block_sequence(450)))
    assert len(documents) == 1


def test_partial_limits_leave_other_resources_unrestricted():
    limits = ResourceLimits(max_nodes=None, max_bytes=None,
            max_scalar_length=None, max_aliases=None,
            max_depth=None, max_anchor_refs=None)
    assert limits.enabled is False
    yaml.safe_load(anchor_bomb(14), limits)


def test_budget_exception_is_a_yaml_error_and_carries_details():
    try:
        yaml.safe_load('- 1' + NL + '- 2' + NL,
                       ResourceLimits(max_nodes=1))
    except ResourceBudgetExceeded as exc:
        assert isinstance(exc, yaml.YAMLError)
        assert exc.resource == 'node'
        assert exc.used == 2
        assert exc.mark is not None
        assert 'node' in str(exc)
    else:
        pytest.fail('ResourceBudgetExceeded was not raised')
