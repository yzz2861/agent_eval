import time

import pytest

import yaml
from yaml import (
    MergeAudit,
    MergeBudget,
    MergeBudgetExceededError,
    MergeCycleError,
    MergeDuplicateSourceError,
    MergeOrigin,
    MergePolicy,
)


LEGACY_MERGE_DOC = "\n".join([
    '- &CENTER { x: 1, \'y\': 2 }',
    '- &BIG { r: 10 }',
    '- &SMALL { r: 1 }',
    '- # single mapping merge',
    '  <<: *CENTER',
    '  r: 10',
    '  label: center/big',
    '- # sequence merge with override precedence',
    '  <<: [ *BIG, *SMALL ]',
    '  x: 1',
    '  label: center/big',
    '',
])


def test_legacy_merge_semantics_unchanged_without_options():
    center, big, small, single, sequence = yaml.safe_load(LEGACY_MERGE_DOC)

    assert center == {"x": 1, "y": 2}
    assert single == {"x": 1, "y": 2, "r": 10, "label": "center/big"}
    # First merge source wins; explicit keys win over merged keys.
    assert sequence == {"r": 10, "x": 1, "label": "center/big"}


def test_legacy_merge_semantics_unchanged_with_budget():
    data = yaml.safe_load(LEGACY_MERGE_DOC, merge_budget=MergeBudget())

    assert data[3] == {"x": 1, "y": 2, "r": 10, "label": "center/big"}
    assert data[4] == {"r": 10, "x": 1, "label": "center/big"}


def test_safe_load_return_type_unchanged():
    assert isinstance(yaml.safe_load(LEGACY_MERGE_DOC), list)
    assert isinstance(yaml.safe_load("x: 1\n"), dict)
    data, audit = yaml.safe_load("x: 1\n", audit=True)
    assert data == {"x": 1}
    assert isinstance(audit, MergeAudit)


def test_audit_does_not_change_business_values():
    plain = yaml.safe_load(LEGACY_MERGE_DOC)
    data, audit = yaml.safe_load(LEGACY_MERGE_DOC, audit=True)

    assert data == plain
    origin = audit.get((3, "y"))
    assert isinstance(origin, MergeOrigin)
    assert origin.merged is True
    assert origin.key == "y"
    assert origin.source_anchor == "CENTER"
    assert origin.key_line == 1


def test_audit_tracks_explicit_and_merged_origins():
    source = "\n".join([
        'base: &base {x: 1, y: 2}',
        'target:',
        '  <<: *base',
        '  x: 99',
        '',
    ])
    data, audit = yaml.safe_load(source, audit=True)

    assert data["target"] == {"x": 99, "y": 2}
    explicit = audit.get(("target", "x"))
    merged = audit.get(("target", "y"))
    assert explicit.merged is False
    assert explicit.key_line == 4
    assert merged.merged is True
    assert merged.source_anchor == "base"
    assert merged.source_line == 1
    assert ("target", "y") in audit.paths()


def test_audit_records_nested_sequence_paths():
    source = "\n".join([
        'base: &base {x: 1}',
        'root:',
        '  - <<: *base',
        '',
    ])
    _data, audit = yaml.safe_load(source, audit=True)
    origin = audit.get(("root", 0, "x"))
    assert origin is not None
    assert origin.merged is True


def test_depth_budget_rejects_merge_chain_quickly():
    lines = ["n0: &n0 {k0: 0}"]
    for index in range(1, 500):
        lines.append(
            "n%d: &n%d {<<: *n%d, k%d: %d}"
            % (index, index, index - 1, index, index)
        )
    lines.append("root: {<<: *n499}")
    bomb = "\n".join(lines)
    budget = MergeBudget(
            max_depth=10, max_total_keys=None, max_branches=None)

    started = time.monotonic()
    with pytest.raises(MergeBudgetExceededError) as exc_info:
        yaml.safe_load(bomb, merge_budget=budget)
    elapsed = time.monotonic() - started

    assert elapsed < 1.0
    message = str(exc_info.value)
    assert "merge depth 11 exceeds budget 10" in message
    assert "k499" not in message


def test_branch_budget_rejects_fanout_bomb():
    lines = [
        "m%d: &m%d {k%d: %d}" % (i, i, i, i)
        for i in range(500)
    ]
    lines.append("root:")
    lines.append("  <<: [%s]" % ", ".join("*m%d" % i for i in range(500)))
    bomb = "\n".join(lines)

    with pytest.raises(MergeBudgetExceededError) as exc_info:
        yaml.safe_load(bomb, merge_budget=MergeBudget(max_branches=100))
    assert "merge branch count exceeds budget 100" in str(exc_info.value)


def test_total_keys_budget_rejects_wide_merge():
    lines = [
        "m%d: &m%d {%s}"
        % (i, i, ", ".join("k%d: %d" % (j, j) for j in range(100)))
        for i in range(500)
    ]
    lines.append("root:")
    lines.append("  <<: [%s]" % ", ".join("*m%d" % i for i in range(500)))
    bomb = "\n".join(lines)

    with pytest.raises(MergeBudgetExceededError) as exc_info:
        yaml.safe_load(
                bomb, merge_budget=MergeBudget(max_total_keys=10_000))
    assert "total merge key count exceeds budget 10000" in str(
            exc_info.value)


def test_scalar_length_budget_reports_path_not_value():
    secret = "a" * 5000
    source = "base: &base {token: '%s'}\ntarget: {<<: *base}\n" % secret

    with pytest.raises(MergeBudgetExceededError) as exc_info:
        yaml.safe_load(
            source, merge_budget=MergeBudget(max_scalar_length=100))
    message = str(exc_info.value)
    assert "scalar value length 5000 exceeds budget 100" in message
    assert secret not in message
    assert "aaaa" not in message


def test_cyclic_merge_is_rejected_even_without_budget():
    # Aliases must reference earlier anchors, so a textual document cannot
    # express a cycle purely through merge edges. Build the node graph
    # directly to exercise the planner's ancestor-chain guard.
    from yaml.nodes import MappingNode, ScalarNode
    from yaml.merge import MergePlanner

    merge_key = ScalarNode("tag:yaml.org,2002:merge", "<<")
    node_a = MappingNode("tag:yaml.org,2002:map", [])
    node_b = MappingNode("tag:yaml.org,2002:map", [])
    node_a.value = [(merge_key, node_b)]
    node_b.value = [(merge_key, node_a)]

    loader = yaml.SafeLoader("")
    planner = MergePlanner(loader)
    with pytest.raises(MergeCycleError) as exc_info:
        planner.flatten_mapping(node_a)
    message = str(exc_info.value)
    assert "cyclic merge reference detected" in message


def test_self_referential_merge_node_is_rejected():
    from yaml.nodes import MappingNode, ScalarNode
    from yaml.merge import MergePlanner

    merge_key = ScalarNode("tag:yaml.org,2002:merge", "<<")
    node = MappingNode("tag:yaml.org,2002:map", [])
    node.value = [(merge_key, node)]

    planner = MergePlanner(yaml.SafeLoader(""))
    with pytest.raises(MergeCycleError):
        planner.flatten_mapping(node)


def test_duplicate_merge_source_allowed_by_default_but_rejected_strict():
    source = "\n".join([
        'base: &base {x: 1}',
        'target: {<<: [*base, *base]}',
        '',
    ])
    assert yaml.safe_load(source)["target"] == {"x": 1}

    with pytest.raises(MergeDuplicateSourceError) as exc_info:
        yaml.safe_load(
            source,
            merge_budget=MergeBudget(),
            merge_strict=True,
        )
    message = str(exc_info.value)
    assert "duplicate merge source rejected" in message
    assert "anchor 'base'" in message


def test_strict_mode_rejects_duplicate_direct_merge_keys():
    source = "\n".join([
        'base: &base {x: 1}',
        'target:',
        '  <<: *base',
        '  <<: *base',
        '',
    ])
    with pytest.raises(MergeDuplicateSourceError):
        yaml.safe_load(
            source,
            merge_budget=MergeBudget(),
            merge_strict=True,
        )


def test_protected_key_blocks_tenant_override():
    source = "\n".join([
        'security: &security {tls_verify: true}',
        'tenant:',
        '  <<: *security',
        '  tls_verify: false',
        '',
    ])
    assert yaml.safe_load(source)["tenant"]["tls_verify"] is False

    policy = MergePolicy(protected_keys=["tls_verify"])
    with pytest.raises(yaml.MergeProtectedKeyError) as exc_info:
        yaml.safe_load(source, merge_policy=policy)
    message = str(exc_info.value)
    assert "protected key 'tls_verify' cannot be overridden" in message
    assert "line 1" in message
    assert "true" not in message


def test_protected_key_allowed_when_not_contested():
    source = "\n".join([
        'tenant:',
        '  tls_verify: true',
        '  name: acme',
        '',
    ])
    policy = MergePolicy(protected_keys=["tls_verify"])
    data = yaml.safe_load(source, merge_policy=policy)
    assert data["tenant"] == {"tls_verify": True, "name": "acme"}


def test_protected_key_blocks_lower_priority_merge_source():
    source = "\n".join([
        'sec: &sec {tls_verify: true}',
        'tenant_cfg: &tenant {tls_verify: false}',
        'root:',
        '  <<: [*sec, *tenant]',
        '',
    ])
    policy = MergePolicy(protected_keys=["tls_verify"])
    with pytest.raises(yaml.MergeProtectedKeyError) as exc_info:
        yaml.safe_load(source, merge_policy=policy)
    message = str(exc_info.value)
    assert "protected key 'tls_verify' cannot be overridden" in message
    assert "true" not in message
    assert "false" not in message
    assert "anchor 'tenant'" in message


def test_loader_attributes_expose_audit_after_construction():
    source = "base: &base {x: 1}\ntarget: {<<: *base}\n"
    loader = yaml.SafeLoader(source)
    loader.merge_audit_enabled = True
    data = loader.get_single_data()
    audit = loader.get_merge_audit()
    loader.dispose()

    assert data["target"] == {"x": 1}
    assert audit.get(("target", "x")).source_anchor == "base"


def test_safe_load_all_audit_yields_per_document_audits():
    stream = (
        "base: &base {x: 1}\ntarget: {<<: *base}\n"
        "---\nleft: &left {y: 2}\nright: {<<: *left}\n"
    )
    documents = list(yaml.safe_load_all(stream, audit=True))
    assert len(documents) == 2
    second_data, second_audit = documents[1]
    assert second_data == {"left": {"y": 2}, "right": {"y": 2}}
    assert second_audit.get(("right", "y")).merged is True


def test_budget_counters_reset_between_documents():
    stream = "\n".join([
        'base: &base {a: 1, b: 2, c: 3}',
        'first: {<<: *base}',
        '---',
        'base: &base {a: 1, b: 2, c: 3}',
        'second: {<<: *base}',
        '',
    ])
    budget = MergeBudget(max_total_keys=3)
    documents = list(yaml.safe_load_all(stream, merge_budget=budget))
    assert documents[0]["first"] == {"a": 1, "b": 2, "c": 3}
    assert documents[1]["second"] == {"a": 1, "b": 2, "c": 3}


def test_invalid_merge_value_keeps_constructor_error():
    with pytest.raises(yaml.constructor.ConstructorError):
        yaml.safe_load("target: {<<: 5}\n")
    with pytest.raises(yaml.constructor.ConstructorError):
        yaml.safe_load("target: {<<: [5]}\n")
