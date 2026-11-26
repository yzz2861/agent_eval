import pytest

import yaml


def loader_classes():
    classes = [yaml.SafeLoader]
    if hasattr(yaml, "CSafeLoader"):
        classes.append(yaml.CSafeLoader)
    return classes


DEFAULTS_FIRST = """
local_defaults: &local_defaults
  retries: 3
  timeout: 30
  require_approval: true
policy:
  <<: *local_defaults
  retries: 5
"""

OVERRIDES_FIRST = """
local_defaults: &local_defaults
  retries: 3
  timeout: 30
  require_approval: true
policy:
  retries: 5
  <<: *local_defaults
"""

CONFIG_VARIANTS = [
    pytest.param(DEFAULTS_FIRST, 7, id="defaults-first"),
    pytest.param(OVERRIDES_FIRST, 6, id="overrides-first"),
]

EXPECTED_MANAGED_ITEMS = [
    ("retries", "override", 5),
    ("timeout", "local-default", 30),
    ("require_approval", "local-default", True),
]


def get_mapping_value(node, key):
    for key_node, value_node in node.value:
        if key_node.value == key:
            return value_node
    raise AssertionError("mapping key %r was not found" % key)


def explicit_keys(node):
    return {
        key_node.value
        for key_node, value_node in node.value
        if key_node.tag != "tag:yaml.org,2002:merge"
    }


@pytest.mark.parametrize("Loader", loader_classes())
@pytest.mark.parametrize("source", [variant.values[0] for variant in CONFIG_VARIANTS])
def test_managed_keys_use_defaults_or_explicit_overrides(Loader, source):
    config = yaml.load(source, Loader=Loader)
    root_node = yaml.compose(source, Loader=Loader)
    policy_node = get_mapping_value(root_node, "policy")
    overridden_keys = explicit_keys(policy_node)

    resolved_items = [
        (
            key,
            "override" if key in overridden_keys else "local-default",
            config["policy"][key],
        )
        for key, layer, value in EXPECTED_MANAGED_ITEMS
    ]

    assert resolved_items == EXPECTED_MANAGED_ITEMS
    assert config["policy"]["require_approval"] is True


@pytest.mark.parametrize("Loader", loader_classes())
def test_legacy_approval_value_matches_across_variants(Loader):
    approval_values = [
        yaml.load(source, Loader=Loader)["policy"]["require_approval"]
        for variant in CONFIG_VARIANTS
        for source in (variant.values[0],)
    ]

    assert approval_values == [True, True]


@pytest.mark.parametrize("Loader", loader_classes())
@pytest.mark.parametrize("source, override_line", CONFIG_VARIANTS)
def test_explicit_override_is_locatable_from_static_node(Loader, source, override_line):
    root_node = yaml.compose(source, Loader=Loader)
    policy_node = get_mapping_value(root_node, "policy")
    override_pair = [
        (key_node, value_node)
        for key_node, value_node in policy_node.value
        if key_node.value == "retries"
    ]

    assert len(override_pair) == 1
    key_node, value_node = override_pair[0]

    assert key_node.start_mark.line == override_line
    assert key_node.start_mark.column == 2
    assert value_node.start_mark.line == override_line
    assert value_node.start_mark.column == 11
    assert source[value_node.start_mark.index:value_node.end_mark.index] == "5"
