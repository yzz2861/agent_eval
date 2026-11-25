import pytest

import yaml


LOADER_CLASSES = [yaml.SafeLoader]
if hasattr(yaml, "CSafeLoader"):
    LOADER_CLASSES.append(yaml.CSafeLoader)


OLD_APPROVAL_ID = "CHG-2026-1021-07"

APPROVED_VALUES = {
    "backup_bucket": "ops-prod-backups-cn-east-1",
    "retention_days": 180,
    "encryption_required": True,
    "replica_count": 3,
}

EXPLICIT_OVERRIDES = {
    "replica_count": 5,
}

EXPECTED_DECISIONS = {
    "backup_bucket": ("local_defaults", "ops-prod-backups-cn-east-1"),
    "retention_days": ("local_defaults", 180),
    "encryption_required": ("local_defaults", True),
    "replica_count": ("explicit_overrides", 5),
}

DEFAULTS_FIRST = """\
review:
  old_approval: CHG-2026-1021-07
local_defaults:
  backup_bucket: ops-prod-backups-cn-east-1
  retention_days: 180
  encryption_required: true
  replica_count: 3
explicit_overrides:
  replica_count: 5
"""

OVERRIDES_FIRST = """\
review:
  old_approval: CHG-2026-1021-07
explicit_overrides:
  replica_count: 5
local_defaults:
  backup_bucket: ops-prod-backups-cn-east-1
  retention_days: 180
  encryption_required: true
  replica_count: 3
"""

SOURCE_ORDERS = [
    pytest.param(DEFAULTS_FIRST, id="defaults-first"),
    pytest.param(OVERRIDES_FIRST, id="overrides-first"),
]

OVERRIDE_LOCATIONS = [
    pytest.param(DEFAULTS_FIRST, 9, id="defaults-first"),
    pytest.param(OVERRIDES_FIRST, 4, id="overrides-first"),
]


def mapping_entries(node):
    assert isinstance(node, yaml.MappingNode)
    return {key_node.value: (key_node, value_node)
            for key_node, value_node in node.value}


def section_node(root, section_name):
    assert isinstance(root, yaml.MappingNode)
    return mapping_entries(root)[section_name][1]


def decide_managed_values(document):
    decisions = {}
    defaults = document["local_defaults"]
    overrides = document["explicit_overrides"]
    for key in EXPECTED_DECISIONS:
        if key in overrides:
            decisions[key] = ("explicit_overrides", overrides[key])
        else:
            decisions[key] = ("local_defaults", defaults[key])
    return decisions


@pytest.mark.parametrize("Loader", LOADER_CLASSES)
@pytest.mark.parametrize("source", SOURCE_ORDERS)
def test_two_section_orders_are_the_same_legal_mapping(Loader, source):
    first = yaml.load(DEFAULTS_FIRST, Loader=Loader)
    ordered = yaml.load(source, Loader=Loader)

    assert ordered == first
    assert ordered["review"]["old_approval"] == OLD_APPROVAL_ID
    assert ordered["local_defaults"] == APPROVED_VALUES
    assert ordered["explicit_overrides"] == EXPLICIT_OVERRIDES


@pytest.mark.parametrize("Loader", LOADER_CLASSES)
@pytest.mark.parametrize("source", SOURCE_ORDERS)
def test_managed_keys_keep_approval_values_or_follow_explicit_layer(
        Loader, source):
    document = yaml.load(source, Loader=Loader)

    assert set(EXPECTED_DECISIONS) == set(APPROVED_VALUES)
    assert set(document["local_defaults"]) == set(APPROVED_VALUES)
    override_decisions = {
        key for key, (layer, _) in EXPECTED_DECISIONS.items()
        if layer == "explicit_overrides"
    }
    assert override_decisions == set(EXPLICIT_OVERRIDES)
    assert decide_managed_values(document) == EXPECTED_DECISIONS

    for key, approved_value in APPROVED_VALUES.items():
        assert document["local_defaults"][key] == approved_value
        if key not in EXPLICIT_OVERRIDES:
            layer, adopted_value = EXPECTED_DECISIONS[key]
            assert layer == "local_defaults"
            assert adopted_value == approved_value

    changed_layer, changed_value = EXPECTED_DECISIONS["replica_count"]
    assert changed_layer == "explicit_overrides"
    assert changed_value != APPROVED_VALUES["replica_count"]


@pytest.mark.parametrize("Loader", LOADER_CLASSES)
@pytest.mark.parametrize(("source", "override_line"), OVERRIDE_LOCATIONS)
def test_explicit_override_location_is_available_on_static_node(
        Loader, source, override_line):
    root = yaml.compose(source, Loader=Loader)
    overrides = section_node(root, "explicit_overrides")
    key_node, value_node = mapping_entries(overrides)["replica_count"]
    default_node = section_node(root, "local_defaults")
    _, old_value_node = mapping_entries(default_node)["replica_count"]

    assert key_node.start_mark.line + 1 == override_line
    assert key_node.start_mark.column + 1 == 3
    assert value_node.start_mark.line + 1 == override_line
    assert value_node.start_mark.column + 1 == 18
    assert value_node.value == "5"
    assert old_value_node.value == "3"

    source_line = source.splitlines()[override_line - 1]
    assert source_line == "  replica_count: 5"
    assert source_line[value_node.start_mark.column] == "5"


def test_c_safe_loader_is_tested_when_available():
    assert yaml.SafeLoader in LOADER_CLASSES
    if hasattr(yaml, "CSafeLoader"):
        assert yaml.CSafeLoader in LOADER_CLASSES
