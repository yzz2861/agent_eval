import re

import pytest

import yaml
from yaml.composer import ComposerError


def test_same_anchor_can_be_authorized_differently_at_each_destination():
    source = """\
shared: &shared fake-secret-id
release:
  token: *shared
debug:
  echo: *shared
"""

    report = yaml.release_check(source, {"fake-secret-id": ["release.token"]})

    assert report.ok is False
    assert [finding.path for finding in report.findings] == [
        "/release/token",
        "/debug/echo",
    ]
    assert [finding.allowed for finding in report.findings] == [True, False]
    assert report.findings[0].used_at["line"] == 3
    assert report.findings[1].used_at["line"] == 5

    anchor = report.anchor_definitions["shared"]
    assert anchor["path"] == "/shared"
    assert anchor["defined_at"] == {"line": 1, "column": 9, "index": 8}
    assert [alias["path"] for alias in anchor["aliases"]] == [
        "/release/token",
        "/debug/echo",
    ]


def test_merged_alias_expands_to_consumer_paths():
    source = """\
base: &base
  token: fake-token
release:
  <<: *base
debug:
  <<: *base
"""

    report = yaml.release_check(source, {"fake-token": ["/release/token"]})

    assert [finding.path for finding in report.findings] == [
        "/release/token",
        "/debug/token",
    ]
    assert [finding.allowed for finding in report.findings] == [True, False]


def test_reverse_consumer_rules_are_supported():
    source = """\
base: &base {token: fake-token}
release: &release
  value: *base
debug:
  value: *base
"""

    report = yaml.release_check(
        source,
        consumer_rules={
            "/release/value/token": {"fake-token"},
            "/debug/value/token": set(),
        },
    )

    assert [finding.allowed for finding in report.findings] == [True, False]


def test_identifier_rule_and_consumption_predicate_work_together():
    source = """\
release:
  token: fake://payments
debug:
  token: fake://payments
"""

    report = yaml.release_check(
        source,
        identifier_rule=re.compile(r"fake://[a-z]+"),
        consumption_rule=lambda identifier, location: (
            identifier == "fake://payments" and location == "/release/token"
        ),
    )

    assert [finding.allowed for finding in report.findings] == [True, False]


def test_literal_reference_is_checked_and_report_has_no_source_value_field():
    source = """\
debug:
  token: fake-literal-id
"""

    report = yaml.release_check(source, {"fake-literal-id": ["release.token"]})

    finding = report.findings[0]
    assert finding.source == "literal"
    assert "value" not in finding
    assert all("value" not in item for item in report.anchors)
    assert report.violations == report["denied"]


def test_quoted_merge_key_is_a_normal_key():
    source = """\
base: &base {token: fake-token}
preview:
  '<<': *base
"""

    report = yaml.release_check(source, {"fake-token": ["/preview/<</token"]})

    assert [finding.path for finding in report.findings] == [
        "/preview/<</token"
    ]
    assert report.ok is True


def test_duplicate_anchor_still_fails_safely():
    source = """\
first: &same one
second: &same two
"""

    with pytest.raises(ComposerError):
        yaml.release_check(source, {"one": ["/first"]})
