import pytest

import yaml
from yaml.review import (
    MappingUpdate,
    ResourceRole,
    ReviewError,
    review_update,
)

POLICY = """
shared_limits: &shared_limits
  max_per_hour: 100
  burst: 20
  endpoint: !sec/endpoint {host: api.internal, port: 443}
test_queue:
  <<: *shared_limits
  owner: qa-team
prod_ban_rules:
  limits: *shared_limits
  action: ban
"""

ROLES = [
    ResourceRole('test', ['test_queue', 'test_queue.*'], scope='test-queue'),
    ResourceRole('prod', ['prod_ban_rules', 'prod_ban_rules.*'],
                 scope='prod-ban'),
]


def review(change, approvals=('test-queue',), source=POLICY):
    return review_update(
        source,
        change=change,
        roles=ROLES,
        approvals=approvals,
        allowed_tags=['!sec/endpoint'],
    )


def test_shared_block_update_releases_test_and_holds_prod():
    report = review(MappingUpdate('shared_limits', {'max_per_hour': 500}))

    # The shared block is actually consumed by both resources: the test
    # queue through a merge key, the prod ban rules through an alias.
    assert report.consumption['shared_limits'] == [
        'prod_ban_rules.limits',
        'shared_limits',
        'test_queue.<<',
    ]

    # The test queue is covered by the granted approval and is released.
    allowed = report.allowed
    assert [impact.path for impact in allowed] == ['test_queue']
    assert allowed[0].role == 'test'
    assert allowed[0].via_merge
    assert report.permitted

    # The prod ban rules still require their own approval.
    pending = report.requires_approval
    assert [impact.path for impact in pending] == ['prod_ban_rules.limits']
    assert pending[0].role == 'prod'
    assert pending[0].scope == 'prod-ban'

    # The legitimate partial update only touches the given keys.
    assert report.updated['max_per_hour'] == 500
    assert report.updated['burst'] == 20
    assert report.updated['endpoint'] == {'host': 'api.internal', 'port': 443}


def test_full_approval_releases_every_consumer():
    report = review(
        MappingUpdate('shared_limits', {'burst': 50}),
        approvals=('test-queue', 'prod-ban'),
    )
    assert report.requires_approval == []
    assert {impact.path for impact in report.allowed} == {
        'test_queue', 'prod_ban_rules.limits'}


def test_unclassified_consumer_requires_explicit_role():
    source = POLICY + "audit_copy:\n  <<: *shared_limits\n"
    report = review(MappingUpdate('shared_limits', {'burst': 5}), source=source)
    unclassified = [impact for impact in report.requires_approval
                    if impact.role is None]
    assert [impact.path for impact in unclassified] == ['audit_copy']


def test_unknown_anchor_is_rejected():
    with pytest.raises(ReviewError):
        review(MappingUpdate('missing_anchor', {'x': 1}))


def test_non_mapping_anchor_is_rejected():
    with pytest.raises(ReviewError):
        review_update(
            "name: &name test\n",
            change=MappingUpdate('name', {'x': 1}),
            roles=ROLES,
        )


def test_update_values_must_be_plain_data():
    with pytest.raises(ReviewError):
        MappingUpdate('shared_limits', {'x': object()})


def test_custom_tags_outside_caller_prefixes_stay_restricted():
    source = POLICY + "backdoor: !sec/eval now\n"
    with pytest.raises(yaml.YAMLError):
        review(MappingUpdate('shared_limits', {'burst': 1}), source=source)


def test_review_does_not_construct_custom_objects():
    class Exploit:
        pass

    class ExploitLoader(yaml.SafeLoader):
        pass

    ExploitLoader.add_constructor(
        '!sec/endpoint', lambda loader, node: Exploit())
    report = review(MappingUpdate('shared_limits', {'burst': 7}))
    # The restricted tag is constructed as plain data, never as an object.
    assert isinstance(report.updated['endpoint'], dict)
