import datetime
import logging

import pytest
import yaml

from yaml.authorized import (
    TagAuthority,
    TagAuthorizationError,
    AuthorizedSafeLoader,
    authorized_safe_load,
    authorized_safe_load_all,
)


TEAM_TAG = '!team/internal'
VENDOR_TAG = '!vendor/widget'

TEAM_DOC = """
name: config-a
marker: !team/internal 42
items:
  - 1
  - true
  - null
"""

VENDOR_DOC = """
name: upload-b
marker: !vendor/widget "hello"
"""


def team_constructor(loader, node):
    return ('team', loader.construct_scalar(node))


def vendor_constructor(loader, node):
    return ('vendor', loader.construct_scalar(node))


@pytest.fixture
def team_authority():
    authority = TagAuthority('team')
    authority.grant(TEAM_TAG, team_constructor)
    return authority


@pytest.fixture
def vendor_authority():
    authority = TagAuthority('third_party')
    authority.grant(VENDOR_TAG, vendor_constructor)
    return authority


def test_inherits_standard_safe_tags(team_authority):
    data = authorized_safe_load(
        'i: 1\nf: 2.5\nb: true\nn: null\ns: text\nseq: [a, b]\n'
        'map: {k: v}\ndate: 2026-11-23\n',
        team_authority)
    assert data == {
        'i': 1, 'f': 2.5, 'b': True, 'n': None, 's': 'text',
        'seq': ['a', 'b'], 'map': {'k': 'v'},
        'date': datetime.date(2026, 11, 23),
    }


def test_safe_load_paths_still_work(team_authority):
    # The existing safe loading entry points and class are untouched.
    assert yaml.safe_load('a: 1') == {'a': 1}
    assert list(yaml.safe_load_all('a: 1\n---\nb: 2\n')) == [
        {'a': 1}, {'b': 2}]
    assert yaml.load('a: 1', Loader=yaml.SafeLoader) == {'a': 1}
    assert TEAM_TAG not in yaml.SafeLoader.yaml_constructors
    assert VENDOR_TAG not in yaml.SafeLoader.yaml_constructors


def test_interleaved_loads_only_bound_authority_accepts_tag(
        team_authority, vendor_authority, caplog):
    caplog.set_level(logging.INFO, logger='yaml.authorized')

    data = authorized_safe_load(TEAM_DOC, team_authority)
    assert data['marker'] == ('team', '42')

    with pytest.raises(yaml.constructor.ConstructorError, match=TEAM_TAG):
        authorized_safe_load(TEAM_DOC, vendor_authority)

    data = authorized_safe_load(TEAM_DOC, team_authority)
    assert data['marker'] == ('team', '42')

    data = authorized_safe_load(VENDOR_DOC, vendor_authority)
    assert data['marker'] == ('vendor', 'hello')

    with pytest.raises(yaml.constructor.ConstructorError, match=VENDOR_TAG):
        authorized_safe_load(VENDOR_DOC, team_authority)

    accept_records = [r for r in caplog.records
                      if 'accepted tag' in r.getMessage()]
    reject_records = [r for r in caplog.records
                      if 'rejected tag' in r.getMessage()]

    assert sum(TEAM_TAG in r.getMessage() for r in accept_records) == 2
    assert all("authority 'team'" in r.getMessage() for r in accept_records
               if TEAM_TAG in r.getMessage())
    assert sum(VENDOR_TAG in r.getMessage() for r in accept_records) == 1
    assert all("authority 'third_party'" in r.getMessage()
               for r in accept_records if VENDOR_TAG in r.getMessage())
    assert sum(TEAM_TAG in r.getMessage() for r in reject_records) == 1
    assert sum(VENDOR_TAG in r.getMessage() for r in reject_records) == 1
    assert all("authority 'third_party'" in r.getMessage()
               for r in reject_records if TEAM_TAG in r.getMessage())
    assert all("authority 'team'" in r.getMessage() for r in reject_records
               if VENDOR_TAG in r.getMessage())


def test_revoked_tag_is_rejected_and_reviewable(team_authority, caplog):
    caplog.set_level(logging.INFO, logger='yaml.authorized')

    assert authorized_safe_load(TEAM_DOC, team_authority)['marker'] == \
        ('team', '42')

    scope_before = {event['action']: event['scope']
                    for event in team_authority.review(TEAM_TAG)}
    assert frozenset([TEAM_TAG]) in scope_before.values()

    team_authority.revoke(TEAM_TAG)

    with pytest.raises(yaml.constructor.ConstructorError, match=TEAM_TAG):
        authorized_safe_load(TEAM_DOC, team_authority)

    history = team_authority.review(TEAM_TAG)
    actions = [event['action'] for event in history]
    assert actions == ['grant', 'accept', 'revoke', 'reject']

    # The revoked tag's prior acceptance scope can still be reviewed.
    grant_event = next(e for e in history if e['action'] == 'grant')
    revoke_event = next(e for e in history if e['action'] == 'revoke')
    assert TEAM_TAG in grant_event['scope']
    assert TEAM_TAG not in revoke_event['scope']
    assert grant_event['constructor'] == 'team_constructor'
    assert revoke_event['constructor'] == 'team_constructor'

    # Current scope no longer contains the tag, and the class table is clean.
    assert team_authority.accepted_tags() == {}
    assert TEAM_TAG not in yaml.SafeLoader.yaml_constructors


def test_re_grant_after_revoke_does_not_grandfather_old_decisions(
        team_authority):
    authorized_safe_load(TEAM_DOC, team_authority)
    team_authority.revoke(TEAM_TAG)
    with pytest.raises(yaml.constructor.ConstructorError):
        authorized_safe_load(TEAM_DOC, team_authority)

    team_authority.grant(TEAM_TAG, team_constructor)
    assert authorized_safe_load(TEAM_DOC, team_authority)['marker'] == \
        ('team', '42')

    actions = [e['action'] for e in team_authority.review(TEAM_TAG)]
    assert actions == ['grant', 'accept', 'revoke', 'reject',
                       'grant', 'accept']

    # Revoke again: the earlier accept records must not change the decision.
    team_authority.revoke(TEAM_TAG)
    with pytest.raises(yaml.constructor.ConstructorError):
        authorized_safe_load(TEAM_DOC, team_authority)


def test_instance_registration_is_isolated_and_scope_locked(
        team_authority, vendor_authority):
    loader = AuthorizedSafeLoader(TEAM_DOC, team_authority)
    try:
        loader.register(TEAM_TAG)
        assert loader.yaml_constructors[TEAM_TAG] is team_constructor
        # Another loader for the same authority gets its own table.
        other = AuthorizedSafeLoader(TEAM_DOC, team_authority)
        try:
            assert other.yaml_constructors is not loader.yaml_constructors
            assert other.yaml_constructors[TEAM_TAG] is team_constructor
        finally:
            other.dispose()
    finally:
        loader.dispose()

    # A loader for the other authority cannot widen its scope locally.
    blocked = AuthorizedSafeLoader(TEAM_DOC, vendor_authority)
    try:
        with pytest.raises(TagAuthorizationError, match=TEAM_TAG):
            blocked.register(TEAM_TAG)
        with pytest.raises(TagAuthorizationError):
            blocked.register(TEAM_TAG, team_constructor)
    finally:
        blocked.dispose()

    # Revocation also locks the instance-level entry point.
    team_authority.revoke(TEAM_TAG)
    stale = AuthorizedSafeLoader(TEAM_DOC, team_authority)
    try:
        with pytest.raises(TagAuthorizationError):
            stale.register(TEAM_TAG)
    finally:
        stale.dispose()


def test_loaders_do_not_mutate_each_other_or_global_table(
        team_authority, vendor_authority):
    team_loader = AuthorizedSafeLoader(TEAM_DOC, team_authority)
    vendor_loader = AuthorizedSafeLoader(VENDOR_DOC, vendor_authority)
    try:
        assert TEAM_TAG in team_loader.yaml_constructors
        assert VENDOR_TAG not in team_loader.yaml_constructors
        assert VENDOR_TAG in vendor_loader.yaml_constructors
        assert TEAM_TAG not in vendor_loader.yaml_constructors
    finally:
        team_loader.dispose()
        vendor_loader.dispose()

    assert TEAM_TAG not in yaml.SafeLoader.yaml_constructors
    assert VENDOR_TAG not in yaml.SafeLoader.yaml_constructors


def test_audit_trails_are_partitioned_by_authority(
        team_authority, vendor_authority):
    authorized_safe_load(TEAM_DOC, team_authority)
    with pytest.raises(yaml.constructor.ConstructorError):
        authorized_safe_load(TEAM_DOC, vendor_authority)
    authorized_safe_load(VENDOR_DOC, vendor_authority)

    team_events = team_authority.review()
    vendor_events = vendor_authority.review()
    assert {e['authority'] for e in team_events} == {'team'}
    assert {e['authority'] for e in vendor_events} == {'third_party'}
    assert all(e['tag'] != VENDOR_TAG for e in team_events)
    assert {e['tag'] for e in vendor_events} == {TEAM_TAG, VENDOR_TAG}


def test_authorized_safe_load_all(team_authority):
    stream = 'a: !team/internal 1\n---\nb: !team/internal 2\n'
    docs = list(authorized_safe_load_all(stream, team_authority))
    assert docs == [{'a': ('team', '1')}, {'b': ('team', '2')}]

    vendor = TagAuthority('third_party')
    with pytest.raises(yaml.constructor.ConstructorError):
        list(authorized_safe_load_all(stream, vendor))
