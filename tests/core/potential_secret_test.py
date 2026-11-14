import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from testing.factories import potential_secret_factory


@pytest.mark.parametrize(
    'a, b, is_equal',
    [
        (
            potential_secret_factory(line_number=1),
            potential_secret_factory(line_number=2),
            True,
        ),
        (
            potential_secret_factory(type='A'),
            potential_secret_factory(type='B'),
            False,
        ),
        (
            potential_secret_factory(secret='A'),
            potential_secret_factory(secret='B'),
            False,
        ),
    ],
)
def test_equality(a, b, is_equal):
    assert (a == b) is is_equal

    # As a sanity check that it works both ways
    assert (a != b) is not is_equal


def test_secret_storage():
    secret = potential_secret_factory(secret='secret')
    assert secret.secret_hash != 'secret'


def test_json():
    secret = potential_secret_factory(secret='blah')
    for value in secret.json().values():
        assert value != 'blah'


@pytest.mark.parametrize(
    'kwargs',
    (
        {
            'line_number': 0,
        },
        {
            'is_secret': True,
            'is_verified': False,
        },
    ),
)
def test_load_secret_from_dict(kwargs):
    secret = potential_secret_factory(**kwargs)
    new_secret = PotentialSecret.load_secret_from_dict(secret.json())

    assert secret == new_secret
    assert new_secret.secret_value is None


def test_end_line_number_round_trip():
    secret = potential_secret_factory(line_number=2, end_line_number=5)

    data = secret.json()
    assert data['end_line_number'] == 5

    new_secret = PotentialSecret.load_secret_from_dict(data)
    assert new_secret.end_line_number == 5
    assert secret == new_secret


def test_end_line_number_not_serialized_when_absent():
    # Baselines for single-line secrets must remain byte-for-byte compatible.
    assert 'end_line_number' not in potential_secret_factory().json()


def test_end_line_number_does_not_affect_equality():
    a = potential_secret_factory(end_line_number=5)
    b = potential_secret_factory(end_line_number=9)

    assert a == b
    assert hash(a) == hash(b)


def test_multiline_secret_hash_is_content_based():
    # The fingerprint of a multi-line secret is the hash of its full content,
    # so it stays stable regardless of where the secret appears in a file.
    block = (
        '-----BEGIN PRIVATE KEY-----\n'
        'super secret body\n'
        '-----END PRIVATE KEY-----'
    )
    secret = potential_secret_factory(secret=block, line_number=2, end_line_number=4)

    assert secret.secret_hash == PotentialSecret.hash_secret(block)


def test_stringify():
    secret = potential_secret_factory(type='secret_type', secret='blah')
    assert str(secret) == (
        'Secret Type: secret_type\n'
        'Location:    filename:1\n'
    )
