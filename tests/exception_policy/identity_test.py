import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.exception_policy import SecretIdentity


def test_same_content_same_identity_regardless_of_location():
    first = SecretIdentity.from_potential_secret(
        PotentialSecret(type="AWS", filename="old/app.yaml", secret="abc", line_number=1),
    )
    moved = SecretIdentity.from_potential_secret(
        PotentialSecret(type="AWS", filename="new/app.yaml", secret="abc", line_number=99),
    )
    assert first == moved


def test_rotated_secret_gets_new_identity():
    old = SecretIdentity.from_hashed_secret(
        "AWS", PotentialSecret.hash_secret("old-key"),
    )
    rotated = SecretIdentity.from_hashed_secret(
        "AWS", PotentialSecret.hash_secret("new-key"),
    )
    assert old != rotated


def test_type_is_part_of_identity():
    digest = PotentialSecret.hash_secret("abc")
    assert SecretIdentity.from_hashed_secret("AWS", digest) != SecretIdentity.from_hashed_secret(
        "GCP", digest,
    )


def test_baseline_hash_round_trips():
    # Replaying from a baseline (hash only) must resolve to the same identity
    # as a live scan, without reconstructing plaintext.
    live = SecretIdentity.from_potential_secret(
        PotentialSecret(type="AWS", filename="x", secret="abc"),
    )
    replayed = SecretIdentity.from_dict(live.to_dict())
    assert replayed == live
    assert "abc" not in str(replayed.to_dict())


def test_rejects_empty_inputs():
    with pytest.raises(ValueError):
        SecretIdentity.from_plaintext("AWS", "")
    with pytest.raises(ValueError):
        SecretIdentity.from_hashed_secret("", "deadbeef")
