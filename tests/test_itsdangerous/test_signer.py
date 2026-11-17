import hashlib
from functools import partial

import pytest

from itsdangerous.exc import BadSignature
from itsdangerous.signer import HMACAlgorithm
from itsdangerous.signer import NoneAlgorithm
from itsdangerous.signer import Signer
from itsdangerous.signer import SigningAlgorithm


class _ReverseAlgorithm(SigningAlgorithm):
    def get_signature(self, key, value):
        return (key + value)[::-1]


class TestSigner:
    @pytest.fixture()
    def signer_factory(self):
        return partial(Signer, secret_key="secret-key")

    @pytest.fixture()
    def signer(self, signer_factory):
        return signer_factory()

    def test_signer(self, signer):
        signed = signer.sign("my string")
        assert isinstance(signed, bytes)
        assert signer.validate(signed)
        out = signer.unsign(signed)
        assert out == b"my string"

    def test_no_separator(self, signer):
        signed = signer.sign("my string")
        signed = signed.replace(signer.sep, b"*", 1)
        assert not signer.validate(signed)

        with pytest.raises(BadSignature):
            signer.unsign(signed)

    def test_broken_signature(self, signer):
        signed = signer.sign("b")
        bad_signed = signed[:-1]
        bad_sig = bad_signed.rsplit(b".", 1)[1]
        assert not signer.verify_signature(b"b", bad_sig)

        with pytest.raises(BadSignature) as exc_info:
            signer.unsign(bad_signed)

        assert exc_info.value.payload == b"b"

    def test_changed_value(self, signer):
        signed = signer.sign("my string")
        signed = signed.replace(b"my", b"other", 1)
        assert not signer.validate(signed)

        with pytest.raises(BadSignature):
            signer.unsign(signed)

    def test_invalid_separator(self, signer_factory):
        with pytest.raises(ValueError) as exc_info:
            signer_factory(sep="-")

        assert "separator cannot be used" in str(exc_info.value)

    @pytest.mark.parametrize(
        "key_derivation", ("concat", "django-concat", "hmac", "none")
    )
    def test_key_derivation(self, signer_factory, key_derivation):
        signer = signer_factory(key_derivation=key_derivation)
        assert signer.unsign(signer.sign("value")) == b"value"

    def test_invalid_key_derivation(self, signer_factory):
        signer = signer_factory(key_derivation="invalid")

        with pytest.raises(TypeError):
            signer.derive_key()

    def test_digest_method(self, signer_factory):
        signer = signer_factory(digest_method=hashlib.md5)
        assert signer.unsign(signer.sign("value")) == b"value"

    @pytest.mark.parametrize(
        "algorithm", (None, NoneAlgorithm(), HMACAlgorithm(), _ReverseAlgorithm())
    )
    def test_algorithm(self, signer_factory, algorithm):
        signer = signer_factory(algorithm=algorithm)
        assert signer.unsign(signer.sign("value")) == b"value"

        if algorithm is None:
            assert signer.algorithm.digest_method == signer.digest_method

    def test_secret_keys(self):
        signer = Signer("a")
        signed = signer.sign("my string")
        assert isinstance(signed, bytes)

        signer = Signer(["a", "b"])
        assert signer.validate(signed)
        out = signer.unsign(signed)
        assert out == b"my string"


class _RecordingAlgorithm(HMACAlgorithm):
    """Counts how many signatures were verified, to observe whether
    verification exits early or checks every key.
    """

    def __init__(self):
        super().__init__()
        self.calls = 0

    def verify_signature(self, key, value, sig):
        self.calls += 1
        return super().verify_signature(key, value, sig)


def _strip_key_id(signer, signed):
    """Remove the key id prefix from a signed value, producing the
    legacy format used before key ids existed.
    """
    value, sig = signed.rsplit(signer.sep, 1)
    return value + signer.sep + sig[signer.key_id_length :]


class TestKeyId:
    def test_sign_includes_key_id(self):
        signer = Signer("secret-key")
        signed = signer.sign("my string")
        sig = signed.rsplit(signer.sep, 1)[1]
        assert sig.startswith(signer.key_id)
        assert len(signer.key_id) == signer.key_id_length
        assert signer.key_id == signer.get_key_id(b"secret-key")

    def test_key_id_distinct_per_key(self):
        signer = Signer(["a", "b"])
        assert len(set(signer.key_ids)) == 2
        assert signer.key_ids == [signer.get_key_id(b"a"), signer.get_key_id(b"b")]
        assert signer.key_id == signer.key_ids[-1]

    def test_missing_key_id_falls_back(self):
        signer = Signer("secret-key")
        legacy = _strip_key_id(signer, signer.sign("my string"))
        assert signer.unsign(legacy) == b"my string"

    def test_unknown_key_id_falls_back(self):
        signer = Signer("secret-key")
        signed = signer.sign("my string")
        value, sig = signed.rsplit(signer.sep, 1)
        unknown_id = b"0" * signer.key_id_length
        assert unknown_id != signer.key_id
        forged = value + signer.sep + unknown_id + sig[signer.key_id_length :]

        with pytest.raises(BadSignature):
            signer.unsign(forged)

    def test_key_rotation(self):
        old_signed = Signer("old-key").sign("data")
        rotated = Signer(["old-key", "new-key"])
        # A signature made by an old key is still accepted, selected by id.
        assert rotated.unsign(old_signed) == b"data"
        # New signatures use the newest key's id.
        new_signed = rotated.sign("data")
        sig = new_signed.rsplit(rotated.sep, 1)[1]
        assert sig.startswith(rotated.get_key_id(b"new-key"))

        # Retiring the old key rejects its signatures, new ones still pass.
        retired = Signer("new-key")
        assert retired.unsign(new_signed) == b"data"

        with pytest.raises(BadSignature):
            retired.unsign(old_signed)

    def test_key_id_selects_single_key(self):
        algorithm = _RecordingAlgorithm()
        signer = Signer(["k1", "k2", "k3"], algorithm=algorithm)
        signed = signer.sign("data")
        algorithm.calls = 0
        assert signer.validate(signed)
        assert algorithm.calls == 1

    def test_fallback_checks_all_keys(self):
        # Without a known key id, every key is tried without exiting
        # early, so timing does not reveal which key matched.
        algorithm = _RecordingAlgorithm()
        signer = Signer(["k1", "k2", "k3"], algorithm=algorithm)
        legacy = _strip_key_id(signer, signer.sign("data"))
        algorithm.calls = 0
        assert signer.unsign(legacy) == b"data"
        assert algorithm.calls == 3

    def test_unknown_key_id_checks_all_keys(self):
        algorithm = _RecordingAlgorithm()
        signer = Signer(["k1", "k2", "k3"], algorithm=algorithm)
        signed = signer.sign("data")
        value, sig = signed.rsplit(signer.sep, 1)
        forged = value + signer.sep + b"0" * signer.key_id_length + sig
        algorithm.calls = 0
        assert not signer.validate(forged)
        assert algorithm.calls == 3


def test_abstract_algorithm():
    alg = SigningAlgorithm()

    with pytest.raises(NotImplementedError):
        alg.get_signature(b"a", b"b")
