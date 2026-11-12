import hashlib
from functools import partial

import pytest
from itsdangerous.encoding import base64_encode
from itsdangerous.exc import BadSignature
from itsdangerous.exc import PolicyError
from itsdangerous.exc import UnsupportedAlgorithm
from itsdangerous.exc import WeakDigestError
from itsdangerous.exc import WeakKeyError
from itsdangerous.signer import HMACAlgorithm
from itsdangerous.signer import NoneAlgorithm
from itsdangerous.signer import SignaturePolicy
from itsdangerous.signer import Signer
from itsdangerous.signer import SigningAlgorithm
from itsdangerous.signer import SigningPolicy
from itsdangerous.signer import VerificationPolicy


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


class TestSignerPolicy:
    key = b"k" * 32

    @pytest.fixture()
    def policies(self):
        signing = SigningPolicy(
            digest_method=hashlib.sha256, min_key_bits=128, key_derivation="hmac"
        )
        verification = VerificationPolicy(
            allowed_digests=(hashlib.sha1, hashlib.sha256),
            min_key_bits=128,
            key_derivations=("django-concat", "hmac"),
        )
        return SignaturePolicy(signing, verification)

    def test_bytes_and_str_keys(self, policies):
        for key in (self.key, self.key.decode()):
            signer = Signer(key, policy=policies)
            assert signer.unsign(signer.sign(b"value")) == b"value"

    def test_short_key_rejected_at_startup(self, policies):
        with pytest.raises(WeakKeyError):
            Signer(b"short", policy=policies)

    def test_policy_defaults_are_strong(self):
        signing = SigningPolicy()
        verification = VerificationPolicy()
        assert signing.digest_method is hashlib.sha256
        assert signing.key_derivation == "hmac"
        assert verification.allowed_digests == (hashlib.sha256,)
        assert not verification.allow_none

        with pytest.raises(PolicyError):
            SigningPolicy(digest_method=None)

        assert VerificationPolicy(None).allow_none

    def test_weak_digest_rejected_at_startup(self):
        with pytest.raises(WeakDigestError):
            SigningPolicy(digest_method=hashlib.sha1, key_derivation="hmac")

    @pytest.mark.parametrize("digest_method", (hashlib.sha1, hashlib.sha256))
    def test_verification_legacy_digests(self, digest_method):
        legacy = Signer(self.key, digest_method=digest_method).sign(b"legacy")
        verifier = Signer(
            self.key,
            verification_policy=VerificationPolicy(
                allowed_digests=(hashlib.sha1, hashlib.sha256),
                min_key_bits=128,
                key_derivations=("django-concat", "hmac"),
            ),
        )
        assert verifier.unsign(legacy) == b"legacy"

    def test_underived_key_rejected(self):
        with pytest.raises(PolicyError):
            SigningPolicy(digest_method=hashlib.sha256, key_derivation="none")

    def test_algorithm_downgrade_rejected(self, policies):
        with pytest.raises(PolicyError):
            Signer(
                self.key,
                policy=policies,
                algorithm=HMACAlgorithm(hashlib.sha1),
            )

        with pytest.raises(PolicyError):
            Signer(self.key, policy=policies, algorithm=NoneAlgorithm())

    def test_unsupported_algorithm_rejected(self, policies):
        with pytest.raises(UnsupportedAlgorithm):
            Signer(self.key, policy=policies, algorithm=_ReverseAlgorithm())

        with pytest.raises(UnsupportedAlgorithm):
            SigningPolicy(digest_method="sha999", key_derivation="hmac")

    def test_policy_reads_legacy_but_writes_current_digest(self, policies):
        legacy = Signer(self.key).sign(b"legacy")
        modern = Signer(self.key, policy=policies)
        assert modern.unsign(legacy) == b"legacy"

        signed = modern.sign(b"current")
        value, sig = signed.rsplit(b".", 1)
        expected = HMACAlgorithm(hashlib.sha256).get_signature(
            modern.derive_key(), value
        )
        assert sig == base64_encode(expected)

    def test_key_list(self, policies):
        signer = Signer([b"a" * 32, b"b" * 32], policy=policies)
        assert signer.unsign(signer.sign(b"value")) == b"value"

        old = Signer([b"a" * 32], policy=policies).sign(b"value")
        assert signer.unsign(old) == b"value"

    def test_none_is_explicit_verification_only(self, policies):
        unsigned = Signer(self.key, algorithm=NoneAlgorithm()).sign(b"value")
        verifier = Signer(
            self.key,
            verification_policy=VerificationPolicy(
                allowed_digests=(None,), min_key_bits=128
            ),
        )
        assert verifier.unsign(unsigned) == b"value"

        with pytest.raises(PolicyError):
            verifier.sign(b"new")

        with pytest.raises(PolicyError):
            Signer(self.key, policy=policies, algorithm="none")

    def test_explicit_verify_only_with_both_policies(self, policies):
        signer = Signer(self.key, policy=policies, verify_only=True)
        assert signer.verify_only
        legacy = Signer(self.key).sign(b"value")
        assert signer.unsign(legacy) == b"value"

        with pytest.raises(PolicyError):
            signer.sign(b"value")

    def test_tampering_is_bad_signature_not_policy_error(self, policies):
        signer = Signer(self.key, policy=policies)
        signed = signer.sign(b"value")

        with pytest.raises(BadSignature) as exc_info:
            signer.unsign(signed.replace(b"value", b"other"))

        assert not isinstance(exc_info.value, PolicyError)

    def test_instances_are_isolated(self, policies):
        first = Signer(self.key, policy=policies)
        second = Signer(self.key)
        assert first.digest_method is hashlib.sha256
        assert second.digest_method is Signer.default_digest_method
        assert first.sign(b"value") != second.sign(b"value")

        first.algorithm.digest_method = hashlib.sha512
        assert second.algorithm.digest_method is Signer.default_digest_method


def test_abstract_algorithm():
    alg = SigningAlgorithm()

    with pytest.raises(NotImplementedError):
        alg.get_signature(b"a", b"b")
