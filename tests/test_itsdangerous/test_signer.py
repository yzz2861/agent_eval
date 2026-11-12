import hashlib
import logging
import time
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

    def test_secret_keys_deduplicated(self):
        signer = Signer(["a", "a", "b"])
        assert signer.secret_keys == [b"a", b"b"]

        # A repeated key keeps its newest (last) position, so the key
        # used for signing does not change.
        signer = Signer(["b", "a", "b"])
        assert signer.secret_keys == [b"a", b"b"]
        assert signer.secret_key == b"b"
        assert Signer("b").validate(signer.sign("value"))

    def test_secret_keys_mixed_str_bytes(self):
        signer = Signer(["old-key", b"new-key"])
        assert signer.secret_keys == [b"old-key", b"new-key"]
        assert signer.unsign(signer.sign("value")) == b"value"

    @pytest.mark.parametrize(
        "secret_key",
        ("", b"", [], ["a", ""], [b"a", b""], iter([])),
    )
    def test_empty_secret_key_rejected(self, secret_key):
        with pytest.raises(ValueError):
            Signer(secret_key)

    def test_short_signing_key_rejected(self, signer_factory):
        # Construction succeeds, the configuration error is raised
        # before signing, not as a runtime exception during it.
        signer = signer_factory(secret_key="abc", min_key_length=8)

        with pytest.raises(ValueError):
            signer.sign("value")

    def test_short_old_key_still_verifies(self, signer_factory):
        old = signer_factory(secret_key="old")
        signed_old = old.sign("value")

        signer = signer_factory(
            secret_key=["old", "new-secret-key"], min_key_length=8
        )
        assert signer.unsign(signer.sign("value")) == b"value"
        assert signer.validate(signed_old)

    def test_invalid_digest_method(self, signer_factory):
        with pytest.raises(ValueError):
            signer_factory(digest_method="not-a-real-hash")

        with pytest.raises(TypeError):
            signer_factory(digest_method=123)

    def test_digest_method_name(self, signer_factory):
        signer = signer_factory(digest_method="sha256")
        assert signer.unsign(signer.sign("value")) == b"value"

    def test_key_rotation(self, signer_factory):
        old = signer_factory(secret_key="old-key")
        signed_old = old.sign("value")

        rotated = signer_factory(secret_key=["old-key", "new-key"])
        assert rotated.unsign(signed_old) == b"value"

        signed_new = rotated.sign("value")
        assert rotated.unsign(signed_new) == b"value"
        assert not old.validate(signed_new)

    def test_all_keys_compared_without_early_exit(self, signer_factory):
        calls = []

        class RecordingAlgorithm(HMACAlgorithm):
            def verify_signature(self, key, value, sig):
                calls.append(key)
                return super().verify_signature(key, value, sig)

        signer = signer_factory(
            secret_key=["k1", "k2", "k3"], algorithm=RecordingAlgorithm()
        )

        # The newest key matches, but every candidate is still compared.
        assert signer.unsign(signer.sign("value")) == b"value"
        assert len(calls) == 3

        # The oldest key matches, the number of comparisons is the same.
        calls.clear()
        signed_old = signer_factory(secret_key="k1").sign("value")
        assert signer.unsign(signed_old) == b"value"
        assert len(calls) == 3

    def test_verify_time_independent_of_key_position(self, signer_factory):
        keys = [f"key-{i}" for i in range(5)]
        signer = signer_factory(secret_key=keys)
        signed_oldest = signer_factory(secret_key=keys[0]).sign("value")
        signed_newest = signer_factory(secret_key=keys[-1]).sign("value")

        def measure(signed, n=300):
            start = time.perf_counter()

            for _ in range(n):
                signer.unsign(signed)

            return time.perf_counter() - start

        # Warm up, then compare relative timings only.
        measure(signed_oldest, 20)
        measure(signed_newest, 20)
        t_oldest = measure(signed_oldest)
        t_newest = measure(signed_newest)
        assert 0.5 < t_oldest / t_newest < 2.0

    def test_unsign_failure_debug_reason(self, signer, caplog):
        logger = "itsdangerous.signer"

        with caplog.at_level(logging.DEBUG, logger=logger):
            with pytest.raises(BadSignature):
                signer.unsign("no separator")

        assert any(
            getattr(record, "reason", None) == "missing-separator"
            for record in caplog.records
        )

        caplog.clear()
        signed = signer.sign("value").replace(b"value", b"other")

        with caplog.at_level(logging.DEBUG, logger=logger):
            with pytest.raises(BadSignature):
                signer.unsign(signed)

        assert any(
            getattr(record, "reason", None) == "bad-signature"
            for record in caplog.records
        )


def test_abstract_algorithm():
    alg = SigningAlgorithm()

    with pytest.raises(NotImplementedError):
        alg.get_signature(b"a", b"b")
