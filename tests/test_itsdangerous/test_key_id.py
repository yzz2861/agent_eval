from concurrent.futures import ThreadPoolExecutor

import pytest

from itsdangerous.exc import BadSignature
from itsdangerous.serializer import Serializer
from itsdangerous.signer import Signer
from itsdangerous.timed import TimestampSigner


class TestSignerKeyId:
    @pytest.fixture()
    def signer(self):
        return Signer({"k1": "old-secret", "k2": "new-secret"})

    def test_sign_embeds_key_id(self, signer):
        signed = signer.sign("my string")
        value, key_id, sig = signed.rsplit(b".", 2)
        assert value == b"my string"
        assert key_id == b"k2"
        assert signer.unsign(signed) == b"my string"
        assert signer.validate(signed)

    def test_get_key_id(self, signer):
        signed = signer.sign("my string")
        assert signer.get_key_id(signed) == b"k2"
        assert signer.get_key_id(b"no separator") is None

    def test_newest_key_signs(self):
        signer = Signer({"k1": "one", "k2": "two", "k3": "three"})
        assert signer.get_key_id(signer.sign("v")) == b"k3"
        assert signer.secret_key == b"three"

    def test_rotation_old_key_verifies(self):
        old_signer = Signer({"k1": "old-secret"})
        signed = old_signer.sign("my string")
        assert old_signer.get_key_id(signed) == b"k1"

        rotated = Signer({"k1": "old-secret", "k2": "new-secret"})
        assert rotated.unsign(signed) == b"my string"
        assert rotated.get_key_id(rotated.sign("my string")) == b"k2"

    def test_rotation_drop_old_key(self):
        old_signer = Signer({"k1": "old-secret", "k2": "new-secret"})
        signed = old_signer.sign("my string")

        rotated = Signer({"k2": "new-secret"})
        assert rotated.unsign(signed) == b"my string"

        old_signed = Signer({"k1": "old-secret"}).sign("my string")

        with pytest.raises(BadSignature):
            rotated.unsign(old_signed)

    def test_unknown_key_id(self, signer):
        signed = signer.sign("my string")
        forged = signed.replace(b".k2.", b".k9.")
        assert not signer.validate(forged)

        with pytest.raises(BadSignature):
            signer.unsign(forged)

    def test_other_signer_key_id_unknown(self, signer):
        other = Signer({"k9": "new-secret"})
        signed = other.sign("my string")
        assert not signer.validate(signed)

    def test_missing_key_id_legacy_token(self, signer):
        legacy = Signer(["old-secret", "new-secret"])
        signed = legacy.sign("my string")
        assert signer.get_key_id(signed) is None
        assert signer.unsign(signed) == b"my string"

    def test_legacy_signer_unchanged(self):
        signer = Signer(["old-secret", "new-secret"])
        signed = signer.sign("my string")
        assert signed.rsplit(b".", 1)[0] == b"my string"
        assert signer.unsign(signed) == b"my string"

    def test_single_key_legacy_token(self):
        legacy = Signer("new-secret")
        signed = legacy.sign("my string")
        keyed = Signer({"k2": "new-secret"})
        assert keyed.unsign(signed) == b"my string"

    def test_tampered_value(self, signer):
        signed = signer.sign("my string").replace(b"my", b"other", 1)
        assert not signer.validate(signed)

        with pytest.raises(BadSignature):
            signer.unsign(signed)

    def test_verify_signature_with_key_id(self, signer):
        signed = signer.sign("my string")
        value, key_id, sig = signed.rsplit(b".", 2)
        assert signer.verify_signature(value, sig, key_id=key_id)
        assert not signer.verify_signature(value, sig, key_id=b"k1")
        assert not signer.verify_signature(value, sig, key_id=b"k9")

    def test_verify_signature_key_id_without_map(self):
        signer = Signer("secret")
        signed = signer.sign("my string")
        value, sig = signed.rsplit(b".", 1)
        assert not signer.verify_signature(value, sig, key_id=b"k1")

    @pytest.mark.parametrize("key_id", ("", "has.sep"))
    def test_invalid_key_id(self, key_id):
        with pytest.raises(ValueError) as exc_info:
            Signer({key_id: "secret"})

        assert "Key ids" in str(exc_info.value)

    def test_bytes_key_id(self):
        signer = Signer({b"k1": "secret"})
        signed = signer.sign("my string")
        assert signer.get_key_id(signed) == b"k1"
        assert signer.unsign(signed) == b"my string"

    def test_value_with_separator(self, signer):
        signed = signer.sign("a.b.c")
        assert signer.get_key_id(signed) == b"k2"
        assert signer.unsign(signed) == b"a.b.c"

    def test_concurrent_sign_unsign(self, signer):
        legacy = Signer(["old-secret", "new-secret"])
        legacy_signed = legacy.sign("shared")

        def work(i):
            signed = signer.sign(f"value-{i}")
            assert signer.get_key_id(signed) == b"k2"
            assert signer.unsign(signed) == f"value-{i}".encode()
            assert signer.unsign(legacy_signed) == b"shared"
            return signer.validate(signed)

        with ThreadPoolExecutor(max_workers=8) as pool:
            assert all(pool.map(work, range(200)))


class TestSerializerKeyId:
    def test_dumps_loads(self):
        serializer = Serializer({"k1": "old-secret", "k2": "new-secret"})
        signed = serializer.dumps({"a": 1})
        assert serializer.loads(signed) == {"a": 1}
        assert serializer.make_signer().get_key_id(signed) == b"k2"

    def test_rotation(self):
        old_serializer = Serializer({"k1": "old-secret"})
        old_signed = old_serializer.dumps({"a": 1})

        rotated = Serializer({"k1": "old-secret", "k2": "new-secret"})
        assert rotated.loads(old_signed) == {"a": 1}
        new_signed = rotated.dumps({"a": 1})

        dropped = Serializer({"k2": "new-secret"})
        assert dropped.loads(new_signed) == {"a": 1}

        with pytest.raises(BadSignature):
            dropped.loads(old_signed)

    def test_legacy_token_fallback(self):
        legacy = Serializer(["old-secret", "new-secret"])
        signed = legacy.dumps({"a": 1})

        keyed = Serializer({"k1": "old-secret", "k2": "new-secret"})
        assert keyed.make_signer().get_key_id(signed) is None
        assert keyed.loads(signed) == {"a": 1}

    def test_unknown_key_id(self):
        serializer = Serializer({"k1": "old-secret", "k2": "new-secret"})
        signed = serializer.dumps({"a": 1}).replace(".k2.", ".k9.")

        with pytest.raises(BadSignature):
            serializer.loads(signed)

    def test_concurrent_loads(self):
        serializer = Serializer({"k1": "old-secret", "k2": "new-secret"})
        tokens = [serializer.dumps({"i": i}) for i in range(50)]

        def work(i):
            assert serializer.loads(tokens[i % 50]) == {"i": i % 50}
            return serializer.make_signer().get_key_id(tokens[i % 50])

        with ThreadPoolExecutor(max_workers=8) as pool:
            assert set(pool.map(work, range(500))) == {b"k2"}


class TestTimestampSignerKeyId:
    def test_sign_unsign(self):
        signer = TimestampSigner({"k1": "old-secret", "k2": "new-secret"})
        signed = signer.sign("my string")
        assert signer.get_key_id(signed) == b"k2"
        assert signer.unsign(signed, max_age=60) == b"my string"

    def test_legacy_token_fallback(self):
        legacy = TimestampSigner(["old-secret", "new-secret"])
        signed = legacy.sign("my string")
        keyed = TimestampSigner({"k1": "old-secret", "k2": "new-secret"})
        assert keyed.unsign(signed, max_age=60) == b"my string"
