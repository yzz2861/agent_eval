from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import partial

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.keyed import KeyedSerializer
from itsdangerous.keyed import KeyedSigner
from itsdangerous.keyed import KeyedTimedSerializer
from itsdangerous.keyed import KeyedTimestampSigner
from itsdangerous.keyed import KeyedURLSafeSerializer
from itsdangerous.keyed import KeyedURLSafeTimedSerializer
from itsdangerous.keyed import UnknownKeyId
from itsdangerous.serializer import Serializer
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from itsdangerous.url_safe import URLSafeSerializer

KEYS = {"k1": "old-secret", "k2": "new-secret"}


class TestKeyedSigner:
    @pytest.fixture()
    def signer_factory(self):
        return partial(KeyedSigner, KEYS)

    @pytest.fixture()
    def signer(self, signer_factory):
        return signer_factory()

    def test_sign_format(self, signer):
        signed = signer.sign("my string")
        assert isinstance(signed, bytes)
        assert signed.startswith(b"v1.k2.my string.")
        assert signer.unsign(signed) == b"my string"
        assert signer.validate(signed)

    def test_unsign_with_info_active_key(self, signer):
        info = signer.unsign_with_info(signer.sign("value"))
        assert info.value == b"value"
        assert info.key_id == "k2"
        assert not info.legacy
        assert not info.resign_recommended
        assert info.timestamp is None

    def test_rotation_old_key_still_verifies(self, signer_factory):
        old_signer = signer_factory(active_key_id="k1")
        signed = old_signer.sign("value")
        assert signed.startswith(b"v1.k1.")

        new_signer = signer_factory(active_key_id="k2")
        info = new_signer.unsign_with_info(signed)
        assert info.value == b"value"
        assert info.key_id == "k1"
        assert not info.legacy
        assert info.resign_recommended

    def test_unknown_key_id_fails_immediately(self, signer):
        signed = signer.sign("value").replace(b"v1.k2.", b"v1.k9.")

        with pytest.raises(UnknownKeyId) as exc_info:
            signer.unsign(signed)

        assert exc_info.value.key_id == "k9"
        assert exc_info.value.payload == b"value"

    def test_unknown_key_id_no_legacy_fallback(self, signer_factory):
        # Even with the compatibility flag, an unknown id must not fall
        # back to trying every key.
        signer = signer_factory(accept_legacy=True)
        signed = signer.sign("value").replace(b"v1.k2.", b"v1.k9.")

        with pytest.raises(UnknownKeyId):
            signer.unsign(signed)

    def test_tampered_key_id_rejected(self, signer):
        # k1 is a known id, but the signature covers the original id.
        signed = signer.sign("value").replace(b"v1.k2.", b"v1.k1.")
        assert not signer.validate(signed)

        with pytest.raises(BadSignature) as exc_info:
            signer.unsign(signed)

        assert not isinstance(exc_info.value, UnknownKeyId)

    def test_tampered_version_rejected(self, signer):
        signed = signer.sign("value").replace(b"v1.", b"v2.", 1)
        assert not signer.validate(signed)

        with pytest.raises(BadSignature):
            signer.unsign(signed)

    def test_other_version_verifies_but_resign_recommended(self, signer_factory):
        signed = signer_factory(version=2).sign("value")
        assert signed.startswith(b"v2.k2.")

        info = signer_factory(version=1).unsign_with_info(signed)
        assert info.value == b"value"
        assert info.key_id == "k2"
        assert info.resign_recommended

    def test_legacy_rejected_by_default(self, signer):
        legacy = Signer("new-secret").sign("value")
        assert not signer.validate(legacy)

        with pytest.raises(BadSignature):
            signer.unsign(legacy)

    def test_legacy_accepted_with_flag(self, signer_factory):
        signer = signer_factory(accept_legacy=True)
        legacy = Signer("new-secret").sign("value")
        info = signer.unsign_with_info(legacy)
        assert info.value == b"value"
        assert info.key_id is None
        assert info.legacy
        assert info.resign_recommended

    def test_legacy_tries_all_keys(self, signer_factory):
        signer = signer_factory(accept_legacy=True)
        legacy = Signer("old-secret").sign("value")
        assert signer.unsign(legacy) == b"value"

    def test_salt_isolation(self, signer_factory):
        signed = signer_factory(salt="one").sign("value")

        with pytest.raises(BadSignature):
            signer_factory(salt="two").unsign(signed)

    @pytest.mark.parametrize("key_id", ("", "has space", "bad.id"))
    def test_invalid_key_id(self, key_id):
        with pytest.raises(ValueError):
            KeyedSigner({key_id: "secret"})

    def test_active_key_id_must_exist(self):
        with pytest.raises(ValueError):
            KeyedSigner(KEYS, active_key_id="k9")

    def test_secret_keys_must_be_mapping(self):
        with pytest.raises(TypeError):
            KeyedSigner(["old-secret", "new-secret"])

    def test_invalid_version(self, signer_factory):
        with pytest.raises(ValueError):
            signer_factory(version=0)

    def test_old_api_format_unchanged(self):
        # The existing signer does not add an envelope, and its output
        # is accepted by a keyed signer in legacy mode.
        signed = Signer("secret-key").sign("my string")
        value, _ = signed.rsplit(b".", 1)
        assert value == b"my string"
        assert not signed.startswith(b"v1.")

        keyed = KeyedSigner({"k1": "secret-key"}, accept_legacy=True)
        assert keyed.unsign(signed) == b"my string"


class TestKeyedTimestampSigner:
    @pytest.fixture()
    def ts(self):
        return datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)

    @pytest.fixture(autouse=True)
    def freeze(self, ts):
        with freeze_time(ts) as ft:
            yield ft

    @pytest.fixture()
    def signer(self):
        return KeyedTimestampSigner(KEYS)

    def test_sign_unsign(self, signer, ts):
        signed = signer.sign("value")
        assert signed.startswith(b"v1.k2.value.")
        assert signer.unsign(signed) == b"value"
        assert signer.unsign(signed, return_timestamp=True) == (b"value", ts)

    def test_max_age(self, signer, freeze):
        signed = signer.sign("value")
        freeze.tick()
        assert signer.unsign(signed, max_age=10) == b"value"
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired):
            signer.unsign(signed, max_age=10)

    def test_unsign_with_info(self, signer, ts):
        info = signer.unsign_with_info(signer.sign("value"))
        assert info.value == b"value"
        assert info.key_id == "k2"
        assert not info.legacy
        assert not info.resign_recommended
        assert info.timestamp == ts

    def test_unsign_with_info_max_age(self, signer, freeze):
        signed = signer.sign("value")
        freeze.tick(timedelta(seconds=20))

        with pytest.raises(SignatureExpired):
            signer.unsign_with_info(signed, max_age=10)

    def test_rotation(self):
        old_signer = KeyedTimestampSigner(KEYS, active_key_id="k1")
        signed = old_signer.sign("value")
        info = KeyedTimestampSigner(KEYS).unsign_with_info(signed)
        assert info.value == b"value"
        assert info.key_id == "k1"
        assert info.resign_recommended

    def test_unknown_key_id(self, signer):
        signed = signer.sign("value").replace(b"v1.k2.", b"v1.k9.")

        with pytest.raises(UnknownKeyId):
            signer.unsign(signed)

    def test_tampered_key_id(self, signer):
        signed = signer.sign("value").replace(b"v1.k2.", b"v1.k1.")

        with pytest.raises(BadSignature):
            signer.unsign(signed)

    def test_legacy_timed(self, ts):
        legacy = TimestampSigner("new-secret").sign("value")
        signer = KeyedTimestampSigner(KEYS, accept_legacy=True)
        assert signer.unsign(legacy, return_timestamp=True) == (b"value", ts)

        info = signer.unsign_with_info(legacy)
        assert info.legacy
        assert info.key_id is None
        assert info.timestamp == ts


class TestKeyedSerializer:
    def test_roundtrip(self):
        serializer = KeyedSerializer(KEYS)
        signed = serializer.dumps({"a": 1})
        assert signed.startswith("v1.k2.")
        assert serializer.loads(signed) == {"a": 1}

    def test_loads_with_info(self):
        serializer = KeyedSerializer(KEYS)
        payload, info = serializer.loads_with_info(serializer.dumps({"a": 1}))
        assert payload == {"a": 1}
        assert info.key_id == "k2"
        assert not info.legacy
        assert not info.resign_recommended

    def test_rotation(self):
        old_serializer = KeyedSerializer(KEYS, active_key_id="k1")
        signed = old_serializer.dumps("value")

        new_serializer = KeyedSerializer(KEYS)
        payload, info = new_serializer.loads_with_info(signed)
        assert payload == "value"
        assert info.key_id == "k1"
        assert info.resign_recommended

    def test_unknown_key_id(self):
        serializer = KeyedSerializer(KEYS)
        signed = serializer.dumps("value").replace("v1.k2.", "v1.k9.")

        with pytest.raises(UnknownKeyId):
            serializer.loads(signed)

    def test_tampered_key_id(self):
        serializer = KeyedSerializer(KEYS)
        signed = serializer.dumps("value").replace("v1.k2.", "v1.k1.")

        with pytest.raises(BadSignature):
            serializer.loads(signed)

    def test_legacy(self):
        legacy = Serializer("new-secret").dumps("value")
        assert KeyedSerializer(KEYS, accept_legacy=True).loads(legacy) == "value"

        with pytest.raises(BadSignature):
            KeyedSerializer(KEYS).loads(legacy)

    def test_salt_isolation(self):
        signed = KeyedSerializer(KEYS, salt="one").dumps("value")

        with pytest.raises(BadSignature):
            KeyedSerializer(KEYS, salt="two").loads(signed)

    def test_old_api_format_unchanged(self):
        # The existing serializer produces the unversioned format.
        signed = Serializer("secret-key").dumps("value")
        assert signed == Signer("secret-key", salt=b"itsdangerous").sign(
            b'"value"'
        ).decode("utf-8")
        assert not signed.startswith("v1.")


class TestKeyedTimedSerializer:
    @pytest.fixture()
    def ts(self):
        return datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)

    @pytest.fixture(autouse=True)
    def freeze(self, ts):
        with freeze_time(ts) as ft:
            yield ft

    def test_roundtrip(self, ts):
        serializer = KeyedTimedSerializer(KEYS)
        signed = serializer.dumps("value")
        assert serializer.loads(signed) == "value"
        assert serializer.loads(signed, return_timestamp=True) == ("value", ts)

    def test_max_age(self, freeze):
        serializer = KeyedTimedSerializer(KEYS)
        signed = serializer.dumps("value")
        freeze.tick(timedelta(seconds=10))
        assert serializer.loads(signed, max_age=10) == "value"

        with pytest.raises(SignatureExpired):
            serializer.loads(signed, max_age=5)

    def test_loads_with_info(self, ts):
        serializer = KeyedTimedSerializer(KEYS)
        payload, info = serializer.loads_with_info(
            serializer.dumps("value"), max_age=60
        )
        assert payload == "value"
        assert info.key_id == "k2"
        assert info.timestamp == ts

    def test_legacy(self):
        legacy = TimedSerializer("new-secret").dumps("value")
        serializer = KeyedTimedSerializer(KEYS, accept_legacy=True)
        assert serializer.loads(legacy, max_age=60) == "value"

        with pytest.raises(BadSignature):
            KeyedTimedSerializer(KEYS).loads(legacy)


class TestKeyedURLSafeSerializer:
    def test_roundtrip(self):
        serializer = KeyedURLSafeSerializer(KEYS)
        signed = serializer.dumps({"a": [1, 2, 3]})
        assert signed.startswith("v1.k2.")
        assert serializer.loads(signed) == {"a": [1, 2, 3]}

        payload, info = serializer.loads_with_info(signed)
        assert payload == {"a": [1, 2, 3]}
        assert info.key_id == "k2"
        assert not info.resign_recommended

    def test_rotation_and_tampering(self):
        old_serializer = KeyedURLSafeSerializer(KEYS, active_key_id="k1")
        signed = old_serializer.dumps("value")

        new_serializer = KeyedURLSafeSerializer(KEYS)
        payload, info = new_serializer.loads_with_info(signed)
        assert payload == "value"
        assert info.key_id == "k1"
        assert info.resign_recommended

        tampered = signed.replace("v1.k1.", "v1.k2.")

        with pytest.raises(BadSignature):
            new_serializer.loads(tampered)

    def test_legacy(self):
        legacy = URLSafeSerializer("new-secret").dumps("value")
        serializer = KeyedURLSafeSerializer(KEYS, accept_legacy=True)
        assert serializer.loads(legacy) == "value"


class TestKeyedURLSafeTimedSerializer:
    @pytest.fixture()
    def ts(self):
        return datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)

    @pytest.fixture(autouse=True)
    def freeze(self, ts):
        with freeze_time(ts) as ft:
            yield ft

    def test_roundtrip_max_age(self, freeze):
        serializer = KeyedURLSafeTimedSerializer(KEYS)
        signed = serializer.dumps("value")
        freeze.tick(timedelta(seconds=5))
        assert serializer.loads(signed, max_age=10) == "value"

        with pytest.raises(SignatureExpired):
            serializer.loads(signed, max_age=1)

    def test_loads_with_info(self, ts):
        serializer = KeyedURLSafeTimedSerializer(KEYS)
        payload, info = serializer.loads_with_info(
            serializer.dumps("value"), max_age=60
        )
        assert payload == "value"
        assert info.key_id == "k2"
        assert info.timestamp == ts
