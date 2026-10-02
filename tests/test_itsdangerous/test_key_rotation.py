import hashlib

import pytest

from itsdangerous.exc import BadHeader
from itsdangerous.exc import BadSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.serializer import Serializer
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.url_safe import URLSafeTimedSerializer

KEYS = {"old": "old-secret", "new": "new-secret"}
VALUE = {"id": 42}


class TestVersionedSigner:
    def test_key_rotation(self):
        old_signer = Signer(KEYS, accept_legacy=True)
        new_signer = Signer(KEYS)
        legacy_signed = Signer("old-secret").sign(b"value")
        new_signed = new_signer.sign(b"value")

        assert new_signed.startswith(b"v1.bmV3.")

        legacy_result = old_signer.unsign_with_info(legacy_signed)
        assert legacy_result.value == b"value"
        assert legacy_result.info.version is None
        assert legacy_result.info.key_id == "old"
        assert legacy_result.info.active_key_id == "new"
        assert legacy_result.info.should_resign is True

        old_result = old_signer.unsign_with_info(new_signed)
        assert old_result.value == b"value"
        assert old_result.info.version == 1
        assert old_result.info.key_id == "new"
        assert old_result.info.should_resign is False

        assert new_signer.unsign_with_info(new_signed).info.should_resign is False

    def test_versioned_old_key_is_selected_directly(self):
        old_versioned = Signer({"old": "old-secret"}).sign(b"value")
        current = Signer(KEYS)
        result = current.unsign_with_info(old_versioned)

        assert result.value == b"value"
        assert result.info.version == 1
        assert result.info.key_id == "old"
        assert result.info.should_resign is True

    def test_legacy_requires_explicit_switch(self):
        signer = Signer(KEYS)
        legacy_signed = Signer("old-secret").sign(b"value")

        with pytest.raises(BadHeader, match="Legacy signatures"):
            signer.unsign(legacy_signed)

    def test_unknown_key_id_fails_immediately(self):
        signer = Signer(KEYS)
        signed = signer.sign(b"value")
        authenticated, signature = signed.rsplit(b".", 1)
        unknown = authenticated.replace(b"v1.bmV3.", b"v1.bWlzc2luZw.", 1)

        with pytest.raises(BadHeader, match="Unknown key id") as exc_info:
            signer.unsign(unknown + b"." + signature)

        assert exc_info.value.header == b"v1.bWlzc2luZw"

    def test_tampered_version_header_is_rejected(self):
        signer = Signer(KEYS)
        signed = signer.sign(b"value")

        with pytest.raises(BadHeader):
            signer.unsign(signed.replace(b"v1.bmV3.", b"v2.bmV3.", 1))

        with pytest.raises(BadSignature):
            signer.unsign(signed.replace(b"v1.", b"v1x.", 1))

        swapped = signed.replace(b"v1.bmV3.", b"v1.b2xk.", 1)

        with pytest.raises(BadHeader):
            signer.unsign(swapped)

    def test_unknown_key_id_does_not_traverse_keys(self):
        calls = []

        class TrackingSigner(Signer):
            def derive_key(self, secret_key=None):
                calls.append(secret_key)
                return super().derive_key(secret_key)

        signer = TrackingSigner(KEYS)
        signed = signer.sign(b"value")
        authenticated, signature = signed.rsplit(b".", 1)
        unknown = authenticated.replace(b"v1.bmV3.", b"v1.bWlzc2luZw.", 1)

        with pytest.raises(BadHeader):
            signer.unsign(unknown + b"." + signature)

        assert [call for call in calls if call is not None] == []

    def test_versioned_signature_failure_does_not_use_fallback_signer(self):
        signer = Signer(KEYS)
        signed = signer.sign(b"value")
        tampered = signed.replace(b"value", b"other", 1)

        with pytest.raises(BadHeader):
            signer.unsign(tampered)

    def test_timestamp_rotation_and_max_age(self):
        signer = TimestampSigner(KEYS, accept_legacy=True)
        legacy_signed = TimestampSigner("old-secret").sign(b"value")
        new_signed = TimestampSigner(KEYS).sign(b"value")

        legacy_result = signer.unsign_with_info(legacy_signed, max_age=10)
        assert legacy_result.value == b"value"
        assert legacy_result.info.key_id == "old"
        assert legacy_result.info.should_resign is True
        assert legacy_result.info.date_signed is not None

        new_result = signer.unsign_with_info(new_signed, max_age=10)
        assert new_result.info.key_id == "new"
        assert new_result.info.should_resign is False

        with pytest.raises(SignatureExpired):
            signer.unsign(new_signed, max_age=-1)


@pytest.mark.parametrize(
    "serializer_class",
    (Serializer, TimedSerializer, URLSafeSerializer, URLSafeTimedSerializer),
)
class TestVersionedSerializers:
    def test_rotation_and_legacy_switch(self, serializer_class):
        old_serializer = serializer_class(
            "old-secret", signer_kwargs={"digest_method": hashlib.sha256}
        )
        legacy_token = old_serializer.dumps(VALUE)
        current = serializer_class(
            KEYS,
            signer_kwargs={"digest_method": hashlib.sha256},
            accept_legacy=True,
        )
        new_token = current.dumps(VALUE)

        legacy_result = current.loads_with_info(legacy_token)
        assert legacy_result.payload == VALUE
        assert legacy_result.info.version is None
        assert legacy_result.info.key_id == "old"
        assert legacy_result.info.should_resign is True

        new_result = current.loads_with_info(new_token)
        assert new_result.payload == VALUE
        assert new_result.info.version == 1
        assert new_result.info.key_id == "new"
        assert new_result.info.should_resign is False

        old_versioned_token = serializer_class(
            {"old": "old-secret"},
            signer_kwargs={"digest_method": hashlib.sha256},
        ).dumps(VALUE)
        old_versioned_result = current.loads_with_info(old_versioned_token)
        assert old_versioned_result.info.key_id == "old"
        assert old_versioned_result.info.should_resign is True

        strict = serializer_class(KEYS, signer_kwargs={"digest_method": hashlib.sha256})

        with pytest.raises(BadHeader):
            strict.loads(legacy_token)

    def test_tampered_identifiers_rejected(self, serializer_class):
        serializer = serializer_class(KEYS)
        token = serializer.dumps(VALUE)

        with pytest.raises(BadHeader):
            serializer.loads(token.replace("v1.bmV3.", "v2.bmV3.", 1))

        unknown_token = token.replace("v1.bmV3.", "v1.bWlzc2luZw.", 1)

        with pytest.raises(BadHeader, match="Unknown key id"):
            serializer.loads(unknown_token)

        swapped_token = token.replace("v1.bmV3.", "v1.b2xk.", 1)

        with pytest.raises(BadHeader):
            serializer.loads(swapped_token)

    def test_salt_isolation(self, serializer_class):
        signed = serializer_class(KEYS).dumps(VALUE, salt="one")

        with pytest.raises(BadSignature):
            serializer_class(KEYS).loads(signed, salt="two")

        assert serializer_class(KEYS).loads(signed, salt="one") == VALUE


def test_timed_serializer_info_keeps_timestamp_and_max_age():
    serializer = URLSafeTimedSerializer(KEYS, accept_legacy=True)
    token = serializer.dumps(VALUE)

    result = serializer.loads_with_info(token, max_age=10)
    assert result.payload == VALUE
    assert result.info.date_signed is not None

    with pytest.raises(SignatureExpired):
        serializer.loads_with_info(token, max_age=-1)


def test_legacy_api_format_is_unchanged():
    assert Signer("secret-key").sign(b"value") == (b"value.RI9crmxKpuX1wTw2mg_FHFGXRic")
    assert Serializer("dev key", salt="dev salt").dumps([42]) == (
        "[42].-9cNi0CxsSB3hZPNCe9a2eEs1ZM"
    )
    assert (
        URLSafeSerializer("secret-key").dumps([1, 2, 3, 4])
        == "WzEsMiwzLDRd.wSPHqC0gR7VUqivlSukJ0IeTDgo"
    )
    assert not TimedSerializer("secret-key").dumps([42]).startswith("v1.")
    assert not URLSafeTimedSerializer("secret-key").dumps([42]).startswith("v1.")
