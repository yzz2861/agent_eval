"""Tests for the SAML XML Encryption decryption policy.

The policy layer must reject disallowed algorithms, mismatching key sizes,
bad IV/ciphertext lengths and corrupted structures *before* the xmlsec
backend is invoked. Three error categories are distinguished:

* DecryptionPolicyError  - algorithm/digest forbidden by policy
* DecryptionKeyMismatchError - key material does not match the ciphertext
* DecryptionCorruptError - malformed or truncated ciphertext
"""

import base64

import pytest

from saml2.encryption_errors import DecryptionCorruptError
from saml2.encryption_errors import DecryptionKeyMismatchError
from saml2.encryption_errors import DecryptionPolicyError
from saml2.encryption_errors import EncryptionPolicyConfigurationError
from saml2.encryption_policy import AES128_CBC
from saml2.encryption_policy import AES128_GCM
from saml2.encryption_policy import AES256_GCM
from saml2.encryption_policy import DEFAULT_PROFILE
from saml2.encryption_policy import DIGEST_SHA1
from saml2.encryption_policy import DIGEST_SHA256
from saml2.encryption_policy import RSA_1_5
from saml2.encryption_policy import RSA_OAEP_256
from saml2.encryption_policy import RSA_OAEP_MGF1P
from saml2.encryption_policy import TRIPLE_DES_CBC
from saml2.encryption_policy import EncryptionPolicy
from saml2.encryption_policy import EncryptionPolicyRegistry
from saml2.encryption_policy import validate_encrypted_xml


PRIV_1024 = open("tests/test.key").read()
PRIV_2048 = open("tests/keys/test_2048.key").read()


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


ENCRYPTED_DATA_TEMPLATE = (
    "<xenc:EncryptedData"
    " xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\""
    " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
    "<xenc:EncryptionMethod Algorithm=\"{data_alg}\"/>"
    "<ds:KeyInfo><xenc:EncryptedKey>"
    "<xenc:EncryptionMethod Algorithm=\"{key_alg}\">{digest_element}"
    "</xenc:EncryptionMethod>"
    "<xenc:CipherData><xenc:CipherValue>{key_cipher}</xenc:CipherValue>"
    "</xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>"
    "<xenc:CipherData><xenc:CipherValue>{data_cipher}</xenc:CipherValue>"
    "</xenc:CipherData></xenc:EncryptedData>"
)


def make_document(
    data_alg=AES128_GCM,
    key_alg=RSA_OAEP_MGF1P,
    key_bytes=256,
    data_bytes=28,
    digest_element="",
):
    return ENCRYPTED_DATA_TEMPLATE.format(
        data_alg=data_alg,
        key_alg=key_alg,
        digest_element=digest_element,
        key_cipher=b64(b"k" * key_bytes),
        data_cipher=b64(b"d" * data_bytes),
    )


class TestProfiles:
    def test_profiles_are_closed_allow_lists(self):
        for name in ("modern", "intermediate", "legacy"):
            policy = EncryptionPolicy.from_profile(name)
            assert policy.key_transport
            assert policy.block_encryption
            assert policy.digest

    def test_modern_rejects_legacy_algorithms(self):
        policy = EncryptionPolicy.from_profile("modern")
        assert RSA_1_5 not in policy.key_transport
        assert AES128_CBC not in policy.block_encryption
        assert TRIPLE_DES_CBC not in policy.block_encryption
        assert not policy.is_legacy()

    def test_intermediate_rejects_rsa_1_5_and_cbc(self):
        policy = EncryptionPolicy.from_profile("intermediate")
        assert RSA_1_5 not in policy.key_transport
        assert AES128_CBC not in policy.block_encryption
        assert AES128_GCM in policy.block_encryption
        assert policy.min_rsa_key_size == 2048

    def test_legacy_profile_explicitly_allows_legacy_algorithms(self):
        policy = EncryptionPolicy.from_profile("legacy")
        assert RSA_1_5 in policy.key_transport
        assert TRIPLE_DES_CBC in policy.block_encryption
        assert AES128_CBC in policy.block_encryption
        assert policy.is_legacy()
        assert policy.min_rsa_key_size == 1024

    def test_default_profile_keeps_backward_compatibility(self):
        policy = EncryptionPolicy.from_profile(DEFAULT_PROFILE)
        assert policy.is_legacy()

    def test_unknown_profile_is_configuration_error(self):
        with pytest.raises(EncryptionPolicyConfigurationError):
            EncryptionPolicy.from_profile("anything-goes")

    def test_unknown_algorithm_in_custom_policy_rejected(self):
        with pytest.raises(EncryptionPolicyConfigurationError):
            EncryptionPolicy(
                key_transport=["http://example.com/any-algorithm"],
                block_encryption=[AES128_GCM],
                digest=[DIGEST_SHA256],
            )

    def test_policy_cannot_accept_any_algorithm(self):
        with pytest.raises(EncryptionPolicyConfigurationError):
            EncryptionPolicy.from_dict({
                "key_transport": ["*"],
                "block_encryption": [AES128_GCM],
                "digest": [DIGEST_SHA256],
            })


class TestPolicyRegistry:
    ENTITY_ID = "https://idp.example.com/entity"

    def test_entity_override_can_narrow(self):
        registry = EncryptionPolicyRegistry.from_config({
            "profile": "legacy",
            "entity_overrides": {self.ENTITY_ID: "modern"},
        })
        assert registry.policy_for(self.ENTITY_ID).name == "modern"
        assert registry.policy_for("https://other.example.com").name == "legacy"

    def test_entity_override_cannot_widen_to_disallowed_algorithms(self):
        with pytest.raises(EncryptionPolicyConfigurationError):
            EncryptionPolicyRegistry.from_config({
                "profile": "modern",
                "entity_overrides": {self.ENTITY_ID: "legacy"},
            })

    def test_entity_override_cannot_lower_key_floor(self):
        narrow = EncryptionPolicy.from_profile("modern")
        weak = EncryptionPolicy(
            key_transport=narrow.key_transport,
            block_encryption=narrow.block_encryption,
            digest=narrow.digest,
            min_rsa_key_size=1024,
        )
        with pytest.raises(EncryptionPolicyConfigurationError):
            EncryptionPolicyRegistry(
                default_policy=narrow,
                entity_overrides={self.ENTITY_ID: weak},
            )

    def test_dict_override_is_validated(self):
        with pytest.raises(EncryptionPolicyConfigurationError):
            EncryptionPolicyRegistry.from_config({
                "profile": "modern",
                "entity_overrides": {
                    self.ENTITY_ID: {"profile": "legacy"}
                },
            })

    def test_no_wildcard_through_configuration(self):
        with pytest.raises(EncryptionPolicyConfigurationError):
            EncryptionPolicyRegistry.from_config({
                "policy": {
                    "key_transport": ["*"],
                    "block_encryption": ["*"],
                    "digest": ["*"],
                }
            })


class TestValidation:
    @pytest.fixture
    def strict_policy(self):
        return EncryptionPolicy.from_profile("intermediate")

    @pytest.fixture
    def legacy_policy(self):
        return EncryptionPolicy.from_profile("legacy")

    def test_valid_gcm_message_passes(self, strict_policy):
        document = make_document(
            data_alg=AES128_GCM,
            key_alg=RSA_OAEP_MGF1P,
            key_bytes=256,
            data_bytes=28,
        )
        resolved = validate_encrypted_xml(
            document, strict_policy, available_key_sizes=[2048]
        )
        assert resolved is strict_policy

    def test_algorithm_confusion_rsa_1_5_is_policy_violation(self, strict_policy):
        document = make_document(key_alg=RSA_1_5, key_bytes=256, data_bytes=28)
        with pytest.raises(DecryptionPolicyError):
            validate_encrypted_xml(
                document, strict_policy, available_key_sizes=[2048]
            )

    def test_algorithm_confusion_cbc_is_policy_violation(self, strict_policy):
        document = make_document(
            data_alg=AES128_CBC, key_bytes=256, data_bytes=48
        )
        with pytest.raises(DecryptionPolicyError):
            validate_encrypted_xml(
                document, strict_policy, available_key_sizes=[2048]
            )

    def test_triple_des_only_allowed_in_legacy(self, strict_policy, legacy_policy):
        document = make_document(
            data_alg=TRIPLE_DES_CBC, key_alg=RSA_1_5, key_bytes=128, data_bytes=24
        )
        with pytest.raises(DecryptionPolicyError):
            validate_encrypted_xml(
                document, strict_policy, available_key_sizes=[1024]
            )
        resolved = validate_encrypted_xml(
            document, legacy_policy, available_key_sizes=[1024]
        )
        assert resolved is legacy_policy

    def test_disallowed_oaep_digest_is_policy_violation(self, strict_policy):
        modern = EncryptionPolicy.from_profile("modern")
        digest_element = (
            "<ds:DigestMethod xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""
            " Algorithm=\"%s\"/>" % DIGEST_SHA1
        )
        document = make_document(
            data_alg=AES128_GCM,
            key_alg=RSA_OAEP_256,
            key_bytes=256,
            data_bytes=28,
            digest_element=digest_element,
        )
        with pytest.raises(DecryptionPolicyError):
            validate_encrypted_xml(document, modern, available_key_sizes=[2048])

    def test_short_rsa_key_is_key_mismatch(self, strict_policy):
        document = make_document(key_bytes=128, data_bytes=28)
        with pytest.raises(DecryptionKeyMismatchError):
            validate_encrypted_xml(
                document, strict_policy, available_key_sizes=[1024]
            )

    def test_wrapped_key_length_without_matching_key(self, strict_policy):
        document = make_document(key_bytes=512, data_bytes=28)
        with pytest.raises(DecryptionKeyMismatchError):
            validate_encrypted_xml(
                document, strict_policy, available_key_sizes=[2048]
            )

    def test_legacy_accepts_1024_bit_rsa_1_5(self, legacy_policy):
        document = make_document(
            data_alg=TRIPLE_DES_CBC, key_alg=RSA_1_5, key_bytes=128, data_bytes=24
        )
        validate_encrypted_xml(document, legacy_policy, available_key_sizes=[1024])


class TestCorruptCiphertext:
    @pytest.fixture
    def policy(self):
        return EncryptionPolicy.from_profile("intermediate")

    def test_bad_iv_length_gcm(self, policy):
        # 12 byte nonce required, only 5 bytes available
        document = make_document(key_bytes=256, data_bytes=5)
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])

    def test_bad_iv_length_cbc(self, policy):
        cbc_policy = EncryptionPolicy.from_profile("legacy")
        # CBC needs a 16 byte IV for AES
        document = make_document(
            data_alg=AES128_CBC, key_bytes=128, data_bytes=8
        )
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(
                document, cbc_policy, available_key_sizes=[1024]
            )

    def test_truncated_ciphertext_gcm_missing_tag(self, policy):
        # 12 byte nonce but no room for the 16 byte GCM tag
        document = make_document(key_bytes=256, data_bytes=12 + 10)
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])

    def test_truncated_cbc_not_block_aligned(self):
        cbc_policy = EncryptionPolicy.from_profile("legacy")
        document = make_document(
            data_alg=AES128_CBC, key_bytes=128, data_bytes=16 + 17
        )
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(
                document, cbc_policy, available_key_sizes=[1024]
            )

    def test_invalid_base64(self, policy):
        document = make_document(key_bytes=256, data_bytes=28).replace(
            b64(b"d" * 28), "not valid base64!!"
        )
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])

    def test_empty_cipher_value(self, policy):
        document = make_document(key_bytes=256, data_bytes=28).replace(
            b64(b"d" * 28), ""
        )
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])

    def test_missing_encrypted_key(self, policy):
        document = ("<xenc:EncryptedData"
                    " xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">"
                    "<xenc:EncryptionMethod Algorithm=\"%s\"/>"
                    "<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue>"
                    "</xenc:CipherData></xenc:EncryptedData>") % (
            AES128_GCM, b64(b"d" * 28)
        )
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])

    def test_missing_encryption_method(self, policy):
        document = (
            "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\""
            " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
            "<ds:KeyInfo><xenc:EncryptedKey>"
            "<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue>"
            "</xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>"
            "<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue>"
            "</xenc:CipherData></xenc:EncryptedData>"
        ) % (b64(b"k" * 256), b64(b"d" * 28))
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])

    def test_not_xml(self, policy):
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml("not xml at all", policy)

    def test_no_encrypted_data(self, policy):
        document = "<root xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>"
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(document, policy)

    def test_dangling_retrieval_method(self, policy):
        document = (
            "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\""
            " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
            "<xenc:EncryptionMethod Algorithm=\"%s\"/>"
            "<ds:KeyInfo><ds:RetrievalMethod URI=\"#missing\"/></ds:KeyInfo>"
            "<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue>"
            "</xenc:CipherData></xenc:EncryptedData>"
        ) % (AES128_GCM, b64(b"d" * 28))
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])

RETRIEVAL_TEMPLATE = (
    "<saml:EncryptedAssertion"
    " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
    " xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\""
    " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
    "<xenc:EncryptedData><xenc:EncryptionMethod Algorithm=\"{data_alg}\"/>"
    "<ds:KeyInfo><ds:RetrievalMethod"
    " Type=\"http://www.w3.org/2001/04/xmlenc#EncryptedKey\" URI=\"#EK1\"/>"
    "</ds:KeyInfo>"
    "<xenc:CipherData><xenc:CipherValue>{data_cipher}</xenc:CipherValue>"
    "</xenc:CipherData></xenc:EncryptedData>"
    "<xenc:EncryptedKey Id=\"EK1\">"
    "<xenc:EncryptionMethod Algorithm=\"{key_alg}\"/>"
    "<xenc:CipherData><xenc:CipherValue>{key_cipher}</xenc:CipherValue>"
    "</xenc:CipherData></xenc:EncryptedKey></saml:EncryptedAssertion>"
)


class TestRetrievalMethodLayout:
    def test_sibling_encrypted_key_is_validated(self):
        policy = EncryptionPolicy.from_profile("intermediate")
        document = RETRIEVAL_TEMPLATE.format(
            data_alg=AES128_GCM,
            key_alg=RSA_1_5,
            data_cipher=b64(b"d" * 28),
            key_cipher=b64(b"k" * 256),
        )
        with pytest.raises(DecryptionPolicyError):
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])

    def test_sibling_encrypted_key_accepted_for_legacy(self):
        policy = EncryptionPolicy.from_profile("legacy")
        document = RETRIEVAL_TEMPLATE.format(
            data_alg=TRIPLE_DES_CBC,
            key_alg=RSA_1_5,
            data_cipher=b64(b"d" * 24),
            key_cipher=b64(b"k" * 128),
        )
        validate_encrypted_xml(document, policy, available_key_sizes=[1024])


class TestSecurityContextIntegration:
    def _make_context(self, policy_name):
        from unittest import mock
        from saml2.sigver import CryptoBackend
        from saml2.sigver import SecurityContext

        backend = mock.Mock(spec=CryptoBackend)
        backend.decrypt.return_value = "<decrypted/>"
        context = SecurityContext(
            backend,
            cert_file="",
            encryption_policy={"profile": policy_name},
        )
        return context, backend

    def test_backend_decrypt_never_called_on_policy_violation(self):
        context, backend = self._make_context("intermediate")
        document = make_document(key_alg=RSA_1_5, key_bytes=256, data_bytes=28)
        with pytest.raises(DecryptionPolicyError):
            context.decrypt_keys(document, keys=[])
        backend.decrypt.assert_not_called()

    def test_backend_decrypt_never_called_on_corrupt_ciphertext(self):
        context, backend = self._make_context("intermediate")
        document = make_document(key_bytes=256, data_bytes=4)
        with pytest.raises(DecryptionCorruptError):
            context.decrypt_keys(document, keys=[])
        backend.decrypt.assert_not_called()

    def test_backend_decrypt_never_called_on_key_mismatch(self):
        context, backend = self._make_context("intermediate")
        short_key = open("tests/test.key").read()
        document = make_document(key_bytes=128, data_bytes=28)
        with pytest.raises(DecryptionKeyMismatchError):
            context.decrypt_keys(document, keys=[short_key])
        backend.decrypt.assert_not_called()

    def test_backend_invoked_when_policy_passes(self):
        context, backend = self._make_context("intermediate")
        document = make_document(key_bytes=256, data_bytes=28)
        result = context.decrypt_keys(document, keys=[PRIV_2048])
        assert result == "<decrypted/>"
        backend.decrypt.assert_called_once()

    def test_legacy_profile_accepts_legacy_message_at_context(self):
        context, backend = self._make_context("legacy")
        short_key = open("tests/test.key").read()
        document = make_document(
            data_alg=TRIPLE_DES_CBC, key_alg=RSA_1_5, key_bytes=128, data_bytes=24
        )
        result = context.decrypt_keys(document, keys=[short_key])
        assert result == "<decrypted/>"
        backend.decrypt.assert_called_once()

    def test_entity_override_selects_strict_policy(self):
        from unittest import mock
        from saml2.sigver import CryptoBackend
        from saml2.sigver import SecurityContext

        backend = mock.Mock(spec=CryptoBackend)
        context = SecurityContext(
            backend,
            cert_file="",
            encryption_policy={
                "profile": "legacy",
                "entity_overrides": {"urn:strict": "modern"},
            },
        )
        document = make_document(key_alg=RSA_1_5, key_bytes=128, data_bytes=24)
        with pytest.raises(DecryptionPolicyError):
            context.decrypt_keys(document, keys=[], entity_id="urn:strict")
        backend.decrypt.assert_not_called()


class TestErrorMessages:
    def test_policy_error_identifies_category(self):
        policy = EncryptionPolicy.from_profile("intermediate")
        document = make_document(key_alg=RSA_1_5, key_bytes=256, data_bytes=28)
        with pytest.raises(DecryptionPolicyError) as exc_info:
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])
        message = str(exc_info.value)
        assert RSA_1_5 in message
        assert b64(b"k" * 256) not in message

    def test_corrupt_error_never_contains_ciphertext(self):
        policy = EncryptionPolicy.from_profile("intermediate")
        secret_cipher = b64(b"topsecret-ciphertext-bytes" * 2)
        document = make_document(key_bytes=256, data_bytes=28).replace(
            b64(b"d" * 28), secret_cipher[:12]
        )
        with pytest.raises(DecryptionCorruptError) as exc_info:
            validate_encrypted_xml(document, policy, available_key_sizes=[2048])
        assert "topsecret" not in str(exc_info.value)

    def test_key_mismatch_error_never_contains_key_material(self):
        policy = EncryptionPolicy.from_profile("intermediate")
        document = make_document(key_bytes=128, data_bytes=28)
        with pytest.raises(DecryptionKeyMismatchError) as exc_info:
            validate_encrypted_xml(document, policy, available_key_sizes=[1024])
        message = str(exc_info.value)
        assert b64(b"k" * 128) not in message
        assert "BEGIN" not in message


class TestAdditionalCases:
    def test_bytes_input_accepted(self):
        policy = EncryptionPolicy.from_profile("intermediate")
        document = make_document(key_bytes=256, data_bytes=28).encode("utf-8")
        validate_encrypted_xml(document, policy, available_key_sizes=[2048])

    def test_gcm_empty_plaintext_is_valid(self):
        policy = EncryptionPolicy.from_profile("intermediate")
        # 12 byte nonce + 16 byte tag, zero-length encrypted content
        document = make_document(key_bytes=256, data_bytes=12 + 16)
        validate_encrypted_xml(document, policy, available_key_sizes=[2048])

    def test_implicit_oaep_digest_checked_against_policy(self):
        modern = EncryptionPolicy.from_profile("modern")
        # rsa-oaep-mgf1p implicitly uses SHA-1, which modern forbids
        document = make_document(
            data_alg=AES128_GCM, key_alg=RSA_OAEP_MGF1P,
            key_bytes=256, data_bytes=28,
        )
        with pytest.raises(DecryptionPolicyError):
            validate_encrypted_xml(document, modern, available_key_sizes=[2048])

    def test_registry_resolves_same_policy_for_unknown_entity(self):
        registry = EncryptionPolicyRegistry.from_config({"profile": "intermediate"})
        document = make_document(key_bytes=256, data_bytes=28)
        validate_encrypted_xml(
            document, registry, available_key_sizes=[2048], entity_id="urn:unknown"
        )

    def test_policy_round_trip_through_dict(self):
        policy = EncryptionPolicy.from_profile("modern")
        rebuilt = EncryptionPolicy.from_dict(policy.to_dict())
        assert rebuilt.key_transport == policy.key_transport
        assert rebuilt.block_encryption == policy.block_encryption
        assert rebuilt.digest == policy.digest
        assert rebuilt.min_rsa_key_size == policy.min_rsa_key_size

    def test_unknown_config_options_rejected(self):
        with pytest.raises(EncryptionPolicyConfigurationError):
            EncryptionPolicyRegistry.from_config({
                "profile": "modern", "unexpected": True
            })


    def test_entity_expansion_is_treated_as_corrupt(self):
        policy = EncryptionPolicy.from_profile('intermediate')
        q = chr(34)
        billion_laughs = ''.join([
            '<?xml version=' + q + '1.0' + q + '?>',
            '<!DOCTYPE lolz [<!ENTITY lol ' + q + 'lol' + q + '>',
            '<!ENTITY lol2 ' + q + '&lol;' * 10 + q + '>]>',
            '<xenc:EncryptedData xmlns:xenc=' + q,
            'http://www.w3.org/2001/04/xmlenc#' + q + '>',
            '<xenc:CipherData><xenc:CipherValue>',
            b64(b'd' * 28),
            '</xenc:CipherValue></xenc:CipherData>',
            '</xenc:EncryptedData>',
        ])
        with pytest.raises(DecryptionCorruptError):
            validate_encrypted_xml(billion_laughs, policy)
