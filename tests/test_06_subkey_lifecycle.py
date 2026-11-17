""" test subkey lifecycle enforcement (binding, revocation, expiration) on the
signature verification and encryption key-selection paths
"""
import copy
import time
import warnings
from datetime import timedelta

import pytest

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPUID
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SignatureType
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.errors import PGPError
from pgpy.errors import PGPKeyLifecycleError
from pgpy.types import SorteDeque

def _make_primary():
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = PGPUID.new("Lifecycle Test", comment="subkeys", email="lifecycle@example.com")
    key.add_uid(uid,
                usage={KeyFlags.Sign, KeyFlags.Certify},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB])
    return key

def _make_key(subkey_usage, expires=None, key_expiration=None):
    primary = _make_primary()
    subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    primary.add_subkey(subkey, usage=subkey_usage, expires=expires)
    if key_expiration is not None:
        # attach a key validity period (KeyExpirationTime) to the binding signature
        binding = next(iter(subkey.self_signatures))
        binding._signature.subpackets.addnew("KeyExpirationTime", hashed=True, expires=key_expiration)
    return primary, subkey

@pytest.fixture
def encryption_key():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        primary, subkey = _make_key({KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
    return primary, subkey

@pytest.fixture
def signing_key():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        primary, subkey = _make_key({KeyFlags.Sign})
    return primary, subkey

class TestSubkeyLifecycle(object):
    @staticmethod
    def _revoke_subkey(primary, subkey):
        revocation = primary.revoke(subkey, sigtype=SignatureType.SubkeyRevocation)
        subkey |= revocation
        return revocation

    # --- revoked subkey -------------------------------------------------
    def test_verify_with_revoked_signing_subkey(self, signing_key):
        primary, subkey = signing_key
        signature = subkey.sign("a signed document")
        public = primary.pubkey

        self._revoke_subkey(primary, subkey)
        public.subkeys[subkey.fingerprint.keyid] |= copy.copy(
            next(iter(subkey.revocation_signatures)))

        with pytest.raises(PGPKeyLifecycleError) as excinfo:
            public.verify("a signed document", signature)
        assert "revoked" in str(excinfo.value)
        assert subkey.fingerprint.keyid in str(excinfo.value)

        # legacy compatibility mode still allows the cryptographic operation
        public._enforce_subkey_lifecycle = False
        assert public.verify("a signed document", signature)

    def test_encrypt_with_revoked_subkey(self, encryption_key):
        primary, subkey = encryption_key
        public = primary.pubkey
        self._revoke_subkey(primary, subkey)
        public.subkeys[subkey.fingerprint.keyid] |= copy.copy(
            next(iter(subkey.revocation_signatures)))

        message = PGPMessage.new("secret payload")
        with pytest.raises(PGPKeyLifecycleError) as excinfo:
            public.encrypt(message)
        assert "revoked" in str(excinfo.value)

        public._enforce_subkey_lifecycle = False
        assert public.encrypt(message).is_encrypted

    # --- expired subkey -------------------------------------------------
    def test_verify_with_expired_signing_subkey(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            primary, subkey = _make_key({KeyFlags.Sign}, key_expiration=timedelta(seconds=1))
        signature = subkey.sign("another document")
        public = primary.pubkey

        time.sleep(1.1)
        assert subkey.is_expired

        with pytest.raises(PGPKeyLifecycleError) as excinfo:
            public.verify("another document", signature)
        assert "expired" in str(excinfo.value)
        assert subkey.fingerprint.keyid in str(excinfo.value)

        public._enforce_subkey_lifecycle = False
        assert public.verify("another document", signature)

    def test_encrypt_with_expired_subkey(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            primary, subkey = _make_key(
                {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                key_expiration=timedelta(seconds=1))
        public = primary.pubkey

        time.sleep(1.1)
        assert subkey.is_expired

        message = PGPMessage.new("expiring payload")
        with pytest.raises(PGPKeyLifecycleError) as excinfo:
            public.encrypt(message)
        assert "expired" in str(excinfo.value)

        public._enforce_subkey_lifecycle = False
        assert public.encrypt(message).is_encrypted

    def test_encrypt_with_expired_binding_signature(self):
        # an expired binding signature (SignatureExpirationTime) removes the only valid binding
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            primary, subkey = _make_key(
                {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                expires=timedelta(seconds=1))
        public = primary.pubkey

        time.sleep(1.1)
        assert subkey._binding_signatures() == []

        with pytest.raises(PGPKeyLifecycleError) as excinfo:
            public.encrypt(PGPMessage.new("payload"))
        assert "binding signature" in str(excinfo.value)

    # --- missing binding signature --------------------------------------
    def test_verify_with_unbound_signing_subkey(self, signing_key):
        primary, subkey = signing_key
        signature = subkey.sign("unbound document")
        public = primary.pubkey

        # strip every signature from the public subkey, including its binding signature
        public_subkey = public.subkeys[subkey.fingerprint.keyid]
        public_subkey._signatures = SorteDeque()

        with pytest.raises(PGPKeyLifecycleError) as excinfo:
            public.verify("unbound document", signature)
        assert "binding signature" in str(excinfo.value)

        public._enforce_subkey_lifecycle = False
        assert public.verify("unbound document", signature)

    def test_encrypt_with_unbound_subkey(self, encryption_key):
        primary, subkey = encryption_key
        public = primary.pubkey
        public_subkey = public.subkeys[subkey.fingerprint.keyid]
        public_subkey._signatures = SorteDeque()

        with pytest.raises(PGPKeyLifecycleError) as excinfo:
            public.encrypt(PGPMessage.new("payload"))
        assert "binding signature" in str(excinfo.value)

        # with lifecycle enforcement disabled, the controlled lifecycle error no longer fires;
        # the key instead falls through to the pre-existing usage-flag behavior, since an unbound
        # subkey carries no binding signature and therefore no usage flags
        public._enforce_subkey_lifecycle = False
        with pytest.raises(PGPError):
            public.encrypt(PGPMessage.new("payload"))

    # --- revoked primary key --------------------------------------------
    def test_verify_with_revoked_primary_key(self, signing_key):
        primary, subkey = signing_key
        # a signature made by the primary key itself
        signature = primary.sign("primary signed document")
        public = primary.pubkey

        revocation = primary.revoke(primary, sigtype=SignatureType.KeyRevocation)
        primary |= revocation
        public |= copy.copy(revocation)

        with pytest.raises(PGPKeyLifecycleError) as excinfo:
            public.verify("primary signed document", signature)
        assert "primary key" in str(excinfo.value)
        assert "revoked" in str(excinfo.value)

        public._enforce_subkey_lifecycle = False
        assert public.verify("primary signed document", signature)

    def test_encrypt_with_revoked_primary_key(self, encryption_key):
        primary, subkey = encryption_key
        public = primary.pubkey

        revocation = primary.revoke(primary, sigtype=SignatureType.KeyRevocation)
        primary |= revocation
        public |= copy.copy(revocation)

        with pytest.raises(PGPKeyLifecycleError) as excinfo:
            public.encrypt(PGPMessage.new("payload"))
        assert "primary key" in str(excinfo.value)
        assert "revoked" in str(excinfo.value)

        public._enforce_subkey_lifecycle = False
        assert public.encrypt(PGPMessage.new("payload")).is_encrypted

    # --- happy path ------------------------------------------------------
    def test_valid_key_still_works(self, signing_key, encryption_key):
        sign_primary, sign_sub = signing_key
        signature = sign_sub.sign("healthy document")
        assert sign_primary.pubkey.verify("healthy document", signature)

        enc_primary, enc_sub = encryption_key
        assert enc_primary.pubkey.encrypt(PGPMessage.new("healthy payload")).is_encrypted
