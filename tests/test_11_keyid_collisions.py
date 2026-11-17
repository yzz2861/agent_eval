"""Security regression tests for key ID / short key ID collision attacks.

A forged key can be crafted whose 64-bit key ID (or 32-bit short key ID) is identical to that of a victim key,
while its full 160-bit fingerprint differs. Selecting keys by a truncated identifier would let the forged key
silently take the place of the victim key during decryption or signature verification. These tests pin the
strict default behavior (full fingerprints only), the opt-in lenient mode, collision rejection, and the
full-fingerprint selection paths used for PGPMessage.decrypt and PGPSignature.verify.
"""

import pytest

from pgpy import PGPKey
from pgpy import PGPKeyring
from pgpy import PGPMessage
from pgpy import PGPSignature
from pgpy.constants import PubKeyAlgorithm
from pgpy.errors import PGPError
from pgpy.errors import PGPKeyIDCollisionError
from pgpy.types import Fingerprint


class ForgedKey(PGPKey):
    """A real, freshly generated key that advertises a spoofed fingerprint."""

    def __init__(self, forged_key, spoofed_fingerprint):
        super(ForgedKey, self).__init__()
        self._spoofed_fingerprint = Fingerprint(spoofed_fingerprint)
        self._key = forged_key._key

    @property
    def fingerprint(self):
        return self._spoofed_fingerprint


def _spoofed_fingerprint(target_keyid):
    # a well-formed 40 hex digit fingerprint that ends with the victim key ID but has a different prefix
    return Fingerprint("DEADBEEFDEADBEEFCAFEBABE" + target_keyid)


def _make_forged_public_key(target_keyid):
    forged_key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    return ForgedKey(forged_key.pubkey, _spoofed_fingerprint(target_keyid))


@pytest.fixture(scope="module")
def victim_keys():
    public_key, _ = PGPKey.from_file("tests/testdata/keys/rsa.1.pub.asc")
    private_key, _ = PGPKey.from_file("tests/testdata/keys/rsa.1.sec.asc")
    return public_key, private_key


@pytest.fixture(scope="module")
def signing_keys():
    public_key, _ = PGPKey.from_file("tests/testdata/keys/targette.pub.rsa.asc")
    private_key, _ = PGPKey.from_file("tests/testdata/keys/targette.sec.rsa.asc")
    return public_key, private_key


@pytest.fixture(scope="module")
def forged_primary(victim_keys):
    public_key, _ = victim_keys
    return _make_forged_public_key(public_key.fingerprint.keyid)


class TestStrictKeyring(object):
    def test_strict_mode_is_default(self, victim_keys):
        public_key, _ = victim_keys
        keyring = PGPKeyring(public_key)
        assert keyring.lenient is False

    def test_truncated_identifiers_not_registered(self, victim_keys):
        public_key, _ = victim_keys
        keyring = PGPKeyring(public_key)

        assert str(public_key.fingerprint) in keyring
        assert public_key.fingerprint.keyid not in keyring
        assert public_key.fingerprint.shortid not in keyring

    def test_strict_mode_rejects_keyid_and_shortid_selection(self, victim_keys):
        public_key, _ = victim_keys
        keyring = PGPKeyring(public_key)

        with pytest.raises(KeyError):
            with keyring.key(public_key.fingerprint.keyid):
                pass

        with pytest.raises(KeyError):
            with keyring.key(public_key.fingerprint.shortid):
                pass

    def test_full_fingerprint_still_selects_victim(self, victim_keys, forged_primary):
        public_key, _ = victim_keys
        keyring = PGPKeyring()
        keyring.load(public_key)
        keyring.load(forged_primary)

        with keyring.key(str(public_key.fingerprint)) as selected:
            assert selected.fingerprint == public_key.fingerprint

        with keyring.key(str(forged_primary.fingerprint)) as selected:
            assert selected.fingerprint == forged_primary.fingerprint

    def test_forged_key_cannot_replace_victim_by_keyid(self, victim_keys, forged_primary):
        public_key, _ = victim_keys
        keyring = PGPKeyring()
        keyring.load(public_key)
        keyring.load(forged_primary)

        # the key ID genuinely collides
        assert forged_primary.fingerprint.keyid == public_key.fingerprint.keyid
        assert str(forged_primary.fingerprint) != str(public_key.fingerprint)

        # strict mode never resolves the truncated identifier to either key
        with pytest.raises(KeyError):
            with keyring.key(public_key.fingerprint.keyid):
                pass

    def test_message_keyid_resolution_rejects_collision(self, victim_keys):
        public_key, private_key = victim_keys
        message = PGPMessage.new("collision decryption message")
        encrypted = public_key.encrypt(message)

        # the message is encrypted to the encryption subkey, so the forged key collides with that key ID
        encrypter_keyid = next(iter(encrypted.encrypters))
        forged = _make_forged_public_key(encrypter_keyid)
        victim_subkey = next(sk for sk in public_key.subkeys.values() if sk.fingerprint.keyid == encrypter_keyid)

        keyring = PGPKeyring()
        keyring.load(private_key)
        keyring.load(forged)

        with pytest.raises(PGPKeyIDCollisionError) as excinfo:
            with keyring.key(encrypted):
                pass

        message_text = str(excinfo.value)
        assert str(victim_subkey.fingerprint) in message_text
        assert str(forged.fingerprint) in message_text

    def test_message_resolution_picks_victim_without_collision(self, victim_keys):
        public_key, private_key = victim_keys
        message = PGPMessage.new("collision decryption message")
        encrypted = public_key.encrypt(message)

        keyring = PGPKeyring(private_key)
        with keyring.key(encrypted) as selected:
            decrypted = selected.decrypt(encrypted)
        assert decrypted.message == "collision decryption message"


class TestCollisionRejection(object):
    @pytest.mark.parametrize("lenient", [False, True])
    def test_keyid_collision_lists_all_candidates(self, victim_keys, forged_primary, lenient):
        public_key, _ = victim_keys
        keyring = PGPKeyring(lenient=lenient)
        keyring.load(public_key)

        if lenient:
            # lenient mode registers key ID aliases and rejects the collision while loading
            with pytest.raises(PGPKeyIDCollisionError) as excinfo:
                keyring.load(forged_primary)
            message_text = str(excinfo.value)
        else:
            # strict mode does not register truncated aliases, so loading succeeds but resolving the
            # shared key ID through full fingerprints refuses to pick one of the candidates
            keyring.load(forged_primary)
            with pytest.raises(PGPKeyIDCollisionError) as excinfo:
                keyring._resolve_keyid(public_key.fingerprint.keyid)
            message_text = str(excinfo.value)
        assert public_key.fingerprint.keyid in message_text
        assert str(public_key.fingerprint) in message_text
        assert str(forged_primary.fingerprint) in message_text

    def test_strict_resolution_collision_lists_candidates(self, victim_keys, forged_primary):
        public_key, _ = victim_keys
        keyring = PGPKeyring()
        keyring.load(public_key)
        keyring.load(forged_primary)

        with pytest.raises(PGPKeyIDCollisionError) as excinfo:
            keyring._resolve_keyid(public_key.fingerprint.keyid)

        candidates = str(excinfo.value)
        assert str(public_key.fingerprint) in candidates
        assert str(forged_primary.fingerprint) in candidates

    def test_shortid_collision_rejected_in_lenient_mode(self, victim_keys):
        public_key, _ = victim_keys
        forged = _make_forged_public_key(public_key.fingerprint.keyid)
        assert forged.fingerprint.shortid == public_key.fingerprint.shortid

        with pytest.raises(PGPKeyIDCollisionError):
            PGPKeyring(public_key, forged, lenient=True)

    def test_same_fingerprint_halves_are_not_a_collision(self, victim_keys):
        public_key, private_key = victim_keys
        # public and private halves of the same key share every truncated identifier
        keyring = PGPKeyring(public_key, private_key, lenient=True)
        with keyring.key(public_key.fingerprint.keyid) as selected:
            assert selected.fingerprint == public_key.fingerprint



class TestLenientKeyring(object):
    def test_lenient_mode_enables_truncated_aliases(self, victim_keys):
        public_key, _ = victim_keys
        keyring = PGPKeyring(public_key, lenient=True)
        assert keyring.lenient is True
        assert public_key.fingerprint.keyid in keyring
        assert public_key.fingerprint.shortid in keyring

        with keyring.key(public_key.fingerprint.keyid) as selected:
            assert selected.fingerprint == public_key.fingerprint
        with keyring.key(public_key.fingerprint.shortid) as selected:
            assert selected.fingerprint == public_key.fingerprint

    def test_unexpected_keyword_arguments_rejected(self, victim_keys):
        public_key, _ = victim_keys
        with pytest.raises(TypeError):
            PGPKeyring(public_key, bogus=True)

    def test_resolve_unknown_identifier_raises_keyerror(self, victim_keys):
        public_key, _ = victim_keys
        keyring = PGPKeyring(public_key)
        with pytest.raises(KeyError):
            keyring._resolve_keyid("DEADBEA7CAFED00D")

    def test_message_without_issuers_raises_keyerror(self, victim_keys):
        public_key, _ = victim_keys
        unsigned_message = PGPMessage.new("nothing to select on")
        keyring = PGPKeyring(public_key)
        with pytest.raises(KeyError):
            with keyring.key(unsigned_message):
                pass

    def test_signed_message_selects_signer_by_full_fingerprint(self, signing_keys):
        public_key, private_key = signing_keys
        message = PGPMessage.new("signed message")
        signed_message = private_key.sign(message)

        keyring = PGPKeyring(public_key)
        with keyring.key(signed_message) as selected:
            assert selected.fingerprint == public_key.fingerprint


class TestSignatureVerificationSelection(object):
    def test_forged_key_rejects_victim_signature_by_fingerprint(self, signing_keys):
        public_key, private_key = signing_keys
        forged = _make_forged_public_key(public_key.fingerprint.keyid)
        signature = private_key.sign("signature collision message")

        # the forged key shares the signer key ID but not the issuer fingerprint
        assert signature.signer == forged.fingerprint.keyid
        assert signature.signer_fingerprint == public_key.fingerprint
        assert signature.signer_fingerprint != forged.fingerprint

        # the real key verifies; the forged key never even sees the signature
        assert public_key.verify("signature collision message", signature)
        with pytest.raises(PGPError):
            forged.verify("signature collision message", signature)

    def test_keyring_signature_selection_uses_full_fingerprint(self, signing_keys):
        public_key, private_key = signing_keys
        forged = _make_forged_public_key(public_key.fingerprint.keyid)
        signature = private_key.sign("signature collision message")

        keyring = PGPKeyring()
        keyring.load(public_key)
        keyring.load(forged)

        with keyring.key(signature) as selected:
            assert selected.fingerprint == public_key.fingerprint
            assert selected.verify("signature collision message", signature)

    def test_keyid_only_signature_falls_back_to_keyid_matching(self):
        # a real GnuPG-generated signature that carries no IssuerFingerprint subpacket; selection
        # falls back to resolving its key ID against full fingerprints
        signature = PGPSignature.from_file("tests/testdata/signatures/aptapproval-test.sig.asc")
        public_key, _ = PGPKey.from_file("tests/testdata/signatures/aptapproval-test.key.asc")
        assert signature.signer_fingerprint == ""

        keyring = PGPKeyring(public_key)
        with keyring.key(signature) as selected:
            assert selected.fingerprint == public_key.fingerprint
            assert selected.fingerprint.keyid == signature.signer

    def test_keyid_only_signature_collision_is_rejected(self):
        signature = PGPSignature.from_file("tests/testdata/signatures/aptapproval-test.sig.asc")
        public_key, _ = PGPKey.from_file("tests/testdata/signatures/aptapproval-test.key.asc")
        forged = _make_forged_public_key(signature.signer)

        keyring = PGPKeyring()
        keyring.load(public_key)
        keyring.load(forged)

        with pytest.raises(PGPKeyIDCollisionError) as excinfo:
            with keyring.key(signature):
                pass
        assert str(public_key.fingerprint) in str(excinfo.value)
        assert str(forged.fingerprint) in str(excinfo.value)



class TestDecryptionSelection(object):
    def test_encrypted_message_selection_prefers_real_key(self, victim_keys):
        public_key, private_key = victim_keys
        message = PGPMessage.new("decryption collision message")
        encrypted = public_key.encrypt(message)

        # forge a key colliding with the encryption subkey key ID carried by the message
        encrypter_keyid = next(iter(encrypted.encrypters))
        forged = _make_forged_public_key(encrypter_keyid)

        keyring = PGPKeyring()
        keyring.load(private_key)
        keyring.load(forged)

        with pytest.raises(PGPKeyIDCollisionError):
            with keyring.key(encrypted):
                pass

    def test_decryption_succeeds_when_forged_key_absent(self, victim_keys):
        public_key, private_key = victim_keys
        message = PGPMessage.new("decryption collision message")
        encrypted = public_key.encrypt(message)

        keyring = PGPKeyring(private_key)
        with keyring.key(encrypted) as selected:
            decrypted = selected.decrypt(encrypted)
        assert decrypted.message == "decryption collision message"
