"""A fake, fully offline signer for demos and tests.

Implements the ``securesystemslib.signer.Signer`` and ``Key`` interfaces
with HMAC-SHA256 so the handoff flow can be exercised without cloud
KMS services or real key material. NOT cryptographically meaningful:
the "public" key carries the shared secret.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.formats import encode_canonical
from securesystemslib.signer import KEY_FOR_TYPE_AND_SCHEME, Key, Signature
from securesystemslib.signer._signer import SIGNER_FOR_URI_SCHEME, Signer

FAKE_SCHEME = "fake"
FAKE_KEYTYPE = "fake"
FAKE_SIG_SCHEME = "fake-hmac-sha256"


class FakeKey(Key):
    """Fake public key: keyval carries the shared HMAC secret."""

    def __init__(self, keyid: str, secret: str):
        super().__init__(
            keyid, FAKE_KEYTYPE, FAKE_SIG_SCHEME, {"public": secret}
        )

    @classmethod
    def generate(cls, secret: str | None = None) -> "FakeKey":
        secret = secret or secrets.token_hex(32)
        probe = cls("", secret)
        keyid = hashlib.sha256(
            encode_canonical(probe.to_dict()).encode("utf-8")
        ).hexdigest()
        return cls(keyid, secret)

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> "FakeKey":
        keytype, scheme, keyval = cls._from_dict(key_dict)
        if (keytype, scheme) != (FAKE_KEYTYPE, FAKE_SIG_SCHEME):
            raise ValueError(f"Unsupported fake key {keytype}/{scheme}")
        return cls(keyid, keyval["public"])

    def to_dict(self) -> dict[str, Any]:
        return self._to_dict()

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        expected = hmac.new(
            self.keyval["public"].encode("utf-8"), data, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature.signature):
            raise UnverifiedSignatureError(
                f"Fake signature check failed for key {self.keyid}"
            )


class FakeSigner(Signer):
    """Offline signer over a :class:`FakeKey`."""

    def __init__(self, key: FakeKey):
        self._key = key

    @property
    def public_key(self) -> Key:
        return self._key

    def sign(self, payload: bytes) -> Signature:
        sig = hmac.new(
            self._key.keyval["public"].encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()
        return Signature(self._key.keyid, sig)

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler=None,
    ) -> "FakeSigner":
        scheme, _, secret = priv_key_uri.partition(":")
        if scheme != FAKE_SCHEME or not secret:
            raise ValueError(f"Invalid fake private key URI: {priv_key_uri}")
        if not isinstance(public_key, FakeKey):
            public_key = FakeKey.from_dict(
                public_key.keyid, public_key.to_dict()
            )
        if public_key.keyval["public"] != secret:
            raise ValueError("Private key URI does not match public key")
        return cls(public_key)


SIGNER_FOR_URI_SCHEME.setdefault(FAKE_SCHEME, FakeSigner)
KEY_FOR_TYPE_AND_SCHEME.setdefault((FAKE_KEYTYPE, FAKE_SIG_SCHEME), FakeKey)
