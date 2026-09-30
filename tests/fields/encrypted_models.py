"""Models and a toy (non-cryptographic!) provider for EncryptedField tests.

The ToyCipherProvider below exists ONLY to exercise the framework's
encryption envelope protocol. It is a reversible XOR obfuscation, not real
cryptography - applications must plug in a real provider (e.g. one backed
by the `cryptography` package or a KMS).
"""

from __future__ import annotations

import hashlib
import os

from tortoise import fields
from tortoise.models import Model


class ToyCipherProvider:
    """Test-only provider implementing the EncryptionProvider protocol."""

    provider_id = "tests.fields.encrypted_models.toy_provider"

    def __init__(self, keys: dict[str, bytes], current: str) -> None:
        self.keys = dict(keys)
        self.current = current

    @property
    def current_key_id(self) -> str:
        return self.current

    def rotate_to(self, key_id: str, key: bytes) -> None:
        self.keys[key_id] = key
        self.current = key_id

    def encrypt(self, plaintext: bytes, key_id: str) -> bytes:
        key = self.keys[key_id]
        nonce = os.urandom(8)
        mask = hashlib.sha256(key + nonce).digest()
        return nonce + bytes(b ^ mask[i % len(mask)] for i, b in enumerate(plaintext))

    def decrypt(self, ciphertext: bytes, key_id: str) -> bytes:
        key = self.keys[key_id]
        nonce, body = ciphertext[:8], ciphertext[8:]
        mask = hashlib.sha256(key + nonce).digest()
        return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(body))


toy_provider = ToyCipherProvider({"k1": b"test-key-one"}, "k1")


class SecretNote(Model):
    id = fields.IntField(primary_key=True)
    title = fields.CharField(max_length=64)
    secret = fields.EncryptedField(provider="tests.fields.encrypted_models.toy_provider")
    secret_null = fields.EncryptedField(provider=toy_provider, null=True)


class OrderedSecret(Model):
    id = fields.IntField(primary_key=True)
    secret = fields.EncryptedField(provider=toy_provider)

    class Meta:
        ordering = ["secret"]
