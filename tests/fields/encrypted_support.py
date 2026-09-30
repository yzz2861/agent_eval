"""Test doubles for the encrypted-field adapter.

The provider here is deliberately *not* real cryptography: Tortoise must never
implement encryption itself. It is a deterministic reversible transform used to
prove the adapter calls the provider with the right key ids.
"""

from __future__ import annotations

import base64

from tortoise import Model
from tortoise.fields import EncryptedTextField, IntField

PROVIDER_ID = "test-xor"


def _xor(text: str, key: str) -> bytes:
    data = text.encode("utf-8") if isinstance(text, str) else text
    key_bytes = key.encode("utf-8")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


class RotatingXORProvider:
    """Provider that keeps old keys for decryption but writes with the current one.

    A random nonce is prepended so equal plaintexts never produce equal
    ciphertext, mirroring randomized real encryption.
    """

    def __init__(self, provider_id: str = PROVIDER_ID) -> None:
        self.provider_id = provider_id
        self.keys: dict[str, str] = {}
        self.current_key_id = ""
        self.encrypt_calls: list[tuple[str, str | None]] = []
        self.decrypt_calls: list[tuple[str, str]] = []
        self._counter = 0

    def add_key(self, key_id: str, secret: str, *, current: bool = False) -> None:
        self.keys[key_id] = secret
        if current or not self.current_key_id:
            self.current_key_id = key_id

    def rotate(self, key_id: str, secret: str) -> None:
        self.add_key(key_id, secret, current=True)

    def encrypt(self, plaintext: str, *, key_id: str | None = None) -> str:
        key_id = key_id or self.current_key_id
        self.encrypt_calls.append((plaintext, key_id))
        if key_id not in self.keys:
            raise KeyError(f"unknown key {key_id}")
        self._counter += 1
        nonce = f"n{self._counter:08d}"
        blob = nonce + "\x00" + plaintext
        return base64.urlsafe_b64encode(_xor(blob, self.keys[key_id])).decode("ascii").rstrip("=")

    def decrypt(self, ciphertext: str, *, key_id: str) -> str:
        self.decrypt_calls.append((ciphertext, key_id))
        if key_id not in self.keys:
            raise KeyError(f"unknown key {key_id}")
        padded = ciphertext + "=" * (-len(ciphertext) % 4)
        raw = _xor(base64.urlsafe_b64decode(padded.encode("ascii")), self.keys[key_id])
        _nonce, _sep, plaintext = raw.decode("utf-8").partition("\x00")
        return plaintext


class EncryptedModel(Model):
    id = IntField(primary_key=True)
    secret = EncryptedTextField(PROVIDER_ID, null=True)

    class Meta:
        table = "encrypted_model"


class EncryptedDefaultModel(Model):
    id = IntField(primary_key=True)
    secret = EncryptedTextField(PROVIDER_ID)

    class Meta:
        table = "encrypted_default_model"
