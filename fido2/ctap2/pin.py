# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import annotations

import abc
import logging
import os
from dataclasses import dataclass
from enum import IntEnum, IntFlag, unique
from threading import Event
from typing import Any, Callable, ClassVar, Mapping

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..cose import CoseKey
from ..ctap import CtapError
from ..utils import bytes2int, hmac_sha256, int2bytes, sha256
from .base import Ctap2
from .pin_state import (  # noqa: F401
    FilePinUvStore,
    InMemoryPinUvStore,
    JsonFilePinUvStore,
    PinRetryError,
    PinState,
    PinStateMachine,
    PinUvError,
    PinUvState,
    PinUvStateError,
    PinUvStateMachine,
    PinUvStatus,
    PinUvStore,
    PinUvTracker,
    device_identity,
)

logger = logging.getLogger(__name__)


def _pad_pin(pin: str) -> bytes:
    if not isinstance(pin, str):
        raise ValueError(f"PIN of wrong type, expecting {str}")
    if len(pin) < 4:
        raise ValueError("PIN must be >= 4 characters")
    pin_padded = pin.encode().ljust(64, b"\0")
    pin_padded += b"\0" * (-(len(pin_padded) - 16) % 16)
    if len(pin_padded) > 255:
        raise ValueError("PIN must be <= 255 bytes")
    return pin_padded


class PinProtocol(abc.ABC):
    VERSION: ClassVar[int]

    @abc.abstractmethod
    def encapsulate(self, peer_cose_key: CoseKey) -> tuple[Mapping[int, Any], bytes]:
        """Generates an encapsulation of the public key.
        Returns the message to transmit and the shared secret.
        """

    @abc.abstractmethod
    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        """Encrypts data"""

    @abc.abstractmethod
    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """Decrypts encrypted data"""

    @abc.abstractmethod
    def authenticate(self, key: bytes, message: bytes) -> bytes:
        """Computes a MAC of the given message."""

    @abc.abstractmethod
    def validate_token(self, token: bytes) -> bytes:
        """Validates that a token is well-formed.
        Returns the token, or if invalid, raises a ValueError.
        """


@dataclass
class _PinUv:
    protocol: PinProtocol
    token: bytes


class PinProtocolV1(PinProtocol):
    """Implementation of the CTAP2 PIN/UV protocol v1.

    :param ctap: An instance of a CTAP2 object.
    :cvar VERSION: The version number of the PIV/UV protocol.
    :cvar IV: An all-zero IV used for some cryptographic operations.
    """

    VERSION = 1
    IV = b"\x00" * 16

    def kdf(self, z: bytes) -> bytes:
        return sha256(z)

    def encapsulate(self, peer_cose_key):
        be = default_backend()
        sk = ec.generate_private_key(ec.SECP256R1(), be)
        pn = sk.public_key().public_numbers()
        key_agreement = {
            1: 2,
            3: -25,  # Per the spec, "although this is NOT the algorithm actually used"
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32),
        }

        x = bytes2int(peer_cose_key[-2])
        y = bytes2int(peer_cose_key[-3])
        pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(be)
        shared_secret = self.kdf(sk.exchange(ec.ECDH(), pk))  # x-coordinate, 32b
        return key_agreement, shared_secret

    def _get_cipher_v1(self, secret):
        be = default_backend()
        return Cipher(algorithms.AES(secret), modes.CBC(PinProtocolV1.IV), be)

    def encrypt(self, key, plaintext):
        cipher = self._get_cipher_v1(key)
        enc = cipher.encryptor()
        return enc.update(plaintext) + enc.finalize()

    def decrypt(self, key, ciphertext):
        cipher = self._get_cipher_v1(key)
        dec = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()

    def authenticate(self, key, message):
        return hmac_sha256(key, message)[:16]

    def validate_token(self, token):
        if len(token) not in (16, 32):
            raise ValueError("PIN/UV token must be 16 or 32 bytes")
        return token


class PinProtocolV2(PinProtocolV1):
    """Implementation of the CTAP2 PIN/UV protocol v2.

    :param ctap: An instance of a CTAP2 object.
    :cvar VERSION: The version number of the PIV/UV protocol.
    :cvar IV: An all-zero IV used for some cryptographic operations.
    """

    VERSION = 2
    HKDF_SALT = b"\x00" * 32
    HKDF_INFO_HMAC = b"CTAP2 HMAC key"
    HKDF_INFO_AES = b"CTAP2 AES key"

    def kdf(self, z):
        be = default_backend()
        hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=PinProtocolV2.HKDF_SALT,
            info=PinProtocolV2.HKDF_INFO_HMAC,
            backend=be,
        ).derive(z)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=PinProtocolV2.HKDF_SALT,
            info=PinProtocolV2.HKDF_INFO_AES,
            backend=be,
        ).derive(z)
        return hmac_key + aes_key

    def _get_cipher_v2(self, secret, iv):
        be = default_backend()
        return Cipher(algorithms.AES(secret), modes.CBC(iv), be)

    def encrypt(self, key, plaintext):
        aes_key = key[32:]
        iv = os.urandom(16)

        cipher = self._get_cipher_v2(aes_key, iv)
        enc = cipher.encryptor()
        return iv + enc.update(plaintext) + enc.finalize()

    def decrypt(self, key, ciphertext):
        aes_key = key[32:]
        iv, ciphertext = ciphertext[:16], ciphertext[16:]
        cipher = self._get_cipher_v2(aes_key, iv)
        dec = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()

    def authenticate(self, key, message):
        hmac_key = key[:32]
        return hmac_sha256(hmac_key, message)

    def validate_token(self, token):
        if len(token) != 32:
            raise ValueError("PIN/UV token must be 32 bytes")
        return token


class ClientPin:
    """Implementation of the CTAP2 Client PIN API.

    :param ctap: An instance of a CTAP2 object.
    :param protocol: An optional instance of a PinUvAuthProtocol object. If None is
        provided then the latest protocol supported by both library and Authenticator
        will be used.
    """

    PROTOCOLS = [PinProtocolV2, PinProtocolV1]

    @unique
    class CMD(IntEnum):
        GET_PIN_RETRIES = 0x01
        GET_KEY_AGREEMENT = 0x02
        SET_PIN = 0x03
        CHANGE_PIN = 0x04
        GET_TOKEN_USING_PIN_LEGACY = 0x05
        GET_TOKEN_USING_UV = 0x06
        GET_UV_RETRIES = 0x07
        GET_TOKEN_USING_PIN = 0x09

    @unique
    class RESULT(IntEnum):
        KEY_AGREEMENT = 0x01
        PIN_UV_TOKEN = 0x02
        PIN_RETRIES = 0x03
        POWER_CYCLE_STATE = 0x04
        UV_RETRIES = 0x05

    @unique
    class PERMISSION(IntFlag):
        MAKE_CREDENTIAL = 0x01
        GET_ASSERTION = 0x02
        CREDENTIAL_MGMT = 0x04
        BIO_ENROLL = 0x08
        LARGE_BLOB_WRITE = 0x10
        AUTHENTICATOR_CFG = 0x20
        PERSISTENT_CREDENTIAL_MGMT = 0x40

    @staticmethod
    def is_supported(info):
        """Checks if ClientPin functionality is supported.

        Note that the ClientPin function is still usable without support for client
        PIN functionality, as UV token may still be supported.
        """
        return "clientPin" in info.options

    @staticmethod
    def is_token_supported(info):
        """Checks if pinUvAuthToken is supported."""
        return info.options.get("pinUvAuthToken") is True

    def __init__(
        self,
        ctap: Ctap2,
        protocol: PinProtocol | None = None,
        *,
        device_id: str | bytes | None = None,
        state: PinUvStateMachine | None = None,
        state_machine: PinUvStateMachine | None = None,
        store: PinUvStore | str | os.PathLike[str] | None = None,
        lockout_seconds: float = 60.0,
        soft_lock_after: int = 3,
        max_pin_retries: int = 8,
        max_uv_retries: int = 3,
        enforce_locks: bool = False,
        **kwargs: Any,
    ):
        if store is None:
            store = kwargs.pop(
                "state_store",
                kwargs.pop("retry_store", kwargs.pop("state_path", None)),
            )
        if "lockout" in kwargs:
            lockout_seconds = kwargs.pop("lockout")
        if "soft_lock" in kwargs:
            soft_lock_after = kwargs.pop("soft_lock")
        if kwargs:
            unknown = ", ".join(sorted(kwargs))
            raise TypeError(f"Unexpected arguments: {unknown}")
        self.ctap = ctap
        if protocol is None:
            for proto in ClientPin.PROTOCOLS:
                if proto.VERSION in ctap.info.pin_uv_protocols:
                    self.protocol: PinProtocol = proto()
                    break
            else:
                raise ValueError("No compatible PIN/UV protocols supported!")
        else:
            self.protocol = protocol

        info = getattr(ctap, "info", None)
        options = getattr(info, "options", {})
        if not isinstance(options, Mapping):
            options = {}
        pin_supported = "clientPin" in options
        pin_set = bool(options.get("clientPin"))
        uv_supported = bool(options.get("uv"))
        if device_id is None:
            device_id = self._device_identity(info)
        self._device_id = device_id
        self._store = store
        self._max_pin_retries = max_pin_retries
        self._max_uv_retries = max_uv_retries
        self._lockout_seconds = lockout_seconds
        self._soft_lock_after = soft_lock_after
        self._enforce_locks = enforce_locks
        self._state_machines: dict[str | None, PinUvStateMachine] = {}
        initial_state = state or state_machine
        if initial_state is not None:
            self._state_machines[None] = initial_state
            self._pin_state = initial_state
        else:
            self._pin_state = self._make_state(
                None,
                pin_supported=pin_supported,
                pin_set=pin_set,
                uv_supported=uv_supported,
                lockout_seconds=lockout_seconds,
                soft_lock_after=soft_lock_after,
                max_pin_retries=max_pin_retries,
                max_uv_retries=max_uv_retries,
                enforce_locks=enforce_locks,
            )

    @staticmethod
    def _device_identity(info: Any) -> str:
        return device_identity(info)

    def _make_state(
        self,
        credential_id: str | bytes | None,
        *,
        pin_supported: bool | None = None,
        pin_set: bool | None = None,
        uv_supported: bool = False,
        lockout_seconds: float = 60.0,
        soft_lock_after: int = 3,
        max_pin_retries: int = 8,
        max_uv_retries: int = 3,
        enforce_locks: bool = False,
    ) -> PinUvStateMachine:
        return PinUvStateMachine(
            credential_id,
            device_id=self._device_id,
            pin_supported=pin_supported,
            pin_set=pin_set,
            uv_supported=uv_supported,
            protocol_version=self.protocol.VERSION,
            max_pin_retries=max_pin_retries,
            max_uv_retries=max_uv_retries,
            store=self._store,
            lockout_seconds=lockout_seconds,
            soft_lock_after=soft_lock_after,
            enforce_locks=enforce_locks,
        )

    def _state_for(self, credential_id: str | bytes | None = None) -> PinUvStateMachine:
        key = credential_id.hex() if isinstance(credential_id, bytes) else credential_id
        machine = self._state_machines.get(key)
        if machine is None:
            info = getattr(self.ctap, "info", None)
            options = getattr(info, "options", {})
            if not isinstance(options, Mapping):
                options = {}
            machine = self._make_state(
                credential_id,
                pin_supported="clientPin" in options,
                pin_set=bool(options.get("clientPin")),
                uv_supported=bool(options.get("uv")),
                lockout_seconds=self._lockout_seconds,
                soft_lock_after=self._soft_lock_after,
                max_pin_retries=self._max_pin_retries,
                max_uv_retries=self._max_uv_retries,
                enforce_locks=self._enforce_locks,
            )
            self._state_machines[key] = machine
        return machine

    @property
    def state(self) -> PinUvStatus:
        """Current PIN/UV state, including remaining attempts and lockout."""
        return self._pin_state.status()

    @property
    def pin_state(self) -> PinUvStatus:
        return self.state

    @property
    def state_machine(self) -> PinUvStateMachine:
        return self._pin_state

    @property
    def pin_uv_state_machine(self) -> PinUvStateMachine:
        return self._pin_state

    @property
    def retries(self) -> int:
        return self._pin_state.retries

    @property
    def pin_retries(self) -> int:
        return self._pin_state.retries

    @property
    def uv_retries(self) -> int:
        return self._pin_state.uv_retries

    def get_state(self, credential_id: str | bytes | None = None) -> PinUvStatus:
        return self._state_for(credential_id).status()

    def get_state_machine(
        self, credential_id: str | bytes | None = None
    ) -> PinUvStateMachine:
        return self._state_for(credential_id)

    state_machine_for = get_state_machine
    pin_uv_state_machine_for = get_state_machine

    def state_for(self, credential_id: str | bytes | None = None) -> PinUvStatus:
        return self.get_state(credential_id)

    def get_pin_state(self, credential_id: str | bytes | None = None) -> PinUvStatus:
        return self.get_state(credential_id)

    def get_uv_state(self, credential_id: str | bytes | None = None) -> PinUvStatus:
        return self.get_state(credential_id)

    def reset_state(
        self,
        credential_id: str | bytes | None = None,
        *,
        pin: bool = True,
        uv: bool = True,
    ) -> PinUvStatus:
        """Explicitly reset locally tracked PIN/UV attempts."""
        return self._state_for(credential_id).admin_reset(pin=pin, uv=uv)

    def _record_success(
        self, operation: str, credential_id: str | bytes | None = None
    ) -> None:
        machine = self._state_for(credential_id)
        self._pin_state = machine
        if operation == "uv":
            machine.record_uv_success()
        else:
            machine.record_pin_success()

    def _record_error(
        self,
        error: CtapError,
        operation: str,
        credential_id: str | bytes | None = None,
    ) -> CtapError:
        pin_errors = (
            CtapError.ERR.PIN_INVALID,
            CtapError.ERR.PIN_AUTH_INVALID,
            CtapError.ERR.PIN_BLOCKED,
            CtapError.ERR.PIN_AUTH_BLOCKED,
        )
        uv_errors = (
            CtapError.ERR.UV_INVALID,
            CtapError.ERR.UV_BLOCKED,
            CtapError.ERR.PIN_INVALID,
            CtapError.ERR.PIN_AUTH_INVALID,
        )
        if operation == "uv" and error.code in uv_errors and error.uv_retries is None:
            try:
                resp = self.ctap.client_pin(
                    self.protocol.VERSION, ClientPin.CMD.GET_UV_RETRIES
                )
                if not isinstance(resp, Mapping):
                    raise TypeError("Unexpected PIN response")
                value = resp[ClientPin.RESULT.UV_RETRIES]
                if not isinstance(value, int) or isinstance(value, bool):
                    raise TypeError("Unexpected UV retry count")
                error.uv_retries = value
                error.retry_after = resp.get(0x06) or error.retry_after
                error.locked_until = resp.get(0x07) or error.locked_until
            except Exception:
                logger.debug("Unable to query UV retries", exc_info=True)
        elif operation != "uv" and error.code in pin_errors and error.retries is None:
            try:
                resp = self.ctap.client_pin(
                    self.protocol.VERSION, ClientPin.CMD.GET_PIN_RETRIES
                )
                if not isinstance(resp, Mapping):
                    raise TypeError("Unexpected PIN response")
                value = resp[ClientPin.RESULT.PIN_RETRIES]
                if not isinstance(value, int) or isinstance(value, bool):
                    raise TypeError("Unexpected PIN retry count")
                error.retries = value
                error.retry_after = resp.get(0x06) or error.retry_after
                error.locked_until = resp.get(0x07) or error.locked_until
            except Exception:
                logger.debug("Unable to query PIN retries", exc_info=True)
        machine = self._state_for(credential_id)
        self._pin_state = machine
        status = machine.apply_ctap_error(error, operation=operation)
        error.operation = operation
        error.state = status.state
        error.retries = status.retries
        error.uv_retries = status.uv_retries
        error.retry_after = status.retry_after
        error.locked_until = status.locked_until
        error.retryable = status.retryable
        return error

    def _get_shared_secret(self):
        resp = self.ctap.client_pin(
            self.protocol.VERSION, ClientPin.CMD.GET_KEY_AGREEMENT
        )
        pk = resp[ClientPin.RESULT.KEY_AGREEMENT]

        return self.protocol.encapsulate(pk)

    def get_pin_token(
        self,
        pin: str,
        permissions: ClientPin.PERMISSION | None = None,
        permissions_rpid: str | None = None,
        credential_id: str | bytes | None = None,
    ) -> bytes:
        """Get a PIN/UV token from the authenticator using PIN.

        :param pin: The PIN of the authenticator.
        :param permissions: The permissions to associate with the token.
        :param permissions_rpid: The permissions RPID to associate with the token.
        :return: A PIN/UV token.
        """
        if not ClientPin.is_supported(self.ctap.info):
            raise ValueError("Authenticator does not support get_pin_token")
        if self._pin_state.enforce_locks:
            self._pin_state.ensure_available()

        try:
            key_agreement, shared_secret = self._get_shared_secret()

            pin_hash = sha256(pin.encode())[:16]
            pin_hash_enc = self.protocol.encrypt(shared_secret, pin_hash)

            if ClientPin.is_token_supported(self.ctap.info) and permissions is not None:
                cmd = ClientPin.CMD.GET_TOKEN_USING_PIN
            else:
                cmd = ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY
                # Ignore permissions if not supported
                permissions = None
                permissions_rpid = None

            resp = self.ctap.client_pin(
                self.protocol.VERSION,
                cmd,
                key_agreement=key_agreement,
                pin_hash_enc=pin_hash_enc,
                permissions=permissions,
                permissions_rpid=permissions_rpid,
            )
            pin_token_enc = resp[ClientPin.RESULT.PIN_UV_TOKEN]
            token = self.protocol.validate_token(
                self.protocol.decrypt(shared_secret, pin_token_enc)
            )
        except CtapError as e:
            self._record_error(e, "pin", credential_id)
            raise
        self._record_success("pin", credential_id)
        logger.debug(f"Got PIN token for permissions: {permissions}")
        return token

    def get_uv_token(
        self,
        permissions: ClientPin.PERMISSION | None = None,
        permissions_rpid: str | None = None,
        event: Event | None = None,
        on_keepalive: Callable[[int], None] | None = None,
        credential_id: str | bytes | None = None,
    ) -> bytes:
        """Get a PIN/UV token from the authenticator using built-in UV.

        :param permissions: The permissions to associate with the token.
        :param permissions_rpid: The permissions RPID to associate with the token.
        :param event: An optional threading.Event which can be used to cancel
            the invocation.
        :param on_keepalive: An optional callback to handle keep-alive messages
            from the authenticator. The function is only called once for
            consecutive keep-alive messages with the same status.
        :return: A PIN/UV token.
        """
        if not ClientPin.is_token_supported(self.ctap.info):
            raise ValueError("Authenticator does not support get_uv_token")
        if self._pin_state.enforce_locks:
            self._pin_state.ensure_available(uv=True)

        try:
            key_agreement, shared_secret = self._get_shared_secret()

            resp = self.ctap.client_pin(
                self.protocol.VERSION,
                ClientPin.CMD.GET_TOKEN_USING_UV,
                key_agreement=key_agreement,
                permissions=permissions,
                permissions_rpid=permissions_rpid,
                event=event,
                on_keepalive=on_keepalive,
            )

            pin_token_enc = resp[ClientPin.RESULT.PIN_UV_TOKEN]
            token = self.protocol.validate_token(
                self.protocol.decrypt(shared_secret, pin_token_enc)
            )
        except CtapError as e:
            self._record_error(e, "uv", credential_id)
            raise
        self._record_success("uv", credential_id)
        logger.debug(f"Got UV token for permissions: {permissions}")
        return token

    def get_pin_retries(self) -> tuple[int, int | None]:
        """Get the number of PIN retries remaining.

        :return: A tuple of the number of PIN attempts remaining until the
        authenticator is locked, and the power cycle state, if available.
        The locally tracked counter is monotonic: a device report cannot
        restore attempts that were already consumed.
        """
        try:
            resp = self.ctap.client_pin(
                self.protocol.VERSION, ClientPin.CMD.GET_PIN_RETRIES
            )
        except CtapError as e:
            self._record_error(e, "pin")
            raise
        device_retries = int(resp[ClientPin.RESULT.PIN_RETRIES])
        status = self._pin_state.sync_pin_retries(
            device_retries,
            retry_after=resp.get(0x06),
            locked_until=resp.get(0x07),
        )
        return (
            device_retries if status.retries is None else status.retries,
            resp.get(ClientPin.RESULT.POWER_CYCLE_STATE),
        )

    def get_uv_retries(self) -> int:
        """Get the number of UV retries remaining.

        :return: The number of UV attempts remaining until the authenticator
        is locked.
        """
        try:
            resp = self.ctap.client_pin(
                self.protocol.VERSION, ClientPin.CMD.GET_UV_RETRIES
            )
        except CtapError as e:
            self._record_error(e, "uv")
            raise
        device_retries = int(resp[ClientPin.RESULT.UV_RETRIES])
        status = self._pin_state.sync_uv_retries(
            device_retries,
            retry_after=resp.get(0x06),
            locked_until=resp.get(0x07),
        )
        return device_retries if status.uv_retries is None else status.uv_retries

    def set_pin(self, pin: str) -> None:
        """Set the PIN of the autenticator.

        This only works when no PIN is set. To change the PIN when set, use
        change_pin.

        :param pin: A PIN to set.
        """
        if not ClientPin.is_supported(self.ctap.info):
            raise ValueError("Authenticator does not support ClientPin")

        try:
            key_agreement, shared_secret = self._get_shared_secret()

            pin_enc = self.protocol.encrypt(shared_secret, _pad_pin(pin))
            pin_uv_param = self.protocol.authenticate(shared_secret, pin_enc)
            self.ctap.client_pin(
                self.protocol.VERSION,
                ClientPin.CMD.SET_PIN,
                key_agreement=key_agreement,
                new_pin_enc=pin_enc,
                pin_uv_param=pin_uv_param,
            )
        except CtapError as e:
            self._record_error(e, "pin")
            raise
        self._pin_state.admin_reset(pin=True, uv=False)
        logger.info("PIN has been set")

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        """Change the PIN of the authenticator.

        This only works when a PIN is already set. If no PIN is set, use
        set_pin.

        :param old_pin: The currently set PIN.
        :param new_pin: The new PIN to set.
        """
        if not ClientPin.is_supported(self.ctap.info):
            raise ValueError("Authenticator does not support ClientPin")

        try:
            key_agreement, shared_secret = self._get_shared_secret()

            pin_hash = sha256(old_pin.encode())[:16]
            pin_hash_enc = self.protocol.encrypt(shared_secret, pin_hash)
            new_pin_enc = self.protocol.encrypt(shared_secret, _pad_pin(new_pin))
            pin_uv_param = self.protocol.authenticate(
                shared_secret, new_pin_enc + pin_hash_enc
            )
            self.ctap.client_pin(
                self.protocol.VERSION,
                ClientPin.CMD.CHANGE_PIN,
                key_agreement=key_agreement,
                pin_hash_enc=pin_hash_enc,
                new_pin_enc=new_pin_enc,
                pin_uv_param=pin_uv_param,
            )
        except CtapError as e:
            self._record_error(e, "pin")
            raise
        self._record_success("pin")
        logger.info("PIN has been changed")
