"""Helpers that synthesize valid WebAuthn authentication assertions in tests.

A real authenticator is not available in the unit test environment, so these
helpers generate an ES256 (P-256) keypair and sign the same
`authenticatorData || SHA-256(clientDataJSON)` base that a browser-side
authenticator would produce. Only the authentication ceremony tests consume
these helpers.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256

from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier, COSECRV, COSEKTY, COSEKey
from webauthn.helpers.encode_cbor import encode_cbor
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorDataFlags,
    CredentialDeviceType,
    PublicKeyCredentialType,
)


@dataclass
class SyntheticAuthenticator:
    credential_id: bytes
    user_handle: bytes
    rp_id: str
    origin: str
    private_key: EllipticCurvePrivateKey
    device_type: CredentialDeviceType = CredentialDeviceType.SINGLE_DEVICE
    backed_up: bool = False

    @classmethod
    def create(
        cls,
        *,
        credential_id: bytes,
        user_handle: bytes,
        rp_id: str,
        origin: str,
        device_type: CredentialDeviceType = CredentialDeviceType.SINGLE_DEVICE,
        backed_up: bool = False,
    ) -> "SyntheticAuthenticator":
        return cls(
            credential_id=credential_id,
            user_handle=user_handle,
            rp_id=rp_id,
            origin=origin,
            private_key=generate_private_key(SECP256R1()),
            device_type=device_type,
            backed_up=backed_up,
        )

    @property
    def public_key_cose(self) -> bytes:
        numbers = self.private_key.public_key().public_numbers()
        return encode_cbor(
            {
                COSEKey.KTY: COSEKTY.EC2,
                COSEKey.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEKey.CRV: COSECRV.P256,
                COSEKey.X: numbers.x.to_bytes(32, "big"),
                COSEKey.Y: numbers.y.to_bytes(32, "big"),
            }
        )

    def make_assertion(
        self,
        *,
        challenge: bytes,
        sign_count: int,
        up: bool = True,
        uv: bool = False,
        be: Optional[bool] = None,
        bs: Optional[bool] = None,
        user_handle: Optional[bytes] = "default",
    ) -> AuthenticationCredential:
        if be is None:
            be = self.device_type == CredentialDeviceType.MULTI_DEVICE
        if bs is None:
            bs = self.backed_up
        if user_handle == "default":
            user_handle = self.user_handle

        client_data = {
            "type": "webauthn.get",
            "challenge": bytes_to_base64url(challenge),
            "origin": self.origin,
        }
        client_data_json = json.dumps(
            client_data, separators=(",", ":")
        ).encode("utf-8")

        flags = AuthenticatorDataFlags(
            up=up, uv=uv, be=be, bs=bs, at=False, ed=False
        )
        authenticator_data = self._build_authenticator_data(flags, sign_count)

        signature_base = authenticator_data + hashlib.sha256(client_data_json).digest()
        signature = self.private_key.sign(signature_base, ECDSA(SHA256()))

        return AuthenticationCredential(
            id=bytes_to_base64url(self.credential_id),
            raw_id=self.credential_id,
            response=AuthenticatorAssertionResponse(
                client_data_json=client_data_json,
                authenticator_data=authenticator_data,
                signature=signature,
                user_handle=user_handle,
            ),
            type=PublicKeyCredentialType.PUBLIC_KEY,
        )

    def _build_authenticator_data(
        self, flags: AuthenticatorDataFlags, sign_count: int
    ) -> bytes:
        rp_id_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
        flags_byte = (
            (0b00000001 if flags.up else 0)
            | (0b00000100 if flags.uv else 0)
            | (0b00001000 if flags.be else 0)
            | (0b00010000 if flags.bs else 0)
            | (0b01000000 if flags.at else 0)
            | (0b10000000 if flags.ed else 0)
        )
        return rp_id_hash + bytes((flags_byte,)) + sign_count.to_bytes(4, "big")
