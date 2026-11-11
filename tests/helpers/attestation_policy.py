"""Helpers for building synthetic attestation material in trust-policy tests."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from webauthn.helpers.cose import COSEAlgorithmIdentifier


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def generate_root(
    *,
    cn: str = "Test Attestation Root CA",
    expired: bool = False,
    key: Optional[ec.EllipticCurvePrivateKey] = None,
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    root_key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=30)
    not_after = now - timedelta(days=1) if expired else now + timedelta(days=3650)

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    return root_key, root_cert


def generate_intermediate(
    *,
    issuer_key: ec.EllipticCurvePrivateKey,
    issuer_cert: x509.Certificate,
    cn: str = "Test Attestation Intermediate CA",
    expired: bool = False,
    bad_key_usage: bool = False,
    not_ca: bool = False,
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=15)
    not_after = now - timedelta(days=1) if expired else now + timedelta(days=1825)

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=not not_ca, path_length=None if not not_ca else None),
            critical=True,
        )
    )

    if bad_key_usage:
        # A CA cert that is not allowed to sign other certificates
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    intermediate_cert = builder.sign(issuer_key, hashes.SHA256())
    return intermediate_key, intermediate_cert


def generate_leaf(
    *,
    issuer_key: ec.EllipticCurvePrivateKey,
    issuer_cert: x509.Certificate,
    cn: str = "Test Authenticator Attestation",
    expired: bool = False,
    bad_key_usage: bool = False,
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=10)
    not_after = now - timedelta(days=1) if expired else now + timedelta(days=365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=not bad_key_usage,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    leaf_cert = builder.sign(issuer_key, hashes.SHA256())
    return leaf_key, leaf_cert


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def cose_ec2_public_key(public_key: ec.EllipticCurvePublicKey) -> dict:
    numbers = public_key.public_numbers()
    size = (public_key.curve.key_size + 7) // 8
    return {
        1: 2,
        3: COSEAlgorithmIdentifier.ECDSA_SHA_256,
        -1: 1,
        -2: numbers.x.to_bytes(size, "big"),
        -3: numbers.y.to_bytes(size, "big"),
    }


def build_authenticator_data(
    *,
    rp_id: str,
    aaguid: bytes,
    credential_id: bytes,
    credential_public_key: dict,
    sign_count: int = 0,
) -> bytes:
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = bytes([0b01000001])  # UP (bit 0) + AT (bit 6)
    auth_data = rp_id_hash + flags + sign_count.to_bytes(4, "big")
    auth_data += aaguid
    auth_data += len(credential_id).to_bytes(2, "big") + credential_id
    auth_data += cbor2.dumps(credential_public_key)
    return auth_data


def build_client_data_json(
    *,
    challenge: bytes,
    origin: str,
) -> bytes:
    import json

    from webauthn.helpers import bytes_to_base64url

    return json.dumps(
        {
            "type": "webauthn.create",
            "challenge": bytes_to_base64url(challenge),
            "origin": origin,
            "crossOrigin": False,
        }
    ).encode("utf-8")


def build_packed_credential(
    *,
    rp_id: str = "localhost",
    origin: str = "http://localhost:5000",
    challenge: bytes,
    aaguid: bytes,
    x5c: Optional[List[bytes]] = None,
    signing_key: ec.EllipticCurvePrivateKey,
    alg: COSEAlgorithmIdentifier = COSEAlgorithmIdentifier.ECDSA_SHA_256,
    credential_key: Optional[ec.EllipticCurvePrivateKey] = None,
) -> dict:
    """Build a registration credential dict carrying a synthetic packed attestation."""
    from webauthn.helpers import bytes_to_base64url

    credential_id = b"test-credential-id"
    public_key_source = credential_key or signing_key
    credential_public_key = cose_ec2_public_key(public_key_source.public_key())
    authenticator_data = build_authenticator_data(
        rp_id=rp_id,
        aaguid=aaguid,
        credential_id=credential_id,
        credential_public_key=credential_public_key,
    )
    client_data_json = build_client_data_json(challenge=challenge, origin=origin)

    client_data_hash = hashlib.sha256(client_data_json).digest()
    verification_data = authenticator_data + client_data_hash
    signature = signing_key.sign(verification_data, ec.ECDSA(hashes.SHA256()))

    att_stmt = {"alg": int(alg), "sig": signature}
    if x5c is not None:
        att_stmt["x5c"] = x5c

    attestation_object = cbor2.dumps(
        {
            "fmt": "packed",
            "attStmt": att_stmt,
            "authData": authenticator_data,
        }
    )

    return {
        "id": bytes_to_base64url(credential_id),
        "rawId": bytes_to_base64url(credential_id),
        "response": {
            "attestationObject": bytes_to_base64url(attestation_object),
            "clientDataJSON": bytes_to_base64url(client_data_json),
        },
        "type": "public-key",
        "clientExtensionResults": {},
        "transports": ["usb"],
    }


def build_none_credential(
    *,
    rp_id: str = "localhost",
    origin: str = "http://localhost:5000",
    challenge: bytes,
    aaguid: bytes,
) -> dict:
    from webauthn.helpers import bytes_to_base64url

    credential_id = b"test-none-credential"
    authenticator_key = ec.generate_private_key(ec.SECP256R1())
    credential_public_key = cose_ec2_public_key(authenticator_key.public_key())
    authenticator_data = build_authenticator_data(
        rp_id=rp_id,
        aaguid=aaguid,
        credential_id=credential_id,
        credential_public_key=credential_public_key,
    )
    client_data_json = build_client_data_json(challenge=challenge, origin=origin)
    attestation_object = cbor2.dumps(
        {
            "fmt": "none",
            "attStmt": {},
            "authData": authenticator_data,
        }
    )

    return {
        "id": bytes_to_base64url(credential_id),
        "rawId": bytes_to_base64url(credential_id),
        "response": {
            "attestationObject": bytes_to_base64url(attestation_object),
            "clientDataJSON": bytes_to_base64url(client_data_json),
        },
        "type": "public-key",
        "clientExtensionResults": {},
        "transports": ["internal"],
    }
