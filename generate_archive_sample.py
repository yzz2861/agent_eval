#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from asn1crypto import algos, cms, core, pem, tsp, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_key_and_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Archive Timestamp Authority"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Archive Receipt Lab"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(770013)
        .not_valid_before(now.replace(year=2020, month=1, day=1))
        .not_valid_after(now.replace(year=2036, month=1, day=1))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    asn1_cert = asn1_x509.Certificate.load(cert_der)
    return key, cert, asn1_cert


def sign_signed_attrs(attrs: cms.CMSAttributes, key) -> bytes:
    der = attrs.dump()
    set_der = b"\x31" + der[1:]
    return key.sign(set_der, padding.PKCS1v15(), hashes.SHA256())


def signer_identifier(asn1_cert: asn1_x509.Certificate) -> cms.SignerIdentifier:
    return cms.SignerIdentifier({
        "issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": asn1_cert.issuer,
            "serial_number": asn1_cert.serial_number,
        })
    })


def build_signed_content_info(
    econtent: core.Asn1Value,
    econtent_type: str,
    content_type_oid: str,
    key,
    asn1_cert: asn1_x509.Certificate,
) -> cms.ContentInfo:
    eci = cms.EncapsulatedContentInfo({
        "content_type": econtent_type,
        "content": econtent,
    })
    econtent_bytes = econtent.dump() if econtent_type == "tst_info" else eci["content"].native
    if econtent_type != "tst_info":
        econtent_bytes = bytes(eci["content"].native)
    message_digest = hashlib.sha256(econtent_bytes).digest()
    attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": [core.ObjectIdentifier(content_type_oid)],
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": [core.OctetString(message_digest)],
        }),
    ])
    signature = sign_signed_attrs(attrs, key)
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": signer_identifier(asn1_cert),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        "signature": signature,
    })
    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": eci,
        "certificates": [asn1_cert],
        "signer_infos": [signer_info],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data})


def build_original_cms(text: str, key, asn1_cert: asn1_x509.Certificate) -> bytes:
    payload = text.encode("utf-8")
    econtent = core.OctetString(payload)
    info = build_signed_content_info(
        econtent,
        "data",
        cms.ContentType._map["data"] if "data" in cms.ContentType._map else "1.2.840.113549.1.7.1",
        key,
        asn1_cert,
    )
    return info.dump()


def build_timestamp_receipt(
    record_bytes: bytes,
    gen_time: datetime,
    serial: int,
    key,
    asn1_cert: asn1_x509.Certificate,
) -> tuple[bytes, bytes]:
    imprint = hashlib.sha256(record_bytes).digest()
    tst_info = tsp.TSTInfo({
        "version": "v1",
        "policy": core.ObjectIdentifier("1.2.3.4.60.13.1"),
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "hashed_message": core.OctetString(imprint),
        }),
        "serial_number": core.Integer(serial),
        "gen_time": gen_time,
    })
    token_ci = build_signed_content_info(
        tst_info,
        "tst_info",
        "1.2.840.113549.1.9.16.1.4",
        key,
        asn1_cert,
    )
    response = tsp.TimeStampResp({
        "status": {"status": "granted"},
        "time_stamp_token": token_ci,
    })
    return response.dump(), token_ci.dump()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def pseudo_main_marker():
    return False


def armor_pem(label, der):
    body = base64.encodebytes(der).decode("ascii")
    return ("-----BEGIN " + label + "-----\n" + body + "-----END " + label + "-----\n").encode("ascii")
append-test
