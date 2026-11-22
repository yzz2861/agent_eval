# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime

from asn1crypto import algos, core, keys, x509
from asn1crypto.util import timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from certvalidator import BusinessConstraint


VALIDATION_MOMENT = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

NOT_BEFORE = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
NOT_AFTER = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
EXPIRED_AFTER = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


SERVER_CONSTRAINT = BusinessConstraint(
    key_usage=set(["digital_signature", "key_encipherment"]),
    extended_key_usage=set(["server_auth"]),
    label="tls_server_auth",
)
CLIENT_CONSTRAINT = BusinessConstraint(
    key_usage=set(["digital_signature"]),
    extended_key_usage=set(["client_auth"]),
    label="tls_client_auth",
)
CODE_SIGNING_CONSTRAINT = BusinessConstraint(
    key_usage=set(["digital_signature"]),
    extended_key_usage=set(["code_signing"]),
    label="code_signing",
)


def _public_key_info(private_key):
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return keys.PublicKeyInfo.load(der)


def _time(value):
    return x509.Time(name="utc_time", value=value)


class CertTreeBuilder(object):

    def __init__(self):
        self._serial = 0

    def _next_serial(self):
        self._serial += 1
        return self._serial

    def generate_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def create_cert(self, subject_cn, issuer_cn, issuer_key, subject_key,
                    is_ca, key_usage=None, eku=None,
                    not_before=NOT_BEFORE, not_after=NOT_AFTER,
                    path_len_constraint=None):
        subject_pki = _public_key_info(subject_key)
        issuer_pki = _public_key_info(issuer_key)

        tbs = x509.TbsCertificate()
        tbs["version"] = "v3"
        tbs["serial_number"] = self._next_serial()
        tbs["signature"] = algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
        tbs["issuer"] = x509.Name.build({"common_name": issuer_cn})
        tbs["validity"] = x509.Validity({
            "not_before": _time(not_before),
            "not_after": _time(not_after),
        })
        tbs["subject"] = x509.Name.build({"common_name": subject_cn})
        tbs["subject_public_key_info"] = subject_pki

        extensions = []

        basic_constraints = x509.BasicConstraints({"ca": is_ca})
        if is_ca:
            if path_len_constraint is not None:
                basic_constraints["path_len_constraint"] = path_len_constraint
        extensions.append(x509.Extension({
            "extn_id": "basic_constraints",
            "critical": True,
            "extn_value": basic_constraints,
        }))

        if key_usage is not None:
            extensions.append(x509.Extension({
                "extn_id": "key_usage",
                "critical": True,
                "extn_value": x509.KeyUsage(key_usage),
            }))

        if eku is not None:
            extensions.append(x509.Extension({
                "extn_id": "extended_key_usage",
                "critical": False,
                "extn_value": x509.ExtKeyUsageSyntax(eku),
            }))

        extensions.append(x509.Extension({
            "extn_id": "key_identifier",
            "critical": False,
            "extn_value": core.OctetString(subject_pki.sha1),
        }))
        extensions.append(x509.Extension({
            "extn_id": "authority_key_identifier",
            "critical": False,
            "extn_value": x509.AuthorityKeyIdentifier({
                "key_identifier": core.OctetString(issuer_pki.sha1),
            }),
        }))

        tbs["extensions"] = extensions

        signature = issuer_key.sign(
            tbs.dump(), padding.PKCS1v15(), hashes.SHA256()
        )
        return x509.Certificate({
            "tbs_certificate": tbs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
            "signature_value": signature,
        })


def build_cert_tree():
    """
    Builds a small, fully deterministic certificate tree used for the offline
    impact assessment tests.

    Trust anchors:
      - Root R1 (slated for removal)
      - Root R2 (slated for removal)
      - Root R3 (retained)

    Intermediate CAs:
      - CA A, issued by R1 (path R1 -> A)
      - CA B, issued by R2 (path R2 -> B)
      - CA B is also cross-signed by R3, so B has a second path
        R3 -> B that survives the joint removal of R1 and R2.
      - CA C, issued by R2, with no replacement anchor.
      - CA D, cross-signed by both R1 and R2. Every single-root removal
        leaves one valid anchor, but removing R1 and R2 together leaves no
        anchor since R3 never issued D.

    End-entity certificates:
      - EE V: R1 -> A -> V, only chains to the removed R1
      - EE X: R2 -> B -> X, loses the R2 path but keeps R3 -> B -> X
      - EE C2: R2 -> C -> C2, only chains to the removed R2
      - EE E: R3 -> E3 -> E, expired at the validation moment
      - EE M: R1 -> A -> M, whose intermediate is deliberately withheld
      - EE O: R3 -> O3 -> O, unaffected by the removal
      - EE D: chains through CA D (R1/D or R2/D), only impacted when R1 and
        R2 are removed together
    """

    builder = CertTreeBuilder()
    material = {}

    r1_key = builder.generate_key()
    r2_key = builder.generate_key()
    r3_key = builder.generate_key()
    material["r1"] = builder.create_cert(
        "Historical Root R1", "Historical Root R1", r1_key, r1_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=3,
    )
    material["r2"] = builder.create_cert(
        "Historical Root R2", "Historical Root R2", r2_key, r2_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=3,
    )
    material["r3"] = builder.create_cert(
        "Retained Root R3", "Retained Root R3", r3_key, r3_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=3,
    )

    a_key = builder.generate_key()
    material["ca_a"] = builder.create_cert(
        "Intermediate CA A", "Historical Root R1", r1_key, a_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=2,
    )

    b_key = builder.generate_key()
    material["ca_b_by_r2"] = builder.create_cert(
        "Intermediate CA B", "Historical Root R2", r2_key, b_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=2,
    )
    # Same subject and key as ca_b_by_r2, but signed by the retained R3. The
    # authority key identifier points at R3's key so path building can select
    # it independently of the R2 variant.
    material["ca_b_by_r3"] = builder.create_cert(
        "Intermediate CA B", "Retained Root R3", r3_key, b_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=2,
    )

    c_key = builder.generate_key()
    material["ca_c"] = builder.create_cert(
        "Intermediate CA C", "Historical Root R2", r2_key, c_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=2,
    )

    e3_key = builder.generate_key()
    material["ca_e3"] = builder.create_cert(
        "Intermediate CA E3", "Retained Root R3", r3_key, e3_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=2,
    )

    o3_key = builder.generate_key()
    material["ca_o3"] = builder.create_cert(
        "Intermediate CA O3", "Retained Root R3", r3_key, o3_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=2,
    )

    d_key = builder.generate_key()
    material["ca_d_by_r1"] = builder.create_cert(
        "Intermediate CA D", "Historical Root R1", r1_key, d_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=2,
    )
    material["ca_d_by_r2"] = builder.create_cert(
        "Intermediate CA D", "Historical Root R2", r2_key, d_key,
        is_ca=True, key_usage=set(["key_cert_sign", "crl_sign"]),
        path_len_constraint=2,
    )

    ee_key_usage = set(["digital_signature", "key_encipherment"])

    v_key = builder.generate_key()
    material["ee_v"] = builder.create_cert(
        "vulnerable.example", "Intermediate CA A", a_key, v_key,
        is_ca=False, key_usage=ee_key_usage, eku=["server_auth"],
    )
    x_key = builder.generate_key()
    material["ee_x"] = builder.create_cert(
        "crosssigned.example", "Intermediate CA B", b_key, x_key,
        is_ca=False, key_usage=ee_key_usage, eku=["server_auth", "client_auth"],
    )
    c2_key = builder.generate_key()
    material["ee_c2"] = builder.create_cert(
        "doomed.example", "Intermediate CA C", c_key, c2_key,
        is_ca=False, key_usage=ee_key_usage, eku=["server_auth"],
    )
    e_key = builder.generate_key()
    material["ee_e"] = builder.create_cert(
        "expired.example", "Intermediate CA E3", e3_key, e_key,
        is_ca=False, key_usage=ee_key_usage, eku=["server_auth"],
        not_after=EXPIRED_AFTER,
    )
    m_key = builder.generate_key()
    material["ee_m"] = builder.create_cert(
        "missing-material.example", "Intermediate CA A", a_key, m_key,
        is_ca=False, key_usage=ee_key_usage, eku=["server_auth"],
    )
    o_key = builder.generate_key()
    material["ee_o"] = builder.create_cert(
        "unaffected.example", "Intermediate CA O3", o3_key, o_key,
        is_ca=False, key_usage=ee_key_usage, eku=["server_auth"],
    )
    d_leaf_key = builder.generate_key()
    material["ee_d"] = builder.create_cert(
        "cross-anchored.example", "Intermediate CA D", d_key, d_leaf_key,
        is_ca=False, key_usage=ee_key_usage, eku=["server_auth"],
    )

    material["all_intermediates"] = [
        material[name] for name in [
            "ca_a", "ca_b_by_r2", "ca_b_by_r3", "ca_c", "ca_d_by_r1",
            "ca_d_by_r2", "ca_e3", "ca_o3",
        ]
    ]
    return material
