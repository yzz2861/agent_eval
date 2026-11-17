"""In-memory X.509 test fixtures for the X5Chain validation tests."""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pycose.keys.cosekey import CoseKey


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _der(certificate):
    return certificate.public_bytes(serialization.Encoding.DER)


def build_ca(common_name, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def build_leaf(ca_key, ca_cert, key, common_name, days_from=-1, days_to=365,
               digital_signature=True, key_encipherment=False):
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=days_from))
        .not_valid_after(now + timedelta(days=days_to))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=key_encipherment,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return certificate


def cose_public_key(private_key):
    pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return CoseKey.from_pem_public_key(pem.decode())


class CertificateFixture:
    def __init__(self):
        self.root_key, self.root = build_ca("Test Root CA")
        self.intermediate_key, self.intermediate = build_ca("Test Intermediate CA")
        self.intermediate = self._reissue_intermediate()

        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf = build_leaf(self.intermediate_key, self.intermediate,
                               self.leaf_key, "Test Leaf")

        self.expired_leaf = build_leaf(self.intermediate_key, self.intermediate,
                                       self.leaf_key, "Expired Leaf",
                                       days_from=-30, days_to=-10)

        self.other_key, self.other_root = build_ca("Other Root CA")
        self.wrong_key = ec.generate_private_key(ec.SECP256R1())
        self.wrong_leaf = build_leaf(self.other_key, self.other_root,
                                     self.wrong_key, "Wrong Leaf")

    def _reissue_intermediate(self):
        now = datetime.now(timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(_name("Test Intermediate CA"))
            .issuer_name(self.root.subject)
            .public_key(self.intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.root_key, hashes.SHA256())
        )

    @property
    def chain_der(self):
        return [_der(self.leaf), _der(self.intermediate)]

    @property
    def root_der(self):
        return _der(self.root)

    @property
    def other_root_der(self):
        return _der(self.other_root)

    @property
    def expired_chain_der(self):
        return [_der(self.expired_leaf), _der(self.intermediate)]

    @property
    def wrong_chain_der(self):
        return [_der(self.wrong_leaf)]

