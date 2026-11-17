from binascii import unhexlify
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography import x509 as crypto_x509
from cryptography.x509.oid import NameOID

from pycose import algorithms
from pycose.algorithms import Sha256Trunc64
from pycose.exceptions import CoseIllegalKeyOps, CoseInvalidCertificate
from pycose.extensions.x509 import X5Chain, X5T
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import DeriveKeyOp, SignOp, VerifyOp

from tests.x509_test_certs import CertificateFixture, build_ca, cose_public_key


def _self_signed_certificate(private_key, common_name="Self Signed"):
    now = datetime.now(timezone.utc)
    subject = crypto_x509.Name(
        [crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    hash_algorithm = None if isinstance(private_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    certificate = (
        crypto_x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            crypto_x509.KeyUsage(
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
        .sign(private_key, hash_algorithm)
    )
    return certificate.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="module")
def fixture():
    return CertificateFixture()


def test_valid_chain_matching_key(fixture):
    cose_key = cose_public_key(fixture.leaf_key)
    cose_key.key_ops = [VerifyOp]
    chain = X5Chain(fixture.chain_der)

    assert chain.public_key_matches(cose_key)

    chain.validate(cose_key=cose_key, trust_roots=[fixture.root_der],
                   key_ops=[VerifyOp])


def test_constructor_verify_validates_chain(fixture):
    cose_key = cose_public_key(fixture.leaf_key)
    cose_key.key_ops = [VerifyOp]
    chain = X5Chain(
        fixture.chain_der,
        verify=True,
        cose_key=cose_key,
        trust_roots=[fixture.root_der],
        key_ops=[VerifyOp],
    )
    assert chain.encode() == fixture.chain_der


def test_single_self_issued_certificate_as_trust_root(fixture):
    cose_key = cose_public_key(fixture.root_key)
    chain = X5Chain([fixture.root_der])

    chain.validate(cose_key=cose_key, trust_roots=[fixture.root_der])


def test_leaf_public_key_mismatch(fixture):
    mismatched_key = cose_public_key(fixture.wrong_key)
    chain = X5Chain(fixture.chain_der)

    assert not chain.public_key_matches(mismatched_key)

    with pytest.raises(CoseInvalidCertificate, match="does not match the CoseKey"):
        chain.validate(cose_key=mismatched_key, trust_roots=[fixture.root_der])


def test_chain_with_wrong_leaf_is_rejected(fixture):
    cose_key = cose_public_key(fixture.wrong_key)
    chain = X5Chain(fixture.wrong_chain_der)

    with pytest.raises(CoseInvalidCertificate, match="trusted certificate"):
        chain.validate(cose_key=cose_key, trust_roots=[fixture.root_der])


def test_chain_signature_failure_with_foreign_intermediate(fixture):
    _, foreign_ca = build_ca("Foreign Intermediate CA")
    foreign_intermediate_der = foreign_ca.public_bytes(serialization.Encoding.DER)
    cose_key = cose_public_key(fixture.leaf_key)
    cose_key.key_ops = [VerifyOp]

    chain = X5Chain([fixture.chain_der[0], foreign_intermediate_der])

    with pytest.raises(CoseInvalidCertificate, match="not issued by"):
        chain.validate(cose_key=cose_key, trust_roots=[fixture.root_der])


def test_chain_invalid_signature_with_spoofed_issuer_name(fixture):
    # A self-signed CA with the same subject name but a different key cannot
    # vouch for the leaf, even though the issuer/subject names line up.
    _, spoofed_ca = build_ca("Test Intermediate CA")
    spoofed_der = spoofed_ca.public_bytes(serialization.Encoding.DER)
    cose_key = cose_public_key(fixture.leaf_key)
    cose_key.key_ops = [VerifyOp]

    chain = X5Chain([fixture.chain_der[0], spoofed_der])

    with pytest.raises(CoseInvalidCertificate, match="invalid signature"):
        chain.validate(cose_key=cose_key, trust_roots=[fixture.root_der])


def test_untrusted_chain(fixture):
    cose_key = cose_public_key(fixture.leaf_key)
    chain = X5Chain(fixture.chain_der)

    with pytest.raises(CoseInvalidCertificate, match="trusted certificate"):
        chain.validate(cose_key=cose_key, trust_roots=[fixture.other_root_der])

    with pytest.raises(CoseInvalidCertificate, match="trusted certificate"):
        chain.validate(cose_key=cose_key)


def test_expired_certificate_rejected(fixture):
    cose_key = cose_public_key(fixture.leaf_key)
    chain = X5Chain(fixture.expired_chain_der)

    with pytest.raises(CoseInvalidCertificate, match="expired"):
        chain.validate(cose_key=cose_key, trust_roots=[fixture.root_der])


def test_not_yet_valid_certificate_rejected(fixture):
    cose_key = cose_public_key(fixture.leaf_key)
    cose_key.key_ops = [VerifyOp]
    chain = X5Chain(fixture.chain_der)
    moment = datetime.now(timezone.utc) - timedelta(days=4000)

    with pytest.raises(CoseInvalidCertificate, match="not yet valid"):
        chain.validate(cose_key=cose_key, trust_roots=[fixture.root_der], moment=moment)


def test_key_op_not_allowed_by_cose_key(fixture):
    cose_key = cose_public_key(fixture.leaf_key)
    cose_key.key_ops = [VerifyOp]
    chain = X5Chain(fixture.chain_der)

    with pytest.raises(CoseIllegalKeyOps):
        chain.validate(cose_key=cose_key, trust_roots=[fixture.root_der],
                       key_ops=[SignOp])


def test_key_op_not_allowed_by_certificate(fixture):
    cose_key = cose_public_key(fixture.leaf_key)
    cose_key.key_ops = [DeriveKeyOp]
    chain = X5Chain(fixture.chain_der)

    with pytest.raises(CoseInvalidCertificate, match="key usage"):
        chain.validate(cose_key=cose_key, trust_roots=[fixture.root_der],
                       key_ops=[DeriveKeyOp])


def test_validate_without_cose_key_raises(fixture):
    chain = X5Chain(fixture.chain_der)
    with pytest.raises(CoseInvalidCertificate, match="CoseKey is required"):
        chain.validate(trust_roots=[fixture.root_der])


def test_malformed_certificate_rejected():
    chain = X5Chain([b"not a certificate"])
    with pytest.raises(CoseInvalidCertificate, match="parse X.509"):
        chain.leaf_certificate()


def test_empty_chain_rejected(fixture):
    cose_key = cose_public_key(fixture.leaf_key)
    with pytest.raises(CoseInvalidCertificate, match="empty"):
        X5Chain([]).validate(cose_key=cose_key, trust_roots=[fixture.root_der])


@pytest.mark.parametrize(
    "private_key",
    [
        ed25519.Ed25519PrivateKey.generate(),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    ],
    ids=["ed25519", "rsa"],
)
def test_okp_and_rsa_leaf_binding(private_key):
    encoded_cert = _self_signed_certificate(private_key)
    pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cose_key = CoseKey.from_pem_public_key(pem.decode())
    chain = X5Chain([encoded_cert])

    assert chain.public_key_matches(cose_key)
    chain.validate(cose_key=cose_key, trust_roots=[encoded_cert])


def test_x5t_thumbprint_unchanged():
    data = b'5864c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b05' \
           b'34b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb2'

    tprint = unhexlify(b'6844078a53f312f5')

    head = X5T.from_certificate(Sha256Trunc64, unhexlify(data), True)
    assert head.alg == algorithms.Sha256Trunc64
    assert head.thumbprint is not None
    assert head.encode() == [algorithms.Sha256Trunc64, tprint]
    assert head.matches(unhexlify(data), True)

    head2 = X5T.decode([-15, tprint])
    assert head2 == head
