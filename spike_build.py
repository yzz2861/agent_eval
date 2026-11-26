from datetime import datetime, timezone
import hashlib

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from asn1crypto import algos, cms, core, tsp, x509

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Archive TSA")])
cert = cx509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(12345).not_valid_before(datetime(2020,1,1,tzinfo=timezone.utc)).not_valid_after(datetime(2030,1,1,tzinfo=timezone.utc)).sign(key, hashes.SHA256())
cert_der = cert.public_bytes(serialization.Encoding.DER)
asn1cert = x509.Certificate.load(cert_der)
print("cert loaded", asn1cert.subject.native)

tst_info = tsp.TSTInfo({
    "version": "v1",
    "policy": "1.2.3.4.5",
    "message_imprint": tsp.MessageImprint({
        "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "hashed_message": hashlib.sha256(b"record").digest(),
    }),
    "serial_number": 1,
    "gen_time": datetime(2021,3,1,9,0,0,tzinfo=timezone.utc),
})
tst_der = tst_info.dump()
print("tst", len(tst_der), tst_der[:8].hex())
md = hashlib.sha256(tst_der).digest()
attrs = cms.CMSAttributes([
    cms.CMSAttribute({"type": "content_type", "values": ["1.2.840.113549.1.9.16.1.4"]}),
    cms.CMSAttribute({"type": "message_digest", "values": [md]}),
])
attrs_der = attrs.dump()
print("attrs first", attrs_der[0], len(attrs_der))
set_der = b"\x31" + attrs_der[1:]
sig = key.sign(set_der, padding.PKCS1v15(), hashes.SHA256())
sid = cms.SignerIdentifier({
    "issuer_and_serial_number": cms.IssuerAndSerialNumber({
        "issuer": asn1cert.issuer,
        "serial_number": asn1cert.serial_number,
    })
})
si = cms.SignerInfo({
    "version": "v1",
    "sid": sid,
    "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
    "signed_attrs": attrs,
    "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
    "signature": sig,
})
eci = cms.EncapsulatedContentInfo({
    "content_type": "tst_info",
    "content": tsp.TSTInfo.load(tst_der),
})
sd = cms.SignedData({
    "version": "v3",
    "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
    "encap_content_info": eci,
    "certificates": [asn1cert],
    "signer_infos": [si],
})
ci = cms.ContentInfo({"content_type": "signed_data", "content": sd})
token_der = ci.dump()
resp = tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": ci})
resp_der = resp.dump()
print("token", len(token_der), "resp", len(resp_der))
parsed = tsp.TimeStampResp.load(resp_der)
print("parsed status", parsed["status"]["status"].native)
print("parsed tst imprint", parsed["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed["message_imprint"]["hashed_message"].native.hex()[:16])
