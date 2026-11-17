"""
Offline verification of RFC 3161 timestamp tokens embedded in XAdES signatures.

This private module implements a minimal BER/DER parser and the checks required to validate a
CMS ``SignedData`` TimeStampToken (RFC 3161 section 2.4.2) without contacting a time stamping
authority: the token structure, the message imprint binding to the timestamped data, the CMS
signature, and the TSA certificate chain (including certificate validity at the timestamp
generation time and the time-stamping extended key usage). Certificates are parsed with the
minimal built-in parser because real-world TSA certificates frequently carry legacy encodings
that stricter parsers reject.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from ..exceptions import InvalidCertificate, InvalidDigest, InvalidInput, InvalidSignature

_ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"
_ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_ID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_ID_RSASSA_PSS = "1.2.840.113549.1.1.10"
_ID_MGF1 = "1.2.840.113549.1.1.8"
_ID_EXTENSION_EKU = "2.5.29.37"
_ID_EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"

_DIGEST_ALGORITHM_OIDS = {
    "1.3.14.3.2.26": hashes.SHA1,
    "2.16.840.1.101.3.4.2.4": hashes.SHA224,
    "2.16.840.1.101.3.4.2.1": hashes.SHA256,
    "2.16.840.1.101.3.4.2.2": hashes.SHA384,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512,
    "2.16.840.1.101.3.4.2.5": hashes.SHA512_224,
    "2.16.840.1.101.3.4.2.6": hashes.SHA512_256,
    "2.16.840.1.101.3.4.2.8": hashes.SHA3_256,
    "2.16.840.1.101.3.4.2.9": hashes.SHA3_384,
    "2.16.840.1.101.3.4.2.10": hashes.SHA3_512,
}

_SIGNATURE_ALGORITHM_OIDS = {
    "1.2.840.113549.1.1.5": hashes.SHA1,  # sha1WithRSAEncryption
    "1.2.840.113549.1.1.14": hashes.SHA224,  # sha224WithRSAEncryption
    "1.2.840.113549.1.1.11": hashes.SHA256,  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": hashes.SHA384,  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": hashes.SHA512,  # sha512WithRSAEncryption
    "1.2.840.10045.4.1": hashes.SHA1,  # ecdsa-with-SHA1
    "1.2.840.10045.4.3.1": hashes.SHA224,  # ecdsa-with-SHA224
    "1.2.840.10045.4.3.2": hashes.SHA256,  # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": hashes.SHA384,  # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4": hashes.SHA512,  # ecdsa-with-SHA512
    "1.2.840.10040.4.3": hashes.SHA1,  # dsa-with-sha1
    "2.16.840.1.101.3.4.3.1": hashes.SHA224,  # dsa-with-sha224
    "2.16.840.1.101.3.4.3.2": hashes.SHA256,  # dsa-with-sha256
}

_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_UTC_TIME = 0x17
_TAG_GENERALIZED_TIME = 0x18


@dataclass
class _ASN1Node:
    tag: int
    content: bytes
    raw: bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)


def _read_length(data: bytes, offset: int) -> tuple[int | None, int]:
    first = data[offset]
    offset += 1
    if first == 0x80:
        return None, offset
    if first & 0x80:
        num_bytes = first & 0x7F
        if num_bytes == 0 or num_bytes > 8:
            raise InvalidInput("Invalid ASN.1 length encoding in timestamp token")
        return int.from_bytes(data[offset : offset + num_bytes], "big"), offset + num_bytes
    return first, offset


def _read_tlv(data: bytes, offset: int = 0) -> tuple[_ASN1Node, int]:
    start = offset
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise InvalidInput("Multi-byte ASN.1 tags are not supported in timestamp tokens")
    length, offset = _read_length(data, offset)
    if length is None:
        if not tag & 0x20:
            raise InvalidInput("Indefinite length primitive in timestamp token")
        content = b""
        while True:
            if data[offset] == 0 and data[offset + 1] == 0:
                offset += 2
                break
            child, offset = _read_tlv(data, offset)
            if tag == 0x24:  # constructed OCTET STRING: content is the concatenation of chunk contents
                content += child.content
            else:
                content += child.raw
        return _ASN1Node(tag=tag, content=content, raw=data[start:offset]), offset
    content = data[offset : offset + length]
    offset += length
    return _ASN1Node(tag=tag, content=content, raw=data[start:offset]), offset


def _parse(data: bytes) -> _ASN1Node:
    node, offset = _read_tlv(data, 0)
    if offset != len(data):
        raise InvalidInput("Trailing data after timestamp token")
    return node


def _children(node: _ASN1Node) -> list[_ASN1Node]:
    children = []
    offset = 0
    while offset < len(node.content):
        child, offset = _read_tlv(node.content, offset)
        children.append(child)
    return children


def _encode_tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        length = bytes([len(content)])
    else:
        length_bytes = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(length_bytes)]) + length_bytes
    return bytes([tag]) + length + content


def _der_encode(node: _ASN1Node) -> bytes:
    content = node.content
    if node.constructed:
        encoded_children = [_der_encode(child) for child in _children(node)]
        if node.tag == _TAG_SET:
            encoded_children.sort()
        content = b"".join(encoded_children)
    return _encode_tlv(node.tag, content)


def _parse_oid(content: bytes) -> str:
    if not content:
        raise InvalidInput("Empty OID in timestamp token")
    components = [content[0] // 40, content[0] % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            components.append(value)
            value = 0
    return ".".join(str(component) for component in components)


def _expect_oid(node: _ASN1Node) -> str:
    if node.tag != _TAG_OID:
        raise InvalidInput("Expected OID in timestamp token")
    return _parse_oid(node.content)


def _get_digest_algorithm(algorithm_id: _ASN1Node) -> type[hashes.HashAlgorithm]:
    oid = _expect_oid(_children(algorithm_id)[0])
    if oid not in _DIGEST_ALGORITHM_OIDS:
        raise InvalidInput(f"Unsupported digest algorithm OID {oid} in timestamp token")
    return _DIGEST_ALGORITHM_OIDS[oid]


def _digest(algorithm: type[hashes.HashAlgorithm], data: bytes) -> bytes:
    hasher = hashes.Hash(algorithm())
    hasher.update(data)
    return hasher.finalize()


def _parse_generalized_time(text: str) -> datetime.datetime:
    match = re.fullmatch(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?(Z|[+-]\d{4})", text)
    if match is None:
        raise InvalidInput(f"Invalid generalized time in timestamp token: {text!r}")
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    microsecond = 0
    if match.group(7):
        microsecond = int(match.group(7).ljust(6, "0")[:6])
    tz_text = match.group(8)
    if tz_text == "Z":
        tzinfo: datetime.tzinfo = datetime.timezone.utc
    else:
        sign = 1 if tz_text[0] == "+" else -1
        tzinfo = datetime.timezone(sign * datetime.timedelta(hours=int(tz_text[1:3]), minutes=int(tz_text[3:5])))
    return datetime.datetime(year, month, day, hour, minute, second, microsecond, tzinfo=tzinfo)


def _parse_asn1_time(node: _ASN1Node) -> datetime.datetime:
    text = node.content.decode("ascii")
    if node.tag == _TAG_GENERALIZED_TIME:
        return _parse_generalized_time(text)
    if node.tag == _TAG_UTC_TIME:
        match = re.fullmatch(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z", text)
        if match is None:
            raise InvalidInput(f"Invalid UTC time in timestamp token: {text!r}")
        year = int(match.group(1))
        year += 1900 if year >= 50 else 2000
        return datetime.datetime(year, *(int(match.group(i)) for i in range(2, 7)), tzinfo=datetime.timezone.utc)
    raise InvalidInput("Expected time value in timestamp token")


@dataclass
class _Certificate:
    "A minimal parse of an X.509 certificate, carrying only what timestamp verification needs."

    issuer_der: bytes
    subject_der: bytes
    serial_number: int
    not_before: datetime.datetime
    not_after: datetime.datetime
    public_key: object
    ekus: set[str] | None
    signature_algorithm_oid: str
    signature: bytes
    tbs_der: bytes

    @classmethod
    def from_asn1(cls, certificate: _ASN1Node) -> "_Certificate":
        tbs, _, signature_node = _children(certificate)
        tbs_fields = _children(tbs)
        idx = 0
        if tbs_fields[idx].tag == 0xA0:  # version
            idx += 1
        serial_number = int.from_bytes(tbs_fields[idx].content, "big")
        issuer_node = tbs_fields[idx + 2]
        validity = _children(tbs_fields[idx + 3])
        subject_node = tbs_fields[idx + 4]
        spki_node = tbs_fields[idx + 5]
        ekus = None
        for extension_field in tbs_fields[idx + 6 :]:
            if extension_field.tag != 0xA3:  # extensions
                continue
            for extension in _children(_children(extension_field)[0]):
                extension_fields = _children(extension)
                if _expect_oid(extension_fields[0]) != _ID_EXTENSION_EKU:
                    continue
                eku_value = extension_fields[-1]
                if eku_value.tag == _TAG_OCTET_STRING:
                    ekus = {_expect_oid(node) for node in _children(_parse(eku_value.content))}
        signature_algorithm_oid = _expect_oid(_children(tbs_fields[idx + 1])[0])
        if signature_node.tag != _TAG_BIT_STRING or signature_node.content[:1] != b"\x00":
            raise InvalidInput("Invalid signature bit string in timestamp token certificate")
        return cls(
            issuer_der=_der_encode(issuer_node),
            subject_der=_der_encode(subject_node),
            serial_number=serial_number,
            not_before=_parse_asn1_time(validity[0]),
            not_after=_parse_asn1_time(validity[1]),
            public_key=load_der_public_key(_der_encode(spki_node)),
            ekus=ekus,
            signature_algorithm_oid=signature_algorithm_oid,
            signature=signature_node.content[1:],
            tbs_der=_der_encode(tbs),
        )


def _verify_signature(
    public_key, signature_algorithm_oid: str, hash_algorithm: type[hashes.HashAlgorithm], signature: bytes, data: bytes
):
    if isinstance(public_key, rsa.RSAPublicKey):
        if signature_algorithm_oid == _ID_RSASSA_PSS:
            raise InvalidInput("RSASSA-PSS parameters are not supported in this timestamp token structure")
        public_key.verify(signature, data, asym_padding.PKCS1v15(), hash_algorithm())
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_algorithm()))
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(signature, data, hash_algorithm())
    else:
        raise InvalidInput("Unsupported public key type in timestamp token")


def _parse_pss_params(algorithm_id: _ASN1Node) -> tuple[type[hashes.HashAlgorithm], asym_padding.PSS]:
    hash_algorithm: type[hashes.HashAlgorithm] = hashes.SHA1
    mgf_hash_algorithm: type[hashes.HashAlgorithm] = hashes.SHA1
    salt_length = 20
    fields = _children(algorithm_id)
    if len(fields) > 1 and fields[1].tag == _TAG_SEQUENCE:
        for param in _children(fields[1]):
            if param.tag == 0xA0:
                hash_algorithm = _get_digest_algorithm(_children(param)[0])
            elif param.tag == 0xA1:
                mgf_fields = _children(_children(param)[0])
                if _expect_oid(mgf_fields[0]) != _ID_MGF1:
                    raise InvalidInput("Unsupported mask generation function in timestamp token")
                mgf_hash_algorithm = _get_digest_algorithm(mgf_fields[1])
            elif param.tag == 0xA2:
                salt_length = int.from_bytes(_children(param)[0].content, "big")
    return hash_algorithm, asym_padding.PSS(mgf=asym_padding.MGF1(mgf_hash_algorithm()), salt_length=salt_length)


def _find_signer_cert(sid: _ASN1Node, certs: list[_Certificate]) -> _Certificate:
    if sid.tag == _TAG_SEQUENCE:
        issuer_and_serial = _children(sid)
        issuer_der = _der_encode(issuer_and_serial[0])
        serial = int.from_bytes(issuer_and_serial[1].content, "big")
        for cert in certs:
            if cert.serial_number == serial and cert.issuer_der == issuer_der:
                return cert
    raise InvalidInput("Timestamp token signer certificate not found in token")


def _verify_cms_signature(
    signer_info: _ASN1Node,
    tst_info: bytes,
    certs: list[_Certificate],
    digest_algorithm: type[hashes.HashAlgorithm],
) -> _Certificate:
    fields = _children(signer_info)
    sid = fields[1]
    signed_attrs_node = None
    idx = 3  # fields[2] is the digestAlgorithm
    if fields[idx].tag == 0xA0:
        signed_attrs_node = fields[idx]
        idx += 1
    signature_algorithm_id = fields[idx]
    signature_node = fields[idx + 1]
    if signature_node.tag != _TAG_OCTET_STRING:
        raise InvalidInput("Missing signature in timestamp token signer info")

    signer_cert = _find_signer_cert(sid, certs)

    if signed_attrs_node is not None:
        signed_attrs = _children(signed_attrs_node)
        content_type = None
        message_digest = None
        for attr in signed_attrs:
            attr_fields = _children(attr)
            attr_oid = _expect_oid(attr_fields[0])
            attr_values = _children(attr_fields[1])
            if not attr_values:
                continue
            if attr_oid == _ID_CONTENT_TYPE:
                content_type = _expect_oid(attr_values[0])
            elif attr_oid == _ID_MESSAGE_DIGEST:
                message_digest = attr_values[0].content
        if content_type != _ID_CT_TST_INFO:
            raise InvalidInput("Timestamp token signed attributes do not declare a TSTInfo content type")
        if message_digest is None:
            raise InvalidInput("Timestamp token signed attributes are missing the message digest")
        if message_digest != _digest(digest_algorithm, tst_info):
            raise InvalidDigest("Timestamp token message digest attribute does not match the TSTInfo")
        signed_data = _encode_tlv(_TAG_SET, b"".join(sorted(_der_encode(attr) for attr in signed_attrs)))
    else:
        signed_data = tst_info

    signature_algorithm_oid = _expect_oid(_children(signature_algorithm_id)[0])
    public_key = signer_cert.public_key
    try:
        if signature_algorithm_oid == _ID_RSASSA_PSS:
            hash_algorithm, pss_padding = _parse_pss_params(signature_algorithm_id)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise InvalidInput("RSASSA-PSS signature with a non-RSA key in timestamp token")
            public_key.verify(signature_node.content, signed_data, pss_padding, hash_algorithm())
        else:
            _verify_signature(
                public_key, signature_algorithm_oid, digest_algorithm, signature_node.content, signed_data
            )
    except _CryptoInvalidSignature:
        raise InvalidSignature("Timestamp token signature is invalid")
    return signer_cert


def _verify_cert_issued_by(cert: _Certificate, issuer: _Certificate):
    hash_algorithm = _SIGNATURE_ALGORITHM_OIDS.get(cert.signature_algorithm_oid)
    if hash_algorithm is None:
        if cert.signature_algorithm_oid == _ID_RSASSA_PSS:
            raise InvalidCertificate("RSASSA-PSS is not supported in timestamp token certificate chains")
        raise InvalidCertificate(
            f"Unsupported signature algorithm OID {cert.signature_algorithm_oid} in timestamp token certificate chain"
        )
    _verify_signature(issuer.public_key, cert.signature_algorithm_oid, hash_algorithm, cert.signature, cert.tbs_der)


def _verify_tsa_chain(signer_cert: _Certificate, certs: list[_Certificate], gen_time: datetime.datetime):
    if signer_cert.ekus is None:
        raise InvalidCertificate("Timestamp token signer certificate is missing an extended key usage extension")
    if _ID_EKU_TIME_STAMPING not in signer_cert.ekus:
        raise InvalidCertificate("Timestamp token signer certificate does not allow time stamping")

    chain = [signer_cert]
    remaining = [cert for cert in certs if cert is not signer_cert]
    while remaining:
        issuer = next((cert for cert in remaining if cert.subject_der == chain[-1].issuer_der), None)
        if issuer is None:
            break
        try:
            _verify_cert_issued_by(chain[-1], issuer)
        except _CryptoInvalidSignature:
            raise InvalidCertificate("Timestamp token certificate chain signature is invalid")
        chain.append(issuer)
        remaining.remove(issuer)
        if issuer.subject_der == issuer.issuer_der:
            break

    for cert in chain:
        if gen_time < cert.not_before or gen_time > cert.not_after:
            raise InvalidCertificate(
                f"Timestamp token certificate was not valid at the timestamp generation time {gen_time.isoformat()}"
            )


def verify_timestamp_token(token: bytes, timestamped_data: bytes) -> datetime.datetime:
    """
    Verify an RFC 3161 TimeStampToken (a CMS SignedData structure) offline and return the time at which the
    timestamp was generated. The message imprint in the token must bind the token to ``timestamped_data`` (for
    XAdES SignatureTimeStamp elements, the canonicalized ds:SignatureValue element), the CMS signature must
    verify against the included TSA certificate, and the TSA certificate chain included in the token must be
    valid at the timestamp generation time.

    :param token: DER (or BER) encoded TimeStampToken
    :param timestamped_data: Data that the timestamp is expected to cover
    :return: The genTime field of the verified TSTInfo
    """
    try:
        content_info = _parse(token)
        content_info_fields = _children(content_info)
        if _expect_oid(content_info_fields[0]) != _ID_SIGNED_DATA:
            raise InvalidInput("Timestamp token is not a CMS SignedData structure")
        signed_data = _children(content_info_fields[1])[0]
        signed_data_fields = _children(signed_data)

        encap_content_info = _children(signed_data_fields[2])
        if _expect_oid(encap_content_info[0]) != _ID_CT_TST_INFO:
            raise InvalidInput("Timestamp token does not encapsulate a TSTInfo")
        econtent = _children(encap_content_info[1])[0]
        if econtent.tag != _TAG_OCTET_STRING:
            raise InvalidInput("Timestamp token eContent is not an OCTET STRING")
        tst_info = econtent.content

        certs = []
        signer_infos = None
        for signed_data_field in signed_data_fields[3:]:
            if signed_data_field.tag == 0xA0:
                for cert_node in _children(signed_data_field):
                    if cert_node.tag == _TAG_SEQUENCE:
                        certs.append(_Certificate.from_asn1(cert_node))
            elif signed_data_field.tag == _TAG_SET:
                signer_infos = _children(signed_data_field)
        if not signer_infos:
            raise InvalidInput("Timestamp token carries no signer information")

        tst_info_fields = _children(_parse(tst_info))
        message_imprint = _children(tst_info_fields[2])
        imprint_algorithm = _get_digest_algorithm(message_imprint[0])
        imprint = message_imprint[1].content
        if imprint != _digest(imprint_algorithm, timestamped_data):
            raise InvalidDigest("Timestamp token message imprint does not cover the expected data")
        gen_time = _parse_generalized_time(tst_info_fields[4].content.decode("ascii")).astimezone(datetime.timezone.utc)

        digest_algorithm = _get_digest_algorithm(_children(signer_infos[0])[2])
        signer_cert = _verify_cms_signature(signer_infos[0], tst_info, certs, digest_algorithm)
        _verify_tsa_chain(signer_cert, certs, gen_time)
        return gen_time
    except (IndexError, ValueError, UnicodeDecodeError) as e:
        if isinstance(e, (InvalidInput, InvalidDigest, InvalidSignature, InvalidCertificate)):
            raise
        raise InvalidInput(f"Unable to parse timestamp token: {e}")
