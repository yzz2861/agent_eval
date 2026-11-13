#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""ASN.1 definitions.

Not all ASN.1-handling code use these definitions, but when it does, they should be here.
"""

import typing

from pyasn1.type import univ, namedtype, tag

# Universal DER tag numbers used by the hand-written strict parser.
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OBJECT_IDENTIFIER = 0x06
TAG_SEQUENCE = 0x30


class Asn1Error(ValueError):
    """Raised when a DER blob cannot be parsed as the expected ASN.1 structure.

    This is an internal, audit-only error. Public verification entry points
    translate it into their own generic failure message so no structural
    details are exposed to callers.
    """


def _read_length(data: bytes, offset: int) -> typing.Tuple[int, int]:
    """Reads a DER length, returning (length, next_offset).

    Only the minimal (shortest) DER length encoding is accepted.
    """

    if offset >= len(data):
        raise Asn1Error("truncated DER length")

    first = data[offset]
    if first < 0x80:
        return first, offset + 1

    num_bytes = first & 0x7F
    if num_bytes == 0:
        # Indefinite length is not valid in DER.
        raise Asn1Error("indefinite DER length is not allowed")
    if num_bytes > 4:
        raise Asn1Error("DER length is too large")

    length_offset = offset + 1
    end_offset = length_offset + num_bytes
    if end_offset > len(data):
        raise Asn1Error("truncated DER length")

    # Reject non-minimal encodings, including leading zeroes.
    if data[length_offset] == 0:
        raise Asn1Error("non-minimal DER length encoding")

    length = 0
    for index in range(length_offset, end_offset):
        length = (length << 8) | data[index]

    # Lengths below 128 must use the short form.
    if length < 0x80:
        raise Asn1Error("non-minimal DER length encoding")

    return length, end_offset


def read_tlv(data: bytes, offset: int, expected_tag: int) -> typing.Tuple[bytes, int]:
    """Reads one DER TLV at ``offset`` with the expected universal tag.

    Returns (value_bytes, offset_just_past_the_tlv). The encoded length must be
    minimal and the TLV must be fully contained in ``data``.
    """

    if offset >= len(data):
        raise Asn1Error("truncated DER object")
    if data[offset] != expected_tag:
        raise Asn1Error("unexpected DER tag 0x%02x" % data[offset])

    length, content_offset = _read_length(data, offset + 1)
    end_offset = content_offset + length
    if end_offset > len(data):
        raise Asn1Error("DER object exceeds its container")

    return data[content_offset:end_offset], end_offset


def decode_oid(oid_content: bytes) -> str:
    """Decodes the content bytes of an OBJECT IDENTIFIER TLV into dotted form."""

    if not oid_content:
        raise Asn1Error("empty OBJECT IDENTIFIER")

    arcs = [oid_content[0] // 40, oid_content[0] % 40]
    value = 0
    first_group = True
    for byte in oid_content[1:]:
        if first_group and byte == 0x80:
            # A leading all-zero base-128 group is never part of the minimal
            # encoding of an arc.
            raise Asn1Error("non-minimal OBJECT IDENTIFIER encoding")
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            first_group = True
        else:
            first_group = False

    # A dangling continuation bit means the encoding was truncated.
    if not first_group:
        raise Asn1Error("truncated OBJECT IDENTIFIER")

    return ".".join(str(arc) for arc in arcs)


def parse_digest_info(encoded: bytes) -> typing.Tuple[str, bytes]:
    """Parses a PKCS#1 v1.5 DigestInfo and returns (oid, digest).

    DigestInfo ::= SEQUENCE {
        digestAlgorithm AlgorithmIdentifier,
        digest OCTET STRING
    }

    AlgorithmIdentifier ::= SEQUENCE {
        algorithm OBJECT IDENTIFIER,
        parameters ANY DEFINED BY algorithm OPTIONAL
    }

    For the hash algorithms used with EMSA-PKCS1-v1_5 the parameters field
    must be present and encode ASN.1 NULL. The whole SEQUENCE must consume
    every byte of ``encoded``; trailing data is rejected.
    """

    outer, outer_end = read_tlv(encoded, 0, TAG_SEQUENCE)
    if outer_end != len(encoded):
        raise Asn1Error("trailing data after DigestInfo")

    algorithm, algorithm_end = read_tlv(outer, 0, TAG_SEQUENCE)

    oid_content, oid_end = read_tlv(algorithm, 0, TAG_OBJECT_IDENTIFIER)
    # The hash OIDs used in PKCS#1 v1.5 carry an explicit NULL parameter.
    null_params, params_end = read_tlv(algorithm, oid_end, TAG_NULL)
    if null_params:
        raise Asn1Error("NULL parameters must have an empty value")
    if params_end != len(algorithm):
        raise Asn1Error("trailing data after AlgorithmIdentifier")

    digest, digest_end = read_tlv(outer, algorithm_end, TAG_OCTET_STRING)
    if digest_end != len(outer):
        raise Asn1Error("trailing data after digest OCTET STRING")
    if not digest:
        raise Asn1Error("empty digest OCTET STRING")

    return decode_oid(oid_content), digest


class PubKeyHeader(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("oid", univ.ObjectIdentifier()),
        namedtype.NamedType("parameters", univ.Null()),
    )


class OpenSSLPubKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("header", PubKeyHeader()),
        # This little hack (the implicit tag) allows us to get a Bit String as Octet String
        namedtype.NamedType(
            "key",
            univ.OctetString().subtype(implicitTag=tag.Tag(tagClass=0, tagFormat=0, tagId=3)),
        ),
    )


class AsnPubKey(univ.Sequence):
    """ASN.1 contents of DER encoded public key:

    RSAPublicKey ::= SEQUENCE {
         modulus           INTEGER,  -- n
         publicExponent    INTEGER,  -- e
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("publicExponent", univ.Integer()),
    )
