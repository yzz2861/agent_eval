#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import univ
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.error import PyAsn1Error


class BitStringDecoderTestCase(BaseTestCase):
    def testShortMode(self):
        assert decoder.decode(
            bytes((3, 127, 6) + (170,) * 125 + (128,))
        ) == (((1, 0) * 501), b'')

    def testIndefMode(self):
        try:
            decoder.decode(
                bytes((35, 128, 3, 2, 0, 169, 3, 2, 1, 138, 0, 0))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'indefinite length encoding tolerated'

    def testDefModeChunked(self):
        try:
            assert decoder.decode(
                bytes((35, 8, 3, 2, 0, 169, 3, 2, 1, 138))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'chunked encoding tolerated'

    def testSchemaDrivenChunkedWithIntermediatePadding(self):
        fragments = b'\x03\x02\x03\x10\x03\x02\x00\xa5'
        try:
            decoder.decode(b'\x23\x08' + fragments,
                           asn1Spec=univ.BitString())
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed BIT STRING tolerated under DER'


class OctetStringDecoderTestCase(BaseTestCase):
    def testShortMode(self):
        assert decoder.decode(
            '\004\017Quick brown fox'.encode()
        ) == ('Quick brown fox'.encode(), ''.encode())

    def testIndefMode(self):
        try:
            decoder.decode(
                bytes((36, 128, 4, 15, 81, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 32, 102, 111, 120, 0, 0))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'indefinite length encoding tolerated'

    def testChunkedMode(self):
        try:
            decoder.decode(
                bytes((36, 23, 4, 2, 81, 117, 4, 2, 105, 99, 4, 2, 107, 32, 4, 2, 98, 114, 4, 2, 111, 119, 4, 1, 110))
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, 'chunked encoding tolerated'

    def testSchemaDrivenManyFragments(self):
        fragments = b'\x04\x01A' * 64
        try:
            decoder.decode(b'\x24\x81\xc0' + fragments,
                           asn1Spec=univ.OctetString())
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed OCTET STRING tolerated under DER'

    def testConstructedCharacterString(self):
        fragments = b'\x0c\x01A' * 64
        try:
            decoder.decode(b'\x2c\x81\xc0' + fragments)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed UTF8String tolerated under DER'


class DerTlvHeaderEnforcementTestCase(BaseTestCase):
    def testConstructedOctetStringRejected(self):
        # constructed OCTET STRING, two one-octet fragments
        substrate = b'\x24\x06\x04\x01a\x04\x01b'

        for asn1Spec in None, univ.OctetString():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec)
            except PyAsn1Error as exc:
                assert 'X.690 10.2' in str(exc), \
                    'DER rule missing from error: %s' % exc
                assert 'offset 0' in str(exc), \
                    'offset missing from error: %s' % exc
            else:
                assert 0, 'constructed OCTET STRING tolerated under DER'

    def testConstructedBitStringRejected(self):
        # constructed BIT STRING, two fragments
        substrate = bytes((35, 8, 3, 2, 0, 169, 3, 2, 1, 138))

        for asn1Spec in None, univ.BitString():
            try:
                decoder.decode(substrate, asn1Spec=asn1Spec)
            except PyAsn1Error as exc:
                assert 'X.690 10.2' in str(exc)
            else:
                assert 0, 'constructed BIT STRING tolerated under DER'

    def testConstructedCharacterStringsRejected(self):
        # constructed UTF8String, PrintableString, IA5String, UniversalString
        for constructedTag in 0x2c, 0x33, 0x36, 0x3c:
            # definite-length constructed form holding one primitive fragment
            substrate = bytes((constructedTag, 3, constructedTag & 0x1f, 1, 65))

            try:
                decoder.decode(substrate)
            except PyAsn1Error as exc:
                assert 'X.690 10.2' in str(exc)
            else:
                assert 0, 'constructed character string tolerated under DER'

    def testIndefiniteLengthRejected(self):
        # indefinite-length OCTET STRING
        substrate = bytes((4, 128, 1, 65, 0, 0))

        try:
            decoder.decode(substrate)
        except PyAsn1Error as exc:
            assert 'X.690 10.1' in str(exc), \
                'DER rule missing from error: %s' % exc
            assert 'offset 0' in str(exc), \
                'offset missing from error: %s' % exc
        else:
            assert 0, 'indefinite length tolerated under DER'

    def testLongFormLengthForShortValueRejected(self):
        # long-form length encoding a value below 128
        substrate = b'\x04\x81\x03abc'

        try:
            decoder.decode(substrate)
        except PyAsn1Error as exc:
            assert 'X.690 10.1' in str(exc)
            assert 'offset 0' in str(exc)
        else:
            assert 0, 'non-minimal length tolerated under DER'

    def testPaddedLongFormLengthRejected(self):
        # long-form length with a leading zero octet
        substrate = b'\x04\x82\x00\x80' + b'x' * 128

        try:
            decoder.decode(substrate)
        except PyAsn1Error as exc:
            assert 'X.690 10.1' in str(exc)
        else:
            assert 0, 'padded length tolerated under DER'

    def testMinimalLongFormLengthAccepted(self):
        # long-form length is required at 128 octets and beyond
        substrate = b'\x04\x81\x80' + b'x' * 128

        value, rest = decoder.decode(substrate)

        assert value.asOctets() == b'x' * 128
        assert rest == b''

    def testErrorBeforeValueConstruction(self):
        # the stream must be left right past the TLV header, before any
        # value octets are consumed
        substrate = io.BytesIO(b'\x24\x06\x04\x01a\x04\x01b')

        try:
            list(decoder.StreamingDecoder(substrate))
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed OCTET STRING tolerated under DER'

        assert substrate.tell() == 2, \
            'value octets consumed before the error: %d' % substrate.tell()

    def testNestedConstructedStringRejected(self):
        # constructed OCTET STRING nested in a SEQUENCE
        substrate = b'\x30\x08\x24\x06\x04\x01a\x04\x01b'

        try:
            decoder.decode(substrate)
        except PyAsn1Error as exc:
            assert 'offset 2' in str(exc), \
                'inner TLV offset missing from error: %s' % exc
        else:
            assert 0, 'nested constructed OCTET STRING tolerated under DER'

    def testErrorMessageHidesContent(self):
        substrate = b'\x24\x06\x04\x01a\x04\x01b'

        try:
            decoder.decode(substrate)
        except PyAsn1Error as exc:
            assert 'ab' not in str(exc), \
                'sensitive content echoed in error: %s' % exc
        else:
            assert 0, 'constructed OCTET STRING tolerated under DER'

    def testPrimitiveStringsRoundTrip(self):
        for asn1Value in (univ.OctetString(b'fox'),
                          char.UTF8String('renard'),
                          char.PrintableString('fox'),
                          char.IA5String('fox')):
            substrate = encoder.encode(asn1Value)

            value, rest = decoder.decode(substrate, asn1Spec=asn1Value.clone())

            assert value == asn1Value
            assert rest == b''


class LargeTagDecoderTestCase(BaseTestCase):
    def testExcessiveLongTag(self):
        # 1 << 140 is the smallest tag ID needing 21 octets, one over the limit
        excessiveTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1 << 140)
        asn1Spec = univ.Integer().subtype(implicitTag=excessiveTag)
        substrate = encoder.encode(univ.Integer(1).subtype(implicitTag=excessiveTag))

        try:
            decoder.decode(substrate, asn1Spec=asn1Spec)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'excessive long tag tolerated'


class RealDecoderTestCase(BaseTestCase):
    def testCanonicalLargeBinaryReal(self):
        substrate = encoder.encode(univ.Real((1, 2, 1000000)))
        assert substrate == bytes((9, 5, 0x82, 0x0f, 0x42, 0x40, 1))

        value, rest = decoder.decode(substrate)

        assert tuple(value) == (1, 2, 1000000)
        assert rest == b''

    def testLargeBinaryRoundTrip(self):
        substrate = encoder.encode(univ.Real((-1, 2, 76354972)))
        value, rest = decoder.decode(substrate)

        assert tuple(value) == (-1, 2, 76354972)
        assert rest == b''

    def testLongBinaryMantissa(self):
        mantissa = b'\x80' + b'\x01' * 255
        content = b'\x80\x00' + mantissa
        substrate = b'\x09\x82\x01\x02' + content
        value, rest = decoder.decode(substrate, asn1Spec=univ.Real())

        assert tuple(value) == (int.from_bytes(mantissa, 'big'), 2, 0)
        assert rest == b''


class SequenceDecoderWithUntaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.Any(), openType=openType)
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 1, 2, 1, 12)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 16, 2, 1, 2, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 2
        assert s[1] == univ.OctetString('quick brown')

    def testDecodeOpenTypesUnknownType(self):
        try:
            s, r = decoder.decode(
                bytes((48, 6, 2, 1, 2, 6, 1, 39)), asn1Spec=self.s,
                decodeOpenTypes=True
            )

        except PyAsn1Error:
            pass

        else:
            assert False, 'unknown open type tolerated'

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 3, 6, 1, 39)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue='060127')

    def testDontDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 6, 2, 1, 1, 2, 1, 12)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 1
        assert s[1] == bytes((2, 1, 12))

    def testDontDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 16, 2, 1, 2, 4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 2
        assert s[1] == bytes((4, 11, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110))


class SequenceDecoderWithImplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.Any().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)), openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 131, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 131, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue='02010C')


class SequenceDecoderWithExplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.Any().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)), openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 163, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 163, 3, 2, 1, 12)), asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1] == univ.OctetString(hexValue='02010C')


class SequenceDecoderWithUnaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType('blob', univ.SetOf(componentType=univ.Any()),
                                    openType=openType)
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 49, 3, 2, 1, 12)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 18, 2, 1, 2, 49, 13, 4, 11, 113, 117, 105, 99,
                       107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 2
        assert s[1][0] == univ.OctetString('quick brown')

    def testDecodeOpenTypesUnknownType(self):
        try:
            s, r = decoder.decode(
                bytes((48, 6, 2, 1, 2, 6, 1, 39)), asn1Spec=self.s,
                decodeOpenTypes=True
            )

        except PyAsn1Error:
            pass

        else:
            assert False, 'unknown open type tolerated'

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 3, 49, 3, 2, 1, 12)), asn1Spec=self.s,
            decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue='02010c')

    def testDontDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 8, 2, 1, 1, 49, 3, 2, 1, 12)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == bytes((2, 1, 12))

    def testDontDecodeOpenTypesChoiceTwo(self):
        s, r = decoder.decode(
            bytes((48, 18, 2, 1, 2, 49, 13, 4, 11, 113, 117, 105, 99,
                       107, 32, 98, 114, 111, 119, 110)), asn1Spec=self.s
        )
        assert not r
        assert s[0] == 2
        assert s[1][0] == bytes((4, 11, 113, 117, 105, 99, 107, 32, 98, 114,
                                     111, 119, 110))


class SequenceDecoderWithImplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.SetOf(
                        componentType=univ.Any().subtype(
                            implicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3))),
                    openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 1, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 3, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue='02010C')


class SequenceDecoderWithExplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        openType = opentype.OpenType(
            'id',
            {1: univ.Integer(),
             2: univ.OctetString()}
        )
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType('id', univ.Integer()),
                namedtype.NamedType(
                    'blob', univ.SetOf(
                        componentType=univ.Any().subtype(
                            explicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3))),
                    openType=openType
                )
            )
        )

    def testDecodeOpenTypesChoiceOne(self):
        s, r = decoder.decode(
            bytes((48, 10, 2, 1, 1, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 1
        assert s[1][0] == 12

    def testDecodeOpenTypesUnknownId(self):
        s, r = decoder.decode(
            bytes( (48, 10, 2, 1, 3, 49, 5, 131, 3, 2, 1, 12)),
            asn1Spec=self.s, decodeOpenTypes=True
        )
        assert not r
        assert s[0] == 3
        assert s[1][0] == univ.OctetString(hexValue='02010C')


class NestingDepthLimitTestCase(BaseTestCase):
    """Test DER decoder protection against deeply nested structures."""

    def testDefiniteLenNesting(self):
        """Deeply nested definite-length SEQUENCEs must raise PyAsn1Error."""
        inner = b'\x05\x00'  # NULL
        for _ in range(200):
            length = len(inner)
            if length < 128:
                inner = b'\x30' + bytes([length]) + inner
            else:
                length_bytes = length.to_bytes(
                    (length.bit_length() + 7) // 8, 'big')
                inner = b'\x30' + bytes([0x80 | len(length_bytes)]) + \
                    length_bytes + inner
        try:
            decoder.decode(inner)
        except PyAsn1Error:
            pass
        else:
            assert False, 'Deeply nested definite-length SEQUENCEs not rejected'

    def testNoRecursionError(self):
        """Must raise PyAsn1Error, not RecursionError."""
        inner = b'\x05\x00'
        for _ in range(200):
            length = len(inner)
            if length < 128:
                inner = b'\x30' + bytes([length]) + inner
            else:
                length_bytes = length.to_bytes(
                    (length.bit_length() + 7) // 8, 'big')
                inner = b'\x30' + bytes([0x80 | len(length_bytes)]) + \
                    length_bytes + inner
        try:
            decoder.decode(inner)
        except PyAsn1Error:
            pass
        except RecursionError:
            assert False, 'Got RecursionError instead of PyAsn1Error'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
