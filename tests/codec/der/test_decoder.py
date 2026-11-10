#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import tag
from pyasn1.type import namedtype
from pyasn1.type import opentype
from pyasn1.type import univ
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.error import PyAsn1Error
from pyasn1.error import PyAsn1ResourceError


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
            assert 0, 'constructed-form BIT STRING tolerated'


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
            assert 0, 'constructed-form OCTET STRING tolerated'

    def testConstructedCharacterString(self):
        fragments = b'\x0c\x01A' * 64
        try:
            decoder.decode(b'\x2c\x81\xc0' + fragments)
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed-form character string tolerated'


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


class StrictDerDecodingTestCase(BaseTestCase):
    """DER canonical-encoding checks applied on every decode path."""

    def testIndefiniteLengthRejected(self):
        try:
            decoder.decode(b'\x30\x80\x02\x01\x01\x00\x00')
        except PyAsn1Error:
            pass
        else:
            assert 0, 'indefinite length tolerated'

    def testLongFormLengthForShortValueRejected(self):
        # INTEGER 5 encoded with a long-form length of 1
        try:
            decoder.decode(b'\x02\x81\x01\x05')
        except PyAsn1Error as exc:
            assert 'non-minimal' in str(exc).lower(), \
                'Error message missing encoding info: %s' % exc
        else:
            assert 0, 'non-minimal length tolerated'

    def testLeadingZeroLengthOctetRejected(self):
        # 128-octet OCTET STRING with a zero-padded two-octet length
        substrate = b'\x04\x82\x00\x80' + b'A' * 128
        try:
            decoder.decode(substrate)
        except PyAsn1Error as exc:
            assert 'non-minimal' in str(exc).lower(), \
                'Error message missing encoding info: %s' % exc
        else:
            assert 0, 'zero-padded length tolerated'

    def testMinimalLongFormLengthDecodes(self):
        # 128 octets is the shortest value requiring the long form
        substrate = b'\x04\x81\x80' + b'A' * 128
        value, rest = decoder.decode(substrate)
        assert value.asOctets() == b'A' * 128
        assert rest == b''

    def testConstructedPrimitiveRejectedSchemaless(self):
        try:
            decoder.decode(b'\x24\x06\x04\x01a\x04\x01b')
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed-form OCTET STRING tolerated'

    def testConstructedPrimitiveRejectedWithSchema(self):
        try:
            decoder.decode(b'\x24\x06\x04\x01a\x04\x01b',
                           asn1Spec=univ.OctetString())
        except PyAsn1Error:
            pass
        else:
            assert 0, 'constructed-form OCTET STRING tolerated on schema path'

    def testConstructedContextTagStillDecodes(self):
        # explicit tagging uses constructed context-specific tags
        substrate = b'\xa0\x03\x02\x01\x05'
        value, rest = decoder.decode(substrate)
        assert value is not None
        assert rest == b''

    def testTrailingSubstrateRejected(self):
        try:
            decoder.decode(b'\x02\x01\x01\x00')
        except PyAsn1Error as exc:
            assert 'trailing' in str(exc).lower(), \
                'Error message missing trailing info: %s' % exc
        else:
            assert 0, 'trailing substrate tolerated'


class DecoderBudgetMirrorTestCase(BaseTestCase):
    """Budget options reach the DER decoder through inheritance."""

    def testMaxNodesEnforced(self):
        substrate = b'\x30\x0f' + b'\x02\x01\x01' * 5
        try:
            decoder.decode(substrate, maxNodes=5)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'node count over budget tolerated'

    def testMaxNestingDepthEnforced(self):
        # two nested definite-length SEQUENCEs around a NULL
        substrate = b'\x30\x04\x30\x02\x05\x00'
        try:
            decoder.decode(substrate, maxNestingDepth=1)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'nesting over budget tolerated'

        asn1Object, rest = decoder.decode(substrate, maxNestingDepth=2)
        assert asn1Object is not None


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
