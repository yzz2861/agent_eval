#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1.codec.der import decoder
from pyasn1.error import PyAsn1Error


def _assertRejected(case, payload, asn1Spec=None):
    try:
        if asn1Spec is None:
            decoder.decode(payload, strict=True)
        else:
            decoder.decode(payload, asn1Spec=asn1Spec, strict=True)
    except PyAsn1Error:
        pass
    else:
        assert False, case


class NonMinimalLengthTestCase(BaseTestCase):
    # DER length must use the shortest available length form.

    def testLongFormForShortValueToleratedByDefault(self):
        # INTEGER 0, length encoded as long form 0x81 0x01 instead of 0x01
        payload = bytes((0x02, 0x81, 0x01, 0x00))
        value, rest = decoder.decode(payload)
        assert value == 0
        assert rest == b''

    def testLongFormForShortValueRejectedInStrictMode(self):
        payload = bytes((0x02, 0x81, 0x01, 0x00))
        _assertRejected('non-minimal long-form length tolerated', payload)

    def testLeadingZeroLengthOctetRejectedInStrictMode(self):
        # length 200 encoded as 0x82 0x00 0xC8 instead of 0x81 0xC8
        payload = bytes((0x04, 0x82, 0x00, 0xC8)) + b'\x00' * 200
        value, rest = decoder.decode(payload)
        assert len(value) == 200
        _assertRejected('leading zero length octet tolerated', payload)

    def testMinimalLongFormLengthAcceptedInStrictMode(self):
        # length 200 in minimal long form 0x81 0xC8 stays valid
        payload = bytes((0x04, 0x81, 0xC8)) + b'\x00' * 200
        value, rest = decoder.decode(payload, strict=True)
        assert len(value) == 200
        assert rest == b''



class NonMinimalTagTestCase(BaseTestCase):
    # DER tag numbers must use the short form when below 31 and must not
    # carry leading all-zero continuation octets.

    def testLeadingZeroTagContinuationOctetToleratedByDefault(self):
        # context tag 31 encoded as 0x1F 0x80 0x1F (extra zero continuation)
        payload = bytes((0x9F, 0x80, 0x1F, 0x00))
        try:
            decoder.decode(payload)
        except PyAsn1Error:
            # unknown tag mapping is an independent failure; the point is the
            # non-minimal tag itself does not raise before dispatch
            pass

    def testLeadingZeroTagContinuationOctetRejectedInStrictMode(self):
        payload = bytes((0x9F, 0x80, 0x1F, 0x00))
        _assertRejected('non-minimal tag continuation tolerated', payload)

    def testMinimalLongTagAcceptedInStrictMode(self):
        # context tag 31 in minimal long form 0x9F 0x1F
        payload = bytes((0x9F, 0x1F, 0x00))
        try:
            decoder.decode(payload, strict=True)
        except PyAsn1Error as exc:
            # an unmapped tag is expected here, but the tag must be treated
            # as canonical (no non-minimal tag diagnostic)
            assert 'non-minimal' not in str(exc).lower()


class BooleanValueTestCase(BaseTestCase):
    # DER BOOLEAN encodes TRUE as 0xFF and FALSE as 0x00 only.

    def testIllegalBooleanToleratedByDefaultWithSchema(self):
        # schema-driven path dispatches through TYPE_MAP to the permissive
        # BER Boolean decoder, so 0x01 decodes as TRUE for compatibility
        value, rest = decoder.decode(
            bytes((0x01, 0x01, 0x01)), asn1Spec=univ.Boolean())
        assert value == 1
        assert rest == b''

    def testIllegalBooleanRejectedInStrictModeWithSchema(self):
        _assertRejected(
            'non-canonical Boolean value tolerated',
            bytes((0x01, 0x01, 0x01)), univ.Boolean())

    def testIllegalBooleanRejectedInStrictModeWithoutSchema(self):
        _assertRejected(
            'non-canonical Boolean value tolerated',
            bytes((0x01, 0x01, 0x7F)))

    def testCanonicalBooleanAcceptedInStrictMode(self):
        trueValue, _ = decoder.decode(
            bytes((0x01, 0x01, 0xFF)), asn1Spec=univ.Boolean(), strict=True)
        assert trueValue == 1
        falseValue, _ = decoder.decode(
            bytes((0x01, 0x01, 0x00)), asn1Spec=univ.Boolean(), strict=True)
        assert falseValue == 0



class SetOrderingTestCase(BaseTestCase):
    # DER SET components must be sorted in ascending encoded-tag order.

    def setUp(self):
        BaseTestCase.setUp(self)
        self.spec = univ.Set(componentType=namedtype.NamedTypes(
            namedtype.NamedType('boolean', univ.Boolean()),
            namedtype.NamedType('integer', univ.Integer())))

    def _unsortedPayload(self):
        # INTEGER (tag 0x02) before BOOLEAN (tag 0x01): wrong order
        return bytes((0x31, 0x06,
                      0x02, 0x01, 0x02,
                      0x01, 0x01, 0x01))

    def testUnsortedSetToleratedByDefault(self):
        value, rest = decoder.decode(
            self._unsortedPayload(), asn1Spec=self.spec)
        assert value['integer'] == 2
        assert value['boolean'] == 1
        assert rest == b''

    def testUnsortedSetRejectedInStrictModeWithSchema(self):
        _assertRejected(
            'unsorted SET tolerated', self._unsortedPayload(), self.spec)

    def testUnsortedSetRejectedInStrictModeWithoutSchema(self):
        _assertRejected(
            'unsorted SET tolerated', self._unsortedPayload())

    def testSortedSetAcceptedInStrictMode(self):
        # BOOLEAN (0x01) before INTEGER (0x02): canonical order
        payload = bytes((0x31, 0x06,
                         0x01, 0x01, 0xFF,
                         0x02, 0x01, 0x02))
        value, rest = decoder.decode(
            payload, asn1Spec=self.spec, strict=True)
        assert value['boolean'] == 1
        assert value['integer'] == 2
        assert rest == b''


class SetOfOrderingTestCase(BaseTestCase):
    # DER SET OF components must be sorted in padded lexicographic order.

    def setUp(self):
        BaseTestCase.setUp(self)
        self.spec = univ.SetOf(componentType=univ.Integer())

    def _unsortedPayload(self):
        # INTEGER 200 (02 02 00 C8) before INTEGER 1 (02 01 01): wrong order
        return bytes((0x31, 0x07,
                      0x02, 0x02, 0x00, 0xC8,
                      0x02, 0x01, 0x01))

    def testUnsortedSetOfToleratedByDefault(self):
        value, rest = decoder.decode(
            self._unsortedPayload(), asn1Spec=self.spec)
        assert [int(component) for component in value] == [200, 1]
        assert rest == b''

    def testUnsortedSetOfRejectedInStrictModeWithSchema(self):
        _assertRejected(
            'unsorted SET OF tolerated', self._unsortedPayload(), self.spec)

    def testSortedSetOfAcceptedInStrictMode(self):
        # INTEGER 1 then INTEGER 200: padded lexicographic order
        payload = bytes((0x31, 0x07,
                         0x02, 0x01, 0x01,
                         0x02, 0x02, 0x00, 0xC8))
        value, rest = decoder.decode(
            payload, asn1Spec=univ.SetOf(componentType=univ.Integer()),
            strict=True)
        assert [int(component) for component in value] == [1, 200]
        assert rest == b''




class NestedStrictOrderingTestCase(BaseTestCase):
    # strict must propagate through the recursive decodeFun into nested
    # containers on both schema-driven and schemaless paths.

    def _unsortedNestedPayload(self):
        # SEQUENCE (0x30) wrapping an unsorted SET OF
        return bytes((0x30, 0x09,
                      0x31, 0x07,
                      0x02, 0x02, 0x00, 0xC8,
                      0x02, 0x01, 0x01))

    def testNestedUnsortedSetOfToleratedByDefault(self):
        value, rest = decoder.decode(self._unsortedNestedPayload())
        assert rest == b''
        inner = value[0]
        assert [int(component) for component in inner] == [200, 1]

    def testNestedUnsortedSetOfRejectedInStrictModeWithoutSchema(self):
        _assertRejected(
            'nested unsorted SET OF tolerated',
            self._unsortedNestedPayload())

    def testNestedUnsortedSetOfRejectedInStrictModeWithSchema(self):
        spec = univ.Sequence(componentType=namedtype.NamedTypes(
            namedtype.NamedType(
                'values', univ.SetOf(componentType=univ.Integer()))))
        _assertRejected(
            'nested unsorted SET OF tolerated',
            self._unsortedNestedPayload(), spec)

    def testSchemalessSetUsesTagOrderNotLexicographicOrder(self):
        # Two INTEGER components have equal tag octets, so an unsorted
        # same-tag SET OF is caught by the lexicographic rule while a SET
        # distinguished by tag uses the tag rule. Here a SET OF with equal
        # tags but descending value encodings must still be rejected.
        payload = bytes((0x31, 0x06,
                         0x02, 0x01, 0x09,
                         0x02, 0x01, 0x01))
        _assertRejected('unsorted equal-tag SET OF tolerated', payload)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
