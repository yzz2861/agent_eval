#
# This file is part of pyasn1 software.
#
# Copyright (c) 2026, Simon Pichugin <simon.pichugin@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import io
import sys
import unittest

from tests.base import BaseTestCase

from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.error import PyAsn1ResourceError
from pyasn1.type import univ


def _nestedSequence(depth, inner=b'\x05\x00'):
    """Wrap *inner* into *depth* definite-length SEQUENCEs."""
    for _ in range(depth):
        length = len(inner)
        if length < 128:
            inner = b'\x30' + bytes([length]) + inner
        else:
            lengthBytes = length.to_bytes(
                (length.bit_length() + 7) // 8, 'big')
            inner = b'\x30' + bytes([0x80 | len(lengthBytes)]) + \
                lengthBytes + inner
    return inner


class NestingDepthBudgetTestCase(BaseTestCase):
    """Caller-supplied maxNestingDepth budget."""

    def testDepthBombRejected(self):
        # 50 nested indefinite-length SEQUENCEs, budget of 10
        payload = b'\x30\x80' * 50 + b'\x00\x00' * 50
        try:
            ber_decoder.decode(payload, maxNestingDepth=10)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'depth bomb tolerated'

    def testDepthAtLimitDecodes(self):
        # 10 SEQUENCEs around a NULL: the NULL sits at nesting level 10
        substrate = _nestedSequence(10)
        asn1Object, rest = ber_decoder.decode(substrate, maxNestingDepth=10)
        assert asn1Object is not None
        assert rest == b''

    def testDepthOneOverLimitRejected(self):
        substrate = _nestedSequence(10)
        try:
            ber_decoder.decode(substrate, maxNestingDepth=9)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'nesting one over budget tolerated'

    def testErrorMessageNamesLimit(self):
        payload = b'\x30\x80' * 50 + b'\x00\x00' * 50
        try:
            ber_decoder.decode(payload, maxNestingDepth=10)
        except PyAsn1ResourceError as exc:
            assert 'nesting depth' in str(exc).lower(), \
                'Error message missing depth info: %s' % exc
            assert '10' in str(exc), \
                'Error message missing limit value: %s' % exc
        else:
            assert 0, 'depth bomb tolerated'

    def testDefaultLimitStillApplies(self):
        # 50 levels decode fine without options (default limit is 100)
        asn1Object, rest = ber_decoder.decode(_nestedSequence(50))
        assert asn1Object is not None


class NodeCountBudgetTestCase(BaseTestCase):
    """Caller-supplied maxNodes budget against wide structures."""

    substrate = b'\x30\x0f' + b'\x02\x01\x01' * 5  # SEQUENCE of 5 INTEGERs

    def testWideSequenceRejected(self):
        # 100 shallow siblings, one container: deep nesting is not
        # needed to blow the node budget
        components = b'\x02\x01\x01' * 100
        substrate = b'\x30\x82\x01\x2c' + components
        try:
            ber_decoder.decode(substrate, maxNodes=50)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'wide sequence tolerated'

    def testExactNodeCountDecodes(self):
        # 1 SEQUENCE + 5 INTEGERs = 6 nodes
        asn1Object, rest = ber_decoder.decode(self.substrate, maxNodes=6)
        assert len(asn1Object) == 5
        assert rest == b''

    def testOneOverNodeCountRejected(self):
        try:
            ber_decoder.decode(self.substrate, maxNodes=5)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'node count one over budget tolerated'

    def testSchemaDrivenNodeCount(self):
        schema = univ.SequenceOf(componentType=univ.Integer())
        try:
            ber_decoder.decode(
                self.substrate, asn1Spec=schema, maxNodes=5)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'node count over budget tolerated on schema path'

    def testErrorMessageNamesLimit(self):
        try:
            ber_decoder.decode(self.substrate, maxNodes=5)
        except PyAsn1ResourceError as exc:
            assert 'node count' in str(exc).lower(), \
                'Error message missing node count info: %s' % exc
        else:
            assert 0, 'node count over budget tolerated'


class ValueBytesBudgetTestCase(BaseTestCase):
    """Caller-supplied maxValueBytes budget on cumulative primitive payload."""

    def testCumulativeValueBytesAtLimitDecodes(self):
        # 10 OCTET STRINGs of 10 octets each: 100 payload octets in total
        components = (b'\x04\x0a' + b'A' * 10) * 10
        substrate = b'\x30\x82\x00\x78' + components
        asn1Object, rest = ber_decoder.decode(substrate, maxValueBytes=100)
        assert len(asn1Object) == 10

    def testCumulativeValueBytesOneOverRejected(self):
        components = (b'\x04\x0a' + b'A' * 10) * 10
        substrate = b'\x30\x82\x00\x78' + components
        try:
            ber_decoder.decode(substrate, maxValueBytes=99)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'cumulative value size over budget tolerated'

    def testFailsBeforeSubstrateConsumed(self):
        # 1000-octet OCTET STRING, budget of 5: the decoder must fail
        # right past the header, not after reading the whole value
        substrate = b'\x04\x82\x03\xe8' + b'A' * 1000
        stream = io.BytesIO(substrate)
        streamingDecoder = ber_decoder.StreamingDecoder(
            stream, maxValueBytes=5)
        received = []
        try:
            for asn1Object in streamingDecoder:
                received.append(asn1Object)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'oversized value tolerated'
        assert not received, 'partial object returned on budget exhaustion'
        assert stream.tell() < len(substrate), \
            'whole substrate consumed before budget enforcement'

    def testErrorMessageNamesLimit(self):
        substrate = b'\x04\x0a' + b'A' * 10
        try:
            ber_decoder.decode(substrate, maxValueBytes=5)
        except PyAsn1ResourceError as exc:
            assert 'value size' in str(exc).lower(), \
                'Error message missing value size info: %s' % exc
        else:
            assert 0, 'oversized value tolerated'


class ConstructedLengthBudgetTestCase(BaseTestCase):
    """Caller-supplied maxConstructedLength budget."""

    def testDeclaredLengthFarExceedingInputRejected(self):
        # SEQUENCE declaring 65535 content octets, 3 actually present
        substrate = b'\x30\x82\xff\xff' + b'\x02\x01\x01'
        stream = io.BytesIO(substrate)
        streamingDecoder = ber_decoder.StreamingDecoder(
            stream, maxConstructedLength=100)
        received = []
        try:
            for asn1Object in streamingDecoder:
                received.append(asn1Object)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'oversized constructed length tolerated'
        assert not received, 'partial object returned on budget exhaustion'
        assert stream.tell() < len(substrate), \
            'whole substrate consumed before budget enforcement'

    def testConstructedLengthAtLimitDecodes(self):
        components = b'\x02\x01\x01' * 25  # 75 content octets
        substrate = b'\x30\x4b' + components
        asn1Object, rest = ber_decoder.decode(
            substrate, maxConstructedLength=75)
        assert len(asn1Object) == 25

    def testConstructedLengthOneOverRejected(self):
        components = b'\x02\x01\x01' * 25
        substrate = b'\x30\x4b' + components
        try:
            ber_decoder.decode(substrate, maxConstructedLength=74)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'constructed length one over budget tolerated'

    def testErrorMessageNamesLimit(self):
        substrate = b'\x30\x82\xff\xff' + b'\x02\x01\x01'
        try:
            ber_decoder.decode(substrate, maxConstructedLength=100)
        except PyAsn1ResourceError as exc:
            assert 'constructed value length' in str(exc).lower(), \
                'Error message missing length info: %s' % exc
        else:
            assert 0, 'oversized constructed length tolerated'


class IndefiniteChunkBudgetTestCase(BaseTestCase):
    """Caller-supplied maxIndefiniteChunks budget."""

    substrate = b'\x24\x80' + b'\x04\x01A' * 5 + b'\x00\x00'

    def testExcessiveChunksRejected(self):
        try:
            ber_decoder.decode(self.substrate, maxIndefiniteChunks=4)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'excessive indefinite-length chunks tolerated'

    def testChunksAtLimitDecode(self):
        asn1Object, rest = ber_decoder.decode(
            self.substrate, maxIndefiniteChunks=5)
        assert asn1Object.asOctets() == b'AAAAA'
        assert rest == b''

    def testContainerComponentsCountedAsChunks(self):
        # indefinite SEQUENCE holding 3 INTEGERs
        substrate = b'\x30\x80' + b'\x02\x01\x01' * 3 + b'\x00\x00'
        try:
            ber_decoder.decode(substrate, maxIndefiniteChunks=2)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'excessive indefinite-length components tolerated'

        asn1Object, rest = ber_decoder.decode(
            substrate, maxIndefiniteChunks=3)
        assert len(asn1Object) == 3

    def testChunkedInputDecodesWithoutBudget(self):
        # BER chunked encoding stays decodable by default
        asn1Object, rest = ber_decoder.decode(self.substrate)
        assert asn1Object.asOctets() == b'AAAAA'

    def testErrorMessageNamesLimit(self):
        try:
            ber_decoder.decode(self.substrate, maxIndefiniteChunks=4)
        except PyAsn1ResourceError as exc:
            assert 'chunk' in str(exc).lower(), \
                'Error message missing chunk info: %s' % exc
        else:
            assert 0, 'excessive indefinite-length chunks tolerated'


class BudgetIsolationTestCase(BaseTestCase):
    """Budgets are per decoder instance, never module-global."""

    substrate = b'\x30\x0f' + b'\x02\x01\x01' * 5  # 6 nodes

    def testIndependentStreamingDecoders(self):
        tightDecoder = ber_decoder.StreamingDecoder(
            io.BytesIO(self.substrate), maxNodes=2)
        looseDecoder = ber_decoder.StreamingDecoder(
            io.BytesIO(self.substrate), maxNodes=100)

        try:
            list(tightDecoder)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'tight budget not enforced'

        # the other instance, created in the same process, is unaffected
        decoded = list(looseDecoder)
        assert len(decoded) == 1

    def testFailedDecoderLeavesOthersUnaffected(self):
        try:
            ber_decoder.decode(self.substrate, maxNodes=2)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'tight budget not enforced'

        # a later unbudgeted decode of the same substrate still works
        asn1Object, rest = ber_decoder.decode(self.substrate)
        assert len(asn1Object) == 5

        # and so does a later decode under a looser budget
        asn1Object, rest = ber_decoder.decode(self.substrate, maxNodes=6)
        assert len(asn1Object) == 5

    def testDefaultDepthLimitUnchangedByCustomDecoder(self):
        payload = _nestedSequence(50)
        try:
            ber_decoder.decode(payload, maxNestingDepth=5)
        except PyAsn1ResourceError:
            pass
        else:
            assert 0, 'tight depth budget not enforced'

        # the module-level default (100) still governs budgetless decodes
        asn1Object, rest = ber_decoder.decode(payload)
        assert asn1Object is not None

    def testLargeLegitStructureDecodes(self):
        # a deep-and-wide but in-budget structure passes all budgets
        inner = _nestedSequence(20, inner=b'\x04\x64' + b'A' * 100)
        components = inner * 30
        length = len(components)
        lengthBytes = length.to_bytes(
            (length.bit_length() + 7) // 8, 'big')
        substrate = b'\x30' + bytes([0x80 | len(lengthBytes)]) + \
            lengthBytes + components
        asn1Object, rest = ber_decoder.decode(
            substrate, maxNestingDepth=50, maxNodes=1000,
            maxValueBytes=10000, maxConstructedLength=100000,
            maxIndefiniteChunks=100)
        assert len(asn1Object) == 30


class BerLeniencyTestCase(BaseTestCase):
    """BER keeps its historical tolerance; budgets are opt-in only."""

    def testNonMinimalLengthTolerated(self):
        # long-form length for a one-octet value is legal BER
        asn1Object, rest = ber_decoder.decode(b'\x02\x81\x01\x05')
        assert asn1Object == 5
        assert rest == b''

    def testTrailingSubstrateReturned(self):
        asn1Object, rest = ber_decoder.decode(b'\x02\x01\x01\x00')
        assert rest == b'\x00'

    def testConstructedStringTolerated(self):
        substrate = b'\x24\x06' + b'\x04\x01a' + b'\x04\x01b'
        asn1Object, rest = ber_decoder.decode(substrate)
        assert asn1Object.asOctets() == b'ab'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)

