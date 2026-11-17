#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import warnings

from pyasn1 import error
from pyasn1.codec.ber import decoder as berDecoder
from pyasn1.codec.cer import decoder
from pyasn1.type import univ

__all__ = ['decode', 'StreamingDecoder']


class BitStringPayloadDecoder(decoder.BitStringPayloadDecoder):
    supportConstructedForm = False


class OctetStringPayloadDecoder(decoder.OctetStringPayloadDecoder):
    supportConstructedForm = False


# TODO: prohibit non-canonical encoding
RealPayloadDecoder = decoder.RealPayloadDecoder


class BooleanPayloadDecoder(decoder.BooleanPayloadDecoder):
    """BER-permissive by default; DER-canonical (0x00/0xFF only) in strict mode.

    CER BooleanPayloadDecoder already enforces the 0x00/0xFF rule on the
    tag-driven path, so this class only needs to additionally cover the
    schema-driven path, which dispatches through TYPE_MAP to the permissive
    BER BooleanPayloadDecoder unless strict=True is passed.
    """

    def valueDecoder(self, substrate, asn1Spec,
                     tagSet=None, length=None, state=None,
                     decodeFun=None, substrateFun=None,
                     **options):
        if options.get('strict'):
            return decoder.BooleanPayloadDecoder.valueDecoder(
                self, substrate, asn1Spec, tagSet, length, state,
                decodeFun, substrateFun, **options)

        return berDecoder.BooleanPayloadDecoder.valueDecoder(
            self, substrate, asn1Spec, tagSet, length, state,
            decodeFun, substrateFun, **options)


class _StrictSetOrderingPayloadDecoderMixin(object):
    """Verify DER SET/SET OF component ordering when strict=True.

    The canonical order is checked against the raw serialised components on
    the wire (X.690 section 11.6 and X.680 section 8.6), so every nested TLV
    passes through the same rules, including components carried in untagged
    CHOICE alternatives. The single tag-driven entry must handle both SET and
    SET OF, because schemaless decoding guesses between them from the
    component tags after the payload is read.
    """

    @staticmethod
    def _checkSetTagOrder(components):
        previousTag = None
        for component in components:
            currentTag = component[0]
            if previousTag is not None and currentTag < previousTag:
                raise error.PyAsn1Error(
                    'Non-canonical DER SET: components are not sorted in '
                    'ascending tag order')
            previousTag = currentTag

    @staticmethod
    def _checkSetOfLexicographicOrder(components):
        previous = None
        zero = b'\x00'
        for component in components:
            if previous is not None:
                maxLength = max(len(previous), len(component))
                if previous.ljust(maxLength, zero) > component.ljust(
                        maxLength, zero):
                    raise error.PyAsn1Error(
                        'Non-canonical DER SET OF: components are not sorted '
                        'in lexicographic order')
            previous = component

    def _checkComponentOrder(self, components, asn1Object):
        if isinstance(asn1Object, univ.SetOf):
            self._checkSetOfLexicographicOrder(components)
        else:
            self._checkSetTagOrder(components)

    def valueDecoder(self, substrate, asn1Spec,
                     tagSet=None, length=None, state=None,
                     decodeFun=None, substrateFun=None,
                     **options):
        if not options.get('strict') or substrateFun is not None:
            for component in berDecoder.ConstructedPayloadDecoderBase.valueDecoder(
                    self, substrate, asn1Spec, tagSet, length, state,
                    decodeFun, substrateFun, **options):
                yield component
            return

        componentTlv = []

        def orderingDecodeFun(stream, componentSpec=None, **innerOptions):
            start = stream.tell()
            for component in decodeFun(stream, componentSpec, **innerOptions):
                if isinstance(component, error.SubstrateUnderrunError):
                    yield component
            end = stream.tell()
            stream.seek(start)
            componentTlv.append(stream.read(end - start))
            yield component

        for asn1Object in berDecoder.ConstructedPayloadDecoderBase.valueDecoder(
                self, substrate, asn1Spec, tagSet, length, state,
                orderingDecodeFun, substrateFun, **options):
            if isinstance(asn1Object, error.SubstrateUnderrunError):
                yield asn1Object
            else:
                self._checkComponentOrder(componentTlv, asn1Object)
                yield asn1Object


class SetPayloadDecoder(_StrictSetOrderingPayloadDecoderMixin,
                        berDecoder.SetPayloadDecoder):
    """Strict SET/SET OF ordering for the tag-driven (schemaless) path."""


class SetOfPayloadDecoder(_StrictSetOrderingPayloadDecoderMixin,
                          berDecoder.SetOfPayloadDecoder):
    """Strict SET OF ordering for the schema-driven TYPE_MAP path."""


TAG_MAP = decoder.TAG_MAP.copy()
TAG_MAP.update(
    {univ.BitString.tagSet: BitStringPayloadDecoder(),
     univ.OctetString.tagSet: OctetStringPayloadDecoder(),
     univ.Real.tagSet: RealPayloadDecoder(),
     univ.Set.tagSet: SetPayloadDecoder()}
)

TYPE_MAP = decoder.TYPE_MAP.copy()
TYPE_MAP.update(
    # Schema-driven Boolean and SET/SET OF decodes dispatch through TYPE_MAP,
    # which otherwise stays 100 percent inherited from BER; strict-aware
    # subclasses are required there so strict=True reaches those paths.
    {univ.Boolean.typeId: BooleanPayloadDecoder(),
     univ.Set.typeId: SetPayloadDecoder(),
     univ.SetOf.typeId: SetOfPayloadDecoder()}
)

# Put in non-ambiguous types for faster codec lookup
for typeDecoder in TAG_MAP.values():
    if typeDecoder.protoComponent is not None:
        typeId = typeDecoder.protoComponent.__class__.typeId
        if typeId is not None and typeId not in TYPE_MAP:
            TYPE_MAP[typeId] = typeDecoder


class SingleItemDecoder(decoder.SingleItemDecoder):
    __doc__ = decoder.SingleItemDecoder.__doc__

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP

    supportIndefLength = False

    def _checkTag(self, firstOctet, tagId, tagOctets, options):
        if not options.get('strict'):
            return

        firstOctetValue = (
            ord(firstOctet) if isinstance(firstOctet, bytes) else firstOctet)

        if (firstOctetValue & 0x1F) != 0x1F:
            raise error.PyAsn1Error(
                'Non-minimal DER tag: tag ID %d must use the short tag form'
                % tagId)

        if len(tagOctets) > 1 and tagOctets[0] == 0x80:
            raise error.PyAsn1Error(
                'Non-minimal DER tag: leading zero continuation octet')

    def _checkLength(self, firstOctet, lengthOctets, length, options):
        if not options.get('strict') or firstOctet < 0x80:
            return

        size = firstOctet & 0x7F

        if size == 1 and length < 0x80:
            raise error.PyAsn1Error(
                'Non-minimal DER length: value %d must use the short form'
                % length)

        if size > 1 and lengthOctets and lengthOctets[0] == 0:
            raise error.PyAsn1Error(
                'Non-minimal DER length: leading zero length octet')


class StreamingDecoder(decoder.StreamingDecoder):
    __doc__ = decoder.StreamingDecoder.__doc__

    SINGLE_ITEM_DECODER = SingleItemDecoder


class Decoder(decoder.Decoder):
    __doc__ = decoder.Decoder.__doc__

    STREAMING_DECODER = StreamingDecoder


#: Turns DER octet stream into an ASN.1 object.
#:
#: Takes DER octet-stream and decode it into an ASN.1 object
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative) which
#: may be a scalar or an arbitrary nested structure.
#:
#: Parameters
#: ----------
#: substrate: :py:class:`bytes`
#:     DER octet-stream
#:
#: Keyword Args
#: ------------
#: asn1Spec: any pyasn1 type object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:     A pyasn1 type object to act as a template guiding the decoder. Depending on the ASN.1 structure
#:     being decoded, *asn1Spec* may or may not be required. Most common reason for
#:     it to require is that ASN.1 structure is encoded in *IMPLICIT* tagging mode.
#: strict: :py:class:`bool`
#:     When true, reject non-canonical DER encodings: non-minimal length
#:     encodings, non-minimal tag numbers, Boolean values other than 0x00 and
#:     0xFF, and SET/SET OF components not sorted per X.690. Defaults to
#:     false, preserving the historical BER-compatible lenient behavior.
#:
#: Returns
#: -------
#: : :py:class:`tuple`
#:     A tuple of pyasn1 object recovered from DER substrate (:py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     and the unprocessed trailing portion of the *substrate* (may be empty)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error, ~pyasn1.error.SubstrateUnderrunError
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode DER serialisation without ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03')
#:    >>> str(s)
#: SequenceOf:
#:     1 2 3
#:
#: Decode DER serialisation with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03', asn1Spec=seq)
#:    >>> str(s)
#: SequenceOf:
#:     1 2 3
#:
decode = Decoder()

def __getattr__(attr: str):
    if newAttr := {'tagMap': 'TAG_MAP', 'typeMap': 'TYPE_MAP'}.get(attr):
        warnings.warn(f'{attr} is deprecated. Please use {newAttr} instead.', DeprecationWarning, stacklevel=2)
        return globals()[newAttr]
    raise AttributeError(attr)
