#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import warnings

from pyasn1 import error
from pyasn1.codec.cer import decoder
from pyasn1.type import tag
from pyasn1.type import univ

__all__ = ['decode', 'StreamingDecoder']

# Universal tags keeping the constructed encoding form under DER:
# SEQUENCE/SEQUENCE OF (16) and SET/SET OF (17)
_DER_CONSTRUCTED_TAG_IDS = (16, 17)


class BitStringPayloadDecoder(decoder.BitStringPayloadDecoder):
    supportConstructedForm = False


class OctetStringPayloadDecoder(decoder.OctetStringPayloadDecoder):
    supportConstructedForm = False


# TODO: prohibit non-canonical encoding
RealPayloadDecoder = decoder.RealPayloadDecoder

TAG_MAP = decoder.TAG_MAP.copy()
TAG_MAP.update(
    {univ.BitString.tagSet: BitStringPayloadDecoder(),
     univ.OctetString.tagSet: OctetStringPayloadDecoder(),
     univ.Real.tagSet: RealPayloadDecoder()}
)

TYPE_MAP = decoder.TYPE_MAP.copy()

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

    def _checkTlvHeader(self, tagSet, length, lengthOctets, headerOffset):
        # X.690 10.1: the definite form of length encoding is required,
        # serialized into the minimum number of octets
        if length == -1:
            raise error.PyAsn1Error(
                'Indefinite length encoding prohibited by DER (X.690 10.1) '
                'at offset %d' % headerOffset
            )

        if lengthOctets is not None and (not lengthOctets[0] or length < 128):
            raise error.PyAsn1Error(
                'Non-minimal length encoding prohibited by DER (X.690 10.1) '
                'at offset %d' % headerOffset
            )

        # X.690 10.2: string types must use the primitive encoding form;
        # of the universal tags, only SEQUENCE/SET stay constructed
        firstTag = tagSet[0]

        if (firstTag.tagClass == tag.tagClassUniversal and
                firstTag.tagFormat == tag.tagFormatConstructed and
                firstTag.tagId not in _DER_CONSTRUCTED_TAG_IDS):
            raise error.PyAsn1Error(
                'Constructed encoding of a string type prohibited by DER '
                '(X.690 10.2) at offset %d' % headerOffset
            )


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
#:    SequenceOf:
#:     1 2 3
#:
#: Decode DER serialisation with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03', asn1Spec=seq)
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
decode = Decoder()

def __getattr__(attr: str):
    if newAttr := {"tagMap": "TAG_MAP", "typeMap": "TYPE_MAP"}.get(attr):
        warnings.warn(f"{attr} is deprecated. Please use {newAttr} instead.", DeprecationWarning, stacklevel=2)
        return globals()[newAttr]
    raise AttributeError(attr)
