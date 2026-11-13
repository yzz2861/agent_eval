#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#
import warnings

from pyasn1 import error
from pyasn1.codec.cer import encoder
from pyasn1.type import univ

__all__ = ['Encoder', 'encode', 'SetOfEncoder',
           'DuplicateSetOfElementError']


DUPLICATE_POLICY_REJECT = 'reject'
DUPLICATE_POLICY_DEDUPE = 'dedupe'
DUPLICATE_POLICY_ALLOW = 'allow'
DEFAULT_DUPLICATE_POLICY = DUPLICATE_POLICY_REJECT

_DUPLICATE_POLICY_ALIASES = {
    'reject': DUPLICATE_POLICY_REJECT,
    'error': DUPLICATE_POLICY_REJECT,
    'raise': DUPLICATE_POLICY_REJECT,
    'strict': DUPLICATE_POLICY_REJECT,
    'dedupe': DUPLICATE_POLICY_DEDUPE,
    'deduplicate': DUPLICATE_POLICY_DEDUPE,
    'drop': DUPLICATE_POLICY_DEDUPE,
    'drop-duplicates': DUPLICATE_POLICY_DEDUPE,
    'allow': DUPLICATE_POLICY_ALLOW,
    'keep': DUPLICATE_POLICY_ALLOW,
    'preserve': DUPLICATE_POLICY_ALLOW,
}


def _normalizeDuplicatePolicy(policy):
    """Turn a caller-supplied duplicate policy into a canonical name."""

    try:
        if isinstance(policy, bytes):
            policy = policy.decode('ascii', 'strict')

        policy = str(policy).strip().lower().replace('_', '-')

    except (AttributeError, TypeError, ValueError):
        policy = None

    try:
        return _DUPLICATE_POLICY_ALIASES[policy]

    except KeyError:
        raise error.PyAsn1Error(
            'Invalid SET OF duplicate policy %r; comparison category: '
            'duplicate-policy; expected one of %s' % (
                policy,
                ', '.join((DUPLICATE_POLICY_REJECT,
                           DUPLICATE_POLICY_DEDUPE,
                           DUPLICATE_POLICY_ALLOW)))
        )


class DuplicateSetOfElementError(error.PyAsn1Error):
    """Raised when DER SET OF contains two components with equal TLV bytes."""

    category = 'der-tlv'
    suppressValueEcho = True

    def __init__(self, index, firstIndex):
        self.index = index
        self.firstIndex = firstIndex

        message = (
            'Duplicate SET OF element at index %d (first occurrence at '
            'index %d); comparison category: %s' % (
                index, firstIndex, self.category))

        error.PyAsn1Error.__init__(self, message)
        Exception.__init__(self, message)

    def __str__(self):
        return self._args[0]


class SetOfEncoder(encoder.SetOfEncoder):
    """DER SET OF encoder ordering components by their complete DER TLV."""

    duplicatePolicy = DEFAULT_DUPLICATE_POLICY

    def _getDuplicatePolicy(self, options):
        policy = options.get('duplicatePolicy')

        if policy is None:
            if 'deduplicate' in options:
                policy = (DUPLICATE_POLICY_DEDUPE
                          if options['deduplicate']
                          else DUPLICATE_POLICY_ALLOW)

            elif 'allowDuplicates' in options:
                policy = (DUPLICATE_POLICY_ALLOW
                          if options['allowDuplicates']
                          else DUPLICATE_POLICY_REJECT)

            else:
                policy = self.duplicatePolicy

        return _normalizeDuplicatePolicy(policy)

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        chunks = self._encodeComponents(
            value, asn1Spec, encodeFun, **options)

        # Each component is encoded exactly once above.  Ordering below only
        # compares those pre-computed TLV octets; it must never call encodeFun
        # again, because that would permit unbounded re-encoding while sorting.
        indexedChunks = list(enumerate(chunks))
        indexedChunks.sort(key=lambda indexed: indexed[1])

        policy = self._getDuplicatePolicy(options)

        if policy == DUPLICATE_POLICY_ALLOW:
            chunks = [chunk for _, chunk in indexedChunks]

        else:
            chunks = []
            firstIndex = None
            previousChunk = None

            for index, chunk in indexedChunks:
                if previousChunk is not None and chunk == previousChunk:
                    if policy == DUPLICATE_POLICY_REJECT:
                        raise DuplicateSetOfElementError(index, firstIndex)

                    continue

                firstIndex = index
                previousChunk = chunk
                chunks.append(chunk)

        return b''.join(chunks), True, True


class SetEncoder(encoder.SetEncoder):
    @staticmethod
    def _componentSortKey(componentAndType):
        """Sort SET components by tag

        Sort depending on the actual Choice value (dynamic sort)
        """
        component, asn1Spec = componentAndType

        if asn1Spec is None:
            compType = component
        else:
            compType = asn1Spec

        if compType.typeId == univ.Choice.typeId and not compType.tagSet:
            if asn1Spec is None:
                return component.getComponent().tagSet
            else:
                # TODO: move out of sorting key function
                names = [namedType.name for namedType in asn1Spec.componentType.namedTypes
                         if namedType.name in component]
                if len(names) != 1:
                    raise error.PyAsn1Error(
                        '%s components for Choice at %r' % (len(names) and 'Multiple ' or 'None ', component))

                # TODO: support nested CHOICE ordering
                return asn1Spec[names[0]].tagSet

        else:
            return compType.tagSet


TAG_MAP = encoder.TAG_MAP.copy()

TAG_MAP.update({
    # Set & SetOf have same tags; SetOf is registered by typeId below
    univ.Set.tagSet: SetEncoder()
})

TYPE_MAP = encoder.TYPE_MAP.copy()

TYPE_MAP.update({
    # Set & SetOf have same tags
    univ.SetOf.typeId: SetOfEncoder(),
    univ.Set.typeId: SetEncoder()
})


class SingleItemEncoder(encoder.SingleItemEncoder):
    fixedDefLengthMode = True
    fixedChunkSize = 0

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP


class Encoder(encoder.Encoder):
    SINGLE_ITEM_ENCODER = SingleItemEncoder

    # None means "use SetOfEncoder.duplicatePolicy", which callers can
    # reconfigure without rebuilding the encoder maps.
    duplicatePolicy = None

    def __init__(self, *args, **kwargs):
        policy = kwargs.pop('duplicatePolicy', None)

        if policy is None:
            if 'deduplicate' in kwargs:
                policy = (DUPLICATE_POLICY_DEDUPE
                          if kwargs.pop('deduplicate')
                          else DUPLICATE_POLICY_ALLOW)

            elif 'allowDuplicates' in kwargs:
                policy = (DUPLICATE_POLICY_ALLOW
                          if kwargs.pop('allowDuplicates')
                          else DUPLICATE_POLICY_REJECT)

        if policy is not None:
            self.duplicatePolicy = _normalizeDuplicatePolicy(policy)

        encoder.Encoder.__init__(self, *args, **kwargs)

    def __call__(self, pyObject, asn1Spec=None, **options):
        if (not any(option in options for option in (
                'duplicatePolicy', 'deduplicate', 'allowDuplicates')) and
                self.duplicatePolicy is not None):
            options['duplicatePolicy'] = self.duplicatePolicy

        return encoder.Encoder.__call__(
            self, pyObject, asn1Spec=asn1Spec, **options)


#: Turns ASN.1 object into DER octet stream.
#:
#: Takes any ASN.1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#: walks all its components recursively and produces a DER octet stream.
#:
#: Parameters
#: ----------
#: value: either a Python or pyasn1 object (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     A Python or pyasn1 object to encode. If Python object is given, `asnSpec`
#:     parameter is required to guide the encoding process.
#:
#: Keyword Args
#: ------------
#: asn1Spec:
#:     Optional ASN.1 schema or value object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:
#: Returns
#: -------
#: : :py:class:`bytes`
#:     Given ASN.1 object encoded into BER octet-stream
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error
#:     On encoding errors
#:
#: Examples
#: --------
#: Encode Python value into DER with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> encode([1, 2, 3], asn1Spec=seq)
#:    b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'
#:
#: Encode ASN.1 value object into DER
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> seq.extend([1, 2, 3])
#:    >>> encode(seq)
#:    b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03'
#:
encode = Encoder()

def __getattr__(attr: str):
    if newAttr := {"tagMap": "TAG_MAP", "typeMap": "TYPE_MAP"}.get(attr):
        warnings.warn(f"{attr} is deprecated. Please use {newAttr} instead.", DeprecationWarning, stacklevel=2)
        return globals()[newAttr]
    raise AttributeError(attr)
