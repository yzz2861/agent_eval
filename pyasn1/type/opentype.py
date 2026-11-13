#
# This file is part of pyasn1 software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://pyasn1.readthedocs.io/en/latest/license.html
#

from pyasn1 import error

__all__ = ['OpenType', 'AmbiguousOpenTypeError']


class AmbiguousOpenTypeError(error.PyAsn1Error):
    """Open type selector resolved to more than one matching schema.

    The exception is raised when an explicit selector mapping offers
    multiple candidate schemas whose tags match the serialized value.
    Callers must not rely on the order in which candidates were
    registered with :class:`OpenType`.
    """


class OpenType(object):
    """Create ASN.1 type map indexed by a value

    The *OpenType* object models an untyped field of a constructed ASN.1
    type. In ASN.1 syntax it is usually represented by the
    `ANY DEFINED BY` for scalars or `SET OF ANY DEFINED BY`,
    `SEQUENCE OF ANY DEFINED BY` for container types clauses. Typically
    used together with :class:`~pyasn1.type.univ.Any` object.

    OpenType objects duck-type a read-only Python :class:`dict` objects,
    however the passed `typeMap` is not copied, but stored by reference.
    That means the user can manipulate `typeMap` at run time having this
    reflected on *OpenType* object behavior.

    The |OpenType| class models an untyped field of a constructed ASN.1
    type. In ASN.1 syntax it is usually represented by the
    `ANY DEFINED BY` for scalars or `SET OF ANY DEFINED BY`,
    `SEQUENCE OF ANY DEFINED BY` for container types clauses. Typically
    used with :class:`~pyasn1.type.univ.Any` type.

    Parameters
    ----------
    name: :py:class:`str`
        Field name

    typeMap: :py:class:`dict`
        A map of value->ASN.1 type. It's stored by reference and can be
        mutated later to register new mappings. A mapping value may also
        be a list, tuple or set of tag-distinguishable ASN.1 types for
        one selector value. Lookups never fall back to scanning other
        mapping entries by tag.

    Examples
    --------

    For untyped scalars:

    .. code-block:: python

        openType = OpenType(
            'id', {1: Integer(),
                   2: OctetString()}
        )
        Sequence(
            componentType=NamedTypes(
                NamedType('id', Integer()),
                NamedType('blob', Any(), openType=openType)
            )
        )

    For untyped `SET OF` or `SEQUENCE OF` vectors:

    .. code-block:: python

        openType = OpenType(
            'id', {1: Integer(),
                   2: OctetString()}
        )
        Sequence(
            componentType=NamedTypes(
                NamedType('id', Integer()),
                NamedType('blob', SetOf(componentType=Any()),
                          openType=openType)
            )
        )

    A selector value mapped to several candidates is disambiguated by the
    tag of the serialized value. Duplicate matching tags raise
    :class:`AmbiguousOpenTypeError`; registration order is not used.
    """

    def __init__(self, name, typeMap=None):
        self.__name = name
        if typeMap is None:
            self.__typeMap = {}
        else:
            self.__typeMap = typeMap

    @property
    def name(self):
        return self.__name

    # Python dict protocol

    def values(self):
        return self.__typeMap.values()

    def keys(self):
        return self.__typeMap.keys()

    def items(self):
        return self.__typeMap.items()

    def __contains__(self, key):
        return key in self.__typeMap

    def __getitem__(self, key):
        return self.__typeMap[key]

    def __iter__(self):
        return iter(self.__typeMap)

    @staticmethod
    def _isCandidateCollection(value):
        return isinstance(value, (list, tuple, set, frozenset))

    def getCandidates(self, selectorValue):
        """Return schema candidates explicitly mapped to *selectorValue*.

        A mapping value is normally a single ASN.1 schema. Values may also
        be a list, tuple or set of schemas when one selector value permits
        more than one tag-distinguishable alternative. In the latter case
        the caller has to select the candidate whose tag matches the
        serialized value.

        Returns an empty tuple if *selectorValue* is not present in the
        explicit map. No tag-based fallback is attempted.
        """
        try:
            mappedValue = self.__typeMap[selectorValue]

        except (KeyError, TypeError):
            return ()

        if self._isCandidateCollection(mappedValue):
            return tuple(mappedValue)

        return (mappedValue,)

    @staticmethod
    def _candidateMatchesTag(candidate, tagSet):
        try:
            if candidate.tagSet == tagSet:
                return True

        except AttributeError:
            return False

        try:
            return tagSet in candidate.tagMap

        except (AttributeError, error.PyAsn1Error):
            return False

    def resolve(self, selectorValue, tagSet=None):
        """Resolve an explicit selector value to a schema candidate.

        With a single candidate the schema is returned directly. With a
        collection of candidates *tagSet* is used to narrow the selection.
        More than one matching candidate is an error: registration order
        must never decide which schema is used.

        Returns :obj:`None` when the selector is not present in the
        explicit map or when no candidate matches the given *tagSet*.
        """
        candidates = self.getCandidates(selectorValue)

        if not candidates:
            return None

        if tagSet is None or len(candidates) == 1:
            return candidates[0]

        matches = [
            candidate for candidate in candidates
            if self._candidateMatchesTag(candidate, tagSet)
        ]

        if len(matches) == 1:
            return matches[0]

        if len(matches) > 1:
            descriptions = sorted(
                candidate.__class__.__name__ for candidate in matches
            )

            raise AmbiguousOpenTypeError(
                'Ambiguous open type selector %r: %d of %d candidate '
                'schemas match tag %s (%s); tag conflict; registration '
                'order must not decide the schema' % (
                    self.name, len(matches), len(candidates), tagSet,
                    ', '.join(descriptions)
                ),
                context={
                    'selector': self.name,
                    'candidates': len(candidates),
                    'matches': len(matches),
                    'tagSet': tagSet
                }
            )

        return None
