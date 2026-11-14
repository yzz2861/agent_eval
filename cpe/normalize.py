#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Canonical, reversible cross-version conversion between CPE 2.2 and
CPE 2.3 names.

The binding-specific classes (``CPE2_2``, ``CPE2_3_URI``, ``CPE2_3_FS`` and
``CPE2_3_WFN``) store the parsed components of a name, but they do not keep
track of the information that is lost when a value cannot be expressed in the
target binding.  In particular:

* a CPE 2.2 URI has no concept of the 2.3 logical value ``NA`` (``-`` is a
  legal 2.2 literal), so parsing the same URI through the two versions used
  to give two different names;
* the four extended 2.3 attributes (``sw_edition``, ``target_sw``,
  ``target_hw`` and ``other``) only fit in a 2.2 URI through the packed
  edition convention;
* a stray ``%`` is a literal character in 2.2 but the start of a percent
  encoding in 2.3.

This module introduces a single :class:`CanonicalName` representation built on
top of the eleven WFN attributes.  Every conversion keeps the values that the
target binding can express and records the rest as *losses* instead of
guessing a replacement.  All rendered names use the fixed attribute order of
the CPE specification, and comparisons follow the WFN set semantics rather
than plain string equality.
"""

from collections import OrderedDict
from collections import namedtuple
import re

from .comp.cpecomp import CPEComponent


# CPE language tag: 2-3 letter language with an optional two letter or three
# digit region, matching the validation shared by the 2.2 and 2.3 components.
_LANGUAGE_TAG_RE = re.compile(r"^[a-z]{2,3}(-([a-z]{2}|[0-9]{3}))?$")


# Logical values shared by every binding, expressed in their WFN form.
VALUE_ANY = "ANY"
VALUE_NA = "NA"

#: Attributes in the canonical (WFN) order defined by the CPE specification.
ATTRIBUTES = CPEComponent.CPE_COMP_KEYS_EXTENDED

#: Attributes that exist in a CPE 2.2 URI.
ATTRIBUTES_2_2 = CPEComponent.CPE_COMP_KEYS

#: Extended 2.3 attributes that are not first-class fields in a 2.2 URI.
EXTENDED_ATTRIBUTES = (
    CPEComponent.ATT_SW_EDITION,
    CPEComponent.ATT_TARGET_SW,
    CPEComponent.ATT_TARGET_HW,
    CPEComponent.ATT_OTHER,
)

URI_PREFIX = "cpe:/"
FS_PREFIX = "cpe:2.3:"
WFN_PREFIX = "wfn:["
WFN_SUFFIX = "]"
PACKED_SEPARATOR = "~"

# Percent encodings allowed in a CPE 2.3 URI (RFC 3986 unreserved set plus
# the printable punctuation required by the CPE 2.3 specification).
_URI_PCT_ENCODED = {
    "%21": "!", "%22": '"', "%23": "#", "%24": "$", "%25": "%",
    "%26": "&", "%27": "'", "%28": "(", "%29": ")", "%2a": "*",
    "%2b": "+", "%2c": ",", "%2f": "/", "%3a": ":", "%3b": ";",
    "%3c": "<", "%3d": "=", "%3e": ">", "%3f": "?", "%40": "@",
    "%5b": "[", "%5c": "\\", "%5d": "]", "%5e": "^", "%60": "`",
    "%7b": "{", "%7c": "|", "%7d": "}", "%7e": "~",
}
_URI_ENCODE = {
    value: encoding for encoding, value in _URI_PCT_ENCODED.items()
}

# Punctuation that must stay quoted when it appears in a WFN value.
_WFN_PUNCTUATION = set('!"#$%&\'()+,./:;<=>@[]^`{|}~')

# Attribute comparison relations used by the CPE 2.3 name matching rules.
_RELATION_SUPERSET = 1
_RELATION_SUBSET = 2
_RELATION_EQUAL = 3
_RELATION_DISJOINT = 4
_RELATION_UNDEFINED = 5


def _unquote_wfn(value):
    """Return the literal characters represented by an escaped WFN string."""

    result = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            result.append(value[index + 1])
            index += 2
        else:
            result.append(value[index])
            index += 1
    return "".join(result)


def _wfn_to_regex(value):
    """Translate a WFN attribute value into an exact matching regex.

    Escaped punctuation is matched literally, ``?`` matches one character and
    ``*`` matches any sequence of characters.  The pattern is anchored so that
    a partial match is never mistaken for a CPE match.
    """

    pieces = [r"\A"]
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            pieces.append(re.escape(value[index + 1]))
            index += 2
        elif char == "?":
            pieces.append(".")
            index += 1
        elif char == "*":
            pieces.append(".*")
            index += 1
        else:
            pieces.append(re.escape(char))
            index += 1
    pieces.append(r"\Z")
    return re.compile("".join(pieces), re.DOTALL | re.IGNORECASE)


def _compare_attribute(source, target):
    """Compare two canonical values of the same attribute."""

    if target not in (VALUE_ANY, VALUE_NA) and (
            "*" in target or "?" in target):
        # Wildcards in the target yield an undefined relation per the spec.
        return _RELATION_UNDEFINED

    if source == target:
        return _RELATION_EQUAL
    if source == VALUE_ANY:
        return _RELATION_SUPERSET
    if target == VALUE_ANY:
        return _RELATION_SUBSET
    if source == VALUE_NA or target == VALUE_NA:
        return _RELATION_DISJOINT

    source_literal = _unquote_wfn(source).lower()
    target_literal = _unquote_wfn(target).lower()
    if source_literal == target_literal:
        return _RELATION_EQUAL
    if "*" in source or "?" in source:
        if _wfn_to_regex(source).match(target):
            return _RELATION_SUPERSET
    return _RELATION_DISJOINT


class ConversionError(ValueError):
    """Base class for the errors raised by the canonical conversion layer."""


class InvalidCPEError(ConversionError):
    """Raised when an input name cannot be parsed in its declared binding."""


class UnrepresentableValueError(ConversionError):
    """
    Raised in strict mode when a canonical value has no representation in the
    requested binding.

    The matching :class:`InformationLoss` object is available as
    ``error.loss`` so callers can report exactly what could not be converted.
    """

    def __init__(self, loss):
        self.loss = loss
        super(UnrepresentableValueError, self).__init__(
            "{0}: {1}".format(loss.attribute, loss.reason))


class InformationLoss(namedtuple("InformationLoss",
                                 ("attribute", "reason", "value", "binding"))):
    """
    Description of a canonical value that cannot be represented in a binding.

    ``attribute`` is the WFN attribute name, ``value`` its canonical value
    and ``binding`` the target binding (``2.2``, ``2.3-uri``, ``2.3-fs`` or
    ``2.3-wfn``).  ``reason`` is a stable, machine-readable keyword.
    """

    __slots__ = ()


class ConversionResult(namedtuple("ConversionResult",
                                  ("index", "source", "output", "losses",
                                   "error"))):
    """
    Result of converting one item in a batch.

    ``output`` is the rendered target name when the conversion succeeded and
    ``None`` otherwise; ``losses`` lists the values that could not be carried
    over and ``error`` keeps the parsing/conversion exception of failures.
    """

    __slots__ = ()

    @property
    def ok(self):
        return self.error is None


# ---------------------------------------------------------------------------
# Binding specific (un)escaping helpers
# ---------------------------------------------------------------------------


def _decode_uri_value(encoded, allow_reserved_percent, attribute):
    """
    Decode a percent encoded URI component into a canonical WFN value.

    When ``allow_reserved_percent`` is True (CPE 2.2) a percent sign that is
    not part of a recognised encoding is a literal character.  In a 2.3 URI
    the same sequence is invalid and raises :class:`InvalidCPEError`.
    """

    result = []
    index = 0
    while index < len(encoded):
        char = encoded[index]

        if char in (".", "-", "~"):
            result.append("\\")
            result.append(char)
            index += 1
            continue

        if char != "%":
            result.append(char)
            index += 1
            continue

        form = encoded[index:index + 3].lower()
        if form == "%01":
            result.append("?")
            index += 3
            continue
        if form == "%02":
            result.append("*")
            index += 3
            continue
        if form in _URI_PCT_ENCODED:
            decoded = _URI_PCT_ENCODED[form]
            if decoded in _WFN_PUNCTUATION or decoded == "\\":
                result.append("\\")
            result.append(decoded)
            index += 3
            continue

        if allow_reserved_percent:
            # In CPE 2.2 the percent sign is an ordinary character.  Keep it
            # quoted in the canonical value so that a later 2.3 rendering
            # percent-encodes it instead of treating it as an escape.
            result.append("\\%")
            index += 1
            continue

        raise InvalidCPEError(
            "Invalid percent encoding in attribute '{0}': {1}".format(
                attribute, encoded))

    return "".join(result)


def _encode_uri_value(canonical):
    """Render a canonical WFN value as a CPE 2.3 URI component."""

    result = []
    index = 0
    while index < len(canonical):
        char = canonical[index]

        if char == "\\":
            if index + 1 >= len(canonical):
                raise InvalidCPEError("Trailing escape in canonical value")
            quoted = canonical[index + 1]
            if quoted in (".", "-", "~"):
                result.append(quoted)
            else:
                result.append(_URI_ENCODE[quoted])
            index += 2
            continue

        if char in ("?", "*"):
            result.append("%01" if char == "?" else "%02")
        else:
            result.append(char)
        index += 1

    return "".join(result)


def _decode_fs_value(encoded, attribute):
    """Decode a formatted string component into a canonical WFN value."""

    result = []
    index = 0
    while index < len(encoded):
        char = encoded[index]

        if char == "\\":
            if index + 1 >= len(encoded):
                raise InvalidCPEError(
                    "Trailing escape in attribute '{0}'".format(attribute))
            result.append(encoded[index:index + 2])
            index += 2
            continue

        if char.isalnum() or char == "_":
            result.append(char)
            index += 1
            continue

        if char in ("-", "."):
            # Punctuation that is unquoted in a formatted string still needs
            # quoting in the canonical WFN value.
            result.append("\\")
            result.append(char)
            index += 1
            continue

        if char in ("?", "*"):
            result.append(char)
            index += 1
            continue

        # Every other unquoted character is invalid in a formatted string.
        raise InvalidCPEError(
            "Unquoted special character in attribute '{0}': {1}".format(
                attribute, char))

    return "".join(result)


def _encode_fs_value(canonical):
    """Render a canonical WFN value as a formatted string component."""

    result = []
    index = 0
    while index < len(canonical):
        char = canonical[index]

        if char == "\\":
            if index + 1 >= len(canonical):
                raise InvalidCPEError("Trailing escape in canonical value")
            quoted = canonical[index + 1]
            if quoted in (".", "-", "_"):
                # These punctuation marks are not escaped in formatted
                # strings, even though they stay quoted in the WFN.
                result.append(quoted)
            else:
                result.append(canonical[index:index + 2])
            index += 2
            continue

        result.append(char)
        index += 1

    return "".join(result)


def _decode_wfn_value(encoded, attribute):
    """Validate and normalize the quoted string body of a WFN attribute."""

    result = []
    index = 0
    while index < len(encoded):
        char = encoded[index]

        if char == "\\":
            if index + 1 >= len(encoded):
                raise InvalidCPEError(
                    "Trailing escape in attribute '{0}'".format(attribute))
            result.append(encoded[index:index + 2])
            index += 2
            continue

        if char in ('"',):
            raise InvalidCPEError(
                "Unquoted double quote in attribute '{0}'".format(attribute))

        result.append(char)
        index += 1

    return "".join(result)


def _split_uri(uri):
    """Split a ``cpe:/`` URI into its seven positional field strings."""

    if not uri.startswith(URI_PREFIX):
        raise InvalidCPEError("URI must start with '{0}'".format(URI_PREFIX))

    body = uri[len(URI_PREFIX):]
    if " " in body:
        raise InvalidCPEError("CPE URIs must not contain whitespace")

    fields = body.split(":")
    if len(fields) > 7:
        raise InvalidCPEError("URI has more than seven components")
    fields.extend([None] * (7 - len(fields)))
    return fields


def _unpack_edition(packed):
    """Split a ``~ed~sw~ts~th~other`` packed edition into five values."""

    parts = packed.split(PACKED_SEPARATOR)
    if len(parts) != 6 or parts[0] != "":
        raise InvalidCPEError(
            "Packed edition must contain five tilde delimited values")
    return parts[1:]


def _is_valid_part(value):
    return value in ("h", "o", "a")


# ---------------------------------------------------------------------------
# Canonical name
# ---------------------------------------------------------------------------


class CanonicalName(object):
    """
    Binding independent representation of a CPE name.

    The eleven attributes are kept in the fixed WFN order.  A concrete
    attribute holds its escaped WFN string (without the surrounding quotes);
    logical attributes hold :data:`VALUE_ANY` or :data:`VALUE_NA`.
    """

    def __init__(self, values=None, losses=None):
        attributes = OrderedDict((att, VALUE_ANY) for att in ATTRIBUTES)
        if values is not None:
            for att, value in values.items():
                if att not in attributes:
                    raise InvalidCPEError("Unknown attribute '{0}'".format(att))
                attributes[att] = value

        part = attributes[CPEComponent.ATT_PART]
        if part != VALUE_ANY and not _is_valid_part(part):
            raise InvalidCPEError(
                "Invalid part value '{0}'".format(part))

        language = attributes[CPEComponent.ATT_LANGUAGE]
        if language not in (VALUE_ANY, VALUE_NA) and \
                _LANGUAGE_TAG_RE.match(_unquote_wfn(language)) is None:
            raise InvalidCPEError(
                "Invalid language tag '{0}'".format(language))

        self._attributes = attributes
        self.losses = list(losses or ())

    # -- introspection -----------------------------------------------------

    @property
    def attributes(self):
        return OrderedDict(self._attributes)

    def get(self, attribute):
        return self._attributes[attribute]

    def __eq__(self, other):
        if not isinstance(other, CanonicalName):
            return NotImplemented
        return self._attributes == other._attributes

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(tuple(self._attributes.items()))

    def __repr__(self):
        return "CanonicalName({0})".format(dict(self._attributes))

    def __getitem__(self, attribute):
        return self._attributes[attribute]

    # -- parsing -----------------------------------------------------------

    @classmethod
    def from_cpe_2_2(cls, uri):
        """
        Parse a CPE 2.2 URI.

        Empty and omitted 2.2 fields become :data:`VALUE_ANY`.  A hyphen is a
        legal 2.2 literal, so it is kept as a quoted value rather than being
        promoted to ``NA``; the cross-version ambiguity is recorded as a loss
        marker instead of silently changing the semantics.
        """

        fields = _split_uri(uri)
        part_field = fields[0] or VALUE_ANY
        if part_field != VALUE_ANY and not _is_valid_part(part_field):
            raise InvalidCPEError("Invalid part value '{0}'".format(part_field))

        values = OrderedDict()
        packed_edition = False
        for att, field in zip(ATTRIBUTES_2_2, fields):
            if field is None or field == "":
                values[att] = VALUE_ANY
            elif att == CPEComponent.ATT_EDITION and \
                    field.startswith(PACKED_SEPARATOR):
                # A leading tilde is the packed edition convention.  It is a
                # 2.3 binding feature, but accepting it here keeps the
                # cross-version transformation reversible while the explicit
                # loss marker records that 2.2 itself has no such semantics.
                packed_edition = True
                packed = (
                    CPEComponent.ATT_EDITION,
                    CPEComponent.ATT_SW_EDITION,
                    CPEComponent.ATT_TARGET_SW,
                    CPEComponent.ATT_TARGET_HW,
                    CPEComponent.ATT_OTHER,
                )
                for packed_att, packed_value in zip(
                        packed, _unpack_edition(field)):
                    values[packed_att] = cls._uri_field_to_value(
                        packed_att, packed_value)
            else:
                values[att] = _decode_uri_value(
                    field, allow_reserved_percent=True, attribute=att)

        for att in ATTRIBUTES:
            values.setdefault(att, VALUE_ANY)

        losses = []
        if packed_edition:
            losses.append(InformationLoss(
                attribute=CPEComponent.ATT_EDITION,
                reason="packed_edition_is_2_3_convention",
                value=fields[ATTRIBUTES_2_2.index(CPEComponent.ATT_EDITION)],
                binding="2.2"))
        for att, field in zip(ATTRIBUTES_2_2, fields):
            if field == "-":
                losses.append(InformationLoss(
                    attribute=att,
                    reason="hyphen_literal_in_2_2",
                    value=values[att],
                    binding="2.3-uri"))

        return cls(values, losses=losses)

    @classmethod
    def from_cpe_2_3_uri(cls, uri):
        """Parse a CPE 2.3 URI binding (the seven-field ``cpe:/`` form)."""

        fields = _split_uri(uri)
        values = OrderedDict((att, VALUE_ANY) for att in ATTRIBUTES)

        for index, att in enumerate(ATTRIBUTES_2_2):
            field = fields[index]
            if field is None or field == "":
                values[att] = VALUE_ANY
            elif field == "-":
                values[att] = VALUE_NA
            else:
                if att == CPEComponent.ATT_EDITION and field.startswith(
                        PACKED_SEPARATOR):
                    edition, sw_edition, target_sw, target_hw, other = \
                        _unpack_edition(field)
                    packed = (
                        CPEComponent.ATT_EDITION,
                        CPEComponent.ATT_SW_EDITION,
                        CPEComponent.ATT_TARGET_SW,
                        CPEComponent.ATT_TARGET_HW,
                        CPEComponent.ATT_OTHER,
                    )
                    for packed_att, packed_value in zip(packed, (
                            edition, sw_edition, target_sw, target_hw, other)):
                        values[packed_att] = cls._uri_field_to_value(
                            packed_att, packed_value)
                else:
                    values[att] = cls._uri_field_to_value(att, field)

        return cls(values)

    @staticmethod
    def _uri_field_to_value(attribute, field):
        if field is None or field == "":
            return VALUE_ANY
        if field == "-":
            return VALUE_NA
        return _decode_uri_value(
            field, allow_reserved_percent=False, attribute=attribute)

    @classmethod
    def from_cpe_2_3_fs(cls, formatted_string):
        """Parse an eleven-field CPE 2.3 formatted string."""

        if not formatted_string.startswith(FS_PREFIX):
            raise InvalidCPEError(
                "Formatted string must start with '{0}'".format(FS_PREFIX))
        if " " in formatted_string:
            raise InvalidCPEError(
                "Formatted strings must not contain whitespace")

        fields = formatted_string[len(FS_PREFIX):].split(":")
        if len(fields) != 11:
            raise InvalidCPEError(
                "Formatted string must contain eleven components")

        values = OrderedDict()
        for att, field in zip(ATTRIBUTES, fields):
            if field == "*":
                values[att] = VALUE_ANY
            elif field == "-":
                values[att] = VALUE_NA
            else:
                values[att] = _decode_fs_value(field, att)

        return cls(values)

    @classmethod
    def from_cpe_2_3_wfn(cls, wfn):
        """Parse a well-formed name."""

        if not (wfn.startswith(WFN_PREFIX) and wfn.endswith(WFN_SUFFIX)):
            raise InvalidCPEError("Malformed WFN prefix or suffix")

        content = wfn[len(WFN_PREFIX):-len(WFN_SUFFIX)]
        values = OrderedDict((att, VALUE_ANY) for att in ATTRIBUTES)
        if not content:
            return cls(values)

        for pair in content.split(", "):
            if "=" not in pair:
                raise InvalidCPEError("Malformed WFN attribute pair")
            att, raw_value = pair.split("=", 1)
            if att not in values:
                raise InvalidCPEError("Unknown WFN attribute '{0}'".format(att))

            if raw_value == VALUE_ANY:
                values[att] = VALUE_ANY
            elif raw_value == VALUE_NA:
                values[att] = VALUE_NA
            elif len(raw_value) >= 2 and raw_value[0] == '"' and \
                    raw_value[-1] == '"':
                values[att] = _decode_wfn_value(raw_value[1:-1], att)
            else:
                raise InvalidCPEError(
                    "Invalid WFN value for attribute '{0}': {1}".format(
                        att, raw_value))

        return cls(values)

    @classmethod
    def from_string(cls, name, version=None):
        """
        Parse a CPE name using an explicit binding or, when ``version`` is
        ``None``, the unambiguous prefix of the input string.
        """

        if version in ("2.3", "2.3-uri", "uri"):
            return cls.from_cpe_2_3_uri(name)
        if version in ("2.3-fs", "fs"):
            return cls.from_cpe_2_3_fs(name)
        if version in ("2.3-wfn", "wfn"):
            return cls.from_cpe_2_3_wfn(name)
        if version in ("2.2",):
            return cls.from_cpe_2_2(name)
        if version is not None:
            raise InvalidCPEError("Unsupported CPE binding '{0}'".format(version))

        if name.startswith(FS_PREFIX):
            return cls.from_cpe_2_3_fs(name)
        if name.startswith(WFN_PREFIX):
            return cls.from_cpe_2_3_wfn(name)
        if name.startswith(URI_PREFIX):
            # A cpe:/ URI is ambiguous across versions.  Default to the
            # explicit 2.2 reading; callers needing 2.3 semantics pass the
            # version explicitly.
            return cls.from_cpe_2_2(name)
        raise InvalidCPEError("Unable to detect binding of '{0}'".format(name))

    # -- rendering ---------------------------------------------------------

    def as_cpe_2_3_uri(self):
        """Render the canonical name as a CPE 2.3 URI without information
        loss (all eleven WFN values are representable in this binding)."""

        fields = []
        for att in ATTRIBUTES_2_2:
            value = self._attributes[att]
            if value == VALUE_ANY:
                fields.append("")
            elif value == VALUE_NA:
                fields.append("-")
            else:
                fields.append(_encode_uri_value(value))

        edition = self._packed_edition()
        if edition is not None:
            fields[ATTRIBUTES_2_2.index(CPEComponent.ATT_EDITION)] = edition

        uri = URI_PREFIX + ":".join(fields)
        return self._trim_uri(uri)

    def _packed_edition(self):
        extended = [self._attributes[att] for att in (
            CPEComponent.ATT_EDITION,
            CPEComponent.ATT_SW_EDITION,
            CPEComponent.ATT_TARGET_SW,
            CPEComponent.ATT_TARGET_HW,
            CPEComponent.ATT_OTHER,
        )]
        if all(value == VALUE_ANY for value in extended[1:]):
            return None

        parts = [""]
        for value in extended:
            if value == VALUE_ANY:
                parts.append("")
            elif value == VALUE_NA:
                parts.append("-")
            else:
                parts.append(_encode_uri_value(value))
        parts.append("")
        return PACKED_SEPARATOR.join(parts[:-1])

    @staticmethod
    def _trim_uri(uri):
        return uri.rstrip(":")

    def as_cpe_2_3_fs(self):
        """Render the canonical name as an eleven-field formatted string."""

        fields = []
        for att in ATTRIBUTES:
            value = self._attributes[att]
            if value == VALUE_ANY:
                fields.append("*")
            elif value == VALUE_NA:
                fields.append("-")
            else:
                fields.append(_encode_fs_value(value))
        return FS_PREFIX + ":".join(fields)

    def as_cpe_2_3_wfn(self):
        """Render the canonical name as a well-formed name."""

        pairs = []
        for att in ATTRIBUTES:
            value = self._attributes[att]
            if value == VALUE_ANY:
                continue
            if value == VALUE_NA:
                pairs.append("{0}={1}".format(att, VALUE_NA))
            else:
                pairs.append('{0}="{1}"'.format(att, value))
        return WFN_PREFIX + ", ".join(pairs) + WFN_SUFFIX

    def as_cpe_2_2(self, strict=True):
        """
        Render the canonical name as a CPE 2.2 URI.

        Values that cannot be expressed in 2.2 are reported as
        :class:`InformationLoss` objects.  In strict mode the first such value
        raises :class:`UnrepresentableValueError`; otherwise the unrepresentable
        fields are omitted (logical ANY) and every loss is returned together
        with the rendered name.
        """

        losses = self._losses_in_2_2()

        if strict and losses:
            raise UnrepresentableValueError(losses[0])

        rendered = self._render_2_2_uri()
        return rendered, losses

    def _losses_in_2_2(self):
        """Return the values that have no legal CPE 2.2 representation.

        The four extended 2.3 attributes are carried by the packed edition
        convention (``~edition~sw_edition~target_sw~target_hw~other``), so
        they only count as losses when their value (NA or a wildcard) cannot
        be packed.
        """

        losses = []
        for att in ATTRIBUTES:
            value = self._attributes[att]
            if value == VALUE_NA:
                losses.append(InformationLoss(
                    att, "na_not_defined_in_2_2", value, "2.2"))
            elif value != VALUE_ANY and any(
                    char in value for char in ("?", "*")):
                losses.append(InformationLoss(
                    att, "wildcard_not_defined_in_2_2", value, "2.2"))
        return losses

    def _render_2_2_uri(self):
        fields = []
        for att in ATTRIBUTES_2_2:
            value = self._attributes[att]
            if att == CPEComponent.ATT_EDITION and self._has_packed_extension():
                fields.append(self._render_2_2_edition())
            elif value == VALUE_ANY or value == VALUE_NA:
                fields.append("")
            elif any(char in value for char in ("?", "*")):
                fields.append("")
            else:
                fields.append(_encode_uri_value(value))

        # Preserve explicitly empty middle components up to the last concrete
        # value, then trim trailing empty components for a stable canonical
        # 2.2 URI.  Keeping the leading separators makes the position of each
        # remaining field (including a packed edition in field 6) unambiguous.
        last_concrete = -1
        for index, att in enumerate(ATTRIBUTES_2_2):
            if self._attribute_has_value(att):
                last_concrete = index
        fields = fields[:last_concrete + 1]
        return URI_PREFIX + ":".join(fields)

    def _attribute_has_value(self, attribute):
        if self._attributes[attribute] != VALUE_ANY:
            return True
        if attribute == CPEComponent.ATT_EDITION:
            return self._has_packed_extension()
        return False

    def _has_packed_extension(self):
        return any(
            self._attributes[att] != VALUE_ANY
            for att in EXTENDED_ATTRIBUTES)

    def _render_2_2_edition(self):
        """Render edition, packing the extended attributes when needed."""

        edition = self._attributes[CPEComponent.ATT_EDITION]
        extended = [self._attributes[att] for att in EXTENDED_ATTRIBUTES]

        if all(value == VALUE_ANY for value in extended):
            if edition == VALUE_ANY:
                return ""
            return _encode_uri_value(edition)

        values = [edition] + extended
        parts = [""]
        for value in values:
            if value == VALUE_ANY:
                parts.append("")
            elif value == VALUE_NA or any(
                    char in value for char in ("?", "*")):
                # Unpackable value: keep the field blank and surface the loss
                # through _losses_in_2_2 instead of guessing an encoding.
                parts.append("")
            else:
                parts.append(_encode_uri_value(value))
        return PACKED_SEPARATOR.join(parts)

    # -- canonical comparison ----------------------------------------------

    def is_equal(self, other):
        """Return True when both names have identical WFN attribute values."""

        self._check_canonical(other)
        return self._attributes == other._attributes

    def is_subset(self, other):
        """CPE 2.3 subset relation: every attribute of ``self`` is matched by
        the corresponding attribute of ``other`` (other is more general)."""

        return self._compare(other, expect_superset=False)

    def is_superset(self, other):
        """CPE 2.3 superset relation: ``self`` matches every name matched by
        ``other`` (self is more general)."""

        return self._compare(other, expect_superset=True)

    def matches(self, candidate):
        """Return True when ``self`` (typically a known, more general name)
        matches the candidate name according to the CPE 2.3 attribute rules."""

        self._check_canonical(candidate)
        return self.is_superset(candidate)

    @staticmethod
    def _check_canonical(other):
        if not isinstance(other, CanonicalName):
            raise TypeError("comparison requires a CanonicalName instance")

    def _compare(self, other, expect_superset):
        self._check_canonical(other)
        for att in ATTRIBUTES:
            source = self._attributes[att]
            target = other._attributes[att]
            relation = _compare_attribute(source, target)
            if relation == _RELATION_DISJOINT:
                return False
            if relation == _RELATION_UNDEFINED:
                # An undefined relation cannot prove the requested set
                # containment; do not fall back to loose ANY matching.
                return False
            if expect_superset:
                if relation not in (_RELATION_EQUAL, _RELATION_SUPERSET):
                    return False
            else:
                if relation not in (_RELATION_EQUAL, _RELATION_SUBSET):
                    return False
        return True


# ---------------------------------------------------------------------------
# Module level conversion helpers
# ---------------------------------------------------------------------------

def parse(name, version=None):
    """Parse a CPE name string into a :class:`CanonicalName`."""

    return CanonicalName.from_string(name, version=version)


def convert_2_2_to_2_3(uri, binding="uri"):
    """
    Convert a CPE 2.2 URI to a 2.3 binding.

    ``binding`` selects ``uri``, ``fs`` or ``wfn``.  The returned tuple is
    ``(rendered_name, canonical_name, losses)``; losses are limited to the
    documented 2.2/2.3 hyphen ambiguity because all 2.2 values are otherwise
    representable in 2.3.
    """

    canonical = CanonicalName.from_cpe_2_2(uri)
    rendered = _render(canonical, binding)
    return rendered, canonical, canonical.losses


def convert_2_3_to_2_2(name, version=None, strict=True):
    """
    Convert a CPE 2.3 name (URI, formatted string or WFN) to a 2.2 URI.

    Returns ``(uri, canonical_name, losses)``.  Unrepresentable values raise
    :class:`UnrepresentableValueError` in strict mode; otherwise they are
    dropped to logical ANY and returned in ``losses``.
    """

    canonical = CanonicalName.from_string(name, version=version)
    uri, losses = canonical.as_cpe_2_2(strict=strict)
    return uri, canonical, losses


def _render(canonical, binding):
    if binding in ("uri", "2.3-uri"):
        return canonical.as_cpe_2_3_uri()
    if binding in ("fs", "2.3-fs"):
        return canonical.as_cpe_2_3_fs()
    if binding in ("wfn", "2.3-wfn"):
        return canonical.as_cpe_2_3_wfn()
    raise InvalidCPEError("Unsupported target binding '{0}'".format(binding))


def convert_batch(names, source_version=None, target_binding="2.2",
                  strict=False):
    """
    Convert a batch of CPE names with per-item failure location.

    Each input is converted independently, so a single malformed name never
    aborts the batch.  The returned :class:`BatchReport` exposes the
    successful outputs, the indexed failures and every information loss; this
    gives callers an explicit partial-success report instead of a binary
    pass/fail.
    """

    results = []
    for index, name in enumerate(names):
        result = _convert_one(index, name, source_version, target_binding,
                              strict)
        results.append(result)
    return BatchReport(results)


def _convert_one(index, name, source_version, target_binding, strict):
    try:
        canonical = CanonicalName.from_string(name, version=source_version)
        if target_binding == "2.2":
            output, losses = canonical.as_cpe_2_2(strict=strict)
        else:
            output = _render(canonical, target_binding)
            losses = list(canonical.losses)
        return ConversionResult(index=index, source=name, output=output,
                                losses=tuple(losses), error=None)
    except ConversionError as error:
        return ConversionResult(index=index, source=name, output=None,
                                losses=(), error=error)


class BatchReport(object):
    """Partial-success report for :func:`convert_batch`."""

    def __init__(self, results):
        self.results = list(results)

    @property
    def successes(self):
        return [result for result in self.results if result.ok]

    @property
    def failures(self):
        return [result for result in self.results if not result.ok]

    @property
    def losses(self):
        report = []
        for result in self.results:
            for loss in result.losses:
                report.append((result.index, loss))
        return report

    @property
    def output_names(self):
        return [result.output for result in self.successes]

    def __len__(self):
        return len(self.results)

    def __iter__(self):
        return iter(self.results)

    def __getitem__(self, index):
        return self.results[index]
