#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This file is part of cpe package.

This module allows to store the value of the components of a CPE name
of version 2.3 of CPE (Common Platform Enumeration) specification
with Universal Resource Identifier (URI) style.

Copyright (C) 2013  Alejandro Galindo García, Roberto Abdelkader Martínez Pérez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

For any problems using the cpe package, or general questions and
feedback about it, please contact:

- Alejandro Galindo García: galindo.garcia.alejandro@gmail.com
- Roberto Abdelkader Martínez Pérez: robertomartinezp@gmail.com
"""

from .cpecomp2_3 import CPEComponent2_3
from .cpecomp2_3_wfn import CPEComponent2_3_WFN
from .cpecomp import CPEComponent

import re


class CPEComponent2_3_URI(CPEComponent2_3):
    """
    Represents a component of version 2.3 of CPE specification with URI style.
    """

    ###############
    #  CONSTANTS  #
    ###############

    #: Separator of components of CPE name with URI style
    SEPARATOR_COMP = ":"

    #: Separator of language parts: language and region
    SEPARATOR_LANG = "-"

    #: Separator of edition part components in CPE uri
    SEPARATOR_PACKED_EDITION = "~"

    # Logical values in string format

    #: Logical value associated with a any value logical value
    VALUE_ANY = ""

    #: Logical value associated with a not applicable logical value
    VALUE_NA = "-"

    #: Logical value associated with a component without value
    VALUE_EMPTY = ""

    #: Logical value associated with a undefined component
    VALUE_UNDEFINED = None

    #: Constant associated with a wildcard to indicate a sequence of chars
    WILDCARD_MULTI = "%02"
    #: Constant associated with a wildcard to indicate a character
    WILDCARD_ONE = "%01"

    #: Maximum allowed length of a single component value
    MAX_COMPONENT_LENGTH = 4096

    ###############
    #  VARIABLES  #
    ###############

    #: Characters to convert to percent-encoded characters
    char_to_pce = {
        '!': "%21",
        '"': "%22",
        '#': "%23",
        '$': "%24",
        '%': "%25",
        '&': "%26",
        '\'': "%27",
        '(': "%28",
        ')': "%29",
        '*': "%2a",
        '+': "%2b",
        ',': "%2c",
        '/': "%2f",
        ':': "%3a",
        ';': "%3b",
        '<': "%3c",
        '=': "%3d",
        '>': "%3e",
        '?': "%3f",
        '@': "%40",
        '[': "%5b",
        '\\': "%5c",
        ']': "%5d",
        '^': "%5e",
        '`': "%60",
        '{': "%7b",
        '|': "%7c",
        '}': "%7d",
        '~': "%7e"}

    #: Percent-encoded characters to decode, kept for backwards compatibility
    pce_char_to_decode = {
        "%21": '\\!',
        "%22": '\\\"',
        "%23": '\\#',
        "%24": '\\$',
        "%25": '\\%',
        "%26": '\\&',
        "%27": "\\'",
        "%28": '\\(',
        "%29": '\\)',
        "%2a": '\\*',
        "%2b": '\\+',
        "%2c": '\\,',
        "%2f": '\\/',
        "%3a": '\\:',
        "%3b": '\\;',
        "%3c": '\\<',
        "%3d": '\\=',
        "%3e": '\\>',
        "%3f": '\\?',
        "%40": '\\@',
        "%5b": '\\[',
        "%5c": '\\\\',
        "%5d": '\\]',
        "%5e": '\\^',
        "%60": '\\`',
        "%7b": '\\{',
        "%7c": '\\|',
        "%7d": '\\}',
        "%7e": '\\~'}

    # Reverse mapping of the allowed percent-encoded punctuation, used by the
    # single-pass decoder. Only the encodings declared in the CPE 2.3 URI
    # binding are legal; everything else (including '%41', '%00', '%zz' and
    # dangling '%') is rejected with its offset.
    _PCE_TO_CHAR = dict((key, value[1:])
                        for key, value in pce_char_to_decode.items())

    _HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

    # Characters that may appear unencoded in an URI attribute value.
    _UNRESERVED_RE = re.compile(r"^[A-Za-z0-9_\.\-]+$")

    # Backwards-compatible validation pattern. The strict decoder below is
    # authoritative; this pattern is retained so external callers keep a
    # working class attribute.
    _PCT_ENCODED = ("%21|%22|%23|%24|%25|%26|%27|%28|%29|%2a|%2b|%2c|%2f|%3a|"
                    "%3b|%3c|%3d|%3e|%3f|%40|%5b|%5c|%5d|%5e|%60|%7b|%7c|%7d|%7e")
    _SPEC_CHRS = "((%01)+|%02)"
    _UNRESERVED = r"[\w\-\.]"
    _str_w_special = "({0}?({1}|{2})+{3}?)".format(_SPEC_CHRS, _UNRESERVED,
                                                   _PCT_ENCODED, _SPEC_CHRS)
    _str_wo_special = "({0}|{1})*".format(_UNRESERVED, _PCT_ENCODED)
    _string = "({0}|{1})".format(_str_wo_special, _str_w_special)
    _value_pattern = "^{0}$".format(_string)
    _value_rxc = re.compile(_value_pattern)

    ####################
    #  OBJECT METHODS  #
    ####################

    def _decode(self):
        """
        Convert the URI-encoded component value to its standard (WFN) value
        in a single pass and return the decoded string.

        Every percent-encoded sequence is consumed exactly once, therefore a
        sequence such as '%252a' is decoded to the quoted literal '\\%2a'
        instead of being decoded twice into an unquoted wildcard. Wildcards
        ('%01'/'%02') are only accepted at the positions allowed by the CPE
        2.3 URI binding.

        :returns: the standard (WFN) value of the component
        :rtype: string
        :exception: ValueError - invalid character or encoding in the value,
            the message identifies the attribute and the offset
        """

        encoded = self._encoded_value
        result = []
        idx = 0
        length = len(encoded)
        # True once an ordinary (non leading-wildcard) character was seen.
        embedded = False

        while idx < length:
            char = encoded[idx]

            if char == '%':
                form = encoded[idx:idx + 3]
                if (len(form) != 3 or form[1] not in self._HEX_DIGITS or
                        form[2] not in self._HEX_DIGITS):
                    self._raise_decode_error(
                        idx, "malformed percent-encoded sequence {0!r}".format(
                            encoded[idx:idx + 3]))

                if form == self.WILDCARD_ONE:
                    self._check_wildcard_one(encoded, idx, embedded)
                    result.append(CPEComponent2_3_WFN.WILDCARD_ONE)
                    idx += 3
                    # '%01' sequences may be embedded only in groups and
                    # 'embedded' is toggled again when the group ends.
                    if idx >= length or encoded[idx:idx + 3] != self.WILDCARD_ONE:
                        embedded = True
                    continue

                if form == self.WILDCARD_MULTI:
                    if idx != 0 and idx != length - 3:
                        self._raise_decode_error(
                            idx, "wildcard '%02' is only allowed at the "
                                 "beginning or end of a component")
                    result.append(CPEComponent2_3_WFN.WILDCARD_MULTI)
                    idx += 3
                    embedded = True
                    continue

                decoded = self._PCE_TO_CHAR.get(form.lower())
                if decoded is None:
                    self._raise_decode_error(
                        idx, "percent-encoded sequence {0!r} is not allowed "
                             "in a CPE 2.3 URI component".format(form))

                # Quoted punctuation always keeps its backslash in WFN form.
                result.append("\\")
                result.append(decoded)
                idx += 3
                embedded = True
                continue

            if char in (".", "-"):
                # In WFN form the unreserved punctuation characters '.' and
                # '-' must be quoted with a backslash.
                result.append("\\")
                result.append(char)
                idx += 1
                embedded = True
                continue

            if char == "~":
                # The tilde is the packed-edition separator and therefore a
                # raw tilde is never legal in a simple component value.
                self._raise_decode_error(
                    idx, "reserved character '~' must be percent-encoded "
                         "in a CPE 2.3 URI component")

            if not self._is_unreserved(char):
                self._raise_decode_error(
                    idx, "character {0!r} is not allowed in a CPE 2.3 URI "
                         "component".format(char))

            result.append(char)
            idx += 1
            embedded = True

        return "".join(result)

    def _check_wildcard_one(self, encoded, idx, embedded):
        """Validate the placement of a '%01' wildcard."""

        length = len(encoded)
        at_boundary = idx == 0 or idx == length - 3
        follows_question = (
            not embedded and
            encoded[idx - 3:idx] == self.WILDCARD_ONE)
        precedes_question = (
            embedded and length >= idx + 6 and
            encoded[idx + 3:idx + 6] == self.WILDCARD_ONE)

        if at_boundary or follows_question or precedes_question:
            return

        self._raise_decode_error(
            idx, "wildcard '%01' is only allowed at the beginning or end, "
                 "or inside a contiguous group of '%01' sequences")

    def _raise_decode_error(self, offset, reason):
        """Raise an error that pinpoints the component and the offset."""

        msg = "Invalid value of attribute '{0}' at offset {1}: {2}".format(
            getattr(self, '_component_attribute', 'unknown'), offset, reason)
        raise ValueError(msg)

    @classmethod
    def _is_unreserved(cls, char):
        """Return True if char is an unreserved URI character."""

        return cls._UNRESERVED_RE.match(char) is not None

    def _is_valid_edition(self):
        """
        Return True if the input value of attribute "edition" is valid.

        A packed edition (a value beginning with '~') is validated through
        the packed structure check; ordinary values use the generic grammar.
        """

        if self._encoded_value.startswith(self.SEPARATOR_PACKED_EDITION):
            return self._is_valid_packed_edition(self._encoded_value)

        return self._is_valid_value()

    @classmethod
    def _is_valid_packed_edition(cls, value):
        """Check the structure of a packed edition value."""

        fields = value.split(cls.SEPARATOR_PACKED_EDITION)
        # A packed edition looks like '~e~sw~ts~th~o', so splitting on '~'
        # yields exactly six elements, the first one being empty.
        return len(fields) == 6 and fields[0] == ""

    def _is_valid_value(self):
        """
        Structural check of the raw component value.

        The authoritative, offset-aware validation happens in the single
        :meth:`_decode` pass; this method only verifies the conditions that
        do not require decoding (non-empty value, maximum length and the
        allowed character set).
        """

        value = self._encoded_value

        if not value or len(value) > self.MAX_COMPONENT_LENGTH:
            return False

        for offset, char in enumerate(value):
            if char == '%' or self._is_unreserved(char):
                continue
            return False

        return True

    def _validate_structure(self, comp_att):
        """
        Validate every structural rule that can be checked without decoding,
        raising an offset-aware error instead of a boolean result.

        :param string comp_att: attribute associated with the value
        :exception: ValueError - incorrect value of component
        """

        value = self._encoded_value

        if not value:
            raise ValueError(
                "Invalid value of attribute '{0}': empty components are not "
                "allowed".format(comp_att))

        if len(value) > self.MAX_COMPONENT_LENGTH:
            raise ValueError(
                "Invalid value of attribute '{0}': component length {1} "
                "exceeds the maximum of {2} characters".format(
                    comp_att, len(value), self.MAX_COMPONENT_LENGTH))

        for offset, char in enumerate(value):
            if char == '%' or self._is_unreserved(char):
                continue
            if char == "~":
                reason = ("reserved character '~' must be percent-encoded "
                          "in a CPE 2.3 URI component")
            else:
                reason = ("character {0!r} is not allowed in a CPE 2.3 URI "
                          "component".format(char))
            self._component_attribute = comp_att
            self._raise_decode_error(offset, reason)

    def set_value(self, comp_str, comp_att):
        """
        Validate and store the component value in a single normalization
        pass.

        The base implementation validates the encoded value first and
        decodes it afterwards; both steps share the same grammar here and the
        decoder is the authoritative, single place in which percent-encoded
        sequences are consumed.

        :param string comp_str: new value of component
        :param string comp_att: attribute associated with the value
        :returns: None
        :exception: ValueError - incorrect value of component
        """

        if not CPEComponent.is_valid_attribute(comp_att):
            raise ValueError("Invalid attribute '{0}'".format(comp_att))

        self._component_attribute = comp_att
        old_value = self._encoded_value
        self._encoded_value = comp_str

        try:
            self._validate_structure(comp_att)
            if comp_att == CPEComponent.ATT_LANGUAGE:
                if not self._is_valid_language():
                    raise ValueError(
                        "Invalid value of attribute '{0}': {1}".format(
                            comp_att, comp_str))
            elif comp_att == CPEComponent.ATT_PART:
                if not self._is_valid_part():
                    raise ValueError(
                        "Invalid value of attribute '{0}': {1}".format(
                            comp_att, comp_str))
            elif comp_att == CPEComponent.ATT_EDITION:
                if not self._is_valid_edition():
                    raise ValueError(
                        "Invalid value of attribute '{0}': {1}".format(
                            comp_att, comp_str))
            self._standard_value = self._decode()
        except ValueError:
            self._encoded_value = old_value
            raise


if __name__ == "__main__":
    import doctest
    doctest.testmod()
    doctest.testfile("../tests/testfile_cpecomp2_3_uri.txt")
