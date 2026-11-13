"""
"""

# Created on 2014.09.08
#
# Author: Giovanni Cannata
#
# Copyright 2014 - 2025 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

from string import hexdigits, ascii_letters, digits

from .. import SEQUENCE_TYPES
from ..core.exceptions import LDAPInvalidDnError


STATE_ANY = 0
STATE_ESCAPE = 1
STATE_ESCAPE_HEX = 2

# characters that RFC 4514 mandates to be escaped in an AttributeValue
_ESCAPE_ANYWHERE = set('\\"+,;<=>\x00')
_SPECIAL_AT_START = set('# ')


class DN(object):
    """A distinguished name with three explicit representations.

    - ``raw`` keeps the string exactly as provided by the caller.
    - ``escaped`` is a valid RFC 4514 string suitable for display and for
      being sent on the wire, with every value properly escaped.
    - ``canonical`` is the normalized string used for comparison and group
      authorization decisions: attribute types are lowercased, redundant
      whitespace and trailing commas are removed, escaped hex pairs and
      UTF-8 sequences are decoded and special characters are re-escaped
      uniformly.

    Ambiguous input (unescaped commas, empty RDNs, repeated attribute types
    inside one RDN or an invalid ``#hex`` value) raises
    :class:`ldap3.core.exceptions.LDAPInvalidDnError` instead of being
    guessed.
    """

    def __init__(self, dn):
        if isinstance(dn, DN):
            self.raw = dn.raw
            self.escaped = dn.escaped
            self.canonical = dn.canonical
            # each rdn is a tuple of (type, original_type, value) tuples,
            # value is either a decoded str or a bytes object (BER #hex)
            self._rdns = tuple(tuple(ava) for ava in dn._rdns)
            return
        if not isinstance(dn, str):
            raise TypeError('DN must be created from a string or another DN object, got ' + type(dn).__name__)

        self.raw = dn
        self._rdns = _parse_dn_strict(dn)
        self.escaped = _render_dn(self._rdns, canonical=False)
        self.canonical = _render_dn(self._rdns, canonical=True)

    def rdns(self):
        """Return the parsed structure: a tuple of RDNs, each RDN a tuple of
        ``(attribute_type, attribute_value)`` pairs.  Values are decoded
        ``str`` objects or ``bytes`` for binary ``#hex`` values."""
        return tuple(tuple((ava[0], ava[2]) for ava in rdn) for rdn in self._rdns)

    def _key(self):
        return tuple(tuple(sorted((ava[0], ava[2]) for ava in rdn)) for rdn in self._rdns)

    def __eq__(self, other):
        if not isinstance(other, DN):
            return NotImplemented
        return self._key() == other._key()

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(self._key())

    def __str__(self):
        return self.escaped

    def __repr__(self):
        return 'DN(' + self.raw + ')'

    def is_equal(self, other):
        """True when the two DN objects name the exact same object."""
        return dn_equals(self, other)

    def is_descendant_of(self, other):
        """True when this DN is strictly below ``other`` in the DIT."""
        return is_descendant_dn(self, other)

    def is_ancestor_of(self, other):
        """True when this DN is strictly above ``other`` in the DIT."""
        return is_ancestor_dn(self, other)


def _require_dn(value, name):
    if not isinstance(value, DN):
        raise TypeError(name + ' must be a DN object, not a bare string of type ' + type(value).__name__)


def dn_equals(first, second):
    """Compare two :class:`DN` objects structurally.

    Only :class:`DN` instances are accepted; bare strings are rejected so
    callers cannot accidentally rely on textual prefix/suffix matching.
    """
    _require_dn(first, 'first')
    _require_dn(second, 'second')
    return first == second


def is_descendant_dn(descendant, ancestor):
    """True when ``descendant`` is strictly below ``ancestor`` in the DIT.

    The check compares the parsed RDN sequence, never string prefixes, so
    ``cn=admin,dc=example,dc=com`` cannot be confused with a different DN
    that merely happens to share a textual suffix.
    """
    _require_dn(descendant, 'descendant')
    _require_dn(ancestor, 'ancestor')
    ancestor_key = ancestor._key()
    descendant_key = descendant._key()
    if len(descendant_key) <= len(ancestor_key):
        return False
    return descendant_key[-len(ancestor_key):] == ancestor_key


def is_ancestor_dn(ancestor, descendant):
    """True when ``ancestor`` is strictly above ``descendant`` in the DIT."""
    _require_dn(ancestor, 'ancestor')
    _require_dn(descendant, 'descendant')
    return is_descendant_dn(descendant, ancestor)


def _split_top_level(value):
    """Split a DN string on unescaped COMMA and PLUS characters."""
    parts = []
    current = ''
    index = 0
    length = len(value)
    while index < length:
        char = value[index]
        if char == '\\':
            if index + 1 >= length:
                raise LDAPInvalidDnError('dangling escape in dn ' + value)
            current += char + value[index + 1]
            index += 2
            continue
        if char in (',', '+'):
            parts.append((current, char))
            current = ''
            index += 1
            continue
        current += char
        index += 1
    parts.append((current, ''))
    return parts


def _validate_strict_attribute_type(attribute_type):
    if not attribute_type:
        raise LDAPInvalidDnError('attribute type not present')
    if attribute_type[0] in digits:
        # numeric OID, dotted-decimal as per RFC 4512
        for char in attribute_type:
            if char not in digits and char != '.':
                raise LDAPInvalidDnError("character '" + char + "' not allowed in numeric OID attribute type")
        if '..' in attribute_type or attribute_type.endswith('.'):
            raise LDAPInvalidDnError("invalid numeric OID attribute type '" + attribute_type + "'")
        return True
    for char in attribute_type:
        if not (char in ascii_letters or char in digits or char == '-'):
            raise LDAPInvalidDnError("character '" + char + "' not allowed in attribute type")
    if attribute_type[0] == '-':
        raise LDAPInvalidDnError("character '" + attribute_type[0] + "' not allowed as first character of attribute type")
    return True


def _decode_attribute_value(raw_value):
    """Decode an RFC 4514 attribute value into a str or bytes (for #hex)."""
    if not raw_value:
        raise LDAPInvalidDnError('empty attribute value')

    raw_value = _strip_unespaced_spaces(raw_value)
    if raw_value[0] == '#':
        hex_part = raw_value[1:]
        if not hex_part or len(hex_part) % 2 != 0:
            raise LDAPInvalidDnError('hex representation must be in the form of <HEX><HEX> pairs')
        for char in hex_part:
            if char not in hexdigits:
                raise LDAPInvalidDnError('character ' + char + ' not allowed in hex representation of attribute value')
        binary = bytes(bytearray(int(hex_part[pos:pos + 2], 16) for pos in range(0, len(hex_part), 2)))
        try:
            return binary.decode('utf-8')
        except UnicodeDecodeError:
            return binary

    decoded = ''
    byte_buffer = bytearray()
    index = 0
    length = len(raw_value)
    while index < length:
        char = raw_value[index]
        if char == '\\':
            if index + 1 >= length:
                raise LDAPInvalidDnError('dangling escape in attribute value ' + raw_value)
            escaped = raw_value[index + 1]
            if escaped in ' "#+,;<=>\\':
                if byte_buffer:
                    try:
                        decoded += byte_buffer.decode('utf-8')
                    except UnicodeDecodeError:
                        raise LDAPInvalidDnError('invalid UTF-8 sequence in attribute value ' + raw_value)
                    byte_buffer = bytearray()
                decoded += escaped
                index += 2
            elif escaped in hexdigits:
                if index + 2 >= length or raw_value[index + 2] not in hexdigits:
                    raise LDAPInvalidDnError('invalid hex escape in attribute value ' + raw_value)
                byte_buffer.append(int(raw_value[index + 1:index + 3], 16))
                index += 3
            else:
                raise LDAPInvalidDnError('invalid escaped character ' + escaped)
        elif char in '"+,;<>=':
            # unescaped special characters make the boundary ambiguous
            raise LDAPInvalidDnError('special character ' + char + ' must be escaped in attribute value ' + raw_value)
        else:
            if byte_buffer:
                try:
                    decoded += byte_buffer.decode('utf-8')
                except UnicodeDecodeError:
                    raise LDAPInvalidDnError('invalid UTF-8 sequence in attribute value ' + raw_value)
                byte_buffer = bytearray()
            decoded += char
            index += 1

    if byte_buffer:
        try:
            decoded += byte_buffer.decode('utf-8')
        except UnicodeDecodeError:
            # keep binary values (for example a BER-encoded #hex equivalent) as bytes
            return bytes(byte_buffer)
    return decoded


def _strip_unespaced_spaces(value):
    """Remove leading/trailing SPACE characters that are not escaped.

    RFC 4514 only allows a SPACE at the start or end of a value when it is
    escaped, so an unescaped one is redundant formatting while an escaped one
    carries meaning and must be preserved.
    """
    start = 0
    length = len(value)
    while start < length and value[start] == ' ':
        start += 1
    end = length
    while end > start and value[end - 1] == ' ':
        # a trailing space preceded by an unescaped backslash is significant
        backslashes = 0
        index = end - 2
        while index >= 0 and value[index] == '\\':
            backslashes += 1
            index -= 1
        if backslashes % 2 == 1:
            break
        end -= 1
    return value[start:end]


def _encode_attribute_value(value):
    """Render a decoded value as an unambiguous RFC 4514 string."""
    if isinstance(value, bytes):
        return '#' + ''.join('{:02X}'.format(byte) for byte in bytearray(value))

    encoded = ''
    for char in value:
        if char in _ESCAPE_ANYWHERE:
            encoded += '\\' + char
        elif ord(char) < 0x20 or ord(char) == 0x7f:
            encoded += '\\{:02X}'.format(ord(char))
        else:
            encoded += char
    if encoded and encoded[0] in _SPECIAL_AT_START:
        encoded = '\\' + encoded
    if len(encoded) > 1 and encoded[-1] == ' ' and encoded[-2] != '\\':
        encoded = encoded[:-1] + '\\ '
    return encoded


def _parse_dn_strict(dn):
    """Strict RFC 4514-ish parser returning a tuple of RDN structures."""
    if not isinstance(dn, str) or not dn.strip():
        raise LDAPInvalidDnError('empty dn')

    text = dn.strip()
    # accept exactly one trailing (unquoted) comma, multiple leave an empty RDN
    if text.endswith(',') and not text.endswith('\\,'):
        text = text[:-1].rstrip()
    if not text or text.endswith(','):
        raise LDAPInvalidDnError('empty RDN in dn ' + dn)

    parts = _split_top_level(text)
    rdns = []
    current_rdn = []
    seen_types = set()
    for raw_ava, separator in parts:
        if not raw_ava.strip() or '=' not in raw_ava:
            raise LDAPInvalidDnError('empty or malformed RDN in dn ' + dn)

        equal = _find_first_unescaped(raw_ava, '=', 0)
        if equal <= 0:
            raise LDAPInvalidDnError('attribute type not present in ' + raw_ava)
        attribute_type = raw_ava[:equal].strip()
        raw_value = raw_ava[equal + 1:]
        _validate_strict_attribute_type(attribute_type)
        value = _decode_attribute_value(raw_value)

        lowered_type = attribute_type.lower()
        if lowered_type in seen_types:
            raise LDAPInvalidDnError("duplicate attribute type '" + attribute_type + "' in RDN")
        seen_types.add(lowered_type)
        current_rdn.append((lowered_type, attribute_type, value))

        if separator != '+':
            rdns.append(tuple(current_rdn))
            current_rdn = []
            seen_types = set()

    if current_rdn:
        rdns.append(tuple(current_rdn))
    if not rdns:
        raise LDAPInvalidDnError('empty dn')
    return tuple(rdns)


def _render_dn(rdns, canonical):
    rendered_rdns = []
    for rdn in rdns:
        rendered_avas = []
        for lowered_type, original_type, value in rdn:
            attribute_type = lowered_type if canonical else original_type
            rendered_avas.append(attribute_type + '=' + _encode_attribute_value(value))
        rendered_rdns.append('+'.join(rendered_avas))
    return ','.join(rendered_rdns)


def _add_ava(ava, decompose, remove_space, space_around_equal):
    if not ava:
        return ''

    space = ' ' if space_around_equal else ''
    attr_name, _, value = ava.partition('=')
    if decompose:
        if remove_space:
            component = (attr_name.strip(), value.strip())
        else:
            component = (attr_name, value)
    else:
        if remove_space:
            component = attr_name.strip() + space + '=' + space + value.strip()
        else:
            component = attr_name + space + '=' + space + value

    return component


def to_dn(iterator, decompose=False, remove_space=False, space_around_equal=False, separate_rdn=False):
    """
    Convert an iterator to a list of dn parts
    if decompose=True return a list of tuple (one for each dn component) else return a list of strings
    if remove_space=True removes unneeded spaces
    if space_around_equal=True add spaces around equal in returned strings
    if separate_rdn=True consider multiple RDNs as different component of DN
    """
    dn = []
    component = ''
    escape_sequence = False
    for c in iterator:
        if c == '\\':  # escape sequence
            escape_sequence = True
        elif escape_sequence and c != ' ':
            escape_sequence = False
        elif c == '+' and separate_rdn:
            dn.append(_add_ava(component, decompose, remove_space, space_around_equal))
            component = ''
            continue
        elif c == ',':
            if '=' in component:
                dn.append(_add_ava(component, decompose, remove_space, space_around_equal))
                component = ''
                continue

        component += c

    dn.append(_add_ava(component, decompose, remove_space, space_around_equal))
    return dn


def _find_first_unescaped(dn, char, pos):
    while True:
        pos = dn.find(char, pos)
        if pos == -1:
            break  # no char found
        if pos > 0 and dn[pos - 1] != '\\':  # unescaped char
            break
        elif pos > 1 and dn[pos - 1] == '\\':  # may be unescaped
            escaped = True
            for c in dn[pos - 2:0:-1]:
                if c == '\\':
                    escaped = not escaped
                else:
                    break
            if not escaped:
                break
        pos += 1

    return pos


def _find_last_unescaped(dn, char, start, stop=0):
    while True:
        stop = dn.rfind(char, start, stop)
        if stop == -1:
            break
        if stop >= 0 and dn[stop - 1] != '\\':
            break
        elif stop > 1 and dn[stop - 1] == '\\':  # may be unescaped
            escaped = True
            for c in dn[stop - 2:0:-1]:
                if c == '\\':
                    escaped = not escaped
                else:
                    break
            if not escaped:
                break
        if stop < start:
            stop = -1
            break

    return stop


def _get_next_ava(dn):
    comma = _find_first_unescaped(dn, ',', 0)
    plus = _find_first_unescaped(dn, '+', 0)

    if plus > 0 and (plus < comma or comma == -1):
        equal = _find_first_unescaped(dn, '=', plus + 1)
        if equal > plus + 1:
            plus = _find_last_unescaped(dn, '+', plus, equal)
            return dn[:plus], '+'

    if comma > 0:
        equal = _find_first_unescaped(dn, '=', comma + 1)
        if equal > comma + 1:
            comma = _find_last_unescaped(dn, ',', comma, equal)
            return dn[:comma], ','

    return dn, ''


def _split_ava(ava, escape=False, strip=True):
    equal = ava.find('=')
    while equal > 0:  # not first character
        if ava[equal - 1] != '\\':  # not an escaped equal so it must be an ava separator
            # attribute_type1 = ava[0:equal].strip() if strip else ava[0:equal]
            if strip:
                attribute_type = ava[0:equal].strip()
                attribute_value = _escape_attribute_value(ava[equal + 1:].strip()) if escape else ava[equal + 1:].strip()
            else:
                attribute_type = ava[0:equal]
                attribute_value = _escape_attribute_value(ava[equal + 1:]) if escape else ava[equal + 1:]

            return attribute_type, attribute_value
        equal = ava.find('=', equal + 1)

    return '', (ava.strip() if strip else ava)  # if no equal found return only value


def _validate_attribute_type(attribute_type):
    if not attribute_type:
        raise LDAPInvalidDnError('attribute type not present')

    if attribute_type == '<GUID':  # patch for AD DirSync
        return True

    for c in attribute_type:
        if not (c in ascii_letters or c in digits or c == '-'):  # allowed uppercase and lowercase letters, digits and hyphen as per RFC 4512
            raise LDAPInvalidDnError('character \'' + c + '\' not allowed in attribute type')

    if attribute_type[0] in digits or attribute_type[0] == '-':  # digits and hyphen not allowed as first character
        raise LDAPInvalidDnError('character \'' + attribute_type[0] + '\' not allowed as first character of attribute type')

    return True


def _validate_attribute_value(attribute_value):
    if not attribute_value:
        return False

    if attribute_value[0] == '#':  # only hex characters are valid
        for c in attribute_value:
            if c not in hexdigits:  # allowed only hex digits as per RFC 4514
                raise LDAPInvalidDnError('character ' + c + ' not allowed in hex representation of attribute value')
        if len(attribute_value) % 2 == 0:  # string must be # + HEX HEX (an odd number of chars)
            raise LDAPInvalidDnError('hex representation must be in the form of <HEX><HEX> pairs')
    if attribute_value[0] == ' ':  # unescaped space cannot be used as leading or last character
        raise LDAPInvalidDnError('SPACE must be escaped as leading character of attribute value')
    if attribute_value.endswith(' ') and not attribute_value.endswith('\\ '):
        raise LDAPInvalidDnError('SPACE must be escaped as trailing character of attribute value')

    state = STATE_ANY
    for c in attribute_value:
        if state == STATE_ANY:
            if c == '\\':
                state = STATE_ESCAPE
            elif c in '"#+,;<=>\00':
                raise LDAPInvalidDnError('special character ' + c + ' must be escaped')
        elif state == STATE_ESCAPE:
            if c in hexdigits:
                state = STATE_ESCAPE_HEX
            elif c in ' "#+,;<=>\\\00':
                state = STATE_ANY
            else:
                raise LDAPInvalidDnError('invalid escaped character ' + c)
        elif state == STATE_ESCAPE_HEX:
            if c in hexdigits:
                state = STATE_ANY
            else:
                raise LDAPInvalidDnError('invalid escaped character ' + c)

    # final state
    if state != STATE_ANY:
        raise LDAPInvalidDnError('invalid final character')

    return True


def _escape_attribute_value(attribute_value):
    if not attribute_value:
        return ''

    if attribute_value[0] == '#':  # with leading SHARP only pairs of hex characters are valid
        valid_hex = True
        if len(attribute_value) % 2 == 0:  # string must be # + HEX HEX (an odd number of chars)
            valid_hex = False

        if valid_hex:
            for c in attribute_value:
                if c not in hexdigits:  # allowed only hex digits as per RFC 4514
                    valid_hex = False
                    break

        if valid_hex:
            return attribute_value

    state = STATE_ANY
    escaped = ''
    tmp_buffer = ''
    for c in attribute_value:
        if state == STATE_ANY:
            if c == '\\':
                state = STATE_ESCAPE
            elif c in '"#+,;<=>\00':
                escaped += '\\' + c
            else:
                escaped += c
        elif state == STATE_ESCAPE:
            if c in hexdigits:
                tmp_buffer = c
                state = STATE_ESCAPE_HEX
            elif c in ' "#+,;<=>\\\00':
                escaped += '\\' + c
                state = STATE_ANY
            else:
                escaped += '\\\\' + c
        elif state == STATE_ESCAPE_HEX:
            if c in hexdigits:
                escaped += '\\' + tmp_buffer + c
            else:
                escaped += '\\\\' + tmp_buffer + c
            tmp_buffer = ''
            state = STATE_ANY

    # final state
    if state == STATE_ESCAPE:
        escaped += '\\\\'
    elif state == STATE_ESCAPE_HEX:
        escaped += '\\\\' + tmp_buffer

    if escaped[0] == ' ':  # leading SPACE must be escaped
        escaped = '\\' + escaped

    if escaped[-1] == ' ' and len(escaped) > 1 and escaped[-2] != '\\':  # trailing SPACE must be escaped
        escaped = escaped[:-1] + '\\ '

    return escaped


def parse_dn(dn, escape=False, strip=False):
    """
    Parses a DN into syntactic components
    :param dn:
    :param escape:
    :param strip:
    :return:
    a list of tripels representing `attributeTypeAndValue` elements
    containing `attributeType`, `attributeValue` and the following separator (`COMMA` or `PLUS`) if given, else an empty `str`.
    in their original representation, still containing escapes or encoded as hex.
    """
    rdns = []
    avas = []
    while dn:
        ava, separator = _get_next_ava(dn)  # if returned ava doesn't containg any unescaped equal it'a appended to last ava in avas

        dn = dn[len(ava) + 1:]
        if _find_first_unescaped(ava, '=', 0) > 0 or len(avas) == 0:
            avas.append((ava, separator))
        else:
            avas[len(avas) - 1] = (avas[len(avas) - 1][0] + avas[len(avas) - 1][1] + ava, separator)

    for ava, separator in avas:
        attribute_type, attribute_value = _split_ava(ava, escape, strip)

        if not _validate_attribute_type(attribute_type):
            raise LDAPInvalidDnError('unable to validate attribute type in ' + ava)

        if not _validate_attribute_value(attribute_value):
            raise LDAPInvalidDnError('unable to validate attribute value in ' + ava)

        rdns.append((attribute_type, attribute_value, separator))
        dn = dn[len(ava) + 1:]

    if not rdns:
        raise LDAPInvalidDnError('empty dn')

    return rdns


def safe_dn(dn, decompose=False, reverse=False):
    """
    normalize and escape a dn, if dn is a sequence it is joined.
    the reverse parameter changes the join direction of the sequence
    """
    if isinstance(dn, SEQUENCE_TYPES):
        components = [rdn for rdn in dn]
        if reverse:
            dn = ','.join(reversed(components))
        else:
            dn = ','.join(components)
    if decompose:
        escaped_dn = []
    else:
        escaped_dn = ''

    if dn.startswith('<GUID=') and dn.endswith('>'):  # Active Directory allows looking up objects by putting its GUID in a specially-formatted DN (e.g. '<GUID=7b95f0d5-a3ed-486c-919c-077b8c9731f2>')
        escaped_dn = dn
    elif dn.startswith('<WKGUID=') and dn.endswith('>'):  # Active Directory allows Binding to Well-Known Objects Using WKGUID in a specially-formatted DN (e.g. <WKGUID=a9d1ca15768811d1aded00c04fd8d5cd,dc=Fabrikam,dc=com>)
        escaped_dn = dn
    elif dn.startswith('<SID=') and dn.endswith('>'):  # Active Directory allows looking up objects by putting its security identifier (SID) in a specially-formatted DN (e.g. '<SID=S-#-#-##-##########-##########-##########-######>')
        escaped_dn = dn
    elif '@' not in dn:  # active directory UPN (User Principal Name) consist of an account, the at sign (@) and a domain, or the domain level logn name domain\username
        for component in parse_dn(dn, escape=True):
            if decompose:
                escaped_dn.append((component[0], component[1], component[2]))
            else:
                escaped_dn += component[0] + '=' + component[1] + component[2]
    elif '@' in dn and '=' not in dn and len(dn.split('@')) != 2:
        raise LDAPInvalidDnError('Active Directory User Principal Name must consist of name@domain')
    elif '\\' in dn and '=' not in dn and len(dn.split('\\')) != 2:
        raise LDAPInvalidDnError('Active Directory Domain Level Logon Name must consist of name\\domain')
    else:
        escaped_dn = dn

    return escaped_dn


def safe_rdn(dn, decompose=False):
    """Returns a list of rdn for the dn, usually there is only one rdn, but it can be more than one when the + sign is used"""
    escaped_rdn = []
    one_more = True
    for component in parse_dn(dn, escape=True):
        if component[2] == '+' or one_more:
            if decompose:
                escaped_rdn.append((component[0], component[1]))
            else:
                escaped_rdn.append(component[0] + '=' + component[1])
            if component[2] == '+':
                one_more = True
            else:
                one_more = False
                break

    if one_more:
        raise LDAPInvalidDnError('bad dn ' + str(dn))

    return escaped_rdn


def escape_rdn(rdn):
    """
    Escape rdn characters to prevent injection according to RFC 4514.
    """

    # '/' must be handled first or the escape slashes will be escaped!
    for char in ['\\', ',', '+', '"', '<', '>', ';', '=', '\x00']:
        rdn = rdn.replace(char, '\\' + char)

    if rdn[0] == '#' or rdn[0] == ' ':
        rdn = ''.join(('\\', rdn))

    if rdn[-1] == ' ':
        rdn = ''.join((rdn[:-1], '\\ '))

    return rdn
