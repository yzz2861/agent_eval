# dictionary.py
#
# Copyright 2002,2005,2007,2016 Wichert Akkerman <wichert@wiggy.net>
"""
RADIUS uses dictionaries to define the attributes that can
be used in packets. The Dictionary class stores the attribute
definitions from one or more dictionary files in the FreeRADIUS format.

Dictionary files are text files with one command per line.
Comments are specified by starting with a # character, and empty
lines are ignored.

The commands supported are:

``ATTRIBUTE <attribute> <code> <type> [<vendor>|<flags>]``
  Define an attribute and its data type. The code is decimal, or
  hexadecimal with a ``0x`` prefix (octal with ``0o``), and
  ``<tlv code>.<code>`` for a sub-attribute of a TLV.

``VALUE <attribute> <valuename> <value>``
  Define a named value of an attribute.

``VENDOR <name> <id> [format=<t>,<l>]``
  Define a vendor and its ID. Only the RFC 2865 format ``format=1,1`` (the
  default) is supported, the attributes of vendors with another format
  are skipped.

``BEGIN-VENDOR <name> [format=<attribute>]``
  Begin the definition of the attributes of a vendor. The attributes of a
  block with a ``format=`` option are extended vendor-specific attributes
  (RFC 6929) and are skipped.

``END-VENDOR <name>``
  End the definition of the attributes of a vendor.

``$INCLUDE <filename>``
  Read another dictionary file. A relative file name is relative to the
  directory of the current file, or to the current working directory if
  the dictionary is read from a file-like object. Include targets are
  normalized and confined to the directory of the root file: a path that
  escapes it (including with ``..`` or a symlink), a recursive include
  or an include chain deeper than
  :data:`pyrad.dictfile.MAX_INCLUDE_DEPTH` raises a ``ParseError``.
  The visited files are recorded in the read-only include snapshots of
  the dictionary.

``$INCLUDE- <filename>``
  Like ``$INCLUDE``, but a file that doesn't exist is ignored.

Other commands are ignored.

The attribute flags are a comma separated list of:

``has_tag``
  The attribute is tagged (RFC 2868).

``encrypt=1``
  User-Password encryption (RFC 2865 section 5.2). It is not applied
  automatically, see :meth:`pyrad.packet.AuthPacket.PwCrypt` and
  :meth:`pyrad.packet.AuthPacket.PwDecrypt`.

``encrypt=2``
  Salt encryption (RFC 2868 section 3.5), applied automatically.

``encrypt=3``
  Ascend-Send-Secret encryption. Accepted, but not applied.

The FreeRADIUS flags ``secret``, ``virtual`` and ``concat`` are accepted
and ignored.

FreeRADIUS dictionaries also define attributes that pyrad cannot encode or
decode. These are skipped with a warning, so that the FreeRADIUS dictionary
files can be read as they are:

- attributes of the data types ``vsa``, ``extended``, ``long-extended``,
  ``evs`` (the RFC 6929 extended attributes), ``ipv4prefix``,
  ``combo-ip``, ``bool``, ``uint16`` and ``uint32``, and their
  sub-attributes
- attributes with the ``array`` flag
- TLVs nested more than one level deep
- attributes of vendors with a format other than ``format=1,1``
  (``VENDOR``)
- vendor attributes in a ``BEGIN-VENDOR`` block with a ``format=``
  option, which are extended vendor-specific attributes (RFC 6929)

VALUE definitions for skipped attributes are ignored, and VALUE definitions
for unknown attributes are ignored with a warning. Received attributes
that were skipped are decoded as undefined attributes.

The data types currently supported, and the Python values used for them in
packets:

.. list-table::
   :header-rows: 1
   :widths: 15 40 45

   * - type
     - description
     - Python value
   * - string
     - UTF-8 string
     - :class:`str` or :class:`bytes`, at most 253 octets encoded; a
       received value which is not valid UTF-8 is returned as
       :class:`bytes`
   * - ipaddr
     - IPv4 address
     - :class:`str`, e.g. ``'192.0.2.1'``
   * - date
     - 32 bits UNIX timestamp
     - :class:`int`
   * - octets
     - arbitrary binary data
     - :class:`bytes`; a value starting with ``0x`` is decoded from hex
   * - abinary
     - Ascend binary filter
     - Ascend filter :class:`str`, e.g. ``'family=ipv4 action=accept
       direction=in'``; received values are returned as :class:`bytes`
   * - ipv6addr
     - 16 octets in network byte order
     - :class:`str` or :class:`ipaddress.IPv6Address`; received values
       are returned as :class:`str`
   * - ipv6prefix
     - up to 18 octets in network byte order
     - :class:`str` ``'address/length'``, e.g. ``'2001:db8::/32'``
   * - integer
     - 32 bits unsigned number
     - :class:`int`
   * - signed
     - 32 bits signed number
     - :class:`int`
   * - short
     - 16 bits unsigned number
     - :class:`int`
   * - byte
     - 8 bits unsigned number
     - :class:`int`
   * - integer64
     - 64 bits unsigned number
     - :class:`int`
   * - tlv
     - nested type-length-value
     - set the sub-attributes by their names; reading the TLV returns a
       :class:`dict` mapping sub-attribute names to lists of values
   * - ifid
     - 8 octets IPv6 interface identifier
     - :class:`str` ``'hhhh:hhhh:hhhh:hhhh'``, ``h`` being a hex digit
   * - ether
     - 6 octets Ethernet MAC address
     - :class:`str` ``'hh:hh:hh:hh:hh:hh'``, ``h`` being a hex digit,
       upper or lowercase
"""
import logging
import struct

from pyrad import bidict
from pyrad import tools
from pyrad import dictfile
from copy import copy

__docformat__ = "restructuredtext en"

logger = logging.getLogger('pyrad')


DATATYPES = frozenset(['string', 'ipaddr', 'integer', 'date', 'octets',
                       'abinary', 'ipv6addr', 'ipv6prefix', 'short', 'byte',
                       'signed', 'ifid', 'ether', 'tlv', 'integer64'])

# FreeRADIUS data types which pyrad does not support. Attributes of these
# types are skipped with a warning instead of failing the parse.
UNSUPPORTED_DATATYPES = frozenset(['vsa', 'extended', 'long-extended', 'evs',
                                   'ipv4prefix', 'combo-ip', 'bool', 'uint16',
                                   'uint32'])

# Attribute flags; a fifth ATTRIBUTE column that contains one of them is a
# list of flags instead of a vendor name.
ATTRIBUTE_FLAGS = frozenset(['has_tag', 'encrypt', 'secret', 'array',
                             'virtual', 'concat'])


class ParseError(Exception):
    """A dictionary file can't be parsed.

    Raised for syntax errors, recursive includes and includes outside of
    the dictionary directory. Note that it is not a subclass of
    :exc:`ValueError`.

    :ivar msg: error message
    :vartype msg: str
    :ivar file: name of the dictionary file, or ``''``
    :vartype file: str
    :ivar line: line number on which the error occurred, or -1
    :vartype line: int
    :ivar scope: name of the scope (the current dictionary file) in which
        the error occurred, or ``''``
    :vartype scope: str
    """

    def __init__(self, msg=None, **data):
        self.msg = msg
        self.file = data.get('file', '')
        self.line = data.get('line', -1)
        self.scope = data.get('scope', '')

    def __str__(self):
        str = ''
        if self.file:
            str += self.file
        if self.line > -1:
            str += '(%d)' % self.line
        if self.scope and self.scope != self.file:
            if self.file or self.line > -1:
                str += ' '
            str += '[scope %s]' % self.scope
        if self.file or self.line > -1 or self.scope:
            str += ': '
        str += 'Parse error'
        if self.msg:
            str += ': %s' % self.msg

        return str


class Attribute(object):
    """The definition of an attribute in a :class:`Dictionary`.

    Raises :exc:`ValueError` for an unsupported data type.

    :ivar name: name of the attribute
    :vartype name: str
    :ivar code: attribute code, for a sub-attribute its code in the TLV
    :vartype code: int
    :ivar type: data type, e.g. ``'string'``
    :vartype type: str
    :ivar vendor: name of the vendor, ``''`` for a standard attribute
    :vartype vendor: str
    :ivar encrypt: encryption method of the ``encrypt=`` flag, 0 for none
    :vartype encrypt: int
    :ivar has_tag: the attribute is tagged (RFC 2868)
    :vartype has_tag: bool
    :ivar values: named values, mapping the name to the encoded value
    :vartype values: pyrad.bidict.BiDict
    :ivar sub_attributes: names of the sub-attributes of a TLV by their
        code
    :vartype sub_attributes: dict[int, str]
    :ivar parent: the TLV of a sub-attribute, else None
    :vartype parent: Attribute or None
    :ivar is_sub_attribute: the attribute is a sub-attribute of a TLV
    :vartype is_sub_attribute: bool
    """

    def __init__(self, name, code, datatype, is_sub_attribute=False, vendor='', values=None,
                 encrypt=0, has_tag=False):
        if datatype not in DATATYPES:
            raise ValueError('Invalid data type')
        self.name = name
        self.code = code
        self.type = datatype
        self.vendor = vendor
        self.encrypt = encrypt
        self.has_tag = has_tag
        self.values = bidict.BiDict()
        self.sub_attributes = {}
        self.parent = None
        self.is_sub_attribute = is_sub_attribute
        if values:
            for (key, value) in values.items():
                self.values.Add(key, value)


class Dictionary:
    """RADIUS dictionary.

    Stores the vendors, attributes and their values defined in RADIUS
    dictionary files. ``Dictionary(path, *more)`` reads the files in
    order, see :meth:`ReadDictionary`. ``dictionary['User-Name']`` returns
    the :class:`Attribute` of that name and ``'User-Name' in dictionary``
    checks whether it is defined.

    :ivar attributes: attributes by name
    :vartype attributes: dict[str, Attribute]
    :ivar attrindex: attribute names and the keys of the attributes in a
        packet: the code, ``(vendor, code)`` for a vendor attribute,
        ``(tlv code, code)`` for a sub-attribute and
        ``(vendor, tlv code, code)`` for a sub-attribute of a vendor TLV,
        with the vendor ID as vendor
    :vartype attrindex: pyrad.bidict.BiDict
    :ivar vendors: vendor names and IDs, ``''`` is vendor 0
    :vartype vendors: pyrad.bidict.BiDict
    :ivar skipped_attributes: names of the attributes that were skipped
        because pyrad does not support them; using them raises a
        :exc:`KeyError`
    :vartype skipped_attributes: set[str]
    :ivar definition_sources: ``(file, line, scope)`` a vendor or attribute
        was defined at, keyed by its name; the file is ``''`` for a
        dictionary read from a file-like object
    :vartype definition_sources: dict[str, tuple[str, int, str]]
    :ivar include_snapshots: read-only snapshots of the files visited by
        the :meth:`ReadDictionary` calls, oldest first
    :vartype include_snapshots: list[pyrad.dictfile.IncludeSnapshot]
    """

    def __init__(self, dict=None, *dicts):
        """
        :param dict: path of a dictionary file or file-like object to read
        :type  dict: str or io.TextIOBase
        :param dicts: further dictionary files to read
        :type  dicts: str or io.TextIOBase
        """
        self.vendors = bidict.BiDict()
        self.vendors.Add('', 0)
        self.attrindex = bidict.BiDict()
        self.attributes = {}
        self.defer_parse = []
        self.skipped_attributes = set()
        # vendors whose attribute format is not the RFC 2865 one
        self._unsupported_vendors = set()
        # TLVs by (vendor code, attribute code), kept across ReadDictionary
        # calls so that sub-attributes can be defined in another file
        self._tlvs = {}
        # (vendor code, attribute code) of skipped top-level attributes,
        # whose sub-attributes are skipped as well
        self._skipped_codes = set()
        # vendor owning each TLV by (vendor code, attribute code)
        self._tlv_owner = {}
        # definition location (file, line, scope) by attribute/vendor name
        self.definition_sources = {}
        # read-only snapshots of the include graph of each parsed file
        self.include_snapshots = []

        if dict:
            self.ReadDictionary(dict)

        for i in dicts:
            self.ReadDictionary(i)

    def __len__(self):
        return len(self.attributes)

    def __getitem__(self, key):
        return self.attributes[key]

    def __contains__(self, key):
        return key in self.attributes

    has_key = __contains__

    def __DefinitionSource(self, state):
        """Return the (file, line, scope) of the current definition."""
        return (state['file'], state['line'], state['scope'])

    def __WarnDuplicate(self, state, what, name, previous):
        """Report a same-scope duplicate kept for FreeRADIUS compatibility.

        Later definitions win, as in previous pyrad releases; the warning
        and the recorded source make the override auditable. File contents
        are never logged.
        """
        logger.warning(
            '%s(%d): duplicate %s %r in scope %r overrides the definition '
            'from %s(%d)',
            state['file'], state['line'], what, name, state['scope'],
            previous[0] or '<input>', previous[1])

    def __CheckParent(self, state, parent, vendor):
        """Validate that a sub-attribute TLV exists in its vendor scope.

        TLVs are keyed by vendor, so a TLV defined under another vendor (or
        in the standard scope) does not exist here: the sub-attribute is
        rejected instead of being attached to the wrong parent.
        """
        owner = self._tlv_owner.get(
            (self.vendors.GetForward(vendor), parent.code))
        if owner is None or owner != self.vendors.GetForward(vendor):
            if vendor:
                msg = ('Sub-attribute of TLV %d defined by another vendor'
                       % parent.code)
            else:
                msg = ('Sub-attribute of vendor TLV %d outside of a '
                       'vendor scope' % parent.code)
            raise ParseError(msg, file=state['file'], line=state['line'],
                             scope=state['scope'])

    def __SkipAttribute(self, state, name, reason):
        self.skipped_attributes.add(name)
        state['skipped'].append(reason)
        logger.debug('%s(%d): skipping attribute %s: %s',
                     state['file'], state['line'], name, reason)

    def __ParseAttribute(self, state, tokens):
        if len(tokens) not in [4, 5]:
            raise ParseError(
                'Incorrect number of tokens for attribute definition',
                file=state['file'],
                line=state['line'], scope=state['scope'])

        vendor = state['vendor']
        has_tag = False
        encrypt = 0
        array = False
        if len(tokens) >= 5:
            def keyval(o):
                kv = o.split('=')
                if len(kv) == 2:
                    return (kv[0], kv[1])
                else:
                    return (kv[0], None)
            options = [keyval(o) for o in tokens[4].split(',')]
            is_flags = any(key in ATTRIBUTE_FLAGS for (key, val) in options)
            if self.vendors.HasForward(tokens[4]) and \
                    not any(key in ('has_tag', 'encrypt')
                            for (key, val) in options):
                vendor = tokens[4]
            elif not is_flags:
                raise ParseError('Unknown vendor ' + tokens[4],
                                 file=state['file'],
                                 line=state['line'], scope=state['scope'])
            for (key, val) in options if is_flags else []:
                if key == 'has_tag':
                    has_tag = True
                elif key == 'encrypt':
                    if val not in ['1', '2', '3']:
                        raise ParseError(
                                'Illegal attribute encryption: %s' % val,
                                file=state['file'],
                                line=state['line'], scope=state['scope'])
                    encrypt = int(val)
                elif key == 'array':
                    array = True

        (attribute, code, datatype) = tokens[1:4]

        codes = code.split('.')

        # Codes can be sent as hex, or octal or decimal string representations.
        tmp = []
        try:
            for c in codes:
                if c.startswith('0x'):
                    tmp.append(int(c, 16))
                elif c.startswith('0o'):
                    tmp.append(int(c, 8))
                else:
                    tmp.append(int(c, 10))
        except ValueError:
            raise ParseError('Illegal attribute code: ' + code,
                             file=state['file'],
                             line=state['line'], scope=state['scope'])
        codes = tmp

        datatype = datatype.split("[")[0]

        if datatype not in DATATYPES and datatype not in UNSUPPORTED_DATATYPES:
            raise ParseError('Illegal type: ' + datatype,
                             file=state['file'],
                             line=state['line'], scope=state['scope'])

        vendor_code = self.vendors.GetForward(vendor)
        if len(codes) > 1 and (vendor_code, codes[0]) in self._skipped_codes:
            return self.__SkipAttribute(
                state, attribute, 'sub-attribute of unsupported attribute')
        if state['vendor_format']:
            return self.__SkipAttribute(
                state, attribute, 'extended vendor-specific attribute')
        if vendor in self._unsupported_vendors:
            return self.__SkipAttribute(state, attribute, 'vendor format')
        if datatype in UNSUPPORTED_DATATYPES:
            if len(codes) == 1:
                self._skipped_codes.add((vendor_code, codes[0]))
                self._tlvs.pop((vendor_code, codes[0]), None)
                self.definition_sources.pop(attribute, None)
            return self.__SkipAttribute(state, attribute,
                                        'data type ' + datatype)
        if array:
            return self.__SkipAttribute(state, attribute, 'array flag')
        if (len(codes) > 2
                or (len(codes) == 2 and datatype == 'tlv')):
            return self.__SkipAttribute(state, attribute, 'nested TLV')

        is_sub_attribute = (len(codes) > 1)
        if len(codes) == 2:
            code = int(codes[1])
            parent_code = int(codes[0])
            parent = self._tlvs.get((vendor_code, parent_code))
            if parent is None:
                raise ParseError(
                    'Sub-attribute %s of unknown TLV %d' % (attribute,
                                                            parent_code),
                    file=state['file'], line=state['line'],
                    scope=state['scope'])
            self.__CheckParent(state, parent, vendor)
        else:
            code = int(codes[0])
            parent_code = None

        if vendor:
            if is_sub_attribute:
                key = (vendor_code, parent_code, code)
            else:
                key = (vendor_code, code)
        else:
            if is_sub_attribute:
                key = (parent_code, code)
            else:
                key = code

        old_parent = None
        old_name = None
        if is_sub_attribute:
            old_name = parent.sub_attributes.get(code)
        elif self.attrindex.HasBackward(key):
            old_name = self.attrindex.GetBackward(key)
        if (old_name is not None and old_name != attribute
                and old_name in self.attributes):
            # Another name already maps to this code in this scope. For
            # FreeRADIUS compatibility (aliases) the old attribute object
            # stays reachable by name; the new name wins the reverse
            # lookup. The override is warned about and its source recorded.
            self.__WarnDuplicate(
                state, 'attribute code', attribute,
                self.definition_sources.get(
                    old_name, (state['file'], state['line'],
                               state['scope'])))
            old = self.attributes[old_name]
            if is_sub_attribute:
                old_parent = old.parent
            self.attrindex.backward.pop(key, None)
        elif attribute in self.attributes:
            # the same name is redefined: the later definition replaces it
            self.__WarnDuplicate(
                state, 'attribute', attribute,
                self.definition_sources.get(
                    attribute, (state['file'], state['line'],
                                state['scope'])))
            if self.attributes[attribute].is_sub_attribute:
                old_parent = self.attributes[attribute].parent
            del self.attrindex[attribute]

        self.attrindex.Add(attribute, key)
        self.attributes[attribute] = Attribute(
            attribute, code, datatype, is_sub_attribute, vendor,
            encrypt=encrypt, has_tag=has_tag)
        self.definition_sources[attribute] = self.__DefinitionSource(state)
        if is_sub_attribute:
            # save sub attribute in parent tlv and update their parent field
            if old_parent is not None and old_parent is not parent:
                old_parent.sub_attributes.pop(
                    self.attributes[attribute].code, None)
            parent.sub_attributes[code] = attribute
            self.attributes[attribute].parent = parent
        else:
            # a (re)defined top-level attribute replaces a skipped attribute
            # or TLV with the same code; drop the sub-attributes of a TLV
            # that ceases to be one or that is redefined from scratch
            old_tlv = self._tlvs.get((vendor_code, code))
            if old_tlv is not None:
                same_name_redefine = self.attributes[attribute] is old_tlv
                tlv_aliased = (
                    datatype == 'tlv' and not same_name_redefine
                    and old_name is not None and old_name != attribute)
                if not same_name_redefine and not tlv_aliased:
                    # the code stops being a TLV, or the same TLV name is
                    # redefined from scratch: its old sub-attributes vanish
                    for sub_name in list(old_tlv.sub_attributes.values()):
                        sub_key = self.attrindex.forward.pop(sub_name, None)
                        if sub_key is not None:
                            self.attrindex.backward.pop(sub_key, None)
                        self.attributes.pop(sub_name, None)
                        self.definition_sources.pop(sub_name, None)
                    old_tlv.sub_attributes.clear()
                elif tlv_aliased:
                    # a second TLV name for the same code shares the
                    # existing TLV and its sub-attributes
                    self.attributes[attribute].sub_attributes = (
                        old_tlv.sub_attributes)
            self._skipped_codes.discard((vendor_code, code))
            if datatype == 'tlv':
                self._tlvs[(vendor_code, code)] = self.attributes[attribute]
                self._tlv_owner[(vendor_code, code)] = vendor_code
            else:
                self._tlvs.pop((vendor_code, code), None)
                self._tlv_owner.pop((vendor_code, code), None)

    def __ParseValue(self, state, tokens, defer):
        if len(tokens) != 4:
            raise ParseError('Incorrect number of tokens for value definition',
                             file=state['file'],
                             line=state['line'], scope=state['scope'])

        (attr, key, value) = tokens[1:]

        if attr in self.skipped_attributes and attr not in self.attributes:
            return

        try:
            adef = self.attributes[attr]
        except KeyError:
            if defer:
                self.defer_parse.append((copy(state), copy(tokens)))
                return
            # FreeRADIUS dictionaries contain a few of these, so warn
            # instead of failing the parse
            logger.warning('%s(%d): ignoring value defined for unknown '
                           'attribute %s', state['file'], state['line'], attr)
            return

        try:
            if adef.type in ['integer', 'signed', 'short', 'byte',
                             'integer64', 'date']:
                value = int(value, 0)
            value = tools.EncodeAttr(adef.type, value)
        except (ValueError, TypeError, struct.error) as e:
            raise ParseError('Illegal value %s for attribute %s: %s'
                             % (tokens[3], attr, e),
                             file=state['file'],
                             line=state['line'], scope=state['scope'])
        self.attributes[attr].values.Add(key, value)

    def __ParseVendor(self, state, tokens):
        if len(tokens) not in [3, 4]:
            raise ParseError(
                    'Incorrect number of tokens for vendor definition',
                    file=state['file'],
                    line=state['line'], scope=state['scope'])

        (vendorname, vendor) = tokens[1:3]

        # pyrad only encodes the RFC 2865 vendor attribute format (1 octet
        # type, 1 octet length), attributes of vendors with another format
        # are skipped
        if len(tokens) == 4:
            fmt = tokens[3].split('=')
            if fmt[0] != 'format':
                raise ParseError(
                        "Unknown option '%s' for vendor definition" % (fmt[0]),
                        file=state['file'],
                        line=state['line'], scope=state['scope'])
            try:
                fmtargs = fmt[1].split(',')
                # ",c": WiMAX continuation octet
                continuation = len(fmtargs) == 3 and fmtargs[2] == 'c'
                if continuation:
                    fmtargs = fmtargs[:2]
                (token, length) = tuple(int(a) for a in fmtargs)
            except ValueError:
                raise ParseError(
                        'Syntax error in vendor specification',
                        file=state['file'],
                        line=state['line'], scope=state['scope'])
            if token not in [1, 2, 4] or length not in [0, 1, 2]:
                raise ParseError(
                    'Unknown vendor format specification %s' % (fmt[1]),
                    file=state['file'],
                    line=state['line'], scope=state['scope'])
            if (token, length, continuation) != (1, 1, False):
                self._unsupported_vendors.add(vendorname)
            else:
                self._unsupported_vendors.discard(vendorname)

        try:
            vendor_code = int(vendor, 0)
        except ValueError:
            raise ParseError('Illegal vendor code: ' + vendor,
                             file=state['file'],
                             line=state['line'], scope=state['scope'])
        self.vendors.Add(vendorname, vendor_code)
        self.definition_sources[vendorname] = self.__DefinitionSource(state)

    def __ParseBeginVendor(self, state, tokens):
        if len(tokens) not in [2, 3]:
            raise ParseError(
                    'Incorrect number of tokens for begin-vendor statement',
                    file=state['file'],
                    line=state['line'], scope=state['scope'])

        # BEGIN-VENDOR <vendor> format=<Extended-Vendor-Specific attribute>
        # defines extended vendor-specific attributes (RFC 6929), which are
        # skipped
        vendor_format = None
        if len(tokens) == 3:
            if not tokens[2].startswith('format='):
                raise ParseError(
                        "Unknown option '%s' for begin-vendor statement" %
                        tokens[2],
                        file=state['file'],
                        line=state['line'], scope=state['scope'])
            vendor_format = tokens[2][len('format='):]

        vendor = tokens[1]

        if not self.vendors.HasForward(vendor):
            raise ParseError(
                    'Unknown vendor %s in begin-vendor statement' % vendor,
                    file=state['file'],
                    line=state['line'], scope=state['scope'])

        state['vendor'] = vendor
        state['vendor_format'] = vendor_format

    def __ParseEndVendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                'Incorrect number of tokens for end-vendor statement',
                file=state['file'],
                line=state['line'], scope=state['scope'])

        vendor = tokens[1]

        if state['vendor'] != vendor:
            raise ParseError(
                    'Ending non-open vendor ' + vendor,
                    file=state['file'],
                    line=state['line'], scope=state['scope'])
        state['vendor'] = ''
        state['vendor_format'] = None

    def SourceOf(self, name):
        """Return where an attribute or vendor was defined.

        :param name: an attribute or vendor name
        :type name: str
        :return: (file, line, scope) of its current definition, the
            file being '' for a dictionary read from a file-like
            object, or None for an unknown name
        :rtype: tuple[str, int, str] or None
        """
        return self.definition_sources.get(name)

    def ReadDictionary(self, file):
        """Read a dictionary file.

        Its definitions are merged into the dictionary; later definitions
        replace earlier ones. A redefinition of an attribute name replaces
        it, while several names aliasing the same code in one scope are all
        kept for FreeRADIUS compatibility; both cases log a warning, and
        the definition location of every attribute and vendor is recorded
        in ``definition_sources``. Unsupported attributes are skipped,
        listed in ``skipped_attributes``, and reported with one warning
        on the ``pyrad`` logger. A read-only snapshot of the include
        graph is appended to ``include_snapshots``.

        :param file: path of a dictionary file or a file-like object
        :type  file: str or io.TextIOBase
        :raises ParseError: for a syntax error, a recursive or too deep
            include, an include outside of the dictionary directory, an
            unknown or cross-vendor TLV parent
        :raises OSError: if a file can't be opened
        """

        fil = dictfile.DictFile(file)
        # walk the whole include graph first so the audit snapshot exists
        # even if the parse of its lines fails afterwards
        self.include_snapshots.append(fil.BuildSnapshot())

        state = {}
        state['vendor'] = ''
        state['vendor_format'] = None
        state['skipped'] = []
        self.defer_parse = []
        for line in fil:
            state['file'] = fil.File()
            state['line'] = fil.Line()
            # the scope is the active vendor block inside the current file
            state['scope'] = state['vendor'] or fil.Scope()
            line = line.split('#', 1)[0].strip()

            tokens = line.split()
            if not tokens:
                continue

            key = tokens[0].upper()
            if key == 'ATTRIBUTE':
                self.__ParseAttribute(state, tokens)
            elif key == 'VALUE':
                self.__ParseValue(state, tokens, True)
            elif key == 'VENDOR':
                self.__ParseVendor(state, tokens)
            elif key == 'BEGIN-VENDOR':
                self.__ParseBeginVendor(state, tokens)
            elif key == 'END-VENDOR':
                self.__ParseEndVendor(state, tokens)

        for state, tokens in self.defer_parse:
            key = tokens[0].upper()
            if key == 'VALUE':
                self.__ParseValue(state, tokens, False)
        self.defer_parse = []

        if state['skipped']:
            reasons = sorted(set(state['skipped']))
            logger.warning('Skipped %d unsupported dictionary attributes (%s)',
                           len(state['skipped']), ', '.join(reasons))
