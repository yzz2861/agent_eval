"""Distinguished Encoding Rules (DER) codec.

"""

import binascii

from . import ber
from . import restricted_utc_time_to_datetime
from . import restricted_utc_time_from_datetime
from . import restricted_generalized_time_to_datetime
from . import restricted_generalized_time_from_datetime
from .compiler import clean_bit_string_value
from .ber import Class, DecodeTagError, DecodeError, StandardEncodeMixin
from .ber import Encoding
from .ber import Tag
from .ber import encode_length_definite
from .ber import decode_full_length
from .ber import encode_signed_integer
from .ber import OutOfByteDataError
from .ber import MissingDataError
from .ber import TAG_MISMATCH
from .ber import Boolean
from .ber import Real
from .ber import Null
from .ber import ObjectIdentifier
from .ber import Enumerated
from .ber import Sequence
from .ber import Set
from .ber import Choice
from .ber import Any
from .ber import AnyDefinedBy
from .ber import Recursive
from .ber import ObjectDescriptor
from .ber import Date
from .ber import TimeOfDay
from .ber import DateTime
# These imports are not used in this module but referenced externally
from .ber import encode_tag
from .ber import encode_real
from .ber import decode_length
from .ber import decode_real


class DERDecodeError(DecodeError):

    """Base class for DER canonicalization errors raised while decoding."""


class NonMinimalLengthError(DERDecodeError):

    """Raised when a length is not encoded in the minimum number of octets."""


class NonCanonicalIntegerError(DERDecodeError):

    """Raised when an integer is not in minimal two's complement form."""


class IndefiniteLengthError(DERDecodeError):

    """Raised when an indefinite length encoding is encountered in DER."""


class TrailingDataError(DERDecodeError):

    """Raised when bytes remain after the outermost DER element."""


def decode_length_der(encoded, offset):
    """Decode a DER length octet, rejecting indefinite and non-minimal forms.

    Only definite lengths are valid in DER, and the long form must use the
    smallest possible number of length octets. BER-specific relaxations are
    intentionally not applied here.
    """
    try:
        first_octet = encoded[offset]
    except IndexError:
        raise OutOfByteDataError('Ran out of data when trying to read length',
                                 offset=offset)

    length_offset = offset
    offset += 1

    if first_octet < 0x80:
        length = first_octet
    elif first_octet == 0x80:
        raise IndefiniteLengthError(
            'Expected definite length, but got indefinite.',
            offset=length_offset)
    else:
        number_of_bytes = first_octet & 0x7f
        encoded_length = encoded[offset:number_of_bytes + offset]

        if len(encoded_length) != number_of_bytes:
            raise OutOfByteDataError(
                'Expected {} length byte(s) at offset {}, but got {}.'.format(
                    number_of_bytes, offset, len(encoded_length)),
                offset=offset)

        if encoded_length[0] == 0x00:
            raise NonMinimalLengthError(
                'Non-minimal DER length encoding: leading zero in length '
                'octets.',
                offset=length_offset)

        length = int(binascii.hexlify(encoded_length), 16)
        offset += number_of_bytes

        if length <= 0x7f:
            raise NonMinimalLengthError(
                'Non-minimal DER length encoding: length {} must use the '
                'short form.'.format(length),
                offset=length_offset)

    data_length = len(encoded)

    if offset + length > data_length:
        raise MissingDataError(
            'Expected at least {} contents byte(s), but got {}.'.format(
                length, data_length - offset),
            offset,
            length)

    return length, offset


def check_minimal_integer(data, offset, length, error_offset):
    """Validate the minimal two's complement contents octets of an integer."""
    if length == 0:
        raise NonCanonicalIntegerError(
            'Expected non-empty integer contents.',
            offset=error_offset)

    if length == 1:
        return

    first_octet = data[offset]
    second_octet = data[offset + 1]

    if first_octet == 0x00 and second_octet < 0x80:
        raise NonCanonicalIntegerError(
            'Non-canonical integer: redundant leading 0x00 octet.',
            offset=error_offset)

    if first_octet == 0xff and second_octet >= 0x80:
        raise NonCanonicalIntegerError(
            'Non-canonical integer: redundant leading 0xff octet.',
            offset=error_offset)


class StrictDecodeMixin(object):

    """Decode mixin enforcing the DER restrictions of a single tagged type."""

    def decode(self, data, offset, values=None):
        start_offset = offset
        offset += self.tag_len
        tag_data = data[start_offset:offset]

        if tag_data != self.tag:
            if len(tag_data) != self.tag_len:
                raise OutOfByteDataError(
                    'Ran out of data when reading tag',
                    offset=start_offset)

            return TAG_MISMATCH, start_offset

        length, offset = decode_length_der(data, offset)

        return self.decode_content(data, offset, length)


class Type(StrictDecodeMixin, ber.Type):

    def set_tag(self, number, flags):
        if not Class.APPLICATION & flags:
            flags |= Class.CONTEXT_SPECIFIC

        super().set_tag(number, flags)


class StringType(StandardEncodeMixin, Type):

    TAG = None
    ENCODING = None

    def __init__(self, name):
        super(StringType, self).__init__(name,
                                         self.__class__.__name__,
                                         self.TAG)

    def encode_content(self, data, values=None):
        return data.encode(self.ENCODING)

    def decode_content(self, data, offset, length):
        end_offset = offset + length
        return data[offset:end_offset].decode(self.ENCODING), end_offset


class ArrayType(StandardEncodeMixin, Type):

    def __init__(self, name, tag_name, tag, element_type):
        super(ArrayType, self).__init__(name,
                                        tag_name,
                                        tag,
                                        Encoding.CONSTRUCTED)
        self.element_type = element_type

    def set_tag(self, number, flags):
        super(ArrayType, self).set_tag(number,
                                       flags | Encoding.CONSTRUCTED)

    def encode_content(self, data, values=None):
        encoded_elements = bytearray()

        for entry in data:
            self.element_type.encode(entry, encoded_elements)

        return encoded_elements

    def decode_content(self, data, offset, length):
        decoded = []
        start_offset = offset

        while (offset - start_offset) < length:
            decoded_element, offset = self.element_type.decode(data, offset)
            if decoded_element == TAG_MISMATCH:
                raise DecodeTagError(self.element_type, data, offset,
                                     location=self.element_type)
            decoded.append(decoded_element)

        if offset != start_offset + length:
            raise DERDecodeError(
                'Constructed contents end at offset {}, but the declared '
                'length ends at offset {}.'.format(
                    offset, start_offset + length),
                offset=offset)

        return decoded, offset

    def __repr__(self):
        return '{}({}, {})'.format(self.__class__.__name__,
                                   self.name,
                                   self.element_type)


class Integer(StandardEncodeMixin, Type):

    def __init__(self, name):
        super(Integer, self).__init__(name,
                                      'INTEGER',
                                      Tag.INTEGER)

    def encode_content(self, data, values=None):
        return encode_signed_integer(data)

    def decode_content(self, data, offset, length):
        end_offset = offset + length
        check_minimal_integer(data, offset, length, offset - 1)

        value = int.from_bytes(data[offset:end_offset],
                               byteorder='big', signed=True)

        return value, end_offset


class BitString(Type):

    def __init__(self, name, has_named_bits):
        super(BitString, self).__init__(name,
                                        'BIT STRING',
                                        Tag.BIT_STRING)
        self.has_named_bits = has_named_bits

    def is_default(self, value):
        if self.default is None:
            return False

        clean_value = clean_bit_string_value(value,
                                             self.has_named_bits)
        clean_default = clean_bit_string_value(self.default,
                                               self.has_named_bits)

        return clean_value == clean_default

    def encode(self, data, encoded, values=None):
        number_of_bytes, number_of_rest_bits = divmod(data[1], 8)
        data = bytearray(data[0])

        if number_of_rest_bits == 0:
            data = data[:number_of_bytes]
            number_of_unused_bits = 0
        else:
            last_byte = data[number_of_bytes]
            last_byte &= ((0xff >> number_of_rest_bits) ^ 0xff)
            data = data[:number_of_bytes]
            data.append(last_byte)
            number_of_unused_bits = (8 - number_of_rest_bits)

        encoded.extend(self.tag)
        encoded.extend(encode_length_definite(len(data) + 1))
        encoded.append(number_of_unused_bits)
        encoded.extend(data)

    def decode_content(self, data, offset, length):
        end_offset = offset + length
        number_of_bits = 8 * (length - 1) - data[offset]
        offset += 1

        return (bytes(data[offset:end_offset]), number_of_bits), end_offset


class OctetString(StandardEncodeMixin, Type):

    def __init__(self, name):
        super(OctetString, self).__init__(name,
                                          'OCTET STRING',
                                          Tag.OCTET_STRING)

    def encode_content(self, data, values=None):
        return data

    def decode_content(self, data, offset, length):
        end_offset = offset + length

        return bytes(data[offset:end_offset]), end_offset


class SequenceOf(ArrayType):

    def __init__(self, name, element_type):
        super(SequenceOf, self).__init__(name,
                                         'SEQUENCE OF',
                                         Tag.SEQUENCE,
                                         element_type)


class SetOf(ArrayType):

    def __init__(self, name, element_type):
        super(SetOf, self).__init__(name,
                                    'SET OF',
                                    Tag.SET,
                                    element_type)


class UTF8String(StringType):

    TAG = Tag.UTF8_STRING
    ENCODING = 'utf-8'


class NumericString(StringType):

    TAG = Tag.NUMERIC_STRING
    ENCODING = 'ascii'


class PrintableString(StringType):

    TAG = Tag.PRINTABLE_STRING
    ENCODING = 'ascii'


class IA5String(StringType):

    TAG = Tag.IA5_STRING
    ENCODING = 'ascii'


class VisibleString(StringType):

    TAG = Tag.VISIBLE_STRING
    ENCODING = 'ascii'


class GeneralString(StringType):

    TAG = Tag.GENERAL_STRING
    ENCODING = 'latin-1'


class BMPString(StringType):

    TAG = Tag.BMP_STRING
    ENCODING = 'utf-16-be'


class UniversalString(StringType):

    TAG = Tag.UNIVERSAL_STRING
    ENCODING = 'utf-32-be'


class GraphicString(StringType):

    TAG = Tag.GRAPHIC_STRING
    ENCODING = 'latin-1'


class TeletexString(StringType):

    TAG = Tag.T61_STRING
    ENCODING = 'iso-8859-1'


class UTCTime(StandardEncodeMixin, Type):

    def __init__(self, name):
        super(UTCTime, self).__init__(name,
                                      'UTCTime',
                                      Tag.UTC_TIME)

    def encode_content(self, data, values=None):
        return restricted_utc_time_from_datetime(data).encode('ascii')

    def decode_content(self, data, offset, length):
        end_offset = offset + length
        decoded = data[offset:end_offset].decode('ascii')

        return restricted_utc_time_to_datetime(decoded), end_offset


class GeneralizedTime(StandardEncodeMixin, Type):

    def __init__(self, name):
        super(GeneralizedTime, self).__init__(name,
                                              'GeneralizedTime',
                                              Tag.GENERALIZED_TIME)

    def encode_content(self, data, values=None):
        return restricted_generalized_time_from_datetime(data).encode('ascii')

    def decode_content(self, data, offset, length):
        end_offset = offset + length
        decoded = data[offset:end_offset].decode('ascii')

        return restricted_generalized_time_to_datetime(decoded), end_offset


class Enumerated(StrictDecodeMixin, ber.Enumerated):

    def __init__(self, name, values, numeric):
        ber.Enumerated.__init__(self, name, values, numeric)

    def decode_content(self, data, offset, length):
        check_minimal_integer(data, offset, length, offset - 1)

        return ber.Enumerated.decode_content(self, data, offset, length)


class Boolean(StrictDecodeMixin, ber.Boolean):
    pass


class Null(StrictDecodeMixin, ber.Null):
    pass


class ObjectIdentifier(StrictDecodeMixin, ber.ObjectIdentifier):
    pass


class Real(StrictDecodeMixin, ber.Real):
    pass


class Sequence(StrictDecodeMixin, ber.Sequence):

    def __init__(self, name, root_members, additions):
        ber.MembersType.__init__(self, name,
                                 'SEQUENCE',
                                 Tag.SEQUENCE,
                                 root_members,
                                 additions)

    def decode_content(self, data, offset, length):
        end_offset = offset + length
        values, member_offset = self._decode_members_strict(
            data, offset, length)

        if member_offset != end_offset:
            raise DERDecodeError(
                'Constructed {} contents end at offset {}, but the declared '
                'length ends at offset {}.'.format(
                    self.type_name, member_offset, end_offset),
                offset=member_offset)

        return values, end_offset

    def _decode_members_strict(self, data, offset, length):
        end_offset = None if length is None else offset + length
        values = {}

        member_offset, _ = self.decode_members(
            self.root_members, data, values, offset, end_offset)

        if self.additions:
            member_offset, _ = self.decode_members(
                ber.flatten(self.additions), data, values,
                member_offset, end_offset, ignore_missing=True)

        # Preserve the pre-existing BER-compatible behavior for recursive
        # types whose members cannot be matched at all (see Sequence12 in
        # tests/files/all_types.asn): report an empty container instead of a
        # boundary error. Every other DER encoding must fill its container.
        if not values and self._is_recursive():
            member_offset = end_offset

        return values, member_offset

    def _is_recursive(self):
        for member in self.root_members:
            if isinstance(member, ber.Recursive):
                return True

            inner = getattr(member, 'element_type', None)

            if isinstance(inner, Recursive):
                return True

        return False


class Set(Sequence, ber.Set):
    def __init__(self, name, root_members, additions):
        ber.MembersType.__init__(self, name,
                                 'SET',
                                 Tag.SET,
                                 root_members,
                                 additions)


class Choice(ber.Choice):

    def decode(self, data, offset, values=None):
        tag = bytes(ber.read_tag(data, offset))

        if tag in self.tag_to_member:
            member = self.tag_to_member[tag]
        elif self.has_extension_marker:
            offset = ber.skip_tag(data, offset)
            length, offset = decode_length_der(data, offset)

            return (None, None), offset + length
        else:
            return TAG_MISMATCH, offset

        decoded, offset = member.decode(data, offset)

        if decoded == TAG_MISMATCH:
            raise DecodeTagError(member, data, offset, location=member)

        return (member.name, decoded), offset


class ExplicitTag(StrictDecodeMixin, ber.ExplicitTag):

    def __init__(self, name, inner):
        ber.ExplicitTag.__init__(self, name, inner)

    def decode_content(self, data, offset, length):
        end_offset = offset + length
        values, inner_offset = self.inner.decode(data, offset)

        if values == TAG_MISMATCH:
            raise DecodeTagError(self.inner, data, offset, location=self.inner)

        if inner_offset != end_offset:
            raise DERDecodeError(
                'Explicit tag contents end at offset {}, but the declared '
                'length ends at offset {}.'.format(inner_offset, end_offset),
                offset=inner_offset)

        return values, end_offset


class Any(ber.Any):

    def decode(self, data, offset, values=None):
        start = offset
        offset = ber.skip_tag(data, offset)
        length, offset = decode_length_der(data, offset)
        end_offset = offset + length

        return data[start:end_offset], end_offset


class AnyDefinedBy(ber.AnyDefinedBy):

    def decode(self, data, offset, values):
        if self.choices:
            try:
                choice = self.choices[values[self.type_member]]
            except KeyError:
                raise DecodeError(
                    'Bad AnyDefinedBy choice {}.'.format(
                        values[self.type_member]),
                    offset=offset)

            return choice.decode(data, offset)

        start = offset
        offset = ber.skip_tag(data, offset)
        length, offset = decode_length_der(data, offset)
        end_offset = offset + length

        return data[start:end_offset], end_offset


class Recursive(ber.Recursive):

    def decode(self, data, offset, values=None):
        return self.inner.decode(data, offset)


class Date(StrictDecodeMixin, ber.Date):
    pass


class TimeOfDay(StrictDecodeMixin, ber.TimeOfDay):
    pass


class DateTime(StrictDecodeMixin, ber.DateTime):
    pass


class ObjectDescriptor(GraphicString):

    TAG = Tag.OBJECT_DESCRIPTOR


class Compiler(ber.Compiler):

    def process_type(self, type_name, type_descriptor, module_name):
        compiled_type = self.compile_type(type_name,
                                          type_descriptor,
                                          module_name)

        return CompiledType(compiled_type)

    def compile_type(self, name, type_descriptor, module_name):
        module_name = self.get_module_name(type_descriptor, module_name)
        compiled = self.compile_implicit_type(name,
                                              type_descriptor,
                                              module_name)

        if self.is_explicit_tag(type_descriptor):
            compiled = ExplicitTag(name, compiled)

        if 'tag' in type_descriptor:
            compiled = self.copy(compiled)
            tag = type_descriptor['tag']
            class_ = tag.get('class', None)

            if class_ == 'APPLICATION':
                flags = Class.APPLICATION
            elif class_ == 'PRIVATE':
                flags = Class.PRIVATE
            elif class_ == 'UNIVERSAL':
                flags = 0
            else:
                flags = Class.CONTEXT_SPECIFIC

            compiled.set_tag(tag['number'], flags)

        return compiled

    def compile_implicit_type(self, name, type_descriptor, module_name):
        type_name = type_descriptor['type']

        if type_name == 'SEQUENCE':
            compiled = Sequence(
                name,
                *self.compile_members(type_descriptor['members'],
                                      module_name))
        elif type_name == 'SEQUENCE OF':
            compiled = SequenceOf(name,
                                  self.compile_type('',
                                                    type_descriptor['element'],
                                                    module_name))
        elif type_name == 'SET':
            compiled = Set(
                name,
                *self.compile_members(type_descriptor['members'],
                                      module_name))
        elif type_name == 'SET OF':
            compiled = SetOf(name,
                             self.compile_type('',
                                               type_descriptor['element'],
                                               module_name))
        elif type_name == 'CHOICE':
            compiled = Choice(
                name,
                *self.compile_members(type_descriptor['members'],
                                      module_name))
        elif type_name == 'INTEGER':
            compiled = Integer(name)
        elif type_name == 'REAL':
            compiled = Real(name)
        elif type_name == 'ENUMERATED':
            compiled = Enumerated(name,
                                  self.get_enum_values(type_descriptor,
                                                       module_name),
                                  self._numeric_enums)
        elif type_name == 'BOOLEAN':
            compiled = Boolean(name)
        elif type_name == 'OBJECT IDENTIFIER':
            compiled = ObjectIdentifier(name)
        elif type_name == 'OCTET STRING':
            compiled = OctetString(name)
        elif type_name == 'TeletexString':
            compiled = TeletexString(name)
        elif type_name == 'NumericString':
            compiled = NumericString(name)
        elif type_name == 'PrintableString':
            compiled = PrintableString(name)
        elif type_name == 'IA5String':
            compiled = IA5String(name)
        elif type_name == 'VisibleString':
            compiled = VisibleString(name)
        elif type_name == 'GeneralString':
            compiled = GeneralString(name)
        elif type_name == 'UTF8String':
            compiled = UTF8String(name)
        elif type_name == 'BMPString':
            compiled = BMPString(name)
        elif type_name == 'GraphicString':
            compiled = GraphicString(name)
        elif type_name == 'UTCTime':
            compiled = UTCTime(name)
        elif type_name == 'UniversalString':
            compiled = UniversalString(name)
        elif type_name == 'GeneralizedTime':
            compiled = GeneralizedTime(name)
        elif type_name == 'DATE':
            compiled = Date(name)
        elif type_name == 'TIME-OF-DAY':
            compiled = TimeOfDay(name)
        elif type_name == 'DATE-TIME':
            compiled = DateTime(name)
        elif type_name == 'BIT STRING':
            has_named_bits = ('named-bits' in type_descriptor)
            compiled = BitString(name, has_named_bits)
        elif type_name == 'ANY':
            compiled = Any(name)
        elif type_name == 'ANY DEFINED BY':
            choices = {}

            for key, value in type_descriptor['choices'].items():
                choices[key] = self.compile_type(key,
                                                 value,
                                                 module_name)

            compiled = AnyDefinedBy(name,
                                    type_descriptor['value'],
                                    choices)
        elif type_name == 'NULL':
            compiled = Null(name)
        elif type_name == 'EXTERNAL':
            compiled = Sequence(
                name,
                *self.compile_members(self.external_type_descriptor()['members'],
                                      module_name))
            compiled.set_tag(Tag.EXTERNAL, 0)
        elif type_name == 'ObjectDescriptor':
            compiled = ObjectDescriptor(name)
        else:
            if type_name in self.types_backtrace:
                compiled = Recursive(name,
                                     type_name,
                                     module_name)
                self.recursive_types.append(compiled)
            else:
                compiled = self.compile_user_type(name,
                                                  type_name,
                                                  module_name)

        return compiled


class CompiledType(ber.CompiledType):

    def decode_with_length(self, data):
        decoded, offset = super().decode_with_length(data)

        if offset != len(data):
            raise TrailingDataError(
                'Trailing data of {} byte(s) after the outermost DER '
                'element.'.format(len(data) - offset),
                offset=offset)

        return decoded, offset


def compile_dict(specification, numeric_enums=False):
    return Compiler(specification, numeric_enums).process()
