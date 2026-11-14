# coding: utf-8

"""
Functions for parsing and dumping using the ASN.1 DER encoding. Exports the
following items:

- ParseBudget()
- DepthLimitExceeded()
- NodeLimitExceeded()
- LengthLimitExceeded()
- ValueSizeLimitExceeded()
- TimeLimitExceeded()
- emit()
- parse()
- peek()

Other type classes are defined that help compose the types listed above.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import time

from ._types import byte_cls, chr_cls, type_name
from .util import int_from_bytes, int_to_bytes

_PY2 = sys.version_info <= (3,)
_INSUFFICIENT_DATA_MESSAGE = 'Insufficient data - %s bytes requested but only %s available'

# Default limits for a ParseBudget() created when no explicit budget is
# provided. These are intentionally generous enough that every legitimate
# certificate, CRL, CMS and BER sample parses unchanged, while still bounding
# the resources that a hostile 3 KB input can force the parser to consume.
DEFAULT_MAX_DEPTH = 100
DEFAULT_MAX_NODES = 500000
DEFAULT_MAX_VALUE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_LENGTH = 16 * 1024 * 1024
DEFAULT_MAX_TIME = 30.0

if hasattr(time, 'monotonic'):
    _monotonic = time.monotonic
else:
    _monotonic = time.time


class ParseLimitExceeded(ValueError):

    """
    The base class for all errors raised when a ParseBudget limit is hit.
    Each subclass identifies which limit was exceeded so callers can
    distinguish depth, node, length, value-size and time failures.
    """


class DepthLimitExceeded(ParseLimitExceeded):
    """Raised when the nesting depth exceeds the budget's max_depth"""


class NodeLimitExceeded(ParseLimitExceeded):
    """Raised when the number of parsed nodes exceeds max_nodes"""


class LengthLimitExceeded(ParseLimitExceeded):
    """Raised when a single TLV length octet declares more than max_length"""


class ValueSizeLimitExceeded(ParseLimitExceeded):
    """Raised when cumulative value bytes exceed max_value_bytes"""


class TimeLimitExceeded(ParseLimitExceeded):
    """Raised when parsing takes longer than max_time_seconds"""


class ParseBudget(object):

    """
    A mutable, pass-through resource budget shared by every stage of a
    BER/DER decode: the header/length parser, indefinite-length EOC scanning,
    constructed-type nesting and the lazy re-parsing performed by Any(),
    Choice() and ParsableOctetString() objects.

    A single budget instance is handed to the top-level parse call and then
    carried on every parsed object, so deferred parsing continues to draw
    from the same cumulative limits instead of opening a new context.

    Any limit may be set to None to disable that particular check.
    """

    def __init__(self, max_depth=DEFAULT_MAX_DEPTH, max_nodes=DEFAULT_MAX_NODES,
                 max_value_bytes=DEFAULT_MAX_VALUE_BYTES, max_length=DEFAULT_MAX_LENGTH,
                 max_time_seconds=DEFAULT_MAX_TIME):
        """
        :param max_depth:
            An integer maximum number of nested constructed/indefinite levels,
            or None to disable the depth check

        :param max_nodes:
            An integer maximum number of TLV nodes that may be visited,
            or None to disable the node check

        :param max_value_bytes:
            An integer maximum number of cumulative value (content) bytes that
            may be accounted across all visited nodes, or None to disable

        :param max_length:
            An integer maximum value that a single length octet may declare,
            or None to disable the per-length check

        :param max_time_seconds:
            A float maximum number of seconds that may elapse while parsing,
            or None to disable the time check
        """

        self.max_depth = self._validate_limit('max_depth', max_depth)
        self.max_nodes = self._validate_limit('max_nodes', max_nodes)
        self.max_value_bytes = self._validate_limit('max_value_bytes', max_value_bytes)
        self.max_length = self._validate_limit('max_length', max_length)
        self.max_time_seconds = self._validate_limit('max_time_seconds', max_time_seconds)

        self.depth = 0
        self.node_count = 0
        self.value_bytes = 0
        self.max_seen_length = 0
        self._start_time = _monotonic()

    @staticmethod
    def _validate_limit(name, value):
        if value is None:
            return None
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
            raise TypeError('%s must be a positive number or None, not %r' % (name, value))
        return value

    def check_time(self):
        """
        Raises TimeLimitExceeded if the elapsed wall time has exceeded
        max_time_seconds.
        """

        if self.max_time_seconds is not None:
            if _monotonic() - self._start_time > self.max_time_seconds:
                raise TimeLimitExceeded(
                    'Parsing time limit exceeded - more than %s seconds elapsed' % self.max_time_seconds
                )

    def enter_node(self):
        """
        Accounts for one parsed TLV node, checking the time and node limits.
        """

        self.check_time()
        if self.max_nodes is not None and self.node_count >= self.max_nodes:
            raise NodeLimitExceeded(
                'Node limit exceeded - more than %d ASN.1 nodes encountered' % self.max_nodes
            )
        self.node_count += 1

    def enter_depth(self):
        """
        Accounts for descending into a constructed or indefinite-length value.
        """

        if self.max_depth is not None and self.depth >= self.max_depth:
            raise DepthLimitExceeded(
                'Nesting depth limit exceeded - more than %d levels of nesting' % self.max_depth
            )
        self.depth += 1

    def leave_depth(self):
        """
        Accounts for returning from a constructed or indefinite-length value.
        """

        self.depth -= 1

    def check_length(self, length):
        """
        Accounts for a length declared in a TLV header, enforcing the
        per-value length cap before the contents are touched.

        :param length:
            The integer number of content bytes declared by the header
        """

        if length > self.max_seen_length:
            self.max_seen_length = length
        if self.max_length is not None and length > self.max_length:
            raise LengthLimitExceeded(
                'Length limit exceeded - a value declares a length of %d bytes, '
                'but the limit is %d bytes' % (length, self.max_length)
            )

    def add_value_bytes(self, num_bytes):
        """
        Accounts for the value bytes of a parsed TLV node.

        :param num_bytes:
            The integer number of content bytes in the node
        """

        self.value_bytes += num_bytes
        if self.max_value_bytes is not None and self.value_bytes > self.max_value_bytes:
            raise ValueSizeLimitExceeded(
                'Value size limit exceeded - more than %d cumulative value bytes encountered' % self.max_value_bytes
            )


def emit(class_, method, tag, contents):
    """
    Constructs a byte string of an ASN.1 DER-encoded value

    This is typically not useful. Instead, use one of the standard classes from
    asn1crypto.core, or construct a new class with specific fields, and call the
    .dump() method.

    :param class_:
        An integer ASN.1 class value: 0 (universal), 1 (application),
        2 (context), 3 (private)

    :param method:
        An integer ASN.1 method value: 0 (primitive), 1 (constructed)

    :param tag:
        An integer ASN.1 tag value

    :param contents:
        A byte string of the encoded byte contents

    :return:
        A byte string of the ASN.1 DER value (header and contents)
    """

    if not isinstance(class_, int):
        raise TypeError('class_ must be an integer, not %s' % type_name(class_))

    if class_ < 0 or class_ > 3:
        raise ValueError('class_ must be one of 0, 1, 2 or 3, not %s' % class_)

    if not isinstance(method, int):
        raise TypeError('method must be an integer, not %s' % type_name(method))

    if method < 0 or method > 1:
        raise ValueError('method must be 0 or 1, not %s' % method)

    if not isinstance(tag, int):
        raise TypeError('tag must be an integer, not %s' % type_name(tag))

    if tag < 0:
        raise ValueError('tag must be greater than zero, not %s' % tag)

    if not isinstance(contents, byte_cls):
        raise TypeError('contents must be a byte string, not %s' % type_name(contents))

    return _dump_header(class_, method, tag, contents) + contents


def parse(contents, strict=False, budget=None):
    """
    Parses a byte string of ASN.1 BER/DER-encoded data.

    This is typically not useful. Instead, use one of the standard classes from
    asn1crypto.core, or construct a new class with specific fields, and call the
    .load() class method.

    :param contents:
        A byte string of BER/DER-encoded data

    :param strict:
        A boolean indicating if trailing data should be forbidden - if so, a
        ValueError will be raised when trailing data exists

    :param budget:
        A ParseBudget() object bounding the depth, node count, value bytes,
        length and time used while parsing. If omitted, a default ParseBudget()
        is used.

    :raises:
        ValueError - when the contents do not contain an ASN.1 header or are truncated in some way
        TypeError - when contents is not a byte string

    :return:
        A 6-element tuple:
         - 0: integer class (0 to 3)
         - 1: integer method
         - 2: integer tag
         - 3: byte string header
         - 4: byte string content
         - 5: byte string trailer
    """

    if not isinstance(contents, byte_cls):
        raise TypeError('contents must be a byte string, not %s' % type_name(contents))

    if budget is None:
        budget = ParseBudget()
    elif not isinstance(budget, ParseBudget):
        raise TypeError('budget must be an instance of ParseBudget, not %s' % type_name(budget))

    contents_len = len(contents)
    info, consumed = _parse(contents, contents_len, budget=budget)
    if strict and consumed != contents_len:
        raise ValueError('Extra data - %d bytes of trailing data were provided' % (contents_len - consumed))
    return info


def peek(contents, budget=None):
    """
    Parses a byte string of ASN.1 BER/DER-encoded data to find the length

    This is typically used to look into an encoded value to see how long the
    next chunk of ASN.1-encoded data is. Primarily it is useful when a
    value is a concatenation of multiple values.

    :param contents:
        A byte string of BER/DER-encoded data

    :raises:
        ValueError - when the contents do not contain an ASN.1 header or are truncated in some way
        TypeError - when contents is not a byte string

    :param budget:
        A ParseBudget() object bounding the resources used while parsing. If
        omitted, a default ParseBudget() is used.

    :return:
        An integer with the number of bytes occupied by the ASN.1 value
    """

    if not isinstance(contents, byte_cls):
        raise TypeError('contents must be a byte string, not %s' % type_name(contents))

    if budget is None:
        budget = ParseBudget()
    elif not isinstance(budget, ParseBudget):
        raise TypeError('budget must be an instance of ParseBudget, not %s' % type_name(budget))

    info, consumed = _parse(contents, len(contents), budget=budget)
    return consumed


def _parse(encoded_data, data_len, pointer=0, lengths_only=False, budget=None):
    """
    Parses a byte string into component parts

    :param encoded_data:
        A byte string that contains BER-encoded data

    :param data_len:
        The integer length of the encoded data

    :param pointer:
        The index in the byte string to parse from

    :param lengths_only:
        A boolean to cause the call to return a 2-element tuple of the integer
        number of bytes in the header and the integer number of bytes in the
        contents. Internal use only.

    :param budget:
        The ParseBudget() object tracking depth, node, value-byte, length and
        time limits. The same instance is shared by every recursive call so
        that indefinite-length EOC scanning and regular nesting draw from one
        cumulative set of counters.

    :return:
        A 2-element tuple:
         - 0: A tuple of (class_, method, tag, header, content, trailer)
         - 1: An integer indicating how many bytes were consumed
    """

    if budget is None:
        budget = ParseBudget()

    budget.enter_node()

    start = pointer

    if data_len < pointer + 1:
        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (1, data_len - pointer))
    first_octet = ord(encoded_data[pointer]) if _PY2 else encoded_data[pointer]

    pointer += 1

    tag = first_octet & 31
    constructed = (first_octet >> 5) & 1
    # Base 128 length using 8th bit as continuation indicator
    if tag == 31:
        tag = 0
        while True:
            if data_len < pointer + 1:
                raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (1, data_len - pointer))
            num = ord(encoded_data[pointer]) if _PY2 else encoded_data[pointer]
            pointer += 1
            if num == 0x80 and tag == 0:
                raise ValueError('Non-minimal tag encoding')
            tag *= 128
            tag += num & 127
            if num >> 7 == 0:
                break
        if tag < 31:
            raise ValueError('Non-minimal tag encoding')

    if data_len < pointer + 1:
        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (1, data_len - pointer))
    length_octet = ord(encoded_data[pointer]) if _PY2 else encoded_data[pointer]
    pointer += 1
    trailer = b''

    if length_octet >> 7 == 0:
        content_length = length_octet & 127
        budget.check_length(content_length)
        contents_end = pointer + content_length

    else:
        length_octets = length_octet & 127
        if length_octets:
            if data_len < pointer + length_octets:
                raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (length_octets, data_len - pointer))
            pointer += length_octets
            content_length = int_from_bytes(encoded_data[pointer - length_octets:pointer], signed=False)
            # Enforce the per-value length cap before any allocation or read
            # driven by the declared length.
            budget.check_length(content_length)
            contents_end = pointer + content_length

        else:
            # To properly parse indefinite length values, we need to scan forward
            # parsing headers until we find a value with a length of zero. If we
            # just scanned looking for \x00\x00, nested indefinite length values
            # would not work.
            if not constructed:
                raise ValueError('Indefinite-length element must be constructed')
            budget.enter_depth()
            contents_end = pointer
            try:
                while data_len < contents_end + 2 or encoded_data[contents_end:contents_end+2] != b'\x00\x00':
                    _, contents_end = _parse(encoded_data, data_len, contents_end, lengths_only=True, budget=budget)
                contents_end += 2
            finally:
                budget.leave_depth()
            trailer = b'\x00\x00'
            content_length = contents_end - pointer - len(trailer)

    if contents_end > data_len:
        raise ValueError(_INSUFFICIENT_DATA_MESSAGE % (contents_end - pointer, data_len - pointer))

    budget.add_value_bytes(content_length)

    if lengths_only:
        return (pointer, contents_end)

    return (
        (
            first_octet >> 6,
            constructed,
            tag,
            encoded_data[start:pointer],
            encoded_data[pointer:contents_end-len(trailer)],
            trailer
        ),
        contents_end
    )


def _dump_header(class_, method, tag, contents):
    """
    Constructs the header bytes for an ASN.1 object

    :param class_:
        An integer ASN.1 class value: 0 (universal), 1 (application),
        2 (context), 3 (private)

    :param method:
        An integer ASN.1 method value: 0 (primitive), 1 (constructed)

    :param tag:
        An integer ASN.1 tag value

    :param contents:
        A byte string of the encoded byte contents

    :return:
        A byte string of the ASN.1 DER header
    """

    header = b''

    id_num = 0
    id_num |= class_ << 6
    id_num |= method << 5

    if tag >= 31:
        cont_bit = 0
        while tag > 0:
            header = chr_cls(cont_bit | (tag & 0x7f)) + header
            if not cont_bit:
                cont_bit = 0x80
            tag = tag >> 7
        header = chr_cls(id_num | 31) + header
    else:
        header += chr_cls(id_num | tag)

    length = len(contents)
    if length <= 127:
        header += chr_cls(length)
    else:
        length_bytes = int_to_bytes(length)
        header += chr_cls(0x80 | len(length_bytes))
        header += length_bytes

    return header
