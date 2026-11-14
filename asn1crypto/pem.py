# coding: utf-8

"""
Encoding DER to PEM and decoding PEM to DER. Exports the following items:

 - armor()
 - detect()
 - unarmor()
 - unarmor_one()
 - unarmor_certificate()
 - unarmor_certificates()
 - unarmor_private_key()
 - PEMBlock()

"""

from __future__ import unicode_literals, division, absolute_import, print_function

import base64
from collections import namedtuple
import re
import sys

from ._errors import unwrap
from ._ordereddict import OrderedDict
from ._types import type_name as _type_name, str_cls, byte_cls

if sys.version_info < (3,):
    from cStringIO import StringIO as BytesIO
else:
    from io import BytesIO


#: Labels that identify PEM blocks containing a DER-encoded private key
PRIVATE_KEY_LABELS = (
    'PRIVATE KEY',
    'RSA PRIVATE KEY',
    'DSA PRIVATE KEY',
    'EC PRIVATE KEY',
    'ENCRYPTED PRIVATE KEY',
)

#: Labels that identify PEM blocks containing a DER-encoded certificate
CERTIFICATE_LABELS = (
    'CERTIFICATE',
    'TRUSTED CERTIFICATE',
)

# A named tuple containing the parsed contents and location of one PEM block:
# (label, headers, der_bytes, start_offset, end_offset)
PEMBlock = namedtuple('PEMBlock', ['label', 'headers', 'der_bytes', 'start_offset', 'end_offset'])

_LABEL_CHARS = re.compile(b'^[A-Z0-9]+(?:[ ][A-Z0-9]+)*$')
_LINE_ENDING = re.compile(b'\r\n|\r|\n')
_BASE64_CHARS = re.compile(b'^[A-Za-z0-9+/]+={0,2}$')


def _split_lines(pem_bytes):
    """
    Split PEM bytes into (line_bytes, start_offset, end_offset) tuples

    Both LF and CRLF line endings are accepted. The offsets refer to the
    original byte string and do not include the line ending.
    """

    lines = []
    offset = 0
    for match in _LINE_ENDING.finditer(pem_bytes):
        lines.append((pem_bytes[offset:match.start()], offset, match.start()))
        offset = match.end()
    if offset < len(pem_bytes):
        lines.append((pem_bytes[offset:], offset, len(pem_bytes)))
    return lines


def _parse_boundary(line):
    """
    Parse a BEGIN or END boundary line into (keyword, label)

    :return:
        A tuple of (keyword, label) where keyword is "BEGIN" or "END", or
        None when the line is not a boundary line

    :raises:
        ValueError - when the line looks like a boundary line but uses a
            malformed label, whitespace or dash layout
    """

    stripped = line.rstrip(b' \\t')

    # Both the modern "-----BEGIN LABEL-----" format and the legacy
    # "---- BEGIN LABEL ----" format are accepted.
    match = re.match(
        b'^----(?:-| )(BEGIN|END) (.*?)(?:-| )----$',
        stripped
    )
    if not match:
        if line.lstrip(b' \\t').startswith((b'-----', b'---- ')):
            raise ValueError(unwrap(
                '''
                malformed PEM boundary line - boundary labels must be
                uppercase ASCII and wrapped in five dashes
                '''
            ))
        return None

    keyword = match.group(1).decode('ascii')
    label_bytes = match.group(2)
    if not label_bytes or not _LABEL_CHARS.match(label_bytes):
        raise ValueError(unwrap(
            '''
            malformed PEM %s boundary line - labels may only contain
            uppercase ASCII letters, digits and single spaces
            ''',
            keyword
        ))

    label = label_bytes.decode('ascii')
    return keyword, label


def _decode_base64(base64_data, block_label):
    """
    Decode strictly-canonical base64 data without echoing it in errors
    """

    if not base64_data:
        raise ValueError(unwrap(
            '''
            empty PEM block with label %s - the base64 body is missing
            ''',
            block_label
        ))

    joined = b''.join(base64_data)
    if not _BASE64_CHARS.match(joined):
        raise ValueError(unwrap(
            '''
            invalid base64 in PEM block with label %s - only the standard
            base64 alphabet with canonical padding is permitted
            ''',
            block_label
        ))

    if len(joined) % 4:
        raise ValueError(unwrap(
            '''
            invalid base64 in PEM block with label %s - the encoded data
            length must be a multiple of four characters
            ''',
            block_label
        ))

    try:
        # Python 2.6's binascii does not accept bytearray objects, so use
        # a plain byte string for the decode call.
        if sys.version_info < (2, 7):
            joined = str(bytearray(joined))
        der_bytes = base64.b64decode(joined)
    except (TypeError, ValueError):
        raise ValueError(unwrap(
            '''
            invalid base64 in PEM block with label %s
            ''',
            block_label
        ))

    # Reject non-canonical encodings, including excess padding and
    # non-zero unused bits, by requiring an exact round trip.
    if base64.b64encode(der_bytes) != joined:
        raise ValueError(unwrap(
            '''
            non-canonical base64 in PEM block with label %s
            ''',
            block_label
        ))

    return der_bytes


def _validate_der_prefix(der_bytes, label):
    """
    Verify that decoded block content is complete DER data

    The content must begin with a DER SEQUENCE tag, use definite-length
    minimal encoding, and consist of one or more complete TLVs that consume
    every decoded byte. The concatenated TLV layout is used by trusted
    certificate blocks.
    """

    offset = 0
    total_length = len(der_bytes)
    found_tlv = False

    while offset < total_length:
        if not found_tlv and der_bytes[offset:offset + 1] != b'\x30':
            raise ValueError(unwrap(
                '''
                PEM block with label %s does not contain DER data - the
                content must begin with a DER SEQUENCE tag
                ''',
                label
            ))

        if total_length - offset < 2:
            raise ValueError(unwrap(
                '''
                PEM block with label %s contains a truncated DER TLV at byte
                offset %d
                ''',
                label,
                offset
            ))

        first_length_byte = der_bytes[offset + 1]
        if first_length_byte == 0x80:
            raise ValueError(unwrap(
                '''
                PEM block with label %s contains an indefinite-length DER
                encoding, which is not valid DER
                ''',
                label
            ))

        if first_length_byte < 0x80:
            length_size = 0
            content_length = first_length_byte
        else:
            length_size = first_length_byte & 0x7F
            header_end = offset + 2 + length_size
            if length_size == 0 or length_size > 4 or header_end > total_length:
                raise ValueError(unwrap(
                    '''
                    PEM block with label %s contains a malformed DER length
                    at byte offset %d
                    ''',
                    label,
                    offset
                ))
            length_bytes = der_bytes[offset + 2:header_end]
            if length_bytes[0:1] == b'\x00':
                raise ValueError(unwrap(
                    '''
                    PEM block with label %s contains a non-minimal DER
                    length at byte offset %d
                    ''',
                    label,
                    offset
                ))
            content_length = 0
            for byte in bytearray(length_bytes):
                content_length = (content_length << 8) | byte

        tlv_length = 2 + length_size + content_length
        if offset + tlv_length > total_length:
            raise ValueError(unwrap(
                '''
                PEM block with label %s contains a truncated DER TLV at
                byte offset %d
                ''',
                label,
                offset
            ))
        offset += tlv_length
        found_tlv = True

    if not found_tlv:
        raise ValueError(unwrap(
            '''
            PEM block with label %s does not contain DER data
            ''',
            label
        ))


def _as_label_tuple(expected_label):
    if isinstance(expected_label, str_cls):
        return (expected_label,)
    try:
        labels = tuple(expected_label)
    except TypeError:
        raise TypeError(unwrap(
            '''
            expected_label must be a unicode string or an iterable of
            unicode strings, not %s
            ''',
            _type_name(expected_label)
        ))
    for label in labels:
        if not isinstance(label, str_cls):
            raise TypeError(unwrap(
                '''
                expected_label values must be unicode strings, not %s
                ''',
                _type_name(label)
            ))
    return labels


def detect(byte_string):
    """
    Detect if a byte string seems to contain a PEM-encoded block

    :param byte_string:
        A byte string to look through

    :return:
        A boolean, indicating if a PEM-encoded block is contained in the byte
        string
    """

    if not isinstance(byte_string, byte_cls):
        raise TypeError(unwrap(
            '''
            byte_string must be a byte string, not %s
            ''',
            _type_name(byte_string)
        ))

    return byte_string.find(b'-----BEGIN') != -1 or byte_string.find(b'---- BEGIN') != -1


def armor(type_name, der_bytes, headers=None):
    """
    Armors a DER-encoded byte string in PEM

    :param type_name:
        A unicode string that will be capitalized and placed in the header
        and footer of the block. E.g. "CERTIFICATE", "PRIVATE KEY", etc. This
        will appear as "-----BEGIN CERTIFICATE-----" and
        "-----END CERTIFICATE-----".

    :param der_bytes:
        A byte string to be armored

    :param headers:
        An OrderedDict of the header lines to write after the BEGIN line

    :return:
        A byte string of the PEM block
    """

    if not isinstance(der_bytes, byte_cls):
        raise TypeError(unwrap(
            '''
            der_bytes must be a byte string, not %s
            ''' % _type_name(der_bytes)
        ))

    if not isinstance(type_name, str_cls):
        raise TypeError(unwrap(
            '''
            type_name must be a unicode string, not %s
            ''',
            _type_name(type_name)
        ))

    type_name = type_name.upper().encode('ascii')

    output = BytesIO()
    output.write(b'-----BEGIN ')
    output.write(type_name)
    output.write(b'-----\n')
    if headers:
        for key in headers:
            output.write(key.encode('ascii'))
            output.write(b': ')
            output.write(headers[key].encode('ascii'))
            output.write(b'\n')
        output.write(b'\n')
    b64_bytes = base64.b64encode(der_bytes)
    b64_len = len(b64_bytes)
    i = 0
    while i < b64_len:
        output.write(b64_bytes[i:i + 64])
        output.write(b'\n')
        i += 64
    output.write(b'-----END ')
    output.write(type_name)
    output.write(b'-----\n')

    return output.getvalue()


def _unarmor_blocks(pem_bytes):
    """
    Parse every PEM block in a byte string with strict boundary and content
    rules

    :param pem_bytes:
        A byte string of the PEM-encoded data

    :raises:
        ValueError - when the data is not valid PEM, including mismatched
            labels, malformed boundaries, invalid or non-canonical base64,
            invalid DER prefixes, empty blocks, nested boundaries or any data
            outside of a block
        TypeError - when pem_bytes is not a byte string

    :return:
        A list of PEMBlock named tuples, including byte offsets for each block
    """

    if not isinstance(pem_bytes, byte_cls):
        raise TypeError(unwrap(
            '''
            pem_bytes must be a byte string, not %s
            ''',
            _type_name(pem_bytes)
        ))

    blocks = []

    # Valid states are "outside", "headers" and "body"
    state = 'outside'
    label = None
    headers = None
    body_lines = None
    start_offset = None
    block_index = 0

    for line, start, end in _split_lines(pem_bytes):
        boundary = _parse_boundary(line)

        if state == 'outside':
            if boundary is None:
                if line.strip():
                    raise ValueError(unwrap(
                        '''
                        unexpected non-PEM data at byte offset %d - only
                        PEM blocks and blank lines are permitted
                        ''',
                        start
                    ))
                continue

            keyword, label = boundary
            if keyword != 'BEGIN':
                raise ValueError(unwrap(
                    '''
                    END boundary with label %s found at byte offset %d
                    without a matching BEGIN boundary
                    ''',
                    label,
                    start
                ))

            state = 'headers'
            headers = OrderedDict()
            body_lines = []
            start_offset = start
            continue

        if boundary is not None:
            keyword, boundary_label = boundary
            if keyword == 'BEGIN':
                raise ValueError(unwrap(
                    '''
                    nested BEGIN boundary with label %s found inside PEM
                    block %d (label %s) at byte offset %d
                    ''',
                    boundary_label,
                    block_index,
                    label,
                    start
                ))
            if boundary_label != label:
                raise ValueError(unwrap(
                    '''
                    mismatched PEM labels - block %d begins with %s but
                    ends with %s at byte offset %d
                    ''',
                    block_index,
                    label,
                    boundary_label,
                    start
                ))

            der_bytes = _decode_base64(body_lines, label)
            # Legacy OpenSSL encrypted keys ("Proc-Type: 4,ENCRYPTED") hold
            # raw ciphertext rather than a DER SEQUENCE in the PEM body.
            if headers.get('Proc-Type') != '4,ENCRYPTED':
                _validate_der_prefix(der_bytes, label)
            blocks.append(PEMBlock(
                label=label,
                headers=headers,
                der_bytes=der_bytes,
                start_offset=start_offset,
                end_offset=end
            ))

            block_index += 1
            state = 'outside'
            label = None
            headers = None
            body_lines = None
            start_offset = None
            continue

        elif state == 'headers':
            if not line:
                # A blank line separates legacy header fields from the body,
                # but blank lines before the first header are harmless.
                state = 'body'
                continue
            colon_index = line.find(b':')
            if colon_index <= 0 or colon_index == len(line) - 1:
                state = 'body'
            else:
                try:
                    header_line = line.decode('ascii')
                except UnicodeDecodeError:
                    raise ValueError(unwrap(
                        '''
                        PEM header field at byte offset %d must contain
                        ASCII text
                        ''',
                        start
                    ))
                name, value = header_line.split(':', 1)
                if not name or not name.strip() or not value.strip():
                    raise ValueError(unwrap(
                        '''
                        malformed PEM header field at byte offset %d
                        ''',
                        start
                    ))
                headers[name] = value.strip()
                continue

        if state == 'body':
            if not line:
                # RFC 7468 permits blank lines in the base64 portion.
                continue
            if line.strip() != line or not re.match(b'^[A-Za-z0-9+/=]+$', line):
                raise ValueError(unwrap(
                    '''
                    invalid base64 line in PEM block with label %s at byte
                    offset %d
                    ''',
                    label,
                    start
                ))
            body_lines.append(line)

    if state != 'outside':
        raise ValueError(unwrap(
            '''
            PEM block with label %s is missing its END boundary
            ''',
            label
        ))

    if not blocks:
        raise ValueError(unwrap(
            '''
            pem_bytes does not appear to contain PEM-encoded data - no
            BEGIN/END combination found
            '''
        ))

    return blocks


def unarmor(pem_bytes):
    """
    Parse all PEM blocks and return an explicit block list

    Every block is fully validated before it is returned. Unknown but
    syntactically valid labels are retained in the result; callers that need a
    specific object type must inspect or filter the labels instead of assuming
    the first block is safe.

    :param pem_bytes:
        A byte string of the PEM-encoded data

    :raises:
        ValueError - when the data is not valid PEM or contains data outside
            of the PEM blocks
        TypeError - when pem_bytes is not a byte string

    :return:
        A list of PEMBlock named tuples, each containing label, headers,
        der_bytes, start_offset and end_offset
    """

    return _unarmor_blocks(pem_bytes)


def unarmor_one(pem_bytes, expected_label):
    """
    Parse exactly one PEM block with the caller-declared label

    :param pem_bytes:
        A byte string containing exactly one PEM block

    :param expected_label:
        A unicode label string or iterable of allowed label strings, such as
        "CERTIFICATE" or pem.PRIVATE_KEY_LABELS

    :raises:
        ValueError - when there is not exactly one block, the label is not
            allowed, or the PEM data is otherwise invalid
        TypeError - when an argument has the wrong type

    :return:
        The matching PEMBlock named tuple
    """

    labels = _as_label_tuple(expected_label)
    blocks = _unarmor_blocks(pem_bytes)

    if len(blocks) != 1:
        raise ValueError(unwrap(
            '''
            expected exactly one PEM block, but found %d blocks
            ''',
            len(blocks)
        ))

    block = blocks[0]
    if block.label not in labels:
        raise ValueError(unwrap(
            '''
            expected PEM label %s, but found %s
            ''',
            ' or '.join(labels),
            block.label
        ))

    return block


def unarmor_certificate(pem_bytes):
    """
    Read exactly one certificate PEM block and return its DER bytes

    Private-key labels and any other non-certificate label are rejected,
    instead of being treated as a certificate.

    :param pem_bytes:
        A byte string containing exactly one certificate PEM block

    :return:
        A byte string of DER-encoded certificate data
    """

    return unarmor_one(pem_bytes, CERTIFICATE_LABELS).der_bytes


def unarmor_certificates(pem_bytes):
    """
    Read a certificate or a multi-certificate bundle

    Every block must use a certificate label. A bundle of several valid
    certificate blocks is returned as a list of PEMBlock named tuples.

    :param pem_bytes:
        A byte string containing one or more certificate PEM blocks

    :return:
        A list of PEMBlock named tuples for the certificate blocks
    """

    blocks = _unarmor_blocks(pem_bytes)
    for block in blocks:
        if block.label not in CERTIFICATE_LABELS:
            raise ValueError(unwrap(
                '''
                expected a PEM certificate label, but found %s
                ''',
                block.label
            ))
    return blocks


def unarmor_private_key(pem_bytes):
    """
    Read exactly one private-key PEM block

    Only recognized private-key labels are accepted, so an unrecognized or
    certificate block can never silently degrade into key material.

    :param pem_bytes:
        A byte string containing exactly one private-key PEM block

    :return:
        The matching PEMBlock named tuple, including any encryption headers
    """

    return unarmor_one(pem_bytes, PRIVATE_KEY_LABELS)
