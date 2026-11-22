# coding: utf-8

"""
Forensic inventory of CMS / PKCS#7 signing material.

A CMS message has three different views that are easy to conflate:

 - the exact bytes that a signature was computed over
 - the decoded ASN.1 semantics
 - changes made by an archival tool to the outer BER/DER encoding

The helpers in this module keep those views separate. Original byte strings
are sliced from the value loaded by asn1crypto and are never replaced by a
canonical DER serialization.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import base64
import datetime
import hashlib
import json
import sys

from ._ordereddict import OrderedDict
from ._types import byte_cls, str_cls, type_name
from .parser import _parse, _dump_header


OID_DATA = '1.2.840.113549.1.7.1'
OID_SIGNED_DATA = '1.2.840.113549.1.7.2'

OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
OID_SIGNING_TIME = '1.2.840.113549.1.9.5'
OID_COUNTER_SIGNATURE = '1.2.840.113549.1.9.6'
OID_TIMESTAMP_TOKEN = '1.2.840.113549.1.9.16.2.14'
OID_MICROSOFT_NESTED_SIGNATURE = '1.3.6.1.4.1.311.2.4.1'
OID_MICROSOFT_TIMESTAMP_TOKEN = '1.3.6.1.4.1.311.3.3.1'

_MAX_LAYER_DEPTH = 8


class ForensicError(ValueError):
    """
    Raised when a CMS value can not be given a meaningful forensic inventory
    """


class _Record(OrderedDict):
    """
    An OrderedDict with attribute access, used for all public records
    """

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value

    @property
    def native(self):
        return self

    def as_dict(self):
        """
        :return:
            A recursively converted plain dict, preserving byte strings
        """

        return _as_plain(self)

    to_dict = as_dict

    def as_jsonable(self):
        """
        :return:
            A recursively converted value that json.dumps() accepts
        """

        return _as_jsonable(self)

    def as_json(self, **kwargs):
        """
        :return:
            A JSON string. Byte strings are base64 encoded.
        """

        if 'sort_keys' not in kwargs:
            kwargs['sort_keys'] = True
        if 'indent' not in kwargs:
            kwargs['indent'] = 2
        return json.dumps(self.as_jsonable(), **kwargs)


class Tlv(_Record):
    """
    A BER/DER tag-length-value located in the original byte string.

    The parser here deliberately does not normalize indefinite lengths, tag
    forms, SET OF ordering or anything else. .raw is always the exact input
    slice.
    """

    def __init__(self, blob, start, end, class_, method, tag, header, content,
                 trailer):
        _Record.__init__(self)
        self['blob'] = blob
        self['start'] = start
        self['end'] = end
        self['class'] = class_
        self['method'] = method
        self['tag'] = tag
        self['header'] = header
        self['content'] = content
        self['trailer'] = trailer
        self['indefinite'] = bool(trailer == b'\x00\x00' and header[-1:] == b'\x80')
        self['header_start'] = start
        self['header_end'] = start + len(header)
        self['content_start'] = self['header_end']
        self['content_end'] = end - len(trailer)

    @property
    def raw(self):
        return self['blob'][self['start']:self['end']]

    @property
    def encoded(self):
        return self.raw

    @property
    def is_constructed(self):
        return self['method'] == 1

    @property
    def is_indefinite(self):
        return self['indefinite']

    @property
    def is_der(self):
        try:
            if self.is_indefinite:
                return False
            expected = _dump_header(self['class'], self['method'], self['tag'], self['content'])
            if expected != self['header']:
                return False
            if not self.is_constructed:
                return True
            for child in self.children():
                if not child.is_der:
                    return False
            return True
        except Exception:
            return False

    def children(self):
        if not self.is_constructed:
            return []
        output = []
        pointer = 0
        length = len(self['content'])
        while pointer < length:
            child = parse_tlv(self['blob'], self['content_start'] + pointer,
                              base_offset=0, content_limit=length)
            output.append(child)
            pointer = child['end'] - self['content_start']
            if pointer <= 0:
                raise ForensicError('zero-length TLV while walking children')
        return output

    def find(self, class_, tag):
        for child in self.children():
            if child['class'] == class_ and child['tag'] == tag:
                return child
        return None

    def find_all(self, class_, tag):
        return [
            child for child in self.children()
            if child['class'] == class_ and child['tag'] == tag
        ]

    def walk(self):
        yield self
        for child in self.children():
            for descendant in child.walk():
                yield descendant

    def region(self):
        """
        :return:
            A stable description of the byte range occupied by this value
        """

        return _Record([
            ('start', self['start']),
            ('end', self['end']),
            ('header_start', self['header_start']),
            ('header_end', self['header_end']),
            ('content_start', self['content_start']),
            ('content_end', self['content_end']),
            ('length', self['end'] - self['start']),
            ('header_length', len(self['header'])),
            ('content_length', len(self['content'])),
            ('trailer_length', len(self['trailer'])),
            ('indefinite', self.is_indefinite),
            ('der', self.is_der),
            ('sha256', _sha256(self.raw)),
            ('hex', _hex(self.raw)),
        ])

    def __repr__(self):
        return '<Tlv class=%d tag=%d [%d:%d]>' % (
            self['class'], self['tag'], self['start'], self['end']
        )


def parse_tlv(blob, offset=0, base_offset=0, content_limit=None):
    """
    Parses one BER/DER value without normalizing it.

    :param blob:
        The complete byte string that offsets are relative to

    :param offset:
        Offset of the identifier octet in blob

    :param base_offset:
        Unused compatibility argument; offsets are always absolute in blob

    :param content_limit:
        An optional limit used while walking an indefinite-length container

    :return:
        A Tlv
    """

    if not isinstance(blob, byte_cls):
        raise TypeError('blob must be a byte string, not %s' % type_name(blob))
    if offset < 0 or offset >= len(blob):
        raise ForensicError('TLV offset %d is outside the input' % offset)

    limit = len(blob) if content_limit is None else offset + content_limit
    info, end = _parse(blob[:limit], limit, pointer=offset)
    class_, method, tag, header, content, trailer = info
    return Tlv(blob, offset, end, class_, method, tag, header, content, trailer)


def iter_tlvs(blob, start=0, end=None):
    """
    Iterates over adjacent TLVs in blob
    """

    if end is None:
        end = len(blob)
    pointer = start
    while pointer < end:
        value = parse_tlv(blob, pointer, content_limit=end - pointer)
        yield value
        pointer = value['end']


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _sha1(data):
    return hashlib.sha1(data).hexdigest()


def _hex(data):
    if sys.version_info < (3,):
        return data.encode('hex')
    return data.hex()


def _b64(data):
    if not isinstance(data, byte_cls):
        return data
    if sys.version_info < (3,):
        return base64.b64encode(data)
    return base64.b64encode(data).decode('ascii')


def _as_plain(value):
    if isinstance(value, _Record):
        return dict((key, _as_plain(item)) for key, item in value.items())
    if isinstance(value, dict):
        return dict((key, _as_plain(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return [_as_plain(item) for item in value]
    return value


def _as_jsonable(value):
    if isinstance(value, dict):
        return dict((str_cls(key), _as_jsonable(item)) for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return [_as_jsonable(item) for item in value]
    if isinstance(value, byte_cls):
        return _b64(value)
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, str_cls):
        return value
    return str_cls(value)


def _json_key(value):
    return json.dumps(_as_jsonable(value), sort_keys=True, separators=(',', ':'))


def _digest(algo, data):
    if data is None:
        return None
    name = algo
    aliases = {
        'sha512_224': 'sha512_224',
        'sha512_256': 'sha512_256',
    }
    name = aliases.get(name, name)
    try:
        return hashlib.new(name, data).digest()
    except (ValueError, TypeError):
        return None


def _oid(tlv):
    """
    Decodes the dotted form of a universal OBJECT IDENTIFIER TLV
    """

    if tlv is None or tlv['class'] != 0 or tlv['tag'] != 6:
        return None
    content = tlv['content']
    parts = []
    value = 0
    first = True
    for octet in _iter_bytes(content):
        value = (value << 7) | (octet & 0x7f)
        if not octet & 0x80:
            if first:
                if value < 40:
                    parts.extend([0, value])
                elif value < 80:
                    parts.extend([1, value - 40])
                else:
                    parts.extend([2, value - 80])
                first = False
            else:
                parts.append(value)
            value = 0
    return '.'.join(str_cls(part) for part in parts)


def _iter_bytes(data):
    if sys.version_info < (3,):
        return (ord(char) for char in data)
    return iter(data)


def _oid_name(dotted):
    if dotted == OID_DATA:
        return 'data'
    if dotted == OID_SIGNED_DATA:
        return 'signed_data'
    return dotted


def _tlv_text(tlv):
    """
    Returns the text value of a string TLV, or None
    """

    if tlv is None or tlv['class'] != 0:
        return None
    if tlv['tag'] in (12, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30):
        content = tlv['content']
        try:
            if tlv['tag'] == 30:
                return content.decode('utf-16-be')
            if tlv['tag'] == 28:
                return content.decode('utf-32-be')
            if tlv['tag'] == 20:
                return content.decode('latin1')
            return content.decode('utf-8')
        except Exception:
            return _hex(content)
    return None


def _merge_octets(tlv):
    """
    Returns the octets of a primitive or constructed OCTET STRING without
    normalizing the surrounding encoding.
    """

    if tlv is None:
        return None
    if tlv['class'] != 0 or tlv['tag'] != 4:
        return None
    if not tlv.is_constructed:
        return tlv['content']
    output = []
    for child in tlv.children():
        part = _merge_octets(child)
        if part is None:
            return None
        output.append(part)
    return b''.join(output)


def _octet_regions(tlv):
    if tlv is None:
        return []
    if not tlv.is_constructed:
        return [tlv.region()]
    output = []
    for child in tlv.children():
        output.extend(_octet_regions(child))
    return output


def _retag_set(encoded):
    """
    Changes an implicit [0] SET (0xa0) to the universal SET OF identifier
    (0x31) used as the CMS signature input. Length and content octets are not
    touched, so indefinite contents remain visible as such.
    """

    if not encoded:
        return encoded
    if encoded[0] == 0xa0:
        return b'\x31' + encoded[1:]
    return encoded


def _same_bytes(left, right):
    return left is not None and right is not None and left == right


def _first_difference(left, right):
    length = min(len(left), len(right))
    for index in range(0, length):
        lval = left[index:index + 1]
        rval = right[index:index + 1]
        if lval != rval:
            return index
    if len(left) != len(right):
        return length
    return None


def _canonical_bytes(value):
    try:
        return value.dump(force=True)
    except Exception:
        return None


def _outer_changes(original, canonical, root_tlv=None, trailing=b''):
    """
    Describes the difference between the on-disk bytes and a DER serialization.
    """

    changes = []
    indefinite = []
    if root_tlv is not None:
        for item in root_tlv.walk():
            if item.is_indefinite:
                indefinite.append(_Record([
                    ('offset', item['start']),
                    ('class', item['class']),
                    ('tag', item['tag']),
                    ('length', item['end'] - item['start']),
                ]))
    if trailing:
        changes.append(_Record([
            ('kind', 'trailing_data'),
            ('offset', len(original) - len(trailing)),
            ('length', len(trailing)),
            ('sha256', _sha256(trailing)),
        ]))
    if canonical is not None and canonical != original:
        changes.append(_Record([
            ('kind', 'indefinite_length' if indefinite else 'der_normalization'),
            ('offset', _first_difference(original, canonical)),
            ('original_length', len(original)),
            ('canonical_length', len(canonical)),
        ]))
    if indefinite and (canonical is None or canonical == original):
        changes.append(_Record([
            ('kind', 'indefinite_length'),
            ('offset', indefinite[0]['offset']),
            ('count', len(indefinite)),
        ]))
    return _Record([
        ('byte_identical', canonical is not None and canonical == original and not trailing),
        ('original_length', len(original)),
        ('canonical_length', None if canonical is None else len(canonical)),
        ('original_sha256', _sha256(original)),
        ('canonical_sha256', None if canonical is None else _sha256(canonical)),
        ('first_difference', None if canonical is None else _first_difference(original, canonical)),
        ('indefinite_values', indefinite),
        ('trailing_bytes', len(trailing)),
        ('changes', changes),
        ('der', canonical is not None and canonical == original and not trailing and not indefinite),
    ])


def _semantic_attributes(attrs):
    if attrs is None:
        return None
    output = []
    for attr in attrs:
        values = []
        try:
            for value in attr['values']:
                values.append(value.native)
        except Exception:
            continue
        values.sort(key=_json_key)
        output.append(_Record([
            ('type', attr['type'].native),
            ('values', values),
        ]))
    output.sort(key=_json_key)
    return output


def _semantic_view(sd_obj, content_bytes, content_type, nested_semantic=None, depth=0):
    """
    Builds a decoded view that deliberately excludes archive-level bytes.
    """

    if depth > _MAX_LAYER_DEPTH:
        return _Record([('error', 'maximum nesting depth exceeded')])
    signers = []
    try:
        signer_values = list(sd_obj['signer_infos'])
    except Exception:
        signer_values = []
    for signer in signer_values:
        try:
            attrs = signer['signed_attrs']
            attrs_native = None if attrs.native is None else _semantic_attributes(attrs)
        except Exception:
            attrs_native = None
        try:
            sid = _signer_identifier(signer)
        except Exception:
            sid = None
        signers.append(_Record([
            ('sid', sid),
            ('digest_algorithm', _native(signer, 'digest_algorithm')),
            ('signed_attrs', attrs_native),
            ('signature_algorithm', _native(signer, 'signature_algorithm')),
            ('signature', _native(signer, 'signature')),
            ('unsigned_attrs', _native(signer, 'unsigned_attrs')),
        ]))
    encap = _Record([
        ('content_type', content_type),
        ('content_sha256', None if content_bytes is None else _sha256(content_bytes)),
        ('content_length', None if content_bytes is None else len(content_bytes)),
    ])
    if nested_semantic is not None:
        encap['signed_data'] = nested_semantic
    return _Record([
        ('version', _native(sd_obj, 'version')),
        ('digest_algorithms', _native(sd_obj, 'digest_algorithms')),
        ('encap_content_info', encap),
        ('signers', signers),
    ])


def _native(obj, field):
    try:
        return obj[field].native
    except Exception:
        return None


def _signer_identifier(signer):
    sid = signer['sid']
    if sid.name == 'subject_key_identifier':
        return 'ski:' + _hex(sid.chosen.native)
    chosen = sid.chosen
    issuer = chosen['issuer'].human_friendly
    serial = chosen['serial_number'].native
    return 'issuer=%s;serial=%s' % (issuer, serial)


def _find_certificate(sd_obj, signer):
    try:
        choices = sd_obj['certificates']
    except Exception:
        return None
    if choices.native is None:
        return None
    sid = signer['sid']
    matches = []
    for choice in choices:
        if choice.name != 'certificate':
            continue
        cert = choice.chosen
        matched = False
        if sid.name == 'subject_key_identifier':
            try:
                matched = cert.key_identifier == sid.chosen.native
            except Exception:
                matched = False
        else:
            try:
                wanted = sid.chosen
                matched = (
                    cert.issuer == wanted['issuer'] and
                    cert.serial_number == wanted['serial_number'].native
                )
            except Exception:
                matched = False
        if matched:
            matches.append(cert)
    if len(matches) == 1:
        return matches[0]
    if matches:
        return matches[0]
    return None


def _load_public_key(cert):
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
    except Exception:
        return None
    try:
        spki = cert['tbs_certificate']['subject_public_key_info']
        return load_der_public_key(spki.dump())
    except Exception:
        return None


def _hash_object(name):
    try:
        from cryptography.hazmat.primitives import hashes
    except Exception:
        return None
    mapping = {
        'md5': getattr(hashes, 'MD5', None),
        'sha1': getattr(hashes, 'SHA1', None),
        'sha224': getattr(hashes, 'SHA224', None),
        'sha256': getattr(hashes, 'SHA256', None),
        'sha384': getattr(hashes, 'SHA384', None),
        'sha512': getattr(hashes, 'SHA512', None),
        'sha512_224': getattr(hashes, 'SHA512_224', None),
        'sha512_256': getattr(hashes, 'SHA512_256', None),
        'sha3_224': getattr(hashes, 'SHA3_224', None),
        'sha3_256': getattr(hashes, 'SHA3_256', None),
        'sha3_384': getattr(hashes, 'SHA3_384', None),
        'sha3_512': getattr(hashes, 'SHA3_512', None),
    }
    cls = mapping.get(name)
    if cls is None:
        return None
    try:
        return cls()
    except Exception:
        return None


def _rsa_pss_padding(signer, hash_name):
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
    except Exception:
        return None
    params = signer['signature_algorithm']['parameters']
    mgf_hash_name = hash_name
    salt_length = None
    try:
        pss = params.parsed
        mgf_hash_name = pss['mask_gen_algorithm']['parameters']['algorithm'].native
        salt_length = pss['salt_length'].native
    except Exception:
        pass
    mgf_hash = _hash_object(mgf_hash_name)
    if mgf_hash is None:
        return None
    if salt_length is None:
        try:
            salt_length = hashes.SHA1().digest_size
        except Exception:
            salt_length = 20
    try:
        return padding.PSS(
            mgf=padding.MGF1(mgf_hash),
            salt_length=salt_length
        )
    except Exception:
        return None


def _verify_signature(signer, cert, signed_bytes, signature):
    """
    :return:
        A tuple of (status, reason). Status is "valid", "invalid" or
        "unavailable".
    """

    if cert is None:
        return 'unavailable', 'no matching certificate'
    if signed_bytes is None:
        return 'unavailable', 'signed bytes are not available'
    if signature is None:
        return 'unavailable', 'signature is not available'
    public_key = _load_public_key(cert)
    if public_key is None:
        return 'unavailable', 'cryptography backend or public key unavailable'
    signature_algo = None
    hash_name = None
    try:
        signature_algo = signer['signature_algorithm'].signature_algo
    except Exception as exc:
        return 'unavailable', 'unsupported signature algorithm: %s' % exc
    try:
        hash_name = signer['signature_algorithm'].hash_algo
    except Exception:
        try:
            hash_name = signer['digest_algorithm']['algorithm'].native
        except Exception:
            return 'unavailable', 'signature hash algorithm is not available'
    try:
        from cryptography.hazmat.primitives.asymmetric import padding, ec
        from cryptography.exceptions import InvalidSignature
    except Exception:
        return 'unavailable', 'cryptography backend unavailable'
    try:
        if signature_algo in ('rsassa_pkcs1v15', 'rsassa_pss'):
            hash_obj = _hash_object(hash_name)
            if hash_obj is None:
                return 'unavailable', 'unsupported digest algorithm %s' % hash_name
            if signature_algo == 'rsassa_pss':
                pad = _rsa_pss_padding(signer, hash_name)
                if pad is None:
                    return 'unavailable', 'unsupported RSASSA-PSS parameters'
            else:
                pad = padding.PKCS1v15()
            public_key.verify(signature, signed_bytes, pad, hash_obj)
        elif signature_algo == 'ecdsa':
            hash_obj = _hash_object(hash_name)
            if hash_obj is None:
                return 'unavailable', 'unsupported digest algorithm %s' % hash_name
            public_key.verify(signature, signed_bytes, ec.ECDSA(hash_obj))
        elif signature_algo == 'dsa':
            hash_obj = _hash_object(hash_name)
            if hash_obj is None:
                return 'unavailable', 'unsupported digest algorithm %s' % hash_name
            public_key.verify(signature, signed_bytes, hash_obj)
        elif signature_algo in ('ed25519', 'ed448'):
            public_key.verify(signature, signed_bytes)
        else:
            return 'unavailable', 'unsupported signature algorithm %s' % signature_algo
        return 'valid', None
    except InvalidSignature:
        return 'invalid', 'signature does not match the supplied bytes'
    except Exception as exc:
        return 'unavailable', '%s: %s' % (type(exc).__name__, exc)


def _attribute(signer, oid):
    attrs = signer['signed_attrs']
    if attrs.native is None:
        return None
    for attr in attrs:
        if attr['type'].dotted == oid:
            return attr
    return None


def _attribute_value(signer, oid):
    attr = _attribute(signer, oid)
    if attr is None:
        return None
    try:
        return attr['values'][0].native
    except Exception:
        return None


def _signed_attributes_record(signer, attrs_tlv):
    attrs = signer['signed_attrs']
    present = attrs.native is not None
    record = _Record([
        ('present', present),
        ('available', present and attrs_tlv is not None),
        ('decoded', None if not present else attrs.native),
        ('source_bytes', None if attrs_tlv is None else attrs_tlv.raw),
        ('original_bytes', None if attrs_tlv is None else attrs_tlv.raw),
        ('source_sha256', None if attrs_tlv is None else _sha256(attrs_tlv.raw)),
        ('source_region', None if attrs_tlv is None else attrs_tlv.region()),
        ('source_der', False if attrs_tlv is None else attrs_tlv.is_der),
        ('source_indefinite', False if attrs_tlv is None else attrs_tlv.is_indefinite),
        ('source_bytes_form', None if attrs_tlv is None else _encode_form(attrs_tlv.raw)),
        ('bytes', None),
        ('sha256', None),
        ('canonical_bytes', None),
        ('canonical_sha256', None),
        ('matches_canonical', None),
        ('representation', 'absent'),
    ])
    if not present:
        return record
    source_input = None
    canonical_input = None
    if attrs_tlv is not None:
        source_input = _retag_set(attrs_tlv.raw)
    try:
        canonical_input = _retag_set(attrs.dump(force=True))
    except Exception:
        canonical_input = None
    if canonical_input is None:
        canonical_input = source_input
    record['bytes'] = canonical_input
    record['sha256'] = None if canonical_input is None else _sha256(canonical_input)
    record['canonical_bytes'] = canonical_input
    record['canonical_sha256'] = None if canonical_input is None else _sha256(canonical_input)
    record['matches_canonical'] = _same_bytes(source_input, canonical_input)
    if source_input is not None and _same_bytes(source_input, canonical_input):
        record['representation'] = 'original'
    elif source_input is not None:
        record['representation'] = 'original_ber' if attrs_tlv.is_indefinite else 'original_reencoded'
    elif canonical_input is not None:
        record['representation'] = 'reconstructed'
    else:
        record['representation'] = 'unavailable'
    record['source_signature_input'] = source_input
    record['source_signature_input_sha256'] = (
        None if source_input is None else _sha256(source_input)
    )
    return record


def _encode_form(raw):
    if raw is None:
        return None
    if len(raw) >= 2 and raw[1:2] == b'\x80':
        return 'indefinite'
    if len(raw) >= 2 and raw[1] != len(raw) - 2 and raw[1] & 0x80:
        return 'long_form_length'
    return 'definite'


def _content_record(encap_tlv, econtent_tlv, content_bytes, nested_codec):
    content_type = None
    if encap_tlv is not None:
        kids = encap_tlv.children()
        if kids:
            content_type = _oid(kids[0])
    record = _Record([
        ('content_type', _oid_name(content_type)),
        ('type', _oid_name(content_type)),
        ('content_type_oid', content_type),
        ('bytes', content_bytes),
        ('length', None if content_bytes is None else len(content_bytes)),
        ('sha256', None if content_bytes is None else _sha256(content_bytes)),
        ('regions', [] if econtent_tlv is None else _octet_regions(econtent_tlv)),
        ('representation', 'absent' if content_bytes is None else 'original'),
    ])
    if nested_codec is not None:
        record['signed_data'] = nested_codec
    return record


def _next_signer_field(children, index, class_, tag):
    if index < len(children):
        child = children[index]
        if child['class'] == class_ and child['tag'] == tag:
            return child, index + 1
    return None, index


def _layer_signers(sd_obj, sd_tlv):
    fields = sd_tlv.children()
    signer_set = None
    if fields:
        for child in reversed(fields):
            if child['class'] == 0 and child['tag'] == 17:
                signer_set = child
                break
    if signer_set is None:
        return []
    return _Record([
        ('tlv', signer_set),
        ('signers', signer_set.children()),
    ])


def _signature_tlv(fields):
    """
    Locates the OCTET STRING signature in a SignerInfo field list.
    """

    for index, child in enumerate(fields):
        if index < 3:
            continue
        if child['class'] == 0 and child['tag'] == 4:
            return child
    return None


def _signed_attrs_tlv(fields):
    # version, sid, digest_algorithm, signed_attrs?, signature_algorithm, ...
    if len(fields) > 3 and fields[3]['class'] == 2 and fields[3]['tag'] == 0:
        return fields[3]
    return None


def _unsigned_attrs_tlv(fields):
    sig = _signature_tlv(fields)
    if sig is None:
        return None
    for child in fields:
        if child['class'] == 2 and child['tag'] == 1 and child['start'] > sig['start']:
            return child
    return None


def _analyze_signer(signer, signer_tlv, sd_obj, layer_path, econtent,
                    verify=True, archived=False):
    fields = signer_tlv.children()
    attrs_tlv = _signed_attrs_tlv(fields)
    sig_tlv = _signature_tlv(fields)
    digest_name = None
    try:
        digest_name = signer['digest_algorithm']['algorithm'].native
    except Exception:
        pass

    attrs_record = _signed_attributes_record(signer, attrs_tlv)
    content_digest = None if econtent is None else _digest(digest_name, econtent)
    declared_digest = _attribute_value(signer, OID_MESSAGE_DIGEST)
    digest_record = _Record([
        ('algorithm', digest_name),
        ('declared', declared_digest),
        ('declared_sha256', None if declared_digest is None else _sha256(declared_digest)),
        ('computed', content_digest),
        ('computed_sha256', None if content_digest is None else _sha256(content_digest)),
        ('match', None if declared_digest is None or content_digest is None else declared_digest == content_digest),
    ])

    signature = None
    if sig_tlv is not None:
        signature = sig_tlv['content']
    sid = None
    try:
        sid = _signer_identifier(signer)
    except Exception:
        pass

    if attrs_record['present']:
        signed_kind = 'signed_attributes'
        signed_bytes = attrs_record['bytes']
        signed_source_bytes = attrs_record.get('source_signature_input')
        signed_regions = [] if attrs_tlv is None else [attrs_tlv.region()]
    else:
        signed_kind = 'content'
        signed_bytes = econtent
        signed_source_bytes = econtent
        signed_regions = []
        if sd_obj is not None:
            pass

    signed_record = _Record([
        ('kind', signed_kind),
        ('bytes', signed_bytes),
        ('signature_input', signed_bytes),
        ('source_bytes', signed_source_bytes),
        ('original_bytes', signed_source_bytes),
        ('sha256', None if signed_bytes is None else _sha256(signed_bytes)),
        ('length', None if signed_bytes is None else len(signed_bytes)),
        ('regions', signed_regions),
        ('representation', attrs_record['representation'] if attrs_record['present'] else 'original'),
    ])

    cert = _find_certificate(sd_obj, signer)
    attempts = []
    if verify:
        candidates = []
        if attrs_record['present']:
            if attrs_record.get('source_signature_input') is not None:
                candidates.append(('source', attrs_record['source_signature_input']))
            if attrs_record.get('canonical_bytes') is not None and not _same_bytes(
                    attrs_record.get('source_signature_input'),
                    attrs_record.get('canonical_bytes')):
                candidates.append(('canonical', attrs_record['canonical_bytes']))
        elif econtent is not None:
            candidates.append(('source', econtent))
        for label, candidate in candidates:
            status, reason = _verify_signature(signer, cert, candidate, signature)
            attempts.append(_Record([
                ('input', label),
                ('status', status),
                ('reason', reason),
                ('sha256', _sha256(candidate)),
            ]))

    statuses = [item['status'] for item in attempts]
    if 'valid' in statuses:
        signature_status = 'valid'
    elif attempts and all(item == 'invalid' for item in statuses):
        signature_status = 'invalid'
    elif not attempts:
        signature_status = 'not_run' if not verify else 'unavailable'
    else:
        signature_status = 'unavailable'

    source_attempt = None
    for item in attempts:
        if item['input'] == 'source':
            source_attempt = item

    representation = attrs_record['representation']
    direct = None
    lost = None
    reason = None
    if signature_status == 'valid':
        if attrs_record['present']:
            if source_attempt is not None and source_attempt['status'] == 'valid':
                direct = True
                lost = False
                reason = 'signature verified over the preserved signed attributes'
            else:
                direct = False
                lost = True
                reason = 'signature verified only after canonical reconstruction'
        else:
            direct = True
            lost = False
            reason = 'signature verified over the preserved content octets'
    elif signature_status == 'invalid':
        direct = False
        if attrs_record['present'] and (
                archived or representation in (
                    'original_ber', 'original_reencoded', 'reconstructed')):
            lost = True
            reason = (
                'signature does not match the repackaged signed bytes; '
                'the historical representation is not directly evidenced'
            )
        else:
            lost = False
            reason = 'signature does not match the preserved bytes'
    elif attrs_record['present'] and representation in (
            'original_ber', 'original_reencoded', 'reconstructed'):
        lost = True
        reason = 'original signed-attrs representation differs from canonical DER; signature was not checked'
    else:
        reason = 'signature verification unavailable'

    if digest_record['match'] is True:
        digest_verdict = 'valid'
    elif digest_record['match'] is False:
        digest_verdict = 'invalid'
    else:
        digest_verdict = 'unavailable'

    if direct is True:
        evidence = 'direct'
    elif digest_verdict == 'valid' or signature_status == 'valid':
        evidence = 'semantic_only'
    else:
        evidence = 'insufficient'

    if direct is True:
        conclusion = 'signature_verified_over_preserved_bytes'
    elif lost is True and signature_status == 'invalid':
        conclusion = 'signature_unverifiable_after_rewrapping'
    elif lost is True:
        conclusion = 'original_signed_bytes_not_preserved'
    elif signature_status == 'valid':
        conclusion = 'signature_verified'
    elif digest_verdict == 'valid':
        conclusion = 'content_digest_only'
    else:
        conclusion = 'insufficient_evidence'

    return _Record([
        ('index', None),
        ('layer_path', layer_path),
        ('signer_id', sid),
        ('version', _native(signer, 'version')),
        ('semantics', None if signer.native is None else signer.native),
        ('digest_algorithm', digest_name),
        ('signature_algorithm', _native(signer, 'signature_algorithm')),
        ('signed_attributes', attrs_record),
        ('signed_region', signed_record),
        ('signed_content', _Record([
            ('type', None),
            ('bytes', econtent),
            ('length', None if econtent is None else len(econtent)),
            ('sha256', None if econtent is None else _sha256(econtent)),
            ('regions', []),
        ])),
        ('message_digest', digest_record),
        ('signature', _Record([
            ('bytes', signature),
            ('length', None if signature is None else len(signature)),
            ('sha256', None if signature is None else _sha256(signature)),
            ('region', None if sig_tlv is None else sig_tlv.region()),
        ])),
        ('verification', _Record([
            ('signature', signature_status),
            ('digest', digest_verdict),
            ('signed_bytes', representation if attrs_record['present'] else 'original'),
            ('backend', 'cryptography' if attempts else None),
            ('attempts', attempts),
            ('reason', reason),
        ])),
        ('evidence', evidence),
        ('direct_evidence', direct),
        ('lost_direct_evidence', lost),
        ('conclusion', conclusion),
        ('historical_conclusion', _Record([
            ('direct_evidence', direct),
            ('lost_direct_evidence', lost),
            ('conclusion', conclusion),
            ('reason', reason),
        ])),
    ])


def _encap_tlv(sd_tlv):
    fields = sd_tlv.children()
    if len(fields) > 2:
        return fields[2]
    return None


def _econtent_tlv(encap_tlv):
    if encap_tlv is None:
        return None, None
    fields = encap_tlv.children()
    if len(fields) < 2:
        return None, None
    wrapper = fields[1]
    if wrapper['class'] != 2 or wrapper['tag'] != 0:
        return wrapper, None
    kids = wrapper.children()
    if not kids:
        return wrapper, None
    return wrapper, kids[0]


def _try_nested_signed_data(sd_obj, inner_tlv, content_type):
    if content_type != OID_SIGNED_DATA:
        return None
    from . import cms as _cms
    candidates = []
    if inner_tlv is not None:
        data = _merge_octets(inner_tlv)
        if data is not None and data != inner_tlv.raw:
            candidates.append(data)
        candidates.append(inner_tlv.raw)
    for candidate in candidates:
        try:
            ci = _cms.ContentInfo.load(candidate)
            if ci['content_type'].native == 'signed_data':
                ci_tlv = parse_tlv(candidate, 0)
                wrapper = ci_tlv.children()[1]
                kids = wrapper.children()
                if kids:
                    return ci['content'], kids[0]
        except Exception:
            pass
        try:
            return _cms.SignedData.load(candidate), parse_tlv(candidate, 0)
        except Exception:
            pass
    return None


def _analyze_layer(sd_obj, sd_tlv, path, source_bytes, verify, depth, seen, archived_outer=False):
    if depth > _MAX_LAYER_DEPTH:
        raise ForensicError('maximum CMS signing layer depth exceeded')
    marker = (sd_tlv['start'], sd_tlv['end'])
    if marker in seen:
        return None
    seen.add(marker)
    archived = archived_outer

    encap_tlv = _encap_tlv(sd_tlv)
    wrapper_tlv, inner_tlv = _econtent_tlv(encap_tlv)
    content_type = None
    if encap_tlv is not None and encap_tlv.children():
        content_type = _oid(encap_tlv.children()[0])
    content_bytes = None
    nested = None
    if inner_tlv is not None:
        content_bytes = _merge_octets(inner_tlv)
        if content_type == OID_SIGNED_DATA:
            found = _try_nested_signed_data(sd_obj, inner_tlv, content_type)
            if found is not None:
                nested = _analyze_layer(
                    found[0], found[1], path + '/encap_content_info',
                    found[1].raw, verify, depth + 1, seen, archived
                )

    canonical = _canonical_bytes(sd_obj)
    outer = _outer_changes(sd_tlv.raw, canonical, sd_tlv)
    archived = archived or not outer['byte_identical']
    if nested is not None:
        outer['changes'].append(_Record([
            ('kind', 'nested_signed_data'),
            ('offset', inner_tlv['start']),
        ]))

    semantic = _semantic_view(
        sd_obj, content_bytes, _oid_name(content_type),
        None if nested is None else nested['semantics']
    )

    signer_info = _layer_signers(sd_obj, sd_tlv)
    signer_tlvs = signer_info['signers'] if signer_info else []
    try:
        signer_objs = list(sd_obj['signer_infos'])
    except Exception:
        signer_objs = []

    child_layers = [] if nested is None else [nested]
    signers = []
    for index, signer in enumerate(signer_objs):
        signer_tlv = signer_tlvs[index] if index < len(signer_tlvs) else None
        if signer_tlv is None:
            continue
        record = _analyze_signer(
            signer, signer_tlv, sd_obj, path, content_bytes,
            verify=verify, archived=archived
        )
        record['index'] = index
        record['signer_ref'] = '%s#signer[%d]' % (path, index)
        record['signed_content']['type'] = _oid_name(content_type)
        if wrapper_tlv is not None:
            record['signed_content']['regions'] = _octet_regions(inner_tlv)
        signers.append(record)

    child_layers.extend(_nested_layers(
        sd_obj, None, path, source_bytes, verify, depth, seen
    ))

    return _Record([
        ('path', path),
        ('source_region', sd_tlv.region()),
        ('version', _native(sd_obj, 'version')),
        ('content_type', _oid_name(content_type)),
        ('semantics', semantic),
        ('encap_content', _content_record(
            encap_tlv, inner_tlv, content_bytes,
            None if nested is None else nested['semantics']
        )),
        ('outer', outer),
        ('archive_changes', outer['changes']),
        ('signers', signers),
        ('signed_regions', [signer['signed_region'] for signer in signers]),
        ('decoded', semantic),
        ('children', child_layers),
        ('nested_layers', child_layers),
        ('nested', None if nested is None else nested['semantics']),
    ])


def _counter_signature_layer(parent_signer, counter_signer, sd_obj, path,
                             signer_index, attr_index, value_index, verify):
    raw = counter_signer.original_dump()
    tlv = parse_tlv(raw, 0)
    parent_signature = None
    try:
        parent_signature = parent_signer['signature'].native
    except Exception:
        pass
    canonical = _canonical_bytes(counter_signer)
    outer = _outer_changes(tlv.raw, canonical, tlv)
    archived = not outer['byte_identical']
    record = _analyze_signer(
        counter_signer, tlv, sd_obj,
        '%s/signer[%d]/unsigned_attrs[%d]/counter_signature[%d]' % (
            path, signer_index, attr_index, value_index
        ),
        parent_signature, verify=verify, archived=archived
    )
    record['index'] = value_index
    record['signer_ref'] = '%s#counter_signature[%d]' % (path, value_index)
    record['signed_content']['type'] = 'counter_signature'
    semantic = _Record([
        ('kind', 'counter_signature'),
        ('signed_content_sha256', None if parent_signature is None else _sha256(parent_signature)),
    ])
    return _Record([
        ('path', record['layer_path']),
        ('source_region', tlv.region()),
        ('version', _native(counter_signer, 'version')),
        ('content_type', 'counter_signature'),
        ('semantics', semantic),
        ('encap_content', _Record([
            ('content_type', 'counter_signature'),
            ('type', 'counter_signature'),
            ('bytes', parent_signature),
            ('length', None if parent_signature is None else len(parent_signature)),
            ('sha256', None if parent_signature is None else _sha256(parent_signature)),
            ('regions', []),
            ('representation', 'original' if parent_signature is not None else 'absent'),
        ])),
        ('outer', outer),
        ('archive_changes', outer['changes']),
        ('signers', [record]),
        ('signed_regions', [record['signed_region']]),
        ('decoded', semantic),
        ('children', []),
        ('nested_layers', []),
        ('nested', None),
    ])


def _nested_layers(sd_obj, layer, path, source_bytes, verify, depth, seen):
    """
    Finds SignedData values embedded in unsigned attributes, counter
    signatures, timestamp tokens and nested signatures.
    """

    output = []
    try:
        signer_objs = list(sd_obj['signer_infos'])
    except Exception:
        signer_objs = []
    for index, signer in enumerate(signer_objs):
        try:
            attrs = signer['unsigned_attrs']
        except Exception:
            continue
        if attrs.native is None:
            continue
        for attr_index, attr in enumerate(attrs):
            oid = attr['type'].dotted
            if oid not in (
                    OID_COUNTER_SIGNATURE,
                    OID_TIMESTAMP_TOKEN,
                    OID_MICROSOFT_NESTED_SIGNATURE,
                    OID_MICROSOFT_TIMESTAMP_TOKEN):
                continue
            if oid == OID_COUNTER_SIGNATURE:
                for value_index, value in enumerate(attr['values']):
                    try:
                        counter_layer = _counter_signature_layer(
                            signer, value, sd_obj, path, index, attr_index,
                            value_index, verify
                        )
                        output.append(counter_layer)
                    except Exception:
                        continue
                continue
            for value_index, value in enumerate(attr['values']):
                candidate = None
                raw = None
                try:
                    candidate = cms_signed_data_from_content_info(value)
                    if candidate is not None:
                        raw = candidate[0].original_dump()
                except Exception:
                    candidate = None
                if candidate is None:
                    continue
                try:
                    nested_tlv = parse_tlv(raw, 0)
                    if nested_tlv['class'] == 2 and nested_tlv['tag'] == 0:
                        kids = nested_tlv.children()
                        if kids:
                            nested_tlv = kids[0]
                    nested_layer = _analyze_layer(
                        candidate[0], nested_tlv,
                        '%s/signer[%d]/unsigned_attrs[%d]/value[%d]' % (
                            path, index, attr_index, value_index
                        ),
                        raw, verify, depth + 1, seen
                    )
                    if nested_layer is not None:
                        output.append(nested_layer)
                except Exception:
                    continue
    return output


def cms_signed_data_from_value(value):
    """
    Best-effort conversion of a CMS attribute value to SignedData.
    """

    name = getattr(value, '__class__', None).__name__
    if name == 'SignedData':
        return value, value
    if name == 'SignerInfo':
        return None
    return None


def cms_signed_data_from_content_info(value):
    name = getattr(value, '__class__', None).__name__
    if name == 'ContentInfo':
        if value['content_type'].native == 'signed_data':
            return value['content'], value
    if name == 'SignedData':
        return value, value
    return None


def _load_input(value):
    """
    :return:
        (object, source_bytes, root_tlv, parsed_prefix)
    """

    from . import cms as _cms

    if isinstance(value, bytearray):
        value = bytes(value)
    if isinstance(value, byte_cls):
        source = value
        root = parse_tlv(source, 0)
        obj = None
        try:
            obj = _cms.ContentInfo.load(source)
            if not isinstance(obj, _cms.ContentInfo):
                obj = None
        except Exception:
            obj = None
        if obj is None:
            obj = _cms.SignedData.load(source)
        prefix = root.raw
        return obj, source, root, prefix

    obj = value
    try:
        prefix = obj.original_dump()
    except Exception:
        prefix = obj.dump()
    try:
        source = obj.original_input
    except Exception:
        source = prefix
    if not isinstance(source, byte_cls) or not source.startswith(prefix):
        source = prefix
    root = parse_tlv(source, 0)
    return obj, source, root, prefix


def inventory(value, verify=True):
    """
    Produces a forensic inventory of the CMS signing material in value.

    :param value:
        A byte string containing a CMS ContentInfo or SignedData, or a
        ContentInfo/SignedData object already loaded by asn1crypto

    :param verify:
        If True and the optional cryptography package is available, signatures
        with a matching embedded certificate are checked. A missing backend or
        certificate is reported as "unavailable", never as a valid signature.

    :return:
        A SigningMaterialInventory, which is an OrderedDict with attribute
        access
    """

    from . import cms as _cms

    obj, source, root, prefix = _load_input(value)
    if isinstance(obj, _cms.ContentInfo):
        content_type = obj['content_type'].native
        if content_type != 'signed_data':
            raise ForensicError(
                'ContentInfo content type is %s, not signed_data' % content_type
            )
        sd_obj = obj['content']
        root_children = root.children()
        if not root_children or len(root_children) < 2:
            raise ForensicError('ContentInfo does not contain a content field')
        wrapper = root_children[1]
        sd_kids = wrapper.children()
        if not sd_kids:
            raise ForensicError('ContentInfo content field is empty')
        sd_tlv = sd_kids[0]
        layer_path = 'content'
    elif isinstance(obj, _cms.SignedData):
        sd_obj = obj
        sd_tlv = root
        if sd_tlv['class'] == 2 and sd_tlv['tag'] == 0:
            kids = sd_tlv.children()
            if kids:
                sd_tlv = kids[0]
        layer_path = '$'
    else:
        raise TypeError(
            'value must be bytes or a CMS ContentInfo/SignedData, not %s' %
            type_name(obj)
        )

    trailing = source[len(prefix):]
    outer = _outer_changes(source, _canonical_bytes(obj), root, trailing)
    seen = set()
    layer = _analyze_layer(
        sd_obj, sd_tlv, layer_path, source, verify, 0, seen,
        archived_outer=not outer['byte_identical']
    )

    layers = []
    def _walk(node):
        layers.append(node)
        for child in node.get('children') or []:
            _walk(child)
    _walk(layer)

    signers = []
    for item in layers:
        for signer in item['signers']:
            signer['layer_path'] = item['path']
            signers.append(signer)

    semantic = layer['semantics']
    semantic_fingerprint = _sha256(_json_key(semantic).encode('utf-8'))
    content_semantics = _Record([
        ('content_type', layer['encap_content']['content_type']),
        ('content_sha256', layer['encap_content']['sha256']),
        ('signers', [
            _Record([
                ('sid', signer['sid']),
                ('digest_algorithm', signer['digest_algorithm']),
                ('signed_attrs', signer['signed_attrs']),
                ('signature_algorithm', signer['signature_algorithm']),
            ])
            for signer in semantic['signers']
        ]),
    ])
    content_fingerprint = _sha256(_json_key(content_semantics).encode('utf-8'))

    lost = [
        signer['signer_id'] for signer in signers
        if signer['lost_direct_evidence'] is True
    ]
    preserved = [
        signer['signer_id'] for signer in signers
        if signer['direct_evidence'] is True
    ]
    conclusions = []
    for signer in signers:
        conclusions.append(_Record([
            ('signer_ref', signer['signer_ref']),
            ('index', signer['index']),
            ('signer_id', signer['signer_id']),
            ('layer_path', signer['layer_path']),
            ('conclusion', signer['conclusion']),
            ('direct_evidence', signer['direct_evidence']),
            ('lost_direct_evidence', signer['lost_direct_evidence']),
            ('reason', signer['historical_conclusion']['reason']),
        ]))

    def _brief(signer):
        return _Record([
            ('signer_ref', signer['signer_ref']),
            ('index', signer['index']),
            ('layer_path', signer['layer_path']),
            ('signer_id', signer['signer_id']),
            ('conclusion', signer['conclusion']),
        ])

    lost_signers = [_brief(signer) for signer in signers if signer['lost_direct_evidence'] is True]
    preserved_signers = [_brief(signer) for signer in signers if signer['direct_evidence'] is True]

    source_record = _Record([
        ('bytes', source),
        ('length', len(source)),
        ('sha256', _sha256(source)),
        ('sha1', _sha1(source)),
        ('parsed_length', len(prefix)),
        ('trailing_length', len(trailing)),
        ('indefinite', root.is_indefinite),
        ('der', root.is_der and not trailing),
    ])
    return SigningMaterialInventory([
        ('source', source_record),
        ('original', source_record),
        ('outer', outer),
        ('archive', outer),
        ('archive_changes', outer['changes']),
        ('outer_changes', outer['changes']),
        ('layers', layers),
        ('signers', signers),
        ('signed_regions', [signer['signed_region'] for signer in signers]),
        ('semantics', semantic),
        ('decoded', semantic),
        ('semantic_fingerprint', semantic_fingerprint),
        ('content_semantics', content_semantics),
        ('content_fingerprint', content_fingerprint),
        ('conclusions', conclusions),
        ('historical_conclusions', conclusions),
        ('lost_direct_evidence', lost),
        ('preserved_direct_evidence', preserved),
        ('lost_signers', lost_signers),
        ('preserved_signers', preserved_signers),
        ('has_lost_direct_evidence', bool(lost)),
        ('complete', True),
    ])


class SigningMaterialInventory(_Record):
    """
    Public inventory record returned by inventory()
    """

    def compare(self, other):
        """
        Compares two inventories that may have different outer encodings.
        """

        return _Record([
            ('same_semantics', self['semantic_fingerprint'] == other['semantic_fingerprint']),
            ('same_source_bytes', self['source']['sha256'] == other['source']['sha256']),
            ('outer_changes', other['outer']['changes']),
            ('lost_direct_evidence', other['lost_direct_evidence']),
            ('preserved_direct_evidence', other['preserved_direct_evidence']),
        ])


SignatureMaterialInventory = SigningMaterialInventory
ForensicInventory = SigningMaterialInventory
ForensicMessage = SigningMaterialInventory
SignatureMaterial = SigningMaterialInventory


def signing_material(value, verify=True):
    return inventory(value, verify=verify)


def inventory_signing_material(value, verify=True):
    return inventory(value, verify=verify)


def signature_material(value, verify=True):
    return inventory(value, verify=verify)


def signing_material_inventory(value, verify=True):
    return inventory(value, verify=verify)


def forensic_inventory(value, verify=True):
    return inventory(value, verify=verify)


def analyze(value, verify=True):
    return inventory(value, verify=verify)


load = inventory
