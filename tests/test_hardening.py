"""Hardening tests for KDBX4 parsing.

These tests feed deliberately malformed or hostile databases to the parser and
assert that parameter bounds, stream size limits and XML validation reject
them with structured errors - before any expensive key derivation or oversized
allocation can take place, and without leaving partially decrypted plaintext
on the PyKeePass instance.
"""

import io
import struct
import time
import unittest
import zlib
from pathlib import Path

from construct import Container, GreedyBytes, Int32ul
from lxml import etree

from pykeepass import PyKeePass
from pykeepass.exceptions import (
    KDBXFormatError,
    KDBXParameterError,
    StreamLimitError,
    XMLParseError,
)
from pykeepass.kdbx_parsing import KDBX
from pykeepass.kdbx_parsing.common import (
    MAX_ARGON2_ITERATIONS,
    MAX_FIELD_SIZE,
    MAX_XML_SIZE,
    BoundedPrefixed,
    Decompressed,
    XML as XMLAdapter,
)
from pykeepass.kdbx_parsing.kdbx4 import (
    VariantDictionaryItem,
    kdf_uuids,
    validate_kdf_parameters,
)

base_dir = Path(__file__).resolve().parent
KDBX4_FIXTURE = base_dir / 'test4_argon2id.kdbx'
PASSWORD = 'password'


def _load_raw():
    return bytearray(KDBX4_FIXTURE.read_bytes())


def _find_kdf_value_offset(raw, key_char):
    """Return the offset of the 8-byte value of an Int64 KDF parameter.

    Variant dictionary layout: type(1) + key_len(4) + key + value_len(4) + value
    """
    needle = bytes([0x05]) + struct.pack('<I', 1) + key_char.encode('ascii')
    idx = raw.find(needle)
    if idx < 0:
        raise RuntimeError('KDF parameter {} not found in fixture'.format(key_char))
    # type(1) + key_len(4) + key(1) + value_len(4)
    return idx + 1 + 4 + 1 + 4


class KDFParameterLimitTests(unittest.TestCase):
    def setUp(self):
        self.raw = _load_raw()

    def _parse_expect_failure(self):
        with self.assertRaises(KDBXFormatError):
            PyKeePass(io.BytesIO(bytes(self.raw)), password=PASSWORD)

    def test_extreme_iterations_rejected_before_kdf_runs(self):
        offset = _find_kdf_value_offset(self.raw, 'I')
        struct.pack_into('<Q', self.raw, offset, 10 ** 9)
        start = time.monotonic()
        self._parse_expect_failure()
        # the parser must bail out during validation, not argon2 itself
        self.assertLess(time.monotonic() - start, 1.0)

    def test_iterations_above_limit_reported_with_structured_error(self):
        offset = _find_kdf_value_offset(self.raw, 'I')
        struct.pack_into('<Q', self.raw, offset, MAX_ARGON2_ITERATIONS + 1)
        with self.assertRaises(KDBXParameterError) as ctx:
            PyKeePass(io.BytesIO(bytes(self.raw)), password=PASSWORD)
        self.assertIn('Argon2 iterations', str(ctx.exception))

    def test_extreme_memory_rejected(self):
        offset = _find_kdf_value_offset(self.raw, 'M')
        struct.pack_into('<Q', self.raw, offset, 2 ** 40)
        with self.assertRaises(KDBXParameterError) as ctx:
            PyKeePass(io.BytesIO(bytes(self.raw)), password=PASSWORD)
        self.assertIn('memory', str(ctx.exception))

    def test_aes_kdf_extreme_rounds_rejected(self):
        raw = bytearray((base_dir / 'test4_aeskdf.kdbx').read_bytes())
        offset = _find_kdf_value_offset(raw, 'R')
        struct.pack_into('<Q', raw, offset, 10 ** 12)
        with self.assertRaises(KDBXParameterError) as ctx:
            PyKeePass(io.BytesIO(bytes(raw)), password=PASSWORD)
        self.assertIn('AES-KDF rounds', str(ctx.exception))

    def test_missing_kdf_parameter_reports_structured_error(self):
        parameters = {'$UUID': Container(value=kdf_uuids['argon2'])}
        with self.assertRaises(KDBXParameterError) as ctx:
            validate_kdf_parameters(parameters)
        self.assertIn('missing or malformed', str(ctx.exception))

    def test_unsupported_kdf_uuid_rejected(self):
        parameters = {'$UUID': Container(value=b'\x00' * 16)}
        with self.assertRaises(KDBXParameterError):
            validate_kdf_parameters(parameters)

    def test_salt_size_bounds_enforced(self):
        base = {
            '$UUID': Container(value=kdf_uuids['argon2']),
            'S': Container(value=b'\x00' * 7),
            'I': Container(value=10),
            'M': Container(value=64 * 1024 * 1024),
            'P': Container(value=2),
        }
        with self.assertRaises(KDBXParameterError):
            validate_kdf_parameters(dict(base))
        base['S'] = Container(value=b'\x00' * 8)
        validate_kdf_parameters(dict(base))

    def test_invalid_database_keeps_no_partial_plaintext(self):
        offset = _find_kdf_value_offset(self.raw, 'I')
        struct.pack_into('<Q', self.raw, offset, 10 ** 9)
        kp = PyKeePass.__new__(PyKeePass)
        with self.assertRaises(KDBXFormatError):
            kp.read(io.BytesIO(bytes(self.raw)), password=PASSWORD)
        # a failed parse must not retain any (partially) decrypted database
        self.assertIsNone(kp.kdbx)

    def test_legitimate_database_still_opens(self):
        kp = PyKeePass(KDBX4_FIXTURE, password=PASSWORD)
        self.assertEqual(kp.version[0], 4)


class StreamLimitTests(unittest.TestCase):
    def test_bounded_prefixed_rejects_huge_declared_length(self):
        bounded = BoundedPrefixed(Int32ul, GreedyBytes, MAX_FIELD_SIZE, 'test')
        malicious = struct.pack('<I', MAX_FIELD_SIZE + 1)
        with self.assertRaises(StreamLimitError):
            bounded.parse(malicious)

    def test_bounded_prefixed_accepts_normal_data_and_roundtrips(self):
        bounded = BoundedPrefixed(Int32ul, GreedyBytes, MAX_FIELD_SIZE, 'test')
        payload = b'keepass'
        encoded = bounded.build(payload)
        self.assertEqual(bounded.parse(encoded), payload)

    def test_variant_dictionary_item_oversized_value_rejected(self):
        # type Int32ul, one-byte key, advertised value length beyond the cap
        malicious = (
            bytes([0x04])
            + struct.pack('<I', 1)
            + b'X'
            + struct.pack('<I', 0x7FFFFFFF)
        )
        with self.assertRaises(StreamLimitError) as ctx:
            VariantDictionaryItem.parse(malicious)
        self.assertIn('variant dictionary value', str(ctx.exception))

    def test_dynamic_header_oversized_field_rejected_end_to_end(self):
        raw = _load_raw()
        # master_seed header item: id byte 0x04 followed by a 32-byte length
        idx = raw.find(bytes([0x04]) + struct.pack('<I', 32))
        self.assertGreaterEqual(idx, 0)
        struct.pack_into('<I', raw, idx + 1, 0x7FFFFFFF)
        with self.assertRaises(StreamLimitError) as ctx:
            PyKeePass(io.BytesIO(bytes(raw)), password=PASSWORD)
        self.assertIn('dynamic header field', str(ctx.exception))

    def test_truncated_database_does_not_expose_plaintext(self):
        raw = _load_raw()
        kp = PyKeePass.__new__(PyKeePass)
        with self.assertRaises(Exception):
            kp.read(io.BytesIO(bytes(raw[:-64])), password=PASSWORD)
        self.assertIsNone(kp.kdbx)


class XMLHardeningTests(unittest.TestCase):
    def test_truncated_xml_raises_structured_error(self):
        kp = PyKeePass(KDBX4_FIXTURE, password=PASSWORD)
        full_xml = etree.tostring(kp.kdbx.body.payload.xml)
        truncated = full_xml[: int(len(full_xml) * 0.6)]
        with self.assertRaises(XMLParseError):
            XMLAdapter(GreedyBytes).parse(truncated)

    def test_non_xml_payload_raises_structured_error(self):
        for payload in (b'', b'not xml at all', b'<KeePassFile><Root>'):
            with self.subTest(payload=payload):
                with self.assertRaises(XMLParseError):
                    XMLAdapter(GreedyBytes).parse(payload)

    def test_xml_size_cap_is_enforced(self):
        oversized = b'<a>' + b'x' * (MAX_XML_SIZE + 1) + b'</a>'
        with self.assertRaises((XMLParseError, StreamLimitError)):
            XMLAdapter(GreedyBytes).parse(oversized)

    def test_truncated_xml_rejected_end_to_end(self):
        # build a database whose decrypted payload contains a structurally
        # truncated XML document while all outer framing stays valid
        import pykeepass.kdbx_parsing.common as common

        class RawXML:
            def __init__(self, data):
                self._raw = data

            def xpath(self, query):
                return []

        original_encode = common.XML._encode

        def raw_encode(self, tree, con, path):
            if isinstance(tree, RawXML):
                return tree._raw
            return original_encode(self, tree, con, path)

        common.XML._encode = raw_encode
        try:
            kp = PyKeePass(KDBX4_FIXTURE, password=PASSWORD)
            full_xml = etree.tostring(kp.kdbx.body.payload.xml)
            kp.kdbx.body.payload.xml = RawXML(full_xml[: int(len(full_xml) * 0.6)])
            buffer = io.BytesIO()
            KDBX.build_stream(
                kp.kdbx,
                buffer,
                password=PASSWORD,
                transformed_key=kp.kdbx.body.transformed_key,
                decrypt=True,
            )
            with self.assertRaises(XMLParseError):
                PyKeePass(io.BytesIO(buffer.getvalue()), password=PASSWORD)
        finally:
            common.XML._encode = original_encode

    def test_decompression_bomb_rejected(self):
        # highly compressible gzip stream that expands past MAX_XML_SIZE
        compressor = zlib.compressobj(
            6, zlib.DEFLATED, 16 + 15, zlib.DEF_MEM_LEVEL, 0
        )
        bomb = (
            compressor.compress(b'0' * (MAX_XML_SIZE + 1024))
            + compressor.flush()
        )
        with self.assertRaises(StreamLimitError):
            Decompressed(GreedyBytes).parse(bomb)


if __name__ == '__main__':
    unittest.main()
