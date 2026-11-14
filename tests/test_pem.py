# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import sys
import os

from asn1crypto import pem, util

from .unittest_data import data_decorator, data
from ._unittest_compat import patch

patch()

if sys.version_info < (3,):
    byte_cls = str
    num_cls = long  # noqa
else:
    byte_cls = bytes
    num_cls = int


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def _read_fixture(relative_path):
    with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
        return f.read()


@data_decorator
class PEMTests(unittest.TestCase):

    @staticmethod
    def detect_files():
        return (
            (
                'keys/test-der.crt',
                False
            ),
            (
                'keys/test-inter-der.crt',
                False
            ),
            (
                'keys/test-third-der.crt',
                False
            ),
            (
                'keys/test.crt',
                True
            ),
            (
                'keys/test-inter.crt',
                True
            ),
            (
                'keys/test-third.crt',
                True
            ),
        )

    @data('detect_files')
    def detect(self, relative_path, is_pem):
        with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
            byte_string = f.read()
        self.assertEqual(is_pem, pem.detect(byte_string))

    @staticmethod
    def unarmor_armor_files():
        return (
            (
                'keys/test.crt',
                'keys/test-der.crt',
                'CERTIFICATE',
                {}
            ),
            (
                'keys/test-inter.crt',
                'keys/test-inter-der.crt',
                'CERTIFICATE',
                {}
            ),
            (
                'keys/test-third.crt',
                'keys/test-third-der.crt',
                'CERTIFICATE',
                {}
            ),
            (
                'keys/test-pkcs8.key',
                'keys/test-pkcs8-der.key',
                'PRIVATE KEY',
                {}
            ),
            (
                'test-third.csr',
                'test-third-der.csr',
                'CERTIFICATE REQUEST',
                {}
            ),
            (
                'keys/test-aes128.key',
                'keys/test-aes128-der.key',
                'RSA PRIVATE KEY',
                util.OrderedDict([
                    ('Proc-Type', '4,ENCRYPTED'),
                    ('DEK-Info', 'AES-128-CBC,01F6EE04516C912788B11BD7377626C2')
                ])
            ),
        )

    @data('unarmor_armor_files')
    def unarmor(self, relative_path, expected_bytes_filename, expected_type_name, expected_headers):
        byte_string = _read_fixture(relative_path)

        blocks = pem.unarmor(byte_string)
        self.assertEqual(1, len(blocks))
        block = blocks[0]
        self.assertIsInstance(block, pem.PEMBlock)
        self.assertEqual(expected_type_name, block.label)
        self.assertEqual(expected_headers, block.headers)
        expected_bytes = _read_fixture(expected_bytes_filename)
        self.assertEqual(expected_bytes, block.der_bytes)
        self.assertEqual(0, block.start_offset)
        self.assertEqual(len(byte_string.rstrip(b'\r\n')), block.end_offset)

    def test_unarmor_multiple(self):
        data = self.unarmor_armor_files()
        input_data = b''
        der_data = []
        for pem_file, der_file in ((data[0][0], data[0][1]), (data[1][0], data[1][1])):
            input_data += _read_fixture(pem_file) + b'\n'
            der_data.append(_read_fixture(der_file))
        i = 0
        blocks = pem.unarmor(input_data)
        self.assertEqual(2, len(blocks))
        first_start = blocks[0].start_offset
        for block in blocks:
            self.assertEqual('CERTIFICATE', block.label)
            self.assertEqual({}, block.headers)
            self.assertEqual(der_data[i], block.der_bytes)
            self.assertLess(block.start_offset, block.end_offset)
            self.assertEqual(input_data[block.start_offset:block.end_offset].find(b'-----BEGIN'), 0)
            i += 1
        self.assertEqual(2, i)
        self.assertEqual(0, first_start)

    @data('unarmor_armor_files')
    def armor(self, expected_bytes_filename, relative_path, type_name, headers):
        with open(os.path.join(fixtures_dir, relative_path), 'rb') as f:
            byte_string = f.read()

        encoded_bytes = pem.armor(type_name, byte_string, headers=headers)
        with open(os.path.join(fixtures_dir, expected_bytes_filename), 'rb') as f:
            expected_bytes = f.read()
            # In case a user on Windows has CRLF translation on in Git.
            # Ran into this with the GitHub Actions Windows environments.
            expected_bytes = expected_bytes.replace(b'\r\n', b'\n')
            self.assertEqual(expected_bytes, encoded_bytes)

    def test_armor_wrong_type(self):
        with self.assertRaisesRegex(TypeError, 'type_name must be a unicode string'):
            pem.armor(b'CERTIFICATE', b'')

    def test_armor_wrong_type2(self):
        with self.assertRaisesRegex(TypeError, 'der_bytes must be a byte string'):
            pem.armor('CERTIFICATE', '')

    def test_detect_wrong_type(self):
        with self.assertRaisesRegex(TypeError, 'byte_string must be a byte string'):
            pem.detect('CERTIFICATE')

    def _cert_pem(self, index=0):
        paths = ('keys/test.crt', 'keys/test-inter.crt')
        return _read_fixture(paths[index])

    def _cert_der(self, index=0):
        paths = ('keys/test-der.crt', 'keys/test-inter-der.crt')
        return _read_fixture(paths[index])

    def _key_pem(self):
        return _read_fixture('keys/test-pkcs8.key')

    def _key_der(self):
        return _read_fixture('keys/test-pkcs8-der.key')

    def test_unarmor_returns_all_blocks_without_hiding_second_block(self):
        bundle = self._cert_pem(0) + self._cert_pem(1)

        blocks = pem.unarmor(bundle)

        self.assertEqual(2, len(blocks))
        self.assertEqual(['CERTIFICATE', 'CERTIFICATE'], [b.label for b in blocks])
        self.assertEqual(self._cert_der(0), blocks[0].der_bytes)
        self.assertEqual(self._cert_der(1), blocks[1].der_bytes)
        self.assertEqual(0, blocks[0].start_offset)
        self.assertEqual(blocks[0].end_offset, blocks[1].start_offset - 1)
        self.assertEqual(len(bundle.rstrip(b'\r\n')), blocks[1].end_offset)

    def test_unarmor_certificate_accepts_single_cert_and_bundle(self):
        der_bytes = pem.unarmor_certificate(self._cert_pem())
        self.assertEqual(self._cert_der(), der_bytes)

        blocks = pem.unarmor_certificates(self._cert_pem() + self._cert_pem(1))
        self.assertEqual(2, len(blocks))

    def test_unarmor_certificate_rejects_private_key_label(self):
        with self.assertRaisesRegex(ValueError, 'expected PEM label'):
            pem.unarmor_certificate(self._key_pem())
        with self.assertRaisesRegex(ValueError, 'expected a PEM certificate label'):
            pem.unarmor_certificates(self._cert_pem() + self._key_pem())

    def test_unarmor_private_key_accepts_recognized_key_labels(self):
        block = pem.unarmor_private_key(self._key_pem())
        self.assertEqual('PRIVATE KEY', block.label)
        self.assertEqual(self._key_der(), block.der_bytes)

        legacy_key = _read_fixture('keys/test.key')
        block = pem.unarmor_private_key(legacy_key)
        self.assertEqual('RSA PRIVATE KEY', block.label)

    def test_unarmor_private_key_never_falls_back_to_certificate(self):
        with self.assertRaisesRegex(ValueError, 'expected PEM label'):
            pem.unarmor_private_key(self._cert_pem())

        unknown_block = pem.armor('OPENSSH PRIVATE KEY', self._key_der())
        with self.assertRaisesRegex(ValueError, 'expected PEM label'):
            pem.unarmor_private_key(unknown_block)

    def test_unarmor_one_requires_declared_label_and_single_block(self):
        block = pem.unarmor_one(self._cert_pem(), 'CERTIFICATE')
        self.assertEqual(self._cert_der(), block.der_bytes)

        with self.assertRaisesRegex(ValueError, 'expected PEM label'):
            pem.unarmor_one(self._key_pem(), 'CERTIFICATE')
        with self.assertRaisesRegex(ValueError, 'found 2 blocks'):
            pem.unarmor_one(self._cert_pem() + self._cert_pem(1), 'CERTIFICATE')

    def test_unarmor_rejects_mismatched_end_label(self):
        broken = self._cert_pem().replace(b'END CERTIFICATE', b'END PRIVATE KEY')

        with self.assertRaisesRegex(ValueError, 'mismatched PEM labels') as context:
            pem.unarmor(broken)
        self.assertNotIn(b'MIIC', str(context.exception).encode('ascii'))

    def test_unarmor_rejects_lowercase_and_case_changed_labels(self):
        lowercase = self._cert_pem().replace(b'BEGIN CERTIFICATE', b'begin certificate')
        with self.assertRaisesRegex(ValueError, 'malformed PEM'):
            pem.unarmor(lowercase)

        mixed_case = self._cert_pem().replace(b'BEGIN CERTIFICATE', b'BEGIN Certificate')
        with self.assertRaisesRegex(ValueError, 'malformed PEM'):
            pem.unarmor(mixed_case)

    def test_unarmor_rejects_trailing_der_bytes(self):
        trailing_der = self._cert_pem() + self._cert_der()

        with self.assertRaisesRegex(ValueError, 'unexpected non-PEM data'):
            pem.unarmor(trailing_der)
        with self.assertRaisesRegex(ValueError, 'unexpected non-PEM data'):
            pem.unarmor_certificate(trailing_der)

    def test_unarmor_rejects_trailing_text(self):
        with self.assertRaisesRegex(ValueError, 'unexpected non-PEM data'):
            pem.unarmor(self._cert_pem() + b'attacker-controlled trailing data\n')

    def test_unarmor_rejects_nested_pem(self):
        nested = self._cert_pem().replace(
            b'-----END CERTIFICATE-----',
            pem.armor('CERTIFICATE', self._cert_der(1)) + b'-----END CERTIFICATE-----'
        )

        with self.assertRaisesRegex(ValueError, 'nested BEGIN boundary'):
            pem.unarmor(nested)

    def test_unarmor_rejects_empty_block(self):
        empty = b'-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n'
        with self.assertRaisesRegex(ValueError, 'empty PEM block'):
            pem.unarmor(empty)

    def test_unarmor_rejects_bad_and_non_canonical_base64(self):
        valid_block = self._cert_pem()
        lines = valid_block.splitlines()
        lines[1] = b'!' + lines[1][1:]
        with self.assertRaisesRegex(ValueError, 'invalid base64') as context:
            pem.unarmor(b'\n'.join(lines))
        self.assertNotIn(b'MII', str(context.exception).encode('ascii'))

        non_canonical = b'-----BEGIN CERTIFICATE-----\nAB==\n-----END CERTIFICATE-----\n'
        with self.assertRaisesRegex(ValueError, 'non-canonical base64'):
            pem.unarmor(non_canonical)

        missing_padding = b'-----BEGIN CERTIFICATE-----\nAB\n-----END CERTIFICATE-----\n'
        with self.assertRaisesRegex(ValueError, 'multiple of four'):
            pem.unarmor(missing_padding)

    def test_unarmor_rejects_invalid_der_prefix(self):
        not_der = pem.armor('CERTIFICATE', b'\x01\x01\x00')
        with self.assertRaisesRegex(ValueError, 'DER SEQUENCE tag'):
            pem.unarmor(not_der)

        truncated = b'-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n'
        with self.assertRaisesRegex(ValueError, 'truncated DER'):
            pem.unarmor(truncated)

    def test_unarmor_rejects_unknown_boundary_and_keeps_unknown_label_at_low_level(self):
        malformed = b'-----BEGIN CERTIFICATE ----\n-----END CERTIFICATE -----\n'
        with self.assertRaisesRegex(ValueError, 'malformed PEM'):
            pem.unarmor(malformed)

        unknown = pem.armor('WEIRD OBJECT', self._cert_der())
        blocks = pem.unarmor(unknown)
        self.assertEqual(1, len(blocks))
        self.assertEqual('WEIRD OBJECT', blocks[0].label)
        with self.assertRaisesRegex(ValueError, 'expected PEM label'):
            pem.unarmor_one(unknown, 'CERTIFICATE')

    def test_unarmor_accepts_crlf_blank_lines_and_legacy_headers(self):
        crlf = self._cert_pem().replace(b'\n', b'\r\n')
        blocks = pem.unarmor(crlf)
        self.assertEqual(1, len(blocks))
        self.assertEqual(self._cert_der(), blocks[0].der_bytes)

        with_blank_lines = self._cert_pem().replace(
            b'-----BEGIN CERTIFICATE-----\n',
            b'-----BEGIN CERTIFICATE-----\n\n'
        )
        self.assertEqual(1, len(pem.unarmor(with_blank_lines)))

        legacy = _read_fixture('keys/test-aes128.key')
        block = pem.unarmor(legacy)[0]
        self.assertEqual('RSA PRIVATE KEY', block.label)
        self.assertEqual('4,ENCRYPTED', block.headers['Proc-Type'])
        self.assertEqual(
            'AES-128-CBC,01F6EE04516C912788B11BD7377626C2',
            block.headers['DEK-Info']
        )

    def test_unarmor_rejects_malformed_legacy_header_fields(self):
        empty_value = b'-----BEGIN CERTIFICATE-----\nFoo:\n-----END CERTIFICATE-----\n'
        with self.assertRaisesRegex(ValueError, 'invalid base64 line'):
            pem.unarmor(empty_value)

        empty_name = b'-----BEGIN CERTIFICATE-----\n: value\n-----END CERTIFICATE-----\n'
        with self.assertRaisesRegex(ValueError, 'invalid base64 line'):
            pem.unarmor(empty_name)

    def test_unarmor_accepts_legacy_dashed_boundaries(self):
        legacy = self._cert_pem().replace(b'-----BEGIN ', b'---- BEGIN ')
        legacy = legacy.replace(b'-----END ', b'---- END ')
        legacy = legacy.replace(b'-----\n', b' ----\n')

        blocks = pem.unarmor(legacy)
        self.assertEqual(1, len(blocks))
        self.assertEqual('CERTIFICATE', blocks[0].label)

    def test_unarmor_rejects_non_pem_and_wrong_types(self):
        with self.assertRaisesRegex(ValueError, 'unexpected non-PEM data'):
            pem.unarmor(self._cert_der())
        with self.assertRaisesRegex(TypeError, 'pem_bytes must be a byte string'):
            pem.unarmor('not bytes')
        with self.assertRaisesRegex(TypeError, 'expected_label'):
            pem.unarmor_one(self._cert_pem(), 123)
