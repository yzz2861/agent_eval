"""
Local tests for the idempotent LDAP filter escaping boundary API, the
structured filter builder and the strict filter parser. These tests do not
require any external directory server.
"""

import unittest

from pyasn1.codec.ber import encoder

from ldap3 import SUBTREE, DEREF_NEVER
from ldap3.core.exceptions import LDAPInvalidFilterError, LDAPFilterEscapeError, \
    LDAPInvalidFilterStructureError, LDAPTruncatedFilterError
from ldap3.operation.search import parse_filter, compile_filter, build_filter, search_operation, \
    MATCH_EQUAL, MATCH_SUBSTRING, MATCH_PRESENT, AND, OR, NOT, MAX_FILTER_DEPTH
from ldap3.utils.conv import escape_filter_chars


def _parse(search_filter, strict=False):
    return parse_filter(search_filter, None, True, False, None, False, strict=strict)


class TestEscapeFilterChars(unittest.TestCase):
    def test_default_escapes_rfc4515_specials(self):
        self.assertEqual(escape_filter_chars('*)(uid=*'), '\\2a\\29\\28uid=\\2a')
        self.assertEqual(escape_filter_chars('\\'), '\\5c')
        self.assertEqual(escape_filter_chars('\x00'), '\\00')
        self.assertEqual(escape_filter_chars('()'), '\\28\\29')

    def test_default_keeps_legacy_double_escaping_behaviour(self):
        # Legacy behaviour is preserved when strict mode is not requested:
        # escaping an already escaped value doubles the backslash.
        once = escape_filter_chars('*')
        self.assertEqual(once, '\\2a')
        self.assertEqual(escape_filter_chars(once), '\\5c2a')

    def test_strict_escapes_specials_nul_and_unicode(self):
        self.assertEqual(escape_filter_chars('*)(uid=*', strict=True), '\\2a\\29\\28uid=\\2a')
        self.assertEqual(escape_filter_chars('\x00', strict=True), '\\00')
        self.assertEqual(escape_filter_chars(u'\u00e9', strict=True), '\\c3\\a9')
        self.assertEqual(escape_filter_chars(u'\u4e2d\u6587', strict=True), '\\e4\\b8\\ad\\e6\\96\\87')
        self.assertEqual(escape_filter_chars(u'a\u00e9*b', strict=True), 'a\\c3\\a9\\2ab')

    def test_strict_escapes_raw_bytes_octet_by_octet(self):
        self.assertEqual(escape_filter_chars(b'\xff\x00*', strict=True), '\\ff\\00\\2a')

    def test_strict_rejects_already_escaped_input(self):
        self.assertRaises(LDAPFilterEscapeError, escape_filter_chars, 'a\\2ab', None, True)
        self.assertRaises(LDAPFilterEscapeError, escape_filter_chars, 'a\\2Ab', None, True)
        self.assertRaises(LDAPFilterEscapeError, escape_filter_chars, b'a\\2ab', None, True)

    def test_strict_preserve_accepts_escaped_bytes(self):
        already_escaped = b'a\\28b\\29'
        self.assertEqual(
            escape_filter_chars(already_escaped, strict=True, already_escaped='preserve'),
            'a\\28b\\29')

    def test_strict_preserve_keeps_already_escaped_input_unchanged(self):
        already_escaped = 'a\\2ab\\28'
        self.assertEqual(
            escape_filter_chars(already_escaped, strict=True, already_escaped='preserve'),
            already_escaped)
        # Preserving is idempotent: the value keeps the same semantics no
        # matter how many times it crosses the boundary.
        self.assertEqual(
            escape_filter_chars(
                escape_filter_chars(already_escaped, strict=True, already_escaped='preserve'),
                strict=True, already_escaped='preserve'),
            already_escaped)

    def test_strict_rejects_malformed_and_truncated_escapes(self):
        for bad in ('a\\', 'a\\2', 'a\\zz', 'a\\x0', '\\'):
            self.assertRaises(LDAPFilterEscapeError, escape_filter_chars, bad, None, True)

    def test_strict_rejects_unknown_already_escaped_policy(self):
        self.assertRaises(LDAPFilterEscapeError, escape_filter_chars, 'abc', None, True, 'nope')

    def test_strict_plain_value_is_idempotent(self):
        escaped = escape_filter_chars('plain value', strict=True)
        self.assertEqual(escaped, 'plain value')
        self.assertEqual(escape_filter_chars(escaped, strict=True, already_escaped='preserve'), escaped)


class TestBuildFilter(unittest.TestCase):
    def test_leaf_equality_escapes_user_input(self):
        self.assertEqual(build_filter(('uid', '*)(uid=*')), '(uid=\\2a\\29\\28uid=\\2a)')

    def test_operators_present_and_substring(self):
        self.assertEqual(build_filter(('cn', 'present', None)), '(cn=*)')
        self.assertEqual(build_filter(('sn', 'sub', ['a', 'b'])), '(sn=a*b)')
        self.assertEqual(build_filter(('sn', 'sub', ['', 'a', ''])), '(sn=*a*)')
        self.assertEqual(build_filter(('cn', '~=', 'x')), '(cn~=x)')
        self.assertEqual(build_filter(('cn', '>=', 'x')), '(cn>=x)')
        self.assertEqual(build_filter(('cn', '<=', 'x')), '(cn<=x)')
        self.assertEqual(build_filter(('cn', ':=', 'x')), '(cn:=x)')

    def test_dict_leaf_and_boolean_nesting(self):
        structured = ('&', [
            {'attr': 'uid', 'value': 'admin'},
            ('|', [('cn', 'present', None), ('sn', 'sub', ['a', 'b'])]),
            ('!', ('objectClass', 'person')),
        ])
        self.assertEqual(
            build_filter(structured),
            '(&(uid=admin)(|(cn=*)(sn=a*b))(!(objectClass=person)))')

    def test_unicode_and_nul_values_are_escaped(self):
        self.assertEqual(build_filter(('cn', u'\u00e9\x00')), '(cn=\\c3\\a9\\00)')

    def test_built_filter_round_trips_through_parser(self):
        search_filter = build_filter(('&', [('uid', '*)(uid=*'), ('sn', 'sub', ['john', 'doe'])]))
        root = _parse(search_filter)
        self.assertEqual(root.elements[0].tag, AND)
        equality = root.elements[0].elements[0]
        self.assertEqual(equality.tag, MATCH_EQUAL)
        self.assertEqual(equality.assertion['value'], b'\\2a\\29\\28uid=\\2a')
        substring = root.elements[0].elements[1]
        self.assertEqual(substring.tag, MATCH_SUBSTRING)
        self.assertEqual(substring.assertion['initial'], b'john')
        self.assertEqual(substring.assertion['final'], b'doe')

    def test_invalid_structures_are_rejected(self):
        invalid_nodes = (
            ('cn', 'bad-op', 'x'),
            ('cn(', 'x'),
            ('cn', 'present', 'x'),
            ('cn', 'sub', []),
            ('cn', 'sub', 'not-a-sequence'),
            ('&', []),
            ('|', {'attr': 'cn', 'value': 'x'}),
            ('!', [('cn', 'x')]),
            ('?', [('cn', 'x')]),
            ('cn', None),
            'not-a-node',
        )
        for node in invalid_nodes:
            self.assertRaises(LDAPInvalidFilterStructureError, build_filter, node)

    def test_nesting_depth_is_limited(self):
        node = ('cn', 'x')
        for _ in range(MAX_FILTER_DEPTH):
            node = ('!', node)
        self.assertRaises(LDAPInvalidFilterStructureError, build_filter, node)


class TestParseFilterStrict(unittest.TestCase):
    def test_strict_and_default_return_identical_nodes_for_legal_filter(self):
        search_filter = '(&(cn=admin)(!(:DN:2.4.6.8.10:=Dino))(sn=a*b))'
        default_root = _parse(search_filter)
        strict_root = _parse(search_filter, strict=True)
        self.assertEqual(repr(strict_root), repr(default_root))
        self.assertEqual(strict_root.elements[0].tag, AND)
        self.assertEqual(strict_root.elements[0].elements[1].tag, NOT)

    def test_escaped_and_mixed_case_hex_pairs_are_accepted(self):
        root = _parse('(uid=a\\2Ab\\2ac\\28)', strict=True)
        self.assertEqual(root.elements[0].tag, MATCH_EQUAL)
        self.assertEqual(root.elements[0].assertion['value'], b'a\\2Ab\\2ac\\28')

    def test_escaped_nul_is_accepted(self):
        root = _parse('(uid=a\\00b)', strict=True)
        self.assertEqual(root.elements[0].assertion['value'], b'a\\00b')

    def test_present_filter_is_accepted(self):
        root = _parse('(cn=*)', strict=True)
        self.assertEqual(root.elements[0].tag, MATCH_PRESENT)

    def test_deep_nesting_is_supported_up_to_limit(self):
        depth = 50
        search_filter = '(&' * depth + '(cn=x)' + ')' * depth
        root = _parse(search_filter, strict=True)
        node = root.elements[0]
        seen = 0
        while node.tag in (AND, OR, NOT):
            seen += 1
            node = node.elements[0]
        self.assertEqual(seen, depth)

    def test_nesting_beyond_limit_is_classified(self):
        depth = MAX_FILTER_DEPTH + 10
        search_filter = '(' * depth + 'cn=x' + ')' * depth
        self.assertRaises(LDAPInvalidFilterStructureError, _parse, search_filter, True)

    def test_malformed_filters_are_classified_without_echoing_values(self):
        secret_dn = 'cn=admin,dc=example,dc=com'
        secret_password = 'supersecretpassword'
        cases = {
            LDAPInvalidFilterStructureError: (
                '',
                '((cn=x))',
                '(!(a=b)(c=d))',
                '()',
            ),
            LDAPTruncatedFilterError: (
                '(',
                '(&(a=b)(c=d)',
                '(cn=x',
                '(cn=' + secret_dn,
                '(cn=' + secret_password + '\\)',
            ),
            LDAPFilterEscapeError: (
                '(cn=\\zz)',
                '(cn=\\2)',
            ),
            LDAPInvalidFilterError: (
                '(cn=x\x00)',
            ),
        }
        for expected_error, filters in cases.items():
            for search_filter in filters:
                with self.assertRaises(LDAPInvalidFilterError) as caught:
                    _parse(search_filter, strict=True)
                self.assertIsInstance(caught.exception, expected_error)
                message = str(caught.exception)
                self.assertNotIn(secret_dn, message)
                self.assertNotIn(secret_password, message)

    def test_default_mode_keeps_legacy_permissive_behaviour(self):
        # Strict validation is opt-in: the legacy parser still accepts the
        # same input and returns the same node shape.
        root = _parse('(uid=\\2)')
        self.assertEqual(root.elements[0].assertion['value'], b'\\2')
        self.assertIsInstance(_parse('(cn=admin)').elements[0].assertion['value'], bytes)

    def test_legacy_keyword_signature_remains_supported(self):
        root = parse_filter(
            '(cn=admin)', schema=None, auto_escape=True, auto_encode=False,
            validator=None, check_names=False)
        self.assertEqual(root.elements[0].assertion['value'], b'admin')

    def test_compile_filter_output_is_unchanged_for_legal_filters(self):
        search_filter = '(cn=admin)'
        compiled = compile_filter(_parse(search_filter, strict=True).elements[0])
        legacy = compile_filter(_parse(search_filter).elements[0])
        self.assertEqual(encoder.encode(compiled), encoder.encode(legacy))


class TestFilterWireBytes(unittest.TestCase):
    def _encoded_request(self, search_filter):
        request = search_operation(
            search_base='o=test',
            search_filter=search_filter,
            search_scope=SUBTREE,
            dereference_aliases=DEREF_NEVER,
            attributes=['cn'],
            size_limit=0,
            time_limit=0,
            types_only=False,
            auto_escape=True,
            auto_encode=False)
        return encoder.encode(request)

    def test_injection_never_reaches_server_as_filter_syntax(self):
        search_filter = build_filter(('uid', '*)(uid=*'))
        encoded = self._encoded_request(search_filter)
        self.assertIn(b'\\2a\\29\\28uid=\\2a', encoded)
        self.assertNotIn(b'*)(uid=*', encoded)

    def test_unicode_is_sent_as_escaped_utf8_octets(self):
        search_filter = build_filter(('cn', u'\u00e9'))
        encoded = self._encoded_request(search_filter)
        self.assertIn(b'\\c3\\a9', encoded)
        raw_utf8 = u'\u00e9'.encode('utf-8')
        self.assertNotIn(raw_utf8, encoded)

    def test_nul_is_sent_as_escaped_sequence(self):
        search_filter = build_filter(('cn', 'a\x00b'))
        encoded = self._encoded_request(search_filter)
        self.assertIn(b'a\\00b', encoded)
        self.assertNotIn(b'a\x00b', encoded)


if __name__ == '__main__':
    unittest.main()
