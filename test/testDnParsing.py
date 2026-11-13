"""
"""

# Created on 2014.09.15
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

import unittest

from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn as p
from ldap3.utils.dn import DN, dn_equals, is_descendant_dn, is_ancestor_dn


class Test(unittest.TestCase):
    def test_parse_dn_single(self):
        parsed = p('cn=admin')
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0], ('cn', 'admin', ''))

    def test_parse_dn_single_multi_rdn(self):
        parsed = p('cn=admin+email=admin@site.com')
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0], ('cn', 'admin', '+'))
        self.assertEqual(parsed[1], ('email', 'admin@site.com', ''))

    def test_parse_dn_escaped_single_multi_rdn(self):
        parsed = p('cn=\\\\\\+admin+email=admin@site.com')
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0], ('cn', '\\\\\\+admin', '+'))
        self.assertEqual(parsed[1], ('email', 'admin@site.com', ''))

    def test_parse_dn_double(self):
        parsed = p('cn=user1,o=users')
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0], ('cn', 'user1', ','))
        self.assertEqual(parsed[1], ('o', 'users', ''))

    def test_parse_dn_multi(self):
        parsed = p('cn=user1,ou=users,dc=branch,dc=company,c=IT')
        self.assertEqual(len(parsed), 5)
        self.assertEqual(parsed[0], ('cn', 'user1', ','))
        self.assertEqual(parsed[1], ('ou', 'users', ','))
        self.assertEqual(parsed[2], ('dc', 'branch', ','))
        self.assertEqual(parsed[3], ('dc', 'company', ','))
        self.assertEqual(parsed[4], ('c', 'IT', ''))

    def test_parse_dn_multi_type(self):
        parsed = p('cn=user1+sn=surname1,o=users')
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0], ('cn', 'user1', '+'))
        self.assertEqual(parsed[1], ('sn', 'surname1', ','))
        self.assertEqual(parsed[2], ('o', 'users', ''))

    def test_parse_dn_escaped_single(self):
        parsed = p('cn=admi\\,n')
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0], ('cn', 'admi\\,n', ''))

    def test_parse_dn_escaped_double(self):
        parsed = p('cn=us\\=er1,o=us\\,ers')
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0], ('cn', 'us\\=er1', ','))
        self.assertEqual(parsed[1], ('o', 'us\\,ers', ''))

    def test_parse_dn_escaped_double_1(self):
        parsed = p('cn=\\\\,o=\\\\')
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0], ('cn', '\\\\', ','))
        self.assertEqual(parsed[1], ('o', '\\\\', ''))

    def test_parse_dn_escaped_multi(self):
        parsed = p('cn=us\\,er1,ou=us\\08ers,dc=br\\,anch,dc=company,c=IT')
        self.assertEqual(len(parsed), 5)
        self.assertEqual(parsed[0], ('cn', 'us\\,er1', ','))
        self.assertEqual(parsed[1], ('ou', 'us\\08ers', ','))
        self.assertEqual(parsed[2], ('dc', 'br\\,anch', ','))
        self.assertEqual(parsed[3], ('dc', 'company', ','))
        self.assertEqual(parsed[4], ('c', 'IT', ''))

    def test_parse_dn_escaped_multi_type(self):
        parsed = p('cn=us\\+er1+sn=su\\,rname1,o=users')
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0], ('cn', 'us\\+er1', '+'))
        self.assertEqual(parsed[1], ('sn', 'su\\,rname1', ','))
        self.assertEqual(parsed[2], ('o', 'users', ''))

    def test_parse_dn_unescaped_single(self):
        parsed = p('cn=admi,n', escape=True)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0], ('cn', 'admi\\,n', ''))

    def test_parse_dn_unescaped_double(self):
        parsed = p('cn=us=er1,o=us,ers', escape=True)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0], ('cn', 'us\\=er1', ','))
        self.assertEqual(parsed[1], ('o', 'us\\,ers', ''))

    def test_parse_dn_unescaped_multi(self):
        parsed = p('cn=us,er1,ou=use<rs,dc=br+anch,dc=company,c=IT', escape=True)
        self.assertEqual(len(parsed), 5)
        self.assertEqual(parsed[0], ('cn', 'us\\,er1', ','))
        self.assertEqual(parsed[1], ('ou', 'use\\<rs', ','))
        self.assertEqual(parsed[2], ('dc', 'br\\+anch', ','))
        self.assertEqual(parsed[3], ('dc', 'company', ','))
        self.assertEqual(parsed[4], ('c', 'IT', ''))

    def test_parse_dn_unescaped_multi_type(self):
        parsed = p('cn=us+er1+sn=su,rname1,o=users', escape=True)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0], ('cn', 'us\\+er1', '+'))
        self.assertEqual(parsed[1], ('sn', 'su\\,rname1', ','))
        self.assertEqual(parsed[2], ('o', 'users', ''))

    def pair_generator(self):
        # escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
        escaped = ['"', '+', ',', ';', '<', '>']
        # special = escaped / SPACE / SHARP / EQUALS
        special = escaped + [' ', '#', '=']
        ESC = ['\\']
        # hexpair = HEX HEX
        hexpairs = ['00', '99', 'aa', 'AA', 'ff', 'FF', 'aF', 'Af']
        # pair = ESC ( ESC / special / hexpair )
        pair = self.combine_strings(ESC, ESC + special + hexpairs)
        return pair

    def test_parse_dn_pair(self):
        if hasattr(self, 'subTest'):  # python3 only
            for onepair in self.pair_generator():
                for attributeValue, mode in [
                    (onepair, "alone"),
                    ("a" + onepair + "b", "between"),
                    ("a" + onepair, "after"),
                    (onepair + "b", "before")
                ]:
                    for separator in [None, '+', ',']:

                        if not separator:
                            dn = r'cn={0}'.format(attributeValue)
                            expected = [('cn', attributeValue, '')]
                        else:
                            dn = r'cn={0}{1}ou={0}'.format(attributeValue, separator)
                            expected = [('cn', attributeValue, separator), ('ou', attributeValue, '')]

                        with self.subTest(pair=onepair, separator=separator, mode=mode, input=dn):
                            self._test_parse_dn(
                                dn,
                                expected
                            )


    def combine_strings(self, *args):
        if len(args) == 0: raise Exception("Invalid parameter")
        if len(args) == 1:
            for variant in args[0]:
                yield variant
        else:
            for head in args[0]:
                for tail in self.combine_strings(*args[1:]):
                    variant = head + tail
                    yield variant

    def test_combine_strings(self):
        variants = set(self.combine_strings(['a', 'b'], ['x', 'y']))
        self.assertEqual(variants, {'ax', 'ay', 'bx', 'by'})

    def test_combine_strings_empty1(self):
        variants = set(self.combine_strings([], ['x', 'y']))
        self.assertEqual(len(variants), 0)

    def test_combine_strings_empty2(self):
        variants = set(self.combine_strings(['a', 'b'], []))
        self.assertEqual(len(variants), 0)

    def _test_parse_dn(self, input, expected):
        parsed = p(input, escape=False)
        self.assertEqual(parsed, expected)

    def test_unit_test_deep_equality(self):
        self.assertEqual([], [])
        self.assertNotEqual([], [()])
        self.assertEqual([()], [()])
        self.assertNotEqual([()], [(), ()])
        self.assertNotEqual([()], [('b')])
        self.assertEqual([('a')], [('a')])
        self.assertNotEqual([('a')], [('b')])
        self.assertEqual([('a', 'b', 'x'), ('a', 'b', 'x')], [('a', 'b', 'x'), ('a', 'b', 'x')])
        self.assertNotEqual([('a', 'b', 'x'), ('a', 'b', 'x')], [('a', 'b', 'x'), ('a', 'b', 'y')])
        self.assertNotEqual([('1')], [(1)])


class TestDnRepresentations(unittest.TestCase):
    def test_raw_representation_is_preserved(self):
        original = ' CN=Admin , OU=Ops , DC=example,DC=com ,'
        dn = DN(original)
        self.assertEqual(dn.raw, original)

    def test_escaped_representation_is_rfc4514_safe(self):
        dn = DN(' CN=Admin , OU=Ops , DC=example,DC=com ,')
        self.assertEqual(dn.escaped, 'CN=Admin,OU=Ops,DC=example,DC=com')
        self.assertEqual(str(dn), dn.escaped)

    def test_canonical_representation_normalizes_type_and_spaces(self):
        dn = DN(' CN=Admin , OU=Ops , DC=example,DC=com ,')
        self.assertEqual(dn.canonical, 'cn=Admin,ou=Ops,dc=example,dc=com')

    def test_single_trailing_comma_is_accepted(self):
        self.assertEqual(DN('cn=a,dc=x,').canonical, 'cn=a,dc=x')

    def test_value_case_is_not_folded(self):
        # RFC 4514 only defines case-insensitivity for attribute types, values stay exact
        self.assertNotEqual(DN('cn=Admin,dc=x'), DN('cn=admin,dc=x'))
        self.assertEqual(DN('CN=Admin,DC=x'), DN('cn=Admin,dc=x'))


class TestDnEquivalenceVectors(unittest.TestCase):
    def test_same_value_different_spelling_is_equal(self):
        variants = [
            DN('CN=Admin,OU=Ops,DC=example,DC=com'),
            DN(' cn=Admin , ou=Ops , dc=example , dc=com ,'),
            DN('cN=Admin,oU=Ops,dC=example,dC=com'),
        ]
        for dn in variants[1:]:
            self.assertTrue(dn_equals(variants[0], dn))
            self.assertEqual(hash(variants[0]), hash(dn))
        self.assertEqual(len(set(variants)), 1)

    def test_hex_escape_and_literal_escape_are_equal(self):
        hex_dn = DN(r'cn=Admin\2c Ops,dc=example,dc=com')
        literal_dn = DN(r'cn=Admin\, Ops,dc=example,dc=com')
        self.assertEqual(hex_dn, literal_dn)
        self.assertEqual(hex_dn.canonical, r'cn=Admin\, Ops,dc=example,dc=com')

    def test_escaped_comma_does_not_split_rdns(self):
        single_rdn = DN(r'cn=Admin\, Ops,ou=ops,dc=com')
        # the escaped comma is part of the value, so only three RDNs exist
        self.assertEqual(len(single_rdn.rdns()), 3)
        multi_rdn = DN('cn=Admin,ou=ops,dc=com')
        self.assertNotEqual(single_rdn, multi_rdn)

    def test_really_different_values_are_not_equal(self):
        self.assertNotEqual(DN('cn=admin,ou=ops,dc=example,dc=com'),
                            DN('cn=administrator,ou=ops,dc=example,dc=com'))
        self.assertNotEqual(DN('cn=admin,ou=ops,dc=example,dc=com'),
                            DN('cn=admin,ou=other,dc=example,dc=com'))

    def test_different_rdn_depth_is_not_equal(self):
        self.assertNotEqual(DN('cn=admin,dc=example,dc=com'),
                            DN('cn=admin,ou=ops,dc=example,dc=com'))

    def test_multivalued_rdn_ava_order_is_insignificant(self):
        self.assertEqual(DN('cn=a+sn=b,dc=example,dc=com'),
                         DN('SN=b+CN=a,dc=example,dc=com'))
        # multivalued RDN is still a different object from a single AVA RDN
        self.assertNotEqual(DN('cn=a+sn=b,dc=example,dc=com'),
                            DN('cn=a,dc=example,dc=com'))

    def test_escaped_leading_and_trailing_spaces_are_significant(self):
        spaced = DN(r'cn=\ admin\ ,ou=ops')
        hex_spaced = DN(r'cn=\20admin\20,ou=ops')
        plain = DN('cn=admin,ou=ops')
        self.assertEqual(spaced, hex_spaced)
        self.assertNotEqual(spaced, plain)
        self.assertEqual(spaced.canonical, r'cn=\ admin\ ,ou=ops')


class TestDnUnicodeAndHex(unittest.TestCase):
    def test_utf8_hex_escape_decodes_to_unicode(self):
        dn = DN(r'cn=\e4\b8\ad,dc=example,dc=com')
        self.assertEqual(dn.canonical, 'cn=\u4e2d,dc=example,dc=com')
        # round trip through the escaped wire representation keeps the value
        self.assertEqual(DN(dn.escaped), dn)

    def test_literal_unicode_is_accepted(self):
        dn = DN('cn=\u4e2d\u6587,dc=example,dc=com')
        self.assertEqual(dn.canonical, 'cn=\u4e2d\u6587,dc=example,dc=com')

    def test_binary_hex_value_is_preserved(self):
        dn = DN('cn=#04ff,dc=x')
        self.assertEqual(dn.rdns()[0][0][1], bytes(bytearray([4, 255])))
        self.assertEqual(dn.canonical, 'cn=#04FF,dc=x')

    def test_hex_value_and_hex_escape_of_same_bytes_are_equal(self):
        self.assertEqual(DN('cn=#4869,dc=x'), DN(r'cn=\48\69,dc=x'))

    def test_special_characters_are_re_escaped_uniformly(self):
        dn = DN(r'ou=R\26D,dc=example,dc=com')
        self.assertEqual(dn.canonical, r'ou=R&D,dc=example,dc=com')


class TestDnDeepOuMatching(unittest.TestCase):
    def setUp(self):
        self.base = DN('dc=example,dc=com')
        self.ops = DN('ou=ops,dc=example,dc=com')
        self.deep = DN('cn=admin,ou=level1,ou=level2,ou=ops,dc=example,dc=com')

    def test_descendant_and_ancestor_are_structural(self):
        self.assertTrue(is_descendant_dn(self.deep, self.base))
        self.assertTrue(is_ancestor_dn(self.base, self.deep))
        self.assertTrue(is_descendant_dn(self.deep, self.ops))
        self.assertFalse(is_descendant_dn(self.base, self.deep))
        self.assertFalse(is_descendant_dn(self.deep, self.deep))

    def test_textual_suffix_cannot_grant_privilege(self):
        # a foreign DN that merely ends with the same text is not a descendant
        foreign = DN('cn=admin,ou=ops,dc=attacker,dc=example,dc=com')
        self.assertFalse(is_descendant_dn(foreign, self.ops))
        # and the same leaf text under a different parent stays distinct
        twin = DN('cn=admin,ou=other,dc=example,dc=com')
        admin = DN('cn=admin,ou=ops,dc=example,dc=com')
        self.assertNotEqual(twin, admin)

    def test_direct_child_uses_rdn_depth(self):
        child = DN('ou=ops,dc=example,dc=com')
        grandchild = DN('cn=admin,ou=ops,dc=example,dc=com')
        self.assertTrue(is_descendant_dn(child, self.base))
        self.assertTrue(is_descendant_dn(grandchild, child))
        self.assertEqual(len(grandchild.rdns()), len(child.rdns()) + 1)


class TestDnRejectsAmbiguousInput(unittest.TestCase):
    def _assert_invalid(self, value):
        with self.assertRaises(LDAPInvalidDnError):
            DN(value)

    def test_unescaped_comma_is_rejected(self):
        self._assert_invalid('cn=admi,n')

    def test_empty_rdn_is_rejected(self):
        for value in ['cn=a,,dc=x', ',dc=x', 'cn=a,dc=x,,', '   ', '']:
            self._assert_invalid(value)

    def test_empty_attribute_value_is_rejected(self):
        self._assert_invalid('cn=,dc=x')

    def test_duplicate_attribute_in_rdn_is_rejected(self):
        self._assert_invalid('cn=a+cn=b,dc=x')

    def test_illegal_hex_value_is_rejected(self):
        for value in ['cn=#zz', 'cn=#abc', 'cn=#', r'cn=\4z', r'cn=\3x']:
            self._assert_invalid(value)

    def test_valid_hex_pair_is_decoded(self):
        # 0x3B is the SEMICOLON, a valid hex pair even though it looks odd
        self.assertEqual(DN(r'cn=a\3bb').rdns()[0][0][1], 'a;b')

    def test_bad_escape_is_rejected(self):
        self._assert_invalid(r'cn=\q')
        self._assert_invalid('cn=test\\')

    def test_unescaped_special_character_is_rejected(self):
        for value in [r'cn=a<b', r'cn=a>b', r'cn=a"b', r'cn=a;b', r'cn=a+b,ou=x']:
            self._assert_invalid(value)

    def test_illegal_attribute_type_is_rejected(self):
        self._assert_invalid('2bad=admin,dc=x')
        self._assert_invalid('-cn=admin,dc=x')
        self._assert_invalid('c n=admin,dc=x')


class TestDnComparisonApi(unittest.TestCase):
    def test_bare_strings_are_rejected(self):
        dn = DN('cn=a,dc=x')
        for call in (lambda: dn_equals(dn, 'cn=a,dc=x'),
                     lambda: dn_equals('cn=a,dc=x', dn),
                     lambda: is_descendant_dn(dn, 'dc=x'),
                     lambda: is_ancestor_dn('dc=x', dn)):
            with self.assertRaises(TypeError):
                call()

    def test_non_string_constructor_is_rejected(self):
        with self.assertRaises(TypeError):
            DN(42)

    def test_dn_copy_constructor(self):
        dn = DN('CN=a,DC=x')
        copy = DN(dn)
        self.assertEqual(dn, copy)
        self.assertEqual(dn.raw, copy.raw)
        self.assertEqual(dn.escaped, copy.escaped)
        self.assertEqual(dn.canonical, copy.canonical)

    def test_legacy_parse_dn_results_are_unchanged(self):
        self.assertEqual(p('cn=user1,o=users'), [('cn', 'user1', ','), ('o', 'users', '')])
        self.assertEqual(p(r'cn=admi\,n'), [('cn', r'admi\,n', '')])
        self.assertEqual(p('cn=admi,n', escape=True), [('cn', r'admi\,n', '')])
