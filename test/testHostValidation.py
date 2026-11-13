"""
Host normalization and certificate identity matching unit tests.
"""

import unittest

from ldap3.core.exceptions import LDAPSSLConfigurationError
from ldap3.utils.host import (
    HostType,
    dns_name_matches,
    ip_name_matches,
    match_certificate_identity,
    normalize_host,
)


class TestNormalizeHost(unittest.TestCase):
    def test_dns_name_is_lowercased_and_trimmed(self):
        normalized = normalize_host('  LDAP3.Example.COM  ')
        self.assertEqual(normalized.host_type, HostType.DNS)
        self.assertEqual(normalized.match_value, 'ldap3.example.com')
        self.assertEqual(normalized.sni_value, 'ldap3.example.com')

    def test_trailing_dot_is_removed(self):
        self.assertEqual(normalize_host('ldap3.example.com.').match_value, 'ldap3.example.com')

    def test_idna_unicode_name_is_a_label_encoded(self):
        normalized = normalize_host(u'\u4f8b\u3048.example')
        self.assertEqual(normalized.host_type, HostType.DNS)
        self.assertTrue(normalized.match_value.startswith('xn--'))
        # A-label input must produce the same normalized form.
        self.assertEqual(normalize_host(normalized.match_value).match_value, normalized.match_value)

    def test_ipv4_literal(self):
        normalized = normalize_host('192.0.2.23')
        self.assertEqual(normalized.host_type, HostType.IP)
        self.assertFalse(normalized.is_ipv6)
        self.assertEqual(normalized.match_value, '192.0.2.23')
        self.assertIsNone(normalized.sni_value)

    def test_ipv6_literal_is_compressed(self):
        normalized = normalize_host('2001:0db8:0000:0000:0000:0000:0000:0001')
        self.assertEqual(normalized.host_type, HostType.IP)
        self.assertTrue(normalized.is_ipv6)
        self.assertEqual(normalized.match_value, '2001:db8::1')
        self.assertIsNone(normalized.sni_value)

    def test_ipv6_zone_identifier_is_not_part_of_match_value(self):
        normalized = normalize_host('fe80::1%eth0')
        self.assertEqual(normalized.host_type, HostType.IP)
        self.assertEqual(normalized.match_value, 'fe80::1')
        self.assertEqual(normalized.zone_id, 'eth0')
        self.assertIsNone(normalized.sni_value)

    def test_bracketed_ipv6_with_zone(self):
        normalized = normalize_host('[fe80::1%25en0]')
        self.assertEqual(normalized.match_value, 'fe80::1')
        self.assertEqual(normalized.zone_id, '25en0')

    def test_empty_name_is_rejected(self):
        self.assertRaises(ValueError, normalize_host, '   ')
        self.assertRaises(ValueError, normalize_host, None)


class TestDnsMatching(unittest.TestCase):
    def test_exact_match_is_case_insensitive(self):
        self.assertTrue(dns_name_matches('ldap3.Example.com', 'LDAP3.example.COM'))

    def test_wildcard_matches_single_label_only(self):
        self.assertTrue(dns_name_matches('*.example.com', 'a.example.com'))
        self.assertFalse(dns_name_matches('*.example.com', 'a.b.example.com'))
        self.assertFalse(dns_name_matches('*.example.com', 'example.com'))

    def test_wildcard_must_stay_in_leftmost_label(self):
        self.assertTrue(dns_name_matches('www*.example.com', 'www2.example.com'))
        self.assertFalse(dns_name_matches('www.*.example.com', 'www.a.example.com'))
        self.assertFalse(dns_name_matches('*.*.example.com', 'a.b.example.com'))

    def test_wildcard_does_not_cross_label_count(self):
        self.assertFalse(dns_name_matches('*.example.com', 'a.example.org'))
        # the trailing root label is stripped on both sides
        self.assertTrue(dns_name_matches('*.example.com', 'a.example.com.'))
        self.assertFalse(dns_name_matches('*.example.com.', 'a.example.org.'))


class TestIpMatching(unittest.TestCase):
    def test_ipv4_and_ipv6_equivalence(self):
        self.assertTrue(ip_name_matches('127.0.0.1', '127.0.0.1'))
        self.assertTrue(ip_name_matches('2001:db8::1', '2001:db8:0:0:0:0:0:1'))
        self.assertFalse(ip_name_matches('127.0.0.1', '127.0.0.2'))
        self.assertFalse(ip_name_matches('not-an-ip', '127.0.0.1'))


class TestCertificateIdentity(unittest.TestCase):
    @staticmethod
    def _cert(san=(), subject_cn=None):
        cert = {}
        if san:
            cert['subjectAltName'] = tuple(san)
        if subject_cn is not None:
            cert['subject'] = ((('commonName', subject_cn),),)
        return cert

    def test_dns_san_match(self):
        cert = self._cert(san=(('DNS', 'ldap3.example.com'),))
        identity_type, identity_value = match_certificate_identity(cert, normalize_host('ldap3.example.com'))
        self.assertEqual(identity_type, 'DNS')

    def test_ip_only_matches_ip_san(self):
        cert = self._cert(san=(('DNS', '127.0.0.1'),))
        self.assertRaises(ValueError, match_certificate_identity, cert, normalize_host('127.0.0.1'))

        cert = self._cert(san=(('IP Address', '127.0.0.1'),))
        identity_type, identity_value = match_certificate_identity(cert, normalize_host('127.0.0.1'))
        self.assertEqual(identity_type, 'IP Address')

    def test_ipv6_zone_is_ignored_while_matching(self):
        cert = self._cert(san=(('IP Address', 'fe80::1'),))
        identity_type, _ = match_certificate_identity(cert, normalize_host('fe80::1%eth0'))
        self.assertEqual(identity_type, 'IP Address')

    def test_idna_name_matches_a_label_san(self):
        host = normalize_host(u'\u4f8b\u3048.example')
        cert = self._cert(san=(('DNS', host.match_value),))
        identity_type, identity_value = match_certificate_identity(cert, host)
        self.assertEqual(identity_type, 'DNS')

    def test_wildcard_san_strict_matching(self):
        cert = self._cert(san=(('DNS', '*.example.com'),))
        self.assertEqual(match_certificate_identity(cert, normalize_host('a.example.com'))[0], 'DNS')
        self.assertRaises(ValueError, match_certificate_identity, cert, normalize_host('a.b.example.com'))

    def test_empty_san_is_rejected_by_default(self):
        cert = self._cert(subject_cn='ldap3.example.com')
        self.assertRaises(ValueError, match_certificate_identity, cert, normalize_host('ldap3.example.com'))

    def test_common_name_fallback_requires_explicit_opt_in(self):
        cert = self._cert(subject_cn='ldap3.example.com')
        identity_type, _ = match_certificate_identity(
            cert, normalize_host('ldap3.example.com'), allow_common_name_fallback=True)
        self.assertEqual(identity_type, 'CN')

    def test_common_name_fallback_ignored_when_san_present(self):
        cert = self._cert(san=(('DNS', 'other.example.com'),), subject_cn='ldap3.example.com')
        self.assertRaises(ValueError, match_certificate_identity, cert,
                          normalize_host('ldap3.example.com'), allow_common_name_fallback=True)

    def test_explicit_empty_san_extension_blocks_common_name_fallback(self):
        cert = self._cert(san=(), subject_cn='ldap3.example.com')
        cert['subjectAltName'] = ()
        self.assertRaises(ValueError, match_certificate_identity, cert,
                          normalize_host('ldap3.example.com'), allow_common_name_fallback=True)

    def test_common_name_fallback_never_applies_to_ip_host(self):
        cert = self._cert(subject_cn='127.0.0.1')
        self.assertRaises(ValueError, match_certificate_identity, cert,
                          normalize_host('127.0.0.1'), allow_common_name_fallback=True)


class TestTlsConfiguration(unittest.TestCase):
    def test_legacy_default_constructor_keeps_cert_none(self):
        import ssl
        from ldap3.core.tls import Tls
        tls = Tls()
        self.assertEqual(tls.validate, ssl.CERT_NONE)
        self.assertFalse(tls.check_hostname_enabled)
        self.assertFalse(tls.allow_common_name_fallback)

    def test_secure_default_when_certificate_required(self):
        import ssl
        from ldap3.core.tls import Tls
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=None)
        self.assertTrue(tls.check_hostname_enabled)

    def test_check_hostname_requires_certificate_validation(self):
        import ssl
        from ldap3.core.tls import Tls
        self.assertRaises(LDAPSSLConfigurationError, Tls, validate=ssl.CERT_NONE, check_hostname=True)


if __name__ == '__main__':
    unittest.main()
