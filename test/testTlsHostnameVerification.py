"""
Integration tests for the StartTLS / LDAPS server identity verification path.

All certificates are generated locally in a temporary directory by
``test/local_tls.py``; no external server is required.
"""

import shutil
import ssl
import unittest

from ldap3.core.exceptions import (
    LDAPCertificateChainError,
    LDAPCertificateExpiredError,
    LDAPCertificateHostnameError,
    LDAPSSLConfigurationError,
    LDAPVerifiedHostChangedError,
)
from ldap3.core.tls import Tls
from ldap3 import Server, Connection
from test.local_tls import CertificateAuthority, InMemoryTlsServer, create_tls_workspace


class FakeServer(object):
    def __init__(self, host):
        self.host = host


class FakeConnection(object):
    """Enough of the Connection surface for Tls.wrap_socket()."""

    def __init__(self, client_socket, host):
        self.socket = client_socket
        self.server = FakeServer(host)
        self.verified_tls_host = None
        self.verified_tls_server = None


class TlsVerificationTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = create_tls_workspace()
        self.ca = CertificateAuthority(self.directory)

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def _wrap(self, tls, host, server):
        client_socket = server.connect()
        connection = FakeConnection(client_socket, host)
        tls.wrap_socket(connection, do_handshake=True)
        server.wait()
        return connection

    def _strict_tls(self, **overrides):
        arguments = dict(validate=ssl.CERT_REQUIRED, ca_certs_file=self.ca.cert_file)
        arguments.update(overrides)
        return Tls(**arguments)

    def test_dns_san_matches_and_handshake_uses_normalized_sni(self):
        key, cert = self.ca.issue_cert('dns', dns_names=['ldap3.example.com'])
        server = InMemoryTlsServer(cert, key)
        tls = self._strict_tls()
        connection = self._wrap(tls, 'ldap3.example.com', server)

        self.assertTrue(server.handshake_completed)
        self.assertEqual(server.sni_name, 'ldap3.example.com')
        self.assertEqual(connection.verified_tls_host, 'ldap3.example.com')
        self.assertEqual(tls.peer_identity[0], 'DNS')

    def test_idna_unicode_host_matches_a_label_san(self):
        unicode_host = u'\u4f8b\u3048.example'
        key, cert = self.ca.issue_cert('idna', dns_names=['xn--r8jz45g.example'])
        server = InMemoryTlsServer(cert, key)
        tls = self._strict_tls()
        connection = self._wrap(tls, unicode_host, server)

        self.assertTrue(server.handshake_completed)
        self.assertEqual(server.sni_name, 'xn--r8jz45g.example')
        self.assertEqual(connection.verified_tls_host, 'xn--r8jz45g.example')

    def test_ipv4_host_matches_ip_san_without_dns_sni(self):
        key, cert = self.ca.issue_cert('ipv4', dns_names=['ldap3.example.com'], ip_names=['127.0.0.1'])
        server = InMemoryTlsServer(cert, key)
        tls = self._strict_tls()
        connection = self._wrap(tls, '127.0.0.1', server)

        self.assertTrue(server.handshake_completed)
        self.assertIsNone(server.sni_name)
        self.assertEqual(connection.verified_tls_host, '127.0.0.1')
        self.assertEqual(tls.peer_identity[0], 'IP Address')

    def test_ipv6_zone_identifier_matches_ip_san_and_is_not_in_sni(self):
        key, cert = self.ca.issue_cert('ipv6', ip_names=['fe80::1'])
        server = InMemoryTlsServer(cert, key)
        tls = self._strict_tls()
        connection = self._wrap(tls, 'fe80::1%eth0', server)

        self.assertTrue(server.handshake_completed)
        self.assertIsNone(server.sni_name)
        self.assertEqual(connection.verified_tls_host, 'fe80::1')

    def test_ip_host_never_matches_dns_san(self):
        key, cert = self.ca.issue_cert('dns-only', dns_names=['127.0.0.1'])
        server = InMemoryTlsServer(cert, key)
        with self.assertRaises(LDAPCertificateHostnameError):
            self._wrap(self._strict_tls(), '127.0.0.1', server)
        server.wait()
        self.assertTrue(server.handshake_completed)  # TLS handshake happened, identity check failed

    def test_hostname_mismatch_is_reported_separately_from_chain_errors(self):
        key, cert = self.ca.issue_cert('mismatch', dns_names=['expected.example.com'])
        server = InMemoryTlsServer(cert, key)
        with self.assertRaises(LDAPCertificateHostnameError):
            self._wrap(self._strict_tls(), 'unexpected.example.com', server)
        server.wait()
        self.assertTrue(server.handshake_completed)

    def test_untrusted_chain_is_reported_as_chain_error(self):
        foreign_key, foreign_cert = self.ca.issue_cert('foreign', self_signed=True, dns_names=['ldap3.example.com'])
        server = InMemoryTlsServer(foreign_cert, foreign_key)
        with self.assertRaises(LDAPCertificateChainError):
            self._wrap(self._strict_tls(), 'ldap3.example.com', server)
        server.wait()
        self.assertFalse(server.handshake_completed)

    def test_expired_certificate_is_reported_as_expiration_error(self):
        expired_key, expired_cert = self.ca.issue_cert(
            'expired', dns_names=['ldap3.example.com'], expired=True)
        server = InMemoryTlsServer(expired_cert, expired_key)
        with self.assertRaises(LDAPCertificateExpiredError):
            self._wrap(self._strict_tls(), 'ldap3.example.com', server)
        server.wait()
        self.assertFalse(server.handshake_completed)

    def test_wildcard_cert_does_not_match_multiple_labels(self):
        key, cert = self.ca.issue_cert('wildcard', dns_names=['example.com'], wildcard=True)
        server = InMemoryTlsServer(cert, key)
        tls = self._strict_tls()

        connection = self._wrap(tls, 'a.example.com', server)
        self.assertTrue(server.handshake_completed)
        self.assertEqual(tls.peer_identity[1], '*.example.com')

        server_two = InMemoryTlsServer(cert, key)
        with self.assertRaises(LDAPCertificateHostnameError):
            self._wrap(tls, 'a.b.example.com', server_two)
        server_two.wait()

    def test_empty_san_rejected_in_strict_mode_even_with_matching_cn(self):
        key, cert = self.ca.issue_cert('cn-only', dns_names=(), common_name='ldap3.example.com')
        server = InMemoryTlsServer(cert, key)
        with self.assertRaises(LDAPCertificateHostnameError):
            self._wrap(self._strict_tls(), 'ldap3.example.com', server)
        server.wait()

    def test_common_name_fallback_only_works_when_explicitly_enabled(self):
        key, cert = self.ca.issue_cert('cn-fallback', dns_names=(), common_name='ldap3.example.com')
        server = InMemoryTlsServer(cert, key)
        tls = self._strict_tls(allow_common_name_fallback=True)
        connection = self._wrap(tls, 'ldap3.example.com', server)

        self.assertTrue(server.handshake_completed)
        self.assertEqual(connection.verified_tls_host, 'ldap3.example.com')
        self.assertEqual(tls.peer_identity[0], 'CN')

    def test_server_name_pins_verified_identity_behind_proxy(self):
        key, cert = self.ca.issue_cert('proxy', dns_names=['real.example.com'], ip_names=['127.0.0.1'])
        server = InMemoryTlsServer(cert, key)
        tls = self._strict_tls(server_name='real.example.com')
        # connection target is an IP address, verification target is the DNS name
        connection = self._wrap(tls, '127.0.0.1', server)

        self.assertTrue(server.handshake_completed)
        self.assertEqual(server.sni_name, 'real.example.com')
        self.assertEqual(connection.verified_tls_host, 'real.example.com')

    def test_legacy_sni_parameter_still_drives_verification(self):
        key, cert = self.ca.issue_cert('legacy-sni', dns_names=['legacy.example.com'])
        server = InMemoryTlsServer(cert, key)
        tls = self._strict_tls(sni='legacy.example.com')
        connection = self._wrap(tls, '127.0.0.1', server)
        self.assertEqual(connection.verified_tls_host, 'legacy.example.com')
        self.assertEqual(server.sni_name, 'legacy.example.com')

    def test_cert_none_keeps_legacy_non_verifying_behavior(self):
        foreign_key, foreign_cert = self.ca.issue_cert('untrusted', self_signed=True, dns_names=['whatever.example.com'])
        server = InMemoryTlsServer(foreign_cert, foreign_key)
        tls = Tls(validate=ssl.CERT_NONE)
        connection = self._wrap(tls, 'whatever.example.com', server)

        self.assertTrue(server.handshake_completed)
        self.assertIsNone(connection.verified_tls_host)

    def test_handshake_observation_distinguishes_completed_and_rejected_tls(self):
        good_key, good_cert = self.ca.issue_cert('good', dns_names=['good.example.com'])
        good_server = InMemoryTlsServer(good_cert, good_key)
        self._wrap(self._strict_tls(), 'good.example.com', good_server)
        self.assertTrue(good_server.handshake_completed)
        self.assertIsNone(good_server.handshake_error)

        bad_key, bad_cert = self.ca.issue_cert('bad', self_signed=True, dns_names=['good.example.com'])
        bad_server = InMemoryTlsServer(bad_cert, bad_key)
        with self.assertRaises(LDAPCertificateChainError):
            self._wrap(self._strict_tls(), 'good.example.com', bad_server)
        bad_server.wait()
        self.assertFalse(bad_server.handshake_completed)
        self.assertIsNotNone(bad_server.handshake_error)

    def test_valid_names_still_accepted_as_additional_identities(self):
        key, cert = self.ca.issue_cert('additional', dns_names=['alternate.example.com'])
        server = InMemoryTlsServer(cert, key)
        tls = self._strict_tls(valid_names=['alternate.example.com'])
        connection = self._wrap(tls, 'primary.example.com', server)
        self.assertEqual(tls.peer_identity[2], 'alternate.example.com')
        self.assertTrue(server.handshake_completed)


class VerifiedIdentityGuardTestCase(unittest.TestCase):
    def test_connection_cannot_be_redirected_after_verification(self):
        from ldap3.strategy.base import BaseStrategy

        class DummyPool(object):
            def get_server(self, connection):
                return Server('other.example.com', port=389)

        class DummyConnection(object):
            def __init__(self):
                self.server = Server('verified.example.com', port=389)
                self.server_pool = DummyPool()
                self.verified_tls_server = self.server
                self.verified_tls_host = 'verified.example.com'
                self.usage = None
                self.last_error = None
                self.lazy = False
                self._executing_deferred = False
                self.closed = True
                self._outstanding = None
                self.no_real_dsa = True

        strategy = BaseStrategy.__new__(BaseStrategy)
        strategy.connection = DummyConnection()
        with self.assertRaises(LDAPVerifiedHostChangedError):
            strategy.open()

    def test_same_host_different_server_object_is_allowed(self):
        from ldap3.strategy.base import BaseStrategy

        class DummyPool(object):
            def get_server(self, connection):
                return Server('verified.example.com', port=389)

        class DummyConnection(object):
            def __init__(self):
                self.server = Server('verified.example.com', port=389)
                self.server_pool = DummyPool()
                self.verified_tls_server = Server('verified.example.com', port=389)
                self.verified_tls_host = 'verified.example.com'
                self.usage = None
                self.last_error = None

        strategy = BaseStrategy.__new__(BaseStrategy)
        strategy.connection = DummyConnection()
        # no exception: the normalized host still matches the verified one
        strategy._guard_verified_identity(Server('VERIFIED.example.com', port=389))

        strategy = BaseStrategy.__new__(BaseStrategy)
        strategy.connection = DummyConnection()
        # no exception: the normalized host still matches the verified one
        strategy._guard_verified_identity(Server('VERIFIED.example.com', port=389))


class ServerConstructionCompatibilityTestCase(unittest.TestCase):
    def test_legacy_tls_constructor_arguments_remain_accepted(self):
        tls = Tls(
            validate=ssl.CERT_REQUIRED,
            version=ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, 'PROTOCOL_TLS_CLIENT') else None,
            ssl_options=[ssl.OP_NO_SSLv2] if hasattr(ssl, 'OP_NO_SSLv2') else [],
            ciphers='HIGH:!aNULL',
            valid_names=['one.example.com'],
        )
        self.assertTrue(tls.check_hostname_enabled)
        self.assertIn('one.example.com', tls.valid_names)
        self.assertIsInstance(Server('localhost', tls=tls), Server)

    def test_invalid_check_hostname_configuration(self):
        with self.assertRaises(LDAPSSLConfigurationError):
            Tls(validate=ssl.CERT_NONE, check_hostname=True)

    def test_bundled_self_signed_ca_pem_remains_loadable(self):
        import os
        bundled_ca = os.path.join(os.path.dirname(__file__), 'local-openldap-ca-cert.pem')
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=bundled_ca)
        self.assertTrue(tls.check_hostname_enabled)
        self.assertEqual(tls.ca_certs_file, bundled_ca)


if __name__ == '__main__':
    unittest.main()
