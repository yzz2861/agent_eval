"""
Tests for the referral following trust policy: same-origin trust,
explicit whitelists, scheme downgrade protection, loop/depth/time
limits and clean-state guarantees after referral failures.
"""

import unittest
from time import monotonic
from unittest import mock

from ldap3 import Server, Connection, MOCK_SYNC, ANONYMOUS, SIMPLE, SUBTREE
from ldap3.core.exceptions import LDAPReferralError
from ldap3.core.results import RESULT_REFERRAL
from ldap3.strategy.base import BaseStrategy
from ldap3.utils.referral import parse_referral_host_spec, referral_host_spec_matches, referral_origin, referral_target_key


def search_request():
    return {'type': 'searchRequest',
            'base': 'ou=apps,dc=example,dc=com',
            'filter': '(objectClass=*)',
            'scope': SUBTREE,
            'dereferenceAlias': 0,
            'attributes': ['cn'],
            'sizeLimit': 0,
            'timeLimit': 0,
            'typesOnly': False,
            'controls': None}


class ReferralInterceptor(object):
    """Patches Connection.open/bind/unbind/start_tls/search so that referral
    connections never touch a real socket while recording which host/port/scheme
    would have been contacted and which credentials would have been sent."""

    def __init__(self):
        self.opened = []   # (host, port, ssl) of every socket that would be opened
        self.binds = []    # (host, user, password, authentication) of every bind
        self.unbinds = []  # connections that were unbound/discarded
        self.tls_started = []
        self.connections = []  # referral Connection objects that were bound
        self._patchers = []

    def __enter__(self):
        interceptor = self

        def fake_open(strategy, reset_usage=True, read_server_info=True):
            connection = strategy.connection
            interceptor.opened.append((connection.server.host, connection.server.port, connection.server.ssl))
            connection.closed = False
            return True

        def fake_bind(connection, controls=None):
            interceptor.binds.append((connection.server.host, connection.user, connection.password, connection.authentication))
            interceptor.connections.append(connection)
            connection.bound = True
            connection.result = {'result': 0, 'description': 'success', 'dn': '', 'message': '', 'referrals': None, 'type': 'bindResponse'}
            return True

        def fake_unbind(connection, controls=None):
            interceptor.unbinds.append(connection.server.host)
            connection.bound = False
            return True

        def fake_start_tls(connection, read_server_info=True):
            interceptor.tls_started.append(connection.server.host)
            connection.tls_started = True
            return True

        def fake_search(connection, *args, **kwargs):
            connection.response = []
            connection.result = {'result': 0, 'description': 'success', 'dn': '', 'message': '', 'referrals': None, 'type': 'searchResDone'}
            return True

        def fake_refresh_server_info(connection):
            return None

        self._patchers = [
            mock.patch.object(BaseStrategy, 'open', fake_open),
            mock.patch.object(Connection, 'bind', fake_bind),
            mock.patch.object(Connection, 'unbind', fake_unbind),
            mock.patch.object(Connection, 'start_tls', fake_start_tls),
            mock.patch.object(Connection, 'search', fake_search),
            mock.patch.object(Connection, 'refresh_server_info', fake_refresh_server_info),
        ]
        for patcher in self._patchers:
            patcher.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for patcher in self._patchers:
            patcher.stop()


class TestReferralTrust(unittest.TestCase):
    def make_connection(self, allowed_referral_hosts=None, use_ssl=True, port=636, **kwargs):
        server = Server('dir.example.com', port=port, use_ssl=use_ssl, allowed_referral_hosts=allowed_referral_hosts)
        connection = Connection(server,
                                user='cn=admin,dc=example,dc=com',
                                password='secret',
                                client_strategy=MOCK_SYNC,
                                lazy=True,
                                **kwargs)
        connection.bound = True  # simulate an already bound origin connection
        connection.closed = False
        return connection

    def follow(self, connection, referrals, request=None):
        return connection.strategy.do_operation_on_referral(request or search_request(), referrals)

    # trust scope ---------------------------------------------------------

    def test_same_origin_referral_reuses_credentials(self):
        connection = self.make_connection()
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://dir.example.com:636/dc=example,dc=com'])
        self.assertEqual(result['result'], 0)
        self.assertEqual(intercepted.opened, [('dir.example.com', 636, True)])
        self.assertEqual(intercepted.binds, [('dir.example.com', 'cn=admin,dc=example,dc=com', 'secret', SIMPLE)])
        self.assertTrue(connection.bound)

    def test_same_origin_default_port_normalization(self):
        connection = self.make_connection()
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://dir.example.com/dc=example,dc=com'])
        self.assertEqual(result['result'], 0)
        self.assertEqual(intercepted.opened, [('dir.example.com', 636, True)])
        self.assertEqual(len(intercepted.binds), 1)

    def test_trailing_dot_and_case_normalize_to_same_origin(self):
        connection = self.make_connection()
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://DIR.example.COM.:636/dc=example,dc=com'])
        self.assertEqual(result['result'], 0)
        self.assertEqual(len(intercepted.binds), 1)

    def test_cross_host_referral_rejected_by_default(self):
        connection = self.make_connection()
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://evil.example.com/dc=example,dc=com'])
        self.assertIsNone(response)
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertIn('not followed', connection.last_error)
        self.assertEqual(intercepted.opened, [])  # no socket opened to the untrusted host
        self.assertEqual(intercepted.binds, [])   # credentials never leave the origin
        self.assertTrue(connection.bound)         # origin connection left untouched

    def test_cross_host_whitelisted_with_authentication(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', True)])
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://trusted.example.com/dc=example,dc=com'])
        self.assertEqual(result['result'], 0)
        self.assertEqual(intercepted.opened, [('trusted.example.com', 636, True)])
        self.assertEqual(intercepted.binds, [('trusted.example.com', 'cn=admin,dc=example,dc=com', 'secret', SIMPLE)])

    def test_cross_host_whitelisted_anonymous_only(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', False)])
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://trusted.example.com/dc=example,dc=com'])
        self.assertEqual(result['result'], 0)
        self.assertEqual(intercepted.binds, [('trusted.example.com', None, None, ANONYMOUS)])

    # scheme / port / dns distinctions ------------------------------------

    def test_scheme_downgrade_is_not_same_origin(self):
        connection = self.make_connection()  # origin is ldaps://dir.example.com:636
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldap://dir.example.com/dc=example,dc=com'])
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertEqual(intercepted.binds, [])

    def test_scheme_downgrade_never_forwards_credentials(self):
        connection = self.make_connection(allowed_referral_hosts=[('dir.example.com', True)])
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldap://dir.example.com:389/dc=example,dc=com'])
        self.assertEqual(result['result'], 0)
        # whitelisted, but the ldaps -> ldap downgrade forces an anonymous bind
        self.assertEqual(intercepted.binds, [('dir.example.com', None, None, ANONYMOUS)])

    def test_port_change_is_not_same_origin(self):
        connection = self.make_connection()
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://dir.example.com:1636/dc=example,dc=com'])
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertEqual(intercepted.binds, [])

    def test_whitelist_entry_with_exact_port(self):
        connection = self.make_connection(allowed_referral_hosts=[('dir.example.com:1636', True)])
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://dir.example.com:1636/dc=example,dc=com'])
        self.assertEqual(result['result'], 0)
        self.assertEqual(intercepted.opened, [('dir.example.com', 1636, True)])
        self.assertEqual(len(intercepted.binds), 1)

    def test_whitelist_entry_port_does_not_match_other_ports(self):
        connection = self.make_connection(allowed_referral_hosts=[('dir.example.com:636', True)])
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://dir.example.com:1636/dc=example,dc=com'])
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertEqual(intercepted.binds, [])

    def test_ip_literal_not_equivalent_to_dns_name(self):
        # even if dir.example.com resolved to 192.0.2.1 the policy must not
        # consider the IP literal the same target as the DNS name
        connection = self.make_connection()
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://192.0.2.1:636/dc=example,dc=com'])
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertEqual(intercepted.binds, [])

    # loops, duplicates, malformed urls ------------------------------------

    def test_referral_loop_is_detected(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', True)])
        strategy = connection.strategy
        # simulate a chain that already visited the origin and the target
        strategy._referral_chain_start = monotonic()
        strategy._referral_depth = 1
        strategy._referrals = [referral_target_key(referral_origin(True, 'dir.example.com', 636), 'ou=apps,dc=example,dc=com'),
                               referral_target_key(referral_origin(True, 'trusted.example.com', 636), 'dc=example,dc=com')]
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://trusted.example.com/dc=example,dc=com'])
        self.assertIsNone(response)
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertIn('loop', connection.last_error)
        self.assertEqual(intercepted.binds, [])

    def test_repeated_target_in_same_list_followed_once(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', True)])
        referrals = ['ldaps://trusted.example.com/dc=a', 'ldaps://trusted.example.com:636/dc=a']
        valid = connection.strategy.valid_referral_list(referrals)
        self.assertEqual(len(valid), 1)

    def test_same_server_different_base_is_not_a_loop(self):
        connection = self.make_connection()
        referrals = ['ldaps://dir.example.com/dc=a', 'ldaps://dir.example.com/dc=b']
        valid = connection.strategy.valid_referral_list(referrals)
        self.assertEqual(len(valid), 2)

    def test_empty_and_malformed_urls_rejected(self):
        connection = self.make_connection(allowed_referral_hosts=[('*', True)])
        referrals = ['', 'not-a-url', 'ldap://', 'http://dir.example.com/dc=a',
                     'ldap://dir.example.com:99999/dc=a', 'ldaps://dir.example.com:0/dc=a', None]
        valid = connection.strategy.valid_referral_list(referrals)
        self.assertEqual(valid, [])
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, referrals)
        self.assertIsNone(response)
        self.assertIsNone(result)  # nothing valid to follow, original referral result is kept
        self.assertEqual(intercepted.opened, [])

    # depth and time limits -------------------------------------------------

    def test_max_referral_depth_enforced(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', True)],
                                          max_referral_depth=3)
        strategy = connection.strategy
        strategy._referral_chain_start = monotonic()
        strategy._referral_depth = 3
        strategy._referrals = []
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://trusted.example.com/dc=a'])
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertIn('depth', connection.last_error)
        self.assertEqual(intercepted.binds, [])

    def test_max_referral_time_enforced(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', True)],
                                          max_referral_time=30)
        strategy = connection.strategy
        strategy._referral_chain_start = monotonic() - 100  # chain started long ago
        strategy._referral_depth = 1
        strategy._referrals = []
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://trusted.example.com/dc=a'])
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertIn('time', connection.last_error)
        self.assertEqual(intercepted.binds, [])

    def test_chain_state_reset_after_operation(self):
        connection = self.make_connection()
        strategy = connection.strategy
        strategy._referral_chain_start = monotonic()
        strategy._referral_depth = 4
        strategy._referrals = [referral_origin(True, 'other.example.com', 636)]
        strategy.close()
        self.assertEqual(strategy._referral_depth, 0)
        self.assertIsNone(strategy._referral_chain_start)
        self.assertEqual(strategy._referrals, [])

    # clean state after failures ---------------------------------------------

    def test_failed_referral_bind_leaves_clean_state(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', True)])
        with ReferralInterceptor() as intercepted:
            with mock.patch.object(Connection, 'bind', side_effect=LDAPReferralError('bind failed')):
                response, result = self.follow(connection, ['ldaps://trusted.example.com/dc=a'])
        self.assertIsNone(response)
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertEqual(intercepted.unbinds, ['trusted.example.com'])  # failed session discarded
        self.assertEqual(connection.strategy.referral_cache, {})
        self.assertTrue(connection.bound)  # origin connection still bound and usable
        self.assertFalse(connection.closed)

    def test_failed_referral_operation_evicts_cached_connection(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', True)],
                                          use_referral_cache=True)
        cachekey = (True, 'trusted.example.com', 636, False)
        stale = mock.MagicMock()
        connection.strategy.referral_cache[cachekey] = stale
        stale.search.side_effect = Exception('connection broken')
        response, result = self.follow(connection, ['ldaps://trusted.example.com/dc=a'])
        self.assertEqual(result['result'], RESULT_REFERRAL)
        self.assertNotIn(cachekey, connection.strategy.referral_cache)
        stale.unbind.assert_called_once()
        self.assertTrue(connection.bound)

    def test_raise_exceptions_propagates_referral_error(self):
        connection = self.make_connection(raise_exceptions=True)
        with ReferralInterceptor():
            with self.assertRaises(LDAPReferralError):
                self.follow(connection, ['ldaps://evil.example.com/dc=a'])
        self.assertTrue(connection.bound)

    # multiple credentials / targets ------------------------------------------

    def test_multiple_targets_get_distinct_credential_scopes(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', True),
                                                                  ('anon.example.com', False)])
        with ReferralInterceptor() as intercepted:
            self.follow(connection, ['ldaps://trusted.example.com/dc=a'])
            connection.strategy._referrals = []  # a new operation starts a new chain
            connection.strategy._referral_chain_start = None
            connection.strategy._referral_depth = 0
            self.follow(connection, ['ldaps://anon.example.com/dc=a'])
        self.assertEqual(intercepted.opened, [('trusted.example.com', 636, True),
                                              ('anon.example.com', 636, True)])
        self.assertEqual(intercepted.binds, [('trusted.example.com', 'cn=admin,dc=example,dc=com', 'secret', SIMPLE),
                                             ('anon.example.com', None, None, ANONYMOUS)])

    # host spec parsing --------------------------------------------------------

    def test_chain_state_propagates_to_referral_connection(self):
        connection = self.make_connection(allowed_referral_hosts=[('trusted.example.com', True)])
        with ReferralInterceptor() as intercepted:
            response, result = self.follow(connection, ['ldaps://trusted.example.com/dc=example,dc=com'])
        self.assertEqual(result['result'], 0)
        referral_connection = intercepted.connections[0]
        # the next hop inherits the visited targets, an increased depth and the chain clock
        self.assertEqual(referral_connection.strategy._referral_depth, 1)
        self.assertIsNotNone(referral_connection.strategy._referral_chain_start)
        visited = referral_connection.strategy._referrals
        self.assertIn(referral_target_key(referral_origin(True, 'dir.example.com', 636), 'ou=apps,dc=example,dc=com'), visited)
        self.assertIn(referral_target_key(referral_origin(True, 'trusted.example.com', 636), 'dc=example,dc=com'), visited)
        # the referral connection keeps the same trust policy and chain limits
        self.assertEqual(referral_connection.server.allowed_referral_hosts, [('trusted.example.com', True)])
        self.assertEqual(referral_connection.max_referral_depth, connection.max_referral_depth)
        self.assertEqual(referral_connection.max_referral_time, connection.max_referral_time)

    def test_host_spec_forms(self):
        origin = referral_origin(True, 'dir.example.com', 636)
        self.assertTrue(referral_host_spec_matches('*', origin))
        self.assertTrue(referral_host_spec_matches('dir.example.com', origin))
        self.assertTrue(referral_host_spec_matches('dir.example.com:636', origin))
        self.assertTrue(referral_host_spec_matches('ldaps://dir.example.com:636', origin))
        self.assertFalse(referral_host_spec_matches('ldap://dir.example.com:636', origin))
        self.assertFalse(referral_host_spec_matches('dir.example.com:389', origin))
        self.assertFalse(referral_host_spec_matches('other.example.com', origin))
        self.assertFalse(referral_host_spec_matches('ldaps://dir.example.com', referral_origin(False, 'dir.example.com', 389)))

    def test_malformed_host_spec_never_matches(self):
        origin = referral_origin(True, 'dir.example.com', 636)
        self.assertFalse(referral_host_spec_matches('http://dir.example.com', origin))
        self.assertFalse(referral_host_spec_matches('dir.example.com:notaport', origin))
        self.assertFalse(referral_host_spec_matches('://', origin))

    # defaults ------------------------------------------------------------------

    def test_default_policy_values(self):
        connection = self.make_connection()
        self.assertEqual(connection.server.allowed_referral_hosts, [])
        self.assertEqual(connection.max_referral_depth, 5)
        self.assertEqual(connection.max_referral_time, 60.0)


if __name__ == '__main__':
    unittest.main()
