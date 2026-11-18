import http.server
import os
import threading
import unittest
from unittest import mock

from unfurl import safe_http
from unfurl.tests.http_mocks import PUBLIC_ADDRESS, FakeResponse


class TestIsPublicAddress(unittest.TestCase):

    def test_public_addresses(self):
        for address in ('93.184.216.34', '8.8.8.8', '2606:4700:4700::1111'):
            with self.subTest(address=address):
                self.assertTrue(safe_http.is_public_address(address))

    def test_non_public_addresses(self):
        cases = {
            '127.0.0.1': 'loopback',
            '10.0.0.5': 'private',
            '172.16.0.1': 'private',
            '192.168.1.1': 'private',
            '169.254.169.254': 'link-local (cloud metadata)',
            '100.64.0.1': 'carrier-grade NAT',
            '0.0.0.0': 'unspecified',
            '::1': 'IPv6 loopback',
            'fe80::1': 'IPv6 link-local',
            'fd00::1': 'IPv6 unique local',
            '::ffff:10.0.0.1': 'private IPv4 written as IPv6',
            '::ffff:127.0.0.1': 'loopback IPv4 written as IPv6',
        }
        for address, kind in cases.items():
            with self.subTest(address=address, kind=kind):
                self.assertFalse(safe_http.is_public_address(address))

    def test_something_that_is_not_an_address(self):
        self.assertFalse(safe_http.is_public_address('example.com'))
        self.assertFalse(safe_http.is_public_address(''))


class TestLooksLikeIpAddress(unittest.TestCase):

    def test_forms_a_resolver_reads_as_an_address(self):
        # All of these but the last two are 127.0.0.1 or 10.0.0.1 to a resolver.
        for hostname in ('127.0.0.1', '127.1', '10.1', '0x7f.1', '0x7f000001', '2130706433',
                         '017700000001', '0', '1.2.3.4', '1.2.3.4.', '::1', 'fe80::1'):
            with self.subTest(hostname=hostname):
                self.assertTrue(safe_http.looks_like_ip_address(hostname))

    def test_names(self):
        for hostname in ('t.co', 'a.io', 'vault', '1drv.ms', '3.ly', 'x0.at', 'example.com', ''):
            with self.subTest(hostname=hostname):
                self.assertFalse(safe_http.looks_like_ip_address(hostname))


class TestCheckDestination(unittest.TestCase):

    def check(self, url, addresses):
        with mock.patch.object(safe_http, 'resolve_host', return_value=addresses):
            safe_http.check_destination(url)

    def test_public_host_is_allowed(self):
        self.check('https://t.co/abc', [PUBLIC_ADDRESS])

    def test_private_host_is_refused(self):
        with self.assertRaises(safe_http.RefusedDestination) as refused:
            self.check('https://intranet.example/abc', ['10.0.0.5'])
        self.assertIn('not on the public internet', refused.exception.reason)

    def test_one_private_address_among_public_ones_is_enough_to_refuse(self):
        """There is no saying which address the connection would pick."""

        with self.assertRaises(safe_http.RefusedDestination):
            self.check('https://mixed.example/abc', [PUBLIC_ADDRESS, '127.0.0.1'])

    def test_host_that_does_not_resolve_is_refused(self):
        with mock.patch.object(safe_http, 'resolve_host', side_effect=OSError('no such host')):
            with self.assertRaises(safe_http.RefusedDestination) as refused:
                safe_http.check_destination('https://nx.example/abc')
        self.assertIn('does not resolve', refused.exception.reason)

    def test_host_that_resolves_to_nothing_is_refused(self):
        with self.assertRaises(safe_http.RefusedDestination):
            self.check('https://empty.example/abc', [])

    def test_only_http_and_https_are_requested(self):
        for url in ('ftp://example.com/x', 'file:///etc/passwd', 'gopher://example.com/', 'example.com/x'):
            with self.subTest(url=url):
                with self.assertRaises(safe_http.RefusedDestination):
                    self.check(url, [PUBLIC_ADDRESS])

    def test_url_without_a_host_is_refused(self):
        with self.assertRaises(safe_http.RefusedDestination):
            self.check('https:///abc', [PUBLIC_ADDRESS])

    def test_the_port_in_the_url_is_the_one_resolved(self):
        with mock.patch.object(safe_http, 'resolve_host', return_value=[PUBLIC_ADDRESS]) as resolve:
            safe_http.check_destination('https://t.co:8443/abc')
            safe_http.check_destination('http://ow.ly/abc')
        self.assertEqual([mock.call('t.co', 8443), mock.call('ow.ly', 80)], resolve.call_args_list)


class TestGet(unittest.TestCase):

    def test_nothing_is_sent_when_the_destination_is_refused(self):
        with mock.patch.object(safe_http, 'resolve_host', return_value=['192.168.1.1']), \
                mock.patch.object(safe_http, '_send') as send:
            with self.assertRaises(safe_http.RefusedDestination):
                safe_http.get('https://router.example/admin', timeout=3)
        send.assert_not_called()

    def test_redirects_are_never_followed(self):
        """A redirect would lead to a second destination that nothing has checked."""

        with mock.patch.object(safe_http, 'resolve_host', return_value=[PUBLIC_ADDRESS]), \
                mock.patch.object(safe_http, '_send', return_value=FakeResponse()) as send:
            safe_http.get('https://t.co/abc', timeout=3, allow_redirects=True)
        send.assert_called_once_with('https://t.co/abc', timeout=3, allow_redirects=False)


class _CountingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests_seen += 1
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *args):
        pass


class TestConnectedAddressIsChecked(unittest.TestCase):
    """The check on the socket itself, against a real server on loopback.

    This is the case the lookup-time check cannot catch: DNS says the host is public,
    and the connection goes somewhere private anyway (a DNS server that gives a
    different answer the second time it is asked). It is reproduced here by telling the
    lookup-time check that 127.0.0.1 is public, and then really connecting to it.
    """

    def setUp(self):
        self.server = http.server.HTTPServer(('127.0.0.1', 0), _CountingHandler)
        self.server.requests_seen = 0
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        # Keep a proxy configured on the machine running the tests out of the way; the
        # point is to connect straight to the loopback server.
        no_proxy = mock.patch.dict(os.environ, {'NO_PROXY': '127.0.0.1', 'no_proxy': '127.0.0.1'})
        no_proxy.start()
        self.addCleanup(no_proxy.stop)

        dns_says_public = mock.patch.object(safe_http, 'resolve_host', return_value=[PUBLIC_ADDRESS])
        dns_says_public.start()
        self.addCleanup(dns_says_public.stop)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_connection_to_a_private_address_is_dropped_before_anything_is_sent(self):
        for scheme in ('http', 'https'):
            with self.subTest(scheme=scheme):
                with self.assertRaises(safe_http.RefusedDestination) as refused:
                    safe_http.get(f'{scheme}://127.0.0.1:{self.port}/secret', timeout=3)
                self.assertIn('connection went to an address', refused.exception.reason)

        self.assertEqual(0, self.server.requests_seen,
                         msg='the server must not have received a request')

    def test_the_same_request_goes_through_when_the_address_is_acceptable(self):
        """Control for the test above: the refusal comes from the address check.

        Without this, a transport that was simply broken would pass that test too.
        """

        with mock.patch.object(safe_http, 'is_public_address', return_value=True):
            response = safe_http.get(f'http://127.0.0.1:{self.port}/ok', timeout=3)

        self.assertEqual(200, response.status_code)
        self.assertEqual(1, self.server.requests_seen)


class TestFollowRedirects(unittest.TestCase):
    """The checked redirect follower; the network it runs on is entirely fake."""

    def test_each_hop_is_checked_before_it_is_sent_and_redirects_are_followed(self):
        routes = [
            FakeResponse(status_code=302, headers={'location': 'https://hop.example/two'},
                         url='https://start.example/one'),
            FakeResponse(status_code=200, url='https://hop.example/two'),
        ]
        sent = []

        def fake_send(url, **kwargs):
            sent.append(url)
            self.assertFalse(kwargs['allow_redirects'])
            return routes[len(sent) - 1]

        checked = []
        with mock.patch.object(safe_http, '_send', side_effect=fake_send), \
                mock.patch.object(safe_http, 'check_destination',
                                  side_effect=lambda url: checked.append(url)):
            response = safe_http.follow_redirects('https://start.example/one', timeout=3)

        self.assertEqual(200, response.status_code)
        self.assertEqual(['https://start.example/one', 'https://hop.example/two'], sent)
        self.assertEqual(sent, checked)

    def test_relative_location_is_resolved_before_the_next_hop_is_checked(self):
        routes = [
            FakeResponse(status_code=302, headers={'location': 'next?x=1'},
                         url='https://start.example/one'),
            FakeResponse(status_code=200, url='https://start.example/next?x=1'),
        ]
        sent = []

        def fake_send(url, **kwargs):
            sent.append(url)
            return routes[len(sent) - 1]

        with mock.patch.object(safe_http, '_send', side_effect=fake_send), \
                mock.patch.object(safe_http, 'resolve_host', return_value=[PUBLIC_ADDRESS]):
            safe_http.follow_redirects('https://start.example/one')

        self.assertEqual(['https://start.example/one',
                          'https://start.example/next?x=1'], sent)

    def test_a_redirect_to_a_private_address_is_refused_without_a_request_to_it(self):
        def fake_resolve(hostname, port):
            if hostname == 'intranet.example':
                return ['10.0.0.5']
            return [PUBLIC_ADDRESS]

        sent = []

        def fake_send(url, **kwargs):
            sent.append(url)
            if 'start.example' in url:
                return FakeResponse(
                    status_code=302,
                    headers={'location': 'https://intranet.example/admin'})
            return FakeResponse(status_code=404)

        with mock.patch.object(safe_http, '_send', side_effect=fake_send), \
                mock.patch.object(safe_http, 'resolve_host', side_effect=fake_resolve):
            with self.assertRaises(safe_http.RefusedDestination) as refused:
                safe_http.follow_redirects('https://start.example/go')

        self.assertIn('not on the public internet', refused.exception.reason)
        self.assertEqual(['https://start.example/go'], sent)

    def test_a_redirect_to_a_non_http_scheme_is_refused(self):
        response = FakeResponse(status_code=302,
                                headers={'location': 'file:///etc/passwd'})

        with mock.patch.object(safe_http, '_send', return_value=response), \
                mock.patch.object(safe_http, 'resolve_host', return_value=[PUBLIC_ADDRESS]):
            with self.assertRaises(safe_http.RefusedDestination) as refused:
                safe_http.follow_redirects('https://start.example/go')

        self.assertIn('not a scheme', refused.exception.reason)

    def test_the_redirect_chain_is_capped_at_the_hop_limit(self):
        sent = []

        def fake_send(url, **kwargs):
            sent.append(url)
            number = len(sent)
            return FakeResponse(status_code=302,
                                headers={'location': f"https://loop.example/{number + 1}"},
                                url=url)

        with mock.patch.object(safe_http, '_send', side_effect=fake_send), \
                mock.patch.object(safe_http, 'resolve_host', return_value=[PUBLIC_ADDRESS]):
            with self.assertRaises(safe_http.RedirectChainError) as exceeded:
                safe_http.follow_redirects('https://loop.example/1', max_redirects=3)

        self.assertIn('limit of 3 hops', exceeded.exception.reason)
        self.assertEqual(4, len(sent))
        self.assertEqual('https://loop.example/4', sent[-1])

    def test_the_redirect_chain_is_capped_by_total_time(self):
        response = FakeResponse(status_code=302,
                                headers={'location': 'https://slow.example/two'})
        monotonic_values = iter([0.0, 0.0, 20.0])

        with mock.patch.object(safe_http, '_send', return_value=response), \
                mock.patch.object(safe_http, 'resolve_host', return_value=[PUBLIC_ADDRESS]), \
                mock.patch.object(safe_http.time, 'monotonic',
                                  side_effect=monotonic_values):
            with self.assertRaises(safe_http.RedirectChainError) as exceeded:
                safe_http.follow_redirects('https://slow.example/one', max_total_time=10)

        self.assertIn('10 second total time limit', exceeded.exception.reason)

    def test_clip_timeout_caps_each_value_at_the_remaining_budget(self):
        self.assertEqual(2.0, safe_http._clip_timeout(3, 2.0))
        self.assertEqual(1.0, safe_http._clip_timeout(1, 2.0))
        self.assertEqual(2.0, safe_http._clip_timeout(None, 2.0))
        self.assertEqual((2.0, 1.5), safe_http._clip_timeout((5, 1.5), 2.0))


class TestRedirectChainConnectedAddressIsChecked(unittest.TestCase):
    """DNS rebinding on a redirect hop, exercised through the real guarded connection.

    The lookup-time check sees a public address, but the socket the guarded connection
    opens reports a private peer. A real loopback server cannot be bound in every
    environment the tests run in, so the base connection _new_conn is replaced with a
    fake socket whose peer address is private. The guard under test is the production
    code in _GuardedHTTP(Connection), not a mock.
    """

    def test_a_hop_that_connects_to_a_private_address_is_dropped(self):
        for scheme in ('http', 'https'):
            with self.subTest(scheme=scheme):
                first_url = f"{scheme}://start.example/one"
                redirect_url = f"{scheme}://rebind.example/two"
                response = FakeResponse(status_code=302,
                                        headers={'location': redirect_url}, url=first_url)

                real_send = safe_http._send

                def fake_send(url, **kwargs):
                    if url == first_url:
                        return response
                    return real_send(url, **kwargs)

                fake_socket = mock.Mock()
                fake_socket.getpeername.return_value = ('127.0.0.1', 443)
                no_proxy = mock.patch.dict(
                    os.environ,
                    {'NO_PROXY': 'start.example,rebind.example',
                     'no_proxy': 'start.example,rebind.example'})

                with no_proxy, \
                        mock.patch.object(safe_http, 'resolve_host',
                                          return_value=[PUBLIC_ADDRESS]), \
                        mock.patch.object(safe_http, '_send', side_effect=fake_send), \
                        mock.patch.object(safe_http.HTTPConnection, '_new_conn',
                                          return_value=fake_socket) as new_conn:
                    with self.assertRaises(safe_http.RefusedDestination) as refused:
                        safe_http.follow_redirects(first_url)

                self.assertIn('connection went to an address',
                              refused.exception.reason)
                new_conn.assert_called_once()
                fake_socket.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
