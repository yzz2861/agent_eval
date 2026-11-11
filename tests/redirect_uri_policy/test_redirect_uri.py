import json
import urllib.parse

from oauthlib.common import Request
from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.redirect_uri import (
    DuplicateRedirectURIError,
    RedirectURIError,
    RedirectURIRegistry,
    WildcardRedirectURIError,
    canonicalize_redirect_uri,
)
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from tests.unittest import TestCase


class RecordingValidator(RequestValidator):

    def __init__(self):
        self.codes = {}
        self.saved_redirects = []
        self.confirm_calls = []
        self.validate_redirect_uri_called = False

    def validate_client_id(self, client_id, request, *args, **kwargs):
        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        self.validate_redirect_uri_called = True
        return True

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        return True

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return True

    def is_pkce_required(self, client_id, request, *args, **kwargs):
        return False

    def get_code_challenge(self, code, request, *args, **kwargs):
        return None

    def save_authorization_code(self, client_id, grant, request, *args, **kwargs):
        self.codes[grant['code']] = request.redirect_uri
        self.saved_redirects.append(request.redirect_uri)

    def client_authentication_required(self, request, *args, **kwargs):
        return True

    def authenticate_client(self, request, *args, **kwargs):
        request.client = type('Client', (), {'client_id': request.client_id})()
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        return True

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        return code in self.codes

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             request, *args, **kwargs):
        self.confirm_calls.append(redirect_uri)
        return self.codes.get(code) == redirect_uri

    def save_token(self, token, request, *args, **kwargs):
        pass

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        pass


class RedirectURIRegistryTest(TestCase):

    def setUp(self):
        self.registry = RedirectURIRegistry()

    def test_case_and_default_port_equivalence(self):
        registered = self.registry.register(
            'client', 'HTTPS://Shop.Example.COM:443/cb')
        self.assertEqual(registered, 'https://shop.example.com/cb')
        self.assertEqual(
            self.registry.match('client', 'https://shop.example.com/cb'),
            'https://shop.example.com/cb')
        self.assertEqual(
            self.registry.match('client', 'http://shop.example.com:80/cb'),
            None)

    def test_unreserved_percent_escape_equivalence(self):
        registered = self.registry.register(
            'client', 'https://shop.example.com/%7Ecallback')
        self.assertEqual(registered, 'https://shop.example.com/~callback')
        self.assertEqual(
            self.registry.match('client', 'https://shop.example.com/~callback'),
            'https://shop.example.com/~callback')
        self.assertEqual(
            self.registry.match('client', 'https://shop.example.com/%7ecallback'),
            'https://shop.example.com/~callback')

    def test_reserved_escapes_remain_distinct_but_hex_is_normalized(self):
        self.assertEqual(
            canonicalize_redirect_uri('https://example.com/a%2fb'),
            'https://example.com/a%2Fb')
        self.assertNotEqual(
            canonicalize_redirect_uri('https://example.com/a%2fb'),
            canonicalize_redirect_uri('https://example.com/a/b'))

    def test_path_and_query_are_exact(self):
        self.assertEqual(
            canonicalize_redirect_uri('https://example.com/a//b/'),
            'https://example.com/a//b/')
        self.assertNotEqual(
            canonicalize_redirect_uri('https://example.com/a//b/'),
            canonicalize_redirect_uri('https://example.com/a/b'))
        self.assertNotEqual(
            canonicalize_redirect_uri('https://example.com/cb?b=2&a=1'),
            canonicalize_redirect_uri('https://example.com/cb?a=1&b=2'))
        self.assertEqual(
            canonicalize_redirect_uri('https://example.com/cb?tenant=%7e'),
            'https://example.com/cb?tenant=~')
        self.assertEqual(
            canonicalize_redirect_uri('https://example.com/cb?path=%5c'),
            'https://example.com/cb?path=%5C')

    def test_malicious_ambiguous_uris_are_rejected(self):
        bad_uris = [
            'https://shop.example.com@evil.example/cb',
            'https://shop.example.com/cb#fragment',
            'https://shop.example.com/../cb',
            'https://shop.example.com/%2E%2E/cb',
            'https://shop.example.com/%zz/cb',
            'https://shop.example.com/cb%',
            'https://shop.example.com/a\\b/cb',
            'https://shop.example.com/a%5cb/cb',
            'https://shop.example.com./cb',
            'https://shop.example.com/cb\x00',
            'https://shop.example.com/cb%0d%0a',
        ]
        for uri in bad_uris:
            with self.assertRaises(RedirectURIError, msg=uri):
                canonicalize_redirect_uri(uri)
            self.assertIsNone(self.registry.match('client', uri))

    def test_registry_rejects_wildcards_and_duplicate_canonical_forms(self):
        with self.assertRaises(WildcardRedirectURIError):
            self.registry.register('client', 'https://*.example.com/cb')
        with self.assertRaises(WildcardRedirectURIError):
            canonicalize_redirect_uri('https://*.example.com/cb')

        self.registry.register('client', 'HTTPS://Shop.Example.COM:443/cb')
        with self.assertRaises(DuplicateRedirectURIError):
            self.registry.register('client', 'https://shop.example.com/cb')

        # The same canonical URI is still valid for a different client.
        self.registry.register('other-client', 'https://shop.example.com/cb')

    def test_duplicate_canonical_forms_are_rejected_at_startup(self):
        with self.assertRaises(DuplicateRedirectURIError):
            RedirectURIRegistry({
                'client': [
                    'HTTPS://Shop.Example.COM:443/cb',
                    'https://shop.example.com/cb',
                ]
            })

    def test_registrations_are_isolated_per_client(self):
        self.registry.register('client-a', 'https://shop.example.com/cb')
        self.assertIsNone(
            self.registry.match('client-b', 'https://shop.example.com/cb'))

    def test_loopback_accepts_any_valid_port_and_keeps_actual_port(self):
        self.registry.register('client', 'http://127.0.0.1/cb')
        self.assertEqual(
            self.registry.match('client', 'http://127.0.0.1:54321/cb'),
            'http://127.0.0.1:54321/cb')
        self.registry.register('query-client', 'http://127.0.0.1/cb?x=1')
        self.assertEqual(
            self.registry.match('query-client', 'http://127.0.0.1:8080/cb?x=1'),
            'http://127.0.0.1:8080/cb?x=1')
        self.assertIsNone(
            self.registry.match('client', 'http://127.0.0.1:8080/other'))

    def test_ipv6_loopback_accepts_any_valid_port(self):
        self.registry.register('client', 'http://[::1]/cb')
        self.assertEqual(
            self.registry.match('client', 'http://[::1]:54321/cb'),
            'http://[::1]:54321/cb')

    def test_loopback_exception_is_limited(self):
        self.registry.register('client', 'http://localhost/cb')
        self.assertIsNone(
            self.registry.match('client', 'http://localhost:54321/cb'))
        self.registry.register('external', 'http://example.com/cb')
        self.assertIsNone(
            self.registry.match('external', 'http://example.com:54321/cb'))
        self.registry.register('secure', 'https://127.0.0.1/cb')
        self.assertIsNone(
            self.registry.match('secure', 'https://127.0.0.1:54321/cb'))


class RedirectURIGrantBindingTest(TestCase):

    def setUp(self):
        self.validator = RecordingValidator()

    def authorization_grant(self, registry):
        return AuthorizationCodeGrant(
            self.validator, redirect_uri_registry=registry)

    def authorization_request(self, redirect_uri):
        request = Request('https://as.example/authorize')
        request.client_id = 'client'
        request.response_type = 'code'
        request.scopes = ['read']
        request.redirect_uri = redirect_uri
        request.state = 'state-value'
        return request

    def token_request(self, code, redirect_uri):
        request = Request('https://as.example/token')
        request.client_id = 'client'
        request.grant_type = 'authorization_code'
        request.code = code
        request.scopes = ['read']
        request.redirect_uri = redirect_uri
        return request

    def authorize(self, grant, redirect_uri):
        request = self.authorization_request(redirect_uri)
        headers, _, status = grant.create_authorization_response(
            request, BearerToken(self.validator))
        self.assertEqual(status, 302)
        code = dict(Request(headers['Location']).uri_query_params)['code']
        return request, headers['Location'], code

    def test_authorization_redirect_and_saved_code_use_canonical_request(self):
        registry = RedirectURIRegistry()
        registry.register('client', 'HTTPS://Shop.Example.COM:443/%7Ecb')
        grant = self.authorization_grant(registry)

        request, location, code = self.authorize(
            grant, 'HTTPS://Shop.Example.COM:443/%7Ecb')

        self.assertEqual(request.redirect_uri, 'https://shop.example.com/~cb')
        self.assertTrue(location.startswith('https://shop.example.com/~cb?'))
        self.assertEqual(self.validator.codes[code], 'https://shop.example.com/~cb')
        self.assertEqual(
            self.validator.saved_redirects[-1], 'https://shop.example.com/~cb')
        self.assertFalse(self.validator.validate_redirect_uri_called)

    def test_token_exchange_recanonicalizes_before_confirming(self):
        registry = RedirectURIRegistry()
        registry.register('client', 'HTTPS://Shop.Example.COM:443/%7Ecb')
        grant = self.authorization_grant(registry)

        _, _, code = self.authorize(
            grant, 'HTTPS://Shop.Example.COM:443/%7ecb')
        token_request = self.token_request(
            code, 'https://SHOP.example.com:443/~cb')
        _headers, body, status = grant.create_token_response(
            token_request, BearerToken(self.validator))

        self.assertEqual(status, 200, body)
        self.assertIn('access_token', json.loads(body))
        self.assertEqual(token_request.redirect_uri, 'https://shop.example.com/~cb')
        self.assertEqual(
            self.validator.confirm_calls,
            ['https://shop.example.com/~cb'])

    def test_query_difference_is_not_equivalent_during_exchange(self):
        registry = RedirectURIRegistry()
        registry.register('client', 'https://shop.example.com/cb?tenant=a')
        grant = self.authorization_grant(registry)

        _, _, code = self.authorize(
            grant, 'https://shop.example.com/cb?tenant=a')
        with self.assertRaises(errors.MismatchingRedirectURIError):
            grant.validate_token_request(
                self.token_request(code, 'https://shop.example.com/cb?tenant=b'))
        self.assertEqual(self.validator.confirm_calls, [])

    def test_malformed_redirect_is_invalid_at_both_stages(self):
        registry = RedirectURIRegistry()
        registry.register('client', 'https://shop.example.com/cb')
        grant = self.authorization_grant(registry)

        with self.assertRaises(errors.InvalidRedirectURIError):
            grant.validate_authorization_request(
                self.authorization_request('https://shop.example.com/../cb'))

        _, _, code = self.authorize(grant, 'https://shop.example.com/cb')
        with self.assertRaises(errors.InvalidRedirectURIError):
            grant.validate_token_request(
                self.token_request(code, 'https://shop.example.com/../cb'))
        self.assertEqual(self.validator.confirm_calls, [])

    def test_loopback_port_is_bound_and_cannot_change_at_exchange(self):
        registry = RedirectURIRegistry()
        registry.register('client', 'http://127.0.0.1/cb')
        grant = self.authorization_grant(registry)

        _request, _, code = self.authorize(
            grant, 'http://127.0.0.1:54321/cb')
        self.assertEqual(
            self.validator.codes[code], 'http://127.0.0.1:54321/cb')

        token_request = self.token_request(code, 'http://127.0.0.1:54321/cb')
        _, _, status = grant.create_token_response(
            token_request, BearerToken(self.validator))
        self.assertEqual(status, 200)
        self.assertEqual(
            self.validator.confirm_calls[-1], 'http://127.0.0.1:54321/cb')

        changed_port = self.token_request(code, 'http://127.0.0.1:54322/cb')
        with self.assertRaises(errors.MismatchingRedirectURIError):
            grant.validate_token_request(changed_port)
        self.assertEqual(
            changed_port.redirect_uri, 'http://127.0.0.1:54322/cb')
        self.assertEqual(
            self.validator.confirm_calls[-1], 'http://127.0.0.1:54322/cb')


class RedirectURIServerWiringTest(TestCase):

    def test_preconfigured_server_passes_registry_to_both_stages(self):
        registry = RedirectURIRegistry()
        registry.register('client', 'HTTPS://Shop.Example.COM:443/%7Ecb')
        validator = RecordingValidator()
        server = WebApplicationServer(
            validator, redirect_uri_registry=registry)

        auth_uri = ('https://as.example/authorize?client_id=client'
                    '&response_type=code&redirect_uri=' +
                    urllib.parse.quote(
                        'HTTPS://Shop.Example.COM:443/%7Ecb', safe=''))
        headers, _, status = server.create_authorization_response(
            auth_uri, scopes=['read'])
        self.assertEqual(status, 302)
        self.assertTrue(
            headers['Location'].startswith('https://shop.example.com/~cb?'))
        code = dict(Request(headers['Location']).uri_query_params)['code']

        body = urllib.parse.urlencode({
            'grant_type': 'authorization_code',
            'client_id': 'client',
            'code': code,
            'redirect_uri': 'https://SHOP.example.com:443/~cb',
        })
        _, response_body, status = server.create_token_response(
            'https://as.example/token', body=body)
        self.assertEqual(status, 200, response_body)
        self.assertIn('access_token', json.loads(response_body))
        self.assertEqual(
            validator.confirm_calls, ['https://shop.example.com/~cb'])
