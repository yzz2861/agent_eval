# -*- coding: utf-8 -*-
import json
import threading
import urllib.parse
from unittest import mock

import jwt

from cryptography.hazmat.primitives.asymmetric import rsa

from oauthlib import common
from oauthlib.oauth2.rfc6749.client_assertion import (
    InMemoryJtiStore,
    JWTClientAssertionValidator,
)
from oauthlib.oauth2.rfc6749 import errors, tokens
from oauthlib.oauth2.rfc6749.endpoints import Server
from oauthlib.oauth2.rfc6749.endpoints.authorization import (
    AuthorizationEndpoint,
)
from oauthlib.oauth2.rfc6749.endpoints.resource import ResourceEndpoint
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.grant_types import (
    AuthorizationCodeGrant, ClientCredentialsGrant, ImplicitGrant,
    ResourceOwnerPasswordCredentialsGrant,
)
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator

from tests.unittest import TestCase


TOKEN_URI = 'https://as.example.com:8443/oauth2/token'
ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'


class AuthorizationEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.mock_validator.get_code_challenge.return_value = None
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = AuthorizationCodeGrant(
            request_validator=self.mock_validator)
        auth_code.save_authorization_code = mock.MagicMock()
        implicit = ImplicitGrant(
            request_validator=self.mock_validator)
        implicit.save_token = mock.MagicMock()

        response_types = {
            'code': auth_code,
            'token': implicit,
            'none': auth_code
        }
        self.expires_in = 1800
        token = tokens.BearerToken(
            self.mock_validator,
            expires_in=self.expires_in
        )
        self.endpoint = AuthorizationEndpoint(
            default_response_type='code',
            default_token_type=token,
            response_types=response_types
        )

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        uri = 'http://i.b/l?response_type=code&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?code=abc&state=xyz')

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_implicit_grant(self):
        uri = 'http://i.b/l?response_type=token&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me#access_token=abc&expires_in=' + str(self.expires_in) + '&token_type=Bearer&state=xyz&scope=all+of+them', parse_fragment=True)

    def test_none_grant(self):
        uri = 'http://i.b/l?response_type=none&client_id=me&scope=all+of+them&state=xyz'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, body, status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?state=xyz', parse_fragment=True)
        self.assertIsNone(body)
        self.assertEqual(status_code, 302)

        # and without the state parameter
        uri = 'http://i.b/l?response_type=none&client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        headers, body, status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me', parse_fragment=True)
        self.assertIsNone(body)
        self.assertEqual(status_code, 302)

    def test_missing_type(self):
        uri = 'http://i.b/l?client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
            side_effect=errors.InvalidRequestError())
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?error=invalid_request&error_description=Missing+response_type+parameter.')

    def test_invalid_type(self):
        uri = 'http://i.b/l?response_type=invalid&client_id=me&scope=all+of+them'
        uri += '&redirect_uri=http%3A%2F%2Fback.to%2Fme'
        self.mock_validator.validate_request = mock.MagicMock(
            side_effect=errors.UnsupportedResponseTypeError())
        headers, _body, _status_code = self.endpoint.create_authorization_response(
            uri, scopes=['all', 'of', 'them'])
        self.assertIn('Location', headers)
        self.assertURLEqual(headers['Location'], 'http://back.to/me?error=unsupported_response_type')


class TokenEndpointTest(TestCase):

    def setUp(self):
        def set_user(request):
            request.user = mock.MagicMock()
            request.client = mock.MagicMock()
            request.client.client_id = request.client_id
            return True

        self.mock_validator = mock.MagicMock()
        self.mock_validator.authenticate_client.side_effect = set_user
        self.mock_validator.get_code_challenge.return_value = None
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        auth_code = AuthorizationCodeGrant(
            request_validator=self.mock_validator)
        password = ResourceOwnerPasswordCredentialsGrant(
            request_validator=self.mock_validator)
        client = ClientCredentialsGrant(
            request_validator=self.mock_validator)
        supported_types = {
            'authorization_code': auth_code,
            'password': password,
            'client_credentials': client,
        }
        self.expires_in = 1800
        token = tokens.BearerToken(
            self.mock_validator,
            expires_in=self.expires_in
        )
        self.endpoint = TokenEndpoint(
            'authorization_code',
            default_token_type=token,
            grant_types=supported_types
        )

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        body = 'grant_type=authorization_code&code=abc&scope=all+of+them'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'refresh_token': 'abc',
            'scope': 'all of them'
        }
        self.assertEqual(json.loads(body), token)

        body = 'grant_type=authorization_code&code=abc'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'refresh_token': 'abc'
        }
        self.assertEqual(json.loads(body), token)

        # try with additional custom variables
        body = 'grant_type=authorization_code&code=abc&state=foobar'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        self.assertEqual(json.loads(body), token)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_password_grant(self):
        body = 'grant_type=password&username=a&password=hello&scope=all+of+them'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'refresh_token': 'abc',
            'scope': 'all of them',
        }
        self.assertEqual(json.loads(body), token)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_client_grant(self):
        body = 'grant_type=client_credentials&scope=all+of+them'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': 'abc',
            'scope': 'all of them',
        }
        self.assertEqual(json.loads(body), token)

    def test_missing_type(self):
        _, body, _ = self.endpoint.create_token_response('', body='')
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)

    def test_invalid_type(self):
        body = 'grant_type=invalid'
        _, body, _ = self.endpoint.create_token_response('', body=body)
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)


class SignedTokenEndpointTest(TestCase):

    def setUp(self):
        self.expires_in = 1800

        def set_user(request):
            request.user = mock.MagicMock()
            request.client = mock.MagicMock()
            request.client.client_id = request.client_id
            return True

        self.mock_validator = mock.MagicMock()
        self.mock_validator.get_code_challenge.return_value = None
        self.mock_validator.authenticate_client.side_effect = set_user
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())

        self.private_pem = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA6TtDhWGwzEOWZP6m/zHoZnAPLABfetvoMPmxPGjFjtDuMRPv
EvI1sbixZBjBtdnc5rTtHUUQ25Am3JzwPRGo5laMGbj1pPyCPxlVi9LK82HQNX0B
YK7tZtVfDHElQA7F4v3j9d3rad4O9/n+lyGIQ0tT7yQcBm2A8FEaP0bZYCLMjwMN
WfaVLE8eXHyv+MfpNNLI9wttLxygKYM48I3NwsFuJgOa/KuodXaAmf8pJnx8t1Wn
nxvaYXFiUn/TxmhM/qhemPa6+0nqq+aWV5eT7xn4K/ghLgNs09v6Yge0pmPl9Oz+
+bjJ+aKRnAmwCOY8/5U5EilAiUOeBoO9+8OXtwIDAQABAoIBAGFTTbXXMkPK4HN8
oItVdDlrAanG7hECuz3UtFUVE3upS/xG6TjqweVLwRqYCh2ssDXFwjy4mXRGDzF4
e/e/6s9Txlrlh/w1MtTJ6ZzTdcViR9RKOczysjZ7S5KRlI3KnGFAuWPcG2SuOWjZ
dZfzcj1Crd/ZHajBAVFHRsCo/ATVNKbTRprFfb27xKpQ2BwH/GG781sLE3ZVNIhs
aRRaED4622kI1E/WXws2qQMqbFKzo0m1tPbLb3Z89WgZJ/tRQwuDype1Vfm7k6oX
xfbp3948qSe/yWKRlMoPkleji/WxPkSIalzWSAi9ziN/0Uzhe65FURgrfHL3XR1A
B8UR+aECgYEA7NPQZV4cAikk02Hv65JgISofqV49P8MbLXk8sdnI1n7Mj10TgzU3
lyQGDEX4hqvT0bTXe4KAOxQZx9wumu05ejfzhdtSsEm6ptGHyCdmYDQeV0C/pxDX
JNCK8XgMku2370XG0AnyBCT7NGlgtDcNCQufcesF2gEuoKiXg6Zjo7sCgYEA/Bzs
9fWGZZnSsMSBSW2OYbFuhF3Fne0HcxXQHipl0Rujc/9g0nccwqKGizn4fGOE7a8F
usQgJoeGcinL7E9OEP/uQ9VX1C9RNVjIxP1O5/Guw1zjxQQYetOvbPhN2QhD1Ye7
0TRKrW1BapcjwLpFQlVg1ZeTPOi5lv24W/wX9jUCgYEAkrMSX/hPuTbrTNVZ3L6r
NV/2hN+PaTPeXei/pBuXwOaCqDurnpcUfFcgN/IP5LwDVd+Dq0pHTFFDNv45EFbq
R77o5n3ZVsIVEMiyJ1XgoK8oLDw7e61+15smtjT69Piz+09pu+ytMcwGn4y3Dmsb
dALzHYnL8iLRU0ubrz0ec4kCgYAJiVKRTzNBPptQom49h85d9ac3jJCAE8o3WTjh
Gzt0uHXrWlqgO280EY/DTnMOyXjqwLcXxHlu26uDP/99tdY/IF8z46sJ1KxetzgI
84f7kBHLRAU9m5UNeFpnZdEUB5MBTbwWAsNcYgiabpMkpCcghjg+fBhOsoLqqjhC
CnwhjQKBgQDkv0QTdyBU84TE8J0XY3eLQwXbrvG2yD5A2ntN3PyxGEneX5WTJGMZ
xJxwaFYQiDS3b9E7b8Q5dg8qa5Y1+epdhx3cuQAWPm+AoHKshDfbRve4txBDQAqh
c6MxSWgsa+2Ld5SWSNbGtpPcmEM3Fl5ttMCNCKtNc0UE16oHwaPAIw==
-----END RSA PRIVATE KEY-----
        """

        self.public_pem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6TtDhWGwzEOWZP6m/zHo
ZnAPLABfetvoMPmxPGjFjtDuMRPvEvI1sbixZBjBtdnc5rTtHUUQ25Am3JzwPRGo
5laMGbj1pPyCPxlVi9LK82HQNX0BYK7tZtVfDHElQA7F4v3j9d3rad4O9/n+lyGI
Q0tT7yQcBm2A8FEaP0bZYCLMjwMNWfaVLE8eXHyv+MfpNNLI9wttLxygKYM48I3N
wsFuJgOa/KuodXaAmf8pJnx8t1WnnxvaYXFiUn/TxmhM/qhemPa6+0nqq+aWV5eT
7xn4K/ghLgNs09v6Yge0pmPl9Oz++bjJ+aKRnAmwCOY8/5U5EilAiUOeBoO9+8OX
twIDAQAB
-----END PUBLIC KEY-----
        """

        signed_token = tokens.signed_token_generator(self.private_pem,
                                                     user_id=123)
        self.endpoint = Server(
            self.mock_validator,
            token_expires_in=self.expires_in,
            token_generator=signed_token,
            refresh_token_generator=tokens.random_token_generator
        )

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_authorization_grant(self):
        body = 'client_id=me&redirect_uri=http%3A%2F%2Fback.to%2Fme&grant_type=authorization_code&code=abc&scope=all+of+them'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        body = json.loads(body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': body['access_token'],
            'refresh_token': 'abc',
            'scope': 'all of them'
        }
        self.assertEqual(body, token)

        body = 'client_id=me&redirect_uri=http%3A%2F%2Fback.to%2Fme&grant_type=authorization_code&code=abc'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        body = json.loads(body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': body['access_token'],
            'refresh_token': 'abc'
        }
        self.assertEqual(body, token)

        # try with additional custom variables
        body = 'client_id=me&redirect_uri=http%3A%2F%2Fback.to%2Fme&grant_type=authorization_code&code=abc&state=foobar'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        body = json.loads(body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': body['access_token'],
            'refresh_token': 'abc'
        }
        self.assertEqual(body, token)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_password_grant(self):
        body = 'grant_type=password&username=a&password=hello&scope=all+of+them'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        body = json.loads(body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': body['access_token'],
            'refresh_token': 'abc',
            'scope': 'all of them',
        }
        self.assertEqual(body, token)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_scopes_and_user_id_stored_in_access_token(self):
        body = 'grant_type=password&username=a&password=hello&scope=all+of+them'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)

        access_token = json.loads(body)['access_token']

        claims = common.verify_signed_token(self.public_pem, access_token)

        self.assertEqual(claims['scope'], 'all of them')
        self.assertEqual(claims['user_id'], 123)

    @mock.patch('oauthlib.common.generate_token', new=lambda: 'abc')
    def test_client_grant(self):
        body = 'grant_type=client_credentials&scope=all+of+them'
        _headers, body, _status_code = self.endpoint.create_token_response(
            '', body=body)
        body = json.loads(body)
        token = {
            'token_type': 'Bearer',
            'expires_in': self.expires_in,
            'access_token': body['access_token'],
            'scope': 'all of them',
        }
        self.assertEqual(body, token)

    def test_missing_type(self):
        _, body, _ = self.endpoint.create_token_response('', body='client_id=me&redirect_uri=http%3A%2F%2Fback.to%2Fme&code=abc')
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)

    def test_invalid_type(self):
        body = 'client_id=me&redirect_uri=http%3A%2F%2Fback.to%2Fme&grant_type=invalid&code=abc'
        _, body, _ = self.endpoint.create_token_response('', body=body)
        token = {'error': 'unsupported_grant_type'}
        self.assertEqual(json.loads(body), token)


class ResourceEndpointTest(TestCase):

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.addCleanup(setattr, self, 'mock_validator', mock.MagicMock())
        token = tokens.BearerToken(request_validator=self.mock_validator)
        self.endpoint = ResourceEndpoint(
            default_token='Bearer',
            token_types={'Bearer': token}
        )

    def test_defaults(self):
        uri = 'http://a.b/path?some=query'
        self.mock_validator.validate_bearer_token.return_value = False
        valid, request = self.endpoint.verify_request(uri)
        self.assertFalse(valid)
        self.assertEqual(request.token_type, 'Bearer')


class PrivateKeyJwtTokenEndpointTest(TestCase):
    """End-to-end private_key_jwt lifecycle on the TokenEndpoint."""

    class _AssertionGrantValidator(RequestValidator):
        """Real signature/jti defaults with mocked grant callbacks."""

        def __init__(self, outer):
            self._outer = outer
            self.mock = outer.mock_validator

        def get_client_assertion_time(self, request):
            return self._outer.now

        def validate_grant_type(self, *args, **kwargs):
            return self.mock.validate_grant_type(*args, **kwargs)

        def get_default_scopes(self, *args, **kwargs):
            return self.mock.get_default_scopes(*args, **kwargs)

        def validate_scopes(self, *args, **kwargs):
            return self.mock.validate_scopes(*args, **kwargs)

        def save_bearer_token(self, *args, **kwargs):
            return self.mock.save_bearer_token(*args, **kwargs)

        def authenticate_client(self, *args, **kwargs):
            return self.mock.authenticate_client(*args, **kwargs)

        def client_authentication_required(self, *args, **kwargs):
            return self.mock.client_authentication_required(*args, **kwargs)

    def setUp(self):
        self.now = 1_700_000_000
        self.clock = lambda: self.now

        self.private_key = rsa.generate_private_key(public_exponent=65537,
                                                    key_size=2048)
        self.public_key = self.private_key.public_key()
        self.other_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048)
        self.client_id = 'client-123'
        self.kid = 'key-1'

        self.mock_validator = mock.MagicMock()
        self.mock_validator.get_code_challenge.return_value = None
        self.mock_validator.get_client_assertion_time.side_effect = self.clock

        def set_user(request):
            request.user = mock.MagicMock()
            request.client = mock.MagicMock()
            request.client.client_id = request.client_id
            return True

        self.mock_validator.authenticate_client.side_effect = set_user
        self.mock_validator.authenticate_client_assertion.side_effect = \
            lambda client_id, request, claims=None: set_user(request)

        self.jti_store = InMemoryJtiStore(clock=self.clock)
        grant_validator = self._AssertionGrantValidator(self)
        self.assertion_validator = JWTClientAssertionValidator(
            grant_validator,
            expected_audience=TOKEN_URI,
            signing_keys={self.kid: self.public_key},
            jti_store=self.jti_store,
            clock=self.clock,
        )

        auth_code = AuthorizationCodeGrant(
            request_validator=grant_validator)
        client_credentials = ClientCredentialsGrant(
            request_validator=grant_validator)
        token = tokens.BearerToken(grant_validator, expires_in=1800)
        self.endpoint = TokenEndpoint(
            'client_credentials',
            default_token_type=token,
            grant_types={
                'client_credentials': client_credentials,
                'authorization_code': auth_code,
            },
            client_assertion_validator=self.assertion_validator,
        )

    def make_assertion(self, jti='jti-1', aud=TOKEN_URI, kid=None,
                       key=None, iss=None, sub=None, iat=None, exp=None,
                       nbf=None, alg='RS256'):
        payload = {
            'iss': iss or self.client_id,
            'sub': sub or self.client_id,
            'aud': aud,
            'iat': iat if iat is not None else self.now - 5,
            'nbf': nbf,
            'exp': exp if exp is not None else self.now + 300,
            'jti': jti,
        }
        return jwt.encode(payload, key or self.private_key,
                          algorithm=alg,
                          headers={'kid': kid or self.kid})

    def make_body(self, assertion, **extra):
        params = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_assertion_type': ASSERTION_TYPE,
            'client_assertion': assertion,
        }
        params.update(extra)
        return urllib.parse.urlencode(params)

    def error_code(self, body):
        return json.loads(body)['error']

    def test_success_consumes_jti_and_authenticates_without_secret(self):
        assertion = self.make_assertion()
        _headers, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(assertion))
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertEqual(token['token_type'], 'Bearer')
        self.assertTrue(self.jti_store.is_consumed(self.client_id, 'jti-1'))
        self.assertFalse(self.jti_store.is_reserved(self.client_id, 'jti-1'))
        # The classic client_secret path must not be invoked.
        self.mock_validator.authenticate_client.assert_not_called()

    def test_replayed_assertion_is_rejected(self):
        assertion = self.make_assertion()
        _, _body_1, status_1 = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(assertion))
        self.assertEqual(status_1, 200)
        _, body_2, status_2 = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(assertion))
        self.assertEqual(status_2, 401)
        self.assertEqual(self.error_code(body_2),
                         'replayed_client_assertion')

    def test_concurrent_exchanges_only_one_succeeds(self):
        assertion = self.make_assertion(jti='jti-concurrent')
        body = self.make_body(assertion)
        barrier = threading.Barrier(4)
        results = []

        def exchange():
            barrier.wait()
            results.append(self.endpoint.create_token_response(
                TOKEN_URI, body=body))

        threads = [threading.Thread(target=exchange) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        successes = [r for r in results if r[2] == 200]
        failures = [r for r in results if r[2] != 200]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 3)
        # Losers that overlap the winner's reservation see
        # concurrent_client_assertion; a loser scheduled after the commit
        # sees replayed_client_assertion. Both are distinct from success and
        # from every other assertion error.
        self.assertTrue(all(
            self.error_code(b) in ('concurrent_client_assertion',
                                   'replayed_client_assertion')
            for _h, b, _s in failures))

    def test_clock_rollback_is_rejected(self):
        assertion = self.make_assertion(jti='jti-rollback')
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(assertion))
        self.assertEqual(status, 200)
        self.now -= 60
        rollback_assertion = self.make_assertion(jti='jti-rollback-2')
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI,
            body=self.make_body(rollback_assertion))
        self.assertEqual(status, 401)
        self.assertEqual(self.error_code(body), 'clock_rollback')

    def test_audience_requires_exact_port_and_path_match(self):
        # Same host, different port.
        wrong_port = self.make_assertion(
            jti='jti-aud-1', aud='https://as.example.com/oauth2/token')
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(wrong_port))
        self.assertEqual(status, 401)
        self.assertEqual(self.error_code(body),
                         'invalid_client_assertion_audience')

        # Same host and port, different path.
        wrong_path = self.make_assertion(
            jti='jti-aud-2', aud='https://as.example.com:8443/oauth2/other')
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(wrong_path))
        self.assertEqual(self.error_code(body),
                         'invalid_client_assertion_audience')

        # No consumed state may survive a failed validation.
        self.assertFalse(self.jti_store.is_reserved(self.client_id,
                                                    'jti-aud-1'))
        self.assertFalse(self.jti_store.is_consumed(self.client_id,
                                                    'jti-aud-1'))

    def test_unknown_kid_is_rejected(self):
        assertion = self.make_assertion(kid='unknown-kid')
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(assertion))
        self.assertEqual(status, 401)
        self.assertEqual(self.error_code(body),
                         'unknown_client_assertion_key')

    def test_expired_assertion_is_rejected(self):
        assertion = self.make_assertion(
            jti='jti-exp', exp=self.now - 1)
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(assertion))
        self.assertEqual(status, 401)
        self.assertEqual(self.error_code(body),
                         'expired_client_assertion')
        self.assertFalse(self.jti_store.is_reserved(self.client_id,
                                                    'jti-exp'))

    def test_bad_signature_and_binding_failures_are_distinct_from_replay(self):
        # Signed with an unregistered key.
        forged = self.make_assertion(jti='jti-forged',
                                     key=self.other_private_key)
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(forged))
        self.assertEqual(status, 401)
        self.assertEqual(self.error_code(body), 'invalid_client')

        # iss/sub must be bound to the authenticated client.
        mismatched = self.make_assertion(jti='jti-bind', sub='other-client')
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(mismatched))
        self.assertEqual(self.error_code(body), 'invalid_client')

        # Nothing was consumed by the failed exchanges.
        self.assertFalse(self.jti_store.is_consumed(self.client_id,
                                                    'jti-forged'))
        self.assertFalse(self.jti_store.is_consumed(self.client_id,
                                                    'jti-bind'))

    def test_failed_grant_releases_reservation(self):
        assertion = self.make_assertion(jti='jti-grant-fail')
        self.mock_validator.validate_grant_type.side_effect = \
            lambda *args, **kwargs: False
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(assertion))
        self.assertEqual(status, 400)
        self.assertEqual(self.error_code(body), 'unauthorized_client')
        self.assertFalse(self.jti_store.is_consumed(
            self.client_id, 'jti-grant-fail'))
        self.assertFalse(self.jti_store.is_reserved(
            self.client_id, 'jti-grant-fail'))

        # The same assertion can be retried successfully after rollback.
        self.mock_validator.validate_grant_type.side_effect = None
        retry_assertion = self.make_assertion(jti='jti-grant-fail')
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(retry_assertion))
        self.assertEqual(status, 200)
        self.assertTrue(self.jti_store.is_consumed(
            self.client_id, 'jti-grant-fail'))

    def test_error_responses_do_not_leak_assertion_or_key(self):
        assertion = self.make_assertion(
            jti='jti-leak', aud='https://as.example.com/wrong')
        _, body, _status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(assertion))
        self.assertNotIn(assertion, body)
        self.assertNotIn('BEGIN', body)
        self.assertNotIn('jti-leak', body)

    def test_client_secret_path_is_unchanged(self):
        body = urllib.parse.urlencode({
            'grant_type': 'client_credentials',
            'scope': 'all of them',
        })
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=body)
        self.assertEqual(status, 200)
        token = json.loads(body)
        self.assertEqual(token['token_type'], 'Bearer')
        self.mock_validator.authenticate_client.assert_called_once()

    def test_not_before_and_issued_at_windows_are_enforced(self):
        not_before = self.make_assertion(jti='jti-nbf', nbf=self.now + 30)
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(not_before))
        self.assertEqual(status, 401)
        self.assertEqual(self.error_code(body), 'invalid_client')

        future_iat = self.make_assertion(jti='jti-iat', iat=self.now + 30)
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(future_iat))
        self.assertEqual(self.error_code(body), 'invalid_client')

        stale_iat = self.make_assertion(
            jti='jti-stale', iat=self.now - 601)
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=self.make_body(stale_iat))
        self.assertEqual(self.error_code(body), 'invalid_client')
        for jti in ('jti-nbf', 'jti-iat', 'jti-stale'):
            self.assertFalse(self.jti_store.is_reserved(self.client_id, jti))

    def test_missing_and_duplicate_assertion_parameters(self):
        body = urllib.parse.urlencode({
            'grant_type': 'client_credentials',
            'client_assertion_type': ASSERTION_TYPE,
        })
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=body)
        self.assertEqual(status, 400)
        self.assertEqual(self.error_code(body), 'invalid_request')

        assertion = self.make_assertion(jti='jti-dup')
        body = self.make_body(assertion) + '&client_assertion=' + assertion
        _, body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=body)
        self.assertEqual(status, 400)
        self.assertEqual(self.error_code(body), 'invalid_request')

    def test_client_id_can_be_derived_from_issuer_claim(self):
        assertion = self.make_assertion(jti='jti-iss')
        params = urllib.parse.parse_qsl(self.make_body(assertion))
        params = [(k, v) for k, v in params if k != 'client_id']
        _, _body, status = self.endpoint.create_token_response(
            TOKEN_URI, body=urllib.parse.urlencode(params))
        self.assertEqual(status, 200)
        self.assertTrue(self.jti_store.is_consumed(self.client_id, 'jti-iss'))
