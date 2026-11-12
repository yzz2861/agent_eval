from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.errors import InvalidTokenError
from oauthlib.oauth2.rfc6749.tokens import (
    MAX_BEARER_CHALLENGE_LENGTH, BearerToken, parse_bearer_challenge,
    prepare_bearer_body, prepare_bearer_challenge,
    prepare_bearer_challenge_headers, prepare_bearer_headers,
    prepare_bearer_uri, prepare_mac_header,
)

from tests.unittest import TestCase


class TokenTest(TestCase):

    # MAC without body/payload or extension
    mac_plain = {
        'token': 'h480djs93hd8',
        'uri': 'http://example.com/resource/1?b=1&a=2',
        'key': '489dks293j39',
        'http_method': 'GET',
        'nonce': '264095:dj83hs9s',
        'hash_algorithm': 'hmac-sha-1'
    }
    auth_plain = {
        'Authorization': 'MAC id="h480djs93hd8", nonce="264095:dj83hs9s",'
        ' mac="SLDJd4mg43cjQfElUs3Qub4L6xE="'
    }

    # MAC with body/payload, no extension
    mac_body = {
        'token': 'jd93dh9dh39D',
        'uri': 'http://example.com/request',
        'key': '8yfrufh348h',
        'http_method': 'POST',
        'nonce': '273156:di3hvdf8',
        'hash_algorithm': 'hmac-sha-1',
        'body': 'hello=world%21'
    }
    auth_body = {
        'Authorization': 'MAC id="jd93dh9dh39D", nonce="273156:di3hvdf8",'
        ' bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=", mac="W7bdMZbv9UWOTadASIQHagZyirA="'
    }

    # MAC with body/payload and extension
    mac_both = {
        'token': 'h480djs93hd8',
        'uri': 'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q',
        'key': '489dks293j39',
        'http_method': 'GET',
        'nonce': '264095:7d8f3e4a',
        'hash_algorithm': 'hmac-sha-1',
        'body': 'Hello World!',
        'ext': 'a,b,c'
    }
    auth_both = {
        'Authorization': 'MAC id="h480djs93hd8", nonce="264095:7d8f3e4a",'
        ' bodyhash="Lve95gjOVATpfV8EL5X4nxwjKHE=", ext="a,b,c",'
        ' mac="Z3C2DojEopRDIC88/imW8Ez853g="'
    }

    # Bearer
    token = 'vF9dft4qmT'
    uri = 'http://server.example.com/resource'
    bearer_headers = {
        'Authorization': 'Bearer vF9dft4qmT'
    }
    valid_bearer_header_lowercase = {"Authorization": "bearer vF9dft4qmT"}
    fake_bearer_headers = [
        {'Authorization': 'Beaver vF9dft4qmT'},
        {'Authorization': 'BeavervF9dft4qmT'},
        {'Authorization': 'Beaver  vF9dft4qmT'},
        {'Authorization': 'BearerF9dft4qmT'},
        {'Authorization': 'Bearer vF9d ft4qmT'},
    ]
    valid_header_with_multiple_spaces = {'Authorization': 'Bearer  vF9dft4qmT'}
    bearer_body = 'access_token=vF9dft4qmT'
    bearer_uri = 'http://server.example.com/resource?access_token=vF9dft4qmT'

    def _mocked_validate_bearer_token(self, token, scopes, request):
        if not token:  # noqa: SIM103
            return False
        return True

    def test_prepare_mac_header(self):
        """Verify mac signatures correctness

        TODO: verify hmac-sha-256
        """
        self.assertEqual(prepare_mac_header(**self.mac_plain), self.auth_plain)
        self.assertEqual(prepare_mac_header(**self.mac_body), self.auth_body)
        self.assertEqual(prepare_mac_header(**self.mac_both), self.auth_both)

    def test_prepare_mac_header_rejects_unsafe_values(self):
        for field, value in (
            ('nonce', 'legit\r\nX-Injected: evil'),
            ('nonce', 'legit\nX-Injected: evil'),
            ('nonce', 'legit\0'),
            ('nonce', 'legit"'),
            ('nonce', 'l\u00e9git'),
            ('ext', 'a,b\r\nSet-Cookie: pwned=1'),
            ('ext', 'a,b\nSet-Cookie: pwned=1'),
            ('ext', 'a\0,b'),
            ('ext', 'a"b'),
            ('ext', '\u00e9xt'),
        ):
            with self.subTest(field=field, value=repr(value)), \
                    self.assertRaises(ValueError):
                prepare_mac_header(
                    **{
                        **self.mac_plain,
                        field: value,
                    })

    def test_prepare_mac_header_rejects_crlf_in_nonce(self):
        with self.assertRaises(ValueError):
            prepare_mac_header(
                **{
                    **self.mac_plain,
                    'nonce': 'legit\r\nX-Injected: evil',
                })
        with self.assertRaises(ValueError):
            prepare_mac_header(
                **{
                    **self.mac_plain,
                    'nonce': 'legit\nX-Injected: evil',
                })

    def test_prepare_mac_header_rejects_crlf_in_ext(self):
        with self.assertRaises(ValueError):
            prepare_mac_header(
                **{
                    **self.mac_plain,
                    'ext': 'a,b\r\nSet-Cookie: pwned=1',
                })
        with self.assertRaises(ValueError):
            prepare_mac_header(
                **{
                    **self.mac_plain,
                    'ext': 'a,b\nSet-Cookie: pwned=1',
                })
        self.assertIn('Authorization',
                      prepare_mac_header(**{**self.mac_plain, 'ext': 'a,b,c'}))

    def test_prepare_bearer_request(self):
        """Verify proper addition of bearer tokens to requests.

        They may be represented as query components in body or URI or
        in a Bearer authorization header.
        """
        self.assertEqual(prepare_bearer_headers(self.token), self.bearer_headers)
        self.assertEqual(prepare_bearer_body(self.token), self.bearer_body)
        self.assertEqual(prepare_bearer_uri(self.token, uri=self.uri), self.bearer_uri)

    def test_bearer_challenge_round_trip(self):
        challenge = prepare_bearer_challenge(
            realm='photos "shared" \\ archive',
            error='invalid_token',
            error_description='The token "expired" \\ revoked.',
            scope={'write', 'read'},
            error_uri='https://example.com/errors/invalid_token',
            strict=True,
        )

        self.assertNotIn('\r', challenge)
        self.assertNotIn('\n', challenge)
        self.assertIn('realm="photos \\"shared\\" \\\\ archive"', challenge)
        self.assertIn('scope="read write"', challenge)
        self.assertEqual(parse_bearer_challenge(challenge), {
            'realm': 'photos "shared" \\ archive',
            'error': 'invalid_token',
            'error_description': 'The token "expired" \\ revoked.',
            'scope': 'read write',
            'error_uri': 'https://example.com/errors/invalid_token',
        })
        self.assertEqual(
            prepare_bearer_challenge_headers(error='invalid_token'),
            {'WWW-Authenticate': 'Bearer error="invalid_token"'},
        )

    def test_bearer_challenge_scope_is_deterministic(self):
        first = prepare_bearer_challenge(
            realm='api', scope={'write', 'read', 'read'}, strict=True)
        second = prepare_bearer_challenge(
            realm='api', scope=['read', 'write'], strict=True)

        self.assertEqual(first, second)
        self.assertIn('scope="read write"', first)
        self.assertEqual(
            parse_bearer_challenge(
                'Bearer realm="api", scope="write read write"')['scope'],
            'read write',
        )

    def test_bearer_challenge_builder_rejects_unsafe_values(self):
        for field, value in (
            ('realm', 'legit\r\nX-Injected: evil'),
            ('realm', 'legit\nX-Injected: evil'),
            ('realm', 'legit\0value'),
            ('realm', 'l\u00e9git'),
            ('error_description', 'bad\r\nSet-Cookie: pwned=1'),
            ('error_description', 'bad\0value'),
            ('error_description', 'caf\u00e9'),
            ('scope', 'read\r\nwrite'),
            ('scope', 'read"write'),
            ('scope', 'read\\write'),
            ('error_uri', 'https://exa mple.com/error'),
            ('error_uri', 'https://example.com/"error'),
            ('error_uri', ''),
        ):
            with self.subTest(field=field, value=repr(value)), \
                    self.assertRaises(ValueError):
                kwargs = {'strict': True}
                if field != 'realm':
                    kwargs['realm'] = 'api'
                kwargs[field] = value
                prepare_bearer_challenge(**kwargs)

    def test_bearer_challenge_strict_rejects_empty_realm_and_long_scope(self):
        with self.assertRaises(ValueError):
            prepare_bearer_challenge(realm='', strict=True)

        with self.assertRaises(ValueError):
            prepare_bearer_challenge(
                realm='api',
                scope=' '.join('scope%d' % index for index in range(2000)),
                strict=True,
            )

    def test_parse_bearer_challenge_rejects_invalid_challenges(self):
        for challenge in (
            'Bearer error="invalid_token"',
            'Basic realm="api"',
            'Digest realm="api"',
            'Bearer realm=""',
            'Bearer realm="a", realm="b"',
            'Bearer Realm="a", realm="b"',
            'Bearer realm="a',
            'Bearer realm="a",',
        ):
            with self.subTest(challenge=repr(challenge)), \
                    self.assertRaises(ValueError):
                parse_bearer_challenge(challenge)

        with self.assertRaises(ValueError):
            parse_bearer_challenge('Bearer realm="a"', max_length=10)

        with self.assertRaises(ValueError):
            parse_bearer_challenge('Bearer realm="a\r\nX: b"')

        with self.assertRaises(ValueError):
            parse_bearer_challenge(
                'Bearer realm="' + 'a' * MAX_BEARER_CHALLENGE_LENGTH + '"')

    def test_parse_bearer_challenge_accepts_case_insensitive_headers(self):
        parsed = parse_bearer_challenge({
            'www-authenticate':
                'bEaReR   REALM="api", SCOPE="write read", ERROR="invalid_token"',
        })

        self.assertEqual(parsed, {
            'realm': 'api',
            'error': 'invalid_token',
            'scope': 'read write',
        })

    def test_oauth2_error_header_escapes_user_values(self):
        error = InvalidTokenError(
            description='The realm "api" \\ path was not found.')
        header = error.headers['WWW-Authenticate']

        self.assertIn('error_description="The realm \\"api\\" \\\\ path', header)
        self.assertNotIn('\n', header)
        self.assertNotIn('\r', header)

        with self.assertRaises(ValueError):
            InvalidTokenError(description='legit\r\nX-Injected: evil').headers

    def test_valid_bearer_is_validated(self):
        request_validator = mock.MagicMock()
        request_validator.validate_bearer_token = self._mocked_validate_bearer_token

        request = Request("/", headers=self.bearer_headers)
        result = BearerToken(request_validator=request_validator).validate_request(
            request
        )
        self.assertTrue(result)

    def test_lowercase_bearer_is_validated(self):
        request_validator = mock.MagicMock()
        request_validator.validate_bearer_token = self._mocked_validate_bearer_token

        request = Request("/", headers=self.valid_bearer_header_lowercase)
        result = BearerToken(request_validator=request_validator).validate_request(
            request
        )
        self.assertTrue(result)

    def test_fake_bearer_is_not_validated(self):
        request_validator = mock.MagicMock()
        request_validator.validate_bearer_token = self._mocked_validate_bearer_token

        for fake_header in self.fake_bearer_headers:
            request = Request("/", headers=fake_header)
            result = BearerToken(request_validator=request_validator).validate_request(
                request
            )

            self.assertFalse(result)

    def test_header_with_multispaces_is_validated(self):
        request_validator = mock.MagicMock()
        request_validator.validate_bearer_token = self._mocked_validate_bearer_token

        request = Request("/", headers=self.valid_header_with_multiple_spaces)
        result = BearerToken(request_validator=request_validator).validate_request(
            request
        )

        self.assertTrue(result)

    def test_estimate_type(self):
        request_validator = mock.MagicMock()
        request_validator.validate_bearer_token = self._mocked_validate_bearer_token
        request = Request("/", headers=self.bearer_headers)
        result = BearerToken(request_validator=request_validator).estimate_type(request)
        self.assertEqual(result, 9)

    def test_estimate_type_with_fake_header_returns_type_0(self):
        request_validator = mock.MagicMock()
        request_validator.validate_bearer_token = self._mocked_validate_bearer_token

        for fake_header in self.fake_bearer_headers:
            request = Request("/", headers=fake_header)
            result = BearerToken(request_validator=request_validator).estimate_type(
                request
            )

            if (
                fake_header["Authorization"].count(" ") == 2
                and fake_header["Authorization"].split()[0] == "Bearer"
            ):
                # If we're dealing with the header containing 2 spaces, it will be recognized
                # as a Bearer valid header, the token itself will be invalid by the way.
                self.assertEqual(result, 9)
            else:
                self.assertEqual(result, 0)
