from unittest.mock import patch

from oauthlib import signals
from oauthlib.oauth2.rfc6749.errors import *
from oauthlib.oauth2.rfc6749.parameters import *

from tests.unittest import TestCase


@patch('time.time', new=lambda: 1000)
class ParameterTests(TestCase):

    state = 'xyz'
    auth_base = {
        'uri': 'https://server.example.com/authorize',
        'client_id': 's6BhdRkqt3',
        'redirect_uri': 'https://client.example.com/cb',
        'state': state,
        'scope': 'photos'
    }
    list_scope = ['list', 'of', 'scopes']

    auth_grant = {'response_type': 'code'}
    auth_grant_pkce = {'response_type': 'code', 'code_challenge': "code_challenge",
                       'code_challenge_method': 'code_challenge_method'}
    auth_grant_list_scope = {}
    auth_implicit = {'response_type': 'token', 'extra': 'extra'}
    auth_implicit_list_scope = {}

    def setUp(self):
        self.auth_grant.update(self.auth_base)
        self.auth_grant_pkce.update(self.auth_base)
        self.auth_implicit.update(self.auth_base)
        self.auth_grant_list_scope.update(self.auth_grant)
        self.auth_grant_list_scope['scope'] = self.list_scope
        self.auth_implicit_list_scope.update(self.auth_implicit)
        self.auth_implicit_list_scope['scope'] = self.list_scope

    auth_base_uri = ('https://server.example.com/authorize?response_type={0}'
                     '&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2F'
                     'client.example.com%2Fcb&scope={1}&state={2}{3}')

    auth_base_uri_pkce = ('https://server.example.com/authorize?response_type={0}'
                     '&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2F'
                     'client.example.com%2Fcb&scope={1}&state={2}{3}&code_challenge={4}'
                     '&code_challenge_method={5}')

    auth_grant_uri = auth_base_uri.format('code', 'photos', state, '')
    auth_grant_uri_pkce = auth_base_uri_pkce.format('code', 'photos', state, '', 'code_challenge',
                                                    'code_challenge_method')
    auth_grant_uri_list_scope = auth_base_uri.format('code', 'list+of+scopes', state, '')
    auth_implicit_uri = auth_base_uri.format('token', 'photos', state, '&extra=extra')
    auth_implicit_uri_list_scope = auth_base_uri.format('token', 'list+of+scopes', state, '&extra=extra')

    grant_body = {
        'grant_type': 'authorization_code',
        'code': 'SplxlOBeZQQYbYS6WxSbIA',
        'redirect_uri': 'https://client.example.com/cb'
    }
    grant_body_pkce = {
        'grant_type': 'authorization_code',
        'code': 'SplxlOBeZQQYbYS6WxSbIA',
        'redirect_uri': 'https://client.example.com/cb',
        'code_verifier': 'code_verifier'
    }
    grant_body_scope = {'scope': 'photos'}
    grant_body_list_scope = {'scope': list_scope}
    auth_grant_body = ('grant_type=authorization_code&'
                       'code=SplxlOBeZQQYbYS6WxSbIA&'
                       'redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb')
    auth_grant_body_pkce = ('grant_type=authorization_code&'
                       'code=SplxlOBeZQQYbYS6WxSbIA&'
                       'redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb'
                       '&code_verifier=code_verifier')
    auth_grant_body_scope = auth_grant_body + '&scope=photos'
    auth_grant_body_list_scope = auth_grant_body + '&scope=list+of+scopes'

    pwd_body = {
        'grant_type': 'password',
        'username': 'johndoe',
        'password': 'A3ddj3w'
    }
    password_body = 'grant_type=password&username=johndoe&password=A3ddj3w'

    cred_grant = {'grant_type': 'client_credentials'}
    cred_body = 'grant_type=client_credentials'

    grant_response = 'https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz'
    grant_dict = {'code': 'SplxlOBeZQQYbYS6WxSbIA', 'state': state}

    error_nocode = 'https://client.example.com/cb?state=xyz'
    error_nostate = 'https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA'
    error_wrongstate = 'https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=abc'
    error_denied = 'https://client.example.com/cb?error=access_denied&state=xyz'
    error_invalid = 'https://client.example.com/cb?error=invalid_request&state=xyz'

    implicit_base = 'https://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA&scope=abc&'
    implicit_response = implicit_base + 'state={}&token_type=example&expires_in=3600'.format(state)
    implicit_notype = implicit_base + 'state={}&expires_in=3600'.format(state)
    implicit_wrongstate = implicit_base + 'state={}&token_type=exampleexpires_in=3600'.format('invalid')
    implicit_nostate = implicit_base + 'token_type=example&expires_in=3600'
    implicit_notoken = 'https://example.com/cb#state=xyz&token_type=example&expires_in=3600'

    implicit_dict = {
        'access_token': '2YotnFZFEjr1zCsicMWpAA',
        'state': state,
        'token_type': 'example',
        'expires_in': 3600,
        'expires_at': 4600,
        'scope': ['abc']
    }

    json_response = ('{ "access_token": "2YotnFZFEjr1zCsicMWpAA",'
                     '  "token_type": "example",'
                     '  "expires_in": 3600,'
                     '  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",'
                     '  "example_parameter": "example_value",'
                     '  "scope":"abc def"}')
    json_response_noscope = ('{ "access_token": "2YotnFZFEjr1zCsicMWpAA",'
                     '  "token_type": "example",'
                     '  "expires_in": 3600,'
                     '  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",'
                     '  "example_parameter": "example_value" }')
    json_response_noexpire = ('{ "access_token": "2YotnFZFEjr1zCsicMWpAA",'
                     '  "token_type": "example",'
                     '  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",'
                     '  "example_parameter": "example_value"}')
    json_response_expirenull = ('{ "access_token": "2YotnFZFEjr1zCsicMWpAA",'
                     '  "token_type": "example",'
                     '  "expires_in": null,'
                     '  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",'
                     '  "example_parameter": "example_value"}')

    json_custom_error = '{ "error": "incorrect_client_credentials" }'
    json_error = '{ "error": "access_denied" }'

    json_notoken = ('{ "token_type": "example",'
                    '  "expires_in": 3600,'
                    '  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",'
                    '  "example_parameter": "example_value" }')

    json_notype = ('{  "access_token": "2YotnFZFEjr1zCsicMWpAA",'
                   '   "expires_in": 3600,'
                   '   "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",'
                   '   "example_parameter": "example_value" }')

    json_dict = {
       'access_token': '2YotnFZFEjr1zCsicMWpAA',
       'token_type': 'example',
       'expires_in': 3600,
       'expires_at': 4600,
       'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA',
       'example_parameter': 'example_value',
       'scope': ['abc', 'def']
    }

    json_noscope_dict = {
       'access_token': '2YotnFZFEjr1zCsicMWpAA',
       'token_type': 'example',
       'expires_in': 3600,
       'expires_at': 4600,
       'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA',
       'example_parameter': 'example_value'
    }

    json_noexpire_dict = {
        'access_token': '2YotnFZFEjr1zCsicMWpAA',
        'token_type': 'example',
        'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA',
        'example_parameter': 'example_value'
    }

    json_notype_dict = {
       'access_token': '2YotnFZFEjr1zCsicMWpAA',
       'expires_in': 3600,
       'expires_at': 4600,
       'refresh_token': 'tGzv3JOkF0XG5Qx2TlKWIA',
       'example_parameter': 'example_value',
    }

    url_encoded_response = ('access_token=2YotnFZFEjr1zCsicMWpAA'
                            '&token_type=example'
                            '&expires_in=3600'
                            '&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA'
                            '&example_parameter=example_value'
                            '&scope=abc def')

    url_encoded_error = 'error=access_denied'

    url_encoded_notoken = ('token_type=example'
                           '&expires_in=3600'
                           '&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA'
                           '&example_parameter=example_value')


    def test_prepare_grant_uri(self):
        """Verify correct authorization URI construction."""
        self.assertURLEqual(prepare_grant_uri(**self.auth_grant), self.auth_grant_uri)
        self.assertURLEqual(prepare_grant_uri(**self.auth_grant_list_scope), self.auth_grant_uri_list_scope)
        self.assertURLEqual(prepare_grant_uri(**self.auth_implicit), self.auth_implicit_uri)
        self.assertURLEqual(prepare_grant_uri(**self.auth_implicit_list_scope), self.auth_implicit_uri_list_scope)
        self.assertURLEqual(prepare_grant_uri(**self.auth_grant_pkce), self.auth_grant_uri_pkce)

    def test_prepare_token_request(self):
        """Verify correct access token request body construction."""
        self.assertFormBodyEqual(prepare_token_request(**self.grant_body), self.auth_grant_body)
        self.assertFormBodyEqual(prepare_token_request(**self.pwd_body), self.password_body)
        self.assertFormBodyEqual(prepare_token_request(**self.cred_grant), self.cred_body)
        self.assertFormBodyEqual(prepare_token_request(**self.grant_body_pkce), self.auth_grant_body_pkce)

    def test_prepare_token_revocation_request_rejects_callback(self):
        with self.assertRaisesRegex(
                TypeError,
                "prepare_token_revocation_request\\(\\) got an unexpected keyword argument 'callback'"):
            prepare_token_revocation_request(
                "https://server.example.com/revoke", "token", callback="jsonp"
            )

    def test_grant_response(self):
        """Verify correct parameter parsing and validation for auth code responses."""
        params = parse_authorization_code_response(self.grant_response)
        self.assertEqual(params, self.grant_dict)
        params = parse_authorization_code_response(self.grant_response, state=self.state)
        self.assertEqual(params, self.grant_dict)

        self.assertRaises(MissingCodeError, parse_authorization_code_response,
                self.error_nocode)
        self.assertRaises(AccessDeniedError, parse_authorization_code_response,
                self.error_denied)
        self.assertRaises(InvalidRequestFatalError, parse_authorization_code_response,
                self.error_invalid)
        self.assertRaises(MismatchingStateError, parse_authorization_code_response,
                self.error_nostate, state=self.state)
        self.assertRaises(MismatchingStateError, parse_authorization_code_response,
                self.error_wrongstate, state=self.state)

    def test_implicit_token_response(self):
        """Verify correct parameter parsing and validation for implicit responses."""
        self.assertEqual(parse_implicit_response(self.implicit_response),
                self.implicit_dict)
        self.assertRaises(MissingTokenError, parse_implicit_response,
                self.implicit_notoken)
        self.assertRaises(ValueError, parse_implicit_response,
                self.implicit_nostate, state=self.state)
        self.assertRaises(ValueError, parse_implicit_response,
                self.implicit_wrongstate, state=self.state)

    def test_custom_json_error(self):
        self.assertRaises(CustomOAuth2Error, parse_token_response, self.json_custom_error)

    def test_json_token_response(self):
        """Verify correct parameter parsing and validation for token responses. """
        self.assertEqual(parse_token_response(self.json_response), self.json_dict)
        self.assertRaises(AccessDeniedError, parse_token_response, self.json_error)
        self.assertRaises(MissingTokenError, parse_token_response, self.json_notoken)

        self.assertEqual(parse_token_response(self.json_response_noscope,
            scope=['all', 'the', 'scopes']), self.json_noscope_dict)
        self.assertEqual(parse_token_response(self.json_response_noexpire), self.json_noexpire_dict)
        self.assertEqual(parse_token_response(self.json_response_expirenull), self.json_noexpire_dict)

        scope_changes_recorded = []
        def record_scope_change(sender, message, old, new):
            scope_changes_recorded.append((message, old, new))

        os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
        signals.scope_changed.connect(record_scope_change)
        try:
            parse_token_response(self.json_response, scope='aaa')
            self.assertEqual(len(scope_changes_recorded), 1)
            message, old, new = scope_changes_recorded[0]
            for scope in new + old:
                self.assertIn(scope, message)
            self.assertEqual(old, ['aaa'])
            self.assertEqual(set(new), {'abc', 'def'})
        finally:
            signals.scope_changed.disconnect(record_scope_change)
        del os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE']


    def test_json_token_notype(self):
        """Verify strict token type parsing only when configured. """
        self.assertEqual(parse_token_response(self.json_notype), self.json_notype_dict)
        try:
            os.environ['OAUTHLIB_STRICT_TOKEN_TYPE'] = '1'
            self.assertRaises(MissingTokenTypeError, parse_token_response, self.json_notype)
        finally:
            del os.environ['OAUTHLIB_STRICT_TOKEN_TYPE']

    def test_url_encoded_token_response(self):
        """Verify fallback parameter parsing and validation for token responses. """
        self.assertEqual(parse_token_response(self.url_encoded_response), self.json_dict)
        self.assertRaises(AccessDeniedError, parse_token_response, self.url_encoded_error)
        self.assertRaises(MissingTokenError, parse_token_response, self.url_encoded_notoken)

        scope_changes_recorded = []
        def record_scope_change(sender, message, old, new):
            scope_changes_recorded.append((message, old, new))

        os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
        signals.scope_changed.connect(record_scope_change)
        try:
            token = parse_token_response(self.url_encoded_response, scope='aaa')
            self.assertEqual(len(scope_changes_recorded), 1)
            message, old, new = scope_changes_recorded[0]
            for scope in new + old:
                self.assertIn(scope, message)
            self.assertEqual(old, ['aaa'])
            self.assertEqual(set(new), {'abc', 'def'})
        finally:
            signals.scope_changed.disconnect(record_scope_change)
        del os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE']


    def test_parse_expires(self):
        for title, arg, expected in [
                ('none', (None, None), (None, None, None)),
                ('expires_in only', (3600, None), (3600, 4600, 4600)),
                ('expires_in and expires_at', (3600, 200), (3600, 200, 200)),
                ('expires_in and expires_at float', (3600, 200.42), (3600, 200.42, 200.42)),
                ('expires_in and expires_at str-int', (3600, "200"), (3600, 200, 200)),
                ('expires_in and expires_at str-float', (3600, "200.42"), (3600, 200.42, 200.42)),
                ('expires_in float only', (3600.12, None), (3600, 4600, 4600)),
                ('expires_in float and expires_at', (3600.12, 200), (3600, 200, 200)),
                ('expires_in float and expires_at float', (3600.12, 200.42), (3600, 200.42, 200.42)),
                ('expires_in float and expires_at str-int', (3600.12, "200"), (3600, 200, 200)),
                ('expires_in float and expires_at str-float', (3600.12, "200.42"), (3600, 200.42, 200.42)),
                ('expires_in str only', ("3600", None), (3600, 4600, 4600)),
                ('expires_in str and expires_at', ("3600", 200), (3600, 200, 200)),
                ('expires_in str and expires_at float', ("3600", 200.42), (3600, 200.42, 200.42)),
                ('expires_in str and expires_at str-int', ("3600", "200"), (3600, 200, 200)),
                ('expires_in str and expires_at str-float', ("3600", "200.42"), (3600, 200.42, 200.42)),
        ]:
            with self.subTest(msg=title):
                params = {
                    "expires_in": arg[0],
                    "expires_at": arg[1]
                }
                self.assertEqual(expected, parse_expires(params))


class NormalizeRequestParametersTests(TestCase):

    def basic(self, user, password):
        credentials = base64.b64encode(
            ('%s:%s' % (user, password)).encode('utf-8')).decode('ascii')
        return {'Authorization': 'Basic ' + credentials}

    def normalize_error(self, **kwargs):
        try:
            normalize_request_parameters(**kwargs)
        except InvalidRequestError as e:
            return e
        return None

    def test_lenient_preserves_legal_request(self):
        # A request that was valid before must produce the same parameters
        # as the historical dict(query) updated by dict(body) behaviour.
        params = normalize_request_parameters(
            query='response_type=code&client_id=foo&scope=all+of+them',
            body='grant_type=authorization_code&code=abc&redirect_uri=https%3A%2F%2Fback.to%2Fme')
        self.assertEqual(params, {
            'response_type': 'code',
            'client_id': 'foo',
            'scope': 'all of them',
            'grant_type': 'authorization_code',
            'code': 'abc',
            'redirect_uri': 'https://back.to/me',
        })

    def test_duplicate_identical_values_merge(self):
        params = normalize_request_parameters(
            body='grant_type=password&grant_type=password&client_id=a&client_id=a')
        self.assertEqual(params, {'grant_type': 'password', 'client_id': 'a'})

    def test_duplicate_identical_across_query_and_body_merge(self):
        params = normalize_request_parameters(
            query='client_id=foo', body='client_id=foo&grant_type=password')
        self.assertEqual(params, {'client_id': 'foo', 'grant_type': 'password'})

    def test_duplicate_critical_parameter_rejected(self):
        for body in ('grant_type=password&grant_type=client_credentials',
                     'grant_type=client_credentials&grant_type=password'):
            with self.subTest(body=body):
                self.assertRaises(InvalidRequestError,
                                  normalize_request_parameters, body=body)

    def test_duplicate_scope_rejected_regardless_of_order(self):
        # scope=read&scope=admin and its permutation must give the same,
        # stable invalid_request outcome; values are never merged and the
        # first/last value is never silently picked.
        errors = [self.normalize_error(body=body)
                  for body in ('scope=read&scope=admin',
                               'scope=admin&scope=read')]
        self.assertIsNotNone(errors[0])
        self.assertIsNotNone(errors[1])
        self.assertEqual(errors[0].error, 'invalid_request')
        self.assertEqual(errors[0].json, errors[1].json)

    def test_duplicate_rejected_in_strict_mode_for_any_parameter(self):
        body = 'grant_type=password&extra=a&extra=b'
        self.assertEqual(
            normalize_request_parameters(body=body, strict=False),
            {'grant_type': 'password', 'extra': 'b'})
        self.assertRaises(InvalidRequestError, normalize_request_parameters,
                          body=body, strict=True)

    def test_strict_mode_default_from_environment(self):
        body = 'extra=a&extra=b'
        os.environ['OAUTHLIB_STRICT_PARAMETERS'] = '1'
        try:
            self.assertRaises(InvalidRequestError,
                              normalize_request_parameters, body=body)
        finally:
            del os.environ['OAUTHLIB_STRICT_PARAMETERS']
        self.assertEqual(normalize_request_parameters(body=body),
                         {'extra': 'b'})

    def test_encoding_normalized_before_comparison(self):
        # %XX hex case, + vs %20 and encoded parameter names all decode to
        # the same value and therefore merge instead of conflicting.
        params = normalize_request_parameters(body=(
            'scope=read+write&scope=read%20write&'
            'client_id=%66oo&client_id=foo&'
            'redirect_uri=https%3A%2F%2Fa.b%2Fc&redirect_uri=https%3A%2f%2Fa.b%2Fc'))
        self.assertEqual(params, {
            'scope': 'read write',
            'client_id': 'foo',
            'redirect_uri': 'https://a.b/c',
        })

    def test_plus_and_percent_2b_are_distinct(self):
        self.assertEqual(normalize_request_parameters(body='scope=a+b'),
                         {'scope': 'a b'})
        self.assertEqual(normalize_request_parameters(body='scope=a%2Bb'),
                         {'scope': 'a+b'})
        self.assertRaises(InvalidRequestError, normalize_request_parameters,
                          body='scope=a+b&scope=a%2Bb')

    def test_empty_value_and_missing_value_are_equal(self):
        self.assertEqual(normalize_request_parameters(body='scope&scope='),
                         {'scope': ''})
        self.assertRaises(InvalidRequestError, normalize_request_parameters,
                          body='scope=&scope=read')

    def test_parameter_names_remain_case_sensitive(self):
        params = normalize_request_parameters(body='Scope=a&scope=a')
        self.assertEqual(params, {'Scope': 'a', 'scope': 'a'})

    def test_query_body_conflict_on_critical_parameter_rejected(self):
        # A credential in both query and body follows the single documented
        # priority (body over query) in lenient mode, and is rejected in
        # strict mode.
        params = normalize_request_parameters(
            query='client_id=foo', body='client_id=bar')
        self.assertEqual(params, {'client_id': 'bar'})
        self.assertRaises(InvalidRequestError, normalize_request_parameters,
                          query='client_id=foo', body='client_id=bar',
                          strict=True)

    def test_query_body_conflict_on_non_credential_rejected(self):
        # scope is security-critical but not a credential: conflicting
        # values across query and body are always rejected.
        self.assertRaises(InvalidRequestError, normalize_request_parameters,
                          query='scope=read', body='scope=admin')

    def test_credential_priority_lenient(self):
        # Authorization header wins over body, body wins over query.
        headers = self.basic('header-id', 'header-secret')
        params = normalize_request_parameters(
            query='client_id=query-id&client_secret=query-secret',
            body='client_id=body-id&client_secret=body-secret',
            headers=headers)
        self.assertEqual(params, {'client_id': 'header-id',
                                  'client_secret': 'header-secret'})
        params = normalize_request_parameters(
            query='client_id=query-id', body='client_id=body-id&grant_type=password')
        self.assertEqual(params['client_id'], 'body-id')

    def test_credential_in_multiple_locations_rejected_in_strict_mode(self):
        headers = self.basic('header-id', 'header-secret')
        self.assertRaises(InvalidRequestError, normalize_request_parameters,
                          body='client_id=body-id', headers=headers,
                          strict=True)

    def test_basic_credentials_are_form_decoded_once(self):
        headers = self.basic('my%20client', 'sec%2Bret')
        params = normalize_request_parameters(headers=headers)
        self.assertEqual(params, {'client_id': 'my client',
                                  'client_secret': 'sec+ret'})

    def test_client_secret_bytes_preserved(self):
        # Decoded exactly once, never stripped, re-encoded or truncated.
        params = normalize_request_parameters(
            body='client_secret=%20a%2Fb%20c%25%20')
        self.assertEqual(params, {'client_secret': ' a/b c% '})

    def test_error_does_not_echo_secret(self):
        try:
            normalize_request_parameters(
                body='client_secret=sup3rs3cr3t&client_secret=0th3rvalu3')
        except InvalidRequestError as e:
            self.assertNotIn('sup3rs3cr3t', e.json)
            self.assertNotIn('0th3rvalu3', e.json)
            self.assertNotIn('sup3rs3cr3t', str(e))
        else:
            self.fail('duplicate client_secret was not rejected')

    def test_malformed_encoding(self):
        body = 'grant_type=password&scope=%GG'
        self.assertRaises(InvalidRequestError, normalize_request_parameters,
                          body=body, strict=True)
        # Lenient mode matches the historical behaviour of ignoring a body
        # that is not valid x-www-form-urlencoded data.
        self.assertEqual(normalize_request_parameters(body=body), {})

    def test_deterministic_across_repeats_and_permutations(self):
        bodies = ('grant_type=password&code_verifier=a&code_verifier=b',
                  'code_verifier=b&grant_type=password&code_verifier=a',
                  'code_verifier=a&code_verifier=b&grant_type=password')
        outcomes = [self.normalize_error(body=body) for body in bodies]
        outcomes = [e.json if e else 'ok' for e in outcomes]
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertEqual(outcomes[1], outcomes[2])
        # Parsing the same input twice always gives the same result.
        body = 'grant_type=password&username=a&extra=1&extra=1'
        self.assertEqual(normalize_request_parameters(body=body),
                         normalize_request_parameters(body=body))
