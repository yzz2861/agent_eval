"""
oauthlib.oauth2.rfc6749.tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains methods for adding two types of access tokens to requests.

- Bearer https://tools.ietf.org/html/rfc6750
- MAC https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01
"""
import hashlib
import hmac
import re
import warnings
from binascii import b2a_base64
from collections.abc import Mapping
from urllib.parse import urlparse

from oauthlib import common
from oauthlib.common import add_params_to_qs, add_params_to_uri
from oauthlib.uri_validate import is_uri_reference

from . import utils


MAX_BEARER_CHALLENGE_LENGTH = 8192
MAX_CHALLENGE_LENGTH = MAX_BEARER_CHALLENGE_LENGTH

_AUTH_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_CHALLENGE_PARAM_NAMES = (
    'realm', 'error', 'error_description', 'scope', 'error_uri',
)


def _check_challenge_text(name, value):
    """Reject values that cannot safely appear in an HTTP field value."""
    if not isinstance(value, str):
        raise ValueError('%s must be a string' % name)
    for char in value:
        codepoint = ord(char)
        if char in '\r\n':
            raise ValueError('%s must not contain CR or LF characters' % name)
        if codepoint < 0x20 or codepoint == 0x7f:
            raise ValueError('%s must not contain control characters' % name)
        if codepoint > 0x7e:
            raise ValueError('%s must contain ASCII characters only' % name)
    return value


def _quote_challenge_value(name, value):
    _check_challenge_text(name, value)
    return '"{}"'.format(
        value.replace('\\', '\\\\').replace('"', '\\"'))


def _is_scope_token(token):
    return bool(token) and all(
        ord(char) == 0x21 or 0x23 <= ord(char) <= 0x5b or 0x5d <= ord(char) <= 0x7e
        for char in token
    )


def _normalize_scope(scope):
    """Return a deterministic, space-delimited scope set."""
    if scope is None:
        return None
    if isinstance(scope, str):
        _check_challenge_text('scope', scope)
        raw_tokens = scope.split(' ')
    elif isinstance(scope, (set, frozenset, list, tuple)):
        raw_tokens = []
        for item in scope:
            if not isinstance(item, str):
                raise ValueError('scope entries must be strings')
            _check_challenge_text('scope', item)
            raw_tokens.extend(item.split(' '))
    else:
        raise ValueError('scope must be a string, set, tuple, or list')

    tokens = {token for token in raw_tokens if token}
    for token in tokens:
        if not _is_scope_token(token):
            raise ValueError('scope contains an invalid scope token')
    return ' '.join(sorted(tokens)) if tokens else ''


def _check_error_uri(uri):
    _check_challenge_text('error_uri', uri)
    if not uri or not is_uri_reference(uri):
        raise ValueError('error_uri must be a valid URI reference')


def _format_bearer_challenge(realm=None, error=None, error_description=None,
                             scope=None, error_uri=None, *, strict=False,
                             max_length=MAX_BEARER_CHALLENGE_LENGTH,
                             description=None, uri=None):
    """Build a canonical RFC 6750 ``Bearer`` challenge value.

    Values are emitted as quoted strings and escaped according to the HTTP
    quoted-string rules.  ``scope`` accepts a string or a set-like collection;
    duplicate scope tokens are removed and the remaining tokens are sorted.

    :param realm: Protection space.  An explicitly empty realm is rejected.
    :param error: OAuth error code.
    :param error_description: Human-readable error description.
    :param scope: Required scope, as a string or collection of strings.
    :param error_uri: URI reference with human-readable error information.
    :param strict: Enable strict validation.
    :param max_length: Maximum generated challenge length.
    :param description: Alias for ``error_description``.
    :param uri: Alias for ``error_uri``.
    :raises ValueError: if a value cannot safely be represented in a header.
    """
    if description is not None:
        if error_description is not None and error_description != description:
            raise ValueError('description and error_description disagree')
        error_description = description
    if uri is not None:
        if error_uri is not None and error_uri != uri:
            raise ValueError('uri and error_uri disagree')
        error_uri = uri

    if realm is not None:
        _check_challenge_text('realm', realm)
        if not realm:
            raise ValueError('realm must not be empty')
    if error is not None:
        _check_challenge_text('error', error)
        if not error:
            raise ValueError('error must not be empty')
    if error_description is not None:
        _check_challenge_text('error_description', error_description)
    if error_uri is not None:
        _check_error_uri(error_uri)

    normalized_scope = _normalize_scope(scope)
    if strict and scope is not None and not normalized_scope:
        raise ValueError('scope must not be empty')

    authvalues = []
    if realm is not None:
        authvalues.append('realm={}'.format(_quote_challenge_value('realm', realm)))
    if error is not None:
        authvalues.append('error={}'.format(_quote_challenge_value('error', error)))
    if error_description is not None:
        authvalues.append('error_description={}'.format(
            _quote_challenge_value('error_description', error_description)))
    if normalized_scope:
        authvalues.append('scope={}'.format(
            _quote_challenge_value('scope', normalized_scope)))
    if error_uri is not None:
        authvalues.append('error_uri={}'.format(_quote_challenge_value('error_uri', error_uri)))

    challenge = 'Bearer'
    if authvalues:
        challenge += ' ' + ', '.join(authvalues)
    elif strict:
        raise ValueError('Bearer challenge requires at least one auth-param')

    if max_length is not None and len(challenge) > max_length:
        raise ValueError('Bearer challenge exceeds the maximum length')
    return challenge


class BearerChallengeHeaders(dict):
    """Headers mapping for a Bearer challenge.

    The mapping contains the canonical ``WWW-Authenticate`` entry.  String
    operations and comparisons are delegated to that value so callers that
    consume the challenge value directly remain compatible.
    """

    def __init__(self, challenge):
        super().__init__({'WWW-Authenticate': challenge})

    @property
    def value(self):
        return self['WWW-Authenticate']

    def __str__(self):
        return self.value

    def __repr__(self):
        return repr(self.value)

    def __eq__(self, other):
        if isinstance(other, str):
            return self.value == other
        return super().__eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.value)

    def __contains__(self, item):
        return (dict.__contains__(self, item) or
                (isinstance(item, str) and item in self.value))

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return self.value[key]
        return dict.__getitem__(self, key)

    def __getattr__(self, name):
        return getattr(self.value, name)


def prepare_bearer_challenge(*args, **kwargs):
    """Build a canonical RFC 6750 ``Bearer`` challenge.

    The returned mapping contains the ``WWW-Authenticate`` header value and
    also supports direct string comparison and string methods.
    """
    return BearerChallengeHeaders(_format_bearer_challenge(*args, **kwargs))


def prepare_bearer_challenge_headers(*args, **kwargs):
    """Return a ``WWW-Authenticate`` headers mapping for a Bearer challenge."""
    return {'WWW-Authenticate': _format_bearer_challenge(*args, **kwargs)}


build_bearer_challenge = prepare_bearer_challenge
format_bearer_challenge = _format_bearer_challenge
create_bearer_challenge = prepare_bearer_challenge
prepare_www_authenticate = prepare_bearer_challenge


def _consume_token(text, position):
    match = _AUTH_TOKEN_RE.match(text, position)
    if match is None:
        return '', position
    return match.group(0), match.end()


def _consume_quoted_string(text, position):
    value = []
    while position < len(text):
        char = text[position]
        if char == '"':
            return ''.join(value), position + 1
        if char == '\\':
            position += 1
            if position >= len(text):
                raise ValueError('unterminated quoted-string escape')
            char = text[position]
        value.append(char)
        position += 1
    raise ValueError('unterminated quoted-string')


def _parse_bearer_params(text, position):
    params = {}
    while position < len(text):
        name, position = _consume_token(text, position)
        if not name:
            raise ValueError('invalid auth-param name')
        name = name.lower()
        if name in params:
            raise ValueError('duplicate auth-param %s' % name)

        while position < len(text) and text[position] == ' ':
            position += 1
        if position >= len(text) or text[position] != '=':
            raise ValueError('auth-param is missing a value')
        position += 1
        while position < len(text) and text[position] == ' ':
            position += 1
        if position >= len(text):
            raise ValueError('auth-param is missing a value')

        if text[position] == '"':
            value, position = _consume_quoted_string(text, position + 1)
        else:
            value, position = _consume_token(text, position)
            if not value:
                raise ValueError('auth-param is missing a value')
        params[name] = value

        while position < len(text) and text[position] == ' ':
            position += 1
        if position < len(text):
            if text[position] != ',':
                raise ValueError('invalid data after auth-param value')
            position += 1
            while position < len(text) and text[position] == ' ':
                position += 1
            if position >= len(text):
                raise ValueError('trailing comma in challenge')
    return params


def _validate_parsed_params(params, strict):
    if 'realm' in params and not params['realm']:
        raise ValueError('realm must not be empty')
    if strict and 'realm' not in params:
        raise ValueError('Bearer challenge is missing realm')

    if 'scope' in params:
        params['scope'] = _normalize_scope(params['scope'])
    if 'error_uri' in params:
        _check_error_uri(params['error_uri'])
    if 'error' in params and not params['error']:
        raise ValueError('error must not be empty')


def _canonicalize_params(params):
    result = {}
    for name in _CHALLENGE_PARAM_NAMES:
        if name in params:
            result[name] = params[name]
    for name in sorted(params):
        if name not in result:
            result[name] = params[name]
    return result


def parse_bearer_challenge(challenge=None, *, strict=True,
                           max_length=MAX_BEARER_CHALLENGE_LENGTH,
                           header=None, headers=None):
    """Parse a ``WWW-Authenticate`` Bearer challenge.

    The parser accepts either a header value or a mapping containing a
    ``WWW-Authenticate`` entry.  Auth-scheme and parameter names are matched
    case-insensitively and returned with canonical lowercase names.

    :param challenge: Challenge string or headers mapping.
    :param strict: Require a non-empty ``realm`` parameter and validate it.
    :param max_length: Maximum accepted challenge length.
    :return: Parsed challenge parameters.
    :raises ValueError: if the challenge is malformed or not a Bearer challenge.
    """
    if headers is not None:
        if challenge is not None:
            raise ValueError('challenge and headers cannot both be provided')
        challenge = headers
    if header is not None:
        if challenge is not None:
            raise ValueError('challenge and header cannot both be provided')
        challenge = header
    if challenge is None:
        raise ValueError('challenge must not be empty')

    if isinstance(challenge, Mapping):
        for name, value in challenge.items():
            if str(name).lower() == 'www-authenticate':
                challenge = value
                break
        else:
            raise ValueError('WWW-Authenticate header is missing')

    if not isinstance(challenge, str):
        raise ValueError('challenge must be a string')
    if max_length is not None and len(challenge) > max_length:
        raise ValueError('Bearer challenge exceeds the maximum length')
    _check_challenge_text('challenge', challenge)

    text = challenge.strip(' ')
    if not text:
        raise ValueError('challenge must not be empty')

    scheme, position = _consume_token(text, 0)
    if not scheme or scheme.lower() != 'bearer':
        raise ValueError('unsupported authentication scheme')
    if position >= len(text) or text[position] != ' ':
        raise ValueError('Bearer challenge is missing auth-param values')
    while position < len(text) and text[position] == ' ':
        position += 1

    params = _parse_bearer_params(text, position)
    _validate_parsed_params(params, strict)
    return _canonicalize_params(params)


parse_www_authenticate = parse_bearer_challenge
parse_bearer_challenge_header = parse_bearer_challenge
parse_www_authenticate_header = parse_bearer_challenge
parse_bearer_www_authenticate = parse_bearer_challenge


class OAuth2Token(dict):

    def __init__(self, params, old_scope=None):
        super().__init__(params)
        self._new_scope = None
        if params.get('scope'):
            self._new_scope = set(utils.scope_to_list(params['scope']))
        if old_scope is not None:
            self._old_scope = set(utils.scope_to_list(old_scope))
            if self._new_scope is None:
                # the rfc says that if the scope hasn't changed, it's optional
                # in params so set the new scope to the old scope
                self._new_scope = self._old_scope
        else:
            self._old_scope = self._new_scope

    @property
    def scope_changed(self):
        return self._new_scope != self._old_scope

    @property
    def old_scope(self):
        return utils.list_to_scope(self._old_scope)

    @property
    def old_scopes(self):
        return list(self._old_scope)

    @property
    def scope(self):
        return utils.list_to_scope(self._new_scope)

    @property
    def scopes(self):
        return list(self._new_scope)

    @property
    def missing_scopes(self):
        return list(self._old_scope - self._new_scope)

    @property
    def additional_scopes(self):
        return list(self._new_scope - self._old_scope)


def prepare_mac_header(token, uri, key, http_method,
                       nonce=None,
                       headers=None,
                       body=None,
                       ext='',
                       hash_algorithm='hmac-sha-1',
                       issue_time=None,
                       draft=0):
    """Add an `MAC Access Authentication`_ signature to headers.

    Unlike OAuth 1, this HMAC signature does not require inclusion of the
    request payload/body, neither does it use a combination of client_secret
    and token_secret but rather a mac_key provided together with the access
    token.

    Currently two algorithms are supported, "hmac-sha-1" and "hmac-sha-256",
    `extension algorithms`_ are not supported.

    Example MAC Authorization header, linebreaks added for clarity

    Authorization: MAC id="h480djs93hd8",
                       nonce="1336363200:dj83hs9s",
                       mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="

    .. _`MAC Access Authentication`: https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01
    .. _`extension algorithms`: https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01#section-7.1

    :param token:
    :param uri: Request URI.
    :param key: MAC given provided by token endpoint.
    :param http_method: HTTP Request method.
    :param nonce:
    :param headers: Request headers as a dictionary.
    :param body:
    :param ext:
    :param hash_algorithm: HMAC algorithm provided by token endpoint.
    :param issue_time: Time when the MAC credentials were issued (datetime).
    :param draft: MAC authentication specification version.
    :return: headers dictionary with the authorization field added.
    """
    http_method = http_method.upper()
    host, port = utils.host_from_uri(uri)

    common.check_http_header_value('nonce', nonce)
    common.check_http_header_value('ext', ext)

    if hash_algorithm.lower() == 'hmac-sha-1':
        h = hashlib.sha1
    elif hash_algorithm.lower() == 'hmac-sha-256':
        h = hashlib.sha256
    else:
        raise ValueError('unknown hash algorithm')

    if draft == 0:
        nonce = nonce or '{}:{}'.format(utils.generate_age(issue_time),
                                          common.generate_nonce())
    else:
        ts = common.generate_timestamp()
        nonce = common.generate_nonce()

    _sch, _net, path, _par, query, _fra = urlparse(uri)

    request_uri = path + '?' + query if query else path

    # Hash the body/payload
    if body is not None and draft == 0:
        body = body.encode('utf-8')
        bodyhash = b2a_base64(h(body).digest())[:-1].decode('utf-8')
    else:
        bodyhash = ''

    # Create the normalized base string
    base = []
    if draft == 0:
        base.append(nonce)
    else:
        base.append(ts)
        base.append(nonce)
    base.append(http_method.upper())
    base.append(request_uri)
    base.append(host)
    base.append(port)
    if draft == 0:
        base.append(bodyhash)
    base.append(ext or '')
    base_string = '\n'.join(base) + '\n'

    # hmac struggles with unicode strings - http://bugs.python.org/issue5285
    if isinstance(key, str):
        key = key.encode('utf-8')
    sign = hmac.new(key, base_string.encode('utf-8'), h)
    sign = b2a_base64(sign.digest())[:-1].decode('utf-8')

    header = []
    header.append('MAC id="%s"' % token)
    if draft != 0:
        header.append('ts="%s"' % ts)
    header.append('nonce="%s"' % nonce)
    if bodyhash:
        header.append('bodyhash="%s"' % bodyhash)
    if ext:
        header.append('ext="%s"' % ext)
    header.append('mac="%s"' % sign)

    headers = headers or {}
    headers['Authorization'] = ', '.join(header)
    return headers


def prepare_bearer_uri(token, uri):
    """Add a `Bearer Token`_ to the request URI.
    Not recommended, use only if client can't use authorization header or body.

    http://www.example.com/path?access_token=h480djs93hd8

    .. _`Bearer Token`: https://tools.ietf.org/html/rfc6750

    :param token:
    :param uri:
    """
    return add_params_to_uri(uri, [(('access_token', token))])


def prepare_bearer_headers(token, headers=None):
    """Add a `Bearer Token`_ to the request URI.
    Recommended method of passing bearer tokens.

    Authorization: Bearer h480djs93hd8

    .. _`Bearer Token`: https://tools.ietf.org/html/rfc6750

    :param token:
    :param headers:
    """
    headers = headers or {}
    headers['Authorization'] = 'Bearer %s' % token
    return headers


def prepare_bearer_body(token, body=''):
    """Add a `Bearer Token`_ to the request body.

    access_token=h480djs93hd8

    .. _`Bearer Token`: https://tools.ietf.org/html/rfc6750

    :param token:
    :param body:
    """
    return add_params_to_qs(body, [(('access_token', token))])


def random_token_generator(request, refresh_token=False):
    """
    :param request: OAuthlib request.
    :type request: oauthlib.common.Request
    :param refresh_token:
    """
    return common.generate_token()


def signed_token_generator(private_pem, **kwargs):
    """
    :param private_pem:
    """
    def signed_token_generator(request):
        request.claims = kwargs
        return common.generate_signed_token(private_pem, request)

    return signed_token_generator


def get_token_from_header(request):
    """
    Helper function to extract a token from the request header.

    :param request: OAuthlib request.
    :type request: oauthlib.common.Request
    :return: Return the token or None if the Authorization header is malformed.
    """
    token = None

    if 'Authorization' in request.headers:
        split_header = request.headers.get('Authorization').split()
        if len(split_header) == 2 and split_header[0].lower() == 'bearer':
            token = split_header[1]
    else:
        token = request.access_token

    return token


class TokenBase:
    __slots__ = ()

    def __call__(self, request, refresh_token=False):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def estimate_type(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        raise NotImplementedError('Subclasses must implement this method.')


class BearerToken(TokenBase):
    __slots__ = (
        'request_validator', 'token_generator',
        'refresh_token_generator', 'expires_in'
    )

    def __init__(self, request_validator=None, token_generator=None,
                 expires_in=None, refresh_token_generator=None):
        self.request_validator = request_validator
        self.token_generator = token_generator or random_token_generator
        self.refresh_token_generator = (
            refresh_token_generator or self.token_generator
        )
        self.expires_in = expires_in or 3600

    def create_token(self, request, refresh_token=False, **kwargs):
        """
        Create a BearerToken, by default without refresh token.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param refresh_token:
        """
        if "save_token" in kwargs:
            warnings.warn("`save_token` has been deprecated, it was not called internally."
                          "If you do, call `request_validator.save_token()` instead.",
                          DeprecationWarning)

        expires_in = self.expires_in(request) if callable(self.expires_in) else self.expires_in

        request.expires_in = expires_in

        token = {
            'access_token': self.token_generator(request),
            'expires_in': expires_in,
            'token_type': 'Bearer',
        }

        # If provided, include - this is optional in some cases https://tools.ietf.org/html/rfc6749#section-3.3 but
        # there is currently no mechanism to coordinate issuing a token for only a subset of the requested scopes so
        # all tokens issued are for the entire set of requested scopes.
        if request.scopes is not None:
            token['scope'] = ' '.join(request.scopes)

        if refresh_token:
            if (request.refresh_token and
                    not self.request_validator.rotate_refresh_token(request)):
                token['refresh_token'] = request.refresh_token
            else:
                token['refresh_token'] = self.refresh_token_generator(request)

        token.update(request.extra_credentials or {})
        return OAuth2Token(token)

    def validate_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        token = get_token_from_header(request)
        return self.request_validator.validate_bearer_token(
            token, request.scopes, request)

    def estimate_type(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        if request.headers.get('Authorization', '').split(' ')[0].lower() == 'bearer':
            return 9
        elif request.access_token is not None:
            return 5
        else:
            return 0
