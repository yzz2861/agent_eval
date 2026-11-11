"""Redirect URI registration and canonical matching.

The registry deliberately normalizes only differences that do not change
what the URI means.  Anything ambiguous is rejected instead of guessed at.
"""
import unicodedata
import urllib.parse as urlparse

from oauthlib.uri_validate import is_absolute_uri


class RedirectURIError(ValueError):
    """A redirect URI cannot be canonicalized or registered safely."""


class DuplicateRedirectURIError(RedirectURIError):
    """Two registered spellings canonicalize to the same URI."""


class WildcardRedirectURIError(RedirectURIError):
    """Wildcards are not permitted in a redirect URI registry."""


_UNRESERVED = frozenset(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
)
_HEX_DIGITS = frozenset('0123456789abcdefABCDEF')
_DEFAULT_PORTS = {'http': 80, 'https': 443}
_LOOPBACK_HOSTS = frozenset(('127.0.0.1', '::1'))


def _reject_control_characters(value):
    for char in value:
        if unicodedata.category(char) == 'Cc':
            raise RedirectURIError('Redirect URI must not contain control characters.')


def _normalize_pct_encoded(value, *, component, reject_wildcard=False,
                           reject_backslash=False):
    """Normalize percent escapes without changing reserved characters.

    Escapes for unreserved characters are decoded, as RFC 3986 section 6.2.2.2
    requires when comparing URIs.  Other escapes are kept, with uppercase hex,
    so they remain distinct from their literal delimiter characters.
    """
    normalized = []
    index = 0
    length = len(value)
    while index < length:
        char = value[index]
        if char != '%':
            if reject_wildcard and char == '*':
                raise WildcardRedirectURIError(
                    'Wildcards are not permitted in registered redirect URIs.')
            normalized.append(char)
            index += 1
            continue

        if index + 2 >= length:
            raise RedirectURIError(
                'Invalid percent escape in redirect URI %s.' % component)
        digits = value[index + 1:index + 3]
        if not all(digit in _HEX_DIGITS for digit in digits):
            raise RedirectURIError(
                'Invalid percent escape in redirect URI %s.' % component)

        byte = int(digits, 16)
        if reject_backslash and byte == 0x5C:
            raise RedirectURIError(
                'Backslashes are not permitted in redirect URIs.')
        if byte < 0x20 or byte == 0x7F:
            raise RedirectURIError(
                'Redirect URI must not contain control characters.')
        if reject_wildcard and byte == 0x2A:
            raise WildcardRedirectURIError(
                'Wildcards are not permitted in registered redirect URIs.')

        if chr(byte) in _UNRESERVED:
            normalized.append(chr(byte))
        else:
            normalized.append('%%%02X' % byte)
        index += 3
    return ''.join(normalized)


class _CanonicalRedirectURI:
    __slots__ = ('has_authority', 'has_query', 'host', 'path', 'port',
                 'query', 'scheme', 'uri')

    def __init__(self, uri, scheme, host, port, path, query, has_query,
                 has_authority):
        self.uri = uri
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
        self.query = query
        self.has_query = has_query
        self.has_authority = has_authority


def _parse_authority(netloc, scheme, reject_wildcard):
    """Return ``(host, port, is_ipv6)`` for a validated authority."""
    if '@' in netloc:
        raise RedirectURIError('Userinfo is not permitted in redirect URIs.')

    if netloc.startswith('['):
        closing = netloc.find(']')
        if closing < 0:
            raise RedirectURIError('Malformed IPv6 host in redirect URI.')
        raw_host = netloc[1:closing]
        remainder = netloc[closing + 1:]
        if remainder and not remainder.startswith(':'):
            raise RedirectURIError('Malformed authority in redirect URI.')
        raw_port = remainder[1:] if remainder else None
        is_ipv6 = True
    else:
        if netloc.count(':') > 1:
            raise RedirectURIError('IPv6 hosts must be enclosed in brackets.')
        if ':' in netloc:
            raw_host, raw_port = netloc.rsplit(':', 1)
        else:
            raw_host, raw_port = netloc, None
        is_ipv6 = False

    if not raw_host:
        raise RedirectURIError('Redirect URI must include a host.')

    host = _normalize_pct_encoded(
        raw_host, component='host', reject_wildcard=reject_wildcard,
        reject_backslash=True)
    if '%' in host:
        raise RedirectURIError(
            'Percent-encoded delimiters are not permitted in redirect URI hosts.')
    host = host.lower()
    if host.endswith('.'):
        raise RedirectURIError(
            'Hostnames with a trailing dot are not permitted in redirect URIs.')

    port = None
    if raw_port is not None:
        if not raw_port or not raw_port.isdigit():
            raise RedirectURIError('Invalid port in redirect URI.')
        port = int(raw_port)
        if not 0 < port <= 65535:
            raise RedirectURIError('Invalid port in redirect URI.')

    if scheme in _DEFAULT_PORTS and port == _DEFAULT_PORTS[scheme]:
        port = None
    return host, port, is_ipv6


def _canonicalize_path(raw_path, reject_wildcard):
    path = _normalize_pct_encoded(
        raw_path, component='path', reject_wildcard=reject_wildcard,
        reject_backslash=True)
    for segment in path.split('/'):
        if segment in ('.', '..'):
            raise RedirectURIError(
                'Dot segments are not permitted in redirect URI paths.')
    return path


def _canonicalize(uri, *, reject_wildcard=False):
    if not isinstance(uri, str) or not uri:
        raise RedirectURIError('Redirect URI must be a non-empty string.')

    _reject_control_characters(uri)
    if '\\' in uri:
        raise RedirectURIError('Backslashes are not permitted in redirect URIs.')
    if '#' in uri:
        raise RedirectURIError('Fragments are not permitted in redirect URIs.')
    if not is_absolute_uri(uri):
        raise RedirectURIError('Redirect URI must be an absolute URI.')

    try:
        parsed = urlparse.urlsplit(uri)
    except ValueError as error:
        raise RedirectURIError('Invalid redirect URI: %s' % error) from error
    scheme = parsed.scheme.lower()
    if not scheme:
        raise RedirectURIError('Redirect URI must include a scheme.')

    # ``urlsplit`` treats an empty authority the same as no authority.
    # Keep the distinction so that malformed http(s) URIs cannot become
    # opaque paths by accident.
    has_authority = parsed.netloc != '' or uri[len(scheme) + 1:].startswith('//')
    if scheme in ('http', 'https') and not parsed.netloc:
        raise RedirectURIError('HTTP redirect URIs must include a host.')

    if has_authority:
        if parsed.username is not None or parsed.password is not None:
            raise RedirectURIError('Userinfo is not permitted in redirect URIs.')
        host, port, is_ipv6 = _parse_authority(
            parsed.netloc, scheme, reject_wildcard)
    else:
        host, port, is_ipv6 = None, None, False

    path = _canonicalize_path(parsed.path, reject_wildcard)

    query = _normalize_pct_encoded(
        parsed.query, component='query', reject_wildcard=reject_wildcard)
    has_query = '?' in uri

    if has_authority:
        netloc = '[%s]' % host if is_ipv6 else host
        if port is not None:
            netloc += ':%d' % port
    else:
        netloc = ''

    canonical = scheme + ':'
    if has_authority:
        canonical += '//' + netloc
    canonical += path
    if has_query:
        canonical += '?' + query

    return _CanonicalRedirectURI(
        canonical, scheme, host, port, path, query, has_query, has_authority)


def canonicalize_redirect_uri(redirect_uri):
    """Return the canonical form of ``redirect_uri``.

    :raises RedirectURIError: if the URI contains an ambiguous or unsafe
        difference that URL normalization cannot resolve, or a wildcard.
    """
    return _canonicalize(redirect_uri, reject_wildcard=True).uri


normalize_redirect_uri = canonicalize_redirect_uri
canonical_redirect_uri = canonicalize_redirect_uri


class RedirectURIRegistry:
    """A per-client registry of redirect URIs.

    Registration normalizes only harmless spelling differences.  Matching
    returns the canonical spelling of the request URI, including the actual
    port for registered loopback callbacks, so that the value used for the
    browser redirect, authorization code binding, and token confirmation are
    all identical.
    """

    def __init__(self, registrations=None):
        self._registrations = {}
        if registrations:
            items = (registrations.items()
                     if hasattr(registrations, 'items') else registrations)
            for client_id, redirect_uris in items:
                self.register_many(client_id, redirect_uris)

    def register(self, client_id, redirect_uri):
        """Register ``redirect_uri`` for ``client_id`` and return its canonical form."""
        canonical_uri = _canonicalize(
            redirect_uri, reject_wildcard=True).uri
        client_registrations = self._registrations.setdefault(client_id, {})
        if canonical_uri in client_registrations:
            existing = client_registrations[canonical_uri]
            raise DuplicateRedirectURIError(
                'Redirect URI %r for client %r canonicalizes to %r, which is '
                'already registered as %r.' % (
                    redirect_uri, client_id, canonical_uri, existing))
        client_registrations[canonical_uri] = redirect_uri
        return canonical_uri

    register_uri = register
    register_redirect_uri = register
    add = register
    add_redirect_uri = register

    def register_many(self, client_id, redirect_uris):
        """Register multiple redirect URIs for one client atomically."""
        if isinstance(redirect_uris, str):
            redirect_uris = (redirect_uris,)
        existing = self._registrations.get(client_id, {})
        pending = {}
        for redirect_uri in redirect_uris:
            canonical_uri = _canonicalize(
                redirect_uri, reject_wildcard=True).uri
            if canonical_uri in existing or canonical_uri in pending:
                first = existing.get(canonical_uri, pending[canonical_uri])
                raise DuplicateRedirectURIError(
                    'Redirect URI %r for client %r canonicalizes to %r, which '
                    'is already registered as %r.' % (
                        redirect_uri, client_id, canonical_uri, first))
            pending[canonical_uri] = redirect_uri

        if pending:
            self._registrations.setdefault(client_id, {}).update(pending)
        return list(pending)

    def canonicalize(self, redirect_uri):
        """Return the canonical form of a request URI, rejecting wildcards."""
        return _canonicalize(redirect_uri, reject_wildcard=True).uri

    def match(self, client_id, redirect_uri):
        """Return the canonical request URI if it is registered, else ``None``.

        A registered loopback URI without a port (``http://127.0.0.1/...`` or
        ``http://[::1]/...``) accepts any valid port.  The returned value keeps
        the actual request port so it can be bound to the authorization code.
        """
        try:
            canonical = _canonicalize(redirect_uri, reject_wildcard=True)
        except RedirectURIError:
            return None

        client_registrations = self._registrations.get(client_id)
        if not client_registrations:
            return None
        if canonical.uri in client_registrations:
            return canonical.uri

        if (canonical.scheme == 'http'
                and canonical.host in _LOOPBACK_HOSTS
                and canonical.port is not None):
            loopback_uri = self._without_port(canonical)
            if loopback_uri in client_registrations:
                return canonical.uri

        return None

    match_redirect_uri = match
    get_canonical = match
    get_canonical_uri = match
    lookup = match
    resolve = match
    match_uri = match

    def is_registered(self, client_id, redirect_uri):
        """Return whether ``redirect_uri`` matches a registration for the client."""
        return self.match(client_id, redirect_uri) is not None

    is_match = is_registered
    matches = is_registered

    def validate(self, client_id, redirect_uri):
        """Boolean form of :meth:`match`."""
        return self.is_registered(client_id, redirect_uri)

    def registered_uris(self, client_id):
        """Return a tuple of canonical redirect URIs registered for the client."""
        return tuple(self._registrations.get(client_id, ()))

    @property
    def registrations(self):
        """Return a read-only snapshot of canonical URIs per client."""
        return {client_id: tuple(entries)
                for client_id, entries in self._registrations.items()}

    def __contains__(self, item):
        client_id, redirect_uri = item
        return self.is_registered(client_id, redirect_uri)

    @staticmethod
    def _without_port(canonical):
        netloc = '[%s]' % canonical.host if canonical.host == '::1' else canonical.host
        uri = canonical.scheme + '://' + netloc + canonical.path
        if canonical.has_query:
            uri += '?' + canonical.query
        return uri


# Common spelling variant, kept as an alias for callers that title-case
# acronyms differently.
RedirectUriRegistry = RedirectURIRegistry
RedirectURIMatcher = RedirectURIRegistry
