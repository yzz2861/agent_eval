# coding: utf-8
"""
An injectable HTTP fetch policy for CRL and OCSP retrieval.

This module provides a FetchPolicy class that constrains how CRLs and OCSP
responses are fetched over HTTP, and a fetch_url() function that enforces
such a policy. The policy restricts the URL scheme, host and port to
explicit allowlists, rejects loopback and link-local addresses (both as URL
literals and as DNS results), refuses cross-origin redirects, and caps the
response size and request timeout.

Error messages and log records produced by this module never contain a full
URL, so credentials or key material embedded in URL paths, query strings or
request bodies can not leak. Only the origin (scheme://host[:port]) is ever
included.
"""
from __future__ import unicode_literals, division, absolute_import, print_function

import ipaddress
import logging
import socket
import sys

from ._errors import pretty_message
from ._types import str_cls, byte_cls, type_name
from ._urllib import Request
from .errors import FetchPolicyError

if sys.version_info < (3,):
    from urlparse import urlsplit, urljoin
    from urllib2 import build_opener, HTTPRedirectHandler, HTTPError
else:
    from urllib.parse import urlsplit, urljoin
    from urllib.request import build_opener, HTTPRedirectHandler
    from urllib.error import HTTPError


logger = logging.getLogger(__name__)

_SCHEME_DEFAULT_PORTS = {
    'http': 80,
    'https': 443,
}

_REDIRECT_STATUSES = set([301, 302, 303, 307, 308])

# Redirect statuses for which a POST is rewritten to a GET
_REDIRECT_DROP_BODY_STATUSES = set([301, 302, 303])


class _NoRedirectHandler(HTTPRedirectHandler):
    """
    A urllib handler that surfaces redirects as HTTPError instead of
    following them, so the fetch policy can inspect every redirect target
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_default_opener = None


def _get_default_opener():
    global _default_opener
    if _default_opener is None:
        _default_opener = build_opener(_NoRedirectHandler())
    return _default_opener


def _default_resolver(host, port):
    """
    Resolves a host to a list of IP address unicode strings using the OS
    """

    infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    return list(set(info[4][0] for info in infos))


def safe_origin(url):
    """
    Builds a sanitized scheme://host[:port] origin from a URL, dropping any
    userinfo, path, query and fragment so sensitive material in the URL is
    never written to logs or error messages

    :param url:
        A unicode string of the URL

    :return:
        A unicode string of the origin
    """

    try:
        parts = urlsplit(url)
    except ValueError:
        return '<invalid-url>'
    scheme = (parts.scheme or '').lower()
    host = parts.hostname or ''
    try:
        port = parts.port
    except ValueError:
        port = None
    origin = '%s://%s' % (scheme, host)
    if port is not None and port != _SCHEME_DEFAULT_PORTS.get(scheme):
        origin += ':%d' % port
    return origin


def _origin_tuple(url):
    """
    Returns a (scheme, host, port) tuple for origin comparison
    """

    parts = urlsplit(url)
    scheme = (parts.scheme or '').lower()
    host = (parts.hostname or '').lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = _SCHEME_DEFAULT_PORTS.get(scheme)
    return (scheme, host, port)


class FetchResult(object):
    """
    The result of a policy-enforced fetch
    """

    def __init__(self, body, headers, url):
        """
        :param body:
            A byte string of the response body

        :param headers:
            The response headers from the final response, or None if the
            opener did not expose any

        :param url:
            A unicode string of the final URL after any redirects
        """

        self.body = body
        self.headers = headers
        self.url = url


class FetchPolicy(object):
    """
    A policy constraining how CRLs and OCSP responses may be fetched over
    HTTP. All allowlists are explicit: a scheme, host or port that is not
    permitted by the configuration is rejected.
    """

    def __init__(self, allowed_schemes=('http', 'https'), allowed_hosts=None,
                 allowed_ports=None, allow_loopback=False, allow_link_local=False,
                 allow_private=False, max_redirects=3,
                 allow_cross_origin_redirects=False,
                 max_response_size=8 * 1024 * 1024, max_timeout=30, resolver=None):
        """
        :param allowed_schemes:
            A tuple/list of unicode strings of permitted URL schemes.
            Defaults to ("http", "https").

        :param allowed_hosts:
            None, or a tuple/list/set of unicode strings of permitted
            (case-insensitive) hostnames. If None, any host is permitted,
            subject to the IP address checks.

        :param allowed_ports:
            None, or a tuple/list/set of ints of permitted ports. If None,
            only the default port for the scheme (80 for http, 443 for
            https) is permitted.

        :param allow_loopback:
            A bool - if loopback addresses (127.0.0.0/8, ::1) are permitted,
            both as URL literals and as DNS results

        :param allow_link_local:
            A bool - if link-local addresses (169.254.0.0/16, fe80::/10) are
            permitted, both as URL literals and as DNS results

        :param allow_private:
            A bool - if private network addresses (10.0.0.0/8, 172.16.0.0/12,
            192.168.0.0/16, fc00::/7) are permitted as DNS results

        :param max_redirects:
            An int of the maximum number of redirects followed for a single
            fetch

        :param allow_cross_origin_redirects:
            A bool - if a redirect to a different origin (scheme, host or
            port) may be followed. Cross-origin redirect targets are still
            subject to all other policy checks.

        :param max_response_size:
            An int of the maximum number of bytes read from a response

        :param max_timeout:
            A number capping the per-request timeout in seconds

        :param resolver:
            None, or a callable accepting (host, port) and returning an
            iterable of unicode strings of IP addresses. Used to check DNS
            results before connecting; re-invoked for every redirect hop.
            If None, socket.getaddrinfo() is used.
        """

        if isinstance(allowed_schemes, str_cls) or not isinstance(allowed_schemes, (tuple, list, set, frozenset)):
            raise TypeError(pretty_message(
                '''
                allowed_schemes must be a tuple or list of unicode strings,
                not %s
                ''',
                type_name(allowed_schemes)
            ))
        self.allowed_schemes = frozenset(scheme.lower() for scheme in allowed_schemes)

        if allowed_hosts is not None:
            if isinstance(allowed_hosts, str_cls) or not isinstance(allowed_hosts, (tuple, list, set, frozenset)):
                raise TypeError(pretty_message(
                    '''
                    allowed_hosts must be None or a tuple or list of unicode
                    strings, not %s
                    ''',
                    type_name(allowed_hosts)
                ))
            allowed_hosts = frozenset(host.lower() for host in allowed_hosts)
        self.allowed_hosts = allowed_hosts

        if allowed_ports is not None:
            if not isinstance(allowed_ports, (tuple, list, set, frozenset)):
                raise TypeError(pretty_message(
                    '''
                    allowed_ports must be None or a tuple or list of ints,
                    not %s
                    ''',
                    type_name(allowed_ports)
                ))
            allowed_ports = frozenset(int(port) for port in allowed_ports)
        self.allowed_ports = allowed_ports

        for flag_name, flag_value in [('allow_loopback', allow_loopback),
                                      ('allow_link_local', allow_link_local),
                                      ('allow_private', allow_private),
                                      ('allow_cross_origin_redirects', allow_cross_origin_redirects)]:
            if not isinstance(flag_value, bool):
                raise TypeError(pretty_message(
                    '''
                    %s must be a bool, not %s
                    ''',
                    flag_name,
                    type_name(flag_value)
                ))
            setattr(self, flag_name, flag_value)

        if not isinstance(max_redirects, int) or max_redirects < 0:
            raise TypeError(pretty_message(
                '''
                max_redirects must be a non-negative int, not %s
                ''',
                type_name(max_redirects)
            ))
        self.max_redirects = max_redirects

        if not isinstance(max_response_size, int) or max_response_size < 1:
            raise TypeError(pretty_message(
                '''
                max_response_size must be a positive int, not %s
                ''',
                type_name(max_response_size)
            ))
        self.max_response_size = max_response_size

        if not isinstance(max_timeout, (int, float)) or max_timeout <= 0:
            raise TypeError(pretty_message(
                '''
                max_timeout must be a positive number, not %s
                ''',
                type_name(max_timeout)
            ))
        self.max_timeout = max_timeout

        if resolver is not None and not callable(resolver):
            raise TypeError(pretty_message(
                '''
                resolver must be None or a callable, not %s
                ''',
                type_name(resolver)
            ))
        self.resolver = resolver or _default_resolver

    def check_url(self, url):
        """
        Checks a URL against this policy, resolving the host and validating
        every resulting IP address

        :param url:
            A unicode string of the URL to check

        :raises:
            certvalidator.errors.FetchPolicyError - when the URL is rejected

        :return:
            A tuple of (scheme, host, port) for the permitted URL
        """

        origin = safe_origin(url)

        try:
            parts = urlsplit(url)
        except ValueError:
            raise self._reject('invalid_url', 'the URL could not be parsed', origin)

        scheme = (parts.scheme or '').lower()
        if scheme not in self.allowed_schemes:
            raise self._reject('scheme_not_allowed', 'the URL scheme is not allowed', origin)

        host = parts.hostname
        if not host:
            raise self._reject('invalid_url', 'the URL has no host', origin)
        host = host.lower()

        if self.allowed_hosts is not None and host not in self.allowed_hosts:
            raise self._reject('host_not_allowed', 'the URL host is not allowed', origin)

        try:
            port = parts.port
        except ValueError:
            raise self._reject('invalid_url', 'the URL has an invalid port', origin)

        effective_port = port
        if effective_port is None:
            effective_port = _SCHEME_DEFAULT_PORTS.get(scheme)
        if effective_port is None:
            raise self._reject('port_not_allowed', 'the URL scheme has no default port', origin)

        if self.allowed_ports is not None:
            if effective_port not in self.allowed_ports:
                raise self._reject('port_not_allowed', 'the URL port is not allowed', origin)
        elif effective_port != _SCHEME_DEFAULT_PORTS.get(scheme):
            raise self._reject(
                'port_not_allowed',
                'non-default ports require an explicit allowed_ports entry',
                origin
            )

        self._check_host_addresses(host, effective_port, origin)

        return (scheme, host, effective_port)

    def _check_host_addresses(self, host, port, origin):
        """
        Resolves a host and validates every resulting IP address
        """

        try:
            addresses = self.resolver(host, port)
        except (socket.error, UnicodeError) as e:
            raise self._reject('dns_failure', 'the host could not be resolved: %s' % e, origin)

        addresses = list(addresses or [])
        if not addresses:
            raise self._reject('dns_failure', 'the host did not resolve to any addresses', origin)

        for address in addresses:
            self._check_address(address, origin)

    def _check_address(self, address, origin):
        """
        Validates a single IP address against the blocked network ranges
        """

        if isinstance(address, byte_cls):
            address = address.decode('ascii')

        try:
            ip = ipaddress.ip_address(str_cls(address))
        except ValueError:
            raise self._reject('dns_failure', 'the resolver returned an invalid address', origin)

        if ip.is_loopback and not self.allow_loopback:
            raise self._reject('loopback_address', 'the host resolves to a loopback address', origin)

        if ip.is_link_local and not self.allow_link_local:
            raise self._reject('link_local_address', 'the host resolves to a link-local address', origin)

        if ip.is_private and not self.allow_private:
            raise self._reject('private_address', 'the host resolves to a private address', origin)

        if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            raise self._reject('reserved_address', 'the host resolves to a reserved address', origin)

    def _reject(self, reason, message, origin):
        """
        Logs a policy rejection (origin only, never a full URL) and builds
        the FetchPolicyError for it
        """

        logger.info('HTTP fetch rejected by policy (%s) for origin %s', reason, origin)
        return FetchPolicyError(
            pretty_message(
                '''
                HTTP fetch rejected by policy (%s): %s [origin: %s]
                ''',
                reason,
                message,
                origin
            ),
            reason=reason
        )


def fetch_url(url, headers=None, data=None, timeout=10, policy=None, opener=None):
    """
    Fetches a URL while enforcing a FetchPolicy

    :param url:
        A unicode string of the URL to fetch

    :param headers:
        None or a dict of unicode string header names and values

    :param data:
        None or a byte string of the request body

    :param timeout:
        The number of seconds after which the request should timeout. The
        effective timeout is capped at policy.max_timeout.

    :param policy:
        None or a FetchPolicy object. If None, a default FetchPolicy is
        used.

    :param opener:
        None or a callable with the signature of urllib.request.urlopen(),
        accepting (request, data, timeout) and returning a response object.
        When combined with a policy, the opener must not follow redirects
        itself; it must surface them as urllib.error.HTTPError so the
        policy can inspect every redirect target. If None, an internal
        no-redirect opener is used.

    :raises:
        certvalidator.errors.FetchPolicyError - when the policy rejects the
            URL, a redirect, or the response
        urllib.error.URLError/urllib2.URLError - when a URL/HTTP error occurs
        socket.error - when a socket error occurs

    :return:
        A FetchResult object with the response body, headers and final URL
    """

    if policy is None:
        policy = FetchPolicy()
    elif not isinstance(policy, FetchPolicy):
        raise TypeError(pretty_message(
            '''
            policy must be None or a certvalidator.http_policy.FetchPolicy
            object, not %s
            ''',
            type_name(policy)
        ))

    if opener is None:
        def opener(request, request_data, request_timeout):
            return _get_default_opener().open(request, request_data, request_timeout)

    if timeout is None or timeout > policy.max_timeout:
        timeout = policy.max_timeout

    current_url = url
    current_data = data
    redirect_count = 0

    while True:
        policy.check_url(current_url)

        request = Request(current_url)
        for name, value in (headers or {}).items():
            request.add_header(name, value)

        try:
            response = opener(request, current_data, timeout)
        except HTTPError as e:
            location = e.headers.get('Location') if e.headers is not None else None
            if e.code not in _REDIRECT_STATUSES or not location:
                raise
            if redirect_count >= policy.max_redirects:
                raise policy._reject(
                    'too_many_redirects',
                    'too many redirects',
                    safe_origin(current_url)
                )
            next_url = urljoin(current_url, location)
            if not policy.allow_cross_origin_redirects and _origin_tuple(current_url) != _origin_tuple(next_url):
                raise policy._reject(
                    'cross_origin_redirect',
                    'redirect to a different origin',
                    safe_origin(next_url)
                )
            redirect_count += 1
            current_url = next_url
            if e.code in _REDIRECT_DROP_BODY_STATUSES:
                current_data = None
            continue
        break

    body = response.read(policy.max_response_size + 1)
    if len(body) > policy.max_response_size:
        raise policy._reject(
            'response_too_large',
            'the response exceeds the maximum size of %d bytes' % policy.max_response_size,
            safe_origin(current_url)
        )

    return FetchResult(body, getattr(response, 'headers', None), current_url)
