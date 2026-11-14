# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import email
import sys
import unittest
import os

from asn1crypto import crl, x509, pem
from certvalidator import crl_client
from certvalidator.context import ValidationContext
from certvalidator.errors import (
    CRLFetchError,
    CRLValidationIndeterminateError,
    FetchPolicyError,
)
from certvalidator.http_policy import FetchPolicy, fetch_url, safe_origin
from certvalidator.validate import verify_crl

if sys.version_info < (3,):
    from urllib2 import HTTPError
else:
    from urllib.error import HTTPError


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class CRLClientTests(unittest.TestCase):

    def test_fetch_crl(self):
        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            file_bytes = f.read()
            if pem.detect(file_bytes):
                _, _, file_bytes = pem.unarmor(file_bytes)
            intermediate = x509.Certificate.load(file_bytes)

        crls = crl_client.fetch(intermediate, timeout=3)
        context = ValidationContext(crls=crls)
        registry = context.certificate_registry
        path = registry.build_paths(intermediate)[0]

        verify_crl(intermediate, path, context)


def _load_test_crl():
    with open(os.path.join(fixtures_dir, 'nist_pkits', 'crls', 'BadSignedCACRL.crl'), 'rb') as f:
        return f.read()


def _load_intermediate_cert():
    with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
        file_bytes = f.read()
        if pem.detect(file_bytes):
            _, _, file_bytes = pem.unarmor(file_bytes)
        return x509.Certificate.load(file_bytes)


def _request_url(request):
    if sys.version_info < (3,):
        return request.get_full_url()
    return request.full_url


def _redirect_error(url, location, code=302):
    headers = email.message.Message()
    headers['Location'] = location
    headers['Content-Type'] = 'text/plain'
    return HTTPError(url, code, 'Found', headers, None)


class _FakeResponse(object):

    def __init__(self, body, headers=None):
        self._body = body
        self.headers = headers if headers is not None else {}

    def read(self, amt=None):
        if amt is None:
            return self._body
        return self._body[:amt]


class _FakeOpener(object):
    """
    A urlopen-compatible stub that serves canned responses and records
    requests. Routes map URLs to _FakeResponse objects or exceptions to
    raise. Any unmapped URL falls back to the default response.
    """

    def __init__(self, routes=None, default=None):
        self.routes = routes or {}
        self.default = default
        self.requests = []

    def __call__(self, request, data, timeout):
        url = _request_url(request)
        self.requests.append((url, data, timeout))
        route = self.routes.get(url, self.default)
        if route is None:
            raise AssertionError('Unexpected URL requested: %s' % url)
        if isinstance(route, Exception):
            raise route
        return route


def _public_resolver(expected_host='crl.example.com'):
    def resolver(host, port):
        # IP literals resolve to themselves
        if host.replace('.', '').isdigit() or ':' in host:
            return [host]
        return ['93.184.216.34']
    return resolver


class CRLFetchPolicyTests(unittest.TestCase):

    def test_safe_origin_strips_path_query_and_userinfo(self):
        self.assertEqual(
            'http://crl.example.com:8080',
            safe_origin('http://user:pass@crl.example.com:8080/ca.crl?token=secret#frag')
        )
        self.assertEqual('https://crl.example.com', safe_origin('https://crl.example.com/ca.crl'))

    def test_policy_rejects_loopback_url(self):
        policy = FetchPolicy()
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url('http://127.0.0.1/ca.crl', policy=policy, opener=_FakeOpener())
        self.assertEqual('loopback_address', cm.exception.reason)

    def test_policy_rejects_link_local_url(self):
        policy = FetchPolicy()
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url('http://169.254.169.254/latest/meta-data', policy=policy, opener=_FakeOpener())
        self.assertEqual('link_local_address', cm.exception.reason)

    def test_policy_rejects_disallowed_scheme(self):
        policy = FetchPolicy(resolver=_public_resolver())
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url('ftp://crl.example.com/ca.crl', policy=policy, opener=_FakeOpener())
        self.assertEqual('scheme_not_allowed', cm.exception.reason)

    def test_policy_rejects_non_default_port(self):
        policy = FetchPolicy(resolver=_public_resolver())
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url('http://crl.example.com:8080/ca.crl', policy=policy, opener=_FakeOpener())
        self.assertEqual('port_not_allowed', cm.exception.reason)

    def test_policy_allows_explicit_port_allowlist(self):
        crl_bytes = _load_test_crl()
        policy = FetchPolicy(allowed_ports=set([8080]), resolver=_public_resolver())
        opener = _FakeOpener(default=_FakeResponse(crl_bytes))
        result = fetch_url('http://crl.example.com:8080/ca.crl', policy=policy, opener=opener)
        self.assertEqual(crl_bytes, result.body)

    def test_policy_rejects_host_not_in_allowlist(self):
        policy = FetchPolicy(allowed_hosts=['crl.example.com'], resolver=_public_resolver())
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url('http://other.example.com/ca.crl', policy=policy, opener=_FakeOpener())
        self.assertEqual('host_not_allowed', cm.exception.reason)

    def test_policy_rejects_cross_origin_redirect(self):
        start_url = 'http://crl.example.com/ca.crl'
        opener = _FakeOpener(routes={
            start_url: _redirect_error(start_url, 'http://127.0.0.1/ca.crl'),
        })
        policy = FetchPolicy(resolver=_public_resolver())
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url(start_url, policy=policy, opener=opener)
        self.assertEqual('cross_origin_redirect', cm.exception.reason)
        self.assertEqual(1, len(opener.requests))

    def test_policy_rejects_loopback_redirect_target(self):
        # Even when cross-origin redirects are allowed, a redirect to a
        # loopback address must be rejected
        start_url = 'http://crl.example.com/ca.crl'
        opener = _FakeOpener(routes={
            start_url: _redirect_error(start_url, 'http://127.0.0.1/ca.crl'),
        })
        policy = FetchPolicy(allow_cross_origin_redirects=True, resolver=_public_resolver())
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url(start_url, policy=policy, opener=opener)
        self.assertEqual('loopback_address', cm.exception.reason)

    def test_policy_allows_same_origin_redirect(self):
        crl_bytes = _load_test_crl()
        start_url = 'http://crl.example.com/old.crl'
        final_url = 'http://crl.example.com/ca.crl'
        opener = _FakeOpener(routes={
            start_url: _redirect_error(start_url, '/ca.crl'),
            final_url: _FakeResponse(crl_bytes),
        })
        policy = FetchPolicy(resolver=_public_resolver())
        result = fetch_url(start_url, policy=policy, opener=opener)
        self.assertEqual(crl_bytes, result.body)
        self.assertEqual(final_url, result.url)
        self.assertEqual(2, len(opener.requests))

    def test_policy_rechecks_dns_on_every_hop(self):
        # Simulates DNS rebinding: the first resolution is a public address,
        # the resolution for the redirect target returns a loopback address
        resolutions = [['93.184.216.34'], ['127.0.0.1']]
        resolved_hosts = []

        def resolver(host, port):
            resolved_hosts.append(host)
            return resolutions[min(len(resolved_hosts) - 1, len(resolutions) - 1)]

        start_url = 'http://crl.example.com/ca.crl'
        opener = _FakeOpener(routes={
            start_url: _redirect_error(start_url, 'http://crl.example.com/ca2.crl'),
        })
        policy = FetchPolicy(resolver=resolver)
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url(start_url, policy=policy, opener=opener)
        self.assertEqual('loopback_address', cm.exception.reason)
        self.assertEqual(2, len(resolved_hosts))

    def test_policy_rejects_oversized_response(self):
        crl_bytes = _load_test_crl()
        opener = _FakeOpener(default=_FakeResponse(crl_bytes))
        policy = FetchPolicy(max_response_size=64, resolver=_public_resolver())
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url('http://crl.example.com/ca.crl', policy=policy, opener=opener)
        self.assertEqual('response_too_large', cm.exception.reason)

    def test_policy_caps_timeout(self):
        crl_bytes = _load_test_crl()
        opener = _FakeOpener(default=_FakeResponse(crl_bytes))
        policy = FetchPolicy(max_timeout=5, resolver=_public_resolver())
        fetch_url('http://crl.example.com/ca.crl', timeout=60, policy=policy, opener=opener)
        self.assertEqual(5, opener.requests[0][2])

    def test_policy_error_does_not_leak_full_url(self):
        policy = FetchPolicy(resolver=_public_resolver())
        with self.assertRaises(FetchPolicyError) as cm:
            fetch_url(
                'http://crl.example.com:8080/private/ca.crl?token=abc123secret',
                policy=policy,
                opener=_FakeOpener()
            )
        message = str(cm.exception)
        self.assertNotIn('abc123secret', message)
        self.assertNotIn('/private/ca.crl', message)
        self.assertIn('http://crl.example.com:8080', message)

    def test_fetch_crl_with_policy_and_fetcher(self):
        intermediate = _load_intermediate_cert()
        crl_bytes = _load_test_crl()
        opener = _FakeOpener(default=_FakeResponse(crl_bytes))
        policy = FetchPolicy(resolver=_public_resolver())

        crls = crl_client.fetch(intermediate, http_policy=policy, fetcher=opener)

        self.assertEqual(2, len(crls))
        for certificate_list in crls:
            self.assertIsInstance(certificate_list, crl.CertificateList)
            self.assertEqual('Bad Signed CA', certificate_list.issuer.native['common_name'])

    def test_fetch_crl_policy_rejection_is_diagnosable(self):
        intermediate = _load_intermediate_cert()
        opener = _FakeOpener(default=_FakeResponse(_load_test_crl()))
        policy = FetchPolicy(resolver=lambda host, port: ['127.0.0.1'])

        with self.assertRaises(CRLFetchError) as cm:
            crl_client.fetch(intermediate, http_policy=policy, fetcher=opener)

        self.assertIsInstance(cm.exception, CRLValidationIndeterminateError)
        self.assertEqual('loopback_address', cm.exception.reason)
        self.assertEqual(1, len(cm.exception.failures))

    def test_fetch_crl_custom_fetcher_without_policy(self):
        intermediate = _load_intermediate_cert()
        opener = _FakeOpener(default=_FakeResponse(_load_test_crl()))

        crls = crl_client.fetch(intermediate, fetcher=opener)

        self.assertEqual(2, len(crls))
        self.assertEqual(2, len(opener.requests))

    def test_validation_context_passes_fetch_params(self):
        intermediate = _load_intermediate_cert()
        crl_bytes = _load_test_crl()
        opener = _FakeOpener(default=_FakeResponse(crl_bytes))
        policy = FetchPolicy(resolver=_public_resolver())

        context = ValidationContext(
            allow_fetching=True,
            crl_fetch_params={'http_policy': policy, 'fetcher': opener}
        )
        crls = context.retrieve_crls(intermediate)

        self.assertEqual(2, len(crls))
        self.assertEqual(2, len(opener.requests))
