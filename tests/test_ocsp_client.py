# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import base64
import sys
import unittest

from asn1crypto import pem, x509
from certvalidator import ocsp_client
from certvalidator.errors import OCSPFetchError, OCSPValidationIndeterminateError
from certvalidator.http_policy import FetchPolicy
from certvalidator.registry import CertificateRegistry
from certvalidator.context import ValidationContext
from certvalidator.validate import verify_ocsp_response

if sys.version_info < (3,):
    from urllib2 import HTTPError  # noqa
else:
    from urllib.error import HTTPError  # noqa

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class OCSPClientTests(unittest.TestCase):

    def test_fetch_ocsp(self):
        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            intermediate = x509.Certificate.load(cert_bytes)

        registry = CertificateRegistry()
        path = registry.build_paths(intermediate)[0]
        issuer = path.find_issuer(intermediate)

        try:
            ocsp_response = ocsp_client.fetch(intermediate, issuer)
        except (HTTPError) as e:
            # If we get a 500 error, retry to reduce test failures
            if e.code < 500 or e.code >= 600:
                raise
            ocsp_response = ocsp_client.fetch(intermediate, issuer)

        context = ValidationContext(ocsps=[ocsp_response])
        verify_ocsp_response(intermediate, path, context)


class _FakeResponse(object):

    def __init__(self, body, headers=None):
        self._body = body
        self.headers = headers if headers is not None else {}

    def read(self, amt=None):
        if amt is None:
            return self._body
        return self._body[:amt]


class OCSPFetchPolicyTests(unittest.TestCase):

    def _load_intermediate_and_issuer(self):
        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            intermediate = x509.Certificate.load(cert_bytes)

        with open(os.path.join(fixtures_dir, 'digicert-global-root-ca.crt'), 'rb') as f:
            root_bytes = f.read()
            if pem.detect(root_bytes):
                _, _, root_bytes = pem.unarmor(root_bytes)

        registry = CertificateRegistry(trust_roots=[root_bytes])
        path = registry.build_paths(intermediate)[0]
        issuer = path.find_issuer(intermediate)
        return intermediate, issuer

    def test_fetch_ocsp_policy_rejection_is_diagnosable(self):
        intermediate, issuer = self._load_intermediate_and_issuer()
        policy = FetchPolicy(resolver=lambda host, port: ['127.0.0.1'])

        with self.assertRaises(OCSPFetchError) as cm:
            ocsp_client.fetch(intermediate, issuer, http_policy=policy)

        self.assertIsInstance(cm.exception, OCSPValidationIndeterminateError)
        self.assertEqual('loopback_address', cm.exception.reason)

    def test_fetch_ocsp_with_policy_and_fetcher(self):
        intermediate, issuer = self._load_intermediate_and_issuer()
        with open(os.path.join(fixtures_dir, 'openssl-ocsp', 'D1.ors'), 'rb') as f:
            ocsp_bytes = base64.b64decode(f.read())

        requests = []

        def fetcher(request, data, timeout):
            requests.append((request, data, timeout))
            return _FakeResponse(ocsp_bytes)

        policy = FetchPolicy(resolver=lambda host, port: ['93.184.216.34'])
        ocsp_response = ocsp_client.fetch(
            intermediate,
            issuer,
            http_policy=policy,
            fetcher=fetcher
        )

        self.assertEqual('successful', ocsp_response['response_status'].native)
        self.assertEqual(1, len(requests))
        # The OCSP request body must be sent, but never end up in errors
        self.assertTrue(len(requests[0][1]) > 0)
