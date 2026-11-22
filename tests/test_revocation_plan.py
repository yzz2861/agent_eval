# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import base64
import binascii
import os
import unittest

from asn1crypto import crl, ocsp, pem, x509
from asn1crypto.util import timezone

from oscrypto import asymmetric

from certvalidator import ValidationContext
from certvalidator.revocation_plan import plan_revocation_evidence
from certvalidator.validate import validate_path

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class RevocationPlanTests(unittest.TestCase):

    def _load_nist_cert(self, filename):
        return self._load_cert_object('nist_pkits', 'certs', filename)

    def _load_nist_crl(self, filename):
        with open(os.path.join(fixtures_dir, 'nist_pkits', 'crls', filename), 'rb') as f:
            return crl.CertificateList.load(f.read())

    def _load_openssl_ors(self, filename):
        with open(os.path.join(fixtures_dir, 'openssl-ocsp', filename), 'rb') as f:
            return ocsp.OCSPResponse.load(base64.b64decode(f.read()))

    def _load_cert_object(self, *path_components):
        with open(os.path.join(fixtures_dir, *path_components), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)
        return cert

    def test_shared_response_then_revoked_permission(self):
        root = self._load_nist_cert('TrustAnchorRootCertificate.crt')
        good_ca = self._load_nist_cert('GoodCACert.crt')
        ee1 = self._load_nist_cert('ValidCertificatePathTest1EE.crt')
        ee2 = self._load_nist_cert('ValidNameChainingWhitespaceTest3EE.crt')
        ee3 = self._load_nist_cert('ValidNameChainingCapitalizationTest5EE.crt')
        comodo_ee = self._load_cert_object('openssl-ocsp', 'ND1_Cert_EE.pem')

        crls = [
            self._load_nist_crl('GoodCACRL.crl'),
            self._load_nist_crl('TrustAnchorRootCRL.crl'),
        ]

        # Two adjacent time windows - the Good CA CRL covers everything up to
        # 2030-12-31 08:30, and the next window begins right after
        window_one_moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        window_two_moment = datetime(2031, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(
            trust_roots=[root],
            other_certs=[good_ca],
            crls=crls,
            moment=window_one_moment,
            revocation_mode='hard-fail'
        )

        # Mock the oscrypto signature verification so the test can run
        # without access to the OS crypto backend
        orig_load_public_key = asymmetric.load_public_key
        orig_load_certificate = asymmetric.load_certificate
        orig_rsa_verify = asymmetric.rsa_pkcs1v15_verify
        orig_dsa_verify = asymmetric.dsa_verify
        orig_ecdsa_verify = asymmetric.ecdsa_verify

        asymmetric.load_public_key = lambda public_key: public_key
        asymmetric.load_certificate = lambda cert: cert
        asymmetric.rsa_pkcs1v15_verify = lambda key, sig, data, hash_algo: None
        asymmetric.dsa_verify = lambda key, sig, data, hash_algo: None
        asymmetric.ecdsa_verify = lambda key, sig, data, hash_algo: None

        try:
            # Both end-entity certs are validated in the same transaction,
            # reusing the single shared Good CA CRL
            for ee_cert in (ee1, ee2):
                paths = context.certificate_registry.build_paths(ee_cert)
                self.assertEqual(1, len(paths))
                validate_path(context, paths[0])
        finally:
            asymmetric.load_public_key = orig_load_public_key
            asymmetric.load_certificate = orig_load_certificate
            asymmetric.rsa_pkcs1v15_verify = orig_rsa_verify
            asymmetric.dsa_verify = orig_dsa_verify
            asymmetric.ecdsa_verify = orig_ecdsa_verify

        batch = [ee1, ee2, ee3, comodo_ee]

        # While the Comodo OCSP service may still be told about the Comodo
        # cert, the plan lists that cert as needing a query
        policy = {
            'http://ocsp.comodoca.com': [comodo_ee],
        }
        plan = plan_revocation_evidence(
            context,
            batch,
            moment=window_two_moment,
            disclosure_policy=policy
        )
        self.assertEqual([ee1, ee2], plan.covered)
        self.assertEqual([(comodo_ee, ['http://ocsp.comodoca.com'])], plan.to_fetch)
        self.assertEqual([ee3], plan.suspended)

        # Once the query permission is revoked, the remaining gaps are
        # suspended since no permitted channel is left
        plan = plan_revocation_evidence(
            context,
            batch,
            moment=window_two_moment,
            disclosure_policy={}
        )
        self.assertEqual([ee1, ee2], plan.covered)
        self.assertEqual([], plan.to_fetch)
        self.assertEqual([ee3, comodo_ee], plan.suspended)

    def test_cached_crl_covers_only_its_window(self):
        root = self._load_nist_cert('TrustAnchorRootCertificate.crt')
        good_ca = self._load_nist_cert('GoodCACert.crt')
        ee = self._load_nist_cert('ValidCertificatePathTest1EE.crt')

        crls = [
            self._load_nist_crl('GoodCACRL.crl'),
            self._load_nist_crl('TrustAnchorRootCRL.crl'),
        ]

        window_one_moment = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        window_two_moment = datetime(2031, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(
            trust_roots=[root],
            other_certs=[good_ca],
            crls=crls,
            moment=window_one_moment
        )

        # Within the CRL time window the cached CRL covers the cert
        plan = plan_revocation_evidence(context, [ee], moment=window_one_moment)
        self.assertEqual([ee], plan.covered)
        self.assertEqual([], plan.to_fetch)
        self.assertEqual([], plan.suspended)

        # In the adjacent window the CRL is stale, and the cert has no
        # revocation service URLs, so the gap is suspended
        plan = plan_revocation_evidence(context, [ee], moment=window_two_moment)
        self.assertEqual([], plan.covered)
        self.assertEqual([], plan.to_fetch)
        self.assertEqual([ee], plan.suspended)

    def test_cached_ocsp_response_covers_only_its_window(self):
        root = self._load_cert_object('openssl-ocsp', 'ND2_Issuer_Root.pem')
        ica = self._load_cert_object('openssl-ocsp', 'ND1_Issuer_ICA.pem')
        ee = self._load_cert_object('openssl-ocsp', 'ND1_Cert_EE.pem')
        ocsp_response = self._load_openssl_ors('ND1.ors')

        # The OCSP response is valid from 2012-10-11 08:41:13 until
        # 2012-10-15 08:41:13, the adjacent window begins right after
        window_one_moment = datetime(2012, 10, 12, 0, 0, 0, tzinfo=timezone.utc)
        window_two_moment = datetime(2012, 10, 16, 0, 0, 0, tzinfo=timezone.utc)

        context = ValidationContext(
            trust_roots=[root],
            other_certs=[ica],
            ocsps=[ocsp_response],
            moment=window_one_moment
        )

        # Within the response time window the cached response covers the cert
        plan = plan_revocation_evidence(context, [ee], moment=window_one_moment)
        self.assertEqual([ee], plan.covered)
        self.assertEqual([], plan.to_fetch)
        self.assertEqual([], plan.suspended)

        # In the adjacent window the response is stale, so the cert needs a
        # query via any channel the disclosure policy permits
        fingerprint = binascii.hexlify(ee.sha1).decode('ascii')
        policy = {
            'http://ocsp.comodoca.com': [fingerprint],
        }
        plan = plan_revocation_evidence(
            context,
            [ee],
            moment=window_two_moment,
            disclosure_policy=policy
        )
        self.assertEqual([], plan.covered)
        self.assertEqual([(ee, ['http://ocsp.comodoca.com'])], plan.to_fetch)
        self.assertEqual([], plan.suspended)

        # Without permission to disclose the cert identity, the gap is
        # suspended
        plan = plan_revocation_evidence(context, [ee], moment=window_two_moment)
        self.assertEqual([], plan.covered)
        self.assertEqual([], plan.to_fetch)
        self.assertEqual([ee], plan.suspended)
