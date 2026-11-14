# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os

from asn1crypto import pem, x509
from certvalidator.registry import CertificateRegistry
from certvalidator.errors import PathBuildingError
from certvalidator.path import ValidationPath


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class RegistryTests(unittest.TestCase):

    def test_build_paths(self):
        with open(os.path.join(fixtures_dir, 'mozilla.org.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)

        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            other_certs = [f.read()]

        repo = CertificateRegistry(other_certs=other_certs)
        paths = repo.build_paths(cert)

        expected_names = [
            "Common Name: DigiCert Global Root CA, Organizational Unit: www.digicert.com, "
            "Organization: DigiCert Inc, Country: US",
            "Common Name: DigiCert SHA2 Secure Server CA, Organization: DigiCert Inc, Country: US",
            "Common Name: www.mozilla.org, Organizational Unit: WebOps, Organization: Mozilla Corporation, "
            "Locality: Mountain View, State/Province: California, Country: US",
        ]

        expected_hashes = [
            b'\x80Q\x06\x012\xad\x9a\xc2}Q\x87\xa0\xe8\x87\xfb\x01b\x01U\xee',
            b"\x10_\xa6z\x80\x08\x9d\xb5'\x9f5\xce\x83\x0bC\x88\x9e\xa3\xc7\r",
            b'I\xac\x03\xf8\xf3Km\xca)V)\xf2I\x9a\x98\xbe\x98\xdc.\x81'
        ]

        names = [[item.subject.human_friendly for item in path] for path in paths]
        hashes = [[item.subject.sha1 for item in path] for path in paths]

        if len(paths) == 2:
            self.assertEqual([expected_names[1:], expected_names], names)
            self.assertEqual([expected_hashes[1:], expected_hashes], hashes)
        else:
            self.assertEqual([expected_names], names)
            self.assertEqual([expected_hashes], hashes)

    def test_build_paths_custom_ca_certs(self):
        with open(os.path.join(fixtures_dir, 'mozilla.org.crt'), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            cert = x509.Certificate.load(cert_bytes)

        with open(os.path.join(fixtures_dir, 'digicert-sha2-secure-server-ca.crt'), 'rb') as f:
            other_certs = [f.read()]

        repo = CertificateRegistry(trust_roots=other_certs)
        paths = repo.build_paths(cert)
        self.assertEqual(1, len(paths))

        path = paths[0]
        self.assertEqual(2, len(path))
        self.assertEqual(
            [
                b"\x10_\xa6z\x80\x08\x9d\xb5'\x9f5\xce\x83\x0bC\x88\x9e\xa3\xc7\r",
                b'I\xac\x03\xf8\xf3Km\xca)V)\xf2I\x9a\x98\xbe\x98\xdc.\x81'
            ],
            [item.subject.sha1 for item in path]
        )


class PathBuildingTests(unittest.TestCase):

    def _load_cert(self, filename):
        with open(os.path.join(fixtures_dir, 'path_building', filename), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            return x509.Certificate.load(cert_bytes)

    def test_build_paths_cross_signed_roots(self):
        root_a = self._load_cert('root-a.pem')
        root_b = self._load_cert('root-b.pem')
        cross_a_by_b = self._load_cert('root-a-cross-by-b.pem')
        leaf = self._load_cert('leaf-root-a.pem')

        repo = CertificateRegistry(
            trust_roots=[root_a, root_b],
            other_certs=[cross_a_by_b]
        )
        paths = repo.build_paths(leaf)

        self.assertEqual(2, len(paths))

        # The shortest path, anchored directly at the issuer's own root,
        # must be preferred over the cross-signed detour
        self.assertEqual(
            [root_a.sha256, leaf.sha256],
            [cert.sha256 for cert in paths[0]]
        )
        self.assertEqual(
            [root_b.sha256, cross_a_by_b.sha256, leaf.sha256],
            [cert.sha256 for cert in paths[1]]
        )

    def test_build_paths_cross_signed_root_not_trusted(self):
        root_a = self._load_cert('root-a.pem')
        root_b = self._load_cert('root-b.pem')
        cross_a_by_b = self._load_cert('root-a-cross-by-b.pem')
        leaf = self._load_cert('leaf-root-a.pem')

        # root_b is supplied as an untrusted certificate, so no path may be
        # anchored at it
        repo = CertificateRegistry(
            trust_roots=[root_a],
            other_certs=[cross_a_by_b, root_b]
        )
        paths = repo.build_paths(leaf)

        self.assertEqual(1, len(paths))
        self.assertEqual(
            [root_a.sha256, leaf.sha256],
            [cert.sha256 for cert in paths[0]]
        )

    def test_build_paths_same_subject_roots_aki(self):
        root_1 = self._load_cert('shared-root-1.pem')
        root_2 = self._load_cert('shared-root-2.pem')
        intermediate = self._load_cert('intermediate-shared.pem')
        leaf = self._load_cert('leaf-shared.pem')

        repo = CertificateRegistry(
            trust_roots=[root_1, root_2],
            other_certs=[intermediate]
        )
        paths = repo.build_paths(leaf)

        # The AKI/SKI pair must ensure the path is built to the root that
        # actually signed the intermediate, despite both roots sharing a
        # subject name
        self.assertEqual(1, len(paths))
        self.assertEqual(
            [root_2.sha256, intermediate.sha256, leaf.sha256],
            [cert.sha256 for cert in paths[0]]
        )

    def test_build_paths_same_subject_roots_no_aki(self):
        root_1 = self._load_cert('shared-noski-root-1.pem')
        root_2 = self._load_cert('shared-noski-root-2.pem')
        leaf = self._load_cert('leaf-shared-noski.pem')

        repo = CertificateRegistry(trust_roots=[root_1, root_2])
        paths = repo.build_paths(leaf)

        # Without AKI/SKI information both roots are possible issuers, and
        # the caller's trust root order defines the priority
        self.assertEqual(2, len(paths))
        self.assertEqual(root_1.sha256, paths[0].first.sha256)
        self.assertEqual(root_2.sha256, paths[1].first.sha256)

    def test_build_paths_missing_intermediate(self):
        root_a = self._load_cert('root-a.pem')
        leaf = self._load_cert('leaf-a.pem')

        repo = CertificateRegistry(trust_roots=[root_a])

        with self.assertRaisesRegex(PathBuildingError, 'no issuer matching'):
            repo.build_paths(leaf)

    def test_build_paths_loop(self):
        cross_a_by_b = self._load_cert('root-a-cross-by-b.pem')
        cross_b_by_a = self._load_cert('root-b-cross-by-a.pem')
        leaf = self._load_cert('leaf-root-a.pem')

        repo = CertificateRegistry(
            trust_roots=[],
            other_certs=[cross_a_by_b, cross_b_by_a]
        )

        with self.assertRaisesRegex(PathBuildingError, 'loop'):
            repo.build_paths(leaf)

    def test_build_paths_max_length(self):
        root = self._load_cert('long-root.pem')
        intermediates = [
            self._load_cert('long-int-%d.pem' % i) for i in range(1, 8)
        ]
        leaf = self._load_cert('long-leaf.pem')

        repo = CertificateRegistry(
            trust_roots=[root],
            other_certs=intermediates
        )

        with self.assertRaisesRegex(PathBuildingError, 'maximum length'):
            repo.build_paths(leaf)

    def test_build_paths_max_length_boundary(self):
        root = self._load_cert('long-root.pem')
        intermediates = [
            self._load_cert('long-int-%d.pem' % i) for i in range(2, 8)
        ]
        leaf = self._load_cert('long-leaf-2.pem')

        repo = CertificateRegistry(
            trust_roots=[root],
            other_certs=intermediates
        )
        paths = repo.build_paths(leaf)

        self.assertEqual(1, len(paths))
        self.assertEqual(8, len(paths[0]))
        self.assertEqual(root.sha256, paths[0].first.sha256)

    def test_find_issuer_uses_aki_with_duplicate_subjects(self):
        root_1 = self._load_cert('shared-root-1.pem')
        root_2 = self._load_cert('shared-root-2.pem')
        intermediate = self._load_cert('intermediate-shared.pem')

        path = ValidationPath(intermediate)
        path.prepend(root_2)
        path.prepend(root_1)

        issuer = path.find_issuer(intermediate)
        self.assertEqual(root_2.sha256, issuer.sha256)

    def test_find_issuer_ambiguous_duplicate_subjects(self):
        root_1 = self._load_cert('shared-noski-root-1.pem')
        root_2 = self._load_cert('shared-noski-root-2.pem')
        leaf = self._load_cert('leaf-shared-noski.pem')

        path = ValidationPath(leaf)
        path.prepend(root_2)
        path.prepend(root_1)

        with self.assertRaisesRegex(LookupError, 'multiple certificates named'):
            path.find_issuer(leaf)

    def test_find_issuer_only_searches_before_cert(self):
        root_1 = self._load_cert('shared-root-1.pem')
        root_2 = self._load_cert('shared-root-2.pem')

        path = ValidationPath(root_2)
        path.prepend(root_1)

        # The first certificate in the path has no issuer within the path,
        # even though another certificate with the same subject name follows
        with self.assertRaisesRegex(LookupError, 'Unable to find the issuer'):
            path.find_issuer(root_1)
