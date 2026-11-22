# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import json
import os
import unittest

from asn1crypto import approval, core, csr, pem, x509
from ._unittest_compat import patch

patch()

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")


def ext(name, value):
    extension = x509.Extension()
    extension["extn_id"] = name
    extension["critical"] = False
    extension["extn_value"] = value
    return extension


def eku(*values):
    return x509.ExtKeyUsageSyntax(list(values))


class ApprovalTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(fixtures_dir, "test-third-der.csr"), "rb") as f:
            cls.base_csr = csr.CertificationRequest.load(f.read())
        with open(os.path.join(fixtures_dir, "keys", "test-der.crt"), "rb") as f:
            cls.base_cert = x509.Certificate.load(f.read())

    def _csr(self, attribute_extensions):
        info = self.base_csr["certification_request_info"]
        attributes = []
        for extensions in attribute_extensions:
            attribute = csr.CRIAttribute()
            attribute["type"] = "extension_request"
            attribute["values"] = [extensions]
            attributes.append(attribute)
        cri = csr.CertificationRequestInfo()
        cri["version"] = "v1"
        cri["subject"] = info["subject"]
        cri["subject_pk_info"] = info["subject_pk_info"]
        cri["attributes"] = attributes
        request = csr.CertificationRequest()
        request["certification_request_info"] = cri
        request["signature_algorithm"] = self.base_csr["signature_algorithm"]
        request["signature"] = self.base_csr["signature"]
        return request

    def _certificate(self, extensions, subject=None, spki=None):
        base_tbs = self.base_cert["tbs_certificate"]
        info = self.base_csr["certification_request_info"]
        tbs = x509.TbsCertificate()
        tbs["version"] = "v3"
        tbs["serial_number"] = 1
        tbs["signature"] = base_tbs["signature"]
        tbs["issuer"] = base_tbs["issuer"]
        tbs["validity"] = base_tbs["validity"]
        tbs["subject"] = info["subject"] if subject is None else subject
        tbs["subject_public_key_info"] = info["subject_pk_info"] if spki is None else spki
        tbs["extensions"] = extensions
        certificate = x509.Certificate()
        certificate["tbs_certificate"] = tbs
        certificate["signature_algorithm"] = self.base_cert["signature_algorithm"]
        certificate["signature_value"] = self.base_cert["signature_value"]
        return certificate

    def test_legal_narrowing_and_trace(self):
        request = self._csr([[
            ext("extended_key_usage", eku("client_auth", "server_auth", "code_signing"))
        ]])
        certificate = self._certificate([
            ext("extended_key_usage", eku("client_auth", "server_auth"))
        ])
        view = approval.compare_csr_to_certificate(request, certificate)
        self.assertEqual("approved", view.verdict)
        self.assertTrue(view.approved)
        row = view.find("extended_key_usage")
        self.assertEqual("narrowed", row.status)
        self.assertTrue(row.legal_narrowing)
        self.assertEqual(["code_signing"], row["change"]["removed"])
        self.assertEqual("semantic_narrowed", row["evidence"]["match_basis"])
        request_path = row.trace["selected_request_path"]
        self.assertEqual("certification_request_info.attributes[0].values[0][0]", request_path)
        self.assertEqual(
            ["client_auth", "server_auth", "code_signing"],
            view.request_extension(request_path)["extn_value"].native
        )
        self.assertEqual("tbs_certificate.extensions[0]", row.trace["certificate_path"])

    def test_extra_purpose_is_rejected(self):
        request = self._csr([[
            ext("extended_key_usage", eku("client_auth", "server_auth"))
        ]])
        certificate = self._certificate([
            ext("extended_key_usage", eku("client_auth", "server_auth", "code_signing"))
        ])
        view = approval.compare_csr_to_certificate(request, certificate)
        self.assertEqual("rejected", view.verdict)
        self.assertFalse(view.approved)
        row = view.find("extended_key_usage")
        self.assertEqual("widened", row.status)
        self.assertFalse(row.approved)
        self.assertEqual(["code_signing"], row["change"]["added"])
        self.assertEqual(request, view.csr)
        self.assertEqual("certification_request_info.attributes[0].values[0][0]", row.trace["selected_request_path"])
        self.assertEqual("EXTENSION_WIDENED", view.findings[0]["code"])

    def test_equivalent_requests_keep_encoding_evidence(self):
        request = self._csr([
            [ext("extended_key_usage", eku("client_auth", "server_auth"))],
            [ext("extended_key_usage", eku("server_auth", "client_auth"))]
        ])
        certificate = self._certificate([
            ext("extended_key_usage", eku("client_auth", "server_auth"))
        ])
        view = approval.compare_csr_to_certificate(request, certificate)
        self.assertEqual("approved", view.verdict)
        row = view.find("extended_key_usage")
        self.assertEqual("exact", row.status)
        self.assertFalse(row["request_conflict"])
        self.assertEqual(1, len(row["request_variants"]))
        self.assertEqual(2, len(row["request_variants"][0]["paths"]))
        self.assertEqual(2, row["evidence"]["request_encoding_count"])
        bases = set([encoding["match_basis"] for encoding in row["evidence"]["request_encodings"]])
        self.assertEqual(set(["der_exact", "semantic_exact"]), bases)
        self.assertEqual(2, len(row["evidence"]["equivalent_request_paths"]))
        self.assertEqual(
            ["server_auth", "client_auth"],
            view.request_extension("certification_request_info.attributes[1].values[0][0]")["extn_value"].native
        )

    def test_issuer_added_provenance(self):
        request = self._csr([[
            ext("extended_key_usage", eku("client_auth"))
        ]])
        aki = x509.AuthorityKeyIdentifier()
        aki["key_identifier"] = b"01234567890123456789"
        unknown = x509.Extension()
        unknown["extn_id"] = "1.2.3.4.5"
        unknown["critical"] = False
        unknown["extn_value"] = core.ParsableOctetString(b"opaque")
        certificate = self._certificate([
            ext("extended_key_usage", eku("client_auth")),
            ext("authority_key_identifier", aki),
            unknown
        ])
        view = approval.compare_csr_to_certificate(request, certificate)
        self.assertEqual("rejected", view.verdict)
        aki_row = view.find("authority_key_identifier")
        self.assertEqual("issuer_added", aki_row.status)
        self.assertTrue(aki_row.approved)
        self.assertEqual("issuer_certificate", aki_row.provenance["source"])
        unknown_row = view.find("1.2.3.4.5")
        self.assertEqual("unrequested", unknown_row.status)
        self.assertFalse(unknown_row.approved)
        self.assertEqual("unknown", unknown_row.provenance["kind"])
        self.assertEqual("UNREQUESTED_EXTENSION", view.findings[0]["code"])

    def test_safe_omission_policy(self):
        requested_bc = x509.BasicConstraints()
        requested_bc["ca"] = True
        request = self._csr([[
            ext("basic_constraints", requested_bc)
        ]])
        certificate = self._certificate([])
        view = approval.build_comparison_view(request, certificate)
        self.assertEqual("approved", view.verdict)
        row = view.find("basic_constraints")
        self.assertEqual("omitted", row.status)
        self.assertTrue(row.approved)
        self.assertTrue(row.legal_narrowing)
        strict = approval.compare_csr_to_certificate(
            request,
            certificate,
            policy={"allow_omission": False}
        )
        self.assertEqual("rejected", strict.verdict)
        self.assertFalse(strict.find("basic_constraints").approved)

    def test_omitting_usage_restriction_is_widening(self):
        request = self._csr([[
            ext("extended_key_usage", eku("client_auth"))
        ]])
        certificate = self._certificate([])
        view = approval.compare_csr_to_certificate(request, certificate)
        self.assertEqual("rejected", view.verdict)
        row = view.find("extended_key_usage")
        self.assertEqual("widened", row.status)
        self.assertFalse(row.approved)
        self.assertEqual("EXTENSION_OMITTED_WIDENS_SCOPE", view.findings[0]["code"])

    def test_basic_constraints_narrowing(self):
        requested_bc = x509.BasicConstraints()
        requested_bc["ca"] = True
        requested_bc["path_len_constraint"] = 2
        issued_bc = x509.BasicConstraints()
        issued_bc["ca"] = True
        issued_bc["path_len_constraint"] = 1
        request = self._csr([[
            ext("basic_constraints", requested_bc)
        ]])
        certificate = self._certificate([
            ext("basic_constraints", issued_bc)
        ])
        view = approval.compare_csr_to_certificate(request, certificate)
        row = view.find("basic_constraints")
        self.assertEqual("narrowed", row.status)
        self.assertTrue(row.approved)
        self.assertEqual(2, row["change"]["details"]["requested_path_len"])
        self.assertEqual(1, row["change"]["details"]["issued_path_len"])

    def test_conflicting_request_variants_require_review(self):
        request = self._csr([
            [ext("extended_key_usage", eku("client_auth"))],
            [ext("extended_key_usage", eku("client_auth", "server_auth"))]
        ])
        certificate = self._certificate([
            ext("extended_key_usage", eku("client_auth", "server_auth"))
        ])
        view = approval.compare_csr_to_certificate(request, certificate)
        self.assertEqual("review_required", view.verdict)
        row = view.find("extended_key_usage")
        self.assertTrue(row["request_conflict"])
        self.assertFalse(row.approved)
        self.assertEqual("CONFLICTING_REQUEST_VARIANTS", view.findings[0]["code"])

    def test_subject_alt_name_semantics_and_type(self):
        requested_names = x509.GeneralNames([
            x509.GeneralName(name="dns_name", value="Example.COM"),
            x509.GeneralName(name="dns_name", value="www.example.com")
        ])
        issued_names = x509.GeneralNames([
            x509.GeneralName(name="dns_name", value="example.com")
        ])
        request = self._csr([[
            ext("subject_alt_name", requested_names)
        ]])
        certificate = self._certificate([
            ext("subject_alt_name", issued_names)
        ])
        view = approval.compare_csr_to_certificate(request, certificate)
        row = view.find("subject_alt_name")
        self.assertEqual("narrowed", row.status)
        self.assertTrue(row.approved)
        self.assertEqual(1, len(row["change"]["removed"]))
        self.assertEqual("dns_name", row["change"]["removed"][0]["type"])
        self.assertEqual("www.example.com", row["change"]["removed"][0]["value"])

    def test_pem_bytes_and_json(self):
        request = self._csr([[
            ext("extended_key_usage", eku("client_auth"))
        ]])
        certificate = self._certificate([
            ext("extended_key_usage", eku("client_auth"))
        ])
        view = certificate.compare_to_csr(request)
        pem_view = approval.compare(request, pem.armor("CERTIFICATE", certificate.dump()))
        der_view = approval.compare(request.dump(), certificate.dump())
        self.assertTrue(pem_view.approved)
        self.assertTrue(der_view.approved)
        self.assertTrue(view.approved)
        payload = pem_view.to_dict()
        self.assertEqual("approved", payload["verdict"])
        json.dumps(payload)
        self.assertEqual(payload, approval.compare(request, certificate).to_dict())


if __name__ == "__main__":
    unittest.main()
