# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import datetime
import hashlib
import os
import unittest

from asn1crypto import cms, cms_forensics, parser, pem, util, x509
from ._unittest_compat import patch

patch()

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    HAVE_CRYPTOGRAPHY = True
except Exception:
    HAVE_CRYPTOGRAPHY = False

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")


def _fixture(name):
    with open(os.path.join(fixtures_dir, name), "rb") as f:
        return f.read()


def _cert_and_key():
    with open(os.path.join(fixtures_dir, "keys", "test.crt"), "rb") as f:
        cert = x509.Certificate.load(pem.unarmor(f.read())[2])
    with open(os.path.join(fixtures_dir, "keys", "test.key"), "rb") as f:
        key = serialization.load_pem_private_key(f.read(), None)
    return cert, key


def _build_pair():
    cert, key = _cert_and_key()
    content = b"historical issuance payload\n"
    digest = hashlib.sha256(content).digest()
    stamp = datetime.datetime(2020, 1, 2, 3, 4, 5, tzinfo=util.timezone.utc)

    def make_attrs(time_kind):
        time_value = cms.Time(name=time_kind, value=stamp)
        return cms.CMSAttributes([
            cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [digest]}),
            cms.CMSAttribute({"type": "signing_time", "values": [time_value]}),
        ])

    attrs_forward = make_attrs("utc_time")
    attrs_repack = make_attrs("generalized_time")
    attrs_der = attrs_forward.dump(force=True)
    signature_input = b"\x31" + attrs_der[1:]
    signature_a = key.sign(signature_input, padding.PKCS1v15(), hashes.SHA256())
    signature_b = key.sign(content, padding.PKCS1v15(), hashes.SHA256())
    sid = cms.IssuerAndSerialNumber({
        "issuer": cert.issuer,
        "serial_number": cert.serial_number,
    })

    def signer(attrs):
        fields = {
            "version": "v1",
            "sid": cms.SignerIdentifier(name="issuer_and_serial_number", value=sid),
            "digest_algorithm": {"algorithm": "sha256"},
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": signature_a,
        }
        if attrs is not None:
            fields["signed_attrs"] = attrs
        else:
            fields["signature"] = signature_b
        return cms.SignerInfo(fields)

    def wrap(attrs, repack):
        signed_data = cms.SignedData({
            "version": "v1",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "data", "content": content},
            "certificates": [cms.CertificateChoices(name="certificate", value=cert)],
            "signer_infos": [signer(None), signer(attrs)],
        })
        info = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
        der = info.dump(force=True)
        if repack:
            first = der[1]
            header_len = 2 + (first & 0x7f) if first & 0x80 else 2
            der = b"\x30\x80" + der[header_len:] + b"\x00\x00"
        return der

    return content, wrap(attrs_forward, False), wrap(attrs_repack, True)



class CmsForensicInventoryTests(unittest.TestCase):

    def test_existing_signed_fixture_has_direct_signer_evidence(self):
        inv = cms.signing_material(_fixture("cms-signed.der"))
        self.assertEqual(1, len(inv["signers"]))
        signer = inv["signers"][0]
        self.assertTrue(signer["signed_attributes"]["present"])
        self.assertEqual("valid", signer["verification"]["signature"])
        self.assertEqual("valid", signer["verification"]["digest"])
        self.assertTrue(signer["direct_evidence"])
        self.assertFalse(signer["lost_direct_evidence"])
        self.assertTrue(inv["outer"]["byte_identical"])

    def test_original_bytes_are_not_replaced_by_forced_serialization(self):
        raw = _fixture("cms-signed-indefinite-length.der")
        info = cms.ContentInfo.load(raw)
        before = cms.signing_material(info)
        self.assertEqual(raw, before["source"]["bytes"])
        self.assertEqual(1, before["source"]["trailing_length"])
        self.assertEqual(raw[:-1], info.original_dump())
        info.dump(force=True)
        after = cms.signing_material(info)
        self.assertEqual(raw[:-1], info.original_dump())
        self.assertEqual(before["source"]["sha256"], after["source"]["sha256"])
        self.assertEqual(
            before["signers"][0]["signed_region"]["sha256"],
            after["signers"][0]["signed_region"]["sha256"]
        )
        self.assertEqual(
            before["signers"][0]["signature"]["sha256"],
            after["signers"][0]["signature"]["sha256"]
        )

    def test_json_view_keeps_forensic_bytes(self):
        inv = cms.signing_material(_fixture("cms-signed.der"))
        encoded = inv.as_json()
        self.assertIn("signed_region", encoded)
        self.assertIn("source", encoded)
        self.assertTrue(inv["source"]["bytes"].startswith(b"\x30"))

    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography is not available")
    def test_two_samples_same_content_separate_archive_and_evidence(self):
        content, forward, repacked = _build_pair()
        first = cms.signing_material(forward)
        second = cms.signing_material(repacked)

        self.assertEqual(first["semantic_fingerprint"], second["semantic_fingerprint"])
        self.assertEqual(content, first["layers"][0]["encap_content"]["bytes"])
        self.assertEqual(content, second["layers"][0]["encap_content"]["bytes"])
        self.assertTrue(first["outer"]["byte_identical"])
        self.assertFalse(second["outer"]["byte_identical"])
        self.assertEqual(
            "indefinite_length",
            second["outer"]["changes"][0]["kind"]
        )
        self.assertFalse(first["has_lost_direct_evidence"])
        self.assertTrue(second["has_lost_direct_evidence"])

        def split(inv):
            with_attrs = []
            without_attrs = []
            for signer in inv["signers"]:
                if signer["signed_attributes"]["present"]:
                    with_attrs.append(signer)
                else:
                    without_attrs.append(signer)
            return with_attrs, without_attrs

        first_with, first_without = split(first)
        second_with, second_without = split(second)
        self.assertEqual(1, len(first_with))
        self.assertEqual(1, len(second_with))

        self.assertEqual("valid", first_with[0]["verification"]["signature"])
        self.assertTrue(first_with[0]["direct_evidence"])
        self.assertFalse(first_with[0]["lost_direct_evidence"])

        self.assertEqual("valid", second_without[0]["verification"]["signature"])
        self.assertTrue(second_without[0]["direct_evidence"])

        self.assertEqual("invalid", second_with[0]["verification"]["signature"])
        self.assertTrue(second_with[0]["message_digest"]["match"])
        self.assertFalse(second_with[0]["direct_evidence"])
        self.assertTrue(second_with[0]["lost_direct_evidence"])
        self.assertEqual(
            "signature_unverifiable_after_rewrapping",
            second_with[0]["conclusion"]
        )
        self.assertEqual(1, len(second["lost_direct_evidence"]))
        self.assertEqual(1, len(second["lost_signers"]))
        self.assertEqual(1, second["lost_signers"][0]["index"])
        self.assertEqual(1, len(second["preserved_signers"]))
        self.assertEqual(0, second["preserved_signers"][0]["index"])
        self.assertNotEqual(
            second["lost_signers"][0]["signer_ref"],
            second["preserved_signers"][0]["signer_ref"]
        )

    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography is not available")
    def test_signed_data_and_content_info_entries_agree(self):
        content, forward, repacked = _build_pair()
        info = cms.ContentInfo.load(repacked)
        from_info = info.signing_material()
        from_data = info["content"].signing_material()
        from_module = cms_forensics.inventory(repacked)
        self.assertEqual(
            from_info["semantic_fingerprint"],
            from_data["semantic_fingerprint"]
        )
        self.assertEqual(
            from_info["semantic_fingerprint"],
            from_module["semantic_fingerprint"]
        )


    def test_ber_signed_attrs_keep_canonical_reconstruction_available(self):
        raw = _fixture("cms-signed-indefinite-length.der")
        first = cms.signing_material(raw)
        region = first["signers"][0]["signed_attributes"]["source_region"]
        self.assertEqual(4, region["header_length"])
        body = raw[region["header_end"]:region["content_end"]]
        wrapped = b"\xa0\x80" + body + b"\x00\x00"
        mutated = raw[:region["start"]] + wrapped + raw[region["end"]:]
        second = cms.signing_material(mutated)
        signer = second["signers"][0]
        attempts = dict((a["input"], a["status"]) for a in signer["verification"]["attempts"])
        self.assertEqual("original_ber", signer["signed_attributes"]["representation"])
        self.assertEqual("invalid", attempts["source"])
        self.assertEqual("valid", attempts["canonical"])
        self.assertFalse(signer["direct_evidence"])
        self.assertTrue(signer["lost_direct_evidence"])
        self.assertEqual("original_signed_bytes_not_preserved", signer["conclusion"])


def _tlv(class_, method, tag, content):
    return parser.emit(class_, method, tag, content)


class CmsNestedLayerTests(unittest.TestCase):

    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography is not available")
    def test_nested_signed_data_layers_are_independently_checked(self):
        content, inner_der, unused = _build_pair()
        inner_sd = cms_forensics.parse_tlv(inner_der, 0).children()[1].children()[0]
        signer_infos = inner_sd.children()[-1].raw
        oid = cms.ContentType("signed_data").dump()
        octet = _tlv(0, 0, 4, inner_der)
        encap = _tlv(0, 1, 16, oid + _tlv(2, 1, 0, octet))
        version = cms.CMSVersion("v3").dump()
        digests = cms.DigestAlgorithms([{"algorithm": "sha256"}]).dump()
        outer_sd = _tlv(0, 1, 16, version + digests + encap + signer_infos)
        outer = _tlv(0, 1, 16, oid + _tlv(2, 1, 0, outer_sd))

        inv = cms.signing_material(outer)
        self.assertEqual(2, len(inv["layers"]))
        self.assertEqual("signed_data", inv["layers"][0]["content_type"])
        self.assertEqual("data", inv["layers"][1]["content_type"])
        self.assertEqual(1, len(inv["layers"][0]["children"]))
        inner_layer = inv["layers"][1]
        self.assertEqual(2, len(inner_layer["signers"]))
        self.assertEqual(
            ["valid", "valid"],
            [signer["verification"]["signature"] for signer in inner_layer["signers"]]
        )
        self.assertEqual(
            content,
            inner_layer["encap_content"]["bytes"]
        )



class CmsCounterSignatureTests(unittest.TestCase):

    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "cryptography is not available")
    def test_counter_signature_is_a_separate_verifiable_layer(self):
        cert, key = _cert_and_key()
        content = b"counter signature payload"
        digest = hashlib.sha256(content).digest()
        attrs = cms.CMSAttributes([
            cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [digest]}),
        ])
        parent_signature = key.sign(
            b"\x31" + attrs.dump(force=True)[1:], padding.PKCS1v15(), hashes.SHA256()
        )
        sid = cms.IssuerAndSerialNumber({
            "issuer": cert.issuer,
            "serial_number": cert.serial_number,
        })
        sid_choice = cms.SignerIdentifier(
            name="issuer_and_serial_number", value=sid
        )
        counter_signature = key.sign(
            parent_signature, padding.PKCS1v15(), hashes.SHA256()
        )
        counter = cms.SignerInfo({
            "version": "v1",
            "sid": sid_choice,
            "digest_algorithm": {"algorithm": "sha256"},
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": counter_signature,
        })
        unsigned = cms.CMSAttributes([
            cms.CMSAttribute({
                "type": "counter_signature",
                "values": cms.SignerInfos([counter]),
            })
        ])
        signer = cms.SignerInfo({
            "version": "v1",
            "sid": sid_choice,
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": attrs,
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": parent_signature,
            "unsigned_attrs": unsigned,
        })
        signed_data = cms.SignedData({
            "version": "v1",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "data", "content": content},
            "certificates": [cms.CertificateChoices(name="certificate", value=cert)],
            "signer_infos": [signer],
        })
        raw = cms.ContentInfo({
            "content_type": "signed_data",
            "content": signed_data,
        }).dump(force=True)

        inv = cms.signing_material(raw)
        self.assertEqual(2, len(inv["layers"]))
        self.assertEqual("counter_signature", inv["layers"][1]["content_type"])
        self.assertEqual(2, len(inv["signers"]))
        self.assertEqual(
            ["valid", "valid"],
            [item["verification"]["signature"] for item in inv["signers"]]
        )
        self.assertEqual(
            "content#counter_signature[0]",
            inv["signers"][1]["signer_ref"]
        )

