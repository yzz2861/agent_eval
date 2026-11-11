import unittest

import dns._features
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

try:
    import cryptography  # noqa: F401
except ImportError:
    pass
else:
    dns._features.force("dnssec", True)

import dns.dnssec

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    ed25519 = None


APEX = dns.name.from_text("example.")
NOW = 1_800_000_000


@unittest.skipUnless(dns.dnssec._have_pyca, "DNSSEC support requires cryptography")
class DenialValidationTestCase(unittest.TestCase):
    def setUp(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.dnskey = dns.dnssec.make_dnskey(
            self.private_key.public_key(), dns.dnssec.ED25519
        )
        self.dnskey_rrset = dns.rrset.from_rdata(APEX, 3600, self.dnskey)
        self.dnskey_sig = self.sign(self.dnskey_rrset)

    def sign(self, rrset):
        rrsig = dns.dnssec.sign(
            rrset,
            self.private_key,
            APEX,
            self.dnskey,
            inception=NOW - 3600,
            expiration=NOW + 3600,
        )
        return dns.rrset.from_rdata(rrset.name, 3600, rrsig)

    def signed(self, rrset):
        return [rrset, self.sign(rrset)]

    def base_rrsets(self):
        return [self.dnskey_rrset, self.dnskey_sig]

    def nsec(self, owner, next_name, *types):
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC,
            f"{next_name} " + " ".join(types),
        )
        return self.signed(dns.rrset.from_rdata(owner, 300, rdata))

    def hashed_owner(self, name, salt=b"\xaa\xbb", iterations=2):
        text_hash = dns.dnssec.nsec3_hash(name, salt, iterations, 1).lower()
        return dns.name.from_text(f"{text_hash}.example.")

    def nsec3(
        self, owner_name, next_name, *types, flags=0, salt=b"\xaa\xbb", iterations=2
    ):
        next_hash = dns.dnssec.nsec3_hash(next_name, salt, iterations, 1).lower()
        salt_text = salt.hex() if salt else "-"
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            f"1 {flags} {iterations} {salt_text} {next_hash} " + " ".join(types),
        )
        owner = self.hashed_owner(owner_name, salt, iterations)
        return self.signed(dns.rrset.from_rdata(owner, 300, rdata))

    def nsec3param(self, salt=b"\xaa\xbb", iterations=2, flags=0):
        salt_text = salt.hex() if salt else "-"
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3PARAM,
            f"1 {flags} {iterations} {salt_text}",
        )
        return self.signed(dns.rrset.from_rdata(APEX, 300, rdata))

    def validate(self, qname, qtype, rrsets, rcode=None):
        return dns.dnssec.validate_denial(
            qname, qtype, APEX, self.dnskey, rrsets, rcode=rcode, now=NOW
        )

    def test_nsec_nxdomain_wrapping_interval(self):
        rrsets = self.base_rrsets() + self.nsec(APEX, APEX, "SOA RRSIG")
        result = self.validate("missing.example.", "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)
        self.assertEqual(result.closest_encloser, APEX)
        self.assertEqual(result.next_closer, dns.name.from_text("missing.example."))
        self.assertEqual(len(result.proofs), 1)

    def test_nsec_nodata_empty_bitmap(self):
        rrsets = self.base_rrsets() + self.nsec(APEX, APEX, "SOA RRSIG")
        result = self.validate(APEX, "A", rrsets, "NOERROR")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)

    def test_nsec_nodata_proof_cannot_claim_nxdomain(self):
        rrsets = self.base_rrsets() + self.nsec(APEX, APEX, "SOA RRSIG")
        result = self.validate(APEX, "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec_nodata_bitmap_with_qtype_is_bogus(self):
        rrsets = self.base_rrsets() + self.nsec(APEX, APEX, "A SOA RRSIG")
        result = self.validate(APEX, "A", rrsets, "NOERROR")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec_ds_nodata_at_unsigned_delegation_is_insecure(self):
        delegation = dns.name.from_text("unsigned.example.")
        ns = dns.rrset.from_text(delegation, 3600, "IN", "NS", "ns.example.")
        rrsets = self.base_rrsets() + [ns] + self.nsec(delegation, APEX, "NS RRSIG")
        result = self.validate(delegation, "DS", rrsets, "NOERROR")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.INSECURE)

    def test_nsec_wildcard_expansion(self):
        wildcard = dns.name.from_text("*.example.")
        rrsets = self.base_rrsets() + self.nsec(wildcard, APEX, "TXT RRSIG")
        result = self.validate("host.example.", "A", rrsets, "NOERROR")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)
        self.assertTrue(result.wildcard_expanded)
        self.assertEqual(result.wildcard, wildcard)

    def test_nsec_missing_next_closer_is_bogus(self):
        missing = dns.name.from_text("missing.example.")
        rrsets = self.base_rrsets() + self.nsec(APEX, missing, "SOA RRSIG")
        result = self.validate(missing, "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec_non_apex_self_next_is_bogus(self):
        owner_name = dns.name.from_text("host.example.")
        rrsets = self.base_rrsets() + self.nsec(owner_name, owner_name, "A RRSIG")
        result = self.validate("missing.example.", "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec_nxdomain_with_non_apex_closest_encloser(self):
        parent = dns.name.from_text("host.example.")
        child = dns.name.from_text("a.host.example.")
        successor = dns.name.from_text("z.host.example.")
        rrsets = (
            self.base_rrsets()
            + self.nsec(parent, successor, "A RRSIG")
            + self.nsec(successor, APEX, "A RRSIG")
        )
        result = self.validate(child, "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)
        self.assertEqual(result.closest_encloser, parent)
        self.assertEqual(result.next_closer, child)

    def test_nsec3_nxdomain_and_closest_encloser(self):
        rrsets = (
            self.base_rrsets()
            + self.nsec3param()
            + self.nsec3(APEX, APEX, "SOA RRSIG NSEC3PARAM")
        )
        result = self.validate("missing.example.", "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)
        self.assertEqual(result.closest_encloser, APEX)
        self.assertEqual(result.next_closer, dns.name.from_text("missing.example."))

    def test_nsec3_nxdomain_with_non_apex_closest_encloser(self):
        parent = dns.name.from_text("host.example.")
        child = dns.name.from_text("a.host.example.")
        successor = dns.name.from_text("z.host.example.")
        rrsets = (
            self.base_rrsets()
            + self.nsec3param()
            + self.nsec3(parent, successor, "A RRSIG")
            + self.nsec3(successor, APEX, "A RRSIG")
        )
        result = self.validate(child, "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)
        self.assertEqual(result.closest_encloser, parent)
        self.assertEqual(result.next_closer, child)

    def test_nsec3_nodata(self):
        rrsets = (
            self.base_rrsets()
            + self.nsec3param()
            + self.nsec3(APEX, APEX, "SOA RRSIG NSEC3PARAM")
        )
        result = self.validate(APEX, "A", rrsets, "NOERROR")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)

    def test_nsec3_wildcard(self):
        wildcard = dns.name.from_text("*.example.")
        rrsets = (
            self.base_rrsets()
            + self.nsec3param()
            + self.nsec3(wildcard, APEX, "TXT RRSIG")
        )
        result = self.validate("host.example.", "A", rrsets, "NOERROR")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)
        self.assertEqual(result.wildcard, wildcard)
        self.assertTrue(result.wildcard_expanded)

    def test_nsec3_wildcard_bitmap_with_qtype_is_bogus(self):
        wildcard = dns.name.from_text("*.example.")
        rrsets = self.base_rrsets() + self.nsec3(wildcard, APEX, "A RRSIG")
        result = self.validate("host.example.", "A", rrsets, "NOERROR")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec3_opt_out_is_insecure(self):
        delegation = dns.name.from_text("unsigned.example.")
        ns = dns.rrset.from_text(delegation, 3600, "IN", "NS", "ns.example.")
        rrsets = (
            self.base_rrsets()
            + [ns]
            + self.nsec3(
                delegation,
                dns.name.from_text("host.unsigned.example."),
                "NS RRSIG",
                flags=1,
            )
            + self.nsec3(
                dns.name.from_text("x.example."), delegation, "A RRSIG", flags=1
            )
        )
        result = self.validate("host.unsigned.example.", "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.INSECURE)
        self.assertIn("opt-out", result.reason)

    def test_nsec3_opt_out_without_signature_is_bogus(self):
        delegation = dns.name.from_text("unsigned.example.")
        ns = dns.rrset.from_text(delegation, 3600, "IN", "NS", "ns.example.")
        proof = self.nsec3(
            delegation,
            dns.name.from_text("host.unsigned.example."),
            "NS RRSIG",
            flags=1,
        )[0]
        result = self.validate(
            "host.unsigned.example.",
            "A",
            self.base_rrsets() + [ns, proof],
            "NXDOMAIN",
        )
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec3_wrong_salt_is_bogus(self):
        good_salt = b"\xaa\xbb"
        rrsets = (
            self.base_rrsets()
            + self.nsec3param(salt=b"\xcc\xdd")
            + self.nsec3(APEX, APEX, "SOA RRSIG", salt=good_salt)
        )
        result = self.validate("missing.example.", "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec3_wrong_iterations_is_bogus(self):
        rrsets = (
            self.base_rrsets()
            + self.nsec3param(iterations=3)
            + self.nsec3(APEX, APEX, "SOA RRSIG", iterations=2)
        )
        result = self.validate("missing.example.", "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec3_iteration_limit_is_enforced(self):
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            f"1 0 {dns.dnssec.MAX_NSEC3_ITERATIONS + 1} - aaaaa SOA",
        )
        owner = dns.name.from_text("0000000000000000000000000000000000.example.")
        rrset = dns.rrset.from_rdata(owner, 300, rdata)
        result = self.validate(
            "missing.example.", "A", self.base_rrsets() + [rrset], "NXDOMAIN"
        )
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)
        self.assertIn("iterations", result.reason)

    def test_nsec3param_iteration_limit_is_enforced(self):
        rrsets = self.base_rrsets() + self.nsec3param(
            iterations=dns.dnssec.MAX_NSEC3_ITERATIONS + 1
        )
        result = self.validate("missing.example.", "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)
        self.assertIn("iterations", result.reason)

    def test_nsec3_missing_next_closer_is_bogus(self):
        missing = dns.name.from_text("missing.example.")
        rrsets = (
            self.base_rrsets()
            + self.nsec3param()
            + self.nsec3(APEX, missing, "SOA RRSIG")
        )
        result = self.validate(missing, "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec3_non_apex_self_next_is_bogus(self):
        owner_name = dns.name.from_text("host.example.")
        rrsets = self.base_rrsets() + self.nsec3(owner_name, owner_name, "A RRSIG")
        result = self.validate("missing.example.", "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_nsec3_only_closing_parameter_group_is_secure(self):
        good_rrset = self.nsec3(APEX, APEX, "SOA RRSIG")[0]
        bad_rrset = self.nsec3(
            APEX, dns.name.from_text("bad.example."), "SOA RRSIG", salt=b"\xcc\xdd"
        )[0]
        combined = dns.rrset.from_rdata(
            good_rrset.name, 300, good_rrset[0], bad_rrset[0]
        )
        rrsets = self.base_rrsets() + [combined, self.sign(combined)]
        result = self.validate("missing.example.", "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)

    def test_nsec3_different_parameter_group_cannot_close_proof(self):
        good_rrset = self.nsec3(APEX, APEX, "SOA RRSIG")[0]
        good_owner = good_rrset.name
        bad_rrset = self.nsec3(
            APEX, dns.name.from_text("bad.example."), "SOA RRSIG", salt=b"\xcc\xdd"
        )[0]
        bad_at_good_owner = dns.rrset.from_rdata(good_owner, 300, bad_rrset[0])
        result = self.validate(
            "missing.example.",
            "A",
            self.base_rrsets() + [bad_at_good_owner, self.sign(bad_at_good_owner)],
            "NXDOMAIN",
        )
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_unsigned_cname_chain_is_bogus(self):
        alias = dns.name.from_text("alias.example.")
        target = dns.name.from_text("target.example.")
        cname = dns.rrset.from_text(alias, 300, "IN", "CNAME", target.to_text())
        rrsets = self.base_rrsets() + [cname] + self.nsec(APEX, APEX, "SOA RRSIG")
        result = self.validate(alias, "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)

    def test_signed_cname_chain_uses_terminal_proof(self):
        alias = dns.name.from_text("alias.example.")
        target = dns.name.from_text("target.example.")
        cname = dns.rrset.from_text(alias, 300, "IN", "CNAME", target.to_text())
        rrsets = (
            self.base_rrsets() + self.signed(cname) + self.nsec(APEX, APEX, "SOA RRSIG")
        )
        result = self.validate(alias, "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)
        self.assertEqual(result.closest_encloser, APEX)

    def test_wildcard_cname_marks_expansion(self):
        alias = dns.name.from_text("host.example.")
        target = dns.name.from_text("target.example.")
        cname = dns.rrset.from_text(alias, 300, "IN", "CNAME", target.to_text())
        wildcard = dns.name.from_text("*.example.")
        wildcard_cname = dns.rrset.from_rdata(wildcard, 300, cname[0])
        wildcard_sig = self.sign(wildcard_cname)
        expanded_sig = dns.rrset.from_rdata(alias, 300, wildcard_sig[0])
        rrsets = (
            self.base_rrsets()
            + [cname]
            + [expanded_sig]
            + self.nsec(APEX, APEX, "SOA RRSIG")
        )
        result = self.validate(alias, "A", rrsets, "NXDOMAIN")
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)
        self.assertTrue(result.wildcard_expanded)

    def test_ds_trust_anchor_validates(self):
        ds = dns.dnssec.make_ds(
            APEX,
            self.dnskey,
            dns.dnssec.DSDigest.SHA256,
            policy=dns.dnssec.allow_all_policy,
        )
        rrsets = self.base_rrsets() + self.nsec(APEX, APEX, "SOA RRSIG")
        result = dns.dnssec.validate_denial(
            "missing.example.", "A", APEX, ds, rrsets, "NXDOMAIN", now=NOW
        )
        self.assertEqual(result.status, dns.dnssec.DenialStatus.SECURE)

    def test_no_trust_anchor_is_insecure(self):
        result = dns.dnssec.validate_denial(
            "missing.example.",
            "A",
            APEX,
            None,
            self.nsec(APEX, APEX, "SOA RRSIG"),
            rcode="NXDOMAIN",
            now=NOW,
        )
        self.assertEqual(result.status, dns.dnssec.DenialStatus.INSECURE)

    def test_missing_proof_signature_is_bogus(self):
        proof = self.nsec(APEX, APEX, "SOA RRSIG")[0]
        result = self.validate(
            "missing.example.", "A", self.base_rrsets() + [proof], "NXDOMAIN"
        )
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)
        self.assertIn("RRSIG", result.reason)

    def test_unsigned_dnskey_rrset_with_trust_anchor_is_bogus(self):
        proof = self.nsec(APEX, APEX, "SOA RRSIG")
        result = self.validate(
            "missing.example.",
            "A",
            [self.dnskey_rrset] + proof,
            "NXDOMAIN",
        )
        self.assertEqual(result.status, dns.dnssec.DenialStatus.BOGUS)


if __name__ == "__main__":
    unittest.main()
