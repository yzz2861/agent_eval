"""Tests for josepy.identifiers."""

import ipaddress
import unittest

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import josepy
from josepy import errors


def _csr(sans):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    )
    if sans is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(key, hashes.SHA256())


class CanonicalizeDNSNameTest(unittest.TestCase):
    """Tests for josepy.identifiers.canonicalize_dns_name."""

    def setUp(self):
        self.canon = josepy.canonicalize_dns_name

    def test_lowercase_and_trailing_dot(self):
        assert self.canon("Example.COM.") == "example.com"

    def test_already_canonical_unchanged(self):
        assert self.canon("sub.example.com") == "sub.example.com"

    def test_idn_to_alabel(self):
        assert self.canon("bücher.de") == "xn--bcher-kva.de"
        assert self.canon("BÜCHER.de.") == "xn--bcher-kva.de"

    def test_alabel_unchanged(self):
        assert self.canon("xn--bcher-kva.de") == "xn--bcher-kva.de"

    def test_unicode_dots(self):
        assert self.canon("example。com") == "example.com"
        assert self.canon("example．com") == "example.com"
        assert self.canon("example｡com") == "example.com"
        assert self.canon("example․com") == "example.com"

    def test_single_level_wildcard(self):
        assert self.canon("*.example.com") == "*.example.com"
        assert self.canon("*.Example.COM.") == "*.example.com"
        assert self.canon("*.bücher.de") == "*.xn--bcher-kva.de"

    def test_double_wildcard_rejected(self):
        with pytest.raises(errors.IdentifierError):
            self.canon("*.*.example.com")

    def test_bare_wildcard_rejected(self):
        with pytest.raises(errors.IdentifierError):
            self.canon("*")

    def test_wildcard_not_leftmost_rejected(self):
        with pytest.raises(errors.IdentifierError):
            self.canon("foo.*.example.com")

    def test_partial_wildcard_label_rejected(self):
        with pytest.raises(errors.IdentifierError):
            self.canon("foo*.example.com")
        with pytest.raises(errors.IdentifierError):
            self.canon("*foo.example.com")

    def test_empty_label_rejected(self):
        for name in ("a..example.com", ".example.com", "example..com", "example.com.."):
            with pytest.raises(errors.IdentifierError):
                self.canon(name)

    def test_empty_name_rejected(self):
        for name in ("", "."):
            with pytest.raises(errors.IdentifierError):
                self.canon(name)

    def test_ip_rejected(self):
        for name in ("1.2.3.4", "192.168.0.1", "::1", "2001:db8::1", "1。2.3.4"):
            with pytest.raises(errors.IdentifierError):
                self.canon(name)

    def test_port_and_path_rejected(self):
        for name in ("example.com:443", "example.com/path", "user@example.com"):
            with pytest.raises(errors.IdentifierError):
                self.canon(name)

    def test_underscore_rejected(self):
        with pytest.raises(errors.IdentifierError):
            self.canon("_dmarc.example.com")

    def test_non_string_rejected(self):
        for name in (None, 123, b"example.com"):
            with pytest.raises(errors.IdentifierError):
                self.canon(name)

    def test_label_too_long_rejected(self):
        with pytest.raises(errors.IdentifierError):
            self.canon("a" * 64 + ".com")

    def test_name_too_long_rejected(self):
        name = ".".join(["a" * 63] * 4) + ".com"
        with pytest.raises(errors.IdentifierError):
            self.canon(name)

    def test_error_reports_type_and_position(self):
        with pytest.raises(errors.IdentifierError) as excinfo:
            self.canon("1.2.3.4", position=3)
        err = excinfo.value
        assert err.identifier_type == "dns"
        assert err.position == 3
        assert "dns" in str(err)
        assert "3" in str(err)

    def test_error_does_not_echo_value(self):
        with pytest.raises(errors.IdentifierError) as excinfo:
            self.canon("1.2.3.4", position=0)
        assert "1.2.3.4" not in str(excinfo.value)


class DNSIdentifierTest(unittest.TestCase):
    """Tests for josepy.DNSIdentifier."""

    def test_original_and_canonical_preserved(self):
        ident = josepy.DNSIdentifier("*.Example.COM.")
        assert ident.original == "*.Example.COM."
        assert ident.canonical == "*.example.com"
        assert ident.value == "*.example.com"
        assert ident.wildcard is True
        assert ident.type == "dns"

    def test_non_wildcard(self):
        ident = josepy.DNSIdentifier("example.com")
        assert ident.wildcard is False

    def test_eq_and_hash(self):
        ident1 = josepy.DNSIdentifier("Example.COM.")
        ident2 = josepy.DNSIdentifier("example.com")
        assert ident1 == ident2
        assert hash(ident1) == hash(ident2)
        assert ident1 != josepy.DNSIdentifier("*.example.com")
        assert ident1 != "example.com"

    def test_to_partial_json_uses_canonical(self):
        ident = josepy.DNSIdentifier("*.Example.COM.")
        assert ident.to_partial_json() == {"type": "dns", "value": "*.example.com"}

    def test_json_roundtrip(self):
        ident = josepy.DNSIdentifier("bücher.de")
        jobj = {"type": "dns", "value": "xn--bcher-kva.de"}
        assert ident.to_json() == jobj
        assert josepy.DNSIdentifier.from_json(jobj) == ident
        assert josepy.DNSIdentifier.json_loads(ident.json_dumps()) == ident

    def test_from_json_wrong_type(self):
        with pytest.raises(errors.DeserializationError):
            josepy.DNSIdentifier.from_json({"type": "ip", "value": "1.2.3.4"})

    def test_from_json_missing_field(self):
        with pytest.raises(errors.DeserializationError):
            josepy.DNSIdentifier.from_json({"type": "dns"})

    def test_to_x509_keeps_wildcard(self):
        ident = josepy.DNSIdentifier("*.example.com")
        assert ident.to_x509() == x509.DNSName("*.example.com")


class IPIdentifierTest(unittest.TestCase):
    """Tests for josepy.IPIdentifier."""

    def test_canonicalization(self):
        ident = josepy.IPIdentifier("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert ident.original == "2001:0db8:0000:0000:0000:0000:0000:0001"
        assert ident.canonical == "2001:db8::1"
        assert ident.type == "ip"
        assert ident.wildcard is False

    def test_invalid(self):
        with pytest.raises(errors.IdentifierError) as excinfo:
            josepy.IPIdentifier("not-an-ip", position=1)
        assert excinfo.value.identifier_type == "ip"
        assert excinfo.value.position == 1

    def test_json_roundtrip(self):
        ident = josepy.IPIdentifier("1.2.3.4")
        assert ident.to_partial_json() == {"type": "ip", "value": "1.2.3.4"}
        assert josepy.IPIdentifier.from_json({"type": "ip", "value": "1.2.3.4"}) == ident

    def test_to_x509(self):
        ident = josepy.IPIdentifier("1.2.3.4")
        assert ident.to_x509() == x509.IPAddress(ipaddress.ip_address("1.2.3.4"))


class DecodeIdentifierTest(unittest.TestCase):
    """Tests for josepy.decode_identifier and josepy.encode_identifier."""

    def test_dispatch(self):
        dns = josepy.decode_identifier({"type": "dns", "value": "example.com"})
        ip = josepy.decode_identifier({"type": "ip", "value": "1.2.3.4"})
        assert isinstance(dns, josepy.DNSIdentifier)
        assert isinstance(ip, josepy.IPIdentifier)

    def test_roundtrip(self):
        ident = josepy.DNSIdentifier("*.Example.COM.")
        assert josepy.decode_identifier(josepy.encode_identifier(ident)) == ident

    def test_unknown_type(self):
        with pytest.raises(errors.UnrecognizedTypeError):
            josepy.decode_identifier({"type": "uri", "value": "http://example.com"})

    def test_missing_type(self):
        with pytest.raises(errors.DeserializationError):
            josepy.decode_identifier({"value": "example.com"})

    def test_not_a_mapping(self):
        with pytest.raises(errors.DeserializationError):
            josepy.decode_identifier("example.com")


class DNSIdentifiersTest(unittest.TestCase):
    """Tests for josepy.dns_identifiers."""

    def test_mixed_valid_sans(self):
        idents = josepy.dns_identifiers(
            ["example.com", "*.example.org", "bücher.de", "Example.NET."]
        )
        assert [ident.canonical for ident in idents] == [
            "example.com",
            "*.example.org",
            "xn--bcher-kva.de",
            "example.net",
        ]
        assert [ident.wildcard for ident in idents] == [False, True, False, False]

    def test_error_position(self):
        with pytest.raises(errors.IdentifierError) as excinfo:
            josepy.dns_identifiers(["example.com", "*.*.example.org"])
        err = excinfo.value
        assert err.identifier_type == "dns"
        assert err.position == 1
        assert "position 1" in str(err)
        assert "example.com" not in str(err)
        assert "example.org" not in str(err)


class IdentifierFromX509Test(unittest.TestCase):
    """Tests for josepy.identifier_from_x509."""

    def test_dns_name_keeps_wildcard(self):
        ident = josepy.identifier_from_x509(x509.DNSName("*.example.com"))
        assert isinstance(ident, josepy.DNSIdentifier)
        assert ident.wildcard is True
        assert ident.canonical == "*.example.com"

    def test_dns_name_not_confused_with_ip(self):
        ident = josepy.identifier_from_x509(x509.DNSName("example.com"))
        assert isinstance(ident, josepy.DNSIdentifier)

    def test_ip_address(self):
        ident = josepy.identifier_from_x509(x509.IPAddress(ipaddress.ip_address("10.0.0.1")))
        assert isinstance(ident, josepy.IPIdentifier)
        assert ident.canonical == "10.0.0.1"

    def test_unsupported_general_name(self):
        with pytest.raises(errors.IdentifierError):
            josepy.identifier_from_x509(x509.RFC822Name("admin@example.com"))


class IdentifiersFromCSRTest(unittest.TestCase):
    """Tests for josepy.identifiers_from_csr."""

    def test_multi_san_csr(self):
        csr = _csr(
            [
                x509.DNSName("*.Example.COM."),
                x509.DNSName("XN--BCHER-KVA.DE"),
                x509.IPAddress(ipaddress.ip_address("10.0.0.1")),
            ]
        )
        idents = josepy.identifiers_from_csr(csr)
        assert [ident.type for ident in idents] == ["dns", "dns", "ip"]
        assert [ident.canonical for ident in idents] == [
            "*.example.com",
            "xn--bcher-kva.de",
            "10.0.0.1",
        ]
        assert idents[0].wildcard is True

    def test_canonical_values_used_for_issuance(self):
        csr = _csr([x509.DNSName("*.Example.COM."), x509.DNSName("XN--BCHER-KVA.DE")])
        idents = josepy.identifiers_from_csr(csr)
        sans = [ident.to_x509() for ident in idents]
        assert sans == [
            x509.DNSName("*.example.com"),
            x509.DNSName("xn--bcher-kva.de"),
        ]

    def test_invalid_san_reports_position_without_csr_echo(self):
        csr = _csr(
            [
                x509.DNSName("example.com"),
                x509.DNSName("*.*.example.org"),
            ]
        )
        with pytest.raises(errors.IdentifierError) as excinfo:
            josepy.identifiers_from_csr(csr)
        err = excinfo.value
        assert err.identifier_type == "dns"
        assert err.position == 1
        assert "example.com" not in str(err)
        assert "example.org" not in str(err)

    def test_no_san_extension(self):
        assert josepy.identifiers_from_csr(_csr(None)) == ()


if __name__ == "__main__":
    unittest.main()
