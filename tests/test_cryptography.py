import datetime
import ipaddress

import pytest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    ExtensionOID,
    NameOID,
    OtherName,
    SubjectAlternativeName,
    load_pem_x509_certificate,
)

from service_identity.cryptography import (
    ID_ON_DNS_SRV,
    CommonNameFallback,
    extract_common_name_pattern,
    extract_ids,
    extract_patterns,
    verify_certificate_hostname,
    verify_certificate_hostname_with_policy,
    verify_certificate_ip_address,
)
from service_identity.exceptions import (
    CertificateError,
    DNSMismatch,
    InvalidSubjectCommonNameError,
    IPAddressMismatch,
    SubjectAltNameMissingError,
    VerificationError,
)
from service_identity.hazmat import (
    DNS_ID,
    DNSPattern,
    IPAddress_ID,
    IPAddressPattern,
    ServiceMatch,
    SRVPattern,
    URIPattern,
)

from .certificates import (
    PEM_CN_ONLY,
    PEM_DNS_ONLY,
    PEM_EVERYTHING,
    PEM_OTHER_NAME,
)


backend = default_backend()
X509_DNS_ONLY = load_pem_x509_certificate(PEM_DNS_ONLY, backend)
X509_CN_ONLY = load_pem_x509_certificate(PEM_CN_ONLY, backend)
X509_OTHER_NAME = load_pem_x509_certificate(PEM_OTHER_NAME, backend)
CERT_EVERYTHING = load_pem_x509_certificate(PEM_EVERYTHING, backend)


_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_certificate(subject_attributes, san=None):
    """
    Create a self-signed certificate in-process with *subject_attributes*
    (a list of NameAttributes / RelativeDistinguishedNames) and an optional
    *san* list of general names.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(subject_attributes))
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        )
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if san is not None:
        builder = builder.add_extension(
            SubjectAlternativeName(san), critical=False
        )

    return builder.sign(_KEY, hashes.SHA256())


def cn_certificate(common_name, san=None):
    """
    Create a certificate with a single commonName and an optional SAN.
    """
    return make_certificate(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)], san=san
    )


class TestPublicAPI:
    def test_no_cert_patterns_hostname(self):
        """
        A certificate without subjectAltNames raises a helpful
        CertificateError.
        """
        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s",
        ):
            verify_certificate_hostname(X509_CN_ONLY, "example.com")

    @pytest.mark.parametrize("ip", ["203.0.113.0", "2001:db8::"])
    def test_no_cert_patterns_ip_address(self, ip):
        """
        A certificate without subjectAltNames raises a helpful
        CertificateError.
        """
        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s",
        ):
            verify_certificate_ip_address(X509_CN_ONLY, ip)

    def test_certificate_verify_hostname_ok(self):
        """
        verify_certificate_hostname succeeds if the hostnames match.
        """
        verify_certificate_hostname(X509_DNS_ONLY, "twistedmatrix.com")

    def test_certificate_verify_hostname_fail(self):
        """
        verify_certificate_hostname fails if the hostnames don't match and
        provides the user with helpful information.
        """
        with pytest.raises(VerificationError) as ei:
            verify_certificate_hostname(X509_DNS_ONLY, "google.com")

        assert [
            DNSMismatch(mismatched_id=DNS_ID("google.com"))
        ] == ei.value.errors

    @pytest.mark.parametrize("ip", ["1.1.1.1", "::1"])
    def test_verify_certificate_ip_address_ok(self, ip):
        """
        verify_certificate_ip_address succeeds if the addresses match. Works
        both with IPv4 and IPv6.
        """
        verify_certificate_ip_address(CERT_EVERYTHING, ip)

    @pytest.mark.parametrize("ip", ["1.1.1.2", "::2"])
    def test_verify_ip_address_fail(self, ip):
        """
        verify_ip_address fails if the addresses don't match and provides the
        user with helpful information.  Works both with IPv4 and IPv6.
        """
        with pytest.raises(VerificationError) as ei:
            verify_certificate_ip_address(CERT_EVERYTHING, ip)

        assert [
            IPAddressMismatch(mismatched_id=IPAddress_ID(ip))
        ] == ei.value.errors


class TestExtractPatterns:
    def test_dns(self):
        """
        Returns the correct DNSPattern from a certificate.
        """
        rv = extract_patterns(X509_DNS_ONLY)
        assert [
            DNSPattern.from_bytes(b"www.twistedmatrix.com"),
            DNSPattern.from_bytes(b"twistedmatrix.com"),
        ] == rv

    def test_cn_ids_are_ignored(self):
        """
        commonName is not supported anymore and therefore ignored.
        """
        assert [] == extract_patterns(X509_CN_ONLY)

    def test_uri(self):
        """
        Returns the correct URIPattern from a certificate.
        """
        rv = extract_patterns(X509_OTHER_NAME)
        assert [URIPattern.from_bytes(b"http://example.com/")] == [
            id for id in rv if isinstance(id, URIPattern)
        ]

    def test_srv(self):
        """
        Returns the correct SRVPattern from a certificate.
        """
        rv = extract_patterns(X509_OTHER_NAME)
        assert [SRVPattern.from_bytes(b"_xmpp-client.example.net")] == [
            id for id in rv if isinstance(id, SRVPattern)
        ]

    def test_malformed_srv_other_name(self):
        """
        Malformed DER in a SRV-ID otherName raises a CertificateError.
        """

        class Extension:
            def __init__(self, value):
                self.value = value

        class Extensions:
            def __init__(self, value):
                self._value = value

            def get_extension_for_oid(self, oid):
                assert oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME

                return Extension(self._value)

        class Certificate:
            def __init__(self, san):
                self.extensions = Extensions(san)

        cert = Certificate(
            SubjectAlternativeName(
                [OtherName(ID_ON_DNS_SRV, b"\x16\x03abc\x00")]
            )
        )

        with pytest.raises(
            CertificateError, match=r"Unexpected certificate content\."
        ):
            extract_patterns(cert)

    def test_ip(self):
        """
        Returns IP patterns.
        """
        rv = extract_patterns(CERT_EVERYTHING)

        assert [
            DNSPattern.from_bytes(pattern=b"service.identity.invalid"),
            DNSPattern.from_bytes(
                pattern=b"*.wildcard.service.identity.invalid"
            ),
            DNSPattern.from_bytes(pattern=b"service.identity.invalid"),
            DNSPattern.from_bytes(pattern=b"single.service.identity.invalid"),
            IPAddressPattern(pattern=ipaddress.IPv4Address("1.1.1.1")),
            IPAddressPattern(pattern=ipaddress.IPv6Address("::1")),
            IPAddressPattern(pattern=ipaddress.IPv4Address("2.2.2.2")),
            IPAddressPattern(pattern=ipaddress.IPv6Address("2a00:1c38::53")),
        ] == rv

    def test_extract_ids_deprecated(self):
        """
        `extract_ids` raises a DeprecationWarning with correct stacklevel.
        """
        with pytest.deprecated_call() as wr:
            extract_ids(CERT_EVERYTHING)

        w = wr.pop()

        assert (
            "`extract_ids()` is deprecated, please use `extract_patterns()`."
            == w.message.args[0]
        )
        assert __file__ == w.filename


class TestCommonNameFallbackPolicy:
    """
    The commonName fallback is an explicit, auditable policy.
    """

    def test_default_behavior_unchanged(self):
        """
        Without an explicit policy, a certificate without subjectAltNames
        raises the same CertificateError as before, even if it carries a
        matching commonName.
        """
        cert = cn_certificate("legacy.example.com")

        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s",
        ):
            verify_certificate_hostname(cert, "legacy.example.com")

        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s",
        ):
            verify_certificate_hostname_with_policy(cert, "legacy.example.com")

    def test_no_san_fallback_disabled_classification(self):
        """
        "No SAN and fallback disabled" is classified as
        SubjectAltNameMissingError, a CertificateError.
        """
        cert = cn_certificate("legacy.example.com")

        with pytest.raises(SubjectAltNameMissingError) as ei:
            verify_certificate_hostname_with_policy(
                cert,
                "legacy.example.com",
                common_name_fallback=CommonNameFallback.DENY,
            )

        assert isinstance(ei.value, CertificateError)

    def test_fallback_matches_valid_cn(self):
        """
        With ALLOW_IF_NO_SAN, a SAN-less certificate verifies against its
        commonName and the match is returned for auditing.
        """
        cert = cn_certificate("legacy.example.com")

        matches = verify_certificate_hostname_with_policy(
            cert,
            "legacy.example.com",
            common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
        )

        assert [
            ServiceMatch(
                service_id=DNS_ID("legacy.example.com"),
                cert_pattern=DNSPattern.from_bytes(b"legacy.example.com"),
            )
        ] == matches

    def test_fallback_cn_mismatch(self):
        """
        A non-matching commonName fails with a VerificationError even if the
        fallback is allowed.
        """
        cert = cn_certificate("legacy.example.com")

        with pytest.raises(VerificationError) as ei:
            verify_certificate_hostname_with_policy(
                cert,
                "other.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

        assert [
            DNSMismatch(mismatched_id=DNS_ID("other.example.com"))
        ] == ei.value.errors

    def test_uri_only_san_ignores_cn(self):
        """
        A certificate with only a URI subjectAltName is not eligible for the
        commonName fallback: the commonName is ignored and verification
        fails with a VerificationError ("SAN present, but nothing matched").
        """
        cert = cn_certificate(
            "user.example.com",
            san=[x509.UniformResourceIdentifier("https://user.example.com/")],
        )

        with pytest.raises(VerificationError) as ei:
            verify_certificate_hostname_with_policy(
                cert,
                "user.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

        assert [
            DNSMismatch(mismatched_id=DNS_ID("user.example.com"))
        ] == ei.value.errors
        assert [
            URIPattern.from_bytes(b"https://user.example.com/")
        ] == extract_patterns(
            cert, common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN
        )

    def test_ip_only_san_ignores_cn(self):
        """
        A certificate with only an IP subjectAltName is not eligible for
        the commonName fallback either.
        """
        cert = cn_certificate(
            "user.example.com",
            san=[x509.IPAddress(ipaddress.IPv4Address("203.0.113.7"))],
        )

        with pytest.raises(VerificationError):
            verify_certificate_hostname_with_policy(
                cert,
                "user.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

    def test_dns_san_shadows_conflicting_cn(self):
        """
        If a certificate carries both a DNS SAN and a conflicting
        commonName, only the SAN is consulted -- the commonName can never
        be used to escalate.
        """
        cert = cn_certificate(
            "admin.example.com",
            san=[x509.DNSName("user.example.com")],
        )

        verify_certificate_hostname_with_policy(
            cert,
            "user.example.com",
            common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
        )

        with pytest.raises(VerificationError) as ei:
            verify_certificate_hostname_with_policy(
                cert,
                "admin.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

        assert [
            DNSMismatch(mismatched_id=DNS_ID("admin.example.com"))
        ] == ei.value.errors

    def test_invalid_cn_ignored_when_san_present(self):
        """
        A structurally invalid commonName is never even looked at if the
        certificate carries a subjectAltName extension.
        """
        cert = make_certificate(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "a.example.com"),
                x509.NameAttribute(NameOID.COMMON_NAME, "b.example.com"),
            ],
            san=[x509.DNSName("a.example.com")],
        )

        verify_certificate_hostname_with_policy(
            cert,
            "a.example.com",
            common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
        )

    def test_duplicate_cn_rejected(self):
        """
        More than one commonName attribute is structurally invalid.
        """
        cert = make_certificate(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "a.example.com"),
                x509.NameAttribute(NameOID.COMMON_NAME, "b.example.com"),
            ]
        )

        with pytest.raises(
            InvalidSubjectCommonNameError, match="more than one commonName"
        ):
            verify_certificate_hostname_with_policy(
                cert,
                "a.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

    def test_multi_valued_rdn_rejected(self):
        """
        A commonName inside a multi-valued RDN is structurally invalid.
        """
        cert = make_certificate(
            [
                x509.RelativeDistinguishedName(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "a.example.com"
                        ),
                        x509.NameAttribute(
                            NameOID.ORGANIZATIONAL_UNIT_NAME, "ou"
                        ),
                    ]
                )
            ]
        )

        with pytest.raises(
            InvalidSubjectCommonNameError, match="multi-valued RDN"
        ):
            verify_certificate_hostname_with_policy(
                cert,
                "a.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

    def test_empty_cn_rejected(self):
        """
        An empty (whitespace-only) commonName is structurally invalid.
        """
        cert = cn_certificate(" ")

        with pytest.raises(
            InvalidSubjectCommonNameError, match="commonName is empty"
        ):
            verify_certificate_hostname_with_policy(
                cert,
                "a.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

    def test_wildcard_cn_rejected(self):
        """
        A commonName that looks like a wildcard pattern is structurally
        invalid.
        """
        cert = cn_certificate("*.example.com")

        with pytest.raises(InvalidSubjectCommonNameError, match="wildcard"):
            verify_certificate_hostname_with_policy(
                cert,
                "www.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

    def test_bad_idna_cn_rejected(self):
        """
        A commonName that is not IDNA-encodable is structurally invalid.
        """
        cert = cn_certificate(chr(0x1F4A9) + ".example.com")

        with pytest.raises(
            InvalidSubjectCommonNameError, match="not a valid DNS name"
        ):
            verify_certificate_hostname_with_policy(
                cert,
                "whatever.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

    def test_structural_errors_are_certificate_errors(self):
        """
        "Certificate structure invalid" is classified as a CertificateError
        subclass, distinct from SubjectAltNameMissingError.
        """
        cert = cn_certificate("*.example.com")

        with pytest.raises(CertificateError) as ei:
            verify_certificate_hostname_with_policy(
                cert,
                "www.example.com",
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )

        assert isinstance(ei.value, InvalidSubjectCommonNameError)
        assert not isinstance(ei.value, SubjectAltNameMissingError)


class TestExtractCommonNamePattern:
    def test_valid_cn(self):
        """
        A single, well-formed commonName becomes a DNSPattern.
        """
        assert DNSPattern.from_bytes(b"legacy.example.com") == (
            extract_common_name_pattern(cn_certificate("legacy.example.com"))
        )

    def test_cn_is_read_from_subject_not_extensions(self):
        """
        The commonName comes from the subject; a SAN-less certificate
        yields no patterns unless the fallback policy allows it.
        """
        cert = cn_certificate("legacy.example.com")

        assert [] == extract_patterns(cert)
        assert [DNSPattern.from_bytes(b"legacy.example.com")] == (
            extract_patterns(
                cert,
                common_name_fallback=CommonNameFallback.ALLOW_IF_NO_SAN,
            )
        )

    def test_no_cn(self):
        """
        A subject without any commonName is structurally invalid for the
        fallback.
        """
        cert = make_certificate(
            [x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "no-cn")]
        )

        with pytest.raises(
            InvalidSubjectCommonNameError, match="no commonName"
        ):
            extract_common_name_pattern(cert)
