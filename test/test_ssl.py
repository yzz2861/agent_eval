from __future__ import annotations

import ssl
import sys
import typing
from unittest import mock

import pytest

from urllib3.exceptions import ProxySchemeUnsupported, SSLError
from urllib3.util import ssl_
from urllib3.util.ssl_match_hostname import (
    CertificateError,
    _dnsname_match,
    match_hostname,
    normalize_hostname,
)


class TestSSL:
    @pytest.mark.parametrize(
        "addr",
        [
            # IPv6
            "::1",
            "::",
            "FE80::8939:7684:D84b:a5A4%251",
            # IPv4
            "127.0.0.1",
            "8.8.8.8",
            b"127.0.0.1",
            # Non-standard IPv4 forms accepted by socket.connect
            "2130706433",  # decimal integer
            "0x7f000001",  # hex integer
            "0177.0.0.01",  # dotted octal
            "0x7f.0x0.0x0.0x1",  # dotted hex
            "127.1",  # 2-part
            "127.0.1",  # 3-part
            # IPv6 w/ Zone IDs
            "FE80::8939:7684:D84b:a5A4%251",
            b"FE80::8939:7684:D84b:a5A4%251",
            "FE80::8939:7684:D84b:a5A4%19",
            b"FE80::8939:7684:D84b:a5A4%19",
        ],
    )
    def test_is_ipaddress_true(self, addr: bytes | str) -> None:
        assert ssl_.is_ipaddress(addr)

    @pytest.mark.parametrize(
        "addr",
        [
            "www.python.org",
            b"www.python.org",
            "v2.sg.media-imdb.com",
            b"v2.sg.media-imdb.com",
        ],
    )
    def test_is_ipaddress_false(self, addr: bytes | str) -> None:
        assert not ssl_.is_ipaddress(addr)

    def test_create_urllib3_context_set_ciphers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ciphers = "ECDH+AESGCM:ECDH+CHACHA20"
        context = mock.create_autospec(ssl_.SSLContext)
        context.set_ciphers = mock.Mock()
        context.options = 0
        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        assert ssl_.create_urllib3_context(ciphers=ciphers) is context

        assert context.set_ciphers.call_count == 1
        assert context.set_ciphers.call_args == mock.call(ciphers)

    def test_create_urllib3_no_context(self) -> None:
        with mock.patch("urllib3.util.ssl_.SSLContext", None):
            with pytest.raises(TypeError):
                ssl_.create_urllib3_context()

    def test_create_urllib3_context_default_verify_flags(self) -> None:
        context = ssl_.create_urllib3_context()
        if sys.version_info >= (3, 13):
            assert context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
            assert context.verify_flags & ssl.VERIFY_X509_STRICT
        else:
            assert not (context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN)
            assert not (context.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_create_urllib3_context_custom_verify_flags(self) -> None:
        context = ssl_.create_urllib3_context()
        assert not (context.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF)
        context = ssl_.create_urllib3_context(verify_flags=ssl.VERIFY_CRL_CHECK_LEAF)
        assert context.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF

    def test_wrap_socket_given_context_no_load_default_certs(self) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.load_default_certs = mock.Mock()

        sock = mock.Mock()
        ssl_.ssl_wrap_socket(sock, ssl_context=context)

        context.load_default_certs.assert_not_called()

    def test_wrap_socket_given_ca_certs_no_load_default_certs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.load_default_certs = mock.Mock()
        context.options = 0

        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        sock = mock.Mock()
        ssl_.ssl_wrap_socket(sock, ca_certs="/tmp/fake-file")

        context.load_default_certs.assert_not_called()
        context.load_verify_locations.assert_called_with("/tmp/fake-file", None, None)

    def test_wrap_socket_default_loads_default_certs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.load_default_certs = mock.Mock()
        context.options = 0

        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        sock = mock.Mock()
        ssl_.ssl_wrap_socket(sock)

        context.load_default_certs.assert_called_with()

    def test_wrap_socket_no_ssltransport(self) -> None:
        with mock.patch("urllib3.util.ssl_.SSLTransport", None):
            with pytest.raises(ProxySchemeUnsupported):
                sock = mock.Mock()
                ssl_.ssl_wrap_socket(sock, tls_in_tls=True)

    @pytest.mark.parametrize(
        ["pha", "expected_pha", "cert_reqs"],
        [
            (None, None, None),
            (None, None, ssl.CERT_NONE),
            (None, None, ssl.CERT_OPTIONAL),
            (None, None, ssl.CERT_REQUIRED),
            (False, True, None),
            (False, True, ssl.CERT_NONE),
            (False, True, ssl.CERT_OPTIONAL),
            (False, True, ssl.CERT_REQUIRED),
            (True, True, None),
            (True, True, ssl.CERT_NONE),
            (True, True, ssl.CERT_OPTIONAL),
            (True, True, ssl.CERT_REQUIRED),
        ],
    )
    def test_create_urllib3_context_pha(
        self,
        monkeypatch: pytest.MonkeyPatch,
        pha: bool | None,
        expected_pha: bool | None,
        cert_reqs: int | None,
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.set_ciphers = mock.Mock()
        context.options = 0
        context.post_handshake_auth = pha
        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        assert ssl_.create_urllib3_context(cert_reqs=cert_reqs) is context

        assert context.post_handshake_auth == expected_pha

    def test_create_urllib3_context_default_ciphers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.create_autospec(ssl_.SSLContext)
        context.set_ciphers = mock.Mock()
        context.options = 0
        monkeypatch.setattr(ssl_, "SSLContext", lambda *_, **__: context)

        ssl_.create_urllib3_context()

        context.set_ciphers.assert_not_called()

    # PROTOCOL_TLS_SERVER is used as a stand-in for any non-default ssl_version.
    # PROTOCOL_TLSv1/TLSv1_2 are unavailable when Python is built with OpenSSL 4+.
    @pytest.mark.parametrize(
        "kwargs",
        [
            {
                "ssl_version": ssl.PROTOCOL_TLS_SERVER,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
            {
                "ssl_version": ssl.PROTOCOL_TLS_SERVER,
                "ssl_maximum_version": ssl.TLSVersion.TLSv1,
            },
            {
                "ssl_version": ssl.PROTOCOL_TLS_SERVER,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
                "ssl_maximum_version": ssl.TLSVersion.MAXIMUM_SUPPORTED,
            },
        ],
    )
    def test_create_urllib3_context_ssl_version_and_ssl_min_max_version_errors(
        self, kwargs: dict[str, typing.Any]
    ) -> None:
        with pytest.raises(ValueError) as e:
            ssl_.create_urllib3_context(**kwargs)

        assert str(e.value) == (
            "Can't specify both 'ssl_version' and either 'ssl_minimum_version' or 'ssl_maximum_version'"
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {
                "ssl_version": ssl.PROTOCOL_TLS,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
            {
                "ssl_version": ssl.PROTOCOL_TLS_CLIENT,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
            {
                "ssl_version": None,
                "ssl_minimum_version": ssl.TLSVersion.MINIMUM_SUPPORTED,
            },
        ],
    )
    def test_create_urllib3_context_ssl_version_and_ssl_min_max_version_no_warning(
        self, kwargs: dict[str, typing.Any]
    ) -> None:
        ssl_.create_urllib3_context(**kwargs)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"ssl_version": ssl.PROTOCOL_TLS_SERVER, "ssl_minimum_version": None},
            {"ssl_version": ssl.PROTOCOL_TLS_SERVER, "ssl_maximum_version": None},
            {
                "ssl_version": ssl.PROTOCOL_TLS_SERVER,
                "ssl_minimum_version": None,
                "ssl_maximum_version": None,
            },
        ],
    )
    def test_create_urllib3_context_ssl_version_and_ssl_min_max_version_no_error(
        self, kwargs: dict[str, typing.Any]
    ) -> None:
        with pytest.warns(
            FutureWarning,
            match=r"'ssl_version' option is deprecated and will be removed in "
            r"urllib3 v3\.0\. Instead use 'ssl_minimum_version'",
        ):
            ssl_.create_urllib3_context(**kwargs)

    def test_assert_fingerprint_raises_exception_on_none_cert(self) -> None:
        with pytest.raises(SSLError):
            ssl_.assert_fingerprint(
                cert=None, fingerprint="55:39:BF:70:05:12:43:FA:1F:D1:BF:4E:E8:1B:07:1D"
            )

    @pytest.mark.parametrize(
        "fingerprint",
        [
            "g" * 32,
            "g" * 40,
            "g" * 64,
            "a" * 39 + "g",
            "GG:" * 19 + "GG",
        ],
    )
    def test_assert_fingerprint_raises_sslerror_on_non_hexadecimal(
        self, fingerprint: str
    ) -> None:
        with pytest.raises(SSLError):
            ssl_.assert_fingerprint(b"certificate", fingerprint)


class TestHostnameMatching:
    def test_normalize_hostname_unicode_case_and_trailing_dot(self) -> None:
        assert normalize_hostname("BÜCHER.Example.COM.") == (
            "xn--bcher-kva.example.com"
        )
        assert normalize_hostname("xn--BCHER-KVA.EXAMPLE.") == ("xn--bcher-kva.example")
        assert normalize_hostname("bu\u0308cher.example") == ("xn--bcher-kva.example")

    def test_normalize_hostname_rejects_empty_labels(self) -> None:
        for name in ("example..com", ".example.com", "example.."):
            with pytest.raises(CertificateError, match="empty label"):
                normalize_hostname(name)

    def test_normalize_hostname_ip_literals(self) -> None:
        assert normalize_hostname("127.0.0.1") == "127.0.0.1"
        assert normalize_hostname("[::1]") == "::1"
        assert normalize_hostname("[2001:db8::1%42]") == "2001:db8::1"

    def test_match_hostname_unicode_domain(self) -> None:
        cert = {"subjectAltName": (("DNS", "xn--bcher-kva.example"),)}
        match_hostname(cert, "BÜCHER.EXAMPLE.")

    def test_match_hostname_punycode_and_case(self) -> None:
        cert = {"subjectAltName": (("DNS", "XN--BCHER-KVA.EXAMPLE"),)}
        match_hostname(cert, "bücher.example")

    def test_match_hostname_ipv4_requires_ip_san(self) -> None:
        match_hostname(
            {"subjectAltName": (("IP Address", "127.0.0.1"),)},
            "127.0.0.1",
        )
        with pytest.raises(CertificateError, match="IP literal.*DNS SAN"):
            match_hostname(
                {"subjectAltName": (("DNS", "127.0.0.1"),)},
                "127.0.0.1",
            )

    def test_match_hostname_ipv6_literal_and_zone_id(self) -> None:
        cert = {"subjectAltName": (("IP Address", "2001:db8::1"),)}
        match_hostname(cert, "[2001:db8::1]")
        match_hostname(cert, "2001:db8::1%en0")

    def test_match_hostname_ipv6_does_not_match_dns_san(self) -> None:
        with pytest.raises(CertificateError, match="IP literal.*DNS SAN"):
            match_hostname(
                {"subjectAltName": (("DNS", "example.com"),)},
                "[2001:db8::1]",
            )

    def test_match_hostname_ip_type_mismatch(self) -> None:
        with pytest.raises(CertificateError, match="IP type mismatch"):
            match_hostname(
                {"subjectAltName": (("IP Address", "2001:db8::1"),)},
                "127.0.0.1",
            )

    def test_match_hostname_wildcard_leftmost_only(self) -> None:
        cert = {"subjectAltName": (("DNS", "*.example.com"),)}
        match_hostname(cert, "a.example.com")
        with pytest.raises(CertificateError, match="SAN mismatch"):
            match_hostname(cert, "a.b.example.com")

    def test_dnsname_match_wildcard_cannot_match_empty_label(self) -> None:
        assert not _dnsname_match("*.example.com", ".example.com")
        assert not _dnsname_match("example.*.com", "example.foo.com")

    def test_match_hostname_multiple_sans(self) -> None:
        cert = {
            "subjectAltName": (
                ("DNS", "first.example.com"),
                ("DNS", "*.example.com"),
                ("IP Address", "127.0.0.1"),
            )
        }
        match_hostname(cert, "second.example.com")
        match_hostname(cert, "127.0.0.1")

    def test_match_hostname_common_name_fallback(self) -> None:
        cert = {"subject": ((("commonName", "example.com"),),)}
        with pytest.raises(CertificateError, match="SAN mismatch"):
            match_hostname(cert, "example.com")
        match_hostname(cert, "EXAMPLE.COM.", hostname_checks_common_name=True)

    def test_match_hostname_common_name_not_used_with_san(self) -> None:
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "subjectAltName": (("DNS", "other.example.com"),),
        }
        with pytest.raises(CertificateError, match="SAN mismatch"):
            match_hostname(cert, "example.com", hostname_checks_common_name=True)

    def test_match_hostname_expired_certificate(self) -> None:
        cert = {
            "subjectAltName": (("DNS", "example.com"),),
            "notAfter": "Jan  1 00:00:00 2020 GMT",
        }
        with pytest.raises(CertificateError, match="certificate is expired"):
            match_hostname(cert, "example.com")

    def test_match_hostname_invalid_certificate(self) -> None:
        with pytest.raises(CertificateError, match="invalid certificate"):
            match_hostname(None, "example.com")
        with pytest.raises(CertificateError, match="invalid certificate"):
            match_hostname({}, "example.com")
        with pytest.raises(CertificateError, match="empty label"):
            match_hostname(
                {"subjectAltName": (("DNS", "example..com"),)},
                "example.com",
            )

    def test_hostname_check_disabled_skips_only_hostname_verification(self) -> None:
        from urllib3.connection import _ssl_wrap_socket_and_match_hostname

        context = mock.Mock(spec=ssl.SSLContext)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.hostname_checks_common_name = False
        ssl_sock = mock.Mock()
        ssl_sock.getpeercert.return_value = {
            "subjectAltName": (("DNS", "not-example.com"),)
        }

        match = mock.Mock()
        with (
            mock.patch("urllib3.connection.ssl_wrap_socket", return_value=ssl_sock),
            mock.patch("urllib3.connection._match_hostname", match),
        ):
            result = _ssl_wrap_socket_and_match_hostname(
                sock=mock.Mock(),
                cert_reqs=ssl.CERT_REQUIRED,
                ssl_version=None,
                ssl_minimum_version=None,
                ssl_maximum_version=None,
                cert_file=None,
                key_file=None,
                key_password=None,
                ca_certs=None,
                ca_cert_dir=None,
                ca_cert_data=None,
                assert_hostname=False,
                assert_fingerprint=None,
                server_hostname="example.com",
                ssl_context=context,
            )

        assert result.is_verified is True
        assert context.check_hostname is False
        assert context.verify_mode == ssl.CERT_REQUIRED
        match.assert_not_called()
        ssl_sock.getpeercert.assert_not_called()

    def test_ssl_wrap_socket_normalizes_unicode_server_hostname(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = mock.Mock(spec=ssl.SSLContext)
        context.load_default_certs = mock.Mock()
        wrapped = mock.Mock()
        monkeypatch.setattr(
            ssl_,
            "_ssl_wrap_socket_impl",
            mock.Mock(return_value=wrapped),
        )

        result = ssl_.ssl_wrap_socket(
            sock=mock.Mock(),
            ssl_context=context,
            server_hostname="BÜCHER.Example.",
        )

        assert result is wrapped
        ssl_._ssl_wrap_socket_impl.assert_called_once_with(  # type: ignore[attr-defined]
            mock.ANY,
            context,
            False,
            "xn--bcher-kva.example",
        )
