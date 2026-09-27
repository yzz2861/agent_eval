from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from hypercorn.config import Config
from hypercorn.sni import Certificate, CertificateError


def _make_certificate(directory: Path, name: str, common_name: str) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certfile = directory / f"{name}.crt"
    keyfile = directory / f"{name}.key"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(certfile), str(keyfile)


def _handshake(
    server_context: ssl.SSLContext,
    server_hostname: str | None,
    alpn_protocols: list[str] | None = None,
) -> tuple[ssl.SSLObject, ssl.SSLObject]:
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    if alpn_protocols is not None:
        client_context.set_alpn_protocols(alpn_protocols)
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(
        client_in, client_out, server_side=False, server_hostname=server_hostname
    )
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    for _ in range(100):
        client_done = server_done = False
        try:
            client.do_handshake()
            client_done = True
        except ssl.SSLWantReadError:
            pass
        data = client_out.read()
        if data:
            server_in.write(data)
        try:
            server.do_handshake()
            server_done = True
        except ssl.SSLWantReadError:
            pass
        data = server_out.read()
        if data:
            client_in.write(data)
        if client_done and server_done:
            return client, server
    raise AssertionError("Handshake did not complete")


def _served_common_name(
    server_context: ssl.SSLContext, server_hostname: str | None
) -> str:
    client, _ = _handshake(server_context, server_hostname)
    certificate = x509.load_der_x509_certificate(client.getpeercert(binary_form=True))
    return str(certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)


@pytest.fixture(name="certificates")
def _certificates(tmp_path: Path) -> dict[str, tuple[str, str]]:
    return {
        "one": _make_certificate(tmp_path, "one", "one.example.com"),
        "two": _make_certificate(tmp_path, "two", "two.example.com"),
    }


def _config(certificates: dict[str, tuple[str, str]]) -> Config:
    config = Config()
    config.certfile, config.keyfile = certificates["one"]
    config.sni_certificates = [
        {
            "domains": ["exact.example.net", "*.example.com"],
            "certfile": certificates["two"][0],
            "keyfile": certificates["two"][1],
        },
        {
            "domains": ["exact.example.com"],
            "certfile": certificates["one"][0],
            "keyfile": certificates["one"][1],
        },
    ]
    return config


def test_sni_selects_certificate(certificates: dict[str, tuple[str, str]]) -> None:
    context = _config(certificates).create_ssl_context()
    # Exact matches
    assert _served_common_name(context, "exact.example.net") == "two.example.com"
    # Exact matches take precedence over wildcards
    assert _served_common_name(context, "exact.example.com") == "one.example.com"
    # Single level wildcard matches
    assert _served_common_name(context, "anything.example.com") == "two.example.com"
    # Wildcards do not match multiple levels
    assert _served_common_name(context, "deep.sub.example.com") == "one.example.com"
    # Unknown and missing SNI use the default certificate
    assert _served_common_name(context, "unknown.example.org") == "one.example.com"
    assert _served_common_name(context, None) == "one.example.com"


def test_sni_reload_applies_to_new_handshakes(
    certificates: dict[str, tuple[str, str]], tmp_path: Path
) -> None:
    config = _config(certificates)
    context = config.create_ssl_context()
    assert _served_common_name(context, "exact.example.net") == "two.example.com"
    renewed = _make_certificate(tmp_path, "renewed", "renewed.example.net")
    config.certificate_store.reload(
        Certificate(*certificates["one"]),
        [("exact.example.net", Certificate(*renewed))],
    )
    assert _served_common_name(context, "exact.example.net") == "renewed.example.net"
    assert _served_common_name(context, None) == "one.example.com"


def test_sni_reload_is_atomic(
    certificates: dict[str, tuple[str, str]], tmp_path: Path
) -> None:
    config = _config(certificates)
    context = config.create_ssl_context()
    store = config.certificate_store
    broken_key = tmp_path / "broken.key"
    broken_key.write_text("not a private key")
    with pytest.raises(CertificateError):
        store.reload(
            Certificate(*certificates["one"]),
            [("exact.example.net", Certificate(certificates["two"][0], str(broken_key)))],
        )
    with pytest.raises(CertificateError):
        store.reload(
            Certificate(*certificates["one"]),
            [("invalid.*.example.net", Certificate(*certificates["two"]))],
        )
    with pytest.raises(CertificateError):
        store.reload(
            Certificate(*certificates["one"]),
            [
                ("exact.example.net", Certificate(*certificates["two"])),
                ("EXACT.example.net", Certificate(*certificates["two"])),
            ],
        )
    # The failed updates have no effect, every domain still handshakes
    assert _served_common_name(context, "exact.example.net") == "two.example.com"
    assert _served_common_name(context, "exact.example.com") == "one.example.com"
    assert _served_common_name(context, "anything.example.com") == "two.example.com"
    assert _served_common_name(context, "unknown.example.org") == "one.example.com"
    assert _served_common_name(context, None) == "one.example.com"


def test_sni_does_not_change_alpn_or_verification(
    certificates: dict[str, tuple[str, str]],
) -> None:
    config = _config(certificates)
    config.alpn_protocols = ["h2"]
    config.verify_mode = ssl.CERT_OPTIONAL
    context = config.create_ssl_context()
    store = config.certificate_store
    for server_name in ["exact.example.net", "anything.example.com", "unknown.org", None]:
        assert store.select(server_name).verify_mode == ssl.CERT_OPTIONAL
    _, server = _handshake(context, "exact.example.net", alpn_protocols=["h2"])
    assert server.selected_alpn_protocol() == "h2"
    _, server = _handshake(context, "unknown.example.org", alpn_protocols=["h2"])
    assert server.selected_alpn_protocol() == "h2"


def test_single_certificate_configuration_still_works(
    certificates: dict[str, tuple[str, str]],
) -> None:
    config = Config()
    config.certfile, config.keyfile = certificates["one"]
    context = config.create_ssl_context()
    assert _served_common_name(context, "anything.example.org") == "one.example.com"
    assert _served_common_name(context, None) == "one.example.com"
