from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path

import pytest
import trustme

from hypercorn.config import Config
from hypercorn.sni import CertificateGroup


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="module")
def cert_dir(tmp_path_factory: pytest.TempPathFactory, ca: trustme.CA) -> Path:
    directory = tmp_path_factory.mktemp('certs')
    (directory / "ca.pem").write_bytes(ca.cert_pem.bytes())
    return directory


def _issue(ca: trustme.CA, directory: Path, name: str, *identities: str) -> tuple[str, str]:
    cert = ca.issue_cert(*identities)
    certfile = directory / f"{name}.crt"
    keyfile = directory / f"{name}.key"
    certfile.write_bytes(cert.cert_chain_pems[0].bytes())
    keyfile.write_bytes(cert.private_key_pem.bytes())
    return str(certfile), str(keyfile)


def _der(certfile: str) -> bytes:
    pem = Path(certfile).read_text()
    return ssl.PEM_cert_to_DER_cert(pem)


def _handshake(
    context: ssl.SSLContext,
    server_name: str | None,
    *,
    alpn_protocols: list[str] | None = None,
) -> tuple[ssl.SSLSocket, ssl.SSLSocket, dict[str, Exception]]:
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    if alpn_protocols is not None:
        client_context.set_alpn_protocols(alpn_protocols)
    server_raw, client_raw = socket.socketpair()
    server = context.wrap_socket(server_raw, server_side=True, do_handshake_on_connect=False)
    client = client_context.wrap_socket(
        client_raw, server_hostname=server_name, do_handshake_on_connect=False
    )
    server.settimeout(5)
    client.settimeout(5)
    errors: dict[str, Exception] = {}

    def shake(sock: ssl.SSLSocket, key: str) -> None:
        try:
            sock.do_handshake()
        except Exception as error:  # noqa: BLE001
            errors[key] = error

    threads = [
        threading.Thread(target=shake, args=(server, 'server')),
        threading.Thread(target=shake, args=(client, 'client')),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return server, client, errors


def _config(
    cert_dir: Path,
    ca: trustme.CA,
    sni_certificates: dict,
    *,
    sni_default: str = 'certificate',
    with_default: bool = True,
) -> Config:
    config = Config()
    if with_default:
        config.certfile, config.keyfile = _issue(ca, cert_dir, 'default', 'default.example.com')
    config.sni_certificates = sni_certificates
    config.sni_default = sni_default
    return config


def test_sni_selects_certificate_by_domain(cert_dir: Path, ca: trustme.CA) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    beta = _issue(ca, cert_dir, 'beta', 'beta.example.com')
    config = _config(
        cert_dir,
        ca,
        {'alpha.example.com': alpha, 'beta.example.com': {'certfile': beta[0], 'keyfile': beta[1]}},
    )
    context = config.create_ssl_context()
    assert config.certificate_group is not None

    for server_name, expected in [
        ('alpha.example.com', alpha),
        ('ALPHA.example.com', alpha),
        ('alpha.example.com.', alpha),
        ('beta.example.com', beta),
    ]:
        server, client, errors = _handshake(context, server_name)
        assert not errors
        assert client.getpeercert(binary_form=True) == _der(expected[0])
        server.close()
        client.close()


def test_sni_unknown_and_missing_name_uses_default_certificate(
    cert_dir: Path, ca: trustme.CA
) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    config = _config(cert_dir, ca, {'alpha.example.com': alpha})
    context = config.create_ssl_context()

    for server_name in ('unknown.example.com', None):
        server, client, errors = _handshake(context, server_name)
        assert not errors
        assert client.getpeercert(binary_form=True) == _der(config.certfile)
        server.close()
        client.close()


def test_sni_exact_beats_single_level_wildcard(cert_dir: Path, ca: trustme.CA) -> None:
    wildcard = _issue(ca, cert_dir, 'wildcard', '*.wild.example.com')
    exact = _issue(ca, cert_dir, 'exact', 'exact.wild.example.com')
    config = _config(
        cert_dir,
        ca,
        {'*.wild.example.com': wildcard, 'exact.wild.example.com': exact},
    )
    context = config.create_ssl_context()

    server, client, errors = _handshake(context, 'foo.wild.example.com')
    assert not errors
    assert client.getpeercert(binary_form=True) == _der(wildcard[0])
    server.close()
    client.close()

    server, client, errors = _handshake(context, 'exact.wild.example.com')
    assert not errors
    assert client.getpeercert(binary_form=True) == _der(exact[0])
    server.close()
    client.close()

    # A single-level wildcard must not match multiple labels or the bare domain
    for server_name in ('a.b.wild.example.com', 'wild.example.com'):
        server, client, errors = _handshake(context, server_name)
        assert not errors
        assert client.getpeercert(binary_form=True) == _der(config.certfile)
        server.close()
        client.close()


def test_sni_reject_default_policy(cert_dir: Path, ca: trustme.CA) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    config = _config(cert_dir, ca, {'alpha.example.com': alpha}, sni_default='reject')
    context = config.create_ssl_context()

    server, client, errors = _handshake(context, 'alpha.example.com')
    assert not errors
    assert client.getpeercert(binary_form=True) == _der(alpha[0])
    server.close()
    client.close()

    for server_name in ('unknown.example.com', None):
        server, client, errors = _handshake(context, server_name)
        assert 'server' in errors
        assert 'client' in errors
        server.close()
        client.close()


def test_sni_selection_preserves_alpn_and_verify_policy(cert_dir: Path, ca: trustme.CA) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    config = _config(cert_dir, ca, {'alpha.example.com': alpha})
    config.alpn_protocols = ['h2', 'http/1.1']
    config.ca_certs = str(cert_dir / 'ca.pem')
    config.verify_mode = ssl.CERT_OPTIONAL
    context = config.create_ssl_context()

    server, client, errors = _handshake(
        context, 'alpha.example.com', alpn_protocols=['h2', 'http/1.1']
    )
    assert not errors
    assert client.getpeercert(binary_form=True) == _der(alpha[0])
    assert server.selected_alpn_protocol() == 'h2'
    assert server.context is not context
    assert server.context.verify_mode == ssl.CERT_OPTIONAL
    server.close()
    client.close()


def test_certificate_group_reload_applies_to_new_handshakes(
    cert_dir: Path, ca: trustme.CA
) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    config = _config(cert_dir, ca, {'alpha.example.com': alpha})
    context = config.create_ssl_context()
    group = config.certificate_group

    renewed = _issue(ca, cert_dir, 'alpha-renewed', 'alpha.example.com')
    group.reload({'alpha.example.com': renewed})

    server, client, errors = _handshake(context, 'alpha.example.com')
    assert not errors
    assert client.getpeercert(binary_form=True) == _der(renewed[0])
    server.close()
    client.close()


def test_certificate_group_reload_is_atomic_on_broken_key(
    cert_dir: Path, ca: trustme.CA
) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    beta = _issue(ca, cert_dir, 'beta', 'beta.example.com')
    config = _config(cert_dir, ca, {'alpha.example.com': alpha, 'beta.example.com': beta})
    context = config.create_ssl_context()
    group = config.certificate_group

    broken_key = cert_dir / 'broken.key'
    broken_key.write_text('not a private key')
    with pytest.raises(ssl.SSLError):
        group.reload(
            {
                'alpha.example.com': (alpha[0], str(broken_key)),
                'beta.example.com': beta,
            }
        )

    # The failed update must not take effect: every domain still handshakes
    for server_name, expected in [
        ('alpha.example.com', alpha),
        ('beta.example.com', beta),
        ('unknown.example.com', (config.certfile, config.keyfile)),
    ]:
        server, client, errors = _handshake(context, server_name)
        assert not errors
        assert client.getpeercert(binary_form=True) == _der(expected[0])
        server.close()
        client.close()


def test_certificate_group_reload_is_atomic_on_invalid_domain(
    cert_dir: Path, ca: trustme.CA
) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    config = _config(cert_dir, ca, {'alpha.example.com': alpha})
    context = config.create_ssl_context()
    group = config.certificate_group

    with pytest.raises(ValueError):
        group.reload({'alpha.*.example.com': alpha})

    server, client, errors = _handshake(context, 'alpha.example.com')
    assert not errors
    assert client.getpeercert(binary_form=True) == _der(alpha[0])
    server.close()
    client.close()


@pytest.mark.parametrize(
    'domain',
    ['', '*', '*.', 'foo.*.com', 'ex*ample.com', 'a..com', '-bad.com', 'bad-.com', 'bad_name.com'],
)
def test_invalid_domain_rules_rejected(cert_dir: Path, ca: trustme.CA, domain: str) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    with pytest.raises(ValueError):
        CertificateGroup(
            {domain: alpha},
            context_factory=lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
            has_default_certificate=False,
            default='reject',
        )


def test_duplicate_domains_rejected(cert_dir: Path, ca: trustme.CA) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    with pytest.raises(ValueError):
        CertificateGroup(
            {'alpha.example.com': alpha, 'ALPHA.example.com.': alpha},
            context_factory=lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
            has_default_certificate=False,
            default='reject',
        )


def test_unknown_default_policy_rejected(cert_dir: Path, ca: trustme.CA) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    with pytest.raises(ValueError):
        CertificateGroup(
            {'alpha.example.com': alpha},
            context_factory=lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
            has_default_certificate=True,
            default='invalid',
        )


def test_certificate_default_policy_requires_default_certificate(
    cert_dir: Path, ca: trustme.CA
) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    config = _config(cert_dir, ca, {'alpha.example.com': alpha}, with_default=False)
    assert config.ssl_enabled
    with pytest.raises(ValueError):
        config.create_ssl_context()


def test_sni_only_configuration_handshakes(cert_dir: Path, ca: trustme.CA) -> None:
    alpha = _issue(ca, cert_dir, 'alpha', 'alpha.example.com')
    config = _config(
        cert_dir, ca, {'alpha.example.com': alpha}, sni_default='reject', with_default=False
    )
    context = config.create_ssl_context()
    assert context is not None

    server, client, errors = _handshake(context, 'alpha.example.com')
    assert not errors
    assert client.getpeercert(binary_form=True) == _der(alpha[0])
    server.close()
    client.close()


def test_single_certificate_config_still_works(cert_dir: Path, ca: trustme.CA) -> None:
    config = Config()
    config.certfile, config.keyfile = _issue(ca, cert_dir, 'default', 'default.example.com')
    context = config.create_ssl_context()
    assert config.certificate_group is None

    server, client, errors = _handshake(context, 'anything.example.com')
    assert not errors
    assert client.getpeercert(binary_form=True) == _der(config.certfile)
    server.close()
    client.close()
