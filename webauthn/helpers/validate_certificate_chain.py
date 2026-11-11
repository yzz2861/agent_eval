from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from OpenSSL.crypto import (
    X509,
    X509Store,
    X509StoreContext,
    X509StoreContextError,
    load_certificate,
    FILETYPE_ASN1,
)

from .exceptions import InvalidCertificateChain
from .pem_cert_bytes_to_open_ssl_x509 import pem_cert_bytes_to_open_ssl_x509


def validate_certificate_chain(
    *,
    x5c: List[bytes],
    pem_root_certs_bytes: Optional[List[bytes]] = None,
    pem_intermediate_certs_bytes: Optional[List[bytes]] = None,
) -> bool:
    """Validate that the certificates in x5c chain back to a known root certificate

    Args:
        `x5c`: X5C certificates from a registration response's attestation statement
        (optional) `pem_root_certs_bytes`: Any additional (PEM-formatted)
        root certificates that may complete the certificate chain
        (optional) `pem_intermediate_certs_bytes`: Any additional (PEM-formatted)
        intermediate certificates that may complete the certificate chain

    Raises:
        `helpers.exceptions.InvalidCertificateChain` if chain cannot be validated
    """
    if pem_root_certs_bytes is None or len(pem_root_certs_bytes) < 1:
        # We have no root certs to chain back to, so just pass on validation
        return True

    # Make sure we have at least one certificate to try and link back to a root cert
    if len(x5c) < 1:
        raise InvalidCertificateChain("x5c was empty")

    # Prepare leaf cert
    try:
        leaf_cert_bytes = x5c[0]
        leaf_cert = load_certificate(FILETYPE_ASN1, leaf_cert_bytes)
    except Exception as exc:
        raise InvalidCertificateChain(
            "Could not prepare leaf cert. See __cause__ for more info"
        ) from exc

    # Prepare any intermediate certs
    try:
        # May be an empty array, that's fine
        intermediate_certs_bytes = x5c[1:]
        # Include intermediates explicitly supplied by the caller (e.g. by a trust policy)
        intermediate_certs_bytes.extend(pem_intermediate_certs_bytes or [])
        intermediate_certs = [
            (
                pem_cert_bytes_to_open_ssl_x509(cert)
                if b"-----BEGIN" in cert
                else load_certificate(FILETYPE_ASN1, cert)
            )
            for cert in intermediate_certs_bytes
        ]
    except Exception as exc:
        raise InvalidCertificateChain(
            "Could not prepare intermediate certs. See __cause__ for more info"
        ) from exc

    # Prepare a collection of possible root certificates
    cert_store = _generate_new_cert_store()
    try:
        for cert in pem_root_certs_bytes:
            cert_store.add_cert(pem_cert_bytes_to_open_ssl_x509(cert))
    except Exception as exc:
        raise InvalidCertificateChain(
            "Could not prepare root certs. See __cause__ for more info"
        ) from exc

    # Load certs into a "context" for validation
    context = X509StoreContext(
        store=cert_store,
        certificate=leaf_cert,
        chain=intermediate_certs,
    )

    # Validate the chain (will raise if it can't)
    try:
        context.verify_certificate()
    except X509StoreContextError as exc:
        raise InvalidCertificateChain(
            "Certificate chain could not be validated. See __cause__ for more info"
        ) from exc

    return True


def _generate_new_cert_store() -> X509Store:
    """
    Something that can be patched during testing to return an X509Store instance with its time
    adjusted to some datetime in the past. This allows full certificate validity checks even after
    cert expiration in the real world. See here:

    https://www.pyopenssl.org/en/stable/api/crypto.html#OpenSSL.crypto.X509Store.set_time
    """
    return X509Store()


def _load_policy_cert(cert_bytes: bytes) -> x509.Certificate:
    """Load a PEM- or DER-formatted certificate configured on an attestation trust policy."""
    try:
        return x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        return x509.load_der_x509_certificate(cert_bytes)


def _cert_not_expired(cert: x509.Certificate) -> bool:
    now = datetime.now(timezone.utc)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - older cryptography releases
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return not_before <= now <= not_after


def _verify_cert_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify `child` was signed by `issuer`'s private key. Raises InvalidSignature on failure."""
    issuer_public_key = issuer.public_key()
    if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        issuer_public_key.verify(
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )
    elif isinstance(issuer_public_key, rsa.RSAPublicKey):
        if child.signature_algorithm_oid == x509.SignatureAlgorithmOID.RSASSA_PSS:
            try:
                hash_alg = child.signature_hash_algorithm
                assert hash_alg is not None
                issuer_public_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hash_alg),
                        salt_length=padding.PSS.AUTO,
                    ),
                    hash_alg,
                )
            except Exception:
                # Fall back to MAX_LENGTH, which mirrors verify_signature()'s PSS behavior
                hash_alg = child.signature_hash_algorithm
                assert hash_alg is not None
                issuer_public_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hash_alg),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hash_alg,
                )
        else:
            issuer_public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
    elif isinstance(issuer_public_key, ed25519.Ed25519PublicKey):
        issuer_public_key.verify(child.signature, child.tbs_certificate_bytes)
    else:
        raise InvalidSignature(
            f"Unsupported issuer public key type {type(issuer_public_key).__name__}"
        )


def _load_roots_and_intermediates(
    pem_root_certs_bytes: List[bytes],
    pem_intermediate_certs_bytes: Optional[List[bytes]] = None,
) -> Tuple[List[x509.Certificate], List[x509.Certificate]]:
    roots: List[x509.Certificate] = []
    for root_bytes in pem_root_certs_bytes:
        roots.append(_load_policy_cert(root_bytes))

    intermediates: List[x509.Certificate] = []
    for intermediate_bytes in pem_intermediate_certs_bytes or []:
        intermediates.append(_load_policy_cert(intermediate_bytes))

    return roots, intermediates


def _find_issuer(
    cert: x509.Certificate,
    candidates: List[x509.Certificate],
) -> Optional[x509.Certificate]:
    """Find a candidate certificate that both names itself as issuer and signs `cert`.

    Matching on the cryptographic signature (not just subject/issuer names) means a chain cannot
    be "completed" by a certificate that merely shares a subject name with the real issuer.
    """
    for candidate in candidates:
        if candidate.subject != cert.issuer:
            continue
        try:
            _verify_cert_signature(cert, candidate)
        except InvalidSignature:
            continue
        except Exception:
            continue
        return candidate
    return None


def _find_subject_match(
    cert: x509.Certificate,
    candidates: List[x509.Certificate],
) -> Optional[x509.Certificate]:
    """Return a candidate whose subject matches `cert`'s issuer, regardless of signature."""
    for candidate in candidates:
        if candidate.subject == cert.issuer:
            return candidate
    return None


def _check_key_usage(cert: x509.Certificate, is_ca: bool) -> None:
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        # RFC 5280 marks key usage optional; absent means no key-usage restriction is asserted
        return

    if is_ca:
        if not key_usage.key_cert_sign:
            raise InvalidCertificateChain("CA certificate was not permitted to sign certificates")
    elif not key_usage.digital_signature:
        raise InvalidCertificateChain(
            "Attestation certificate was not permitted for digital signature"
        )


def _check_basic_constraints(cert: x509.Certificate, is_ca: bool) -> None:
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        if is_ca:
            raise InvalidCertificateChain(
                "CA certificate was missing the basic constraints extension"
            )
        return

    if is_ca and not basic_constraints.ca:
        raise InvalidCertificateChain(
            "Intermediate/root certificate did not assert CA basic constraints"
        )


def validate_policy_certificate_chain(
    *,
    x5c: List[bytes],
    pem_root_certs_bytes: List[bytes],
    pem_intermediate_certs_bytes: Optional[List[bytes]] = None,
) -> x509.Certificate:
    """Strictly validate an attestation `x5c` chain against an explicit trust policy.

    Unlike :func:`validate_certificate_chain`, this never silently passes when no roots are
    configured: every link of the chain must be present (in `x5c` or in the policy's configured
    intermediates), be within its validity period, assert suitable key usage and basic
    constraints, and chain cryptographically to a configured root. The returned value is the
    parsed leaf certificate so callers can perform additional checks without re-parsing `x5c`.

    Error messages deliberately reference certificate position/role rather than certificate
    contents so that full certificates never end up in logs.

    Raises:
        `InvalidCertificateChain` with a category-specific message when validation fails.
    """
    if not x5c:
        raise InvalidCertificateChain("Attestation statement did not include an x5c chain")

    try:
        x5c_certs = [x509.load_der_x509_certificate(cert_bytes) for cert_bytes in x5c]
    except Exception as exc:
        raise InvalidCertificateChain(
            "Could not parse an x5c certificate. See __cause__ for more info"
        ) from exc

    try:
        roots, policy_intermediates = _load_roots_and_intermediates(
            pem_root_certs_bytes, pem_intermediate_certs_bytes
        )
    except Exception as exc:
        raise InvalidCertificateChain(
            "Could not parse a configured trust certificate. See __cause__ for more info"
        ) from exc

    if not roots:
        raise InvalidCertificateChain("No trusted root certificate was configured for this format")

    # Every configured root must itself be a valid, self-asserted CA
    for root in roots:
        if not _cert_not_expired(root):
            raise InvalidCertificateChain(
                "Configured root certificate was expired or not yet valid"
            )
        _check_basic_constraints(root, is_ca=True)
        _check_key_usage(root, is_ca=True)

    leaf_cert = x5c_certs[0]
    if not _cert_not_expired(leaf_cert):
        raise InvalidCertificateChain("Attestation leaf certificate was expired or not yet valid")
    _check_basic_constraints(leaf_cert, is_ca=False)
    _check_key_usage(leaf_cert, is_ca=False)

    # Intermediates available to complete the chain: everything after the leaf in x5c, plus any
    # intermediates explicitly configured on the policy for this format.
    available_intermediates: List[x509.Certificate] = list(x5c_certs[1:])
    available_intermediates.extend(policy_intermediates)

    # Walk the chain from leaf to root, verifying each link cryptographically
    current_cert = leaf_cert
    visited_subjects: Set[str] = set()
    chain_for_store: List[x509.Certificate] = []
    while True:
        current_subject = current_cert.subject.rfc4514_string()
        if current_subject in visited_subjects:
            raise InvalidCertificateChain("Certificate chain contained a loop")
        visited_subjects.add(current_subject)

        # A self-issued leaf/intermediate cannot be a trust anchor unless it is also a configured
        # root; check roots first so a self-signed root terminates the walk.
        root = _find_issuer(current_cert, roots)
        if root is not None:
            # Defense in depth: re-verify the assembled chain through OpenSSL's X509 store
            _verify_chain_with_x509_store(
                leaf_cert=leaf_cert,
                chain_certs=chain_for_store,
                root_certs=roots,
            )
            return leaf_cert

        if current_cert.issuer == current_cert.subject:
            # Self-signed certificate that was not present among the configured roots
            raise InvalidCertificateChain(
                "TRUST_ROOT_MISSING: chain terminated at a self-signed certificate that was "
                "not a configured root"
            )

        issuer = _find_issuer(current_cert, available_intermediates)
        if issuer is None:
            # Distinguish "roots exist but none validate this chain" from "a required
            # intermediate certificate is missing". The x5c entries after the leaf describe the
            # chain the authenticator claimed to provide: if we have not consumed all of them
            # yet, or the walk is still at/before the first hop, a missing link means the
            # presented chain was truncated. Once every presented intermediate has been consumed
            # and the top cert still cannot anchor at a configured root, the trusted roots do
            # not match this attestation.
            named_root = _find_subject_match(current_cert, roots)
            named_intermediate = _find_subject_match(current_cert, available_intermediates)
            if named_root is not None:
                raise InvalidCertificateChain(
                    "TRUST_ROOT_MISSING: configured root certificate did not validate the chain"
                )
            if named_intermediate is not None:
                # A same-named intermediate exists but its key does not validate the current
                # certificate. This is a malformed/incomplete presented chain unless we have
                # already walked every x5c intermediate, in which case the failure is at the
                # root boundary.
                if len(chain_for_store) >= len(x5c_certs) - 1:
                    raise InvalidCertificateChain(
                        "TRUST_ROOT_MISSING: a named intermediate certificate could not "
                        "validate the chain at the trust boundary"
                    )
                raise InvalidCertificateChain(
                    "CHAIN_INCOMPLETE: a named intermediate certificate could not validate "
                    "the chain"
                )
            # We have not yet successfully walked to any intermediate certificate, i.e. the
            # authenticator's x5c (plus policy intermediates) cannot even get past the leaf. That
            # is a truncated chain. Once at least one intermediate has been traversed, the walk
            # has reached the trust boundary and failure means no configured root anchors it.
            if not chain_for_store:
                raise InvalidCertificateChain(
                    "CHAIN_INCOMPLETE: no configured root or intermediate certificate could "
                    "complete the chain"
                )
            raise InvalidCertificateChain(
                "TRUST_ROOT_MISSING: no configured root certificate anchored the chain"
            )

        if not _cert_not_expired(issuer):
            raise InvalidCertificateChain("Intermediate certificate was expired or not yet valid")
        _check_basic_constraints(issuer, is_ca=True)
        _check_key_usage(issuer, is_ca=True)

        # Don't traverse the same intermediate again on subsequent iterations
        available_intermediates = [
            candidate for candidate in available_intermediates if candidate is not issuer
        ]
        chain_for_store.append(issuer)
        current_cert = issuer


def _verify_chain_with_x509_store(
    *,
    leaf_cert: x509.Certificate,
    chain_certs: List[x509.Certificate],
    root_certs: List[x509.Certificate],
) -> None:
    """Re-verify an already cryptographically-linked chain through an OpenSSL X509Store."""
    store = _generate_new_cert_store()
    for root in root_certs:
        store.add_cert(X509().from_cryptography(root))

    openssl_leaf = X509().from_cryptography(leaf_cert)
    openssl_chain = [X509().from_cryptography(cert) for cert in chain_certs]

    context = X509StoreContext(
        store=store,
        certificate=openssl_leaf,
        chain=openssl_chain,
    )
    try:
        context.verify_certificate()
    except X509StoreContextError as exc:
        raise InvalidCertificateChain(
            "Certificate chain could not be validated. See __cause__ for more info"
        ) from exc
