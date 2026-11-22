# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import oscrypto


def _openssl_public_symbols():
    # Only the asymmetric module is required for X.509 path validation. The
    # tls/symmetric modules initialize OpenSSL at import time and conflict
    # with the already-loaded platform backend, so they are deliberately not
    # rewired here.
    from oscrypto._openssl import asymmetric as openssl_asymmetric
    return {
        "asymmetric": openssl_asymmetric,
    }


def _mac_backend_works():
    from oscrypto import asymmetric
    try:
        public_key, private_key = asymmetric.generate_pair("ec", curve="secp256r1")
        signature = asymmetric.ecdsa_sign(
            private_key, b"backend probe", "sha256"
        )
        asymmetric.ecdsa_verify(public_key, signature, b"backend probe", "sha256")
        return True
    except (OSError):
        return False


def ensure_working_backend():
    """
    Returns the name of the oscrypto backend that should be used.

    On a normal host the platform default is returned untouched. In restricted
    environments where the platform backend (e.g. macOS Security/CSSM) can not
    load, oscrypto's bundled OpenSSL backend is wired into the public modules
    instead. This only affects the test process and never changes production
    validation logic.
    """

    if oscrypto.backend() != "mac":
        return oscrypto.backend()

    if _mac_backend_works():
        return "mac"

    import importlib
    oscrypto_asymmetric = importlib.import_module("oscrypto.asymmetric")

    oscrypto._module_values["backend"] = "openssl"
    openssl_modules = _openssl_public_symbols()
    openssl_asymmetric = openssl_modules["asymmetric"]
    oscrypto_asymmetric._backend = "openssl"
    for symbol in dir(openssl_asymmetric):
        if symbol.startswith("_"):
            continue
        setattr(oscrypto_asymmetric, symbol, getattr(openssl_asymmetric, symbol))
    return "openssl"
