"""authlib.oauth2.rfc9449.nonce.
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional server-provided nonce policy for DPoP proofs, per RFC 9449
Section 8. Developers MAY re-implement this interface to issue and
validate nonce values (e.g. signed, expiring nonces stored nowhere,
or random nonces kept in a shared cache).
"""

__all__ = ["DPoPNonceProvider"]


class DPoPNonceProvider:
    """Interface of a DPoP nonce policy. When a provider is configured
    on a validator, proofs without a valid ``nonce`` claim are rejected
    with a ``use_dpop_nonce`` error carrying a fresh nonce, and clients
    retry with a new proof containing that nonce.
    """

    def get_nonce(self) -> str:
        """Return a fresh nonce value to send in the ``DPoP-Nonce``
        response header."""
        raise NotImplementedError()

    def validate_nonce(self, nonce: str) -> bool:
        """Check whether the ``nonce`` claim of a proof is acceptable.

        :param nonce: value of the proof ``nonce`` claim
        :return: ``True`` if the nonce is valid
        """
        raise NotImplementedError()
