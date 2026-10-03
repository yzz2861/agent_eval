"""authlib.oauth2.rfc9449.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP error responses defined by RFC 9449.

https://www.rfc-editor.org/rfc/rfc9449#section-11.2
"""

from ..base import OAuth2Error

__all__ = ["InvalidDPoPProofError", "UseDPoPNonceError"]


class InvalidDPoPProofError(OAuth2Error):
    """The DPoP proof is invalid, e.g. malformed, bad signature, wrong
    ``htm``/``htu``/``ath`` claims, or a replayed ``jti``.

    https://www.rfc-editor.org/rfc/rfc9449#section-11.2
    """

    error = "invalid_dpop_proof"
    description = "The DPoP proof is invalid."
    status_code = 400

    def __init__(
        self,
        description=None,
        uri=None,
        status_code=None,
        state=None,
        realm=None,
        extra_attributes=None,
    ):
        super().__init__(description, uri, status_code, state)
        self.realm = realm
        self.extra_attributes = extra_attributes or {}

    def get_headers(self):
        """The resource server responds with ``WWW-Authenticate: DPoP``
        per RFC 9449 Section 7.1."""
        headers = super().get_headers()
        extras = []
        if self.realm:
            extras.append(f'realm="{self.realm}"')
        if self.extra_attributes:
            extras.extend(
                [f'{k}="{self.extra_attributes[k]}"' for k in self.extra_attributes]
            )
        extras.append(f'error="{self.error}"')
        error_description = self.get_error_description()
        extras.append(f'error_description="{error_description}"')
        headers.append(("WWW-Authenticate", "DPoP " + ", ".join(extras)))
        return headers


class UseDPoPNonceError(OAuth2Error):
    """The authorization or resource server requires a ``nonce`` value in
    the DPoP proof. The client retries with a new proof containing the
    server supplied nonce.

    https://www.rfc-editor.org/rfc/rfc9449#section-8
    """

    error = "use_dpop_nonce"
    description = "The server requires a nonce in the DPoP proof."
    status_code = 400

    def __init__(
        self,
        description=None,
        uri=None,
        status_code=None,
        state=None,
        nonce=None,
        realm=None,
        extra_attributes=None,
    ):
        super().__init__(description, uri, status_code, state)
        self.nonce = nonce
        self.realm = realm
        self.extra_attributes = extra_attributes or {}

    def get_headers(self):
        headers = super().get_headers()
        extras = []
        if self.realm:
            extras.append(f'realm="{self.realm}"')
        if self.extra_attributes:
            extras.extend(
                [f'{k}="{self.extra_attributes[k]}"' for k in self.extra_attributes]
            )
        extras.append(f'error="{self.error}"')
        error_description = self.get_error_description()
        extras.append(f'error_description="{error_description}"')
        headers.append(("WWW-Authenticate", "DPoP " + ", ".join(extras)))
        if self.nonce:
            headers.append(("DPoP-Nonce", self.nonce))
        return headers
