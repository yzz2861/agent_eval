from __future__ import annotations

from authlib.common.errors import AuthlibHTTPError

from ..rfc6750.errors import InvalidTokenError
from ..rfc6749.errors import InvalidRequestError


class DPoPError:
    dpop_nonce = None

    def get_headers(self):
        headers = AuthlibHTTPError.get_headers(self)
        fields = [f'error="{self.error}"']
        if self.dpop_nonce:
            fields.append(f'nonce="{self.dpop_nonce}"')
        headers.append(("WWW-Authenticate", "DPoP " + ", ".join(fields)))
        if self.dpop_nonce:
            headers.append(("DPoP-Nonce", self.dpop_nonce))
        return headers


class InvalidDPoPProofError(DPoPError, InvalidRequestError):
    error = "invalid_dpop_proof"
    description = "The DPoP proof is missing, malformed, or invalid."

    def __init__(self, description=None, nonce=None):
        super().__init__(description=description)
        self.dpop_nonce = nonce


class UseDPoPNonceError(DPoPError, InvalidRequestError):
    error = "use_dpop_nonce"
    description = "The request requires a DPoP nonce."

    def __init__(self, description=None, nonce=None):
        super().__init__(description=description)
        self.dpop_nonce = nonce


class UseDPoPNonceResourceError(DPoPError, InvalidTokenError):
    error = "use_dpop_nonce"
    status_code = 401

    def __init__(self, description=None, nonce=None):
        super().__init__(description=description)
        self.dpop_nonce = nonce


class InvalidDPoPTokenError(DPoPError, InvalidRequestError):
    error = "invalid_token"
    description = "The DPoP-bound access token is invalid."

    def __init__(self, description=None, nonce=None):
        super().__init__(description=description)
        self.dpop_nonce = nonce


class InvalidDPoPResourceProofError(DPoPError, InvalidTokenError):
    error = "invalid_dpop_proof"
    status_code = 401

    def __init__(self, description=None, nonce=None):
        super().__init__(description=description)
        self.dpop_nonce = nonce
