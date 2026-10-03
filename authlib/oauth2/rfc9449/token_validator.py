"""authlib.oauth2.rfc9449.token_validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Resource server side validator for DPoP-bound access tokens, per
RFC 9449 Section 7. It extends the bearer token validator with proof
validation (including the ``ath`` hash of the access token) and checks
that the token is bound to the proof public key via its ``cnf.jkt``
confirmation claim.
"""

from ..rfc6750 import BearerTokenValidator
from ..rfc6750 import InvalidTokenError
from .dpop import DPoPProofValidator
from .errors import InvalidDPoPProofError

__all__ = ["DPoPTokenValidator"]


class DPoPTokenValidator(BearerTokenValidator):
    """Validate ``Authorization: DPoP <token>`` requests together with
    their ``DPoP`` proof header."""

    TOKEN_TYPE = "dpop"

    def __init__(self, proof_validator=None, realm=None, **extra_attributes):
        super().__init__(realm, **extra_attributes)
        if proof_validator is None:
            proof_validator = DPoPProofValidator(realm=realm)
        self.proof_validator = proof_validator

    def validate_request(self, request):
        """Validate the DPoP proof of the request, including the ``ath``
        hash of the presented access token. The validated proof is
        stored on the request as ``dpop_proof``."""
        auth = request.headers.get("Authorization")
        if not auth:
            raise InvalidDPoPProofError(
                "Missing access token.",
                realm=self.realm,
                extra_attributes=self.extra_attributes,
            )
        token_string = auth.split(None, 1)[-1]
        proof = self.proof_validator.validate_request(
            request, access_token=token_string
        )
        request.dpop_proof = proof

    def validate_token(self, token, scopes, request):
        """Validate the token itself and its binding to the proof
        public key."""
        super().validate_token(token, scopes, request)
        proof = getattr(request, "dpop_proof", None)
        jkt = self.get_token_jkt(token)
        if proof is None or not jkt or jkt != proof.jkt:
            raise InvalidTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            )

    @staticmethod
    def get_token_jkt(token):
        """Extract the ``cnf.jkt`` confirmation value of a token."""
        getter = getattr(token, "get_cnf_jkt", None)
        if callable(getter):
            return getter()
        cnf = getattr(token, "cnf", None)
        if isinstance(cnf, dict):
            return cnf.get("jkt")
        if isinstance(token, dict):
            token_cnf = token.get("cnf")
            if isinstance(token_cnf, dict):
                return token_cnf.get("jkt")
        return None
