from __future__ import annotations

from typing import TYPE_CHECKING

from ..rfc6749.resource_protector import TokenValidator
from .errors import InvalidDPoPProofError
from .errors import InvalidDPoPResourceProofError
from .errors import UseDPoPNonceError
from .errors import UseDPoPNonceResourceError
from .validator import DPoPProofValidator

if TYPE_CHECKING:
    from ..rfc6750.validator import BearerTokenValidator


class DPoPTokenValidator(TokenValidator):
    """Resource-server validator for DPoP-bound access tokens."""

    TOKEN_TYPE = "dpop"

    def __init__(
        self,
        bearer_validator: BearerTokenValidator,
        dpop_validator: DPoPProofValidator,
    ):
        super().__init__(
            realm=bearer_validator.realm,
            **bearer_validator.extra_attributes,
        )
        self.bearer_validator = bearer_validator
        self.dpop_validator = dpop_validator

    def authenticate_token(self, token_string):
        return self.bearer_validator.authenticate_token(token_string)

    def validate_request_credential(self, request, token_string):
        try:
            proof = self.dpop_validator.validate_resource_request(
                request,
                token_string,
            )
        except UseDPoPNonceError as error:
            raise UseDPoPNonceResourceError(
                description=error.description,
                nonce=error.dpop_nonce,
            ) from error
        except InvalidDPoPProofError as error:
            raise InvalidDPoPResourceProofError(
                description=error.description,
                nonce=error.dpop_nonce,
            ) from error
        request.dpop_proof = proof

    def validate_token(self, token, scopes, request, **kwargs):
        proof = request.dpop_proof
        if not token:
            raise InvalidDPoPResourceProofError("The access token is invalid.")
        self.validate_token_binding(token, proof.jkt)
        self.bearer_validator.validate_token(token, scopes, request, **kwargs)

    @staticmethod
    def validate_token_binding(token, expected_jkt: str):
        if isinstance(token, dict):
            confirmation = token.get("cnf")
        else:
            get_confirmation = getattr(token, "get_cnf", None)
            confirmation = (
                get_confirmation() if callable(get_confirmation) else None
            )
        if not isinstance(confirmation, dict):
            raise InvalidDPoPResourceProofError("Missing DPoP key binding.")
        actual_jkt = confirmation.get("jkt")
        if actual_jkt != expected_jkt:
            raise InvalidDPoPResourceProofError("Invalid DPoP key binding.")
