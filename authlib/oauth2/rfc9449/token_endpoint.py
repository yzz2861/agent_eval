from __future__ import annotations

from typing import Any

from .validator import DPoPProof
from .validator import DPoPProofValidator


class DPoPProofExtension:
    """Bind token-endpoint issued access tokens to a DPoP proof public key.

    Register it with grants that may issue DPoP tokens::

        server.register_grant(
            ClientCredentialsGrant,
            [DPoPProofExtension(validator)],
        )

    The extension is optional per client request: requests without a DPoP
    header receive an ordinary bearer token unless a nonce policy requires
    DPoP.
    """

    def __init__(self, validator: DPoPProofValidator):
        self.validator = validator

    def __call__(self, grant: Any):
        original_generate_token = grant.generate_token
        original_create_token_response = grant.create_token_response

        def generate_token(*args, **kwargs):
            proof = self.validator.validate_token_request(grant.request)
            grant.request.dpop_proof = proof
            token = original_generate_token(*args, **kwargs)
            return DPoPProofValidator.bind_token(token, proof)

        def create_token_response():
            proof = getattr(grant.request, "dpop_proof", None)
            result = original_create_token_response()
            if proof is None:
                return result
            status, token, headers = result
            return (
                status,
                token,
                self.with_nonce_header(headers, grant.request, proof),
            )

        grant.generate_token = generate_token
        grant.create_token_response = create_token_response

    def with_nonce_header(self, headers, request: Any, proof: DPoPProof):
        nonce = proof.claims.get("nonce")
        if not nonce or self.validator.nonce_policy is None:
            return headers
        current = self.validator.issue_nonce(request)
        if current and current != nonce:
            headers = [*headers, ("DPoP-Nonce", current)]
        return headers
