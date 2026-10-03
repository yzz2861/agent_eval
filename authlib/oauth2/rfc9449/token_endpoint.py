"""authlib.oauth2.rfc9449.token_endpoint.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP validation component for the token endpoint, per RFC 9449
Section 5. The returned JWK thumbprint is bound to the issued access
token as its ``cnf.jkt`` confirmation claim.
"""

from .dpop import DPoPProofValidator

__all__ = ["DPoPTokenEndpointValidator"]


class DPoPTokenEndpointValidator:
    """Validate the DPoP proof of a token request.

    Usage inside a token endpoint implementation::

        validator = DPoPTokenEndpointValidator()
        jkt = validator.validate_request(request)
        if jkt:
            # issue a DPoP-bound token with "cnf": {"jkt": jkt}
            # and token_type "DPoP"

    :param proof_validator: an optional pre-configured
        :class:`DPoPProofValidator`; extra keyword arguments are
        forwarded to its constructor otherwise
    """

    def __init__(self, proof_validator=None, **kwargs):
        if proof_validator is None:
            proof_validator = DPoPProofValidator(**kwargs)
        self.proof_validator = proof_validator

    def validate_request(self, request):
        """Validate the ``DPoP`` header of a token request.

        :param request: an object with ``method``, ``uri`` and
            ``headers`` attributes
        :return: the JWK thumbprint (``jkt``) of the proof public key
            to bind the issued token to, or ``None`` when the request
            carries no DPoP proof
        """
        if not request.headers.get("DPoP"):
            return None
        proof = self.proof_validator.validate_request(request)
        return proof.jkt
