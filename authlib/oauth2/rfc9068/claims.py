from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError
from joserfc.jwt import JWTClaimsRegistry

from authlib._joserfc_helpers import audience_matches
from authlib.oauth2.claims import JWTClaims

_ACCESS_TOKEN_TYPES = ("at+jwt", "application/at+jwt")

#: Claims that RFC 9068 section 2.2 makes mandatory in a JWT access token,
#: with the JSON type each claim MUST have.
REQUIRED_CLAIM_TYPES = {
    "iss": str,
    "sub": str,
    "client_id": str,
    "aud": (str, list),
    "exp": (int, float),
    "iat": (int, float),
    "jti": str,
}

#: Optional claims with a known JSON type. The ``scope`` claim is only
#: type-checked in strict mode: the default profile keeps accepting tokens
#: that encode scopes as a JSON array, for backward compatibility.
OPTIONAL_CLAIM_TYPES = {
    "auth_time": (int, float),
    "acr": str,
    "amr": list,
    "groups": list,
    "roles": list,
    "entitlements": list,
}


def _is_access_token(claims) -> bool:
    """Tell if the JWT header declares an access token."""
    typ = claims.header.get("typ")
    return bool(typ) and typ.lower() in _ACCESS_TOKEN_TYPES


class JWTAccessTokenClaimsValidator(JWTClaimsRegistry):
    def validate_auth_time(self, auth_time):
        if not isinstance(auth_time, (int, float)):
            raise InvalidClaimError("auth_time")
        self.check_value("auth_time", auth_time)

    def validate_amr(self, amr):
        if not isinstance(amr, list):
            raise InvalidClaimError("amr", amr)


class JWTAccessTokenClaims(JWTClaims):
    registry_cls = JWTAccessTokenClaimsValidator
    REGISTERED_CLAIMS = JWTClaims.REGISTERED_CLAIMS + [
        "client_id",
        "auth_time",
        "acr",
        "amr",
        "scope",
        "groups",
        "roles",
        "entitlements",
    ]

    def get_scope(self) -> str | None:
        """Return the value of the ``scope`` claim, or ``None`` if the token
        has no scope.
        """
        return self.get("scope")

    def validate_token_type(self):
        """Validate the ``typ`` header, per RFC 9068 section 2.1.

        The header MUST be present and declare an access token. In strict
        mode only the canonical ``at+jwt`` value is accepted.
        """
        typ = self.header.get("typ")
        if self.params.get("strict"):
            valid = isinstance(typ, str) and typ == "at+jwt"
        else:
            valid = isinstance(typ, str) and typ.lower() in _ACCESS_TOKEN_TYPES
        if not valid:
            raise InvalidClaimError("typ")

    def validate_claim_structure(self):
        """Validate the presence and the JSON type of every known claim.

        Missing claims and claims with the wrong type raise distinct errors
        (:class:`MissingClaimError` and :class:`InvalidClaimError`) so that
        audits can tell them apart. The claim name is carried by the error,
        but the token itself is never logged.
        """
        for claim in REQUIRED_CLAIM_TYPES:
            if claim not in self:
                raise MissingClaimError(claim)

        strict = self.params.get("strict", False)
        claim_types = dict(REQUIRED_CLAIM_TYPES)
        claim_types.update(OPTIONAL_CLAIM_TYPES)
        if strict:
            claim_types["scope"] = str
        for claim, expected in claim_types.items():
            if claim not in self:
                continue
            value = self[claim]
            if not self._has_claim_type(value, expected):
                raise InvalidClaimError(claim)

    @staticmethod
    def _has_claim_type(value, expected) -> bool:
        # A NumericDate is a JSON number: booleans must not be accepted.
        if isinstance(value, bool) and expected is not bool:
            return False
        if not isinstance(value, expected):
            return False
        if expected is list:
            return all(isinstance(item, str) for item in value)
        return True

    def validate_issuer_binding(self, issuer):
        """Validate that the token was issued by the configured issuer."""
        if self.get("iss") != issuer:
            raise InvalidClaimError("iss")

    def validate_resource_audience(self, resource_server):
        """Validate that the token is intended for this resource server."""
        if resource_server is not None and not audience_matches(
            self.get("aud"), resource_server
        ):
            raise InvalidClaimError("aud")

    def validate_lifetime(self, now=None, leeway=0):
        """Validate the time claims, in particular the expiration time."""
        registry = self.registry_cls(now, leeway)
        registry.validate_exp(self["exp"])
        registry.validate_iat(self["iat"])

    def validate(self, **kwargs):
        # Per RFC 9068 §4, the resource server MUST verify that the typ header
        # value is at+jwt or application/at+jwt.
        self.validate_token_type()
        self.validate_claim_structure()
        super().validate(**kwargs)
