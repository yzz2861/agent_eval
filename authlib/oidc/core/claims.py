from __future__ import annotations

import hmac

from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError

from authlib.common.encoding import to_bytes
from authlib.common.language import is_valid_language_tag
from authlib.oauth2.claims import JWTClaims
from authlib.oauth2.rfc6749.util import normalize_response_type
from authlib.oauth2.rfc6749.util import scope_to_list

from .util import create_half_hash

__all__ = [
    "IDToken",
    "CodeIDToken",
    "ImplicitIDToken",
    "HybridIDToken",
    "UserInfo",
    "get_claim_cls_by_response_type",
]

_REGISTERED_CLAIMS = [
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "azp",
    "at_hash",
]


class IDToken(JWTClaims):
    ESSENTIAL_CLAIMS = ["iss", "sub", "aud", "exp", "iat"]

    def validate(self, now=None, leeway=0):
        for k in self.ESSENTIAL_CLAIMS:
            if k not in self:
                raise MissingClaimError(k)

        super().validate(now, leeway)
        self.validate_aud()
        self.validate_auth_time()
        self.validate_nonce()
        self.validate_amr()
        self.validate_azp()
        self.validate_at_hash()

    def validate_aud(self):
        """REQUIRED. Audience(s) that this ID Token is intended for.

        Per OpenID Connect Core §2, a single audience is a
        case-sensitive string and multiple audiences are an array of
        strings. A single-element array is accepted for compatibility with
        issuers that always encode ``aud`` as an array. The Client MUST
        validate that ``aud`` contains its ``client_id``.
        """
        client_id = self.params.get("client_id")
        aud = self["aud"]
        if isinstance(aud, list):
            if not aud or not all(isinstance(item, str) for item in aud):
                raise InvalidClaimError("aud")
        elif not isinstance(aud, str):
            raise InvalidClaimError("aud")

        if not client_id:
            return

        audiences = aud if isinstance(aud, list) else [aud]
        if client_id not in audiences:
            raise InvalidClaimError("aud")

    def validate_auth_time(self):
        """Time when the End-User authentication occurred. Its value is a JSON
        number representing the number of seconds from 1970-01-01T0:0:0Z as
        measured in UTC until the date/time. When a max_age request is made or
        when auth_time is requested as an Essential Claim, then this Claim is
        REQUIRED; otherwise, its inclusion is OPTIONAL.
        """
        auth_time = self.get("auth_time")
        if self.params.get("max_age") and not auth_time:
            raise MissingClaimError("auth_time")

        if auth_time and not isinstance(auth_time, (int, float)):
            raise InvalidClaimError("auth_time")

    def validate_nonce(self):
        """String value used to associate a Client session with an ID Token,
        and to mitigate replay attacks. The value is passed through unmodified
        from the Authentication Request to the ID Token. If present in the ID
        Token, Clients MUST verify that the nonce Claim Value is equal to the
        value of the nonce parameter sent in the Authentication Request. If
        present in the Authentication Request, Authorization Servers MUST
        include a nonce Claim in the ID Token with the Claim Value being the
        nonce value sent in the Authentication Request. Authorization Servers
        SHOULD perform no other processing on nonce values used. The nonce
        value is a case sensitive string.
        """
        nonce_value = self.params.get("nonce")
        if nonce_value:
            if "nonce" not in self:
                raise MissingClaimError("nonce")
            if not hmac.compare_digest(to_bytes(nonce_value), to_bytes(self["nonce"])):
                raise InvalidClaimError("nonce")

    def validate_amr(self):
        """OPTIONAL. Authentication Methods References. JSON array of strings
        that are identifiers for authentication methods used in the
        authentication. For instance, values might indicate that both password
        and OTP authentication methods were used. The definition of particular
        values to be used in the amr Claim is beyond the scope of this
        specification. Parties using this claim will need to agree upon the
        meanings of the values used, which may be context-specific. The amr
        value is an array of case sensitive strings.
        """
        amr = self.get("amr")
        if amr and not isinstance(self["amr"], list):
            raise InvalidClaimError("amr")

    def validate_azp(self):
        """OPTIONAL. Authorized party - the party to which the ID Token was
        issued. If present, it MUST contain the OAuth 2.0 Client ID of this
        party. When the ID Token has several audiences, ``azp`` is REQUIRED
        and MUST be the client ID of the current client, so a token issued
        to another client is rejected. It MAY be included even when the
        authorized party is the same as the sole audience. The azp value is
        a case sensitive string containing a StringOrURI value.
        """
        aud = self.get("aud")
        client_id = self.params.get("client_id")
        required = bool(client_id) and isinstance(aud, list) and len(aud) > 1
        azp = self.get("azp")
        if required and not azp:
            raise MissingClaimError("azp")

        if azp and not isinstance(azp, str):
            raise InvalidClaimError("azp")

        if (
            azp
            and client_id
            and not hmac.compare_digest(to_bytes(azp), to_bytes(client_id))
        ):
            raise InvalidClaimError("azp")

    def validate_at_hash(self):
        """OPTIONAL. Access Token hash value. Its value is the base64url
        encoding of the left-most half of the hash of the octets of the ASCII
        representation of the access_token value, where the hash algorithm
        used is the hash algorithm used in the alg Header Parameter of the
        ID Token's JOSE Header. For instance, if the alg is RS256, hash the
        access_token value with SHA-256, then take the left-most 128 bits and
        base64url encode them. The at_hash value is a case sensitive string.
        """
        self._validate_hash_claim("at_hash", self.params.get("access_token"))

    def validate_c_hash(self):
        """Validate the ``c_hash`` claim when the flow returns a code from
        the authorization endpoint. The base class does not require it:
        :class:`HybridIDToken` overrides this method.
        """

    def _validate_hash_claim(self, claim_name, value):
        """Validate an ``at_hash`` or ``c_hash`` claim.

        The hash is the base64url encoding of the left-most half of the hash
        of the value, with the hash algorithm of the JWS ``alg`` header. The
        comparison is constant-time and case-sensitive, so truncated or
        differently cased hashes are rejected. Error messages only name the
        claim, never the token value.
        """
        hash_claim = self.get(claim_name)
        if not hash_claim:
            return
        if (
            not isinstance(hash_claim, str)
            or not value
            or not _verify_hash(hash_claim, value, self.header["alg"])
        ):
            raise InvalidClaimError(claim_name)


class CodeIDToken(IDToken):
    RESPONSE_TYPES = ("code",)
    REGISTERED_CLAIMS = _REGISTERED_CLAIMS


class ImplicitIDToken(IDToken):
    RESPONSE_TYPES = ("id_token", "id_token token")
    REGISTERED_CLAIMS = _REGISTERED_CLAIMS

    def validate_at_hash(self):
        """``at_hash`` is REQUIRED with ``response_type=id_token token`` and
        forbidden with ``response_type=id_token``, which never returns an
        Access Token from the authorization endpoint.
        """
        access_token = self.params.get("access_token")
        if access_token and "at_hash" not in self:
            raise MissingClaimError("at_hash")
        if not access_token and "at_hash" in self:
            raise InvalidClaimError("at_hash")
        super().validate_at_hash()


class HybridIDToken(ImplicitIDToken):
    RESPONSE_TYPES = ("code id_token", "code token", "code id_token token")
    REGISTERED_CLAIMS = _REGISTERED_CLAIMS + ["c_hash"]

    def validate(self, now=None, leeway=0):
        super().validate(now=now, leeway=leeway)
        self.validate_c_hash()

    def validate_c_hash(self):
        """Code hash value. Its value is the base64url encoding of the
        left-most half of the hash of the octets of the ASCII representation
        of the code value, where the hash algorithm used is the hash algorithm
        used in the alg Header Parameter of the ID Token's JOSE Header. For
        instance, if the alg is HS512, hash the code value with SHA-512, then
        take the left-most 256 bits and base64url encode them. The c_hash
        value is a case sensitive string.
        If the ID Token is issued from the Authorization Endpoint with a code,
        which is the case for the response_type values code id_token and code
        id_token token, this is REQUIRED; otherwise, its inclusion is OPTIONAL.
        """
        code = self.params.get("code")
        if code and "c_hash" not in self:
            raise MissingClaimError("c_hash")
        self._validate_hash_claim("c_hash", code)


class UserInfo(dict):
    """The standard claims of a UserInfo object. Defined per `Section 5.1`_.

    .. _`Section 5.1`: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    """

    #: registered claims that UserInfo supports
    REGISTERED_CLAIMS = [
        "sub",
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "email",
        "email_verified",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "phone_number",
        "phone_number_verified",
        "address",
        "updated_at",
    ]

    SCOPES_CLAIMS_MAPPING = {
        "openid": ["sub"],
        "profile": [
            "name",
            "family_name",
            "given_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
        ],
        "email": ["email", "email_verified"],
        "address": ["address"],
        "phone": ["phone_number", "phone_number_verified"],
    }

    def validate_locale(self):
        """Validate the locale claim is a BCP 47 language tag."""
        locale = self.get("locale")
        if locale is not None and not is_valid_language_tag(locale):
            raise ValueError('"locale" MUST be a BCP 47 language tag')

    def filter(self, scope: str):
        """Return a new UserInfo object containing only the claims matching the scope passed in parameter."""
        scope = scope_to_list(scope)
        filtered_claims = [
            claim
            for scope_part in scope
            for claim in self.SCOPES_CLAIMS_MAPPING.get(scope_part, [])
        ]
        filtered_items = {
            key: val for key, val in self.items() if key in filtered_claims
        }
        return UserInfo(filtered_items)

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in self.REGISTERED_CLAIMS:
                return self.get(key)
            raise error


def get_claim_cls_by_response_type(response_type):
    """Return the ID Token claims class for a response type.

    Per RFC 6749 §3.1.1, the order of the values does not matter.

    :param response_type: the ``response_type`` of the authorization request
    :return: a claims class, or ``None`` if no class matches
    """
    response_type = normalize_response_type(response_type)
    claims_classes = (CodeIDToken, ImplicitIDToken, HybridIDToken)
    for claims_cls in claims_classes:
        if response_type in {
            normalize_response_type(rt) for rt in claims_cls.RESPONSE_TYPES
        }:
            return claims_cls


def _verify_hash(signature, s, alg):
    hash_value = create_half_hash(s, alg)
    if hash_value is None:
        return False
    return hmac.compare_digest(hash_value, to_bytes(signature))
