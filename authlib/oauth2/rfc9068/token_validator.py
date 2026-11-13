"""authlib.oauth2.rfc9068.token_validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of Validating JWT Access Tokens per :rfc:`9068#section-4`.

The validation is organized in five layers:

1. Signature trust: the token is verified with keys from the resource server
   configuration. A token-provided ``jku`` or ``jwk`` header is never used.
2. Issuer binding: the token issuer selects the issuer-bound key, and the
   ``iss`` claim must match it after verification.
3. Type and purpose: the ``typ`` header must declare an access token.
4. Claim structure: required claims must be present with the right JSON type.
5. Resource audience: the ``aud`` claim must contain the resource server.
"""

import logging

from joserfc import jwt
from joserfc.errors import JoseError

from authlib._joserfc_helpers import import_any_key
from authlib.common.encoding import json_loads
from authlib.common.encoding import urlsafe_b64decode
from authlib.oauth2.claims import ClaimsOption
from authlib.oauth2.rfc6750.errors import InsufficientScopeError
from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc6750.validator import BearerTokenValidator

from .claims import JWTAccessTokenClaims

logger = logging.getLogger(__name__)


class JWTBearerTokenValidator(BearerTokenValidator):
    """JWTBearerTokenValidator can protect your resource server endpoints.

    :param issuer: The issuer from which tokens will be accepted. It can be a
        single issuer identifier, or a mapping of issuer identifiers to their
        configuration when the resource server accepts tokens from several
        issuers. Each value is a mapping with optional ``jwks`` and
        ``resource_server`` keys; a global ``resource_server`` applies when an
        issuer does not define its own.
    :param resource_server: An identifier for the current resource server,
        which must appear in the JWT ``aud`` claim. It can be a string or a
        list of accepted identifiers. It is optional, like in the
        introspection and revocation endpoints, in which case the ``aud``
        claim is still required but not bound to a resource identifier.
    :param strict: Enable the strict validation profile. When enabled, the
        ``typ`` header must be the canonical ``at+jwt`` value, and the
        ``scope`` claim, when present, must be a space-separated string as
        required by :rfc:`8693#section-4.2`. The default profile keeps
        accepting legacy tokens that use ``application/at+jwt`` or encode
        scopes as a JSON array.

    Developers needs to implement the missing methods::

        class MyJWTBearerTokenValidator(JWTBearerTokenValidator):
            def get_jwks(self): ...


        require_oauth = ResourceProtector()
        require_oauth.register_token_validator(
            MyJWTBearerTokenValidator(
                issuer="https://authorization-server.example.org",
                resource_server="https://resource-server.example.org",
            )
        )

    You can then protect resources depending on the JWT `scope`, `groups`,
    `roles` or `entitlements` claims::

        @require_oauth(
            scope="profile",
            groups="admins",
            roles="student",
            entitlements="captain",
        )
        def resource_endpoint(): ...
    """

    def __init__(self, issuer, resource_server=None, strict=False, *args, **kwargs):
        if isinstance(issuer, dict):
            self.issuers = dict(issuer)
            self.issuer = None
        else:
            self.issuers = {}
            self.issuer = issuer
        self.resource_server = resource_server
        self.strict = strict
        super().__init__(*args, **kwargs)

    def get_jwks(self, issuer=None):
        """Return the JWKs that will be used to check the JWT access token signature.
        Developers MUST re-implement this method. Typically the JWKs are statically
        stored in the resource server configuration, or dynamically downloaded and
        cached using :ref:`specs/rfc8414`::

            def get_jwks(self):
                if "jwks" in cache:
                    return cache.get("jwks")

                server_metadata = get_server_metadata(self.issuer)
                jwks_uri = server_metadata.get("jwks_uri")
                cache["jwks"] = requests.get(jwks_uri).json()
                return cache["jwks"]

        With several issuers, the selected issuer is passed as the ``issuer``
        argument, so the implementation can return an issuer-specific key set.
        """
        raise NotImplementedError()

    def _get_issuer_config(self, issuer):
        """Return the ``(jwks, resource_server)`` pair bound to an issuer."""
        config = self.issuers.get(issuer)
        if not isinstance(config, dict):
            return None, None
        jwks = config.get("jwks")
        if jwks is None:
            jwks = self.get_jwks(issuer)
        resource_server = config.get("resource_server", self.resource_server)
        return jwks, resource_server

    def _decode_unverified(self, token_string):
        """Decode the header and claims without trusting the token.

        The decoded values are only used to select the issuer-bound key and
        reject token-provided key headers. Every claim is validated again
        after the signature is verified.
        """
        try:
            header_segment, payload_segment, _ = token_string.split(".")
            header = json_loads(urlsafe_b64decode(header_segment.encode("ascii")))
            claims = json_loads(urlsafe_b64decode(payload_segment.encode("ascii")))
        except (ValueError, TypeError, UnicodeError) as exc:
            raise self._invalid_token() from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise self._invalid_token()
        return header, claims

    def _invalid_token(self):
        return InvalidTokenError(
            realm=self.realm, extra_attributes=self.extra_attributes
        )

    def _reject(self, exc):
        """Convert a joserfc error into a generic RFC 6750 error.

        Only the error kind and, when available, the claim name are logged.
        The raw JWT and identifying claims such as ``jti`` are never logged,
        and no internal detail is sent to the client.
        """
        claim = getattr(exc, "claim", None)
        if claim:
            logger.debug(
                "Rejected JWT access token: %s on claim '%s'", exc.error, claim
            )
        else:
            logger.debug("Rejected JWT access token: %s", exc.error)
        return self._invalid_token()

    def validate_iss(self, claims, iss: "str") -> bool:
        # The issuer identifier for the authorization server (which is typically
        # obtained during discovery) MUST exactly match the value of the 'iss'
        # claim.
        return iss == self.issuer

    def authenticate_token(self, token_string):
        """Decode and cryptographically verify the JWT access token.

        Only the signature layer and the issuer-bound key selection are
        applied here. The semantic claim checks live in
        :meth:`validate_token`, so a token with a trusted signature but
        non-compliant claims still reaches the audit-friendly validation
        layers without leaking internal details to the client.
        """

        # Layers 1 and 2: read the unverified claims to select the key that is
        # bound to the issuer the token claims to come from.
        unverified_header, unverified_claims = self._decode_unverified(token_string)

        if self.issuer is not None:
            issuer = self.issuer
            jwks = self.get_jwks()
            resource_server = self.resource_server
        else:
            issuer = unverified_claims.get("iss")
            if not isinstance(issuer, str):
                logger.debug("Rejected JWT access token: missing or invalid 'iss'")
                raise self._invalid_token()
            jwks, resource_server = self._get_issuer_config(issuer)
            if jwks is None:
                logger.debug("Rejected JWT access token: unknown issuer")
                raise self._invalid_token()

        # The token must not dictate where the verification key comes from. A
        # 'jku' or embedded 'jwk' header is always rejected, the key always
        # comes from the resource server configuration.
        if "jku" in unverified_header or "jwk" in unverified_header:
            logger.debug("Rejected JWT access token: token-provided key header")
            raise self._invalid_token()

        key = import_any_key(jwks)

        # If the JWT access token is encrypted, decrypt it using the keys and algorithms
        # that the resource server specified during registration. If encryption was
        # negotiated with the authorization server at registration time and the incoming
        # JWT access token is not encrypted, the resource server SHOULD reject it.

        # The resource server MUST validate the signature of all incoming JWT access
        # tokens according to [RFC7515] using the algorithm specified in the JWT 'alg'
        # Header Parameter. The resource server MUST reject any JWT in which the value
        # of 'alg' is 'none'. The resource server MUST use the keys provided by the
        # authorization server.
        try:
            token = jwt.decode(token_string, key=key)
        except JoseError as exc:
            raise self._reject(exc) from exc

        claims_options: dict[str, ClaimsOption] = {}
        if self.issuer is not None:
            claims_options["iss"] = {
                "essential": True,
                "validate": self.validate_iss,
            }
        claims = JWTAccessTokenClaims(
            token.claims,
            token.header,
            claims_options,
            params={
                "strict": self.strict,
                "issuer": issuer,
                "resource_server": resource_server,
            },
        )
        return claims

    def validate_token(
        self,
        token: JWTAccessTokenClaims,
        scopes,
        request,
        groups=None,
        roles=None,
        entitlements=None,
    ):
        """Apply the semantic validation layers and scope restrictions."""
        try:
            # Layer 3: type and purpose of the token.
            token.validate_token_type()

            # Layer 4: structure of the claims. Missing claims and wrong
            # claim types raise distinct error classes for the audit logs.
            token.validate_claim_structure()

            # Layer 2: bind the token to the issuer whose key verified it.
            token.validate_issuer_binding(token.params["issuer"])

            # Layer 5: the token is intended for this resource server.
            token.validate_resource_audience(token.params["resource_server"])

            # Time claims (exp/iat) and the remaining claims options hooks.
            token.validate_lifetime()
            token._run_validate_hooks()
        except JoseError as exc:
            raise self._reject(exc) from exc

        # If an authorization request includes a scope parameter, the corresponding
        # issued JWT access token SHOULD include a 'scope' claim as defined in Section
        # 4.2 of [RFC8693]. All the individual scope strings in the 'scope' claim MUST
        # have meaning for the resources indicated in the 'aud' claim. See Section 5 for
        # more considerations about the relationship between scope strings and resources
        # indicated by the 'aud' claim.

        if self.scope_insufficient(token.get("scope", []), scopes):
            raise InsufficientScopeError()

        # Many authorization servers embed authorization attributes that go beyond the
        # delegated scenarios described by [RFC7519] in the access tokens they issue.
        # Typical examples include resource owner memberships in roles and groups that
        # are relevant to the resource being accessed, entitlements assigned to the
        # resource owner for the targeted resource that the authorization server knows
        # about, and so on. An authorization server wanting to include such attributes
        # in a JWT access token SHOULD use the 'groups', 'roles', and 'entitlements'
        # attributes of the 'User' resource schema defined by Section 4.1.2 of
        # [RFC7643]) as claim types.

        if self.scope_insufficient(token.get("groups"), groups):
            raise InvalidTokenError()

        if self.scope_insufficient(token.get("roles"), roles):
            raise InvalidTokenError()

        if self.scope_insufficient(token.get("entitlements"), entitlements):
            raise InvalidTokenError()
