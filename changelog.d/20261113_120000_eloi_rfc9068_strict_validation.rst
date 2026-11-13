Added
~~~~~

- :class:`~authlib.oauth2.rfc9068.JWTBearerTokenValidator` accepts a
  ``strict`` argument. In strict mode, the JWT ``typ`` header must be the
  canonical ``at+jwt`` value and the ``scope`` claim must be a
  space-separated string, per :rfc:`9068#section-2` and
  :rfc:`8693#section-4.2`. The default profile keeps accepting legacy
  ``application/at+jwt`` tokens and JSON array ``scope`` claims.
- :class:`~authlib.oauth2.rfc9068.JWTBearerTokenValidator` can be configured
  with several issuers. Pass a mapping of issuer identifiers to their JWK sets
  and resource server identifiers as the ``issuer`` argument, or re-implement
  ``get_jwks(issuer)`` to resolve issuer-specific keys.

Security
~~~~~~~~

- The RFC 9068 resource server validation is organized in five explicit
  layers: signature trust, issuer binding, token type, claim structure and
  resource audience. Missing claims and claims with the wrong JSON type now
  raise distinct ``MissingClaimError`` and ``InvalidClaimError`` errors that
  carry the claim name for audits, while clients only receive the generic
  ``invalid_token`` error.
- :class:`~authlib.oauth2.rfc9068.JWTBearerTokenValidator` never fetches or
  trusts a ``jku`` or ``jwk`` header carried by the token: verification keys
  always come from the resource server configuration. Rejected tokens are
  logged without the raw JWT or identifying claims such as ``jti``.
