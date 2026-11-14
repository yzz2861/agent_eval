Changed
~~~~~~~

- The RFC 7591 registration endpoint fully validates the client metadata
  before the client is saved, so a rejected request cannot leave a
  half-registered client behind. URI metadata only accept the schemes declared
  by ``ClientMetadataClaims.uri_schemes`` and
  ``ClientMetadataClaims.redirect_uri_schemes`` (``https`` by default) and
  must not contain a fragment or a userinfo component. A ``jwks`` document is
  bounded to ``ClientMetadataClaims.jwks_max_keys`` keys, and ``grant_types``
  and ``response_types`` must be consistent with each other when both are
  present.

Added
~~~~~

- ``ClientRegistrationEndpoint.get_software_statement_issuers`` names the
  approved software statement issuers. A software statement is also rejected
  when its ``scope`` is wider than the scope requested at the top level of
  the registration request.
